'use strict';

/**
 * Polls primary-source advisory feeds that sit EARLIER in the disclosure
 * pipeline than the kev / epss / nvd / ghsa / osv sources, which see only its
 * last step and lag by 3-14 days. Report-only: applyDiff never writes.
 *
 * Cache mode (--from-cache <dir>) reads <dir>/advisories/<feed>.<ext> via
 * `ctx.cacheDir`; fixture mode reads `ctx.fixtures.advisories[<feed>]`.
 */

const path = require('path');
const fs = require('fs');
const { withRetry } = require('../vendor/blamejs/retry.js');

const TODAY = new Date().toISOString().slice(0, 10);

// Feed registry; `kind` selects the parser checkFeed() applies.
const FEEDS = [
  {
    name: 'qualys',
    url: 'https://blog.qualys.com/category/vulnerability-research/feed',
    kind: 'rss',
    description: 'Qualys Threat Research Unit blog — originator of high-impact disclosures (ssh-keysign-pwn class)',
  },
  {
    name: 'rhsa',
    url: 'https://access.redhat.com/security/data/csaf/v2/advisories/2026/index.txt',
    kind: 'csaf-index',
    description: 'Red Hat CSAF v2 advisory index — RHEL security advisories with NVD-class enrichment at T+1',
  },
  {
    name: 'usn',
    url: 'https://ubuntu.com/security/notices/rss.xml',
    kind: 'rss',
    description: 'Ubuntu USN RSS — Ubuntu security notices, typically published 1-2 days post-disclosure',
  },
  {
    name: 'zdi',
    url: 'https://www.zerodayinitiative.com/rss/published/',
    kind: 'rss',
    description: 'Zero Day Initiative — vendor-acknowledged advisories from ZDI + Pwn2Own pipeline',
  },
  {
    name: 'kernel-org',
    url: 'https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/atom?h=master',
    kind: 'rss',
    description: 'kernel.org torvalds/linux master commits — first-hop after a kernel CVE fix lands upstream (where ssh-keysign-pwn appeared at T+0 as commit 31e62c2ebbfd before any advisory)',
  },
  {
    name: 'oss-security',
    url: 'https://www.openwall.com/lists/oss-security/feeds/atom.xml',
    kind: 'rss',
    description: 'oss-security mailing list — coordinated disclosure venue; many distros announce CVEs here before NVD',
  },
  {
    name: 'jfrog',
    url: 'https://jfrog.com/blog/category/security-research/feed/',
    kind: 'rss',
    description: 'JFrog SecOps research blog — npm/PyPI/Maven supply-chain disclosures with CVE assignments (TanStack / Mini Shai-Hulud class)',
  },
  {
    name: 'cisa-current',
    url: 'https://www.cisa.gov/cybersecurity-advisories/all.xml',
    kind: 'rss',
    description: 'CISA cybersecurity advisories feed — federal-vendor coordinated disclosures (separate from KEV which captures only exploited-in-the-wild items)',
  },
  {
    name: 'microsoft-security-blog',
    url: 'https://www.microsoft.com/en-us/security/blog/feed/',
    kind: 'rss',
    description: 'Microsoft Security Blog — covers Linux-kernel CVE intel (Dirty Frag analysis 2026-05-08, Windows + cross-platform research). Vendor publishes ahead of standard advisory feeds for class-of-bug regressions.',
  },
  {
    name: 'sysdig-blog',
    url: 'https://www.sysdig.com/blog/feed/',
    kind: 'rss',
    description: 'Sysdig research blog — kernel-LPE detection writeups (Copy Fail, Dirty Frag CVE-2026-43284 / 43500). Names CVE IDs in titles, often before NVD enrichment completes.',
  },
  {
    name: 'trail-of-bits-blog',
    url: 'https://blog.trailofbits.com/feed/',
    kind: 'rss',
    description: 'Trail of Bits research blog — MCP / supply-chain / AI-tool security disclosures with CVE assignments. Anchored CVE-2026-30615 (Windsurf MCP) and the MCP tool-poisoning class.',
  },
  {
    name: 'embrace-the-red',
    url: 'https://embracethered.com/blog/index.xml',
    kind: 'rss',
    description: 'Embrace the Red (Johann Rehberger) — AI-tool prompt-injection + agentic-AI research. Anchored CVE-2025-53773 (Copilot YOLO mode) and the agentic-IDE host-execution class.',
  },
  {
    name: 'bleepingcomputer-security',
    url: 'https://www.bleepingcomputer.com/feed/',
    kind: 'rss',
    description: 'BleepingComputer security feed — canonical tech-press venue for "researcher dropped PoC on GitHub, no advisory yet" events (BlueHammer / RedSun / UnDefend / MiniPlasma / YellowKey / GreenPlasma anchor cluster). CVE-ID-bearing items extracted via the standard CVE_RE; non-CVE researcher drops surface as named-handle items consumed by NEW-CTRL-073 handle tracker. v0.13.17.',
  },
  {
    name: 'thehackernews',
    url: 'https://feeds.feedburner.com/TheHackersNews',
    kind: 'rss',
    description: 'The Hacker News RSS — canonical tech-press venue for PoC drops + zero-day weaponization writeups. Anchored MiniPlasma 2026-05-14 writeup which the 12-feed set missed. CVE-ID extraction same as bleepingcomputer-security. v0.13.17.',
  },
  {
    name: 'nightmare-eclipse-gitlab',
    url: 'https://gitlab.com/Nightmare-Eclipse.atom',
    kind: 'gitlab-activity',
    researcher_handle: 'Nightmare-Eclipse',
    description: 'GitLab public-activity Atom feed for the Nightmare-Eclipse / Chaotic Eclipse researcher handle, migrated from GitHub after the account was removed. Anchored the BlueHammer (CVE-2026-33825) + MiniPlasma cluster — the handle is the canonical signal source for unpatched Windows LPE / BitLocker / Defender drops since April 2026. NEW-CTRL-073 handle-tracker class; additional handles registered as their drops land in the catalog.',
  },
];

// Permissive: some feeds emit lowercase "cve-yyyy-nnnn" in URLs and filenames,
// so the match is case-insensitive and extractCveIds() uppercases and dedupes.
const CVE_RE = /CVE-(?:19|20)\d{2}-\d{4,7}/gi;

function extractCveIds(text) {
  if (typeof text !== 'string' || text.length === 0) return [];
  const matches = text.match(CVE_RE);
  if (!matches) return [];
  return [...new Set(matches.map((s) => s.toUpperCase()))];
}

const { parseFeedDetailed: tokenizerParseFeedDetailed } = require('./xml-tokenizer');

// Returns [{ title, link, published, body }, ...]. Passing `errors` copies the
// tokenizer's parse errors out, so an unparsable feed reads 'partial', not '0'.
function parseRssAtom(xml, errors = null) {
  const { items, errors: collected } = tokenizerParseFeedDetailed(xml);
  if (Array.isArray(errors)) {
    for (const e of collected) errors.push(e);
  }
  return items;
}

/**
 * Red Hat ships a plain-text index whose lines are advisory JSON filenames. The
 * per-advisory JSON is never fetched, so only CVE IDs in a filename surface.
 */
function parseCsafIndex(text) {
  if (typeof text !== 'string') return [];
  const lines = text.split(/\r?\n/).filter((l) => l.trim().length > 0);
  return lines.map((line) => {
    const cves = extractCveIds(line);
    return { title: line.trim(), link: '', published: '', body: '', cves_from_filename: cves };
  });
}

/**
 * Researcher-handle tracker (NEW-CTRL-073) over the JSON body of
 * `https://api.github.com/users/<handle>/events/public`. Flattens each
 * PushEvent / ReleaseEvent / CreateEvent / PublicEvent into the standard
 * { title, link, published, body, researcher_handle } shape.
 */
function parseGitHubEvents(body, feed) {
  let arr;
  try {
    arr = JSON.parse(body);
  } catch (e) {
    return [];
  }
  if (!Array.isArray(arr)) return [];
  const handle = (feed.url.match(/users\/([^/]+)\/events/) || [])[1] || null;
  const out = [];
  const wanted = new Set(['PushEvent', 'ReleaseEvent', 'CreateEvent', 'PublicEvent']);
  for (const ev of arr) {
    if (!ev || typeof ev !== 'object') continue;
    if (!wanted.has(ev.type)) continue;
    const repo = (ev.repo && ev.repo.name) || '';
    const payload = ev.payload || {};
    let label = '';
    if (ev.type === 'ReleaseEvent') label = `release ${(payload.release && payload.release.tag_name) || ''} — ${(payload.release && payload.release.name) || ''}`;
    else if (ev.type === 'PushEvent') label = `push ${payload.ref || ''} ${((payload.commits || []).map(c => c.message).join(' || '))}`;
    else if (ev.type === 'CreateEvent') label = `create ${payload.ref_type || ''} ${payload.ref || ''} — ${payload.description || ''}`;
    else if (ev.type === 'PublicEvent') label = 'repository made public';
    const title = `[${ev.type}] ${repo} — ${label}`.slice(0, 240);
    out.push({
      title,
      link: `https://github.com/${repo}`,
      published: ev.created_at || '',
      body: label,
      researcher_handle: handle,
      event_type: ev.type,
      repo_name: repo,
    });
  }
  return out;
}

/**
 * Researcher-handle tracker over a GitLab public-activity Atom feed
 * (https://gitlab.com/<handle>.atom). Entry titles are classified into the same
 * event_type vocabulary parseGitHubEvents emits, so checkFeed's handle-drop diff
 * fires identically for both sources.
 */
function parseGitLabActivity(body, feed, errorsOut = null) {
  const errors = [];
  const entries = parseRssAtom(body, errors);
  // Thread the Atom parse errors back so this feed reads 'partial' like RSS.
  if (Array.isArray(errorsOut)) {
    for (const e of errors) errorsOut.push(e);
  }
  const handle = feed.researcher_handle
    || (feed.url.match(/gitlab\.com\/([^/.]+)\.atom/) || [])[1]
    || null;
  return entries.map((it) => {
    const t = `${it.title || ''}`;
    let event_type = 'ActivityEvent';
    if (/pushed (?:new )?tag|created tag|released/i.test(t)) event_type = 'ReleaseEvent';
    else if (/created (?:repository|project)|imported project/i.test(t)) event_type = 'PublicEvent';
    else if (/pushed (?:new commits|to)/i.test(t)) event_type = 'PushEvent';
    else if (/created branch/i.test(t)) event_type = 'CreateEvent';
    // Activity titles read "<handle> pushed to project <ns>/<repo>"; link is fallback.
    let repo_name = '';
    const titleM = t.match(/project\s+(\S+\/\S+)/i);
    if (titleM) repo_name = titleM[1];
    else {
      const linkM = (it.link || '').match(/gitlab\.com\/([^?#]+?)(?:\/-\/|$)/);
      if (linkM) repo_name = linkM[1];
    }
    return {
      title: it.title || '',
      link: it.link || feed.url,
      published: it.published || '',
      body: it.body || it.title || '',
      researcher_handle: handle,
      event_type,
      repo_name,
    };
  });
}

async function fetchFeed(feed, ctx) {
  if (ctx.fixtures && ctx.fixtures.advisories && ctx.fixtures.advisories[feed.name]) {
    return { ok: true, body: ctx.fixtures.advisories[feed.name] };
  }
  if (ctx.cacheDir) {
    const ext = feed.kind === 'csaf-index' ? '.txt' : feed.kind === 'github-events' ? '.json' : '.xml';
    const p = path.join(ctx.cacheDir, 'advisories', `${feed.name}${ext}`);
    if (!fs.existsSync(p)) return { ok: false, error: `cache miss: ${p}` };
    return { ok: true, body: fs.readFileSync(p, 'utf8') };
  }
  if (typeof fetch !== 'function') return { ok: false, error: 'fetch() not available — Node 18+ required' };
  // A transient failure (429/5xx, timeout/abort, network reset) is retried with
  // backoff + jitter; a permanent 4xx is not. Each attempt gets its own timer.
  const attempt = async () => {
    const ac = new AbortController();
    const timer = setTimeout(() => ac.abort(), 8000);
    try {
      const r = await fetch(feed.url, { signal: ac.signal, headers: { 'User-Agent': 'exceptd-advisories-poller/0.13.1 (+https://exceptd.com)' } });
      if (!r.ok) { const e = new Error(`HTTP ${r.status}`); e.statusCode = r.status; throw e; }
      return await r.text();
    } finally {
      clearTimeout(timer);
    }
  };
  const retryable = (err) => {
    if (err && typeof err.statusCode === 'number') return err.statusCode === 429 || err.statusCode >= 500;
    if (err && (err.name === 'AbortError' || err.name === 'TimeoutError')) return true;
    const code = err && (err.code || (err.cause && err.cause.code));
    return !!code && /^(ECONNRESET|ECONNREFUSED|ECONNABORTED|ETIMEDOUT|EPIPE|EAGAIN|ENOTFOUND|ENETUNREACH|UND_ERR)/.test(String(code));
  };
  try {
    const body = await withRetry(attempt, { maxAttempts: 3, baseDelayMs: 100, maxDelayMs: 2000, jitterFactor: 0.5, isRetryable: retryable });
    return { ok: true, body };
  } catch (e) {
    return { ok: false, error: e.message || String(e) };
  }
}

/**
 * Walk one feed: fetch, parse, extract CVE IDs, compare to the local catalog.
 * Returns { diffs, observations, errors, status, parse_errors }.
 */
async function checkFeed(feed, ctx) {
  const res = await fetchFeed(feed, ctx);
  if (!res.ok) return { diffs: [], errors: 1, status: 'unreachable', _why: res.error };
  let items;
  // Collected on the XML feed kinds so an unparsable feed reads 'partial'.
  const parseErrors = [];
  if (feed.kind === 'csaf-index') {
    items = parseCsafIndex(res.body);
    items = items.map((it) => ({ ...it, cve_ids: it.cves_from_filename || [] }));
  } else if (feed.kind === 'github-events') {
    items = parseGitHubEvents(res.body, feed);
    items = items.map((it) => ({ ...it, cve_ids: extractCveIds(`${it.title} ${it.body} ${it.link}`) }));
  } else if (feed.kind === 'gitlab-activity') {
    items = parseGitLabActivity(res.body, feed, parseErrors);
    items = items.map((it) => ({ ...it, cve_ids: extractCveIds(`${it.title} ${it.body} ${it.link}`) }));
  } else {
    items = parseRssAtom(res.body, parseErrors);
    items = items.map((it) => ({ ...it, cve_ids: extractCveIds(`${it.title} ${it.body} ${it.link}`) }));
  }
  const diffs = [];
  // observations carries EVERY extracted CVE ID, in-catalog included, for the
  // regression watcher (lib/cve-regression-watcher.js), whose "annotate" verdict
  // fires on a catalog key. diffs[] stays filtered to not-in-catalog.
  const observations = [];
  for (const it of items) {
    for (const cveId of it.cve_ids) {
      const inCatalog = !!ctx.cveCatalog[cveId];
      const baseRecord = {
        id: cveId,
        source: feed.name,
        advisory_url: it.link || feed.url,
        disclosed_at: it.published || null,
        title: it.title.slice(0, 200),
        in_catalog: inCatalog,
      };
      observations.push(baseRecord);
      if (!inCatalog) {
        diffs.push({ ...baseRecord });
      }
    }
    // Handle-drop diff: a researcher publishes an alias name before the advisory
    // and CVE assignment, so the drop surfaces with handle + event_type.
    if ((feed.kind === 'github-events' || feed.kind === 'gitlab-activity') && it.cve_ids.length === 0 && (it.event_type === 'ReleaseEvent' || it.event_type === 'PublicEvent')) {
      diffs.push({
        id: `HANDLE:${it.researcher_handle || feed.name}:${it.repo_name || 'unknown'}@${(it.published || '').slice(0, 10)}`,
        source: feed.name,
        advisory_url: it.link || feed.url,
        disclosed_at: it.published || null,
        title: it.title.slice(0, 200),
        in_catalog: false,
        researcher_handle: it.researcher_handle || null,
        repo_name: it.repo_name || null,
        event_type: it.event_type,
        triage_class: 'researcher-handle-drop',
      });
    }
  }
  // `errors` stays the UNREACHABLE count (0 here — the feed WAS reached), so the
  // aggregate math keeps working. A parse failure travels on parse_errors.
  return {
    diffs,
    observations,
    errors: 0,
    status: parseErrors.length ? 'partial' : 'ok',
    parse_errors: parseErrors.length,
    _parse_errors: parseErrors.slice(0, 5),
  };
}

/** The exported SOURCE definition, in the shape ALL_SOURCES expects. */
const ADVISORIES_SOURCE = {
  name: 'advisories',
  description: 'Primary-source advisory feeds (Qualys TRU, Red Hat RHSA, Ubuntu USN, Zero Day Initiative / ZDI) — surfaces CVE IDs disclosed at T+0 to T+1 that lag NVD enrichment. Report-only — does not auto-write the catalog.',
  applies_to: 'data/cve-catalog.json',
  // Callers read this flag, not the no-op applyDiff: refresh-external counts a
  // source toward the upsert total only when `!report_only`, and the refresh
  // workflow gates its apply step and open-pr job on that total. This feed never
  // reports zero, so clearing the flag opens a PR unconditionally, forever.
  report_only: true,
  async fetchDiff(ctx) {
    const results = await Promise.all(FEEDS.map((feed) => checkFeed(feed, ctx)));
    const allDiffs = [];
    const allObservations = [];
    let unreachable = 0;
    let parseErrorFeeds = 0;       // feeds reachable but with >=1 parse error
    const parseErrorSamples = [];  // bounded sample of {message, position}
    for (const r of results) {
      allDiffs.push(...r.diffs);
      if (Array.isArray(r.observations)) allObservations.push(...r.observations);
      if (r.status === 'unreachable') unreachable++;
      if (typeof r.parse_errors === 'number' && r.parse_errors > 0) {
        parseErrorFeeds++;
        if (Array.isArray(r._parse_errors)) {
          for (const e of r._parse_errors) {
            if (parseErrorSamples.length < 5) parseErrorSamples.push(e);
          }
        }
      }
    }
    // Collapse per CVE across feeds; sources[] lists every contributing feed.
    const byCve = new Map();
    for (const d of allDiffs) {
      if (!byCve.has(d.id)) {
        byCve.set(d.id, { ...d, sources: [d.source], advisory_urls: [d.advisory_url] });
      } else {
        const existing = byCve.get(d.id);
        if (!existing.sources.includes(d.source)) existing.sources.push(d.source);
        if (!existing.advisory_urls.includes(d.advisory_url)) existing.advisory_urls.push(d.advisory_url);
      }
    }
    const diffs = Array.from(byCve.values()).map((d) => {
      delete d.source;
      delete d.advisory_url;
      return d;
    });
    // Deduped like diffs[], but keeping in-catalog IDs for the annotate path.
    const obsByCve = new Map();
    for (const o of allObservations) {
      // HANDLE:* ids are handle drops, not CVE observations.
      if (!/^CVE-/.test(o.id)) continue;
      if (!obsByCve.has(o.id)) {
        obsByCve.set(o.id, {
          id: o.id,
          sources: [o.source],
          advisory_urls: [o.advisory_url],
          first_title: o.title,
          in_catalog: o.in_catalog,
        });
      } else {
        const existing = obsByCve.get(o.id);
        if (!existing.sources.includes(o.source)) existing.sources.push(o.source);
        if (!existing.advisory_urls.includes(o.advisory_url)) existing.advisory_urls.push(o.advisory_url);
      }
    }
    const observations = Array.from(obsByCve.values());
    // Reachable-but-unparsable folds into 'partial'; `errors` stays unreachable-only.
    const status =
      unreachable === FEEDS.length ? 'unreachable' :
      (unreachable > 0 || parseErrorFeeds > 0) ? 'partial' :
      'ok';
    const summary = `${FEEDS.length - unreachable}/${FEEDS.length} feeds reachable; ${diffs.length} new CVE references found, ${observations.length} total CVE observations across primary advisory sources`
      + (parseErrorFeeds > 0 ? `; ${parseErrorFeeds} feed${parseErrorFeeds === 1 ? '' : 's'} returned parse errors` : '');
    return {
      status,
      diffs,
      observations,
      errors: unreachable,
      parse_errors: parseErrorFeeds,
      _parse_errors: parseErrorSamples,
      summary,
    };
  },
  applyDiff(_ctx, _diffs) {
    return {
      updated: 0,
      added: 0,
      drift_updated: 0,
      errors: [],
      note: 'ADVISORIES_SOURCE is report-only. Route promising IDs through `exceptd refresh --advisory <CVE-ID>` to auto-import a draft via the GHSA / OSV / NVD enrichment pipeline.',
    };
  },
};

module.exports = {
  ADVISORIES_SOURCE,
  // Exposed for tests + future schedule-agent reuse:
  FEEDS,
  extractCveIds,
  parseRssAtom,
  parseGitLabActivity,
  parseCsafIndex,
  parseGitHubEvents,
};
