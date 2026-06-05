'use strict';

/**
 * lib/source-advisories.js — primary-source advisory-feed polling.
 *
 * Why this exists. The post-mortem on CVE-2026-46333 (ssh-keysign-pwn,
 * disclosed 2026-05-14, missed by the toolkit at T+0 through T+3) found
 * that the existing source set (kev, epss, nvd, rfc, pins, ghsa, osv)
 * sits at the END of the disclosure pipeline. Qualys → kernel.org commit
 * → distro advisory → NVD enrichment is sequential; the existing pollers
 * only see the last step, which lags by 3-14 days.
 *
 * The 4 feeds below sit much earlier in the pipeline:
 *
 *   Qualys TRU RSS    — Qualys-disclosed CVEs at T+0 (the originator of
 *                       the ssh-keysign-pwn class of disclosure)
 *   Red Hat RHSA RSS  — RHEL security advisories at T+1, often before NVD
 *   Ubuntu USN RSS    — Ubuntu security notices at T+1, often before NVD
 *   ZDI advisories    — Zero Day Initiative + Pwn2Own disclosures at T+0
 *
 * Behaviour. Each call returns a structured REPORT — not a catalog mutation.
 * Operators consume the report via `exceptd refresh --check-advisories` and
 * decide which advisories warrant a `refresh --advisory <CVE-ID>` auto-import
 * to seed a draft entry. The report is informational; nothing is auto-written
 * to the catalog. This is the conservative-by-default contract: primary-source
 * surfacing must not silently mutate the catalog without operator triage.
 *
 * Output shape:
 *   {
 *     status: 'ok' | 'partial' | 'unreachable',
 *     diffs: [
 *       { id: 'CVE-2026-46333', source: 'qualys', advisory_url: '...',
 *         disclosed_at: '2026-05-14', title: '...', in_catalog: false }
 *     ],
 *     summary: '4/4 feeds reachable; 3 new CVE references found'
 *   }
 *
 * Each diff is read-only — there is no `applyDiff` that writes the catalog.
 * That's by design: a fresh advisory from a primary source has insufficient
 * fields to satisfy Hard Rule #1 (CVSS / KEV / PoC / AI-discovery /
 * active-exploitation / patch-availability). The operator routes the
 * promising ones through `refresh --advisory <CVE-ID>` which goes through
 * the existing GHSA / OSV / NVD enrichment path (those pollers are mature).
 *
 * Cache mode (--from-cache <dir>): expected cache layout is
 *   <dir>/advisories/<feed>.xml — caller passes `ctx.cacheDir`.
 * Fixture mode: `ctx.fixtures.advisories = { qualys: '<xml>', ... }`.
 */

const path = require('path');
const fs = require('fs');

const TODAY = new Date().toISOString().slice(0, 10);

// Feed registry. Each entry has a kind (rss | json), a URL, and a parser.
// Parsers return [{ cve_ids: [...], title, link, published }, ...].
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
  // v0.13.3 additions — extend coverage to 4 more primary-source venues
  // identified in the v0.13.1 post-mortem follow-up:
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
  // v0.13.14 additions — closes the "silent kernel patch + delayed-research-
  // disclosure" intake gap surfaced by DirtyDecrypt (CVE-2026-31635). That
  // CVE was patched in mainline 2026-04-25, the kernel.org Atom-feed rolling
  // window rotated past the fix commit before the daily intake noticed, the
  // V12 rediscovery on 2026-05-09 went to maintainers privately rather than
  // to oss-security@openwall, and the PoC publication on 2026-05-17 surfaced
  // on vendor security blogs (Microsoft / Sysdig / Trail of Bits) that the
  // 8-feed primary-source set did not cover. Vendor security blogs are the
  // canonical signal channel for "kernel-class CVE patched silently, then
  // class-of-bug research published weeks later" — adding them closes the
  // class without polluting the catalog with news-aggregator noise.
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
  // v0.13.17 additions — closes the "researcher GitHub-release drop +
  // tech-press writeup" intake gap surfaced by the four Nightmare-Eclipse
  // catalog entries (MiniPlasma / YellowKey / GreenPlasma / UnDefend).
  // The 12-feed set polled advisory venues + vendor research blogs but
  // had no coverage for either (a) named researcher handles whose prior
  // drops are already in the catalog (BlueHammer / CVE-2026-33825 was in,
  // four sibling drops were not) nor (b) the canonical tech-press
  // venues that surface "researcher dropped PoC on GitHub, no advisory
  // yet" events. The bleepingcomputer-security + thehackernews feeds
  // close (b); the nightmare-eclipse-github feed closes (a) as the
  // anchor handle for the v0.13.17 backfill. NEW-CTRL-073 generalises
  // the handle-tracker control — additional handles get registered as
  // their drops land in the catalog. See also NEW-CTRL-074 (CVE-
  // regression-watcher) in lib/cve-regression-watcher.js for the
  // complementary detection method that catches re-broken historical
  // CVEs without depending on a new ID being assigned.
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

// Permissive CVE-ID matcher. The official format is CVE-YYYY-NNNN+ but
// some feeds embed CVEs in arbitrary surrounding markup AND occasionally
// emit lowercase "cve-yyyy-nnnn" in URLs or filenames. Case-insensitive
// match, then uppercase + dedupe in extractCveIds().
const CVE_RE = /CVE-(?:19|20)\d{2}-\d{4,7}/gi;

/**
 * Extract CVE IDs from a string blob. De-duplicates within the blob.
 */
function extractCveIds(text) {
  if (typeof text !== 'string' || text.length === 0) return [];
  const matches = text.match(CVE_RE);
  if (!matches) return [];
  return [...new Set(matches.map((s) => s.toUpperCase()))];
}

/**
 * RSS / Atom parser. v0.13.20 replaces the original regex-based parser
 * (which silently failed on XML namespaces, nested CDATA, self-closing
 * tags, HTML entities, and multi-line content) with a proper streaming
 * XML tokenizer defined in lib/xml-tokenizer.js. Parser errors surface
 * via the second `errors` argument so consumers can observe parse
 * failures instead of receiving a silent empty array.
 *
 * Returns [{ title, link, published, body }, ...].
 */
const { parseFeed: tokenizerParseFeed } = require('./xml-tokenizer');

function parseRssAtom(xml, errors = null) {
  return tokenizerParseFeed(xml, errors);
}

/**
 * CSAF index parser — Red Hat ships a plain-text index of advisory JSON
 * files under data/csaf/v2/advisories/YYYY/index.txt. Each line is a
 * relative filename. We don't fetch the per-advisory JSON in v0.13.1
 * (would blow the polling budget); we surface the advisory IDs that
 * mention CVE-YYYY-NNNN inline.
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
 * GitHub public-events parser — NEW-CTRL-073 researcher-handle tracker.
 *
 * Input is the JSON body of `https://api.github.com/users/<handle>/events/public`
 * (array of event objects). Output flattens each event into a standard
 * { title, link, published, body, researcher_handle } shape that
 * extractCveIds() can scan and the diff-deduplicator can route. Events of
 * interest: PushEvent (release commits), ReleaseEvent (tagged drops),
 * CreateEvent (tag / branch creation often signals an upcoming drop),
 * PublicEvent (a private repo flipped public — frequent drop pattern).
 *
 * The diff carries `researcher_handle` so callers + tests can assert the
 * handle-tracker fired even when no CVE ID is present in the commit text
 * (the MiniPlasma class — drop names a researcher-coined alias rather
 * than a CVE ID until MITRE / vendor assigns).
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
 * GitLab public-activity parser — NEW-CTRL-073 researcher-handle tracker.
 *
 * GitLab publishes a public activity Atom feed at
 * https://gitlab.com/<handle>.atom. Each <entry> describes one activity
 * (pushed a tag, created a project/repository, pushed commits). We parse it
 * with the shared Atom tokenizer and classify the entry title into the same
 * event_type vocabulary the GitHub tracker emits, so the handle-drop diff in
 * checkFeed fires identically across both sources. researcher_handle comes
 * from the feed's explicit field (authoritative; the .atom URL also carries
 * the handle as a fallback). This is the migration target after the handle's
 * GitHub account was removed — the .atom feed needs no API token and the
 * existing parseRssAtom tokenizer already handles its XML.
 */
function parseGitLabActivity(body, feed) {
  const errors = [];
  const entries = parseRssAtom(body, errors);
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
    // Project path: GitLab activity titles read "<handle> pushed to project
    // <ns>/<repo>"; the entry link path is the secondary source.
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

/**
 * Fetch a feed body. In fixture / cache modes, read from disk.
 */
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
  try {
    const ac = new AbortController();
    const timer = setTimeout(() => ac.abort(), 8000);
    const r = await fetch(feed.url, { signal: ac.signal, headers: { 'User-Agent': 'exceptd-advisories-poller/0.13.1 (+https://exceptd.com)' } });
    clearTimeout(timer);
    if (!r.ok) return { ok: false, error: `HTTP ${r.status}` };
    return { ok: true, body: await r.text() };
  } catch (e) {
    return { ok: false, error: e.message || String(e) };
  }
}

/**
 * Walk one feed: fetch, parse, extract CVE IDs, compare to local catalog.
 * Returns { diffs, errors, status }.
 */
async function checkFeed(feed, ctx) {
  const res = await fetchFeed(feed, ctx);
  if (!res.ok) return { diffs: [], errors: 1, status: 'unreachable', _why: res.error };
  let items;
  if (feed.kind === 'csaf-index') {
    items = parseCsafIndex(res.body);
    // Flatten cves_from_filename onto cve_ids field uniformly.
    items = items.map((it) => ({ ...it, cve_ids: it.cves_from_filename || [] }));
  } else if (feed.kind === 'github-events') {
    items = parseGitHubEvents(res.body, feed);
    items = items.map((it) => ({ ...it, cve_ids: extractCveIds(`${it.title} ${it.body} ${it.link}`) }));
  } else if (feed.kind === 'gitlab-activity') {
    items = parseGitLabActivity(res.body, feed);
    items = items.map((it) => ({ ...it, cve_ids: extractCveIds(`${it.title} ${it.body} ${it.link}`) }));
  } else {
    items = parseRssAtom(res.body);
    items = items.map((it) => ({ ...it, cve_ids: extractCveIds(`${it.title} ${it.body} ${it.link}`) }));
  }
  const diffs = [];
  // v0.13.17: surface EVERY extracted CVE-ID — including IDs already in
  // catalog — for NEW-CTRL-074 (cve-regression-watcher) consumption. The
  // diffs[] array remains filtered to NOT-IN-CATALOG so existing callers
  // see no behavior change, but a parallel observations[] carries the
  // full set with the in_catalog flag preserved. The regression watcher
  // routes historical-CVE references (e.g. CVE-2020-17103) through this
  // path so its action: "annotate" verdict can fire even when the
  // historical entry IS a catalog key.
  const observations = [];
  for (const it of items) {
    // Standard CVE-ID-bearing diff (every feed kind).
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
    // NEW-CTRL-073 — researcher-handle diff. Github-events surfaces drop
    // activity even when no CVE ID is present yet (the MiniPlasma class:
    // researcher publishes alias name, vendor advisory + CVE assignment
    // arrive days / weeks later). The diff carries handle + event_type
    // so downstream triage can prioritise without waiting for an ID.
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
  return { diffs, observations, errors: 0, status: 'ok' };
}

/**
 * The exported SOURCE definition, matching the shape ALL_SOURCES expects.
 */
const ADVISORIES_SOURCE = {
  name: 'advisories',
  description: 'Primary-source advisory feeds (Qualys TRU, Red Hat RHSA, Ubuntu USN, Zero Day Initiative / ZDI) — surfaces CVE IDs disclosed at T+0 to T+1 that lag NVD enrichment. Report-only — does not auto-write the catalog.',
  applies_to: 'data/cve-catalog.json',
  async fetchDiff(ctx) {
    const results = await Promise.all(FEEDS.map((feed) => checkFeed(feed, ctx)));
    const allDiffs = [];
    const allObservations = [];
    let unreachable = 0;
    for (const r of results) {
      allDiffs.push(...r.diffs);
      if (Array.isArray(r.observations)) allObservations.push(...r.observations);
      if (r.status === 'unreachable') unreachable++;
    }
    // Deduplicate by CVE-ID across feeds — multiple advisories for the
    // same CVE collapse to one entry with sources[] array of contributing
    // feed names.
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
    // v0.13.17: observations are the FULL per-feed extraction list,
    // including in-catalog CVE-IDs. NEW-CTRL-074 cve-regression-watcher
    // consumes this so an "annotate" verdict can fire on historical IDs
    // (CVE-2020-17103) that are already keys in the catalog — diffs[]
    // alone would have filtered them out and broken the watcher's
    // annotate path. Dedupe + sources[] follow the diffs[] pattern so
    // downstream consumers see one record per CVE with all observing
    // feed names listed.
    const obsByCve = new Map();
    for (const o of allObservations) {
      // The github-events handle-drop diffs use a HANDLE:* id shape and
      // are not CVE observations — skip them.
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
    const status =
      unreachable === 0 ? 'ok' :
      unreachable === FEEDS.length ? 'unreachable' : 'partial';
    return {
      status,
      diffs,
      observations,
      errors: unreachable,
      summary: `${FEEDS.length - unreachable}/${FEEDS.length} feeds reachable; ${diffs.length} new CVE references found, ${observations.length} total CVE observations across primary advisory sources`,
    };
  },
  // Report-only: no applyDiff. Operators route promising CVE IDs through
  // `exceptd refresh --advisory <CVE-ID>` (GHSA / OSV / NVD enrichment).
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
