#!/usr/bin/env node
"use strict";
/**
 * scripts/refresh-upstream-catalogs.js
 *
 * Unified entrypoint + library for refreshing the four canonical upstream
 * catalogs from their official sources. Each refresher is idempotent and
 * never overwrites operator-curated entries (rows that lack the
 * `_auto_imported: true` flag are preserved verbatim).
 *
 *   rfc      ietf-rfc-index            data/rfc-references.json
 *   attack   mitre-attack-stix         data/attack-techniques.json
 *   atlas    mitre-atlas-stix          data/atlas-ttps.json
 *   d3fend   mitre-d3fend-owl          data/d3fend-catalog.json
 *
 * CLI usage:
 *
 *   node scripts/refresh-upstream-catalogs.js                      # all four
 *   node scripts/refresh-upstream-catalogs.js --source rfc         # one
 *   node scripts/refresh-upstream-catalogs.js --source rfc,atlas   # two
 *   node scripts/refresh-upstream-catalogs.js --dry-run            # report only
 *   CAP=200 node scripts/refresh-upstream-catalogs.js --source attack
 *
 * Module usage (per-type wrappers under scripts/refresh-{rfc,attack,atlas,
 * d3fend}.js import the corresponding refreshX function from this file):
 *
 *   const { refreshRfc } = require("./refresh-upstream-catalogs.js");
 *   await refreshRfc({ dry: false });
 *
 * npm aliases (package.json scripts):
 *   refresh-upstream-catalogs  runs all four
 *   refresh-rfc-index          --source rfc
 *   refresh-mitre-attack       --source attack
 *   refresh-mitre-atlas        --source atlas
 *   refresh-mitre-d3fend       --source d3fend
 */

const fs = require("fs");
const https = require("https");
const path = require("path");

const ROOT = path.join(__dirname, "..");
const TODAY = new Date().toISOString().slice(0, 10);

// v0.13.20 class-3.11 fix: refreshers read their required-context list
// from the audit SPEC. Eliminates the parallel hardcoded field arrays
// that v0.13.17→19 carried (and forgot to keep in sync — the v0.13.19
// audit found 106 ATT&CK rows missing `description` + `tactic` because
// the v0.13.18 backfill list omitted those fields). One source of truth
// = the audit-catalog-gaps SPEC.
const AUDIT_SPEC = require("./audit-catalog-gaps.js").SPEC;
function specRequiredFields(catalogKey) {
  const spec = AUDIT_SPEC[catalogKey];
  if (!spec || !Array.isArray(spec.required_context)) return [];
  return spec.required_context.map((r) => r.field);
}

const MAX_REDIRECTS = 5;

// Hardened fetch helper. Three properties the hand-rolled follower lacked:
//   1. Redirect-depth cap + base-URL resolution + response drain, so a
//      redirect loop rejects within the cap (rather than recursing/hanging
//      unbounded) and a relative Location resolves against the current URL.
//   2. 4xx/5xx (and a missing statusCode edge) reject instead of resolving an
//      error body as a "successful" empty result — every consumer fails
//      closed on an HTTP error rather than stamping _meta on a non-fetch.
//   3. A 3xx with no Location header rejects with a clear message rather than
//      throwing an opaque ERR_INVALID_URL on `new URL(undefined, url)`.
function fetchUrl(url, depth = 0) {
  return new Promise((resolve, reject) => {
    https.get(url, { headers: { "User-Agent": "exceptd-refresh-upstream-catalogs" } }, (r) => {
      const code = r.statusCode;
      if (code == null) {
        r.resume();
        return reject(new Error(`no HTTP status code for ${url}`));
      }
      if (code >= 300 && code < 400) {
        r.resume(); // drain the redirect response so the socket is freed/reused
        const loc = r.headers.location;
        if (!loc) return reject(new Error(`redirect ${code} from ${url} with no Location header`));
        if (depth >= MAX_REDIRECTS) return reject(new Error(`too many redirects (>${MAX_REDIRECTS}) fetching ${url}`));
        let next;
        try { next = new URL(loc, url).toString(); } // resolves relative AND absolute Location
        catch (e) { return reject(new Error(`invalid redirect target "${loc}" from ${url}: ${e.message}`)); }
        return fetchUrl(next, depth + 1).then(resolve, reject);
      }
      if (code >= 400) {
        r.resume(); // drain so the socket is freed
        return reject(new Error("HTTP " + code + " for " + url));
      }
      let b = "";
      r.on("data", (c) => (b += c));
      r.on("end", () => resolve(b));
    }).on("error", reject);
  });
}

function loadCatalog(rel) {
  return JSON.parse(fs.readFileSync(path.join(ROOT, "data", rel), "utf8"));
}

// Atomic write: a crash / disk-full / SIGKILL mid-write would otherwise leave a
// truncated JSON catalog on disk. Write to a temp sibling and rename — rename is
// atomic on POSIX and on same-volume Windows renames (the .tmp sibling is
// adjacent to the target, same volume), so a reader / the next run only ever
// sees the complete old or complete new file. Mirrors build-indexes#writeJson.
function writeCatalog(rel, obj) {
  const abs = path.join(ROOT, "data", rel);
  const tmp = `${abs}.tmp-${process.pid}`;
  fs.writeFileSync(tmp, JSON.stringify(obj, null, 2) + "\n");
  fs.renameSync(tmp, abs);
}

function getTag(blk, tag) {
  const re = new RegExp(`<${tag}>([\\s\\S]*?)<\\/${tag}>`);
  const m = blk.match(re);
  return m ? m[1].trim() : null;
}

// ---------------- RFC ----------------

const RFC_SRC = "https://www.rfc-editor.org/rfc-index.xml";
const RFC_STATUS_MAP = {
  "INTERNET STANDARD": "Internet Standard",
  "PROPOSED STANDARD": "Proposed Standard",
  "DRAFT STANDARD": "Draft Standard",
  "BEST CURRENT PRACTICE": "Best Current Practice",
  "INFORMATIONAL": "Informational",
  "EXPERIMENTAL": "Experimental",
  "HISTORIC": "Historic",
  "UNKNOWN": "Unknown"
};
const RFC_MONTHS = {
  January: "01", February: "02", March: "03", April: "04",
  May: "05", June: "06", July: "07", August: "08",
  September: "09", October: "10", November: "11", December: "12"
};

// Extract every doc-id reference inside a parent tag like
// <obsoleted-by><doc-id>RFC123</doc-id><doc-id>RFC456</doc-id></obsoleted-by>.
function getDocIdList(blk, parentTag) {
  const re = new RegExp(`<${parentTag}>([\\s\\S]*?)<\\/${parentTag}>`);
  const m = blk.match(re);
  if (!m) return [];
  const inner = m[1];
  const ids = [];
  const idRe = /<doc-id>([^<]+)<\/doc-id>/g;
  let im;
  while ((im = idRe.exec(inner)) !== null) {
    ids.push(im[1].trim());
  }
  return ids;
}

// <abstract><p>line1</p><p>line2</p></abstract> → joined plain text.
function getAbstract(blk) {
  const m = blk.match(/<abstract>([\s\S]*?)<\/abstract>/);
  if (!m) return null;
  const inner = m[1];
  const paras = [];
  const pRe = /<p>([\s\S]*?)<\/p>/g;
  let pm;
  while ((pm = pRe.exec(inner)) !== null) {
    paras.push(pm[1].replace(/\s+/g, " ").trim());
  }
  return paras.length ? paras.join(" ") : null;
}

// <keywords><kw>k1</kw><kw>k2</kw></keywords>
function getKeywords(blk) {
  const m = blk.match(/<keywords>([\s\S]*?)<\/keywords>/);
  if (!m) return [];
  const out = [];
  const kRe = /<kw>([^<]+)<\/kw>/g;
  let km;
  while ((km = kRe.exec(m[1])) !== null) {
    out.push(km[1].trim());
  }
  return out;
}

// <author><name>X</name><title>Editor</title><organization>Y</organization></author>
function getAuthors(blk) {
  const out = [];
  const aRe = /<author>([\s\S]*?)<\/author>/g;
  let am;
  while ((am = aRe.exec(blk)) !== null) {
    const inner = am[1];
    const name = getTag(inner, "name");
    const titleField = getTag(inner, "title");
    const org = getTag(inner, "organization");
    if (name) {
      const role = titleField && titleField.toLowerCase() === "editor" ? " (Editor)" : "";
      const aff = org ? `, ${org}` : "";
      out.push(`${name}${role}${aff}`);
    }
  }
  return out;
}

function parseRfcEntry(blk) {
  const docId = getTag(blk, "doc-id");
  if (!docId || !docId.startsWith("RFC")) return null;
  const num = Number(docId.replace(/^RFC0*/, ""));
  if (!Number.isFinite(num)) return null;
  const title = (getTag(blk, "title") || "").replace(/\s+/g, " ").trim();
  const status = (getTag(blk, "current-status") || "UNKNOWN").trim().toUpperCase();
  const dateBlk = (blk.match(/<date>([\s\S]*?)<\/date>/) || [, ""])[1];
  const month = RFC_MONTHS[(getTag(dateBlk, "month") || "").trim()] || null;
  const year = (getTag(dateBlk, "year") || "").trim() || null;
  const published = year && month ? `${year}-${month}` : (year || "unknown");
  const hasErrata = /<errata-url>/.test(blk);
  const obsoleted = /<obsoleted-by>/.test(blk);
  // New context-search fields (v0.13.18+): the AI needs more than the
  // title to locate an RFC by topic. abstract + keywords + area +
  // wg_acronym + stream + authors + obsoletes/updates relationships are
  // all present in the IETF index — we were only extracting title before.
  const abstract = getAbstract(blk);
  const keywords = getKeywords(blk);
  const area = getTag(blk, "area");
  const wg = getTag(blk, "wg_acronym");
  const stream = getTag(blk, "stream");
  const authors = getAuthors(blk);
  const doi = getTag(blk, "doi");
  const pageCount = Number(getTag(blk, "page-count")) || null;
  const obsoletes = getDocIdList(blk, "obsoletes");
  const updates = getDocIdList(blk, "updates");
  const updatedBy = getDocIdList(blk, "updated-by");
  const obsoletedBy = getDocIdList(blk, "obsoleted-by");
  const isAlso = getDocIdList(blk, "is-also");
  return {
    num, title, status, published, hasErrata, obsoleted,
    abstract, keywords, area, wg, stream, authors, doi, pageCount,
    obsoletes, updates, updatedBy, obsoletedBy, isAlso
  };
}

async function refreshRfc({ dry = false, _deps = {} } = {}) {
  const _fetchUrl = _deps.fetchUrl || fetchUrl;
  const _loadCatalog = _deps.loadCatalog || loadCatalog;
  const _writeCatalog = _deps.writeCatalog || writeCatalog;
  console.log("[refresh-upstream:rfc] fetching IETF RFC index...");
  const body = await _fetchUrl(RFC_SRC);
  console.log(`[refresh-upstream:rfc] index size: ${(body.length / 1e6).toFixed(2)} MB`);
  const re = /<rfc-entry>([\s\S]*?)<\/rfc-entry>/g;
  const entries = [];           // current — eligible for new-add
  const backfillable = [];      // any-status — eligible for backfill on existing rows
  let m;
  while ((m = re.exec(body)) !== null) {
    const e = parseRfcEntry(m[1]);
    if (!e) continue;
    backfillable.push(e);
    if (e.obsoleted || e.status === "HISTORIC" || e.status === "UNKNOWN") continue;
    entries.push(e);
  }
  // Sanity floor: the IETF index has ~9000+ RFCs, so a successful fetch can
  // never parse to zero entries. A zero count means the fetch returned an
  // error/empty/soft-error body (a 200 with a CDN error page, a captive portal,
  // or a truncated body the HTTP-status guard can't see) — refuse to stamp
  // _meta or write rfc-references.json, matching the JSON-parse failures the
  // STIX sources surface for free (an empty index is never a legitimate result).
  if (backfillable.length === 0) {
    throw new Error("RFC index parsed 0 entries (fetch likely returned an error/empty body) — refusing to stamp _meta or write rfc-references.json");
  }
  console.log(`[refresh-upstream:rfc] current entries: ${entries.length} (+ ${backfillable.length - entries.length} obsoleted/historic available for backfill on existing rows)`);
  const cat = _loadCatalog("rfc-references.json");
  const existing = new Set(Object.keys(cat).filter((k) => k !== "_meta"));
  let added = 0, statusBumped = 0, backfilledCount = 0;
  // First pass: backfill ALL existing rows from the broader entry set
  // (including obsoleted historics). Operator may have curated an
  // obsoleted RFC in for documentation; we still want abstract/authors.
  for (const e of backfillable) {
    const id = `RFC-${e.num}`;
    if (!existing.has(id)) continue;
    const cur = cat[id];
    if (!cur) continue;
    let touched = false;
    if (cur._auto_imported && cur.status !== RFC_STATUS_MAP[e.status]) {
      cur.status = RFC_STATUS_MAP[e.status];
      touched = true;
      statusBumped++;
    }
    if (!cur.abstract && e.abstract) { cur.abstract = e.abstract; touched = true; }
    if ((!cur.keywords || cur.keywords.length === 0) && e.keywords.length) { cur.keywords = e.keywords; touched = true; }
    if (!cur.area && e.area) { cur.area = e.area; touched = true; }
    if (!cur.working_group && e.wg) { cur.working_group = e.wg; touched = true; }
    if (!cur.stream && e.stream) { cur.stream = e.stream; touched = true; }
    if ((!cur.authors || cur.authors.length === 0) && e.authors.length) { cur.authors = e.authors; touched = true; }
    if (!cur.doi && e.doi) { cur.doi = e.doi; touched = true; }
    if (!cur.page_count && e.pageCount) { cur.page_count = e.pageCount; touched = true; }
    if ((!cur.obsoletes || cur.obsoletes.length === 0) && e.obsoletes.length) { cur.obsoletes = e.obsoletes; touched = true; }
    if ((!cur.updates || cur.updates.length === 0) && e.updates.length) { cur.updates = e.updates; touched = true; }
    if ((!cur.updated_by || cur.updated_by.length === 0) && e.updatedBy.length) { cur.updated_by = e.updatedBy; touched = true; }
    if ((!cur.obsoleted_by || cur.obsoleted_by.length === 0) && e.obsoletedBy.length) { cur.obsoleted_by = e.obsoletedBy; touched = true; }
    if ((!cur.is_also || cur.is_also.length === 0) && e.isAlso.length) { cur.is_also = e.isAlso; touched = true; }
    if (!cur.txt_url) { cur.txt_url = `https://www.rfc-editor.org/rfc/rfc${e.num}.txt`; touched = true; }
    if (!cur.html_url) { cur.html_url = `https://www.rfc-editor.org/rfc/rfc${e.num}.html`; touched = true; }
    if (touched) { cur.last_verified = TODAY; backfilledCount++; }
  }
  // Second pass: add new "current" entries that weren't in the catalog.
  // Add new rows from the FULL index, not just the current series. Obsoleted
  // and historic RFCs were previously excluded, so "is RFC N still current?"
  // had no offline answer and forced a datatracker lookup. They are added here
  // marked `_obsoleted` (with obsoleted_by populated) so the resolver can say
  // "Historic, superseded by RFC X" offline. UNKNOWN-status index rows
  // (placeholders / not-issued numbers) are still skipped.
  for (const e of backfillable) {
    const id = `RFC-${e.num}`;
    // Existing rows handled in the first-pass backfill above.
    if (existing.has(id)) continue;
    if (e.status === "UNKNOWN") continue;
    const obsoleted = !!e.obsoleted || e.status === "HISTORIC";
    cat[id] = {
      number: e.num,
      title: e.title,
      status: RFC_STATUS_MAP[e.status] || e.status,
      published: e.published,
      authors: e.authors,
      stream: e.stream || null,
      area: e.area || null,
      working_group: e.wg || null,
      abstract: e.abstract || null,
      keywords: e.keywords,
      page_count: e.pageCount,
      doi: e.doi || null,
      obsoletes: e.obsoletes,
      updates: e.updates,
      updated_by: e.updatedBy,
      obsoleted_by: e.obsoletedBy,
      is_also: e.isAlso,
      errata_count: e.hasErrata ? null : 0,
      tracker: `https://www.rfc-editor.org/info/rfc${e.num}`,
      txt_url: `https://www.rfc-editor.org/rfc/rfc${e.num}.txt`,
      html_url: `https://www.rfc-editor.org/rfc/rfc${e.num}.html`,
      relevance: "Auto-imported from the IETF RFC index. Operator-curated relevance pending — refine when this RFC becomes operationally cited in a skill body or finding.",
      skills_referencing: [],
      last_verified: TODAY,
      _auto_imported: true,
      _intake_method: "ietf-rfc-index",
      ...(obsoleted ? { _obsoleted: true } : {}),
    };
    existing.add(id);
    added++;
  }
  // Only restamp _meta + write when something actually changed. A genuine
  // no-op leaves the file byte-identical so the daily refresh doesn't emit a
  // spurious _meta-only diff (and so the freshness gates stay honest — a
  // wall-clock restamp on an unchanged catalog masks real staleness).
  const changed = added > 0 || backfilledCount > 0 || statusBumped > 0;
  if (dry) {
    console.log(`[refresh-upstream:rfc] DRY-RUN: +${added} new, ${backfilledCount} backfilled, ${statusBumped} status bumps.`);
    return { added, statusBumped, backfilled: backfilledCount };
  }
  if (changed) {
    if (cat._meta) {
      cat._meta.last_updated = TODAY;
      cat._meta.last_threat_review = TODAY;
    }
    _writeCatalog("rfc-references.json", cat);
    console.log(`[ok] rfc-references.json: +${added} entries, ${backfilledCount} backfilled, ${statusBumped} status bumps (now ${existing.size} total)`);
  } else {
    console.log("[ok] rfc-references.json: no upstream changes — file unchanged");
  }
  return { added, statusBumped, backfilled: backfilledCount };
}

// ---------------- ATT&CK ----------------

const ATTACK_SRC = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json";
const ATTACK_TACTIC_NAME = {
  "reconnaissance": "Reconnaissance", "resource-development": "Resource Development",
  "initial-access": "Initial Access", "execution": "Execution",
  "persistence": "Persistence", "privilege-escalation": "Privilege Escalation",
  "defense-evasion": "Defense Evasion", "stealth": "Stealth",
  "defense-impairment": "Defense Impairment", "credential-access": "Credential Access",
  "discovery": "Discovery", "lateral-movement": "Lateral Movement",
  "collection": "Collection", "command-and-control": "Command and Control",
  "exfiltration": "Exfiltration", "impact": "Impact"
};

// Extract the full STIX-bundle context fields the AI needs to find
// techniques by topic (not just by ID). description_full preserves the
// MITRE description; description (short) is the first-sentence
// extractive summary used by token-budgeted consumers.
function attackEntryFromStix(t, extRef) {
  const id = extRef.external_id;
  const tactics = (t.kill_chain_phases || [])
    .filter((p) => p.kill_chain_name === "mitre-attack")
    .map((p) => ATTACK_TACTIC_NAME[p.phase_name] || p.phase_name);
  const fullDesc = String(t.description || "").replace(/\s+/g, " ").trim();
  let shortDesc = fullDesc.split(/\.\s/)[0];
  if (shortDesc.length > 500) shortDesc = shortDesc.slice(0, 497) + "...";
  if (shortDesc && !shortDesc.endsWith(".")) shortDesc += ".";
  return {
    id,
    name: t.name,
    version: "v19",
    tactic: tactics,
    description: shortDesc || `MITRE ATT&CK Enterprise technique ${id}. Reference: ${extRef.url}`,
    description_full: fullDesc || null,
    platforms: Array.isArray(t.x_mitre_platforms) ? t.x_mitre_platforms : [],
    data_sources: Array.isArray(t.x_mitre_data_sources) ? t.x_mitre_data_sources : [],
    permissions_required: Array.isArray(t.x_mitre_permissions_required) ? t.x_mitre_permissions_required : [],
    defense_bypassed: Array.isArray(t.x_mitre_defense_bypassed) ? t.x_mitre_defense_bypassed : [],
    effective_permissions: Array.isArray(t.x_mitre_effective_permissions) ? t.x_mitre_effective_permissions : [],
    detection: (t.x_mitre_detection || "").replace(/\s+/g, " ").trim() || null,
    is_subtechnique: !!t.x_mitre_is_subtechnique,
    mitre_version: t.x_mitre_version || null,
    reference_url: extRef.url || `https://attack.mitre.org/techniques/${id.replace(".", "/")}/`,
    stix_id: t.id || null,
    last_verified: TODAY,
    _auto_imported: true,
    _intake_method: "mitre-attack-stix"
  };
}

function backfillAttack(cur, fresh) {
  let touched = false;
  const fillIfEmpty = (key, val) => {
    if (val == null) return;
    if (Array.isArray(val)) {
      if ((!cur[key] || cur[key].length === 0) && val.length) { cur[key] = val; touched = true; }
    } else {
      if (!cur[key] && val) { cur[key] = val; touched = true; }
    }
  };
  // v0.13.19: include description (short) + tactic in the backfill set.
  // Existing rows from the original 110-entry catalog often have only
  // {name, version} — they need tactic + short-description too, not just
  // the v0.13.18 description_full / platforms / detection additions.
  fillIfEmpty("description", fresh.description);
  // tactic: arrays only (existing rows may have a string tactic; do
  // not overwrite a stringified tactic with an array form).
  if ((!cur.tactic || (Array.isArray(cur.tactic) && cur.tactic.length === 0)) && Array.isArray(fresh.tactic) && fresh.tactic.length) {
    cur.tactic = fresh.tactic;
    touched = true;
  }
  fillIfEmpty("description_full", fresh.description_full);
  fillIfEmpty("platforms", fresh.platforms);
  fillIfEmpty("data_sources", fresh.data_sources);
  fillIfEmpty("permissions_required", fresh.permissions_required);
  fillIfEmpty("defense_bypassed", fresh.defense_bypassed);
  fillIfEmpty("effective_permissions", fresh.effective_permissions);
  fillIfEmpty("detection", fresh.detection);
  fillIfEmpty("reference_url", fresh.reference_url);
  fillIfEmpty("stix_id", fresh.stix_id);
  if (cur.is_subtechnique === undefined && fresh.is_subtechnique != null) {
    cur.is_subtechnique = fresh.is_subtechnique; touched = true;
  }
  return touched;
}

async function refreshAttack({ dry = false, cap = Infinity, _deps = {} } = {}) {
  const _fetchUrl = _deps.fetchUrl || fetchUrl;
  const _loadCatalog = _deps.loadCatalog || loadCatalog;
  const _writeCatalog = _deps.writeCatalog || writeCatalog;
  console.log("[refresh-upstream:attack] fetching MITRE ATT&CK STIX...");
  const body = await _fetchUrl(ATTACK_SRC);
  const stix = JSON.parse(body);
  // For NEW adds: live techniques only (skip revoked / deprecated).
  // For BACKFILL on existing rows: include revoked too — an operator-
  // curated row that references a now-revoked MITRE ID may still want
  // the context fields (name / description / platforms) from the
  // pre-revocation STIX record. Same logic as the RFC obsoleted-but-
  // backfillable two-pass design.
  const liveTechs = (stix.objects || []).filter(
    (o) => o.type === "attack-pattern" && !o.revoked && !o.x_mitre_deprecated
  );
  const backfillTechs = (stix.objects || []).filter(
    (o) => o.type === "attack-pattern"
  );
  console.log(`[refresh-upstream:attack] STIX live techniques: ${liveTechs.length} (+ ${backfillTechs.length - liveTechs.length} revoked/deprecated available for backfill on existing rows)`);
  const techs = liveTechs;
  const local = _loadCatalog("attack-techniques.json");
  const existing = new Set(Object.keys(local).filter((k) => k !== "_meta"));
  techs.sort((a, b) => {
    const aSub = a.x_mitre_is_subtechnique ? 1 : 0;
    const bSub = b.x_mitre_is_subtechnique ? 1 : 0;
    if (aSub !== bSub) return aSub - bSub;
    const aId = (a.external_references || []).find((r) => r.source_name === "mitre-attack");
    const bId = (b.external_references || []).find((r) => r.source_name === "mitre-attack");
    return ((aId && aId.external_id) || "").localeCompare((bId && bId.external_id) || "");
  });
  let added = 0;
  let backfilled = 0;
  // First pass: backfill existing rows against the FULL technique set
  // (including revoked) so operator-curated rows still get context.
  for (const t of backfillTechs) {
    const extRef = (t.external_references || []).find((r) => r.source_name === "mitre-attack");
    if (!extRef || !extRef.external_id) continue;
    const id = extRef.external_id;
    if (!existing.has(id)) continue;
    const fresh = attackEntryFromStix(t, extRef);
    const cur = local[id];
    if (backfillAttack(cur, fresh)) {
      cur.last_verified = TODAY;
      backfilled++;
    }
  }
  // Second pass: add new entries from live techniques only.
  for (const t of techs) {
    const extRef = (t.external_references || []).find((r) => r.source_name === "mitre-attack");
    if (!extRef || !extRef.external_id) continue;
    const id = extRef.external_id;
    if (existing.has(id)) continue;
    if (added >= cap) continue;
    local[id] = attackEntryFromStix(t, extRef);
    existing.add(id);
    added++;
  }
  if (dry) { console.log(`[refresh-upstream:attack] DRY-RUN: +${added} new, ${backfilled} context backfills`); return { added, backfilled }; }
  const changed = added > 0 || backfilled > 0;
  if (changed) {
    if (local._meta) { local._meta.last_updated = TODAY; local._meta.last_threat_review = TODAY; }
    _writeCatalog("attack-techniques.json", local);
    console.log(`[ok] attack-techniques.json: +${added} entries, ${backfilled} context backfills (now ${existing.size} total)`);
  } else {
    console.log("[ok] attack-techniques.json: no upstream changes — file unchanged");
  }
  return { added, backfilled };
}

// ---------------- ICS-ATT&CK ----------------

const ICS_ATTACK_SRC = "https://raw.githubusercontent.com/mitre/cti/master/ics-attack/ics-attack.json";
const ICS_TACTIC_NAME = {
  "initial-access": "Initial Access (ICS)",
  "execution": "Execution (ICS)",
  "persistence": "Persistence (ICS)",
  "privilege-escalation": "Privilege Escalation (ICS)",
  "evasion": "Evasion (ICS)",
  "discovery": "Discovery (ICS)",
  "lateral-movement": "Lateral Movement (ICS)",
  "collection": "Collection (ICS)",
  "command-and-control": "Command and Control (ICS)",
  "inhibit-response-function": "Inhibit Response Function",
  "impair-process-control": "Impair Process Control",
  "impact": "Impact (ICS)"
};

async function refreshIcsAttack({ dry = false, cap = Infinity, _deps = {} } = {}) {
  const _fetchUrl = _deps.fetchUrl || fetchUrl;
  const _loadCatalog = _deps.loadCatalog || loadCatalog;
  const _writeCatalog = _deps.writeCatalog || writeCatalog;
  console.log("[refresh-upstream:ics-attack] fetching MITRE ICS-attack STIX...");
  const body = await _fetchUrl(ICS_ATTACK_SRC);
  const stix = JSON.parse(body);
  const techs = (stix.objects || []).filter(
    (o) => o.type === "attack-pattern" && !o.revoked && !o.x_mitre_deprecated
  );
  console.log(`[refresh-upstream:ics-attack] STIX live ICS techniques: ${techs.length}`);
  const local = _loadCatalog("attack-techniques.json");
  const existing = new Set(Object.keys(local).filter((k) => k !== "_meta"));
  let added = 0, backfilled = 0;
  for (const t of techs) {
    const extRef = (t.external_references || []).find((r) => r.source_name === "mitre-ics-attack" || r.source_name === "mitre-attack");
    if (!extRef || !extRef.external_id) continue;
    const id = extRef.external_id;
    const tactics = (t.kill_chain_phases || [])
      .filter((p) => (p.kill_chain_name || "").includes("ics"))
      .map((p) => ICS_TACTIC_NAME[p.phase_name] || `${p.phase_name} (ICS)`);
    const fullDesc = String(t.description || "").replace(/\s+/g, " ").trim();
    let shortDesc = fullDesc.split(/\.\s/)[0];
    if (shortDesc.length > 500) shortDesc = shortDesc.slice(0, 497) + "...";
    if (shortDesc && !shortDesc.endsWith(".")) shortDesc += ".";
    const fresh = {
      id, name: t.name, version: "ics-attack-v15",
      tactic: tactics,
      description: shortDesc,
      description_full: fullDesc,
      platforms: Array.isArray(t.x_mitre_platforms) ? t.x_mitre_platforms : [],
      detection: (t.x_mitre_detection || "").replace(/\s+/g, " ").trim() || null,
      reference_url: extRef.url || `https://attack.mitre.org/techniques/${id}/`,
      stix_id: t.id || null,
      last_verified: TODAY,
      _auto_imported: true,
      _intake_method: "mitre-ics-attack-stix",
      _matrix: "ics-attack"
    };
    if (existing.has(id)) {
      const cur = local[id];
      if (backfillAttack(cur, fresh)) { cur.last_verified = TODAY; backfilled++; }
      continue;
    }
    if (added >= cap) continue;
    local[id] = fresh;
    existing.add(id);
    added++;
  }
  if (dry) { console.log(`[refresh-upstream:ics-attack] DRY-RUN: +${added} new, ${backfilled} backfills`); return { added, backfilled }; }
  const changed = added > 0 || backfilled > 0;
  if (changed) {
    if (local._meta) { local._meta.last_updated = TODAY; local._meta.last_threat_review = TODAY; }
    _writeCatalog("attack-techniques.json", local);
    console.log(`[ok] attack-techniques.json: +${added} ICS entries, ${backfilled} backfills (now ${existing.size} total)`);
  } else {
    console.log("[ok] attack-techniques.json: no upstream ICS changes — file unchanged");
  }
  return { added, backfilled };
}

// ---------------- ATLAS ----------------

const ATLAS_SRC = "https://raw.githubusercontent.com/mitre-atlas/atlas-navigator-data/main/dist/stix-atlas.json";

function atlasTactic(phases) {
  const map = {
    "reconnaissance": "Reconnaissance", "resource-development": "Resource Development",
    "initial-access": "Initial Access", "ml-model-access": "AI Model Access",
    "execution": "Execution", "persistence": "Persistence",
    "privilege-escalation": "Privilege Escalation", "defense-evasion": "Defense Evasion",
    "credential-access": "Credential Access", "discovery": "Discovery",
    "collection": "Collection", "ml-attack-staging": "AI Attack Staging",
    "command-and-control": "Command and Control", "exfiltration": "Exfiltration",
    "impact": "Impact"
  };
  return (phases || [])
    .filter((p) => (p.kill_chain_name || "").includes("atlas") || (p.kill_chain_name || "").includes("ml-"))
    .map((p) => map[p.phase_name] || p.phase_name);
}

function atlasEntryFromStix(t, ext) {
  const id = ext.external_id;
  const tactics = atlasTactic(t.kill_chain_phases);
  const fullDesc = String(t.description || "").replace(/\s+/g, " ").trim();
  let shortDesc = fullDesc.split(/\.\s/)[0];
  if (shortDesc.length > 500) shortDesc = shortDesc.slice(0, 497) + "...";
  if (shortDesc && !shortDesc.endsWith(".")) shortDesc += ".";
  return {
    id,
    name: t.name,
    tactic: tactics.length === 1 ? tactics[0] : tactics,
    description: shortDesc || `MITRE ATLAS technique ${id}. Reference: ${ext.url}`,
    description_full: fullDesc || null,
    platforms: Array.isArray(t.x_mitre_platforms) ? t.x_mitre_platforms : [],
    detection: (t.x_mitre_detection || "").replace(/\s+/g, " ").trim() || null,
    is_subtechnique: !!t.x_mitre_is_subtechnique,
    mitre_version: t.x_mitre_version || null,
    reference_url: ext.url || `https://atlas.mitre.org/techniques/${id}`,
    stix_id: t.id || null,
    last_verified: TODAY,
    _auto_imported: true,
    _intake_method: "mitre-atlas-stix"
  };
}

function backfillAtlas(cur, fresh) {
  let touched = false;
  const fillIfEmpty = (key, val) => {
    if (val == null) return;
    if (Array.isArray(val)) {
      if ((!cur[key] || cur[key].length === 0) && val.length) { cur[key] = val; touched = true; }
    } else {
      if (!cur[key] && val) { cur[key] = val; touched = true; }
    }
  };
  fillIfEmpty("description_full", fresh.description_full);
  fillIfEmpty("platforms", fresh.platforms);
  fillIfEmpty("detection", fresh.detection);
  fillIfEmpty("reference_url", fresh.reference_url);
  fillIfEmpty("stix_id", fresh.stix_id);
  if (cur.is_subtechnique === undefined && fresh.is_subtechnique != null) {
    cur.is_subtechnique = fresh.is_subtechnique; touched = true;
  }
  return touched;
}

async function refreshAtlas({ dry = false, _deps = {} } = {}) {
  const _fetchUrl = _deps.fetchUrl || fetchUrl;
  const _loadCatalog = _deps.loadCatalog || loadCatalog;
  const _writeCatalog = _deps.writeCatalog || writeCatalog;
  console.log("[refresh-upstream:atlas] fetching MITRE ATLAS STIX...");
  const body = await _fetchUrl(ATLAS_SRC);
  const stix = JSON.parse(body);
  const techs = (stix.objects || []).filter(
    (o) => o.type === "attack-pattern" && !o.revoked && !o.x_mitre_deprecated
  );
  const aml = techs.filter((t) => {
    const ext = (t.external_references || []).find((r) => r.source_name === "mitre-atlas");
    return ext && (ext.external_id || "").startsWith("AML.");
  });
  console.log(`[refresh-upstream:atlas] AML.* techniques: ${aml.length}`);
  let atlasVersion = null;
  for (const o of stix.objects || []) {
    if (o.type === "x-mitre-matrix" && (o.name || "").toLowerCase().includes("atlas") && o.x_mitre_version) {
      atlasVersion = o.x_mitre_version; break;
    }
  }
  const local = _loadCatalog("atlas-ttps.json");
  const existing = new Set(Object.keys(local).filter((k) => k !== "_meta"));
  aml.sort((a, b) => {
    const aSub = a.x_mitre_is_subtechnique ? 1 : 0;
    const bSub = b.x_mitre_is_subtechnique ? 1 : 0;
    if (aSub !== bSub) return aSub - bSub;
    const aExt = (a.external_references || []).find((r) => r.source_name === "mitre-atlas");
    const bExt = (b.external_references || []).find((r) => r.source_name === "mitre-atlas");
    return ((aExt && aExt.external_id) || "").localeCompare((bExt && bExt.external_id) || "");
  });
  let added = 0, backfilled = 0;
  for (const t of aml) {
    const ext = (t.external_references || []).find((r) => r.source_name === "mitre-atlas");
    if (!ext || !ext.external_id) continue;
    const id = ext.external_id;
    if (existing.has(id)) {
      const fresh = atlasEntryFromStix(t, ext);
      const cur = local[id];
      if (backfillAtlas(cur, fresh)) { cur.last_verified = TODAY; backfilled++; }
      continue;
    }
    local[id] = atlasEntryFromStix(t, ext);
    existing.add(id);
    added++;
  }
  if (dry) { console.log(`[refresh-upstream:atlas] DRY-RUN: +${added} new, ${backfilled} backfills${atlasVersion ? `, v${atlasVersion}` : ""}`); return { added, backfilled, atlasVersion }; }
  // A newly-detected ATLAS matrix version that differs from the recorded one
  // is itself a change (the catalog should bump atlas_version + last_updated
  // together), independent of any added/backfilled rows.
  const versionChanged = !!(atlasVersion && local._meta && local._meta.atlas_version !== atlasVersion);
  const changed = added > 0 || backfilled > 0 || versionChanged;
  if (changed) {
    if (local._meta) {
      if (atlasVersion) local._meta.atlas_version = atlasVersion;
      local._meta.last_updated = TODAY;
      local._meta.last_threat_review = TODAY;
    }
    _writeCatalog("atlas-ttps.json", local);
    console.log(`[ok] atlas-ttps.json: +${added} entries, ${backfilled} backfills (now ${existing.size} total${atlasVersion ? `, ATLAS v${atlasVersion}` : ""})`);
  } else {
    console.log("[ok] atlas-ttps.json: no upstream changes — file unchanged");
  }
  return { added, backfilled, atlasVersion };
}

// ---------------- D3FEND ----------------

const D3FEND_SRC = "https://d3fend.mitre.org/ontologies/d3fend.json";

function d3fendTactic(parent) {
  const known = {
    "Application Hardening": "Harden", "Credential Hardening": "Harden",
    "Message Hardening": "Harden", "Platform Hardening": "Harden",
    "File Analysis": "Detect", "Identifier Analysis": "Detect",
    "Message Analysis": "Detect", "Network Traffic Analysis": "Detect",
    "Platform Monitoring": "Detect", "Process Analysis": "Detect",
    "User Behavior Analysis": "Detect",
    "Execution Isolation": "Isolate", "Network Isolation": "Isolate",
    "Decoy Environment": "Deceive", "Decoy Object": "Deceive",
    "Credential Eviction": "Evict", "Process Eviction": "Evict"
  };
  if (parent && known[parent]) return known[parent];
  return "Defensive";
}

function d3fendIdList(t, field) {
  const v = t[field];
  if (!v) return [];
  const arr = Array.isArray(v) ? v : [v];
  return arr.map((x) => (x && x["@id"]) ? String(x["@id"]).replace(/^d3f:/, "") : null).filter(Boolean);
}

function d3fendEntryFromOwl(t) {
  // Strip a trailing period from the OWL d3fend-id: a few upstream artifact ids
  // (e.g. "D3A-C4.") carry a spurious terminal dot that no id token regex can
  // round-trip, leaving the entry unmatchable by the orphan/cross-ref scanners.
  // No legitimate d3fend technique id ends in a period.
  const rawId = t["d3f:d3fend-id"];
  const id = typeof rawId === "string" ? rawId.replace(/\.$/, "") : rawId;
  const labelRaw = t["rdfs:label"];
  const name = Array.isArray(labelRaw)
    ? (typeof labelRaw[0] === "object" ? labelRaw[0]["@value"] : labelRaw[0])
    : (typeof labelRaw === "object" ? labelRaw["@value"] : labelRaw);
  const def = t["d3f:definition"];
  const fullDesc = typeof def === "string" ? def : (def && def["@value"]) || "";
  let desc = fullDesc.split(/\.\s/)[0];
  if (desc.length > 500) desc = desc.slice(0, 497) + "...";
  if (desc && !desc.endsWith(".")) desc += ".";
  const syns = t["d3f:synonym"];
  const synonyms = Array.isArray(syns) ? syns : (syns ? [syns] : []);
  const kbRef = t["d3f:kb-reference"];
  const kbRefId = kbRef && kbRef["@id"] ? String(kbRef["@id"]).replace(/^d3f:/, "") : null;
  return {
    id,
    name: name || id,
    tactic: d3fendTactic(name),
    description: desc || `D3FEND defensive technique ${id}. Reference: https://d3fend.mitre.org/technique/${id}/`,
    description_full: fullDesc || null,
    synonyms,
    // Relationship fields — what offensive techniques this counters,
    // what defensive technique it enables / falls under, the parent
    // narrower/broader classes for hierarchical lookup.
    defends_against: d3fendIdList(t, "d3f:defends-against"),
    counters: d3fendIdList(t, "d3f:counters"),
    enables: d3fendIdList(t, "d3f:enables"),
    broader_of: d3fendIdList(t, "d3f:broader"),
    narrower_of: d3fendIdList(t, "d3f:narrower"),
    requires: d3fendIdList(t, "d3f:requires"),
    inventories: d3fendIdList(t, "d3f:inventories"),
    kb_reference: kbRefId,
    reference_url: `https://d3fend.mitre.org/technique/${id}/`,
    last_verified: TODAY,
    _auto_imported: true,
    _intake_method: "mitre-d3fend-owl"
  };
}

function backfillD3fend(cur, fresh) {
  let touched = false;
  const fillIfEmpty = (key, val) => {
    if (val == null) return;
    if (Array.isArray(val)) {
      if ((!cur[key] || cur[key].length === 0) && val.length) { cur[key] = val; touched = true; }
    } else {
      if (!cur[key] && val) { cur[key] = val; touched = true; }
    }
  };
  fillIfEmpty("description_full", fresh.description_full);
  fillIfEmpty("synonyms", fresh.synonyms);
  fillIfEmpty("defends_against", fresh.defends_against);
  fillIfEmpty("counters", fresh.counters);
  fillIfEmpty("enables", fresh.enables);
  fillIfEmpty("broader_of", fresh.broader_of);
  fillIfEmpty("narrower_of", fresh.narrower_of);
  fillIfEmpty("requires", fresh.requires);
  fillIfEmpty("inventories", fresh.inventories);
  fillIfEmpty("kb_reference", fresh.kb_reference);
  fillIfEmpty("reference_url", fresh.reference_url);
  return touched;
}

async function refreshD3fend({ dry = false, cap = Infinity, _deps = {} } = {}) {
  const _fetchUrl = _deps.fetchUrl || fetchUrl;
  const _loadCatalog = _deps.loadCatalog || loadCatalog;
  const _writeCatalog = _deps.writeCatalog || writeCatalog;
  console.log("[refresh-upstream:d3fend] fetching MITRE D3FEND ontology...");
  const body = await _fetchUrl(D3FEND_SRC);
  const j = JSON.parse(body);
  const graph = j["@graph"] || [];
  const techs = graph.filter((o) => o["@id"] && o["d3f:d3fend-id"] && o["rdfs:label"]);
  console.log(`[refresh-upstream:d3fend] ontology techniques: ${techs.length}`);
  const local = _loadCatalog("d3fend-catalog.json");
  const existing = new Set(Object.keys(local).filter((k) => k !== "_meta"));
  techs.sort((a, b) => String(a["d3f:d3fend-id"]).localeCompare(String(b["d3f:d3fend-id"])));
  let added = 0, backfilled = 0;
  for (const t of techs) {
    const id = t["d3f:d3fend-id"];
    if (existing.has(id)) {
      const fresh = d3fendEntryFromOwl(t);
      const cur = local[id];
      if (backfillD3fend(cur, fresh)) { cur.last_verified = TODAY; backfilled++; }
      continue;
    }
    if (added >= cap) continue;
    local[id] = d3fendEntryFromOwl(t);
    existing.add(id);
    added++;
  }
  if (dry) { console.log(`[refresh-upstream:d3fend] DRY-RUN: +${added} new, ${backfilled} backfills`); return { added, backfilled }; }
  const changed = added > 0 || backfilled > 0;
  if (changed) {
    if (local._meta) { local._meta.last_updated = TODAY; local._meta.last_threat_review = TODAY; }
    _writeCatalog("d3fend-catalog.json", local);
    console.log(`[ok] d3fend-catalog.json: +${added} entries, ${backfilled} backfills (now ${existing.size} total)`);
  } else {
    console.log("[ok] d3fend-catalog.json: no upstream changes — file unchanged");
  }
  return { added, backfilled };
}

// ---------------- CLI dispatcher ----------------

const SOURCES = {
  rfc:        { name: "ietf-rfc-index",       run: refreshRfc },
  attack:     { name: "mitre-attack-stix",    run: refreshAttack },
  "ics-attack": { name: "mitre-ics-attack-stix", run: refreshIcsAttack },
  atlas:      { name: "mitre-atlas-stix",     run: refreshAtlas },
  d3fend:     { name: "mitre-d3fend-owl",     run: refreshD3fend }
};

function parseArgs(argv) {
  const out = { source: null, dry: false };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--dry-run") out.dry = true;
    else if (a === "--source") { out.source = argv[++i]; }
    else if (a.startsWith("--source=")) out.source = a.slice("--source=".length);
  }
  return out;
}

async function runCli(argv = process.argv) {
  const { source, dry } = parseArgs(argv);
  const cap = Number(process.env.CAP || Infinity);
  const wanted = source
    ? source.split(",").map((s) => s.trim()).filter(Boolean)
    : Object.keys(SOURCES);
  for (const key of wanted) {
    if (!SOURCES[key]) {
      console.error(`[err] unknown source "${key}" — valid: ${Object.keys(SOURCES).join(", ")}`);
      process.exitCode = 2;
      continue;
    }
    try {
      await SOURCES[key].run({ dry, cap });
    } catch (e) {
      console.error(`[err] ${key}: ${e.message}`);
      process.exitCode = 1;
    }
  }
}

if (require.main === module) {
  runCli();
}

module.exports = {
  refreshRfc,
  refreshAttack,
  refreshIcsAttack,
  refreshAtlas,
  refreshD3fend,
  SOURCES,
  runCli,
  // Exported for regression tests: fetchUrl's status/redirect handling and
  // writeCatalog's atomicity are load-bearing fail-closed properties.
  fetchUrl,
  writeCatalog
};
