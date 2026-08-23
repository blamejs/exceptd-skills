"use strict";
/**
 * Catalog gap detection. Each detector is a pure function over the loaded
 * catalogs plus options, returning an array of findings; DETECTOR_CLASSES below
 * names the full set.
 */

// Placeholder / curation-pending sentinels, applied to every text-heavy field.
const PLACEHOLDER_SENTINELS = [
  /pending operator curation/i,
  /refer to vendor advisory for IOC list/i,
  /bulk-imported KEV entry, IOCs not extracted/i,
  /\bTBD\b/,
  /\bTKTK\b/,
  /\bcoming soon\b/i,
  /^\s*\[\s*\]\s*$/,
  /\bplaceholder\b/i
];

function hasPlaceholderLanguage(str) {
  if (typeof str !== "string" || str.length === 0) return false;
  for (const re of PLACEHOLDER_SENTINELS) {
    if (re.test(str)) return true;
  }
  return false;
}

// Fields present but weak; what counts as weak is per catalog and field.
function contentQualityFindings(loaded) {
  const out = [];
  const cve = loaded["cve-catalog"];
  if (!cve) return out;

  for (const id of Object.keys(cve)) {
    if (id === "_meta") continue;
    const e = cve[id];
    if (!e) continue;

    // A short or placeholder vector means the exploitation primitive is undescribed.
    if (typeof e.vector === "string" && e.vector.length > 0 && e.vector.length < 50) {
      out.push({ class: "content-quality", catalog: "cve-catalog", id,
        field: "vector", reason: `vector is ${e.vector.length} chars (< 50 threshold) — likely a stub` });
    }
    if (typeof e.vector === "string" && hasPlaceholderLanguage(e.vector)) {
      out.push({ class: "content-quality", catalog: "cve-catalog", id,
        field: "vector", reason: "vector contains placeholder-language sentinel" });
    }

    // poc_available:true with placeholder text claims a PoC without saying where.
    if (e.poc_available === true && hasPlaceholderLanguage(e.poc_description)) {
      out.push({ class: "content-quality", catalog: "cve-catalog", id,
        field: "poc_description", reason: "poc_available:true but description carries placeholder sentinel" });
    }

    // A KEV listing implies CISA linked advisory metadata, so empty is a curation gap.
    if (e.cisa_kev === true && (!Array.isArray(e.vendor_advisories) || e.vendor_advisories.length === 0)) {
      out.push({ class: "content-quality", catalog: "cve-catalog", id,
        field: "vendor_advisories", reason: "cisa_kev:true but vendor_advisories is empty" });
    }

    if (typeof e.name === "string" && typeof e.description === "string"
        && e.name === e.description && e.name.length > 0) {
      out.push({ class: "content-quality", catalog: "cve-catalog", id,
        field: "description", reason: "description is just the name repeated" });
    }
  }
  return out;
}

// Time-based decay: stale entries become an operator re-verify work queue.
function daysSince(iso, now) {
  if (typeof iso !== "string" || !/^\d{4}-\d{2}-\d{2}/.test(iso)) return null;
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return null;
  return Math.floor((now.getTime() - t) / (1000 * 60 * 60 * 24));
}

function temporalStalenessFindings(loaded, opts = {}) {
  const now = opts.now || new Date();
  const STALE_VERIFIED_DAYS = opts.stale_verified_days || 180;
  const STALE_UPDATED_DAYS = opts.stale_updated_days || 365;
  const STALE_EPSS_DAYS = opts.stale_epss_days || 90;
  const out = [];
  const cve = loaded["cve-catalog"];
  if (!cve) return out;

  for (const id of Object.keys(cve)) {
    if (id === "_meta") continue;
    const e = cve[id];
    if (!e) continue;

    const sinceVerified = daysSince(e.source_verified || e.last_verified, now);
    if (sinceVerified !== null && sinceVerified > STALE_VERIFIED_DAYS) {
      out.push({ class: "temporal-staleness", catalog: "cve-catalog", id,
        field: "source_verified", reason: `source_verified is ${sinceVerified}d old (threshold ${STALE_VERIFIED_DAYS}d)` });
    }
    const sinceUpdated = daysSince(e.last_updated, now);
    if (sinceUpdated !== null && sinceUpdated > STALE_UPDATED_DAYS) {
      out.push({ class: "temporal-staleness", catalog: "cve-catalog", id,
        field: "last_updated", reason: `last_updated is ${sinceUpdated}d old (threshold ${STALE_UPDATED_DAYS}d)` });
    }

    // A passed CISA KEV due-date is NOT temporal staleness: it is a fixed
    // external remediation deadline, and every historical entry's passes by
    // calendar while saying nothing about catalog currency.

    // EPSS has its own currency clock; FIRST recalculates daily.
    if (typeof e.epss_score === "number" && typeof e.epss_date === "string") {
      const sinceEpss = daysSince(e.epss_date, now);
      if (sinceEpss !== null && sinceEpss > STALE_EPSS_DAYS) {
        out.push({ class: "temporal-staleness", catalog: "cve-catalog", id,
          field: "epss_date", reason: `epss_date is ${sinceEpss}d old (threshold ${STALE_EPSS_DAYS}d); refresh via 'exceptd refresh --source epss'` });
      }
    }
  }
  return out;
}

// Multi-field rules: combinations that pass schema validation yet contradict.
function logicalConsistencyFindings(loaded) {
  const out = [];
  const cve = loaded["cve-catalog"];
  if (!cve) return out;

  for (const id of Object.keys(cve)) {
    if (id === "_meta") continue;
    const e = cve[id];
    if (!e) continue;

    // CISA's JSON carries dateAdded on every listing, so null means intake lost it.
    if (e.cisa_kev === true && (e.cisa_kev_date == null || e.cisa_kev_date === "")) {
      out.push({ class: "logical-consistency", catalog: "cve-catalog", id,
        rule: "cisa_kev_date_present_when_kev_true",
        reason: "cisa_kev:true requires cisa_kev_date (CISA's dateAdded)" });
    }

    // The RWEP deduction only holds when the tools list names a real live-patch path.
    if (e.live_patch_available === true
        && (!Array.isArray(e.live_patch_tools) || e.live_patch_tools.length === 0)) {
      out.push({ class: "logical-consistency", catalog: "cve-catalog", id,
        rule: "live_patch_tools_required_when_available",
        reason: "live_patch_available:true but live_patch_tools is empty — RWEP factor would mis-fire" });
    }

    // The schema validator catches discovery_source==unknown, not a too-short note.
    if (e.ai_discovered === true) {
      const note = e.ai_discovery_notes || e.discovery_attribution_note || "";
      if (typeof note !== "string" || note.length < 30) {
        out.push({ class: "logical-consistency", catalog: "cve-catalog", id,
          rule: "ai_discovery_attribution_text_required",
          reason: "ai_discovered:true but attribution text is missing or too short to name the AI tool" });
      }
    }

    if (e.active_exploitation === "confirmed"
        && (!Array.isArray(e.verification_sources) || e.verification_sources.length < 2)) {
      out.push({ class: "logical-consistency", catalog: "cve-catalog", id,
        rule: "confirmed_exploitation_needs_sources",
        reason: `active_exploitation:"confirmed" requires >= 2 verification_sources; have ${(e.verification_sources || []).length}` });
    }

    if (typeof e.rwep_score === "number"
        && (!e.rwep_factors || Object.keys(e.rwep_factors).length === 0)) {
      out.push({ class: "logical-consistency", catalog: "cve-catalog", id,
        rule: "rwep_factors_required_when_score_set",
        reason: "rwep_score declared but rwep_factors is empty — score is unjustified" });
    }
  }
  return out;
}

// The dangling-ref class verifies the forward direction; this one verifies the
// back-reference: the target entry lists the CVE that cited it.
function crossRefCompletenessFindings(loaded) {
  const out = [];
  const cve = loaded["cve-catalog"];
  const cwe = loaded["cwe-catalog"];
  const att = loaded["attack-techniques"];
  const fwc = loaded["framework-control-gaps"];

  // Build forward-ref maps: target-id → set of CVE-IDs that cite it.
  const cveByCwe = new Map();
  const cveByAttack = new Map();
  const cveByFwc = new Map();

  for (const cid of Object.keys(cve || {})) {
    if (cid === "_meta") continue;
    const e = cve[cid];
    if (!e) continue;
    // Drafts excluded — an auto-imported entry has no curated refs yet.
    if (e._auto_imported) continue;
    for (const c of (e.cwe_refs || [])) {
      if (!cveByCwe.has(c)) cveByCwe.set(c, new Set());
      cveByCwe.get(c).add(cid);
    }
    for (const a of (e.attack_refs || [])) {
      if (!cveByAttack.has(a)) cveByAttack.set(a, new Set());
      cveByAttack.get(a).add(cid);
    }
    for (const k of Object.keys(e.framework_control_gaps || {})) {
      if (!cveByFwc.has(k)) cveByFwc.set(k, new Set());
      cveByFwc.get(k).add(cid);
    }
  }

  // CWE: every CVE-citation must be in the CWE entry's evidence_cves.
  for (const [cweId, citingSet] of cveByCwe.entries()) {
    const entry = cwe && cwe[cweId];
    if (!entry) continue; // dangling-ref class handles this
    const evidence = new Set(Array.isArray(entry.evidence_cves) ? entry.evidence_cves : []);
    const missing = [];
    for (const cid of citingSet) if (!evidence.has(cid)) missing.push(cid);
    if (missing.length > 0) {
      out.push({ class: "cross-ref-completeness", source: "cve-catalog", target: "cwe-catalog",
        target_id: cweId, reason: `CWE entry's evidence_cves missing ${missing.length} CVE(s) that cite it: ${missing.slice(0, 3).join(", ")}` });
    }
  }

  // Same back-ref check for ATT&CK and framework-control-gaps.
  for (const [attId, citingSet] of cveByAttack.entries()) {
    const entry = att && att[attId];
    if (!entry) continue;
    const evidence = new Set(Array.isArray(entry.cve_refs) ? entry.cve_refs : []);
    const missing = [];
    for (const cid of citingSet) if (!evidence.has(cid)) missing.push(cid);
    if (missing.length > 0) {
      out.push({ class: "cross-ref-completeness", source: "cve-catalog", target: "attack-techniques",
        target_id: attId, reason: `ATT&CK entry's cve_refs missing ${missing.length} CVE(s) that cite it: ${missing.slice(0, 3).join(", ")}` });
    }
  }
  for (const [fwId, citingSet] of cveByFwc.entries()) {
    const entry = fwc && fwc[fwId];
    if (!entry) continue;
    const evidence = new Set(Array.isArray(entry.evidence_cves) ? entry.evidence_cves : []);
    const missing = [];
    for (const cid of citingSet) if (!evidence.has(cid)) missing.push(cid);
    if (missing.length > 0) {
      out.push({ class: "cross-ref-completeness", source: "cve-catalog", target: "framework-control-gaps",
        target_id: fwId, reason: `framework-gap entry's evidence_cves missing ${missing.length} CVE(s) that cite it: ${missing.slice(0, 3).join(", ")}` });
    }
  }
  return out;
}

// Fields the schema requires today that were optional on older entries.
const REQUIRED_SINCE = {
  "cve-catalog": [
    { field: "ai_discovered", since: "0.12.36", check: (v) => typeof v === "boolean" },
    { field: "ai_assisted_weaponization", since: "0.12.36", check: (v) => typeof v === "boolean" },
    { field: "rwep_factors", since: "0.12.36", check: (v) => v && Object.keys(v).length > 0 }
  ]
};

function schemaEvolutionFindings(loaded) {
  const out = [];
  for (const catalogKey of Object.keys(REQUIRED_SINCE)) {
    const cat = loaded[catalogKey];
    if (!cat) continue;
    for (const id of Object.keys(cat)) {
      if (id === "_meta") continue;
      const e = cat[id];
      if (!e) continue;
      for (const r of REQUIRED_SINCE[catalogKey]) {
        if (!r.check(e[r.field])) {
          out.push({ class: "schema-evolution", catalog: catalogKey, id,
            field: r.field, since: r.since,
            reason: `${r.field} required since v${r.since}; missing on this entry` });
        }
      }
    }
  }
  return out;
}

// Past the SLA, an entry's un-curated state is itself the finding.
function operatorActionSlaFindings(loaded, opts = {}) {
  const now = opts.now || new Date();
  const AUTO_IMPORT_SLA_DAYS = opts.auto_import_sla_days || 60;
  const DRAFT_SLA_DAYS = opts.draft_sla_days || 90;
  const out = [];
  const cve = loaded["cve-catalog"];
  if (!cve) return out;

  for (const id of Object.keys(cve)) {
    if (id === "_meta") continue;
    const e = cve[id];
    if (!e) continue;
    if (e._auto_imported === true) {
      const age = daysSince(e.last_updated, now);
      if (age !== null && age > AUTO_IMPORT_SLA_DAYS) {
        out.push({ class: "operator-action-sla", catalog: "cve-catalog", id,
          reason: `_auto_imported entry is ${age}d old (SLA ${AUTO_IMPORT_SLA_DAYS}d); operator-curation pending` });
      }
    }
    if (e._draft === true) {
      const age = daysSince(e.last_updated, now);
      if (age !== null && age > DRAFT_SLA_DAYS) {
        out.push({ class: "operator-action-sla", catalog: "cve-catalog", id,
          reason: `_draft entry is ${age}d old (SLA ${DRAFT_SLA_DAYS}d); promote-or-quarantine SLA breached` });
      }
    }
  }
  return out;
}

// Entries nothing references — dead weight to repurpose or remove.

// Any id token in a skill body or playbook JSON counts as a reference, and the
// full text is scanned rather than the structured fields, because skill bodies
// cite ids in prose. The D3FEND alternative must cover D3-, D3A- and D3F-: a
// narrower `D3-[A-Z]+` misses a D3A- citation and mis-flags its entry as orphan.
const REFERENCE_TOKEN_RE = /\b(?:CWE-\d+|T\d{4}(?:\.\d{3})?|AML\.T\d{4}(?:\.\d{3})?|D3[AF]?-[A-Z0-9]+(?:-[A-Z0-9]+)*|RFC-\d+)\b/g;

function buildExternalRefs(rootPath) {
  // Returns { skillRefs, playbookRefs } as Sets of id strings; a missing
  // skills/ or playbooks/ tree yields an empty set rather than throwing.
  if (!rootPath) {
    const path = require("path");
    rootPath = path.join(__dirname, "..");
  }
  const path = require("path");
  const fs = require("fs");
  const skillRefs = new Set();
  const playbookRefs = new Set();
  const skillsDir = path.join(rootPath, "skills");
  if (fs.existsSync(skillsDir)) {
    for (const skillName of fs.readdirSync(skillsDir)) {
      const skillPath = path.join(skillsDir, skillName, "skill.md");
      if (!fs.existsSync(skillPath)) continue;
      const text = fs.readFileSync(skillPath, "utf8");
      const matches = text.match(REFERENCE_TOKEN_RE);
      if (matches) for (const m of matches) skillRefs.add(m);
    }
  }
  const playbooksDir = path.join(rootPath, "data", "playbooks");
  if (fs.existsSync(playbooksDir)) {
    for (const pbName of fs.readdirSync(playbooksDir)) {
      if (!pbName.endsWith(".json")) continue;
      const text = fs.readFileSync(path.join(playbooksDir, pbName), "utf8");
      const matches = text.match(REFERENCE_TOKEN_RE);
      if (matches) for (const m of matches) playbookRefs.add(m);
    }
  }
  return { skillRefs, playbookRefs };
}

function unusedOrphanFindings(loaded, opts = {}) {
  const out = [];
  // Auto-populate the reference sets when the caller supplies neither; a caller
  // wanting genuinely empty sets passes _autoLoadRefs:false.
  let skillRefs = opts.skillRefs;
  let playbookRefs = opts.playbookRefs;
  if (!skillRefs && !playbookRefs && opts._autoLoadRefs !== false) {
    const refs = buildExternalRefs(opts._rootPath);
    skillRefs = refs.skillRefs;
    playbookRefs = refs.playbookRefs;
  }
  skillRefs = skillRefs || new Set();
  playbookRefs = playbookRefs || new Set();
  const cve = loaded["cve-catalog"];
  const cveRefIds = new Set();
  for (const id of Object.keys(cve || {})) {
    if (id === "_meta") continue;
    const e = cve[id];
    if (!e) continue;
    for (const r of (e.cwe_refs || [])) cveRefIds.add(r);
    for (const r of (e.attack_refs || [])) cveRefIds.add(r);
    for (const r of (e.atlas_refs || [])) cveRefIds.add(r);
    for (const k of Object.keys(e.framework_control_gaps || {})) cveRefIds.add(k);
  }
  const isReferenced = (id) => skillRefs.has(id) || playbookRefs.has(id) || cveRefIds.has(id);

  for (const catKey of ["cwe-catalog", "attack-techniques", "atlas-ttps", "d3fend-catalog", "framework-control-gaps"]) {
    const cat = loaded[catKey];
    if (!cat) continue;
    for (const id of Object.keys(cat)) {
      if (id === "_meta") continue;
      const e = cat[id];
      if (!e) continue;
      if (e._auto_imported !== true) continue; // only flag auto-imported orphans
      if (e.forward_looking === true) continue; // legitimate forward-looking
      if (isReferenced(id)) continue;
      out.push({ class: "unused-orphan", catalog: catKey, id,
        reason: "auto-imported entry with zero references from skills / playbooks / CVE entries — consider quarantine or curation" });
    }
  }
  return out;
}

function runAllDetectors(loaded, opts = {}) {
  // Build the external reference sets once and thread them through, so a composed
  // run does not re-scan per detector or measure against different sets.
  const orphanOpts = { ...opts };
  if (!orphanOpts.skillRefs && !orphanOpts.playbookRefs && opts._autoLoadRefs !== false) {
    const refs = buildExternalRefs(opts._rootPath);
    orphanOpts.skillRefs = refs.skillRefs;
    orphanOpts.playbookRefs = refs.playbookRefs;
  }
  return [
    ...contentQualityFindings(loaded),
    ...temporalStalenessFindings(loaded, opts),
    ...logicalConsistencyFindings(loaded),
    ...crossRefCompletenessFindings(loaded),
    ...schemaEvolutionFindings(loaded),
    ...operatorActionSlaFindings(loaded, opts),
    ...unusedOrphanFindings(loaded, orphanOpts)
  ];
}

// Every class runAllDetectors can emit. The budget gate asserts class-set equality
// against this list, so a detector added without a budget entry fails closed.
const DETECTOR_CLASSES = [
  "content-quality",
  "temporal-staleness",
  "logical-consistency",
  "cross-ref-completeness",
  "schema-evolution",
  "operator-action-sla",
  "unused-orphan"
];

module.exports = {
  hasPlaceholderLanguage,
  daysSince,
  contentQualityFindings,
  temporalStalenessFindings,
  logicalConsistencyFindings,
  crossRefCompletenessFindings,
  schemaEvolutionFindings,
  operatorActionSlaFindings,
  unusedOrphanFindings,
  runAllDetectors,
  buildExternalRefs,
  DETECTOR_CLASSES,
  REQUIRED_SINCE,
  PLACEHOLDER_SENTINELS,
  REFERENCE_TOKEN_RE
};
