"use strict";
/**
 * lib/gap-detectors.js
 *
 * v0.13.21 — Catalog gap detection beyond the v0.13.19 missing-context /
 * dangling-ref / draft-debt classes. The audit-catalog-gaps detector
 * surfaced field-presence holes; this module adds seven cross-cutting
 * detection classes the prior detector did not cover.
 *
 * Each detector is a pure function: takes the loaded catalogs + options,
 * returns an array of findings. The audit-catalog-gaps CLI composes them
 * into a unified report; the integrity test exercises them against the
 * shipped catalogs; --class filters select between them.
 *
 * Detection classes:
 *
 *   1. content-quality       — fields present but content weak
 *                              (short, placeholder-language, name-as-
 *                              description, KEV-listed but no advisories)
 *
 *   2. temporal-staleness    — last_verified > 180d, last_updated > 365d,
 *                              CISA-KEV due-date passed, EPSS stale
 *
 *   3. logical-consistency   — internal-state contradictions
 *                              (cisa_kev:true + date:null, etc.)
 *
 *   4. cross-ref-completeness — bidirectional references
 *                               (CVE→CWE present but CWE.evidence_cves
 *                               missing the back-ref)
 *
 *   5. schema-evolution      — required-since-version fields missing
 *                              on older entries
 *
 *   6. operator-action-sla   — auto-imported entries older than the
 *                              curation-SLA without operator action
 *
 *   7. unused-orphan         — catalog entries no skill / playbook /
 *                              CVE references — dead-weight content
 *
 * Why pure functions: each detector is independently testable against
 * synthetic catalog inputs, and the integration is just `Array.concat`
 * over the seven results. Composing in audit-catalog-gaps.js stays
 * thin.
 */

// Sentinel strings that indicate placeholder / curation-pending content.
// Adding new sentinels here makes them findable across every text-heavy
// field without changing the call sites.
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

// ---------- 1. content-quality ----------
//
// Fields present but content weak. Each rule is per-catalog + per-field
// because the "what's weak" depends on the field's semantic role.

function contentQualityFindings(loaded) {
  const out = [];
  const cve = loaded["cve-catalog"];
  if (!cve) return out;

  for (const id of Object.keys(cve)) {
    if (id === "_meta") continue;
    const e = cve[id];
    if (!e) continue;

    // Vector text: < 50 chars or placeholder-language indicates the
    // operator didn't actually describe the primitive. Hard Rule #1
    // implicit: every CVE needs a real exploitation-vector description.
    if (typeof e.vector === "string" && e.vector.length > 0 && e.vector.length < 50) {
      out.push({ class: "content-quality", catalog: "cve-catalog", id,
        field: "vector", reason: `vector is ${e.vector.length} chars (< 50 threshold) — likely a stub` });
    }
    if (typeof e.vector === "string" && hasPlaceholderLanguage(e.vector)) {
      out.push({ class: "content-quality", catalog: "cve-catalog", id,
        field: "vector", reason: "vector contains placeholder-language sentinel" });
    }

    // poc_description with placeholder language while poc_available:true
    // is a contradiction — the project claims PoC exists but didn't
    // document where.
    if (e.poc_available === true && hasPlaceholderLanguage(e.poc_description)) {
      out.push({ class: "content-quality", catalog: "cve-catalog", id,
        field: "poc_description", reason: "poc_available:true but description carries placeholder sentinel" });
    }

    // KEV-listed CVEs MUST have vendor_advisories[] non-empty — the
    // KEV listing implies CISA has linked vendor advisory metadata.
    // Empty vendor_advisories is an operator-curation gap.
    if (e.cisa_kev === true && (!Array.isArray(e.vendor_advisories) || e.vendor_advisories.length === 0)) {
      out.push({ class: "content-quality", catalog: "cve-catalog", id,
        field: "vendor_advisories", reason: "cisa_kev:true but vendor_advisories is empty" });
    }

    // Name reused as description (catalog noise — operator didn't
    // write a real description, just echoed the name).
    if (typeof e.name === "string" && typeof e.description === "string"
        && e.name === e.description && e.name.length > 0) {
      out.push({ class: "content-quality", catalog: "cve-catalog", id,
        field: "description", reason: "description is just the name repeated" });
    }
  }
  return out;
}

// ---------- 2. temporal-staleness ----------
//
// Time-based decay. Catalog entries get stale as the threat-intelligence
// landscape shifts. Surfacing stale entries gives operators a re-verify
// work-queue.

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

    // CISA KEV due-date passed without remediation status — surfaces
    // operationally-stale CURATED entries the operator should re-verify.
    // Auto-imported drafts are excluded: a KEV due-date passing with wall-clock
    // time on the un-curated bulk-import backlog is expected (and grows the
    // count purely by calendar drift, which would mechanically breach the
    // budget gate on a no-op release). The finding is actionable only once the
    // entry is curated, so it is scoped to non-draft entries.
    const isDraft = e._auto_imported === true || e._draft === true;
    if (!isDraft && e.cisa_kev === true && typeof e.cisa_kev_due_date === "string") {
      const sinceDue = daysSince(e.cisa_kev_due_date, now);
      if (sinceDue !== null && sinceDue > 0) {
        out.push({ class: "temporal-staleness", catalog: "cve-catalog", id,
          field: "cisa_kev_due_date", reason: `CISA KEV due date passed ${sinceDue}d ago; verify remediation status` });
      }
    }

    // EPSS score has its own currency clock — FIRST recalculates daily.
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

// ---------- 3. logical-consistency ----------
//
// Internal-state rules that must hold across multiple fields. These are
// the bugs that pass schema validation (every required field is present)
// but the field combinations don't make sense.

function logicalConsistencyFindings(loaded) {
  const out = [];
  const cve = loaded["cve-catalog"];
  if (!cve) return out;

  for (const id of Object.keys(cve)) {
    if (id === "_meta") continue;
    const e = cve[id];
    if (!e) continue;

    // cisa_kev:true with null cisa_kev_date — KEV listing has a
    // dateAdded field in CISA's authoritative JSON; null means we
    // failed to record it at intake time.
    if (e.cisa_kev === true && (e.cisa_kev_date == null || e.cisa_kev_date === "")) {
      out.push({ class: "logical-consistency", catalog: "cve-catalog", id,
        rule: "cisa_kev_date_present_when_kev_true",
        reason: "cisa_kev:true requires cisa_kev_date (CISA's dateAdded)" });
    }

    // live_patch_available:true with empty live_patch_tools[] — the
    // RWEP live_patch_available factor only fires when tools list
    // names a real live-patch path; the boolean alone is a lie.
    if (e.live_patch_available === true
        && (!Array.isArray(e.live_patch_tools) || e.live_patch_tools.length === 0)) {
      out.push({ class: "logical-consistency", catalog: "cve-catalog", id,
        rule: "live_patch_tools_required_when_available",
        reason: "live_patch_available:true but live_patch_tools is empty — RWEP factor would mis-fire" });
    }

    // ai_discovered:true requires named AI tool in attribution_note
    // (Hard Rule #1 enforcement). The schema-validator catches
    // discovery_source==unknown but not the attribution-text absence.
    if (e.ai_discovered === true) {
      const note = e.ai_discovery_notes || e.discovery_attribution_note || "";
      if (typeof note !== "string" || note.length < 30) {
        out.push({ class: "logical-consistency", catalog: "cve-catalog", id,
          rule: "ai_discovery_attribution_text_required",
          reason: "ai_discovered:true but attribution text is missing or too short to name the AI tool" });
      }
    }

    // active_exploitation:"confirmed" with empty verification_sources
    // is a credibility gap — exploitation claims need sourcing.
    if (e.active_exploitation === "confirmed"
        && (!Array.isArray(e.verification_sources) || e.verification_sources.length < 2)) {
      out.push({ class: "logical-consistency", catalog: "cve-catalog", id,
        rule: "confirmed_exploitation_needs_sources",
        reason: `active_exploitation:"confirmed" requires >= 2 verification_sources; have ${(e.verification_sources || []).length}` });
    }

    // rwep_score declared but rwep_factors empty — score is unsupported.
    if (typeof e.rwep_score === "number"
        && (!e.rwep_factors || Object.keys(e.rwep_factors).length === 0)) {
      out.push({ class: "logical-consistency", catalog: "cve-catalog", id,
        rule: "rwep_factors_required_when_score_set",
        reason: "rwep_score declared but rwep_factors is empty — score is unjustified" });
    }
  }
  return out;
}

// ---------- 4. cross-ref-completeness ----------
//
// Bidirectional reference checks. Pre-v0.13.21, the dangling-ref class
// only verified the forward direction (CVE.cwe_refs[] resolves into
// cwe-catalog). This class verifies the BACK-reference is present too
// (CWE.evidence_cves[] includes the CVE that cited it).

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
    // Drafts excluded — auto-imported entries don't yet have curated
    // refs.
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

// ---------- 5. schema-evolution ----------
//
// Required-since-version checks. Fields the schema requires today were
// optional on entries added in older releases. The audit surfaces those
// pre-existing entries so operator-curation can backfill.

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

// ---------- 6. operator-action-sla ----------
//
// Auto-imported entries are intake-class events. The catalog allows them
// to ship un-curated (operators add detail later) but past a threshold
// the un-curated state IS the problem.

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

// ---------- 7. unused-orphan ----------
//
// Entries that no skill / playbook / CVE references — dead-weight
// content the operator can either repurpose or remove.

// Build reference sets from skills/*.md frontmatter + body and from
// data/playbooks/*.json content. Pre-v0.13.21 follow-up (codex P1 PR
// #61): unusedOrphanFindings defaulted these to empty sets, which
// flagged D3FEND / CWE / ATT&CK IDs referenced in skill bodies as
// "unused orphans" — false positive. v0.13.21+ builds the reference
// sets internally when the caller doesn't supply them.
//
// The regex is permissive — any CWE-NNN / T1234[.456] / AML.TNNNN /
// D3-XX / RFC-NNN token in a skill body or playbook JSON counts as a
// reference. We deliberately scan the FULL text, not just structured
// fields, because skill bodies cite IDs in prose ("see CWE-79") as
// often as in frontmatter.
const REFERENCE_TOKEN_RE = /\b(?:CWE-\d+|T\d{4}(?:\.\d{3})?|AML\.T\d{4}(?:\.\d{3})?|D3-[A-Z]+(?:-[A-Z]+)*|RFC-\d+)\b/g;

function buildExternalRefs(rootPath) {
  // Lazy require — `path` + `fs` are already in scope at module level.
  // Tolerate the absence of either directory (synthetic-test contexts
  // may not have a skills/ tree). Returns { skillRefs, playbookRefs }
  // as Sets of stringified IDs.
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
  // Auto-populate skill/playbook refs when the caller didn't supply
  // them. The composing runAllDetectors() also auto-populates via
  // _autoLoadRefs unless tests pin explicit empty sets.
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

  // CWE / ATT&CK / ATLAS / D3FEND / framework-gap entries that nothing
  // references are orphans. Operator-curated entries get a longer
  // grace period (intentional forward-looking content); auto-imported
  // entries with no reference are clearer waste.
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

// ---------- Composite ----------

function runAllDetectors(loaded, opts = {}) {
  // Pre-populate external reference sets ONCE and thread them through
  // every detector that needs them. Avoids re-scanning skills/ +
  // playbooks/ per detector and keeps the same reference set
  // consistent across the composed run.
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

// Canonical list of detection classes runAllDetectors can emit. The
// budget gate asserts class-set equality against this list so a future
// 8th detector added without a budget entry fails-closed (codex P2
// PR #61).
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
