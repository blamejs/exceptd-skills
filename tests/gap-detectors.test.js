"use strict";

/**
 * tests/gap-detectors.test.js
 *
 * Pins each of the seven v0.13.21 extended detection classes against
 * synthetic catalog inputs. Each pin asserts the detector fires on the
 * shape it's designed to catch and does NOT fire on the inverse shape
 * (no false positives).
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");
const D = require(path.join(__dirname, "..", "lib", "gap-detectors.js"));

// ---------- helpers ----------

function makeCatalogs(overrides) {
  return Object.assign({
    "cve-catalog": { _meta: {} },
    "cwe-catalog": { _meta: {} },
    "attack-techniques": { _meta: {} },
    "atlas-ttps": { _meta: {} },
    "d3fend-catalog": { _meta: {} },
    "rfc-references": { _meta: {} },
    "framework-control-gaps": { _meta: {} },
    "zeroday-lessons": { _meta: {} }
  }, overrides);
}

// ---------- 1. content-quality ----------

test("content-quality: short vector field flagged", () => {
  const cats = makeCatalogs({
    "cve-catalog": { _meta: {}, "CVE-2026-0001": { vector: "short stub" } }
  });
  const f = D.contentQualityFindings(cats);
  assert.ok(f.some((x) => x.field === "vector" && x.id === "CVE-2026-0001"),
    "vector under 50 chars must surface");
});

test("content-quality: placeholder language in vector flagged", () => {
  const cats = makeCatalogs({
    "cve-catalog": { _meta: {}, "CVE-2026-0001": { vector: "Pending operator curation — see vendor advisory" } }
  });
  const f = D.contentQualityFindings(cats);
  assert.ok(f.some((x) => x.id === "CVE-2026-0001" && /placeholder/.test(x.reason)),
    "placeholder-language vector must surface");
});

test("content-quality: KEV-listed entry without vendor_advisories flagged", () => {
  const cats = makeCatalogs({
    "cve-catalog": { _meta: {}, "CVE-2026-0001": { vector: "a".repeat(60), cisa_kev: true, vendor_advisories: [] } }
  });
  const f = D.contentQualityFindings(cats);
  assert.ok(f.some((x) => x.id === "CVE-2026-0001" && x.field === "vendor_advisories"),
    "cisa_kev:true with empty vendor_advisories must surface");
});

test("content-quality: name-as-description flagged", () => {
  const cats = makeCatalogs({
    "cve-catalog": { _meta: {}, "CVE-2026-0001": { vector: "a".repeat(60), name: "Test CVE", description: "Test CVE" } }
  });
  const f = D.contentQualityFindings(cats);
  assert.ok(f.some((x) => x.field === "description" && /repeated/.test(x.reason)),
    "description echoing name must surface");
});

// ---------- 2. temporal-staleness ----------

test("temporal-staleness: source_verified older than threshold fires", () => {
  const cats = makeCatalogs({
    "cve-catalog": { _meta: {}, "CVE-2026-0001": { source_verified: "2024-01-01" } }
  });
  const f = D.temporalStalenessFindings(cats, { now: new Date("2026-05-19T00:00:00Z") });
  assert.ok(f.some((x) => x.id === "CVE-2026-0001" && x.field === "source_verified"),
    "source_verified > 180d must surface");
});

test("temporal-staleness: CISA KEV due-date passed without remediation surfaces", () => {
  const cats = makeCatalogs({
    "cve-catalog": { _meta: {}, "CVE-2026-0001": {
      cisa_kev: true, cisa_kev_due_date: "2026-04-01", source_verified: "2026-05-15"
    } }
  });
  const f = D.temporalStalenessFindings(cats, { now: new Date("2026-05-19T00:00:00Z") });
  assert.ok(f.some((x) => x.field === "cisa_kev_due_date"),
    "passed CISA KEV due date must surface");
});

test("temporal-staleness: fresh entry does NOT fire", () => {
  const cats = makeCatalogs({
    "cve-catalog": { _meta: {}, "CVE-2026-0001": {
      source_verified: "2026-05-15", last_updated: "2026-05-15",
      cisa_kev: false
    } }
  });
  const f = D.temporalStalenessFindings(cats, { now: new Date("2026-05-19T00:00:00Z") });
  assert.equal(f.length, 0, "fresh entry must not produce any temporal-staleness findings");
});

// ---------- 3. logical-consistency ----------

test("logical-consistency: cisa_kev:true with null cisa_kev_date fires", () => {
  const cats = makeCatalogs({
    "cve-catalog": { _meta: {}, "CVE-2026-0001": { cisa_kev: true, cisa_kev_date: null } }
  });
  const f = D.logicalConsistencyFindings(cats);
  assert.ok(f.some((x) => x.rule === "cisa_kev_date_present_when_kev_true"),
    "cisa_kev:true with null date must surface");
});

test("logical-consistency: live_patch_available:true with empty tools fires", () => {
  const cats = makeCatalogs({
    "cve-catalog": { _meta: {}, "CVE-2026-0001": {
      live_patch_available: true, live_patch_tools: []
    } }
  });
  const f = D.logicalConsistencyFindings(cats);
  assert.ok(f.some((x) => x.rule === "live_patch_tools_required_when_available"),
    "live_patch_available:true with empty tools must surface — RWEP factor would mis-fire");
});

test("logical-consistency: confirmed exploitation needs >= 2 verification_sources", () => {
  const cats = makeCatalogs({
    "cve-catalog": { _meta: {}, "CVE-2026-0001": {
      active_exploitation: "confirmed", verification_sources: ["https://only.one"]
    } }
  });
  const f = D.logicalConsistencyFindings(cats);
  assert.ok(f.some((x) => x.rule === "confirmed_exploitation_needs_sources"),
    "confirmed exploitation with < 2 sources must surface");
});

// ---------- 4. cross-ref-completeness ----------

test("cross-ref-completeness: CWE entry missing back-ref fires", () => {
  const cats = makeCatalogs({
    "cve-catalog": { _meta: {}, "CVE-2026-0001": {
      cwe_refs: ["CWE-79"]
    } },
    "cwe-catalog": { _meta: {}, "CWE-79": { evidence_cves: [] } }
  });
  const f = D.crossRefCompletenessFindings(cats);
  assert.ok(f.some((x) => x.target_id === "CWE-79" && /missing/.test(x.reason)),
    "CWE.evidence_cves missing back-ref must surface");
});

test("cross-ref-completeness: auto-imported CVEs excluded from check", () => {
  const cats = makeCatalogs({
    "cve-catalog": { _meta: {}, "CVE-2026-0001": {
      cwe_refs: ["CWE-79"], _auto_imported: true
    } },
    "cwe-catalog": { _meta: {}, "CWE-79": { evidence_cves: [] } }
  });
  const f = D.crossRefCompletenessFindings(cats);
  assert.equal(f.length, 0,
    "auto-imported CVE refs are excluded — operator-curation hasn't yet validated the ref direction");
});

// ---------- 5. schema-evolution ----------

test("schema-evolution: pre-v0.12.36 entry lacks ai_discovered fires", () => {
  const cats = makeCatalogs({
    "cve-catalog": { _meta: {}, "CVE-2026-0001": { /* missing ai_discovered */ } }
  });
  const f = D.schemaEvolutionFindings(cats);
  assert.ok(f.some((x) => x.field === "ai_discovered"),
    "missing ai_discovered (required since v0.12.36) must surface");
});

test("schema-evolution: post-bump entry passes", () => {
  const cats = makeCatalogs({
    "cve-catalog": { _meta: {}, "CVE-2026-0001": {
      ai_discovered: false, ai_assisted_weaponization: false,
      rwep_factors: { cisa_kev: 0, poc_available: 20 }
    } }
  });
  const f = D.schemaEvolutionFindings(cats);
  assert.equal(f.length, 0, "post-v0.12.36 shape passes");
});

// ---------- 6. operator-action-sla ----------

test("operator-action-sla: stale _auto_imported entry surfaces", () => {
  const cats = makeCatalogs({
    "cve-catalog": { _meta: {}, "CVE-2024-0001": {
      _auto_imported: true, last_updated: "2024-01-01"
    } }
  });
  const f = D.operatorActionSlaFindings(cats, { now: new Date("2026-05-19T00:00:00Z") });
  assert.ok(f.some((x) => /SLA/.test(x.reason)), "stale auto-import must surface");
});

test("operator-action-sla: fresh _auto_imported entry passes", () => {
  const cats = makeCatalogs({
    "cve-catalog": { _meta: {}, "CVE-2026-0001": {
      _auto_imported: true, last_updated: "2026-05-15"
    } }
  });
  const f = D.operatorActionSlaFindings(cats, { now: new Date("2026-05-19T00:00:00Z") });
  assert.equal(f.length, 0, "fresh auto-import within SLA window must not fire");
});

// ---------- 7. unused-orphan ----------

test("unused-orphan: auto-imported CWE referenced by no CVE / skill / playbook surfaces", () => {
  const cats = makeCatalogs({
    "cwe-catalog": { _meta: {}, "CWE-9999": { _auto_imported: true } }
  });
  const f = D.unusedOrphanFindings(cats, {});
  assert.ok(f.some((x) => x.id === "CWE-9999"), "orphan auto-imported CWE must surface");
});

test("unused-orphan: operator-curated entry is excluded (intentional content)", () => {
  const cats = makeCatalogs({
    "cwe-catalog": { _meta: {}, "CWE-1234": { /* no _auto_imported */ } }
  });
  const f = D.unusedOrphanFindings(cats, {});
  assert.equal(f.length, 0, "operator-curated catalog entries are intentional content; not flagged as orphans");
});

test("unused-orphan: forward_looking flag exempts the entry", () => {
  const cats = makeCatalogs({
    "framework-control-gaps": { _meta: {}, "ALL-AI-PIPELINE-INTEGRITY": {
      _auto_imported: true, forward_looking: true
    } }
  });
  const f = D.unusedOrphanFindings(cats, {});
  assert.equal(f.length, 0, "forward_looking entries are intentional forward-look content");
});

// ---------- composite ----------

test("runAllDetectors: composes all seven classes into one flat array", () => {
  const cats = makeCatalogs({
    "cve-catalog": { _meta: {}, "CVE-2026-0001": {
      vector: "short",
      cisa_kev: true, cisa_kev_date: null
    } }
  });
  const f = D.runAllDetectors(cats, { now: new Date("2026-05-19T00:00:00Z") });
  const classes = new Set(f.map((x) => x.class));
  assert.ok(classes.has("content-quality"), "content-quality must be in the union");
  assert.ok(classes.has("logical-consistency"), "logical-consistency must be in the union");
});

// ---------- placeholder + daysSince helpers ----------

test("hasPlaceholderLanguage detects TBD / pending / coming-soon sentinels", () => {
  assert.equal(D.hasPlaceholderLanguage("TBD"), true);
  assert.equal(D.hasPlaceholderLanguage("Pending operator curation."), true);
  assert.equal(D.hasPlaceholderLanguage("Coming soon."), true);
  assert.equal(D.hasPlaceholderLanguage("[]"), true);
  assert.equal(D.hasPlaceholderLanguage("Real exploitation primitive description."), false);
  assert.equal(D.hasPlaceholderLanguage(""), false);
  assert.equal(D.hasPlaceholderLanguage(null), false);
});

test("daysSince computes day-delta from ISO-8601 dates", () => {
  const now = new Date("2026-05-19T00:00:00Z");
  assert.equal(D.daysSince("2026-05-12", now), 7);
  assert.equal(D.daysSince("2025-05-19", now), 365);
  assert.equal(D.daysSince("not-a-date", now), null);
  assert.equal(D.daysSince(null, now), null);
});
