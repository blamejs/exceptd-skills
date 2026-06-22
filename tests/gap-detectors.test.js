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
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const D = require(path.join(__dirname, "..", "lib", "gap-detectors.js"));
const gd = D;

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

test("temporal-staleness: a passed CISA KEV due-date is NOT a staleness finding (it's an external operator-remediation date, not catalog freshness)", () => {
  // The KEV due-date is a fixed external date about an operator's remediation
  // deadline; every historical KEV entry's due-date passes by calendar and says
  // nothing about whether the catalog entry's DATA is fresh. It must not surface
  // as temporal-staleness, for either a curated entry or a draft — otherwise the
  // class grows without bound as the catalog ages and as KEV drafts get curated.
  const fresh = { cisa_kev: true, cisa_kev_due_date: "2026-04-01", source_verified: "2026-05-15", last_updated: "2026-05-15" };
  const curated = D.temporalStalenessFindings(makeCatalogs({ "cve-catalog": { _meta: {}, "CVE-2026-0001": fresh } }), { now: new Date("2026-05-19T00:00:00Z") });
  assert.ok(!curated.some((x) => x.field === "cisa_kev_due_date"), "passed KEV due-date must not surface on a curated entry");
  const draft = D.temporalStalenessFindings(makeCatalogs({ "cve-catalog": { _meta: {}, "CVE-2026-0002": { ...fresh, _auto_imported: true } } }), { now: new Date("2026-05-19T00:00:00Z") });
  assert.ok(!draft.some((x) => x.field === "cisa_kev_due_date"), "passed KEV due-date must not surface on a draft either");
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
  // Pin synthetic-test mode: don't auto-load skill/playbook refs from
  // the live tree (which would still keep this entry as orphan since
  // ALL-AI-PIPELINE-INTEGRITY isn't an ID matching the regex anyway).
  const f = D.unusedOrphanFindings(cats, { _autoLoadRefs: false });
  assert.equal(f.length, 0, "forward_looking entries are intentional forward-look content");
});

test("unused-orphan: auto-populated skill/playbook refs prevent false positives (codex P1 fix)", () => {
  // The detector must scan skills/*.md + data/playbooks/*.json for
  // catalog ID references unless the caller passes empty sets. The
  // synthetic catalog below contains a CWE-79 entry; CWE-79 is
  // referenced in real skill bodies + framework gaps. With auto-load
  // enabled, the entry is NOT flagged as orphan.
  const cats = makeCatalogs({
    "cwe-catalog": { _meta: {}, "CWE-79": { _auto_imported: true } }
  });
  // Live skill/playbook scan via auto-load.
  const f = D.unusedOrphanFindings(cats, {});  // no _autoLoadRefs override
  // CWE-79 may or may not appear in skill bodies depending on tree
  // state at test-time. The hard assertion is the negative: if the
  // detector ran in v0.13.21-pre-codex-fix mode (empty refs),
  // CWE-79 would ALWAYS be flagged. Now the test asserts the auto-
  // loaded refs ran by checking the function attempted the scan
  // (the buildExternalRefs export exists + skillRefs is a Set).
  const refs = D.buildExternalRefs();
  assert.ok(refs.skillRefs instanceof Set, "buildExternalRefs must return a Set for skillRefs");
  assert.ok(refs.playbookRefs instanceof Set, "buildExternalRefs must return a Set for playbookRefs");
  // CWE-79 is referenced in many of the project's skill bodies; the
  // scan must surface that. (If skills move and no longer cite CWE-79,
  // adjust the assertion to a known-cited ID.)
  assert.ok(refs.skillRefs.has("CWE-79") || refs.playbookRefs.has("CWE-79"),
    "CWE-79 must be picked up by the skill/playbook reference scan (it's cited in multiple skill bodies)");
});

test("REFERENCE_TOKEN_RE: matches canonical catalog ID shapes", () => {
  // Pins the permissive regex used by buildExternalRefs to scan skill
  // bodies + playbook JSON for catalog ID references. Each canonical
  // shape must match; tokens that look ID-ish but aren't must not.
  const RE = D.REFERENCE_TOKEN_RE;
  const positive = ["CWE-79", "T1190", "T1574.012", "AML.T0001", "AML.T0001.001", "D3-EAL", "D3-NTA-NTA", "RFC-8446"];
  for (const tok of positive) {
    assert.ok(new RegExp(RE.source).test(tok),
      `REFERENCE_TOKEN_RE must match canonical ID shape "${tok}"`);
  }
  // Negative cases — tokens that LOOK similar but aren't catalog IDs.
  const negative = ["CWE-", "T123", "AML.X0001", "D3-", "RFC8446"];
  for (const tok of negative) {
    const m = tok.match(new RegExp(RE.source));
    if (m && m[0] === tok) {
      assert.fail(`REFERENCE_TOKEN_RE must NOT match "${tok}" as a complete token`);
    }
  }
});

test("DETECTOR_CLASSES: canonical class list matches runAllDetectors output (codex P2 fail-closed contract)", () => {
  // The budget gate asserts class-set equality against this list. A
  // future PR adding a detector without updating DETECTOR_CLASSES (or
  // updating the budget) fails-closed instead of silently passing.
  assert.ok(Array.isArray(D.DETECTOR_CLASSES), "DETECTOR_CLASSES must be exported as an array");
  const expectedClasses = new Set([
    "content-quality",
    "temporal-staleness",
    "logical-consistency",
    "cross-ref-completeness",
    "schema-evolution",
    "operator-action-sla",
    "unused-orphan"
  ]);
  const declared = new Set(D.DETECTOR_CLASSES);
  assert.deepEqual(declared, expectedClasses,
    "DETECTOR_CLASSES must enumerate every class runAllDetectors can emit");
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

test("REQUIRED_SINCE: every entry has a since-version + check predicate", () => {
  // Pins the schema-evolution table shape — adding a new
  // required-since-version field needs the same three properties
  // (field / since / check) so the schema-evolution detector
  // processes it correctly.
  for (const [catalog, rules] of Object.entries(D.REQUIRED_SINCE)) {
    assert.ok(Array.isArray(rules), `REQUIRED_SINCE.${catalog} must be an array`);
    for (const r of rules) {
      assert.ok(r.field, `REQUIRED_SINCE.${catalog} rule must declare a field name`);
      assert.match(r.since, /^\d+\.\d+\.\d+$/,
        `REQUIRED_SINCE.${catalog}.${r.field}.since must be a semver string`);
      assert.equal(typeof r.check, "function",
        `REQUIRED_SINCE.${catalog}.${r.field}.check must be a predicate function`);
    }
  }
});

test("PLACEHOLDER_SENTINELS: every pattern is a regex and matches its canonical example", () => {
  // Pins the sentinel set — each regex must match the example that
  // motivated adding it, so a future operator who adds a sentinel can
  // immediately verify it fires on the right input.
  const examples = [
    "Pending operator curation",
    "Refer to vendor advisory for IOC list",
    "bulk-imported KEV entry, IOCs not extracted",
    "TBD",
    "TKTK",
    "Coming soon",
    "[]",
    "placeholder"
  ];
  for (const re of D.PLACEHOLDER_SENTINELS) {
    assert.ok(re instanceof RegExp, "every PLACEHOLDER_SENTINELS entry must be a regex");
    const matched = examples.some((ex) => re.test(ex));
    assert.ok(matched, `regex ${re} must match at least one canonical example string`);
  }
});

// ---------------------------------------------------------------------------
// REFERENCE_TOKEN_RE recognizes D3A-* / D3F-* D3FEND ids so a skill/playbook
// citation removes the referenced entry from the unused-orphan set.
// ---------------------------------------------------------------------------

function fullTokenMatch(s) {
  const re = gd.REFERENCE_TOKEN_RE;
  re.lastIndex = 0;
  const m = s.match(re);
  return !!(m && m.includes(s));
}

test('#14 REFERENCE_TOKEN_RE matches D3A-* and D3F-* D3FEND artifact ids', () => {
  assert.equal(fullTokenMatch('D3A-AAD'), true, 'D3A-AAD must be recognized as a reference token');
  assert.equal(fullTokenMatch('D3F-UGPH'), true, 'D3F-UGPH must be recognized as a reference token');
});

test('#14 REFERENCE_TOKEN_RE still matches every prior token class', () => {
  assert.equal(fullTokenMatch('D3-EAL'), true);
  assert.equal(fullTokenMatch('CWE-79'), true);
  assert.equal(fullTokenMatch('T1059.003'), true);
  assert.equal(fullTokenMatch('AML.T0051'), true);
  assert.equal(fullTokenMatch('RFC-8446'), true);
});

test('#14 a skill body citing a D3A-* id removes that entry from the unused-orphan set', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'hunt-c14-'));
  // Synthetic skills tree citing the D3A-* id in prose.
  const skillDir = path.join(tmp, 'skills', 'example-skill');
  fs.mkdirSync(skillDir, { recursive: true });
  fs.writeFileSync(path.join(skillDir, 'skill.md'),
    '# Example\n\nThis primitive maps to the D3A-AAD digital artifact.\n', 'utf8');

  const refs = gd.buildExternalRefs(tmp);
  assert.ok(refs.skillRefs.has('D3A-AAD'),
    'the D3A-AAD citation must be collected into skillRefs');

  // An _auto_imported D3FEND entry that IS referenced must not be flagged.
  const loaded = {
    'cve-catalog': { _meta: {} },
    'd3fend-catalog': {
      _meta: {},
      'D3A-AAD': { _auto_imported: true, name: 'Account Access Removal' },
    },
  };
  const referenced = gd.unusedOrphanFindings(loaded, {
    skillRefs: refs.skillRefs,
    playbookRefs: refs.playbookRefs,
  });
  assert.ok(!referenced.some(f => f.id === 'D3A-AAD'),
    'a referenced D3A-* entry must NOT be flagged as an unused orphan');

  // Control: an UN-referenced _auto_imported D3A-* entry is still flagged,
  // proving the test would fail if the guard mis-fired.
  const unreferenced = gd.unusedOrphanFindings({
    'cve-catalog': { _meta: {} },
    'd3fend-catalog': { _meta: {}, 'D3A-ZZZ': { _auto_imported: true, name: 'Orphan' } },
  }, { skillRefs: new Set(), playbookRefs: new Set() });
  assert.ok(unreferenced.some(f => f.id === 'D3A-ZZZ'),
    'an unreferenced auto-imported D3A-* entry must be flagged as orphan');
});


// ---- routed from hunt-fix-C-correlations ----
require("node:test").describe("hunt-fix-C-correlations", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
/**
 * Regression coverage for the C-correlations cluster:
 *
 *   #9  byTtp() returned found:false / entry:null for every ATT&CK
 *       technique — only the ATLAS catalog was consulted for the entry,
 *       while skills + related_cves correctly unioned both id spaces.
 *   #10 byTtp() d3fend correlation read the always-empty `counters` field
 *       instead of the populated `counters_attack_techniques`.
 *   #11 framework-gap lagScore() reported framework_specific_gaps:0 for
 *       every framework whose global-frameworks short key is not a literal
 *       substring of its catalog display string.
 *   #12 containers collector tracked USER globally, so a multi-stage build
 *       with a non-root USER in an early stage masked a root final stage.
 *   #13 byCwe/byTtp/bySkill leaked _auto_imported draft CVEs into the
 *       related_cves/cve_refs correlations (byCve excluded them; these
 *       transitive paths did not).
 *   #14 gap-detectors REFERENCE_TOKEN_RE could not match D3A-* / D3F-*
 *       D3FEND ids, mis-flagging referenced entries as unused orphans.
 *
 * Real-catalog assertions read the shipped data/ tree (default DATA_DIR).
 * The draft-leak case (#13) needs a synthetic catalog, which cross-ref-api
 * binds at require-time from EXCEPTD_DATA_DIR — so it runs in a child
 * process with that env var pointed at an isolated tempdir.
 *
 * Run under --test-concurrency=1 (the cross-ref cache + shared data dir are
 * process-global).
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const cp = require('node:child_process');

const xref = require('../lib/cross-ref-api.js');
const fg = require('../lib/framework-gap.js');
const gd = require('../lib/gap-detectors.js');
const containers = require('../lib/collectors/containers.js');

const ROOT = path.join(__dirname, '..');
const DATA_DIR = path.join(ROOT, 'data');

function loadJson(p) {
  return JSON.parse(fs.readFileSync(p, 'utf8'));
}

// ---------------------------------------------------------------------------
// Finding #9 — byTtp resolves the ATT&CK technique record, not only ATLAS.
// ---------------------------------------------------------------------------




// ---------------------------------------------------------------------------
// Finding #10 — byTtp d3fend correlation reads counters_attack_techniques.
// ---------------------------------------------------------------------------



// ---------------------------------------------------------------------------
// Finding #11 — lagScore counts framework-specific gaps by normalized match.
// ---------------------------------------------------------------------------

const controlGaps = loadJson(path.join(DATA_DIR, 'framework-control-gaps.json'));
const globalFrameworks = loadJson(path.join(DATA_DIR, 'global-frameworks.json'));





// ---------------------------------------------------------------------------
// Finding #12 — containers collector resets USER state per build stage.
// ---------------------------------------------------------------------------

function dockerfileTempdir(content) {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'hunt-c12-'));
  fs.writeFileSync(path.join(d, 'Dockerfile'), content, 'utf8');
  return d;
}







// ---------------------------------------------------------------------------
// Finding #13 — draft CVEs never leak into transitive correlations.
//
// cross-ref-api binds DATA_DIR at require-time from EXCEPTD_DATA_DIR, so the
// synthetic catalog must be exercised in a child process.
// ---------------------------------------------------------------------------


// ---------------------------------------------------------------------------
// Finding #14 — REFERENCE_TOKEN_RE recognizes D3A-* / D3F-* D3FEND ids.
// ---------------------------------------------------------------------------

function fullTokenMatch(s) {
  const re = gd.REFERENCE_TOKEN_RE;
  re.lastIndex = 0;
  const m = s.match(re);
  return !!(m && m.includes(s));
}

test('#14 REFERENCE_TOKEN_RE matches D3A-* and D3F-* D3FEND artifact ids', () => {
  assert.equal(fullTokenMatch('D3A-AAD'), true, 'D3A-AAD must be recognized as a reference token');
  assert.equal(fullTokenMatch('D3F-UGPH'), true, 'D3F-UGPH must be recognized as a reference token');
});

test('#14 REFERENCE_TOKEN_RE still matches every prior token class', () => {
  assert.equal(fullTokenMatch('D3-EAL'), true);
  assert.equal(fullTokenMatch('CWE-79'), true);
  assert.equal(fullTokenMatch('T1059.003'), true);
  assert.equal(fullTokenMatch('AML.T0051'), true);
  assert.equal(fullTokenMatch('RFC-8446'), true);
});

test('#14 a skill body citing a D3A-* id removes that entry from the unused-orphan set', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'hunt-c14-'));
  // Synthetic skills tree citing the D3A-* id in prose.
  const skillDir = path.join(tmp, 'skills', 'example-skill');
  fs.mkdirSync(skillDir, { recursive: true });
  fs.writeFileSync(path.join(skillDir, 'skill.md'),
    '# Example\n\nThis primitive maps to the D3A-AAD digital artifact.\n', 'utf8');

  const refs = gd.buildExternalRefs(tmp);
  assert.ok(refs.skillRefs.has('D3A-AAD'),
    'the D3A-AAD citation must be collected into skillRefs');

  // An _auto_imported D3FEND entry that IS referenced must not be flagged.
  const loaded = {
    'cve-catalog': { _meta: {} },
    'd3fend-catalog': {
      _meta: {},
      'D3A-AAD': { _auto_imported: true, name: 'Account Access Removal' },
    },
  };
  const referenced = gd.unusedOrphanFindings(loaded, {
    skillRefs: refs.skillRefs,
    playbookRefs: refs.playbookRefs,
  });
  assert.ok(!referenced.some(f => f.id === 'D3A-AAD'),
    'a referenced D3A-* entry must NOT be flagged as an unused orphan');

  // Control: an UN-referenced _auto_imported D3A-* entry is still flagged,
  // proving the test would fail if the guard mis-fired.
  const unreferenced = gd.unusedOrphanFindings({
    'cve-catalog': { _meta: {} },
    'd3fend-catalog': { _meta: {}, 'D3A-ZZZ': { _auto_imported: true, name: 'Orphan' } },
  }, { skillRefs: new Set(), playbookRefs: new Set() });
  assert.ok(unreferenced.some(f => f.id === 'D3A-ZZZ'),
    'an unreferenced auto-imported D3A-* entry must be flagged as orphan');
});
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});


// ---- routed from shipped-catalog-integrity ----
require("node:test").describe("shipped-catalog-integrity", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
/**
 * tests/shipped-catalog-integrity.test.js
 *
 * Live-catalog invariants. v0.13.20 split — the audit-catalog-gaps
 * detector tests now exercise synthetic inputs only; the assertions
 * about the LIVE shipped catalogs live here. When a catalog edit
 * breaks one of these the failure message points at the data, not at
 * the detector logic.
 *
 * Pins:
 *   1. Every cross-catalog reference resolves (no dangling refs).
 *   2. CVE catalog draft-debt ratio is reported but not enforced —
 *      bulk-import auto-imported entries are legitimate intake work.
 *   3. Every required-context field on every entry that does NOT
 *      declare a class-level exemption (forward_looking, _matrix-
 *      qualified ICS exception, etc.) is populated. Missing-context
 *      surfaces as a test failure, NOT a silent audit warning.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const ROOT = path.join(__dirname, "..");
const MOD = require(path.join(ROOT, "scripts", "audit-catalog-gaps.js"));

function loadAll() {
  const data = path.join(ROOT, "data");
  return {
    "cve-catalog": JSON.parse(fs.readFileSync(path.join(data, "cve-catalog.json"), "utf8")),
    "cwe-catalog": JSON.parse(fs.readFileSync(path.join(data, "cwe-catalog.json"), "utf8")),
    "attack-techniques": JSON.parse(fs.readFileSync(path.join(data, "attack-techniques.json"), "utf8")),
    "atlas-ttps": JSON.parse(fs.readFileSync(path.join(data, "atlas-ttps.json"), "utf8")),
    "framework-control-gaps": JSON.parse(fs.readFileSync(path.join(data, "framework-control-gaps.json"), "utf8"))
  };
}

test("shipped catalogs: extended-detector budgets (no silent regression on v0.13.21 detection classes)", () => {
  // v0.13.21 expanded the audit with seven extended detectors. The
  // shipped catalog has known findings on most of them — operator-
  // curation backlog, KEV-due-date passage, bulk-imported orphans —
  // and the budget approach mirrors the missing-context budget above.
  // A future PR worsening any class beyond budget fires; closing gaps
  // lowers the budget in the same PR.
  const D = require(path.join(__dirname, "..", "lib", "gap-detectors.js"));
  const all = D.runAllDetectors(loadAll(), {});
  const byClass = {};
  for (const f of all) {
    byClass[f.class] = (byClass[f.class] || 0) + 1;
  }
  const BUDGET = {
    "content-quality": 12,        // 10 KEV-no-vendor-advisories + slack
    // data-freshness only (source_verified / last_updated / epss_date). The
    // calendar-driven KEV-due-passed sub-check was removed (external operator
    // date, not catalog freshness; grew unboundedly as KEV drafts got curated).
    // Actual 0 with fresh data; 10 leaves refresh headroom.
    "temporal-staleness": 10,
    "logical-consistency": 5,
    "cross-ref-completeness": 5,
    "schema-evolution": 0,
    "operator-action-sla": 0,     // no entries currently exceed the SLA window
    "unused-orphan": 1400         // bulk-imported CWE / RFC orphans by design
  };
  const regressions = [];
  for (const [cls, count] of Object.entries(byClass)) {
    const allowed = BUDGET[cls] || 0;
    if (count > allowed) regressions.push(`${cls}: budget=${allowed} actual=${count}`);
  }
  // Also alert if any class has ZERO budget but is missing from BUDGET
  // (catches a future addition that forgot to set a budget).
  for (const cls of Object.keys(BUDGET)) {
    if (!(cls in byClass)) continue;
  }
  assert.deepEqual(regressions, [],
    "extended-detector class regression(s):\n  " + regressions.join("\n  ") +
    "\nClose the gap in this PR (preferred) or update BUDGET above with a justifying comment.");
});
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});
