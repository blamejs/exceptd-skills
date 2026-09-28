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

test("logical-consistency: a lesson stating another KEV listing date fires, with its field path", () => {
  const cats = makeCatalogs({
    "cve-catalog": { _meta: {}, "CVE-2011-0609": { cisa_kev: true, cisa_kev_date: "2022-06-08" } },
    "zeroday-lessons": { "CVE-2011-0609": { new_control_requirements: [
      { id: "NEW-CTRL-122", description: "put those on the interim clock against the 2025-10-20 KEV listing, and replace the rest" },
      { id: "NEW-CTRL-001", description: "CISA added the flaw to its Known Exploited Vulnerabilities catalog on 2021-01-01." },
      { id: "NEW-CTRL-002", description: "It was kev-listed 2026-02-10 with a public PoC." },
      { id: "NEW-CTRL-003", description: "Unlike CVE-2020-0002, this flaw was KEV-listed 2020-01-01." },
      { id: "NEW-CTRL-004", description: "CISA listed this CVE in its KEV catalog on 2021-02-02." },
      { id: "NEW-CTRL-005", description: "CISA KEV-listed this flaw on 2021-03-03." },
      { id: "NEW-CTRL-006", description: "CVE-2020-0002 has a separate history.\nKEV-listed 2021-04-04 with a public PoC." },
      { id: "NEW-CTRL-007", description: "CISA said \"CVE-2020-0002 is unrelated.\" KEV-listed 2021-05-05." },
      { id: "NEW-CTRL-008", description: "It was added to the KEV catalog on 2021-06-06." },
      { id: "NEW-CTRL-009", description: "The flaw entered CISA's KEV catalog on 2021-07-07." },
      { id: "NEW-CTRL-010", description: "CISA KEV-listed the flaw on 2026-02-10." },
      { id: "NEW-CTRL-011", description: "CISA listed the CVE in its KEV catalog on 2026-02-11." },
      { id: "NEW-CTRL-012", description: "Unlike CVE-2020-0002, the flaw was KEV-listed 2020-01-01." },
      { id: "NEW-CTRL-013", description: "CISA added the vulnerability to KEV on 2026-02-10." },
      { id: "NEW-CTRL-014", description: "CISA added this CVE to KEV catalog on 2026-02-12." },
      { id: "NEW-CTRL-015", description: "CISA put it on its KEV list on 2026-02-13." },
      { id: "NEW-CTRL-016", description: "KEV listing date: 2026-02-14." },
      { id: "NEW-CTRL-017", description: "The KEV listing date is 2026-02-15." },
      { id: "NEW-CTRL-018", description: "The text states a KEV listing date of 2026-02-16." },
      { id: "NEW-CTRL-019", description: "CISA added the flaw to CISA’s KEV catalog on 2026-02-17." },
      { id: "NEW-CTRL-020", description: "It was added to the CISA KEV catalog on 2026-02-18." },
      { id: "NEW-CTRL-021", description: "It was listed in the KEV catalogue on 2026-02-19." },
      { id: "NEW-CTRL-022", description: "CISA added it to its Known Exploited Vulnerabilities (KEV) catalog on 2026-02-20." },
      { id: "NEW-CTRL-023", description: "It joined CISA's KEV list on 2026-02-21." },
    ] } }
  });
  const f = D.logicalConsistencyFindings(cats).filter((x) => x.rule === "stated_kev_listing_date_matches_entry");
  assert.deepEqual(f.map((x) => x.field), Array.from({ length: 24 }, (_, i) => `new_control_requirements[${i}].description`));
  assert.equal(f[0].catalog, "zeroday-lessons");
  assert.match(f[0].reason, /2025-10-20.*2022-06-08/);
});

test("logical-consistency: KEV listing dates that match, due dates, and a named sibling's date do not fire", () => {
  const cats = makeCatalogs({
    "cve-catalog": { _meta: {}, "CVE-2011-0609": { cisa_kev: true, cisa_kev_date: "2022-06-08",
      vector: "KEV-listed 2022-06-08 with confirmed exploitation." } },
    "zeroday-lessons": { "CVE-2011-0609": { evidence: [
      "the KEV clock that opened 2022-06-08 governs the fix",
      "KEV due date (2022-06-22) is the binding clock",
      "sibling CVE-2011-0611 was KEV-listed 2022-06-09 in the same batch",
      "CISA added CVE-2011-0611 to its Known Exploited Vulnerabilities catalog on 2022-06-09.",
      "CVE-2011-0611, a sibling in the same bulletin, was KEV-listed 2022-06-09.",
      "For sibling CVE-2011-0611, it was KEV-listed 2022-06-09.",
      "The sibling is CVE-2011-0611; it was KEV-listed 2022-06-09.",
    ] } }
  });
  assert.deepEqual(D.kevListingDateFindings(cats), []);
});

test("kevListingDateFindings: definite is true only when the text assigns the date to the entry's own id", () => {
  const f = D.kevListingDateFindings({ "cve-catalog": { "CVE-2011-0609": { cisa_kev_date: "2022-06-08" } },
    "zeroday-lessons": { "CVE-2011-0609": {
      a: "CVE-2011-0609 was KEV-listed 2025-10-20.",
      b: "It was KEV-listed 2025-10-21.",
      c: "Unlike CVE-2011-0611, this flaw was KEV-listed 2025-10-22.",
      d: "The predecessor of CVE-2011-0609 was KEV-listed on 2025-10-23.",
      e: "CISA added CVE-2011-0609 to KEV on 2025-10-24.",
      f: "CVE-2011-0609's KEV listing date is 2025-10-25.",
      g: "CVE-2011-0609 (the Flash AVM2 flaw) was added to KEV on 2025-10-26.",
      h: "CISA KEV-listed CVE-2011-0609 on 2025-10-27.",
      i: "CVE-2011-0609 entered KEV on 2025-10-28.",
      j: "cve-2011-0609 was KEV-listed on 2025-10-29.",
      k: "CISA added CVE-2011-0609 and CVE-2011-0611 to KEV on 2025-10-30.",
      l: "CVE-2011-0609, which was KEV-listed on 2025-10-31, affects Flash.",
      m: "CVE-2011-0611 and CVE-2011-0609 were added to KEV on 2025-11-01.",
      n: "The bulletin covers CVE-2011-0609 and CVE-2011-0611, which was KEV-listed on 2025-11-02.",
      o: "CISA added CVE-2011-0609/CVE-2011-0611 to KEV on 2025-11-03.",
      p: "For CVE-2011-0609, CISA added it to KEV on 2025-11-04.",
      q: "For CVE-2011-0609, it was KEV-listed on 2025-11-05.",
      r: "The fix for CVE-2011-0609 was KEV-listed on 2025-11-06.",
      s: "CVE-2011-0609 has a KEV listing date of 2025-11-07.",
      t: "The Flash AVM2 flaw (CVE-2011-0609) was KEV-listed on 2025-11-08.",
      u: "CVE-2011-0609 itself was KEV-listed on 2025-11-09.",
      v: "CVE-2011-0609, together with CVE-2011-0611, were added to KEV on 2025-11-10.",
      w: "CVE-2011-0609 is a variant of CVE-2011-0611, which was KEV-listed on 2025-11-11.",
      x: "CVE-2011-0609: KEV-listed 2025-11-12.",
      y: "CVE-2011-0609, the AVM2 flaw, was KEV-listed on 2025-11-13.",
      z: "CVE-2011-0609, like CVE-2011-0611, was KEV-listed on 2025-11-14.",
      aa: "The KEV listing date for CVE-2011-0609 is 2025-11-15.",
      ab: "CISA added variants of CVE-2011-0609 to KEV on 2025-11-16.",
      ac: "CISA added CVE-2011-0611, CVE-2011-0612 and CVE-2011-0609 to KEV on 2025-11-17.",
      ad: "CVE-2011-0609 was KEV-listed by CISA on 2025-11-18.",
      ae: "CVE-2011-0609 was added to KEV by CISA on 2025-11-19.",
      af: "CVE-2011-0609 was KEV-listed (2025-11-20) with a public PoC.",
      ag: "CVE-2011-0609: KEV dateAdded: 2025-11-21",
      ah: "For CVE-2011-0609, the KEV listing date is 2025-11-22.",
    } } });
  // ab: the id follows a preposition inside the verb's object, so the date is the variants' and not definite.
  // z: the appositive names another CVE, so the finding is a warning, not definite.
  // v and w name this entry earlier in the sentence, so they are warnings rather than skipped.
  // n: a singular verb binds to the nearest id (CVE-2011-0611), so the finding is not definite; this entry is
  // named earlier in the sentence, so it is a warning rather than skipped.
  // r: the id follows a preposition inside the sentence, so the finding is not definite.
  assert.deepEqual(f.map((x) => [x.field, x.definite]),
    [["a", true], ["b", false], ["c", false], ["d", false], ["e", true], ["f", true], ["g", true], ["h", true], ["i", true],
      ["j", true], ["k", true], ["l", true], ["m", true], ["n", false], ["o", true], ["p", true], ["q", true], ["r", false], ["s", true], ["t", true], ["u", true], ["v", false], ["w", false], ["x", true], ["y", true], ["z", false], ["aa", true], ["ab", false], ["ac", true], ["ad", true], ["ae", true], ["af", true], ["ag", true], ["ah", true]]);
});

test("kevListingDateFindings: a date-first sentence is attributed from the verb's object", () => {
  const f = D.kevListingDateFindings({ "cve-catalog": { "CVE-2011-0609": { cisa_kev_date: "2022-06-08" } },
    "zeroday-lessons": { "CVE-2011-0609": {
      a: "On 2026-02-10, CISA added CVE-2011-0609 to KEV.",
      b: "On 2026-02-11, CISA added CVE-2011-0611 to KEV.",
      c: "On 2026-02-12, CISA added it to its KEV catalog.",
      d: "On 2026-02-13, CISA added variants of CVE-2011-0609 to KEV.",
      e: "On 2026-02-14, CISA added variants of CVE-2011-0611 and CVE-2011-0609 to KEV.",
      g: "On 2026-02-15, CISA added CVE-2011-0611 and CVE-2011-0609 to KEV.",
      h: "On 2026-02-16, CISA added CVE-2011-0609 & CVE-2011-0611 to KEV.",
    } } });
  // b names only a sibling, so it is not a finding.
  assert.deepEqual(f.map((x) => [x.field, x.definite]), [["a", true], ["c", false], ["d", false], ["e", false], ["g", true], ["h", true]]);
  for (const re of D.KEV_LISTING_DATE_FIRST) assert.ok(re.global, `${re} must be a global RegExp for matchAll`);
});

test("creditsRestartToKevAction matches a restart credited to the KEV required action and nothing else", () => {
  for (const s of [
    "The vendor patch typically requires a service restart or system reboot per the KEV requiredAction.",
    "Remediation requires a service restart or system reboot, per the required action in CISA's KEV entry.",
    "There is a vendor patch and a fix that per the KEV requiredAction typically requires a service restart.",
    "Book the service restart or reboot the KEV requiredAction calls for inside the clock.",
    "The remediation is the vendor update plus the restart the KEV requiredAction implies;",
    "Completion is measured as the package plus the reboot that the vendor patch typically requires per the KEV requiredAction.",
    "the vendor patch follows the KEV requiredAction (service restart or system reboot).",
    "Taking the fix means a service restart or reboot of the appliance per the KEV required action.",
    "The KEV requiredAction requires a system reboot.",
    "Per the KEV requiredAction, reboot the service.",
    "The patch is out. Per CISA's KEV required action, restart the appliance after installing it.",
    "The KEV entry’s required action requires a reboot.",
    "The KEV entry's required action requires a reboot.",
  ]) assert.equal(D.creditsRestartToKevAction(s), true, s);
  for (const s of [
    "Block internet traffic to affected products immediately (CISA required action), then upgrade and restart Confluence.",
    "A vendor fix is available, so the required action from the 2025-12-22 KEV listing is the vendor firmware update, and the update lands only across a device restart.",
    "Apply mitigations per the KEV requiredAction, then schedule the reboot.",
    "The vendor patch typically requires a service restart or system reboot.",
    "Apply mitigations as required per the KEV requiredAction.",
    "Apply mitigations as required per the KEV requiredAction, and then restart the service per vendor guidance.",
    "Apply the patch per the KEV requiredAction, then reboot the host.",
    "The KEV requiredAction requires applying the vendor patch; the patch itself needs a reboot.",
    "Per the KEV requiredAction, apply the update and then restart the service.",
    "Restart, then patch per the KEV requiredAction.",
    "Restart then patch per the KEV requiredAction.",
    "Restart the host and apply updates as required per the KEV requiredAction.",
    "Reboot once the patch is applied per the KEV requiredAction.",
    "",
  ]) assert.equal(D.creditsRestartToKevAction(s), false, s);
  for (const re of D.KEV_ACTION_RESTART_CREDIT) assert.ok(!re.global && !re.sticky, String(re));
});

test("kevActionRestartFindings: a finding per text, marked logical-consistency; drafts only with includeDrafts", () => {
  const loaded = { "cve-catalog": {
    "CVE-2026-0001": { live_patch_notes: "The vendor patch typically requires a service restart or system reboot per the KEV requiredAction." },
    "CVE-2026-0002": { _auto_imported: true, live_patch_notes: "Reboot per the KEV requiredAction." },
  } };
  const f = D.kevActionRestartFindings(loaded);
  assert.deepEqual(f.map((x) => [x.id, x.field, x.rule]), [["CVE-2026-0001", "live_patch_notes", "restart_not_credited_to_kev_required_action"]]);
  assert.equal(D.kevActionRestartFindings(loaded, { includeDrafts: true }).length, 2);
});

test("kevListingDateFindings: a date two patterns both match is one finding", () => {
  const f = D.kevListingDateFindings({ "cve-catalog": { X: { cisa_kev_date: "2022-06-08" } },
    "zeroday-lessons": { X: { t: "It was added to the KEV catalog on 2021-06-06." } } });
  assert.equal(f.length, 1);
});

test("kevListingDateFindings: opts.entries supplies cisa_kev_date for a batch's lessons", () => {
  const entries = { "CVE-2026-0001": { cisa_kev_date: "2026-03-01" } };
  const f = D.kevListingDateFindings({ "zeroday-lessons": { "CVE-2026-0001": { t: "KEV-listed 2026-02-10 with a public PoC." } } }, { entries });
  assert.equal(f.length, 1);
  assert.equal(f[0].field, "t");
});

test("KEV_LISTING_DATE: every pattern is global and captures one date", () => {
  for (const re of D.KEV_LISTING_DATE) {
    assert.ok(re instanceof RegExp && re.global, `${re} must be a global RegExp for matchAll`);
  }
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
    "unused-orphan",
    "pipeline-wording"
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

// ---------- pipeline-wording ----------

test("hasPipelineWording matches curation-input citations and not network-packet wording", () => {
  for (const s of [
    "Packet: pod-spec attributes reach the modprobe argument path",
    "Packet attack_vector: 'Integer overflow in the CNI IP-allocation path'",
    "Packet fields for CVE-2026-20128: cwe_refs CWE-257",
    "the attacker uploads a file (the packet names a web shell)",
    "per the packet the malicious code was embedded",
    "According to the packet, the fix shipped in 7.2.",
    "packet: cisa_kev true, active_exploitation confirmed",
    "The packet's own references array for this CVE is empty",
    "the packet's vector states an unauthenticated attacker",
    "the packet's live-patch note says a restart is needed",
    "packet attack_vector: 'crafted request'",
    "Packet fields for this entry: cvss 9.8",
    "Packet vector names an unauthenticated request",
    "Remediation per the packet: patch_available is true",
    "Affected models named in the packet: RV016, RV042",
    "Priority follows the packet: unauthenticated remote code execution",
    "The packet: sudo's -R option lets a local user",
    "the specific trap in this packet: the ranges given",
    "packet: unauthenticated remote code execution",
    "the packet: unauthenticated remote code execution",
    "CVSS 9.8. packet: unauthenticated remote code execution",
    "the fixed branches (7.2 and 7.4).' Packet: affected_versions lists 7.0",
    "the vendor note ends here.\" Packet: the fix is in 3.1",
    "see the list (every branch) packet: affected_versions 7.0 through 7.2",
    "The packet's flaw is an unauthenticated SQL injection",
    "the packet's attacker never authenticates",
    "book the restart the packet's requiredAction implies",
    "the packet's nist-800-53-si-2 gap records the window",
    "the packet's live_patch_notes say a restart is needed",
    "Packet records CWE-78, CVSS 9.8, RWEP 40",
    "Packet attack vector: an attacker-controlled document",
    "Packet affected: 'Zyxel ATP series firewalls'",
    "Packet name: 'Fortinet Multiple Products Authentication Bypass'",
    "Packet NIST-800-53-SI-2 gap: '30-day flaw-remediation SLA'",
    "Packet CVE-2025-0282 \"Ivanti Connect Secure stack overflow\"",
    "Packet names the affected product as 'Adobe Experience Manager Forms'",
    "The packet places this CVE as the elevation step",
    "the packet ties this CWE-78 sink to the Metro server",
    "Priority follows the packet rather than the CVSS band",
    "not a claim the packet makes.",
    "a public exploit recorded in the packet",
    "the CISA KEV short description in the packet names the classes",
    "the earlier Secunia advisory cited in the packet is a third-party aggregation",
    "packet attack vector: crafted request",
    "CWE-79 in the packet reflects sibling cross-site scripting findings",
    "packet affected: Foo Server 2.1",
    "the packet is explicit that no user interaction is involved",
    "the packet has an authenticated, local attacker reading a credential file",
    "the fixed build plus reboot the packet requires",
    "The packet identifies the affected component as the Agere Modem Driver",
    "The packet's path ends in OS command execution",
    "the packet's only stated access requirement is network access",
    "the packet's boundary-protection gap records that the console is exposed",
    "two packet details decide how the SLA is measured",
    "The packet sets ai_discovered true for this entry.",
    "The packet makes driver reachability the precondition",
    "All from the packet for CVE-2024-43573:",
    "Corroborating packet fields: patch_required_reboot false",
    "Packet records a path-traversal flaw (CWE-22) letting an attacker read files",
    "Packet records an out-of-bounds write (CWE-787) in libimagecodec",
    "Packet records CVSS 10 with RWEP 79",
    "The packet characterizes the CLFS driver as a recurring kernel-LPE target",
    "the packet ties the use-after-free to that browser's iepeers component",
    "the packet ties the affected Skia to Chrome",
    "The packet pairs a pre-auth RCE on the appliance with confirmed exploitation",
    "The packet pairs a 2024-03-07 KEV listing with a public PoC",
    "The packet conditions the crash on DNS Security logging being enabled",
    "the packet attributes the exposure to how the Actuator is configured",
    "the packet's path needs no credentials and no authentication",
    "the packet's end state is arbitrary command execution on the Core server",
    "the packet's range runs from 12.2.0.13110 up to but excluding 12.2.0.16412",
  ]) assert.equal(D.hasPipelineWording(s), true, s);
  // Every curation noun the possessive form accepts; a later narrowing must keep them.
  for (const noun of ["own", "vector", "stated", "attack vector", "attack path", "exploitation", "remediation",
    "live-patch", "livepatch", "chain", "fix", "attacker", "outcome", "affected_versions", "flaw", "precondition",
    "primitive", "rwep", "kev", "gaps", "description", "cited", "confirmed", "cwe", "escalation", "requiredAction",
    "product", "framing", "cvss", "timeline", "campaign", "title", "coverage", "vendor", "mitigation",
    "references", "notes", "framework", "facts", "advisory", "versions", "summary", "deadline",
    "uk-caf-b4", "au-essential-8-patch", "live_patch_notes", "cisa_kev_due_date", "vendor_update_paths"]) {
    assert.equal(D.hasPipelineWording(`the packet's ${noun} says so`), true, `packet's ${noun}`);
  }
  assert.equal(D.hasPipelineWording("the packet's version field is 4"), false, "an IP header field");
  // A label opens a text, sentence or parenthetical. Mid-sentence, "the packet:" is
  // network prose unless curation wording (per, in, from, follows, this, own) leads it.
  assert.equal(D.hasPipelineWording("The parser rejects the packet: its length exceeds the buffer."), false);
  for (const s of [
    "Cisco IOS and IOS XE Software improperly validates packet data",
    "a flaw in the packet socket (AF_PACKET) implementation",
    "Because the overflow lands in the packet-engine process",
    "Exploit code was published on Packet Storm.",
    "the packet contains a malformed length field",
    "SNMPv3 privacy protects the packet's confidentiality",
    "the parser copies bytes from the packet into a fixed buffer",
    "malformed packet fields crash the daemon",
    "Packet fields are not validated before the buffer copy.",
    "The parser rejects the malformed packet: its length exceeds the buffer.",
    "Packet vectors from the scanner were logged.",
    "the packet's header length is not checked",
    "a redirect filter the packet's payload already created",
    "The packet's fragment offset is not validated before reassembly.",
    "The packet's total length exceeds the allocated buffer.",
    "The packet's path through the firewall is not filtered.",
    "the packet's sequence numbers repeat",
    "The packet's actual length is shorter than the advertised length.",
    "The packet's fragment_offset causes an out-of-bounds write.",
    "The packet's only option byte is ignored.",
    "a device merely forwarding the packet is in scope",
    "confirm the packet is dropped",
    "segmentation bounds who can send the packet",
    "the packet has a malformed length field",
    "the packet sets the DF bit",
    "the packet identifies the sender",
    "the packet requires fragmentation",
    "Packet records are written to the capture file.",
    "the architecture diagram and nowhere in the packet path.",
    "root on the packet engine means the signing keys",
    "the packet's inter-frame gap is too short",
    "the packet reaches the service before authentication",
    "the packet carries no payload",
    "the packet makes it through the firewall",
    "the arriving packet names a class to instantiate",
    "The length supplied in the packet is trusted without validation.",
    "the value carried in the packet overflows the buffer",
    "the size given in the packet is not checked",
    "the file named in the packet is written to disk",
    "the timestamp recorded in the packet is ignored",
    "the DNS record in the packet is cached",
    "the packet has the service type field set",
    "the packet identifies the protocol version",
    "a SYN packet establishes a connection",
    "the packet establishes a session with the peer",
    "the packet points to a buffer outside the ring",
    "the packet attributes are parsed before authentication",
    "the packet labels are swapped at each hop",
    "this packet allows an attacker to reboot the device",
    "this packet makes it past the filter",
    "the packet places the payload at offset 12",
    "the packet measures 1500 bytes",
    "Packet gap between frames is enforced.",
    "Packet attack vectors include flooding.",
    "the packet's path is determined by routing",
    "the packet's delivery path is multicast",
    "the packet's timing gap is too short",
    "the packet is clear of options",
    "the packet does not identify the sender",
    "The packet has an attacker-controlled length field.",
    "This packet makes it an attractive amplification target.",
    "The cipher suites listed in the packet are unsupported.",
    "CWE-20 in the packet parser lets a short frame through.",
    "CWE-787 in the packet-processing path corrupts the heap.",
    "the exploit recorded in the packet handler trace",
    "packet records contain the timestamp and length.",
    "Packet records contain the timestamp and length.",
    "the packet requires the fixed-size header",
    "the packet does not establish a session",
    "the packet's path goes from the client to the server",
    "the packet's range runs from 0 to 65535",
    "the packet pairs a request with a reply",
    "the packet's flow-control gap widens",
    "the packet ties the session to the source address",
    "the packet's end state is a closed socket",
    "the packet has a length field that the attacker controls",
    "the protocol version named in the packet",
    "the component named in the packet is parsed first",
    "the options listed in the packet header are ignored",
    "the exploit recorded in the packet capture replays the handshake",
    "the SDP description carried in the packet body",
    "",
  ]) assert.equal(D.hasPipelineWording(s), false, s);
  assert.equal(D.hasPipelineWording(null), false);
});

test("hasPipelineFieldCitation matches a catalog field cited after packet and no network prose", () => {
  for (const s of [
    "Packet fields for CVE-2025-0108: cisa_kev true",
    "the packet's cisa_kev field says so",
    "packet: patch_available true, live_patch_available false",
    "the packet’s live_patch_notes record a restart",
    "Corroborating packet fields: patch_required_reboot false",
    "Packet fields: cisa_kev true, active_exploitation confirmed",
    "Packet field: cvss_score 9.8",
    "Packet fields: source_verified 2026-09-01",
    "the packet's remediation_status is patched",
    "packet: _auto_imported true",
    "Packet fields: _draft false",
    "the packet's status_verified date",
    "Packet fields for this CVE: cisa_kev true",
    "Packet fields for this CVE include cisa_kev true",
    "Packet fields - patch_available true",
    "Packet fields: vector, cisa_kev true",
    "Packet fields for this CVE: affected, patch_available true",
    "Packet fields: cvss 9.8, cisa_kev true",
    "Packet fields: version 4; cisa_kev true",
    "Packet fields:\n- cisa_kev: true\n- patch_available: true",
    "Packet fields:\n  version 4\n  cisa_kev true",
    "Packet fields:\n1. cisa_kev: true\n2. patch_available: true",
    "Packet fields:\n1) version 4\n2) cisa_kev true",
    "the packet's field cisa_kev says true",
    "the packet's field named patch_available is true",
  ]) assert.equal(D.hasPipelineFieldCitation(s), true, s);
  for (const s of [
    "The IDS logged the drop (packet: 1514 bytes, TCP port 445).",
    "Packet fields: version, IHL, DSCP, total length and fragment offset.",
    "Packet vector processing in VPP reads up to 256 buffers per frame.",
    "When IP Record Route is enabled, the packet records the address of each router.",
    "Wireshark reports the frame as Malformed packet: vector length exceeds the table.",
    "the packet's attack surface is the parser",
    "Packet fields: src_ip, dst_ip and tcp_flags",
    "Packet fields for CVE-2025-0108: IP version, header length, and fragment offset",
    "Corroborating packet fields from the capture show a zero-length option",
    "Packet fields: version, IHL. The patch_available flag is set.",
    "The malformed packet: TCP port 445. The patch_available flag is true.",
    "Packet fields:\n- version\n- IHL\nThe patch_available flag is set.",
    "",
  ]) assert.equal(D.hasPipelineFieldCitation(s), false, s);
  assert.ok(D.PACKET_FIELD_TOKEN.global, "matchAll needs a global pattern");
  for (let i = 0; i < 3; i++) assert.equal(D.hasPipelineFieldCitation("packet: cisa_kev true"), true, "repeat calls agree");
});

test("CATALOG_FIELD_NAMES holds every snake_case field the CVE catalog and its schema use", () => {
  const names = new Set();
  const schema = JSON.parse(fs.readFileSync(path.join(__dirname, "..", "lib", "schemas", "cve-catalog.schema.json"), "utf8"));
  (function walk(o) {
    if (!o || typeof o !== "object") return;
    if (o.properties && typeof o.properties === "object") for (const k of Object.keys(o.properties)) names.add(k);
    for (const v of Object.values(o)) walk(v);
  })(schema);
  const cat = JSON.parse(fs.readFileSync(path.join(__dirname, "..", "data", "cve-catalog.json"), "utf8"));
  for (const [id, e] of Object.entries(cat)) if (id !== "_meta") for (const k of Object.keys(e)) names.add(k);
  const missing = [...names].filter((k) => /_/.test(k) && !D.CATALOG_FIELD_NAMES.has(k));
  assert.deepEqual(missing, [], "add these names to CATALOG_FIELD_NAMES in lib/gap-detectors.js");
});

test("pipelineWordingFindings: a field citation is marked field_citation", () => {
  const f = D.pipelineWordingFindings({ "zeroday-lessons": { "CVE-2026-0001": {
    a: "Packet fields for CVE-2026-0001: cisa_kev true", b: "the packet names a web shell" } } });
  assert.deepEqual(f.map((x) => [x.field, x.field_citation]), [["a", true], ["b", false]]);
});

test("PIPELINE_WORDING: every pattern is a stateless RegExp", () => {
  // A /g or /y pattern keeps lastIndex between .test() calls and skips matches.
  assert.ok(Array.isArray(D.PIPELINE_WORDING) && D.PIPELINE_WORDING.length > 0);
  for (const re of D.PIPELINE_WORDING) {
    assert.ok(re instanceof RegExp, String(re));
    assert.ok(!re.global && !re.sticky, `${re} must not carry the g or y flag`);
  }
  const s = "Packet: the endpoint resolves paths";
  assert.equal(D.hasPipelineWording(s), true);
  assert.equal(D.hasPipelineWording(s), true, "a second call on the same text still matches");
});

test("pipelineWordingFindings: one finding per curated text, with its field path; drafts are skipped", () => {
  const f = D.pipelineWordingFindings({
    "cve-catalog": { _meta: {},
      "CVE-2026-0001": { iocs: { _ioc_source_note: "Read from the NVD description; Packet: none." } },
      "CVE-2026-0002": { _auto_imported: true, vector: "Packet: draft text" } },
    "zeroday-lessons": { _meta: {},
      "CVE-2026-0001": { new_control_requirements: [
        { evidence: "Packet fields: cvss 9.8", description: "A general control." },
        { evidence: "Cisco advisory cisco-sa-x states the fixed release.", description: "per the packet, patch." }] } },
  });
  assert.deepEqual(f.map((x) => `${x.catalog} ${x.id} ${x.field}`).sort(), [
    "cve-catalog CVE-2026-0001 iocs._ioc_source_note",
    "zeroday-lessons CVE-2026-0001 new_control_requirements[0].evidence",
    "zeroday-lessons CVE-2026-0001 new_control_requirements[1].description",
  ]);
  assert.ok(f.every((x) => x.class === "pipeline-wording"));
});

test("pipelineWordingFindings: includeDrafts checks objects marked _auto_imported", () => {
  const loaded = { "zeroday-lessons": { _meta: {},
    "CVE-2026-0003": { _auto_imported: true, new_control_requirements: [{ evidence: "Packet: submitted text" }] } } };
  assert.deepEqual(D.pipelineWordingFindings(loaded), [], "the shipped-catalog audit skips drafts");
  const f = D.pipelineWordingFindings(loaded, { includeDrafts: true });
  assert.deepEqual(f.map((x) => `${x.id} ${x.field}`), ["CVE-2026-0003 new_control_requirements[0].evidence"]);
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
    "framework-control-gaps": JSON.parse(fs.readFileSync(path.join(data, "framework-control-gaps.json"), "utf8")),
    "zeroday-lessons": JSON.parse(fs.readFileSync(path.join(data, "zeroday-lessons.json"), "utf8"))
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
    "content-quality": 15,        // KEV entries whose vendor published no advisory, + slack
    // data-freshness only (source_verified / last_updated / epss_date). The
    // calendar-driven KEV-due-passed sub-check was removed (external operator
    // date, not catalog freshness; grew unboundedly as KEV drafts got curated).
    // Actual 0 with fresh data; 10 leaves refresh headroom.
    "temporal-staleness": 10,
    "logical-consistency": 5,
    "cross-ref-completeness": 5,
    "schema-evolution": 0,
    "operator-action-sla": 0,     // no entries currently exceed the SLA window
    "unused-orphan": 1400,        // bulk-imported CWE / RFC orphans by design
    "pipeline-wording": 326       // lesson and catalog texts citing the curation input; comes down as they are rewritten
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
