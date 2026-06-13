"use strict";

/**
 * Regression suite for a cluster found auditing the structured-bundle emitters
 * and the doctor subchecks:
 *
 *   CSAF threats text hard-coded "(CISA KEV)" for any confirmed-exploitation
 *     CVE, even when cisa_kev is false — operator-facing misattribution.
 *   SARIF/OpenVEX rendered the literal "null" for an unassessed blast_radius.
 *   SARIF cve_match results carried no locations, so GitHub Code Scanning
 *     silently dropped the highest-severity result class.
 *   An empty-vulnerabilities run emitted a csaf_security_advisory (Profile 4,
 *     where empty vulnerabilities is wrong) instead of csaf_informational.
 *   ci --format csaf/sarif/openvex wrapped documents in an exceptd envelope
 *     carrying a top-level `ok` key — invalid in all three standard formats.
 *   doctor --rfcs scraped table rows and undercounted the catalog, dropping
 *     non-RFC families; its freshness fields statted a nonexistent file.
 *
 * Discipline: exact values + types; presence paired with content.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");
const { ROOT, makeSuiteHome, makeCli, tryJson } = require("./_helpers/cli");

const cli = makeCli(makeSuiteHome("exceptd-bundledoc-"));

// sbom + package-matches-catalogued-cve fires CVE-2026-45321. The CSAF
// threats text once hard-coded "(CISA KEV)" for any confirmed-exploitation
// CVE; the invariant under test is that the attribution tracks the entry's
// live cisa_kev flag. The flag itself churns with reality (the automated
// KEV refresh flips it when CISA lists the CVE), so the assertion reads the
// catalog instead of pinning one value — pinning false broke the day CISA
// added the CVE to KEV.
const SBOM_CVE = JSON.stringify({ signal_overrides: { "package-matches-catalogued-cve": "hit" } });
const CVE_CATALOG = require(path.join(ROOT, "data", "cve-catalog.json"));
const MATCHED_ENTRY = CVE_CATALOG["CVE-2026-45321"];

test("CSAF threats text attributes '(CISA KEV)' if and only if the entry's cisa_kev flag is set", () => {
  const r = cli(["run", "sbom", "--evidence", "-", "--format", "csaf-2.0", "--json"], { input: SBOM_CVE });
  const doc = tryJson(r.stdout);
  assert.ok(doc && doc.document, "expected a CSAF document");
  const v = (doc.vulnerabilities || [])[0];
  assert.ok(v, "expected a vulnerability for the matched CVE");
  const details = (v.threats || []).map(t => t.details).join(" | ");
  if (MATCHED_ENTRY.active_exploitation === "confirmed") {
    assert.match(details, /Active exploitation confirmed/, "must state confirmed exploitation");
  }
  if (MATCHED_ENTRY.cisa_kev === true) {
    assert.match(details, /CISA KEV/, "must attribute to CISA KEV when cisa_kev is true");
  } else {
    assert.doesNotMatch(details, /CISA KEV/, "must NOT attribute to CISA KEV when cisa_kev is false");
  }
});

test("SARIF cve_match result carries locations and renders 'not assessed' for null blast_radius", () => {
  const r = cli(["run", "sbom", "--evidence", "-", "--format", "sarif", "--json"], { input: SBOM_CVE });
  const sarif = tryJson(r.stdout);
  assert.ok(sarif && sarif.version === "2.1.0", "expected SARIF 2.1.0");
  const results = sarif.runs?.[0]?.results || [];
  const cve = results.filter(x => x.properties?.kind === "cve_match");
  assert.ok(cve.length >= 1, "expected at least one cve_match result");
  for (const c of cve) {
    assert.ok(Array.isArray(c.locations) && c.locations.length >= 1, "cve_match result must carry locations (else GitHub Code Scanning drops it)");
    assert.ok(c.locations[0].physicalLocation?.artifactLocation?.uri, "location must have an artifact uri");
  }
  const withBlast = cve.find(c => /blast_radius/.test(c.message.text));
  assert.match(withBlast.message.text, /blast_radius not assessed/, "null blast_radius must render 'not assessed', not 'null'");
});

test("OpenVEX impact_statement renders 'not assessed' for null blast_radius (not 'null/5')", () => {
  const r = cli(["run", "sbom", "--evidence", "-", "--format", "openvex", "--json"], { input: SBOM_CVE });
  const vex = tryJson(r.stdout);
  assert.ok(vex && vex["@context"], "expected an OpenVEX document");
  const stmt = (vex.statements || []).find(s => /Blast radius/.test(s.impact_statement || ""));
  if (stmt) {
    assert.match(stmt.impact_statement, /Blast radius not assessed/, "null blast_radius must render 'not assessed'");
    assert.doesNotMatch(stmt.impact_statement, /null\/5/, "must not render 'null/5'");
  }
});

test("an empty-evidence run emits a csaf_informational_advisory, not a security_advisory with empty vulnerabilities", () => {
  const r = cli(["run", "crypto", "--evidence", "-", "--format", "csaf-2.0", "--json"], { input: '{"precondition_checks":{"linux-platform":true}}' });
  const doc = tryJson(r.stdout);
  assert.ok(doc && doc.document, "expected a CSAF document");
  assert.equal((doc.vulnerabilities || []).length, 0, "this run has no vulnerabilities");
  assert.equal(doc.document.category, "csaf_informational_advisory", "empty advisory must use the informational category");
});

test("a firing run still emits csaf_security_advisory", () => {
  const r = cli(["run", "sbom", "--evidence", "-", "--format", "csaf-2.0", "--json"], { input: SBOM_CVE });
  const doc = tryJson(r.stdout);
  assert.equal(doc.document.category, "csaf_security_advisory", "a run with vulnerabilities keeps the security-advisory category");
});

test("ci --format csaf emits a bare array of documents with no top-level 'ok' wrapper", () => {
  const r = cli(["ci", "--scope", "code", "--evidence", "-", "--format", "csaf", "--json"], { input: "{}" });
  const out = tryJson(r.stdout);
  assert.ok(Array.isArray(out), "ci --format csaf must emit a JSON array of documents");
  // A bare array carries no exceptd envelope keys (`ok` / `verb` / `bundles_count`).
  assert.ok(!("ok" in out), "the array must not carry an `ok` property (invalid in CSAF)");
  assert.ok(!("bundles_count" in out), "the array must not carry the old envelope's bundles_count");
});

test("doctor --rfcs counts the full catalog (incl. non-RFC families) with a by_prefix breakdown and real freshness", () => {
  const r = cli(["doctor", "--rfcs", "--json"]);
  const out = tryJson(r.stdout);
  const rfcs = out.checks?.rfcs;
  assert.ok(rfcs, "expected a rfcs check");
  assert.ok(typeof rfcs.total === "number" && rfcs.total >= 8888, `rfcs.total must count the whole catalog; got ${rfcs.total}`);
  assert.ok(rfcs.by_prefix && typeof rfcs.by_prefix === "object", "must expose a by_prefix breakdown");
  const sum = Object.values(rfcs.by_prefix).reduce((a, b) => a + b, 0);
  assert.equal(sum, rfcs.total, "by_prefix entries must sum to total");
  assert.ok("RFC" in rfcs.by_prefix && rfcs.by_prefix.RFC > 8000, "RFC family must dominate");
  // freshness must stat the real catalog file, not a nonexistent one
  assert.ok(typeof rfcs.index_age_days === "number", "index_age_days must be populated (real catalog file), not null");
});
