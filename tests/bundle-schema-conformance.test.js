"use strict";

/**
 * Regression suite for strict CSAF 2.0 / SARIF 2.1.0 schema-conformance fixes
 * (validated against the published schemas / profile mandatory tests):
 *
 *   CSAF 6.1.27.5 — every /vulnerabilities[] item carries `notes` (the
 *     CVE-keyed entries previously omitted it).
 *   CSAF 6.1.27.3 / §4.3 — a csaf_informational_advisory carries NO
 *     /vulnerabilities and no /product_tree.
 *   CSAF 6.1.27.2 — a csaf_informational_advisory carries /document/references
 *     with an external item.
 *   CSAF 6.1.16 + 6.1.30 — tracking.version equals the last revision_history
 *     number, and both use the same (semantic) versioning scheme.
 *   SARIF §3.27.9 — a result with kind:"informational" has level:"none"
 *     (not "note").
 *   SARIF artifactLocation.uri is a URI reference: a submission-supplied
 *     Windows backslash path is normalized to forward slashes.
 *
 * Discipline: exact field assertions tied to the cited rule.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const { makeSuiteHome, makeCli, tryJson } = require("./_helpers/cli");

const cli = makeCli(makeSuiteHome("exceptd-conformance-"));
const SBOM_CVE = JSON.stringify({ signal_overrides: { "package-matches-catalogued-cve": "hit" } });

test("CSAF: every CVE-keyed vulnerability carries notes (6.1.27.5)", () => {
  const doc = tryJson(cli(["run", "sbom", "--evidence", "-", "--format", "csaf-2.0", "--json"], { input: SBOM_CVE }).stdout);
  assert.equal(doc.document.category, "csaf_security_advisory");
  const cveVulns = (doc.vulnerabilities || []).filter(v => v.cve);
  assert.ok(cveVulns.length >= 1, "expected at least one CVE-keyed vulnerability");
  for (const v of cveVulns) {
    assert.ok(Array.isArray(v.notes) && v.notes.length >= 1, `CVE vuln ${v.cve} must carry notes`);
    assert.equal(typeof v.notes[0].text, "string");
  }
});

test("CSAF: tracking.version equals the last revision number, homogeneous versioning (6.1.16 + 6.1.30)", () => {
  const doc = tryJson(cli(["run", "sbom", "--evidence", "-", "--format", "csaf-2.0", "--json"], { input: SBOM_CVE }).stdout);
  const t = doc.document.tracking;
  const last = t.revision_history[t.revision_history.length - 1];
  assert.equal(t.version, last.number, "tracking.version must equal the last revision_history number");
  // Both must be the same scheme: semantic versioning (contains a dot) here.
  const isSemver = (s) => /^\d+\.\d+\.\d+/.test(s);
  assert.equal(isSemver(t.version), isSemver(last.number), "version and revision number must share a versioning scheme");
  assert.ok(isSemver(t.version), "this emitter uses semantic versioning for both");
});

test("CSAF: an informational advisory omits vulnerabilities + product_tree and carries an external reference", () => {
  const doc = tryJson(cli(["run", "crypto", "--evidence", "-", "--format", "csaf-2.0", "--json"], { input: "{}" }).stdout);
  assert.equal(doc.document.category, "csaf_informational_advisory");
  assert.ok(!("vulnerabilities" in doc), "informational advisory must NOT carry /vulnerabilities (6.1.27.3)");
  assert.ok(!("product_tree" in doc), "informational advisory must NOT carry /product_tree (§4.3)");
  assert.ok(Array.isArray(doc.document.references) && doc.document.references.length >= 1, "must carry /document/references (6.1.27.2)");
  assert.ok(doc.document.references.some(r => r.category === "external"), "must include an external reference");
});

test("SARIF: a kind:informational result has level:none, not note (§3.27.9)", () => {
  const sarif = tryJson(cli(["run", "sbom", "--evidence", "-", "--format", "sarif", "--json"], { input: SBOM_CVE }).stdout);
  const informational = (sarif.runs?.[0]?.results || []).filter(r => r.kind === "informational");
  assert.ok(informational.length >= 1, "expected at least one informational (framework-gap) result");
  for (const r of informational) {
    assert.equal(r.level, "none", "kind:informational requires level:none, never note/warning");
  }
});

test("SARIF: a submission-supplied backslash evidence path normalizes to a forward-slash URI", () => {
  const bs = String.fromCharCode(92);
  const sub = JSON.stringify({
    observations: { w: { captured: true, indicator: "publish-workflow-uses-static-token", result: "hit" } },
    evidence_locations: { "publish-workflow-uses-static-token": [["a", "b", "c.env"].join(bs), { uri: ["d", "e.txt"].join(bs), startLine: 2 }] },
  });
  const sarif = tryJson(cli(["run", "library-author", "--evidence", "-", "--format", "sarif", "--json"], { input: sub }).stdout);
  const uris = (sarif.runs?.[0]?.results || []).flatMap(r => (r.locations || []).map(l => l.physicalLocation?.artifactLocation?.uri));
  assert.ok(uris.length >= 1, "expected located results");
  for (const u of uris) {
    assert.ok(!u.includes(bs), `SARIF uri must use forward slashes (RFC 3986); got ${u}`);
  }
  assert.ok(uris.includes("a/b/c.env"), "the backslash string path must normalize to a/b/c.env");
});
