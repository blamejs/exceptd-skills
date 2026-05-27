"use strict";

/**
 * Regression suite for the refresh/flag-wiring cluster:
 *   - refresh --advisory <id> --air-gap refuses (no network egress) — the flag
 *     was previously parsed but dropped, so --air-gap leaked to the network.
 *   - --tlp stamps the CSAF distribution marking, validates against TLP 2.0,
 *     and is refused on info-only verbs (it was a silent no-op before).
 *   - refresh --advisory "" errors instead of silently running a full refresh.
 *
 * Deterministic + offline (the air-gap path refuses without touching the net).
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const { makeSuiteHome, makeCli, tryJson } = require("./_helpers/cli");

const cli = makeCli(makeSuiteHome("exceptd-refreshtlp-"));

test("refresh --advisory <id> --air-gap refuses instead of egressing", () => {
  const r = cli(["refresh", "--advisory", "CVE-2026-45321", "--air-gap"]);
  assert.equal(r.status, 2);
  assert.match(r.stderr, /air-gap/);
  assert.doesNotMatch(r.stdout, /advisory-seed-dry-run/);
});

test("refresh --advisory '' errors (does not fall through to a full refresh)", () => {
  const r = cli(["refresh", "--advisory", ""]);
  assert.equal(r.status, 2);
  const body = tryJson(r.stderr) || tryJson(r.stdout);
  assert.ok(body && body.ok === false);
  assert.match(body.error, /--advisory requires a non-empty identifier/);
});

test("--tlp stamps the CSAF distribution marking", () => {
  const r = cli(["run", "sbom", "--evidence", "-", "--tlp", "amber", "--format", "csaf-2.0"], { input: "{}" });
  assert.equal(r.status, 0);
  const csaf = tryJson(r.stdout);
  assert.ok(csaf && csaf.document, "expected a CSAF document");
  assert.ok(csaf.document.distribution, "CSAF distribution must be present with --tlp");
  assert.equal(csaf.document.distribution.tlp.label, "AMBER", "lowercase --tlp amber normalizes to AMBER");
  assert.equal(csaf.document.distribution.text, "TLP:AMBER");
});

test("--tlp rejects a non-TLP value", () => {
  const r = cli(["run", "sbom", "--evidence", "-", "--tlp", "BOGUS"], { input: "{}" });
  assert.equal(r.status, 1);
  const body = tryJson(r.stderr) || tryJson(r.stdout);
  assert.ok(body && body.ok === false);
  assert.match(body.error, /--tlp must be one of/);
});

test("--tlp is refused on an info-only verb (brief)", () => {
  const r = cli(["brief", "sbom", "--tlp", "AMBER"]);
  assert.equal(r.status, 1);
  const body = tryJson(r.stderr) || tryJson(r.stdout);
  assert.ok(body && body.ok === false);
  assert.match(body.error, /--tlp is irrelevant on this verb/);
});
