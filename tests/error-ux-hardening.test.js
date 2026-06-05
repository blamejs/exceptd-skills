"use strict";

/**
 * Error-UX hardening regression suite.
 *
 * Pins the operator-facing error improvements: a case-only playbook typo gets a
 * suggestion, input-validation errors are not mislabeled "internal error", the
 * `ask` verb points a CVE/RFC question at the resolver, and the CVE
 * malformed-id message is accurate for a short year (not just a non-numeric
 * tail). All offline + deterministic.
 *
 * Discipline: exact exit codes; value/type assertions paired with presence.
 */

const test = require("node:test");
const assert = require("node:assert/strict");

const { makeSuiteHome, makeCli, tryJson } = require("./_helpers/cli");
const SUITE_HOME = makeSuiteHome("exceptd-erruxe-");
const cli = makeCli(SUITE_HOME);

test("run SECRETS (case-only typo) → invalid-id error WITH a did-you-mean suggestion", () => {
  const r = cli(["run", "SECRETS"]);
  assert.equal(r.status, 1);
  const body = tryJson(r.stderr);
  assert.ok(body && body.ok === false, `expected ok:false body; got ${r.stderr.slice(0, 200)}`);
  assert.match(body.error, /invalid <playbook> id/);
  assert.match(body.error, /Did you mean: secrets\?/);
  assert.ok(Array.isArray(body.did_you_mean) && body.did_you_mean.includes("secrets"));
});

test("brief --scope bogus → a validation error, NOT an 'internal error / file a bug'", () => {
  const r = cli(["brief", "--scope", "bogus"]);
  assert.equal(r.status, 1);
  const body = tryJson(r.stderr);
  assert.ok(body && body.ok === false);
  assert.match(body.error, /--scope must be one of/);
  assert.doesNotMatch(body.error, /internal error/);
  assert.doesNotMatch(body.error, /file at https/);
  assert.equal(body.type, "validation_error");
});

test("ask with a CVE identifier points at `exceptd cve` on stderr", () => {
  const r = cli(["ask", "is CVE-2017-9006 a real cve"]);
  assert.equal(r.status, 0);
  assert.match(r.stderr, /exceptd cve CVE-2017-9006/);
});

test("ask with an RFC number points at `exceptd rfc` on stderr", () => {
  const r = cli(["ask", "what is RFC 9404 about"]);
  assert.equal(r.status, 0);
  assert.match(r.stderr, /exceptd rfc 9404/);
});

test("cve with a short year is reported as malformed, not 'non-numeric tail'", () => {
  const r = cli(["cve", "CVE-17-9006", "--air-gap", "--json"]);
  // fabricated/malformed format → exit 2 (won't stand up)
  assert.equal(r.status, 2);
  const body = tryJson(r.stdout);
  assert.ok(body && body.status === "fabricated");
  assert.match(body.reason, /canonical CVE-YYYY-NNNN form/);
  assert.doesNotMatch(body.reason, /non-numeric tail/);
});
