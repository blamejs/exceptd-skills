"use strict";

// ---- routed from attest-replay-and-discover-cwd ----
;(() => {
/**
 * Regression suite for the attestation-replay + discover-cwd + collect/lint
 * fixes:
 *   - reattest replays the ORIGINAL submission, so an unchanged session reports
 *     "unchanged" (it previously reported a false "drifted" every time).
 *   - discover honors --cwd (it previously scanned the process cwd silently).
 *   - collect warns on ANY failed precondition (not only empty-signal skips).
 *   - lint distinguishes a present-but-uncaptured required artifact from an
 *     absent one.
 *
 * Discipline: exact exit codes; value/type assertions paired with presence.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const { makeSuiteHome, makeCli, tryJson } = require("./_helpers/cli");
const SUITE_HOME = makeSuiteHome("exceptd-replayfix-");
const cli = makeCli(SUITE_HOME);

test("collect warns when a non-platform precondition fails (artifacts still emitted)", () => {
  // cicd-pipeline-compromise gathers workflow artifacts but gates on the
  // operator-owns-ci-fleet consent precondition, which is false without
  // --attest-ownership.
  const r = cli(["collect", "cicd-pipeline-compromise"]);
  assert.equal(r.status, 0);
  assert.match(r.stderr, /precondition not satisfied: operator-owns-ci-fleet/);
  assert.match(r.stderr, /block at preflight/);
});
})();
