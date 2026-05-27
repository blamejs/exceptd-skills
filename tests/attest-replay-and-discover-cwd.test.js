"use strict";

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

test("reattest reports 'unchanged' for an unchanged session (no false drift)", () => {
  const sid = "replayfix-base";
  const run = cli(["run", "secrets", "--evidence", "-", "--session-id", sid], { input: '{"artifacts":{},"signals":{}}' });
  assert.equal(run.status, 0, `setup run failed: ${run.stderr.slice(0, 200)}`);
  // --force-replay so the test runs on a host with OR without .keys/private.pem:
  // a key-less host writes an unsigned attestation, which reattest refuses to
  // replay without --force-replay. The replay-the-original fix under test is
  // independent of signing, so this exercises the same drift comparison either way.
  const r = cli(["reattest", sid, "--force-replay", "--json"]);
  const body = tryJson(r.stdout) || tryJson(r.stderr);
  assert.ok(body, `reattest must emit JSON; got stdout=${r.stdout.slice(0, 200)} stderr=${r.stderr.slice(0, 200)}`);
  assert.equal(body.status, "unchanged");
  assert.equal(body.prior_evidence_hash, body.replay_evidence_hash);
});

test("discover honors --cwd: an empty target dir yields no repo recommendations", () => {
  const empty = fs.mkdtempSync(path.join(os.tmpdir(), "exceptd-disc-empty-"));
  try {
    const r = cli(["discover", "--cwd", empty, "--json"]);
    assert.equal(r.status, 0);
    const body = tryJson(r.stdout);
    assert.ok(body && body.ok === true);
    const detected = body.detected_files || body.detected || [];
    assert.ok(Array.isArray(detected) && detected.length === 0,
      `empty dir should detect nothing; got ${JSON.stringify(detected)}`);
  } finally {
    fs.rmSync(empty, { recursive: true, force: true });
  }
});

test("discover --cwd to a nonexistent path errors cleanly (not silently ignored)", () => {
  const r = cli(["discover", "--cwd", path.join(os.tmpdir(), "exceptd-no-such-dir-xyz123"), "--json"]);
  assert.equal(r.status, 1);
  const body = tryJson(r.stderr);
  assert.ok(body && body.ok === false);
  assert.match(body.error, /--cwd .* does not exist/);
});

test("collect warns when a non-platform precondition fails (artifacts still emitted)", () => {
  // cicd-pipeline-compromise gathers workflow artifacts but gates on the
  // operator-owns-ci-fleet consent precondition, which is false without
  // --attest-ownership.
  const r = cli(["collect", "cicd-pipeline-compromise"]);
  assert.equal(r.status, 0);
  assert.match(r.stderr, /precondition not satisfied: operator-owns-ci-fleet/);
  assert.match(r.stderr, /block at preflight/);
});

test("lint flags a present-but-uncaptured required artifact distinctly from an absent one", () => {
  const tmp = path.join(os.tmpdir(), `lint-uncaptured-${Date.now()}.json`);
  // secrets requires `world-writable-secret-files`; supply it present but
  // captured:false (the shape a collector emits when it skips a platform probe).
  fs.writeFileSync(tmp, JSON.stringify({
    artifacts: { "world-writable-secret-files": { value: "skipped on win32", captured: false, reason: "POSIX mode bits not meaningful on Windows" } },
  }));
  try {
    const r = cli(["lint", "secrets", tmp, "--json"]);
    const body = tryJson(r.stdout);
    assert.ok(body, `lint must emit JSON; got ${r.stdout.slice(0, 200)}`);
    const kinds = (body.issues || []).filter(i => i.artifact_id === "world-writable-secret-files").map(i => i.kind);
    assert.ok(kinds.includes("uncaptured_required_artifact"),
      `expected uncaptured_required_artifact for a present captured:false artifact; got ${JSON.stringify(kinds)}`);
    assert.ok(!kinds.includes("missing_required_artifact"),
      "a present artifact must NOT be reported as missing");
  } finally {
    fs.rmSync(tmp, { force: true });
  }
});
