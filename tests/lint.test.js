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

test("lint flags a present-but-uncaptured required artifact distinctly from an absent one", () => {
  const tmp = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'lint-uncaptured-')), 'ev.json');
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
})();
