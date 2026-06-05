"use strict";

/**
 * Guards three places where an operator-facing CLI surface drifted from the
 * real behavior:
 *
 *   - attest diff's signal-override catalog fallback read the wrong phase
 *     (look.indicators is always undefined; indicators live under detect), so
 *     the empty-both total_compared count was 0 instead of the indicator count.
 *   - run's --directive/--explain/--signal-list were documented + consumed but
 *     absent from the flag allowlist, so the known_flags list omitted them and
 *     a typo could not be suggested.
 *   - the shared collector walkTree emitted native-separator rel paths, so
 *     Windows artifact summaries used backslashes while SARIF evidence
 *     locations used forward slashes for the same file.
 *
 * Discipline: exact exit codes; presence assertions paired with content/value
 * assertions; all writes confined to os.tmpdir().
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const { makeSuiteHome, makeCli, tryJson } = require("./_helpers/cli");
const { flagsFor, suggestFlag } = require("../lib/flag-suggest.js");
const runner = require("../lib/playbook-runner.js");
const { walkTree } = require("../lib/collectors/scan-excludes.js");

const SUITE_HOME = makeSuiteHome("exceptd-surface-drift-");
const cli = makeCli(SUITE_HOME);

const SIGNAL_PB = "secrets"; // cross-platform; detect.indicators non-empty

test("attest diff signal_override_diff.total_compared reflects detect.indicators for empty-both submissions", () => {
  const pb = runner.loadPlaybook(SIGNAL_PB);
  const indicatorCount = (pb.phases?.detect?.indicators || []).filter(i => i && i.id).length;
  assert.ok(indicatorCount > 0, "fixture playbook must have detect.indicators");

  const a = cli(["run", SIGNAL_PB, "--evidence", "-", "--session-id", "sigdrift-a"], { input: '{"artifacts":{},"signals":{}}' });
  assert.equal(a.status, 0, `setup run a failed: ${a.stderr.slice(0, 200)}`);
  const b = cli(["run", SIGNAL_PB, "--evidence", "-", "--session-id", "sigdrift-b"], { input: '{"artifacts":{},"signals":{}}' });
  assert.equal(b.status, 0, `setup run b failed: ${b.stderr.slice(0, 200)}`);

  const d = cli(["attest", "diff", "sigdrift-a", "--against", "sigdrift-b", "--json"]);
  assert.equal(d.status, 0, `attest diff failed: ${d.stderr.slice(0, 200)}`);
  const body = tryJson(d.stdout) || tryJson(d.stderr);
  assert.ok(body && body.signal_override_diff, `attest diff must carry signal_override_diff; got ${d.stdout.slice(0, 200)}`);
  // The empty-both fallback now counts the catalog indicators, not 0.
  assert.equal(body.signal_override_diff.total_compared, indicatorCount);
  assert.equal(body.signal_override_diff.unchanged_count, indicatorCount);
});

test("flagsFor('run') includes --directive/--explain/--signal-list and typos resolve", () => {
  const flags = flagsFor("run");
  for (const f of ["directive", "explain", "signal-list"]) {
    assert.ok(flags.includes(f), `run must accept --${f}`);
  }
  assert.equal(suggestFlag("explan", flags), "explain", "a --explain typo must resolve");
  assert.equal(suggestFlag("directiv", flags), "directive", "a --directive typo must resolve");
});

test("run's known_flags list (printed on an unknown flag) includes the documented run flags", () => {
  const r = cli(["run", "secrets", "--definitely-not-a-flag"]);
  assert.equal(r.status, 1);
  const err = tryJson(r.stderr) || tryJson(r.stdout);
  assert.ok(err, `expected an unknown-flag envelope; got ${r.stderr.slice(0, 200)}`);
  assert.ok(Array.isArray(err.known_flags), "known_flags must be an array");
  for (const f of ["--directive", "--explain", "--signal-list"]) {
    assert.ok(err.known_flags.includes(f), `known_flags must list ${f}; got ${JSON.stringify(err.known_flags)}`);
  }
});

test("walkTree emits forward-slash rel paths so artifact summaries match SARIF evidence locations", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "walk-rel-"));
  try {
    fs.mkdirSync(path.join(root, "src", "config"), { recursive: true });
    const target = path.join(root, "src", "config", "app.env");
    fs.writeFileSync(target, "TOKEN=x");
    const files = walkTree(root);
    const hit = files.find(f => f.name === "app.env");
    assert.ok(hit, "walkTree must surface the nested file");
    assert.equal(hit.rel, "src/config/app.env");
    assert.ok(!hit.rel.includes("\\"), "rel must not contain a backslash separator");
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});
