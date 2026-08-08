"use strict";

/**
 * tests/check-ttp-references.test.js
 *
 * Subject coverage for the scripts/check-ttp-references.js predeploy gate.
 * Every file outside the two pinned MITRE catalogs that names a technique is
 * referring INTO them; the gate proves those references resolve, so a pin bump
 * cannot leave a retired id rendering in operator output (AGENTS.md Hard
 * Rule #4 — no orphaned controls).
 *
 *  - PASS contract (live): the shipped tree resolves;
 *  - the id pattern distinguishes ATLAS from ATT&CK, including the filename
 *    form where the namespace separator is a hyphen;
 *  - namespace shorthand ("AML.T0096 / T0017") is caught, since a bare T0017
 *    is a real and different ICS technique;
 *  - every allowlist entry carries a reason and still exists where it claims.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const ROOT = path.resolve(__dirname, "..");
const SCRIPT = path.join(ROOT, "scripts", "check-ttp-references.js");
const { TTP_PATTERN, NOT_REFERENCES, loadKnownIds } = require(SCRIPT);

function matches(text) {
  const re = new RegExp(TTP_PATTERN.source, "g");
  return text.match(re) || [];
}

test("every technique referenced in the shipped tree resolves against the pinned catalogs", () => {
  const r = spawnSync(process.execPath, [SCRIPT], { encoding: "utf8" });
  assert.equal(r.status, 0, `${r.stdout || ""}${r.stderr || ""}`);
  assert.match(r.stdout, /every referenced technique resolves/);
});

test("an ATLAS id is read whole, not as a bare ATT&CK id hiding inside it", () => {
  assert.deepEqual(matches("see AML.T0017 for detail"), ["AML.T0017"]);
  assert.deepEqual(matches("see AML.T0115.000 for detail"), ["AML.T0115.000"]);
});

test("the ATLAS namespace is recognised with a hyphen separator, as used in filenames", () => {
  // AML-T0051-prompt-injection.md must not read as bare ATT&CK T0051.
  assert.deepEqual(matches("AML-T0051-prompt-injection.md"), []);
});

test("a genuinely bare ATT&CK id is still matched", () => {
  assert.deepEqual(matches("mitigates T1059.001 on the host"), ["T1059.001"]);
});

test("namespace shorthand leaves the trailing ids bare, which is why it is a defect", () => {
  // The gate's job: T0017 here means AML.T0017, but reads as the ICS technique.
  assert.deepEqual(matches("AML.T0096 / T0017"), ["AML.T0096", "T0017"]);
});

test("each allowlisted token carries a reason and still occurs where it claims to", () => {
  for (const entry of NOT_REFERENCES) {
    assert.ok(entry.why && entry.why.length > 20, `${entry.id} needs a stated reason`);
    const f = path.join(ROOT, entry.file);
    assert.ok(fs.existsSync(f), `${entry.file} no longer exists — drop the stale allowlist entry`);
    assert.ok(
      fs.readFileSync(f, "utf8").includes(entry.id),
      `${entry.id} no longer occurs in ${entry.file} — drop the stale allowlist entry`
    );
  }
});

test("the pinned catalogs are the definition source and are not scanned as referrers", () => {
  const known = loadKnownIds();
  assert.ok(known.size > 900, `expected the pinned catalogs to define most ids, got ${known.size}`);
  assert.ok(known.has("T1059"), "ATT&CK ids missing from the known set");
  assert.ok(known.has("AML.T0115"), "ATLAS ids missing from the known set");
  assert.ok(!known.has("_meta"), "_meta must not be treated as a technique id");
});

test("scan() reports which files name an id the pinned catalogs do not define", () => {
  const { scan } = require(SCRIPT);
  const live = scan();
  assert.equal(live.unresolved.size, 0, `unresolved: ${[...live.unresolved.keys()].join(", ")}`);
  assert.ok(live.knownCount > 900, `expected the pinned catalogs, got ${live.knownCount}`);
});

test("TTP_PATTERN is global, so a file with several references yields all of them", () => {
  // Without the /g flag the scanner would report only the first id per file.
  assert.ok(TTP_PATTERN.global, "the scanner relies on repeated exec() over each file");
  const re = new RegExp(TTP_PATTERN.source, "g");
  assert.deepEqual("T1059 and AML.T0115.000 and T1685".match(re), ["T1059", "AML.T0115.000", "T1685"]);
});
