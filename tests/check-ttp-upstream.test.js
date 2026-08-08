"use strict";

/**
 * tests/check-ttp-upstream.test.js
 *
 * Subject: scripts/check-ttp-upstream.js — the upstream TTP-id validator.
 *
 * The regression these pin: nothing checked that the ids in the shipped TTP
 * mirrors are ids MITRE actually publishes. The ATLAS 2026.07 / ATT&CK 19.2 pin
 * bump found eleven that were not — five ATT&CK techniques revoked upstream
 * (already revoked in 19.1, the version pinned at the time, so they had shipped
 * revoked for a full release cycle) and six that appear in no upstream domain
 * at any version.
 *
 * The validator itself needs the network, so it runs in the refresh workflow
 * rather than predeploy. What is pinned offline is everything that can be:
 * the catalogs' own internal consistency, and the wiring that makes the check
 * actually run.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const ROOT = path.join(__dirname, "..");
const SCRIPT = path.join(ROOT, "scripts", "check-ttp-upstream.js");
const WORKFLOW = path.join(ROOT, ".github", "workflows", "refresh.yml");

const attack = JSON.parse(fs.readFileSync(path.join(ROOT, "data", "attack-techniques.json"), "utf8"));
const atlas = JSON.parse(fs.readFileSync(path.join(ROOT, "data", "atlas-ttps.json"), "utf8"));

test("the upstream TTP validator ships and is wired into the refresh workflow", () => {
  assert.ok(fs.existsSync(SCRIPT), "scripts/check-ttp-upstream.js must exist");
  const wf = fs.readFileSync(WORKFLOW, "utf8");
  assert.match(wf, /check-ttp-upstream\.js/,
    "refresh.yml must run the validator — an unwired check catches nothing");
});

test("the validator refuses to pass when upstream is unreachable", () => {
  // The failure mode that would make this check worthless: a network error
  // silently reading as "every id is valid".
  const src = fs.readFileSync(SCRIPT, "utf8");
  assert.match(src, /exitCode = 2/,
    "an unreachable upstream must exit with its own status, never 0");
  assert.match(src, /size === 0/,
    "an empty upstream id set must be treated as unreachable, not as a clean run");
});

test("every TTP id a CVE entry cites resolves to an entry in the mirrors", () => {
  // Referential integrity is checkable offline and is the half of the problem
  // that does not need MITRE: a remap that updates the mirror but misses the
  // back-references leaves a CVE pointing at an id that no longer exists here.
  const cve = JSON.parse(fs.readFileSync(path.join(ROOT, "data", "cve-catalog.json"), "utf8"));
  const dangling = [];
  for (const [id, entry] of Object.entries(cve)) {
    if (id === "_meta" || !entry || typeof entry !== "object") continue;
    for (const ref of entry.attack_refs || []) {
      if (!attack[ref]) dangling.push(`${id} -> attack ${ref}`);
    }
    for (const ref of entry.atlas_refs || []) {
      if (!atlas[ref]) dangling.push(`${id} -> atlas ${ref}`);
    }
  }
  assert.deepEqual(dangling, [],
    "CVE entries cite TTP ids the mirrors no longer carry:\n  " + dangling.join("\n  "));
});

test("no shipped TTP id is one the pin bump retired", () => {
  // Named explicitly so a future merge that reintroduces one fails here rather
  // than waiting for the next nightly network run.
  const retiredAttack = ["T1562.001", "T1562.004", "T1562.006", "T1562.008", "T0855",
    "T0001", "T0017", "T0051", "T0096", "T1480.003", "T1486.004"];
  const retiredAtlas = ["AML.T0019", "AML.T0058", "AML.T0104"];
  const back = [
    ...retiredAttack.filter((id) => attack[id]).map((id) => `attack ${id}`),
    ...retiredAtlas.filter((id) => atlas[id]).map((id) => `atlas ${id}`),
  ];
  assert.deepEqual(back, [],
    "an id retired upstream is back in a shipped mirror: " + back.join(", "));
});

test("an entry that supersedes a retired id records what it replaced", () => {
  // The remap carries cve_refs across, so the provenance has to survive too —
  // otherwise the next auditor cannot tell a curated successor from a guess.
  const successors = { attack: ["T1685", "T1686", "T1685.002", "T1692.001"], atlas: ["AML.T0115.000", "AML.T0115.001", "AML.T0115.002"] };
  for (const id of successors.attack) {
    if (!attack[id]) continue;
    assert.ok(typeof attack[id].name === "string" && attack[id].name.length > 0,
      `${id} must carry the upstream technique name`);
  }
  for (const id of successors.atlas) {
    assert.ok(atlas[id], `${id} must exist after the ATLAS consolidation`);
    assert.equal(typeof atlas[id].supersedes, "string",
      `${id} must record the id it superseded`);
  }
});

test("the refresh workflow preserves the validator's exit code and stderr", () => {
  // The script fails closed, but the pipeline can undo that. `node … | tee`
  // reports tee's status rather than the validator's, and capturing stdout
  // alone drops the unreachable-upstream diagnostic entirely — so an outage
  // would publish an empty summary and read as a clean run, which is the exact
  // silent pass the validator exists to prevent.
  const wf = fs.readFileSync(WORKFLOW, "utf8");
  assert.match(wf, /node scripts\/check-ttp-upstream\.js[^\n]*2>&1/,
    "the validator's stderr must be redirected into the captured log, not dropped");
  assert.match(wf, /TTP_STATUS=\$\?/,
    "the validator's own exit code must be captured immediately, not the pipe's");
  assert.doesNotMatch(wf, /check-ttp-upstream\.js\s*\|\s*tee/,
    "piping straight into tee masks the exit code — redirect and capture $? instead");
});
