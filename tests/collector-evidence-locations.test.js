"use strict";

/**
 * tests/collector-evidence-locations.test.js
 *
 * Pins the code-scope collectors' per-indicator evidence-location output:
 *   - A collector that knows WHICH file triggered an indicator surfaces it
 *     as a top-level `evidence_locations: { "<indicator-id>": [ {uri, ...} ] }`
 *     keyed by the same indicator id it flips to "hit".
 *   - The runner threads those onto the firing indicator so SARIF
 *     results[].locations gets a real file location instead of the coarse
 *     playbook-source fallback.
 *
 * citation-hygiene is the most deterministic wired collector: a fabricated
 * CVE id (e.g. CVE-2024-XXXX) flips `fabricated-cve-id` to "hit" from a
 * single fixture file with no catalog dependency.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const os = require("node:os");
const { spawnSync } = require("node:child_process");

const ROOT = path.join(__dirname, "..");
const CLI = path.join(ROOT, "bin", "exceptd.js");

function cli(args, opts = {}) {
  return spawnSync(process.execPath, [CLI, ...args], {
    encoding: "utf8",
    cwd: opts.cwd || ROOT,
    env: { ...process.env, EXCEPTD_DEPRECATION_SHOWN: "1", EXCEPTD_UNSIGNED_WARNED: "1", ...(opts.env || {}) },
    input: opts.input,
  });
}

function mkFixture() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "exceptd-evloc-"));
  // A fabricated (non-canonical) CVE citation flips fabricated-cve-id.
  fs.writeFileSync(path.join(dir, "notes.md"), "We patched CVE-2024-XXXX last week.\n");
  return dir;
}

const citationCollector = require(path.join(ROOT, "lib", "collectors", "citation-hygiene.js"));

test("citation-hygiene emits evidence_locations keyed by the indicator it flips to hit", () => {
  const dir = mkFixture();
  try {
    const sub = citationCollector.collect({ cwd: dir });
    assert.equal(sub.signal_overrides["fabricated-cve-id"], "hit", "fabricated CVE must flip the indicator");
    assert.ok(sub.evidence_locations && typeof sub.evidence_locations === "object", "evidence_locations present");
    const locs = sub.evidence_locations["fabricated-cve-id"];
    assert.ok(Array.isArray(locs) && locs.length >= 1, "fabricated-cve-id has >= 1 location");
    assert.equal(locs[0].uri, "notes.md", "uri points at the fixture file");
    // file-level only — the collector records no line for citation hits.
    assert.equal(locs[0].startLine, undefined, "no startLine when the hit has no real line number");
    // Every evidence_locations key must be an indicator the collector
    // actually flipped to "hit" (no orphan keys).
    for (const id of Object.keys(sub.evidence_locations)) {
      assert.equal(sub.signal_overrides[id], "hit", `evidence_locations key ${id} must be a flipped-to-hit indicator`);
    }
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("run --format sarif surfaces the collector's evidence_locations as result.locations", () => {
  const dir = mkFixture();
  try {
    const sub = citationCollector.collect({ cwd: dir });
    // The fabricated-cve-id indicator declares false_positive_checks_required;
    // a hit verdict only survives when those checks are attested. Attest by
    // index so the deterministic hit reaches verdict=hit and emits a result.
    sub.signal_overrides["fabricated-cve-id__fp_checks"] = { "0": true, "1": true };
    const subPath = path.join(dir, "sub.json");
    fs.writeFileSync(subPath, JSON.stringify(sub));

    const r = cli(["run", "citation-hygiene", "--evidence", subPath, "--format", "sarif"]);
    assert.equal(r.status, 0, `run exited 0 (stderr: ${r.stderr})`);
    const sarif = JSON.parse(r.stdout);
    const results = sarif.runs[0].results || [];
    const fired = results.filter(x => x.ruleId.endsWith("/fabricated-cve-id"));
    assert.equal(fired.length, 1, "exactly one fabricated-cve-id SARIF result");
    const result = fired[0];
    assert.ok(Array.isArray(result.locations) && result.locations.length >= 1, "result has locations");
    const uri = result.locations[0].physicalLocation.artifactLocation.uri;
    assert.equal(uri, "notes.md", "SARIF location uri matches the fixture file");
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
