"use strict";

/**
 * tests/secrets-depth-cap-visibility.test.js
 *
 * The secrets collector caps its tree walk at depth 6. A secret living in a
 * subtree deeper than the cap is never emitted and never scanned. Before this
 * fix that was a silent false negative: the unscanned deep file produced
 * `aws-access-key-id=miss` with `collector_errors=[]`, indistinguishable from
 * "scanned the whole tree and found nothing". Unlike the per-file size cap —
 * which records `file_too_large_skipped` so the operator knows a file went
 * unscanned — depth truncation recorded nothing.
 *
 * The collector now records a `depth_capped` collector_errors entry naming the
 * pruned subtree(s), so absence-of-scan is observable rather than reported as
 * absence-of-secret.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const os = require("node:os");

const ROOT = path.join(__dirname, "..");
const secrets = require(path.join(ROOT, "lib", "collectors", "secrets.js"));
const { walkTree } = require(path.join(ROOT, "lib", "collectors", "scan-excludes.js"));

function mkTmp(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

// A valid AWS access-key-id: AKIA followed by exactly 16 [0-9A-Z].
const DEEP_KEY = "AKIAQ7DEEPSECRET0001";

test("secrets: a subtree pruned at the depth cap records a depth_capped collector_errors entry", () => {
  const tmp = mkTmp("sec-depthcap-");
  try {
    // root/a/b/c/d/e/f/g/h/.env is at depth 8 — beyond the depth-6 cap.
    const deepDir = path.join(tmp, "a", "b", "c", "d", "e", "f", "g", "h");
    fs.mkdirSync(deepDir, { recursive: true });
    fs.writeFileSync(path.join(deepDir, ".env"), "aws_access_key_id=" + DEEP_KEY + "\n");

    const r = secrets.collect({ cwd: tmp });

    // The deep file is genuinely beyond reach of the default walk.
    assert.equal(r.signal_overrides["aws-access-key-id"], "miss",
      "the depth-8 secret is not scanned at the depth-6 cap (this is the gap)");

    // ...but the unscanned subtree is now OBSERVABLE, not silent.
    const depthCapped = r.collector_errors.filter((e) => e.kind === "depth_capped");
    assert.equal(depthCapped.length, 1,
      "exactly one depth_capped entry records the pruned subtree");
    assert.equal(typeof depthCapped[0].reason, "string");
    assert.ok(depthCapped[0].truncated_count >= 1,
      "truncated_count reports at least the one pruned subtree");
    assert.ok(Array.isArray(depthCapped[0].truncated_paths)
      && depthCapped[0].truncated_paths.length >= 1,
      "truncated_paths names the pruned subtree path(s)");
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("secrets: a fully shallow tree records NO depth_capped entry", () => {
  const tmp = mkTmp("sec-depthcap-shallow-");
  try {
    // Deepest file is at depth 6 (root/a/b/c/d/e/f/<file>) — within the cap.
    const d6 = path.join(tmp, "a", "b", "c", "d", "e", "f");
    fs.mkdirSync(d6, { recursive: true });
    fs.writeFileSync(path.join(d6, "config.env"), "aws_access_key_id=" + DEEP_KEY + "\n");

    const r = secrets.collect({ cwd: tmp });
    assert.equal(r.signal_overrides["aws-access-key-id"], "hit",
      "the depth-6 secret IS scanned and fires");
    assert.equal(r.collector_errors.filter((e) => e.kind === "depth_capped").length, 0,
      "no subtree was pruned, so no depth_capped notice");
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("walkTree: opts.truncations is appended with the pruned dir but the return value is unchanged", () => {
  const tmp = mkTmp("sec-walk-trunc-");
  try {
    const d7 = path.join(tmp, "a", "b", "c", "d", "e", "f", "g");
    fs.mkdirSync(d7, { recursive: true });
    fs.writeFileSync(path.join(d7, "deep.txt"), "x\n");
    fs.writeFileSync(path.join(tmp, "shallow.txt"), "y\n");

    const truncations = [];
    const files = walkTree(tmp, { maxDepth: 6, truncations });

    // Return value: only the in-cap file (shallow.txt at depth 0). deep.txt
    // at depth 7 is pruned.
    assert.ok(Array.isArray(files), "walkTree still returns a file array");
    assert.equal(files.some((f) => f.name === "deep.txt"), false,
      "the depth-7 file is not emitted");
    assert.equal(files.some((f) => f.name === "shallow.txt"), true,
      "the depth-0 file is emitted");

    // The pruned directory (a/b/c/d/e/f/g, the depth-7 dir whose contents are
    // dropped) is recorded.
    assert.ok(truncations.length >= 1, "the pruned directory is recorded in truncations");
    assert.equal(typeof truncations[0].rel, "string");
    assert.equal(truncations[0].rel, "a/b/c/d/e/f/g",
      "the recorded path is the forward-slash rel path of the pruned dir");
    assert.equal(truncations[0].depth, 7, "the recorded depth is the would-be descent depth");

    // Backward-compat: not passing truncations still works and never throws.
    const files2 = walkTree(tmp, { maxDepth: 6 });
    assert.ok(Array.isArray(files2));
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});
