"use strict";

/**
 * tests/check-version-tags.test.js
 *
 * Pins the version-tag check itself:
 *   1. The baseline file exists and is well-formed JSON.
 *   2. Running the scan on the current tree produces no NEW
 *      regressions vs. the baseline (the standard predeploy gate).
 *   3. The scan correctly identifies a synthetic new violation
 *      when one is introduced in a tempfile.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const ROOT = path.join(__dirname, "..");
const SCRIPT = path.join(ROOT, "scripts", "check-version-tags.js");
const BASELINE = path.join(ROOT, "tests", ".version-tag-baseline.json");

const { VERSION_TAG_RE } = require(SCRIPT);

test("baseline file exists and is well-formed JSON", () => {
  assert.ok(fs.existsSync(BASELINE), `expected baseline at ${path.relative(ROOT, BASELINE)}`);
  const body = JSON.parse(fs.readFileSync(BASELINE, "utf8"));
  assert.equal(typeof body.byFile, "object");
  assert.ok(Array.isArray(body.filenameViolations));
  assert.ok(typeof body.recorded_at === "string");
});

test("current tree has no new version-tag regressions vs. baseline", () => {
  const r = spawnSync(process.execPath, [SCRIPT], { encoding: "utf8", cwd: ROOT });
  assert.equal(r.status, 0,
    `check must pass on the current tree; stdout: ${r.stdout.slice(0, 400)}; stderr: ${r.stderr.slice(0, 400)}`);
  assert.match(r.stdout, /\[check-version-tags\] ok/);
});

test("a synthetic new version-tag comment in an unsanctioned file is caught", () => {
  // Drop a fake .js file under scripts/ with a version-tagged comment.
  // The check must FAIL because this is a new file (not in the baseline)
  // carrying a tag. The filename must NOT be git-ignored (the gate skips
  // ignored files): an untracked-but-shippable new file is exactly what it
  // guards. The literal is string-constructed so the scanner doesn't flag
  // THIS test file as a violation.
  const fakePath = path.join(ROOT, "scripts", "_fake_version_tag_probe.js");
  const fakeTag = "v" + "0." + "99." + "99";
  fs.writeFileSync(fakePath, `// ${fakeTag} fake comment\nmodule.exports = {};\n`);
  try {
    const r = spawnSync(process.execPath, [SCRIPT], { encoding: "utf8", cwd: ROOT });
    assert.equal(r.status, 1,
      `check must fail on a new version-tag comment; got status=${r.status}, stderr=${r.stderr.slice(0, 400)}`);
    assert.match(r.stderr, /scripts[\\/]_fake_version_tag_probe\.js/,
      "check must name the offending file path");
    assert.match(r.stderr, /version-tag line count grew|version-tag line\(s\)/,
      "check must explain WHY the violation matters");
  } finally {
    fs.unlinkSync(fakePath);
  }
});

// --------------------------------------------------------------------------
// VERSION_TAG_RE allows a sentence-ending period
// --------------------------------------------------------------------------

test('#26 VERSION_TAG_RE matches a version stamp that ends a sentence (trailing period)', () => {
  assert.equal(VERSION_TAG_RE.test('// fixed in 0.18.9.'), true);
});

test('#26 VERSION_TAG_RE matches v-prefixed and bare stamps', () => {
  assert.equal(VERSION_TAG_RE.test('v0.18.9'), true);
  assert.equal(VERSION_TAG_RE.test('0.18.9'), true);
  assert.equal(VERSION_TAG_RE.test('0.18.99'), true); // longer patch still matches
});

test('#26 VERSION_TAG_RE rejects an IPv4 address and a longer dotted-numeric run', () => {
  assert.equal(VERSION_TAG_RE.test('127.0.0.1'), false);
  assert.equal(VERSION_TAG_RE.test('1.2.0.18.9.3'), false);
  assert.equal(VERSION_TAG_RE.test('// build 0.18.9.42 nightly'), false);
});

test("a version literal inside a quoted string on a code line IS counted (whole-line contract)", () => {
  // The scan is deliberately whole-line, not comment-only: a 0.x stamp inside a
  // shipped string literal (CLI --help text, error message, test fixture) is
  // operator-readable residue and must be caught the same as a `//` comment.
  // This locks that contract so a future "comment-only" narrowing can't silently
  // stop catching version stamps in operator-facing strings.
  const fakePath = path.join(ROOT, "scripts", "_fake_version_string_probe.js");
  const fakeVer = "0." + "99." + "98";
  // No `//` on this line — the version stamp lives ONLY inside a string literal.
  fs.writeFileSync(fakePath, `module.exports = { version: "${fakeVer}" };\n`);
  try {
    const r = spawnSync(process.execPath, [SCRIPT], { encoding: "utf8", cwd: ROOT });
    assert.equal(r.status, 1,
      `a 0.x stamp inside a code-line string must trip the gate; got status=${r.status}, stderr=${r.stderr.slice(0, 400)}`);
    assert.match(r.stderr, /scripts[\\/]_fake_version_string_probe\.js/,
      "check must name the offending file path even when the stamp is in a string, not a comment");
  } finally {
    fs.unlinkSync(fakePath);
  }
});
