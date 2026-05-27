"use strict";

/**
 * tests/collectors-redos-whitespace-line.test.js
 *
 * Regression coverage for a catastrophic-backtracking (ReDoS) hazard in
 * three line-scanning collector regexes that anchored leading indentation
 * with two adjacent `\s*` runs around an optional list-dash
 * (`^\s*-?\s*<literal>:`). A single long all-whitespace line — well under
 * the 512KB readSafe cap — drove O(n^2) backtracking and blocked the event
 * loop for ~2 minutes per file.
 *
 * Two guarantees per collector:
 *   (a) a fixture with a ~200KB whitespace line returns in well under 1s,
 *   (b) normal `uses:` / `image:` lines still produce the expected hit and
 *       capture, with and without the `- ` list marker, quoted and unquoted.
 *
 * Affected sites:
 *   lib/collectors/library-author.js        publish-workflow `uses:` scan
 *   lib/collectors/cicd-pipeline-compromise  workflow `uses:` scan
 *   lib/collectors/containers.js             k8s manifest `image:` scan
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const os = require("node:os");

const ROOT = path.join(__dirname, "..");

const libraryAuthor = require(path.join(ROOT, "lib", "collectors", "library-author.js"));
const cicd = require(path.join(ROOT, "lib", "collectors", "cicd-pipeline-compromise.js"));
const containers = require(path.join(ROOT, "lib", "collectors", "containers.js"));

// A line long enough that the pre-fix O(n^2) backtracking takes tens of
// seconds, but comfortably under readSafe's 512KB cap.
const WHITESPACE_LINE = " ".repeat(200 * 1024);
// A hit must complete fast even with the hostile line present.
const FAST_MS = 2000;

function mkTmp(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

function writeFileEnsuringDir(file, content) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, content);
}

// ---------------------------------------------------------------------------
// library-author — publish-workflow `uses:` scan
// ---------------------------------------------------------------------------

test("library-author: long-whitespace workflow line returns fast and still flags mutable refs", () => {
  const tmp = mkTmp("redos-libauthor-");
  try {
    // release.yml matches the publish-workflow filename prefix. The body
    // carries normal `uses:` lines (with/without dash, quoted/unquoted) plus
    // a hostile 200KB whitespace line that previously triggered backtracking.
    const wf = [
      "name: release",
      "jobs:",
      "  publish:",
      "    steps:",
      "      - uses: actions/checkout@v4",          // first-party: excluded, but exercises the regex
      "      - uses: third/party@v1",               // mutable third-party ref -> HIT
      "        uses: 'quoted/action@main'",         // quoted, no dash -> HIT
      WHITESPACE_LINE,                               // hostile line
      "      - uses: another/thing@1.2.3",          // mutable -> HIT
    ].join("\n");
    writeFileEnsuringDir(path.join(tmp, ".github", "workflows", "release.yml"), wf);

    const start = Date.now();
    const r = libraryAuthor.collect({ cwd: tmp });
    const elapsed = Date.now() - start;

    assert.ok(elapsed < FAST_MS, `collect took ${elapsed}ms (expected < ${FAST_MS}ms) — ReDoS not mitigated`);
    assert.equal(r.signal_overrides["publish-workflow-action-refs-mutable"], "hit",
      "normal mutable `uses:` refs must still flip the indicator");
    const locs = r.evidence_locations["publish-workflow-action-refs-mutable"] || [];
    assert.ok(locs.length >= 3, `expected >= 3 mutable-ref hits, got ${locs.length}`);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("library-author: clean workflow (all refs SHA-pinned) is a MISS with normal `uses:` shapes", () => {
  const tmp = mkTmp("redos-libauthor-clean-");
  try {
    const sha = "a".repeat(40);
    const wf = [
      "name: release",
      "jobs:",
      "  publish:",
      "    steps:",
      `      - uses: actions/checkout@${sha}`,
      `        uses: "third/party@${sha}"`,
      "      - uses: ./.github/actions/local",      // local: excluded
    ].join("\n");
    writeFileEnsuringDir(path.join(tmp, ".github", "workflows", "release.yml"), wf);

    const r = libraryAuthor.collect({ cwd: tmp });
    assert.equal(r.signal_overrides["publish-workflow-action-refs-mutable"], "miss",
      "SHA-pinned refs and a local action must not flip the indicator");
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// cicd-pipeline-compromise — workflow `uses:` scan
// ---------------------------------------------------------------------------

test("cicd: long-whitespace workflow line returns fast and still flags floating tag pins", () => {
  const tmp = mkTmp("redos-cicd-");
  try {
    // The collector requires a .git directory at cwd.
    fs.mkdirSync(path.join(tmp, ".git"), { recursive: true });
    const wf = [
      "name: ci",
      "jobs:",
      "  build:",
      "    steps:",
      "      - uses: actions/checkout@v4",          // owner=actions: first-party, excluded
      "      - uses: third/party@v1",               // floating tag -> HIT
      "        uses: 'quoted/action@main'",         // quoted, no dash -> HIT
      WHITESPACE_LINE,                               // hostile line
      "      - uses: another/thing@1.2.3",          // floating tag -> HIT
    ].join("\n");
    writeFileEnsuringDir(path.join(tmp, ".github", "workflows", "release.yml"), wf);

    const start = Date.now();
    const r = cicd.collect({ cwd: tmp });
    const elapsed = Date.now() - start;

    assert.ok(elapsed < FAST_MS, `collect took ${elapsed}ms (expected < ${FAST_MS}ms) — ReDoS not mitigated`);
    assert.equal(r.signal_overrides["actions-floating-tag-pin"], "hit",
      "normal floating-tag `uses:` refs must still flip the indicator");
    const locs = r.evidence_locations["actions-floating-tag-pin"] || [];
    assert.ok(locs.length >= 3, `expected >= 3 floating-tag hits, got ${locs.length}`);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("cicd: clean workflow (SHA-pinned third-party + first-party) is a MISS", () => {
  const tmp = mkTmp("redos-cicd-clean-");
  try {
    fs.mkdirSync(path.join(tmp, ".git"), { recursive: true });
    const sha = "b".repeat(40);
    const wf = [
      "name: ci",
      "jobs:",
      "  build:",
      "    steps:",
      "      - uses: actions/checkout@v4",          // first-party owner: excluded
      `        uses: "third/party@${sha}"`,        // SHA-pinned: excluded
      "      - uses: ./local-action",               // local: excluded
    ].join("\n");
    writeFileEnsuringDir(path.join(tmp, ".github", "workflows", "release.yml"), wf);

    const r = cicd.collect({ cwd: tmp });
    assert.equal(r.signal_overrides["actions-floating-tag-pin"], "miss",
      "first-party + SHA-pinned + local refs must not flip the indicator");
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// containers — k8s manifest `image:` scan
// ---------------------------------------------------------------------------

test("containers: long-whitespace k8s manifest line returns fast and still flags :latest images", () => {
  const tmp = mkTmp("redos-containers-");
  try {
    const manifest = [
      "apiVersion: v1",
      "kind: Pod",
      "spec:",
      "  containers:",
      "    - image: nginx:latest",                  // :latest -> HIT (with dash, unquoted)
      "      image: 'redis:latest'",                // :latest -> HIT (quoted, no dash)
      WHITESPACE_LINE,                               // hostile line
      "    - image: busybox",                        // no tag (defaults to latest) -> HIT
      "      image: pinned/app:v1.2.3",             // explicit non-latest tag -> not a latest hit
    ].join("\n");
    writeFileEnsuringDir(path.join(tmp, "pod.yaml"), manifest);

    const start = Date.now();
    const r = containers.collect({ cwd: tmp });
    const elapsed = Date.now() - start;

    assert.ok(elapsed < FAST_MS, `collect took ${elapsed}ms (expected < ${FAST_MS}ms) — ReDoS not mitigated`);
    assert.equal(r.signal_overrides["k8s-image-latest"], "hit",
      "normal `image:` :latest / untagged lines must still flip the indicator");
    const locs = r.evidence_locations["k8s-image-latest"] || [];
    assert.ok(locs.length >= 3, `expected >= 3 latest-image hits, got ${locs.length}`);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("containers: pinned-tag k8s manifest is a MISS for k8s-image-latest", () => {
  const tmp = mkTmp("redos-containers-clean-");
  try {
    const manifest = [
      "apiVersion: v1",
      "kind: Pod",
      "spec:",
      "  containers:",
      "    - image: nginx:1.27.0",
      "      image: 'redis:7.2'",
    ].join("\n");
    writeFileEnsuringDir(path.join(tmp, "pod.yaml"), manifest);

    const r = containers.collect({ cwd: tmp });
    assert.equal(r.signal_overrides["k8s-image-latest"], "miss",
      "explicitly tagged images must not flip the latest-image indicator");
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});
