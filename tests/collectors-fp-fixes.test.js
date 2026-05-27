"use strict";

/**
 * tests/collectors-fp-fixes.test.js
 *
 * Regression tests for a batch of collector false-positive / completeness
 * fixes:
 *   1. sbom: lockfile-no-integrity must NOT fire on a clean npm 7+ lockfile
 *      whose `""` root entry carries name+version but no integrity. It must
 *      still fire when a REMOTE-tarball entry (one with `resolved`) is missing
 *      integrity.
 *   2. secrets: a text file over the 1 MB scan limit is no longer silently
 *      dropped — the skip is recorded in collector_errors.
 *   3. secrets: the AWS-published example access-key id AKIAIOSFODNN7EXAMPLE
 *      does not flip aws-access-key-id.
 *   4. cicd-pipeline-compromise: an OIDC trust JSON under a build-output dir
 *      (dist/) is excluded from the scan via the shared code-exclude set.
 *   5. content-regex collectors (secrets / crypto-codebase / citation-hygiene)
 *      attach a 1-based startLine to their evidence_locations.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const os = require("node:os");

const ROOT = path.join(__dirname, "..");

const sbomCollector = require(path.join(ROOT, "lib", "collectors", "sbom.js"));
const secretsCollector = require(path.join(ROOT, "lib", "collectors", "secrets.js"));
const cryptoCollector = require(path.join(ROOT, "lib", "collectors", "crypto-codebase.js"));
const citationCollector = require(path.join(ROOT, "lib", "collectors", "citation-hygiene.js"));
const cicdCollector = require(path.join(ROOT, "lib", "collectors", "cicd-pipeline-compromise.js"));
const { lineFromOffset } = require(path.join(ROOT, "lib", "collectors", "scan-excludes.js"));

function mkTmp(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

// ---------------------------------------------------------------------------
// Finding 1 — sbom lockfile-no-integrity
// ---------------------------------------------------------------------------

test("sbom: clean npm 7+ lockfile (root entry has name+version, no integrity) is a MISS", () => {
  const tmp = mkTmp("fp-sbom-clean-");
  try {
    fs.writeFileSync(path.join(tmp, "package-lock.json"), JSON.stringify({
      name: "my-project",
      version: "1.0.0",
      lockfileVersion: 3,
      packages: {
        "": { name: "my-project", version: "1.0.0" },
        "node_modules/foo": { version: "1.2.3", resolved: "https://registry.npmjs.org/foo/-/foo-1.2.3.tgz", integrity: "sha512-deadbeef" },
      },
    }, null, 2));
    const r = sbomCollector.collect({ cwd: tmp });
    assert.equal(r.signal_overrides["lockfile-no-integrity"], "miss",
      "root entry without integrity must not trip the indicator");
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("sbom: remote-tarball entry missing integrity is still a HIT", () => {
  const tmp = mkTmp("fp-sbom-bad-");
  try {
    fs.writeFileSync(path.join(tmp, "package-lock.json"), JSON.stringify({
      name: "my-project",
      version: "1.0.0",
      lockfileVersion: 3,
      packages: {
        "": { name: "my-project", version: "1.0.0" },
        "node_modules/good": { version: "1.0.0", resolved: "https://registry.npmjs.org/good/-/good-1.0.0.tgz", integrity: "sha512-abc" },
        // resolved to a remote tarball but no integrity hash -> the real bug
        "node_modules/evil": { version: "2.0.0", resolved: "https://evil.example/evil-2.0.0.tgz" },
      },
    }, null, 2));
    const r = sbomCollector.collect({ cwd: tmp });
    assert.equal(r.signal_overrides["lockfile-no-integrity"], "hit",
      "a resolved remote entry without integrity must fire the indicator");
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// Finding 2 — secrets >1 MB skip is recorded
// ---------------------------------------------------------------------------

test("secrets: text file over 1 MB is recorded as file_too_large_skipped (not silent)", () => {
  const tmp = mkTmp("fp-secrets-big-");
  try {
    // 1 MB limit is exclusive (> MAX). Build a >1 MB .txt file.
    const big = "A".repeat(1024 * 1024 + 64) + "\n";
    fs.writeFileSync(path.join(tmp, "huge.txt"), big);
    const r = secretsCollector.collect({ cwd: tmp });
    const skip = r.collector_errors.find(e => e.kind === "file_too_large_skipped");
    assert.ok(skip, "a >1 MB text file must produce a file_too_large_skipped collector error");
    assert.equal(skip.artifact_id, "secret-regex-scan-text-files");
    assert.match(skip.reason, /huge\.txt/);
    assert.match(skip.reason, /not scanned/);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// Finding 3 — AWS doc example key demotion
// ---------------------------------------------------------------------------

test("secrets: AWS doc example key AKIAIOSFODNN7EXAMPLE does NOT flip aws-access-key-id", () => {
  const tmp = mkTmp("fp-secrets-awsexample-");
  try {
    fs.writeFileSync(path.join(tmp, "README.md"),
      "# Example\n\nUse your AWS key, e.g. `AKIAIOSFODNN7EXAMPLE`, from the AWS docs.\n");
    const r = secretsCollector.collect({ cwd: tmp });
    assert.equal(r.signal_overrides["aws-access-key-id"], "miss",
      "the published AWS example key must be demoted");
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("secrets: a non-example AKIA key DOES flip aws-access-key-id", () => {
  const tmp = mkTmp("fp-secrets-awsreal-");
  try {
    // 16 trailing uppercase/digit chars, not the example value.
    fs.writeFileSync(path.join(tmp, "config.txt"),
      "aws_access_key_id = AKIA1234567890ABCDEF\n");
    const r = secretsCollector.collect({ cwd: tmp });
    assert.equal(r.signal_overrides["aws-access-key-id"], "hit",
      "a real-shaped AKIA key must still fire");
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// Finding 4 — cicd OIDC scan honors code-exclude set (dist/)
// ---------------------------------------------------------------------------

const WILDCARD_OIDC = JSON.stringify({
  Statement: [{
    Effect: "Allow",
    Principal: { Federated: "token.actions.githubusercontent.com" },
    Condition: {
      StringLike: {
        "token.actions.githubusercontent.com:sub": "repo:acme/*:*",
      },
    },
  }],
}, null, 2);

test("cicd: OIDC trust JSON under dist/ (build output) is NOT scanned", () => {
  const tmp = mkTmp("fp-cicd-dist-");
  try {
    fs.mkdirSync(path.join(tmp, ".git")); // satisfy cwd-is-repo precondition
    const distInfra = path.join(tmp, "dist", "infra");
    fs.mkdirSync(distInfra, { recursive: true });
    fs.writeFileSync(path.join(distInfra, "trust.json"), WILDCARD_OIDC);
    const r = cicdCollector.collect({ cwd: tmp });
    assert.equal(r.signal_overrides["wildcarded-oidc-sub-claim"], "miss",
      "a wildcarded OIDC policy buried in dist/ build output must be excluded");
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("cicd: the same OIDC trust JSON under infra/ (source) IS scanned and HITs", () => {
  const tmp = mkTmp("fp-cicd-infra-");
  try {
    fs.mkdirSync(path.join(tmp, ".git"));
    const infra = path.join(tmp, "infra");
    fs.mkdirSync(infra, { recursive: true });
    fs.writeFileSync(path.join(infra, "trust.json"), WILDCARD_OIDC);
    const r = cicdCollector.collect({ cwd: tmp });
    assert.equal(r.signal_overrides["wildcarded-oidc-sub-claim"], "hit",
      "the control case (source-tree policy) must still fire");
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// Finding 5 — evidence_locations carry startLine
// ---------------------------------------------------------------------------

test("lineFromOffset maps byte offset to 1-based line", () => {
  const content = "line1\nline2\nline3";
  assert.equal(lineFromOffset(content, 0), 1);
  assert.equal(lineFromOffset(content, 6), 2);   // start of line2
  assert.equal(lineFromOffset(content, 12), 3);  // start of line3
  assert.equal(lineFromOffset(content, -5), 1);  // fallback
  assert.equal(lineFromOffset(content, 99999), 3); // clamped to content end
});

test("secrets: evidence_locations carry a startLine pointing at the secret's line", () => {
  const tmp = mkTmp("fp-secrets-line-");
  try {
    // Real GitHub PAT shape on line 3 (1-based).
    const ghp = "ghp_" + "A".repeat(36);
    fs.writeFileSync(path.join(tmp, "leak.env"),
      `# comment line 1\nFOO=bar\nTOKEN=${ghp}\n`);
    const r = secretsCollector.collect({ cwd: tmp });
    assert.equal(r.signal_overrides["github-personal-access-token"], "hit");
    const locs = r.evidence_locations["github-personal-access-token"];
    assert.ok(Array.isArray(locs) && locs.length === 1, "exactly one location expected");
    assert.equal(locs[0].uri, "leak.env");
    assert.equal(locs[0].startLine, 3, "startLine must point at the line carrying the token");
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("crypto-codebase: evidence_locations for bcrypt-cost-low carry a startLine", () => {
  const tmp = mkTmp("fp-crypto-line-");
  try {
    // bcrypt call with cost 4 (<12) on line 3.
    const src = [
      "const bcrypt = require('bcrypt');",
      "async function hash(pw) {",
      "  return bcrypt.hash(pw, 4);",
      "}",
      "",
    ].join("\n");
    fs.writeFileSync(path.join(tmp, "auth.js"), src);
    const r = cryptoCollector.collect({ cwd: tmp });
    assert.equal(r.signal_overrides["bcrypt-cost-low"], "hit");
    const locs = r.evidence_locations["bcrypt-cost-low"];
    assert.ok(Array.isArray(locs) && locs.length >= 1);
    assert.equal(locs[0].uri, "auth.js");
    assert.equal(locs[0].startLine, 3, "startLine must point at the bcrypt call");
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("citation-hygiene: fabricated-cve-id evidence_locations carry a startLine", () => {
  const tmp = mkTmp("fp-cite-line-");
  try {
    // Malformed (non-canonical) CVE on line 2 of a doc file.
    fs.writeFileSync(path.join(tmp, "NOTES.md"),
      "# Security notes\nWe patched CVE-2024-XXXX last week.\n");
    const r = citationCollector.collect({ cwd: tmp });
    assert.equal(r.signal_overrides["fabricated-cve-id"], "hit");
    const locs = r.evidence_locations["fabricated-cve-id"];
    assert.ok(Array.isArray(locs) && locs.length === 1);
    assert.equal(locs[0].uri, "NOTES.md");
    assert.equal(locs[0].startLine, 2, "startLine must point at the bad citation");
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});
