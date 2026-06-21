'use strict';

/**
 * tests/collectors-secrets.test.js
 *
 * Subject coverage for lib/collectors/secrets.js:
 *  - a text file over the 1 MB scan limit is no longer silently dropped — the
 *    skip is recorded in collector_errors;
 *  - the AWS-published example access-key id AKIAIOSFODNN7EXAMPLE does not flip
 *    aws-access-key-id, while a real-shaped AKIA key does;
 *  - evidence_locations carry a 1-based startLine pointing at the secret's line.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');

const ROOT = path.join(__dirname, '..');

const secretsCollector = require(path.join(ROOT, 'lib', 'collectors', 'secrets.js'));

function mkTmp(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

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
