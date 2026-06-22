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


// ---- routed from collector-comment-marker-fp ----
require("node:test").describe("collector-comment-marker-fp", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
/**
 * tests/collector-comment-marker-fp.test.js
 *
 * Collectors must not read a `#`-commented MENTION of a publish-shape token,
 * command, or runner as the real thing, and a doc/detection-pattern snippet of
 * a private key must not register as an embedded secret.
 *
 *  - library-author: the classifier already strips YAML comments before its
 *    publish-shape probes; the INDICATOR scanner (static-token / non-frozen
 *    install / self-hosted runner) and the provenance / SBOM-capability probes
 *    must use the same comment-stripped view. Otherwise a comment produces a
 *    deterministic false HIT, and — in the provenance direction — a commented
 *    `--provenance` suppresses a real gap (a security-relevant false NEGATIVE).
 *  - secrets: gcp-service-account-json must require a full PEM block, not just
 *    the `-----BEGIN PRIVATE KEY-----` header, so a service-account JSON shown
 *    as a placeholder / redaction-pattern literal does not register as a key.
 *
 * Exact-value pins (miss/hit), fail-before / pass-after, per the
 * anti-coincidence rule.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const libauthor = require('../lib/collectors/library-author.js');
const secrets = require('../lib/collectors/secrets.js');

const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'exceptd-comment-fp-'));
process.on('exit', () => { try { fs.rmSync(TMP, { recursive: true, force: true }); } catch { /* non-fatal */ } });
let _n = 0;
function mkfx(files) {
  const d = path.join(TMP, 'fx-' + _n++);
  for (const [rel, body] of Object.entries(files)) {
    const p = path.join(d, rel);
    fs.mkdirSync(path.dirname(p), { recursive: true });
    fs.writeFileSync(p, body);
  }
  return d;
}
function overrides(d) { return libauthor.collect({ cwd: d }).signal_overrides || {}; }




// --- secrets: gcp-service-account-json full-block guard -----------------

// Assemble the PEM markers + body at runtime so no contiguous private-key
// literal exists in this source file (push-protection / gitleaks safe).
const BEGIN = '-----BEGIN' + ' PRIVATE KEY-----';
const END = '-----END' + ' PRIVATE KEY-----';
function fakePemBody(repeats) {
  // Non-secret fixed base64-shaped filler, JSON-encoded with \n line breaks.
  const chunk = 'MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj';
  const lines = [];
  for (let i = 0; i < repeats; i++) lines.push(chunk);
  return BEGIN + '\\n' + lines.join('\\n') + '\\n' + END + '\\n';
}
function gcpHit(text) {
  const re = secrets.__INDICATOR_PATTERNS
    ? secrets.__INDICATOR_PATTERNS.find(p => p.id === 'gcp-service-account-json').re
    : null;
  if (re) { re.lastIndex = 0; return re.test(text); }
  // Fall back to the collector surface if the pattern table isn't exported.
  const d = mkfx({ 'creds.json': text });
  const ov = secrets.collect({ cwd: d }).signal_overrides || {};
  return ov['gcp-service-account-json'] === 'hit';
}

test('secrets: a full service-account key still registers (HIT preserved)', () => {
  const full = '{"type": "service_account", "project_id": "p-294857", ' +
    '"private_key_id": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0", ' +
    '"private_key": "' + fakePemBody(26) + '", ' +
    '"client_email": "svc@p-294857.iam.gserviceaccount.com"}';
  assert.equal(gcpHit(full), true);
});

test('secrets: a header-only service-account snippet does not register (FP fixed)', () => {
  const headerOnly = '{"type": "service_account", "private_key": "' + BEGIN + '"}';
  assert.equal(gcpHit(headerOnly), false);
});
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});
