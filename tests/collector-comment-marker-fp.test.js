'use strict';

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

test('library-author: comment-only publish-shape mentions do not fire the indicators (FP)', () => {
  // Publishes cleanly via `npm publish --provenance` with OIDC. The ONLY
  // mentions of `npm install`, `runs-on: self-hosted`, and `secrets.NPM_TOKEN`
  // are inside `#` comments — none is a real command/token/runner. No `npm ci`
  // either, so the non-frozen probe is exercised on the comment alone.
  const d = mkfx({
    'package.json': '{"name":"x","version":"1.0.0","publishConfig":{"provenance":true}}',
    '.github/workflows/release.yml':
      'name: release\n' +
      "on: { push: { tags: ['v*'] } }\n" +
      'permissions:\n  id-token: write\n  contents: read\n' +
      'jobs:\n  publish:\n    runs-on: ubuntu-latest\n    steps:\n' +
      '      # legacy note: do NOT npm install here; never runs-on: self-hosted;\n' +
      '      # never use secrets.NPM_TOKEN — OIDC + provenance only.\n' +
      '      - run: npm publish --provenance --access public\n',
  });
  const o = overrides(d);
  assert.equal(o['release-workflow-non-frozen-install'], 'miss');
  assert.equal(o['publish-workflow-runs-on-self-hosted'], 'miss');
  assert.equal(o['publish-workflow-uses-static-token'], 'miss');
});

test('library-author: a commented `--provenance` does not suppress provenance-missing (FN)', () => {
  // No publishConfig.provenance, a real `npm publish` WITHOUT --provenance, and
  // only a COMMENT mentions --provenance. The gap must still be reported.
  const d = mkfx({
    'package.json': '{"name":"y","version":"1.0.0"}',
    '.github/workflows/release.yml':
      'name: release\n' +
      'jobs:\n  publish:\n    runs-on: ubuntu-latest\n    steps:\n' +
      '      # TODO: switch to `npm publish --provenance` once OIDC is configured\n' +
      '      - run: npm publish\n',
  });
  assert.equal(overrides(d)['package-json-provenance-missing'], 'hit');
});

test('library-author: real static token / npm install / self-hosted still fire (no over-correction)', () => {
  const d = mkfx({
    'package.json': '{"name":"z","version":"1.0.0"}',
    '.github/workflows/release.yml':
      'name: release\n' +
      'jobs:\n  publish:\n    runs-on: self-hosted\n    steps:\n' +
      '      - run: npm install\n' +
      '      - run: npm publish\n        env:\n          NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}\n',
  });
  const o = overrides(d);
  assert.equal(o['release-workflow-non-frozen-install'], 'hit');
  assert.equal(o['publish-workflow-runs-on-self-hosted'], 'hit');
  assert.equal(o['publish-workflow-uses-static-token'], 'hit');
});

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
