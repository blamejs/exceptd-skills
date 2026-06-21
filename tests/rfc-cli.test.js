'use strict';

/**
 * rfc-cli regression suite (lib/rfc-cli.js).
 *
 * Covers the title-matcher (titleMatches) and the rfc CLI's positional/--check
 * argument parsing:
 *
 *   - --check title match must be whole-word + phrase-aware, not a lenient
 *     bidirectional substring (which let "TLS" match the DTLS title).
 *   - rfc positional/--check parsing must resolve the RFC number regardless of
 *     flag order ("rfc --check <title> <n>" must read id=<n>).
 *
 * Discipline: assert EXACT exit codes (never notEqual(0)); pair every
 * field-presence check with a value/type assertion. CLI-spawn tests use an
 * isolated tempdir for both the RFC index fixture and the resolve cache so the
 * repo tree is never mutated and the network is never touched.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const ROOT = path.join(__dirname, '..');
const RFC_CLI = path.join(ROOT, 'lib', 'rfc-cli.js');

function tryJson(s) {
  try { return JSON.parse(s); } catch { return null; }
}

function makeIsolatedDir(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

// ===================================================================
// rfc --check title match is whole-word + phrase-aware
// ===================================================================

const { titleMatches } = require('../lib/rfc-cli.js');
const DTLS_TITLE = 'The Datagram Transport Layer Security (DTLS) Protocol Version 1.3';
const TLS_TITLE = 'The Transport Layer Security (TLS) Protocol Version 1.3';
const RFC2119_TITLE = 'Key words for use in RFCs to Indicate Requirement Levels';

test('#30 "TLS" does NOT match the DTLS title (no substring-of-dtls match)', () => {
  assert.equal(titleMatches('TLS', DTLS_TITLE), false);
});

test('#30 "TLS" DOES match the TLS 1.3 title (standalone whole-word token)', () => {
  assert.equal(titleMatches('TLS', TLS_TITLE), true);
});

test('#30 "Transport Layer Security" does NOT match the DTLS title (tail-of-phrase trap)', () => {
  // The run "transport layer security" exists in the DTLS title only as the tail
  // of "datagram transport layer security" — a distinguishing content qualifier
  // the claim omits. Pre-fix the bidirectional substring matched it.
  assert.equal(titleMatches('Transport Layer Security', DTLS_TITLE), false);
});

test('#30 "Transport Layer Security" DOES match the TLS 1.3 title (run preceded only by a stopword)', () => {
  assert.equal(titleMatches('Transport Layer Security', TLS_TITLE), true);
});

test('#30 legitimate partial "Key words for use in RFCs" matches RFC-2119', () => {
  assert.equal(titleMatches('Key words for use in RFCs', RFC2119_TITLE), true);
});

test('#30 rfc CLI: --check "TLS" against the DTLS index entry yields title_match:false and exit 2', () => {
  // Drive the real CLI against a fixture RFC index whose entry is a DTLS spec.
  const dir = makeIsolatedDir('k30-cli-');
  try {
    const index = path.join(dir, 'rfc-index.json');
    fs.writeFileSync(index, JSON.stringify({
      'RFC-9147': { number: 9147, title: DTLS_TITLE, status: 'Proposed Standard' },
    }));
    const out = spawnSync(process.execPath, [RFC_CLI, '9147', '--check', 'TLS', '--json'], {
      encoding: 'utf8',
      env: { ...process.env, EXCEPTD_RFC_INDEX: index, EXCEPTD_RESOLVE_CACHE_DIR: dir },
    });
    assert.equal(out.status, 2, `expected exit 2; got ${out.status} (stderr: ${out.stderr.slice(0, 200)})`);
    const body = tryJson(out.stdout.trim());
    assert.ok(body, `stdout must be JSON; got: ${out.stdout.slice(0, 200)}`);
    assert.equal(body.title_match, false);
    assert.equal(body.ok, false);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('#30 rfc CLI: a correct --check title yields title_match:true and exit 0', () => {
  const dir = makeIsolatedDir('k30-cli-ok-');
  try {
    const index = path.join(dir, 'rfc-index.json');
    fs.writeFileSync(index, JSON.stringify({
      'RFC-8446': { number: 8446, title: TLS_TITLE, status: 'Proposed Standard' },
    }));
    const out = spawnSync(process.execPath, [RFC_CLI, '8446', '--check', 'Transport Layer Security', '--json'], {
      encoding: 'utf8',
      env: { ...process.env, EXCEPTD_RFC_INDEX: index, EXCEPTD_RESOLVE_CACHE_DIR: dir },
    });
    assert.equal(out.status, 0, `expected exit 0; got ${out.status} (stderr: ${out.stderr.slice(0, 200)})`);
    const body = tryJson(out.stdout.trim());
    assert.ok(body, `stdout must be JSON; got: ${out.stdout.slice(0, 200)}`);
    assert.equal(body.title_match, true);
    assert.equal(body.ok, true);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// ===================================================================
// rfc positional/--check parsing is order-independent
// ===================================================================

test('#50 rfc CLI: --check before the number resolves id to the number, not the title', () => {
  const dir = makeIsolatedDir('k50-');
  try {
    const index = path.join(dir, 'rfc-index.json');
    fs.writeFileSync(index, JSON.stringify({
      'RFC-9404': { number: 9404, title: 'JMAP Blob Management Extension', status: 'Proposed Standard' },
    }));
    // Reordered form: title value sits BEFORE the number.
    const out = spawnSync(
      process.execPath,
      [RFC_CLI, '--check', 'Sieve Email Filtering', '9404', '--json'],
      { encoding: 'utf8', env: { ...process.env, EXCEPTD_RFC_INDEX: index, EXCEPTD_RESOLVE_CACHE_DIR: dir } },
    );
    const body = tryJson(out.stdout.trim());
    assert.ok(body, `stdout must be JSON; got: ${out.stdout.slice(0, 200)} / stderr: ${out.stderr.slice(0, 200)}`);
    // Pre-fix: id resolved to "Sieve Email Filtering" -> a format error, body.id
    // === 'Sieve Email Filtering', not found. Post-fix: id === 9404 resolved.
    assert.equal(body.number, 9404);
    assert.equal(body.found, true);
    assert.equal(body.claimed_title, 'Sieve Email Filtering');
    // The claimed title does not match the JMAP entry -> mismatch -> exit 2.
    assert.equal(body.title_match, false);
    assert.equal(out.status, 2, `expected exit 2; got ${out.status}`);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('#50 rfc CLI: canonical order (number then --check) still resolves the number', () => {
  const dir = makeIsolatedDir('k50-canon-');
  try {
    const index = path.join(dir, 'rfc-index.json');
    fs.writeFileSync(index, JSON.stringify({
      'RFC-9404': { number: 9404, title: 'JMAP Blob Management Extension', status: 'Proposed Standard' },
    }));
    const out = spawnSync(
      process.execPath,
      [RFC_CLI, '9404', '--check', 'Sieve Email Filtering', '--json'],
      { encoding: 'utf8', env: { ...process.env, EXCEPTD_RFC_INDEX: index, EXCEPTD_RESOLVE_CACHE_DIR: dir } },
    );
    const body = tryJson(out.stdout.trim());
    assert.ok(body, `stdout must be JSON; got: ${out.stdout.slice(0, 200)}`);
    assert.equal(body.number, 9404);
    assert.equal(body.title_match, false);
    assert.equal(out.status, 2);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
