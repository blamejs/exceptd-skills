'use strict';

/**
 * Adjacent-hunt regression coverage: the unit-testable fixes from the
 * read-only adjacent/non-surfaced bug hunt.
 *
 *  - reattest BUG-2: the sidecar classifier checks tamper_class BEFORE the
 *    reason strings, so an unsigned-SUBSTITUTION attestation (reason contains
 *    "explicitly unsigned" but carries tamper_class:'unsigned-substitution') is
 *    not mislabeled as the benign 'explicitly-unsigned'.
 *  - EXCEPTD-001/002/003: empty-string flag values are rejected, not silently
 *    degraded to "no scope".
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const bin = require('../bin/exceptd.js');
const { makeCli } = require('./_helpers/cli');

test('reattest sidecar classifier: tamper_class wins over a reason string (unsigned-substitution not mislabeled)', () => {
  // An unsigned-substitution attack: the sidecar is "unsigned" on a host that
  // HAS a private key, so the reason mentions "explicitly unsigned" but the
  // tamper_class flags the substitution. The classifier must surface the attack.
  const cls = bin._classifySidecarVerify({
    signed: false,
    verified: false,
    tamper_class: 'unsigned-substitution',
    reason: 'attestation explicitly unsigned but a private key is present — substitution suspected',
  });
  assert.equal(cls, 'unsigned-substitution', 'a substitution attack must not be classified as benign explicitly-unsigned');

  // A genuinely-unsigned attestation (no tamper_class) still classifies benign.
  const benign = bin._classifySidecarVerify({
    signed: false,
    verified: false,
    reason: 'attestation explicitly unsigned (no private key when written)',
  });
  assert.equal(benign, 'explicitly-unsigned');
});

test('brief --phase "" is rejected, not silently treated as the full brief', () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'v0188-brief-'));
  try {
    const cli = makeCli(home);
    const r = cli(['brief', 'secrets', '--phase', '', '--json'], { env: { EXCEPTD_HOME: home } });
    assert.notEqual(r.status, 0, 'empty --phase must be refused'); // allow-notEqual: a structured refusal; any non-zero exit is correct, the point is it does not run the full brief
  } finally {
    fs.rmSync(home, { recursive: true, force: true });
  }
});

test('brief --all --playbook "" is rejected, not silently planned across all playbooks', () => {
  // The legacy standalone multi-playbook verb was removed; the live path is
  // `brief --all`, which delegates to the multi-playbook planner where the empty
  // --playbook guard lives.
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'v0188-plan-'));
  try {
    const cli = makeCli(home);
    const r = cli(['brief', '--all', '--playbook', '', '--json'], { env: { EXCEPTD_HOME: home } });
    assert.notEqual(r.status, 0, 'empty --playbook must be refused'); // allow-notEqual: structured refusal; any non-zero is correct, the point is it does not plan across all playbooks
    let body = null;
    for (const s of [r.stdout, r.stderr]) { try { const j = JSON.parse(s); if (j) { body = j; break; } } catch { /* not this stream */ } }
    assert.ok(body && body.flag === 'playbook', `the refusal must name the offending flag; got ${r.stdout || r.stderr}`);
  } finally {
    fs.rmSync(home, { recursive: true, force: true });
  }
});
