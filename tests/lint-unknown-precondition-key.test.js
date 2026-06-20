'use strict';

/**
 * Regression: `lint` flags precondition_checks keys the playbook does not
 * declare. Pre-fix, the flat `observations` shape surfaced a foreign
 * precondition id (e.g. crypto collector attesting `kernel-symbols-readable`, which
 * belongs to kernel/runtime/hardening) as unknown_observation_key, but the
 * nested `precondition_checks` shape every collector actually emits was never
 * checked — so collector↔playbook precondition-id drift was silent on the
 * canonical collect→lint path. The new unknown_precondition_key check mirrors
 * unknown_artifact_key / unknown_signal_override_key symmetrically.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const { makeSuiteHome, makeCli, tryJson, secureTmpFile } = require('./_helpers/cli');

const SUITE_HOME = makeSuiteHome('exceptd-lint-precondition-');
const cli = makeCli(SUITE_HOME);

function writeEvidence(name, obj) {
  const p = secureTmpFile(`${name}.json`, 'exceptd-lint-pre-');
  fs.writeFileSync(p, JSON.stringify(obj));
  return p;
}

function lint(playbook, evidencePath) {
  const r = cli(['lint', playbook, evidencePath, '--json']);
  const body = tryJson((r.stdout || '').trim()) || {};
  return { r, body, issues: body.issues || [] };
}

test('nested precondition_checks with a foreign id is flagged unknown_precondition_key', () => {
  // `kernel-symbols-readable` is a precondition id crypto does not declare
  // (crypto declares filesystem-read, openssl-or-equivalent-present, linux-platform).
  const ev = writeEvidence('foreign', { precondition_checks: { 'kernel-symbols-readable': false } });
  const { issues } = lint('crypto', ev);
  const hit = issues.find((i) => i.kind === 'unknown_precondition_key' && i.precondition_id === 'kernel-symbols-readable');
  assert.ok(hit, `expected unknown_precondition_key for kernel-symbols-readable; got kinds=${issues.map((i) => i.kind).join(',')}`);
  assert.equal(hit.severity, 'warn', 'unknown_precondition_key should be a warn (collector drift, not a hard error)');
});

test('precondition_checks with only declared ids yields zero unknown_precondition_key', () => {
  // filesystem-read IS a declared crypto precondition → no unknown-key flag.
  const ev = writeEvidence('known', { precondition_checks: { 'filesystem-read': true } });
  const { issues } = lint('crypto', ev);
  const unknown = issues.filter((i) => i.kind === 'unknown_precondition_key');
  assert.equal(unknown.length, 0,
    `a declared precondition id must not be flagged; got ${JSON.stringify(unknown)}`);
});

test('the same foreign id is flagged in BOTH the nested and flat shapes (parity)', () => {
  // Nested shape: precondition_checks → unknown_precondition_key.
  const nested = lint('crypto', writeEvidence('parity-nested', { precondition_checks: { 'kernel-symbols-readable': false } }));
  const nestedHit = nested.issues.find((i) => i.kind === 'unknown_precondition_key' && i.precondition_id === 'kernel-symbols-readable');
  assert.ok(nestedHit, 'nested shape must flag kernel-symbols-readable via unknown_precondition_key');

  // Flat shape: the same key under observations → unknown_observation_key.
  // The foreign id surfaces in BOTH shapes; pre-fix only the flat side did.
  const flat = lint('crypto', writeEvidence('parity-flat', { observations: { 'kernel-symbols-readable': false } }));
  const flatHit = flat.issues.find(
    (i) => (i.kind === 'unknown_observation_key' || i.kind === 'unknown_precondition_key')
      && (i.key === 'kernel-symbols-readable' || i.precondition_id === 'kernel-symbols-readable'),
  );
  assert.ok(flatHit, `flat shape must also flag kernel-symbols-readable; got kinds=${flat.issues.map((i) => i.kind).join(',')}`);
});
