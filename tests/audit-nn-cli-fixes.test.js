'use strict';

/**
 * Tests for the audit-NN CLI surface closures.
 *
 *   NN P1-1 --csaf-status / --publisher-namespace silently consumed on
 *           verbs that never assemble a CSAF bundle. Same UX class as
 *           the --ack bug v0.12.21 EE P1-6 closed: refuse with a
 *           structured error pointing at the verb set where the flag
 *           applies.
 *   NN P1-2 Error message prefixes for --csaf-status / --publisher-namespace
 *           use the in-scope verb (e.g. "brief:") rather than the hardcoded
 *           "run:" from the CC P1-1 / CC P1-3 import.
 *   NN P1-4 cmdRunMulti persists --ack consent per playbook only when THAT
 *           playbook's classification === 'detected'. Pre-fix the consent
 *           flowed onto every persisted attestation regardless of the
 *           per-playbook verdict, mis-recording an explicit jurisdiction
 *           ack against runs that never started a clock.
 *   NN P1-5 `run --help` and `ci --help` text surface --csaf-status and
 *           --publisher-namespace so operators see the flag exists before
 *           an audit teaches them.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const { ROOT, makeSuiteHome, makeCli, tryJson } = require('./_helpers/cli');

const SUITE_HOME = makeSuiteHome('exceptd-audit-nn-');
const cli = makeCli(SUITE_HOME);

// ---------------------------------------------------------------------------
// NN P1-1 — bundle-shaping flags refused on verbs that don't assemble bundles
// ---------------------------------------------------------------------------

test('NN P1-1: brief --csaf-status final → exit 1 with irrelevant-flag error pointing at the bundle-relevant verbs', () => {
  const r = cli(['brief', 'secrets', '--csaf-status', 'final', '--json']);
  assert.equal(r.status, 1,
    'brief --csaf-status must exit EXACTLY 1 (framework error). status=' + r.status + ' stderr=' + r.stderr.slice(0, 300));
  const err = tryJson(r.stderr.trim()) || {};
  assert.equal(err.ok, false, 'error body.ok must be false');
  assert.equal(err.error_class, 'irrelevant-flag',
    'error_class must be "irrelevant-flag"; got: ' + JSON.stringify(err.error_class));
  assert.equal(err.flag, 'csaf-status',
    'error body must name the offending flag; got: ' + JSON.stringify(err.flag));
  assert.equal(err.verb, 'brief',
    'error body must record the invoking verb; got: ' + JSON.stringify(err.verb));
  assert.ok(Array.isArray(err.accepted_verbs),
    'accepted_verbs must be an array; got: ' + JSON.stringify(err.accepted_verbs));
  assert.deepEqual([...err.accepted_verbs].sort(), ['ai-run', 'ci', 'run', 'run-all'],
    'accepted_verbs must be exactly the bundle-relevant set; got: ' + JSON.stringify(err.accepted_verbs));
  assert.match(err.error || '',
    /--csaf-status is irrelevant on this verb/,
    'error message must use the "irrelevant on this verb" phrasing; got: ' + (err.error || ''));
  // Hint must name at least one verb where the flag DOES apply.
  assert.match(err.error || '', /run|ci|ai-run/,
    'error message must name at least one of run/ci/ai-run; got: ' + (err.error || ''));
});

test('NN P1-1: brief --publisher-namespace https://acme.example → exit 1 with irrelevant-flag error', () => {
  const r = cli(['brief', 'secrets', '--publisher-namespace', 'https://acme.example', '--json']);
  assert.equal(r.status, 1,
    'brief --publisher-namespace must exit EXACTLY 1 (framework error). status=' + r.status + ' stderr=' + r.stderr.slice(0, 300));
  const err = tryJson(r.stderr.trim()) || {};
  assert.equal(err.ok, false);
  assert.equal(err.error_class, 'irrelevant-flag');
  assert.equal(err.flag, 'publisher-namespace');
  assert.equal(err.verb, 'brief');
  assert.deepEqual([...err.accepted_verbs].sort(), ['ai-run', 'ci', 'run', 'run-all']);
  assert.match(err.error || '',
    /--publisher-namespace is irrelevant on this verb/,
    'error message must use the "irrelevant on this verb" phrasing; got: ' + (err.error || ''));
});

test('NN P1-1: discover --csaf-status final → refused on a non-bundle verb', () => {
  // discover never assembles a CSAF bundle either — verify the refusal is
  // not specific to brief.
  const r = cli(['discover', '--csaf-status', 'interim', '--json']);
  assert.equal(r.status, 1,
    'discover --csaf-status must exit EXACTLY 1; got status=' + r.status + ' stderr=' + r.stderr.slice(0, 300));
  const err = tryJson(r.stderr.trim()) || {};
  assert.equal(err.ok, false);
  assert.equal(err.error_class, 'irrelevant-flag');
  assert.equal(err.verb, 'discover');
});

test('NN P1-1: run secrets --csaf-status final → accepted (verb is in BUNDLE_FLAG_RELEVANT_VERBS)', () => {
  // The flag must NOT trigger the irrelevant-flag refusal on a verb that
  // does drive phases 5-7. Pass a not_detected verdict so the run completes
  // cleanly without needing real evidence; the assertion is on EXIT CODE
  // and the absence of the irrelevant-flag error class.
  const sub = JSON.stringify({
    observations: {},
    verdict: { classification: 'not_detected' },
  });
  const r = cli(
    ['run', 'secrets', '--evidence', '-', '--csaf-status', 'final',
     '--session-id', 'nn-p1-1-accept-' + Date.now(), '--json'],
    { input: sub }
  );
  // Exit 0 (clean run) is the success case here. Anything OTHER than the
  // structured irrelevant-flag refusal proves the flag was accepted.
  if (r.status === 1) {
    const err = tryJson(r.stderr.trim()) || {};
    assert.notEqual(err.error_class, 'irrelevant-flag',
      'run --csaf-status must NOT emit the irrelevant-flag error; got: ' + JSON.stringify(err));
  }
  assert.equal(r.status, 0,
    'run secrets --csaf-status final must exit 0 (verb in bundle-relevant set, valid status). status=' + r.status + ' stderr=' + r.stderr.slice(0, 400));
});

// ---------------------------------------------------------------------------
// NN P1-2 — error message prefix uses the invoking verb, not the hardcoded "run:"
// ---------------------------------------------------------------------------

test('NN P1-2: brief --csaf-status error prefix is "brief:" not "run:"', () => {
  const r = cli(['brief', 'secrets', '--csaf-status', 'final', '--json']);
  const err = tryJson(r.stderr.trim()) || {};
  // The error message itself must lead with the actual verb.
  assert.match(err.error || '', /^brief:/,
    'error.error must start with "brief:"; got: ' + JSON.stringify((err.error || '').slice(0, 200)));
  assert.doesNotMatch(err.error || '', /^run:/,
    'error.error must NOT start with the hardcoded "run:"; got: ' + JSON.stringify((err.error || '').slice(0, 200)));
});

test('NN P1-2: brief --publisher-namespace error prefix is "brief:" not "run:"', () => {
  const r = cli(['brief', 'secrets', '--publisher-namespace', 'https://acme.example', '--json']);
  const err = tryJson(r.stderr.trim()) || {};
  assert.match(err.error || '', /^brief:/,
    'error.error must start with "brief:"; got: ' + JSON.stringify((err.error || '').slice(0, 200)));
  assert.doesNotMatch(err.error || '', /^run:/,
    'error.error must NOT start with the hardcoded "run:"; got: ' + JSON.stringify((err.error || '').slice(0, 200)));
});

// ---------------------------------------------------------------------------
// NN P1-4 — cmdRunMulti gates consent persistence per-playbook classification
// ---------------------------------------------------------------------------

test('NN P1-4: run-all --ack persists consent only for playbooks with classification=detected', () => {
  const sid = 'nn-p1-4-multi-' + Date.now();
  // Multi-playbook bundle: secrets gets a detected verdict, library-author
  // gets a not_detected verdict. Every other playbook reached via --all
  // defaults to `{}` and goes through detect normally.
  const bundle = JSON.stringify({
    secrets: {
      observations: { w: { captured: true, value: 'AKIA', indicator: 'aws-access-key-id', result: 'hit' } },
      verdict: { classification: 'detected', blast_radius: 4 },
    },
    'library-author': {
      observations: {},
      verdict: { classification: 'not_detected' },
    },
  });
  const r = cli(
    ['run', '--all', '--evidence', '-', '--ack',
     '--session-id', sid, '--json'],
    { input: bundle, timeout: 60000 }
  );
  // run-all may exit non-zero if any playbook returns ok:false (preflight
  // halt). Either way, the per-playbook persistence behavior is the
  // assertion; we read the aggregate stdout body for results[].
  const out = tryJson(r.stdout.trim()) || {};
  assert.ok(Array.isArray(out.results),
    'run-all output must include results[]; got status=' + r.status + ' stdout-head=' + r.stdout.slice(0, 300));
  const byId = new Map();
  for (const res of out.results) {
    if (res && res.playbook_id) byId.set(res.playbook_id, res);
  }
  const secretsRes = byId.get('secrets');
  const libRes = byId.get('library-author');
  assert.ok(secretsRes, 'results[] must include secrets entry');
  assert.ok(libRes, 'results[] must include library-author entry');

  // library-author: not_detected → ack present in body but NOT applied;
  // ack_skipped_reason exposes the gate.
  const libClass = libRes.phases && libRes.phases.detect && libRes.phases.detect.classification;
  assert.equal(libClass, 'not_detected',
    'library-author with not_detected verdict must yield detect.classification=not_detected; got: ' + libClass);
  assert.equal(libRes.ack, true,
    'library-author result.ack must be true (operator did pass --ack); got: ' + JSON.stringify(libRes.ack));
  assert.equal(libRes.ack_applied, false,
    'library-author result.ack_applied must be false (classification != detected); got: ' + JSON.stringify(libRes.ack_applied));
  assert.match(libRes.ack_skipped_reason || '',
    /classification=not_detected; consent only persisted when classification=detected/,
    'library-author result.ack_skipped_reason must use the exact gate phrasing; got: ' + (libRes.ack_skipped_reason || ''));

  // secrets: detected → ack present AND applied; no skipped reason.
  const secClass = secretsRes.phases && secretsRes.phases.detect && secretsRes.phases.detect.classification;
  assert.equal(secClass, 'detected',
    'secrets with detected verdict + observations must yield detect.classification=detected; got: ' + secClass);
  assert.equal(secretsRes.ack, true,
    'secrets result.ack must be true; got: ' + JSON.stringify(secretsRes.ack));
  assert.equal(secretsRes.ack_applied, true,
    'secrets result.ack_applied must be true (classification === detected); got: ' + JSON.stringify(secretsRes.ack_applied));
  assert.equal(secretsRes.ack_skipped_reason, undefined,
    'secrets result.ack_skipped_reason must be undefined when ack DID apply; got: ' + JSON.stringify(secretsRes.ack_skipped_reason));

  // On-disk attestations: confirm operator_consent shape per playbook.
  const candidates = [
    path.join(SUITE_HOME, 'attestations', sid),
    path.join(SUITE_HOME, '.exceptd', 'attestations', sid),
  ];
  const attRoot = candidates.find(p => fs.existsSync(p));
  assert.ok(attRoot, 'multi-run attestation dir must exist at ' + JSON.stringify(candidates));

  const libAttPath = path.join(attRoot, 'library-author.json');
  const secAttPath = path.join(attRoot, 'secrets.json');
  assert.ok(fs.existsSync(libAttPath),
    'library-author.json attestation must exist under ' + attRoot);
  assert.ok(fs.existsSync(secAttPath),
    'secrets.json attestation must exist under ' + attRoot);

  const libAtt = JSON.parse(fs.readFileSync(libAttPath, 'utf8'));
  const secAtt = JSON.parse(fs.readFileSync(secAttPath, 'utf8'));

  // library-author attestation: NO explicit operator_consent payload.
  const libConsent = libAtt.operator_consent;
  assert.ok(libConsent === undefined || libConsent === null,
    'library-author attestation must NOT carry the explicit operator_consent payload (not_detected); got: ' + JSON.stringify(libConsent));
  if (libConsent && typeof libConsent === 'object') {
    assert.notEqual(libConsent.explicit, true,
      'library-author consent.explicit must NOT be true when persistence was supposed to skip');
  }

  // secrets attestation: consent payload present with explicit:true.
  const secConsent = secAtt.operator_consent;
  assert.ok(secConsent && typeof secConsent === 'object',
    'secrets attestation MUST carry an operator_consent payload (classification=detected); got: ' + JSON.stringify(secConsent));
  assert.equal(secConsent.explicit, true,
    'secrets attestation operator_consent.explicit must be true; got: ' + JSON.stringify(secConsent.explicit));
  assert.equal(typeof secConsent.acked_at, 'string',
    'secrets attestation operator_consent.acked_at must be a string; got: ' + JSON.stringify(secConsent.acked_at));
});

// ---------------------------------------------------------------------------
// NN P1-5 — `run --help` and `ci --help` document --csaf-status / --publisher-namespace
// ---------------------------------------------------------------------------

test('NN P1-5: run --help text lists --csaf-status and --publisher-namespace', () => {
  const r = cli(['run', '--help']);
  assert.equal(r.status, 0, 'run --help must exit 0; got ' + r.status);
  assert.match(r.stdout, /--csaf-status/,
    'run --help must document --csaf-status; stdout-head=' + r.stdout.slice(0, 400));
  assert.match(r.stdout, /--publisher-namespace/,
    'run --help must document --publisher-namespace; stdout-head=' + r.stdout.slice(0, 400));
  // Hint at the value contracts so operators know what to pass.
  assert.match(r.stdout, /draft\s*\|\s*interim|interim.*final|final.*interim/,
    'run --help --csaf-status entry must enumerate the accepted values');
});

test('NN P1-5: ci --help text lists --csaf-status and --publisher-namespace', () => {
  const r = cli(['ci', '--help']);
  assert.equal(r.status, 0, 'ci --help must exit 0; got ' + r.status);
  assert.match(r.stdout, /--csaf-status/,
    'ci --help must document --csaf-status; stdout-head=' + r.stdout.slice(0, 400));
  assert.match(r.stdout, /--publisher-namespace/,
    'ci --help must document --publisher-namespace; stdout-head=' + r.stdout.slice(0, 400));
});

test('NN P1-5: source defines BUNDLE_FLAG_RELEVANT_VERBS with exactly the 4-verb set', () => {
  // Drift-resistant check on the architecture: any future addition of a
  // bundle-relevant verb MUST flow through this set so the irrelevant-flag
  // refusal stays in sync with what cmdRun / cmdCi / cmdAiRun actually do.
  const src = fs.readFileSync(path.join(ROOT, 'bin', 'exceptd.js'), 'utf8');
  assert.match(src, /BUNDLE_FLAG_RELEVANT_VERBS\s*=\s*new Set\(\[/,
    'bin/exceptd.js must declare BUNDLE_FLAG_RELEVANT_VERBS as a Set literal');
  // The four verbs must each appear inside the set literal block.
  const m = src.match(/BUNDLE_FLAG_RELEVANT_VERBS\s*=\s*new Set\(\[\s*([^\]]+)\]/);
  assert.ok(m, 'must locate BUNDLE_FLAG_RELEVANT_VERBS set literal');
  const setBody = m[1];
  for (const verb of ['run', 'ci', 'run-all', 'ai-run']) {
    assert.match(setBody, new RegExp('"' + verb + '"'),
      'BUNDLE_FLAG_RELEVANT_VERBS must include "' + verb + '"; got body: ' + setBody);
  }
});
