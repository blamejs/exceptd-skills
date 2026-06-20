'use strict';

/**
 * Regression: `attest diff <session> --against ""` (or `--against=`) must
 * REFUSE, not silently fall through to the auto-prior comparison.
 *
 * `--against` is in REQUIRES_VALUE, which catches the value-less form
 * (`--against` parsed as boolean `true`). It does NOT catch the empty-string
 * form: `--against ""` and `--against=` both parse to `args.against === ""`,
 * which is falsy. Pre-fix the diff subverb gated the explicit two-session
 * branch on `if (args.against)`, so an empty value skipped it and dropped into
 * the no-against path that auto-selects the most-recent prior for the same
 * playbook. The operator's named comparison target was silently swapped for a
 * different baseline — the classic `--against "$VAR"` footgun where $VAR
 * expanded to empty yields a drift verdict against the wrong session with no
 * signal.
 *
 * Exact exit-code + message-content assertions per the anti-coincidence rule:
 * assert status === 1 (GENERIC_FAILURE) AND the /empty value/ message, never
 * just status !== 0 (which would also pass for the tamper/no-prior paths).
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const { ROOT, makeSuiteHome, makeCli, tryJson } = require('./_helpers/cli');
const { EXIT_CODES } = require(path.join(ROOT, 'lib', 'exit-codes.js'));

const SUITE_HOME = makeSuiteHome('exceptd-attest-diff-against-empty-');
const cli = makeCli(SUITE_HOME);

const GENERIC_FAILURE = EXIT_CODES.GENERIC_FAILURE; // 1

// Stage a minimal session dir directly (no signing key needed): the empty-
// --against guard fires before any sidecar verification, so the attestation
// content/signature is irrelevant to this refusal. The session dir only has
// to EXIST so the primary-sid findSessionDir() lookup succeeds and execution
// reaches the diff subverb's argument handling.
function stageSession(sid, playbookId) {
  const dir = path.join(SUITE_HOME, 'attestations', sid);
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(
    path.join(dir, 'attestation.json'),
    JSON.stringify({
      kind: 'attestation',
      playbook_id: playbookId,
      session_id: sid,
      captured_at: '2026-06-19T12:00:00.000Z',
      evidence_hash: 'hash-' + sid,
      submission: {},
    }, null, 2),
  );
  return dir;
}

function lastJson(s) {
  return tryJson((s || '').split('\n').filter((l) => l.trim().startsWith('{')).pop() || '') || {};
}

test('attest diff --against "" refuses with exit 1 and an empty-value message', () => {
  const sid = 'against-empty-self-' + Date.now();
  stageSession(sid, 'mcp-supply-chain');

  const r = cli(['attest', 'diff', sid, '--against', '', '--json']);
  assert.equal(r.status, GENERIC_FAILURE,
    `empty --against must exit ${GENERIC_FAILURE} (GENERIC_FAILURE), not fall through. Got ${r.status}. stderr=${r.stderr.slice(0, 400)}`);
  const body = lastJson([r.stdout, r.stderr].join('\n'));
  assert.equal(body.ok, false, 'refusal body must carry ok:false');
  assert.equal(body.verb, 'attest diff');
  assert.equal(body.flag, 'against', 'refusal must identify the offending flag');
  assert.match(body.error, /empty value/i, 'message must name the empty-value cause');
});

test('attest diff --against= (eq form) also refuses with exit 1', () => {
  const sid = 'against-eq-empty-self-' + (Date.now() + 1);
  stageSession(sid, 'mcp-supply-chain');

  const r = cli(['attest', 'diff', sid, '--against=', '--json']);
  assert.equal(r.status, GENERIC_FAILURE,
    `--against= must exit ${GENERIC_FAILURE}. Got ${r.status}. stderr=${r.stderr.slice(0, 400)}`);
  const body = lastJson([r.stdout, r.stderr].join('\n'));
  assert.equal(body.ok, false);
  assert.match(body.error, /empty value/i);
});

test('attest diff with NO --against still runs the auto-prior path (no false refusal)', () => {
  // Guard against over-broadening the refusal: the absent-flag case must reach
  // the auto-prior branch, not be caught by the empty-string guard. With no
  // prior for the playbook this run becomes the baseline (status no-prior,
  // exit 0) — proving the absent flag is NOT treated as empty.
  const sid = 'against-absent-self-' + (Date.now() + 2);
  stageSession(sid, 'kernel-lpe-unique-' + Date.now());

  const r = cli(['attest', 'diff', sid, '--json']);
  assert.equal(r.status, 0,
    `no --against with no prior must exit 0 (baseline), not refuse. Got ${r.status}. stderr=${r.stderr.slice(0, 400)}`);
  const body = lastJson(r.stdout);
  assert.equal(body.status, 'no-prior',
    'absent --against must reach the auto-prior branch (no-prior baseline), not the empty-value refusal');
});
