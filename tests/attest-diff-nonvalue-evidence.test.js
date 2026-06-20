'use strict';

/**
 * Regression: `attest diff` must surface evidence drift when an observation or
 * artifact carries its secret/path/match under a key OTHER than `value`.
 *
 * Two failure modes shared one root:
 *   (1) A direct artifacts entry whose evidence lives under a non-canonical key
 *       (e.g. `matched_secret`) diffed with a_value_preview/b_value_preview =
 *       null/null — the per-field equality compare correctly flagged "changed"
 *       but the differing content was hidden behind a null preview.
 *   (2) Worse: an observation-shape submission carrying its evidence under
 *       `path`/`matched` (a natural collector shape, no explicit `value`) was
 *       normalized to `{ captured }` only — `value` undefined, path/matched
 *       discarded. Two attestations capturing DIFFERENT secrets at DIFFERENT
 *       paths then diffed byte-identical (`unchanged_count:1`, changed empty),
 *       a false "unchanged" that masks the exact drift `attest diff` exists to
 *       expose. (The top-level `status` still read "drifted" because the
 *       evidence_hash hashes the raw observations — so the diff contradicted
 *       its own status.)
 *
 * normalizeSubmission now preserves the observation's extra evidence keys, and
 * the diff renderer falls back to previewing the whole evidence object (minus
 * the captured flag) when `.value` is absent.
 */

const test = require('node:test');
const assert = require('node:assert/strict');

const runner = require('../lib/playbook-runner.js');
const { _diffArtifacts: diffArtifacts } = require('../bin/exceptd.js');

// Mirror the bin/exceptd.js normalizedArtifacts() observation path: a submission
// carrying observations is normalized through the real playbook before diffing.
function normalizedArtifacts(submission, playbookId) {
  const pb = runner.loadPlaybook(playbookId);
  const norm = runner.normalizeSubmission({ observations: submission.observations }, pb);
  return (norm && norm.artifacts) || {};
}

test('Mode 2: observation evidence under path/matched is preserved through normalize', () => {
  const sub = { observations: { 'env-files': { captured: true, path: '/srv/app/.env', matched: 'AWS_SECRET=AKIA...' } } };
  const art = normalizedArtifacts(sub, 'secrets')['env-files'];
  assert.equal(art.captured, true, 'captured flag survives');
  assert.equal(art.path, '/srv/app/.env', 'path evidence is preserved, not discarded');
  assert.equal(art.matched, 'AWS_SECRET=AKIA...', 'matched secret is preserved, not discarded');
});

test('Mode 2: two observations with different path/matched diff as CHANGED, not unchanged', () => {
  const a = normalizedArtifacts(
    { observations: { 'env-files': { captured: true, path: '/srv/app/.env', matched: 'AWS_SECRET=AKIA...' } } }, 'secrets');
  const b = normalizedArtifacts(
    { observations: { 'env-files': { captured: true, path: '/srv/app/.env.prod', matched: 'GCP_KEY=xyz...' } } }, 'secrets');
  const d = diffArtifacts(a, b);
  assert.equal(d.unchanged_count, 0, 'differing secrets must NOT count as unchanged');
  assert.equal(d.changed.length, 1, 'the differing artifact must be reported as changed');
  assert.equal(d.changed[0].id, 'env-files');
  // Preview is non-null AND reflects the differing content.
  assert.equal(typeof d.changed[0].a_value_preview, 'string', 'a preview must be a non-null string');
  assert.equal(typeof d.changed[0].b_value_preview, 'string', 'b preview must be a non-null string');
  assert.ok(/srv\/app\/\.env(?!\.prod)/.test(d.changed[0].a_value_preview), 'a preview shows the A-side path');
  assert.ok(d.changed[0].b_value_preview.includes('/srv/app/.env.prod'), 'b preview shows the B-side path');
  assert.notEqual(d.changed[0].a_value_preview, d.changed[0].b_value_preview, 'previews must differ');
});

test('Mode 2: identical observations still diff as unchanged (no false positive)', () => {
  const obs = { observations: { 'env-files': { captured: true, path: '/srv/app/.env', matched: 'AWS_SECRET=AKIA...' } } };
  const a = normalizedArtifacts(obs, 'secrets');
  const b = normalizedArtifacts(obs, 'secrets');
  const d = diffArtifacts(a, b);
  assert.equal(d.changed.length, 0, 'identical evidence must not be reported as changed');
  assert.equal(d.unchanged_count, 1);
});

test('Mode 1: direct artifacts with secret under a non-value key diff with NON-null previews', () => {
  const a = { 'env-files': { captured: true, matched_secret: 'AKIAEXAMPLE' } };
  const b = { 'env-files': { captured: false, matched_secret: 'DIFFERENT' } };
  const d = diffArtifacts(a, b);
  assert.equal(d.changed.length, 1, 'differing artifacts must be reported as changed');
  assert.equal(typeof d.changed[0].a_value_preview, 'string', 'preview must not be null when evidence is under a non-value key');
  assert.equal(typeof d.changed[0].b_value_preview, 'string');
  assert.ok(d.changed[0].a_value_preview.includes('AKIAEXAMPLE'), 'A-side secret content surfaces');
  assert.ok(d.changed[0].b_value_preview.includes('DIFFERENT'), 'B-side secret content surfaces');
});

test('canonical value-bearing observation still previews the raw value (no regression)', () => {
  const a = normalizedArtifacts({ observations: { 'env-files': { captured: true, value: 'AWS_SECRET=AKIA...' } } }, 'secrets');
  const b = normalizedArtifacts({ observations: { 'env-files': { captured: true, value: 'GCP_KEY=xyz...' } } }, 'secrets');
  const d = diffArtifacts(a, b);
  assert.equal(d.changed.length, 1);
  // When `.value` is present, the preview is the raw value string — not a wrapped object.
  assert.equal(d.changed[0].a_value_preview, 'AWS_SECRET=AKIA...');
  assert.equal(d.changed[0].b_value_preview, 'GCP_KEY=xyz...');
});

test('reserved control keys (indicator/result) are not leaked into the artifact', () => {
  // An observation that only declares an indicator/result drives signal_overrides;
  // it must not echo those control keys as artifact evidence.
  const norm = runner.normalizeSubmission(
    { observations: { w: { captured: true, indicator: 'aws-access-key-id', result: 'hit' } } },
    runner.loadPlaybook('secrets'));
  assert.deepEqual(norm.artifacts.w, { captured: true }, 'control-only observation yields a bare {captured} artifact');
  assert.equal(norm.signal_overrides['aws-access-key-id'], 'hit', 'the indicator still drives signal_overrides');
});
