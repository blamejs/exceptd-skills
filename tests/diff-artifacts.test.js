'use strict';

/**
 * Subject: the `_diffArtifacts` (diffArtifacts) helper exported from
 * bin/exceptd.js — the field-level artifact comparison that backs
 * `attest diff`.
 *
 * Consolidated from per-finding test files; each source file's contribution is
 * wrapped in a describe() block carrying its original basename so file-local
 * helper/const names cannot collide across merged sources.
 */

const { test, describe } = require('node:test');
const assert = require('node:assert/strict');

const { _diffArtifacts: diffArtifacts } = require('../bin/exceptd.js');
const runner = require('../lib/playbook-runner.js');

test('diff-artifacts subject file loaded', () => {
  assert.ok(true);
});

// ===========================================================================
describe('attest-diff-artifact-key-order', () => {
  test('key-order-only difference is unchanged, not changed', () => {
    const a = { x: { captured: true, value: 'v' } };
    const b = { x: { value: 'v', captured: true } };
    const d = diffArtifacts(a, b);
    assert.equal(d.changed.length, 0, 'reordered-but-equal artifacts must not be "changed"');
    assert.equal(d.unchanged_count, 1, 'reordered-but-equal artifacts must count as unchanged');
  });

  test('nested extra-key reordering is unchanged', () => {
    const a = { x: { captured: true, foo: 1, bar: 2 } };
    const b = { x: { captured: true, bar: 2, foo: 1 } };
    const d = diffArtifacts(a, b);
    assert.equal(d.changed.length, 0, 'nested key reordering must compare equal');
    assert.equal(d.unchanged_count, 1);
  });

  test('a genuine value change is still reported as changed', () => {
    const a = { x: { captured: true, value: 'a' } };
    const b = { x: { captured: true, value: 'b' } };
    const d = diffArtifacts(a, b);
    assert.equal(d.changed.length, 1, 'a real value difference must still be detected');
    assert.equal(d.unchanged_count, 0);
  });

  test('changed[] count agrees with the unchanged verdict for reordered duplicates', () => {
    const a = { artifactA: { captured: true, value: 'v', note: 'n' } };
    const b = { artifactA: { note: 'n', value: 'v', captured: true } };
    const d = diffArtifacts(a, b);
    const statusUnchanged = d.changed.length === 0 && d.added.length === 0 && d.removed.length === 0;
    assert.ok(statusUnchanged, 'reordered duplicates must produce an all-unchanged diff to match status');
  });
});

// ===========================================================================
describe('attest-diff-nonvalue-evidence', () => {
  // Mirror the bin/exceptd.js normalizedArtifacts() observation path: a
  // submission carrying observations is normalized through the real playbook
  // before diffing.
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
    assert.equal(d.changed[0].a_value_preview, 'AWS_SECRET=AKIA...');
    assert.equal(d.changed[0].b_value_preview, 'GCP_KEY=xyz...');
  });
});
