'use strict';

/**
 * Regression: README.md is consumed by the stale-content index builder
 * (badge-count drift check), so it must be a hashed source in _meta.json —
 * otherwise a README edit is invisible to the --changed planner and the
 * validate-indexes freshness gate, breaking the "every consumed source is
 * hashed" invariant.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const ROOT = path.join(__dirname, '..');
const META = JSON.parse(fs.readFileSync(path.join(ROOT, 'data', '_indexes', '_meta.json'), 'utf8'));

test('README.md is a tracked/hashed index source', () => {
  assert.ok(META.source_hashes && typeof META.source_hashes === 'object', '_meta.source_hashes must exist');
  assert.equal(
    Object.prototype.hasOwnProperty.call(META.source_hashes, 'README.md'),
    true,
    'README.md must be hashed in _meta.source_hashes (the stale-content builder consumes it)'
  );
  assert.equal(typeof META.source_hashes['README.md'], 'string');
});

test('validate-indexes accepts README.md as a hashed source (does not flag it removed)', () => {
  // build-indexes and validate-indexes maintain parallel source-set
  // definitions; both must include README or the validator reports the hashed
  // README as a "removed file" and the freshness gate fails.
  const r = spawnSync(process.execPath, [path.join(ROOT, 'lib', 'validate-indexes.js')], { encoding: 'utf8' });
  assert.equal(r.status, 0,
    `validate-indexes must pass with README hashed; stdout:\n${r.stdout}\nstderr:\n${r.stderr}`);
  assert.equal(/README\.md/.test(r.stderr || '') && /removed|stale source/.test(r.stderr || ''), false,
    'validate-indexes must not report README.md as a removed/stale source');
});
