'use strict';

/**
 * Subject suite for the package.json manifest — the npm publish-readiness
 * invariants and the bin.exceptd entry point. These guard the shape the
 * registry pulls at pack time (files allowlist, scoped public access,
 * provenance) and that the declared bin actually points at bin/exceptd.js.
 */

const test = require('node:test');
const { describe } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

// ===================================================================
// Source: bin-dispatcher.test.js
// ===================================================================
describe('bin-dispatcher.test.js', () => {
  const ROOT = path.join(__dirname, '..');
  const BIN = path.join(ROOT, 'bin', 'exceptd.js');

  test('bin/exceptd.js: package.json bin.exceptd points at this file', () => {
    const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'));
    assert.ok(pkg.bin && pkg.bin.exceptd, 'package.json must declare bin.exceptd');
    const expected = path.normalize(BIN);
    const actual = path.normalize(path.join(ROOT, pkg.bin.exceptd));
    assert.equal(actual, expected);
  });

  test('package.json: publish-readiness invariants', () => {
    const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'));
    assert.notEqual(pkg.private, true, '"private": true blocks npm publish');
    assert.equal(pkg.name, '@blamejs/exceptd-skills');
    assert.ok(Array.isArray(pkg.files) && pkg.files.length > 0, 'files[] whitelist required for clean publish');
    assert.ok(pkg.publishConfig, 'publishConfig required for scoped public publish');
    assert.equal(pkg.publishConfig.access, 'public');
    assert.equal(pkg.publishConfig.provenance, true, 'provenance must be true for OIDC attestation');
  });
});
