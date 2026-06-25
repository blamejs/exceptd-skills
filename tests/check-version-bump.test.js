"use strict";


// ---- routed from version-bump-cadence ----
require("node:test").describe("version-bump-cadence", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
/**
 * Regression for the patch-only-cadence gate (scripts/check-version-bump.js).
 * Patch is the only default bump; minor/major require an explicit committed
 * ack naming the exact target version. These tests pin both the bump
 * classification and the authorization policy.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');

const { classifyBump, checkBump, changelogVersions, determinePrevious } =
  require(path.resolve(__dirname, '..', 'scripts', 'check-version-bump.js'));

test('classifyBump distinguishes patch / minor / major / none / downgrade', () => {
  assert.equal(classifyBump('0.18.2', '0.18.3'), 'patch');
  assert.equal(classifyBump('0.18.2', '0.19.0'), 'minor');
  assert.equal(classifyBump('0.18.2', '1.0.0'), 'major');
  assert.equal(classifyBump('0.18.2', '0.18.2'), 'none');
  assert.equal(classifyBump('0.18.2', '0.18.1'), 'downgrade');
  assert.equal(classifyBump('0.18.2', '0.17.9'), 'downgrade');
  assert.equal(classifyBump('0.18.2', '0.0.0'), 'downgrade');
  assert.equal(classifyBump('not-a-version', '0.18.3'), 'unknown');
});

test('a patch bump passes with no ack required', () => {
  const r = checkBump('0.18.2', '0.18.3', null);
  assert.equal(r.ok, true);
  assert.equal(r.bump, 'patch');
});

test('an equal version (re-run) passes', () => {
  const r = checkBump('0.18.2', '0.18.2', null);
  assert.equal(r.ok, true);
  assert.equal(r.bump, 'none');
});

test('an UNAUTHORIZED minor bump is blocked', () => {
  const r = checkBump('0.18.2', '0.19.0', null);
  assert.equal(r.ok, false);
  assert.equal(r.bump, 'minor');
  assert.match(r.reason, /not the patch-only default/);
});

test('a minor bump with a matching ack is allowed', () => {
  const r = checkBump('0.18.2', '0.19.0', { version: '0.19.0', type: 'minor' });
  assert.equal(r.ok, true);
  assert.equal(r.bump, 'minor');
});

test('an ack for a DIFFERENT version does not authorize the bump', () => {
  const r = checkBump('0.18.2', '0.19.0', { version: '0.20.0', type: 'minor' });
  assert.equal(r.ok, false, 'a stale/mismatched ack must not authorize');
});

test('an ack with the wrong type does not authorize the bump', () => {
  const r = checkBump('0.18.2', '1.0.0', { version: '1.0.0', type: 'minor' });
  assert.equal(r.ok, false, 'a major bump needs a major ack, not a minor ack');
});

test('an UNAUTHORIZED major bump is blocked', () => {
  const r = checkBump('0.18.2', '1.0.0', null);
  assert.equal(r.ok, false);
  assert.equal(r.bump, 'major');
});

test('a major bump with a matching ack is allowed', () => {
  const r = checkBump('0.18.2', '1.0.0', { version: '1.0.0', type: 'major' });
  assert.equal(r.ok, true);
  assert.equal(r.bump, 'major');
});

test('a downgrade is blocked even with an ack', () => {
  const r = checkBump('0.18.2', '0.18.1', { version: '0.18.1', type: 'minor' });
  assert.equal(r.ok, false);
  assert.equal(r.bump, 'downgrade');
});

test('the first release (no previous version) passes', () => {
  const r = checkBump(null, '0.1.0', null);
  assert.equal(r.ok, true);
});

test('changelogVersions extracts headings in document order', () => {
  const md = '# Changelog\n\n## 0.19.0 — 2026-06-14\n\nstuff\n\n## 0.18.2 — 2026-06-13\n\nmore\n';
  assert.deepEqual(changelogVersions(md), ['0.19.0', '0.18.2']);
});

// The cadence gate must FAIL CLOSED when it cannot determine the previous
// version. Previously main() swallowed a CHANGELOG read error to '' so
// versions=[] -> prev=null -> checkBump's initial-release pass authorized ANY
// bump (incl. an unapproved major). determinePrevious is the fail-closed guard.
test('determinePrevious fails closed when CHANGELOG is unreadable (null text)', () => {
  const r = determinePrevious(null, '0.18.17');
  assert.equal(r.ok, false, 'an unreadable CHANGELOG must fail the gate, not pass as "initial release"');
});

test('determinePrevious fails closed on a CHANGELOG with no version headings', () => {
  const r = determinePrevious('# Changelog\n\nsome prose, no headings\n', '0.18.17');
  assert.equal(r.ok, false, 'a heading-less CHANGELOG cannot determine cadence — fail closed');
});

test('determinePrevious yields the prior version for a normal CHANGELOG', () => {
  const r = determinePrevious('## 0.18.17\n\nx\n\n## 0.18.16\n\ny\n', '0.18.17');
  assert.equal(r.ok, true);
  assert.equal(r.prev, '0.18.16');
});

test('determinePrevious allows a genuine first release (sole heading == cur, prev=null)', () => {
  const r = determinePrevious('## 0.1.0\n\nfirst\n', '0.1.0');
  assert.equal(r.ok, true);
  assert.equal(r.prev, null, 'a real first release has its own heading and resolves prev=null with ok:true');
});

test('an unauthorized major cannot sail through via a missing CHANGELOG', () => {
  // The exact false-pass shape: read failed (text=null) while package.json
  // jumped to a major. The gate must refuse to even reach checkBump's
  // initial-release pass.
  const prevRes = determinePrevious(null, '5.0.0');
  assert.equal(prevRes.ok, false, 'no previous-version context => fail closed, never the initial-release pass');
});
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});
