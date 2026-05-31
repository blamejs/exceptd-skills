'use strict';

/**
 * tests/dogfood-precondition-fixes.test.js
 *
 * Pins the fixes the blamejs dogfood surfaced:
 *  - collectors auto-attest the preconditions they can verify from collected
 *    evidence (so `collect --cwd <repo> | run` doesn't spuriously warn on a
 *    repo that clearly has a lockfile / manifest / assistant config — the
 *    runner can't probe the scanned --cwd);
 *  - a YAML COMMENT mentioning a publish verb no longer mis-classifies a CI
 *    workflow as a publish workflow;
 *  - an explicit-false precondition HALT carries a specific remediation, and
 *    the human renderer no longer asserts a platform-gate ("Linux-only") cause
 *    for every precondition block.
 * Exact-value pins per the anti-coincidence rule.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const sbom = require('../lib/collectors/sbom.js');
const libauthor = require('../lib/collectors/library-author.js');
const mcp = require('../lib/collectors/mcp.js');
const { makeSuiteHome, makeCli, tryJson } = require('./_helpers/cli');

const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'exceptd-dogfix-'));
process.on('exit', () => { try { fs.rmSync(TMP, { recursive: true, force: true }); } catch { /* non-fatal */ } });
let _n = 0;
function mkfx() { const d = path.join(TMP, 'fx-' + _n++); fs.mkdirSync(d, { recursive: true }); return d; }

test('sbom collector attests any-package-manager-present from a collected lockfile (and false without one)', () => {
  const withLock = mkfx();
  fs.writeFileSync(path.join(withLock, 'package-lock.json'), '{"lockfileVersion":3,"packages":{"":{}}}');
  assert.equal(sbom.collect({ cwd: withLock }).precondition_checks['any-package-manager-present'], true);
  assert.equal(sbom.collect({ cwd: mkfx() }).precondition_checks['any-package-manager-present'], false);
});

test('library-author collector attests publishable-artifact-evidence from a manifest (and false without one)', () => {
  const withManifest = mkfx();
  fs.writeFileSync(path.join(withManifest, 'package.json'), '{"name":"x","version":"1.0.0"}');
  assert.equal(libauthor.collect({ cwd: withManifest }).precondition_checks['publishable-artifact-evidence'], true);
  assert.equal(libauthor.collect({ cwd: mkfx() }).precondition_checks['publishable-artifact-evidence'], false);
});

test('library-author does NOT classify a CI workflow as publish from a comment-only publish verb', () => {
  const fx = mkfx();
  const wf = path.join(fx, '.github', 'workflows');
  fs.mkdirSync(wf, { recursive: true });
  // ci.yml's only "npm publish" is inside a comment — must not count.
  fs.writeFileSync(path.join(wf, 'ci.yml'),
    'name: ci\njobs:\n  t:\n    steps:\n      - run: echo hi # matches the npm publish workflow depth\n');
  // a real publish workflow with an actual command — must count.
  fs.writeFileSync(path.join(wf, 'release.yml'),
    'name: release\njobs:\n  p:\n    steps:\n      - run: npm publish --provenance\n');
  fs.writeFileSync(path.join(fx, 'package.json'), '{"name":"x","version":"1.0.0"}');
  const meta = libauthor.collect({ cwd: fx }).collector_meta || {};
  const pw = JSON.stringify(meta.publish_workflows || meta.publishWorkflows || []);
  assert.ok(/release\.yml/.test(pw), 'a real npm-publish workflow IS classified as publish');
  assert.ok(!/ci\.yml/.test(pw), 'a CI workflow whose only publish mention is a comment is NOT classified as publish');
});

test('mcp collector attests any-ai-coding-assistant-installed from a config OR an install dir, and never submits false', () => {
  // (a) a vendor config FILE present -> true
  const cfg = mkfx();
  fs.mkdirSync(path.join(cfg, '.cursor'), { recursive: true });
  fs.writeFileSync(path.join(cfg, '.cursor', 'mcp.json'), '{}');
  assert.equal(mcp.collect({ env: { HOME: cfg, USERPROFILE: cfg } }).precondition_checks['any-ai-coding-assistant-installed'], true);
  // (b) an install DIRECTORY present but NO config file yet -> still true
  //     (the precondition treats the dir as satisfying the gate; submitting
  //     false here would wrongly skip the detect phase — codex P2).
  const dirOnly = mkfx();
  fs.mkdirSync(path.join(dirOnly, '.config', 'Code'), { recursive: true });
  assert.equal(mcp.collect({ env: { HOME: dirOnly, USERPROFILE: dirOnly } }).precondition_checks['any-ai-coding-assistant-installed'], true);
  // (c) nothing present -> the key is OMITTED (never false), leaving the
  //     skip_phase gate to the host-side resolver rather than force-skipping.
  const bare = mkfx();
  assert.equal('any-ai-coding-assistant-installed' in mcp.collect({ env: { HOME: bare, USERPROFILE: bare } }).precondition_checks, false);
});

test('explicit-false precondition halt carries a specific remediation, not the generic platform hint', () => {
  const cli = makeCli(makeSuiteHome());
  const ev = JSON.stringify({ precondition_checks: { 'operator-owns-ci-fleet': false } });
  const j = tryJson(cli(['run', 'cicd-pipeline-compromise', '--evidence', '-', '--json'], { input: ev }).stdout);
  assert.equal(j.blocked_by, 'precondition');
  assert.equal(typeof j.remediation, 'string');
  assert.ok(/submitted as false/.test(j.remediation), 'remediation names the specific gate, not a platform guess');
  // The universal satisfaction mechanism (submit the precondition true) must
  // be named — it works for every playbook regardless of which verb blocked.
  assert.ok(/precondition_checks/.test(j.remediation), 'remediation points at the precondition_checks submission mechanism');
  assert.ok(j.remediation.includes('"operator-owns-ci-fleet": true'), 'remediation shows the exact attestation to submit');
  // The flag example must be attributed to the collect verb (it is a collect
  // flag; the block surfaces at run, where passing it is silently ignored).
  assert.ok(/collect cicd-pipeline-compromise --attest-ownership/.test(j.remediation), 'the --attest-ownership example names the collect verb');
  const human = cli(['run', 'cicd-pipeline-compromise', '--evidence', '-'], { input: ev });
  assert.equal(/Linux-only playbook/.test(human.stdout), false, 'the misleading platform-gate hint must not appear on an intent-gate halt');
});
