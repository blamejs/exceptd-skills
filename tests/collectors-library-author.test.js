'use strict';

/**
 * tests/collectors-library-author.test.js
 *
 * Subject coverage for lib/collectors/library-author.js:
 *  - the collector auto-attests the `publishable-artifact-evidence`
 *    precondition from a manifest (false without one);
 *  - a YAML COMMENT mentioning a publish verb does NOT mis-classify a CI
 *    workflow as a publish workflow, while a real `npm publish` command does.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const libauthor = require('../lib/collectors/library-author.js');

const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'exceptd-libauthor-coll-'));
process.on('exit', () => { try { fs.rmSync(TMP, { recursive: true, force: true }); } catch { /* non-fatal */ } });
let _n = 0;
function mkfx() { const d = path.join(TMP, 'fx-' + _n++); fs.mkdirSync(d, { recursive: true }); return d; }

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

test('library-author flags a floating action ref that carries a trailing YAML comment', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'libauth-'));
  try {
    const wfDir = path.join(dir, '.github', 'workflows');
    fs.mkdirSync(wfDir, { recursive: true });
    // A publish-shaped workflow with a floating (non-SHA) ref AND a trailing
    // comment — the case the `$`-anchored regex used to miss entirely.
    fs.writeFileSync(path.join(wfDir, 'release.yml'), [
      'name: release',
      'on: { push: { tags: ["v*"] } }',
      'jobs:',
      '  publish:',
      '    runs-on: ubuntu-latest',
      '    steps:',
      '      - uses: actions/checkout@v4  # pin this eventually',
      '      - run: npm publish',
    ].join('\n'));
    const res = libauthor.collect({ cwd: dir });
    assert.equal(
      res.signal_overrides['publish-workflow-action-refs-mutable'],
      'hit',
      `a floating ref with a trailing comment must register a hit; signal_overrides=${JSON.stringify(res.signal_overrides)}`,
    );
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
