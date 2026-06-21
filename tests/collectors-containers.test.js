'use strict';

/**
 * tests/collectors-containers.test.js
 *
 * Subject coverage for lib/collectors/containers.js:
 *  - the collector resets USER state per build stage, so a multi-stage build
 *    with a non-root USER in an early stage does NOT mask a root final stage;
 *    FROM <alias> inherits the parent stage USER, scratch resets to root;
 *  - hasContainerArtifacts finds Dockerfiles / compose anywhere in the tree, by
 *    filename variant.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const containers = require('../lib/collectors/containers.js');
const containersCollector = containers;
const { makeSuiteHome, makeCli, tryJson } = require('./_helpers/cli');

const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'exceptd-containers-coll-'));
process.on('exit', () => { try { fs.rmSync(TMP, { recursive: true, force: true }); } catch { /* non-fatal */ } });
let _n = 0;
function mkfx() { const d = path.join(TMP, 'fx-' + _n++); fs.mkdirSync(d, { recursive: true }); return d; }

function dockerfileTempdir(content) {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'hunt-c12-'));
  fs.writeFileSync(path.join(d, 'Dockerfile'), content, 'utf8');
  return d;
}

test('#12 multi-stage build with non-root builder USER but root final stage is a HIT', () => {
  const d = dockerfileTempdir(
    'FROM node:20 AS builder\nUSER node\nRUN echo build\nFROM nginx:1.27\nCOPY --from=builder /app /app\n'
  );
  const r = containers.collect({ cwd: d });
  assert.equal(r.signal_overrides['dockerfile-runs-as-root'], 'hit',
    'final stage has no USER directive — must fire runs-as-root');
});

test('#12 single-stage build with a trailing non-root USER is a MISS', () => {
  const d = dockerfileTempdir('FROM node:20\nRUN echo build\nUSER node\n');
  const r = containers.collect({ cwd: d });
  assert.equal(r.signal_overrides['dockerfile-runs-as-root'], 'miss');
});

test('#12 single-stage root build is a HIT', () => {
  const d = dockerfileTempdir('FROM node:20\nRUN echo build\n');
  const r = containers.collect({ cwd: d });
  assert.equal(r.signal_overrides['dockerfile-runs-as-root'], 'hit');
});

test('#12 final stage built FROM a prior alias inherits the parent USER (MISS)', () => {
  const d = dockerfileTempdir(
    'FROM node:20 AS base\nUSER node\nFROM base AS final\nRUN echo build\n'
  );
  const r = containers.collect({ cwd: d });
  assert.equal(r.signal_overrides['dockerfile-runs-as-root'], 'miss',
    'FROM <alias> inherits the parent stage USER — must not reset to root');
});

test('#12 final stage FROM an alias that never set USER is a HIT', () => {
  const d = dockerfileTempdir(
    'FROM node:20 AS base\nRUN echo build\nFROM base AS final\nRUN echo more\n'
  );
  const r = containers.collect({ cwd: d });
  assert.equal(r.signal_overrides['dockerfile-runs-as-root'], 'hit');
});

test('#12 scratch final stage with no USER is a HIT', () => {
  const d = dockerfileTempdir(
    'FROM node:20 AS builder\nUSER node\nFROM scratch\nCOPY --from=builder /app /app\n'
  );
  const r = containers.collect({ cwd: d });
  assert.equal(r.signal_overrides['dockerfile-runs-as-root'], 'hit',
    'scratch starts a fresh stage (root) — must reset and fire');
});

test('containers.hasContainerArtifacts finds Dockerfiles/compose anywhere in the tree, by filename variant', () => {
  const fx = mkfx();
  fs.mkdirSync(path.join(fx, 'examples', 'wiki'), { recursive: true });
  fs.writeFileSync(path.join(fx, 'examples', 'wiki', 'Dockerfile'), 'FROM node:latest\n');
  fs.writeFileSync(path.join(fx, 'docker-compose.test.yml'), 'services:\n  app:\n    image: x\n');
  const found = containersCollector.hasContainerArtifacts(fx);
  assert.ok(found.some((r) => /Dockerfile$/i.test(r)), 'finds the subdir Dockerfile');
  assert.ok(found.some((r) => /docker-compose\.test\.yml$/.test(r)), 'finds the compose variant');
  // An empty tree yields no artifacts.
  assert.deepEqual(containersCollector.hasContainerArtifacts(mkfx()), [], 'no container files -> empty list');
});

test('discover recommends containers for a subdir Dockerfile / compose variant (not just a root exact-name file)', () => {
  const cli = makeCli(makeSuiteHome());
  // A subdir Dockerfile + a compose variant — neither is a root-level
  // exact-name Dockerfile/docker-compose.yml, so the old root-only probes
  // missed them and discover never recommended the containers playbook.
  const fx = mkfx();
  fs.mkdirSync(path.join(fx, 'examples', 'wiki'), { recursive: true });
  fs.writeFileSync(path.join(fx, 'examples', 'wiki', 'Dockerfile'), 'FROM node:latest\n');
  fs.writeFileSync(path.join(fx, 'docker-compose.test.yml'), 'services:\n  app:\n    image: x\n');
  const ids = ((tryJson(cli(['discover', '--cwd', fx, '--json']).stdout) || {}).recommended_playbooks || []).map((r) => r.playbook || r.id || r);
  assert.ok(ids.includes('containers'), 'discover recommends containers for a subdir Dockerfile + compose variant');
  // A tree with no container config must NOT recommend containers.
  const empty = mkfx();
  fs.writeFileSync(path.join(empty, 'README.md'), '# nothing container-ish here\n');
  const ids2 = ((tryJson(cli(['discover', '--cwd', empty, '--json']).stdout) || {}).recommended_playbooks || []).map((r) => r.playbook || r.id || r);
  assert.equal(ids2.includes('containers'), false, 'no container config means no containers recommendation');
});
