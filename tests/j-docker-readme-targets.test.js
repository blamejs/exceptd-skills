'use strict';

/**
 * tests/j-docker-readme-targets.test.js
 *
 * docker/README.md documents the build targets defined in
 * docker/test.Dockerfile. This pins the README to the actual `FROM base AS
 * <target>` stages so a target can't ship undocumented, and confirms each
 * documented target's run script exists in package.json.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');
const README = fs.readFileSync(path.join(ROOT, 'docker', 'README.md'), 'utf8');
const DOCKERFILE = fs.readFileSync(path.join(ROOT, 'docker', 'test.Dockerfile'), 'utf8');
const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'));

function dockerfileTargets() {
  const targets = [];
  const re = /^FROM\s+\S+\s+AS\s+(\S+)/gm;
  let m;
  while ((m = re.exec(DOCKERFILE)) !== null) targets.push(m[1]);
  return targets;
}

test('docker/README.md documents every runnable target the Dockerfile ships', () => {
  // `base` is the shared build stage, not a runnable target — exclude it.
  const runnable = dockerfileTargets().filter((t) => t !== 'base');
  // Sanity: the Dockerfile must define at least the e2e target this gate exists for.
  assert.ok(runnable.includes('e2e'), 'test.Dockerfile is missing the e2e target');
  for (const target of runnable) {
    assert.ok(
      new RegExp('`' + target + '`').test(README),
      `docker/README.md does not document the \`${target}\` target`
    );
  }
});

test('docker/README.md target count word matches the runnable target count', () => {
  const runnable = dockerfileTargets().filter((t) => t !== 'base');
  const WORDS = { 1: 'One', 2: 'Two', 3: 'Three', 4: 'Four', 5: 'Five' };
  const expected = WORDS[runnable.length];
  assert.ok(expected, `unexpected runnable-target count ${runnable.length}`);
  assert.match(
    README,
    new RegExp(expected + ' build targets defined in'),
    `docker/README.md should say "${expected} build targets" for ${runnable.length} runnable targets`
  );
});

test('package.json ships a docker run script for every documented target', () => {
  assert.equal(typeof pkg.scripts['test:docker'], 'string'); // predeploy target
  assert.equal(typeof pkg.scripts['test:docker:fresh'], 'string'); // fresh-bootstrap target
  assert.equal(typeof pkg.scripts['test:docker:e2e'], 'string'); // e2e target
  assert.match(pkg.scripts['test:docker:e2e'], /--target e2e\b/);
});
