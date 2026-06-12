'use strict';

/**
 * tests/readme-run-format-consistency.test.js
 *
 * The `run --format` value list must stay consistent across the three
 * operator-facing surfaces: the README synopsis, the `exceptd help` text, and
 * the runtime's accepted `supported_formats`. A README that omits a value the
 * runtime accepts and `--help` advertises misleads an operator reading the
 * command reference to learn which formats are valid.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');
const README = fs.readFileSync(path.join(ROOT, 'README.md'), 'utf8');
const HELP = fs.readFileSync(path.join(ROOT, 'bin', 'exceptd.js'), 'utf8');
const RUNNER = fs.readFileSync(path.join(ROOT, 'lib', 'playbook-runner.js'), 'utf8');

// Anchors the run --format synopsis line uniquely in both README and --help.
const ANCHOR = 'csaf-2.0 | sarif | openvex';

function pipeTokens(text, anchor) {
  const line = text.split('\n').find(l => l.includes(anchor));
  assert.ok(line, `expected a line containing "${anchor}"`);
  const run = line.slice(line.indexOf('csaf-2.0'));
  return run.replace(/[.\s]+$/, '').split('|').map(s => s.trim()).filter(Boolean);
}

function runtimeFormats(text) {
  const m = text.match(/supported_formats:\s*\[([^\]]*)\]/);
  assert.ok(m, 'expected a supported_formats array literal in lib/playbook-runner.js');
  return m[1].split(',').map(s => s.trim().replace(/^['"]|['"]$/g, '')).filter(Boolean);
}

test('README run --format synopsis advertises json', () => {
  const readme = pipeTokens(README, ANCHOR);
  assert.equal(readme.includes('json'), true,
    `README --format list must include json; got: ${readme.join(' | ')}`);
});

test('README and `exceptd help` advertise the identical run --format value set', () => {
  const readme = pipeTokens(README, ANCHOR);
  const help = pipeTokens(HELP, ANCHOR);
  assert.deepEqual([...readme].sort(), [...help].sort(),
    `README (${readme.join('|')}) and --help (${help.join('|')}) must advertise the same --format values`);
});

test('every README-advertised run --format value is accepted by the runtime', () => {
  const readme = pipeTokens(README, ANCHOR);
  const runtime = runtimeFormats(RUNNER);
  for (const tok of readme) {
    assert.equal(runtime.includes(tok), true,
      `README advertises --format ${tok}, but the runtime supported_formats does not accept it`);
  }
});
