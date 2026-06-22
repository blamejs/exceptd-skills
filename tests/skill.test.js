'use strict';

/**
 * Subject coverage for the `skill` CLI verb (bin/exceptd.js): missing-arg
 * handling that honors --json (no "Skill not found: --json"), positional
 * resolution with --json filtered out, and the no-args skill listing so every
 * skill ID is discoverable.
 *
 * Each contributing source file's tests are wrapped in a describe() block named
 * for that source so the per-source requires/consts/helpers stay isolated.
 */

const test = require('node:test');
const assert = require('node:assert/strict');

// ===========================================================================
test.describe('cli-flag-and-envelope-hardening', () => {
  const { makeSuiteHome, makeCli, tryJson } = require('./_helpers/cli');

  const SUITE_HOME = makeSuiteHome('exceptd-flag-envelope-skill-');
  const cli = makeCli(SUITE_HOME);

  test('F5: skill --json missing-arg → ok:false JSON exit 1 (not "Skill not found: --json")', () => {
    const r = cli(['skill', '--json'], { timeout: 20000 });
    assert.equal(r.status, 1);
    const body = tryJson(r.stdout.trim());
    assert.ok(body, 'must emit a parseable JSON envelope on stdout');
    assert.equal(body.ok, false);
    assert.equal(body.verb, 'skill');
    assert.equal(typeof body.error, 'string');
    assert.doesNotMatch(body.error, /Skill not found: --json/,
      '--json must not be treated as the skill name');
  });

  test('F5: skill <real-skill> still resolves with --json filtered from positionals, exit 0', () => {
    const r = cli(['skill', 'kernel-lpe-triage', '--json'], { timeout: 20000 });
    assert.equal(r.status, 0);
    assert.match(r.stdout, /Skill: kernel-lpe-triage/);
  });
});

// ===========================================================================
test.describe('usability-fixes', () => {
  const { makeSuiteHome, makeCli, tryJson } = require('./_helpers/cli');

  const home = makeSuiteHome('exceptd-usability-skill-');
  const cli = makeCli(home);

  test('exceptd skill (no args) lists every skill ID so they are discoverable', () => {
    const manifest = require('../manifest.json');
    const r = cli(['skill', '--json']);
    assert.equal(r.status, 1, 'no-args skill is a usage error (exit 1)');
    const body = tryJson(r.stdout) || {};
    assert.equal(body.ok, false, 'usage envelope is ok:false');
    assert.ok(Array.isArray(body.skills), 'lists a skills array');
    assert.equal(body.skills.length, manifest.skills.length, 'lists every manifest skill');
    assert.ok(body.skills.every(s => s.id && typeof s.description === 'string'), 'each entry has an id + description');
    const human = cli(['skill']);
    assert.match(human.stderr || '', new RegExp(`Available skills \\(${manifest.skills.length}\\)`), 'human usage shows the skill count');
  });
});
