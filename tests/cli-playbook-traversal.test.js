'use strict';

/**
 * Path-traversal refusal for `--playbook` / positional playbook ids.
 *
 * Cycle 6 P1 gap: the validateIdComponent('playbook') gate
 * (lib/id-validation.js PLAYBOOK_RE = `^[a-z][a-z0-9-]{0,63}$`) was
 * load-bearing but had no end-to-end test covering the adversarial cases
 * an operator (or a misbehaving wrapper script) might pass. This file
 * covers the eight canonical traversal / boundary inputs. Each spawn
 * asserts the exact refusal code (1) and a message that names the
 * validation class — "must match", "invalid", or "traversal".
 *
 * Pinning the exact status (1) follows the CLAUDE.md anti-coincidence
 * rule: notEqual(0) would silently pass if a future regression made the
 * verb crash with exit 2 or 137 before reaching the validation gate.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const { makeSuiteHome, makeCli } = require('./_helpers/cli');

const SUITE_HOME = makeSuiteHome('exceptd-cli-traversal-');
const cli = makeCli(SUITE_HOME);

const REFUSAL_RE = /invalid.*playbook.*id|traversal|must match/i;

const cases = [
  { name: 'parent-traversal absolute-shape', id: '../../etc/passwd' },
  { name: 'single-parent', id: '../' },
  { name: 'embedded parent suffix', id: 'kernel/../../..' },
  { name: 'dot-dot', id: '..' },
  { name: 'single dot', id: '.' },
  { name: 'absolute unix path', id: '/etc/passwd' },
  { name: 'absolute windows path', id: 'C:\\Windows\\System32\\drivers\\etc\\hosts' },
  { name: 'leading dot', id: '.kernel' },
  { name: 'length overflow', id: 'a'.repeat(200) },
  { name: 'url-encoded parent', id: '%2e%2e%2f' },
];

for (const c of cases) {
  test(`run <${c.name}> is refused with exit 1 + validation message`, () => {
    const r = cli(['run', c.id, '--evidence', '-'], { input: '{}' });
    assert.equal(r.status, 1,
      `expected exit 1 (validation refusal); got ${r.status} for input ${JSON.stringify(c.id)}; stderr=${r.stderr.slice(0,200)}`);
    assert.match(
      r.stderr + r.stdout,
      REFUSAL_RE,
      `output must label the refusal class (invalid playbook id / traversal / must match). got: ${r.stderr.slice(0,300)}`
    );
  });
}

// Null bytes in argv are rejected by Node's child_process layer before the
// CLI ever runs (`Error: argv[0] must not contain null bytes`). The validator
// layer at lib/id-validation.js still rejects null bytes for in-process
// callers via `loadPlaybook(id)` — that contract is covered by
// tests/lib-id-validation.test.js. Testing it via spawnSync would just
// assert Node's argv guard, not exceptd's.
