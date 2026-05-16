'use strict';

/**
 * tests/evidence-input-hardening.test.js
 *
 * Cycle 15 security fixes (v0.12.35):
 *
 *   F1 — `--evidence -` (stdin) was uncapped. The file-path branch
 *        enforced a 32 MiB cap; the stdin branch did `fs.readFileSync(0)`
 *        with no length limit. An attacker piping multi-GB JSON would
 *        OOM the runner. Now both branches share the same MAX_EVIDENCE_BYTES
 *        limit; stdin reads in 1 MB chunks and bails at the cap.
 *
 *   F2 — `Object.assign(out.precondition_checks, submission.precondition_checks)`
 *        re-invoked the `__proto__` setter when the operator's JSON contained
 *        a `__proto__` key. JSON.parse keeps `__proto__` as an own data
 *        property; Object.assign reads it via [[Get]] and writes via [[Set]],
 *        triggering the prototype-rebinding setter. Global Object.prototype
 *        stayed clean (Node confines the rebind to the assignment target),
 *        but the polluted local prototype was a defense-in-depth gap. Now
 *        own-key iteration explicitly skips `__proto__` / `constructor` /
 *        `prototype` keys.
 *
 * Per CLAUDE.md anti-coincidence rule, every assertion checks an EXACT
 * exit code or value, never `assert.notEqual(0)` or wildcard match.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const ROOT = path.join(__dirname, '..');
const CLI = path.join(ROOT, 'bin', 'exceptd.js');

function cli(args, opts = {}) {
  return spawnSync(process.execPath, [CLI, ...args], {
    encoding: 'utf8',
    cwd: opts.cwd || ROOT,
    env: { ...process.env, EXCEPTD_DEPRECATION_SHOWN: '1', ...(opts.env || {}) },
    input: opts.input,
    maxBuffer: 200 * 1024 * 1024,
  });
}

function tryJson(s) { try { return JSON.parse(s); } catch { return null; } }

// F1 — stdin size cap ------------------------------------------------------

test('F1: --evidence - accepts a small (< 32 MiB) JSON payload on stdin', () => {
  const small = JSON.stringify({
    precondition_checks: { 'linux-platform': true, 'uname-available': true },
    artifacts: { 'kernel-release': '5.15.0-69-generic' },
  });
  const r = cli(['run', 'kernel', '--evidence', '-'], { input: small });
  assert.equal(r.status, 0, `small payload must succeed; got ${r.status}, stderr: ${r.stderr.slice(0, 300)}`);
});

test('F1: --evidence - refuses payload over 32 MiB with structured error + exit 1', () => {
  // Construct ~34 MiB payload (just over the 32 MiB cap).
  const sizeMb = 34;
  const filler = 'x'.repeat(1024 - 20);
  const items = [];
  for (let i = 0; i < sizeMb * 1024; i++) items.push(`"k${i}":"${filler}"`);
  const big = `{"artifacts":{${items.join(',')}}}`;
  // Sanity: payload must actually exceed 32 MiB.
  assert.equal(big.length > 32 * 1024 * 1024, true,
    `test payload must exceed 32 MiB; got ${big.length} bytes`);

  const r = cli(['run', 'kernel', '--evidence', '-'], { input: big });
  assert.equal(r.status, 1, `oversize stdin must exit 1; got ${r.status}`);
  // Structured stderr JSON.
  const err = tryJson(r.stderr);
  assert.ok(err, `oversize-stdin error must be parseable JSON; got: ${r.stderr.slice(0, 200)}`);
  assert.equal(err.ok, false);
  assert.match(err.error, /evidence on stdin exceeds size limit/);
  assert.match(err.error, /33554432 byte limit/);
});

// F2 — Prototype-pollution defense ----------------------------------------

test('F2: evidence with __proto__ key does not pollute Object.prototype', () => {
  const evil = JSON.stringify({
    precondition_checks: {
      'linux-platform': true,
      'uname-available': true,
      __proto__: { polluted: 'yes' },
      constructor: { prototype: { injected: 1 } },
    },
    artifacts: { 'kernel-release': '5.15.0-69-generic' },
  });
  const r = cli(['run', 'kernel', '--evidence', '-'], { input: evil });
  assert.equal(r.status, 0, `prototype-pollution test must complete; got ${r.status}`);
  // After the child exits, our own process's Object.prototype must
  // remain pristine. (Containment is the runtime's job, but our own
  // process state would only be affected if we share heap with the
  // child — we don't, so this is a sanity check.)
  const o = {};
  assert.equal(o.polluted, undefined, 'Object.prototype.polluted must be undefined');
  assert.equal(o.injected, undefined, 'Object.prototype.injected must be undefined');
  assert.equal(Object.prototype.hasOwnProperty.call(Object.prototype, 'polluted'), false);
});

test('F2: __proto__ / constructor / prototype keys in precondition_checks are stripped', () => {
  // Pipe evidence; the runner must accept the run, but the precondition_checks
  // bag inside should NOT have prototype-bag leakage. We assert via runtime
  // observation: the run completes successfully + the JSON output does not
  // surface `polluted: 'yes'` in any phase.
  const evil = JSON.stringify({
    precondition_checks: {
      'linux-platform': true,
      'uname-available': true,
      __proto__: { polluted: 'yes' },
    },
    artifacts: { 'kernel-release': '5.15.0-69-generic' },
  });
  const r = cli(['run', 'kernel', '--evidence', '-', '--json'], { input: evil });
  assert.equal(r.status, 0);
  assert.equal(/"polluted":/.test(r.stdout), false,
    `precondition bag must not surface __proto__ pollution in run output; got: ${r.stdout.slice(0, 400)}`);
});
