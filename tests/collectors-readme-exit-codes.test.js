'use strict';

/**
 * The collectors README documents the `exceptd collect` exit codes. That doc
 * ships in the npm tarball, so it is operator-facing and must match runtime.
 *
 * Runtime ground truth:
 *   - bin/exceptd.js cmdCollect routes BOTH the "no collector for the playbook"
 *     case and the "collector threw an unhandled exception" case through
 *     emitError() with no exit_code override.
 *   - emitError() sets process.exitCode = EXIT_CODES.GENERIC_FAILURE.
 *   - lib/exit-codes.js pins GENERIC_FAILURE = 1 and reserves 2 for
 *     DETECTED_ESCALATE (the CI escalation gate), which `collect` never emits.
 *
 * So a collector crash exits 1, not 2. This guard asserts the README cannot
 * drift back to claiming a distinct exit 2 for a collector crash, and that the
 * documented crash code equals the constant the code actually uses.
 *
 * The test reads bin/exceptd.js read-only — it does not import or run the CLI.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');
const README = path.join(ROOT, 'lib', 'collectors', 'README.md');
const BIN = path.join(ROOT, 'bin', 'exceptd.js');

const { EXIT_CODES } = require(path.join(ROOT, 'lib', 'exit-codes.js'));

// The exit code a collector crash actually produces. emitError() sets
// GENERIC_FAILURE and the collector-throw path supplies no override.
const COLLECTOR_CRASH_EXIT = EXIT_CODES.GENERIC_FAILURE;

test('GENERIC_FAILURE is 1 and DETECTED_ESCALATE is 2 (the reserved CI-gate code)', () => {
  assert.equal(EXIT_CODES.GENERIC_FAILURE, 1);
  assert.equal(EXIT_CODES.DETECTED_ESCALATE, 2);
  assert.equal(COLLECTOR_CRASH_EXIT, 1, 'a collector crash exits via GENERIC_FAILURE');
});

test('cmdCollect routes the collector-throw case through emitError with no exit_code override', () => {
  const src = fs.readFileSync(BIN, 'utf8');

  // Locate the collector-invocation `submission = mod.collect(...)` call and
  // inspect the catch handler that immediately follows it. A fixed forward
  // window is used rather than brace-balancing because the handler's message
  // template contains `}` (e.g. `${e.message}`).
  const anchor = src.search(/submission\s*=\s*mod\.collect\(/);
  assert.ok(anchor >= 0, 'could not find the cmdCollect `submission = mod.collect(...)` call');
  const window = src.slice(anchor, anchor + 700);

  assert.match(window, /catch\s*\(e\)/, 'the collector call must be wrapped in a catch');
  assert.match(window, /threw an unhandled exception/, 'the catch must be the collector-crash handler');
  assert.match(window, /emitError/, 'the collector-crash path must route through emitError (which sets GENERIC_FAILURE)');
  assert.ok(
    !/exit_code\s*:/.test(window),
    'the collector-crash path must NOT override exit_code — it must inherit GENERIC_FAILURE (1)',
  );
});

// Parse the "- `N` — ..." exit-code bullets out of the README's exit-code
// section so the doc text itself is checked, not just the runtime.
function readmeExitBullets() {
  const text = fs.readFileSync(README, 'utf8');
  const start = text.indexOf('Exit codes:');
  assert.ok(start >= 0, 'README must have an "Exit codes:" section');
  const section = text.slice(start);
  const bullets = [];
  const re = /^- `(\d+)`\s*—\s*(.*)$/gm;
  let mm;
  while ((mm = re.exec(section)) !== null) {
    bullets.push({ code: Number(mm[1]), text: mm[2] });
  }
  return bullets;
}

test('the README documents the collector-crash exit code as the actual runtime code', () => {
  const bullets = readmeExitBullets();
  assert.ok(bullets.length > 0, 'no exit-code bullets parsed from the README');

  // The bullet describing a collector crash must carry the real crash code.
  const crashBullet = bullets.find(b => /unhandled exception|collector threw|threw/i.test(b.text));
  assert.ok(crashBullet, 'README must describe the collector-crash exit behavior');
  assert.equal(
    crashBullet.code,
    COLLECTOR_CRASH_EXIT,
    `README documents the collector crash as exit ${crashBullet.code}, but the code exits ${COLLECTOR_CRASH_EXIT}`,
  );
});

test('the README never assigns the reserved escalation code 2 to the collect verb', () => {
  const bullets = readmeExitBullets();
  const two = bullets.find(b => b.code === EXIT_CODES.DETECTED_ESCALATE);
  assert.equal(
    two,
    undefined,
    'exit 2 is reserved for DETECTED_ESCALATE (CI gate) and must not appear as a documented collect exit code',
  );
});
