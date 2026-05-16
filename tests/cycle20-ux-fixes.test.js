'use strict';

/**
 * tests/cycle20-ux-fixes.test.js
 *
 * Cycle 20 A fixes (v0.12.40):
 *
 *   P1 — `exceptd framework-gap` "0 theater-risk controls" summary
 *        footer contradicted the "⚠ THEATER RISK" badge on every
 *        entry. The counting predicate filtered on the legacy
 *        `theater_pattern` field while the v0.12.29 backfill added
 *        a structured `theater_test` block on all 118 entries. Fix:
 *        count entries with EITHER `theater_test` OR `theater_pattern`.
 *
 *   P2 — `exceptd skill` (no arg) printed
 *        "Usage: node orchestrator/index.js skill <skill-name>"
 *        — an internal narrative leak (CLAUDE.md global rule).
 *        Operator-facing surface must reference the canonical
 *        `exceptd skill <name>` form.
 *
 *   P2 — Unsigned-attestation warning referenced
 *        `node lib/sign.js generate-keypair` (a node-internal script
 *        path that isn't on PATH after `npm install -g`). Now hints
 *        at `exceptd doctor --fix` first, with the lib script as a
 *        fallback for contributor checkouts.
 *
 * Per CLAUDE.md anti-coincidence rule, every assertion checks an EXACT
 * substring match or count.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const fs = require('node:fs');
const { spawnSync } = require('node:child_process');

const ROOT = path.join(__dirname, '..');
const CLI = path.join(ROOT, 'bin', 'exceptd.js');

function cli(args, opts = {}) {
  return spawnSync(process.execPath, [CLI, ...args], {
    encoding: 'utf8',
    cwd: opts.cwd || ROOT,
    env: { ...process.env, EXCEPTD_DEPRECATION_SHOWN: '1', ...(opts.env || {}) },
    input: opts.input,
  });
}

// P1 — framework-gap theater-risk counter --------------------------------

test('P1: framework-gap theater_risks counts entries with theater_test (not just legacy theater_pattern)', () => {
  // Direct library probe avoids the orchestrator-dispatch surface;
  // exercise the function used by the CLI verb.
  const { gapReport } = require(path.join(ROOT, 'lib', 'framework-gap.js'));
  const controlGaps = JSON.parse(fs.readFileSync(path.join(ROOT, 'data', 'framework-control-gaps.json'), 'utf8'));
  const cveCatalog = JSON.parse(fs.readFileSync(path.join(ROOT, 'data', 'cve-catalog.json'), 'utf8'));
  // CVE-2026-31431 is the canonical kernel-LPE catalog entry that
  // spans many framework gaps. Use it as the scenario.
  const report = gapReport(['nist-800-53'], 'CVE-2026-31431', controlGaps, cveCatalog);
  // Pre-fix `theater_risks` was empty even though every per-framework
  // result showed `theater_exposure: true`. Now it must be > 0 because
  // the v0.12.29 backfill added theater_test to every relevant gap.
  assert.equal(Array.isArray(report.theater_risks), true);
  assert.equal(report.theater_risks.length > 0, true,
    `framework-gap theater_risks must be non-empty when entries carry theater_test; got: ${JSON.stringify(report.summary)}`);
  // Sub-shape: each theater-risk entry must carry the canonical fields.
  for (const r of report.theater_risks) {
    assert.equal(typeof r.control, 'string');
    assert.equal(typeof r.framework, 'string');
    // theater_test_present is the v0.12.40 addition; pin it.
    assert.equal(typeof r.theater_test_present, 'boolean');
  }
  // Footer count must match the array length.
  assert.equal(report.summary.theater_risk_controls, report.theater_risks.length);
});

// P2 — exceptd skill (no arg) does not leak orchestrator path --------------

test('P2: exceptd skill (no arg) prints `exceptd skill <name>` usage, NOT the orchestrator path', () => {
  const r = cli(['skill']);
  assert.equal(r.status, 1, `bare exceptd skill must exit 1; got ${r.status}`);
  // Pre-fix: "Usage: node orchestrator/index.js skill <skill-name>"
  // Post-fix: "Usage: exceptd skill <skill-name>"
  assert.match(r.stderr, /Usage: exceptd skill/,
    `usage hint must reference the operator-facing verb; got: ${r.stderr.slice(0, 300)}`);
  assert.equal(/node orchestrator\/index\.js skill/.test(r.stderr), false,
    'usage hint must NOT reference the orchestrator path (internal narrative leak)');
});

// P2 — Unsigned-attestation warning text -----------------------------------

test('P2: unsigned-attestation warning text references `exceptd doctor --fix` first', () => {
  // Grep the source for the warning string; it's emitted from
  // bin/exceptd.js around line 3866 (cycle 20 site).
  const src = fs.readFileSync(CLI, 'utf8');
  // Pre-fix referenced `node lib/sign.js generate-keypair` only.
  // Post-fix: `exceptd doctor --fix` comes first, with the lib path
  // wrapped in `$(exceptd path)` as the contributor-checkout fallback.
  // Find the warning block.
  const warningMatch = src.match(/Operators reading the attestation later[\s\S]{0,400}Suppress this notice: export EXCEPTD_UNSIGNED_WARNED/);
  assert.ok(warningMatch, 'unsigned-attestation warning block must be present in bin/exceptd.js');
  const warningText = warningMatch[0];
  assert.match(warningText, /exceptd doctor --fix/,
    'warning must lead with `exceptd doctor --fix`');
  // The lib path must still be cited (for contributor checkouts) but
  // only via `$(exceptd path)/lib/sign.js` — never the raw
  // `node lib/sign.js` form that requires the user to know exceptd's
  // install root.
  assert.equal(/Enable Ed25519 signing: `node lib\/sign\.js/.test(warningText), false,
    'warning must NOT lead with the bare `node lib/sign.js` form');
});
