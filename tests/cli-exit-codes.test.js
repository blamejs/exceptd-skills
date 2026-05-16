'use strict';

/**
 * Tests for the v0.12.19 audit-R CLI surface closures.
 *
 *   R-F1  attest verify on tampered attestation → ok:false + exit 6
 *   R-F3  cmdRun / cmdIngest stdin auto-detect uses truthy isTTY check
 *         (Windows MSYS bash exposes isTTY=undefined for piped stdin)
 *   R-F4  --vex rejects empty vulnerabilities[] without a CycloneDX marker
 *   R-F5  --vex enforces a 32 MB size cap
 *   R-F7  attest <verb> distinguishes session-id validation failure
 *         from session-not-found
 *   R-F8  main dispatcher unknown-command / missing-script / spawn-error
 *         use emitError() (exitCode + return) instead of process.exit(N)
 *   R-F9  run --scope "" rejects via validateScopeOrThrow rather than
 *         falling through to auto-detect
 *   R-F10 attest list / reattest --since requires ISO-8601 calendar shape
 *         (rejects bare "99", which Date.parse silently maps to 1999)
 *   R-F11 jurisdiction_clock_rollup exposes both `obligation` and the
 *         kept-name `obligation_ref` alias
 *   R-F12 --evidence-dir refuses symbolic-link entries
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const { ROOT, makeSuiteHome, makeCli, tryJson } = require('./_helpers/cli');

const SUITE_HOME = makeSuiteHome('exceptd-audit-r-');
const cli = makeCli(SUITE_HOME);

// ---------------------------------------------------------------------------
// R-F1 — attest verify must exit 6 on TAMPERED
// ---------------------------------------------------------------------------

test('R-F1: attest verify on a tampered attestation exits 6 with ok:false', { skip: !fs.existsSync(path.join(ROOT, '.keys', 'private.pem')) && 'private key absent — signed-tamper path cannot be exercised without .keys/private.pem' }, () => {
  // Produce a real attestation under SUITE_HOME, then mutate the on-disk
  // attestation.json AFTER signing so the Ed25519 sidecar fails.
  const sid = 'rf1-tamper-' + Date.now();
  const sub = JSON.stringify({ observations: {}, verdict: { classification: 'not_detected' } });
  const r1 = cli(['run', 'library-author', '--evidence', '-', '--session-id', sid], { input: sub });
  assert.equal(r1.status, 0, 'pre-tamper run must succeed; stderr=' + r1.stderr.slice(0, 400));

  // Locate the attestation. resolveAttestationRoot() under EXCEPTD_HOME
  // returns `${EXCEPTD_HOME}/attestations` (no `.exceptd` prefix when the
  // env var already points at the exceptd home). Falls back to the cwd
  // shape on platforms where the env-var path is missing.
  const candidates = [
    path.join(SUITE_HOME, 'attestations', sid),
    path.join(SUITE_HOME, '.exceptd', 'attestations', sid),
  ];
  const attRoot = candidates.find(p => fs.existsSync(p));
  assert.ok(attRoot, 'attestation directory must exist after run; tried: ' + JSON.stringify(candidates));
  const files = fs.readdirSync(attRoot).filter(f => f.endsWith('.json') && !f.endsWith('.sig'));
  assert.ok(files.length >= 1, 'at least one attestation .json must exist; found: ' + JSON.stringify(files));
  const target = path.join(attRoot, files[0]);

  // Pre-tamper: verify must currently pass (verified:true).
  const rOk = cli(['attest', 'verify', sid, '--json']);
  const okBody = tryJson(rOk.stdout) || tryJson(rOk.stderr) || {};
  assert.ok(okBody.results && okBody.results.length >= 1, 'pre-tamper verify must emit results');

  // Tamper: append a byte that's still valid JSON so JSON.parse downstream
  // doesn't trip but the Ed25519 signature breaks.
  const orig = fs.readFileSync(target, 'utf8');
  const tampered = orig.replace(/\}\s*$/, ', "__tampered": true }');
  assert.notEqual(tampered, orig, 'tamper transform must alter bytes');
  fs.writeFileSync(target, tampered, 'utf8');

  // Run verify against the tampered attestation.
  const r = cli(['attest', 'verify', sid, '--json']);
  // Exact-exit assertion per CLAUDE.md "coincidence-passing tests" rule —
  // tamper must yield 6, not just non-zero.
  assert.equal(r.status, 6,
    `attest verify on a tampered attestation must exit 6 (TAMPERED). Got status=${r.status}. stdout=${r.stdout.slice(0,400)} stderr=${r.stderr.slice(0,400)}`);
  // Body must carry ok:false and surface the per-file verified:false result.
  const body = tryJson(r.stdout) || tryJson(r.stderr) || {};
  assert.equal(body.ok, false, 'tampered verify body must carry ok:false');
  assert.ok(Array.isArray(body.results), 'verify result must include results array');
  assert.ok(body.results.some(x => x.signed === true && x.verified === false),
    'at least one result must report signed:true verified:false');
});

// ---------------------------------------------------------------------------
// R-F3 — Windows MSYS bash isTTY=undefined parity
// ---------------------------------------------------------------------------
//
// We cannot literally simulate Windows MSYS pipe semantics in unit tests on
// every platform, but the regression is that the check uses `=== false`
// (strict) instead of `!isTTY` (truthy). Read the source and assert the
// fixed form is present at both cmdRun and cmdIngest sites. The source-grep
// shape mirrors how AGENTS.md Hard Rule #15 enforces test coverage for
// per-flag / per-call-site behavior: the literal check is the contract.

test('R-F3: cmdRun + cmdIngest + cmdAiRun route stdin detection through hasReadableStdin (no inline strict checks at dispatcher sites)', () => {
  const src = fs.readFileSync(path.join(ROOT, 'bin', 'exceptd.js'), 'utf8');
  // The dispatcher sites (cmdRun, cmdIngest, cmdAiRun --no-stream) must
  // route stdin detection through the hasReadableStdin() helper, NOT call
  // `process.stdin.isTTY === false` inline. The helper itself is allowed
  // to use the strict check internally as its Windows fallback (where a
  // piped stream legitimately reports isTTY === false and size === 0 on
  // fstat); the regression class this test exists to prevent is the
  // dispatcher sites returning false for the wrapped-MSYS-bash case where
  // isTTY === undefined.
  //
  // Scope the strict-check ban to outside the hasReadableStdin function
  // body. Extract the function, then assert the strict literal doesn't
  // appear in the rest of the source.
  const helperMatch = src.match(/function hasReadableStdin\(\)\s*\{[\s\S]*?\n\}/);
  assert.ok(helperMatch, 'bin/exceptd.js must define a top-level hasReadableStdin function');
  const srcOutsideHelper = src.replace(helperMatch[0], '');
  const strictHits = srcOutsideHelper.match(/process\.stdin\.isTTY === false/g) || [];
  assert.equal(strictHits.length, 0,
    `process.stdin.isTTY === false must not appear in dispatcher sites of bin/exceptd.js — wrapped MSYS-bash streams expose isTTY=undefined and would silently skip stdin. The check is permitted only inside hasReadableStdin's Windows fallback. Found ${strictHits.length} dispatcher-side occurrences.`);
  // Confirm the dispatcher sites route through hasReadableStdin (≥ 3
  // call sites: cmdRun, cmdIngest, cmdAiRun --no-stream).
  const helperCalls = src.match(/\bhasReadableStdin\s*\(\s*\)/g) || [];
  assert.ok(helperCalls.length >= 3,
    `hasReadableStdin() must be called at cmdRun, cmdIngest, and cmdAiRun stdin-detection sites (≥ 3). Found ${helperCalls.length}.`);
});

// ---------------------------------------------------------------------------
// R-F4 — --vex empty vulnerabilities[] without CycloneDX marker is refused
// ---------------------------------------------------------------------------

test('R-F4: --vex refuses empty vulnerabilities[] when bomFormat is not "CycloneDX"', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'rf4-'));
  try {
    const vexPath = path.join(tmp, 'fake.vex.json');
    // Adversarial shape: empty vulnerabilities[] paired with a bogus
    // bomFormat. Pre-fix, the heuristic `length === 0 || ...` passed and
    // the document was accepted as cyclonedx-vex.
    fs.writeFileSync(vexPath, JSON.stringify({
      bomFormat: 'NOT-CycloneDX',
      vulnerabilities: [],
    }), 'utf8');
    const sub = JSON.stringify({ observations: {}, verdict: {} });
    const r = cli(['run', 'library-author', '--evidence', '-', '--vex', vexPath], { input: sub });
    assert.equal(r.status, 1,
      'run with adversarial --vex must exit 1 (arg-validation refusal). stdout=' + r.stdout.slice(0,300) + ' stderr=' + r.stderr.slice(0,300));
    const err = tryJson(r.stderr.trim()) || {};
    assert.equal(err.ok, false, '--vex refusal body must carry ok:false');
    assert.match(err.error || '',
      /empty-vulnerabilities-without-cyclonedx-marker|doesn't look like CycloneDX or OpenVEX/,
      'error must name the detected shape problem; got: ' + (err.error || ''));
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test('R-F4 positive: --vex accepts a legitimate CycloneDX-marked empty vulnerabilities[]', () => {
  // Empty vulnerabilities[] is legitimate when bomFormat is "CycloneDX" or
  // specVersion is set. This guards against an over-corrected fix that
  // would refuse all empty-array VEX submissions.
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'rf4-pos-'));
  try {
    const vexPath = path.join(tmp, 'real.vex.json');
    fs.writeFileSync(vexPath, JSON.stringify({
      bomFormat: 'CycloneDX',
      specVersion: '1.5',
      vulnerabilities: [],
    }), 'utf8');
    const sub = JSON.stringify({ observations: {}, verdict: {} });
    const r = cli(['run', 'library-author', '--evidence', '-', '--vex', vexPath], { input: sub });
    // Run may succeed or block on independent criteria, but the --vex shape
    // check must not be the reason. Assert no "doesn't look like" failure.
    const err = tryJson(r.stderr.trim()) || {};
    if (err.error) {
      assert.doesNotMatch(err.error,
        /doesn't look like CycloneDX or OpenVEX|empty-vulnerabilities-without-cyclonedx-marker/,
        'legitimate empty CycloneDX VEX must not be rejected as malformed; got: ' + err.error);
    }
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// R-F5 — --vex 32 MB size cap
// ---------------------------------------------------------------------------

test('R-F5: --vex refuses files larger than 32 MB', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'rf5-'));
  try {
    const vexPath = path.join(tmp, 'huge.vex.json');
    // Write 33 MB of arbitrary content. We don't care that it's not valid
    // VEX — the size check must fire BEFORE JSON.parse.
    const oneMb = 'A'.repeat(1024 * 1024);
    const fh = fs.openSync(vexPath, 'w');
    try {
      for (let i = 0; i < 33; i++) fs.writeSync(fh, oneMb);
    } finally { fs.closeSync(fh); }
    const stat = fs.statSync(vexPath);
    assert.ok(stat.size > 32 * 1024 * 1024, 'fixture must exceed 32 MB; got ' + stat.size);
    const sub = JSON.stringify({ observations: {}, verdict: {} });
    const r = cli(['run', 'library-author', '--evidence', '-', '--vex', vexPath], { input: sub });
    assert.equal(r.status, 1, '--vex with oversized file must exit 1 (size-cap refusal). status=' + r.status);
    const err = tryJson(r.stderr.trim()) || {};
    assert.equal(err.ok, false);
    assert.match(err.error || '', /--vex file too large/,
      'error must name the size-cap refusal; got: ' + (err.error || ''));
    assert.equal(err.limit_bytes, 32 * 1024 * 1024,
      'error body must include limit_bytes for operator visibility');
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// R-F7 — validation rejected vs session-not-found are distinct errors
// ---------------------------------------------------------------------------

test('R-F7: attest show rejects path-traversal session-id with validation error (not "no session dir")', () => {
  const r = cli(['attest', 'show', '../../..', '--json']);
  assert.equal(r.status, 1, 'path-traversal session-id must exit 1 (validation refusal). status=' + r.status);
  const err = tryJson(r.stderr.trim()) || {};
  assert.equal(err.ok, false);
  // The validation error names the regex, not "no session dir for".
  assert.match(err.error || '', /Invalid session-id|Must match/,
    'attest <verb> with a traversal-shaped id must surface the validation error, not the lookup-miss error. Got: ' + (err.error || ''));
  assert.doesNotMatch(err.error || '', /no session dir for/,
    'pre-fix: findSessionDir collapsed validation failure to the not-found path. Got: ' + (err.error || ''));
});

test('R-F7: attest show with a valid-shape but missing session id still emits the not-found error', () => {
  const r = cli(['attest', 'show', 'definitely-not-a-real-session-' + Date.now(), '--json']);
  assert.equal(r.status, 1, 'valid-shape but missing session-id must exit 1 (not-found). status=' + r.status);
  const err = tryJson(r.stderr.trim()) || {};
  assert.equal(err.ok, false);
  assert.match(err.error || '', /no session dir for/,
    'a valid-shape id that simply does not exist must still emit the not-found message');
});

// ---------------------------------------------------------------------------
// R-F8 — main dispatcher exits don't truncate stderr JSON
// ---------------------------------------------------------------------------

test('R-F8: unknown-command stderr JSON is parseable AND exit code is EXIT_CODES.UNKNOWN_COMMAND (10)', () => {
  // Cycle 9 B1 (v0.12.29): split unknown-command from DETECTED_ESCALATE (2).
  // Operators wiring `case 2)` for escalation triage no longer false-alarm
  // on dispatcher refusals (typos, missing scripts, spawn errors).
  const r = cli(['definitely-not-a-real-verb-xyz']);
  assert.equal(r.status, 10,
    'unknown-command must exit 10 (UNKNOWN_COMMAND). status=' + r.status);
  const err = tryJson(r.stderr.trim());
  assert.ok(err, 'stderr must be parseable JSON post-fix (process.exitCode + return drains buffered writes).');
  assert.equal(err.ok, false);
  assert.match(err.error, /unknown command/);
  assert.match(err.hint || '', /exceptd help/);
});

// ---------------------------------------------------------------------------
// R-F9 — --scope "" must be rejected, not silently auto-detected
// ---------------------------------------------------------------------------

test('R-F9: run --scope "" rejects with the accepted-set message', () => {
  const r = cli(['run', '--scope', '']);
  assert.equal(r.status, 1,
    'run --scope "" must exit 1 (validateScopeOrThrow refusal). status=' + r.status + ' stdout=' + r.stdout.slice(0,300));
  const err = tryJson(r.stderr.trim()) || {};
  assert.equal(err.ok, false);
  assert.match(err.error || '', /--scope must be one of/,
    'empty-string scope must surface the same validateScopeOrThrow message as any other invalid scope. Got: ' + (err.error || ''));
});

// ---------------------------------------------------------------------------
// R-F10 — --since rejects "99" (Date.parse → 1999)
// ---------------------------------------------------------------------------

test('R-F10: attest list --since 99 is refused (regex check before Date.parse)', () => {
  const r = cli(['attest', 'list', '--since', '99', '--json']);
  assert.equal(r.status, 1,
    'attest list --since 99 must exit 1 (regex refusal — Date.parse silently maps "99" to 1999-12-01). status=' + r.status);
  const err = tryJson(r.stderr.trim()) || {};
  assert.equal(err.ok, false);
  assert.match(err.error || '', /ISO-8601 calendar timestamp/,
    'error must name the ISO-8601-calendar requirement so the operator knows what shape to use. Got: ' + (err.error || ''));
});

test('R-F10: reattest --since 99 is refused (same regex contract)', () => {
  const r = cli(['reattest', 'somesid', '--since', '99', '--json']);
  assert.equal(r.status, 1,
    'reattest --since 99 must exit 1 (regex refusal). status=' + r.status);
  const err = tryJson(r.stderr.trim()) || {};
  assert.equal(err.ok, false);
  assert.match(err.error || '', /ISO-8601 calendar timestamp/,
    'reattest must enforce the same regex contract as attest list. Got: ' + (err.error || ''));
});

test('R-F10 positive: --since 2026-05-01 is accepted (regex still passes legitimate inputs)', () => {
  // Guards against over-correction — the regex must accept the canonical
  // date and date-time forms.
  const r = cli(['attest', 'list', '--since', '2026-05-01', '--json']);
  // Validation must pass; downstream lookup may emit empty results, which
  // is fine — we only care the gate didn't trip on the timestamp shape.
  const out = tryJson(r.stdout) || tryJson(r.stderr.trim()) || {};
  if (out.error) {
    assert.doesNotMatch(out.error, /ISO-8601 calendar timestamp/,
      'a real ISO-8601 date must not be rejected by the regex gate. Got: ' + out.error);
  }
});

// ---------------------------------------------------------------------------
// R-F11 — jurisdiction_clock_rollup exposes both obligation + obligation_ref
// ---------------------------------------------------------------------------

test('R-F11: buildJurisdictionClockRollup output carries both `obligation` and `obligation_ref`', () => {
  // The dedupe key keeps `obligation_ref` (that's the field the upstream
  // notification stub carries). The OUTPUT shape must also expose
  // `obligation`, which is the field name CHANGELOG v0.12.16 promised.
  // Drive the helper directly via require so we don't depend on a full
  // multi-playbook run.
  // Drive the helper directly: replicate the input shape close() emits and
  // assert the rollup output carries both `obligation` and `obligation_ref`.
  // The helper isn't exported as a named module export, so reach in by
  // forcing a tiny multi-playbook run and inspecting jurisdiction_clock_rollup.
  const sub = JSON.stringify({ observations: {}, verdict: { classification: 'not_detected' } });
  // --scope cross-cutting picks playbooks that emit close.notification_actions
  // (the EU NIS2 / DORA / GDPR clocks); the rollup is built across the set.
  const r = cli(['run', '--scope', 'cross-cutting', '--evidence', '-', '--json'], { input: sub });
  // Even if blocked (exit 1), the body must be parseable.
  const body = tryJson(r.stdout) || tryJson(r.stderr) || {};
  const rollup = body.jurisdiction_clock_rollup;
  // Skip if the scope doesn't produce any rollup entries (engine state may
  // change with playbook catalog churn); the source-text fallback below
  // covers the contract either way.
  if (Array.isArray(rollup) && rollup.length > 0) {
    const sample = rollup[0];
    assert.ok('obligation' in sample,
      `rollup entry must carry an 'obligation' field. Got keys: ${Object.keys(sample).join(',')}`);
    assert.ok('obligation_ref' in sample,
      `rollup entry must continue to carry 'obligation_ref' alias. Got keys: ${Object.keys(sample).join(',')}`);
    assert.equal(sample.obligation, sample.obligation_ref,
      'obligation and obligation_ref must be the same value (alias).');
  }
  // Source-text fallback: ensure the helper emits both keys in the entry
  // shape literal. Tolerant of shorthand-property syntax (`obligation,` vs
  // `obligation: obligation,`).
  const binSrc = fs.readFileSync(path.join(ROOT, 'bin', 'exceptd.js'), 'utf8');
  // Look at the helper body specifically.
  const helperMatch = binSrc.match(/function buildJurisdictionClockRollup[\s\S]*?\n\}\n/);
  assert.ok(helperMatch, 'buildJurisdictionClockRollup helper must exist');
  const helperBody = helperMatch[0];
  assert.match(helperBody, /\bobligation\b\s*[,:]/,
    'buildJurisdictionClockRollup must include an `obligation` key in rollup entries');
  assert.match(helperBody, /\bobligation_ref\b\s*:/,
    'buildJurisdictionClockRollup must continue to set `obligation_ref` as a kept-name alias');
});

// ---------------------------------------------------------------------------
// R-F12 — --evidence-dir refuses symlink entries
// ---------------------------------------------------------------------------

test('R-F12: --evidence-dir refuses symbolic-link entries', (t) => {
  // Windows symlink creation requires elevated privileges by default. Skip
  // when symlink() throws EPERM — Junction creation is also restricted.
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'rf12-'));
  try {
    const real = path.join(tmp, 'real.json');
    fs.writeFileSync(real, '{}', 'utf8');
    const linkPath = path.join(tmp, 'library-author.json');
    try {
      fs.symlinkSync(real, linkPath, 'file');
    } catch (e) {
      if (e.code === 'EPERM' || e.code === 'EACCES' || e.code === 'ENOTSUP') {
        t.skip('platform refuses symlink creation (' + e.code + ')');
        return;
      }
      throw e;
    }
    const r = cli(['run', '--evidence-dir', tmp]);
    assert.equal(r.status, 1,
      '--evidence-dir with a symlink entry must exit 1 (symlink refusal). status=' + r.status);
    const err = tryJson(r.stderr.trim()) || {};
    assert.equal(err.ok, false);
    assert.match(err.error || '', /symbolic link|symlink/i,
      'refusal must name the symlink reason so the operator can fix the directory. Got: ' + (err.error || ''));
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});
