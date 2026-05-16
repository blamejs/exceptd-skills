'use strict';

/**
 * tests/attestation-mode-0600.test.js
 *
 * Cycle 18 P1 F2 fix (v0.12.38): attestation files were written with the
 * umask-derived mode (typically 0o644 — group/world readable). On
 * multi-tenant shared hosts a different user account could read the
 * operator's evidence submission, jurisdiction obligations, and consent
 * records. Fix: mirror the existing private-key handling in lib/sign.js
 * (`fs.writeFileSync(path, content, { mode: 0o600 })` + restrictWindowsAcl
 * for Windows ACL inheritance stripping).
 *
 * Per CLAUDE.md anti-coincidence rule, every assertion checks an EXACT
 * mode value (0o600) — not "less permissive than 0o644".
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
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

function findAttestation(rootDir) {
  // resolveAttestationRoot returns $EXCEPTD_HOME/attestations/. The
  // persist layer writes to <root>/<session-id>/attestation.json (one
  // level deep). Some CI shapes wrap with an extra run-tag dir; walk
  // both 1-level and 2-level structures to be robust across platforms.
  if (!fs.existsSync(rootDir)) return null;
  for (const ent of fs.readdirSync(rootDir, { withFileTypes: true })) {
    if (!ent.isDirectory()) continue;
    const level1 = path.join(rootDir, ent.name);
    // Try 1-level (session at this depth).
    const direct = path.join(level1, 'attestation.json');
    if (fs.existsSync(direct)) return direct;
    // Try 2-level (run-tag wrapper).
    for (const inner of fs.readdirSync(level1, { withFileTypes: true })) {
      if (!inner.isDirectory()) continue;
      const att = path.join(level1, inner.name, 'attestation.json');
      if (fs.existsSync(att)) return att;
    }
  }
  return null;
}

test('attestation.json is written with mode 0o600 (owner-read/write only)', (t) => {
  // Windows file permissions don't map to POSIX 0o600 reliably — ACL
  // hardening is the Windows-side guard. Test the POSIX side on
  // Linux/macOS only; skip on Windows.
  if (process.platform === 'win32') {
    t.skip('POSIX mode bits do not apply on Windows; restrictWindowsAcl is the Windows-side test surface');
    return;
  }

  const tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'exceptd-mode-test-'));
  try {
    // Use the kernel positive-detect path (cycle 14 sanity check shape):
    // signal_overrides forces kver-in-affected-range to hit, which
    // triggers CVE matching → classification=detected → close phase
    // emits an evidence_package + the runner persists an attestation.
    const evidence = JSON.stringify({
      precondition_checks: { 'linux-platform': true, 'uname-available': true },
      artifacts: { 'kernel-release': '5.15.0-69-generic' },
      signal_overrides: { 'kver-in-affected-range': 'hit' },
    });
    // `--attestation-root` flag is more explicit than EXCEPTD_HOME for
    // test harnesses: it bypasses any env-var inheritance subtlety. CI
    // shapes (Linux/macOS) needed this to consistently route the
    // persist to the tmpdir.
    const attestationsRoot = path.join(tmpHome, 'attestations');
    const r = cli(['run', 'kernel', '--evidence', '-', '--attestation-root', attestationsRoot], {
      input: evidence,
    });
    assert.equal(r.status, 0, `run must succeed; got ${r.status}, stderr: ${r.stderr.slice(0, 200)}`);

    const attFile = findAttestation(attestationsRoot);
    assert.ok(attFile, `attestation.json must exist under ${attestationsRoot}; stdout: ${r.stdout.slice(0, 300)}`);

    const stat = fs.statSync(attFile);
    const perm = stat.mode & 0o777;
    assert.equal(perm, 0o600,
      `attestation.json mode must be 0o600 (got 0o${perm.toString(8)}). ` +
      `World-readable attestations leak evidence + consent records on multi-tenant hosts.`);
  } finally {
    try { fs.rmSync(tmpHome, { recursive: true, force: true }); } catch {}
  }
});

test('EXCEPTD_HOME override documented in README', () => {
  const readme = fs.readFileSync(path.join(ROOT, 'README.md'), 'utf8');
  // Pre-v0.12.38 the env var was only mentioned in inline help text.
  // Cycle 18 P2 F6 surfaced this gap: multi-tenant operators had no way
  // to discover the override without grepping the binary.
  assert.match(readme, /EXCEPTD_HOME/,
    'README must document EXCEPTD_HOME env var for multi-tenant attestation-root override');
});

test('MAL-2026-NODE-IPC-STEALER remediation_status reflects 2026-05-14 npm removal', () => {
  // Cycle 18 C state-change finding: npm pulled all 3 malicious versions
  // (9.1.6, 9.2.3, 12.0.1) within ~2 hours of publication on 2026-05-14.
  // Catalog must surface that the active-in-registry phase is over —
  // operators upgrading to a clean version are protected against the
  // npm-registry attack vector, but the expired-domain TTP class (per
  // NEW-CTRL-047) still applies.
  const c = JSON.parse(fs.readFileSync(path.join(ROOT, 'data', 'cve-catalog.json'), 'utf8'));
  const entry = c['MAL-2026-NODE-IPC-STEALER'];
  assert.ok(entry, 'MAL-2026-NODE-IPC-STEALER must remain in catalog (historical record)');
  assert.equal(entry.remediation_status, 'removed_from_registry');
  assert.equal(typeof entry.remediation_note, 'string');
  assert.equal(entry.remediation_note.length >= 50, true, 'note must be substantive');
  assert.equal(entry.remediation_status_verified_at, '2026-05-16');
});

test('CVE-2026-42897 still flags patch_available: false (no binary patch as of 2026-05-16)', () => {
  // Cycle 18 C verified Microsoft has not shipped a binary patch;
  // Exchange Emergency Mitigation Service Mitigation M2 is still the
  // only remediation. This is a regression test on the catalog truth.
  const c = JSON.parse(fs.readFileSync(path.join(ROOT, 'data', 'cve-catalog.json'), 'utf8'));
  const entry = c['CVE-2026-42897'];
  assert.ok(entry, 'CVE-2026-42897 must remain in catalog');
  assert.equal(entry.patch_available, false,
    'CVE-2026-42897 must NOT claim patch_available: true until Microsoft ships the binary SU. EEMS mitigation is M-only, not P.');
});
