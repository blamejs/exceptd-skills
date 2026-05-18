'use strict';

/**
 * tests/doctor-ai-config-substantive.test.js
 *
 * Beyond the v0.13.3 smoke pin — real fixture-driven file walk against
 * a temp HOME with controlled file modes. Verifies:
 *   - findings actually fire on non-0600 sensitive files (POSIX)
 *   - the pattern matcher catches each documented filename pattern
 *   - non-sensitive files in the inspected dirs are SKIPPED
 *   - missing dirs degrade silently (scanned_dirs reflects what's there)
 *   - the JSON envelope shape is consumable
 *
 * POSIX-only — the mode-bit check is meaningless on Windows. The Windows
 * info-level fallback is covered by the v0.13.3 smoke pin.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const { spawnSync } = require('node:child_process');

const ROOT = path.join(__dirname, '..');
const CLI = path.join(ROOT, 'bin', 'exceptd.js');

const isWindows = process.platform === 'win32';
const SKIP_REASON = isWindows ? 'POSIX-only — Windows ACL handling is the smoke test' : null;

function cli(args, opts = {}) {
  return spawnSync(process.execPath, [CLI, ...args], {
    encoding: 'utf8',
    cwd: ROOT,
    env: { ...process.env, EXCEPTD_DEPRECATION_SHOWN: '1', ...(opts.env || {}) },
    ...opts,
  });
}

function tryJson(s) { try { return JSON.parse(s); } catch { return null; } }

// Stage a temp HOME with controlled AI-assistant config files. Each dir
// gets one sensitive file at the requested mode, plus an unrelated file
// (README.md) to verify the non-sensitive filter.
function stageTempHome() {
  const tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'exceptd-ai-config-'));
  const dirs = ['.claude', '.cursor', '.codeium', '.aider', '.continue'];
  for (const d of dirs) {
    const abs = path.join(tmpHome, d);
    fs.mkdirSync(abs, { recursive: true, mode: 0o755 });
    // README — non-sensitive; must be ignored by the lint.
    fs.writeFileSync(path.join(abs, 'README.md'), '# unrelated', { mode: 0o644 });
  }
  return tmpHome;
}

function rmTempHome(p) {
  try { fs.rmSync(p, { recursive: true, force: true }); } catch { /* best effort */ }
}

test('--ai-config: finds non-0600 settings.json with warn severity', { skip: SKIP_REASON }, () => {
  const tmpHome = stageTempHome();
  try {
    const target = path.join(tmpHome, '.claude', 'settings.json');
    fs.writeFileSync(target, '{"theme":"dark"}', { mode: 0o644 });
    const r = cli(['doctor', '--ai-config', '--json'], { env: { ...process.env, HOME: tmpHome, USERPROFILE: tmpHome } });
    const body = tryJson(r.stdout);
    assert.ok(body && body.checks && body.checks.ai_config, 'must emit ai_config check');
    const c = body.checks.ai_config;
    const hit = c.findings.find((f) => f.path && f.path.endsWith('settings.json'));
    assert.ok(hit, `expected a finding for settings.json; got findings: ${JSON.stringify(c.findings)}`);
    assert.equal(hit.severity, 'warn');
    assert.equal(hit.issue, 'group_or_other_readable');
    assert.match(hit.mode, /^0[67]\d\d$/);
  } finally {
    rmTempHome(tmpHome);
  }
});

test('--ai-config: 0600 file produces NO finding (mode hardened)', { skip: SKIP_REASON }, () => {
  const tmpHome = stageTempHome();
  try {
    const target = path.join(tmpHome, '.cursor', 'mcp.json');
    fs.writeFileSync(target, '{}', { mode: 0o600 });
    const r = cli(['doctor', '--ai-config', '--json'], { env: { ...process.env, HOME: tmpHome, USERPROFILE: tmpHome } });
    const body = tryJson(r.stdout);
    assert.ok(body);
    const findings = body.checks.ai_config.findings.filter((f) => f.path && f.path.endsWith('mcp.json'));
    assert.equal(findings.length, 0, `0600 mode must NOT trigger a finding; got ${JSON.stringify(findings)}`);
  } finally {
    rmTempHome(tmpHome);
  }
});

test('--ai-config: each documented pattern matches', { skip: SKIP_REASON }, () => {
  const tmpHome = stageTempHome();
  try {
    // One file per documented sensitive pattern, all at insecure mode.
    const cases = [
      ['.claude/settings.json', 'settings\\.json'],
      ['.cursor/mcp.json', 'mcp\\.json'],
      ['.codeium/windsurf/mcp_config.json', 'mcp_config\\.json'],
      ['.aider/api_key_main', 'api_key'],
      ['.continue/session.token', '\\.token'],
      ['.claude/cli.credentials', '\\.credentials'],
    ];
    for (const [rel] of cases) {
      const abs = path.join(tmpHome, rel);
      fs.mkdirSync(path.dirname(abs), { recursive: true, mode: 0o755 });
      fs.writeFileSync(abs, 'x', { mode: 0o644 });
    }
    const r = cli(['doctor', '--ai-config', '--json'], { env: { ...process.env, HOME: tmpHome, USERPROFILE: tmpHome } });
    const body = tryJson(r.stdout);
    const findings = body.checks.ai_config.findings;
    for (const [rel] of cases) {
      const hit = findings.find((f) => f.path && f.path.endsWith(path.basename(rel)));
      assert.ok(hit, `pattern ${rel} must surface as a finding; got: ${JSON.stringify(findings.map((f) => f.path))}`);
    }
  } finally {
    rmTempHome(tmpHome);
  }
});

test('--ai-config: README.md and other non-sensitive files are NOT flagged', { skip: SKIP_REASON }, () => {
  // stageTempHome() already writes README.md at 0o644 in every inspected
  // dir. Verify none surfaces as a finding.
  const tmpHome = stageTempHome();
  try {
    const r = cli(['doctor', '--ai-config', '--json'], { env: { ...process.env, HOME: tmpHome, USERPROFILE: tmpHome } });
    const body = tryJson(r.stdout);
    const readmeFindings = body.checks.ai_config.findings.filter((f) => f.path && f.path.endsWith('README.md'));
    assert.equal(readmeFindings.length, 0, 'README.md must NOT match the sensitive-pattern allowlist');
  } finally {
    rmTempHome(tmpHome);
  }
});

test('--ai-config: missing dirs reduce scanned_dirs but do not error', { skip: SKIP_REASON }, () => {
  // tempHome with NO AI-config dirs at all — just an empty HOME.
  const tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'exceptd-ai-config-empty-'));
  try {
    const r = cli(['doctor', '--ai-config', '--json'], { env: { ...process.env, HOME: tmpHome, USERPROFILE: tmpHome } });
    assert.equal(r.status, 0, `empty HOME must NOT error; got status ${r.status}`);
    const body = tryJson(r.stdout);
    assert.equal(body.checks.ai_config.scanned_dirs, 0);
    assert.equal(body.checks.ai_config.findings.length, 0);
    assert.equal(body.checks.ai_config.ok, true);
  } finally {
    rmTempHome(tmpHome);
  }
});
