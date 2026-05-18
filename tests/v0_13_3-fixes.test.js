'use strict';

/**
 * tests/v0_13_3-fixes.test.js
 *
 * Pin tests for the v0.13.3 patch.
 *
 * Coverage:
 *   A — refresh.yml split into refresh-data (no creds) + open-pr
 *       (contents:write + pull-requests:write scoped to PR creation only).
 *   B — Hard Rule #1 body-scan flipped from warning to hard error.
 *   E — doctor --ai-config produces a structured check matching the shape
 *       documented under NEW-CTRL-050.
 *   F — watchlist --org-scan refuses without --org / GITHUB_ORG; surfaces
 *       error envelope shape.
 *   G — ADVISORIES_SOURCE FEEDS grew from 4 to 8 (added kernel-org,
 *       oss-security, jfrog, cisa-current).
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const ROOT = path.join(__dirname, '..');
const CLI = path.join(ROOT, 'bin', 'exceptd.js');

function cli(args, opts = {}) {
  return spawnSync(process.execPath, [CLI, ...args], {
    encoding: 'utf8',
    cwd: ROOT,
    env: { ...process.env, EXCEPTD_DEPRECATION_SHOWN: '1', ...(opts.env || {}) },
    ...opts,
  });
}

function tryJson(s) { try { return JSON.parse(s); } catch { return null; } }

function extractJobBlock(yml, jobName) {
  const lines = yml.split('\n');
  let startIdx = -1;
  for (let i = 0; i < lines.length; i++) {
    if (lines[i] === `  ${jobName}:`) { startIdx = i; break; }
  }
  if (startIdx === -1) return null;
  let endIdx = lines.length;
  for (let i = startIdx + 1; i < lines.length; i++) {
    if (/^  [a-z][a-z0-9_-]*:\s*$/.test(lines[i])) { endIdx = i; break; }
  }
  return lines.slice(startIdx, endIdx).join('\n');
}

const PERM_DECL = (key, value) =>
  new RegExp(`^\\s+${key}:\\s+${value}\\s*$`, 'm');

// ---------- A. refresh.yml split-checkout ----------

test('A: refresh.yml has refresh-data job with NO write credentials', () => {
  const yml = fs.readFileSync(path.join(ROOT, '.github', 'workflows', 'refresh.yml'), 'utf8');
  const block = extractJobBlock(yml, 'refresh-data');
  assert.ok(block, 'refresh-data job must exist');
  assert.match(block, PERM_DECL('contents', 'read'));
  assert.ok(!PERM_DECL('contents', 'write').test(block),
    'refresh-data must NOT carry contents:write');
  assert.ok(!PERM_DECL('pull-requests', 'write').test(block),
    'refresh-data must NOT carry pull-requests:write');
  assert.ok(!PERM_DECL('issues', 'write').test(block),
    'refresh-data must NOT carry issues:write');
  // The checkout must persist-credentials: false in the no-creds job.
  assert.match(block, /persist-credentials:\s*false/);
});

test('A: refresh.yml has open-pr job with write credentials scoped here only', () => {
  const yml = fs.readFileSync(path.join(ROOT, '.github', 'workflows', 'refresh.yml'), 'utf8');
  const block = extractJobBlock(yml, 'open-pr');
  assert.ok(block, 'open-pr job must exist');
  assert.match(block, PERM_DECL('contents', 'write'));
  assert.match(block, PERM_DECL('pull-requests', 'write'));
  assert.match(block, /needs:\s*refresh-data/,
    'open-pr must depend on refresh-data');
});

test('A: pre-v0.13.3 monolithic refresh job is gone', () => {
  const yml = fs.readFileSync(path.join(ROOT, '.github', 'workflows', 'refresh.yml'), 'utf8');
  assert.ok(!/^  refresh:\s*$/m.test(yml),
    'pre-v0.13.3 monolithic refresh job must be removed');
});

// ---------- B. lint Hard Rule #1 body-scan is now hard error ----------

test('B: lint-skills body-scan flipped from warning to hard error', () => {
  const src = fs.readFileSync(path.join(ROOT, 'lib', 'lint-skills.js'), 'utf8');
  // The body-scan block: missing-from-catalog must push to skillErrors,
  // not skillWarnings. Match the canonical body-scan paragraph and
  // assert it now uses skillErrors.push for the "no such entry" case.
  const m = src.match(/no stale threat intel[\s\S]{0,400}body cites[\s\S]{0,800}/);
  assert.ok(m, 'body-scan block not found');
  // Find the missing-from-catalog branch (the `if (!entry)` arm).
  assert.match(src, /if \(!entry\) \{[\s\S]*?skillErrors\.push/,
    'missing-from-catalog must push to skillErrors (not skillWarnings)');
  // Draft case stays as warning.
  assert.match(src, /entry\._draft === true[\s\S]*?skillWarnings\.push/,
    'draft case still surfaces as warning');
});

// ---------- E. doctor --ai-config ----------

test('E: doctor --ai-config emits structured check with ai_config key', () => {
  const r = cli(['doctor', '--ai-config', '--json']);
  // Status may be 0 (no findings) or 1 (warn-level findings). Both fine.
  const body = tryJson(r.stdout);
  assert.ok(body, `expected JSON; got ${r.stdout.slice(0, 200)}`);
  assert.equal(body.verb, 'doctor');
  assert.ok(body.checks && body.checks.ai_config, 'checks.ai_config must be present');
  const c = body.checks.ai_config;
  assert.equal(typeof c.scanned_dirs, 'number');
  assert.equal(typeof c.scanned_files, 'number');
  assert.ok(Array.isArray(c.directories_inspected));
  assert.ok(c.directories_inspected.includes('~/.claude'),
    'must include ~/.claude in inspected dirs');
  assert.ok(c.directories_inspected.includes('~/.cursor'),
    'must include ~/.cursor in inspected dirs');
  assert.ok(c.directories_inspected.includes('~/.codeium'),
    'must include ~/.codeium in inspected dirs');
  assert.ok(Array.isArray(c.sensitive_patterns));
  assert.ok(Array.isArray(c.findings));
  assert.equal(c.control_reference, 'NEW-CTRL-050 (MAL-2026-SHAI-HULUD-OSS lesson)');
  assert.ok(['win32', 'darwin', 'linux', 'freebsd', 'openbsd', 'sunos', 'aix'].includes(c.platform));
});

// ---------- F. watchlist --org-scan ----------

test('F: watchlist --org-scan refuses without --org argument', () => {
  const r = cli(['watchlist', '--org-scan', '--json'], { env: { ...process.env, GITHUB_ORG: '', EXCEPTD_DEPRECATION_SHOWN: '1' } });
  assert.equal(r.status, 1, `expected exit 1; got ${r.status}`);
  const body = tryJson(r.stdout.trim()) || tryJson(r.stderr.trim());
  assert.ok(body && body.ok === false);
  assert.equal(body.verb, 'watchlist');
  assert.equal(body.mode, 'org-scan');
  assert.match(body.error, /requires --org/);
});

// ---------- G. 4 more primary-source pollers ----------

test('G: ADVISORIES_SOURCE FEEDS grew to 8 (v0.13.1 4 + v0.13.3 4)', () => {
  const { FEEDS } = require(path.join(ROOT, 'lib', 'source-advisories'));
  assert.equal(FEEDS.length, 8);
  const names = FEEDS.map((f) => f.name).sort();
  assert.deepEqual(names,
    ['cisa-current', 'jfrog', 'kernel-org', 'oss-security', 'qualys', 'rhsa', 'usn', 'zdi']);
});

test('G: every v0.13.3 feed URL uses HTTPS and matches a feed kind', () => {
  const { FEEDS } = require(path.join(ROOT, 'lib', 'source-advisories'));
  const v013_3 = ['kernel-org', 'oss-security', 'jfrog', 'cisa-current'];
  for (const name of v013_3) {
    const f = FEEDS.find((x) => x.name === name);
    assert.ok(f, `${name}: feed must exist in FEEDS`);
    assert.match(f.url, /^https:\/\//);
    assert.ok(['rss', 'csaf-index'].includes(f.kind),
      `${name}: kind must be rss or csaf-index`);
    assert.ok(typeof f.description === 'string' && f.description.length > 0);
  }
});
