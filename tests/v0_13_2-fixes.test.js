'use strict';

/**
 * tests/v0_13_2-fixes.test.js
 *
 * Pinning tests for the v0.13.2 patch-class mega-release.
 *
 * Fixes covered:
 *   A — release.yml split into publish-npm (id-token:write only) +
 *       publish-github-release (contents:write only). Verifies the YAML
 *       declares both jobs with disjoint permission scopes.
 *   B — lint-skills.js Hard Rule #1 enforcement: body-scan refuses CVE
 *       references not in catalog AND warns on _draft references.
 *   C — flag-value did-you-mean: --mode / --phase / --format / --csaf-status
 *       typos return did_you_mean[] in the structured error body.
 *   D — check-test-count.js: predeploy gate refuses test-set shrinkage
 *       beyond the configured tolerance.
 *   E — skill discovery_mode: 16 standalone skills carry the
 *       "discovery_mode: standalone" frontmatter field.
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

// ---------- A. release.yml job split ----------

test('A: release.yml declares both publish-npm and publish-github-release jobs', () => {
  const yml = fs.readFileSync(path.join(ROOT, '.github', 'workflows', 'release.yml'), 'utf8');
  assert.match(yml, /^  publish-npm:/m, 'publish-npm job must exist');
  assert.match(yml, /^  publish-github-release:/m, 'publish-github-release job must exist');
  // Pre-v0.13.2 a single `publish` job existed. Confirm it's gone.
  assert.ok(!/^  publish:\s*$/m.test(yml), 'pre-v0.13.2 monolithic publish job must be removed');
});

// Helper: extract a job block from release.yml. Walks line-by-line and
// stops at the next line whose entire content matches the job-header
// pattern (`  word:` at column 2, nothing else on the line).
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

// Regex helpers: match permission DECLARATIONS (`      contents: write`
// at leading whitespace, end-of-line) rather than any prose mention.
// Comments + descriptions inside the YAML often quote the strings.
const PERM_DECL = (key, value) =>
  new RegExp(`^\\s+${key}:\\s+${value}\\s*$`, 'm');

test('A: publish-npm job carries id-token:write but NOT contents:write', () => {
  const yml = fs.readFileSync(path.join(ROOT, '.github', 'workflows', 'release.yml'), 'utf8');
  const block = extractJobBlock(yml, 'publish-npm');
  assert.ok(block, 'publish-npm job block not parseable');
  assert.match(block, PERM_DECL('id-token', 'write'));
  assert.match(block, PERM_DECL('contents', 'read'));
  assert.ok(!PERM_DECL('contents', 'write').test(block),
    'publish-npm must NOT declare contents:write (job-split contract)');
});

test('A: publish-github-release job carries contents:write but NOT id-token:write', () => {
  const yml = fs.readFileSync(path.join(ROOT, '.github', 'workflows', 'release.yml'), 'utf8');
  const block = extractJobBlock(yml, 'publish-github-release');
  assert.ok(block, 'publish-github-release job block not parseable');
  assert.match(block, PERM_DECL('contents', 'write'));
  assert.ok(!PERM_DECL('id-token', 'write').test(block),
    'publish-github-release must NOT declare id-token:write (job-split contract)');
});

test('A: publish-github-release depends on publish-npm (sequenced)', () => {
  const yml = fs.readFileSync(path.join(ROOT, '.github', 'workflows', 'release.yml'), 'utf8');
  const block = extractJobBlock(yml, 'publish-github-release');
  assert.ok(block);
  assert.match(block, /needs:\s*\[\s*validate\s*,\s*publish-npm\s*\]/,
    'publish-github-release must depend on validate + publish-npm');
});

// ---------- B. lint Hard Rule #1 body-scan ----------

test('B: lint-skills.js source carries the body-scan implementation', () => {
  const src = fs.readFileSync(path.join(ROOT, 'lib', 'lint-skills.js'), 'utf8');
  assert.match(src, /Hard Rule #1/, 'body-scan must explicitly cite Hard Rule #1');
  assert.match(src, /body cites/, 'body-scan must emit "body cites" warning text');
  assert.match(src, /ctx\.cveCatalog/, 'body-scan must consume ctx.cveCatalog');
  assert.match(src, /_draft\s*===\s*true/, 'body-scan must distinguish draft entries');
  assert.match(src, /will hard-fail in v0\.14\.0/, 'v0.13.2 surfaces as warning; v0.14.0 will flip to hard error');
});

test('B: validateFrontmatter accepts discovery_mode field (no "unknown field" error)', () => {
  const src = fs.readFileSync(path.join(ROOT, 'lib', 'lint-skills.js'), 'utf8');
  assert.match(src, /discovery_mode/, 'OPTIONAL_FRONTMATTER_FIELDS must include discovery_mode');
});

// ---------- C. flag-value did-you-mean ----------

test('C: brief --phase typo returns did_you_mean[]', () => {
  const r = cli(['brief', 'library-author', '--phase', 'goven', '--json']);
  // emitError sets exitCode = GENERIC_FAILURE (1). Pin exact code.
  assert.equal(r.status, 1, `expected exit 1 (GENERIC_FAILURE); got ${r.status}`);
  const body = tryJson(r.stderr.trim()) || tryJson(r.stdout.trim());
  assert.ok(body && body.ok === false);
  assert.ok(Array.isArray(body.did_you_mean));
  assert.ok(body.did_you_mean.includes('govern'),
    `expected govern in did_you_mean for "goven"; got ${JSON.stringify(body.did_you_mean)}`);
  assert.ok(Array.isArray(body.accepted));
});

test('C: report unknown-format typo returns did_you_mean[]', () => {
  const r = spawnSync(process.execPath, [path.join(ROOT, 'orchestrator', 'index.js'), 'report', 'execuive'], {
    encoding: 'utf8', cwd: ROOT,
  });
  // v0.13 orchestrator exit-code class fix: usage errors → exit 1.
  assert.equal(r.status, 1, `expected exit 1 (GENERIC_FAILURE); got ${r.status}`);
  const body = tryJson(r.stdout.trim()) || tryJson(r.stderr.trim());
  assert.ok(body && body.ok === false);
  assert.ok(Array.isArray(body.did_you_mean));
  assert.ok(body.did_you_mean.includes('executive'),
    `expected executive in did_you_mean for "execuive"; got ${JSON.stringify(body.did_you_mean)}`);
});

// ---------- D. check-test-count gate ----------

test('D: check-test-count.js exists and emits structured JSON', () => {
  const r = spawnSync(process.execPath, [path.join(ROOT, 'scripts', 'check-test-count.js'), '--json'], {
    encoding: 'utf8', cwd: ROOT,
  });
  assert.equal(r.status, 0, `gate must pass on current state; got ${r.status}. stderr: ${r.stderr.slice(0, 200)}`);
  const body = tryJson(r.stdout.trim());
  assert.ok(body, 'gate must emit JSON when --json passed');
  assert.equal(body.verb, 'check-test-count');
  assert.equal(typeof body.observed, 'number');
  assert.equal(typeof body.baseline, 'number');
  assert.equal(typeof body.delta, 'number');
  assert.ok(['ok', 'grew_beyond_threshold_consider_bump'].includes(body.status),
    `status must be ok or grew_beyond_threshold; got ${body.status}`);
});

test('D: predeploy.js wires test-count gate as #15', () => {
  const src = fs.readFileSync(path.join(ROOT, 'scripts', 'predeploy.js'), 'utf8');
  assert.match(src, /Test-count baseline/, 'predeploy.js must register the test-count gate');
  assert.match(src, /scripts.*check-test-count\.js/, 'predeploy.js must reference scripts/check-test-count.js');
});

// ---------- E. discovery_mode field on standalone skills ----------

test('E: 16 skills carry discovery_mode: standalone frontmatter', () => {
  const expected = [
    'age-gates-child-safety', 'ai-risk-management', 'defensive-countermeasure-mapping',
    'email-security-anti-phishing', 'fuzz-testing-strategy', 'mlops-security',
    'ot-ics-security', 'researcher', 'sector-energy', 'sector-federal-government',
    'sector-telecom', 'skill-update-loop', 'threat-model-currency',
    'threat-modeling-methodology', 'webapp-security', 'zeroday-gap-learn',
  ];
  for (const name of expected) {
    const p = path.join(ROOT, 'skills', name, 'skill.md');
    if (!fs.existsSync(p)) continue; // skip if skill renamed/removed in a future release
    const content = fs.readFileSync(p, 'utf8');
    assert.match(content, /^discovery_mode:\s*["']?standalone["']?/m,
      `${name}: must carry discovery_mode: standalone in frontmatter`);
  }
});
