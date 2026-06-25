'use strict';

/**
 * tests/release-workflow.test.js
 *
 * Shape tests for .github/workflows/release.yml.
 *
 * The publish path is split into two jobs with disjoint permission scopes:
 *   - publish-npm carries id-token:write (OIDC provenance) but NOT
 *     contents:write.
 *   - publish-github-release grants NO workflow write — it creates the Release
 *     with a per-run, scoped GitHub App installation token, so its workflow
 *     permission is contents:read; it carries no id-token:write and is
 *     sequenced after publish-npm.
 *
 * This file pins that job split and the least-privilege permission scoping
 * so a refactor can't silently re-merge the jobs or broaden a token.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');

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

test('A: release.yml declares both publish-npm and publish-github-release jobs', () => {
  const yml = fs.readFileSync(path.join(ROOT, '.github', 'workflows', 'release.yml'), 'utf8');
  assert.match(yml, /^  publish-npm:/m, 'publish-npm job must exist');
  assert.match(yml, /^  publish-github-release:/m, 'publish-github-release job must exist');
  // A single monolithic `publish` job must not exist.
  assert.ok(!/^  publish:\s*$/m.test(yml), 'monolithic publish job must be removed');
});

test('A: publish-npm job carries id-token:write but NOT contents:write', () => {
  const yml = fs.readFileSync(path.join(ROOT, '.github', 'workflows', 'release.yml'), 'utf8');
  const block = extractJobBlock(yml, 'publish-npm');
  assert.ok(block, 'publish-npm job block not parseable');
  assert.match(block, PERM_DECL('id-token', 'write'));
  assert.match(block, PERM_DECL('contents', 'read'));
  assert.ok(!PERM_DECL('contents', 'write').test(block),
    'publish-npm must NOT declare contents:write (job-split contract)');
});

test('A: publish-github-release uses a scoped App token, not a workflow contents:write', () => {
  const yml = fs.readFileSync(path.join(ROOT, '.github', 'workflows', 'release.yml'), 'utf8');
  const block = extractJobBlock(yml, 'publish-github-release');
  assert.ok(block, 'publish-github-release job block not parseable');
  // The workflow grants NO write — the Release is created with a per-run GitHub
  // App installation token, so the job permission is read-only (the avoidable
  // contents:write was removed to clear the Scorecard Token-Permissions finding).
  assert.match(block, PERM_DECL('contents', 'read'));
  assert.ok(!PERM_DECL('contents', 'write').test(block),
    'publish-github-release must NOT declare a workflow contents:write (the App token supplies the write)');
  assert.ok(!PERM_DECL('id-token', 'write').test(block),
    'publish-github-release must NOT declare id-token:write (job-split contract)');
  // It mints the scoped App token and passes it to action-gh-release.
  assert.match(block, /create-github-app-token@/,
    'publish-github-release must mint a scoped GitHub App token');
  assert.match(block, /permission-contents:\s*write/,
    'the minted App token must request contents:write for the release');
  assert.match(block, /token:\s*\$\{\{\s*steps\.app-token\.outputs\.token\s*\}\}/,
    'action-gh-release must use the minted App token, not the default GITHUB_TOKEN');
});

test('A: publish-github-release depends on publish-npm (sequenced)', () => {
  const yml = fs.readFileSync(path.join(ROOT, '.github', 'workflows', 'release.yml'), 'utf8');
  const block = extractJobBlock(yml, 'publish-github-release');
  assert.ok(block);
  assert.match(block, /needs:\s*\[\s*validate\s*,\s*publish-npm\s*\]/,
    'publish-github-release must depend on validate + publish-npm');
});
