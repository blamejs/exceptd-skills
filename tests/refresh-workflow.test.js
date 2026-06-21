'use strict';

/**
 * tests/refresh-workflow.test.js
 *
 * Shape tests for .github/workflows/refresh.yml.
 *
 * The data-refresh path is split into two jobs:
 *   - refresh-data fetches upstream data with NO write credentials and a
 *     persist-credentials: false checkout.
 *   - open-pr carries contents:write + pull-requests:write, scoped to PR
 *     creation only, and depends on refresh-data.
 *
 * This file pins that split so a refactor can't re-merge the jobs or grant
 * the data-fetch job write credentials it doesn't need.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');

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

test('A: monolithic refresh job is gone', () => {
  const yml = fs.readFileSync(path.join(ROOT, '.github', 'workflows', 'refresh.yml'), 'utf8');
  assert.ok(!/^  refresh:\s*$/m.test(yml),
    'monolithic refresh job must be removed');
});
