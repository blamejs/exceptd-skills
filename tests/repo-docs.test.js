'use strict';

/**
 * tests/repo-docs.test.js
 *
 * Reads README.md and AGENTS.md and pins that operator-facing docs surface
 * the user-visible CLI features and the control inventory:
 *   - README documents watchlist --alerts / --org-scan (+ GITHUB_TOKEN),
 *     doctor --ai-config, refresh --check-advisories, and names the four
 *     incident-response playbooks.
 *   - AGENTS.md documents NEW-CTRL-048 through NEW-CTRL-055 and the daily
 *     exceptd-threat-intake routine + its schedule.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');

// ---------- README surfaces the CLI features ----------

test('C: README documents watchlist --alerts', () => {
  const readme = fs.readFileSync(path.join(ROOT, 'README.md'), 'utf8');
  assert.match(readme, /watchlist.*--alerts/i, 'README must mention watchlist --alerts');
});

test('C: README documents watchlist --org-scan + GITHUB_TOKEN', () => {
  const readme = fs.readFileSync(path.join(ROOT, 'README.md'), 'utf8');
  assert.match(readme, /--org-scan/, 'README must mention --org-scan');
  assert.match(readme, /GITHUB_TOKEN/, 'README must mention the GITHUB_TOKEN env var for org-scan');
});

test('C: README documents doctor --ai-config', () => {
  const readme = fs.readFileSync(path.join(ROOT, 'README.md'), 'utf8');
  assert.match(readme, /--ai-config/, 'README must mention doctor --ai-config');
  assert.match(readme, /~\/\.claude|~\/\.cursor|~\/\.codeium/,
    'README must name the AI-assistant dirs the audit walks');
});

test('C: README documents refresh --check-advisories', () => {
  const readme = fs.readFileSync(path.join(ROOT, 'README.md'), 'utf8');
  assert.match(readme, /--check-advisories/, 'README must mention refresh --check-advisories');
});

test('C: README names the four incident-response playbooks', () => {
  // The live playbook-count pin lives in tests/doc-playbook-count-currency.test.js
  // (which tracks the catalog total and fires on drift). This test pins that
  // the four incident-response playbooks are mentioned by name in the README
  // synopsis, since they anchor that surface.
  const readme = fs.readFileSync(path.join(ROOT, 'README.md'), 'utf8');
  for (const id of ['webhook-callback-abuse', 'cicd-pipeline-compromise', 'identity-sso-compromise', 'llm-tool-use-exfil']) {
    assert.match(readme, new RegExp(id), `README must name ${id}`);
  }
});

// ---------- AGENTS.md surfaces the control inventory + routine ----------

test('C: AGENTS.md documents NEW-CTRL-048 through NEW-CTRL-055', () => {
  const agents = fs.readFileSync(path.join(ROOT, 'AGENTS.md'), 'utf8');
  for (const id of ['NEW-CTRL-048', 'NEW-CTRL-049', 'NEW-CTRL-050', 'NEW-CTRL-051', 'NEW-CTRL-052', 'NEW-CTRL-053', 'NEW-CTRL-054', 'NEW-CTRL-055']) {
    assert.match(agents, new RegExp(id), `AGENTS.md must document ${id}`);
  }
});

test('C: AGENTS.md documents the daily exceptd-threat-intake routine', () => {
  const agents = fs.readFileSync(path.join(ROOT, 'AGENTS.md'), 'utf8');
  assert.match(agents, /exceptd-threat-intake/);
  assert.match(agents, /14:00\s+UTC|07:00\s+(PDT|PST)/i,
    'AGENTS.md must document the routine schedule');
});
