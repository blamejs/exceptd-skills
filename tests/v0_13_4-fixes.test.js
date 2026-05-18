'use strict';

/**
 * tests/v0_13_4-fixes.test.js
 *
 * Pin tests for the v0.13.4 patch.
 *
 * Coverage:
 *   A — _meta.fed_by is now schema-accepted (drives the 20 cosmetic
 *       validate-playbooks warnings to 0).
 *   C — README + AGENTS surface the v0.13.x operator-facing features.
 *   E — 2 stuck-draft CVEs (MAL-2026-ANTHROPIC-MCP-STDIO + CVE-2026-GTIG-AI-2FA)
 *       are deleted from the catalog and from any cross-referencing data file.
 *   (B and D pin coverage is in their dedicated test files; this file
 *    covers the items that don't have a natural dedicated home.)
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const ROOT = path.join(__dirname, '..');

// ---------- A. fed_by schema acceptance ----------

test('A: playbook.schema.json declares _meta.fed_by as an array of strings', () => {
  const src = fs.readFileSync(path.join(ROOT, 'lib', 'schemas', 'playbook.schema.json'), 'utf8');
  // Schema must accept the field — the "unexpected property fed_by"
  // cosmetic warnings on 20 playbooks should be gone.
  const schema = JSON.parse(src);
  const meta = schema.properties._meta;
  assert.ok(meta, 'schema must declare _meta');
  assert.ok(meta.properties.fed_by, '_meta.fed_by must be declared');
  assert.equal(meta.properties.fed_by.type, 'array');
  assert.equal(meta.properties.fed_by.items.type, 'string');
});

test('A: validate-playbooks no longer emits any "unexpected property fed_by" warnings', () => {
  const r = spawnSync(process.execPath, [path.join(ROOT, 'lib', 'validate-playbooks.js')], {
    encoding: 'utf8', cwd: ROOT,
  });
  // Acceptable: passes or warns on unrelated fields. Must NOT contain
  // any "fed_by" warning.
  assert.ok(!/unexpected property "fed_by"/i.test(r.stdout + r.stderr),
    `validate-playbooks must not warn on fed_by anymore; got:\n${r.stdout.slice(0, 800)}`);
});

// ---------- C. README + AGENTS surface v0.13.x features ----------

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

test('C: README updated playbook count + 4 v0.13.0 playbook names', () => {
  // v0.13.10: the count pin moved to tests/doc-playbook-count-currency.test.js
  // (which tracks the live catalog total and fires on drift). This test
  // still pins that the 4 playbooks added in v0.13.0 are mentioned by name
  // in the README synopsis, since they anchor the v0.13.0 surface.
  const readme = fs.readFileSync(path.join(ROOT, 'README.md'), 'utf8');
  for (const id of ['webhook-callback-abuse', 'cicd-pipeline-compromise', 'identity-sso-compromise', 'llm-tool-use-exfil']) {
    assert.match(readme, new RegExp(id), `README must name ${id}`);
  }
});

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

// ---------- E. 2 stuck-draft CVEs deleted ----------

test('E: MAL-2026-ANTHROPIC-MCP-STDIO is removed from catalog', () => {
  const c = JSON.parse(fs.readFileSync(path.join(ROOT, 'data', 'cve-catalog.json'), 'utf8'));
  assert.ok(!('MAL-2026-ANTHROPIC-MCP-STDIO' in c),
    'MAL-2026-ANTHROPIC-MCP-STDIO must be deleted (duplicate of CVE-2026-30623)');
});

test('E: CVE-2026-GTIG-AI-2FA is removed from catalog', () => {
  const c = JSON.parse(fs.readFileSync(path.join(ROOT, 'data', 'cve-catalog.json'), 'utf8'));
  assert.ok(!('CVE-2026-GTIG-AI-2FA' in c),
    'CVE-2026-GTIG-AI-2FA must be deleted (embargoed placeholder)');
});

test('E: zeroday-lessons.json carries no orphan entries for the deleted CVEs', () => {
  const l = JSON.parse(fs.readFileSync(path.join(ROOT, 'data', 'zeroday-lessons.json'), 'utf8'));
  assert.ok(!('MAL-2026-ANTHROPIC-MCP-STDIO' in l));
  assert.ok(!('CVE-2026-GTIG-AI-2FA' in l));
});

test('E: validate-cve-catalog reports 0 drafts after cleanup', () => {
  const r = spawnSync(process.execPath, [path.join(ROOT, 'lib', 'validate-cve-catalog.js')], {
    encoding: 'utf8', cwd: ROOT,
  });
  assert.equal(r.status, 0, `validator must pass; got ${r.status}. stderr: ${r.stderr.slice(0, 200)}`);
  // Acceptable phrasing: "38/38 CVE entries validated" with no draft count
  // OR "38/38, 0 drafts" — either way no draft segment greater than zero.
  assert.ok(!/[1-9]\d*\s+draft/i.test(r.stdout),
    `catalog must report 0 drafts post-cleanup; got: ${r.stdout.slice(0, 400)}`);
});
