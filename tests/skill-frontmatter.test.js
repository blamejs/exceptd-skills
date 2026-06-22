'use strict';

/**
 * tests/skill-frontmatter.test.js
 *
 * Reads skills/<name>/skill.md frontmatter + prose and pins:
 *   - standalone skills carry the discovery_mode: standalone frontmatter
 *     field.
 *   - CVE-2024-3094 (xz-utils) prose in three skills matches catalog ground
 *     truth (RWEP 70, CVSS 10.0, ai_discovered false), not the drifted
 *     pre-correction values.
 *   - skill bodies use the canonical unhyphenated "Volt Typhoon" form.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');

// ---------- discovery_mode field on standalone skills ----------

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

// ---------- CVE-2024-3094 prose matches catalog ground truth ----------

test('F1/F2: CVE-2024-3094 in supply-chain-integrity skill matches catalog ground truth', () => {
  const body = fs.readFileSync(path.join(ROOT, 'skills', 'supply-chain-integrity', 'skill.md'), 'utf8');
  // Pre-correction claim: "not in current `data/cve-catalog.json` — pre-scope incident"
  assert.equal(/CVE-2024-3094[^\n]*not in current/.test(body), false,
    'supply-chain-integrity must not claim CVE-2024-3094 is "not in current catalog" (it is)');
  // Corrected: the Exploit Availability Matrix table row pins RWEP 70 in
  // the second pipe-cell after the name. Match any line that contains
  // CVE-2024-3094 followed by ` 70 ` (with separators) on the same line.
  const lines = body.split('\n');
  const row = lines.find((l) => /CVE-2024-3094/.test(l) && /\|\s*70\s*\(catalog/.test(l));
  assert.ok(row, `supply-chain-integrity must have a CVE-2024-3094 table row with "70 (catalog: ...)"; matching lines: ${lines.filter(l => /CVE-2024-3094/.test(l)).join(' | ')}`);
});

test('F1/F2: CVE-2024-3094 in sector-federal-government skill matches catalog ground truth', () => {
  const body = fs.readFileSync(path.join(ROOT, 'skills', 'sector-federal-government', 'skill.md'), 'utf8');
  assert.equal(/CVE-2024-3094[^\n]*not in current/.test(body), false,
    'sector-federal-government must not claim CVE-2024-3094 is "not in current catalog"');
  const lines = body.split('\n');
  const row = lines.find((l) => /CVE-2024-3094/.test(l) && /\|\s*70\s*\(catalog/.test(l));
  assert.ok(row, 'sector-federal-government must have CVE-2024-3094 row with "70 (catalog: ...)"');
});

test('F1/F2: CVE-2024-3094 in cloud-iam-incident skill row matches catalog ground truth', () => {
  const body = fs.readFileSync(path.join(ROOT, 'skills', 'cloud-iam-incident', 'skill.md'), 'utf8');
  // Find the table row containing CVE-2024-3094.
  const row = body.split('\n').find((l) => /CVE-2024-3094/.test(l));
  assert.ok(row, 'cloud-iam-incident must contain a CVE-2024-3094 row');
  // Catalog ground truth: rwep_score 70, ai_discovered false, active_exploitation "suspected".
  assert.match(row, /\|\s*10\.0\s*\|\s*70\s*\|/, `cloud-iam-incident CVE-2024-3094 row must show CVSS 10.0 / RWEP 70; got: ${row}`);
  // The drifted value said "Partially" for ai_discovered (catalog is false).
  assert.equal(/Partially/.test(row), false, 'ai_discovered "Partially" was the drifted value (catalog is false)');
});

// ---------- Volt Typhoon hyphenation ----------

test('F3: no skill body contains hyphenated "Volt-Typhoon"', () => {
  const skillsDir = path.join(ROOT, 'skills');
  const violations = [];
  function walk(dir) {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) { walk(full); continue; }
      if (!entry.isFile() || !entry.name.endsWith('.md')) continue;
      const text = fs.readFileSync(full, 'utf8');
      const lines = text.split('\n');
      for (let i = 0; i < lines.length; i++) {
        if (/Volt-Typhoon/.test(lines[i])) {
          violations.push({ file: path.relative(ROOT, full).replace(/\\/g, '/'), line: i + 1, text: lines[i].slice(0, 100) });
        }
      }
    }
  }
  walk(skillsDir);
  assert.deepEqual(violations, [],
    `"Volt-Typhoon" must not appear in skill bodies (canonical form is "Volt Typhoon" without hyphen): ${JSON.stringify(violations, null, 2)}`);
});
