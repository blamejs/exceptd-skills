'use strict';

/**
 * Regression: the jurisdiction-map builder must not free-text match bare
 * 2-letter ISO codes. `\bID\b` / `\bCA\b` / `\bSA\b` collide with prose words
 * ("the ID", "US-based") and control/countermeasure id grammar (`\bCA\b` inside
 * `D3-CA`, `\bSA\b` inside `SA-12`), so Indonesia landed on 41/51 skills and
 * ai-c2-detection (no Canadian content) landed in the CA bucket. These
 * jurisdictions are mapped via the curated regulation-name table instead; every
 * skill in a collision-prone bucket must genuinely reference that jurisdiction.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');
const JURIS = JSON.parse(fs.readFileSync(path.join(ROOT, 'data', '_indexes', 'jurisdiction-map.json'), 'utf8'));
const MANIFEST = JSON.parse(fs.readFileSync(path.join(ROOT, 'manifest.json'), 'utf8'));

function skillBody(name) {
  const entry = MANIFEST.skills.find(s => s.name === name);
  assert.ok(entry, `manifest has no skill ${name}`);
  return fs.readFileSync(path.join(ROOT, entry.path), 'utf8');
}

test('jurisdiction-map: ai-c2-detection (no Canadian content) is not in the CA bucket', () => {
  assert.equal((JURIS.CA?.skills || []).includes('ai-c2-detection'), false);
});

test('jurisdiction-map: every skill in a collision-prone 2-letter bucket references that jurisdiction', () => {
  const markers = {
    ID: /Indonesia|UU PDP|BSSN/,
    CA: /Canada|OSFI|Quebec|PIPEDA/,
    SA: /Saudi|KSA PDPL|SAMA/i,
  };
  for (const [code, re] of Object.entries(markers)) {
    for (const name of (JURIS[code]?.skills || [])) {
      assert.ok(re.test(skillBody(name)),
        `${name} is in the ${code} bucket but its body does not reference ${code} — a bare 2-letter ISO false positive`);
    }
  }
});
