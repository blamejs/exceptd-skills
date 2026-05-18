'use strict';

/**
 * tests/doc-playbook-count-currency.test.js
 *
 * v0.13.10 regression pin. README.md + AGENTS.md include prose like
 * "23 investigation playbooks" or "Grouped-by-scope summary of all 23
 * playbooks". When new playbooks land, the count must move in lockstep
 * with data/playbooks/*.json -- otherwise operators reading the README
 * believe the surface is smaller than it actually is.
 *
 * The pin: every prose number-of-playbooks claim in README.md /
 * AGENTS.md must match the live count of data/playbooks/*.json files.
 * If a future release adds a playbook without bumping the count in
 * docs, this test fires.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');

function livePlaybookCount() {
  return fs.readdirSync(path.join(ROOT, 'data', 'playbooks'))
    .filter((f) => f.endsWith('.json'))
    .length;
}

function findClaims(filePath) {
  const text = fs.readFileSync(filePath, 'utf8');
  // Match "<N> playbook(s)" and "<N> investigation playbook(s)" patterns.
  const re = /\b(\d{1,3})\s+(?:investigation\s+)?playbooks?\b/gi;
  const claims = [];
  let m;
  while ((m = re.exec(text)) !== null) {
    const n = Number(m[1]);
    const start = Math.max(0, m.index - 40);
    const end = Math.min(text.length, m.index + 60);
    claims.push({ n, snippet: text.slice(start, end).replace(/\s+/g, ' ').trim() });
  }
  return claims;
}

test('README + AGENTS playbook-count claims match live catalog count', () => {
  const live = livePlaybookCount();
  assert.ok(live >= 23, `expected live count >= 23; got ${live}`);

  const docs = ['README.md', 'AGENTS.md'];
  const mismatches = [];
  for (const rel of docs) {
    const claims = findClaims(path.join(ROOT, rel));
    for (const c of claims) {
      // Numbers 1-14 are almost certainly grammatical ("five-phase",
      // "two of the playbooks", etc.) -- only assert against the high
      // range that genuinely talks about the catalog total.
      if (c.n < 15) continue;
      if (c.n !== live) {
        mismatches.push(`${rel}: claim "${c.n} playbooks" disagrees with live count ${live} (context: ...${c.snippet}...)`);
      }
    }
  }
  assert.deepEqual(mismatches, [],
    `doc playbook-count drift:\n  - ${mismatches.join('\n  - ')}\n` +
    `Update the claim to "${live} playbooks" in the named file(s).`);
});
