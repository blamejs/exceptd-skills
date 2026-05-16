'use strict';

/**
 * tests/cycle17-ux-fixes.test.js
 *
 * Cycle 17 fixes (v0.12.37):
 *
 *   S4 — `--evidence -` with empty stdin now emits a stderr nudge.
 *        Pre-fix the empty payload was silently accepted as {} and the
 *        run looked successful. Cycle 15 flagged; cycle 17 verified
 *        still open. The fix preserves the legitimate "posture-only
 *        walk" use case (the run still proceeds with {}) but surfaces
 *        a stderr `[exceptd] note: ...` message so the operator at
 *        least knows.
 *
 *   S13 — unknown verb with Levenshtein-1 typo now suggests the
 *         intended verb. `exceptd discoer` → `discover`,
 *         `exceptd attst` → `attest`. Includes transposition detection
 *         so `disocver` also resolves to `discover`. Unknown verbs
 *         outside edit-distance 1 still get the generic hint.
 *
 *   F1/F2 — operator-misleading skill prose about CVE-2024-3094
 *         (xz-utils). Pre-fix 2 skills said "not in current cve-catalog
 *         — pre-scope incident" while the catalog actually carries the
 *         entry; a 3rd skill quoted RWEP 95 against the catalog's 70
 *         plus drifted ai_discovered and active_exploitation. This
 *         test pins the corrected prose.
 *
 *   F3 — Volt-Typhoon hyphenation drift (cosmetic). Two skills used
 *         `Volt-Typhoon-aligned` / `Volt-Typhoon-style`. All others use
 *         unhyphenated `Volt Typhoon`. Test pins single canonical form.
 *
 * Per CLAUDE.md anti-coincidence rule, every assertion checks an EXACT
 * value (string match, deepEqual, or specific count).
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
    cwd: opts.cwd || ROOT,
    env: { ...process.env, EXCEPTD_DEPRECATION_SHOWN: '1', ...(opts.env || {}) },
    input: opts.input,
  });
}

function tryJson(s) { try { return JSON.parse(s); } catch { return null; } }

// S4 — empty-stdin nudge ---------------------------------------------------

test('S4: --evidence - with empty stdin emits stderr nudge + still proceeds', () => {
  // posture-only walk on framework playbook (no preconditions block it).
  const r = cli(['run', 'framework', '--evidence', '-'], { input: '' });
  assert.equal(r.status, 0, `posture-only run must succeed; got ${r.status}`);
  assert.match(r.stderr, /--evidence - read 0 bytes from stdin/,
    `stderr must surface the empty-stdin nudge; got: ${r.stderr.slice(0, 200)}`);
  assert.match(r.stderr, /exceptd brief/, 'nudge must point at `exceptd brief` for the expected shape');
});

test('S4: --evidence - with valid JSON does NOT emit the empty-stdin nudge', () => {
  const r = cli(['run', 'framework', '--evidence', '-'], { input: '{}' });
  assert.equal(r.status, 0);
  assert.equal(/read 0 bytes from stdin/.test(r.stderr), false,
    'non-empty stdin must NOT emit the nudge');
});

// S13 — did-you-mean for unknown verbs -------------------------------------

test('S13: unknown verb within Levenshtein-1 of a real verb returns did_you_mean[]', () => {
  for (const [typo, expected] of [['discoer', 'discover'], ['attst', 'attest'], ['disocver', 'discover']]) {
    const r = cli([typo]);
    assert.equal(r.status, 10, `${typo} must exit UNKNOWN_COMMAND (10); got ${r.status}`);
    const err = tryJson(r.stderr);
    assert.ok(err, `${typo} stderr must be JSON`);
    assert.equal(Array.isArray(err.did_you_mean), true);
    assert.equal(err.did_you_mean.includes(expected), true,
      `${typo} should suggest "${expected}"; got: ${JSON.stringify(err.did_you_mean)}`);
    assert.match(err.hint, /Did you mean/, 'hint must surface the suggestion');
  }
});

test('S13: did_you_mean[] deduplicates across overlapping verb sources (codex P2 v0.12.37 follow-up)', () => {
  // `scan` lives in both COMMANDS and ORCHESTRATOR_PASSTHROUGH; pre-fix
  // the union produced ["scan", "scan"] and the human hint read
  // "Did you mean `scan` or `scan`?". Now deduped via Set.
  const r = cli(['scn']);
  assert.equal(r.status, 10);
  const err = tryJson(r.stderr);
  assert.ok(err, 'stderr must be JSON');
  assert.equal(Array.isArray(err.did_you_mean), true);
  // Set semantics: same verb appears at most once.
  const seen = new Set(err.did_you_mean);
  assert.equal(seen.size, err.did_you_mean.length,
    `did_you_mean must contain unique verbs; got duplicates: ${JSON.stringify(err.did_you_mean)}`);
  assert.equal(err.did_you_mean.includes('scan'), true);
});

test('S13: unknown verb beyond Levenshtein-1 returns empty did_you_mean[] (no false suggestions)', () => {
  const r = cli(['xyzzyzzz']);
  assert.equal(r.status, 10);
  const err = tryJson(r.stderr);
  assert.deepEqual(err.did_you_mean, [], 'distant typo must NOT trigger a suggestion');
  assert.equal(/Did you mean/.test(err.hint), false);
});

// F1/F2 — CVE-2024-3094 prose corrections ----------------------------------

test('F1/F2: CVE-2024-3094 in supply-chain-integrity skill matches catalog ground truth', () => {
  const body = fs.readFileSync(path.join(ROOT, 'skills', 'supply-chain-integrity', 'skill.md'), 'utf8');
  // Pre-fix claim: "not in current `data/cve-catalog.json` — pre-scope incident"
  assert.equal(/CVE-2024-3094[^\n]*not in current/.test(body), false,
    'supply-chain-integrity must not claim CVE-2024-3094 is "not in current catalog" (it is)');
  // Post-fix: the Exploit Availability Matrix table row pins RWEP 70 in
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
  // Pre-fix said "Partially" for ai_discovered + "Confirmed" for active_exploitation.
  assert.equal(/Partially/.test(row), false, 'ai_discovered "Partially" was pre-fix value (catalog is false)');
});

// F3 — Volt-Typhoon hyphenation --------------------------------------------

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
