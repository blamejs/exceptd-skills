'use strict';

/**
 * tests/operator-leak-grep.test.js
 *
 * Operator-facing strings must reference `exceptd <verb>` as the
 * canonical entry point, not `node lib/sign.js …` or
 * `node orchestrator/index.js …` which are contributor-checkout
 * implementation paths that are not on PATH after `npm install -g`.
 *
 * The contributor-checkout form `node $(exceptd path)/lib/…` is allowed
 * as a fallback for users who want to invoke the internal scripts
 * directly — that form is portable because it derives the install path
 * from the operator-facing binary.
 *
 * The class fix: a v0.12.40 finding caught one site; subsequent audits
 * surfaced ~10 more. This test refuses the bare `node lib/…` /
 * `node orchestrator/…` pattern anywhere a string is rendered to the
 * operator.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');

// Files whose string contents reach the operator.
// - bin/exceptd.js + lib/*.js + orchestrator/*.js: runtime strings.
// - orchestrator/README.md: ships in the tarball.
// - .github/workflows/*.yml: visible to PR reviewers + repo browsers.
// - scripts/*.js + scripts/check-test-coverage.README.md: ship in tarball.
// Documented exclusions:
// - lib/sign.js own --help / usage block (lines 60-73, 458, 478-481):
//   it IS the contributor-checkout entry point; its own --help legitimately
//   references its own invocation form.
function collectFiles() {
  const out = [];
  const dirs = [
    { dir: 'bin', exts: ['.js'] },
    { dir: 'lib', exts: ['.js'] },
    { dir: 'orchestrator', exts: ['.js', '.md'] },
    { dir: 'scripts', exts: ['.js', '.md'] },
  ];
  for (const { dir, exts } of dirs) {
    const abs = path.join(ROOT, dir);
    if (!fs.existsSync(abs)) continue;
    for (const name of fs.readdirSync(abs, { withFileTypes: true })) {
      if (!name.isFile()) continue;
      if (!exts.some(e => name.name.endsWith(e))) continue;
      out.push(path.join(dir, name.name));
    }
  }
  // Add workflow files (one level deep).
  const wfDir = path.join(ROOT, '.github', 'workflows');
  if (fs.existsSync(wfDir)) {
    for (const name of fs.readdirSync(wfDir)) {
      if (name.endsWith('.yml') || name.endsWith('.yaml')) {
        out.push(path.join('.github', 'workflows', name));
      }
    }
  }
  return out;
}

// Match a leaked internal-path reference. The `$(exceptd path)/…` form
// is the documented contributor-checkout fallback; allow it through.
// Bare `node lib/sign.js` / `node orchestrator/index.js` is the leak.
const LEAK_RE = /\bnode\s+(lib|orchestrator)\/(sign|verify|index|playbook-runner|scoring)\.js\b/;

// Per-file allowlist:
// - lib/sign.js: its own usage / --help block is the contributor entry
//   point for that script; legitimately self-references.
// - lib/verify.js: same — its own header docs + CLI usage describe the
//   verify.js entry point. Operator-facing strings inside (warnings,
//   errors) are scrubbed separately via the line-level rules below.
// - .github/workflows/*.yml: workflows run in CI's source-tree checkout
//   where the `exceptd` binary isn't on PATH yet; `node orchestrator/…`
//   is the canonical contributor-checkout form there. Browse via
//   `gh workflow view` not via `npm install`.
const FILE_ALLOWLIST = new Set([
  'lib/sign.js',
  'lib/verify.js',
  '.github/workflows/atlas-currency.yml',
  '.github/workflows/ci.yml',
  '.github/workflows/release.yml',
  '.github/workflows/refresh.yml',
  '.github/workflows/scorecard.yml',
]);

test('no internal `node lib/…` / `node orchestrator/…` paths in operator-facing strings', () => {
  const leaks = [];
  for (const rel of collectFiles()) {
    if (FILE_ALLOWLIST.has(rel.replace(/\\/g, '/'))) continue;
    const text = fs.readFileSync(path.join(ROOT, rel), 'utf8');
    const lines = text.split('\n');
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      // Skip the `$(exceptd path)/…` form — that's the documented escape.
      if (/\$\(exceptd\s+path\)/.test(line)) continue;
      if (LEAK_RE.test(line)) {
        leaks.push(`${rel.replace(/\\/g, '/')}:${i + 1} — ${line.trim().slice(0, 140)}`);
      }
    }
  }
  assert.equal(leaks.length, 0,
    `Internal-path leaks in operator-facing strings (use \`exceptd <verb>\` or \`node $(exceptd path)/lib/…\` instead):\n  ${leaks.join('\n  ')}`);
});
