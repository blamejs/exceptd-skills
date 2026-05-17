'use strict';

/**
 * tests/safe-exit-grep.test.js
 *
 * v0.13.0 forcing function for the exit-code class.
 *
 * Bare `process.exit(N)` for non-zero N in the dispatch surface
 * (bin/exceptd.js + orchestrator/index.js) is the source of the truncation
 * regression class that bit the project 5+ times across v0.11.x — a verb
 * that writes ok:false to stdout and then calls process.exit(N) terminates
 * the process before Node's async stdout buffer drains, leaving consumers
 * (CI, test harnesses, --json pipes) with truncated output.
 *
 * The canonical idiom is `safeExit(EXIT_CODES.X); return;` from
 * lib/exit-codes.js. This test refuses any new `process.exit(N)` for N>0
 * in the dispatch surface.
 *
 * `process.exit(0)` at top-level success paths (welcome, help, version,
 * path) is allowed — those are synchronous-print-then-exit by design and
 * Node flushes the synchronous stdout buffer before the exit() call.
 *
 * lib/sign.js, lib/verify.js, scripts/*.js are each their own CLI entry
 * point and may use process.exit() directly. They're excluded from this
 * gate.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');

// Dispatch surface — every verb / subverb / orchestrator entry passes
// through one of these. Adding a new dispatch file means adding it here.
const DISPATCH_FILES = [
  'bin/exceptd.js',
  'orchestrator/index.js',
];

// Match `process.exit(N)` where N is a non-zero integer literal.
// Allowed: `process.exit(0)` (top-level success paths), `process.exitCode = N`,
// `safeExit(EXIT_CODES.X)`, and comments mentioning process.exit (preceded
// by `//` or inside `/* */`).
const BAD_EXIT_RE = /(?<![\/\*\.\w])process\.exit\(\s*([1-9]\d*|EXIT_CODES\.[A-Z_]+|EXIT_CODES\[)/;

function scanFile(rel) {
  const text = fs.readFileSync(path.join(ROOT, rel), 'utf8');
  const lines = text.split('\n');
  const hits = [];
  let inBlockComment = false;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    // Cheap block-comment tracker; not bulletproof for nested cases.
    if (inBlockComment) {
      if (line.includes('*/')) inBlockComment = false;
      continue;
    }
    if (line.match(/^\s*\/\*/) && !line.includes('*/')) {
      inBlockComment = true;
      continue;
    }
    // Skip lines that are entirely line-comments.
    if (line.match(/^\s*\/\//)) continue;
    // Skip lines where process.exit appears only inside a string literal
    // or backtick template — heuristic: check whether it's between quotes
    // before-and-after.
    const m = line.match(BAD_EXIT_RE);
    if (!m) continue;
    // Conservative skip: if the line is clearly a string-literal
    // describing the pattern (e.g. inside an error message), skip when
    // the match is wrapped in quotes.
    const idx = line.indexOf('process.exit(');
    const before = line.slice(0, idx);
    const quotesBefore = (before.match(/['"`]/g) || []).length;
    if (quotesBefore % 2 === 1) continue;
    hits.push(`${rel}:${i + 1} — ${line.trim().slice(0, 120)}`);
  }
  return hits;
}

test('dispatch surface uses safeExit() instead of process.exit(N) for non-zero codes', () => {
  const violations = [];
  for (const rel of DISPATCH_FILES) violations.push(...scanFile(rel));
  assert.equal(violations.length, 0,
    `Dispatch surface must use safeExit(EXIT_CODES.X) / process.exitCode + return for non-zero exits (process.exit(0) at top-level success paths is fine):\n  ${violations.join('\n  ')}`);
});

test('lib/exit-codes.js exports safeExit', () => {
  const mod = require('../lib/exit-codes.js');
  assert.equal(typeof mod.safeExit, 'function', 'safeExit must be exported');
  assert.equal(typeof mod.EXIT_CODES, 'object');
  // Smoke test: safeExit sets exitCode without throwing or terminating.
  const prior = process.exitCode;
  process.exitCode = 0;
  mod.safeExit(mod.EXIT_CODES.GENERIC_FAILURE);
  assert.equal(process.exitCode, 1, 'safeExit must set process.exitCode');
  // Restore to avoid polluting the rest of the suite — and confirm the
  // contract that an already-set non-zero code is not overwritten.
  mod.safeExit(mod.EXIT_CODES.SUCCESS);
  assert.equal(process.exitCode, 1, 'safeExit must not clobber a non-zero exitCode set earlier');
  process.exitCode = prior;
});
