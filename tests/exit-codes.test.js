"use strict";


// ---- routed from orchestrator-watch-exit ----
;(() => {
/**
 * `exceptd watch` exits with the sysexits EX_TEMPFAIL code (75) when the watch
 * lock is already held. The orchestrator reads this from the canonical
 * exit-code table when it carries a WATCH_LOCK_CONTENTION constant and falls
 * back to the literal otherwise, so the value stays stable either way.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const ROOT = path.join(__dirname, '..');
const ORCH = path.join(ROOT, 'orchestrator', 'index.js');

test('watch refuses with exit 75 when the lock is held by a live PID', () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'orch-watch-exit-'));
  try {
    // Forge a lockfile pointing at this (alive) process so the second watcher
    // sees contention and refuses immediately.
    const lockPath = path.join(home, 'watch.lock');
    fs.writeFileSync(lockPath, JSON.stringify({ pid: process.pid, started_at: new Date().toISOString() }));

    const r = spawnSync(process.execPath, [ORCH, 'watch'], {
      encoding: 'utf8',
      timeout: 8000,
      env: {
        ...process.env,
        EXCEPTD_HOME: home,
        EXCEPTD_SUPPRESS_DEPRECATION: '1',
      },
    });

    assert.equal(r.status, 75, `expected EX_TEMPFAIL exit 75; got ${r.status} stderr=${r.stderr}`);
    assert.match(r.stderr, /cannot start watch/);
  } finally {
    fs.rmSync(home, { recursive: true, force: true });
  }
});

test('exit-code table either omits 75 (literal fallback) or documents it consistently', () => {
  // Guard against a future divergence: if the canonical table grows a
  // WATCH_LOCK_CONTENTION constant, it must equal the literal the watch path
  // still falls back to.
  const { EXIT_CODES } = require('../lib/exit-codes');
  if (Object.prototype.hasOwnProperty.call(EXIT_CODES, 'WATCH_LOCK_CONTENTION')) {
    assert.equal(EXIT_CODES.WATCH_LOCK_CONTENTION, 75, 'canonical constant must match the watch exit literal');
  } else {
    assert.equal(EXIT_CODES.WATCH_LOCK_CONTENTION, undefined);
  }
});
})();


// ---- routed from safe-exit-grep ----
;(() => {
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
})();
