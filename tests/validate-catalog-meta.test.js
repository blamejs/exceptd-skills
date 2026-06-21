'use strict';
/**
 * tests/validate-catalog-meta.test.js
 *
 * Unit + CLI coverage for lib/validate-catalog-meta.js:
 *   - validateMeta() honors the caller's requested result shape (bare string[]
 *     vs {errors,warnings}) on the missing-_meta early path, and the CLI loop
 *     continues past a no-_meta file rather than crashing.
 *   - The freshness gate fails closed on a malformed/impossible last_updated
 *     (error under --strict, warning by default) while a valid-but-old date
 *     still reports stale and a fresh date is clean.
 *   - parseIsoDateStrict rejects impossible dates and accepts real ones.
 *
 * CLI-level cases use a copied-into-tempdir mini-repo (validator + exit-codes
 * + the data it reads) so the real on-disk catalogs are never mutated.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const { spawnSync } = require('node:child_process');

const ROOT = path.join(__dirname, '..');

const catalogMeta = require(path.join(ROOT, 'lib', 'validate-catalog-meta.js'));

const { validateMeta, parseIsoDateStrict } = catalogMeta;

// --- tempdir mini-repo helpers ---------------------------------------------

function mkTmp(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

function writeJson(p, obj) {
  fs.mkdirSync(path.dirname(p), { recursive: true });
  // String content for the literal-null case is passed through verbatim.
  fs.writeFileSync(p, typeof obj === 'string' ? obj : JSON.stringify(obj));
}

function copyInto(dst, relPath) {
  const target = path.join(dst, relPath);
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.copyFileSync(path.join(ROOT, relPath), target);
}

function runNode(scriptPath, args) {
  return spawnSync(process.execPath, [scriptPath, ...args], { encoding: 'utf8' });
}

// ===========================================================================
// #17 — validate-catalog-meta missing-_meta early return honors both contracts
// ===========================================================================

test('#17 validateMeta(includeWarnings) on a no-_meta file returns {errors,warnings}, not a bare array', () => {
  const tmp = mkTmp('hfd17-direct-');
  try {
    const p = path.join(tmp, 'no-meta.json');
    writeJson(p, { some: 'data' });
    const r = validateMeta(p, { includeWarnings: true, strict: true });
    // Pre-fix this was a bare ['missing _meta block'] — r.errors was undefined.
    assert.equal(typeof r, 'object');
    assert.ok(Array.isArray(r.errors), 'r.errors must be an array under includeWarnings');
    assert.ok(Array.isArray(r.warnings), 'r.warnings must be an array under includeWarnings');
    assert.equal(r.errors.length, 1);
    assert.equal(r.errors[0], 'missing _meta block');
    assert.equal(r.warnings.length, 0);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test('#17 validateMeta() with no opts still returns a non-empty string[] for a no-_meta file', () => {
  const tmp = mkTmp('hfd17-noopts-');
  try {
    const p = path.join(tmp, 'no-meta.json');
    writeJson(p, { some: 'data' });
    const r = validateMeta(p, {});
    assert.ok(Array.isArray(r));
    assert.equal(r.length, 1);
    assert.equal(r[0], 'missing _meta block');
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test('#17 CLI: a no-_meta file sorted BEFORE a second invalid file FAILs cleanly and the loop continues', () => {
  const tmp = mkTmp('hfd17-cli-');
  try {
    copyInto(tmp, path.join('lib', 'validate-catalog-meta.js'));
    copyInto(tmp, path.join('lib', 'exit-codes.js'));
    // aaa.json lacks _meta (sorts first); zzz.json has a _meta block that fails
    // a downstream check (bad tlp) — its FAIL line appearing proves the loop did
    // not abort after the first file.
    writeJson(path.join(tmp, 'data', 'aaa.json'), { some: 'data' });
    writeJson(path.join(tmp, 'data', 'zzz.json'), { _meta: { tlp: 'BOGUS' } });

    const r = runNode(path.join(tmp, 'lib', 'validate-catalog-meta.js'), ['--strict']);
    // Exact exit code.
    assert.equal(r.status, 1);
    // No stack trace masking the failure (the pre-fix crash printed a TypeError
    // to stderr and produced empty stdout).
    assert.equal(r.stderr, '');
    assert.doesNotMatch(r.stdout, /TypeError|Cannot read properties of undefined/);
    assert.doesNotMatch(r.stderr, /TypeError|Cannot read properties of undefined/);
    // First file reported the clean failure...
    assert.match(r.stdout, /FAIL {2}aaa\.json/);
    assert.match(r.stdout, /missing _meta block/);
    // ...AND the loop continued to the second file (the load-bearing assertion).
    assert.match(r.stdout, /FAIL {2}zzz\.json/);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

// ===========================================================================
// #19 — freshness gate fails closed on a malformed last_updated
// ===========================================================================

function freshMeta(lastUpdated) {
  return {
    _meta: {
      tlp: 'CLEAR',
      source_confidence: { scheme: 'Admiralty', default: 'B2', note: 'curated catalog' },
      freshness_policy: {
        default_review_cadence_days: 30,
        stale_after_days: 90,
        rebuild_after_days: 180,
        note: 'review cadence for this catalog',
        ...(lastUpdated !== undefined ? {} : {}),
      },
      last_updated: lastUpdated,
    },
  };
}

function validateMetaObj(metaObj, opts) {
  // validateMeta reads from disk; stage a one-off file so we exercise the real
  // code path (including the JSON parse) without touching the repo tree.
  const tmp = mkTmp('hfd19-');
  try {
    const p = path.join(tmp, 'catalog.json');
    writeJson(p, metaObj);
    return validateMeta(p, opts);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
}

for (const bad of ['2026-13-99', '2026-04-31', 'unknown', 'soon', '2026/01/01', 123]) {
  test(`#19 malformed last_updated ${JSON.stringify(bad)} is an ERROR under --strict (was silently skipped)`, () => {
    const r = validateMetaObj(freshMeta(bad), { includeWarnings: true, strict: true });
    const hit = r.errors.filter((e) => /last_updated.*not a valid ISO date/.test(e));
    assert.equal(hit.length, 1, `expected exactly one date-validity error, got: ${JSON.stringify(r.errors)}`);
    // It must NOT have also produced a staleness finding for the same field.
    assert.equal(r.errors.filter((e) => /freshness:.*days old/.test(e)).length, 0);
  });

  test(`#19 malformed last_updated ${JSON.stringify(bad)} is a WARNING in default mode (observable, not silent)`, () => {
    const r = validateMetaObj(freshMeta(bad), { includeWarnings: true });
    assert.equal(r.errors.length, 0, `default mode must not error: ${JSON.stringify(r.errors)}`);
    const hit = r.warnings.filter((w) => /last_updated.*not a valid ISO date/.test(w));
    assert.equal(hit.length, 1, `expected exactly one date-validity warning, got: ${JSON.stringify(r.warnings)}`);
  });
}

test('#19 a valid-but-old last_updated still reports STALE (fix does not suppress real staleness)', () => {
  const r = validateMetaObj(freshMeta('1900-01-01'), { includeWarnings: true, strict: true });
  // The old date is a real calendar date, so it must reach the staleness branch,
  // NOT the date-validity branch.
  assert.equal(r.errors.filter((e) => /last_updated.*not a valid ISO date/.test(e)).length, 0);
  const stale = r.errors.filter((e) => /freshness:.*days old/.test(e));
  assert.equal(stale.length, 1, `expected the stale finding, got: ${JSON.stringify(r.errors)}`);
});

test('#19 a fresh (today) last_updated produces neither a validity nor a staleness finding', () => {
  const today = new Date().toISOString().slice(0, 10);
  const r = validateMetaObj(freshMeta(today), { includeWarnings: true, strict: true });
  assert.equal(r.errors.length, 0, `expected clean, got: ${JSON.stringify(r.errors)}`);
  assert.equal(r.warnings.length, 0, `expected clean, got: ${JSON.stringify(r.warnings)}`);
});

test('#19 parseIsoDateStrict rejects impossible dates and accepts real ones (no year floor)', () => {
  assert.equal(parseIsoDateStrict('2026-13-99'), null);
  assert.equal(parseIsoDateStrict('2026-04-31'), null);
  assert.equal(parseIsoDateStrict('2025-02-29'), null); // non-leap-year Feb 29
  assert.equal(parseIsoDateStrict('unknown'), null);
  assert.equal(parseIsoDateStrict('2026/01/01'), null);
  assert.equal(parseIsoDateStrict(123), null);
  assert.equal(parseIsoDateStrict(null), null);
  // Real dates round-trip; deliberately NO 1990 floor so old dates stay valid.
  assert.ok(parseIsoDateStrict('1900-01-01') instanceof Date);
  assert.ok(parseIsoDateStrict('2024-02-29') instanceof Date); // valid leap day
  assert.equal(parseIsoDateStrict('2024-01-15').getUTCFullYear(), 2024);
});
