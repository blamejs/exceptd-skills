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


// ---- routed from predeploy-gates ----
require("node:test").describe("predeploy-gates", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
/**
 * tests/predeploy-gates.test.js
 *
 * Meta-tests for the predeploy gate runners. The pre-existing
 * tests/predeploy.test.js asserts the GATES list maps to ci.yml job
 * names — it does not exercise the gates themselves. This file fills
 * that gap: for each gate that ships a script under lib/ or scripts/,
 * stage a known-bad state in a per-test tempdir and assert the gate
 * actually fires (non-zero exit OR an error-shape return).
 *
 * Why these specific gates: tests/predeploy.test.js only checks the
 * mapping. Other tests cover the data the gates consume but not the
 * gate runners themselves. This file is the regression-prevention layer
 * for the gate runners — when a gate's "bad state" detection regresses
 * (the false-negative class that shipped invisible signature drift in
 * v0.11.x — v0.12.2), one of these tests fires.
 *
 * Isolation model:
 *
 *   - Every test mkdtempSync's its own working tree under os.tmpdir().
 *   - Every test copies the script-under-test (and its strict
 *     dependencies) into <tempdir>/lib/ or <tempdir>/scripts/ so the
 *     script's __dirname anchor resolves to <tempdir>/lib (or
 *     <tempdir>/scripts), and __dirname/.. resolves to <tempdir>.
 *   - No test mutates the real repo ROOT. ROOT is read-only; tempdirs
 *     are the only writable surface.
 *   - Tempdirs are removed in a try/finally even when assertions fail
 *     so a CI run that ends with N failing tests still leaves /tmp clean.
 *
 * No --dir / --root flag was added to any existing script as part of
 * this work — every gate is testable via the cwd + __dirname anchor
 * pattern, except scripts/check-sbom-currency.js which already accepted
 * --root (it was extracted out of an inline `node -e` block in
 * scripts/predeploy.js during this same change; the extracted script
 * is the gate-10 runner going forward).
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const os = require("node:os");
const crypto = require("node:crypto");
const { spawnSync } = require("node:child_process");

const ROOT = path.join(__dirname, "..");

// ---------- tempdir helpers ----------

function mktmp(label) {
  return fs.mkdtempSync(path.join(os.tmpdir(), "predeploy-gate-" + label + "-"));
}

function rmrf(dir) {
  try {
    fs.rmSync(dir, { recursive: true, force: true });
  } catch (_) {
    /* best effort — Windows file locks may keep a handle briefly */
  }
}

function writeFile(dir, rel, content) {
  const abs = path.join(dir, rel);
  fs.mkdirSync(path.dirname(abs), { recursive: true });
  fs.writeFileSync(abs, content);
}

function copyFile(srcAbs, dstAbs) {
  fs.mkdirSync(path.dirname(dstAbs), { recursive: true });
  fs.copyFileSync(srcAbs, dstAbs);
}

// Every staged lib validator now requires lib/exit-codes.js (for safeExit);
// stage it alongside so the mirrored script doesn't crash on require (which
// would yield empty stdout and a confusing content-assertion failure).
function copyExitCodes(tmp) {
  copyFile(path.join(ROOT, "lib", "exit-codes.js"), path.join(tmp, "lib", "exit-codes.js"));
}

// Generate an Ed25519 keypair in PEM form, matching lib/verify.js conventions.
function genKeypair() {
  return crypto.generateKeyPairSync("ed25519", {
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
    publicKeyEncoding: { type: "spki", format: "pem" },
  });
}

function signContent(content, privateKeyPem) {
  return crypto
    .sign(null, Buffer.from(content, "utf8"), {
      key: privateKeyPem,
      dsaEncoding: "ieee-p1363",
    })
    .toString("base64");
}

// ---------- Gate 1: Verify skill signatures (Ed25519) ----------


// ---------- Gate 7: Lint skill files ----------


// ---------- Gate 9: validate-catalog-meta ----------


// ---------- Audit G F2: SBOM gate catches renamed skill ----------



// ---------- Audit G F1: validate-indexes rejects empty source_hashes ----------


// ---------- Gate 10: SBOM currency ----------


// ---------- Gate 11: validate-indexes ----------


// ---------- Gate 12: validate-vendor ----------







// ---------- Gate 13: validate-package ----------


// ---------- Gate 14: verify-shipped-tarball ----------
//
// This is the gate that closed v0.12.4's signature regression. The bug
// class: lib/verify.js against the SOURCE tree passes 38/38, but a fresh
// `npm install` against the SHIPPED tarball produces 0/38. The cause is
// keys/public.pem being swapped between sign and pack (the test that
// did it lived in `tests/operator-bugs.test.js` and synchronously
// regenerated keys mid-suite — see the common-pitfalls list).
//
// The simulated regression here: sign the skill against PRIVATE_KEY_A
// (the original ceremony), then post-sign tamper the skill body but
// leave the signature unchanged. After `npm pack`, the extracted tarball
// will have the tampered body + the original signature, and the gate
// must fail.

test("gate 9: validate-catalog-meta.js fires on a catalog missing _meta.tlp", () => {
  const tmp = mktmp("cat-meta");
  try {
    // validateMeta(catalogPath) is exported. Test the function directly —
    // it ignores REPO_ROOT for the actual validation work; REPO_ROOT only
    // anchors directory walking in main().
    const { validateMeta } = require(path.join(
      ROOT,
      "lib",
      "validate-catalog-meta.js"
    ));
    // Stage a catalog with tlp deleted entirely. validate-catalog-meta.js
    // line 93 ("if (typeof meta.tlp !== 'string')") raises the failure.
    const badCatalog = {
      _meta: {
        // tlp deliberately omitted — gate 9's primary failure mode.
        source_confidence: {
          scheme: "Admiralty (A-F + 1-6)",
          default: "A1",
          note: "test note",
        },
        freshness_policy: {
          default_review_cadence_days: 30,
          stale_after_days: 60,
          rebuild_after_days: 180,
          note: "test note",
        },
      },
    };
    const catalogPath = path.join(tmp, "bad-catalog.json");
    writeFile(tmp, "bad-catalog.json", JSON.stringify(badCatalog));
    const errors = validateMeta(catalogPath);
    assert.ok(
      errors.length > 0,
      "validateMeta should return at least one error on a catalog missing _meta.tlp"
    );
    assert.ok(
      errors.some((e) => /_meta\.tlp/.test(e)),
      `validateMeta should flag the missing tlp field. errors: ${JSON.stringify(errors)}`
    );

    // Also spawn the CLI against a tempdir layout to assert the exit code
    // is non-zero. validate-catalog-meta.js anchors via __dirname; copy it
    // into <tempdir>/lib/ so the data dir resolves to <tempdir>/data/.
    copyFile(
      path.join(ROOT, "lib", "validate-catalog-meta.js"),
      path.join(tmp, "lib", "validate-catalog-meta.js")
    );
    copyExitCodes(tmp);
    fs.mkdirSync(path.join(tmp, "data"), { recursive: true });
    fs.writeFileSync(
      path.join(tmp, "data", "bad.json"),
      JSON.stringify(badCatalog)
    );
    const r = spawnSync(
      process.execPath,
      [path.join(tmp, "lib", "validate-catalog-meta.js")],
      { cwd: tmp, encoding: "utf8" }
    );
    // Exit-1 path: line 191
    // ("process.exit(failed === 0 ? 0 : 1);")
    assert.equal(
      r.status,
      1,
      `validate-catalog-meta.js must exit 1 on a catalog missing _meta.tlp (failed>0 branch).\nstdout: ${r.stdout}\nstderr: ${r.stderr}`
    );
  } finally {
    rmrf(tmp);
  }
});
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});


// ---- routed from hunt-fix-D-validators ----
require("node:test").describe("hunt-fix-D-validators", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
/**
 * tests/hunt-fix-D-validators.test.js
 *
 * Regression locks for five confirmed validator bugs (cluster D-validators):
 *
 *   #17 validate-catalog-meta: validateMeta returned a bare string[] on the
 *       missing-_meta early path while the includeWarnings caller read
 *       result.errors — main() crashed with an uncaught TypeError on the first
 *       no-_meta file, aborting the whole gate. Now the early return honors the
 *       caller's requested shape and the loop continues to later files.
 *
 *   #18 validate-cve-catalog: additionalChecks dereferenced entry.poc_available
 *       before any null guard — a null catalog entry crashed main(). Guarded at
 *       the top; the malformed-entry FAIL still originates in validate().
 *
 *   #19 validate-catalog-meta: the freshness gate silently SKIPPED when
 *       last_updated was unparseable (fail-open). A malformed/impossible date
 *       is now an error under --strict / warning by default; a valid-but-old
 *       date still reports stale.
 *
 *   #20 validate-playbooks: checkCrossRefs read playbook._meta before any null
 *       guard — a literal-null playbook file crashed main(). Guarded at the top.
 *
 *   #21 validate-playbooks: the air-gap network-source detector missed
 *       API-verb-phrased sources ("GET /... via Graph", "Entra ID", "Okta",
 *       "Microsoft Graph"); broadened so such a source under air_gap_mode with
 *       no air_gap_alternative is flagged at error severity — without
 *       over-firing on the shipped corpus.
 *
 * Each case fails on the pre-fix behavior and passes after. CLI-level cases use
 * a copied-into-tempdir mini-repo (validator + exit-codes + schemas + the data
 * it reads) so the real on-disk catalogs are never mutated.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const { spawnSync } = require('node:child_process');

const ROOT = path.join(__dirname, '..');

const catalogMeta = require(path.join(ROOT, 'lib', 'validate-catalog-meta.js'));
const cveCatalog = require(path.join(ROOT, 'lib', 'validate-cve-catalog.js'));
const playbooksMod = require(path.join(ROOT, 'lib', 'validate-playbooks.js'));

const { validateMeta, parseIsoDateStrict } = catalogMeta;
const { additionalChecks } = cveCatalog;
const { checkCrossRefs, loadContext, loadPlaybooks } = playbooksMod;

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




// ===========================================================================
// #18 — validate-cve-catalog additionalChecks null-entry guard
// ===========================================================================




// ===========================================================================
// #20 — validate-playbooks checkCrossRefs null-playbook guard
// ===========================================================================



// ===========================================================================
// #21 — air-gap network-source detector flags API-verb-phrased sources
// ===========================================================================

function minimalAirGapPlaybook(source, withAlt) {
  // Smallest playbook shape that exercises the air-gap completeness check in
  // checkCrossRefs. It needs a TTP mapping (atlas_refs) to avoid the unrelated
  // TTP-floor error muddying the assertion; we use the live atlas key set.
  const atlasKey = '__will_be_filled__';
  const art = { source };
  if (withAlt) art.air_gap_alternative = 'Local file already staged in cwd; read it directly.';
  return {
    _meta: { id: 'synthetic-airgap', air_gap_mode: true, scope: 'cross-cutting' },
    domain: {},
    phases: { look: { artifacts: [art] } },
    __atlasKey: atlasKey,
  };
}

function airGapFindings(source, withAlt) {
  const ctx = loadContext();
  const ids = new Set(['synthetic-airgap']);
  const pb = minimalAirGapPlaybook(source, withAlt);
  delete pb.__atlasKey;
  return checkCrossRefs(pb, ctx, ids).filter((f) => /air_gap_mode is true and source/.test(f.message));
}

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
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});
