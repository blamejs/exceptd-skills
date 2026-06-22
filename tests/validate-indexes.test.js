"use strict";


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

test("Audit G F1: validate-indexes.js rejects an empty source_hashes table", () => {
  const tmp = mktmp("indexes-empty");
  try {
    writeFile(
      tmp,
      "manifest.json",
      JSON.stringify({ skills: [] })
    );
    writeFile(
      tmp,
      "data/_indexes/_meta.json",
      JSON.stringify({
        generated_at: "2026-01-01T00:00:00.000Z",
        source_hashes: {}, // empty — must be rejected
      })
    );
    copyFile(
      path.join(ROOT, "lib", "validate-indexes.js"),
      path.join(tmp, "lib", "validate-indexes.js")
    );
    const r = spawnSync(
      process.execPath,
      [path.join(tmp, "lib", "validate-indexes.js")],
      { cwd: tmp, encoding: "utf8" }
    );
    assert.equal(
      r.status,
      1,
      `validate-indexes.js must exit 1 on empty source_hashes table.\nstdout: ${r.stdout}\nstderr: ${r.stderr}`
    );
    assert.match(
      r.stderr,
      /source_hashes is empty/i,
      `validate-indexes.js should label the empty-table error. stderr: ${r.stderr}`
    );
  } finally {
    rmrf(tmp);
  }
});

test("gate 11: validate-indexes.js fires on a hash mismatch in data/_indexes/_meta.json", () => {
  const tmp = mktmp("indexes");
  try {
    // Stage a manifest with one skill plus one data catalog, then write
    // an _indexes/_meta.json that records the WRONG hash for the catalog.
    // validate-indexes.js re-hashes every source and exits 1 on drift.
    const manifestObj = {
      skills: [{ name: "t", path: "skills/t/skill.md" }],
    };
    const manifestStr = JSON.stringify(manifestObj, null, 2);
    const skillStr = "---\nname: t\n---\nbody\n";
    const catalogStr = '{"_note": "tempdir catalog for gate 11 test"}\n';
    writeFile(tmp, "manifest.json", manifestStr);
    writeFile(tmp, "skills/t/skill.md", skillStr);
    writeFile(tmp, "data/example.json", catalogStr);

    function sha256(s) {
      return crypto.createHash("sha256").update(s).digest("hex");
    }
    // Record the right hash for manifest + skill, but a deliberately-wrong
    // hash for the catalog. The drift branch (line 64 of
    // lib/validate-indexes.js: "if (live !== recorded[p])") fires.
    writeFile(
      tmp,
      "data/_indexes/_meta.json",
      JSON.stringify({
        generated_at: "2026-01-01T00:00:00.000Z",
        source_hashes: {
          "manifest.json": sha256(manifestStr),
          "skills/t/skill.md": sha256(skillStr),
          "data/example.json": "0".repeat(64), // wrong on purpose
        },
      })
    );
    // The script also looks at every .json in data/. Above we created
    // data/example.json — _indexes/_meta.json itself is NOT in data/
    // root (it's in data/_indexes/), so the readdirSync filter only sees
    // example.json. Good.
    copyFile(
      path.join(ROOT, "lib", "validate-indexes.js"),
      path.join(tmp, "lib", "validate-indexes.js")
    );

    const r = spawnSync(
      process.execPath,
      [path.join(tmp, "lib", "validate-indexes.js")],
      { cwd: tmp, encoding: "utf8" }
    );
    // Exit-1 path: line 83 ("process.exit(1)") after the
    // "[validate-indexes] indexes STALE:" header.
    assert.equal(
      r.status,
      1,
      `validate-indexes.js must exit 1 on a recorded-hash mismatch.\nstdout: ${r.stdout}\nstderr: ${r.stderr}`
    );
    assert.match(
      r.stderr,
      /hash drift|indexes STALE/i,
      `validate-indexes.js should label the drift class. stderr: ${r.stderr}`
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


// ---- routed from readme-tracked-index-source ----
require("node:test").describe("readme-tracked-index-source", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
/**
 * Regression: README.md is consumed by the stale-content index builder
 * (badge-count drift check), so it must be a hashed source in _meta.json —
 * otherwise a README edit is invisible to the --changed planner and the
 * validate-indexes freshness gate, breaking the "every consumed source is
 * hashed" invariant.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const ROOT = path.join(__dirname, '..');
const META = JSON.parse(fs.readFileSync(path.join(ROOT, 'data', '_indexes', '_meta.json'), 'utf8'));

test('README.md is a tracked/hashed index source', () => {
  assert.ok(META.source_hashes && typeof META.source_hashes === 'object', '_meta.source_hashes must exist');
  assert.equal(
    Object.prototype.hasOwnProperty.call(META.source_hashes, 'README.md'),
    true,
    'README.md must be hashed in _meta.source_hashes (the stale-content builder consumes it)'
  );
  assert.equal(typeof META.source_hashes['README.md'], 'string');
});

test('validate-indexes accepts README.md as a hashed source (does not flag it removed)', () => {
  // build-indexes and validate-indexes maintain parallel source-set
  // definitions; both must include README or the validator reports the hashed
  // README as a "removed file" and the freshness gate fails.
  const r = spawnSync(process.execPath, [path.join(ROOT, 'lib', 'validate-indexes.js')], { encoding: 'utf8' });
  assert.equal(r.status, 0,
    `validate-indexes must pass with README hashed; stdout:\n${r.stdout}\nstderr:\n${r.stderr}`);
  assert.equal(/README\.md/.test(r.stderr || '') && /removed|stale source/.test(r.stderr || ''), false,
    'validate-indexes must not report README.md as a removed/stale source');
});
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});
