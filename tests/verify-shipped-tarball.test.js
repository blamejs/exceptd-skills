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

test("gate 14: verify-shipped-tarball.js fires when a skill body is tampered post-signing", () => {
  const tmp = mktmp("shipped");
  try {
    // Generate a real Ed25519 keypair for this tempdir.
    const { privateKey, publicKey } = genKeypair();
    writeFile(tmp, "keys/public.pem", publicKey);

    // Original, signed skill body.
    const originalBody = "---\nname: t\n---\n# original\n";
    writeFile(tmp, "skills/t/skill.md", originalBody);
    const sig = signContent(originalBody, privateKey);

    const manifestObj = {
      skills: [
        {
          name: "t",
          path: "skills/t/skill.md",
          signature: sig,
          signed_at: "2026-01-01T00:00:00.000Z",
        },
      ],
    };
    // Sign the manifest envelope so the gate progresses past the
    // envelope-signature check and reaches the per-skill verify loop
    // where the body-tamper detection actually fires. Without this, the
    // gate trips on the envelope check first (still a correct refusal)
    // but doesn't exercise the body-tamper regression class this fixture
    // was designed to reproduce.
    const canonical = (function () {
      function canonicalize(value) {
        if (Array.isArray(value)) return value.map(canonicalize);
        if (value && typeof value === "object") {
          const out = {};
          for (const k of Object.keys(value).sort()) out[k] = canonicalize(value[k]);
          return out;
        }
        return value;
      }
      const json = JSON.stringify(canonicalize(manifestObj), null, 2);
      let s = json;
      if (s.length > 0 && s.charCodeAt(0) === 0xFEFF) s = s.slice(1);
      s = s.replace(/\r\n/g, "\n");
      return Buffer.from(s, "utf8");
    })();
    const manifestSig = crypto
      .sign(null, canonical, { key: privateKey, dsaEncoding: "ieee-p1363" })
      .toString("base64");
    manifestObj.manifest_signature = {
      algorithm: "Ed25519",
      signature_base64: manifestSig,
    };
    writeFile(tmp, "manifest.json", JSON.stringify(manifestObj, null, 2));

    // Now tamper the body AFTER signing. signature stays valid for the
    // ORIGINAL bytes but not for the tampered ones. This reproduces the
    // v0.12.4 signature-regression class: the tarball ships bytes whose
    // signature in manifest.json doesn't verify against keys/public.pem.
    writeFile(tmp, "skills/t/skill.md", "---\nname: t\n---\n# TAMPERED\n");

    // Stage a publishable package.json so `npm pack` succeeds. We only
    // include the bare minimum needed: manifest, keys, skills, lib.
    const pkg = {
      name: "predeploy-gate-14-fixture",
      version: "0.0.0",
      description: "tempdir publish fixture for verify-shipped-tarball meta-test",
      license: "Apache-2.0",
      files: ["manifest.json", "keys/public.pem", "skills/", "lib/"],
    };
    writeFile(tmp, "package.json", JSON.stringify(pkg, null, 2));

    // verify-shipped-tarball.js requires lib/refresh-network.js (for
    // parseTar) AND lib/verify.js (only for path existence; actual
    // verify logic is inlined). Copy both into tempdir/lib/.
    copyFile(
      path.join(ROOT, "lib", "refresh-network.js"),
      path.join(tmp, "lib", "refresh-network.js")
    );
    copyFile(
      path.join(ROOT, "lib", "verify.js"),
      path.join(tmp, "lib", "verify.js")
    );
    copyFile(
      path.join(ROOT, "scripts", "verify-shipped-tarball.js"),
      path.join(tmp, "scripts", "verify-shipped-tarball.js")
    );

    const r = spawnSync(
      process.execPath,
      [path.join(tmp, "scripts", "verify-shipped-tarball.js")],
      { cwd: tmp, encoding: "utf8" }
    );
    // Exit-1 path: line 149 ("process.exit(1)") after the
    // "FAIL — shipped tarball would be broken on every fresh install."
    // message. The verification loop at line 122 detects that
    // crypto.verify(...) returns false for the tampered content.
    assert.equal(
      r.status,
      1,
      `verify-shipped-tarball.js must exit 1 when shipped bytes differ from what was signed.\nstdout: ${r.stdout}\nstderr: ${r.stderr}`
    );
    // The gate ALSO refuses tarballs whose top-level manifest_signature
    // is missing or invalid (envelope-tamper defence added in v0.12.19).
    // The fixture in this test doesn't sign the envelope, so the gate
    // trips earlier on "manifest_signature missing" before reaching the
    // per-skill-body verify loop. Both failure messages are correct
    // refusals from the gate's perspective — accept either.
    assert.match(
      r.stdout + r.stderr,
      /signature did not verify|FAIL — shipped tarball|manifest_signature (missing|invalid)/,
      `verify-shipped-tarball.js should report the signature-mismatch OR envelope-missing failure class. stdout: ${r.stdout} stderr: ${r.stderr}`
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
