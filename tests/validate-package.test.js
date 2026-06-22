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

test("gate 13: validate-package.js fires when a files-allowlist entry is missing on disk", () => {
  const tmp = mktmp("package");
  try {
    // Stage a tempdir publish layout. package.json's files[] declares
    // LICENSE, but we deliberately do NOT create LICENSE on disk —
    // validate-package.js's `npm pack --dry-run` returns the actual
    // tarball file list, which will not include LICENSE; the
    // REQUIRED_PATHS check then fires.
    const pkg = {
      name: "@blamejs/predeploy-gate-test-fixture",
      version: "0.0.0",
      description: "tempdir package layout for predeploy gate 13 meta-test",
      license: "Apache-2.0",
      bin: { exceptd: "bin/exceptd.js" },
      files: [
        "bin/",
        "lib/",
        "data/_indexes/",
        "keys/public.pem",
        "manifest.json",
        "manifest-snapshot.json",
        "sbom.cdx.json",
        "AGENTS.md",
        "README.md",
        // LICENSE omitted from files[] AND from disk — both reasons
        // mean it cannot appear in the npm-pack file list, so the
        // REQUIRED_PATHS check at line 122 of lib/validate-package.js
        // fires for "LICENSE".
      ],
      publishConfig: { access: "public" },
    };
    writeFile(tmp, "package.json", JSON.stringify(pkg, null, 2));
    // Minimum-viable bin shebang so the shebang check on
    // line 110 of validate-package.js does not also fire and confuse the
    // failure-class assertion below.
    writeFile(tmp, "bin/exceptd.js", "#!/usr/bin/env node\n");
    // Everything else the REQUIRED_PATHS list mentions, EXCEPT LICENSE:
    writeFile(tmp, "lib/refresh-external.js", "module.exports = {};\n");
    writeFile(tmp, "lib/job-queue.js", "module.exports = {};\n");
    writeFile(tmp, "lib/prefetch.js", "module.exports = {};\n");
    writeFile(tmp, "lib/worker-pool.js", "module.exports = {};\n");
    writeFile(tmp, "lib/verify.js", "module.exports = {};\n");
    writeFile(tmp, "vendor/blamejs/retry.js", "module.exports = {};\n");
    writeFile(tmp, "vendor/blamejs/worker-pool.js", "module.exports = {};\n");
    writeFile(tmp, "vendor/blamejs/_PROVENANCE.json", "{}");
    writeFile(tmp, "vendor/blamejs/LICENSE", "Apache-2.0\n");
    writeFile(tmp, "data/_indexes/_meta.json", "{}");
    writeFile(tmp, "keys/public.pem", "PEM\n");
    writeFile(tmp, "manifest.json", "{}");
    writeFile(tmp, "manifest-snapshot.json", "{}");
    writeFile(tmp, "sbom.cdx.json", '{"bomFormat":"CycloneDX","specVersion":"1.6"}');
    writeFile(tmp, "AGENTS.md", "tmp\n");
    writeFile(tmp, "NOTICE", "tmp\n");
    writeFile(tmp, "README.md", "tmp\n");
    // NOTE: LICENSE deliberately NOT written and NOT in files[] above.

    copyFile(
      path.join(ROOT, "lib", "validate-package.js"),
      path.join(tmp, "lib", "validate-package.js")
    );
    copyExitCodes(tmp);

    const r = spawnSync(
      process.execPath,
      [path.join(tmp, "lib", "validate-package.js")],
      { cwd: tmp, encoding: "utf8" }
    );
    // Exit-1 path: line 157 ("process.exit(1)") after the issues list.
    // The expected issue line is built at line 124:
    // "required file missing from publish tarball: LICENSE".
    assert.equal(
      r.status,
      1,
      `validate-package.js must exit 1 when a files-allowlist entry is absent.\nstdout: ${r.stdout}\nstderr: ${r.stderr}`
    );
    assert.match(
      r.stderr,
      /required file missing from publish tarball: LICENSE/,
      `validate-package.js should name the missing path. stderr: ${r.stderr}`
    );
  } finally {
    rmrf(tmp);
  }
});

test("gate 13b: validate-package.js fires when npm pack output omits a numeric size (size budget must not fail open)", () => {
  // The size-budget gate previously only ran the comparison when
  // `typeof packInfo.size === "number"` — so an npm-pack output shape that
  // OMITS or non-numbers the `size` field silently skipped the budget check
  // entirely (the absent-field-fails-open class). A bloated tarball whose
  // pack output dropped `size` would then sail through. The fix pushes an
  // explicit issue when size is non-numeric so the gate fails loudly.
  //
  // To force a size-less pack output deterministically and offline, a fake
  // `npm` shim is placed first on PATH. It emits a faithful pack JSON shape
  // (every REQUIRED_PATHS entry present, no forbidden files) so the ONLY
  // failing condition is the absent `size` — isolating the guard under test.
  const tmp = mktmp("package-nosize");
  try {
    const pkg = {
      name: "@blamejs/predeploy-gate-test-fixture",
      version: "0.0.0",
      description: "tempdir package layout for predeploy gate 13b meta-test",
      license: "Apache-2.0",
      bin: { exceptd: "bin/exceptd.js" },
      files: ["bin/", "lib/", "data/_indexes/", "keys/public.pem"],
      publishConfig: { access: "public" },
    };
    writeFile(tmp, "package.json", JSON.stringify(pkg, null, 2));
    writeFile(tmp, "bin/exceptd.js", "#!/usr/bin/env node\n");

    // Resolve REQUIRED_PATHS from the module under test so the shim's file
    // list always satisfies the present-files check regardless of future
    // REQUIRED_PATHS edits.
    const { REQUIRED_PATHS } = require(path.join(ROOT, "lib", "validate-package.js"));
    // pack JSON with files[] = every required path, unpackedSize present, but
    // NO `size` key at all.
    const packJson = JSON.stringify([
      {
        name: pkg.name,
        version: pkg.version,
        unpackedSize: 1234,
        files: REQUIRED_PATHS.map((p) => ({ path: p, size: 1 })),
      },
    ]);

    // Cross-platform npm shim: npm.cmd for Windows shell:true, npm (sh) for
    // POSIX. The script invokes spawnSync("npm", ...) which resolves via PATH.
    const shimDir = path.join(tmp, "shim");
    fs.mkdirSync(shimDir, { recursive: true });
    const b64 = Buffer.from(packJson, "utf8").toString("base64");
    fs.writeFileSync(
      path.join(shimDir, "npm.cmd"),
      `@echo off\r\nnode -e "process.stdout.write(Buffer.from('${b64}','base64').toString('utf8'))"\r\n`
    );
    const sh = path.join(shimDir, "npm");
    fs.writeFileSync(
      sh,
      `#!/bin/sh\nnode -e "process.stdout.write(Buffer.from('${b64}','base64').toString('utf8'))"\n`
    );
    try { fs.chmodSync(sh, 0o755); } catch (_) { /* Windows: no-op */ }

    copyFile(
      path.join(ROOT, "lib", "validate-package.js"),
      path.join(tmp, "lib", "validate-package.js")
    );
    copyExitCodes(tmp);

    const env = Object.assign({}, process.env, {
      PATH: shimDir + path.delimiter + process.env.PATH,
      Path: shimDir + path.delimiter + (process.env.Path || process.env.PATH || ""),
    });
    const r = spawnSync(
      process.execPath,
      [path.join(tmp, "lib", "validate-package.js")],
      { cwd: tmp, encoding: "utf8", env }
    );
    // Without the fix: size check is skipped, every required file is present,
    // no forbidden files → exit 0 (gate fails open). With the fix: the
    // non-numeric-size issue is pushed → exit 1.
    assert.equal(
      r.status,
      1,
      `validate-package.js must exit 1 when npm pack output omits a numeric size.\nstdout: ${r.stdout}\nstderr: ${r.stderr}`
    );
    assert.match(
      r.stderr,
      /npm pack output missing numeric size — cannot enforce size budget/,
      `validate-package.js should name the missing-size class. stderr: ${r.stderr}`
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
