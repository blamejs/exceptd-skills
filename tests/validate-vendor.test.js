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

test("gate 12: validate-vendor.js fires on a vendored file modified outside _PROVENANCE.json", () => {
  const tmp = mktmp("vendor");
  try {
    // Stage a minimal vendored module with the right initial hash, then
    // hand-edit it AFTER computing _PROVENANCE.json — the canonical
    // "silent hand-edit" bug class this gate exists to catch.
    const originalSrc = "module.exports = function ok() { return 1; };\n";
    const licenseText = "Apache-2.0 LICENSE text (vendored)\n";
    function sha256(s) {
      return crypto.createHash("sha256").update(s).digest("hex");
    }
    const prov = {
      license_file: "LICENSE",
      license_sha256: sha256(licenseText),
      pinned_commit: "deadbeef",
      files: {
        "ok.js": {
          vendored_path: "vendor/blamejs/ok.js",
          vendored_sha256: sha256(originalSrc),
          upstream_path: "lib/ok.js",
          upstream_sha256_at_pin: sha256(originalSrc),
        },
      },
    };
    writeFile(tmp, "vendor/blamejs/_PROVENANCE.json", JSON.stringify(prov));
    writeFile(tmp, "vendor/blamejs/LICENSE", licenseText);
    // Drop a tampered copy in place — different bytes than what
    // _PROVENANCE.json hash-pins.
    writeFile(tmp, "vendor/blamejs/ok.js", originalSrc.replace("ok()", "tampered()"));

    copyFile(
      path.join(ROOT, "lib", "validate-vendor.js"),
      path.join(tmp, "lib", "validate-vendor.js")
    );
    copyExitCodes(tmp);

    const r = spawnSync(
      process.execPath,
      [path.join(tmp, "lib", "validate-vendor.js")],
      { cwd: tmp, encoding: "utf8" }
    );
    // Exit-1 path: line 80 ("process.exit(1)") after
    // "[validate-vendor] vendor tree DRIFT:" header. The hash compare
    // happens at line 60 of lib/validate-vendor.js.
    assert.equal(
      r.status,
      1,
      `validate-vendor.js must exit 1 when a vendored file's bytes drift from _PROVENANCE.json.\nstdout: ${r.stdout}\nstderr: ${r.stderr}`
    );
    assert.match(
      r.stderr,
      /vendor tree DRIFT|drift in vendor/i,
      `validate-vendor.js should label the drift class. stderr: ${r.stderr}`
    );
  } finally {
    rmrf(tmp);
  }
});

test("gate 12b: validate-vendor.js fires on an unregistered vendored file (on disk, absent from _PROVENANCE.json)", () => {
  const tmp = mktmp("vendor-unreg");
  try {
    const okSrc = "module.exports = function ok() { return 1; };\n";
    const licenseText = "Apache-2.0 LICENSE text (vendored)\n";
    function sha256(s) { return crypto.createHash("sha256").update(s).digest("hex"); }
    const prov = {
      license_file: "LICENSE",
      license_sha256: sha256(licenseText),
      pinned_commit: "deadbeef",
      files: {
        "ok.js": {
          vendored_path: "vendor/blamejs/ok.js",
          vendored_sha256: sha256(okSrc),
          upstream_path: "lib/ok.js",
          upstream_sha256_at_pin: sha256(okSrc),
        },
      },
    };
    writeFile(tmp, "vendor/blamejs/_PROVENANCE.json", JSON.stringify(prov));
    writeFile(tmp, "vendor/blamejs/LICENSE", licenseText);
    writeFile(tmp, "vendor/blamejs/ok.js", okSrc); // registered, correct hash
    // An unregistered module dropped on disk: present in the tarball + require()-able
    // but absent from _PROVENANCE.json, so nothing verifies its integrity.
    writeFile(tmp, "vendor/blamejs/smuggled.js", "module.exports = function evil() {};\n");
    copyFile(path.join(ROOT, "lib", "validate-vendor.js"), path.join(tmp, "lib", "validate-vendor.js"));
    copyExitCodes(tmp);
    const r = spawnSync(process.execPath, [path.join(tmp, "lib", "validate-vendor.js")], { cwd: tmp, encoding: "utf8" });
    assert.equal(r.status, 1, `validate-vendor must exit 1 on an unregistered vendored file.\nstdout: ${r.stdout}\nstderr: ${r.stderr}`);
    assert.match(r.stderr, /unregistered vendored file: vendor\/blamejs\/smuggled\.js/, `must name the unregistered file. stderr: ${r.stderr}`);
  } finally {
    rmrf(tmp);
  }
});

test("gate 12c: validate-vendor.js fires when license_file is recorded but license_sha256 is absent (LICENSE tampered, hash stripped)", () => {
  const tmp = mktmp("vendor-license-nohash");
  try {
    const okSrc = "module.exports = function ok() { return 1; };\n";
    function sha256(s) { return crypto.createHash("sha256").update(s).digest("hex"); }
    // license_file present, license_sha256 deliberately ABSENT — the
    // fail-open class: the integrity check must NOT skip just because the
    // recorded hash was stripped from the manifest.
    const prov = {
      license_file: "LICENSE",
      pinned_commit: "deadbeef",
      files: {
        "ok.js": {
          vendored_path: "vendor/blamejs/ok.js",
          vendored_sha256: sha256(okSrc),
          upstream_path: "lib/ok.js",
          upstream_sha256_at_pin: sha256(okSrc),
        },
      },
    };
    writeFile(tmp, "vendor/blamejs/_PROVENANCE.json", JSON.stringify(prov));
    // LICENSE bytes are whatever — they cannot be verified without the hash.
    writeFile(tmp, "vendor/blamejs/LICENSE", "TAMPERED license text\n");
    writeFile(tmp, "vendor/blamejs/ok.js", okSrc);
    copyFile(path.join(ROOT, "lib", "validate-vendor.js"), path.join(tmp, "lib", "validate-vendor.js"));
    copyExitCodes(tmp);
    const r = spawnSync(process.execPath, [path.join(tmp, "lib", "validate-vendor.js")], { cwd: tmp, encoding: "utf8" });
    assert.equal(r.status, 1, `validate-vendor must exit 1 when license_file is set but license_sha256 is absent (must not fail open).\nstdout: ${r.stdout}\nstderr: ${r.stderr}`);
    assert.match(r.stderr, /license_file recorded.*without license_sha256.*integrity unverifiable/i, `must name the missing-license-hash class. stderr: ${r.stderr}`);
  } finally {
    rmrf(tmp);
  }
});

test("gate 12d: validate-vendor.js reports a clean issue (not a TypeError crash) when a files[] entry lacks vendored_sha256", () => {
  const tmp = mktmp("vendor-file-nohash");
  try {
    const okSrc = "module.exports = function ok() { return 1; };\n";
    const licenseText = "Apache-2.0 LICENSE text (vendored)\n";
    function sha256(s) { return crypto.createHash("sha256").update(s).digest("hex"); }
    const prov = {
      license_file: "LICENSE",
      license_sha256: sha256(licenseText),
      pinned_commit: "deadbeef",
      files: {
        // vendored_sha256 deliberately ABSENT — formatting the drift message
        // must not crash on `undefined.slice()`.
        "ok.js": {
          vendored_path: "vendor/blamejs/ok.js",
          upstream_path: "lib/ok.js",
          upstream_sha256_at_pin: sha256(okSrc),
        },
      },
    };
    writeFile(tmp, "vendor/blamejs/_PROVENANCE.json", JSON.stringify(prov));
    writeFile(tmp, "vendor/blamejs/LICENSE", licenseText);
    writeFile(tmp, "vendor/blamejs/ok.js", okSrc);
    copyFile(path.join(ROOT, "lib", "validate-vendor.js"), path.join(tmp, "lib", "validate-vendor.js"));
    copyExitCodes(tmp);
    const r = spawnSync(process.execPath, [path.join(tmp, "lib", "validate-vendor.js")], { cwd: tmp, encoding: "utf8" });
    assert.equal(r.status, 1, `validate-vendor must exit 1 when a files[] entry lacks vendored_sha256.\nstdout: ${r.stdout}\nstderr: ${r.stderr}`);
    assert.match(r.stderr, /recorded without vendored_sha256.*integrity unverifiable/i, `must report a clean missing-hash message. stderr: ${r.stderr}`);
    assert.doesNotMatch(r.stderr, /TypeError|Cannot read properties of undefined/, `must not crash with a TypeError. stderr: ${r.stderr}`);
  } finally {
    rmrf(tmp);
  }
});

test("gate 12e: validate-vendor.js fires OFFLINE on a forged upstream_sha256_at_pin for an unstripped vendored file", () => {
  // The vendored_sha256 compare is self-attesting — it proves only that the
  // file matches its OWN recorded hash, never that the bytes matched
  // blamejs@<pin> upstream. The full upstream check
  // (scripts/validate-vendor-online.js) needs the network and is not a
  // predeploy gate. For a file with NO strip rules the vendored bytes are
  // byte-identical to upstream, so upstream_sha256_at_pin must equal
  // vendored_sha256 — a forged pin is therefore catchable offline inside
  // this gate.
  const tmp = mktmp("vendor-forged-pin");
  try {
    const okSrc = "module.exports = function ok() { return 1; };\n";
    const licenseText = "Apache-2.0 LICENSE text (vendored)\n";
    function sha256(s) { return crypto.createHash("sha256").update(s).digest("hex"); }
    const prov = {
      license_file: "LICENSE",
      license_sha256: sha256(licenseText),
      pinned_commit: "deadbeef",
      files: {
        "ok.js": {
          vendored_path: "vendor/blamejs/ok.js",
          vendored_sha256: sha256(okSrc), // on-disk bytes match — offline self-check passes
          upstream_path: "lib/ok.js",
          // No strip rules: vendored MUST equal upstream. This pin is forged
          // (a value that never existed upstream) — the gate must catch it.
          upstream_sha256_at_pin: "deadbeef".padEnd(64, "0"),
          stripped: [],
        },
      },
    };
    writeFile(tmp, "vendor/blamejs/_PROVENANCE.json", JSON.stringify(prov));
    writeFile(tmp, "vendor/blamejs/LICENSE", licenseText);
    writeFile(tmp, "vendor/blamejs/ok.js", okSrc); // bytes match vendored_sha256
    copyFile(path.join(ROOT, "lib", "validate-vendor.js"), path.join(tmp, "lib", "validate-vendor.js"));
    copyExitCodes(tmp);
    const r = spawnSync(process.execPath, [path.join(tmp, "lib", "validate-vendor.js")], { cwd: tmp, encoding: "utf8" });
    // Pin to exact code 1: notEqual(0) would silently pass if a future change
    // routed this through a different non-zero exit.
    assert.equal(
      r.status,
      1,
      `validate-vendor must exit 1 OFFLINE on a forged upstream_sha256_at_pin for an unstripped file.\nstdout: ${r.stdout}\nstderr: ${r.stderr}`
    );
    assert.match(
      r.stderr,
      /forged or inconsistent upstream pin/i,
      `must label the forged-pin class. stderr: ${r.stderr}`
    );
    // No network was touched — the gate is offline-enforceable.
    assert.doesNotMatch(r.stderr, /fetch|ENOTFOUND|getaddrinfo|raw\.githubusercontent/i, `gate must not touch the network. stderr: ${r.stderr}`);
  } finally {
    rmrf(tmp);
  }
});

test("gate 12f: validate-vendor.js does NOT false-positive on an unverifiable-offline stripped file whose upstream pin differs from vendored", () => {
  // A file WITH strip rules legitimately differs from upstream (the strips
  // change bytes), so upstream_sha256_at_pin != vendored_sha256 is EXPECTED.
  // The offline gate cannot verify the upstream side for stripped files (that
  // is what the manual scripts/validate-vendor-online.js exists for), so it
  // must NOT flag the difference — otherwise the real retry.js / worker-pool.js
  // entries (both stripped) would fail every build.
  const tmp = mktmp("vendor-stripped-ok");
  try {
    const okSrc = "module.exports = function ok() { return 1; };\n";
    const licenseText = "Apache-2.0 LICENSE text (vendored)\n";
    function sha256(s) { return crypto.createHash("sha256").update(s).digest("hex"); }
    const prov = {
      license_file: "LICENSE",
      license_sha256: sha256(licenseText),
      pinned_commit: "deadbeef",
      files: {
        "ok.js": {
          vendored_path: "vendor/blamejs/ok.js",
          vendored_sha256: sha256(okSrc),
          upstream_path: "lib/ok.js",
          // Differs from vendored — but that is EXPECTED for a stripped file.
          upstream_sha256_at_pin: "abc123".padEnd(64, "0"),
          stripped: ["removed audit event sink"],
        },
      },
    };
    writeFile(tmp, "vendor/blamejs/_PROVENANCE.json", JSON.stringify(prov));
    writeFile(tmp, "vendor/blamejs/LICENSE", licenseText);
    writeFile(tmp, "vendor/blamejs/ok.js", okSrc);
    copyFile(path.join(ROOT, "lib", "validate-vendor.js"), path.join(tmp, "lib", "validate-vendor.js"));
    copyExitCodes(tmp);
    const r = spawnSync(process.execPath, [path.join(tmp, "lib", "validate-vendor.js")], { cwd: tmp, encoding: "utf8" });
    assert.equal(
      r.status,
      0,
      `validate-vendor must NOT fail on a stripped file whose upstream pin differs from vendored (offline can't verify it).\nstdout: ${r.stdout}\nstderr: ${r.stderr}`
    );
    assert.doesNotMatch((r.stdout || "") + (r.stderr || ""), /forged or inconsistent upstream pin/i, `must not claim a forged pin for a legitimately-stripped file. stderr: ${r.stderr}`);
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


// ---- routed from vendor-upstream-pin-consistency ----
require("node:test").describe("vendor-upstream-pin-consistency", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
/**
 * vendor/blamejs/_PROVENANCE.json upstream-pin consistency.
 *
 * lib/validate-vendor.js (the offline predeploy gate) enforces ONE direction
 * of the strip/upstream-hash relationship: a file recorded with no strip rules
 * (`stripped: []`) must have `upstream_sha256_at_pin === vendored_sha256`,
 * because byte-identical-to-upstream is exactly what "no strips" means.
 *
 * It cannot, offline, enforce the CONVERSE: a file that DOES record strips must
 * NOT have `upstream_sha256_at_pin === vendored_sha256`. Identical hashes there
 * are a contradiction — either the strip never happened, or the "upstream" hash
 * is actually the post-strip (vendored) hash masquerading as upstream. The
 * latter is what shipped for codepoint-class.js: it recorded `stripped: []`
 * with `upstream_sha256_at_pin` set to the vendored hash, even though the
 * vendoring DID strip 12 `// allow:raw-byte-literal — …` lint markers. Because
 * the recorded "upstream" hash was the vendored hash, the online cross-check
 * (scripts/validate-vendor-online.js) reported a false mismatch against the
 * real upstream blob at the pin — while every offline gate stayed green.
 *
 * These assertions lock in both directions of the invariant and pin the
 * corrected codepoint-class values so a future re-vendor cannot silently
 * re-record the post-strip hash as the upstream hash.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const ROOT = path.join(__dirname, "..");
const PROV = path.join(ROOT, "vendor", "blamejs", "_PROVENANCE.json");

function loadProv() {
  return JSON.parse(fs.readFileSync(PROV, "utf8"));
}

test("every vendored file records both vendored and upstream pin hashes", () => {
  const prov = loadProv();
  const files = Object.entries(prov.files || {});
  // Anti-coincidence: the manifest must actually carry files, else the
  // per-file loop below passes vacuously.
  assert.ok(files.length >= 3, `expected >= 3 vendored files, found ${files.length}`);
  for (const [name, info] of files) {
    assert.equal(typeof info.vendored_sha256, "string", `${name} missing vendored_sha256`);
    assert.match(info.vendored_sha256, /^[0-9a-f]{64}$/, `${name} vendored_sha256 not a sha256`);
    assert.equal(typeof info.upstream_sha256_at_pin, "string", `${name} missing upstream_sha256_at_pin`);
    assert.match(info.upstream_sha256_at_pin, /^[0-9a-f]{64}$/, `${name} upstream_sha256_at_pin not a sha256`);
  }
});

test("strip-recorded ⇔ upstream hash differs from vendored hash (both directions)", () => {
  const prov = loadProv();
  for (const [name, info] of Object.entries(prov.files || {})) {
    const strips = Array.isArray(info.stripped) ? info.stripped.length : 0;
    const identical = info.upstream_sha256_at_pin === info.vendored_sha256;
    if (strips === 0) {
      // No strips → vendored bytes are upstream bytes → hashes MUST match.
      assert.equal(
        identical,
        true,
        `${name}: stripped:[] but upstream_sha256_at_pin !== vendored_sha256 — ` +
          `a no-strip file must be byte-identical to upstream`
      );
    } else {
      // Strips recorded → bytes were changed → hashes MUST differ. Equal
      // hashes here mean the "upstream" hash is really the post-strip
      // (vendored) hash — the codepoint-class regression.
      assert.equal(
        identical,
        false,
        `${name}: ${strips} strip rule(s) recorded but upstream_sha256_at_pin === vendored_sha256 — ` +
          `the recorded upstream hash is the post-strip vendored hash, not the true upstream pin`
      );
    }
  }
});

test("codepoint-class.js records its marker strip and the true-upstream pin hash", () => {
  const prov = loadProv();
  const cp = prov.files["codepoint-class.js"];
  assert.ok(cp, "codepoint-class.js missing from provenance");

  // The vendored bytes are unchanged by the fix — this is the integrity
  // anchor the offline gate verifies on disk.
  assert.equal(
    cp.vendored_sha256,
    "2be79cf25de87f46b608aec98ee790f4cf1035ffee48fe70ff082d3cf6f324ba",
    "vendored_sha256 changed — the on-disk vendored file was modified"
  );
  // The corrected upstream pin: the real blamejs@<pin> blob hashes to this,
  // confirmed against raw.githubusercontent.com. It is DISTINCT from the
  // vendored hash (the strip removed 324 bytes of lint-marker prefixes).
  assert.equal(
    cp.upstream_sha256_at_pin,
    "18bcf1e99d168845a41c34e351e2323951319d2054634ca5021b002093e0fc03",
    "upstream_sha256_at_pin must be the true upstream blob hash, not the post-strip vendored hash"
  );
  assert.notEqual(
    cp.upstream_sha256_at_pin,
    cp.vendored_sha256,
    "upstream and vendored hashes must differ for a stripped file"
  );
  // The strip the fix documents must be recorded.
  assert.ok(
    Array.isArray(cp.stripped) && cp.stripped.length >= 1,
    "codepoint-class.js strips the raw-byte-literal lint markers but records stripped:[]"
  );
  assert.ok(
    cp.stripped.some((s) => /raw-byte-literal/.test(s)),
    "the documented strip must name the raw-byte-literal lint markers it removed"
  );
});
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});
