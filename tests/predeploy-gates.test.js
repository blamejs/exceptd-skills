"use strict";
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

test("gate 1: verify.js fires on a byte-flipped signature in manifest.json", () => {
  const tmp = mktmp("verify");
  try {
    // Stage a minimal verify.js-compatible repo layout.
    copyFile(
      path.join(ROOT, "lib", "verify.js"),
      path.join(tmp, "lib", "verify.js")
    );
    // verify.js v0.12.12+ schema-validates the manifest before any skill
    // I/O. The schema lives at lib/schemas/manifest.schema.json — copy it
    // into the temp tree alongside verify.js so the validator can load it.
    copyFile(
      path.join(ROOT, "lib", "schemas", "manifest.schema.json"),
      path.join(tmp, "lib", "schemas", "manifest.schema.json")
    );
    const { privateKey, publicKey } = genKeypair();
    writeFile(tmp, "keys/public.pem", publicKey);
    const skillBody = "---\nname: t\n---\n# tempdir skill body\n";
    writeFile(tmp, "skills/t/skill.md", skillBody);
    const goodSig = signContent(skillBody, privateKey);
    // Byte-flip: flip first character of base64 signature deterministically.
    const flipped =
      (goodSig[0] === "A" ? "B" : "A") + goodSig.slice(1);
    assert.notEqual(flipped, goodSig, "sanity: flipped signature must differ");
    // Manifest must satisfy the schema's required top-level + per-skill
    // fields. Anything missing fails before we ever reach signature
    // verification — which would silently mask the test's intent.
    const manifest = {
      name: "test",
      version: "0.0.1",
      description: "test fixture manifest",
      atlas_version: "5.1.0",
      threat_review_date: "2026-01-01",
      skills: [
        {
          name: "t",
          version: "1.0.0",
          path: "skills/t/skill.md",
          description: "tempdir skill for predeploy-gate test",
          triggers: ["t"],
          data_deps: [],
          atlas_refs: [],
          attack_refs: [],
          framework_gaps: ["G1"],
          last_threat_review: "2026-01-01",
          signature: flipped,
          signed_at: "2026-01-01T00:00:00.000Z",
        },
      ],
    };
    writeFile(tmp, "manifest.json", JSON.stringify(manifest, null, 2));

    const r = spawnSync(
      process.execPath,
      [path.join(tmp, "lib", "verify.js")],
      { cwd: tmp, encoding: "utf8" }
    );
    // lib/verify.js exit-1 path covers the `invalid` branch
    // (line 253: "if (result.invalid.length > 0) { ... process.exit(1); }").
    assert.notEqual(
      r.status,
      0,
      `verify.js must exit non-zero on a tampered signature.\nstdout: ${r.stdout}\nstderr: ${r.stderr}`
    );
    assert.match(
      (r.stderr || "") + (r.stdout || ""),
      /TAMPERED|FAIL/i,
      "verify.js should label the failure as TAMPERED / FAIL"
    );
  } finally {
    rmrf(tmp);
  }
});

// ---------- Gate 7: Lint skill files ----------

test("gate 7: lint-skills.js fires on a skill missing the Threat Context section", () => {
  const tmp = mktmp("lint");
  try {
    copyFile(
      path.join(ROOT, "lib", "lint-skills.js"),
      path.join(tmp, "lib", "lint-skills.js")
    );
    // lint-skills.js loads data/atlas-ttps.json and
    // data/framework-control-gaps.json unconditionally; the optional
    // catalogs (rfc, cwe, d3fend, dlp) are loaded only if present.
    writeFile(
      tmp,
      "data/atlas-ttps.json",
      JSON.stringify({ "AML.T0043": { id: "AML.T0043" } })
    );
    writeFile(
      tmp,
      "data/framework-control-gaps.json",
      JSON.stringify({ "NIST-800-53-SI-2": { id: "NIST-800-53-SI-2" } })
    );
    // Skill body deliberately omits the "Threat Context" required section.
    // The other six are present so we isolate the missing-section failure
    // mode to a single error class.
    const skillBody = [
      "---",
      "name: temp-lint-skill",
      'version: "1.0.0"',
      "description: temp skill used by lint gate meta-test",
      "triggers:",
      "  - temp",
      "data_deps:",
      "  - atlas-ttps.json",
      "atlas_refs:",
      "  - AML.T0043",
      "attack_refs: []",
      "framework_gaps:",
      "  - NIST-800-53-SI-2",
      'last_threat_review: "2026-05-01"',
      "---",
      "",
      "## Framework Lag Declaration",
      "## TTP Mapping",
      "## Exploit Availability Matrix",
      "## Analysis Procedure",
      "## Output Format",
      "## Compliance Theater Check",
    ].join("\n");
    writeFile(tmp, "skills/temp-lint-skill/skill.md", skillBody);
    writeFile(
      tmp,
      "manifest.json",
      JSON.stringify({
        skills: [
          {
            name: "temp-lint-skill",
            path: "skills/temp-lint-skill/skill.md",
          },
        ],
      })
    );

    const r = spawnSync(
      process.execPath,
      [path.join(tmp, "lib", "lint-skills.js")],
      { cwd: tmp, encoding: "utf8" }
    );
    // lib/lint-skills.js exit-1 path: line 523
    // ("process.exit(failed === 0 ? 0 : 1);"). Trigger is the
    // findMissingSections() branch: line 453 pushes
    // 'body: missing required section "Threat Context"'.
    assert.notEqual(
      r.status,
      0,
      `lint-skills.js must exit non-zero on a skill missing "Threat Context".\nstdout: ${r.stdout}\nstderr: ${r.stderr}`
    );
    assert.match(
      r.stdout,
      /missing required section "Threat Context"/,
      `lint-skills.js should report the exact missing-section error.\nstdout: ${r.stdout}`
    );
  } finally {
    rmrf(tmp);
  }
});

// ---------- Gate 9: validate-catalog-meta ----------

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
    assert.notEqual(
      r.status,
      0,
      `validate-catalog-meta.js must exit non-zero on a catalog missing _meta.tlp.\nstdout: ${r.stdout}\nstderr: ${r.stderr}`
    );
  } finally {
    rmrf(tmp);
  }
});

// ---------- Audit G F2: SBOM gate catches renamed skill ----------

test("Audit G F2: SBOM gate fires when a skill named in SBOM components is renamed in manifest", () => {
  const tmp = mktmp("sbom-rename");
  try {
    // Manifest declares skill "renamed-skill", SBOM still names the old one.
    writeFile(
      tmp,
      "manifest.json",
      JSON.stringify({
        skills: [
          { name: "renamed-skill", version: "1.0.0", path: "skills/renamed-skill/skill.md" },
        ],
      })
    );
    writeFile(tmp, "data/x.json", "{}");
    writeFile(
      tmp,
      "sbom.cdx.json",
      JSON.stringify({
        bomFormat: "CycloneDX",
        specVersion: "1.6",
        metadata: {
          properties: [
            { name: "exceptd:catalog:count", value: "1" },
            { name: "exceptd:skill:count", value: "1" },
          ],
        },
        components: [
          {
            "bom-ref": "skill:original-skill",
            name: "original-skill",
            version: "1.0.0",
            type: "library",
          },
        ],
      })
    );

    const r = spawnSync(
      process.execPath,
      [path.join(ROOT, "scripts", "check-sbom-currency.js"), "--root", tmp],
      { encoding: "utf8" }
    );
    assert.notEqual(
      r.status,
      0,
      `check-sbom-currency.js must exit non-zero on a renamed skill not reflected in SBOM.\nstdout: ${r.stdout}\nstderr: ${r.stderr}`
    );
    assert.match(
      r.stderr,
      /not in manifest\.skills/,
      `SBOM gate should report the missing skill. stderr: ${r.stderr}`
    );
  } finally {
    rmrf(tmp);
  }
});

test("Audit G F2: SBOM gate fires on a version-bumped skill", () => {
  const tmp = mktmp("sbom-vbump");
  try {
    writeFile(
      tmp,
      "manifest.json",
      JSON.stringify({
        skills: [
          { name: "my-skill", version: "2.0.0", path: "skills/my-skill/skill.md" },
        ],
      })
    );
    writeFile(tmp, "data/x.json", "{}");
    writeFile(
      tmp,
      "sbom.cdx.json",
      JSON.stringify({
        bomFormat: "CycloneDX",
        specVersion: "1.6",
        metadata: {
          properties: [
            { name: "exceptd:catalog:count", value: "1" },
            { name: "exceptd:skill:count", value: "1" },
          ],
        },
        components: [
          {
            "bom-ref": "skill:my-skill",
            name: "my-skill",
            version: "1.0.0", // stale — manifest has 2.0.0
            type: "library",
          },
        ],
      })
    );

    const r = spawnSync(
      process.execPath,
      [path.join(ROOT, "scripts", "check-sbom-currency.js"), "--root", tmp],
      { encoding: "utf8" }
    );
    assert.notEqual(r.status, 0, "SBOM gate must fire on version skew");
    assert.match(
      r.stderr,
      /version 1\.0\.0 != manifest\.skills version 2\.0\.0/,
      `version-skew message expected; stderr: ${r.stderr}`
    );
  } finally {
    rmrf(tmp);
  }
});

// ---------- Audit G F1: validate-indexes rejects empty source_hashes ----------

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
    assert.notEqual(
      r.status,
      0,
      `validate-indexes.js must reject an empty source_hashes table.\nstdout: ${r.stdout}\nstderr: ${r.stderr}`
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

// ---------- Gate 10: SBOM currency ----------

test("gate 10: check-sbom-currency.js fires on drifted skill count", () => {
  const tmp = mktmp("sbom");
  try {
    // sbom.cdx.json claims one count, manifest.json reports another.
    // scripts/check-sbom-currency.js compares the two and exits 1 on drift.
    writeFile(
      tmp,
      "manifest.json",
      JSON.stringify({
        skills: [
          { name: "a", path: "skills/a/skill.md" },
          { name: "b", path: "skills/b/skill.md" },
        ],
      })
    );
    // Two data/*.json files = 2 catalogs.
    writeFile(tmp, "data/one.json", "{}");
    writeFile(tmp, "data/two.json", "{}");
    // SBOM declares 99 skills + 99 catalogs — both wrong.
    writeFile(
      tmp,
      "sbom.cdx.json",
      JSON.stringify({
        bomFormat: "CycloneDX",
        specVersion: "1.6",
        metadata: {
          properties: [
            { name: "exceptd:catalog:count", value: "99" },
            { name: "exceptd:skill:count", value: "99" },
          ],
        },
      })
    );

    // Invoke the script with --root pointing at the tempdir — this flag
    // was introduced when the gate-10 logic was extracted from the inline
    // `node -e` block in scripts/predeploy.js to its own file in this
    // same change set.
    const r = spawnSync(
      process.execPath,
      [path.join(ROOT, "scripts", "check-sbom-currency.js"), "--root", tmp],
      { encoding: "utf8" }
    );
    // Exit-1 path: drift detected. The script prints
    // "SBOM skill count 99 != live 2" / "SBOM catalog count 99 != live 2".
    assert.notEqual(
      r.status,
      0,
      `check-sbom-currency.js must exit non-zero when sbom.cdx.json drifts from manifest.json + data/.\nstdout: ${r.stdout}\nstderr: ${r.stderr}`
    );
    assert.match(
      r.stderr,
      /SBOM (skill|catalog) count 99 != live 2/,
      `check-sbom-currency.js should report the count mismatch. stderr: ${r.stderr}`
    );
  } finally {
    rmrf(tmp);
  }
});

// ---------- Gate 11: validate-indexes ----------

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
    assert.notEqual(
      r.status,
      0,
      `validate-indexes.js must exit non-zero on a recorded-hash mismatch.\nstdout: ${r.stdout}\nstderr: ${r.stderr}`
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

// ---------- Gate 12: validate-vendor ----------

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

    const r = spawnSync(
      process.execPath,
      [path.join(tmp, "lib", "validate-vendor.js")],
      { cwd: tmp, encoding: "utf8" }
    );
    // Exit-1 path: line 80 ("process.exit(1)") after
    // "[validate-vendor] vendor tree DRIFT:" header. The hash compare
    // happens at line 60 of lib/validate-vendor.js.
    assert.notEqual(
      r.status,
      0,
      `validate-vendor.js must exit non-zero when a vendored file's bytes drift from _PROVENANCE.json.\nstdout: ${r.stdout}\nstderr: ${r.stderr}`
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

// ---------- Gate 13: validate-package ----------

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

    const r = spawnSync(
      process.execPath,
      [path.join(tmp, "lib", "validate-package.js")],
      { cwd: tmp, encoding: "utf8" }
    );
    // Exit-1 path: line 157 ("process.exit(1)") after the issues list.
    // The expected issue line is built at line 124:
    // "required file missing from publish tarball: LICENSE".
    assert.notEqual(
      r.status,
      0,
      `validate-package.js must exit non-zero when a files-allowlist entry is absent.\nstdout: ${r.stdout}\nstderr: ${r.stderr}`
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

// ---------- Gate 14: verify-shipped-tarball ----------
//
// This is the gate that closed v0.12.4's signature regression. The bug
// class: lib/verify.js against the SOURCE tree passes 38/38, but a fresh
// `npm install` against the SHIPPED tarball produces 0/38. The cause is
// keys/public.pem being swapped between sign and pack (the test that
// did it lived in `tests/operator-bugs.test.js` and synchronously
// regenerated keys mid-suite — see CLAUDE.md's pitfall list).
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
    assert.notEqual(
      r.status,
      0,
      `verify-shipped-tarball.js must exit non-zero when shipped bytes differ from what was signed.\nstdout: ${r.stdout}\nstderr: ${r.stderr}`
    );
    assert.match(
      r.stdout + r.stderr,
      /signature did not verify|FAIL — shipped tarball/,
      `verify-shipped-tarball.js should report the signature-mismatch failure class. stdout: ${r.stdout} stderr: ${r.stderr}`
    );
  } finally {
    rmrf(tmp);
  }
});
