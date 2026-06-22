'use strict';

/**
 * tests/lint-skills.test.js
 *
 * Source-shape tests for lib/lint-skills.js.
 *
 * Covers the Hard Rule #1 body-scan: skill bodies that cite a CVE must
 * match the catalog, missing-from-catalog references are a hard error
 * (skillErrors), and draft references stay a warning (skillWarnings). Also
 * pins that validateFrontmatter accepts the discovery_mode optional field.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');

// ---------- lint Hard Rule #1 body-scan ----------

test('B: lint-skills.js source carries the body-scan implementation', () => {
  const src = fs.readFileSync(path.join(ROOT, 'lib', 'lint-skills.js'), 'utf8');
  assert.match(src, /Hard Rule #1/, 'body-scan must explicitly cite Hard Rule #1');
  assert.match(src, /body cites/, 'body-scan must emit "body cites" text');
  assert.match(src, /ctx\.cveCatalog/, 'body-scan must consume ctx.cveCatalog');
  assert.match(src, /_draft\s*===\s*true/, 'body-scan must distinguish draft entries');
  // missing-from-catalog is a hard error.
  assert.match(src, /if \(!entry\) \{[\s\S]*?skillErrors\.push/,
    'missing-from-catalog must push to skillErrors');
});

test('B: validateFrontmatter accepts discovery_mode field (no "unknown field" error)', () => {
  const src = fs.readFileSync(path.join(ROOT, 'lib', 'lint-skills.js'), 'utf8');
  assert.match(src, /discovery_mode/, 'OPTIONAL_FRONTMATTER_FIELDS must include discovery_mode');
});

test('B: lint-skills body-scan flipped from warning to hard error', () => {
  const src = fs.readFileSync(path.join(ROOT, 'lib', 'lint-skills.js'), 'utf8');
  // The body-scan block: missing-from-catalog must push to skillErrors,
  // not skillWarnings. Match the canonical body-scan paragraph and
  // assert it now uses skillErrors.push for the "no such entry" case.
  const m = src.match(/no stale threat intel[\s\S]{0,400}body cites[\s\S]{0,800}/);
  assert.ok(m, 'body-scan block not found');
  // Find the missing-from-catalog branch (the `if (!entry)` arm).
  assert.match(src, /if \(!entry\) \{[\s\S]*?skillErrors\.push/,
    'missing-from-catalog must push to skillErrors (not skillWarnings)');
  // Draft case stays as warning.
  assert.match(src, /entry\._draft === true[\s\S]*?skillWarnings\.push/,
    'draft case still surfaces as warning');
});


// ---- routed from manifest-cover-ref-resolution ----
require("node:test").describe("manifest-cover-ref-resolution", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
/**
 * tests/manifest-cover-ref-resolution.test.js
 *
 * The manifest cross-reference cover arrays (atlas_refs / attack_refs /
 * framework_gaps / rfc_refs / cwe_refs / d3fend_refs / dlp_refs) are an
 * enriched superset of skill frontmatter — the manifest may carry curated
 * refs absent from any skill body. Those manifest-only refs are what
 * scripts/refresh-reverse-refs.js writes into each catalog's reverse field
 * (atlas-ttps.exceptd_skills, cwe-catalog.skills_referencing, ...). The
 * per-skill frontmatter ref-resolution in lint-skills reads only skill
 * bodies, so it never sees the manifest-only delta: a typo'd or stale
 * manifest-only ref (a hand-edit, or one re-signed into manifest_signature)
 * would become an orphaned control reference in the signed manifest and the
 * reverse-ref surface, with no gate to catch it — the exact "no orphaned
 * controls" failure (AGENTS.md Hard Rule #4) the frontmatter resolution
 * prevents, applied to the delta the frontmatter pass is blind to.
 *
 * findUnresolvedManifestCoverRefs() closes that gap. These tests pin:
 *   1. the shipped manifest's cover arrays all resolve (clean baseline);
 *   2. a manifest-only ref absent from the catalog is REPORTED (the bug);
 *   3. a curated manifest-only ref that DOES resolve is ACCEPTED (no
 *      false-positive on legitimate enrichment).
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const lint = require('../lib/lint-skills.js');

const ROOT = path.join(__dirname, '..');
const manifest = JSON.parse(fs.readFileSync(path.join(ROOT, 'manifest.json'), 'utf8'));
const ctx = lint.loadContext();

test('shipped manifest cover arrays all resolve to catalog entries (baseline clean)', () => {
  const errors = lint.findUnresolvedManifestCoverRefs(manifest.skills, ctx);
  assert.deepEqual(errors, [],
    `manifest cover arrays carry unresolved (orphaned) control refs:\n  ${errors.join('\n  ')}`);
});

test('a manifest-only ref absent from the catalog is reported (Hard Rule #4)', () => {
  // A skill entry whose cover arrays mix a real catalog ref with a bogus one
  // present in NEITHER frontmatter NOR the catalog. The bogus refs must be the
  // exact reported set; the real one must not be flagged.
  const realAtlas = [...ctx.atlasKeys][0];
  const realCwe = [...ctx.cweKeys][0];
  const synthetic = [{
    name: 'synthetic-skill',
    atlas_refs: [realAtlas, 'AML.T9999'],
    cwe_refs: [realCwe, 'CWE-99999'],
  }];
  const errors = lint.findUnresolvedManifestCoverRefs(synthetic, ctx);
  assert.deepEqual(errors, [
    'synthetic-skill.atlas_refs: "AML.T9999" not present in data/atlas-ttps.json',
    'synthetic-skill.cwe_refs: "CWE-99999" not present in data/cwe-catalog.json',
  ]);
});

test('a curated manifest-only ref that resolves to a catalog entry is accepted', () => {
  // Enrichment case: a real catalog key that no skill frontmatter declares is
  // legitimate manifest enrichment and must NOT be flagged.
  const realAtlas = [...ctx.atlasKeys][0];
  const synthetic = [{ name: 'synthetic-skill', atlas_refs: [realAtlas] }];
  const errors = lint.findUnresolvedManifestCoverRefs(synthetic, ctx);
  assert.deepEqual(errors, []);
});

test('an absent optional catalog (null key-set) skips that field rather than crashing', () => {
  // loadContext() leaves ctx.attackKeys null when data/attack-techniques.json
  // is absent in older trees. The resolver must degrade gracefully (skip),
  // matching the per-skill attack_refs check's contract — not throw or flag.
  const partialCtx = { ...ctx, attackKeys: null };
  const synthetic = [{ name: 'synthetic-skill', attack_refs: ['T9999'] }];
  const errors = lint.findUnresolvedManifestCoverRefs(synthetic, partialCtx);
  assert.deepEqual(errors, []);
});

test('MANIFEST_COVER_RESOLUTION enumerates the cover-ref fields the resolver walks', () => {
  // Direct reference to the exported config the resolver iterates — pins its
  // shape so a future edit that drops a field/ctxKey/catalog tuple is caught.
  assert.ok(Array.isArray(lint.MANIFEST_COVER_RESOLUTION) && lint.MANIFEST_COVER_RESOLUTION.length >= 1);
  for (const row of lint.MANIFEST_COVER_RESOLUTION) {
    assert.equal(typeof row.field, 'string');
    assert.equal(typeof row.ctxKey, 'string');
    assert.equal(typeof row.catalog, 'string');
  }
});
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
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

test("gate 7: lint-skills.js fires on a skill missing the Threat Context section", () => {
  const tmp = mktmp("lint");
  try {
    copyFile(
      path.join(ROOT, "lib", "lint-skills.js"),
      path.join(tmp, "lib", "lint-skills.js")
    );
    copyExitCodes(tmp);
    // lint-skills.js loads its frontmatter schema at module load — stage it
    // alongside (same reason copyExitCodes exists: a missing require/read
    // crashes before any lint output, yielding empty stdout).
    copyFile(
      path.join(ROOT, "lib", "schemas", "skill-frontmatter.schema.json"),
      path.join(tmp, "lib", "schemas", "skill-frontmatter.schema.json")
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
    assert.equal(
      r.status,
      1,
      `lint-skills.js must exit 1 on a skill missing "Threat Context" (failed>0 branch).\nstdout: ${r.stdout}\nstderr: ${r.stderr}`
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
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});


// ---- routed from sign-verify ----
require("node:test").describe("sign-verify", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
/**
 * Tests for lib/sign.js + lib/verify.js — Ed25519 signing & verification.
 *
 * NOTE (spec vs. code): Both modules' public APIs (`signAll`, `verifyAll`, `verifyOne`,
 * `generateKeypair`) are hard-coded to the repo's `manifest.json`, `.keys/private.pem`,
 * and `keys/public.pem`. They are not parameterised on filesystem paths, so a fully
 * isolated round-trip cannot be driven through those exports without mutating the repo.
 * These tests instead exercise the underlying primitive that both modules use:
 * `crypto.sign(null, content, key)` / `crypto.verify(null, content, key, signature)`
 * with the same `dsaEncoding: 'ieee-p1363'` option both modules apply. This validates
 * the cryptographic contract — generate keypair, sign content, verify pass, tamper,
 * verify fail — without depending on `.keys/` or `keys/` existing on disk.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');

const SAMPLE_SKILL = `---
name: sample-skill
version: "1.0.0"
description: A sample skill used by tests
---

# Sample Skill

This is content used to validate the Ed25519 sign/verify round-trip.
`;

// Replicas of the internal helpers in lib/sign.js and lib/verify.js. They use the
// exact same crypto options so a contract-breaking change in either module would
// require updating these tests too — making the dependency explicit.

function signContent(content, privateKey) {
  const signature = crypto.sign(null, Buffer.from(content, 'utf8'), {
    key: privateKey,
    dsaEncoding: 'ieee-p1363'
  });
  return signature.toString('base64');
}

function verifyContent(content, signatureBase64, publicKey) {
  try {
    const signature = Buffer.from(signatureBase64, 'base64');
    return crypto.verify(null, Buffer.from(content, 'utf8'), {
      key: publicKey,
      dsaEncoding: 'ieee-p1363'
    }, signature);
  } catch (_) {
    return false;
  }
}

function generateTempKeypair() {
  return crypto.generateKeyPairSync('ed25519', {
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    publicKeyEncoding: { type: 'spki', format: 'pem' }
  });
}

// ---------- crypto.generateKeyPairSync round-trip ----------









// ---------- module surface ----------



// ---------- temp-dir keypair write/read sanity ----------
//
// Demonstrates the file-format contract lib/sign.js writes to disk (PKCS8/SPKI PEM)
// without touching the repo's real key paths.


// ---------- v0.12.12 hardening: normalize() byte-stability contract ----------
//
// CRLF + BOM normalization is the round-trip stability contract between
// lib/sign.js and lib/verify.js. Both modules export normalize() so the
// tests can exercise the actual production function rather than a copy.
// If either side's normalize() drifts, this test catches it.

const signMod = require('../lib/sign.js');
const verifyMod = require('../lib/verify.js');

function actualSign(content, privateKey) {
  const normalized = signMod.normalize(content);
  return crypto.sign(null, Buffer.from(normalized, 'utf8'), {
    key: privateKey, dsaEncoding: 'ieee-p1363'
  }).toString('base64');
}

function actualVerify(content, sigB64, publicKey) {
  try {
    const normalized = verifyMod.normalize(content);
    return crypto.verify(null, Buffer.from(normalized, 'utf8'), {
      key: publicKey, dsaEncoding: 'ieee-p1363'
    }, Buffer.from(sigB64, 'base64'));
  } catch { return false; }
}








// ---------- v0.12.12 hardening: S2 manifest path traversal ----------







// ---------- v0.12.12 hardening: S3 manifest schema validation ----------




// ---------- sign-side schema gate: signer must be at least as strict as verifier ----------
//
// lib/verify.js signAll()/loadManifestValidated() schema-validate the manifest
// before (re-)signing / verifying. lib/sign.js — the canonical signer behind
// `node lib/sign.js sign-all` + `npm run bootstrap` — must NOT be the weaker
// check: a manifest that is path-safe but schema-invalid must be REFUSED by the
// signer, otherwise it gets a valid manifest_signature here and then
// lib/verify.js loadManifestValidated() throws on the same schema at install
// time and refuses to verify any skill (producer emits what the consumer
// rejects). signAll()/signOne() read the repo's real manifest/keys, so we
// exercise the extracted validateManifestSchema() helper that both call.

function validBaseManifest() {
  return {
    name: 'x',
    version: '1.2.3',
    description: 'desc',
    atlas_version: '5.1.0',
    threat_review_date: '2026-05-13',
    skills: [{
      name: 'one',
      version: '1.0.0',
      path: 'skills/one/skill.md',
      description: 'a real skill entry',
      triggers: ['x'],
      data_deps: [],
      atlas_refs: [],
      attack_refs: [],
      framework_gaps: ['foo'],
      last_threat_review: '2026-05-13',
    }],
  };
}







// ---------- v0.12.12 hardening: S4 duplicate frontmatter keys ----------



// ---------- v0.12.12 hardening: S6 orphan skill.md detector ----------

test('S4: parseFrontmatter rejects duplicate top-level keys', () => {
  const lint = require('../lib/lint-skills.js');
  const fm = 'name: alpha\nversion: "1.0.0"\nname: beta\n';
  assert.throws(
    () => lint.parseFrontmatter(fm),
    /Duplicate frontmatter key "name"/,
  );
});

test('S4: parseFrontmatter accepts non-duplicate keys', () => {
  const lint = require('../lib/lint-skills.js');
  const fm = 'name: alpha\nversion: "1.0.0"\ndescription: hello\n';
  const parsed = lint.parseFrontmatter(fm);
  assert.equal(parsed.name, 'alpha');
  assert.equal(parsed.version, '1.0.0');
  assert.equal(parsed.description, 'hello');
});

test('S6: findOrphanSkillFiles returns [] when every disk skill is in manifest', () => {
  const lint = require('../lib/lint-skills.js');
  const manifestPath = path.join(__dirname, '..', 'manifest.json');
  const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
  const orphans = lint.findOrphanSkillFiles(manifest.skills);
  assert.deepEqual(orphans, [], `expected no orphans in live repo; got: ${JSON.stringify(orphans)}`);
});

test('S6: findOrphanSkillFiles detects a skill.md not referenced by manifest', () => {
  const lint = require('../lib/lint-skills.js');
  const manifestPath = path.join(__dirname, '..', 'manifest.json');
  const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
  // Drop one entry — its skill.md should become an orphan from the walker's view.
  const reduced = manifest.skills.slice(1);
  const dropped = manifest.skills[0].path.split(path.sep).join('/');
  const orphans = lint.findOrphanSkillFiles(reduced);
  assert.ok(
    orphans.includes(dropped),
    `expected ${dropped} to appear as orphan; got: ${JSON.stringify(orphans)}`,
  );
});
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});


// ---- routed from v0_13_3-fixes ----
require("node:test").describe("v0_13_3-fixes", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
/**
 * tests/v0_13_3-fixes.test.js
 *
 * Pin tests for the v0.13.3 patch.
 *
 * Coverage:
 *   A — refresh.yml split into refresh-data (no creds) + open-pr
 *       (contents:write + pull-requests:write scoped to PR creation only).
 *   B — Hard Rule #1 body-scan flipped from warning to hard error.
 *   E — doctor --ai-config produces a structured check matching the shape
 *       documented under NEW-CTRL-050.
 *   F — watchlist --org-scan refuses without --org / GITHUB_ORG; surfaces
 *       error envelope shape.
 *   G — ADVISORIES_SOURCE FEEDS grew from 4 to 8 (added kernel-org,
 *       oss-security, jfrog, cisa-current).
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const ROOT = path.join(__dirname, '..');
const CLI = path.join(ROOT, 'bin', 'exceptd.js');

function cli(args, opts = {}) {
  return spawnSync(process.execPath, [CLI, ...args], {
    encoding: 'utf8',
    cwd: ROOT,
    env: { ...process.env, EXCEPTD_DEPRECATION_SHOWN: '1', ...(opts.env || {}) },
    ...opts,
  });
}

function tryJson(s) { try { return JSON.parse(s); } catch { return null; } }

function extractJobBlock(yml, jobName) {
  const lines = yml.split('\n');
  let startIdx = -1;
  for (let i = 0; i < lines.length; i++) {
    if (lines[i] === `  ${jobName}:`) { startIdx = i; break; }
  }
  if (startIdx === -1) return null;
  let endIdx = lines.length;
  for (let i = startIdx + 1; i < lines.length; i++) {
    if (/^  [a-z][a-z0-9_-]*:\s*$/.test(lines[i])) { endIdx = i; break; }
  }
  return lines.slice(startIdx, endIdx).join('\n');
}

const PERM_DECL = (key, value) =>
  new RegExp(`^\\s+${key}:\\s+${value}\\s*$`, 'm');

// ---------- A. refresh.yml split-checkout ----------




// ---------- B. lint Hard Rule #1 body-scan is now hard error ----------

test('B: lint-skills body-scan flipped from warning to hard error', () => {
  const src = fs.readFileSync(path.join(ROOT, 'lib', 'lint-skills.js'), 'utf8');
  // The body-scan block: missing-from-catalog must push to skillErrors,
  // not skillWarnings. Match the canonical body-scan paragraph and
  // assert it now uses skillErrors.push for the "no such entry" case.
  const m = src.match(/no stale threat intel[\s\S]{0,400}body cites[\s\S]{0,800}/);
  assert.ok(m, 'body-scan block not found');
  // Find the missing-from-catalog branch (the `if (!entry)` arm).
  assert.match(src, /if \(!entry\) \{[\s\S]*?skillErrors\.push/,
    'missing-from-catalog must push to skillErrors (not skillWarnings)');
  // Draft case stays as warning.
  assert.match(src, /entry\._draft === true[\s\S]*?skillWarnings\.push/,
    'draft case still surfaces as warning');
});

// ---------- E. doctor --ai-config ----------

test('E: doctor --ai-config emits structured check with ai_config key', () => {
  const r = cli(['doctor', '--ai-config', '--json']);
  // Status may be 0 (no findings) or 1 (warn-level findings). Both fine.
  const body = tryJson(r.stdout);
  assert.ok(body, `expected JSON; got ${r.stdout.slice(0, 200)}`);
  assert.equal(body.verb, 'doctor');
  assert.ok(body.checks && body.checks.ai_config, 'checks.ai_config must be present');
  const c = body.checks.ai_config;
  assert.equal(typeof c.scanned_dirs, 'number');
  assert.equal(typeof c.scanned_files, 'number');
  assert.ok(Array.isArray(c.directories_inspected));
  assert.ok(c.directories_inspected.includes('~/.claude'),
    'must include ~/.claude in inspected dirs');
  assert.ok(c.directories_inspected.includes('~/.cursor'),
    'must include ~/.cursor in inspected dirs');
  assert.ok(c.directories_inspected.includes('~/.codeium'),
    'must include ~/.codeium in inspected dirs');
  assert.ok(Array.isArray(c.sensitive_patterns));
  assert.ok(Array.isArray(c.findings));
  assert.equal(c.control_reference, 'NEW-CTRL-050 (MAL-2026-SHAI-HULUD-OSS lesson)');
  assert.ok(['win32', 'darwin', 'linux', 'freebsd', 'openbsd', 'sunos', 'aix'].includes(c.platform));
});

// ---------- F. watchlist --org-scan ----------

test('F: watchlist --org-scan refuses without --org argument', () => {
  const r = cli(['watchlist', '--org-scan', '--json'], { env: { ...process.env, GITHUB_ORG: '', EXCEPTD_DEPRECATION_SHOWN: '1' } });
  assert.equal(r.status, 1, `expected exit 1; got ${r.status}`);
  const body = tryJson(r.stdout.trim()) || tryJson(r.stderr.trim());
  assert.ok(body && body.ok === false);
  assert.equal(body.verb, 'watchlist');
  assert.equal(body.mode, 'org-scan');
  assert.match(body.error, /requires --org/);
});

// ---------- G. 4 more primary-source pollers ----------

test('G: ADVISORIES_SOURCE FEEDS includes all 8 v0.13.1+v0.13.3 entries (count >= 8)', () => {
  // v0.13.14 expanded FEEDS to 12 (added 4 vendor security blogs to close
  // the DirtyDecrypt-class intake gap). The original 8 must still be
  // present; the exact-count assertion lives in
  // tests/source-advisories.test.js where it tracks the live total.
  const { FEEDS } = require(path.join(ROOT, 'lib', 'source-advisories'));
  assert.ok(FEEDS.length >= 8, `expected >= 8 feeds; got ${FEEDS.length}`);
  const names = new Set(FEEDS.map((f) => f.name));
  for (const required of ['cisa-current', 'jfrog', 'kernel-org', 'oss-security', 'qualys', 'rhsa', 'usn', 'zdi']) {
    assert.ok(names.has(required), `original v0.13.3 feed "${required}" must still be present`);
  }
});

test('G: every v0.13.3 feed URL uses HTTPS and matches a feed kind', () => {
  const { FEEDS } = require(path.join(ROOT, 'lib', 'source-advisories'));
  const v013_3 = ['kernel-org', 'oss-security', 'jfrog', 'cisa-current'];
  for (const name of v013_3) {
    const f = FEEDS.find((x) => x.name === name);
    assert.ok(f, `${name}: feed must exist in FEEDS`);
    assert.match(f.url, /^https:\/\//);
    assert.ok(['rss', 'csaf-index'].includes(f.kind),
      `${name}: kind must be rss or csaf-index`);
    assert.ok(typeof f.description === 'string' && f.description.length > 0);
  }
});

;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});


// ---- routed from j-frontmatter-schema-enforced ----
require("node:test").describe("j-frontmatter-schema-enforced", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
/**
 * tests/j-frontmatter-schema-enforced.test.js
 *
 * The skill linter must drive enum and ref-pattern validation from the
 * published lib/schemas/skill-frontmatter.schema.json so the shipped schema is
 * the source of truth, not a decorative artifact. These tests confirm:
 *   - the schema file is loaded by the linter,
 *   - discovery_mode's enum is enforced,
 *   - the cwe/d3fend/dlp/rfc ref-array patterns are enforced,
 *   - a quoted frontmatter scalar followed by an inline comment is normalized
 *     so the enum check sees the bare value (the parser gap that previously
 *     let discovery_mode pass unchecked).
 */

const test = require('node:test');
const assert = require('node:assert/strict');

const {
  schemaConstraintErrors,
  validateFrontmatter,
  FRONTMATTER_SCHEMA,
  unquote,
} = require('../lib/lint-skills.js');

test('linter loads the published frontmatter schema with discovery_mode enum', () => {
  assert.equal(typeof FRONTMATTER_SCHEMA, 'object');
  const dm = FRONTMATTER_SCHEMA.properties && FRONTMATTER_SCHEMA.properties.discovery_mode;
  assert.ok(dm, 'schema is missing discovery_mode');
  assert.deepEqual(dm.enum, ['standalone']);
});

test('schemaConstraintErrors rejects a discovery_mode outside the enum', () => {
  const errors = schemaConstraintErrors({ discovery_mode: 'chained' }, FRONTMATTER_SCHEMA);
  assert.equal(errors.length, 1);
  assert.match(errors[0], /frontmatter\.discovery_mode "chained" is not one of/);
});

test('schemaConstraintErrors accepts the only legal discovery_mode value', () => {
  assert.deepEqual(
    schemaConstraintErrors({ discovery_mode: 'standalone' }, FRONTMATTER_SCHEMA),
    []
  );
});

test('schemaConstraintErrors enforces ref-array item patterns from the schema', () => {
  const fm = {
    cwe_refs: ['CWE-79', 'cwe-79'], // second is wrong case
    d3fend_refs: ['D3-EAL', 'D3-eal'], // second has lowercase
    dlp_refs: ['DLP-EMAIL', 'dlp-email'], // second lowercase
    rfc_refs: ['RFC-8446', 'RFC8446'], // second missing the hyphen
  };
  const errors = schemaConstraintErrors(fm, FRONTMATTER_SCHEMA);
  assert.ok(errors.some((e) => /cwe_refs entry "cwe-79"/.test(e)));
  assert.ok(errors.some((e) => /d3fend_refs entry "D3-eal"/.test(e)));
  assert.ok(errors.some((e) => /dlp_refs entry "dlp-email"/.test(e)));
  assert.ok(errors.some((e) => /rfc_refs entry "RFC8446"/.test(e)));
  // Exactly one error per malformed entry; the four valid entries produce none.
  assert.equal(errors.length, 4);
});

test('schemaConstraintErrors does not double-report atlas_refs/attack_refs/data_deps', () => {
  // These three carry their own dedicated regex checks elsewhere in the linter;
  // the schema-driven pass must skip them so a bad entry is reported once.
  const fm = {
    atlas_refs: ['not-an-id'],
    attack_refs: ['nope'],
    data_deps: ['not-json'],
  };
  assert.deepEqual(schemaConstraintErrors(fm, FRONTMATTER_SCHEMA), []);
});

test('validateFrontmatter surfaces the discovery_mode enum violation', () => {
  const fm = {
    name: 'sample-skill',
    version: '1.0.0',
    description: 'a sufficiently long description',
    triggers: ['do the thing'],
    data_deps: [],
    atlas_refs: [],
    attack_refs: [],
    framework_gaps: [],
    last_threat_review: new Date().toISOString().slice(0, 10),
    discovery_mode: 'chained',
  };
  const { errors } = validateFrontmatter(fm, 'sample-skill');
  assert.ok(
    errors.some((e) => /frontmatter\.discovery_mode "chained" is not one of/.test(e)),
    `expected discovery_mode enum error; got ${JSON.stringify(errors)}`
  );
});

test('unquote normalizes a quoted scalar followed by an inline comment', () => {
  assert.equal(unquote('"standalone"  # why this skill is standalone'), 'standalone');
  assert.equal(unquote("'standalone' # single-quoted"), 'standalone');
  // A plain quoted scalar still unquotes.
  assert.equal(unquote('"standalone"'), 'standalone');
  // A hash inside the quotes is preserved (not treated as a comment).
  assert.equal(unquote('"a # b"'), 'a # b');
  // A bare value with a hash is left intact (no quotes to anchor a comment).
  assert.equal(unquote('bare # value'), 'bare # value');
});
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});


// ---- routed from new-exports-smoke ----
require("node:test").describe("new-exports-smoke", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
/**
 * Smoke tests for the new module exports added in v0.12.24. These tests
 * are intentionally narrow: they verify the export exists, has the expected
 * shape, and handles a representative happy-path input. Behavior-coverage
 * for each function lives in the dedicated test files (csaf-bundle-
 * correctness, openvex-emission, prefetch, lint-skills).
 *
 * The diff-coverage gate (scripts/check-test-coverage.js) treats any
 * exported symbol that has no string reference in tests/ as an uncovered
 * surface change. This file is the canonical "I added an export and a
 * dedicated behavior test will follow" stop-gap that keeps the gate green.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');

const ROOT = path.resolve(__dirname, '..');

// ---------------------------------------------------------------------------
// lib/lint-skills.js — air-gap completeness lint
// ---------------------------------------------------------------------------



// ---------------------------------------------------------------------------
// lib/prefetch.js — _index.json Ed25519 signing
// ---------------------------------------------------------------------------




// ---------------------------------------------------------------------------
// lib/scoring.js — strict CVSS 3.0/3.1 vector parse
// ---------------------------------------------------------------------------



// ---------------------------------------------------------------------------
// scripts/check-test-coverage.js — coincidence-assert ban
// ---------------------------------------------------------------------------

test('lib/lint-skills exposes lintPlaybookAirGap', () => {
  const lint = require(path.join(ROOT, 'lib', 'lint-skills.js'));
  assert.equal(typeof lint.lintPlaybookAirGap, 'function',
    'lintPlaybookAirGap must be exported as a function');
});

test('lib/lint-skills exposes PLAYBOOK_NET_PATTERNS', () => {
  const lint = require(path.join(ROOT, 'lib', 'lint-skills.js'));
  // PLAYBOOK_NET_PATTERNS is the regex list flagging network-shaped sources
  // that need an air_gap_alternative.
  assert.ok(lint.PLAYBOOK_NET_PATTERNS,
    'PLAYBOOK_NET_PATTERNS must be exported');
});
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});


// ---- routed from round4-derivation-lint-attest ----
require("node:test").describe("round4-derivation-lint-attest", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
/**
 * Round-4 correctness regressions:
 *   - diffSignalOverrides must deep-compare (signal_overrides hold object
 *     `*__fp_checks` values; a reference-strict !== reports false drift)
 *   - the skill-section linter must not count headings inside fenced code
 *     blocks, and must not let a deeper heading (H3+) satisfy a top-level
 *     required-section (H2) requirement
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');

const cli = require(path.resolve(__dirname, '..', 'bin', 'exceptd.js'));
const lint = require(path.resolve(__dirname, '..', 'lib', 'lint-skills.js'));

const diffSignalOverrides = cli._diffSignalOverrides;
const findMissingSections = lint.findMissingSections;




const REQUIRED = ['Threat Context', 'Compliance Theater Check'];

test('a required section that exists ONLY inside a fenced code block is reported missing', () => {
  const body = [
    '# Skill',
    '## Threat Context',
    'Real threat context body with more than the minimum number of words here to satisfy the body length check easily.',
    '',
    '```markdown',
    '## Compliance Theater Check',
    'This heading is inside a fence — it is documentation, not a real section, so it must not count.',
    '```',
  ].join('\n');
  const { missing } = findMissingSections(body, REQUIRED);
  assert.ok(missing.includes('Compliance Theater Check'),
    'fenced heading must not satisfy the requirement');
  assert.ok(!missing.includes('Threat Context'), 'the real H2 section still counts');
});

test('a deeper H3 heading does not satisfy a top-level H2 required section', () => {
  const body = [
    '# Skill',
    '## Threat Context',
    'Real threat context body with plenty of words to clear the minimum body length requirement without trouble at all.',
    '',
    '## Output Format',
    '### Compliance Theater Check Result',
    'An H3 result sub-heading must not satisfy the standalone Compliance Theater Check section requirement.',
  ].join('\n');
  const { missing } = findMissingSections(body, REQUIRED);
  assert.ok(missing.includes('Compliance Theater Check'),
    'an H3 must not satisfy the H2 requirement');
});

test('a genuine H2 section (with a trailing qualifier) still satisfies the requirement', () => {
  const body = [
    '# Skill',
    '## Threat Context (mid-2026)',
    'Body with enough words to clear the minimum section body length requirement comfortably for this test case here.',
    '## Compliance Theater Check',
    'Body with enough words to clear the minimum section body length requirement comfortably for this test case here.',
  ].join('\n');
  const { missing } = findMissingSections(body, REQUIRED);
  assert.deepEqual(missing, [], 'real H2 sections (incl. a qualifier) must pass');
});
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});
