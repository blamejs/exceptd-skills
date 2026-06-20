"use strict";
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
