"use strict";


// ---- routed from crypto-codebase-pubkey-provenance-fp ----
require("node:test").describe("crypto-codebase-pubkey-provenance-fp", () => {
const __t = require("node:test"); const __env = Object.assign({}, process.env);
__t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __env)) delete process.env[k]; Object.assign(process.env, __env);
  const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
/**
 * tests/crypto-codebase-pubkey-provenance-fp.test.js
 *
 * Regression tests for two crypto-codebase collector false positives that
 * surfaced when scanning repos doing crypto correctly:
 *
 *   1. `hardcoded-key-material` is a secret-leak signal. It must fire on
 *      PRIVATE key blocks only. Public keys and certificates are published
 *      by design (BIMI trust anchors, release-signing public keys,
 *      autoupdate pubkeys); flagging them inflated RWEP on well-behaved
 *      repos that simply ship a public key.
 *
 *   2. `vendored-pqc-no-provenance` must recognize `vendor/MANIFEST.json`
 *      as a provenance record. A vendored PQC tree whose upstream version,
 *      source, and license live in a MANIFEST.json is documented; it must
 *      not be flagged as provenance-less.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const os = require("node:os");

const ROOT = path.join(__dirname, "..");
const cryptoCollector = require(path.join(ROOT, "lib", "collectors", "crypto-codebase.js"));

function mkTmp(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

const PUBKEY_BLOCK =
  "-----BEGIN PUBLIC KEY-----\n" +
  "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEexampleexampleexampleexampleex\n" +
  "ampleexampleexampleexampleexampleexampleexampleexampleexampleAA==\n" +
  "-----END PUBLIC KEY-----\n";

const CERT_BLOCK =
  "-----BEGIN CERTIFICATE-----\n" +
  "MIIBkTCB+wIJAKexample0123456789abcdefghijklmnopqrstuvwxyzABCDEFGH\n" +
  "-----END CERTIFICATE-----\n";

const PRIVKEY_BLOCK =
  "-----BEGIN OPENSSH PRIVATE KEY-----\n" +
  "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtz\n" +
  "-----END OPENSSH PRIVATE KEY-----\n";

// ---------------------------------------------------------------------------
// Fix 1 — hardcoded-key-material fires on private blocks only
// ---------------------------------------------------------------------------

// The signal scans source code (SOURCE_EXTS), so the realistic shape of
// this FP is a PEM block embedded as a string constant in a .js/.py — a
// published public key pinned in source is normal, a private key pasted in
// source is the leak. Embed in a .js so the file is actually scanned.
test("hardcoded-key-material: a BEGIN PUBLIC KEY embedded in source is a MISS", () => {
  const tmp = mkTmp("crypto-pub-");
  try {
    fs.writeFileSync(path.join(tmp, "pubkey.js"),
      "const AUTOUPDATE_PUBKEY = `" + PUBKEY_BLOCK + "`;\nmodule.exports = { AUTOUPDATE_PUBKEY };\n");
    const r = cryptoCollector.collect({ cwd: tmp });
    assert.equal(r.signal_overrides["hardcoded-key-material"], "miss",
      "a public key pinned in source must not flip the secret-leak signal");
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("hardcoded-key-material: a BEGIN CERTIFICATE embedded in source is a MISS", () => {
  const tmp = mkTmp("crypto-cert-");
  try {
    fs.writeFileSync(path.join(tmp, "anchor.js"),
      "const BIMI_ANCHOR = `" + CERT_BLOCK + "`;\nmodule.exports = { BIMI_ANCHOR };\n");
    const r = cryptoCollector.collect({ cwd: tmp });
    assert.equal(r.signal_overrides["hardcoded-key-material"], "miss",
      "a certificate (public by design) must not flip the secret-leak signal");
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("hardcoded-key-material: a BEGIN PRIVATE KEY embedded in source still HITS", () => {
  const tmp = mkTmp("crypto-priv-");
  try {
    fs.writeFileSync(path.join(tmp, "leaked.js"),
      "const KEY = `" + PRIVKEY_BLOCK + "`;\nmodule.exports = { KEY };\n");
    const r = cryptoCollector.collect({ cwd: tmp });
    assert.equal(r.signal_overrides["hardcoded-key-material"], "hit",
      "an embedded private key must still fire the secret-leak signal");
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("hardcoded-key-material: a BEGIN-marker regex literal (key DETECTOR) is a MISS", () => {
  const tmp = mkTmp("crypto-detector-");
  try {
    // A redaction / DLP library tests strings against a private-key marker.
    // The marker is a detection pattern, not embedded key material.
    fs.writeFileSync(path.join(tmp, "redact.js"),
      'const RULES = [\n' +
      '  { test: (v) => typeof v === "string" && /-----BEGIN OPENSSH PRIVATE KEY-----/.test(v) },\n' +
      '  { test: (v) => typeof v === "string" && /-----BEGIN RSA PRIVATE KEY-----/.test(v) },\n' +
      '];\nmodule.exports = { RULES };\n');
    const r = cryptoCollector.collect({ cwd: tmp });
    assert.equal(r.signal_overrides["hardcoded-key-material"], "miss",
      "a BEGIN-marker regex literal with no body or END is a detector, not a leak");
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("hardcoded-key-material: a JSDoc placeholder marker is a MISS", () => {
  const tmp = mkTmp("crypto-jsdoc-");
  try {
    fs.writeFileSync(path.join(tmp, "mail.js"),
      '/**\n' +
      ' * @param {object} opts\n' +
      ' *   privateKeyPem:  "-----BEGIN PRIVATE KEY----- ..."\n' +
      ' */\nfunction sign(opts) { return opts; }\nmodule.exports = { sign };\n');
    const r = cryptoCollector.collect({ cwd: tmp });
    assert.equal(r.signal_overrides["hardcoded-key-material"], "miss",
      "an elided doc placeholder marker is not embedded key material");
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// Fix 2 — vendored-pqc-no-provenance recognizes vendor/MANIFEST.json
// ---------------------------------------------------------------------------

test("vendored-pqc-no-provenance: a vendor MANIFEST.json counts as provenance (MISS)", () => {
  const tmp = mkTmp("crypto-vendor-prov-");
  try {
    const vendor = path.join(tmp, "vendor");
    fs.mkdirSync(vendor, { recursive: true });
    fs.writeFileSync(path.join(vendor, "MANIFEST.json"), JSON.stringify({
      name: "kyber-ref", version: "1.0.0", source: "https://example/kyber", license: "MIT",
    }, null, 2));
    fs.writeFileSync(path.join(vendor, "kyber.js"), "// ml-kem reference impl\nmodule.exports = {};\n");
    const r = cryptoCollector.collect({ cwd: tmp });
    assert.equal(r.signal_overrides["vendored-pqc-no-provenance"], "miss",
      "a vendored PQC tree with a MANIFEST.json is documented");
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("vendored-pqc-no-provenance: a vendored PQC file with NO provenance still HITS", () => {
  const tmp = mkTmp("crypto-vendor-noprov-");
  try {
    const vendor = path.join(tmp, "vendor");
    fs.mkdirSync(vendor, { recursive: true });
    fs.writeFileSync(path.join(vendor, "kyber.js"), "// ml-kem reference impl\nmodule.exports = {};\n");
    const r = cryptoCollector.collect({ cwd: tmp });
    assert.equal(r.signal_overrides["vendored-pqc-no-provenance"], "hit",
      "a vendored PQC tree with no provenance marker must still fire");
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});
});
