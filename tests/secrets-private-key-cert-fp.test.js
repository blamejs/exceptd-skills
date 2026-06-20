"use strict";

/**
 * tests/secrets-private-key-cert-fp.test.js
 *
 * Regression tests for two secrets-collector false positives in the
 * `ssh-private-key-block` signal, surfaced by scanning repositories that
 * ship public keys and use redaction libraries:
 *
 *   1. Content scan: a bare `BEGIN ... PRIVATE KEY` header with no body —
 *      a redaction/DLP library's regex literal, or a doc placeholder — is a
 *      detection pattern, not embedded key material. A complete block
 *      (header + base64 body + closing marker) is now required.
 *
 *   2. File classification: a `.pem` certificate chain (`fullchain.pem`) or
 *      a public trust anchor (`bimi-trust-anchors.pem`) is conventionally
 *      `.pem` but carries no private key. It must not classify as an SSH
 *      private-key file. A `.pem` / `.key` is treated as a private key only
 *      when its content actually contains a `PRIVATE KEY` block.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const os = require("node:os");

const ROOT = path.join(__dirname, "..");
const secrets = require(path.join(ROOT, "lib", "collectors", "secrets.js"));

function mkTmp(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

const PRIV_BODY =
  "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDexampleexample\n" +
  "exampleexampleexampleexampleexampleexampleexampleexampleexampleAA==";
const FULL_PRIV = "-----BEGIN PRIVATE KEY-----\n" + PRIV_BODY + "\n-----END PRIVATE KEY-----\n";
const CERT_PEM =
  "-----BEGIN CERTIFICATE-----\n" +
  "MIIBkTCB+wIJAKexample0123456789abcdefghijklmnopqrstuvwxyzABCDEFGH\n" +
  "-----END CERTIFICATE-----\n";

// ---------------------------------------------------------------------------
// Content-scan detection patterns
// ---------------------------------------------------------------------------

test("ssh-private-key-block: a BEGIN-marker regex literal in source is a MISS", () => {
  const tmp = mkTmp("sec-detector-");
  try {
    fs.writeFileSync(path.join(tmp, "redact.js"),
      'const RULE = (v) => /-----BEGIN OPENSSH PRIVATE KEY-----/.test(v);\nmodule.exports = { RULE };\n');
    const r = secrets.collect({ cwd: tmp });
    assert.equal(r.signal_overrides["ssh-private-key-block"], "miss",
      "a bare key-header regex literal is a detector, not embedded key material");
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("ssh-private-key-block: a full private-key block embedded in source still HITS", () => {
  const tmp = mkTmp("sec-embedded-");
  try {
    fs.writeFileSync(path.join(tmp, "config.js"), "const KEY = `" + FULL_PRIV + "`;\nmodule.exports = { KEY };\n");
    const r = secrets.collect({ cwd: tmp });
    assert.equal(r.signal_overrides["ssh-private-key-block"], "hit",
      "a complete private-key block pasted into source must still fire");
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// File classification — public .pem vs private .pem/.key
// ---------------------------------------------------------------------------

test("ssh-private-key-block: a .pem certificate chain is a MISS", () => {
  const tmp = mkTmp("sec-cert-");
  try {
    fs.writeFileSync(path.join(tmp, "fullchain.pem"), CERT_PEM + CERT_PEM);
    const r = secrets.collect({ cwd: tmp });
    assert.equal(r.signal_overrides["ssh-private-key-block"], "miss",
      "a certificate chain carries no private key and must not classify as one");
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("ssh-private-key-block: a public trust-anchor .pem is a MISS", () => {
  const tmp = mkTmp("sec-anchor-");
  try {
    fs.writeFileSync(path.join(tmp, "bimi-trust-anchors.pem"), CERT_PEM);
    const r = secrets.collect({ cwd: tmp });
    assert.equal(r.signal_overrides["ssh-private-key-block"], "miss",
      "a published trust anchor must not classify as a private key");
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("ssh-private-key-block: a .pem that actually carries a private key still HITS", () => {
  const tmp = mkTmp("sec-privpem-");
  try {
    fs.writeFileSync(path.join(tmp, "privkey.pem"), FULL_PRIV);
    const r = secrets.collect({ cwd: tmp });
    assert.equal(r.signal_overrides["ssh-private-key-block"], "hit",
      "a .pem holding a real private key must still fire");
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("ssh-private-key-block: a .key holding a real private key still HITS", () => {
  const tmp = mkTmp("sec-privkey-");
  try {
    fs.writeFileSync(path.join(tmp, "server.key"), FULL_PRIV);
    const r = secrets.collect({ cwd: tmp });
    assert.equal(r.signal_overrides["ssh-private-key-block"], "hit",
      "a .key holding a real private key must still fire");
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// Short-read robustness — carriesPrivateKey must read the whole file, not just
// whatever the first read() returns. A partial read on a network / FUSE /
// interrupted descriptor can return fewer bytes than requested; if the BEGIN
// marker sits past that boundary (a .pem with a leading `Bag Attributes` /
// subject= header — the default OpenSSL pkcs12→PEM layout), classifying off a
// truncated buffer would mis-label a real private key as "no key" and silently
// drop the leak from the findings.
// ---------------------------------------------------------------------------

test("ssh-private-key-block: a .pem with the BEGIN marker past a short-read boundary still HITS", () => {
  const tmp = mkTmp("sec-shortread-");
  // Leading header block (OpenSSL pkcs12→PEM default) pushes BEGIN well past a
  // plausible short-read length, so a single truncated read() would miss it.
  const HEADER =
    "Bag Attributes\n" +
    "    localKeyID: 01 00 00 00\n" +
    "    friendlyName: deploy-svc-account\n" +
    "subject=/CN=deploy.internal\n" +
    "issuer=/CN=Internal CA\n";
  const realReadSync = fs.readSync;
  try {
    fs.writeFileSync(path.join(tmp, "deploy.pem"), HEADER + FULL_PRIV);
    const beginOffset = (HEADER + FULL_PRIV).indexOf("-----BEGIN");
    assert.ok(beginOffset > 64,
      "test fixture must place BEGIN past the simulated short-read boundary");
    // Force every readSync to return at most 64 bytes — a short read that stops
    // before the BEGIN marker. The fix reads to EOF, so this must not matter.
    fs.readSync = function (fd, buf, off, len, pos) {
      return realReadSync(fd, buf, off, Math.min(64, len), pos);
    };
    const r = secrets.collect({ cwd: tmp });
    assert.equal(r.signal_overrides["ssh-private-key-block"], "hit",
      "a real private key whose BEGIN marker falls past a short read must still fire");
    assert.ok(
      /deploy\.pem/.test(r.artifacts["ssh-private-keys"].value),
      "the leaked key file must appear in the ssh-private-keys artifact");
  } finally {
    fs.readSync = realReadSync;
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});
