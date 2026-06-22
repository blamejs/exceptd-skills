"use strict";


// ---- routed from secrets-depth-cap-visibility ----
require("node:test").describe("secrets-depth-cap-visibility", () => {
const __t = require("node:test"); const __env = Object.assign({}, process.env);
__t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __env)) delete process.env[k]; Object.assign(process.env, __env);
  const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
/**
 * tests/secrets-depth-cap-visibility.test.js
 *
 * The secrets collector caps its tree walk at depth 6. A secret living in a
 * subtree deeper than the cap is never emitted and never scanned. Before this
 * fix that was a silent false negative: the unscanned deep file produced
 * `aws-access-key-id=miss` with `collector_errors=[]`, indistinguishable from
 * "scanned the whole tree and found nothing". Unlike the per-file size cap —
 * which records `file_too_large_skipped` so the operator knows a file went
 * unscanned — depth truncation recorded nothing.
 *
 * The collector now records a `depth_capped` collector_errors entry naming the
 * pruned subtree(s), so absence-of-scan is observable rather than reported as
 * absence-of-secret.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const os = require("node:os");

const ROOT = path.join(__dirname, "..");
const secrets = require(path.join(ROOT, "lib", "collectors", "secrets.js"));
const { walkTree } = require(path.join(ROOT, "lib", "collectors", "scan-excludes.js"));

function mkTmp(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

// A valid AWS access-key-id: AKIA followed by exactly 16 [0-9A-Z].
const DEEP_KEY = "AKIAQ7DEEPSECRET0001";

test("secrets: a subtree pruned at the depth cap records a depth_capped collector_errors entry", () => {
  const tmp = mkTmp("sec-depthcap-");
  try {
    // root/a/b/c/d/e/f/g/h/.env is at depth 8 — beyond the depth-6 cap.
    const deepDir = path.join(tmp, "a", "b", "c", "d", "e", "f", "g", "h");
    fs.mkdirSync(deepDir, { recursive: true });
    fs.writeFileSync(path.join(deepDir, ".env"), "aws_access_key_id=" + DEEP_KEY + "\n");

    const r = secrets.collect({ cwd: tmp });

    // The deep file is genuinely beyond reach of the default walk.
    assert.equal(r.signal_overrides["aws-access-key-id"], "miss",
      "the depth-8 secret is not scanned at the depth-6 cap (this is the gap)");

    // ...but the unscanned subtree is now OBSERVABLE, not silent.
    const depthCapped = r.collector_errors.filter((e) => e.kind === "depth_capped");
    assert.equal(depthCapped.length, 1,
      "exactly one depth_capped entry records the pruned subtree");
    assert.equal(typeof depthCapped[0].reason, "string");
    assert.ok(depthCapped[0].truncated_count >= 1,
      "truncated_count reports at least the one pruned subtree");
    assert.ok(Array.isArray(depthCapped[0].truncated_paths)
      && depthCapped[0].truncated_paths.length >= 1,
      "truncated_paths names the pruned subtree path(s)");
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("secrets: a fully shallow tree records NO depth_capped entry", () => {
  const tmp = mkTmp("sec-depthcap-shallow-");
  try {
    // Deepest file is at depth 6 (root/a/b/c/d/e/f/<file>) — within the cap.
    const d6 = path.join(tmp, "a", "b", "c", "d", "e", "f");
    fs.mkdirSync(d6, { recursive: true });
    fs.writeFileSync(path.join(d6, "config.env"), "aws_access_key_id=" + DEEP_KEY + "\n");

    const r = secrets.collect({ cwd: tmp });
    assert.equal(r.signal_overrides["aws-access-key-id"], "hit",
      "the depth-6 secret IS scanned and fires");
    assert.equal(r.collector_errors.filter((e) => e.kind === "depth_capped").length, 0,
      "no subtree was pruned, so no depth_capped notice");
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("walkTree: opts.truncations is appended with the pruned dir but the return value is unchanged", () => {
  const tmp = mkTmp("sec-walk-trunc-");
  try {
    const d7 = path.join(tmp, "a", "b", "c", "d", "e", "f", "g");
    fs.mkdirSync(d7, { recursive: true });
    fs.writeFileSync(path.join(d7, "deep.txt"), "x\n");
    fs.writeFileSync(path.join(tmp, "shallow.txt"), "y\n");

    const truncations = [];
    const files = walkTree(tmp, { maxDepth: 6, truncations });

    // Return value: only the in-cap file (shallow.txt at depth 0). deep.txt
    // at depth 7 is pruned.
    assert.ok(Array.isArray(files), "walkTree still returns a file array");
    assert.equal(files.some((f) => f.name === "deep.txt"), false,
      "the depth-7 file is not emitted");
    assert.equal(files.some((f) => f.name === "shallow.txt"), true,
      "the depth-0 file is emitted");

    // The pruned directory (a/b/c/d/e/f/g, the depth-7 dir whose contents are
    // dropped) is recorded.
    assert.ok(truncations.length >= 1, "the pruned directory is recorded in truncations");
    assert.equal(typeof truncations[0].rel, "string");
    assert.equal(truncations[0].rel, "a/b/c/d/e/f/g",
      "the recorded path is the forward-slash rel path of the pruned dir");
    assert.equal(truncations[0].depth, 7, "the recorded depth is the would-be descent depth");

    // Backward-compat: not passing truncations still works and never throws.
    const files2 = walkTree(tmp, { maxDepth: 6 });
    assert.ok(Array.isArray(files2));
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});
});


// ---- routed from secrets-openai-anthropic-disambiguation ----
require("node:test").describe("secrets-openai-anthropic-disambiguation", () => {
const __t = require("node:test"); const __env = Object.assign({}, process.env);
__t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __env)) delete process.env[k]; Object.assign(process.env, __env);
  const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
/**
 * tests/secrets-openai-anthropic-disambiguation.test.js
 *
 * Regression test for the secrets-collector openai-api-key pattern swallowing
 * Anthropic keys. The pattern carried a trailing empty alternative
 * (`(?:proj-|svcacct-|admin-|)`) that made the OpenAI prefix optional, so the
 * pattern reduced to `sk-<20+ chars>` and an Anthropic `sk-ant-api03-*` key
 * matched BOTH indicators — one credential double-firing as two, inflating the
 * hit count and mislabeling the vendor in signal_overrides.
 *
 * A `(?!ant-)` negative lookahead now keeps Anthropic keys out of the OpenAI
 * indicator while still admitting every real OpenAI shape (proj/svcacct/admin
 * prefixes and the bare legacy `sk-` key).
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

test("secrets: a single sk-ant-api03 key fires only anthropic, never openai", () => {
  const tmp = mkTmp("sec-vendor-");
  try {
    const k = "sk-ant-api03-" + "A".repeat(80);
    fs.writeFileSync(path.join(tmp, "config.js"), `const ANTHROPIC_KEY = "${k}";\n`);
    const r = secrets.collect({ cwd: tmp });
    const so = r.signal_overrides;
    assert.equal(so["anthropic-api-key"], "hit",
      "the Anthropic key must fire the anthropic indicator");
    assert.equal(so["openai-api-key"], "miss",
      "the Anthropic key must NOT also fire the openai indicator");
    assert.equal(so["openai-api-key__fp_checks"], undefined,
      "no openai __fp_checks attestation when openai did not fire");
    assert.equal(r.collector_meta.hits_total, 1,
      "one credential must yield exactly one hit, not two");
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("secrets: a real sk-proj OpenAI key still fires only openai", () => {
  const tmp = mkTmp("sec-vendor-");
  try {
    const k = "sk-proj-" + "B".repeat(80);
    fs.writeFileSync(path.join(tmp, "config.js"), `const OPENAI_KEY = "${k}";\n`);
    const r = secrets.collect({ cwd: tmp });
    const so = r.signal_overrides;
    assert.equal(so["openai-api-key"], "hit",
      "a real OpenAI project key must still fire the openai indicator");
    assert.equal(so["anthropic-api-key"], "miss",
      "an OpenAI key must NOT fire the anthropic indicator");
    assert.equal(r.collector_meta.hits_total, 1,
      "one credential must yield exactly one hit");
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("secrets: a bare legacy sk- OpenAI key still fires openai", () => {
  const tmp = mkTmp("sec-vendor-");
  try {
    const k = "sk-" + "C".repeat(48);
    fs.writeFileSync(path.join(tmp, "config.js"), `const OPENAI_KEY = "${k}";\n`);
    const r = secrets.collect({ cwd: tmp });
    const so = r.signal_overrides;
    assert.equal(so["openai-api-key"], "hit",
      "a bare legacy sk- OpenAI key must still fire the openai indicator");
    assert.equal(so["anthropic-api-key"], "miss",
      "a bare sk- key must NOT fire the anthropic indicator");
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});
});


// ---- routed from secrets-private-key-cert-fp ----
require("node:test").describe("secrets-private-key-cert-fp", () => {
const __t = require("node:test"); const __env = Object.assign({}, process.env);
__t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __env)) delete process.env[k]; Object.assign(process.env, __env);
  const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
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
});
