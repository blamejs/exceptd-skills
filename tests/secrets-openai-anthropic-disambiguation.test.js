"use strict";

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
