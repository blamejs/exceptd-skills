"use strict";

/**
 * Async CLI entry points must turn an unexpected throw into the single-line
 * {ok:false,...,error} envelope the verb documents, never a raw V8 stack
 * trace. Three spawned subcommands wrap their whole body in an async IIFE /
 * call; a corrupt data file or a write failure used to reject with no handler,
 * which Node terminates as an unhandled rejection (exit 1 + stack trace) on the
 * pinned engine. These pin the envelope + a deterministic exit code instead.
 *
 * Also pins two CLI-surface guards on bin/exceptd.js:
 *   - `ci --max-rwep` with a forgotten value errors (it used to coerce to a
 *     cap of 1 and silently fail nearly every run).
 *   - collect failure bodies do not advertise an exit_code that disagrees with
 *     the real process exit.
 *
 * Discipline: exact exit codes; every field-presence assertion paired with a
 * content-shape assertion; all writes confined to os.tmpdir().
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const ROOT = path.join(__dirname, "..");
const CLI = path.join(ROOT, "bin", "exceptd.js");
const CVE_CLI = path.join(ROOT, "lib", "cve-cli.js");
const RFC_CLI = path.join(ROOT, "lib", "rfc-cli.js");
const CURATION_CLI = path.join(ROOT, "lib", "cve-curation.js");

function tryJson(s) { try { return JSON.parse(s); } catch { return null; } }

function run(script, args, env) {
  return spawnSync(process.execPath, [script, ...args], {
    encoding: "utf8",
    env: { ...process.env, EXCEPTD_DEPRECATION_SHOWN: "1", EXCEPTD_UNSIGNED_WARNED: "1", EXCEPTD_RAW_JSON: "1", ...env },
  });
}

test("cve resolver emits {ok:false,verb:'cve',error} + exit 1 on a corrupt catalog (no raw crash)", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "cve-badcat-"));
  try {
    const bad = path.join(tmp, "cve-catalog.json");
    fs.writeFileSync(bad, "{ this is not valid json");
    // --air-gap keeps the resolver offline so the only failure is the catalog read.
    const r = run(CVE_CLI, ["CVE-2024-0001", "--json", "--air-gap"], { EXCEPTD_CVE_CATALOG: bad });
    assert.equal(r.status, 1);
    assert.equal(r.stdout.trim(), "", "no partial result must reach stdout on failure");
    const err = tryJson(r.stderr.trim());
    assert.ok(err, `stderr must be a parseable single-line envelope; got ${r.stderr.slice(0, 200)}`);
    assert.equal(err.ok, false);
    assert.equal(err.verb, "cve");
    assert.equal(typeof err.error, "string");
    assert.ok(err.error.length > 0);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("rfc resolver emits {ok:false,verb:'rfc',error} + exit 1 on a corrupt index (no raw crash)", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "rfc-badidx-"));
  try {
    const bad = path.join(tmp, "rfc-references.json");
    fs.writeFileSync(bad, "{ not json either");
    const r = run(RFC_CLI, ["9404", "--json", "--air-gap"], { EXCEPTD_RFC_INDEX: bad });
    assert.equal(r.status, 1);
    assert.equal(r.stdout.trim(), "", "no partial result must reach stdout on failure");
    const err = tryJson(r.stderr.trim());
    assert.ok(err, `stderr must be a parseable single-line envelope; got ${r.stderr.slice(0, 200)}`);
    assert.equal(err.ok, false);
    assert.equal(err.verb, "rfc");
    assert.equal(typeof err.error, "string");
    assert.ok(err.error.length > 0);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("cve-curation --apply emits {ok:false,verb:'refresh',mode:'cve-curation',error} when the catalog write fails", (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "curate-rofail-"));
  let denies = false;
  try {
    const catPath = path.join(dir, "cve-catalog.json");
    // A draft entry so curate reaches the apply/write path (not the
    // "not in catalog" early return).
    fs.writeFileSync(catPath, JSON.stringify({
      "CVE-2099-0001": { name: "fixture draft", _draft: true, _auto_imported: true },
    }));
    const answersPath = path.join(dir, "answers.json");
    fs.writeFileSync(answersPath, JSON.stringify({ rwep_notes: "fixture" }));

    // Deny writes by making the catalog directory read-only, then PROBE: on
    // some platforms (Windows) a read-only directory still permits file
    // creation, so the write would succeed and there is nothing to assert.
    try { fs.chmodSync(dir, 0o555); } catch { /* chmod unsupported */ }
    const probe = path.join(dir, ".probe.tmp");
    try { const fd = fs.openSync(probe, "w"); fs.closeSync(fd); fs.unlinkSync(probe); }
    catch { denies = true; }
    if (!denies) { t.skip("read-only directory does not deny writes on this platform"); return; }

    const r = run(CURATION_CLI, ["--curate", "CVE-2099-0001", "--answers", answersPath, "--apply", "--catalog", catPath, "--json"]);
    // A write failure must not crash with a raw stack trace; the entry-point
    // .catch() turns it into the structured envelope and exit 2 — the same
    // code every in-cli() ok:false path sets.
    assert.equal(r.status, 2);
    const env = tryJson(r.stdout.trim()) || tryJson(r.stderr.trim());
    assert.ok(env, `expected a parseable envelope; stdout=${r.stdout.slice(0, 200)} stderr=${r.stderr.slice(0, 200)}`);
    assert.equal(env.ok, false);
    assert.equal(env.verb, "refresh");
    assert.equal(typeof env.error, "string");
    assert.ok(env.error.length > 0);
  } finally {
    try { fs.chmodSync(dir, 0o755); } catch {}
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("ci --max-rwep with a forgotten value errors instead of silently capping at 1", () => {
  const r = run(CLI, ["ci", "secrets", "--max-rwep"], {});
  assert.equal(r.status, 1);
  const err = tryJson(r.stderr.trim());
  assert.ok(err, `stderr must be a parseable envelope; got ${r.stderr.slice(0, 200)}`);
  assert.equal(err.ok, false);
  assert.equal(err.verb, "ci");
  assert.match(err.error, /--max-rwep/);
});

test("ci --max-rwep with a real numeric value is accepted (the guard rejects only the missing value)", () => {
  // A generous cap that nothing exceeds → the run is not blocked by the cap.
  const r = run(CLI, ["ci", "secrets", "--max-rwep", "100"], {});
  // Exit is one of the documented ci codes (0 PASS / 2 FAIL / 3 NO_EVIDENCE),
  // never the missing-value usage error (1).
  assert.ok([0, 2, 3].includes(r.status), `unexpected ci exit ${r.status}: ${r.stderr.slice(0, 200)}`);
});

test("collect failure body does not advertise an exit_code that disagrees with the real process exit", () => {
  // An unknown collector is the one cmdCollect failure path that ships a body;
  // its advertised exit_code must equal the real process exit.
  const r = run(CLI, ["collect", "this-collector-does-not-exist"], {});
  assert.equal(r.status, 1);
  const err = tryJson(r.stderr.trim());
  assert.ok(err, `stderr must be parseable JSON; got ${r.stderr.slice(0, 200)}`);
  assert.equal(err.ok, false);
  // If the body carries an exit_code field at all, it must match the actual exit.
  if (err.exit_code !== undefined) {
    assert.equal(err.exit_code, r.status, "advertised exit_code must equal the real process exit");
  }
});
