"use strict";

/**
 * Regression suite for `attest verify --require-signed` (strict mode) and
 * `attest prune` (attestation GC).
 *
 * --require-signed is tested on a sig-stripped attestation so the result is
 * deterministic on both keyed (local) and keyless (CI) checkouts: an unsigned
 * attestation must fail under --require-signed (exit 1) but stay lenient
 * (exit 0) without it.
 *
 * Discipline: exact exit codes; value/type assertions paired with presence.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const { makeCli, tryJson } = require("./_helpers/cli");

function freshHome(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}
function findSig(home) {
  const stack = [home];
  while (stack.length) {
    const d = stack.pop();
    let ents;
    try { ents = fs.readdirSync(d, { withFileTypes: true }); } catch { continue; }
    for (const e of ents) {
      const full = path.join(d, e.name);
      if (e.isDirectory()) stack.push(full);
      else if (e.name === "attestation.json.sig") return full;
    }
  }
  return null;
}

test("attest verify --require-signed rejects an unsigned/stripped attestation; lenient verify matches the host's signing state", () => {
  const home = freshHome("exceptd-reqsigned-");
  const cli = makeCli(home);
  const env = { EXCEPTD_HOME: home };
  try {
    const run = cli(["run", "secrets", "--evidence", "-", "--session-id", "rs1"], { input: '{"artifacts":{},"signals":{}}', env });
    assert.equal(run.status, 0, `setup run failed: ${run.stderr.slice(0, 200)}`);
    // Was the attestation actually Ed25519-signed? (keyed local dev vs keyless
    // CI.) This determines whether stripping the sidecar is benign or tamper.
    const sig = findSig(home);
    let wasSigned = false;
    if (sig) { try { wasSigned = JSON.parse(fs.readFileSync(sig, "utf8")).algorithm === "Ed25519"; } catch { /* unsigned */ } }
    if (sig) fs.rmSync(sig, { force: true });

    const lenient = cli(["attest", "verify", "rs1", "--json"], { env });
    if (wasSigned) {
      // C-H1: stripping the sidecar of a signed attestation (a sig was
      // expected — signing key present) is now tamper-detected by default
      // verify, agreeing with reattest.
      assert.equal(lenient.status, 6, "stripping a SIGNED attestation's sidecar must be tamper (exit 6)");
    } else {
      // Keyless host: a missing sidecar with no signing key and no signed peer
      // is a genuinely-unsigned attestation — lenient verify stays benign.
      assert.equal(lenient.status, 0, "lenient verify of a genuinely-unsigned attestation exits 0");
    }

    const strict = cli(["attest", "verify", "rs1", "--require-signed", "--json"], { env });
    const body = tryJson(strict.stdout) || tryJson(strict.stderr);
    assert.ok(body && body.ok === false, "strict verify of an unsigned/stripped attestation must fail");
    if (wasSigned) {
      // Tamper detection (exit 6) precedes the --require-signed gate: a stripped
      // sidecar where one was expected is tamper, which is the stronger signal.
      assert.equal(strict.status, 6, "stripped signed sidecar under --require-signed is still tamper (exit 6)");
    } else {
      assert.equal(strict.status, 1, "--require-signed on a genuinely-unsigned attestation must exit 1");
      assert.equal(body.require_signed, true);
    }
  } finally {
    fs.rmSync(home, { recursive: true, force: true });
  }
});

test("attest verify --require-signed rejects a session with no attestation (empty)", () => {
  const home = freshHome("exceptd-reqsigned-empty-");
  const cli = makeCli(home);
  const env = { EXCEPTD_HOME: home };
  try {
    assert.equal(cli(["run", "secrets", "--evidence", "-", "--session-id", "rsE"], { input: "{}", env }).status, 0);
    // Delete the attestation JSON, leaving the session dir present — the
    // codex edge: [].every() is vacuously true, so this must NOT pass strict.
    const sig = findSig(home);
    if (sig) {
      const att = sig.replace(/\.sig$/, "");
      fs.rmSync(att, { force: true });
    }
    const strict = cli(["attest", "verify", "rsE", "--require-signed", "--json"], { env });
    assert.equal(strict.status, 1, "an empty session must fail --require-signed");
    const body = tryJson(strict.stdout) || tryJson(strict.stderr);
    assert.ok(body && body.ok === false && body.require_signed === true);
    assert.match(body.error, /no signed attestation present/);
  } finally {
    fs.rmSync(home, { recursive: true, force: true });
  }
});

test("attest prune --all-older-than previews with --dry-run, then deletes", () => {
  const home = freshHome("exceptd-prune-");
  const cli = makeCli(home);
  const env = { EXCEPTD_HOME: home };
  try {
    assert.equal(cli(["run", "secrets", "--evidence", "-", "--session-id", "p1"], { input: "{}", env }).status, 0);
    assert.equal(cli(["run", "crypto", "--evidence", "-", "--session-id", "p2"], { input: "{}", env }).status, 0);

    const dry = cli(["attest", "prune", "--all-older-than", "2099-01-01", "--dry-run", "--json"], { env });
    assert.equal(dry.status, 0);
    const dbody = tryJson(dry.stdout);
    assert.ok(dbody && dbody.dry_run === true);
    assert.equal(dbody.pruned_count, 2);
    // dry-run must NOT delete: list still shows them
    const listAfterDry = tryJson(cli(["attest", "list", "--json"], { env }).stdout);
    assert.equal(listAfterDry.count, 2, "dry-run must not delete");

    const real = cli(["attest", "prune", "--all-older-than", "2099-01-01", "--json"], { env });
    assert.equal(real.status, 0);
    const rbody = tryJson(real.stdout);
    assert.equal(rbody.dry_run, false);
    assert.equal(rbody.pruned_count, 2);
    const listAfter = tryJson(cli(["attest", "list", "--json"], { env }).stdout);
    assert.equal(listAfter.count, 0, "real prune must delete the aged sessions");
  } finally {
    fs.rmSync(home, { recursive: true, force: true });
  }
});

test("attest diff --against validates the id with the same gate as the primary sid", () => {
  const home = freshHome("exceptd-against-");
  const cli = makeCli(home);
  const env = { EXCEPTD_HOME: home };
  try {
    assert.equal(cli(["run", "secrets", "--evidence", "-", "--session-id", "d1"], { input: "{}", env }).status, 0);
    const r = cli(["attest", "diff", "d1", "--against", "../../etc/passwd", "--json"], { env });
    assert.equal(r.status, 1);
    const body = tryJson(r.stderr) || tryJson(r.stdout);
    assert.ok(body && body.ok === false);
    assert.match(body.error, /Invalid session-id/);
    assert.doesNotMatch(body.error, /no session dir found/);
  } finally {
    fs.rmSync(home, { recursive: true, force: true });
  }
});

test("attest prune requires --all-older-than", () => {
  const home = freshHome("exceptd-prune2-");
  const cli = makeCli(home);
  try {
    const r = cli(["attest", "prune", "--json"], { env: { EXCEPTD_HOME: home } });
    assert.equal(r.status, 1);
    const body = tryJson(r.stderr);
    assert.ok(body && body.ok === false);
    assert.match(body.error, /--all-older-than .* is required/);
  } finally {
    fs.rmSync(home, { recursive: true, force: true });
  }
});
