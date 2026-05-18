"use strict";

/**
 * tests/doctor-consumer-install-mode.test.js
 *
 * v0.13.13 regression pin for the consumer-install-aware signing check.
 *
 * Pre-fix: a fresh `npm install -g @blamejs/exceptd-skills` printed
 * `[!! warn] attestation signing: private key MISSING` and counted
 * one warning in the JSON summary. That nudge made sense for a
 * contributor checkout (where the operator is expected to generate
 * a keypair and sign skills) but read as a problem for a consumer
 * install where signing is intentionally not enabled — consumers
 * verify shipped signatures, they do not generate new ones.
 *
 * Post-fix: doctor detects PKG_ROOT under node_modules/ and reports
 * the absent-key state as severity:info (with the explanatory hint)
 * on a consumer install, while keeping severity:warn for contributor
 * checkouts. The bucketing logic from v0.13.11 then routes consumer
 * installs to neither warnings nor errors — `all_green: true`.
 *
 * Test approach: shell out to the doctor verb with the working
 * directory inside a fixture tree that mimics each shape, and pin
 * the install_mode + severity + bucket placement.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const os = require("node:os");
const { spawnSync } = require("node:child_process");

const ROOT = path.join(__dirname, "..");
const CLI = path.join(ROOT, "bin", "exceptd.js");

test("doctor: contributor checkout sets install_mode=contributor", () => {
  // Running the in-repo CLI is a contributor checkout — PKG_ROOT is the
  // repo root, NOT under node_modules/. install_mode must reflect that.
  const r = spawnSync(process.execPath, [CLI, "doctor", "--json"], {
    encoding: "utf8",
    cwd: ROOT,
    env: { ...process.env, EXCEPTD_DEPRECATION_SHOWN: "1" },
  });
  const body = JSON.parse(r.stdout);
  assert.equal(body.checks.signing.install_mode, "contributor",
    "in-repo run must detect contributor install_mode");
});

test("doctor: contributor checkout WITH private key reports severity:info + warnings_count=0", () => {
  // The repo ships with .keys/private.pem (the maintainer's signing
  // key checked out in the working tree). Doctor must see the key and
  // report severity:info, with the check absent from both bucket lists.
  if (!fs.existsSync(path.join(ROOT, ".keys", "private.pem"))) {
    // Skip when running on a contributor checkout that doesn't have
    // the key — the next test exercises that path explicitly.
    return;
  }
  const r = spawnSync(process.execPath, [CLI, "doctor", "--json"], {
    encoding: "utf8",
    cwd: ROOT,
    env: { ...process.env, EXCEPTD_DEPRECATION_SHOWN: "1" },
  });
  const body = JSON.parse(r.stdout);
  assert.equal(body.checks.signing.severity, "info");
  assert.equal(body.checks.signing.private_key_present, true);
  assert.ok(!body.summary.warning_checks.includes("signing"));
  assert.ok(!body.summary.failed_checks.includes("signing"));
});

test("doctor: consumer install (PKG_ROOT under node_modules/) reports severity:info on missing key", () => {
  // Stage a fake "consumer install" layout: a temp dir with a
  // `node_modules/@blamejs/exceptd-skills/` shape. The doctor verb is
  // invoked via that shape's bin/exceptd.js so PKG_ROOT resolves to
  // the staged location.
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "exceptd-consumer-"));
  try {
    const pkg = path.join(tmp, "node_modules", "@blamejs", "exceptd-skills");
    fs.mkdirSync(pkg, { recursive: true });
    // Stage the repo tree at the consumer-install path. bin/ MUST be
    // copied (not symlinked) — Node resolves __dirname through symlinks,
    // so a symlinked bin/exceptd.js would compute PKG_ROOT against the
    // REAL repo, not the staged location, defeating the test. The rest
    // of the tree can symlink for speed.
    const SYMLINK_OK = new Set([
      "data", "lib", "orchestrator", "scripts", "sources", "vendor", "skills", "agents", "keys",
      "AGENTS.md", "ARCHITECTURE.md", "CHANGELOG.md", "CONTEXT.md",
      "LICENSE", "NOTICE", "README.md", "SECURITY.md",
      "manifest.json", "manifest-snapshot.json", "manifest-snapshot.sha256", "sbom.cdx.json",
      "package.json",
    ]);
    for (const rel of fs.readdirSync(ROOT)) {
      if (rel === ".keys" || rel === ".git" || rel === "node_modules") continue;
      const src = path.join(ROOT, rel);
      const dst = path.join(pkg, rel);
      if (rel === "bin") {
        // Copy bin/ so __dirname resolves to the staged path.
        fs.cpSync(src, dst, { recursive: true });
      } else if (SYMLINK_OK.has(rel)) {
        try { fs.symlinkSync(src, dst, fs.statSync(src).isDirectory() ? "dir" : "file"); }
        catch { fs.cpSync(src, dst, { recursive: true }); }
      } else {
        // Unknown entry — copy to be safe.
        fs.cpSync(src, dst, { recursive: true });
      }
    }
    const stagedCli = path.join(pkg, "bin", "exceptd.js");
    const r = spawnSync(process.execPath, [stagedCli, "doctor", "--json"], {
      encoding: "utf8",
      cwd: tmp,
      env: { ...process.env, EXCEPTD_DEPRECATION_SHOWN: "1" },
    });
    const body = JSON.parse(r.stdout);
    assert.equal(body.checks.signing.install_mode, "consumer",
      "PKG_ROOT under node_modules/ must detect consumer install_mode");
    assert.equal(body.checks.signing.private_key_present, false);
    assert.equal(body.checks.signing.severity, "info",
      "consumer install with absent key must be severity:info, not :warn");
    // Bucket placement: not in warning_checks, not in failed_checks.
    assert.ok(!body.summary.warning_checks.includes("signing"),
      "consumer install signing check must NOT route to warning_checks");
    assert.ok(!body.summary.failed_checks.includes("signing"),
      "consumer install signing check must NOT route to failed_checks");
    // Hint must explain why signing isn't enabled.
    assert.match(body.checks.signing.hint, /consumer install/i,
      "consumer-install hint must be operator-readable");
  } finally {
    try { fs.rmSync(tmp, { recursive: true, force: true }); } catch { /* best effort */ }
  }
});
