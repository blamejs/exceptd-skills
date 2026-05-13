#!/usr/bin/env node
"use strict";

/**
 * scripts/verify-shipped-tarball.js
 *
 * Pack the package with `npm pack`, extract the tarball to a temp dir,
 * then run lib/verify.js against the EXTRACTED tree (not the source
 * working tree). This catches the class of bug where:
 *
 *   - CI's verify step against the source tree passes (38/38)
 *   - The tarball that npm publish actually uploads has different
 *     content (e.g. keys/public.pem swapped) and verify-on-tarball fails
 *
 * Every release v0.11.x through v0.12.2 shipped a tarball whose
 * keys/public.pem did not match the Ed25519 signatures in manifest.json.
 * Operators installing from npm saw 0/38 verify on every fresh install.
 * The bug was invisible because CI's verify ran against the SOURCE tree,
 * not the shipped tarball. This gate closes that gap.
 *
 * Exit codes:
 *   0  verify passed against the packed tarball
 *   1  verify failed against the packed tarball (the bug class above)
 *   2  pack or extract failed (infrastructure error)
 *
 * Zero npm deps. Node 24 stdlib only.
 */

const fs = require("fs");
const path = require("path");
const os = require("os");
const { spawnSync } = require("child_process");

const ROOT = path.resolve(__dirname, "..");

function emit(msg) { process.stdout.write(`[verify-shipped-tarball] ${msg}\n`); }
function fail(msg, code = 1) {
  process.stderr.write(`[verify-shipped-tarball] FAIL: ${msg}\n`);
  process.exit(code);
}

const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "verify-shipped-"));
try {
  emit(`packing into ${tmpRoot} ...`);
  const pack = spawnSync("npm", ["pack", "--pack-destination", tmpRoot], {
    cwd: ROOT,
    encoding: "utf8",
    shell: process.platform === "win32",
  });
  if (pack.status !== 0) {
    fail(`npm pack failed (exit ${pack.status}): ${pack.stderr || pack.stdout}`, 2);
  }
  const tarballName = pack.stdout.trim().split(/\r?\n/).filter(Boolean).pop();
  const tarballPath = path.join(tmpRoot, tarballName);
  if (!fs.existsSync(tarballPath)) fail(`expected tarball at ${tarballPath}, not found`, 2);
  emit(`tarball: ${tarballPath} (${fs.statSync(tarballPath).size} bytes)`);

  // Extract via Node — bypasses GNU tar's "C:..." path quirk on Windows
  // where it interprets the colon as a remote-host separator.
  const extractDir = path.join(tmpRoot, "extract");
  fs.mkdirSync(extractDir, { recursive: true });
  const zlib = require("zlib");
  const { parseTar } = require(path.join(ROOT, "lib", "refresh-network.js"));
  const tgz = fs.readFileSync(tarballPath);
  const tarBuf = zlib.gunzipSync(tgz);
  const entries = parseTar(tarBuf);
  for (const e of entries) {
    if (!e.name) continue;
    const dst = path.join(extractDir, e.name);
    fs.mkdirSync(path.dirname(dst), { recursive: true });
    fs.writeFileSync(dst, e.body);
  }

  const pkgRoot = path.join(extractDir, "package");
  if (!fs.existsSync(path.join(pkgRoot, "lib", "verify.js"))) {
    fail(`extracted tree missing lib/verify.js at ${pkgRoot}`, 2);
  }
  emit(`extracted to ${pkgRoot}`);

  // Run the verifier inline against the extracted package tree. This avoids
  // having to spawn a separate process whose cwd resolution differs across
  // platforms.
  const crypto = require("crypto");
  const manifestPath = path.join(pkgRoot, "manifest.json");
  const pubKeyPath = path.join(pkgRoot, "keys", "public.pem");
  if (!fs.existsSync(manifestPath)) fail(`extracted tree missing manifest.json`, 2);
  if (!fs.existsSync(pubKeyPath)) fail(`extracted tree missing keys/public.pem`, 2);

  const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
  const pubPem = fs.readFileSync(pubKeyPath, "utf8");
  const pubKey = crypto.createPublicKey(pubPem);
  const pubFp = crypto.createHash("sha256")
    .update(pubKey.export({ type: "spki", format: "der" }))
    .digest("base64");

  // Compute the same fingerprint for the SOURCE-tree public.pem so the log
  // shows the divergence explicitly.
  const sourcePubPem = fs.readFileSync(path.join(ROOT, "keys", "public.pem"), "utf8");
  const sourcePubKey = crypto.createPublicKey(sourcePubPem);
  const sourcePubFp = crypto.createHash("sha256")
    .update(sourcePubKey.export({ type: "spki", format: "der" }))
    .digest("base64");

  emit(`source-tree public.pem fingerprint: SHA256:${sourcePubFp}`);
  emit(`tarball     public.pem fingerprint: SHA256:${pubFp}`);
  if (pubFp !== sourcePubFp) {
    emit(`*** WARNING: tarball public.pem differs from source-tree public.pem ***`);
    emit(`*** Something between sign and pack is swapping the key. Verify will fail below. ***`);
  }

  let pass = 0, miss = 0, fail_count = 0;
  const failures = [];
  for (const s of (manifest.skills || [])) {
    const skillPath = path.join(pkgRoot, s.path);
    if (!fs.existsSync(skillPath)) {
      miss++;
      failures.push(`${s.name}: file not found at ${s.path}`);
      continue;
    }
    const content = fs.readFileSync(skillPath);
    const ok = crypto.verify(null, content, pubKey, Buffer.from(s.signature, "base64"));
    if (ok) pass++;
    else { fail_count++; failures.push(`${s.name}: signature did not verify`); }
  }

  const total = (manifest.skills || []).length;
  emit(`tarball verify result: ${pass}/${total} pass, ${fail_count} fail, ${miss} missing`);
  if (fail_count === 0 && miss === 0 && pass === total) {
    emit(`PASS — shipped tarball is internally consistent`);
    process.exit(0);
  }
  for (const f of failures.slice(0, 10)) emit(`  - ${f}`);
  if (failures.length > 10) emit(`  ... and ${failures.length - 10} more`);
  emit(`FAIL — shipped tarball would be broken on every fresh install. Refusing to publish.`);
  process.exit(1);
} finally {
  // Best-effort cleanup; leave on failure for diagnostics.
  if (process.exitCode === 0) {
    try { fs.rmSync(tmpRoot, { recursive: true, force: true }); } catch {}
  } else {
    emit(`temp dir preserved for inspection: ${tmpRoot}`);
  }
}
