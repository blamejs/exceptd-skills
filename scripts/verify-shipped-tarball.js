#!/usr/bin/env node
"use strict";

/**
 * Packs with `npm pack`, extracts the tarball, and verifies the EXTRACTED tree
 * rather than the source working tree: a keys/public.pem swapped between sign
 * and pack surfaces nowhere else, and every fresh install then fails.
 *
 * Exit: 0 verified, 1 verify failed, 2 pack or extract failed.
 */

const fs = require("fs");
const path = require("path");
const os = require("os");
const { spawnSync } = require("child_process");

// Mirrors the normalize() contract in lib/sign.js, lib/verify.js and
// lib/refresh-network.js. Duplicated deliberately: one bug must not disable the
// source-tree and shipped-tarball checks together. Change all four together.
function normalizeSkillBytes(buf) {
  let s = Buffer.isBuffer(buf) ? buf.toString("utf8") : String(buf);
  if (s.length > 0 && s.charCodeAt(0) === 0xFEFF) s = s.slice(1);
  return Buffer.from(s.replace(/\r\n/g, "\n"), "utf8");
}

// Duplicated for the same reason as normalizeSkillBytes; the canonical-bytes
// computation stays in lockstep, enforced by tests/normalize-contract.test.js.
function canonicalizeForTarball(value) {
  if (Array.isArray(value)) return value.map(canonicalizeForTarball);
  if (value && typeof value === "object") {
    const out = {};
    for (const key of Object.keys(value).sort()) {
      out[key] = canonicalizeForTarball(value[key]);
    }
    return out;
  }
  return value;
}
function canonicalManifestBytesForTarball(manifest) {
  const clone = Object.assign({}, manifest);
  delete clone.manifest_signature;
  const json = JSON.stringify(canonicalizeForTarball(clone), null, 2);
  return normalizeSkillBytes(Buffer.from(json, "utf8"));
}
function verifyExtractedManifestSignature(manifest, publicKeyPem) {
  const cryptoMod = require("crypto");
  const sig = manifest && manifest.manifest_signature;
  if (!sig || typeof sig !== "object") return { status: "missing" };
  if (typeof sig.signature_base64 !== "string") {
    return { status: "invalid", reason: "manifest_signature.signature_base64 missing or not a string" };
  }
  if (sig.algorithm !== "Ed25519") {
    return { status: "invalid", reason: `manifest_signature.algorithm must be 'Ed25519' (got ${JSON.stringify(sig.algorithm)})` };
  }
  let signatureBytes;
  try { signatureBytes = Buffer.from(sig.signature_base64, "base64"); }
  catch (e) { return { status: "invalid", reason: `malformed base64: ${e.message}` }; }
  const bytes = canonicalManifestBytesForTarball(manifest);
  let ok = false;
  try {
    ok = cryptoMod.verify(null, bytes, {
      key: publicKeyPem,
      dsaEncoding: "ieee-p1363",
    }, signatureBytes);
  } catch (e) {
    return { status: "invalid", reason: `crypto.verify threw: ${e.message}` };
  }
  return ok ? { status: "valid" } : { status: "invalid", reason: "Ed25519 manifest signature did not verify against extracted public.pem" };
}

// One skill entry's outcome: { status: 'missing' | 'pass' | 'fail' }, plus a
// `reason` when the base64 is malformed or verify throws. A manifest entry may
// legally omit `signature`, so that case is a structured miss, not a throw.
function verifySkillSignatureOutcome(s, normalizedContent, pubKey) {
  const cryptoMod = require("crypto");
  if (typeof s.signature !== "string" || s.signature.length === 0) {
    return { status: "missing" };
  }
  let sigBytes;
  try {
    sigBytes = Buffer.from(s.signature, "base64");
  } catch (e) {
    return { status: "fail", reason: `malformed base64 signature: ${e.message}` };
  }
  let ok = false;
  try {
    ok = cryptoMod.verify(null, normalizedContent, pubKey, sigBytes);
  } catch (e) {
    return { status: "fail", reason: `crypto.verify threw: ${e.message}` };
  }
  return ok ? { status: "pass" } : { status: "fail" };
}

module.exports = {
  normalizeSkillBytes,
  verifyExtractedManifestSignature,
  canonicalManifestBytesForTarball,
  verifySkillSignatureOutcome,
};

const ROOT = path.resolve(__dirname, "..");

function emit(msg) { process.stdout.write(`[verify-shipped-tarball] ${msg}\n`); }
// Sentinel thrown by fail() so the body's finally still runs its temp-dir
// cleanup — process.exit() would preempt it and leak the npm-pack temp dir.
const ABORT = Symbol("verify-shipped-tarball:abort");
function fail(msg, code = 1) {
  process.stderr.write(`[verify-shipped-tarball] FAIL: ${msg}\n`);
  process.exitCode = code;
  throw ABORT;
}

// Gated on require.main so a test can require() the helpers without npm pack running.
if (require.main !== module) {
  return;
}

const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "verify-shipped-"));
try {
  emit(`packing into ${tmpRoot} ...`);
  // --offline: predeploy must run without registry reachability.
  const pack = spawnSync("npm", ["pack", "--offline", "--pack-destination", tmpRoot], {
    cwd: ROOT,
    encoding: "utf8",
    shell: process.platform === "win32",
  });
  if (pack.status !== 0) {
    fail(`npm pack failed (exit ${pack.status}): ${pack.stderr || pack.stdout}`, 2);
  }
  const tarballName = pack.stdout.trim().split(/\r?\n/).filter(Boolean).pop();
  const tarballPath = path.join(tmpRoot, tarballName);
  // One descriptor for fstat + read, so both observe the same inode — no TOCTOU.
  let tgz;
  try {
    const fd = fs.openSync(tarballPath, "r");
    try {
      const st = fs.fstatSync(fd);
      emit(`tarball: ${tarballPath} (${st.size} bytes)`);
      tgz = Buffer.alloc(st.size);
      fs.readSync(fd, tgz, 0, st.size, 0);
    } finally { fs.closeSync(fd); }
  } catch (e) {
    fail(`expected tarball at ${tarballPath}: ${e.message}`, 2);
  }

  // Extract via Node — bypasses GNU tar's "C:..." path quirk on Windows
  // where it interprets the colon as a remote-host separator.
  const extractDir = path.join(tmpRoot, "extract");
  fs.mkdirSync(extractDir, { recursive: true });
  const zlib = require("zlib");
  const { parseTar: parseTarSource } = require(path.join(ROOT, "lib", "refresh-network.js"));
  const tarBuf = zlib.gunzipSync(tgz);
  const entries = parseTarSource(tarBuf);
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

  // Re-parse with the extracted tree's OWN parseTar: a divergence means CI
  // exercised a different extractor than operators will run.
  const shippedParserPath = path.join(pkgRoot, "lib", "refresh-network.js");
  if (!fs.existsSync(shippedParserPath)) {
    fail(`extracted tree missing lib/refresh-network.js (cannot run F9 cross-parse check)`, 2);
  }
  let parseTarShipped;
  try {
    parseTarShipped = require(shippedParserPath).parseTar;
  } catch (e) {
    fail(`failed to load extracted parseTar: ${e.message}`, 2);
  }
  if (typeof parseTarShipped !== "function") {
    fail(`extracted lib/refresh-network.js does not export parseTar`, 2);
  }
  const shippedEntries = parseTarShipped(tarBuf);
  const divergences = [];
  if (shippedEntries.length !== entries.length) {
    divergences.push(
      `entry count divergence: source-tree parser produced ${entries.length}, ` +
      `shipped parser produced ${shippedEntries.length}`
    );
  } else {
    // Tarball entry order is deterministic, so a positional compare is valid.
    for (let i = 0; i < entries.length; i++) {
      const a = entries[i];
      const b = shippedEntries[i];
      if (a.name !== b.name) {
        divergences.push(`entry[${i}] name mismatch: source=${a.name} shipped=${b.name}`);
        continue;
      }
      const aBuf = Buffer.isBuffer(a.body) ? a.body : Buffer.from(a.body);
      const bBuf = Buffer.isBuffer(b.body) ? b.body : Buffer.from(b.body);
      if (aBuf.length !== bBuf.length || !aBuf.equals(bBuf)) {
        divergences.push(
          `entry[${i}] (${a.name}) body bytes differ between source-tree and shipped parser ` +
          `(source ${aBuf.length} bytes vs shipped ${bBuf.length} bytes)`
        );
      }
    }
  }
  if (divergences.length > 0) {
    emit(`*** F9: parseTar divergence between source-tree and shipped tree ***`);
    for (const d of divergences.slice(0, 5)) emit(`  - ${d}`);
    if (divergences.length > 5) emit(`  ... and ${divergences.length - 5} more`);
    fail(
      `parseTar implementations diverge between source tree and shipped tarball. ` +
      `Operators will run a different extractor than CI exercised. Refusing to publish.`,
      1
    );
  }
  emit(`F9: source-tree and shipped parseTar agree on ${entries.length} entries`);

  // Inline rather than spawned: cwd resolution differs across platforms.
  const crypto = require("crypto");
  const manifestPath = path.join(pkgRoot, "manifest.json");
  const pubKeyPath = path.join(pkgRoot, "keys", "public.pem");
  if (!fs.existsSync(manifestPath)) fail(`extracted tree missing manifest.json`, 2);
  if (!fs.existsSync(pubKeyPath)) fail(`extracted tree missing keys/public.pem`, 2);

  const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
  const pubPem = fs.readFileSync(pubKeyPath, "utf8");
  const pubKey = crypto.createPublicKey(pubPem);

  // Per-skill signatures cover only the skill body bytes, not skill.name or
  // skill.path — a rewritten manifest envelope still passes per-skill verify.
  // A missing envelope signature is a refusal here, not a warning.
  const manifestSigStatus = verifyExtractedManifestSignature(manifest, pubPem);
  if (manifestSigStatus.status !== "valid") {
    fail(
      `tarball manifest_signature ${manifestSigStatus.status} — refusing to publish. ` +
      `reason=${manifestSigStatus.reason || "(none)"}`,
      1
    );
  }
  emit(`manifest envelope signature: valid (Ed25519, signed by extracted public.pem)`);
  const pubFp = crypto.createHash("sha256")
    .update(pubKey.export({ type: "spki", format: "der" }))
    .digest("base64");

  // The same fingerprint for the SOURCE-tree key, so the log names the drift.
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

  // The pin is read from the EXTRACTED tree — the file operators receive on
  // install. Absent warns; mismatched fails unless KEYS_ROTATED=1.
  const expectedFpPath = path.join(pkgRoot, "keys", "EXPECTED_FINGERPRINT");
  if (fs.existsSync(expectedFpPath)) {
    // The shared loader strips a leading U+FEFF, so a BOM-prefixed pin is tolerated.
    const { loadExpectedFingerprintFirstLine } = require(path.join(ROOT, "lib", "verify.js"));
    const firstLine = loadExpectedFingerprintFirstLine(expectedFpPath) || "";
    const liveFpLine = `SHA256:${pubFp}`;
    if (firstLine !== liveFpLine) {
      if (process.env.KEYS_ROTATED === "1") {
        // Also on the structured warning channel, so a listener observes it.
        process.emitWarning(
          `extracted public.pem fingerprint ${liveFpLine} differs from pin ${firstLine}; KEYS_ROTATED=1 accepted. ` +
          `Update keys/EXPECTED_FINGERPRINT to lock the new pin.`,
          { code: "EXCEPTD_KEYS_ROTATED_OVERRIDE" }
        );
        emit(`WARN: extracted public.pem fingerprint ${liveFpLine} differs from pin ${firstLine}; KEYS_ROTATED=1 accepted`);
      } else {
        fail(
          `keys/EXPECTED_FINGERPRINT (${firstLine}) does not match the extracted ` +
          `public.pem fingerprint (${liveFpLine}). If this is an intentional rotation ` +
          `set KEYS_ROTATED=1 and commit the new pin.`,
          1
        );
      }
    } else {
      emit(`F4: key pin verified — ${liveFpLine} matches keys/EXPECTED_FINGERPRINT`);
    }
  } else {
    emit(`WARN: keys/EXPECTED_FINGERPRINT not in extracted tree — key-pin check skipped`);
  }

  let pass = 0, miss = 0, fail_count = 0;
  const failures = [];
  for (const s of (manifest.skills || [])) {
    const skillPath = path.join(pkgRoot, s.path);
    const sourceSkillPath = path.join(ROOT, s.path);
    if (!fs.existsSync(skillPath)) {
      miss++;
      failures.push(`${s.name}: file not found at ${s.path}`);
      continue;
    }
    // Normalize before verify: lib/sign.js signs BOM-stripped, LF-normalized
    // bytes, so feeding raw bytes here reports 0/N wherever line endings changed
    // between sign and pack (`core.autocrlf=true`).
    const rawContent = fs.readFileSync(skillPath);
    const normalizedContent = normalizeSkillBytes(rawContent);
    const outcome = verifySkillSignatureOutcome(s, normalizedContent, pubKey);
    if (outcome.status === "missing") {
      miss++;
      failures.push(`${s.name}: no Ed25519 signature in manifest`);
      continue;
    }
    const ok = outcome.status === "pass";
    if (ok) pass++;
    else {
      fail_count++;
      // Sizes come from rawContent so an operator sees the on-disk shape, but
      // the hashes cover the NORMALIZED bytes actually fed to crypto.verify.
      const tarSha = crypto.createHash("sha256").update(normalizedContent).digest("hex").slice(0, 16);
      let srcSha = "<missing>", srcSize = 0, srcContent;
      if (fs.existsSync(sourceSkillPath)) {
        srcContent = fs.readFileSync(sourceSkillPath);
        srcSize = srcContent.length;
        srcSha = crypto.createHash("sha256").update(normalizeSkillBytes(srcContent)).digest("hex").slice(0, 16);
      }
      const equal = srcContent && rawContent.equals(srcContent) ? "equal" : "DIFFER";
      const reasonSuffix = outcome.reason ? ` [${outcome.reason}]` : "";
      failures.push(`${s.name}: signature did not verify${reasonSuffix} (tarball size=${rawContent.length} sha-normalized=${tarSha}; source size=${srcSize} sha-normalized=${srcSha}; raw bytes ${equal})`);
    }
  }

  const total = (manifest.skills || []).length;
  emit(`tarball verify result: ${pass}/${total} pass, ${fail_count} fail, ${miss} missing`);
  if (fail_count === 0 && miss === 0 && pass === total) {
    emit(`PASS — shipped tarball is internally consistent`);
    process.exitCode = 0;
  } else {
    for (const f of failures.slice(0, 10)) emit(`  - ${f}`);
    if (failures.length > 10) emit(`  ... and ${failures.length - 10} more`);
    emit(`FAIL — shipped tarball would be broken on every fresh install. Refusing to publish.`);
    process.exitCode = 1;
  }
} catch (e) {
  // ABORT is the fail() sentinel; any other error re-propagates after finally.
  if (e !== ABORT) throw e;
} finally {
  // Best-effort cleanup; leave on failure for diagnostics.
  if (process.exitCode === 0 || process.exitCode === undefined) {
    try { fs.rmSync(tmpRoot, { recursive: true, force: true }); } catch {}
  } else {
    emit(`temp dir preserved for inspection: ${tmpRoot}`);
  }
}
