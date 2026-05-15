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
 * *   F9  — After the first-pass extraction (using the source-tree parseTar),
 *         re-parse the tarball using the parseTar shipped INSIDE the
 *         extracted tree itself. If the two parses disagree, fail with a
 *         structured error. Catches the class where the shipped parser
 *         silently rejects entries the source parser accepts (or vice
 *         versa), which would mean operators run a different extractor
 *         than CI exercised.
 *   F15 — Invoke `npm pack --offline` so the gate cannot be blocked by
 *         registry reachability problems during predeploy.
 *   F4  — Cross-check the extracted public.pem against
 *         keys/EXPECTED_FINGERPRINT (warn-and-continue when missing, fail
 *         when present-but-mismatched and KEYS_ROTATED != 1).
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

// v0.12.16: mirror the byte-stability normalize() contract
// from lib/sign.js + lib/verify.js + lib/refresh-network.js. Duplicated
// (not require'd) to keep this script's dep surface minimal and to ensure
// a bug in the normalize() implementation in lib/ doesn't simultaneously
// disable both the source-tree-verify path AND the shipped-tarball-verify
// gate (we want at least one independent check). ANY change to normalize()
// in any of these four files must be mirrored in all of them.
function normalizeSkillBytes(buf) {
  let s = Buffer.isBuffer(buf) ? buf.toString("utf8") : String(buf);
  if (s.length > 0 && s.charCodeAt(0) === 0xFEFF) s = s.slice(1);
  return Buffer.from(s.replace(/\r\n/g, "\n"), "utf8");
}

// In-line manifest-signature verifier for the extracted tarball. Kept
// here (rather than imported) for the same defense-in-depth reasoning as
// normalizeSkillBytes: a bug in lib/verify.js's verifier should not also
// disable this gate — at least one independent check must remain. The
// canonical-bytes computation MUST stay in lockstep with lib/sign.js +
// lib/verify.js + lib/refresh-network.js — enforced by
// tests/normalize-contract.test.js.
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
  const cryptoMod = require("crypto"); // eslint-disable-line no-unused-vars
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

// Exported so tests/normalize-contract.test.js can assert byte-identical
// normalize() behavior across all four implementations.
module.exports = {
  normalizeSkillBytes,
  verifyExtractedManifestSignature,
  canonicalManifestBytesForTarball,
};

const ROOT = path.resolve(__dirname, "..");

function emit(msg) { process.stdout.write(`[verify-shipped-tarball] ${msg}\n`); }
function fail(msg, code = 1) {
  process.stderr.write(`[verify-shipped-tarball] FAIL: ${msg}\n`);
  process.exit(code);
}

// Gate the script body behind require.main === module so tests can
// `require()` this file to load the exported helpers (notably
// normalizeSkillBytes for the byte-stability contract test) without
// invoking npm pack as a side effect of import.
if (require.main !== module) {
  // Loaded as a library (e.g. by tests/normalize-contract.test.js).
  // Skip the script body; consumers use the module.exports surface above.
  return;
}

const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "verify-shipped-"));
try {
  emit(`packing into ${tmpRoot} ...`);
  // F15 — pass --offline. Predeploy must run without registry
  // reachability; `npm pack` does not need the network for a local
  // package and forcing offline mode hard-locks the assumption.
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
  if (!fs.existsSync(tarballPath)) fail(`expected tarball at ${tarballPath}, not found`, 2);
  emit(`tarball: ${tarballPath} (${fs.statSync(tarballPath).size} bytes)`);

  // Extract via Node — bypasses GNU tar's "C:..." path quirk on Windows
  // where it interprets the colon as a remote-host separator.
  const extractDir = path.join(tmpRoot, "extract");
  fs.mkdirSync(extractDir, { recursive: true });
  const zlib = require("zlib");
  const { parseTar: parseTarSource } = require(path.join(ROOT, "lib", "refresh-network.js"));
  const tgz = fs.readFileSync(tarballPath);
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

  // load the extracted tree's OWN parseTar and re-parse the
  // tarball. If the two parsers diverge on entry list or content, the
  // gate trips: this means CI exercised a different parser than operators
  // will. Defense against drift between source and shipped tarball when
  // someone edits lib/refresh-network.js without re-vendoring or vice
  // versa.
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
  // Compare counts first — fast bailout.
  const divergences = [];
  if (shippedEntries.length !== entries.length) {
    divergences.push(
      `entry count divergence: source-tree parser produced ${entries.length}, ` +
      `shipped parser produced ${shippedEntries.length}`
    );
  } else {
    // Walk in parallel; tarball entry order is deterministic so positional
    // compare is correct. Compare name + byte length + body bytes.
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

  // Verify the top-level manifest_signature on the EXTRACTED
  // manifest.json. Per-skill signatures only sign the skill body bytes —
  // they do not sign skill.name / skill.path / skill.atlas_refs or any
  // other manifest envelope metadata. A tarball whose body bytes are
  // signed but whose manifest envelope was rewritten (re-routing a skill
  // path, renaming a skill, changing atlas refs) would pass per-skill
  // verification but fail this gate. v0.12.17+ shipped tarballs always
  // include manifest_signature, so a missing signature here is also a
  // refusal — stricter than the post-install warn-and-continue path,
  // which tolerates legacy v0.12.16-and-earlier installs.
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

  // key-pin cross-check against the EXTRACTED tree. The pin
  // is consumed from keys/EXPECTED_FINGERPRINT in the extracted package —
  // that's the file operators will actually receive on `npm install`.
  // Warn when absent, fail when present-but-mismatched (unless KEYS_ROTATED).
  const expectedFpPath = path.join(pkgRoot, "keys", "EXPECTED_FINGERPRINT");
  if (fs.existsSync(expectedFpPath)) {
    // Route through the shared lib/verify loader so a BOM-prefixed pin
    // file (Notepad with files.encoding=utf8bom in the source tree) is
    // tolerated identically across every verify site. The helper strips
    // leading U+FEFF + ignores comment lines (`#`).
    const { loadExpectedFingerprintFirstLine } = require(path.join(ROOT, "lib", "verify.js"));
    const firstLine = loadExpectedFingerprintFirstLine(expectedFpPath) || "";
    const liveFpLine = `SHA256:${pubFp}`;
    if (firstLine !== liveFpLine) {
      if (process.env.KEYS_ROTATED === "1") {
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
    // v0.12.16: the prior code passed the raw file bytes
    // directly to crypto.verify. lib/sign.js + lib/verify.js both NORMALIZE
    // bytes (strip UTF-8 BOM, convert CRLF -> LF) before sign/verify, per
    // the byte-stability contract in lib/verify.js's normalize() header.
    // Without the same normalization here, this gate (which was added
    // specifically to catch the v0.11.x signature regression class!) would
    // itself report 0/38 on any tree where line-ending normalization
    // touched the source between sign and pack — a Windows contributor
    // with `core.autocrlf=true`, or a tool like Prettier between sign and
    // pack. CLAUDE.md flags this as the recurring CRLF-bypass class.
    const rawContent = fs.readFileSync(skillPath);
    const normalizedContent = normalizeSkillBytes(rawContent);
    const ok = crypto.verify(null, normalizedContent, pubKey, Buffer.from(s.signature, "base64"));
    if (ok) pass++;
    else {
      fail_count++;
      // Forensic detail: log size + sha256 of tarball-extracted content vs source-tree content
      // so we can pinpoint which bytes changed between npm pack and what was signed.
      // v0.12.16: forensic logging uses rawContent (pre-normalization
      // bytes) so an operator inspecting failures sees the actual on-disk
      // shape, but tarSha is computed over the NORMALIZED bytes that
      // were actually fed to crypto.verify — making the comparison to
      // sign-time bytes meaningful.
      const tarSha = crypto.createHash("sha256").update(normalizedContent).digest("hex").slice(0, 16);
      let srcSha = "<missing>", srcSize = 0, srcContent;
      if (fs.existsSync(sourceSkillPath)) {
        srcContent = fs.readFileSync(sourceSkillPath);
        srcSize = srcContent.length;
        srcSha = crypto.createHash("sha256").update(normalizeSkillBytes(srcContent)).digest("hex").slice(0, 16);
      }
      const equal = srcContent && rawContent.equals(srcContent) ? "equal" : "DIFFER";
      failures.push(`${s.name}: signature did not verify (tarball size=${rawContent.length} sha-normalized=${tarSha}; source size=${srcSize} sha-normalized=${srcSha}; raw bytes ${equal})`);
    }
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
