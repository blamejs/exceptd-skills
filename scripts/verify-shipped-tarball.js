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
 * Audit G:
 *   F9  — After the first-pass extraction (using the source-tree parseTar),
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

const ROOT = path.resolve(__dirname, "..");

function emit(msg) { process.stdout.write(`[verify-shipped-tarball] ${msg}\n`); }
function fail(msg, code = 1) {
  process.stderr.write(`[verify-shipped-tarball] FAIL: ${msg}\n`);
  process.exit(code);
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

  // Audit G F9 — load the extracted tree's OWN parseTar and re-parse the
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

  // Audit G F4 — key-pin cross-check against the EXTRACTED tree. The pin
  // is consumed from keys/EXPECTED_FINGERPRINT in the extracted package —
  // that's the file operators will actually receive on `npm install`.
  // Warn when absent, fail when present-but-mismatched (unless KEYS_ROTATED).
  const expectedFpPath = path.join(pkgRoot, "keys", "EXPECTED_FINGERPRINT");
  if (fs.existsSync(expectedFpPath)) {
    const raw = fs.readFileSync(expectedFpPath, "utf8").trim();
    const firstLine = raw.split(/\r?\n/).map((l) => l.trim()).find((l) => l.length > 0) || "";
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
    const content = fs.readFileSync(skillPath);
    const ok = crypto.verify(null, content, pubKey, Buffer.from(s.signature, "base64"));
    if (ok) pass++;
    else {
      fail_count++;
      // Forensic detail: log size + sha256 of tarball-extracted content vs source-tree content
      // so we can pinpoint which bytes changed between npm pack and what was signed.
      const tarSha = crypto.createHash("sha256").update(content).digest("hex").slice(0, 16);
      let srcSha = "<missing>", srcSize = 0, srcContent;
      if (fs.existsSync(sourceSkillPath)) {
        srcContent = fs.readFileSync(sourceSkillPath);
        srcSize = srcContent.length;
        srcSha = crypto.createHash("sha256").update(srcContent).digest("hex").slice(0, 16);
      }
      const equal = srcContent && content.equals(srcContent) ? "equal" : "DIFFER";
      failures.push(`${s.name}: signature did not verify (tarball size=${content.length} sha=${tarSha}; source size=${srcSize} sha=${srcSha}; bytes ${equal})`);
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
