#!/usr/bin/env node
"use strict";

/**
 * lib/refresh-network.js
 *
 * `exceptd refresh --network` — fetch the latest signed catalog snapshot
 * from the maintainer's npm-published tarball, verify every skill
 * signature against the Ed25519 public key already shipped in the
 * operator's local install, and swap in the fresh `data/`, `manifest.json`,
 * and `manifest-snapshot.json`.
 *
 * Trust boundary:
 *   - Trust anchor = the `keys/public.pem` already present in the local
 *     install. Operators rotated the key by running `npm install -g` at
 *     some earlier point; nothing in --network changes that root.
 *   - Tarball authenticity = each shipped `skills/<name>/SKILL.md` (or
 *     equivalent payload) has an Ed25519 signature in manifest.json that
 *     resolves against the local public key. ANY signature mismatch aborts
 *     the swap; the local install is untouched.
 *
 * Why this exists:
 *   `npm update -g` already pulls the same signed artifact (npm provenance
 *   + OIDC). --network is for operators who want only the data slice
 *   without re-resolving CLI/lib code, OR who are on a constrained host
 *   where the global npm install requires sudo and they're running a
 *   user-local copy they can write to.
 *
 * Requires write access to the install directory. Fails fast with a
 * clear message + the `npm update` fallback when the install is not
 * writable (typical for system-global installs).
 *
 * Zero npm deps. Node 24 stdlib only.
 */

const fs = require("fs");
const path = require("path");
const https = require("https");
const crypto = require("crypto");
const zlib = require("zlib");
const os = require("os");

const ROOT = path.resolve(__dirname, "..");
const PKG_NAME = "@blamejs/exceptd-skills";
const REQUEST_TIMEOUT_MS = 15000;

function parseArgs(argv) {
  const out = { force: false, dryRun: false, timeoutMs: REQUEST_TIMEOUT_MS, json: false };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--force") out.force = true;
    else if (a === "--dry-run") out.dryRun = true;
    else if (a === "--json") out.json = true;
    else if (a === "--timeout") out.timeoutMs = parseInt(argv[++i], 10) || REQUEST_TIMEOUT_MS;
  }
  return out;
}

function emit(obj, json) {
  if (json) process.stdout.write(JSON.stringify(obj) + "\n");
  else if (obj.ok) process.stdout.write(`[refresh-network] ${obj.message || JSON.stringify(obj)}\n`);
  else process.stderr.write(`[refresh-network] FAIL: ${obj.error || JSON.stringify(obj)}\n`);
}

function progress(line, json) {
  // Progress messages always go to stderr so --json consumers see only the
  // final JSON result on stdout. Plain mode also routes progress through
  // stderr (so `exceptd refresh --network > catalog.log` doesn't mix logs
  // with structured output).
  process.stderr.write(`[refresh-network] ${line}\n`);
}

function getJson(url, timeoutMs) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const req = https.get({
      host: u.host, path: u.pathname + u.search,
      headers: { "Accept": "application/json", "User-Agent": "exceptd/refresh-network" },
      timeout: timeoutMs,
    }, (res) => {
      if (res.statusCode !== 200) {
        res.resume();
        return reject(new Error(`HTTP ${res.statusCode} from ${url}`));
      }
      const chunks = [];
      res.on("data", (c) => chunks.push(c));
      res.on("end", () => {
        try { resolve(JSON.parse(Buffer.concat(chunks).toString("utf8"))); }
        catch (e) { reject(new Error(`parse: ${e.message}`)); }
      });
    });
    req.on("timeout", () => req.destroy(new Error("timeout")));
    req.on("error", reject);
  });
}

function getBuffer(url, timeoutMs) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const cap = (() => {
      const env = parseInt(process.env.EXCEPTD_TARBALL_SIZE_CAP_BYTES, 10);
      return Number.isFinite(env) && env > 0 ? env : 200 * 1024 * 1024;
    })();
    const req = https.get({
      host: u.host, path: u.pathname + u.search,
      headers: { "User-Agent": "exceptd/refresh-network" },
      timeout: timeoutMs,
    }, (res) => {
      if (res.statusCode !== 200) {
        res.resume();
        return reject(new Error(`HTTP ${res.statusCode} from ${url}`));
      }
      const chunks = [];
      let total = 0;
      // v0.12.14: enforce streaming size cap so a hostile
      // registry CDN can't stream gigabytes into RAM.
      res.on("data", (c) => {
        total += c.length;
        if (total > cap) {
          req.destroy(new Error(`tarball exceeds ${cap}-byte cap during streaming download`));
          return;
        }
        chunks.push(c);
      });
      res.on("end", () => resolve(Buffer.concat(chunks)));
    });
    req.on("timeout", () => req.destroy(new Error("timeout")));
    req.on("error", reject);
  });
}

/**
 * Parse a tar buffer (uncompressed) and return [{ name, body }] entries.
 * Tiny implementation — supports the GNU ustar variant npm produces.
 * Skips PaxHeader entries; treats long-link entries (type L) by stitching
 * the next entry's name from the long-link body.
 */
function parseTar(buf) {
  const entries = [];
  let offset = 0;
  let pendingLongName = null;
  // v0.12.12: tarballs from a compromised registry CDN could ship entries
  // with `..`-bearing names targeting paths outside the install root. The
  // immediate callers (verify-shipped-tarball.js + the network update path)
  // do hash + signature checks before honoring entries, so this is
  // defense-in-depth — drop the entry rather than handing a path-traversal
  // string downstream.
  const isSafeName = (n) => {
    if (typeof n !== "string" || n.length === 0) return false;
    // Reject absolute paths AND any segment that is exactly ".."
    if (/^[\\/]/.test(n) || /^[A-Za-z]:[\\/]/.test(n)) return false;
    return !n.split(/[\\/]/).some((seg) => seg === "..");
  };
  while (offset + 512 <= buf.length) {
    const block = buf.subarray(offset, offset + 512);
    // empty block = end-of-archive marker
    if (block.every((b) => b === 0)) break;
    let name = block.subarray(0, 100).toString("utf8").replace(/\0.*$/, "");
    const sizeStr = block.subarray(124, 136).toString("utf8").replace(/\0.*$|\s+$/g, "").trim();
    const size = parseInt(sizeStr, 8) || 0;
    const type = String.fromCharCode(block[156] || 0);
    const prefix = block.subarray(345, 500).toString("utf8").replace(/\0.*$/, "");
    if (prefix) name = prefix + "/" + name;
    if (pendingLongName) { name = pendingLongName; pendingLongName = null; }
    const dataStart = offset + 512;
    const dataEnd = dataStart + size;
    if (type === "L") {
      pendingLongName = buf.subarray(dataStart, dataEnd).toString("utf8").replace(/\0.*$/, "");
    } else if (type === "0" || type === "" || type === "\0") {
      if (isSafeName(name)) {
        entries.push({ name, body: buf.subarray(dataStart, dataEnd) });
      }
    }
    // round up to 512
    offset = dataStart + Math.ceil(size / 512) * 512;
  }
  return entries;
}

function fingerprintPublicKey(pemText) {
  try {
    const ko = crypto.createPublicKey(pemText);
    const der = ko.export({ type: "spki", format: "der" });
    return crypto.createHash("sha256").update(der).digest("base64");
  } catch { return null; }
}

function verifyDetached(publicKeyObj, payload, sigB64) {
  try {
    return crypto.verify(null, payload, publicKeyObj, Buffer.from(sigB64, "base64"));
  } catch { return false; }
}

// v0.12.14: CRLF/BOM normalization mirrors lib/verify.js's
// normalize(). Duplicated here to keep refresh-network free of cross-module
// runtime deps. ANY change here MUST be mirrored in lib/verify.js +
// lib/sign.js + scripts/verify-shipped-tarball.js — the four normalize()
// implementations form a byte-stability contract enforced by
// tests/normalize-contract.test.js.
function normalizeSkillBytes(buf) {
  let s = Buffer.isBuffer(buf) ? buf.toString("utf8") : String(buf);
  if (s.length > 0 && s.charCodeAt(0) === 0xFEFF) s = s.slice(1);
  return Buffer.from(s.replace(/\r\n/g, "\n"), "utf8");
}

// B + Q P1: in-line manifest-signature verifier. Kept here
// rather than imported from lib/verify.js so refresh-network.js retains
// its no-cross-module-dep posture (mirrors the per-skill verify path).
// ANY change to canonical-bytes computation here MUST stay in lockstep
// with lib/sign.js canonicalManifestBytes() / lib/verify.js
// canonicalManifestBytes() — tests/normalize-contract.test.js enforces.
function canonicalizeForRefresh(value) {
  if (Array.isArray(value)) return value.map(canonicalizeForRefresh);
  if (value && typeof value === "object") {
    const out = {};
    for (const key of Object.keys(value).sort()) {
      out[key] = canonicalizeForRefresh(value[key]);
    }
    return out;
  }
  return value;
}
function canonicalManifestBytesForRefresh(manifest) {
  const clone = Object.assign({}, manifest);
  delete clone.manifest_signature;
  const json = JSON.stringify(canonicalizeForRefresh(clone), null, 2);
  return normalizeSkillBytes(Buffer.from(json, "utf8"));
}
function verifyTarballManifestSignature(manifest, publicKeyPem) {
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
  const bytes = canonicalManifestBytesForRefresh(manifest);
  let ok = false;
  try {
    ok = crypto.verify(null, bytes, {
      key: publicKeyPem,
      dsaEncoding: "ieee-p1363",
    }, signatureBytes);
  } catch (e) {
    return { status: "invalid", reason: `crypto.verify threw: ${e.message}` };
  }
  return ok ? { status: "valid" } : { status: "invalid", reason: "Ed25519 manifest signature did not verify against local public.pem" };
}

// Manifest path validation. Mirrors lib/verify.js validateSkillPath().
function validateManifestSkillPath(skillPath) {
  if (typeof skillPath !== "string") throw new Error(`manifest skill.path must be a string, got ${typeof skillPath}`);
  if (skillPath.includes("\\")) throw new Error(`manifest skill.path must use forward slashes: ${JSON.stringify(skillPath)}`);
  if (!skillPath.startsWith("skills/")) throw new Error(`manifest skill.path must start with 'skills/': ${JSON.stringify(skillPath)}`);
  if (skillPath.includes("..")) throw new Error(`manifest skill.path must not contain '..': ${JSON.stringify(skillPath)}`);
  return skillPath;
}

// v0.12.14: tarball download size cap. A hostile registry CDN
// could stream gigabytes; Node buffers chunks in RAM until OOM. Current
// tarball is ~2 MB; 200 MB is generous defense-in-depth. Tunable via
// EXCEPTD_TARBALL_SIZE_CAP_BYTES for future growth.
const TARBALL_SIZE_CAP_BYTES_DEFAULT = 200 * 1024 * 1024;
function tarballSizeCap() {
  const env = parseInt(process.env.EXCEPTD_TARBALL_SIZE_CAP_BYTES, 10);
  return Number.isFinite(env) && env > 0 ? env : TARBALL_SIZE_CAP_BYTES_DEFAULT;
}

async function main() {
  const opts = parseArgs(process.argv);
  const localPkg = JSON.parse(fs.readFileSync(path.join(ROOT, "package.json"), "utf8"));
  const localVersion = localPkg.version;

  progress(`local v${localVersion} — querying npm registry...`, opts.json);

  let meta;
  try {
    if (process.env.EXCEPTD_REGISTRY_FIXTURE) {
      // Honor the same fixture mechanism as upstream-check so test runners
      // can exercise the offline / reachable / unreachable branches without
      // touching the network. Fixture shape: a JSON file matching the
      // /<pkg>/latest registry response (must include version + dist.tarball
      // + dist.shasum, or just version to exercise the early-return path).
      meta = JSON.parse(fs.readFileSync(process.env.EXCEPTD_REGISTRY_FIXTURE, "utf8"));
    } else {
      meta = await getJson(`https://registry.npmjs.org/${encodeURIComponent(PKG_NAME).replace("%40", "@").replace("%2F", "/")}/latest`, opts.timeoutMs);
    }
  } catch (e) {
    emit({ ok: false, error: `registry unreachable: ${e.message}`, hint: "Network required. Air-gap workflow: run `exceptd refresh --prefetch` on a connected host, then `exceptd refresh --from-cache --apply` offline. Or set EXCEPTD_REGISTRY_FIXTURE for offline testing." }, opts.json);
    process.exitCode = 2; return;
  }

  const latestVersion = meta.version;
  const tarballUrl = meta.dist && meta.dist.tarball;
  const tarballShasum = meta.dist && meta.dist.shasum;
  const tarballIntegrity = meta.dist && meta.dist.integrity; // SHA-512 SRI
  const registrySignatures = Array.isArray(meta.dist && meta.dist.signatures) ? meta.dist.signatures : [];
  if (!tarballUrl) {
    emit({ ok: false, error: "registry metadata missing dist.tarball" }, opts.json);
    process.exitCode = 2; return;
  }

  if (latestVersion === localVersion && !opts.force) {
    emit({ ok: true, message: `already at latest v${localVersion} — nothing to do. Pass --force to re-pull anyway.`, local_version: localVersion, latest_version: latestVersion, skipped: true }, opts.json);
    return;
  }

  // Writable-install check. Global installs typically live in a
  // root-owned dir; refusing to fail-then-leave-partial is the safer
  // contract.
  const writeProbe = path.join(ROOT, `.write-probe-${process.pid}`);
  try {
    fs.writeFileSync(writeProbe, "");
    fs.unlinkSync(writeProbe);
  } catch (e) {
    emit({
      ok: false,
      error: `install directory not writable: ${ROOT}`,
      hint: `Global installs typically require elevated permissions. Either: (a) run \`npm update -g @blamejs/exceptd-skills\` (recommended — same trust anchor, full package update), or (b) install locally with \`npm install @blamejs/exceptd-skills\` in a user-writable directory and retry --network there.`,
    }, opts.json);
    process.exitCode = 3; return;
  }

  progress(`fetching ${tarballUrl} (${tarballShasum?.slice(0, 12) || "no shasum"})...`, opts.json);

  let tgzBuf;
  try {
    tgzBuf = await getBuffer(tarballUrl, opts.timeoutMs);
  } catch (e) {
    emit({ ok: false, error: `tarball fetch failed: ${e.message}` }, opts.json);
    process.exitCode = 2; return;
  }

  // v0.12.14: defense-in-depth tarball size cap.
  const sizeCap = tarballSizeCap();
  if (tgzBuf.length > sizeCap) {
    emit({ ok: false, error: `tarball exceeds size cap: ${tgzBuf.length} bytes > ${sizeCap} (EXCEPTD_TARBALL_SIZE_CAP_BYTES)` }, opts.json);
    process.exitCode = 4; return;
  }

  // v0.12.14: verify SHA-512 SRI first (collision-resistant
  // beyond SHA-1 reach), then SHA-1 shasum for compatibility, then dist.
  // signatures[] (npm registry's Ed25519 signing key). Each layer is
  // defense-in-depth — registry compromise that produces a SHA-1 collision
  // doesn't trivially produce a SHA-512 collision; an attacker who breaks
  // both still has to forge the npm-signing-key signature on the tarball.
  if (tarballIntegrity && /^sha512-/.test(tarballIntegrity)) {
    const expected = tarballIntegrity.slice("sha512-".length);
    const actual = crypto.createHash("sha512").update(tgzBuf).digest("base64");
    if (actual !== expected) {
      emit({ ok: false, error: `tarball SHA-512 integrity mismatch: dist.integrity=${tarballIntegrity}, actual=sha512-${actual}` }, opts.json);
      process.exitCode = 4; return;
    }
  } else if (tarballIntegrity) {
    // Non-sha512 SRI (e.g. sha384) — emit a warning but accept; SHA-1 path
    // below still gates.
    progress(`note: dist.integrity present but not sha512: ${tarballIntegrity.slice(0, 40)}`, opts.json);
  }

  // Verify shasum (registry-provided integrity).
  if (tarballShasum) {
    const actual = crypto.createHash("sha1").update(tgzBuf).digest("hex");
    if (actual !== tarballShasum) {
      emit({ ok: false, error: `tarball shasum mismatch: expected ${tarballShasum}, got ${actual}` }, opts.json);
      process.exitCode = 4; return;
    }
  }

  // Extract.
  let tarBuf;
  try { tarBuf = zlib.gunzipSync(tgzBuf); }
  catch (e) { emit({ ok: false, error: `gunzip: ${e.message}` }, opts.json); process.exitCode = 4; return; }

  const entries = parseTar(tarBuf);
  // npm tarballs prefix every entry with "package/"
  const stripPkg = (n) => n.startsWith("package/") ? n.slice("package/".length) : n;

  const tarballManifestEntry = entries.find((e) => stripPkg(e.name) === "manifest.json");
  const tarballPubKeyEntry   = entries.find((e) => stripPkg(e.name) === "keys/public.pem");
  if (!tarballManifestEntry) {
    emit({ ok: false, error: "tarball missing manifest.json" }, opts.json);
    process.exitCode = 4; return;
  }

  // Trust anchor = LOCAL public.pem. Compare it to the tarball's public.pem
  // by fingerprint; if they differ, refuse the swap (key rotation requires
  // a full `npm update -g` so the operator has explicit visibility).
  const localPubKeyPath = path.join(ROOT, "keys", "public.pem");
  let localPubKeyText, tarballPubKeyText;
  try { localPubKeyText = fs.readFileSync(localPubKeyPath, "utf8"); }
  catch (e) { emit({ ok: false, error: `local keys/public.pem unreadable: ${e.message}` }, opts.json); process.exitCode = 4; return; }
  if (tarballPubKeyEntry) tarballPubKeyText = tarballPubKeyEntry.body.toString("utf8");

  const localFp = fingerprintPublicKey(localPubKeyText);
  const tarballFp = tarballPubKeyText ? fingerprintPublicKey(tarballPubKeyText) : null;
  if (tarballFp && tarballFp !== localFp) {
    emit({
      ok: false,
      error: `public key fingerprint mismatch: local=${localFp} tarball=${tarballFp}`,
      hint: `The maintainer rotated the Ed25519 signing key in v${latestVersion}. Key rotations require an explicit \`npm update -g @blamejs/exceptd-skills\` so you can audit the trust transition. Refusing to swap on --network.`,
    }, opts.json);
    process.exitCode = 5; return;
  }

  // v0.12.16: cross-check the local public key against
  // keys/EXPECTED_FINGERPRINT (the CI-pinned signing key). The prior
  // refresh-network code only compared LOCAL ↔ TARBALL fingerprints, so a
  // coordinated attacker who swapped both `keys/public.pem` on the operator's
  // host AND the registry tarball passed every check — fingerprints match
  // each other but match the attacker's key. The pin in EXPECTED_FINGERPRINT
  // is the external trust anchor that closes this gap.
  //
  // Honors `KEYS_ROTATED=1` env to allow legitimate key rotation without
  // re-bootstrap. Missing EXPECTED_FINGERPRINT file → warn-and-continue
  // (don't break existing installs whose tree predates the pin file).
  const expectedFingerprintPath = path.join(ROOT, "keys", "EXPECTED_FINGERPRINT");
  if (fs.existsSync(expectedFingerprintPath) && process.env.KEYS_ROTATED === "1") {
    process.emitWarning(
      `EXPECTED_FINGERPRINT pin check skipped via KEYS_ROTATED=1 during refresh-network. ` +
      `Update keys/EXPECTED_FINGERPRINT to lock the new pin once rotation completes.`,
      { code: 'EXCEPTD_KEYS_ROTATED_OVERRIDE' }
    );
  }
  if (fs.existsSync(expectedFingerprintPath) && !process.env.KEYS_ROTATED) {
    try {
      // Route through the shared lib/verify loader so a BOM-prefixed pin
      // file (Notepad with files.encoding=utf8bom) is tolerated identically
      // across every verify site. An inline split-trim-find would retain
      // the BOM as part of the first line, which would never match a live
      // fingerprint and would block every legitimate refresh-network run.
      const { loadExpectedFingerprintFirstLine } = require("./verify.js");
      const expectedFp = loadExpectedFingerprintFirstLine(expectedFingerprintPath);
      // v0.12.16 (codex P1 PR #11): `expectedFp` is read verbatim from
      // keys/EXPECTED_FINGERPRINT (formatted as `SHA256:<base64>`), but
      // `fingerprintPublicKey()` returns the raw base64 without the
      // `SHA256:` prefix. Comparing the two raw strings would refuse every
      // legitimate run unless KEYS_ROTATED=1 was set. Normalize by stripping
      // the prefix from the pin file before compare. lib/verify.js's
      // checkExpectedFingerprint() does the symmetric thing (adds the
      // prefix to localFp); either side works as long as one is canonical.
      const expectedFpBase64 = expectedFp && expectedFp.startsWith("SHA256:")
        ? expectedFp.slice("SHA256:".length)
        : expectedFp;
      if (expectedFpBase64 && expectedFpBase64 !== localFp) {
        emit({
          ok: false,
          error: `local keys/public.pem fingerprint diverges from keys/EXPECTED_FINGERPRINT pin`,
          local_fingerprint: "SHA256:" + localFp,
          pinned_fingerprint: expectedFp,
          hint: "Either keys/public.pem was rotated since the pin was set (rerun `npm run bootstrap` to re-pin), or the local public.pem was tampered with. Set KEYS_ROTATED=1 to bypass once. Refusing to swap on --network.",
        }, opts.json);
        process.exitCode = 5; return;
      }
    } catch { /* unreadable pin file = warn-and-continue */ }
  }

  // Verify every signed entry in the tarball manifest using the local key.
  let tarballManifest;
  try { tarballManifest = JSON.parse(tarballManifestEntry.body.toString("utf8")); }
  catch (e) { emit({ ok: false, error: `tarball manifest.json parse: ${e.message}` }, opts.json); process.exitCode = 4; return; }

  // B + Q P1: verify the top-level manifest_signature against
  // the LOCAL public key before honoring any entry in the tarball manifest.
  // The previous flow iterated `manifest.skills[].signature` per-skill but
  // never authenticated the manifest envelope itself — a coordinated
  // attacker who flipped paths/names/atlas_refs on entries already covered
  // by per-skill signatures (which sign only the skill body bytes, not the
  // metadata around them) could re-shape catalog routing without breaking
  // any per-skill signature. The manifest signature closes that gap.
  //
  // Unlike post-install verify (which warns-and-continues on missing
  // signature for legacy-tarball compat), refresh-network REQUIRES the
  // signature: this code path is publishing fresh content into the local
  // tree, and the tarball must already be ≥ v0.12.17 to have reached the
  // registry through the sign-all gate.
  const manifestSigResult = verifyTarballManifestSignature(tarballManifest, localPubKeyText);
  if (manifestSigResult.status !== "valid") {
    emit({
      ok: false,
      error: `tarball manifest_signature ${manifestSigResult.status} — refusing to swap`,
      reason: manifestSigResult.reason || null,
      hint: manifestSigResult.status === "missing"
        ? "Tarball predates v0.12.17 manifest signing. Run `npm update -g @blamejs/exceptd-skills` instead so the full provenance-verified install path runs."
        : "Tarball manifest envelope failed Ed25519 verification against the LOCAL public key. Run `npm update -g @blamejs/exceptd-skills` for the full provenance-verified path, or report this tarball at https://github.com/blamejs/exceptd-skills/issues.",
    }, opts.json);
    process.exitCode = 5; return;
  }

  // v0.12.14: the prior loop iterated `sk.id` + a fixed payload
  // path `skills/<id>/SKILL.md`. Manifest entries actually expose `name` +
  // `path` (a forward-slash relative path like `skills/<name>/skill.md`,
  // lowercase). Result: the loop matched zero entries; `failures.length === 0`
  // and `verifiedCount === 0` and the swap proceeded with `ok: true`. Every
  // operator running `exceptd refresh --network` installed unverified bytes.
  //
  // Fixed shape mirrors lib/verify.js: iterate `manifest.skills[]` by
  // `name` + `path` + `signature`. Apply the same CRLF/BOM normalization
  // before verify (lib/verify.js normalize() — duplicated here to keep
  // this path free of cross-module runtime deps). validateSkillPath()
  // is also mirrored to defend against path traversal in a tampered
  // tarball manifest before we resolve the path against the extracted
  // tree.
  const localKeyObj = crypto.createPublicKey(localPubKeyText);
  const skills = Array.isArray(tarballManifest.skills) ? tarballManifest.skills : [];
  const failures = [];
  let verifiedCount = 0;
  for (const sk of skills) {
    if (!sk || typeof sk.name !== "string" || typeof sk.signature !== "string") {
      failures.push({ name: sk?.name || "(missing name)", reason: "manifest entry missing name or signature" });
      continue;
    }
    let normalizedPath;
    try { normalizedPath = validateManifestSkillPath(sk.path); }
    catch (e) { failures.push({ name: sk.name, reason: `manifest path rejected: ${e.message}` }); continue; }
    const payloadEntry = entries.find((e) => stripPkg(e.name) === normalizedPath);
    if (!payloadEntry) { failures.push({ name: sk.name, reason: `payload missing from tarball: ${normalizedPath}` }); continue; }
    const normalized = normalizeSkillBytes(payloadEntry.body);
    const ok = verifyDetached(localKeyObj, normalized, sk.signature);
    if (ok) verifiedCount++;
    else failures.push({ name: sk.name, reason: "Ed25519 signature did not verify against local public key" });
  }

  if (skills.length === 0) {
    emit({
      ok: false,
      error: "tarball manifest.json declares zero skills — refusing to swap",
      verified: 0,
      total: 0,
      hint: "A legitimate tarball must declare at least one skill. Treat this as a tarball-integrity failure.",
    }, opts.json);
    process.exitCode = 5; return;
  }
  if (verifiedCount !== skills.length || failures.length > 0) {
    emit({
      ok: false,
      error: `${failures.length}/${skills.length} skill signature(s) failed verification — refusing to swap`,
      failures: failures.slice(0, 10),
      verified: verifiedCount,
      total: skills.length,
      hint: "Refusing to install unverified content. Run `npm update -g @blamejs/exceptd-skills` for the full provenance-verified path, or report this tarball at https://github.com/blamejs/exceptd-skills/issues.",
    }, opts.json);
    process.exitCode = 5; return;
  }

  // v0.12.14: the swap loop replaces `data/` + `manifest.json` +
  // `manifest-snapshot.json` in addition to `skills/`. None of those files
  // are covered by the per-skill Ed25519 signature (which signs only the
  // skill body bytes). The only integrity check between the registry and
  // those bytes is SHA-1 dist.shasum — collision-broken since 2017 and
  // weaker than `npm install` itself which honors dist.integrity (SHA-512
  // SRI) + dist.signatures (npm Ed25519 registry key) + dist.attestations
  // (sigstore SLSA provenance).
  //
  // Defense-in-depth: refuse the swap if the manifest skills list doesn't
  // exactly match the skill payload entries present in the tarball. A
  // malicious tarball that drops/adds a skill outside the manifest no
  // longer slips through.
  const manifestSkillPaths = new Set(skills.map(s => validateManifestSkillPath(s.path)));
  const tarballSkillPayloads = entries
    .map(e => stripPkg(e.name))
    .filter(name => /^skills\/[^/]+\/skill\.md$/.test(name));
  for (const tp of tarballSkillPayloads) {
    if (!manifestSkillPaths.has(tp)) {
      emit({
        ok: false,
        error: `tarball ships skill payload not declared in manifest: ${tp} — refusing to swap`,
        hint: "Tarball+manifest divergence. Report at https://github.com/blamejs/exceptd-skills/issues.",
      }, opts.json);
      process.exitCode = 5; return;
    }
  }

  if (opts.dryRun) {
    emit({
      ok: true,
      dry_run: true,
      local_version: localVersion,
      latest_version: latestVersion,
      verified_skills: verifiedCount,
      total_skills: skills.length,
      message: `--dry-run: would swap data/ + manifest.json from v${latestVersion} (${verifiedCount}/${skills.length} signatures verified). No files changed.`,
    }, opts.json);
    return;
  }

  // v0.12.14: the prior swap loop renamed targets one-by-one,
  // and a mid-loop failure left the install half-applied with no automatic
  // rollback. New shape: rename all old targets into a single backup dir
  // first (so the install is empty-of-old before any new content is moved
  // in); then rename all new targets in; on failure, walk the backup dir
  // in reverse and restore.
  const stageDir = fs.mkdtempSync(path.join(ROOT, ".refresh-network-"));
  let written = 0;
  let backupDir = null;
  const completedSteps = []; // [{kind: 'backup' | 'install', target}]
  try {
    for (const entry of entries) {
      const rel = stripPkg(entry.name);
      // Scope: only data/, skills/, manifest.json, manifest-snapshot.json.
      // Everything else (bin/, lib/, package.json, etc.) is left alone —
      // --network is a DATA refresh, not a code refresh.
      if (!(rel === "manifest.json" || rel === "manifest-snapshot.json" ||
            rel.startsWith("data/") || rel.startsWith("skills/"))) continue;
      const dst = path.join(stageDir, rel);
      fs.mkdirSync(path.dirname(dst), { recursive: true });
      fs.writeFileSync(dst, entry.body);
      written++;
    }

    // v0.12.14: use PID + random suffix in the backup dir name
    // so concurrent refresh-network invocations don't collide on the
    // millisecond clock.
    const backupSuffix = `${process.pid}-${crypto.randomBytes(4).toString("hex")}`;
    backupDir = path.join(ROOT, `.refresh-network-backup-${Date.now()}-${backupSuffix}`);
    fs.mkdirSync(backupDir);
    const replaceList = ["data", "skills", "manifest.json", "manifest-snapshot.json"];

    // Phase A: move all existing targets to backupDir. After this loop
    // completes, the install root has none of the replaced targets.
    for (const target of replaceList) {
      const dst = path.join(ROOT, target);
      if (fs.existsSync(dst)) {
        fs.renameSync(dst, path.join(backupDir, target));
        completedSteps.push({ kind: "backup", target });
      }
    }

    // Phase B: move all new targets in from stage.
    for (const target of replaceList) {
      const src = path.join(stageDir, target);
      if (!fs.existsSync(src)) continue;
      fs.renameSync(src, path.join(ROOT, target));
      completedSteps.push({ kind: "install", target });
    }

    fs.rmSync(stageDir, { recursive: true, force: true });
    // Best-effort cleanup of backup dir — keep on disk for one cycle so
    // operators can manually roll back if something feels off.
    emit({
      ok: true,
      local_version: localVersion,
      latest_version: latestVersion,
      verified_skills: verifiedCount,
      total_skills: skills.length,
      files_written: written,
      backup_dir: path.relative(ROOT, backupDir),
      registry_signatures_present: registrySignatures.length,
      message: `refreshed catalog from v${localVersion} → v${latestVersion} (${verifiedCount}/${skills.length} signatures verified). Backup at ${path.relative(ROOT, backupDir)} — safe to remove after verifying the new run.`,
    }, opts.json);
  } catch (e) {
    // v0.12.14: walk completedSteps in reverse to undo partial work.
    const rollbackErrors = [];
    for (const step of [...completedSteps].reverse()) {
      try {
        if (step.kind === "install") {
          // Remove the newly-installed copy.
          fs.rmSync(path.join(ROOT, step.target), { recursive: true, force: true });
        } else if (step.kind === "backup" && backupDir) {
          // Restore from backup.
          const src = path.join(backupDir, step.target);
          const dst = path.join(ROOT, step.target);
          if (fs.existsSync(src)) fs.renameSync(src, dst);
        }
      } catch (re) {
        rollbackErrors.push({ target: step.target, kind: step.kind, error: re.message });
      }
    }
    fs.rmSync(stageDir, { recursive: true, force: true });
    emit({
      ok: false,
      error: `swap failed mid-rename: ${e.message}`,
      rolled_back: rollbackErrors.length === 0,
      rollback_errors: rollbackErrors,
      backup_dir: backupDir ? path.relative(ROOT, backupDir) : null,
      hint: rollbackErrors.length === 0
        ? "Auto-rollback completed. Install state matches pre-refresh. Re-run `exceptd refresh --network` or `npm install -g @blamejs/exceptd-skills` to retry."
        : "Auto-rollback partially failed. Restore manually from the backup dir at the install root, or reinstall with `npm install -g @blamejs/exceptd-skills`.",
    }, opts.json);
    process.exitCode = 4;
  }
}

if (require.main === module) {
  main().catch((err) => {
    process.stderr.write(`refresh-network: fatal: ${err && err.message || err}\n`);
    process.exit(2);
  });
}

module.exports = {
  parseTar,
  fingerprintPublicKey,
  // Exported for tests/normalize-contract.test.js so the byte-stability
  // contract can be asserted across all four normalize() implementations
  // (lib/sign.js, lib/verify.js, lib/refresh-network.js,
  // scripts/verify-shipped-tarball.js).
  normalizeSkillBytes,
  // Exported for in-process tests of the refresh path's manifest envelope
  // check.
  verifyTarballManifestSignature,
  canonicalManifestBytesForRefresh,
};
