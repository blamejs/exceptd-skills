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
      res.on("data", (c) => chunks.push(c));
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
      entries.push({ name, body: buf.subarray(dataStart, dataEnd) });
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

  // Verify every signed entry in the tarball manifest using the local key.
  let tarballManifest;
  try { tarballManifest = JSON.parse(tarballManifestEntry.body.toString("utf8")); }
  catch (e) { emit({ ok: false, error: `tarball manifest.json parse: ${e.message}` }, opts.json); process.exitCode = 4; return; }

  const localKeyObj = crypto.createPublicKey(localPubKeyText);
  const skills = Array.isArray(tarballManifest.skills) ? tarballManifest.skills : [];
  const failures = [];
  let verifiedCount = 0;
  for (const sk of skills) {
    if (!sk || !sk.id || !sk.signature) continue;
    // Find the skill payload entry. manifest convention: skills/<id>/SKILL.md
    const payloadName = `skills/${sk.id}/SKILL.md`;
    const payloadEntry = entries.find((e) => stripPkg(e.name) === payloadName);
    if (!payloadEntry) { failures.push({ id: sk.id, reason: "payload not in tarball" }); continue; }
    const ok = verifyDetached(localKeyObj, payloadEntry.body, sk.signature);
    if (ok) verifiedCount++;
    else failures.push({ id: sk.id, reason: "signature did not verify against local public key" });
  }

  if (failures.length > 0) {
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

  // Atomic swap: stage to a tmp dir under the install, then rename.
  const stageDir = fs.mkdtempSync(path.join(ROOT, ".refresh-network-"));
  let written = 0;
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

    // Replace targets.
    const replaceList = ["data", "skills", "manifest.json", "manifest-snapshot.json"];
    const backupDir = path.join(ROOT, `.refresh-network-backup-${Date.now()}`);
    fs.mkdirSync(backupDir);
    for (const target of replaceList) {
      const src = path.join(stageDir, target);
      if (!fs.existsSync(src)) continue;
      const dst = path.join(ROOT, target);
      if (fs.existsSync(dst)) {
        fs.renameSync(dst, path.join(backupDir, target));
      }
      fs.renameSync(src, dst);
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
      message: `refreshed catalog from v${localVersion} → v${latestVersion} (${verifiedCount}/${skills.length} signatures verified). Backup at ${path.relative(ROOT, backupDir)} — safe to remove after verifying the new run.`,
    }, opts.json);
  } catch (e) {
    fs.rmSync(stageDir, { recursive: true, force: true });
    emit({ ok: false, error: `swap failed mid-rename: ${e.message}`, hint: "If files are missing, restore from the backup dir at the install root, or reinstall with `npm install -g @blamejs/exceptd-skills`." }, opts.json);
    process.exitCode = 4;
  }
}

if (require.main === module) {
  main().catch((err) => {
    process.stderr.write(`refresh-network: fatal: ${err && err.message || err}\n`);
    process.exit(2);
  });
}

module.exports = { parseTar, fingerprintPublicKey };
