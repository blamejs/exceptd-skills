"use strict";

/**
 * Companion collector for the `crypto` playbook, Linux only. Reads the host's
 * TLS library state (openssl version, KEM and signature catalogues) and the
 * effective sshd_config after Include expansion, to flip post-quantum readiness
 * indicators. Indicators needing a live handshake, a certificate-chain review
 * or governance evidence are left unflipped.
 *
 * Interface: see lib/collectors/README.md
 */

const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const COLLECTOR_ID = "crypto";

function readFileSafe(p, max = 256 * 1024) {
  let fd;
  try {
    fd = fs.openSync(p, "r");
    const st = fs.fstatSync(fd);
    if (st.size > max) return null;
    // readFileSync(fd), never a single readSync: on network/FUSE fds a short read
    // leaves the tail NUL-filled. The open fd also keeps fstat-then-read TOCTOU-free.
    return fs.readFileSync(fd, "utf8");
  } catch { return null; }
  finally { if (fd !== undefined) { try { fs.closeSync(fd); } catch { /* non-fatal */ } } }
}

// Drop-in files are inlined in lexical order at the textual position of the
// `Include` directive, so a later first-match-wins parse sees what sshd sees.
// The hardening collector expands sshd_config the same way.
function expandSshdConfig(baseContent, configDPath) {
  if (!baseContent) return "";
  const out = [];
  for (const raw of baseContent.split(/\r?\n/)) {
    const stripped = raw.replace(/#.*$/, "").trim();
    const m = stripped.match(/^Include\s+(\S+)/i);
    if (!m) { out.push(raw); continue; }
    const glob = m[1];
    let dir = null;
    if (glob.endsWith("/sshd_config.d/*.conf")) {
      dir = configDPath;
    } else {
      const dirMatch = glob.match(/^(.*)\/\*\.conf$/);
      if (dirMatch) dir = dirMatch[1];
    }
    if (!dir) { out.push(raw); continue; }
    let entries;
    try { entries = fs.readdirSync(dir).filter(e => /\.conf$/.test(e)).sort(); }
    catch { out.push(raw); continue; }
    for (const e of entries) {
      const c = readFileSafe(path.join(dir, e));
      if (c == null) continue;
      out.push(`# === drop-in: ${e} ===`);
      out.push(c);
    }
  }
  return out.join("\n");
}

// First match wins, as in sshd itself; an unset directive stays null.
function parseSshdEffective(content) {
  if (content == null) return { kex: null, macs: null, ciphers: null };
  const out = { kex: null, macs: null, ciphers: null };
  for (const raw of content.split(/\r?\n/)) {
    const line = raw.replace(/#.*$/, "").trim();
    if (!line) continue;
    const m1 = line.match(/^KexAlgorithms\s+(\S+)/i);
    if (m1 && out.kex == null) out.kex = m1[1].toLowerCase();
    const m2 = line.match(/^MACs\s+(\S+)/i);
    if (m2 && out.macs == null) out.macs = m2[1].toLowerCase();
    const m3 = line.match(/^Ciphers\s+(\S+)/i);
    if (m3 && out.ciphers == null) out.ciphers = m3[1].toLowerCase();
  }
  return out;
}

// 3.5.0 is the native-ML-KEM cutoff: "hit" below it, "miss" at or above, and
// undefined when the banner does not parse, which leaves it inconclusive.
function compareOpensslVersion(verStr) {
  if (!verStr) return undefined;
  const m = verStr.match(/OpenSSL\s+(\d+)\.(\d+)\.(\d+)/);
  if (!m) return undefined;
  const maj = Number(m[1]);
  const min = Number(m[2]);
  if (maj < 3) return "hit";
  if (maj === 3 && min < 5) return "hit";
  return "miss";
}

// Hits when KexAlgorithms is absent (no PQC kex by default) or lacks a hybrid.
function parsePqcKex(content, hasSshdContent) {
  if (!hasSshdContent) return undefined;
  if (content == null) return "hit";
  return /sntrup761x25519|mlkem768x25519|mlkem1024/.test(content) ? "miss" : "hit";
}

// The playbook treats EVERY CBC mode as weak, aes256-cbc included. hmac-md5 and
// hmac-sha1 are weak only without the -etm suffix. Both fields absent leaves the
// indicator undefined, hence inconclusive.
function parseWeakMacOrCipher(macs, ciphers) {
  if (macs == null && ciphers == null) return undefined;
  const macsWeak = macs && /(?:^|,)(?:hmac-md5(?!-etm)|hmac-sha1(?!-etm))(?:,|$)/.test(macs);
  const cipherWeak = ciphers && /(?:^|,)(?:aes(?:128|192|256)-cbc|arcfour(?:128|256)?|3des-cbc|des-cbc|blowfish-cbc)(?:,|$)/.test(ciphers);
  return (macsWeak || cipherWeak) ? "hit" : "miss";
}

// A path override reads a fixture; otherwise the binary is spawned argv-style,
// never through a shell. A missing binary returns null, which the caller
// surfaces as an unflipped indicator. `ssh -V` writes its banner to stderr and
// `openssl version` to stdout, so stdout wins and stderr is the fallback.
function readOrSpawn(pathOverride, cmd, args, errors) {
  if (pathOverride != null) return readFileSafe(pathOverride);
  const r = spawnSync(cmd, args, {
    encoding: "utf8",
    timeout: 5000,
    stdio: ["ignore", "pipe", "pipe"],
  });
  if (r.error) {
    if (errors) errors.push({ artifact_id: cmd, kind: "spawn_failed", reason: `${cmd}: ${r.error.code || r.error.message}` });
    return null;
  }
  const out = r.stdout || "";
  const err = r.stderr || "";
  if (out.length === 0 && err.length === 0) return null;
  return out.length > 0 ? out : err;
}

function collect({ cwd = process.cwd(), env = process.env, args = {} } = {}) {
  const errors = [];
  const startTime = Date.now();
  const root = path.resolve(cwd);
  const paths = args.paths || {};
  const isLinux = args.forceLinux === true || process.platform === "linux";

  if (!isLinux) {
    return {
      precondition_checks: { "linux-platform": false },
      artifacts: {
        "openssl-version": { value: "skipped — non-Linux platform", captured: false, reason: `process.platform=${process.platform} (linux required)` },
        "sshd-config-effective": { value: "skipped — non-Linux platform", captured: false, reason: `process.platform=${process.platform} (linux required)` },
      },
      signal_overrides: {},
      collector_meta: {
        collector_id: COLLECTOR_ID,
        collector_version: "2026-05-21",
        platform: process.platform,
        captured_at: new Date().toISOString(),
        cwd: root,
        duration_ms: Date.now() - startTime,
      },
      collector_errors: errors,
    };
  }

  const opensslVer = readOrSpawn(paths.opensslVersionOutput, "openssl", ["version", "-a"], errors);
  const opensslKem = readOrSpawn(paths.opensslKemOutput, "openssl", ["list", "-kem-algorithms"], errors);
  const opensslSig = readOrSpawn(paths.opensslSignatureOutput, "openssl", ["list", "-signature-algorithms"], errors);
  const sshVer = readOrSpawn(paths.sshVersionOutput, "ssh", ["-V"], errors);

  // A path override lets a test stage a synthetic tree in place of /etc/ssh.
  const sshdConfigPath = paths.sshdConfig || "/etc/ssh/sshd_config";
  const sshdConfigDPath = paths.sshdConfigD || "/etc/ssh/sshd_config.d";
  const sshdBase = readFileSafe(sshdConfigPath);
  const sshdEffective = sshdBase ? expandSshdConfig(sshdBase, sshdConfigDPath) : null;
  const sshdParsed = parseSshdEffective(sshdEffective);

  // An indicator is flipped only when its source was readable; otherwise it stays
  // out of this object and the runner returns inconclusive.
  const signal_overrides = {};

  const verSig = compareOpensslVersion(opensslVer);
  if (verSig !== undefined) signal_overrides["openssl-pre-3-5"] = verSig;

  if (opensslKem !== null) {
    const hasMLKEM = /mlkem(?:512|768|1024)/i.test(opensslKem);
    signal_overrides["ml-kem-absent"] = hasMLKEM ? "miss" : "hit";
  }
  if (opensslSig !== null) {
    const hasPQCsig = /ml-?dsa|slh-?dsa|sphincs|falcon/i.test(opensslSig);
    signal_overrides["ml-dsa-slh-dsa-absent"] = hasPQCsig ? "miss" : "hit";
  }

  const kexSig = parsePqcKex(sshdParsed.kex, sshdEffective !== null);
  if (kexSig !== undefined) signal_overrides["sshd-no-pqc-kex"] = kexSig;

  const weakSig = sshdEffective !== null
    ? parseWeakMacOrCipher(sshdParsed.macs, sshdParsed.ciphers)
    : undefined;
  if (weakSig !== undefined) signal_overrides["weak-mac-or-cipher"] = weakSig;

  let certStoreSummary;
  const certStoreRoot = paths.certStore || "/etc/ssl/certs";
  try {
    const certEntries = fs.readdirSync(certStoreRoot).filter(e => /\.(pem|crt)$/i.test(e));
    certStoreSummary = { value: `${certEntries.length} cert file(s) under ${certStoreRoot}`, captured: true };
  } catch {
    certStoreSummary = { value: `${certStoreRoot} unreadable`, captured: false, reason: "trust-anchor directory not readable" };
  }

  const artifacts = {
    "openssl-version": opensslVer
      ? { value: (opensslVer.split(/\r?\n/, 1)[0] || "").trim(), captured: true }
      : { value: "openssl version banner unavailable", captured: false, reason: "openssl binary missing or non-readable" },
    "openssl-kem-algorithms": opensslKem !== null
      ? { value: opensslKem.slice(0, 2048), captured: true }
      : { value: "openssl list -kem-algorithms unavailable", captured: false, reason: "openssl list exec failed or fixture absent" },
    "openssl-signature-algorithms": opensslSig !== null
      ? { value: opensslSig.slice(0, 2048), captured: true }
      : { value: "openssl list -signature-algorithms unavailable", captured: false, reason: "openssl list exec failed or fixture absent" },
    "openssl-providers": { value: "not captured by this collector — see openssl-version banner for provider line", captured: false, reason: "openssl list -providers depends on runtime config; deferred to operator evidence" },
    "ssh-version": sshVer
      ? { value: sshVer.trim().split(/\r?\n/, 1)[0], captured: true }
      : { value: "ssh -V unavailable", captured: false, reason: "ssh binary missing or non-readable" },
    "sshd-config-effective": sshdEffective !== null
      ? {
          value: [
            `KexAlgorithms=${sshdParsed.kex ?? "(unset)"}`,
            `MACs=${sshdParsed.macs ?? "(unset)"}`,
            `Ciphers=${sshdParsed.ciphers ?? "(unset)"}`,
          ].join("; "),
          captured: true,
        }
      : { value: `${sshdConfigPath} unreadable or absent`, captured: false, reason: "no sshd_config — host may not run sshd" },
    "certificate-store": certStoreSummary,
  };

  return {
    precondition_checks: { "linux-platform": true },
    artifacts,
    signal_overrides,
    collector_meta: {
      collector_id: COLLECTOR_ID,
      collector_version: "2026-05-21",
      platform: process.platform,
      captured_at: new Date().toISOString(),
      cwd: root,
      duration_ms: Date.now() - startTime,
    },
    collector_errors: errors,
  };
}

module.exports = { playbook_id: COLLECTOR_ID, collect };
