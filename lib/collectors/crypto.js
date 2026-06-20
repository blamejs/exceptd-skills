"use strict";

/**
 * lib/collectors/crypto.js
 *
 * Companion collector for the `crypto` playbook. Linux-only. Reads
 * the host's TLS library state (openssl version + KEM / signature
 * algorithm catalogues) and sshd_config (effective directives after
 * Include expansion) to flip post-quantum-readiness indicators.
 *
 * Skipped indicators (require operator judgement or live behavioural
 * data, left unflipped so the runner returns inconclusive rather
 * than a forced miss):
 *
 *   tls-no-hybrid-group         needs a real TLS handshake against
 *                               a target server
 *   rsa-2048-cert-long-life     cert content + chain walk; sensitivity-
 *                               horizon comparison is operator review
 *   no-crypto-inventory         governance / process indicator
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
    // readFileSync(fd) loops read() to EOF — a single readSync may return
    // fewer than st.size bytes on network/FUSE/sync-backed fds, which would
    // leave the buffer tail NUL-filled and silently drop trailing content.
    // Reading via the already-open fd keeps the fstat-then-read TOCTOU-free.
    return fs.readFileSync(fd, "utf8");
  } catch { return null; }
  finally { if (fd !== undefined) { try { fs.closeSync(fd); } catch { /* non-fatal */ } } }
}

// Same sshd_config Include-expansion logic as the hardening
// collector: first-match-wins, inline drop-in files in lexical
// order at the textual position of the `Include` directive.
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

// First-match-wins parse of KexAlgorithms / MACs / Ciphers /
// PermitRootLogin from the effective sshd_config content.
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

// Compare OpenSSL banner string against the 3.5.0 native-ML-KEM cutoff.
// Returns "hit" (< 3.5.0), "miss" (>= 3.5.0), or undefined (banner
// could not be parsed — collector returns inconclusive).
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

// PQC kex: hit when KexAlgorithms is absent (no PQC by default) OR
// present-without sntrup761x25519 / mlkem768x25519 / mlkem1024.
function parsePqcKex(content, hasSshdContent) {
  if (!hasSshdContent) return undefined;
  if (content == null) return "hit";
  return /sntrup761x25519|mlkem768x25519|mlkem1024/.test(content) ? "miss" : "hit";
}

// Weak mac or cipher: hit when MACs contains hmac-md5 / hmac-sha1
// (without -etm suffix) OR Ciphers contains arcfour / 3des-cbc /
// des-cbc / blowfish-cbc / aes-cbc. The playbook treats every CBC
// mode as weak under modern SSH cipher policy (BEAST / padding
// oracle / chosen-plaintext considerations) — aes128-cbc /
// aes192-cbc / aes256-cbc still appear in legacy sshd configs and
// must be flagged. Both fields absent → undefined (inconclusive).
function parseWeakMacOrCipher(macs, ciphers) {
  if (macs == null && ciphers == null) return undefined;
  const macsWeak = macs && /(?:^|,)(?:hmac-md5(?!-etm)|hmac-sha1(?!-etm))(?:,|$)/.test(macs);
  const cipherWeak = ciphers && /(?:^|,)(?:aes(?:128|192|256)-cbc|arcfour(?:128|256)?|3des-cbc|des-cbc|blowfish-cbc)(?:,|$)/.test(ciphers);
  return (macsWeak || cipherWeak) ? "hit" : "miss";
}

// Either read a path-override fixture (synthetic-tempdir tests) or
// invoke the named binary via execFile-shape spawning. Never
// shell-interpolated. ENOENT / EACCES → null; caller surfaces that
// via collector_errors / unflipped indicators. Some binaries write
// their banner to stderr (e.g. `ssh -V`); others to stdout
// (`openssl version`). Prefer stdout, fall back to stderr when
// stdout is empty so the banner is not lost.
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

  // TLS library version + algorithm catalogues.
  const opensslVer = readOrSpawn(paths.opensslVersionOutput, "openssl", ["version", "-a"], errors);
  const opensslKem = readOrSpawn(paths.opensslKemOutput, "openssl", ["list", "-kem-algorithms"], errors);
  const opensslSig = readOrSpawn(paths.opensslSignatureOutput, "openssl", ["list", "-signature-algorithms"], errors);
  const sshVer = readOrSpawn(paths.sshVersionOutput, "ssh", ["-V"], errors);

  // sshd_config: read base + expand Include directives. The base
  // can come from a path override (tests stage a synthetic file
  // tree); otherwise read /etc/ssh/sshd_config directly.
  const sshdConfigPath = paths.sshdConfig || "/etc/ssh/sshd_config";
  const sshdConfigDPath = paths.sshdConfigD || "/etc/ssh/sshd_config.d";
  const sshdBase = readFileSafe(sshdConfigPath);
  const sshdEffective = sshdBase ? expandSshdConfig(sshdBase, sshdConfigDPath) : null;
  const sshdParsed = parseSshdEffective(sshdEffective);

  // Flip indicators only when the underlying source was readable.
  // Unreadable openssl / sshd_config → indicator stays out of
  // signal_overrides so the runner returns inconclusive rather than
  // asserting a clean posture without evidence.
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

  // certificate-store: list count of *.pem / *.crt under the
  // standard trust roots. Path overridable for tests.
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
