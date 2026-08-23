"use strict";

/**
 * Companion collector for the `hardening` playbook. Linux-only: off Linux the
 * precondition fails and the submission comes back empty.
 *
 * Interface: see lib/collectors/README.md
 */

const fs = require("node:fs");
const path = require("node:path");

const COLLECTOR_ID = "hardening";

function readSysctl(p) {
  try {
    const s = fs.readFileSync(p, "utf8").trim();
    return s;
  } catch { return null; }
}

function readFileSafe(p, max = 256 * 1024) {
  let fd;
  try {
    fd = fs.openSync(p, "r");
    const st = fs.fstatSync(fd);
    if (st.size > max) return null;
    // readFileSync(fd) loops to EOF, where one readSync can return short on a
    // network/FUSE fd and NUL-fill the tail; via the fd it is also TOCTOU-free.
    return fs.readFileSync(fd, "utf8");
  } catch { return null; }
  finally { if (fd !== undefined) { try { fs.closeSync(fd); } catch { /* non-fatal */ } } }
}

// Inlines `Include <glob>` at its textual position: OpenSSH is first-match-wins,
// so a drop-in included early beats a later line in the base config.
function expandSshdConfig(baseContent, configDPath) {
  if (!baseContent) return "";
  const out = [];
  for (const raw of baseContent.split(/\r?\n/)) {
    const stripped = raw.replace(/#.*$/, "").trim();
    const m = stripped.match(/^Include\s+(\S+)/i);
    if (!m) { out.push(raw); continue; }
    const glob = m[1];
    // Only the common `<dir>/*.conf` form resolves; other shapes are no-ops.
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

function parseSshdEffective(content) {
  // First occurrence wins, as sshd_config parses these directives.
  if (!content) return { permitRootLogin: null, passwordAuth: null };
  const out = { permitRootLogin: null, passwordAuth: null };
  for (const raw of content.split(/\r?\n/)) {
    const line = raw.replace(/#.*$/, "").trim();
    if (!line) continue;
    const m1 = line.match(/^PermitRootLogin\s+(\S+)/i);
    if (m1 && out.permitRootLogin == null) out.permitRootLogin = m1[1].toLowerCase();
    const m2 = line.match(/^PasswordAuthentication\s+(\S+)/i);
    if (m2 && out.passwordAuth == null) out.passwordAuth = m2[1].toLowerCase();
  }
  return out;
}

function collect({ cwd = process.cwd(), env = process.env, args = {} } = {}) {
  const errors = [];
  const startTime = Date.now();
  const root = path.resolve(cwd);
  // args.paths redirects the /proc, /sys and /etc reads at a synthetic tree.
  const paths = args.paths || {};
  const P = {
    kptrRestrict: paths.kptrRestrict || "/proc/sys/kernel/kptr_restrict",
    unprivUserns: paths.unprivUserns || "/proc/sys/kernel/unprivileged_userns_clone",
    unprivBpf: paths.unprivBpf || "/proc/sys/kernel/unprivileged_bpf_disabled",
    yamaPtrace: paths.yamaPtrace || "/proc/sys/kernel/yama/ptrace_scope",
    suidDumpable: paths.suidDumpable || "/proc/sys/fs/suid_dumpable",
    cmdline: paths.cmdline || "/proc/cmdline",
    lockdown: paths.lockdown || "/sys/kernel/security/lockdown",
    sshdConfig: paths.sshdConfig || "/etc/ssh/sshd_config",
    sshdConfigD: paths.sshdConfigD || "/etc/ssh/sshd_config.d",
    kallsyms: paths.kallsyms || "/proc/kallsyms",
  };
  // args.forceLinux exercises the Linux path from win32 / darwin.
  const isLinux = args.forceLinux === true || process.platform === "linux";

  if (!isLinux) {
    return {
      precondition_checks: { "linux-platform": false },
      artifacts: {
        "sysctl-kernel-hardening": {
          value: "skipped — non-Linux platform",
          captured: false,
          reason: `process.platform=${process.platform} (linux required)`,
        },
        "kernel-cmdline": {
          value: "skipped — non-Linux platform",
          captured: false,
          reason: `process.platform=${process.platform} (linux required)`,
        },
        "sshd-config": {
          value: "skipped — non-Linux platform",
          captured: false,
          reason: `process.platform=${process.platform} (linux required)`,
        },
        "kernel-lockdown": {
          value: "skipped — non-Linux platform",
          captured: false,
          reason: `process.platform=${process.platform} (linux required)`,
        },
      },
      signal_overrides: {},
      collector_meta: {
        collector_id: COLLECTOR_ID,
        collector_version: "2026-05-20",
        platform: process.platform,
        captured_at: new Date().toISOString(),
        cwd: root,
        duration_ms: Date.now() - startTime,
      },
      collector_errors: errors,
    };
  }

  // `null` means the sysctl path is absent (older kernel, non-standard build).
  const kptrRestrict = readSysctl(P.kptrRestrict);
  const unprivUserns = readSysctl(P.unprivUserns);
  const unprivBpf = readSysctl(P.unprivBpf);
  const yamaPtrace = readSysctl(P.yamaPtrace);
  const suidDumpable = readSysctl(P.suidDumpable);
  const cmdline = readFileSafe(P.cmdline) || "";
  const lockdown = readSysctl(P.lockdown) || "";

  const sshdBase = readFileSafe(P.sshdConfig);
  const sshdContent = sshdBase ? expandSshdConfig(sshdBase, P.sshdConfigD) : null;
  const sshdParsed = parseSshdEffective(sshdContent);

  // A sysctl-derived indicator flips only when the sysctl was readable, so an
  // unreadable knob reports inconclusive rather than a "hardened" miss.
  function fromSysctl(value, hitWhen) {
    if (value == null) return undefined; // unreadable → inconclusive
    return value === hitWhen ? "hit" : "miss";
  }

  const signal_overrides = {};
  const kptrSig = fromSysctl(kptrRestrict, "0");
  if (kptrSig !== undefined) signal_overrides["kptr-restrict-disabled"] = kptrSig;
  const usernsSig = fromSysctl(unprivUserns, "1");
  if (usernsSig !== undefined) signal_overrides["unprivileged-userns-enabled"] = usernsSig;
  const bpfSig = fromSysctl(unprivBpf, "0");
  if (bpfSig !== undefined) signal_overrides["unprivileged-bpf-allowed"] = bpfSig;
  const yamaSig = fromSysctl(yamaPtrace, "0");
  if (yamaSig !== undefined) signal_overrides["yama-ptrace-permissive"] = yamaSig;

  // An unreadable cmdline leaves both unflipped, not asserted against nothing.
  if (cmdline) {
    const kaslrDisabled = /\bnokaslr\b/.test(cmdline) || /\bkaslr=off\b/.test(cmdline);
    const mitigationsOff = /\bmitigations=off\b/.test(cmdline);
    signal_overrides["kaslr-disabled-at-boot"] = kaslrDisabled ? "hit" : "miss";
    signal_overrides["mitigations-off"] = mitigationsOff ? "hit" : "miss";
  }

  // Lockdown is none when the file shows `[none]`, or it is absent and no
  // lockdown= rides the cmdline. Both unreadable leaves the indicator unflipped.
  if (lockdown || cmdline) {
    const lockdownShowsNone = /\[none\]/.test(lockdown);
    const lockdownCmdline = /\blockdown=(?:integrity|confidentiality)\b/.test(cmdline);
    const lockdownNoneHit =
      (lockdown && lockdownShowsNone) ||
      (!lockdown && cmdline && !lockdownCmdline);
    signal_overrides["kernel-lockdown-none"] = lockdownNoneHit ? "hit" : "miss";
  }

  // A missing sshd_config (no SSH server) leaves this unflipped.
  let sshdRootHit = false;
  if (sshdContent !== null) {
    sshdRootHit =
      sshdParsed.permitRootLogin === "yes" ||
      sshdParsed.permitRootLogin === "without-password";
    signal_overrides["sshd-permitrootlogin-yes"] = sshdRootHit ? "hit" : "miss";
  }

  const kptrHit = kptrSig === "hit";

  // __fp_checks attests only the checks actually performed; the rest stay
  // unsatisfied so the runner downgrades to inconclusive. Index 1 of
  // kptr-restrict-disabled is the /proc/kallsyms leakage cross-check.
  if (kptrHit) {
    let kallsymsLeaks = false;
    try {
      const head = fs.readFileSync(P.kallsyms, { encoding: "utf8" }).split(/\r?\n/, 1)[0] || "";
      const tok = head.split(/\s+/, 1)[0] || "";
      // Non-zero addr → kernel pointers are leaked → indicator is real.
      kallsymsLeaks = /[1-9a-f]/i.test(tok);
    } catch { /* can't read */ }
    if (kallsymsLeaks) {
      signal_overrides["kptr-restrict-disabled__fp_checks"] = { "1": true };
    }
  }

  const artifacts = {
    "sysctl-kernel-hardening": {
      value: [
        `kptr_restrict=${kptrRestrict ?? "(absent)"}`,
        `unprivileged_userns_clone=${unprivUserns ?? "(absent)"}`,
        `unprivileged_bpf_disabled=${unprivBpf ?? "(absent)"}`,
        `yama/ptrace_scope=${yamaPtrace ?? "(absent)"}`,
        `fs.suid_dumpable=${suidDumpable ?? "(absent)"}`,
      ].join("; "),
      captured: true,
    },
    "kernel-cmdline": cmdline
      ? { value: cmdline.trim(), captured: true }
      : { value: "(/proc/cmdline unreadable)", captured: false, reason: "could not read /proc/cmdline" },
    "kernel-lockdown": lockdown
      ? { value: lockdown, captured: true }
      : { value: "/sys/kernel/security/lockdown absent — lockdown LSM not loaded", captured: true },
    "sshd-config": sshdContent
      ? { value: `PermitRootLogin=${sshdParsed.permitRootLogin ?? "(unset; sshd default applies)"}; PasswordAuthentication=${sshdParsed.passwordAuth ?? "(unset)"}`, captured: true }
      : { value: "/etc/ssh/sshd_config unreadable", captured: false, reason: "/etc/ssh/sshd_config missing or inaccessible" },
  };

  return {
    precondition_checks: {
      "linux-platform": true,
    },
    artifacts,
    signal_overrides,
    collector_meta: {
      collector_id: COLLECTOR_ID,
      collector_version: "2026-05-20",
      platform: process.platform,
      captured_at: new Date().toISOString(),
      cwd: root,
      duration_ms: Date.now() - startTime,
    },
    collector_errors: errors,
  };
}

module.exports = { playbook_id: COLLECTOR_ID, collect };
