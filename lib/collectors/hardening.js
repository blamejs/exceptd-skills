"use strict";

/**
 * lib/collectors/hardening.js
 *
 * Companion collector for the `hardening` playbook. Linux-only:
 * reads `/proc/sys/kernel/*`, `/proc/cmdline`,
 * `/sys/kernel/security/lockdown`, and `/etc/ssh/sshd_config` to
 * flip deterministic indicators. On non-Linux platforms the
 * precondition fails and the collector emits an empty submission.
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
    const buf = Buffer.alloc(st.size);
    fs.readSync(fd, buf, 0, st.size, 0);
    return buf.toString("utf8");
  } catch { return null; }
  finally { if (fd !== undefined) { try { fs.closeSync(fd); } catch { /* non-fatal */ } } }
}

// Expand the base sshd_config into the effective directive stream by
// inlining `Include <glob>` directives at their textual position.
// Mirrors OpenSSH's parse order: first-match-wins, and the first match
// can come from a drop-in file when `Include` appears earlier in the
// base config than the directive it sets. Drop-in files within an
// Include are processed in lexical order (matching OpenSSH glob).
function expandSshdConfig(baseContent, configDPath) {
  if (!baseContent) return "";
  const out = [];
  for (const raw of baseContent.split(/\r?\n/)) {
    const stripped = raw.replace(/#.*$/, "").trim();
    const m = stripped.match(/^Include\s+(\S+)/i);
    if (!m) { out.push(raw); continue; }
    const glob = m[1];
    // Resolve the include glob — only handle the common
    // `<dir>/*.conf` form; other shapes fall back to no-op.
    let dir = null;
    if (glob.endsWith("/sshd_config.d/*.conf")) {
      // The canonical sshd-config drop-in directory. Honour the
      // path override (tests / chroot / sshd_config.d outside the
      // default location).
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
  // Best-effort: scan uncommented `PermitRootLogin <value>` and
  // `PasswordAuthentication <value>` lines. sshd_config is parsed
  // first-match-wins for most directives.
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
  // Path-override hooks for tests: caller can pass args.paths to
  // redirect /proc / /sys / /etc reads to a synthetic tempdir
  // mirroring the real layout. Without overrides the collector
  // reads the live host paths.
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
  // Force-linux switch lets tests exercise the Linux code path even
  // when running on win32 / darwin. Without it, the platform gate
  // remains the source of truth for whether the collector runs.
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

  // Sysctl reads. `null` means the sysctl path didn't exist (older
  // kernel / non-standard build).
  const kptrRestrict = readSysctl(P.kptrRestrict);
  const unprivUserns = readSysctl(P.unprivUserns);
  const unprivBpf = readSysctl(P.unprivBpf);
  const yamaPtrace = readSysctl(P.yamaPtrace);
  const suidDumpable = readSysctl(P.suidDumpable);
  const cmdline = readFileSafe(P.cmdline) || "";
  const lockdown = readSysctl(P.lockdown) || "";

  // sshd_config: expand Include directives in-place so the
  // first-match-wins parse honours OpenSSH's effective directive
  // order. On Debian/Ubuntu the default sshd_config begins with
  // `Include /etc/ssh/sshd_config.d/*.conf` — drop-in values take
  // precedence over the base file's later lines.
  const sshdBase = readFileSafe(P.sshdConfig);
  const sshdContent = sshdBase ? expandSshdConfig(sshdBase, P.sshdConfigD) : null;
  const sshdParsed = parseSshdEffective(sshdContent);

  // Indicator predicates. Each sysctl-derived indicator emits a
  // verdict ONLY when the underlying sysctl was readable; unreadable
  // sysctls (e.g. masked /proc in a constrained container, kernel
  // built without that knob) leave the indicator unflipped so the
  // runner returns inconclusive rather than forging a "hardened"
  // miss without evidence.
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

  // /proc/cmdline derives kaslr / mitigations / lockdown=. If we
  // couldn't read it at all, those three indicators stay unflipped
  // (inconclusive) rather than asserting an absent string.
  if (cmdline) {
    const kaslrDisabled = /\bnokaslr\b/.test(cmdline) || /\bkaslr=off\b/.test(cmdline);
    const mitigationsOff = /\bmitigations=off\b/.test(cmdline);
    signal_overrides["kaslr-disabled-at-boot"] = kaslrDisabled ? "hit" : "miss";
    signal_overrides["mitigations-off"] = mitigationsOff ? "hit" : "miss";
  }

  // kernel-lockdown-none: the file shows `[none]` OR is absent and
  // /proc/cmdline carries no lockdown= parameter. When both the
  // lockdown file AND /proc/cmdline are unreadable, leave the
  // indicator unflipped.
  if (lockdown || cmdline) {
    const lockdownShowsNone = /\[none\]/.test(lockdown);
    const lockdownCmdline = /\blockdown=(?:integrity|confidentiality)\b/.test(cmdline);
    const lockdownNoneHit =
      (lockdown && lockdownShowsNone) ||
      (!lockdown && cmdline && !lockdownCmdline);
    signal_overrides["kernel-lockdown-none"] = lockdownNoneHit ? "hit" : "miss";
  }

  // sshd-permitrootlogin-yes: emit a verdict only when sshd_config
  // was readable. Missing config (no SSH server) → unflipped.
  let sshdRootHit = false;
  if (sshdContent !== null) {
    sshdRootHit =
      sshdParsed.permitRootLogin === "yes" ||
      sshdParsed.permitRootLogin === "without-password";
    signal_overrides["sshd-permitrootlogin-yes"] = sshdRootHit ? "hit" : "miss";
  }

  const kptrHit = kptrSig === "hit";

  // Per-indicator __fp_checks attestation. The collector attests
  // ONLY the checks it actually performed; operator-judgement /
  // network-required FP checks remain unsatisfied so the runner
  // honestly downgrades to inconclusive.
  //
  //   kptr-restrict-disabled:
  //     [0] kdump / perf debug-session runbook — operator judgement
  //     [1] /proc/kallsyms zero-leakage cross-check — collector CAN
  //         attest (read first line as unprivileged user).
  //   yama-ptrace-permissive:
  //     [0] MAC enforcement (AppArmor / SELinux) — operator
  //     [1] container observability — operator
  //     [2] single-tenant dev VM — operator
  //   kaslr-disabled-at-boot:
  //     [0] kdump runbook — operator
  //     [1] dmesg KASLR offsets — collector cannot read dmesg
  //         without root on most distros (dmesg-restrict=1).
  //   mitigations-off:
  //     [0] HPC/benchmark exemption — operator
  //     [1] single-tenant — operator
  //
  // For kptr-restrict-disabled the kallsyms cross-check is the only
  // FP-check the collector can attest; we attest index 1 when we
  // observed the kallsyms first line carries non-zero hex.
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
