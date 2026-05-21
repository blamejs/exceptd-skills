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
  try {
    const st = fs.statSync(p);
    if (st.size > max) return null;
    return fs.readFileSync(p, "utf8");
  } catch { return null; }
}

function parseSshdEffective(content) {
  // Best-effort: scan uncommented `PermitRootLogin <value>` and
  // `PasswordAuthentication <value>` lines. sshd_config is parsed
  // first-match-wins for most directives; we mirror that.
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

  // sshd_config: most distros ship at /etc/ssh/sshd_config; some
  // also have /etc/ssh/sshd_config.d/*.conf. Read the base file
  // first; if a .d directory exists, concatenate after.
  let sshdContent = readFileSafe(P.sshdConfig);
  try {
    const entries = fs.readdirSync(P.sshdConfigD);
    for (const e of entries) {
      if (!/\.conf$/.test(e)) continue;
      const c = readFileSafe(path.join(P.sshdConfigD, e));
      if (c) sshdContent = (sshdContent || "") + "\n" + c;
    }
  } catch { /* .d not present */ }
  const sshdParsed = parseSshdEffective(sshdContent);

  // Indicator predicates.
  const kptrHit = kptrRestrict === "0";
  const unprivUsernsHit = unprivUserns === "1";
  const unprivBpfHit = unprivBpf === "0";
  const yamaPtraceHit = yamaPtrace === "0";
  const kaslrDisabled = /\bnokaslr\b/.test(cmdline) || /\bkaslr=off\b/.test(cmdline);
  const mitigationsOff = /\bmitigations=off\b/.test(cmdline);
  const corePidDumpable = suidDumpable === "1" || suidDumpable === "2";

  // kernel-lockdown-none: the file shows `[none]` OR is absent and
  // cmdline carries no lockdown= parameter.
  const lockdownShowsNone = /\[none\]/.test(lockdown);
  const lockdownCmdline = /\blockdown=(?:integrity|confidentiality)\b/.test(cmdline);
  const lockdownNoneHit =
    (lockdown && lockdownShowsNone) ||
    (!lockdown && !lockdownCmdline);

  // sshd-permitrootlogin-yes: effective value is `yes` or
  // `without-password` (legacy).
  const sshdRootHit =
    sshdParsed.permitRootLogin === "yes" ||
    sshdParsed.permitRootLogin === "without-password";

  // sshd-password-auth-enabled is marked non-deterministic in the
  // playbook; emit a deterministic hit when the directive is
  // literally `yes` (effective default is `yes` too, but we don't
  // assume the operator's defaults here).
  // Leave unflipped — playbook treats it as a behavioral signal.

  const signal_overrides = {
    "kptr-restrict-disabled": kptrHit ? "hit" : "miss",
    "unprivileged-userns-enabled": unprivUsernsHit ? "hit" : "miss",
    "unprivileged-bpf-allowed": unprivBpfHit ? "hit" : "miss",
    "yama-ptrace-permissive": yamaPtraceHit ? "hit" : "miss",
    "kaslr-disabled-at-boot": kaslrDisabled ? "hit" : "miss",
    "mitigations-off": mitigationsOff ? "hit" : "miss",
    "sshd-permitrootlogin-yes": sshdRootHit ? "hit" : "miss",
    "kernel-lockdown-none": lockdownNoneHit ? "hit" : "miss",
  };

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
