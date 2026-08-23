"use strict";

/**
 * Companion collector for the `kernel` playbook: the linux-platform and
 * uname-available preconditions, plus the kernel release, cmdline and sysctl
 * snapshot its indicators read. Off Linux it reports the visibility gap rather
 * than staying silent. Interface: lib/collectors/README.md
 */

const { execFileSync } = require("node:child_process");
const path = require("node:path");

const COLLECTOR_ID = "kernel";

function runUname(arg) {
  try {
    const out = execFileSync("uname", [arg], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], timeout: 5000 });
    return { ok: true, value: out.trim() };
  } catch (e) {
    return { ok: false, reason: (e && e.message) || String(e) };
  }
}

function collect({ cwd = process.cwd(), env = process.env, args = {} } = {}) {
  const errors = [];

  const linuxPlatform = process.platform === "linux";

  const unameR = runUname("-r");
  const unameAvailable = unameR.ok;
  if (!unameAvailable && linuxPlatform) {
    errors.push({
      kind: "command_unavailable",
      reason: `\`uname -r\` failed on linux: ${unameR.reason}`,
    });
  }

  // captured=false carries the reason, so the runner reads dependent indicators
  // as inconclusive rather than as a miss.
  const artifacts = {};
  if (unameR.ok) {
    artifacts["kernel-release"] = { value: unameR.value, captured: true };
  } else {
    artifacts["kernel-release"] = {
      value: null,
      captured: false,
      reason: linuxPlatform
        ? `uname -r failed: ${unameR.reason}`
        : `non-linux platform (${process.platform}); uname not invoked`,
    };
  }

  // kernel-cmdline feeds the KASLR / unpriv-userns / unpriv-bpf indicators.
  if (linuxPlatform) {
    try {
      const fs = require("node:fs");
      const cmdline = fs.readFileSync("/proc/cmdline", "utf8").trim();
      artifacts["kernel-cmdline"] = { value: cmdline, captured: true };
    } catch (e) {
      errors.push({
        artifact_id: "kernel-cmdline",
        kind: "read_failed",
        reason: `/proc/cmdline read failed: ${e.message}`,
      });
    }
    try {
      const fs = require("node:fs");
      const sysctls = {};
      const paths = [
        "/proc/sys/kernel/unprivileged_userns_clone",
        "/proc/sys/kernel/unprivileged_bpf_disabled",
        "/proc/sys/kernel/randomize_va_space",
      ];
      for (const p of paths) {
        try {
          sysctls[path.basename(p)] = fs.readFileSync(p, "utf8").trim();
        } catch {
          // A missing file means the sysctl does not exist on this kernel.
        }
      }
      if (Object.keys(sysctls).length) {
        artifacts["sysctl-snapshot"] = { value: JSON.stringify(sysctls), captured: true };
      }
    } catch (e) {
      errors.push({
        artifact_id: "sysctl-snapshot",
        kind: "read_failed",
        reason: e.message,
      });
    }
  }

  // The running kernel's build config backs the CONFIG_* false-positive checks:
  // a sysctl is moot when the feature is compiled out. Often unreadable.
  let kernelConfig = null;
  if (linuxPlatform && unameR.ok) {
    try {
      const fs = require("node:fs");
      kernelConfig = fs.readFileSync(`/boot/config-${unameR.value}`, "utf8");
    } catch { /* config not readable — CONFIG_* checks stay unattested */ }
  }

  // kver-in-affected-range needs the CVE affected-version catalog, so the runner
  // correlates that; only straight sysctl reads are decided here.
  const signal_overrides = {};
  const sysctl = artifacts["sysctl-snapshot"];
  if (sysctl && sysctl.captured) {
    let parsed = null;
    try { parsed = JSON.parse(sysctl.value); } catch {}
    if (parsed) {
      // kaslr-disabled: randomize_va_space < 2 (0 = off, 1 = partial, 2 = full).
      if (parsed.randomize_va_space != null) {
        const v = parseInt(parsed.randomize_va_space, 10);
        signal_overrides["kaslr-disabled"] = (v < 2) ? "hit" : "miss";
      }
      // unprivileged_userns_clone == 1 means unprivileged userns is enabled.
      if (parsed.unprivileged_userns_clone != null) {
        const v = parseInt(parsed.unprivileged_userns_clone, 10);
        const hit = v === 1;
        signal_overrides["unpriv-userns-enabled"] = hit ? "hit" : "miss";
        // Attests FP[1] only: the sysctl is live only when userns is compiled in.
        if (hit && kernelConfig && /^CONFIG_USER_NS=y$/m.test(kernelConfig)) {
          signal_overrides["unpriv-userns-enabled__fp_checks"] = { "1": true };
        }
      }
      // unprivileged_bpf_disabled == 0 means unprivileged BPF is allowed.
      if (parsed.unprivileged_bpf_disabled != null) {
        const v = parseInt(parsed.unprivileged_bpf_disabled, 10);
        const hit = v === 0;
        signal_overrides["unpriv-bpf-allowed"] = hit ? "hit" : "miss";
        // Attests FP[0] only: the sysctl is moot if BPF is compiled out.
        if (hit && kernelConfig &&
            /^CONFIG_BPF_SYSCALL=y$/m.test(kernelConfig) &&
            /^CONFIG_BPF_JIT=y$/m.test(kernelConfig)) {
          signal_overrides["unpriv-bpf-allowed__fp_checks"] = { "0": true };
        }
      }
    }
  }

  return {
    precondition_checks: {
      "linux-platform": linuxPlatform,
      "uname-available": unameAvailable,
    },
    artifacts,
    signal_overrides,
    collector_meta: {
      collector_id: COLLECTOR_ID,
      collector_version: "2026-05-20",
      platform: process.platform,
      captured_at: new Date().toISOString(),
      cwd,
    },
    collector_errors: errors,
  };
}

module.exports = { playbook_id: COLLECTOR_ID, collect };
