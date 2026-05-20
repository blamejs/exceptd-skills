"use strict";

/**
 * lib/collectors/kernel.js
 *
 * Companion collector for the `kernel` playbook. Establishes
 * preconditions (linux-platform / uname-available) and captures the
 * kernel release string for the kver-in-affected-range indicator.
 *
 * Scope: Linux only. On macOS / Windows the playbook's linux-platform
 * precondition halts at preflight; the collector reports that
 * truthfully so the operator sees the visibility gap without the
 * runner having to re-derive it.
 *
 * Interface: see lib/collectors/README.md
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

  // Precondition 1: linux-platform. Use process.platform first
  // (Node-derived, always available); cross-check against uname -s
  // when available.
  const linuxPlatform = process.platform === "linux";

  // Precondition 2: uname-available. Pure capability check.
  const unameR = runUname("-r");
  const unameAvailable = unameR.ok;
  if (!unameAvailable && linuxPlatform) {
    errors.push({
      kind: "command_unavailable",
      reason: `\`uname -r\` failed on linux: ${unameR.reason}`,
    });
  }

  // Artifact: kernel-release. The exact string returned by `uname -r`,
  // e.g. "5.15.0-69-generic". When uname is unavailable, the artifact
  // is captured=false with the reason; the runner treats the
  // dependent indicators as inconclusive.
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

  // Optional artifact: cmdline. Not always required but useful for
  // KASLR / unpriv-userns / unpriv-bpf indicator evaluation. Read
  // from /proc directly so we don't fork another process.
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
    // sysctl snapshot for kernel.unprivileged_userns_clone +
    // kernel.unprivileged_bpf_disabled when readable.
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
          // Best-effort; a missing file usually means the sysctl
          // doesn't exist on this kernel.
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

  // Signal overrides: we can't decide kver-in-affected-range without
  // the CVE-affected-version catalog (the runner does that
  // correlation). But we CAN flip the deterministic indicators that
  // read directly off the sysctl snapshot.
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
      // unpriv-userns-enabled: clone == 1 means enabled (risky).
      if (parsed.unprivileged_userns_clone != null) {
        const v = parseInt(parsed.unprivileged_userns_clone, 10);
        signal_overrides["unpriv-userns-enabled"] = (v === 1) ? "hit" : "miss";
      }
      // unpriv-bpf-allowed: bpf_disabled == 0 means unprivileged BPF
      // is allowed (risky).
      if (parsed.unprivileged_bpf_disabled != null) {
        const v = parseInt(parsed.unprivileged_bpf_disabled, 10);
        signal_overrides["unpriv-bpf-allowed"] = (v === 0) ? "hit" : "miss";
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
