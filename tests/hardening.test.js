"use strict";

/**
 * tests/hardening.test.js
 *
 * Behavioral coverage for the `hardening` collector
 * (lib/collectors/hardening.js): the Linux-only companion collector that
 * reads /proc/sys/kernel/*, /proc/cmdline,
 * /sys/kernel/security/lockdown, and /etc/ssh/sshd_config to flip
 * deterministic kernel-hardening indicators.
 *
 * The collector exposes two test seams: args.forceLinux (drive the Linux
 * code path on win32/darwin) and args.paths (redirect every /proc /sys
 * /etc read into a synthetic tempdir mirror). Every test builds a small
 * fixture tree in os.tmpdir() and points the collector at it — no host
 * system files are read or mutated, and the suite is deterministic on any
 * platform.
 *
 * Discipline: assert the EXACT verdict; pair presence with content;
 * exercise hit + miss + abstain (unreadable -> unflipped) per indicator.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const os = require("node:os");

const ROOT = path.join(__dirname, "..");
const collector = require(path.join(ROOT, "lib", "collectors", "hardening.js"));

const ENVELOPE_KEYS = [
  "precondition_checks", "artifacts", "signal_overrides",
  "collector_meta", "collector_errors",
];

function mkTree(prefix = "hardening-fix-") {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}
function w(root, rel, content) {
  const full = path.join(root, rel);
  fs.mkdirSync(path.dirname(full), { recursive: true });
  fs.writeFileSync(full, content);
  return full;
}

/**
 * Build a complete synthetic path map under `root`. Pass `overrides` to set
 * specific file contents; any key NOT supplied points at a guaranteed-absent
 * path so the corresponding indicator abstains (stays unflipped) unless the
 * test wires it.
 */
function buildPaths(root, files) {
  const absent = path.join(root, "__absent__");
  const P = {
    kptrRestrict: absent + "-kptr",
    unprivUserns: absent + "-userns",
    unprivBpf: absent + "-bpf",
    yamaPtrace: absent + "-yama",
    suidDumpable: absent + "-suid",
    cmdline: absent + "-cmdline",
    lockdown: absent + "-lockdown",
    sshdConfig: absent + "-sshd",
    sshdConfigD: absent + "-sshd.d",
    kallsyms: absent + "-kallsyms",
  };
  for (const [key, content] of Object.entries(files || {})) {
    if (key === "sshdConfigD") continue; // handled by caller as a dir
    const full = w(root, key + ".file", content);
    P[key] = full;
  }
  return P;
}

function runLinux(P) {
  return collector.collect({ cwd: process.cwd(), env: {}, args: { forceLinux: true, paths: P } });
}

// ---------------------------------------------------------------------------
// Module contract
// ---------------------------------------------------------------------------

test("exports playbook_id 'hardening' + a collect() function", () => {
  assert.equal(collector.playbook_id, "hardening");
  assert.equal(typeof collector.collect, "function");
});

// ---------------------------------------------------------------------------
// Non-Linux platform gate — empty submission with the precondition false
// ---------------------------------------------------------------------------

test("on a non-Linux platform the precondition fails and no signals flip", () => {
  // forceLinux omitted; force the non-Linux branch by NOT setting it and
  // relying on the platform gate. To make this deterministic on a Linux CI
  // host too, drive the documented non-Linux return shape by asserting it
  // only when the platform is actually non-Linux; otherwise assert the
  // Linux branch produces the populated shape.
  const r = collector.collect({ cwd: process.cwd(), env: {}, args: {} });
  for (const k of ENVELOPE_KEYS) assert.ok(k in r, `must carry ${k}`);
  if (process.platform !== "linux") {
    assert.equal(r.precondition_checks["linux-platform"], false);
    assert.deepEqual(r.signal_overrides, {});
    assert.equal(r.artifacts["sysctl-kernel-hardening"].captured, false);
  } else {
    assert.equal(r.precondition_checks["linux-platform"], true);
  }
});

test("forceLinux drives the Linux code path on any host", () => {
  const root = mkTree();
  try {
    const P = buildPaths(root, {});
    const r = runLinux(P);
    assert.equal(r.precondition_checks["linux-platform"], true);
    for (const k of ENVELOPE_KEYS) assert.ok(k in r, `must carry ${k}`);
    assert.equal(r.collector_meta.collector_id, "hardening");
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// sysctl-derived indicators — hit, miss, and abstain (sysctl unreadable)
// ---------------------------------------------------------------------------

test("kptr-restrict-disabled hits when kptr_restrict reads 0", () => {
  const root = mkTree();
  try {
    const P = buildPaths(root, { kptrRestrict: "0\n", kallsyms: "ffffffff81000000 T _stext\n" });
    const r = runLinux(P);
    assert.equal(r.signal_overrides["kptr-restrict-disabled"], "hit");
    // kallsyms first-line carries a non-zero hex address -> FP-check [1] attested.
    assert.deepEqual(r.signal_overrides["kptr-restrict-disabled__fp_checks"], { "1": true });
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("kptr-restrict-disabled misses when kptr_restrict reads 1 (restricted)", () => {
  const root = mkTree();
  try {
    const P = buildPaths(root, { kptrRestrict: "1\n" });
    const r = runLinux(P);
    assert.equal(r.signal_overrides["kptr-restrict-disabled"], "miss");
    // No hit -> no FP-check attestation.
    assert.ok(!("kptr-restrict-disabled__fp_checks" in r.signal_overrides));
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("an unreadable sysctl leaves its indicator unflipped (inconclusive)", () => {
  const root = mkTree();
  try {
    // kptrRestrict path points at an absent file -> indicator must NOT appear.
    const P = buildPaths(root, {});
    const r = runLinux(P);
    assert.ok(!("kptr-restrict-disabled" in r.signal_overrides),
      "an unreadable sysctl must leave the indicator unflipped, not forge a miss");
    assert.ok(!("unprivileged-userns-enabled" in r.signal_overrides));
    assert.ok(!("unprivileged-bpf-allowed" in r.signal_overrides));
    assert.ok(!("yama-ptrace-permissive" in r.signal_overrides));
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("unprivileged-userns / bpf / yama hit on their permissive sysctl values", () => {
  const root = mkTree();
  try {
    const P = buildPaths(root, {
      unprivUserns: "1\n",   // 1 => unprivileged userns enabled
      unprivBpf: "0\n",      // 0 => unprivileged bpf allowed
      yamaPtrace: "0\n",     // 0 => yama ptrace permissive
    });
    const r = runLinux(P);
    assert.equal(r.signal_overrides["unprivileged-userns-enabled"], "hit");
    assert.equal(r.signal_overrides["unprivileged-bpf-allowed"], "hit");
    assert.equal(r.signal_overrides["yama-ptrace-permissive"], "hit");
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("unprivileged-userns / bpf / yama miss on their hardened sysctl values", () => {
  const root = mkTree();
  try {
    const P = buildPaths(root, {
      unprivUserns: "0\n",
      unprivBpf: "1\n",
      yamaPtrace: "1\n",
    });
    const r = runLinux(P);
    assert.equal(r.signal_overrides["unprivileged-userns-enabled"], "miss");
    assert.equal(r.signal_overrides["unprivileged-bpf-allowed"], "miss");
    assert.equal(r.signal_overrides["yama-ptrace-permissive"], "miss");
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// /proc/cmdline derived — kaslr / mitigations
// ---------------------------------------------------------------------------

test("kaslr-disabled-at-boot + mitigations-off hit when cmdline carries nokaslr + mitigations=off", () => {
  const root = mkTree();
  try {
    const P = buildPaths(root, {
      cmdline: "BOOT_IMAGE=/vmlinuz root=/dev/sda1 nokaslr mitigations=off\n",
    });
    const r = runLinux(P);
    assert.equal(r.signal_overrides["kaslr-disabled-at-boot"], "hit");
    assert.equal(r.signal_overrides["mitigations-off"], "hit");
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("kaslr-disabled-at-boot + mitigations-off miss on a clean cmdline", () => {
  const root = mkTree();
  try {
    const P = buildPaths(root, {
      cmdline: "BOOT_IMAGE=/vmlinuz root=/dev/sda1 quiet ro\n",
    });
    const r = runLinux(P);
    assert.equal(r.signal_overrides["kaslr-disabled-at-boot"], "miss");
    assert.equal(r.signal_overrides["mitigations-off"], "miss");
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// kernel-lockdown-none
// ---------------------------------------------------------------------------

test("kernel-lockdown-none hits when the lockdown file shows [none]", () => {
  const root = mkTree();
  try {
    const P = buildPaths(root, {
      lockdown: "[none] integrity confidentiality\n",
      cmdline: "ro quiet\n",
    });
    const r = runLinux(P);
    assert.equal(r.signal_overrides["kernel-lockdown-none"], "hit");
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("kernel-lockdown-none misses when lockdown is in integrity mode", () => {
  const root = mkTree();
  try {
    const P = buildPaths(root, {
      lockdown: "none [integrity] confidentiality\n",
      cmdline: "ro quiet\n",
    });
    const r = runLinux(P);
    assert.equal(r.signal_overrides["kernel-lockdown-none"], "miss");
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// sshd-permitrootlogin-yes — base config + Include drop-in expansion
// ---------------------------------------------------------------------------

test("sshd-permitrootlogin-yes hits on PermitRootLogin yes in the base config", () => {
  const root = mkTree();
  try {
    const P = buildPaths(root, {
      sshdConfig: "PermitRootLogin yes\nPasswordAuthentication no\n",
    });
    const r = runLinux(P);
    assert.equal(r.signal_overrides["sshd-permitrootlogin-yes"], "hit");
    assert.match(r.artifacts["sshd-config"].value, /PermitRootLogin=yes/);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("sshd-permitrootlogin-yes misses on PermitRootLogin no", () => {
  const root = mkTree();
  try {
    const P = buildPaths(root, {
      sshdConfig: "PermitRootLogin no\nPasswordAuthentication no\n",
    });
    const r = runLinux(P);
    assert.equal(r.signal_overrides["sshd-permitrootlogin-yes"], "miss");
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("sshd Include drop-in is expanded at its textual position (first-match-wins)", () => {
  const root = mkTree();
  try {
    // Base config Includes the drop-in dir BEFORE its own PermitRootLogin no,
    // so the drop-in's `PermitRootLogin yes` wins (OpenSSH first-match order).
    const dropinDir = path.join(root, "sshd_config.d");
    fs.mkdirSync(dropinDir, { recursive: true });
    fs.writeFileSync(path.join(dropinDir, "10-hardening.conf"), "PermitRootLogin yes\n");
    const sshdBase = w(root, "sshd.file",
      "Include /etc/ssh/sshd_config.d/*.conf\nPermitRootLogin no\n");
    const P = buildPaths(root, {});
    P.sshdConfig = sshdBase;
    P.sshdConfigD = dropinDir;
    const r = runLinux(P);
    assert.equal(r.signal_overrides["sshd-permitrootlogin-yes"], "hit",
      "the earlier-Included drop-in's PermitRootLogin yes must win over the base file's later no");
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("sshd-permitrootlogin-yes stays unflipped when sshd_config is absent", () => {
  const root = mkTree();
  try {
    const P = buildPaths(root, {}); // sshdConfig points at an absent file
    const r = runLinux(P);
    assert.ok(!("sshd-permitrootlogin-yes" in r.signal_overrides),
      "no SSH server config => indicator unflipped, not a forged miss");
    assert.equal(r.artifacts["sshd-config"].captured, false);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});
