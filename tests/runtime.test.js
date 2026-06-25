"use strict";

/**
 * tests/runtime.test.js
 *
 * Behavioral coverage for the `runtime` collector
 * (lib/collectors/runtime.js): the Linux-only companion collector that
 * walks /etc/sudoers + /etc/sudoers.d/*, parses /etc/passwd for duplicate
 * UID-0 entries, scans trusted-path roots for world-writable files, and
 * inspects /proc/<pid> for orphan-privileged processes.
 *
 * Like the hardening collector it exposes args.forceLinux + args.paths so
 * every read can be redirected into a synthetic tempdir mirror. All
 * fixtures live under os.tmpdir(); no host files are read or mutated, and
 * the suite is deterministic on any platform.
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
const collector = require(path.join(ROOT, "lib", "collectors", "runtime.js"));

const ENVELOPE_KEYS = [
  "precondition_checks", "artifacts", "signal_overrides",
  "collector_meta", "collector_errors",
];

function mkTree(prefix = "runtime-fix-") {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}
function w(root, rel, content) {
  const full = path.join(root, rel);
  fs.mkdirSync(path.dirname(full), { recursive: true });
  fs.writeFileSync(full, content);
  return full;
}

const CANONICAL_INIT = "/usr/lib/systemd/systemd";

/**
 * Build a synthetic /proc tree under `root/proc`. Each pid entry gets a
 * status file (PPid/Uid) and an `exe` symlink target recorded so the
 * collector's readlinkSync resolves it. Returns the proc root path.
 *
 * `procs` is an array of { pid, ppid, uid, exe }. When `exe` is provided a
 * symlink is created pointing at it (the link itself need not resolve to a
 * real file — readlinkSync only reads the link target).
 */
function buildProc(root, procs) {
  const procRoot = path.join(root, "proc");
  for (const p of procs) {
    const dir = path.join(procRoot, String(p.pid));
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, "status"),
      `Name:\tproc${p.pid}\nPPid:\t${p.ppid}\nUid:\t${p.uid}\t${p.uid}\t${p.uid}\t${p.uid}\n`);
    if (p.exe) {
      try { fs.symlinkSync(p.exe, path.join(dir, "exe")); } catch { /* symlink may fail on some FS; tests that need it skip */ }
    }
  }
  return procRoot;
}

function runLinux(root, paths) {
  return collector.collect({ cwd: process.cwd(), env: {}, args: { forceLinux: true, paths } });
}

// Absent placeholders so unset readers abstain.
function absent(root, tag) { return path.join(root, "__absent__-" + tag); }

// ---------------------------------------------------------------------------
// Module contract
// ---------------------------------------------------------------------------

test("exports playbook_id 'runtime' + a collect() function", () => {
  assert.equal(collector.playbook_id, "runtime");
  assert.equal(typeof collector.collect, "function");
});

test("on a non-Linux host the precondition fails and no signals flip", () => {
  const r = collector.collect({ cwd: process.cwd(), env: {}, args: {} });
  for (const k of ENVELOPE_KEYS) assert.ok(k in r, `must carry ${k}`);
  if (process.platform !== "linux") {
    assert.equal(r.precondition_checks["linux-platform"], false);
    assert.deepEqual(r.signal_overrides, {});
    assert.equal(r.artifacts["sudo-rules"].captured, false);
  } else {
    assert.equal(r.precondition_checks["linux-platform"], true);
  }
});

// ---------------------------------------------------------------------------
// sudoers-nopasswd-wildcard
// ---------------------------------------------------------------------------

test("sudoers-nopasswd-wildcard hits on a non-root NOPASSWD: ALL rule", () => {
  const root = mkTree();
  try {
    const sudoers = w(root, "sudoers", "deploy ALL=(ALL) NOPASSWD: ALL\n");
    const P = {
      sudoers,
      sudoersD: absent(root, "sudoersd"),
      passwd: absent(root, "passwd"),
      trustedPaths: [absent(root, "tp")],
      procRoot: absent(root, "proc"),
    };
    const r = runLinux(root, P);
    assert.equal(r.signal_overrides["sudoers-nopasswd-wildcard"], "hit");
    assert.match(r.artifacts["sudo-rules"].value, /NOPASSWD wildcard rule/);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("sudoers-nopasswd-wildcard ignores a root-only NOPASSWD line", () => {
  const root = mkTree();
  try {
    const sudoers = w(root, "sudoers", "root ALL=(ALL) NOPASSWD: ALL\n");
    const P = {
      sudoers,
      sudoersD: absent(root, "sudoersd"),
      passwd: absent(root, "passwd"),
      trustedPaths: [absent(root, "tp")],
      procRoot: absent(root, "proc"),
    };
    const r = runLinux(root, P);
    assert.equal(r.signal_overrides["sudoers-nopasswd-wildcard"], "miss",
      "a root-only NOPASSWD rule is not a privilege-broadening hit");
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("sudoers-nopasswd-wildcard still hits when root shares the line with another principal", () => {
  const root = mkTree();
  try {
    const sudoers = w(root, "sudoers", "root,deploy ALL=(ALL) NOPASSWD: ALL\n");
    const P = {
      sudoers,
      sudoersD: absent(root, "sudoersd"),
      passwd: absent(root, "passwd"),
      trustedPaths: [absent(root, "tp")],
      procRoot: absent(root, "proc"),
    };
    const r = runLinux(root, P);
    assert.equal(r.signal_overrides["sudoers-nopasswd-wildcard"], "hit",
      "root,deploy still grants wildcard sudo to deploy");
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("sudoers-nopasswd-wildcard stays unflipped when /etc/sudoers is unreadable", () => {
  const root = mkTree();
  try {
    const P = {
      sudoers: absent(root, "sudoers"),
      sudoersD: absent(root, "sudoersd"),
      passwd: absent(root, "passwd"),
      trustedPaths: [absent(root, "tp")],
      procRoot: absent(root, "proc"),
    };
    const r = runLinux(root, P);
    assert.ok(!("sudoers-nopasswd-wildcard" in r.signal_overrides),
      "unreadable sudoers => unflipped, not a forged miss");
    assert.equal(r.artifacts["sudo-rules"].captured, false);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("sudoers.d drop-in NOPASSWD rules are folded into the scan", () => {
  const root = mkTree();
  try {
    const sudoers = w(root, "sudoers", "# base\n");
    const sudoersD = path.join(root, "sudoers.d");
    fs.mkdirSync(sudoersD, { recursive: true });
    fs.writeFileSync(path.join(sudoersD, "90-deploy"), "ci ALL=(ALL) NOPASSWD: /usr/bin/*\n");
    // A backup file that must be skipped.
    fs.writeFileSync(path.join(sudoersD, "90-deploy.bak"), "evil ALL=(ALL) NOPASSWD: ALL\n");
    const P = {
      sudoers, sudoersD,
      passwd: absent(root, "passwd"),
      trustedPaths: [absent(root, "tp")],
      procRoot: absent(root, "proc"),
    };
    const r = runLinux(root, P);
    assert.equal(r.signal_overrides["sudoers-nopasswd-wildcard"], "hit",
      "a drop-in NOPASSWD wildcard rule must be detected");
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// duplicate-uid-zero
// ---------------------------------------------------------------------------

test("duplicate-uid-zero hits on two UID-0 accounts in /etc/passwd", () => {
  const root = mkTree();
  try {
    const passwd = w(root, "passwd",
      "root:x:0:0:root:/root:/bin/bash\nbackdoor:x:0:0::/home/backdoor:/bin/bash\nbob:x:1000:1000::/home/bob:/bin/bash\n");
    const P = {
      sudoers: absent(root, "sudoers"),
      sudoersD: absent(root, "sudoersd"),
      passwd,
      trustedPaths: [absent(root, "tp")],
      procRoot: absent(root, "proc"),
    };
    const r = runLinux(root, P);
    assert.equal(r.signal_overrides["duplicate-uid-zero"], "hit");
    assert.match(r.artifacts["passwd-shadow-baseline"].value, /2 UID-0/);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("duplicate-uid-zero misses on a single root UID-0 account", () => {
  const root = mkTree();
  try {
    const passwd = w(root, "passwd",
      "root:x:0:0:root:/root:/bin/bash\nbob:x:1000:1000::/home/bob:/bin/bash\n");
    const P = {
      sudoers: absent(root, "sudoers"),
      sudoersD: absent(root, "sudoersd"),
      passwd,
      trustedPaths: [absent(root, "tp")],
      procRoot: absent(root, "proc"),
    };
    const r = runLinux(root, P);
    assert.equal(r.signal_overrides["duplicate-uid-zero"], "miss");
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// world-writable-in-trusted-path (POSIX-only: mode bits + special-file FP demotion)
// ---------------------------------------------------------------------------

test("world-writable-in-trusted-path hits on a real 0666 file under a trusted path", { skip: process.platform === "win32" }, () => {
  const root = mkTree();
  try {
    const tp = path.join(root, "trusted");
    fs.mkdirSync(tp, { recursive: true });
    const f = path.join(tp, "evil.sh");
    fs.writeFileSync(f, "#!/bin/sh\necho pwned\n");
    fs.chmodSync(f, 0o666);
    const P = {
      sudoers: absent(root, "sudoers"),
      sudoersD: absent(root, "sudoersd"),
      passwd: absent(root, "passwd"),
      trustedPaths: [tp],
      procRoot: absent(root, "proc"),
    };
    const r = runLinux(root, P);
    assert.equal(r.signal_overrides["world-writable-in-trusted-path"], "hit");
    assert.deepEqual(r.signal_overrides["world-writable-in-trusted-path__fp_checks"], { "0": true, "1": true });
    assert.match(r.artifacts["world-writable-paths"].value, /evil\.sh/);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("world-writable-in-trusted-path demotes a 0-byte world-writable stamp file (FP[1])", { skip: process.platform === "win32" }, () => {
  const root = mkTree();
  try {
    const tp = path.join(root, "trusted");
    fs.mkdirSync(tp, { recursive: true });
    const stamp = path.join(tp, ".stamp");
    fs.writeFileSync(stamp, ""); // 0-byte
    fs.chmodSync(stamp, 0o666);
    const P = {
      sudoers: absent(root, "sudoers"),
      sudoersD: absent(root, "sudoersd"),
      passwd: absent(root, "passwd"),
      trustedPaths: [tp],
      procRoot: absent(root, "proc"),
    };
    const r = runLinux(root, P);
    assert.equal(r.signal_overrides["world-writable-in-trusted-path"], "miss",
      "a 0-byte world-writable stamp is a benign carrier, demoted");
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("world-writable-in-trusted-path misses when the trusted path holds only safe-mode files", { skip: process.platform === "win32" }, () => {
  const root = mkTree();
  try {
    const tp = path.join(root, "trusted");
    fs.mkdirSync(tp, { recursive: true });
    const f = path.join(tp, "ok.sh");
    fs.writeFileSync(f, "#!/bin/sh\n");
    fs.chmodSync(f, 0o644);
    const P = {
      sudoers: absent(root, "sudoers"),
      sudoersD: absent(root, "sudoersd"),
      passwd: absent(root, "passwd"),
      trustedPaths: [tp],
      procRoot: absent(root, "proc"),
    };
    const r = runLinux(root, P);
    assert.equal(r.signal_overrides["world-writable-in-trusted-path"], "miss");
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("world-writable-in-trusted-path stays unflipped when every trusted path is unreadable", () => {
  const root = mkTree();
  try {
    const P = {
      sudoers: absent(root, "sudoers"),
      sudoersD: absent(root, "sudoersd"),
      passwd: absent(root, "passwd"),
      trustedPaths: [absent(root, "tp1"), absent(root, "tp2")],
      procRoot: absent(root, "proc"),
    };
    const r = runLinux(root, P);
    assert.ok(!("world-writable-in-trusted-path" in r.signal_overrides),
      "no readable trusted path => unflipped, not a forged miss");
    assert.equal(r.artifacts["world-writable-paths"].captured, false);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// orphan-privileged-process — synthetic /proc tree
// ---------------------------------------------------------------------------

test("orphan-privileged-process hits on a UID-0 PPID-1 process exec'd from /tmp", { skip: process.platform === "win32" }, () => {
  const root = mkTree();
  try {
    const procRoot = buildProc(root, [
      { pid: 1, ppid: 0, uid: 0, exe: CANONICAL_INIT },
      { pid: 4242, ppid: 1, uid: 0, exe: "/tmp/.x/cryptominer" },
    ]);
    // Verify the symlinks were actually created (some CI filesystems / Windows
    // refuse them); if not, the test is meaningless — skip via assertion guard.
    let exeOk = false;
    try { exeOk = fs.readlinkSync(path.join(procRoot, "4242", "exe")) === "/tmp/.x/cryptominer"; } catch { /* */ }
    if (!exeOk) return; // environment can't create the symlink; nothing to assert
    const P = {
      sudoers: absent(root, "sudoers"),
      sudoersD: absent(root, "sudoersd"),
      passwd: absent(root, "passwd"),
      trustedPaths: [absent(root, "tp")],
      procRoot,
    };
    const r = runLinux(root, P);
    assert.equal(r.signal_overrides["orphan-privileged-process"], "hit");
    assert.match(r.artifacts["process-tree"].value, /4242/);
    assert.match(r.artifacts["process-tree"].value, /cryptominer/);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("orphan-privileged-process misses when the only UID-0 PPID-1 process runs a system binary", { skip: process.platform === "win32" }, () => {
  const root = mkTree();
  try {
    const procRoot = buildProc(root, [
      { pid: 1, ppid: 0, uid: 0, exe: CANONICAL_INIT },
      { pid: 900, ppid: 1, uid: 0, exe: "/usr/sbin/sshd" },
    ]);
    let exeOk = false;
    try { exeOk = fs.readlinkSync(path.join(procRoot, "900", "exe")) === "/usr/sbin/sshd"; } catch { /* */ }
    if (!exeOk) return;
    const P = {
      sudoers: absent(root, "sudoers"),
      sudoersD: absent(root, "sudoersd"),
      passwd: absent(root, "passwd"),
      trustedPaths: [absent(root, "tp")],
      procRoot,
    };
    const r = runLinux(root, P);
    assert.equal(r.signal_overrides["orphan-privileged-process"], "miss",
      "a privileged orphan running a system-path binary is not a risky-path hit");
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("orphan-privileged-process stays unflipped when PID 1's exe is unreadable (no anchor)", { skip: process.platform === "win32" }, () => {
  const root = mkTree();
  try {
    // PID 1 with NO exe symlink -> init anchor unreadable -> inconclusive.
    const procRoot = buildProc(root, [
      { pid: 1, ppid: 0, uid: 0 /* no exe */ },
      { pid: 4242, ppid: 1, uid: 0, exe: "/tmp/x" },
    ]);
    const P = {
      sudoers: absent(root, "sudoers"),
      sudoersD: absent(root, "sudoersd"),
      passwd: absent(root, "passwd"),
      trustedPaths: [absent(root, "tp")],
      procRoot,
    };
    const r = runLinux(root, P);
    assert.ok(!("orphan-privileged-process" in r.signal_overrides),
      "an unreadable PID-1 exe anchor must leave the indicator unflipped (inconclusive)");
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// exec-allowed precondition attestation. The runtime playbook declares an
// `exec-allowed` precondition (on_fail=halt) the runner cannot mechanically
// resolve, so the collector must attest it — otherwise the canonical
// `collect runtime | run runtime` pipe halted at preflight even with valid
// evidence. The collector reads its inventory directly via fs (execs nothing),
// so it attests exec-allowed once it reaches at least one inventory source.
// ---------------------------------------------------------------------------

test("attests exec-allowed: true once an inventory source is readable", () => {
  const root = mkTree();
  try {
    const passwd = w(root, "passwd", "root:x:0:0:root:/root:/bin/bash\n");
    const P = {
      sudoers: absent(root, "sudoers"),
      sudoersD: absent(root, "sudoersd"),
      passwd,
      trustedPaths: [absent(root, "tp")],
      procRoot: absent(root, "proc"),
    };
    const r = runLinux(root, P);
    assert.ok("exec-allowed" in r.precondition_checks,
      "the exec-allowed precondition must be attested (it was entirely absent before — halting the collect|run pipe)");
    assert.equal(r.precondition_checks["exec-allowed"], true,
      "a readable inventory source (passwd) satisfies the read-only-inventory intent");
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("exec-allowed: false on a fully-masked scope (no inventory source readable)", () => {
  const root = mkTree();
  try {
    const P = {
      sudoers: absent(root, "sudoers"),
      sudoersD: absent(root, "sudoersd"),
      passwd: absent(root, "passwd"),
      trustedPaths: [absent(root, "tp")],
      procRoot: absent(root, "proc"),
    };
    const r = runLinux(root, P);
    assert.equal(r.precondition_checks["exec-allowed"], false,
      "a scope where nothing is readable reports exec-allowed false (gated on readability)");
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});
