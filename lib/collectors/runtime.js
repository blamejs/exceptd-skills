"use strict";

/**
 * Companion collector for the `runtime` playbook. Linux-only, deterministic
 * indicators only — anything it cannot settle stays unflipped for the runner to
 * call inconclusive. Interface: see lib/collectors/README.md
 */

const fs = require("node:fs");
const path = require("node:path");

const COLLECTOR_ID = "runtime";

function readFileSafe(p, max = 512 * 1024) {
  let fd;
  try {
    fd = fs.openSync(p, "r");
    const s = fs.fstatSync(fd);
    if (s.size > max) return null;
    // readFileSync(fd) loops to EOF; a single readSync can short-read a network
    // fd. Reading through the open fd also keeps the fstat-then-read TOCTOU-free.
    return fs.readFileSync(fd, "utf8");
  } catch { return null; }
  finally { if (fd !== undefined) { try { fs.closeSync(fd); } catch { /* non-fatal */ } } }
}

const NOPASSWD_WILDCARD_RE = /\bNOPASSWD:\s*(?:ALL|\/[^,\n]*\*)/;

// World-writable scan roots; the depth cap keeps the walk off deep filesystems.
const TRUSTED_PATHS = ["/etc", "/usr/local/bin", "/usr/local/sbin", "/opt", "/usr/bin", "/usr/sbin"];
const TRUSTED_PATH_MAX_DEPTH = 2;

const PARENT_INIT_BINARIES = new Set([
  "/sbin/init", "/usr/sbin/init", "/usr/lib/systemd/systemd",
  "/lib/systemd/systemd", "/usr/lib/systemd/systemd-userdbd",
]);
const ORPHAN_RISKY_PREFIXES = ["/tmp/", "/dev/shm/", "/var/tmp/", "/home/"];

function parseSudoersForWildcards(content) {
  if (!content) return [];
  const hits = [];
  for (const raw of content.split(/\r?\n/)) {
    const line = raw.replace(/#.*$/, "").trim();
    if (!line) continue;
    if (!NOPASSWD_WILDCARD_RE.test(line)) continue;
    // Skip only when the principal list is exactly `root` — `root,deploy ALL=(ALL)
    // NOPASSWD: ALL` still grants wildcard sudo to deploy and counts as a hit.
    const userListMatch = line.match(/^([^\s]+)\s/);
    if (userListMatch) {
      const principals = userListMatch[1].split(",").map(s => s.trim()).filter(Boolean);
      if (principals.length === 1 && principals[0] === "root") continue;
    }
    hits.push(line);
  }
  return hits;
}

function parsePasswdUidZero(content) {
  if (!content) return [];
  const uid0 = [];
  for (const raw of content.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    const fields = line.split(":");
    if (fields.length < 3) continue;
    if (fields[2] === "0") uid0.push(fields[0]);
  }
  return uid0;
}

function walkShallow(dir, maxDepth) {
  const out = [];
  const seen = new Set();
  function walk(d, depth) {
    if (depth > maxDepth) return;
    let entries;
    try { entries = fs.readdirSync(d, { withFileTypes: true }); }
    catch { return; }
    for (const e of entries) {
      const full = path.join(d, e.name);
      let real;
      try { real = fs.realpathSync(full); } catch { continue; }
      if (seen.has(real)) continue;
      seen.add(real);
      if (e.isDirectory()) walk(full, depth + 1);
      else if (e.isFile()) out.push(full);
    }
  }
  walk(dir, 0);
  return out;
}

function isWorldWritable(p) {
  try {
    const s = fs.statSync(p);
    return (s.mode & 0o002) !== 0;
  } catch { return false; }
}

// The two deterministic FP checks on world-writable-in-trusted-path: [0] sticky-bit
// per-user-write, [1] 0-byte stamp / socket / FIFO. The caller drops carriers.
function classifyWorldWritable(p) {
  try {
    const s = fs.lstatSync(p);
    const stickyBit = (s.mode & 0o1000) !== 0;
    const special = s.isSocket() || s.isFIFO() || (s.isFile() && s.size === 0);
    return { stickyBit, special };
  } catch { return { stickyBit: false, special: false }; }
}

function readProcPid(pid, procRoot) {
  // Returns { pid, ppid, uid, exe } or null.
  try {
    const statusPath = path.join(procRoot, String(pid), "status");
    const status = fs.readFileSync(statusPath, "utf8");
    const ppidMatch = status.match(/^PPid:\s+(\d+)/m);
    const uidMatch = status.match(/^Uid:\s+(\d+)/m);
    if (!ppidMatch || !uidMatch) return null;
    let exe = null;
    try {
      exe = fs.readlinkSync(path.join(procRoot, String(pid), "exe"));
    } catch { /* no permission to read exe link */ }
    return {
      pid,
      ppid: Number(ppidMatch[1]),
      uid: Number(uidMatch[1]),
      exe,
    };
  } catch { return null; }
}

function scanOrphanPrivileged(procRoot) {
  // Returns { hits, exeReadable }. exeReadable false means no exe-link visibility
  // and the caller must leave the indicator unflipped — a "miss" masks real orphans.
  let entries;
  try { entries = fs.readdirSync(procRoot); } catch { return { hits: [], exeReadable: false }; }
  const hits = [];

  // PID 1's exe is the anchor: unreadable, canonical init and a hijacked PID 1 look alike.
  const initProc = readProcPid(1, procRoot);
  const initExeReadable = !!(initProc && initProc.exe);
  if (!initExeReadable) return { hits: [], exeReadable: false };
  if (!PARENT_INIT_BINARIES.has(initProc.exe)) {
    // Not a canonical init: SysV / BusyBox vs a hijacked PID 1 needs operator review.
    return { hits: [], exeReadable: false };
  }

  let anyExeReadable = false;
  let anyExeUnreadable = false;
  for (const name of entries) {
    if (!/^\d+$/.test(name)) continue;
    const proc = readProcPid(Number(name), procRoot);
    if (!proc) continue;
    if (proc.uid !== 0) continue;
    if (proc.ppid !== 1) continue;
    if (proc.exe) {
      anyExeReadable = true;
      if (ORPHAN_RISKY_PREFIXES.some(p => proc.exe.startsWith(p))) {
        hits.push({ pid: proc.pid, exe: proc.exe });
      }
    } else {
      anyExeUnreadable = true;
    }
  }
  // A verdict needs at least one readable exe behind it; with none, it stays unflipped.
  const exeReadable = anyExeReadable || (!anyExeUnreadable && entries.length > 0);
  return { hits, exeReadable };
}

function collect({ cwd = process.cwd(), env = process.env, args = {} } = {}) {
  const errors = [];
  const startTime = Date.now();
  const root = path.resolve(cwd);
  const paths = args.paths || {};
  const P = {
    sudoers: paths.sudoers || "/etc/sudoers",
    sudoersD: paths.sudoersD || "/etc/sudoers.d",
    passwd: paths.passwd || "/etc/passwd",
    trustedPaths: paths.trustedPaths || TRUSTED_PATHS,
    procRoot: paths.procRoot || "/proc",
  };
  const isLinux = args.forceLinux === true || process.platform === "linux";

  if (!isLinux) {
    return {
      precondition_checks: { "linux-platform": false },
      artifacts: {
        "sudo-rules": { value: "skipped — non-Linux platform", captured: false, reason: `process.platform=${process.platform}` },
        "passwd-shadow-baseline": { value: "skipped — non-Linux platform", captured: false, reason: `process.platform=${process.platform}` },
        "world-writable-paths": { value: "skipped — non-Linux platform", captured: false, reason: `process.platform=${process.platform}` },
        "process-tree": { value: "skipped — non-Linux platform", captured: false, reason: `process.platform=${process.platform}` },
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

  const sudoersBase = readFileSafe(P.sudoers);
  let sudoersContent = sudoersBase || "";
  let sudoersReadable = sudoersBase != null;
  try {
    const dEntries = fs.readdirSync(P.sudoersD);
    for (const e of dEntries) {
      if (/[~]$/.test(e) || /\.(bak|swp|orig)$/.test(e)) continue;
      const c = readFileSafe(path.join(P.sudoersD, e));
      if (c != null) {
        sudoersContent += "\n" + c;
        sudoersReadable = true;
      }
    }
  } catch { /* .d not present */ }
  const sudoersHits = parseSudoersForWildcards(sudoersContent);

  const passwdContent = readFileSafe(P.passwd);
  const uid0 = passwdContent ? parsePasswdUidZero(passwdContent) : null;

  // Genuine hits are regular non-empty files without the sticky bit; carriers are demoted.
  const worldWritableFiles = [];
  let sawStickyBitCarrier = false;
  let sawSpecialCarrier = false;
  for (const tp of P.trustedPaths) {
    for (const f of walkShallow(tp, TRUSTED_PATH_MAX_DEPTH)) {
      if (!isWorldWritable(f)) continue;
      const { stickyBit, special } = classifyWorldWritable(f);
      if (stickyBit) { sawStickyBitCarrier = true; continue; }
      if (special) { sawSpecialCarrier = true; continue; }
      worldWritableFiles.push(f);
    }
  }

  const orphanScan = scanOrphanPrivileged(P.procRoot);

  const signal_overrides = {};
  if (sudoersReadable) {
    signal_overrides["sudoers-nopasswd-wildcard"] = sudoersHits.length > 0 ? "hit" : "miss";
  }
  if (uid0 !== null) {
    signal_overrides["duplicate-uid-zero"] = uid0.length > 1 ? "hit" : "miss";
  }
  // A verdict needs one readable trusted path; an all-unreadable scope stays unflipped.
  const anyTpReadable = P.trustedPaths.some(tp => {
    try { fs.readdirSync(tp); return true; } catch { return false; }
  });
  if (anyTpReadable) {
    const wwHit = worldWritableFiles.length > 0;
    signal_overrides["world-writable-in-trusted-path"] = wwHit ? "hit" : "miss";
    // Both FP checks ran against every flagged file, so a surviving hit satisfies
    // them; without this attestation the runner downgrades the hit to inconclusive.
    if (wwHit) {
      signal_overrides["world-writable-in-trusted-path__fp_checks"] = { "0": true, "1": true };
    }
  }
  // A verdict needs a walkable /proc and exe-link visibility; otherwise exeReadable
  // is false and the indicator stays unflipped.
  let procWalkable = false;
  try { fs.readdirSync(P.procRoot); procWalkable = true; } catch { /* not present */ }
  if (procWalkable && orphanScan.exeReadable) {
    signal_overrides["orphan-privileged-process"] = orphanScan.hits.length > 0 ? "hit" : "miss";
  }

  const artifacts = {
    "sudo-rules": sudoersReadable
      ? { value: `${sudoersHits.length} NOPASSWD wildcard rule(s)` + (sudoersHits.length > 0 ? ": " + sudoersHits.slice(0, 3).join("; ") : ""), captured: true }
      : { value: "/etc/sudoers unreadable", captured: false, reason: "permission denied or absent" },
    "passwd-shadow-baseline": passwdContent
      ? { value: `${(uid0 || []).length} UID-0 entr(y/ies): ${(uid0 || []).join(", ") || "none"}`, captured: true }
      : { value: "/etc/passwd unreadable", captured: false, reason: "permission denied or absent" },
    "world-writable-paths": anyTpReadable
      ? { value: worldWritableFiles.length > 0 ? `${worldWritableFiles.length} world-writable file(s): ${worldWritableFiles.slice(0, 5).join("; ")}` : "no world-writable files under trusted paths", captured: true }
      : { value: "no trusted paths readable from this scope", captured: false, reason: "all trusted paths unreadable (chroot / restricted scope)" },
    "process-tree": procWalkable
      ? (orphanScan.exeReadable
        ? { value: orphanScan.hits.length > 0 ? `${orphanScan.hits.length} orphan-privileged process(es): ` + orphanScan.hits.slice(0, 3).map(p => `pid=${p.pid} exe=${p.exe}`).join("; ") : "no orphan-privileged processes detected", captured: true }
        : { value: "/proc walkable but /proc/<pid>/exe symlinks unreadable (likely hidepid / ptrace-restrict / non-root scope)", captured: false, reason: "insufficient exe-link visibility to reach a verdict" })
      : { value: "/proc not walkable", captured: false, reason: "no /proc on this scope" },
  };

  return {
    precondition_checks: {
      "linux-platform": true,
      // The collector execs nothing, so `exec-allowed` holds by construction; the
      // runner cannot resolve `agent_has_command_exec` mechanically and its
      // on_fail=halt preflight would block `collect runtime | run runtime`.
      "exec-allowed": Boolean(sudoersReadable || passwdContent != null || procWalkable || anyTpReadable),
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
