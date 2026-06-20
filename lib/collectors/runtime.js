"use strict";

/**
 * lib/collectors/runtime.js
 *
 * Companion collector for the `runtime` playbook. Linux-only:
 * walks /etc/sudoers + /etc/sudoers.d/*, parses /etc/passwd for
 * duplicate UID 0 entries, scans well-known trusted-path
 * directories for world-writable files, and inspects /proc/<pid>
 * for orphan-privileged processes. Defers non-deterministic
 * indicators (non-baseline-suid, listening-socket-unknown-bind,
 * cron-or-timer-outside-policy) so the runner returns inconclusive.
 *
 * Interface: see lib/collectors/README.md
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
    // readFileSync(fd) loops read() to EOF — a single readSync may return
    // fewer than s.size bytes on network/FUSE/sync-backed fds, which would
    // leave the buffer tail NUL-filled and silently drop trailing content.
    // Reading via the already-open fd keeps the fstat-then-read TOCTOU-free.
    return fs.readFileSync(fd, "utf8");
  } catch { return null; }
  finally { if (fd !== undefined) { try { fs.closeSync(fd); } catch { /* non-fatal */ } } }
}

const NOPASSWD_WILDCARD_RE = /\bNOPASSWD:\s*(?:ALL|\/[^,\n]*\*)/;

// Trusted-path roots scanned for world-writable files. The
// playbook explicitly lists /etc, /usr/local/bin, /usr/local/sbin,
// /opt. We add /usr/bin and /usr/sbin as common variants but stay
// shallow (depth 2) so we don't walk arbitrarily deep filesystems.
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
    // Sudoers entries lead with a comma-separated user/group list:
    //   `<user1>,<user2>,%group  host = (runas) NOPASSWD: cmd*`
    // Skip ONLY when the user list is exactly `root` (no other
    // principals). A line like `root,deploy ALL=(ALL) NOPASSWD: ALL`
    // still grants wildcard sudo to `deploy` and counts as a hit.
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

// Classify a world-writable hit against the two deterministic
// false_positive_checks_required entries for world-writable-in-trusted-path:
//   [0] sticky-bit (1777-style) dirs/files intentionally permit per-user write
//   [1] 0-byte stamp / unix-socket / FIFO documented for the application
// Returns { stickyBit, special } so the caller can both keep only genuine
// hits and attest exactly the checks it ran.
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
  // Returns { hits, exeReadable }. exeReadable is false when at
  // least one candidate PID (UID 0, PPID 1) had an unreadable
  // /proc/<pid>/exe symlink AND PID 1's exe was also unreadable —
  // in that case the indicator MUST stay unflipped (the caller
  // converts that to inconclusive). hidepid / ptrace-restrict /
  // non-root scope all collapse exe readability to zero, and
  // emitting "miss" there would mask real privileged orphans.
  let entries;
  try { entries = fs.readdirSync(procRoot); } catch { return { hits: [], exeReadable: false }; }
  const hits = [];

  // PID 1's exe is the canonical anchor. If we can't read it, we
  // can't tell whether the parent is canonical init or a hijacked
  // PID 1. That's an inconclusive condition.
  const initProc = readProcPid(1, procRoot);
  const initExeReadable = !!(initProc && initProc.exe);
  if (!initExeReadable) return { hits: [], exeReadable: false };
  if (!PARENT_INIT_BINARIES.has(initProc.exe)) {
    // PID 1's exe is readable but isn't a canonical init. Treat
    // as inconclusive — the playbook predicate explicitly says
    // "parent != systemd/init" is the orphan condition, but
    // distinguishing a legitimate non-systemd init (e.g. SysV,
    // BusyBox init) from a hijacked PID 1 needs operator review.
    return { hits: [], exeReadable: false };
  }

  // PID 1's exe is canonical init. Now scan candidate PIDs.
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
  // If we couldn't read ANY candidate's exe (typical non-root /
  // hidepid scope), the indicator stays unflipped. If we read at
  // least one and saw zero risky-path orphans, the miss is
  // honest. If we saw mixed (some readable, some not), still
  // report what we found — but only emit a verdict when at least
  // one exe was readable so we have evidence to back it.
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

  // Sudo rules: /etc/sudoers + /etc/sudoers.d/*
  const sudoersBase = readFileSafe(P.sudoers);
  let sudoersContent = sudoersBase || "";
  let sudoersReadable = sudoersBase != null;
  try {
    const dEntries = fs.readdirSync(P.sudoersD);
    for (const e of dEntries) {
      // skip editor backup files (~, .bak, .swp)
      if (/[~]$/.test(e) || /\.(bak|swp|orig)$/.test(e)) continue;
      const c = readFileSafe(path.join(P.sudoersD, e));
      if (c != null) {
        sudoersContent += "\n" + c;
        sudoersReadable = true;
      }
    }
  } catch { /* .d not present */ }
  const sudoersHits = parseSudoersForWildcards(sudoersContent);

  // /etc/passwd UID-zero count
  const passwdContent = readFileSafe(P.passwd);
  const uid0 = passwdContent ? parsePasswdUidZero(passwdContent) : null;

  // World-writable files under trusted paths. Split into genuine hits
  // (regular non-empty files without the sticky bit) and benign carriers
  // the two false_positive_checks_required entries demote (sticky-bit
  // per-user-write dirs; 0-byte stamps / sockets / FIFOs). Only the
  // genuine hits flip the indicator; the split records which FP checks
  // the collector deterministically ran.
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

  // Orphan-privileged process scan. Only meaningful on a real
  // /proc; on a synthetic tempdir we still walk it the same way.
  const orphanScan = scanOrphanPrivileged(P.procRoot);

  const signal_overrides = {};
  if (sudoersReadable) {
    signal_overrides["sudoers-nopasswd-wildcard"] = sudoersHits.length > 0 ? "hit" : "miss";
  }
  if (uid0 !== null) {
    signal_overrides["duplicate-uid-zero"] = uid0.length > 1 ? "hit" : "miss";
  }
  // world-writable-in-trusted-path: only emit a verdict if at least
  // one trusted path was readable. If every TP was unreadable
  // (chroot / restricted container), leave the indicator unflipped.
  const anyTpReadable = P.trustedPaths.some(tp => {
    try { fs.readdirSync(tp); return true; } catch { return false; }
  });
  if (anyTpReadable) {
    const wwHit = worldWritableFiles.length > 0;
    signal_overrides["world-writable-in-trusted-path"] = wwHit ? "hit" : "miss";
    // Attest the false_positive_checks_required entries the collector
    // ran against every flagged file: [0] sticky-bit carriers and [1]
    // 0-byte/socket/FIFO carriers were both stat-inspected and excluded,
    // so a surviving hit satisfies both. Without this attestation the
    // runner downgrades a real world-writable hit to inconclusive.
    if (wwHit) {
      signal_overrides["world-writable-in-trusted-path__fp_checks"] = { "0": true, "1": true };
    }
  }
  // orphan-privileged-process: only emit when /proc was walkable
  // AND the scan had enough exe-link visibility to reach a verdict.
  // hidepid / ptrace-restrict / non-root scope leaves
  // exeReadable=false; the indicator stays unflipped so the runner
  // returns inconclusive (codex P1 #80).
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
