"use strict";

/**
 * lib/collectors/mcp.js
 *
 * Companion collector for the `mcp` playbook. Reads MCP client
 * config files (Cursor, Claude Code, Windsurf, VS Code Copilot,
 * Gemini CLI) and tool-response logs, flipping deterministic
 * indicators related to:
 *   - mcp-version-without-integrity (pinned version without
 *     sha256 / sri-integrity sibling)
 *   - copilot-yolo-mode-flag (chat.tools.autoApprove true)
 *   - mcp-response-ansi-escape (0x1B in tool response)
 *   - mcp-response-unicode-tag-smuggling (U+E0000..U+E007F)
 *
 * Defers:
 *   - unsigned-mcp-manifest (needs npm/pip package directory walk
 *     + sigstore lookup; out of stdlib scope)
 *   - vulnerable-windsurf-version (needs Windsurf install detection)
 *   - mcp-server-running-as-root (needs ps + capabilities)
 *   - mcp-server-invoked-from-ci-pipeline (needs process-tree
 *     env-var inspection)
 *
 * Interface: see lib/collectors/README.md
 */

const fs = require("node:fs");
const path = require("node:path");
const os = require("node:os");

const COLLECTOR_ID = "mcp";

function readSafe(full, max = 1024 * 1024) {
  try {
    const s = fs.statSync(full);
    if (s.size > max) return null;
    return fs.readFileSync(full, "utf8");
  } catch { return null; }
}

function readJson(full) {
  const c = readSafe(full);
  if (c == null) return null;
  try { return JSON.parse(c); } catch { return null; }
}

function fileExists(full) {
  try { return fs.statSync(full).isFile(); } catch { return false; }
}

// Per-vendor config locations. We try each and capture which were
// present so the artifact field tells the operator what scope the
// collector actually exercised.
function vendorConfigPaths(home) {
  return {
    cursor: [path.join(home, ".cursor", "mcp.json")],
    "claude-code": [
      path.join(home, ".config", "claude", "config.json"),
      path.join(home, ".claude", "settings.json"),
    ],
    windsurf: [path.join(home, ".codeium", "windsurf", "mcp_config.json")],
    "vscode-copilot": [
      // user-global locations
      path.join(home, ".config", "Code", "User", "settings.json"),
      path.join(home, "Library", "Application Support", "Code", "User", "settings.json"),
      path.join(home, "AppData", "Roaming", "Code", "User", "settings.json"),
      path.join(home, ".vscode", "settings.json"),
    ],
    gemini: [path.join(home, ".gemini", "settings.json")],
  };
}

// Walk mcpServers entries across vendor config shapes. Returns
// [{ vendor, file, name, command, args }].
function collectMcpServers(configsByVendor) {
  const out = [];
  for (const [vendor, files] of Object.entries(configsByVendor)) {
    for (const f of files) {
      const j = readJson(f);
      if (!j) continue;
      // Cursor / Claude Code / Windsurf: { mcpServers: { <name>: {...} } }
      // VS Code Copilot: { chat: { mcp: { servers: { <name>: {...} } } } }
      // Gemini: { mcpServers: { <name>: {...} } }
      const containers = [
        j.mcpServers,
        j["chat.mcp.servers"],
        j?.chat?.mcp?.servers,
      ].filter(c => c && typeof c === "object");
      for (const c of containers) {
        for (const [name, entry] of Object.entries(c)) {
          if (!entry || typeof entry !== "object") continue;
          out.push({
            vendor, file: f, name,
            command: entry.command,
            args: Array.isArray(entry.args) ? entry.args : [],
            integrity: entry.integrity || entry.sha256 || entry.sri || null,
          });
        }
      }
    }
  }
  return out;
}

// A pinned version is the @1.2.3 / @v1.2.3 / =1.2.3 trailer on a
// package spec in args[] or command. We look for shapes that
// downstream operators care about: `npx -y @vendor/pkg@1.2.3`,
// `uvx pkg==1.2.3`, `pip install pkg==1.2.3`, etc.
function isPinnedNoIntegrity(server) {
  if (server.integrity) return false;
  const tokens = [server.command, ...server.args].filter(Boolean);
  for (const tok of tokens) {
    if (typeof tok !== "string") continue;
    // npm package@version (excluding scope name@version)
    if (/@[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+@\d+\.\d+\.\d+\b/.test(tok)) return true;
    if (/\bpip\s+install\b/.test(tok)) continue;
    if (/==\d+\.\d+\.\d+/.test(tok)) return true;
  }
  return false;
}

// VS Code yolo-mode flag: chat.tools.autoApprove === true OR any
// per-tool autoApprove === true.
function hasYoloMode(j) {
  if (!j || typeof j !== "object") return false;
  if (j["chat.tools.autoApprove"] === true) return true;
  if (j?.chat?.tools?.autoApprove === true) return true;
  // Per-server autoApprove flags in chat.mcp.servers.<name>.autoApprove
  const servers = j["chat.mcp.servers"] || j?.chat?.mcp?.servers;
  if (servers && typeof servers === "object") {
    for (const e of Object.values(servers)) {
      if (e && (e.autoApprove === true || e.autoApprove === "all")) return true;
    }
  }
  return false;
}

// ANSI escape: any 0x1B byte in tool response content.
function hasAnsiEscape(content) {
  return content.indexOf("\x1b") !== -1;
}

// Unicode tag smuggling: codepoints in U+E0000..U+E007F. These are
// invisible in normal renders but carry instruction-coercion
// payloads through MCP responses.
function hasUnicodeTagSmuggling(content) {
  for (let i = 0; i < content.length; i++) {
    const code = content.codePointAt(i);
    if (code >= 0xE0000 && code <= 0xE007F) return true;
    // Surrogate pair — skip the low surrogate slot.
    if (code > 0xFFFF) i++;
  }
  return false;
}

function findMcpLogs(home) {
  // Candidate log directories per vendor. Caller scans each for
  // *.jsonl / *.log files. Directories like ~/.claude/logs/mcp/ are
  // already MCP-scoped by path; we accept every log file inside.
  // Generic log directories (~/.cursor/logs/) are filtered to
  // filenames containing "mcp".
  const dirs = [
    { path: path.join(home, ".claude", "logs", "mcp"), filterByName: false },
    { path: path.join(home, ".cursor", "logs"), filterByName: true },
    { path: path.join(home, ".codeium", "windsurf", "logs"), filterByName: true },
  ];
  const out = [];
  for (const { path: d, filterByName } of dirs) {
    let entries;
    try { entries = fs.readdirSync(d, { withFileTypes: true }); } catch { continue; }
    for (const e of entries) {
      if (!e.isFile()) continue;
      if (!/\.(jsonl|log)$/i.test(e.name)) continue;
      if (filterByName && !/mcp/i.test(e.name)) continue;
      out.push(path.join(d, e.name));
    }
  }
  return out;
}

function collect({ cwd = process.cwd(), env = process.env, args = {} } = {}) {
  const errors = [];
  const startTime = Date.now();
  const root = path.resolve(cwd);
  const home = (env && env.HOME) || (env && env.USERPROFILE) || os.homedir();

  // Vendor MCP configs.
  const configsByVendor = vendorConfigPaths(home);
  const servers = collectMcpServers(configsByVendor);
  const pinnedNoIntegrity = servers.filter(isPinnedNoIntegrity);

  // VS Code yolo-mode across the candidate VS Code settings files.
  let yoloHit = false;
  let yoloFile = null;
  for (const f of configsByVendor["vscode-copilot"]) {
    const j = readJson(f);
    if (j && hasYoloMode(j)) { yoloHit = true; yoloFile = f; break; }
  }
  // Project-level .vscode/settings.json under cwd
  if (!yoloHit) {
    const projVsc = path.join(root, ".vscode", "settings.json");
    const j = readJson(projVsc);
    if (j && hasYoloMode(j)) { yoloHit = true; yoloFile = projVsc; }
  }

  // MCP response log scan for ANSI / unicode-tag smuggling.
  const logFiles = findMcpLogs(home);
  let ansiHit = false;
  let unicodeTagHit = false;
  let ansiSourceFile = null;
  let unicodeTagSourceFile = null;
  let logBytesScanned = 0;
  for (const f of logFiles) {
    const c = readSafe(f, 4 * 1024 * 1024);
    if (c == null) continue;
    logBytesScanned += c.length;
    if (!ansiHit && hasAnsiEscape(c)) { ansiHit = true; ansiSourceFile = f; }
    if (!unicodeTagHit && hasUnicodeTagSmuggling(c)) {
      unicodeTagHit = true; unicodeTagSourceFile = f;
    }
    if (ansiHit && unicodeTagHit) break;
  }
  const logsScanned = logFiles.length > 0;

  const signal_overrides = {
    "mcp-version-without-integrity": pinnedNoIntegrity.length > 0 ? "hit" : "miss",
    "copilot-yolo-mode-flag": yoloHit ? "hit" : "miss",
  };
  // ANSI / unicode-tag indicators: only emit when we actually
  // scanned at least one log file. If no logs exist, leave the
  // indicators unflipped (the operator may not have enabled MCP
  // logging — the runner returns inconclusive).
  if (logsScanned) {
    signal_overrides["mcp-response-ansi-escape"] = ansiHit ? "hit" : "miss";
    signal_overrides["mcp-response-unicode-tag-smuggling"] = unicodeTagHit ? "hit" : "miss";
  }

  const artifacts = {
    "cursor-mcp-config": {
      value: fileExists(configsByVendor.cursor[0])
        ? `${configsByVendor.cursor[0]} present`
        : "absent",
      captured: true,
    },
    "claude-code-mcp-config": {
      value: configsByVendor["claude-code"].filter(fileExists).join(", ") || "absent",
      captured: true,
    },
    "windsurf-mcp-config": {
      value: fileExists(configsByVendor.windsurf[0]) ? "present" : "absent",
      captured: true,
    },
    "vscode-copilot-mcp-config": {
      value: configsByVendor["vscode-copilot"].filter(fileExists).map(f => path.relative(home, f)).join(", ") || "absent",
      captured: true,
    },
    "gemini-cli-mcp-config": {
      value: fileExists(configsByVendor.gemini[0]) ? "present" : "absent",
      captured: true,
    },
    "mcp-server-inventory": {
      value: `${servers.length} server(s) across ${new Set(servers.map(s => s.vendor)).size} vendor(s); ${pinnedNoIntegrity.length} pinned without integrity`,
      captured: true,
    },
    "vscode-copilot-yolo-mode": {
      value: yoloHit ? `chat.tools.autoApprove flag set in ${path.relative(home, yoloFile || "")}` : "scanned VS Code settings; auto-approve flag not set",
      captured: true,
    },
    "mcp-tool-response-log": {
      value: logsScanned
        ? `${logFiles.length} log file(s), ${logBytesScanned} byte(s) scanned; ansi_hit=${ansiHit} (${ansiSourceFile ? path.relative(home, ansiSourceFile) : ""}); unicode_tag_hit=${unicodeTagHit} (${unicodeTagSourceFile ? path.relative(home, unicodeTagSourceFile) : ""})`
        : "no MCP log files found at the canonical paths",
      captured: logsScanned,
      reason: logsScanned ? undefined : "MCP client logging may be disabled; ansi-escape / unicode-tag indicators left unflipped (inconclusive)",
    },
    "mcp-process-list": {
      value: "skipped — process-list capture deferred to operator/AI evidence",
      captured: false,
      reason: "mcp-server-running-as-root / mcp-server-invoked-from-ci-pipeline need ps + env-var inspection that's out of stdlib scope",
    },
    "mcp-manifest-signatures": {
      value: "skipped — sigstore lookup deferred to operator/AI evidence",
      captured: false,
      reason: "unsigned-mcp-manifest needs package-directory + sigstore-rekor / in-toto attestation lookup that's out of stdlib scope",
    },
  };

  return {
    precondition_checks: {
      "home-dir-readable": fs.existsSync(home),
      // Auto-attest the any-ai-coding-assistant-installed gate (skip_phase)
      // from the vendor configs we actually found: the runner can't resolve the
      // exists($HOME/.cursor)||... DSL, so otherwise a host that clearly has an
      // assistant config surfaces a spurious precondition_unverified and the
      // detect phase is skipped. (The filesystem-read HALT gate is left to the
      // host-side resolver.)
      "any-ai-coding-assistant-installed": Object.values(configsByVendor).some((files) => files.some(fileExists)),
    },
    artifacts,
    signal_overrides,
    collector_meta: {
      collector_id: COLLECTOR_ID,
      collector_version: "2026-05-20",
      platform: process.platform,
      captured_at: new Date().toISOString(),
      cwd: root,
      home,
      duration_ms: Date.now() - startTime,
      vendors_with_config: Object.entries(configsByVendor)
        .filter(([_, files]) => files.some(fileExists))
        .map(([v]) => v),
      servers_found: servers.length,
      logs_scanned: logFiles.length,
    },
    collector_errors: errors,
  };
}

module.exports = { playbook_id: COLLECTOR_ID, collect };
