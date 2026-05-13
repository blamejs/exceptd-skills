#!/usr/bin/env node
"use strict";
/**
 * scripts/check-test-coverage.js
 *
 * Diff-aware test-coverage gate. Compares the changed surface in the
 * working tree (or a staged set, or any --base..HEAD range) against the
 * tests/ tree and reports any surface change that lacks a covering test.
 *
 * Surfaces detected:
 *   - bin/exceptd.js                CLI verbs / flags (COMMANDS / PLAYBOOK_VERBS)
 *   - lib/*.js, orchestrator/*.js,
 *     scripts/*.js                  exported functions (module.exports = {...})
 *   - data/playbooks/*.json         detect.indicators[].id + look.artifacts[].id
 *   - data/cve-catalog.json         CVE entries whose iocs field changed
 *
 * Categorization (no test required):
 *   - *.md outside data/, .gitignore, .npmrc, .editorconfig
 *   - CHANGELOG.md / README.md / CONTRIBUTING.md / SECURITY.md
 *   - whitespace-only diffs (re-run with --ignore-all-space)
 *   - tests/** changes (no recursion)
 *   - .github/workflows/*.yml      surfaced as manual-review-required
 *   - skills/<name>/skill.md       satisfied by Ed25519 verify gate
 *
 * Exit codes:
 *   0  no uncovered surface (or --warn-only)
 *   1  uncovered surface detected
 *   2  runner error (bad flag, git failure, etc.)
 *
 * Flags:
 *   --base <ref>     compare HEAD against <ref> (default: origin/main)
 *   --staged         use the staged index against HEAD
 *   --json           emit machine-readable report on stdout
 *   --warn-only      print but never exit non-zero
 *   --help, -h       this help
 */

const fs = require("fs");
const path = require("path");
const childProc = require("child_process");

const ROOT = path.resolve(__dirname, "..");

// --- Flag parsing -----------------------------------------------------------

function parseArgs(argv) {
  const out = { base: "origin/main", staged: false, json: false, warnOnly: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--base") out.base = argv[++i];
    else if (a === "--staged") out.staged = true;
    else if (a === "--json") out.json = true;
    else if (a === "--warn-only") out.warnOnly = true;
    else if (a === "--help" || a === "-h") out.help = true;
    else if (a === "--repo") out.repo = argv[++i]; // test-only: override ROOT
    else throw new Error(`Unknown flag: ${a}`);
  }
  return out;
}

function printHelp() {
  const banner =
    "Usage: node scripts/check-test-coverage.js [--base <ref>] [--staged]\n" +
    "                                          [--json] [--warn-only]\n" +
    "\n" +
    "See file header for full surface + categorization rules.\n";
  process.stdout.write(banner);
}

// --- Git plumbing -----------------------------------------------------------

function git(args, cwd) {
  const r = childProc.spawnSync("git", args, { cwd, encoding: "utf8" });
  if (r.status !== 0) {
    const err = new Error("git " + args.join(" ") + " failed: " + (r.stderr || r.stdout));
    err.git = true;
    throw err;
  }
  return r.stdout;
}

function listChangedFiles(opts, cwd) {
  if (opts.staged) {
    return git(["diff", "--name-status", "--cached"], cwd)
      .split("\n").filter(Boolean).map(parseNameStatus);
  }
  let baseRef = opts.base;
  try {
    const mb = git(["merge-base", "HEAD", baseRef], cwd).trim();
    if (mb) baseRef = mb;
  } catch { /* base may not exist locally; use ref literal */ }
  return git(["diff", "--name-status", baseRef + "..HEAD"], cwd)
    .split("\n").filter(Boolean).map(parseNameStatus);
}

function parseNameStatus(line) {
  const parts = line.split("\t");
  const status = parts[0][0]; // A/M/D/R/...
  return { status, file: parts[parts.length - 1] };
}

function fileDiff(opts, file, cwd, ignoreWs) {
  const args = ["diff", "-U0"];
  if (ignoreWs) args.push("--ignore-all-space", "--ignore-blank-lines");
  if (opts.staged) args.push("--cached");
  else args.push(opts.base + "..HEAD");
  args.push("--", file);
  try { return git(args, cwd); } catch { return ""; }
}

function fileAtRef(file, ref, cwd) {
  const r = childProc.spawnSync("git", ["show", ref + ":" + file], { cwd, encoding: "utf8" });
  if (r.status !== 0) return null;
  return r.stdout;
}

function fileBefore(opts, file, cwd) {
  if (opts.staged) return fileAtRef(file, "HEAD", cwd);
  return fileAtRef(file, opts.base, cwd);
}

function fileAfter(opts, file, cwd) {
  if (opts.staged) {
    // Staged content lives in the index. `git show :file` returns it.
    return fileAtRef(file, "", cwd) || readMaybe(path.join(cwd, file));
  }
  return readMaybe(path.join(cwd, file));
}

function readMaybe(p) {
  try { return fs.readFileSync(p, "utf8"); } catch { return null; }
}

// --- Categorization ---------------------------------------------------------

const DOCS_ALWAYS_GREEN = new Set([
  "CHANGELOG.md", "README.md", "CONTRIBUTING.md", "SECURITY.md",
  "LICENSE", "NOTICE", "CODE_OF_CONDUCT.md", "AGENTS.md", "CLAUDE.md",
  "SUPPORT.md", "MIGRATING.md", ".gitignore", ".npmrc", ".editorconfig",
]);

function categorize(file) {
  const norm = file.replace(/\\/g, "/");
  if (DOCS_ALWAYS_GREEN.has(norm)) return "docs";
  if (norm.startsWith("tests/")) return "test"; // no recursion
  if (norm.startsWith("docs/")) return "docs";
  if (norm.endsWith(".md") && !norm.startsWith("data/")) return "docs";
  if (norm.startsWith(".github/workflows/")) return "workflow";
  if (norm.startsWith("skills/") && norm.endsWith("/skill.md")) return "skill";
  if (norm === "bin/exceptd.js") return "cli";
  if (norm.startsWith("lib/") && norm.endsWith(".js")) return "lib";
  if (norm.startsWith("orchestrator/") && norm.endsWith(".js")) return "lib";
  if (norm.startsWith("scripts/") && norm.endsWith(".js")) return "lib";
  if (norm.startsWith("data/playbooks/") && norm.endsWith(".json")) return "playbook";
  if (norm === "data/cve-catalog.json") return "cve-catalog";
  return "other";
}

function isWhitespaceOnly(opts, file, cwd) {
  const wsBlind = fileDiff(opts, file, cwd, true);
  return wsBlind.split("\n").filter(l => l.startsWith("+") || l.startsWith("-"))
    .filter(l => !l.startsWith("+++") && !l.startsWith("---")).length === 0;
}

// --- Surface extraction -----------------------------------------------------

function extractCliSurface(content) {
  if (!content) return { verbs: new Set(), flags: new Set() };
  const verbs = new Set();
  const flags = new Set();
  // Only scan the COMMANDS = {...} block and PLAYBOOK_VERBS Set to avoid
  // picking up arbitrary keys from elsewhere.
  const cmdBlock = content.match(/const COMMANDS = \{([\s\S]*?)\n\};/);
  if (cmdBlock) {
    const re = /^\s*"?([a-zA-Z][\w-]+)"?\s*:/gm;
    let m;
    while ((m = re.exec(cmdBlock[1])) !== null) verbs.add(m[1]);
  }
  const playbookBlock = content.match(/const PLAYBOOK_VERBS = new Set\(\[([\s\S]*?)\]\);/);
  if (playbookBlock) {
    const re = /"([a-zA-Z][\w-]+)"/g;
    let m;
    while ((m = re.exec(playbookBlock[1])) !== null) verbs.add(m[1]);
  }
  const flagRe = /(--[a-zA-Z][\w-]+)/g;
  let m;
  while ((m = flagRe.exec(content)) !== null) flags.add(m[1]);
  for (const f of ["--help", "--version"]) flags.delete(f);
  return { verbs, flags };
}

function diffSets(before, after) {
  const added = new Set();
  const removed = new Set();
  for (const v of after) if (!before.has(v)) added.add(v);
  for (const v of before) if (!after.has(v)) removed.add(v);
  return { added, removed };
}

function extractLibExports(content) {
  if (!content) return new Set();
  const out = new Set();
  const m = content.match(/module\.exports\s*=\s*\{([^}]+)\}/);
  if (m) {
    for (const tok of m[1].split(",")) {
      const id = tok.split(":")[0].trim();
      if (/^[a-zA-Z_$][\w$]*$/.test(id)) out.add(id);
    }
  }
  const re = /module\.exports\.([a-zA-Z_$][\w$]*)\s*=/g;
  let mm;
  while ((mm = re.exec(content)) !== null) out.add(mm[1]);
  const re2 = /^exports\.([a-zA-Z_$][\w$]*)\s*=/gm;
  while ((mm = re2.exec(content)) !== null) out.add(mm[1]);
  return out;
}

function extractPlaybookIds(content) {
  if (!content) return { indicators: new Set(), artifacts: new Set() };
  let obj;
  try { obj = JSON.parse(content); }
  catch { return { indicators: new Set(), artifacts: new Set() }; }
  const ind = new Set();
  const arts = new Set();
  const detect = obj && obj.phases && obj.phases.detect && obj.phases.detect.indicators;
  if (Array.isArray(detect)) for (const i of detect) if (i && i.id) ind.add(i.id);
  const look = obj && obj.phases && obj.phases.look && obj.phases.look.artifacts;
  if (Array.isArray(look)) for (const a of look) if (a && a.id) arts.add(a.id);
  return { indicators: ind, artifacts: arts };
}

function extractCveIocChanges(beforeStr, afterStr) {
  const before = safeParse(beforeStr) || {};
  const after = safeParse(afterStr) || {};
  const changed = new Set();
  const ids = new Set([...Object.keys(before), ...Object.keys(after)]);
  for (const id of ids) {
    if (!/^CVE-\d{4}-\d+/.test(id)) continue;
    const b = JSON.stringify((before[id] && before[id].iocs) || null);
    const a = JSON.stringify((after[id] && after[id].iocs) || null);
    if (b !== a) changed.add(id);
  }
  return changed;
}

function safeParse(s) { try { return s ? JSON.parse(s) : null; } catch { return null; } }

// --- Test corpus + coverage probes ------------------------------------------

function loadTestCorpus(cwd) {
  const root = path.join(cwd, "tests");
  if (!fs.existsSync(root)) return "";
  const acc = [];
  walk(root, p => {
    const norm = p.replace(/\\/g, "/");
    if (/\.(js|json)$/.test(norm)) {
      try { acc.push(fs.readFileSync(p, "utf8")); } catch { /* ignore unreadable */ }
    }
  });
  return acc.join("\n\x00\n");
}

function walk(dir, fn) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, entry.name);
    if (entry.isDirectory()) walk(p, fn);
    else fn(p);
  }
}

function escapeRe(s) { return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"); }

function coversCliVerb(corpus, verb) {
  const v = escapeRe(verb);
  const quoted = new RegExp("['\"`]" + v + "['\"`]");
  return quoted.test(corpus);
}

function coversCliFlag(corpus, flag) {
  return corpus.includes(flag);
}

function coversLibExport(corpus, libRel, ident) {
  const baseName = path.basename(libRel).replace(/\.js$/, "");
  const requireRe = new RegExp("require\\([^)]*" + escapeRe(baseName) + "[^)]*\\)");
  if (!requireRe.test(corpus)) return false;
  const identRe = new RegExp("\\b" + escapeRe(ident) + "\\b");
  return identRe.test(corpus);
}

function coversPlaybookId(corpus, id) {
  const q = new RegExp("['\"`]" + escapeRe(id) + "['\"`]");
  return q.test(corpus);
}

function coversCveIoc(corpus, cveId) {
  if (!corpus.includes(cveId)) return false;
  return /\biocs\b/i.test(corpus);
}

// --- Main analyzer ----------------------------------------------------------

function analyze(opts) {
  const cwd = opts.repo || ROOT;
  const changed = listChangedFiles(opts, cwd);
  const corpus = loadTestCorpus(cwd);

  const findings = [];
  const allowlisted = [];
  const manualReview = [];

  for (const ch of changed) {
    const cat = categorize(ch.file);
    if (cat === "docs" || cat === "test") {
      allowlisted.push({ file: ch.file, reason: cat });
      continue;
    }
    if (cat === "skill") { allowlisted.push({ file: ch.file, reason: "skill-signed" }); continue; }
    if (cat === "workflow") { manualReview.push({ file: ch.file, reason: "workflow" }); continue; }
    if (cat === "other") { allowlisted.push({ file: ch.file, reason: "out-of-scope" }); continue; }
    if (ch.status !== "D" && isWhitespaceOnly(opts, ch.file, cwd)) {
      allowlisted.push({ file: ch.file, reason: "whitespace-only" });
      continue;
    }

    const before = fileBefore(opts, ch.file, cwd);
    const after = ch.status === "D" ? null : fileAfter(opts, ch.file, cwd);

    if (cat === "cli") {
      const b = extractCliSurface(before);
      const a = extractCliSurface(after);
      const verbsDiff = diffSets(b.verbs, a.verbs);
      const flagsDiff = diffSets(b.flags, a.flags);
      for (const v of verbsDiff.added) if (!coversCliVerb(corpus, v))
        findings.push({ file: ch.file, kind: "cli-verb", surface: v, change: "added" });
      for (const v of verbsDiff.removed) if (coversCliVerb(corpus, v))
        findings.push({ file: ch.file, kind: "cli-verb", surface: v, change: "removed-but-test-remains" });
      for (const f of flagsDiff.added) if (!coversCliFlag(corpus, f))
        findings.push({ file: ch.file, kind: "cli-flag", surface: f, change: "added" });
      for (const f of flagsDiff.removed) if (coversCliFlag(corpus, f))
        findings.push({ file: ch.file, kind: "cli-flag", surface: f, change: "removed-but-test-remains" });
    } else if (cat === "lib") {
      const b = extractLibExports(before);
      const a = extractLibExports(after);
      const d = diffSets(b, a);
      for (const id of d.added) if (!coversLibExport(corpus, ch.file, id))
        findings.push({ file: ch.file, kind: "lib-export", surface: id, change: "added" });
      for (const id of d.removed) if (coversLibExport(corpus, ch.file, id))
        findings.push({ file: ch.file, kind: "lib-export", surface: id, change: "removed-but-test-remains" });
    } else if (cat === "playbook") {
      const b = extractPlaybookIds(before);
      const a = extractPlaybookIds(after);
      const ind = diffSets(b.indicators, a.indicators);
      const arts = diffSets(b.artifacts, a.artifacts);
      for (const id of ind.added) if (!coversPlaybookId(corpus, id))
        findings.push({ file: ch.file, kind: "playbook-indicator", surface: id, change: "added" });
      for (const id of arts.added) if (!coversPlaybookId(corpus, id))
        findings.push({ file: ch.file, kind: "playbook-artifact", surface: id, change: "added" });
      for (const id of ind.removed) if (coversPlaybookId(corpus, id))
        findings.push({ file: ch.file, kind: "playbook-indicator", surface: id, change: "removed-but-test-remains" });
    } else if (cat === "cve-catalog") {
      const ids = extractCveIocChanges(before, after);
      for (const id of ids) if (!coversCveIoc(corpus, id))
        findings.push({ file: ch.file, kind: "cve-ioc", surface: id, change: "iocs-modified" });
    }
  }

  return { findings, allowlisted, manualReview, totalChanged: changed.length };
}

// --- Output -----------------------------------------------------------------

function emitHuman(report) {
  const out = [];
  out.push("Diff coverage analyzer — " + report.totalChanged + " changed file(s)");
  out.push("  Allowlisted: " + report.allowlisted.length +
           "   Manual-review: " + report.manualReview.length +
           "   Findings: " + report.findings.length);
  if (report.manualReview.length) {
    out.push("");
    out.push("Manual review required:");
    for (const m of report.manualReview) out.push("  - " + m.file + " [" + m.reason + "]");
  }
  if (report.findings.length) {
    out.push("");
    out.push("Uncovered surface changes:");
    for (const f of report.findings) {
      out.push("  [" + f.kind + "] " + f.file + "  '" + f.surface + "'  (" + f.change + ")");
    }
    out.push("");
    out.push("Each item above adds, removes, or modifies a surface that has no");
    out.push("matching reference in tests/. Add a regression test before merge,");
    out.push("or move the change into the allowlist if it is genuinely test-exempt.");
  } else {
    out.push("");
    out.push("OK: every changed surface has a matching test reference.");
  }
  process.stdout.write(out.join("\n") + "\n");
}

function main() {
  let opts;
  try { opts = parseArgs(process.argv.slice(2)); }
  catch (e) { process.stderr.write(e.message + "\n"); process.exitCode = 2; return; }
  if (opts.help) { printHelp(); return; }

  let report;
  try { report = analyze(opts); }
  catch (e) {
    if (opts.json) process.stdout.write(JSON.stringify({ ok: false, error: e.message }) + "\n");
    else process.stderr.write("check-test-coverage: " + e.message + "\n");
    process.exitCode = 2;
    return;
  }

  if (opts.json) {
    process.stdout.write(JSON.stringify({
      ok: report.findings.length === 0,
      total_changed: report.totalChanged,
      findings: report.findings,
      allowlisted: report.allowlisted,
      manual_review: report.manualReview,
    }) + "\n");
  } else {
    emitHuman(report);
  }

  if (report.findings.length > 0 && !opts.warnOnly) process.exitCode = 1;
}

if (require.main === module) main();

module.exports = {
  analyze, parseArgs, categorize,
  extractCliSurface, extractLibExports, extractPlaybookIds, extractCveIocChanges,
  coversCliVerb, coversCliFlag, coversLibExport, coversPlaybookId, coversCveIoc,
  DOCS_ALWAYS_GREEN,
};
