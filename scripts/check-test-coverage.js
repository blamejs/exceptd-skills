#!/usr/bin/env node
"use strict";
/**
 * Diff-aware test-coverage gate. Compares the changed surface in the working
 * tree (or a staged set, or any --base..HEAD range) against the tests/ tree
 * and reports any surface change that lacks a covering test.
 *
 * Surfaces: CLI verbs and flags in bin/exceptd.js, exported functions in
 * lib / orchestrator / scripts, playbook detect-indicator and look-artifact
 * ids, and CVE entries whose iocs changed. Docs, tooling dotfiles, tests/
 * itself and derived indexes are allowlisted; workflows, manifests, schemas,
 * SBOM and unclassified files are surfaced as manual-review, never auto-green.
 *
 * Exit codes: 0 clean or --warn-only, 1 uncovered surface, 2 runner error.
 */

const fs = require("fs");
const path = require("path");
const childProc = require("child_process");

const ROOT = path.resolve(__dirname, "..");

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

function git(args, cwd) {
  const r = childProc.spawnSync("git", args, { cwd, encoding: "utf8" });
  if (r.status !== 0) {
    const err = new Error("git " + args.join(" ") + " failed: " + (r.stderr || r.stdout));
    err.git = true;
    throw err;
  }
  return r.stdout;
}

// The diff anchor resolves ONCE and the resolved SHA threads through every
// per-file call: passing the raw ref lets origin/main advance mid-run, comparing
// content against a newer tree than the file list came from.
function resolveBaseRef(opts, cwd) {
  if (opts.staged) return null; // staged mode uses --cached / HEAD throughout
  // origin/main is not always reachable — fresh clone, detached worktree, remote
  // under another name — and an unresolvable ref fails every later git call as a
  // runner error rather than a coverage result.
  const tryResolve = (ref) => {
    try {
      git(["merge-base", "HEAD", ref], cwd).trim();
      return ref;
    } catch { /* not resolvable */ }
    try {
      git(["rev-parse", "--verify", ref], cwd).trim();
      return ref;
    } catch { return null; }
  };
  try {
    const mb = git(["merge-base", "HEAD", opts.base], cwd).trim();
    if (mb) return mb;
  } catch { /* fall through */ }
  const direct = tryResolve(opts.base);
  if (direct) return direct;
  const local = tryResolve("main");
  if (local) {
    process.stderr.write(
      `[check-test-coverage] WARN: ${opts.base} unreachable; falling back to local main\n`
    );
    return local;
  }
  const parent = tryResolve("HEAD~1");
  if (parent) {
    process.stderr.write(
      `[check-test-coverage] WARN: ${opts.base} unreachable and no local main; falling back to HEAD~1\n`
    );
    return parent;
  }
  return opts.base;
}

function listChangedFiles(opts, cwd, resolvedBase) {
  if (opts.staged) {
    return git(["diff", "--name-status", "--cached"], cwd)
      .split("\n").filter(Boolean).map(parseNameStatus);
  }
  return git(["diff", "--name-status", resolvedBase + "..HEAD"], cwd)
    .split("\n").filter(Boolean).map(parseNameStatus);
}

function parseNameStatus(line) {
  const parts = line.split("\t");
  const status = parts[0][0]; // A/M/D/R/...
  return { status, file: parts[parts.length - 1] };
}

function fileDiff(opts, file, cwd, ignoreWs, resolvedBase) {
  const args = ["diff", "-U0"];
  if (ignoreWs) args.push("--ignore-all-space", "--ignore-blank-lines");
  if (opts.staged) args.push("--cached");
  else args.push(resolvedBase + "..HEAD");
  args.push("--", file);
  try { return git(args, cwd); } catch { return ""; }
}

function fileAtRef(file, ref, cwd) {
  // maxBuffer far above Node's 1 MiB default: an ENOBUFS-truncated read of a
  // multi-MiB catalog makes every entry in the live file look freshly added.
  // Null is the "missing" sentinel, so a failure never returns partial content.
  const r = childProc.spawnSync("git", ["show", ref + ":" + file], {
    cwd, encoding: "utf8", maxBuffer: 64 * 1024 * 1024
  });
  if (r.status !== 0) return null;
  return r.stdout;
}

function fileBefore(opts, file, cwd, resolvedBase) {
  if (opts.staged) return fileAtRef(file, "HEAD", cwd);
  return fileAtRef(file, resolvedBase, cwd);
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

// Contributor-only docs and tooling dotfiles: no semantic surface to test.
const DOCS_ALWAYS_GREEN = new Set([
  "CONTRIBUTING.md", "LICENSE", "NOTICE", "CODE_OF_CONDUCT.md",
  "SUPPORT.md", ".gitignore", ".npmrc", ".editorconfig",
]);

// Operator-facing docs must not auto-green — a PR could otherwise land
// deceptive copy with no reviewer signal — so they downgrade to manual-review.
const DOCS_MANUAL_REVIEW = new Set([
  "CHANGELOG.md", "README.md", "SECURITY.md", "MIGRATING.md", "AGENTS.md",
]);

function categorize(file) {
  const norm = file.replace(/\\/g, "/");
  if (DOCS_ALWAYS_GREEN.has(norm)) return "docs";
  if (DOCS_MANUAL_REVIEW.has(norm)) return "manual-review";
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
  // Shapes carrying semantic surface the analyzer has no extractor for: a human
  // looks, instead of an allowlist.
  if (norm === "manifest.json") return "manual-review";
  if (norm === "manifest-snapshot.json") return "manual-review";
  if (norm === "manifest-snapshot.sha256") return "manual-review";
  if (norm === "sbom.cdx.json") return "manual-review";
  if (norm.startsWith("lib/schemas/")) return "manual-review";
  // data/_indexes/ is regenerated; the reviewable diff is in the data/ sources.
  if (norm.startsWith("data/_indexes/")) return "allowlist-derived";
  if (norm.startsWith("data/") && norm.endsWith(".json")) return "manual-review";
  if (norm === "package.json") return "manual-review";
  return "other";
}

function isWhitespaceOnly(opts, file, cwd, resolvedBase) {
  const wsBlind = fileDiff(opts, file, cwd, true, resolvedBase);
  return wsBlind.split("\n").filter(l => l.startsWith("+") || l.startsWith("-"))
    .filter(l => !l.startsWith("+++") && !l.startsWith("---")).length === 0;
}

function extractCliSurface(content) {
  if (!content) return { verbs: new Set(), flags: new Set() };
  const verbs = new Set();
  const flags = new Set();
  // Only the COMMANDS block and PLAYBOOK_VERBS Set, not arbitrary keys elsewhere.
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
  // REMOVED_VERBS keys are still CLI surface: invoking one returns a structured
  // refusal that tests cover. Counting them stops a dropped COMMANDS row reading
  // as a fresh "removed-but-test-remains" against the refusal test.
  const removedBlock = content.match(/const REMOVED_VERBS = \{([\s\S]*?)\n\};/);
  if (removedBlock) {
    for (const m of removedBlock[1].matchAll(/^\s*"?([a-zA-Z][\w-]+)"?\s*:/gm)) verbs.add(m[1]);
  }
  // Scans the whole file, prose included, so a flag named in a comment counts as
  // surface. A trailing hyphen means the match stopped at a line break mid-name
  // (`--attest-` wrapping to `ownership`), which is never a flag — admitting one
  // makes deleting that comment read as a removed flag.
  const flagRe = /(--[a-zA-Z][\w-]+)/g;
  let m;
  while ((m = flagRe.exec(content)) !== null) {
    if (!m[1].endsWith("-")) flags.add(m[1]);
  }
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
  // Strip comments first: a `module.exports = {...}` inside a doc comment
  // otherwise shadows the real exports and the export set comes back empty.
  const stripped = content
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .replace(/^\s*\/\/.*$/gm, "");
  // Brace-balanced so a nested member (`{ CONFIG: { a: 1 }, x, y }`) does not
  // truncate the list at the first inner `}` and hide later exports.
  const objStart = stripped.search(/module\.exports\s*=\s*\{/);
  if (objStart !== -1) {
    const openIdx = stripped.indexOf("{", objStart);
    // String-aware: a `}` inside a value (`{ PATTERN: "a}b", realExport }`)
    // must not close the object early and hide the exports that follow.
    let depth = 0, end = -1, inStr = null;
    for (let i = openIdx; i < stripped.length; i++) {
      const ch = stripped[i];
      if (inStr) {
        if (ch === "\\") { i++; continue; }
        if (ch === inStr) inStr = null;
        continue;
      }
      if (ch === "'" || ch === '"' || ch === "`") { inStr = ch; continue; }
      if (ch === "{") depth++;
      else if (ch === "}") { depth--; if (depth === 0) { end = i; break; } }
    }
    if (end !== -1) {
      const body = stripped.slice(openIdx + 1, end);
      // String-aware split: a `,` or bracket inside a string must not split a member.
      let d = 0, cur = "", sInStr = null;
      const members = [];
      for (let i = 0; i < body.length; i++) {
        const ch = body[i];
        if (sInStr) {
          cur += ch;
          if (ch === "\\") { cur += (body[i + 1] || ""); i++; continue; }
          if (ch === sInStr) sInStr = null;
          continue;
        }
        if (ch === "'" || ch === '"' || ch === "`") { sInStr = ch; cur += ch; continue; }
        if (ch === "{" || ch === "[") d++;
        else if (ch === "}" || ch === "]") d--;
        if (ch === "," && d === 0) { members.push(cur); cur = ""; }
        else cur += ch;
      }
      members.push(cur);
      for (const tok of members) {
        const id = tok.split(":")[0].trim();
        if (/^[a-zA-Z_$][\w$]*$/.test(id)) { out.add(id); continue; }
        // Method-shorthand member (`fn(a){}`, `async load(){}`, `*gen(){}`): the
        // colon split leaves `name(...)`, so recover the name before the first
        // `(`, past any modifier keyword or generator `*`.
        const beforeParen = tok.split("(")[0].trim();
        const parts = beforeParen.split(/\s+/);
        const cand = parts[parts.length - 1].replace(/^\*/, "").trim();
        if (/^[a-zA-Z_$][\w$]*$/.test(cand)) out.add(cand);
      }
    }
  }
  // Whole-module export (`module.exports = mainFn;`): the object extractor above
  // matches nothing, so without this the file's only export is invisible.
  const singleIdent = stripped.match(/module\.exports\s*=\s*([a-zA-Z_$][\w$]*)\s*;/);
  if (singleIdent && !/^(function|async|class)$/.test(singleIdent[1])) {
    out.add(singleIdent[1]);
  }
  const re = /module\.exports\.([a-zA-Z_$][\w$]*)\s*=/g;
  let mm;
  while ((mm = re.exec(stripped)) !== null) out.add(mm[1]);
  const re2 = /^exports\.([a-zA-Z_$][\w$]*)\s*=/gm;
  while ((mm = re2.exec(stripped)) !== null) out.add(mm[1]);
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

// Canonical equality, not JSON.stringify: key order, whitespace and numeric
// formatting are not semantic changes to an iocs block.
const { canonicalEqual } = require("../lib/canonical-eq");

function extractCveIocChanges(beforeStr, afterStr) {
  const before = safeParse(beforeStr) || {};
  const after = safeParse(afterStr) || {};
  const changed = new Set();
  const ids = new Set([...Object.keys(before), ...Object.keys(after)]);
  for (const id of ids) {
    if (!/^CVE-\d{4}-\d+/.test(id)) continue;
    // Rows auto-imported on BOTH sides hold stub IoCs by design; without the
    // skip, every fresh KEV bulk-import surfaces as a per-CVE finding.
    const beforeAuto = !!(before[id] && before[id]._auto_imported);
    const afterAuto  = !!(after[id]  && after[id]._auto_imported);
    if (beforeAuto && afterAuto) continue;
    const bIocs = (before[id] && before[id].iocs) || null;
    const aIocs = (after[id]  && after[id].iocs)  || null;
    if (!canonicalEqual(bIocs, aIocs)) changed.add(id);
  }
  return changed;
}

function safeParse(s) { try { return s ? JSON.parse(s) : null; } catch { return null; } }

function loadTestCorpus(cwd) {
  const root = path.join(cwd, "tests");
  if (!fs.existsSync(root)) return { joined: "", files: [] };
  const acc = [];
  const files = [];
  walk(root, p => {
    const norm = p.replace(/\\/g, "/");
    if (/\.(js|json)$/.test(norm)) {
      try {
        const content = fs.readFileSync(p, "utf8");
        acc.push(content);
        files.push({ path: norm, content });
      } catch { /* ignore unreadable */ }
    }
  });
  return { joined: acc.join("\n\x00\n"), files };
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

// Coverage needs same-file context: the identifier must appear inside a real
// test block in the SAME file that requires the module, or a stray require() in
// one file plus a mention in another reads as coverage. `corpus` is either the
// structured `{ joined, files }` from loadTestCorpus or a legacy joined string.
function coversLibExport(corpus, libRel, ident) {
  const baseName = path.basename(libRel).replace(/\.js$/, "");
  const baseFile = path.basename(libRel);
  const identRe = new RegExp("\\b" + escapeRe(ident) + "\\b");
  const requireRe = new RegExp("require\\([^)]*" + escapeRe(baseName) + "[^)]*\\)");
  if (corpus && Array.isArray(corpus.files)) {
    for (const f of corpus.files) {
      const hasRequire = requireRe.test(f.content);
      const mentionsSpawnPath = f.content.includes(baseFile);
      if (!hasRequire && !mentionsSpawnPath) continue;
      if (!identRe.test(f.content)) continue;
      if (mentionsIdentInTestContext(f.content, ident)) return true;
    }
    return false;
  }
  // Fallback: legacy joined-string corpus.
  const joined = typeof corpus === "string" ? corpus : (corpus && corpus.joined) || "";
  if (requireRe.test(joined) && identRe.test(joined)) return true;
  if (joined.includes(baseFile) && identRe.test(joined)) return true;
  return false;
}

// True when `ident` appears as a token inside the parenthesised body of a
// `test(`, `it(`, `describe(`, `assert(` or `assert.<member>(` call. The paren
// walk is approximate by design.
function mentionsIdentInTestContext(content, ident) {
  const tokenRe = new RegExp("\\b" + escapeRe(ident) + "\\b");
  if (!tokenRe.test(content)) return false;
  const callRe = /\b(test|it|describe|assert(?:\.[A-Za-z_$][\w$]*)?)\s*\(/g;
  let m;
  while ((m = callRe.exec(content)) !== null) {
    const start = m.index + m[0].length; // pointer to first char inside (
    let depth = 1;
    let i = start;
    let inStr = null;
    while (i < content.length && depth > 0) {
      const c = content[i];
      if (inStr) {
        if (c === "\\") { i += 2; continue; }
        if (c === inStr) inStr = null;
      } else {
        if (c === '"' || c === "'" || c === "`") inStr = c;
        else if (c === "(") depth++;
        else if (c === ")") depth--;
      }
      i++;
    }
    const body = content.slice(start, i - 1);
    if (tokenRe.test(body)) return true;
  }
  return false;
}

function coversPlaybookId(corpus, id) {
  const q = new RegExp("['\"`]" + escapeRe(id) + "['\"`]");
  return q.test(corpus);
}

function coversCveIoc(corpus, cveId) {
  if (!corpus.includes(cveId)) return false;
  return /\biocs\b/i.test(corpus);
}

// Every exit-code assertion must pin the EXACT code: `assert.notEqual(r.status,
// 0)` passes on any non-zero exit, hiding the regression the test was written
// for. The only opt-out is `// allow-notEqual: <reason>` on the same line, for a
// genuine refusal-pin that asserts NOT a specific code.
function scanForCoincidenceAsserts(cwd) {
  const out = [];
  const testsDir = path.join(cwd, "tests");
  if (!fs.existsSync(testsDir)) return out;
  // The receiver name varies (r, r1, result, child); the `.status` access is the signal.
  const banRe = /assert\.notEqual\s*\(\s*[A-Za-z_$][\w$]*\.status\b/;
  const allowRe = /\/\/\s*allow-notEqual\s*:/;
  const skipPrefix = "_helpers"; // helpers may legitimately reference the pattern
  for (const entry of fs.readdirSync(testsDir, { withFileTypes: true })) {
    if (!entry.isFile()) continue;
    if (entry.name.startsWith(skipPrefix)) continue;
    if (!entry.name.endsWith(".test.js")) continue;
    const filePath = path.join(testsDir, entry.name);
    let body;
    try { body = fs.readFileSync(filePath, "utf8"); }
    catch { continue; }
    const lines = body.split(/\r?\n/);
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (!banRe.test(line)) continue;
      if (allowRe.test(line)) continue;
      out.push({
        file: path.join("tests", entry.name).replace(/\\/g, "/"),
        line: i + 1,
        snippet: line.trim(),
      });
    }
  }
  return out;
}

function analyze(opts) {
  const cwd = opts.repo || ROOT;
  const resolvedBase = resolveBaseRef(opts, cwd);
  const changed = listChangedFiles(opts, cwd, resolvedBase);
  const corpusObj = loadTestCorpus(cwd);
  const corpus = corpusObj.joined;

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
    if (cat === "manual-review") { manualReview.push({ file: ch.file, reason: "manual-review" }); continue; }
    if (cat === "allowlist-derived") { allowlisted.push({ file: ch.file, reason: "derived-artifact" }); continue; }
    if (cat === "other") { manualReview.push({ file: ch.file, reason: "unclassified" }); continue; }
    if (ch.status !== "D" && isWhitespaceOnly(opts, ch.file, cwd, resolvedBase)) {
      allowlisted.push({ file: ch.file, reason: "whitespace-only" });
      continue;
    }

    const before = fileBefore(opts, ch.file, cwd, resolvedBase);
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
      for (const id of d.added) if (!coversLibExport(corpusObj, ch.file, id))
        findings.push({ file: ch.file, kind: "lib-export", surface: id, change: "added" });
      for (const id of d.removed) if (coversLibExport(corpusObj, ch.file, id))
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

  // Runs irrespective of the diff: a coincidence-passing assert can land by a
  // path this analyzer never inspects.
  const coincidenceFindings = scanForCoincidenceAsserts(cwd);
  for (const f of coincidenceFindings) {
    findings.push({
      file: f.file,
      kind: "coincidence-assert",
      surface: f.snippet,
      change: `line ${f.line}: pin to exact exit code (anti-coincidence rule). Opt out only with \`// allow-notEqual: <reason>\` on the same line for genuine refusal-pins.`,
    });
  }

  return { findings, allowlisted, manualReview, totalChanged: changed.length };
}

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
  scanForCoincidenceAsserts,
  DOCS_ALWAYS_GREEN, DOCS_MANUAL_REVIEW,
};
