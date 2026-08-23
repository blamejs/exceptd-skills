#!/usr/bin/env node
"use strict";
/**
 * Grep gate for code-shape bug classes that recur across releases; CLASSES
 * below is the registry.
 *
 * Exceptions live at the violation site:
 *   - file-level, in the first 50 lines:  // codebase-patterns:allow-file <class> — <reason>
 *   - per-line, on the same line or up to 2 lines above:  // allow:<class> — <reason>
 *
 * Owned elsewhere: phase/version vocabulary (check-version-tags.js), CLI-dispatch
 * process.exit (tests/safe-exit-grep.test.js), test assertions
 * (check-test-coverage.js), operator-output path leaks (operator-leak-grep.test.js).
 */

const fs = require("node:fs");
const path = require("node:path");

const ROOT = path.resolve(__dirname, "..");

// Classes that accept an `// allow:<class>` marker. orphan-allow-class is the
// meta-guard itself, so it is not markable.
const VALID_ALLOW_CLASSES = Object.freeze({
  "process-exit-after-stdout-write": true,
  "dynamic-regex": true,
  "bidi-codepoint-literal": true,
  "unsorted-marked-array": true,
  "misaligned-marked-run": true,
  "hand-rolled-sql": true,
});

const EXCLUDE_DIRS = new Set([
  "node_modules", "vendor", ".git", ".cache", ".scratch",
  "data", ".test-output", ".keys", "keys", "coverage",
]);

function relPath(abs) {
  return path.relative(ROOT, abs).split(path.sep).join("/");
}

function walk(dir, out) {
  let entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); }
  catch (_e) { return out; }
  for (const e of entries) {
    const abs = path.join(dir, e.name);
    if (e.isDirectory()) {
      if (EXCLUDE_DIRS.has(e.name)) continue;
      walk(abs, out);
    } else if (e.isFile() && /\.(c|m)?js$/.test(e.name) && !/\.test\.js$/.test(e.name)) {
      out.push(abs);
    }
  }
  return out;
}

// Source files under the given top-level roots, as repo-relative POSIX paths.
function filesUnder(roots) {
  const out = [];
  for (const r of roots) {
    const abs = path.join(ROOT, r);
    try {
      const st = fs.statSync(abs);
      if (st.isDirectory()) walk(abs, out);
      else if (st.isFile()) out.push(abs);
    } catch (_e) { /* missing root — skip */ }
  }
  return out.map(relPath).sort();
}

const _lineCache = new Map();
function readLines(rel) {
  if (_lineCache.has(rel)) return _lineCache.get(rel);
  const abs = path.isAbsolute(rel) ? rel : path.join(ROOT, rel);
  let lines;
  try { lines = fs.readFileSync(abs, "utf8").split(/\r?\n/); }
  catch (_e) { lines = []; }
  _lineCache.set(rel, lines);
  return lines;
}

// Strip a trailing `//` line comment so a class name mentioned in a comment
// can't arm a detector. String-aware: a `//` inside a quoted string (a `http://`
// URL) is not a comment — truncating there hides a real hit later on the line.
function stripLineComment(line) {
  let inStr = null; // active quote char, or null
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (inStr) {
      if (ch === "\\") { i++; continue; }
      if (ch === inStr) inStr = null;
    } else if (ch === "'" || ch === '"' || ch === "`") {
      inStr = ch;
    } else if (ch === "/" && line[i + 1] === "/") {
      return line.slice(0, i);
    }
  }
  return line;
}

function hasFileAllow(rel, cls) {
  const head = readLines(rel).slice(0, 50);
  const re = new RegExp("codebase-patterns:allow-file\\s+" + cls + "\\b");
  return head.some((l) => re.test(l));
}

function hasLineAllow(rel, lineNo /* 1-based */, cls) {
  const lines = readLines(rel);
  const re = new RegExp("//.*\\ballow:" + cls + "\\b");
  for (let n = lineNo; n >= lineNo - 2 && n >= 1; n--) {
    if (re.test(lines[n - 1] || "")) return true;
  }
  return false;
}

function filterMarkers(hits, cls) {
  return hits.filter((h) => !hasFileAllow(h.file, cls) && !hasLineAllow(h.file, h.line, cls));
}

// Counts `{` / `}` in REAL CODE context only: a brace inside a string, template
// or comment must not move the depth, or the computed require.main range slides
// onto a later function. `state` is mutated in place and threaded line to line,
// since `inTemplate` / `inBlock` are cross-line states.
function countCodeBraces(line, state) {
  let delta = 0;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    const next = line[i + 1];
    if (state.inBlock) {
      if (ch === "*" && next === "/") { state.inBlock = false; i++; }
      continue;
    }
    if (state.inSingle) {
      if (ch === "\\") { i++; continue; }
      if (ch === "'") state.inSingle = false;
      continue;
    }
    if (state.inDouble) {
      if (ch === "\\") { i++; continue; }
      if (ch === '"') state.inDouble = false;
      continue;
    }
    if (state.inTemplate) {
      if (ch === "\\") { i++; continue; }
      if (ch === "`") { state.inTemplate = false; continue; }
      if (ch === "$" && next === "{") {
        // Enter an interpolation expression: braces inside ARE code.
        state.templateExpr.push(0);
        state.inTemplate = false;
        i++;
        continue;
      }
      continue;
    }
    if (ch === "/" && next === "/") break;
    if (ch === "/" && next === "*") { state.inBlock = true; i++; continue; }
    if (ch === "'") { state.inSingle = true; continue; }
    if (ch === '"') { state.inDouble = true; continue; }
    if (ch === "`") { state.inTemplate = true; continue; }
    if (ch === "{") {
      if (state.templateExpr.length) state.templateExpr[state.templateExpr.length - 1]++;
      delta++;
    } else if (ch === "}") {
      if (state.templateExpr.length && state.templateExpr[state.templateExpr.length - 1] === 0) {
        // Closes the `${ … }` interpolation — back to template body.
        state.templateExpr.pop();
        state.inTemplate = true;
      } else {
        if (state.templateExpr.length) state.templateExpr[state.templateExpr.length - 1]--;
        delta--;
      }
    }
  }
  return delta;
}

function newBraceState() {
  return { inSingle: false, inDouble: false, inTemplate: false, inBlock: false, templateExpr: [] };
}

// Line ranges (1-based, inclusive) of `if (require.main === module) { ... }` blocks,
// where print-then-exit is correct — owned by tests/safe-exit-grep.test.js.
function requireMainRanges(lines) {
  const ranges = [];
  for (let i = 0; i < lines.length; i++) {
    if (/\brequire\.main\s*===\s*module\b/.test(lines[i])) {
      let depth = 0;
      let started = false;
      let j = i;
      const state = newBraceState();
      for (; j < lines.length; j++) {
        depth += countCodeBraces(lines[j], state);
        if (depth > 0) started = true;
        if (started && depth <= 0) break;
      }
      if (started) ranges.push([i + 1, j + 1]);
    }
  }
  return ranges;
}

function inRanges(ranges, lineNo) {
  return ranges.some(([a, b]) => lineNo >= a && lineNo <= b);
}

// Opens a new function body, so the backward stdout-write scan stops at the
// enclosing function. The bare-identifier alternative must REFUSE control-flow
// openers (`if (…) {`, `for (…) {`): those sit inside the SAME function, and
// stopping there leaves a real exit-after-write unflagged.
const FUNCTION_START = /(^|[^.\w])function\b|=>\s*\{?\s*$|^\s*(async\s+)?(?!(?:if|for|while|switch|catch|do|else|with|finally|return)\b)[A-Za-z_$][\w$]*\s*\([^)]*\)\s*\{/;

function detectProcessExitAfterStdout(files) {
  const hits = [];
  for (const rel of (files || filesUnder(["bin/exceptd.js", "lib", "orchestrator", "scripts"]))) {
    const lines = readLines(rel);
    const mainRanges = requireMainRanges(lines);
    for (let i = 0; i < lines.length; i++) {
      const code = stripLineComment(lines[i]);
      if (!/\bprocess\.exit\s*\(/.test(code)) continue;
      const lineNo = i + 1;
      if (inRanges(mainRanges, lineNo)) continue; // CLI-entry block: legitimate
      // Scan backward within the enclosing function for a result-channel write.
      let sawStdout = false;
      for (let k = i - 1; k >= 0 && k >= i - 60; k--) {
        const prev = stripLineComment(lines[k]);
        if (/\bprocess\.stdout\.write\s*\(/.test(prev) || /\bconsole\.log\s*\(/.test(prev)) {
          sawStdout = true; break;
        }
        if (FUNCTION_START.test(prev)) break; // left the function body
      }
      if (sawStdout) hits.push({ file: rel, line: lineNo, content: lines[i].trim() });
    }
  }
  return filterMarkers(hits, "process-exit-after-stdout-write");
}

// A first arg opening with `"`, `'` or `/` is a literal, so static and safe.
// Backtick is NOT exempt — a template literal can interpolate operator input.
function isStaticRegexFirstChar(ch) {
  return ch === '"' || ch === "'" || ch === "/";
}

function detectDynamicRegex(files) {
  const hits = [];
  for (const rel of (files || filesUnder(["lib", "orchestrator", "bin/exceptd.js"]))) {
    const lines = readLines(rel);
    for (let i = 0; i < lines.length; i++) {
      const code = stripLineComment(lines[i]);
      const m = code.match(/\bnew RegExp\s*\(\s*(.)/);
      if (m) {
        if (isStaticRegexFirstChar(m[1])) continue;
        hits.push({ file: rel, line: i + 1, content: lines[i].trim() });
        continue;
      }
      // Multi-line form: the pattern arg starts on a later line, so look ahead
      // past blank and comment-only lines, capped at 5.
      if (!/\bnew RegExp\s*\(\s*$/.test(code)) continue;
      let firstChar = null;
      for (let k = i + 1; k <= i + 5 && k < lines.length; k++) {
        const ahead = stripLineComment(lines[k]).replace(/^\s+/, "");
        if (ahead === "") continue;
        firstChar = ahead[0];
        break;
      }
      // Nothing parseable within the cap is suspicious — flag it.
      if (firstChar !== null && isStaticRegexFirstChar(firstChar)) continue;
      hits.push({ file: rel, line: i + 1, content: lines[i].trim() });
    }
  }
  return filterMarkers(hits, "dynamic-regex");
}

// Raw bidi-override / zero-width / invisible / null codepoints typed as literals
// — the Trojan-Source class (CVE-2021-42574). Source emits them via
// vendor/blamejs/codepoint-class or a \uXXXX escape instead.
const _BIDI_LITERAL_RANGES = [
  [0x202A, 0x202E], [0x2066, 0x2069], 0x200E, 0x200F, 0x061C, // bidi overrides + isolates
  0x200B, 0x200C, 0x200D, 0x00AD, 0x2060, 0xFEFF,             // zero-width / invisible
  0x0000,                                                      // null
];
function _bidiLiteralRe() {
  const body = _BIDI_LITERAL_RANGES.map((r) =>
    Array.isArray(r)
      ? "\\u" + r[0].toString(16).padStart(4, "0") + "-\\u" + r[1].toString(16).padStart(4, "0")
      : "\\u" + r.toString(16).padStart(4, "0")
  ).join("");
  return new RegExp("[" + body + "]"); // allow:dynamic-regex — codepoints from a static literal range table, not operator input
}
function detectBidiCodepointLiteral(files) {
  const re = _bidiLiteralRe();
  const hits = [];
  for (const rel of (files || filesUnder(["bin/exceptd.js", "lib", "orchestrator", "scripts"]))) {
    if (rel === "scripts/check-codebase-patterns.js") continue; // holds the range table itself
    const lines = readLines(rel);
    for (let i = 0; i < lines.length; i++) {
      if (re.test(lines[i])) hits.push({ file: rel, line: i + 1, content: lines[i].trim() });
    }
  }
  return filterMarkers(hits, "bidi-codepoint-literal");
}

function detectOrphanAllowClass(files) {
  const hits = [];
  for (const rel of (files || filesUnder(["bin/exceptd.js", "lib", "orchestrator", "scripts"]))) {
    if (rel === "scripts/check-codebase-patterns.js") continue; // holds the registry + regexes
    const lines = readLines(rel);
    for (let i = 0; i < lines.length; i++) {
      const cmt = lines[i].indexOf("//");
      if (cmt === -1) continue;
      const comment = lines[i].slice(cmt);
      // Both marker forms carry the same class + reason rules. The file-level
      // form suppresses every hit of its class, so it must be caught here.
      const fileLevel = comment.match(/\bcodebase-patterns:allow-file\s+([a-z0-9-]+)\b(.*)$/);
      const perLine = comment.match(/\ballow:([a-z0-9-]+)\b(.*)$/);
      const m = fileLevel || perLine;
      if (!m) continue;
      const cls = m[1];
      const tail = m[2];
      const label = fileLevel ? `allow-file ${cls}` : `allow:${cls}`;
      if (!VALID_ALLOW_CLASSES[cls]) {
        hits.push({ file: rel, line: i + 1, content: lines[i].trim(), why: `unknown allow-class "${cls}"` });
      } else if (!/[—-]\s*\S/.test(tail)) {
        hits.push({ file: rel, line: i + 1, content: lines[i].trim(), why: `${label} is missing the "— <reason>" tail` });
      }
    }
  }
  return hits;
}

// The two detectors below fire only on sites that opt in via a marker, so
// unmarked code is never flagged.

// `// keep-sorted` marks a flat string-literal array that must stay alphabetically
// sorted; an array with object or nested elements is skipped.
function scanUnsortedMarkedArray(rel, lines) {
  const hits = [];
  for (let i = 0; i < lines.length; i++) {
    if (!/\/\/\s*keep-sorted\b/.test(lines[i])) continue;
    const openIdx = lines[i].indexOf("[");
    if (openIdx === -1) continue;
    let depth = 0, started = false, body = "";
    for (let j = i; j < lines.length; j++) {
      const seg = (j === i) ? lines[j].slice(openIdx) : lines[j];
      for (const ch of seg) {
        if (ch === "[") { depth++; started = true; }
        else if (ch === "]") { depth--; }
      }
      body += " " + seg;
      if (started && depth <= 0) break;
    }
    if (/[{]/.test(body)) continue;
    const strs = [];
    const re = /(['"])((?:\\.|(?!\1).)*)\1/g;
    let m;
    while ((m = re.exec(body)) !== null) strs.push(m[2]);
    if (strs.length < 2) continue;
    const sorted = [...strs].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
    if (strs.join(" ") !== sorted.join(" ")) {
      const k = strs.findIndex((s, idx) => idx > 0 && strs[idx - 1] > s);
      hits.push({ file: rel, line: i + 1, content: lines[i].trim(), why: `marked // keep-sorted but "${strs[k]}" is out of alphabetical order` });
    }
  }
  return hits;
}
function detectUnsortedMarkedArray(files) {
  const hits = [];
  for (const rel of (files || filesUnder(["bin/exceptd.js", "lib", "orchestrator", "scripts"]))) {
    if (rel === "scripts/check-codebase-patterns.js") continue; // holds the detector + its own marker prose
    hits.push(...scanUnsortedMarkedArray(rel, readLines(rel)));
  }
  return hits;
}

// `// keep-aligned` marks a contiguous run of `IDENT = value` / `IDENT: value`
// lines whose assignment columns must all line up. The run starts at the line
// after the marker and ends at the first blank or non-assignment line.
function scanMisalignedMarkedRun(rel, lines) {
  const hits = [];
  for (let i = 0; i < lines.length; i++) {
    if (!/\/\/\s*keep-aligned\b/.test(lines[i])) continue;
    const run = [];
    for (let j = i + 1; j < lines.length; j++) {
      if (/^\s*$/.test(lines[j])) break;
      const code = stripLineComment(lines[j]).replace(/\s+$/, "");
      const m = code.match(/^(\s*[A-Za-z_$][\w$.'"-]*\s*)([:=])\s/);
      if (!m) break;
      run.push({ lineNo: j + 1, col: m[1].length, op: m[2], content: lines[j].trim() });
    }
    if (run.length < 2) continue;
    const op = run[0].op;
    const cols = run.filter((r) => r.op === op).map((r) => r.col);
    const target = Math.max(...cols);
    const bad = run.find((r) => r.op === op && r.col !== target);
    if (bad) {
      hits.push({ file: rel, line: bad.lineNo, content: bad.content, why: `marked // keep-aligned but the '${op}' columns are not all equal` });
    }
  }
  return hits;
}
function detectMisalignedMarkedRun(files) {
  const hits = [];
  for (const rel of (files || filesUnder(["bin/exceptd.js", "lib", "orchestrator", "scripts"]))) {
    if (rel === "scripts/check-codebase-patterns.js") continue;
    hits.push(...scanMisalignedMarkedRun(rel, readLines(rel)));
  }
  return hits;
}

// Forward guard: the driver import is the gate, so prose merely beginning
// "Update …" in a non-DB file is never scanned. In a file that does import one,
// a statement or a concatenated clause is an injection sink.
const SQL_DRIVER_IMPORT = /require\(\s*["'](?:node:sqlite|better-sqlite3|sqlite3|sqlite|pg|mysql2?|knex|sequelize|drizzle-orm|postgres|@libsql\/[\w.-]+)(?:\/[^"']*)?["']\s*\)|\bfrom\s+["'](?:node:sqlite|better-sqlite3|pg|mysql2?|knex|sequelize|drizzle-orm)(?:\/[^"']*)?["']/;
const SQL_STMT_START = /(["'`])\s*(?:SELECT\b|INSERT\s+(?:INTO|OR)\b|REPLACE\s+INTO\b|UPDATE\s+["'`]?[A-Za-z_]|DELETE\s+FROM\b|CREATE\s+(?:TABLE|UNIQUE\s+INDEX|INDEX|TRIGGER|VIRTUAL\s+TABLE)\b|ALTER\s+TABLE\b|DROP\s+(?:TABLE|TRIGGER|INDEX)\b|MERGE\s+INTO\b)/i;
// The trailing-concat form tolerates a quote inside the clause
// (`" WHERE name = 'x' " + id`) by scanning to the first `+`.
const SQL_CLAUSE_FRAG = /(?:\+\s*["'`]\s*(?:SET|FROM|WHERE|VALUES|ORDER\s+BY|GROUP\s+BY|HAVING|RETURNING|LIMIT|OFFSET|ON\s+CONFLICT|(?:INNER\s+|LEFT\s+|RIGHT\s+|CROSS\s+)?JOIN)\b|["'`]\s*(?:SET|FROM|WHERE|VALUES\s*\(|ORDER\s+BY|GROUP\s+BY|HAVING|RETURNING|ON\s+CONFLICT|(?:INNER\s+|LEFT\s+|RIGHT\s+|CROSS\s+)?JOIN)\b[^+]*\+)/i;
function detectHandRolledSql(files) {
  const hits = [];
  for (const rel of (files || filesUnder(["lib", "orchestrator", "bin/exceptd.js", "scripts"]))) {
    const lines = readLines(rel);
    if (!SQL_DRIVER_IMPORT.test(lines.join("\n"))) continue; // not a DB file — never scan prose
    for (let i = 0; i < lines.length; i++) {
      const code = stripLineComment(lines[i]);
      if (SQL_STMT_START.test(code)) { hits.push({ file: rel, line: i + 1, content: lines[i].trim().slice(0, 110), why: "SQL statement in a string literal" }); continue; }
      if (SQL_CLAUSE_FRAG.test(code)) { hits.push({ file: rel, line: i + 1, content: lines[i].trim().slice(0, 110), why: "SQL clause built by concatenation" }); }
    }
  }
  return filterMarkers(hits, "hand-rolled-sql");
}

const CLASSES = [
  {
    id: "process-exit-after-stdout-write",
    run: detectProcessExitAfterStdout,
    warnOnly: false,
    hint: "use `safeExit(EXIT_CODES.X); return;` (lib/exit-codes.js) — process.exit() truncates buffered stdout when piped",
  },
  {
    id: "dynamic-regex",
    run: detectDynamicRegex,
    warnOnly: false,
    hint: "RegExp from operator input is a ReDoS sink — anchor + length-cap, or `// allow:dynamic-regex — <reason>` when the pattern is a trusted bundled schema",
  },
  {
    id: "unsorted-marked-array",
    run: detectUnsortedMarkedArray,
    warnOnly: false,
    hint: "a flat string array tagged `// keep-sorted` drifted out of alphabetical order — re-sort it, or drop the marker if the order is intentional",
  },
  {
    id: "misaligned-marked-run",
    run: detectMisalignedMarkedRun,
    warnOnly: false,
    hint: "a `// keep-aligned` const/weight table has uneven assignment columns — realign the `=`/`:` columns, or drop the marker",
  },
  {
    id: "bidi-codepoint-literal",
    run: detectBidiCodepointLiteral,
    warnOnly: false,
    hint: "raw bidi/zero-width/null codepoint in source — emit it via vendor/blamejs/codepoint-class tables or a \\uXXXX escape, or `// allow:bidi-codepoint-literal — <reason>` if the literal is load-bearing test/illustrative data",
  },
  {
    id: "orphan-allow-class",
    run: detectOrphanAllowClass,
    warnOnly: false,
    hint: "a typo'd or reason-less `// allow:<class>` suppresses nothing — fix the class id or add `— <reason>`",
  },
  {
    id: "hand-rolled-sql",
    run: detectHandRolledSql,
    warnOnly: false,
    hint: "a SQL statement/clause assembled as a string in a file that imports a SQL driver is an injection sink — use bound parameters, or `// allow:hand-rolled-sql — <reason>` for a trusted static DDL string",
  },
];

function main() {
  // Fail closed on an empty scan universe: each detector silently finds no hits
  // when its roots are unreadable. Zero files scanned is not "clean".
  const universe = filesUnder(["bin/exceptd.js", "lib", "orchestrator", "scripts"]);
  if (universe.length === 0) {
    console.error("[check-codebase-patterns] FAIL — zero source files found under bin/lib/orchestrator/scripts; refusing to report clean without scanning anything.");
    process.exitCode = 1;
    return;
  }
  let hardFail = 0;
  let warnTotal = 0;
  let n = 0;
  for (const c of CLASSES) {
    const hits = c.run();
    if (!hits.length) { console.log(`  ok ${c.id}: clean`); continue; }
    for (const h of hits) {
      n++;
      const tag = c.warnOnly ? "[warn]" : "FAIL";
      const extra = h.why ? `  (${h.why})` : "";
      console.error(`  ${n}. ${tag} ${c.id}  ${h.file}:${h.line}: ${String(h.content).slice(0, 110)}${extra}`);
    }
    console.error(`     -> ${c.hint}`);
    if (c.warnOnly) warnTotal += hits.length; else hardFail += hits.length;
  }
  if (hardFail === 0) {
    console.log(`[check-codebase-patterns] ok${warnTotal ? ` (${warnTotal} warning(s))` : ""}`);
    process.exitCode = 0;
    return;
  }
  console.error(`[check-codebase-patterns] FAIL — ${hardFail} blocking violation(s).`);
  process.exitCode = 1;
}

module.exports = {
  VALID_ALLOW_CLASSES,
  CLASSES,
  detectProcessExitAfterStdout,
  detectDynamicRegex,
  detectBidiCodepointLiteral,
  detectOrphanAllowClass,
  detectUnsortedMarkedArray,
  detectMisalignedMarkedRun,
  detectHandRolledSql,
  SQL_DRIVER_IMPORT,
  SQL_STMT_START,
  SQL_CLAUSE_FRAG,
  scanUnsortedMarkedArray,
  scanMisalignedMarkedRun,
  requireMainRanges,
  countCodeBraces,
  newBraceState,
  isStaticRegexFirstChar,
  FUNCTION_START,
  filesUnder,
};

if (require.main === module) main();
