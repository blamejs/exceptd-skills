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
 * Owned elsewhere: phase/version vocabulary (check-version-tags.js), test
 * assertions (check-test-coverage.js), and — both now in tests/cli.test.js,
 * which absorbed the separate safe-exit-grep and operator-leak-grep files —
 * the per-file CLI-dispatch process.exit ban and operator-output path leaks.
 */

const fs = require("node:fs");
const path = require("node:path");
const { regexLiteralEnd, afterControlFlowParen, REGEX_CAN_START } = require("./check-test-count.js");

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
  "number-env-coerce": true,
  "stream-chunk-string-decode": true,
  "british-spelling": true,
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

// Scope, stated so it is not mistaken for full coverage of the class: the
// backward scan recognizes a result-channel write only where it is written
// LITERALLY — `process.stdout.write(` or `console.log(`. A write reached
// INDIRECTLY, through a helper called from the exiting function (`printHelp()`,
// `renderSummary()`), is invisible to it, so an exit-after-write of that shape
// passes this gate and has to be caught by review or a per-file test.
//
// Not closed by matching call sites of same-file writer functions: measured over
// lib/, orchestrator/, scripts/ and bin/, that heuristic cannot tell a helper
// that writes to STDOUT from one that writes to stderr via console.error, and it
// fires on exits that are correct. Closing it properly needs call-graph
// resolution of the write target, not another regex.
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

// Number("") is 0, Number("5x") is NaN and Number("Infinity") is Infinity, and
// none of them throws, so an environment value read this way reaches a bound
// like `added >= cap` as NaN and the bound never holds.
const NUMBER_ENV = /\bNumber\s*\(\s*process\.env\b/;
function detectNumberEnvCoerce(files) {
  const hits = [];
  for (const rel of (files || filesUnder(["bin/exceptd.js", "lib", "orchestrator", "scripts"]))) {
    if (rel === "scripts/check-codebase-patterns.js") continue; // holds the pattern itself
    const lines = readLines(rel);
    for (let i = 0; i < lines.length; i++) {
      if (NUMBER_ENV.test(stripLineComment(lines[i]))) hits.push({ file: rel, line: i + 1, content: lines[i].trim() });
    }
  }
  return filterMarkers(hits, "number-env-coerce");
}

// A 'data' handler that appends each chunk to a string (`b += c`,
// `buf += chunk.toString()`) decodes every chunk on its own, so a multibyte
// character split between two chunks becomes U+FFFD replacement characters. A
// setEncoding call on the same receiver, or a StringDecoder, clears it when it
// appears within the 60 lines before the handler and after the last line above
// it that closes a block: a `}` line indented less than the handler, or a bare
// `}` at column 0. A receiver on the line above `.on(` counts as the receiver.
const DATA_HANDLER = /\.on\(\s*["']data["']\s*,\s*(?:async\s+)?(?:\(\s*([A-Za-z_$][\w$]*)\s*\)|([A-Za-z_$][\w$]*)\s*=>|function\s*\(\s*([A-Za-z_$][\w$]*)\s*\))/;
const RECEIVER_TAIL = /([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)\s*$/;
const BLOCK_CLOSE_LINE = /^\s*\}[\s)\](,;]*$/;
const indentOf = (s) => s.length - s.trimStart().length;
function appendsParamAsString(body, param) {
  const re = /\+=\s*([A-Za-z_$][\w$]*)(\s*\.\s*(?:length|byteLength)\b)?/g;
  let x;
  while ((x = re.exec(body)) !== null) if (x[1] === param && !x[2]) return true;
  return false;
}
// `recv.setEncoding(` where recv is the whole receiver, so `res.setEncoding(`
// does not clear a handler on `s` and `a.r.setEncoding(` does not clear one on `r`.
function callsSetEncoding(text, recv) {
  const needle = recv + ".setEncoding(";
  for (let at = text.indexOf(needle); at !== -1; at = text.indexOf(needle, at + 1)) {
    if (at === 0 || !/[\w$.]/.test(text[at - 1])) return true;
  }
  return false;
}
function detectStreamChunkStringDecode(files) {
  const hits = [];
  for (const rel of (files || filesUnder(["bin/exceptd.js", "lib", "orchestrator", "scripts"]))) {
    if (rel === "scripts/check-codebase-patterns.js") continue; // holds the pattern itself
    const lines = readLines(rel);
    for (let i = 0; i < lines.length; i++) {
      const code = stripLineComment(lines[i]);
      const m = code.match(DATA_HANDLER);
      if (!m) continue;
      const param = m[1] || m[2] || m[3];
      const body = [code.slice(m.index + m[0].length)].concat(lines.slice(i + 1, i + 4).map(stripLineComment)).join("\n");
      if (!appendsParamAsString(body, param)) continue;
      let head = code.slice(0, m.index);
      let recvLine = i;
      if (!head.trim() && i > 0) { recvLine = i - 1; head = stripLineComment(lines[recvLine]); }
      const recv = (head.match(RECEIVER_TAIL) || [])[1];
      const own = indentOf(lines[recvLine]);
      let from = Math.max(0, i - 60);
      for (let j = i - 1; j >= from; j--) {
        if (/^\}\s*$/.test(lines[j]) || (BLOCK_CLOSE_LINE.test(lines[j]) && indentOf(lines[j]) < own)) { from = j + 1; break; }
      }
      const before = lines.slice(from, i + 1).map(stripLineComment).join("\n");
      if (/\bStringDecoder\b/.test(before)) continue;
      if (recv && callsSetEncoding(before, recv)) continue;
      hits.push({ file: rel, line: i + 1, content: lines[i].trim() });
    }
  }
  return filterMarkers(hits, "stream-chunk-string-decode");
}

// The comment and string-literal text on a line, with code left out so an
// identifier, object key or constant keeps its spelling. `state` is a
// newBraceState() threaded line to line: block comments and template literals
// span lines, and a regex literal is code, so a quote inside one does not open
// a string. A '- or "-quoted string cannot run past its line, so a quote whose
// string reaches the end of the line unclosed is read as code and the rest of
// the line is scanned again from just after it.
function proseOf(line, state) {
  let out = "";
  let quoteAt = -1;
  let quoteOut = 0;
  let codeQuoteAt = -1;
  for (let i = 0; i <= line.length; i++) {
    if (i === line.length) {
      if (!(state.inSingle || state.inDouble)) break;
      state.inSingle = false;
      state.inDouble = false;
      out = out.slice(0, quoteOut);
      codeQuoteAt = quoteAt;
      i = quoteAt;
      continue;
    }
    const ch = line[i];
    const next = line[i + 1];
    if (state.inBlock) {
      if (ch === "*" && next === "/") { state.inBlock = false; i++; out += " "; continue; }
      out += ch;
      continue;
    }
    if (state.inSingle || state.inDouble) {
      if (ch === "\\") { i++; out += " "; continue; }
      if (ch === (state.inSingle ? "'" : '"')) { state.inSingle = false; state.inDouble = false; out += " "; continue; }
      out += ch;
      continue;
    }
    if (state.inTemplate) {
      if (ch === "\\") { i++; out += " "; continue; }
      if (ch === "`") { state.inTemplate = false; out += " "; continue; }
      if (ch === "$" && next === "{") { state.templateExpr.push(0); state.inTemplate = false; i++; out += " "; continue; }
      out += ch;
      continue;
    }
    if (ch === "/" && next === "/") { out += " " + line.slice(i + 2); break; }
    if (ch === "/" && next === "*") { state.inBlock = true; i++; continue; }
    if (ch === "/" && (REGEX_CAN_START.test(line.slice(Math.max(0, i - 40), i)) || afterControlFlowParen(line.slice(0, i)))) {
      const end = regexLiteralEnd(line, i);
      if (end !== -1) { i = end; continue; }
    }
    if ((ch === "'" || ch === '"') && i !== codeQuoteAt) {
      if (ch === "'") state.inSingle = true; else state.inDouble = true;
      quoteAt = i;
      quoteOut = out.length;
      continue;
    }
    if (ch === "`") { state.inTemplate = true; continue; }
    if (state.templateExpr.length) {
      const top = state.templateExpr.length - 1;
      if (ch === "{") state.templateExpr[top]++;
      else if (ch === "}" && state.templateExpr[top] === 0) { state.templateExpr.pop(); state.inTemplate = true; }
      else if (ch === "}") state.templateExpr[top]--;
    }
  }
  return out;
}

// British spellings in comments and user-visible strings. A word with a capital
// after its first letter (camelCase, PascalCase, ALL_CAPS) is an identifier and
// is skipped, as is text inside backticks in a comment and the repository term
// "judgement-shaped", which comes from the --include-judgement-shaped flag.
const BRITISH_TERM = new RegExp("^(?:behaviour(?:s|al|ally)?|colour(?:s|ed|ing|ful)?|licence(?:s|d)?" +
  "|cancell(?:ed|ing)|modell(?:ed|ing)|labell(?:ed|ing)|catalogue(?:s|d)?|cataloguing|defence(?:s)?" +
  "|favour(?:s|ed|ing|able|ite|ites)?|honour(?:s|ed|ing|able)?|analogue(?:s)?|programme(?:s|d)?" +
  "|centre(?:s|d)?|metre(?:s)?|litre(?:s)?|fibre(?:s)?|flavour(?:s|ed|ing)?|neighbour(?:s|ing|hood)?" +
  "|ageing|travell(?:ed|ing|er|ers)|tunnell(?:ed|ing)|offence(?:s)?|pretence(?:s)?|judgement(?:s)?" +
  "|fulfil(?:s|ment|ments)?|enrol(?:s|ment|ments)?|whilst|amongst|artefact(?:s)?|acknowledgement(?:s)?" +
  "|paediatric(?:s|ian|ians)?" +
  "|(?:ana|cata|para)lys(?:e|ed|ing))$");
// -ise words that are American spellings too, with their inflections.
const AMERICAN_ISE = new Set();
for (const w of ("advertise advise anise apprise arise appraise braise bruise cerise chastise chemise " +
  "circumcise comprise compromise concise cruise demise despise devise disenfranchise disfranchise disguise " +
  "enfranchise enterprise excise exercise expertise franchise guise improvise incise merchandise misadvise " +
  "mortise noise paradise poise porpoise praise precise premise promise raise remise reprise revise rise " +
  "seise supervise surmise surprise televise tortoise treatise turquoise valise sunrise moonrise uprise " +
  "fundraise malaise liaise").split(" ")) {
  const stem = w.replace(/e$/, "");
  for (const f of [w, w + "s", stem + "ed", stem + "es", stem + "ing", stem + "er", stem + "ers",
    stem + "ation", stem + "ations", stem + "ational", stem + "able", stem + "ability"]) AMERICAN_ISE.add(f);
}
const BRITISH_ISE = /^[a-z]{3,}is(?:e|es|ed|er|ers|ing|ation|ations|ational|ationally|able|ability)$/;
function britishWordsIn(text) {
  const words = [];
  const prose = text.replace(/`[^`]*`/g, " ").replace(/\b(?:include-)?judgement-shaped\b/gi, " ");
  for (const w of prose.match(/[A-Za-z]+/g) || []) {
    if (/^.+[A-Z]/.test(w)) continue;
    const lw = w.toLowerCase();
    if (BRITISH_TERM.test(lw) || (BRITISH_ISE.test(lw) && !AMERICAN_ISE.has(lw) && !/wise$/.test(lw))) words.push(w);
  }
  return words;
}
function detectBritishSpelling(files) {
  const hits = [];
  for (const rel of (files || filesUnder(["bin/exceptd.js", "lib", "orchestrator", "scripts"]))) {
    if (rel === "scripts/check-codebase-patterns.js") continue; // holds the word lists
    const lines = readLines(rel);
    const state = newBraceState();
    for (let i = 0; i < lines.length; i++) {
      const words = britishWordsIn(proseOf(lines[i], state));
      if (words.length) hits.push({ file: rel, line: i + 1, content: lines[i].trim(), why: words.join(", ") });
    }
  }
  return filterMarkers(hits, "british-spelling");
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
  {
    id: "number-env-coerce",
    run: detectNumberEnvCoerce,
    warnOnly: false,
    hint: "Number(process.env.X) turns a typo into NaN or 0 without an error; parse with a strict pattern and refuse anything else (see capFromEnv in scripts/refresh-upstream-catalogs.js)",
  },
  {
    id: "stream-chunk-string-decode",
    run: detectStreamChunkStringDecode,
    warnOnly: false,
    hint: "a 'data' handler that appends chunks to a string splits multibyte characters across chunk boundaries; call <stream>.setEncoding(\"utf8\") first, or collect Buffers and decode once with Buffer.concat",
  },
  {
    id: "british-spelling",
    run: detectBritishSpelling,
    warnOnly: true,
    hint: "comments and user-visible strings use American spelling (behavior, catalog, recognize, organization); an identifier, flag or quoted source text keeps its spelling, marked `// allow:british-spelling — <reason>`",
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
  detectNumberEnvCoerce,
  detectStreamChunkStringDecode,
  detectBritishSpelling,
  britishWordsIn,
  proseOf,
  NUMBER_ENV,
  DATA_HANDLER,
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
