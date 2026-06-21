#!/usr/bin/env node
"use strict";
/**
 * check-codebase-patterns.js — grep-gate enforcement for code-shape bug
 * classes that have recurred across exceptd releases. One run surfaces every
 * class as a single numbered report instead of dying on the first hit.
 *
 * Shipped v1 classes:
 *   - process-exit-after-stdout-write : a library-callable function writes to
 *       the result channel (process.stdout.write / console.log) and then calls
 *       process.exit(), which truncates the buffered write when stdout is
 *       piped. Route through `safeExit(EXIT_CODES.X); return;` (lib/exit-codes).
 *       This is the stdout-flush-truncation class the validate-cves fix closed by hand.
 *   - dynamic-regex : `new RegExp(<non-literal>)` — a ReDoS sink when the
 *       pattern derives from operator input. Use a static literal, or anchor +
 *       length-cap the input, or mark the site `// allow:dynamic-regex —
 *       <reason>` when the source is a trusted bundled schema.
 *   - orphan-allow-class : an `// allow:<class>` marker whose class is not in
 *       VALID_ALLOW_CLASSES, or is missing the `— <reason>` tail. A typo'd
 *       marker suppresses nothing, so the underlying violation would ship
 *       unflagged — this meta-guard keeps the marker mechanism trustworthy.
 *   - unsorted-marked-array : a flat string array tagged `// keep-sorted` that
 *       drifted out of alphabetical order. Opt-in — only marked arrays are
 *       checked, so a one-time allowlist sort becomes a standing guarantee.
 *   - misaligned-marked-run : a `// keep-aligned` const/weight table whose
 *       `=`/`:` assignment columns are not all equal. Opt-in, same shape.
 *
 * Exceptions live at the violation site, not in this file:
 *   - file-level, in the first 50 lines:  // codebase-patterns:allow-file <class> — <reason>
 *   - per-line, on the same line or up to 2 lines above:  // allow:<class> — <reason>
 *
 * NOT covered here (owned elsewhere — do not duplicate):
 *   - internal phase/version vocabulary in comments  -> scripts/check-version-tags.js
 *   - process.exit on the top-level CLI dispatch      -> tests/safe-exit-grep.test.js
 *   - anti-coincidence test assertions                -> scripts/check-test-coverage.js
 *   - internal-path leaks in operator output          -> tests/operator-leak-grep.test.js
 */

const fs = require("node:fs");
const path = require("node:path");

const ROOT = path.resolve(__dirname, "..");

// The classes that accept an `// allow:<class>` marker. orphan-allow-class is
// the meta-guard itself and is intentionally NOT a markable class.
const VALID_ALLOW_CLASSES = Object.freeze({
  "process-exit-after-stdout-write": true,
  "dynamic-regex": true,
  "bidi-codepoint-literal": true,
  "unsorted-marked-array": true,
  "misaligned-marked-run": true,
});

const EXCLUDE_DIRS = new Set([
  "node_modules", "vendor", ".git", ".cache", ".scratch",
  "data", ".test-output", ".keys", "keys", "coverage",
]);

// ---- file walk -----------------------------------------------------------

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

// Strip a trailing `//` line comment for code-shape detection (so a class
// name mentioned in a comment doesn't arm a detector). String-aware: a `//`
// inside a quoted string (e.g. a `http://` URL) is NOT a comment, so the
// scanner skips string contents — otherwise the rest of the line, including a
// real `process.exit(...)` / `new RegExp(...)`, was silently truncated away and
// the detector never fired.
function stripLineComment(line) {
  let inStr = null; // active quote char, or null
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (inStr) {
      if (ch === "\\") { i++; continue; } // skip the escaped char
      if (ch === inStr) inStr = null;
    } else if (ch === "'" || ch === '"' || ch === "`") {
      inStr = ch;
    } else if (ch === "/" && line[i + 1] === "/") {
      return line.slice(0, i);
    }
  }
  return line;
}

// ---- allow-marker engine -------------------------------------------------

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

// ---- require.main block ranges -------------------------------------------

// Count `{` / `}` in `line` that are in REAL CODE context, advancing a
// stateful tokenizer that tracks string / template / comment regions across
// lines. Braces inside a single/double/template string, a `//` line comment,
// or a `/* */` block comment do NOT affect depth — otherwise a `{` or `}`
// typed inside a string literal in the require.main block miscounts the brace
// balance and the computed block range slides onto an unrelated later function
// (whose process.exit() is then wrongly treated as a CLI-entry exit and not
// flagged). `inTemplate` and `inBlockComment` are the cross-line states a
// per-line stripper cannot model, so the tokenizer state object is threaded
// line-to-line by the caller.
//
// `state` is mutated in place: { inSingle, inDouble, inTemplate, inBlock,
// templateDepth } — `templateDepth` tracks `${ … }` interpolation nesting so
// the closing `}` of an interpolation is treated as template punctuation, not
// a code brace, while braces INSIDE the interpolation expression still count.
function countCodeBraces(line, state) {
  let delta = 0;
  let inLine = false; // `//` line comment — resets each line, never persisted
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    const next = line[i + 1];
    if (inLine) break; // rest of the line is a comment
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
        i++; // skip the `{`; the `${` opener is template punctuation
        continue;
      }
      continue;
    }
    // Code context (possibly inside a template interpolation expression).
    if (ch === "/" && next === "/") { inLine = true; break; }
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

// Line ranges (1-based, inclusive) of `if (require.main === module) { ... }`
// blocks — the dual-mode CLI-entry section where synchronous-print-then-exit
// is correct. process.exit there is owned by tests/safe-exit-grep.test.js and
// is not a library-surface concern.
function requireMainRanges(lines) {
  const ranges = [];
  for (let i = 0; i < lines.length; i++) {
    if (/\brequire\.main\s*===\s*module\b/.test(lines[i])) {
      // Find the opening brace (same line or next few), then balance —
      // string/comment/template-aware so braces inside literals don't skew the
      // depth (see countCodeBraces).
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

// ---- detectors -----------------------------------------------------------

// A line that opens a new function body (so a backward stdout-write scan stops
// at the enclosing function and doesn't arm an exit from an unrelated earlier
// function). The bare-identifier (third) alternative matches a declaration /
// method-shorthand opener (`foo() {`, `async bar() {`), but it must REFUSE
// control-flow openers (`for (…) {`, `if (…) {`, `while/switch/catch (…) {`):
// a control-flow block sitting between a stdout write and a process.exit() is
// inside the SAME function, so stopping the backward scan there would wrongly
// leave the exit unflagged. The negative lookahead excludes the control-flow
// keywords; `function` and arrow alternatives are unchanged.
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
      // Scan backward within the enclosing function for a result-channel
      // write (console.log / process.stdout.write). Stop at a function start.
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

// The first non-whitespace char of the first arg is `"`, `'`, or `/` => a
// string/regex literal => static, safe. Anything else (an identifier, a `(`,
// a backtick template) is operator-derivable and flagged. Backtick is NOT
// exempt — a template literal can interpolate operator input, so it must be
// flagged the same as a bare identifier.
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
      // Multi-line form: `new RegExp(` ends the (comment-stripped) line with the
      // open paren as the last token, and the pattern arg is on a following
      // line. The single-line match above can't see the first-arg char, so it
      // would silently pass a dynamic RegExp whose argument starts next line.
      // Look ahead, skipping blank and comment-only lines (capped at 5), and
      // inspect the first code line's first non-whitespace char.
      if (!/\bnew RegExp\s*\(\s*$/.test(code)) continue;
      let firstChar = null;
      for (let k = i + 1; k <= i + 5 && k < lines.length; k++) {
        const ahead = stripLineComment(lines[k]).replace(/^\s+/, "");
        if (ahead === "") continue; // blank or comment-only — skip
        firstChar = ahead[0];
        break;
      }
      // A `new RegExp(` with nothing parseable after it within the cap is
      // suspicious — flag conservatively. Otherwise apply the SAME literal
      // exemption as the single-line path.
      if (firstChar !== null && isStaticRegexFirstChar(firstChar)) continue;
      hits.push({ file: rel, line: i + 1, content: lines[i].trim() });
    }
  }
  return filterMarkers(hits, "dynamic-regex");
}

// Raw bidi-override / zero-width / invisible / null codepoints embedded as
// literals in source — the Trojan-Source class (CVE-2021-42574). A literal
// such codepoint is invisible in review and can reorder or hide code. Source
// should emit them programmatically (via vendor/blamejs/codepoint-class) or
// escape them (\uXXXX), never type them literally. The range table holds only
// numeric codepoints + the regex is built from escapes, so this detector's own
// source is clean (and the file self-skips below regardless).
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
      // Validate BOTH marker forms with the same class + reason rules:
      //   per-line:    allow:<class> — <reason>
      //   file-level:  codebase-patterns:allow-file <class> — <reason>
      // The file-level form is the broadest exemption (it suppresses every hit
      // of its class in the file), so a reason-less or unknown-class file-level
      // marker must be caught here too — otherwise it would suppress silently
      // and never reach the per-line orphan check.
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

// ---- opt-in readability detectors (preventative) -------------------------
// These fire ONLY on sites that explicitly opt in via a marker, so unmarked
// code is never flagged. They turn a one-time cleanup (sorting an allowlist,
// aligning a const table) into a standing guarantee: mark the cleaned site and
// the gate keeps it clean.

// `// keep-sorted` marks a flat string-literal array that must stay
// alphabetically sorted (e.g. an allowlist). Only arrays whose opening line
// carries the marker are checked; arrays containing object/nested elements are
// skipped (not a flat string list).
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
    if (/[{]/.test(body)) continue; // object/nested elements — not a flat string array
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
// lines (a const/weight table) whose assignment columns must all line up. The
// run is the lines immediately after the marker, until a blank or non-assignment
// line. Opt-in, so only deliberately-aligned tables are enforced.
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
];

function main() {
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
