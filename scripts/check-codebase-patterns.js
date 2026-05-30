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
// name mentioned in a comment doesn't arm a detector). Leaves string contents
// alone enough for the coarse line-level checks here.
function stripLineComment(line) {
  const idx = line.indexOf("//");
  return idx === -1 ? line : line.slice(0, idx);
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

// Line ranges (1-based, inclusive) of `if (require.main === module) { ... }`
// blocks — the dual-mode CLI-entry section where synchronous-print-then-exit
// is correct. process.exit there is owned by tests/safe-exit-grep.test.js and
// is not a library-surface concern.
function requireMainRanges(lines) {
  const ranges = [];
  for (let i = 0; i < lines.length; i++) {
    if (/\brequire\.main\s*===\s*module\b/.test(lines[i])) {
      // Find the opening brace (same line or next few), then balance.
      let depth = 0;
      let started = false;
      let j = i;
      for (; j < lines.length; j++) {
        for (const ch of lines[j]) {
          if (ch === "{") { depth++; started = true; }
          else if (ch === "}") { depth--; }
        }
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
// function).
const FUNCTION_START = /(^|[^.\w])function\b|=>\s*\{?\s*$|^\s*(async\s+)?[A-Za-z_$][\w$]*\s*\([^)]*\)\s*\{/;

function detectProcessExitAfterStdout(files) {
  const hits = [];
  for (const rel of (files || filesUnder(["lib", "orchestrator"]))) {
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

function detectDynamicRegex(files) {
  const hits = [];
  for (const rel of (files || filesUnder(["lib", "orchestrator", "bin/exceptd.js"]))) {
    const lines = readLines(rel);
    for (let i = 0; i < lines.length; i++) {
      const code = stripLineComment(lines[i]);
      const m = code.match(/\bnew RegExp\s*\(\s*(.)/);
      if (!m) continue;
      // Literal first arg => a quote or a `/` regex literal => static, safe.
      const firstChar = m[1];
      if (firstChar === '"' || firstChar === "'" || firstChar === "/") continue;
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
    warnOnly: true, // flip to false next release once the known sites carry markers
    hint: "RegExp from operator input is a ReDoS sink — anchor + length-cap, or `// allow:dynamic-regex — <reason>` when the pattern is a trusted bundled schema",
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
  filesUnder,
};

if (require.main === module) main();
