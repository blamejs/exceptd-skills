#!/usr/bin/env node
'use strict';

/**
 * Canonical-test-count predeploy gate: catches test-set shrinkage the lint and
 * diff-coverage gates cannot see.
 *
 * Counts DECLARATIONS statically across `tests/*.test.js` — `test(` and `it(`
 * with their `.only` variants. `describe(` is NOT counted: a container is not
 * a test. `test.skip(`, and a declaration whose options on the same line set
 * `skip` to `true` or to a string, are not counted, so a test disabled in place
 * reads as a lost test. A conditional skip such as `{ skip: !HAS_KEY }` still
 * counts, and so does a skip set on a later line of a multi-line options object.
 *
 * exit 0 at or above baseline minus tolerance, 1 when it drops further, 2 when
 * the baseline file is missing or malformed.
 */

const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const TESTS_DIR = path.join(ROOT, 'tests');
const BASELINE_PATH = path.join(TESTS_DIR, '.test-count-baseline.json');

function listTestFiles(dir) {
  const out = [];
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  for (const e of entries) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) {
      if (e.name === '_helpers' || e.name === 'fixtures' || e.name === 'e2e-scenarios') continue;
      out.push(...listTestFiles(p));
    } else if (e.isFile() && e.name.endsWith('.test.js')) {
      out.push(p);
    }
  }
  return out;
}

// A `/` starts a regex literal, not a division, when the code before it ends in
// an operator, an opening bracket, a separator or one of these keywords.
// A keyword after `.` is a property name (`obj.in / 2` divides).
const REGEX_CAN_START = /(?:^|[(,=:[!&|?{};+\-*%<>~^]|(?<![.\w$])(?:return|typeof|instanceof|in|of|new|delete|void|throw|case|do|else|yield|await))\s*$/;

// True when `code` ends in the `)` that closes an if, while, for or with head,
// after which a `/` starts a regex literal: `if (ok) /it's/.test(s)`.
function afterControlFlowParen(code) {
  const tail = code.replace(/\s+$/, '');
  if (!tail.endsWith(')')) return false;
  let depth = 0;
  for (let k = tail.length - 1; k >= 0 && k >= tail.length - 2000; k--) {
    if (tail[k] === ')') depth++;
    else if (tail[k] === '(' && --depth === 0) return /(?<![.\w$])(?:if|while|for|with)\s*$/.test(tail.slice(0, k));
  }
  return false;
}

// Index of the slash that closes the regex literal opening at `start`, or -1
// when the line holds no closing slash outside a character class. A slash that
// begins `/*` opens a comment and closes no regex, so a division that was read
// as a regex start (`obj.if(x) / 2; /* ... */`) is left a division. A closing
// slash followed by another slash is kept: `/a//* c */` is the regex /a/ and then
// a comment.
function regexLiteralEnd(text, start) {
  let inClass = false;
  for (let j = start + 1; j < text.length && text[j] !== '\n'; j++) {
    const c = text[j];
    if (c === '\\') { j++; continue; }
    if (c === '[') inClass = true;
    else if (c === ']') inClass = false;
    else if (c === '/' && !inClass) return text[j + 1] === '*' ? -1 : j;
  }
  return -1;
}

// Removes /* ... */ block comments and keeps their newlines. A `/*` inside a
// line comment, a string literal or a regex literal does not open one, and a
// quote inside a regex literal does not open a string, so `// lib/*.js`,
// `/it's/` and a later `" */"` do not drop or keep the wrong tests. A '- or
// "-quoted string cannot run past its line, so a quote whose string reaches the
// end of the line unclosed is read as code and the rest of the line is scanned
// again from just after it. The scanner does not parse JavaScript: a `/` after
// `}`, after a `)` that closes no if, while, for or with head, or at the start of
// a line is read as division.
function stripBlockComments(source) {
  const text = source + '\n';
  let out = '';
  let mode = null; // null (code), 'line', 'block', or the open quote character
  let quoteAt = -1;
  let quoteOut = 0;
  let codeQuoteAt = -1;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    const next = text[i + 1];
    if (mode === 'block') {
      if (ch === '*' && next === '/') { mode = null; i++; }
      else if (ch === '\n') out += '\n';
      continue;
    }
    if (mode === 'line') {
      if (ch === '\n') mode = null;
      out += ch;
      continue;
    }
    if (mode) {
      if (ch === '\n' && mode !== '`') {
        out = out.slice(0, quoteOut) + text[quoteAt];
        codeQuoteAt = quoteAt;
        i = quoteAt;
        mode = null;
        continue;
      }
      out += ch;
      if (ch === '\\' && next !== undefined) { out += next; i++; continue; }
      if (ch === mode) mode = null;
      continue;
    }
    if (ch === '/' && next === '*') { mode = 'block'; i++; continue; }
    if (ch === '/' && next === '/') mode = 'line';
    else if (ch === '/' && (REGEX_CAN_START.test(out.slice(-40)) || afterControlFlowParen(out.slice(-2000)))) {
      const end = regexLiteralEnd(text, i);
      if (end !== -1) { out += text.slice(i, end + 1); i = end; continue; }
    } else if ((ch === "'" || ch === '"') && i !== codeQuoteAt) { mode = ch; quoteAt = i; quoteOut = out.length; }
    else if (ch === '`') mode = ch;
    out += ch;
  }
  return out.slice(0, -1);
}

function countTests(filePath) {
  // Strip block comments first: commenting a test out is the usual way to
  // disable one, and counting it anyway defeats the gate.
  const text = stripBlockComments(fs.readFileSync(filePath, 'utf8'));
  let count = 0;
  for (const rawLine of text.split('\n')) {
    // Blank string and template bodies first, so a `test(` inside a string
    // literal is not read as a declaration — a phantom inflates the baseline.
    const noStrings = rawLine.replace(/'(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*"|`(?:[^`\\]|\\.)*`/g, "''");
    // Drop a trailing line comment too (`test('x'); // disabled`).
    const stripped = noStrings.replace(/\/\/.*$/, '').trim();
    if (!stripped) continue;
    if (!/(?<![A-Za-z0-9_$.])(?:test|it)(?:\.only)?\s*\(/.test(stripped)) continue;
    // String literals are blanked to '' above, so `skip: 'reason'` reads as `skip: ''`.
    if (/\bskip\s*:\s*(?:true\b|''\s*[,}])/.test(stripped)) continue;
    count++;
  }
  return count;
}

function main() {
  const wantJson = process.argv.includes('--json');
  const wantUpdate = process.argv.includes('--update-baseline');

  // Branch on the read RESULT, never on a prior existsSync probe: ENOENT from
  // this single read IS the "missing" signal.
  let baselineRaw = null;
  try {
    baselineRaw = fs.readFileSync(BASELINE_PATH, 'utf8');
  } catch (e) {
    if (e.code !== 'ENOENT') {
      console.error(`[check-test-count] cannot read baseline: ${e.message}`);
      process.exit(2);
    }
    if (wantUpdate) {
      const files = listTestFiles(TESTS_DIR);
      const observed = files.reduce((n, f) => n + countTests(f), 0);
      // Exclusive create: EEXIST rather than clobbering a concurrent run's baseline.
      fs.writeFileSync(BASELINE_PATH, JSON.stringify({
        baseline: observed,
        tolerance: 1,
        update_baseline_when_growth_exceeds: 20,
        notes: 'Operator-pinned canonical test count. Bump when new test files land in a release. See scripts/check-test-count.js for the contract.',
        recorded_at: new Date().toISOString().slice(0, 10),
      }, null, 2) + '\n', { encoding: 'utf8', flag: 'wx' });
      console.error(`[check-test-count] wrote initial baseline: ${observed}`);
      process.exit(0);
    }
    console.error(`[check-test-count] baseline missing at ${path.relative(ROOT, BASELINE_PATH)}. Run with --update-baseline to create it.`);
    process.exit(2);
  }

  let baselineFile;
  try { baselineFile = JSON.parse(baselineRaw); }
  catch (e) {
    console.error(`[check-test-count] cannot parse baseline: ${e.message}`);
    process.exit(2);
  }
  const baseline = baselineFile.baseline;
  const tolerance = baselineFile.tolerance || 1;
  const updateThreshold = baselineFile.update_baseline_when_growth_exceeds || 20;
  if (typeof baseline !== 'number' || baseline <= 0) {
    console.error(`[check-test-count] baseline value invalid: ${baseline}`);
    process.exit(2);
  }

  const files = listTestFiles(TESTS_DIR);
  const observed = files.reduce((n, f) => n + countTests(f), 0);

  if (wantUpdate) {
    fs.writeFileSync(BASELINE_PATH, JSON.stringify({
      ...baselineFile,
      baseline: observed,
      recorded_at: new Date().toISOString().slice(0, 10),
    }, null, 2) + '\n', 'utf8');
    console.error(`[check-test-count] baseline updated: ${baseline} -> ${observed}`);
    process.exit(0);
  }

  const delta = observed - baseline;
  const status = delta < -tolerance
    ? 'shrunk_beyond_tolerance'
    : delta > updateThreshold
      ? 'grew_beyond_threshold_consider_bump'
      : 'ok';

  if (wantJson) {
    process.stdout.write(JSON.stringify({
      ok: status === 'ok' || status === 'grew_beyond_threshold_consider_bump',
      verb: 'check-test-count',
      observed,
      baseline,
      tolerance,
      delta,
      status,
      files_scanned: files.length,
    }) + '\n');
  } else {
    console.log(`[check-test-count] observed=${observed} baseline=${baseline} delta=${delta >= 0 ? '+' : ''}${delta} tolerance=${tolerance} files=${files.length} status=${status}`);
  }

  if (status === 'shrunk_beyond_tolerance') {
    console.error(`[check-test-count] FAIL - test count dropped from ${baseline} to ${observed} (delta ${delta}, tolerance -${tolerance}).`);
    console.error('[check-test-count] Either a test file was accidentally removed, a test()/it() invocation was deleted, OR the baseline is stale.');
    console.error('[check-test-count] If the drop is intentional, run: node scripts/check-test-count.js --update-baseline');
    // `process.exitCode`, not `process.exit()`: the buffered stdout write must drain.
    process.exitCode = 1;
    return;
  }
  if (status === 'grew_beyond_threshold_consider_bump') {
    console.error(`[check-test-count] NOTICE - test count grew by ${delta} (above the ${updateThreshold} notice threshold). Consider refreshing the baseline: node scripts/check-test-count.js --update-baseline`);
  }
  process.exitCode = 0;
}

module.exports = { countTests, listTestFiles, stripBlockComments, regexLiteralEnd, afterControlFlowParen, REGEX_CAN_START };

if (require.main === module) main();
