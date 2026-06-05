#!/usr/bin/env node
'use strict';

/**
 * Release-notes extraction + quality gate.
 *
 * The release workflow (.github/workflows/release.yml) publishes the GitHub
 * Release body by awk-extracting the `## <version> ...` CHANGELOG section
 * between the version heading and the next `## ` heading, falling back to a
 * generic "Release of v<version>." line if the extract is empty. This gate
 * runs that SAME extraction locally before tag-push, and additionally lints
 * the extracted notes for operator-facing quality, so a malformed or
 * internal-narrative-laced section fails here rather than shipping as the
 * public release body.
 *
 * Two layers:
 *   1. EXTRACT  — the `## <version> — <date>` section exists, is non-empty
 *                 (won't trigger the workflow's "Release of v…" fallback),
 *                 the heading version matches package.json, and the heading
 *                 carries an ISO date.
 *   2. LINT     — the extracted body is operator-facing-clean: no internal
 *                 phase/pass/slice/sweep narrative, no agent-dispatch /
 *                 conversation residue, no tautological "all tests pass"
 *                 noise. (Mirrors the operator-facing discipline; the release
 *                 body is the most public surface there is.)
 *
 * Exit: process.exitCode 0 on pass, 1 on any failure. Functions are exported
 * for fixture-based testing (no subprocess needed).
 *
 * Usage:
 *   node scripts/check-changelog-extract.js             # uses package.json version
 *   node scripts/check-changelog-extract.js <version>   # explicit MAJOR.MINOR.PATCH
 */

const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.resolve(__dirname, '..');
const CHANGELOG = path.join(ROOT, 'CHANGELOG.md');
const PACKAGE_JSON = path.join(ROOT, 'package.json');

// Replicates the release.yml awk: capture lines AFTER the `## <version> `
// heading up to (not including) the next `## ` heading. The trailing space in
// the heading match mirrors the workflow's `"^## " v " "` so a shorter version
// heading can't accidentally match a longer one that shares its prefix.
function extractSection(text, version) {
  const lines = text.split(/\r?\n/);
  const out = [];
  let capturing = false;
  const startRe = new RegExp('^## ' + version.replace(/\./g, '\\.') + ' ');
  for (const ln of lines) {
    if (capturing) {
      if (/^## /.test(ln)) break;
      out.push(ln);
      continue;
    }
    if (startRe.test(ln)) capturing = true;
  }
  // Trim leading/trailing blank lines (awk keeps them; the body is the same
  // either way, but trimming makes the non-empty test honest).
  while (out.length && out[0].trim() === '') out.shift();
  while (out.length && out[out.length - 1].trim() === '') out.pop();
  return out;
}

// Returns the `## <version> — <date>` heading line for the version, or null.
function headingLine(text, version) {
  const re = new RegExp('^## ' + version.replace(/\./g, '\\.') + ' ');
  return text.split(/\r?\n/).find((l) => re.test(l)) || null;
}

// Operator-facing forbidden patterns. Tight, high-confidence internal-narrative
// markers only — must not false-positive on legitimate operator prose (e.g. a
// bare "phase" in "multi-phase attack" is fine; "Phase 9" is the tell). Each
// entry: { id, re, why }.
const FORBIDDEN = [
  { id: 'phase-number', re: /\bphase\s+\d/i, why: 'internal phase number (operators have no roadmap)' },
  { id: 'pass-number', re: /\b(?:audit|curation|drift|fix|bug)?[- ]?pass\s+\d/i, why: 'internal pass/batch number' },
  { id: 'slice-number', re: /\bslice\s+\d/i, why: 'internal slice number' },
  { id: 'sweep-number', re: /\bsweep\s+\d/i, why: 'internal sweep number' },
  { id: 'tier-letter', re: /\bTier-[ABC]\b/, why: 'internal tier label' },
  { id: 'agent-dispatch', re: /\b(?:sub-?agent|parallel agent|agent dispatch|fan(?:ned)?[ -]out|multi-agent)\b/i, why: 'implementation detail (agent/parallelization)' },
  { id: 'conversation-residue', re: /\b(?:as discussed|per your|operator-confirmed|as you (?:noted|requested)|per the conversation|PR feedback:)\b/i, why: 'conversation residue (invisible to the reader)' },
  { id: 'process-narrative', re: /\b(?:audit-derived|post-phase-\d|as part of the \d|the \d+-gap closure)\b/i, why: 'internal-process narrative' },
  { id: 'tautological-green', re: /\b(?:all tests (?:pass|passing|green)|CI green|smoke \+ e2e (?:clean|pass)|tests? (?:are )?passing)\b/i, why: 'tautological pass/green claim (noise — the release exists)' },
];

function lintOperatorClean(sectionLines) {
  const findings = [];
  sectionLines.forEach((ln, i) => {
    for (const rule of FORBIDDEN) {
      const m = ln.match(rule.re);
      if (m) findings.push({ rule: rule.id, why: rule.why, line: i + 1, match: m[0], text: ln.trim().slice(0, 100) });
    }
  });
  return findings;
}

function readPackageVersion() {
  return JSON.parse(fs.readFileSync(PACKAGE_JSON, 'utf8')).version;
}

function main() {
  const version = process.argv[2] || readPackageVersion();
  if (!/^\d+\.\d+\.\d+$/.test(version)) {
    console.error('[check-changelog-extract] FAIL: bad version ' + JSON.stringify(version) + ' (expected MAJOR.MINOR.PATCH)');
    process.exitCode = 1;
    return;
  }

  let text;
  try { text = fs.readFileSync(CHANGELOG, 'utf8'); }
  catch (e) {
    console.error('[check-changelog-extract] FAIL: cannot read CHANGELOG.md: ' + (e && e.message || e));
    process.exitCode = 1;
    return;
  }

  const heading = headingLine(text, version);
  if (!heading) {
    console.error('[check-changelog-extract] FAIL: no `## ' + version + ' …` heading in CHANGELOG.md — the release workflow extract would be empty and fall back to "Release of v' + version + '."');
    process.exitCode = 1;
    return;
  }
  // Heading must carry an ISO date: `## <version> — YYYY-MM-DD`.
  if (!new RegExp('^## ' + version.replace(/\./g, '\\.') + ' [—-] \\d{4}-\\d{2}-\\d{2}\\s*$').test(heading)) {
    console.error('[check-changelog-extract] FAIL: heading does not match `## ' + version + ' — YYYY-MM-DD`:');
    console.error('[check-changelog-extract]   got: ' + JSON.stringify(heading));
    process.exitCode = 1;
    return;
  }

  const section = extractSection(text, version);
  if (section.length === 0) {
    console.error('[check-changelog-extract] FAIL: v' + version + ' section is empty — the release body would fall back to the generic "Release of v' + version + '." line.');
    process.exitCode = 1;
    return;
  }

  const findings = lintOperatorClean(section);
  if (findings.length > 0) {
    console.error('[check-changelog-extract] FAIL: v' + version + ' release notes carry ' + findings.length + ' operator-facing violation(s):');
    for (const f of findings) {
      console.error('  • [' + f.rule + '] "' + f.match + '" — ' + f.why);
      console.error('      ' + f.text);
    }
    console.error('[check-changelog-extract] The CHANGELOG section IS the public GitHub Release body. Describe the change, not how you arrived at it.');
    process.exitCode = 1;
    return;
  }

  console.log('[check-changelog-extract] OK — v' + version + ' release notes extract cleanly (' + section.length + ' line(s)) and pass the operator-facing lint.');
  process.exitCode = 0;
}

module.exports = { extractSection, headingLine, lintOperatorClean, FORBIDDEN };

if (require.main === module) main();
