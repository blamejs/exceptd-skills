#!/usr/bin/env node
'use strict';

/**
 * Release-notes extraction + quality gate. .github/workflows/release.yml publishes
 * the GitHub Release body by awk-extracting the `## <version> …` CHANGELOG section,
 * falling back to "Release of v<version>." when the extract is empty. This runs the
 * SAME extraction before tag-push and lints what it finds, so a malformed or
 * internal-narrative section fails here rather than shipping as the public body.
 *
 * process.exitCode 0 on pass, 1 on any failure. Takes an optional
 * MAJOR.MINOR.PATCH argument, defaulting to the package.json version.
 */

const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.resolve(__dirname, '..');
const CHANGELOG = path.join(ROOT, 'CHANGELOG.md');
const PACKAGE_JSON = path.join(ROOT, 'package.json');

// Replicates the release.yml awk: lines after the `## <version> ` heading up to
// the next `## `. The trailing space mirrors the workflow's `"^## " v " "`, so a
// shorter version heading cannot match a longer one sharing its prefix.
function extractSection(text, version) {
  const lines = text.split(/\r?\n/);
  const out = [];
  let capturing = false;
  const startRe = new RegExp('^## ' + version.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + ' ');
  for (const ln of lines) {
    if (capturing) {
      if (/^## /.test(ln)) break;
      out.push(ln);
      continue;
    }
    if (startRe.test(ln)) capturing = true;
  }
  // awk keeps the blank lines; trimming them makes the non-empty test honest.
  while (out.length && out[0].trim() === '') out.shift();
  while (out.length && out[out.length - 1].trim() === '') out.pop();
  return out;
}

// Returns the `## <version> — <date>` heading line for the version, or null.
function headingLine(text, version) {
  const re = new RegExp('^## ' + version.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + ' ');
  return text.split(/\r?\n/).find((l) => re.test(l)) || null;
}

// Operator-facing forbidden patterns: high-confidence markers only, since a false
// positive blocks a release. "multi-phase attack" is prose; "Phase 9" is the tell.
const FORBIDDEN = [
  { id: 'phase-number', re: /\bphase\s+\d/i, why: 'internal phase number (operators have no roadmap)' },
  { id: 'pass-number', re: /\b(?:audit|curation|drift|fix|bug)?[- ]?pass\s+\d/i, why: 'internal pass/batch number' },
  { id: 'slice-number', re: /\bslice\s+\d/i, why: 'internal slice number' },
  { id: 'sweep-number', re: /\bsweep\s+\d/i, why: 'internal sweep number' },
  { id: 'tier-letter', re: /\bTier-[ABC]\b/, why: 'internal tier label' },
  { id: 'agent-dispatch', re: /\b(?:sub-?agent|parallel agent|agent dispatch|fan(?:ned)?[ -]out|multi-agent)\b/i, why: 'implementation detail (agent/parallelization)' },
  { id: 'conversation-residue', re: /\b(?:as discussed|per your|operator-confirmed|as you (?:noted|requested)|per the conversation|PR feedback:)\b/i, why: 'conversation residue (invisible to the reader)' },
  { id: 'process-narrative', re: /\b(?:audit-derived|post-phase-\d|as part of the \d|the \d+-gap closure)\b/i, why: 'internal-process narrative' },
  { id: 'tautological-green', re: /\b(?:all(?:\s+\d+)?\s+(?:tests?|checks?|gates?|suites?)\s+(?:pass(?:ing)?|green)|(?:the\s+)?(?:whole|entire|full)\s+(?:test\s+)?suite\s+(?:is\s+)?(?:pass(?:ing|ed|es)?|green)|every\s+(?:test|check|gate)\s+(?:pass(?:es|ing|ed)?|is\s+green)|\d+\s*\/\s*\d+\s+(?:tests?|gates?|checks?)\s+(?:pass(?:ing|es|ed)?|green)|CI green|smoke \+ e2e (?:clean|pass)|tests? (?:are )?passing)\b/i, why: 'tautological pass/green claim (noise — the release exists). Covers the numbered ("all 288 tests green"), count ("288/288 tests pass", "21/21 gates pass"), and synonym ("full suite green", "every check passes") forms of the same banned claim.' },
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

// Every released version keeps its own `## <version> ` heading; tags are the
// authoritative record of which versions those are. An orphan is a tag whose
// release never published: the v* ruleset forbids re-pushing a tag, so the
// recovery was a version bump carrying the same notes under the NEW heading, and
// such a tag legitimately has no CHANGELOG entry of its own.
const ORPHAN_RELEASE_TAGS = new Set(['0.13.111', '0.15.25']);

function releasedVersionsFromTags() {
  try {
    const out = require('node:child_process').execFileSync('git', ['tag', '-l', 'v*'], { cwd: ROOT, encoding: 'utf8' });
    return out.split(/\r?\n/)
      .map((t) => (t.match(/^v(\d+\.\d+\.\d+)$/) || [])[1])
      .filter((v) => v && !ORPHAN_RELEASE_TAGS.has(v));
  } catch {
    // git absent or tags not fetched (shallow checkout) — nothing to check.
    return [];
  }
}

function missingReleasedHeadings(text, versions) {
  return versions.filter((v) => !headingLine(text, v));
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
  if (!new RegExp('^## ' + version.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + ' [—-] \\d{4}-\\d{2}-\\d{2}\\s*$').test(heading)) {
    console.error('[check-changelog-extract] FAIL: heading does not match `## ' + version + ' — YYYY-MM-DD`:');
    console.error('[check-changelog-extract]   got: ' + JSON.stringify(heading));
    process.exitCode = 1;
    return;
  }

  const missing = missingReleasedHeadings(text, releasedVersionsFromTags());
  if (missing.length > 0) {
    console.error('[check-changelog-extract] FAIL: released version(s) lost their CHANGELOG heading: ' + missing.map((v) => '## ' + v).join(', '));
    console.error('[check-changelog-extract] A new entry must be INSERTED ABOVE the previous release heading, never replace it — otherwise the prior release\'s notes merge into the new section and republish in the new release body.');
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

module.exports = { extractSection, headingLine, lintOperatorClean, FORBIDDEN, missingReleasedHeadings, releasedVersionsFromTags };

if (require.main === module) main();
