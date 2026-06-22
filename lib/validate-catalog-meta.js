#!/usr/bin/env node
/*
 * lib/validate-catalog-meta.js — assert every data/*.json carries the
 * source-trust + freshness fields required by the audit follow-up:
 *
 *   _meta.tlp                 — Traffic Light Protocol marking
 *   _meta.source_confidence   — Admiralty scheme (A-F + 1-6), with
 *                                default rating and per-entry override note
 *   _meta.freshness_policy    — review cadence + decay thresholds
 *
 * Per AGENTS.md rule #10 (no placeholder language), this validator
 * rejects empty strings and the usual placeholder tokens. Rule #12
 * (external data version pinning) is enforced informally — every catalog
 * still needs its existing schema_version / last_updated fields, but
 * those are validated by the existing per-catalog validators.
 *
 * Usage:
 *   node lib/validate-catalog-meta.js
 *   node lib/validate-catalog-meta.js --quiet
 *
 * Exit code:
 *   0  all catalogs have the required _meta fields
 *   1  one or more catalogs missing a required field
 *   2  argv error
 *
 * No external dependencies. Node 24 stdlib only.
 */

'use strict';

const fs = require('node:fs');
const path = require('node:path');
const process = require('node:process');
const { safeExit } = require('./exit-codes');

const REPO_ROOT = path.resolve(__dirname, '..');
const DATA_DIR = path.join(REPO_ROOT, 'data');

const REQUIRED_TLP_VALUES = new Set([
  'CLEAR',
  'GREEN',
  'AMBER',
  'AMBER+STRICT',
  'RED',
]);

const PLACEHOLDER_TOKENS = [
  /\btodo\b/i,
  /\btbd\b/i,
  /\bcoming soon\b/i,
  /\bplaceholder\b/i,
  /\bto be determined\b/i,
];

function parseArgs(argv) {
  const opts = { quiet: false, strict: false };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--quiet' || a === '-q') opts.quiet = true;
    else if (a === '--strict') opts.strict = true;
    else if (a === '--help' || a === '-h') {
      console.log(
        'Usage: node lib/validate-catalog-meta.js [--quiet] [--strict]\n' +
          '\n' +
          '  --quiet   Suppress per-catalog PASS output; show failures only.\n' +
          '  --strict  Promote freshness warnings to errors (used by the predeploy gate).\n',
      );
      safeExit(0);
      return null;
    } else {
      console.error(`Unknown argument: ${a}`);
      safeExit(2);
      return null;
    }
  }
  return opts;
}

function readJson(p) {
  return JSON.parse(fs.readFileSync(p, 'utf8'));
}

function containsPlaceholder(s) {
  if (typeof s !== 'string') return false;
  return PLACEHOLDER_TOKENS.some((re) => re.test(s));
}

// Round-trip ISO calendar-date check. Returns a Date for a real YYYY-MM-DD
// calendar date, or null for anything malformed. Unlike a shape-only regex,
// this rejects impossible dates (2026-13-99, 2026-04-31, 2026-02-29 in a
// non-leap year): `new Date('2026-02-30T00:00:00Z')` does NOT throw — it rolls
// over to March 2 with a valid getTime() — so the parsed Y-M-D must round-trip
// back to the input components. Deliberately carries NO year-floor business
// rule (a valid-but-old 1900-01-01 stays a valid date so the staleness branch,
// not the validity branch, reports it).
function parseIsoDateStrict(v) {
  if (typeof v !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(v)) return null;
  const d = new Date(v + 'T00:00:00Z');
  if (Number.isNaN(d.getTime())) return null;
  const [y, m, day] = v.split('-').map(Number);
  if (
    d.getUTCFullYear() !== y ||
    d.getUTCMonth() + 1 !== m ||
    d.getUTCDate() !== day
  ) {
    return null;
  }
  return d;
}

function validateMeta(catalogPath, opts) {
  const errors = [];
  const warnings = [];
  const data = readJson(catalogPath);
  const meta = data._meta;

  if (!meta || typeof meta !== 'object') {
    // Honor both return contracts. The rest of the body dereferences
    // `meta.tlp` / `meta.source_confidence` / `meta.freshness_policy`, so it
    // must NOT run when `meta` is absent or non-object. Return early in the
    // SAME shape the caller asked for: includeWarnings callers (main()) get
    // `{errors, warnings}` so `result.errors` is a real array and the loop
    // reports a clean FAIL + continues; no-opts callers still get a non-empty
    // `string[]`. This still FAILS — it only removes the uncaught TypeError.
    errors.push('missing _meta block');
    if (opts && opts.includeWarnings) return { errors, warnings };
    return errors;
  }

  /* tlp */
  if (typeof meta.tlp !== 'string') {
    errors.push('_meta.tlp is missing or not a string');
  } else if (!REQUIRED_TLP_VALUES.has(meta.tlp)) {
    errors.push(
      `_meta.tlp "${meta.tlp}" not one of CLEAR/GREEN/AMBER/AMBER+STRICT/RED`,
    );
  }

  /* source_confidence */
  const sc = meta.source_confidence;
  if (!sc || typeof sc !== 'object') {
    errors.push('_meta.source_confidence is missing or not an object');
  } else {
    for (const field of ['scheme', 'default', 'note']) {
      if (typeof sc[field] !== 'string' || sc[field].length === 0) {
        errors.push(`_meta.source_confidence.${field} missing or empty`);
      } else if (containsPlaceholder(sc[field])) {
        errors.push(
          `_meta.source_confidence.${field} contains placeholder language`,
        );
      }
    }
    if (typeof sc.default === 'string' && !/^[A-F][1-6]$/.test(sc.default)) {
      errors.push(
        `_meta.source_confidence.default "${sc.default}" is not Admiralty form ([A-F][1-6])`,
      );
    }
  }

  /* freshness_policy */
  const fp = meta.freshness_policy;
  if (!fp || typeof fp !== 'object') {
    errors.push('_meta.freshness_policy is missing or not an object');
  } else {
    for (const field of [
      'default_review_cadence_days',
      'stale_after_days',
      'rebuild_after_days',
    ]) {
      const v = fp[field];
      if (typeof v !== 'number' || !Number.isInteger(v) || v <= 0) {
        errors.push(
          `_meta.freshness_policy.${field} must be a positive integer`,
        );
      }
    }
    if (typeof fp.note !== 'string' || fp.note.length === 0) {
      errors.push('_meta.freshness_policy.note missing or empty');
    } else if (containsPlaceholder(fp.note)) {
      errors.push('_meta.freshness_policy.note contains placeholder language');
    }
    /* Soft check: cadence < stale < rebuild. Catches an obvious copy-paste
     * mistake without being a hard schema constraint. */
    if (
      typeof fp.default_review_cadence_days === 'number' &&
      typeof fp.stale_after_days === 'number' &&
      typeof fp.rebuild_after_days === 'number'
    ) {
      if (
        !(
          fp.default_review_cadence_days <= fp.stale_after_days &&
          fp.stale_after_days <= fp.rebuild_after_days
        )
      ) {
        errors.push(
          '_meta.freshness_policy: expected default_review_cadence_days <= stale_after_days <= rebuild_after_days',
        );
      }
    }

    /* freshness enforcement. When both meta.last_updated and
     * freshness_policy.stale_after_days are present, surface a warning if
     * (now - last_updated) > stale_after_days. Emitted at WARN level by
     * default (does not fail validation).
     *
     * Optional `opts.strict` (or `opts.errorOnStale`) promotes the warning
     * to an error; the predeploy gate runs --strict, plain validation keeps
     * the warning posture.
     */
    if (
      meta.last_updated !== undefined &&
      typeof fp.stale_after_days === 'number' &&
      fp.stale_after_days > 0
    ) {
      const lu = parseIsoDateStrict(meta.last_updated);
      if (lu === null) {
        // Fail-closed on a malformed date instead of silently skipping the
        // freshness gate. A NaN/impossible/wrong-shape last_updated is
        // "invalid input" (error under --strict, warning by default), NOT
        // "no opinion" — otherwise the staleness check fails open.
        const msg =
          `_meta.last_updated ${JSON.stringify(meta.last_updated)} is not a valid ISO date ` +
          `(YYYY-MM-DD calendar date) — cannot evaluate freshness. ` +
          `Promoted to an error under --strict.`;
        if (opts && (opts.strict || opts.errorOnStale)) {
          errors.push(msg);
        } else {
          warnings.push(msg);
        }
      } else {
        const ageDays = Math.floor((Date.now() - lu.getTime()) / 86400000);
        if (ageDays > fp.stale_after_days) {
          const msg =
            `_meta freshness: last_updated ${meta.last_updated} is ${ageDays} days old ` +
            `(stale_after_days = ${fp.stale_after_days}); refresh the catalog or bump _meta.last_updated. ` +
            `Promoted to an error under --strict.`;
          if (opts && (opts.strict || opts.errorOnStale)) {
            errors.push(msg);
          } else {
            warnings.push(msg);
          }
        }
      }
    }
  }

  // Warnings are appended after errors when callers ask for the combined
  // shape via opts.includeWarnings. Default return is errors only so the
  // public function signature is unchanged for existing callers.
  if (opts && opts.includeWarnings) {
    return { errors, warnings };
  }
  return errors;
}

function main() {
  const opts = parseArgs(process.argv);
  if (opts === null) return; // parseArgs handled --help / bad-arg and set the exit code
  const files = fs
    .readdirSync(DATA_DIR)
    .filter((f) => f.endsWith('.json'))
    .sort();

  let failed = 0;
  let warned = 0;
  for (const f of files) {
    const result = validateMeta(path.join(DATA_DIR, f), {
      includeWarnings: true,
      strict: opts.strict,
    });
    const errors = result.errors;
    const warnings = result.warnings || [];
    if (errors.length === 0 && warnings.length === 0) {
      if (!opts.quiet) console.log(`PASS  ${f}`);
    } else if (errors.length === 0) {
      warned++;
      if (!opts.quiet) console.log(`WARN  ${f}`);
      for (const w of warnings) console.log(`        - [warn] ${w}`);
    } else {
      failed++;
      console.log(`FAIL  ${f}`);
      for (const e of errors) console.log(`        - ${e}`);
      for (const w of warnings) console.log(`        - [warn] ${w}`);
    }
  }

  const total = files.length;
  const passed = total - failed - warned;
  const warnSuffix = warned ? `, ${warned} with warnings` : '';
  const failSuffix = failed ? `, ${failed} failed` : '';
  console.log(
    `\n${passed}/${total} catalogs validated${warnSuffix}${failSuffix}.`,
  );
  // process.exitCode + return so buffered writes drain.
  process.exitCode = failed === 0 ? 0 : 1;
}

if (require.main === module) {
  main();
}

module.exports = { validateMeta, parseIsoDateStrict };
