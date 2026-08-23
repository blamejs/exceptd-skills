#!/usr/bin/env node
/*
 * Asserts every data/*.json carries its source-trust and freshness fields:
 * _meta.tlp (TLP marking), _meta.source_confidence (Admiralty scheme) and
 * _meta.freshness_policy. Empty strings and placeholder tokens are rejected.
 * Exits 0 when every catalog passes, 1 on a missing or malformed field, 2 on an
 * argv error. --strict promotes freshness warnings to errors.
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

// A Date for a real YYYY-MM-DD calendar date, null for anything else. The
// round-trip is what rejects an impossible date: `new Date('2026-02-30')` does
// not throw, it rolls over to March 2. No year-floor rule here — a
// valid-but-ancient date stays valid so the staleness branch reports it.
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
    // Must return here — everything below dereferences `meta.*`.
    errors.push('missing _meta block');
    if (opts && opts.includeWarnings) return { errors, warnings };
    return errors;
  }

  if (typeof meta.tlp !== 'string') {
    errors.push('_meta.tlp is missing or not a string');
  } else if (!REQUIRED_TLP_VALUES.has(meta.tlp)) {
    errors.push(
      `_meta.tlp "${meta.tlp}" not one of CLEAR/GREEN/AMBER/AMBER+STRICT/RED`,
    );
  }

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

    /* Staleness is a warning by default; `opts.strict` or `opts.errorOnStale`
     * promotes it to an error, and the predeploy gate runs --strict. */
    if (
      meta.last_updated !== undefined &&
      typeof fp.stale_after_days === 'number' &&
      fp.stale_after_days > 0
    ) {
      const lu = parseIsoDateStrict(meta.last_updated);
      if (lu === null) {
        // A malformed last_updated is invalid input, not "no opinion":
        // skipping it here would let the staleness check fail open.
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

  // Two return shapes: `{errors, warnings}` under opts.includeWarnings,
  // otherwise a bare string[] of errors.
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
  // process.exitCode, not process.exit() — the exit can truncate a piped write.
  process.exitCode = failed === 0 ? 0 : 1;
}

if (require.main === module) {
  main();
}

module.exports = { validateMeta, parseIsoDateStrict };
