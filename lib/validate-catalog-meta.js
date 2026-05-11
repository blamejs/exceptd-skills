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
  const opts = { quiet: false };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--quiet' || a === '-q') opts.quiet = true;
    else if (a === '--help' || a === '-h') {
      console.log(
        'Usage: node lib/validate-catalog-meta.js [--quiet]\n' +
          '\n' +
          '  --quiet   Suppress per-catalog PASS output; show failures only.\n',
      );
      process.exit(0);
    } else {
      console.error(`Unknown argument: ${a}`);
      process.exit(2);
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

function validateMeta(catalogPath) {
  const errors = [];
  const data = readJson(catalogPath);
  const meta = data._meta;

  if (!meta || typeof meta !== 'object') {
    return ['missing _meta block'];
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
  }

  return errors;
}

function main() {
  const opts = parseArgs(process.argv);
  const files = fs
    .readdirSync(DATA_DIR)
    .filter((f) => f.endsWith('.json'))
    .sort();

  let failed = 0;
  for (const f of files) {
    const errors = validateMeta(path.join(DATA_DIR, f));
    if (errors.length === 0) {
      if (!opts.quiet) console.log(`PASS  ${f}`);
    } else {
      failed++;
      console.log(`FAIL  ${f}`);
      for (const e of errors) console.log(`        - ${e}`);
    }
  }

  const total = files.length;
  const passed = total - failed;
  console.log(
    `\n${passed}/${total} catalogs validated${failed ? `, ${failed} failed` : ''}.`,
  );
  process.exit(failed === 0 ? 0 : 1);
}

if (require.main === module) {
  main();
}

module.exports = { validateMeta };
