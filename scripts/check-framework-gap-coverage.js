#!/usr/bin/env node
/*
 * Enforces global-first coverage (AGENTS.md Hard Rule #5): every curated CVE in
 * data/cve-catalog.json must declare a framework_control_gaps statement for all
 * five jurisdiction buckets, so a multi-jurisdiction operator reading the
 * offline catalog gets more than a US-centric subset.
 *
 * Draft entries (_auto_imported) are exempt — they carry raw NVD data, and the
 * curation bar requires promotion before shipping, at which point this applies.
 *
 * Exits 0 when every curated entry is complete, 1 when any omits a bucket.
 * `process.exitCode`, never `process.exit()`: the failure list is a buffered
 * stdout write that the exit can truncate.
 */

'use strict';

const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.resolve(__dirname, '..');
// argv[2] overrides the catalog so the gate's own test can point at a fixture.
const CATALOG = process.argv[2] || path.join(ROOT, 'data', 'cve-catalog.json');

const REQUIRED = ['NIST', 'EU', 'UK', 'AU', 'ISO'];

function bucketOf(key) {
  if (/^NIST/i.test(key)) return 'NIST';
  // The EU bucket is the security-regulation family Hard Rule #5 names. GDPR is
  // data protection and does NOT satisfy it: an entry mapped only to GDPR still
  // owes NIS2/DORA/EU-AI coverage, so EU-GDPR must not match here.
  if (/^(NIS2|DORA|EU-AI|EU-CRA)/i.test(key)) return 'EU';
  if (/^UK-CAF/i.test(key)) return 'UK';
  if (/^(AU-Essential-?8|AU-ISM|Essential-?8)/i.test(key)) return 'AU';
  if (/^ISO-?27001/i.test(key)) return 'ISO';
  return 'OTHER';
}

function main() {
  let catalog;
  try {
    catalog = JSON.parse(fs.readFileSync(CATALOG, 'utf8'));
  } catch (e) {
    process.stdout.write(`[check-framework-gap-coverage] cannot read ${CATALOG}: ${e.message}\n`);
    process.exitCode = 1;
    return;
  }

  const partial = [];
  let checked = 0;
  for (const id of Object.keys(catalog)) {
    if (id === '_meta') continue;
    const entry = catalog[id];
    if (!entry || entry._auto_imported === true) continue;
    checked++;
    const gaps = entry.framework_control_gaps || {};
    const have = new Set(Object.keys(gaps).map(bucketOf));
    const missing = REQUIRED.filter((b) => !have.has(b));
    if (missing.length) partial.push({ id, missing });
  }

  if (partial.length === 0) {
    process.stdout.write(
      `[check-framework-gap-coverage] ok — all ${checked} curated entries declare framework-gap coverage for every required jurisdiction (${REQUIRED.join(', ')}).\n`
    );
    return;
  }

  process.stdout.write(
    `[check-framework-gap-coverage] FAIL: ${partial.length} of ${checked} curated entries omit at least one required jurisdiction bucket (Hard Rule #5, global-first):\n`
  );
  for (const p of partial.slice(0, 40)) {
    process.stdout.write(`  ${p.id}: missing ${p.missing.join(', ')}\n`);
  }
  if (partial.length > 40) {
    process.stdout.write(`  ... and ${partial.length - 40} more\n`);
  }
  process.stdout.write(
    'Add a CVE-specific framework_control_gaps statement for each missing bucket ' +
      '(NIST/EU/UK/AU/ISO). Keys must resolve to a real control in data/framework-control-gaps.json.\n'
  );
  process.exitCode = 1;
}

main();
