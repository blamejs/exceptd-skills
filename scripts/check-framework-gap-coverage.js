#!/usr/bin/env node
/*
 * scripts/check-framework-gap-coverage.js
 *
 * AGENTS.md Hard Rule #5 (global-first) enforcement gate. Every curated CVE
 * in data/cve-catalog.json must declare a framework_control_gaps statement
 * for all five jurisdiction buckets:
 *
 *   NIST  — NIST-800-53-* / NIST-800-63*
 *   EU    — NIS2-* / DORA-* / EU-AI-* / GDPR-*
 *   UK    — UK-CAF-*
 *   AU    — AU-Essential-8-* / AU-ISM-*
 *   ISO   — ISO-27001-2022-*
 *
 * A multi-jurisdiction operator reading the offline catalog's framework-gap
 * output must get coverage for every required jurisdiction on every CVE, not
 * a US-centric subset. Before this gate, two-thirds of the corpus mapped only
 * a subset; a codex review surfaced it, the corpus was completed, and this
 * gate keeps it from regressing when new CVEs are curated.
 *
 * Draft entries (_auto_imported === true) are exempt — they carry raw NVD
 * data that has not been through curation yet. The curation bar (elsewhere)
 * requires drafts to be promoted before shipping, at which point this gate
 * applies.
 *
 * Exit code: 0 when every curated entry is complete, 1 when any entry omits a
 * required bucket (the list is printed). Uses process.exitCode (not
 * process.exit) so buffered stdout drains before the process ends.
 */

'use strict';

const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.resolve(__dirname, '..');
// Catalog path is overridable (argv[2]) so the gate's own test can point it at
// a fixture; defaults to the shipped catalog for the real predeploy run.
const CATALOG = process.argv[2] || path.join(ROOT, 'data', 'cve-catalog.json');

const REQUIRED = ['NIST', 'EU', 'UK', 'AU', 'ISO'];

function bucketOf(key) {
  if (/^NIST/i.test(key)) return 'NIST';
  // EU regulatory family: NIS2, DORA, GDPR, and any EU- prefixed control
  // (EU-AI-Act, EU-CRA Cyber Resilience Act, EU-GDPR-*). Catches every EU
  // instrument the catalog uses so an entry covered by EU-CRA or EU-GDPR is
  // not falsely flagged as EU-missing.
  if (/^(NIS2|DORA|GDPR|EU-)/i.test(key)) return 'EU';
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
