'use strict';

/**
 * tests/v0_12_33-node-ipc-coverage.test.js
 *
 * Diff-coverage gate (Hard Rule #15) requires every new CVE / MAL-* entry
 * whose `iocs` field is non-empty to be referenced in the test corpus
 * alongside the literal string "iocs". This smoke test pins the
 * MAL-2026-NODE-IPC-STEALER entry that landed in v0.12.33 from cycle 13
 * agent C's 24h-window intake check (node-ipc 2026-05-14 expired-domain
 * account-recovery compromise) and the matching zeroday-lessons entry
 * with its headline novel control NEW-CTRL-047 PACKAGE-MAINTAINER-DOMAIN-
 * EXPIRY-MONITORING.
 *
 * Per CLAUDE.md anti-coincidence rule, every assertion checks an EXACT
 * value (boolean, string, RWEP score, partition sum) — never `assert.ok`
 * on a field-presence check alone. Field-presence assertions are paired
 * with content-shape assertions.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');
const catalog = JSON.parse(
  fs.readFileSync(path.join(ROOT, 'data', 'cve-catalog.json'), 'utf8'),
);
const lessons = JSON.parse(
  fs.readFileSync(path.join(ROOT, 'data', 'zeroday-lessons.json'), 'utf8'),
);

const ENTRY_ID = 'MAL-2026-NODE-IPC-STEALER';

test(`v0.12.33 intake: ${ENTRY_ID} catalog entry shape (kev_scope_note, rwep Shape B, iocs object)`, () => {
  const entry = catalog[ENTRY_ID];
  assert.ok(entry, `${ENTRY_ID} must be present in cve-catalog.json (added v0.12.33 cycle 13 intake)`);

  // Exact-value pins on the operational fields. Drift here is intentional
  // (vendor re-attribution, KEV listing, RWEP correction) but must come
  // with a contract update in this test.
  assert.equal(entry.cisa_kev, false);
  assert.equal(entry.cisa_kev_date, null);
  assert.equal(entry.active_exploitation, 'confirmed');
  assert.equal(entry.ai_discovered, false);
  assert.equal(entry.ai_assisted_weaponization, false);
  assert.equal(entry.rwep_score, 43);

  // kev_scope_note must be a substantive paragraph explaining why an
  // ecosystem-package compromise sits outside CISA KEV scope. v0.12.31
  // established this pattern on MAL-2026-TANSTACK-MINI and CVE-2026-45321;
  // v0.12.33 extends it to MAL-2026-NODE-IPC-STEALER.
  assert.equal(typeof entry.kev_scope_note, 'string', `${ENTRY_ID}.kev_scope_note must be a string`);
  assert.equal(
    entry.kev_scope_note.length >= 50,
    true,
    `${ENTRY_ID}.kev_scope_note must be a substantive paragraph (>= 50 chars)`,
  );

  // Shape B invariant: Σ rwep_factors === rwep_score exactly. Asserted
  // here in addition to the catalog-wide test so a regression on this
  // specific entry surfaces by name.
  const sum = Object.values(entry.rwep_factors).reduce(
    (a, b) => a + (typeof b === 'number' ? b : 0),
    0,
  );
  assert.equal(
    sum,
    entry.rwep_score,
    `${ENTRY_ID} Shape B violation: Σ rwep_factors (${sum}) !== rwep_score (${entry.rwep_score})`,
  );

  // Canonical factor block — exact values per the cycle 13 derivation
  // (cisa_kev=0 KEV-scope-excluded, poc_available=20, ai_factor=0,
  // active_exploitation=20 confirmed, blast_radius=28 wide-3.35M-DL,
  // patch_available=-15 yank+clean-versions, live_patch_available=-10
  // audit tools work, reboot_required=0).
  assert.equal(entry.rwep_factors.cisa_kev, 0);
  assert.equal(entry.rwep_factors.poc_available, 20);
  assert.equal(entry.rwep_factors.ai_factor, 0);
  assert.equal(entry.rwep_factors.active_exploitation, 20);
  assert.equal(entry.rwep_factors.blast_radius, 28);
  assert.equal(entry.rwep_factors.patch_available, -15);
  assert.equal(entry.rwep_factors.live_patch_available, -10);
  assert.equal(entry.rwep_factors.reboot_required, 0);

  // iocs object shape. Diff-coverage gate keys on the literal string
  // "iocs" in this test corpus; this assertion contains it.
  assert.equal(typeof entry.iocs, 'object', `${ENTRY_ID}.iocs must be an object (diff-coverage gate keys on the "iocs" literal)`);
  assert.equal(entry.iocs !== null, true, `${ENTRY_ID}.iocs must not be null`);
  assert.equal(
    Object.keys(entry.iocs).length >= 1,
    true,
    `${ENTRY_ID}.iocs must carry at least 1 indicator category`,
  );
  // Content-shape pairing: at least the payload_artifacts category exists
  // and is a non-empty array — paired with the field-presence check above
  // per the CLAUDE.md "field-present ≠ field-populated" pitfall rule.
  assert.equal(
    Array.isArray(entry.iocs.payload_artifacts),
    true,
    `${ENTRY_ID}.iocs.payload_artifacts must be an array`,
  );
  assert.equal(
    entry.iocs.payload_artifacts.length >= 1,
    true,
    `${ENTRY_ID}.iocs.payload_artifacts must contain at least 1 indicator string`,
  );

  // Affected-versions pin: the three malicious version IDs must be
  // present as exact strings so a downstream lockfile audit can grep
  // them out of the catalog.
  for (const v of ['9.1.6', '9.2.3', '12.0.1']) {
    assert.equal(
      entry.affected_versions.some((s) => s.includes(v)),
      true,
      `${ENTRY_ID}.affected_versions must include the malicious node-ipc version ${v}`,
    );
  }
});

test(`v0.12.33 intake: ${ENTRY_ID} zeroday-lessons entry exists with headline NEW-CTRL-047`, () => {
  const lesson = lessons[ENTRY_ID];
  assert.ok(lesson, `${ENTRY_ID} must be present in zeroday-lessons.json (cycle 13 intake)`);

  // Top-level shape mirrors CVE-2026-31431 / MAL-2026-TANSTACK-MINI.
  assert.equal(typeof lesson.name, 'string');
  assert.equal(lesson.name.length >= 1, true);
  assert.equal(typeof lesson.lesson_date, 'string');
  assert.equal(typeof lesson.attack_vector, 'object');
  assert.equal(lesson.attack_vector !== null, true);
  assert.equal(typeof lesson.defense_chain, 'object');
  assert.equal(typeof lesson.framework_coverage, 'object');
  assert.equal(Array.isArray(lesson.new_control_requirements), true);
  assert.equal(typeof lesson.compliance_exposure_score, 'object');
  assert.equal(lesson.ai_discovered_zeroday, false);
  assert.equal(lesson.ai_assist_factor, 'low');

  // Headline novel control: NEW-CTRL-047 PACKAGE-MAINTAINER-DOMAIN-
  // EXPIRY-MONITORING — exact id + name pin so a re-numbering or rename
  // surfaces here rather than silently in framework-gap output.
  const headline = lesson.new_control_requirements.find(
    (c) => c.id === 'NEW-CTRL-047',
  );
  assert.ok(
    headline,
    `${ENTRY_ID} lesson must declare NEW-CTRL-047 as a new_control_requirement`,
  );
  assert.equal(headline.name, 'PACKAGE-MAINTAINER-DOMAIN-EXPIRY-MONITORING');
  assert.equal(typeof headline.description, 'string');
  assert.equal(
    headline.description.length >= 50,
    true,
    'NEW-CTRL-047 description must be a substantive paragraph (>= 50 chars)',
  );
  assert.equal(typeof headline.evidence, 'string');
  assert.equal(Array.isArray(headline.gap_closes), true);
  assert.equal(
    headline.gap_closes.length >= 1,
    true,
    'NEW-CTRL-047 must close at least 1 framework gap',
  );

  // Secondary controls (NEW-CTRL-048 NPM-MAINTAINER-MFA-ENFORCEMENT,
  // NEW-CTRL-049 LOCKFILE-INTEGRITY-VERIFIED-AT-CI-BOOT) also pinned by
  // exact id+name so the cycle-13 control surface is recoverable from
  // this test alone.
  const mfa = lesson.new_control_requirements.find((c) => c.id === 'NEW-CTRL-048');
  assert.ok(mfa, 'NEW-CTRL-048 NPM-MAINTAINER-MFA-ENFORCEMENT must be present');
  assert.equal(mfa.name, 'NPM-MAINTAINER-MFA-ENFORCEMENT');
  const lockfile = lesson.new_control_requirements.find((c) => c.id === 'NEW-CTRL-049');
  assert.ok(lockfile, 'NEW-CTRL-049 LOCKFILE-INTEGRITY-VERIFIED-AT-CI-BOOT must be present');
  assert.equal(lockfile.name, 'LOCKFILE-INTEGRITY-VERIFIED-AT-CI-BOOT');
});
