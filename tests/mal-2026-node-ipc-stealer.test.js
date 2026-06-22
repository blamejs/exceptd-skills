'use strict';

/**
 * tests/mal-2026-node-ipc-stealer.test.js
 *
 * Per-subject coverage for MAL-2026-NODE-IPC-STEALER (node-ipc 2026-05-14
 * expired-domain account-recovery compromise). Combines the catalog entry shape
 * (kev_scope_note, Shape-B rwep factors, iocs object, malicious versions), the
 * remediation-status state-change, the Package-Confidence Score invariants, and
 * the zeroday-lessons entry with its headline NEW-CTRL-047.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');
const catalog = JSON.parse(fs.readFileSync(path.join(ROOT, 'data', 'cve-catalog.json'), 'utf8'));
const lessons = JSON.parse(fs.readFileSync(path.join(ROOT, 'data', 'zeroday-lessons.json'), 'utf8'));
const scoring = require(path.join(ROOT, 'lib', 'scoring.js'));

const ENTRY_ID = 'MAL-2026-NODE-IPC-STEALER';

test(`${ENTRY_ID} catalog entry shape (kev_scope_note, rwep Shape B, iocs object)`, () => {
  const entry = catalog[ENTRY_ID];
  assert.ok(entry, `${ENTRY_ID} must be present in cve-catalog.json`);

  assert.equal(entry.cisa_kev, false);
  assert.equal(entry.cisa_kev_date, null);
  assert.equal(entry.active_exploitation, 'confirmed');
  assert.equal(entry.ai_discovered, false);
  assert.equal(entry.ai_assisted_weaponization, false);
  assert.equal(entry.rwep_score, 43);

  assert.equal(typeof entry.kev_scope_note, 'string', `${ENTRY_ID}.kev_scope_note must be a string`);
  assert.equal(entry.kev_scope_note.length >= 50, true,
    `${ENTRY_ID}.kev_scope_note must be a substantive paragraph (>= 50 chars)`);

  const sum = Object.values(entry.rwep_factors).reduce((a, b) => a + (typeof b === 'number' ? b : 0), 0);
  assert.equal(sum, entry.rwep_score,
    `${ENTRY_ID} Shape B violation: Σ rwep_factors (${sum}) !== rwep_score (${entry.rwep_score})`);

  assert.equal(entry.rwep_factors.cisa_kev, 0);
  assert.equal(entry.rwep_factors.poc_available, 20);
  assert.equal(entry.rwep_factors.ai_factor, 0);
  assert.equal(entry.rwep_factors.active_exploitation, 20);
  assert.equal(entry.rwep_factors.blast_radius, 28);
  assert.equal(entry.rwep_factors.patch_available, -15);
  assert.equal(entry.rwep_factors.live_patch_available, -10);
  assert.equal(entry.rwep_factors.reboot_required, 0);

  assert.equal(typeof entry.iocs, 'object', `${ENTRY_ID}.iocs must be an object (diff-coverage gate keys on the "iocs" literal)`);
  assert.equal(entry.iocs !== null, true, `${ENTRY_ID}.iocs must not be null`);
  assert.equal(Object.keys(entry.iocs).length >= 1, true, `${ENTRY_ID}.iocs must carry at least 1 indicator category`);
  assert.equal(Array.isArray(entry.iocs.payload_artifacts), true, `${ENTRY_ID}.iocs.payload_artifacts must be an array`);
  assert.equal(entry.iocs.payload_artifacts.length >= 1, true, `${ENTRY_ID}.iocs.payload_artifacts must contain at least 1 indicator string`);

  for (const v of ['9.1.6', '9.2.3', '12.0.1']) {
    assert.equal(entry.affected_versions.some((s) => s.includes(v)), true,
      `${ENTRY_ID}.affected_versions must include the malicious node-ipc version ${v}`);
  }
});

test('MAL-2026-NODE-IPC-STEALER remediation_status reflects 2026-05-14 npm removal', () => {
  const entry = catalog['MAL-2026-NODE-IPC-STEALER'];
  assert.ok(entry, 'MAL-2026-NODE-IPC-STEALER must remain in catalog (historical record)');
  assert.equal(entry.remediation_status, 'removed_from_registry');
  assert.equal(typeof entry.remediation_note, 'string');
  assert.equal(entry.remediation_note.length >= 50, true, 'note must be substantive');
  assert.equal(entry.remediation_status_verified_at, '2026-05-16');
});

test(`${ENTRY_ID} carries a valid trust-polarity PCS that matches its inputs`, () => {
  const e = catalog[ENTRY_ID];
  const pc = e.package_confidence;
  assert.ok(pc, `${ENTRY_ID} must carry package_confidence`);
  assert.equal(pc.polarity, 'trust', 'polarity const guards against summing with RWEP');
  assert.ok(Number.isInteger(pc.score) && pc.score >= 0 && pc.score <= 100, 'score is an integer in [0,100]');
  assert.equal(pc.score, scoring.packageConfidence(pc.inputs), `${ENTRY_ID} score must equal packageConfidence(inputs)`);
});

test(`${ENTRY_ID} zeroday-lessons entry exists with headline NEW-CTRL-047`, () => {
  const lesson = lessons[ENTRY_ID];
  assert.ok(lesson, `${ENTRY_ID} must be present in zeroday-lessons.json`);

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

  const headline = lesson.new_control_requirements.find((c) => c.id === 'NEW-CTRL-047');
  assert.ok(headline, `${ENTRY_ID} lesson must declare NEW-CTRL-047 as a new_control_requirement`);
  assert.equal(headline.name, 'PACKAGE-MAINTAINER-DOMAIN-EXPIRY-MONITORING');
  assert.equal(typeof headline.description, 'string');
  assert.equal(headline.description.length >= 50, true, 'NEW-CTRL-047 description must be a substantive paragraph (>= 50 chars)');
  assert.equal(typeof headline.evidence, 'string');
  assert.equal(Array.isArray(headline.gap_closes), true);
  assert.equal(headline.gap_closes.length >= 1, true, 'NEW-CTRL-047 must close at least 1 framework gap');

  const mfa = lesson.new_control_requirements.find((c) => c.id === 'NEW-CTRL-048');
  assert.ok(mfa, 'NEW-CTRL-048 NPM-MAINTAINER-MFA-ENFORCEMENT must be present');
  assert.equal(mfa.name, 'NPM-MAINTAINER-MFA-ENFORCEMENT');
  const lockfile = lesson.new_control_requirements.find((c) => c.id === 'NEW-CTRL-049');
  assert.ok(lockfile, 'NEW-CTRL-049 LOCKFILE-INTEGRITY-VERIFIED-AT-CI-BOOT must be present');
  assert.equal(lockfile.name, 'LOCKFILE-INTEGRITY-VERIFIED-AT-CI-BOOT');
});

test(`v0.12.33 intake: ${ENTRY_ID} catalog entry shape (kev_scope_note, rwep Shape B, iocs object)`, () => {
  const entry = catalog[ENTRY_ID];
  assert.ok(entry, `${ENTRY_ID} must be present in cve-catalog.json (added v0.12.33 cycle 13 intake)`);
  assert.equal(entry.cisa_kev, false);
  assert.equal(entry.cisa_kev_date, null);
  assert.equal(entry.active_exploitation, 'confirmed');
  assert.equal(entry.ai_discovered, false);
  assert.equal(entry.ai_assisted_weaponization, false);
  assert.equal(entry.rwep_score, 43);
  assert.equal(typeof entry.kev_scope_note, 'string');
  assert.equal(entry.kev_scope_note.length >= 50, true);
  const sum = Object.values(entry.rwep_factors).reduce((a, b) => a + (typeof b === 'number' ? b : 0), 0);
  assert.equal(sum, entry.rwep_score);
  assert.equal(typeof entry.iocs, 'object');
  assert.equal(entry.iocs !== null, true);
  assert.equal(Array.isArray(entry.iocs.payload_artifacts), true);
  assert.equal(entry.iocs.payload_artifacts.length >= 1, true);
});
