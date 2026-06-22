'use strict';

/**
 * tests/zeroday-lessons.test.js
 *
 * Data-coherence pins for data/zeroday-lessons.json: the node-ipc
 * maintainer-domain-expiry lesson with its headline novel control
 * NEW-CTRL-047, and the absence of orphan entries for the deleted draft
 * CVEs.
 *
 * Per the anti-coincidence rule, every assertion checks an EXACT value —
 * never `assert.ok` on a field-presence check alone. Field-presence
 * assertions are paired with content-shape assertions.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');
const lessons = JSON.parse(
  fs.readFileSync(path.join(ROOT, 'data', 'zeroday-lessons.json'), 'utf8'),
);

const ENTRY_ID = 'MAL-2026-NODE-IPC-STEALER';

test(`${ENTRY_ID} zeroday-lessons entry exists with headline NEW-CTRL-047`, () => {
  const lesson = lessons[ENTRY_ID];
  assert.ok(lesson, `${ENTRY_ID} must be present in zeroday-lessons.json`);

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
  // exact id+name so the control surface is recoverable from this test
  // alone.
  const mfa = lesson.new_control_requirements.find((c) => c.id === 'NEW-CTRL-048');
  assert.ok(mfa, 'NEW-CTRL-048 NPM-MAINTAINER-MFA-ENFORCEMENT must be present');
  assert.equal(mfa.name, 'NPM-MAINTAINER-MFA-ENFORCEMENT');
  const lockfile = lesson.new_control_requirements.find((c) => c.id === 'NEW-CTRL-049');
  assert.ok(lockfile, 'NEW-CTRL-049 LOCKFILE-INTEGRITY-VERIFIED-AT-CI-BOOT must be present');
  assert.equal(lockfile.name, 'LOCKFILE-INTEGRITY-VERIFIED-AT-CI-BOOT');
});

test('zeroday-lessons.json carries no orphan entries for the deleted CVEs', () => {
  const l = JSON.parse(fs.readFileSync(path.join(ROOT, 'data', 'zeroday-lessons.json'), 'utf8'));
  assert.ok(!('MAL-2026-ANTHROPIC-MCP-STDIO' in l));
  assert.ok(!('CVE-2026-GTIG-AI-2FA' in l));
});


// ---- routed from v0_13_4-fixes ----
require("node:test").describe("v0_13_4-fixes", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
/**
 * tests/v0_13_4-fixes.test.js
 *
 * Pin tests for the v0.13.4 patch.
 *
 * Coverage:
 *   A — _meta.fed_by is now schema-accepted (drives the 20 cosmetic
 *       validate-playbooks warnings to 0).
 *   C — README + AGENTS surface the v0.13.x operator-facing features.
 *   E — 2 stuck-draft CVEs (MAL-2026-ANTHROPIC-MCP-STDIO + CVE-2026-GTIG-AI-2FA)
 *       are deleted from the catalog and from any cross-referencing data file.
 *   (B and D pin coverage is in their dedicated test files; this file
 *    covers the items that don't have a natural dedicated home.)
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const ROOT = path.join(__dirname, '..');

// ---------- A. fed_by schema acceptance ----------



// ---------- C. README + AGENTS surface v0.13.x features ----------








// ---------- E. 2 stuck-draft CVEs deleted ----------

test('E: zeroday-lessons.json carries no orphan entries for the deleted CVEs', () => {
  const l = JSON.parse(fs.readFileSync(path.join(ROOT, 'data', 'zeroday-lessons.json'), 'utf8'));
  assert.ok(!('MAL-2026-ANTHROPIC-MCP-STDIO' in l));
  assert.ok(!('CVE-2026-GTIG-AI-2FA' in l));
});
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});
