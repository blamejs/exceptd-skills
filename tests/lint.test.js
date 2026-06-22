"use strict";


// ---- routed from operator-bugs ----
require("node:test").describe("operator-bugs", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
/**
 * Operator-reported bug regression suite.
 *
 * Every operator-reported bug that has been fixed lands here as a named test
 * case so re-introductions surface at `npm test`, not at user re-report.
 * Numbering matches the operator report sequence (items #1 through #N as
 * reported across the v0.9.5 → v0.11.x arc).
 *
 * Pattern for new items:
 *   describe('#N short label', () => { it('precise behavior', ...); });
 *
 * Avoid coupling tests to file paths / playbook IDs that may change. Prefer
 * direct runner exercises over CLI shell-outs where possible — CLI tests
 * stay narrow (smoke-level) because they spawn subprocesses and slow the
 * suite down.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const fs = require('node:fs');
const { spawnSync } = require('node:child_process');

const { ROOT, CLI, makeSuiteHome, makeCli, tryJson, secureTmpFile } = require('./_helpers/cli');
const runner = require(path.join(ROOT, 'lib', 'playbook-runner.js'));

const SUITE_HOME = makeSuiteHome('exceptd-operator-bugs-');
const cli = makeCli(SUITE_HOME);

// ===================================================================








// ===================================================================





// ===================================================================

// ===================================================================



// ===================================================================



// ===================================================================




// ===================================================================


// ===================================================================

// ===================================================================
// CSAF framework gaps emit as `document.notes[]` with `category: details`,
// not as `vulnerabilities[]` entries with `ids: [{system_name:
// 'exceptd-framework-gap'}]`. The `system_name` slot is reserved for
// recognised vulnerability tracking authorities (CVE, GHSA, etc.); the
// custom string is rejected by NVD / ENISA / Red Hat dashboards. Notes
// are the right home for advisory context, not pseudo-CVEs. The test
// asserts the notes-based shape and anti-asserts the pseudo-vulnerability
// shape.









// ===================================================================







// ===================================================================





// ===================================================================















// ===================================================================
// v0.11.14 freshness additions — opt-in registry check + upstream-check
// + refresh --network. Tests use EXCEPTD_REGISTRY_FIXTURE so they're
// fully offline-deterministic.
// ===================================================================

function withFixture(version, daysAgo) {
  const file = secureTmpFile('npm-fixture.json', 'npm-fixture-');
  const publishedAt = new Date(Date.now() - daysAgo * 24 * 3600 * 1000).toISOString();
  fs.writeFileSync(file, JSON.stringify({
    "dist-tags": { latest: version },
    version,
    time: { [version]: publishedAt, modified: publishedAt },
  }));
  return file;
}








// ===================================================================
// v0.12.0 — GHSA source + refresh --advisory + refresh --curate
// ===================================================================













// ===================================================================

test('#83 lint follows val.artifact indirection', () => {
  // Submission uses arbitrary observation keys + val.artifact indirection.
  // Pre-0.11.5 lint reported missing_required_artifact because it didn't
  // walk val.artifact. Post-fix, lint normalizes through the runner's
  // normalizeSubmission and validates the canonical shape.
  const pb = runner.loadPlaybook('library-author');
  const requiredId = (pb.phases.look.artifacts || []).find(a => a.required)?.id;
  if (!requiredId) return; // skip if playbook has no required artifacts
  const sub = JSON.stringify({
    observations: {
      'obs-1': { artifact: requiredId, captured: true, value: 'x', indicator: 'publish-workflow-uses-static-token', result: 'miss' }
    }
  });
  // Write to a tmp file for lint.
  const tmpFile = secureTmpFile('ev.json', 'lint-');
  fs.writeFileSync(tmpFile, sub);
  const r = cli(['lint', 'library-author', tmpFile, '--json']);
  fs.unlinkSync(tmpFile);
  const data = tryJson(r.stdout);
  assert.ok(data, 'lint output should be JSON');
  const missingErrors = (data.issues || []).filter(i => i.kind === 'missing_required_artifact' && i.artifact_id === requiredId);
  assert.equal(missingErrors.length, 0,
    `lint should follow val.artifact indirection — required artifact ${requiredId} was provided as observations["obs-1"].artifact`);
});

test('#83 lint and run agree on the same flat submission', () => {
  // Load the playbook to discover its real required-artifact ids dynamically
  // rather than hard-coding (which makes the test brittle to playbook edits).
  const pb = runner.loadPlaybook('library-author');
  const requiredArtifacts = (pb.phases.look.artifacts || []).filter(a => a.required);
  const ind = (pb.phases.detect.indicators || [])[0]?.id;
  if (requiredArtifacts.length === 0 || !ind) return; // skip if playbook structure unexpected

  // Build a submission that supplies every required artifact via val.artifact
  // indirection (the case that pre-0.11.5 lint mishandled).
  const observations = {};
  requiredArtifacts.forEach((a, i) => {
    observations[`obs-${i}`] = {
      artifact: a.id, captured: true, value: 'x',
      indicator: ind, result: 'miss',
    };
  });
  const sub = JSON.stringify({ observations });
  const tmpFile = secureTmpFile('ev.json', 'agree-');
  fs.writeFileSync(tmpFile, sub);
  try {
    const lintRes = cli(['lint', 'library-author', tmpFile, '--json']);
    const lintData = tryJson(lintRes.stdout);
    // Lint may emit warnings (e.g. precondition_unverified, unknown_signal)
    // but should NOT emit errors about missing required artifacts.
    const errs = (lintData?.issues || []).filter(i => i.severity === 'error');
    assert.equal(errs.length, 0,
      'lint should not error on a runner-valid submission with val.artifact indirection. Errors: ' +
      JSON.stringify(errs.map(e => e.kind)));

    // Run the same submission.
    const runRes = cli(['run', 'library-author', '--evidence', tmpFile, '--json']);
    const runData = tryJson(runRes.stdout);
    assert.equal(runData?.ok, true, 'run should accept the same submission lint accepted');
  } finally {
    fs.unlinkSync(tmpFile);
  }
});

test('#94 lint missing_required_artifact is a warning, not error', () => {
  // Lint should not error on a submission the runner accepts.
  const tmpFile = secureTmpFile('ev.json', 'lint94-');
  fs.writeFileSync(tmpFile, JSON.stringify({ observations: {} }));
  const r = cli(['lint', 'library-author', tmpFile, '--json']);
  fs.unlinkSync(tmpFile);
  const data = tryJson(r.stdout);
  const errors = (data?.issues || []).filter(i => i.severity === 'error');
  const missingRequiredAsError = errors.filter(i => i.kind === 'missing_required_artifact');
  assert.equal(missingRequiredAsError.length, 0,
    'missing_required_artifact should be warn, not error — runner accepts the same submission');
});
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});
