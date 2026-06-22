'use strict';

/**
 * Subject coverage for the `brief` CLI verb (bin/exceptd.js cmdBrief): the
 * no-arg / --all / --scope / --directives / --phase facets, the output
 * envelope, the irrelevant-flag refusals for run/ci-only flags (--max-rwep,
 * --diff-from-latest, --ack, --csaf-status, --publisher-namespace), --flat
 * grouping, and the help/footer surfaces.
 *
 * Each contributing source file's tests are wrapped in a describe() block named
 * for that source so the per-source requires/consts/helpers stay isolated.
 */

const test = require('node:test');
const assert = require('node:assert/strict');

// ===========================================================================
test.describe('cli-coverage', () => {
  const path = require('node:path');
  const { ROOT, makeSuiteHome, makeCli, tryJson } = require('./_helpers/cli');
  const runner = require(path.join(ROOT, 'lib', 'playbook-runner.js'));

  const SUITE_HOME = makeSuiteHome('exceptd-cli-cov-brief-');
  const cli = makeCli(SUITE_HOME);

  const PLAYBOOK_COUNT = runner.listPlaybooks().length;

  test('brief no-arg dispatches to plan and lists every shipped playbook', () => {
    const r = cli(['brief', '--json']);
    assert.equal(r.status, 0, 'brief no-arg must exit 0');
    const data = tryJson(r.stdout);
    assert.ok(data, 'brief output must be JSON');
    assert.ok(Array.isArray(data.playbooks), 'brief no-arg result must carry playbooks[] (cmdPlan delegate)');
    assert.equal(data.playbooks.length, PLAYBOOK_COUNT,
      `brief no-arg must list all ${PLAYBOOK_COUNT} shipped playbooks`);
    const first = data.playbooks[0];
    assert.equal(typeof first.id, 'string', 'each entry must carry id');
    assert.ok(first.domain && typeof first.domain.name === 'string',
      'each entry must carry domain.name (content, not just key presence)');
  });

  test('brief --all matches brief no-arg shape with every shipped playbook', () => {
    const r = cli(['brief', '--all', '--json']);
    assert.equal(r.status, 0);
    const data = tryJson(r.stdout);
    assert.ok(Array.isArray(data?.playbooks));
    assert.ok(data.playbooks.length >= 13,
      `brief --all must list at least the 13 shipped playbooks (found ${data.playbooks?.length})`);
  });

  test('brief --scope code filters playbooks to the code scope', () => {
    const r = cli(['brief', '--scope', 'code', '--json']);
    assert.equal(r.status, 0);
    const data = tryJson(r.stdout);
    assert.ok(Array.isArray(data?.playbooks));
    assert.ok(data.playbooks.length > 0, '--scope code must return at least one playbook');
    assert.ok(data.playbooks.length < PLAYBOOK_COUNT,
      `--scope code must filter to a subset, not all ${PLAYBOOK_COUNT}`);
    for (const pb of data.playbooks) {
      assert.equal(pb.scope, 'code',
        `every playbook returned by --scope code must self-report scope=code (got ${pb.scope} for ${pb.id})`);
    }
  });

  test('brief --directives expands each playbook with directive metadata', () => {
    const r = cli(['brief', '--directives', '--json']);
    assert.equal(r.status, 0);
    const data = tryJson(r.stdout);
    assert.ok(Array.isArray(data?.playbooks));
    let foundExpanded = false;
    for (const pb of data.playbooks) {
      if (Array.isArray(pb.directives) && pb.directives.length > 0) {
        const d = pb.directives[0];
        assert.equal(typeof d.id, 'string', 'directive entry must have id');
        assert.equal(typeof d.title, 'string', 'directive entry must have title');
        assert.ok('description' in d, 'directive entry must have description key');
        assert.ok('applies_to' in d, 'directive entry must have applies_to key');
        foundExpanded = true;
      }
    }
    assert.ok(foundExpanded,
      '--directives must add expanded directive metadata to at least one playbook');
  });

  test('brief secrets --phase govern emits only the govern phase body', () => {
    const r = cli(['brief', 'secrets', '--phase', 'govern', '--json']);
    assert.equal(r.status, 0);
    const data = tryJson(r.stdout);
    assert.ok(data, 'brief --phase govern must emit JSON');
    assert.equal(data.phase, 'govern', 'output must self-identify as the govern phase');
    assert.equal(data.playbook_id, 'secrets', 'output must carry the requested playbook_id');
    assert.ok(Array.isArray(data.jurisdiction_obligations) && data.jurisdiction_obligations.length > 0,
      'govern output must carry jurisdiction_obligations[] with at least one entry');
  });
});

// ===========================================================================
test.describe('cli-flag-relevance-guard', () => {
  const { makeSuiteHome, makeCli, tryJson } = require('./_helpers/cli');

  const SUITE_HOME = makeSuiteHome('exceptd-flag-relevance-brief-');
  const cli = makeCli(SUITE_HOME);

  test('brief --max-rwep → exit 1 with irrelevant-flag error naming ci as the consumer', () => {
    const r = cli(['brief', 'secrets', '--max-rwep', '5', '--json']);
    assert.equal(r.status, 1,
      `brief --max-rwep must exit EXACTLY 1; status=${r.status} stderr=${r.stderr.slice(0, 300)}`);
    const err = tryJson(r.stderr.trim()) || {};
    assert.equal(err.ok, false, 'error body.ok must be false');
    assert.equal(err.error_class, 'irrelevant-flag',
      `error_class must be "irrelevant-flag"; got ${JSON.stringify(err.error_class)}`);
    assert.equal(err.flag, 'max-rwep',
      `error body must name the offending flag; got ${JSON.stringify(err.flag)}`);
    assert.equal(err.verb, 'brief', `error body must record the invoking verb; got ${JSON.stringify(err.verb)}`);
    assert.deepEqual([...(err.accepted_verbs || [])].sort(), ['ci'],
      `accepted_verbs must be exactly the consuming set; got ${JSON.stringify(err.accepted_verbs)}`);
  });

  test('brief --diff-from-latest → exit 1 with irrelevant-flag error naming run', () => {
    const r = cli(['brief', 'secrets', '--diff-from-latest', '--json']);
    assert.equal(r.status, 1, `brief --diff-from-latest must exit EXACTLY 1; status=${r.status}`);
    const err = tryJson(r.stderr.trim()) || {};
    assert.equal(err.error_class, 'irrelevant-flag');
    assert.equal(err.flag, 'diff-from-latest');
    assert.deepEqual([...(err.accepted_verbs || [])].sort(), ['run']);
  });
});

// ===========================================================================
test.describe('cli-flag-validation', () => {
  const fs = require('node:fs');
  const path = require('node:path');

  const { SUITE_HOME, cli, tryJson } = (() => {
    const helpers = require('./_helpers/cli');
    const home = helpers.makeSuiteHome('exceptd-audit-ee-gg-brief-');
    return { SUITE_HOME: home, cli: helpers.makeCli(home), tryJson: helpers.tryJson };
  })();

  test('EE P1-6: brief --ack is refused with hint to use a run-class verb', () => {
    const r = cli(['brief', 'library-author', '--ack', '--json']);
    assert.equal(r.status, 1,
      'brief --ack must exit 1 (framework error). status=' + r.status + ' stderr=' + r.stderr.slice(0,300));
    const err = tryJson(r.stderr.trim()) || {};
    assert.equal(err.ok, false);
    assert.match(err.error || '',
      /--ack is irrelevant on this verb|no jurisdiction clock at stake/,
      'brief --ack must surface the "irrelevant" hint; got: ' + (err.error || ''));
    assert.match(err.error || '', /run|ci|ai-run/,
      'hint must name at least one of run/ci/ai-run; got: ' + (err.error || ''));
  });
});

// ===========================================================================
test.describe('cli-output-envelope-shape-v0_12_39', () => {
  const path = require('node:path');
  const { spawnSync } = require('node:child_process');

  const ROOT = path.join(__dirname, '..');
  const CLI = path.join(ROOT, 'bin', 'exceptd.js');

  function cli(args, opts = {}) {
    return spawnSync(process.execPath, [CLI, ...args], {
      encoding: 'utf8',
      cwd: opts.cwd || ROOT,
      env: { ...process.env, EXCEPTD_DEPRECATION_SHOWN: '1', ...(opts.env || {}) },
      input: opts.input,
    });
  }

  function tryJson(s) { try { return JSON.parse(s); } catch { return null; } }

  test('brief --all envelope: exact top-level key set', () => {
    const r = cli(['brief', '--all', '--json']);
    assert.equal(r.status, 0);
    const body = tryJson(r.stdout);
    assert.ok(body, `brief --all must emit parseable JSON; got: ${r.stdout.slice(0, 200)}`);
    const expected = [
      'contract', 'exceptd_owns', 'generated_at', 'grouped_by_scope',
      'host_ai_owns', 'ok', 'playbooks', 'scope_summary', 'session_id',
    ];
    assert.deepEqual(Object.keys(body).sort(), expected);
    assert.equal(body.ok, true, 'v0.13: brief --all carries ok:true');
    assert.match(body.contract, /seven-phase: govern → direct → look → detect → analyze → validate → close/);
    assert.match(body.session_id, /^[0-9a-f]{16}$/);
    assert.match(body.generated_at, /^\d{4}-\d{2}-\d{2}T/);
    assert.ok(Array.isArray(body.host_ai_owns));
    assert.ok(Array.isArray(body.exceptd_owns));
    assert.ok(Array.isArray(body.playbooks));
  });
});

// ===========================================================================
test.describe('cli-subverb-dispatch', () => {
  const { makeSuiteHome, makeCli, tryJson } = require('./_helpers/cli');

  const SUITE_HOME = makeSuiteHome('exceptd-audit-nn-brief-');
  const cli = makeCli(SUITE_HOME);

  test('NN P1-1: brief --csaf-status final → exit 1 with irrelevant-flag error pointing at the bundle-relevant verbs', () => {
    const r = cli(['brief', 'secrets', '--csaf-status', 'final', '--json']);
    assert.equal(r.status, 1,
      'brief --csaf-status must exit EXACTLY 1 (framework error). status=' + r.status + ' stderr=' + r.stderr.slice(0, 300));
    const err = tryJson(r.stderr.trim()) || {};
    assert.equal(err.ok, false, 'error body.ok must be false');
    assert.equal(err.error_class, 'irrelevant-flag',
      'error_class must be "irrelevant-flag"; got: ' + JSON.stringify(err.error_class));
    assert.equal(err.flag, 'csaf-status',
      'error body must name the offending flag; got: ' + JSON.stringify(err.flag));
    assert.equal(err.verb, 'brief',
      'error body must record the invoking verb; got: ' + JSON.stringify(err.verb));
    assert.ok(Array.isArray(err.accepted_verbs),
      'accepted_verbs must be an array; got: ' + JSON.stringify(err.accepted_verbs));
    assert.deepEqual([...err.accepted_verbs].sort(), ['ai-run', 'ci', 'run', 'run-all'],
      'accepted_verbs must be exactly the bundle-relevant set (no removed verbs); got: ' + JSON.stringify(err.accepted_verbs));
    assert.ok(!err.accepted_verbs.includes('ingest'),
      'accepted_verbs must not recommend the removed `ingest` verb');
    assert.match(err.error || '',
      /--csaf-status is irrelevant on this verb/,
      'error message must use the "irrelevant on this verb" phrasing; got: ' + (err.error || ''));
    assert.match(err.error || '', /run|ci|ai-run/,
      'error message must name at least one of run/ci/ai-run; got: ' + (err.error || ''));
  });

  test('NN P1-1: brief --publisher-namespace https://acme.example → exit 1 with irrelevant-flag error', () => {
    const r = cli(['brief', 'secrets', '--publisher-namespace', 'https://acme.example', '--json']);
    assert.equal(r.status, 1,
      'brief --publisher-namespace must exit EXACTLY 1 (framework error). status=' + r.status + ' stderr=' + r.stderr.slice(0, 300));
    const err = tryJson(r.stderr.trim()) || {};
    assert.equal(err.ok, false);
    assert.equal(err.error_class, 'irrelevant-flag');
    assert.equal(err.flag, 'publisher-namespace');
    assert.equal(err.verb, 'brief');
    assert.deepEqual([...err.accepted_verbs].sort(), ['ai-run', 'ci', 'run', 'run-all']);
    assert.ok(!err.accepted_verbs.includes('ingest'),
      'accepted_verbs must not recommend the removed `ingest` verb');
    assert.match(err.error || '',
      /--publisher-namespace is irrelevant on this verb/,
      'error message must use the "irrelevant on this verb" phrasing; got: ' + (err.error || ''));
  });

  test('NN P1-2: brief --csaf-status error prefix is "brief:" not "run:"', () => {
    const r = cli(['brief', 'secrets', '--csaf-status', 'final', '--json']);
    const err = tryJson(r.stderr.trim()) || {};
    assert.match(err.error || '', /^brief:/,
      'error.error must start with "brief:"; got: ' + JSON.stringify((err.error || '').slice(0, 200)));
    assert.doesNotMatch(err.error || '', /^run:/,
      'error.error must NOT start with the hardcoded "run:"; got: ' + JSON.stringify((err.error || '').slice(0, 200)));
  });

  test('NN P1-2: brief --publisher-namespace error prefix is "brief:" not "run:"', () => {
    const r = cli(['brief', 'secrets', '--publisher-namespace', 'https://acme.example', '--json']);
    const err = tryJson(r.stderr.trim()) || {};
    assert.match(err.error || '', /^brief:/,
      'error.error must start with "brief:"; got: ' + JSON.stringify((err.error || '').slice(0, 200)));
    assert.doesNotMatch(err.error || '', /^run:/,
      'error.error must NOT start with the hardcoded "run:"; got: ' + JSON.stringify((err.error || '').slice(0, 200)));
  });
});

// ===========================================================================
test.describe('reconciliation-deep-fixes', () => {
  const { makeSuiteHome, makeCli, tryJson } = require('./_helpers/cli');

  const home = makeSuiteHome('exceptd-reconcile-deep-brief-');
  const cli = makeCli(home);

  test('brief --ack irrelevant-flag refusal carries flag + error_class like its siblings', () => {
    const r = cli(['brief', 'kernel-lpe-triage', '--ack', '--json']);
    assert.equal(r.status, 1, '--ack on brief refuses with exit 1');
    const err = tryJson(r.stderr) || tryJson(r.stdout) || {};
    assert.equal(err.ok, false, 'ok:false');
    assert.equal(err.error_class, 'irrelevant-flag', 'error_class names the class');
    assert.equal(err.flag, 'ack', 'flag names the offending flag');
    assert.equal(err.verb, 'brief', 'verb is brief');
  });
});

// ===========================================================================
test.describe('reconciliation-fixes', () => {
  const { makeSuiteHome, makeCli, tryJson } = require('./_helpers/cli');

  const home = makeSuiteHome('exceptd-reconcile-brief-');
  const cli = makeCli(home);

  test('brief --flat drops the scope grouping; default brief --all keeps it', () => {
    const grouped = tryJson(cli(['brief', '--all', '--json']).stdout) || {};
    assert.equal(typeof grouped.grouped_by_scope, 'object', 'default brief --all carries grouped_by_scope');
    const flat = tryJson(cli(['brief', '--all', '--flat', '--json']).stdout) || {};
    assert.ok(!('grouped_by_scope' in flat) && !('scope_summary' in flat),
      'brief --flat must omit grouped_by_scope and scope_summary');
  });

  test('brief --help documents --flat (it lived only in the dead plan help block before)', () => {
    const out = (cli(['brief', '--help']).stdout || '') + (cli(['brief', '--help']).stderr || '');
    assert.match(out, /--flat/, 'brief --help must document --flat');
  });
});

// ===========================================================================
test.describe('usability-fixes', () => {
  const { makeSuiteHome, makeCli } = require('./_helpers/cli');

  const home = makeSuiteHome('exceptd-usability-brief-');
  const cli = makeCli(home);

  test('brief <playbook> footer reveals the collect verb (so brief-first operators do not run on empty evidence)', () => {
    const r = cli(['brief', 'secrets'], { env: { EXCEPTD_RAW_JSON: '' } });
    const out = (r.stdout || '') + (r.stderr || '');
    assert.match(out, /exceptd collect secrets \| exceptd run secrets --evidence -/, 'brief footer must show the collect pipeline');
  });
});


// ---- routed from audit-usability-fixes ----
require("node:test").describe("audit-usability-fixes", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
/**
 * CLI usability regression suite.
 *
 * Pins the behavior of a set of CLI ergonomics fixes so they cannot silently
 * regress at the next refactor. Each test exercises the real CLI through the
 * shared cli() harness (subprocess spawn of bin/exceptd.js) and asserts the
 * EXACT exit code and field shapes per the project anti-coincidence rule:
 * never `notEqual(0)`, never `assert.ok(field)` without a paired value/type
 * assertion.
 *
 * Areas covered:
 *   1. Unknown-flag hard-fail across all verbs (+ typo suggestion + the
 *      tailored cross-verb "irrelevant flag" message that must NOT collapse
 *      into a generic unknown-flag refusal).
 *   2. `--format json` returns the full run result, not a stub.
 *   3. Multiple --format values emit a one-format-wins note to stderr.
 *   4. Standardized bundles (sarif / csaf-2.0 / openvex) carry no top-level
 *      `ok` key and present their spec marker.
 *   5. `skill` / `framework-gap` honor --help; `refresh` keeps its own help.
 *   6. `collect` emits JSON when piped (non-TTY) so the documented pipe works.
 *   7. `refresh --check-advisories` arg parsing (report-only, no network).
 *   8. `attest list --limit` envelope + bad-value rejection.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const fs = require('node:fs');
const os = require('node:os');

const { ROOT, makeSuiteHome, makeCli, tryJson } = require('./_helpers/cli');

const SUITE_HOME = makeSuiteHome('exceptd-audit-usability-');
const cli = makeCli(SUITE_HOME);

// ===================================================================
// 1. Unknown-flag hard-fail (all verbs, not just doctor)
// ===================================================================









// ===================================================================
// 2. `--format json` returns the FULL run result (not a stub)
// ===================================================================


// ===================================================================
// 3. MULTI-FORMAT note to stderr
// ===================================================================


// ===================================================================
// 4. STANDARDIZED BUNDLES carry NO top-level `ok` key
// ===================================================================




// ===================================================================
// 5. `skill --help` / `framework-gap --help` honor --help;
//    refresh keeps its OWN detailed help
// ===================================================================




// ===================================================================
// 6. `collect` emits JSON when piped (non-TTY) so the documented pipe works
// ===================================================================


// ===================================================================
// 7. `refresh --check-advisories` parsing (no network — parseArgs directly)
// ===================================================================


// ===================================================================
// 8. `attest list --limit`
// ===================================================================

test('cross-verb flag yields the tailored "irrelevant" message, not unknown-flag (--csaf-status)', () => {
  // --csaf-status is a real flag on run/ci/ingest but irrelevant on brief.
  // The refusal must say so explicitly rather than collapse into the generic
  // unknown-flag path — that's the whole point of the tailored message.
  const r = cli(['brief', 'secrets', '--csaf-status', 'final']);
  assert.equal(r.status, 1, `expected exit 1; got ${r.status}`);
  const body = tryJson(r.stderr.trim()) || tryJson(r.stdout.trim());
  assert.ok(body, 'response should be parseable JSON');
  assert.equal(body.ok, false);
  assert.equal(typeof body.error, 'string');
  assert.match(body.error, /irrelevant/);
  assert.doesNotMatch(body.error, /unknown flag/);
});

test('cross-verb flag yields the tailored "irrelevant" message, not unknown-flag (--ack)', () => {
  const r = cli(['brief', 'secrets', '--ack']);
  assert.equal(r.status, 1, `expected exit 1; got ${r.status}`);
  const body = tryJson(r.stderr.trim()) || tryJson(r.stdout.trim());
  assert.ok(body, 'response should be parseable JSON');
  assert.equal(body.ok, false);
  assert.equal(typeof body.error, 'string');
  assert.match(body.error, /irrelevant/);
  assert.doesNotMatch(body.error, /unknown flag/);
});
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});


// ---- routed from error-ux-hardening ----
require("node:test").describe("error-ux-hardening", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
/**
 * Error-UX hardening regression suite.
 *
 * Pins the operator-facing error improvements: a case-only playbook typo gets a
 * suggestion, input-validation errors are not mislabeled "internal error", the
 * `ask` verb points a CVE/RFC question at the resolver, and the CVE
 * malformed-id message is accurate for a short year (not just a non-numeric
 * tail). All offline + deterministic.
 *
 * Discipline: exact exit codes; value/type assertions paired with presence.
 */

const test = require("node:test");
const assert = require("node:assert/strict");

const { makeSuiteHome, makeCli, tryJson } = require("./_helpers/cli");
const SUITE_HOME = makeSuiteHome("exceptd-erruxe-");
const cli = makeCli(SUITE_HOME);

test("brief --scope bogus → a validation error, NOT an 'internal error / file a bug'", () => {
  const r = cli(["brief", "--scope", "bogus"]);
  assert.equal(r.status, 1);
  const body = tryJson(r.stderr);
  assert.ok(body && body.ok === false);
  assert.match(body.error, /--scope must be one of/);
  assert.doesNotMatch(body.error, /internal error/);
  assert.doesNotMatch(body.error, /file at https/);
  assert.equal(body.type, "validation_error");
});
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});


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

test('#46 brief --all --directives includes description', () => {
  // v0.13.0: `plan` was removed; `brief --all` is the canonical form
  // and emits the same shape (the v0.11+ alias documented in the
  // removed-verb refusal message).
  const r = cli(['brief', '--all', '--directives', '--json']);
  const data = tryJson(r.stdout);
  assert.ok(data, 'brief --all output should be JSON');
  const pb = data.playbooks?.[0];
  assert.ok(pb, 'plan must surface at least one playbook');
  assert.ok(Array.isArray(pb.directives) && pb.directives.length > 0,
    'first playbook must carry at least one directive');
  const d0 = pb.directives[0];
  assert.ok('description' in d0, 'description key must be present (even if null)');
  // Operators read this to decide which directive to run; "the key exists
  // and might be null" wasn't enough to catch the v0.11.10 class of bug
  // where field-present + content-empty looked correct in shape tests.
  // Require: string OR null, and if string, non-empty after trim.
  if (d0.description !== null) {
    assert.equal(typeof d0.description, 'string',
      'description must be string|null — no objects, no arrays, no undefined');
    assert.ok(d0.description.trim().length > 0,
      'a non-null description must have content; empty strings are the field-populated bug class');
  }
});
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});
