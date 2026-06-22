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


// ---- routed from v0188-adjacent-hunt-edges ----
;(() => {
/**
 * Adjacent-hunt regression coverage: the unit-testable fixes from the
 * read-only adjacent/non-surfaced bug hunt.
 *
 *  - reattest BUG-2: the sidecar classifier checks tamper_class BEFORE the
 *    reason strings, so an unsigned-SUBSTITUTION attestation (reason contains
 *    "explicitly unsigned" but carries tamper_class:'unsigned-substitution') is
 *    not mislabeled as the benign 'explicitly-unsigned'.
 *  - EXCEPTD-001/002/003: empty-string flag values are rejected, not silently
 *    degraded to "no scope".
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const bin = require('../bin/exceptd.js');
const { makeCli } = require('./_helpers/cli');

test('reattest sidecar classifier: tamper_class wins over a reason string (unsigned-substitution not mislabeled)', () => {
  // An unsigned-substitution attack: the sidecar is "unsigned" on a host that
  // HAS a private key, so the reason mentions "explicitly unsigned" but the
  // tamper_class flags the substitution. The classifier must surface the attack.
  const cls = bin._classifySidecarVerify({
    signed: false,
    verified: false,
    tamper_class: 'unsigned-substitution',
    reason: 'attestation explicitly unsigned but a private key is present — substitution suspected',
  });
  assert.equal(cls, 'unsigned-substitution', 'a substitution attack must not be classified as benign explicitly-unsigned');

  // A genuinely-unsigned attestation (no tamper_class) still classifies benign.
  const benign = bin._classifySidecarVerify({
    signed: false,
    verified: false,
    reason: 'attestation explicitly unsigned (no private key when written)',
  });
  assert.equal(benign, 'explicitly-unsigned');
});

test('brief --phase "" is rejected, not silently treated as the full brief', () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'v0188-brief-'));
  try {
    const cli = makeCli(home);
    const r = cli(['brief', 'secrets', '--phase', '', '--json'], { env: { EXCEPTD_HOME: home } });
    assert.notEqual(r.status, 0, 'empty --phase must be refused'); // allow-notEqual: a structured refusal; any non-zero exit is correct, the point is it does not run the full brief
  } finally {
    fs.rmSync(home, { recursive: true, force: true });
  }
});

test('brief --all --playbook "" is rejected, not silently planned across all playbooks', () => {
  // The legacy standalone multi-playbook verb was removed; the live path is
  // `brief --all`, which delegates to the multi-playbook planner where the empty
  // --playbook guard lives.
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'v0188-plan-'));
  try {
    const cli = makeCli(home);
    const r = cli(['brief', '--all', '--playbook', '', '--json'], { env: { EXCEPTD_HOME: home } });
    assert.notEqual(r.status, 0, 'empty --playbook must be refused'); // allow-notEqual: structured refusal; any non-zero is correct, the point is it does not plan across all playbooks
    let body = null;
    for (const s of [r.stdout, r.stderr]) { try { const j = JSON.parse(s); if (j) { body = j; break; } } catch { /* not this stream */ } }
    assert.ok(body && body.flag === 'playbook', `the refusal must name the offending flag; got ${r.stdout || r.stderr}`);
  } finally {
    fs.rmSync(home, { recursive: true, force: true });
  }
});
})();


// ---- routed from v0_13_2-fixes ----
;(() => {
/**
 * tests/v0_13_2-fixes.test.js
 *
 * Pinning tests for the v0.13.2 patch-class mega-release.
 *
 * Fixes covered:
 *   A — release.yml split into publish-npm (id-token:write only) +
 *       publish-github-release (contents:write only). Verifies the YAML
 *       declares both jobs with disjoint permission scopes.
 *   B — lint-skills.js Hard Rule #1 enforcement: body-scan refuses CVE
 *       references not in catalog AND warns on _draft references.
 *   C — flag-value did-you-mean: --mode / --phase / --format / --csaf-status
 *       typos return did_you_mean[] in the structured error body.
 *   D — check-test-count.js: predeploy gate refuses test-set shrinkage
 *       beyond the configured tolerance.
 *   E — skill discovery_mode: 16 standalone skills carry the
 *       "discovery_mode: standalone" frontmatter field.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const ROOT = path.join(__dirname, '..');
const CLI = path.join(ROOT, 'bin', 'exceptd.js');

function cli(args, opts = {}) {
  return spawnSync(process.execPath, [CLI, ...args], {
    encoding: 'utf8',
    cwd: ROOT,
    env: { ...process.env, EXCEPTD_DEPRECATION_SHOWN: '1', ...(opts.env || {}) },
    ...opts,
  });
}

function tryJson(s) { try { return JSON.parse(s); } catch { return null; } }

// ---------- A. release.yml job split ----------

test('A: release.yml declares both publish-npm and publish-github-release jobs', () => {
  const yml = fs.readFileSync(path.join(ROOT, '.github', 'workflows', 'release.yml'), 'utf8');
  assert.match(yml, /^  publish-npm:/m, 'publish-npm job must exist');
  assert.match(yml, /^  publish-github-release:/m, 'publish-github-release job must exist');
  // Pre-v0.13.2 a single `publish` job existed. Confirm it's gone.
  assert.ok(!/^  publish:\s*$/m.test(yml), 'pre-v0.13.2 monolithic publish job must be removed');
});

// Helper: extract a job block from release.yml. Walks line-by-line and
// stops at the next line whose entire content matches the job-header
// pattern (`  word:` at column 2, nothing else on the line).
function extractJobBlock(yml, jobName) {
  const lines = yml.split('\n');
  let startIdx = -1;
  for (let i = 0; i < lines.length; i++) {
    if (lines[i] === `  ${jobName}:`) { startIdx = i; break; }
  }
  if (startIdx === -1) return null;
  let endIdx = lines.length;
  for (let i = startIdx + 1; i < lines.length; i++) {
    if (/^  [a-z][a-z0-9_-]*:\s*$/.test(lines[i])) { endIdx = i; break; }
  }
  return lines.slice(startIdx, endIdx).join('\n');
}

// Regex helpers: match permission DECLARATIONS (`      contents: write`
// at leading whitespace, end-of-line) rather than any prose mention.
// Comments + descriptions inside the YAML often quote the strings.
const PERM_DECL = (key, value) =>
  new RegExp(`^\\s+${key}:\\s+${value}\\s*$`, 'm');

test('A: publish-npm job carries id-token:write but NOT contents:write', () => {
  const yml = fs.readFileSync(path.join(ROOT, '.github', 'workflows', 'release.yml'), 'utf8');
  const block = extractJobBlock(yml, 'publish-npm');
  assert.ok(block, 'publish-npm job block not parseable');
  assert.match(block, PERM_DECL('id-token', 'write'));
  assert.match(block, PERM_DECL('contents', 'read'));
  assert.ok(!PERM_DECL('contents', 'write').test(block),
    'publish-npm must NOT declare contents:write (job-split contract)');
});

test('A: publish-github-release job carries contents:write but NOT id-token:write', () => {
  const yml = fs.readFileSync(path.join(ROOT, '.github', 'workflows', 'release.yml'), 'utf8');
  const block = extractJobBlock(yml, 'publish-github-release');
  assert.ok(block, 'publish-github-release job block not parseable');
  assert.match(block, PERM_DECL('contents', 'write'));
  assert.ok(!PERM_DECL('id-token', 'write').test(block),
    'publish-github-release must NOT declare id-token:write (job-split contract)');
});

test('A: publish-github-release depends on publish-npm (sequenced)', () => {
  const yml = fs.readFileSync(path.join(ROOT, '.github', 'workflows', 'release.yml'), 'utf8');
  const block = extractJobBlock(yml, 'publish-github-release');
  assert.ok(block);
  assert.match(block, /needs:\s*\[\s*validate\s*,\s*publish-npm\s*\]/,
    'publish-github-release must depend on validate + publish-npm');
});

// ---------- B. lint Hard Rule #1 body-scan ----------

test('B: lint-skills.js source carries the body-scan implementation', () => {
  const src = fs.readFileSync(path.join(ROOT, 'lib', 'lint-skills.js'), 'utf8');
  assert.match(src, /Hard Rule #1/, 'body-scan must explicitly cite Hard Rule #1');
  assert.match(src, /body cites/, 'body-scan must emit "body cites" text');
  assert.match(src, /ctx\.cveCatalog/, 'body-scan must consume ctx.cveCatalog');
  assert.match(src, /_draft\s*===\s*true/, 'body-scan must distinguish draft entries');
  // v0.13.3 flipped missing-from-catalog from warning to hard error
  // after the 2 pre-existing violations were triaged.
  assert.match(src, /if \(!entry\) \{[\s\S]*?skillErrors\.push/,
    'missing-from-catalog must push to skillErrors (v0.13.3 flip)');
});

test('B: validateFrontmatter accepts discovery_mode field (no "unknown field" error)', () => {
  const src = fs.readFileSync(path.join(ROOT, 'lib', 'lint-skills.js'), 'utf8');
  assert.match(src, /discovery_mode/, 'OPTIONAL_FRONTMATTER_FIELDS must include discovery_mode');
});

// ---------- C. flag-value did-you-mean ----------

test('C: brief --phase typo returns did_you_mean[]', () => {
  const r = cli(['brief', 'library-author', '--phase', 'goven', '--json']);
  // emitError sets exitCode = GENERIC_FAILURE (1). Pin exact code.
  assert.equal(r.status, 1, `expected exit 1 (GENERIC_FAILURE); got ${r.status}`);
  const body = tryJson(r.stderr.trim()) || tryJson(r.stdout.trim());
  assert.ok(body && body.ok === false);
  assert.ok(Array.isArray(body.did_you_mean));
  assert.ok(body.did_you_mean.includes('govern'),
    `expected govern in did_you_mean for "goven"; got ${JSON.stringify(body.did_you_mean)}`);
  assert.ok(Array.isArray(body.accepted));
});

test('C: report unknown-format typo returns did_you_mean[]', () => {
  const r = spawnSync(process.execPath, [path.join(ROOT, 'orchestrator', 'index.js'), 'report', 'execuive'], {
    encoding: 'utf8', cwd: ROOT,
  });
  // v0.13 orchestrator exit-code class fix: usage errors → exit 1.
  assert.equal(r.status, 1, `expected exit 1 (GENERIC_FAILURE); got ${r.status}`);
  const body = tryJson(r.stdout.trim()) || tryJson(r.stderr.trim());
  assert.ok(body && body.ok === false);
  assert.ok(Array.isArray(body.did_you_mean));
  assert.ok(body.did_you_mean.includes('executive'),
    `expected executive in did_you_mean for "execuive"; got ${JSON.stringify(body.did_you_mean)}`);
});

// ---------- D. check-test-count gate ----------

test('D: check-test-count.js exists and emits structured JSON', () => {
  const r = spawnSync(process.execPath, [path.join(ROOT, 'scripts', 'check-test-count.js'), '--json'], {
    encoding: 'utf8', cwd: ROOT,
  });
  assert.equal(r.status, 0, `gate must pass on current state; got ${r.status}. stderr: ${r.stderr.slice(0, 200)}`);
  const body = tryJson(r.stdout.trim());
  assert.ok(body, 'gate must emit JSON when --json passed');
  assert.equal(body.verb, 'check-test-count');
  assert.equal(typeof body.observed, 'number');
  assert.equal(typeof body.baseline, 'number');
  assert.equal(typeof body.delta, 'number');
  assert.ok(['ok', 'grew_beyond_threshold_consider_bump'].includes(body.status),
    `status must be ok or grew_beyond_threshold; got ${body.status}`);
});

test('D: predeploy.js wires test-count gate as #15', () => {
  const src = fs.readFileSync(path.join(ROOT, 'scripts', 'predeploy.js'), 'utf8');
  assert.match(src, /Test-count baseline/, 'predeploy.js must register the test-count gate');
  assert.match(src, /scripts.*check-test-count\.js/, 'predeploy.js must reference scripts/check-test-count.js');
});

// ---------- E. discovery_mode field on standalone skills ----------

test('E: 16 skills carry discovery_mode: standalone frontmatter', () => {
  const expected = [
    'age-gates-child-safety', 'ai-risk-management', 'defensive-countermeasure-mapping',
    'email-security-anti-phishing', 'fuzz-testing-strategy', 'mlops-security',
    'ot-ics-security', 'researcher', 'sector-energy', 'sector-federal-government',
    'sector-telecom', 'skill-update-loop', 'threat-model-currency',
    'threat-modeling-methodology', 'webapp-security', 'zeroday-gap-learn',
  ];
  for (const name of expected) {
    const p = path.join(ROOT, 'skills', name, 'skill.md');
    if (!fs.existsSync(p)) continue; // skip if skill renamed/removed in a future release
    const content = fs.readFileSync(p, 'utf8');
    assert.match(content, /^discovery_mode:\s*["']?standalone["']?/m,
      `${name}: must carry discovery_mode: standalone in frontmatter`);
  }
});
})();
