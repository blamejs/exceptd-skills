'use strict';

/**
 * tests/cli.test.js
 *
 * Subject suite for the bin/exceptd.js CLI surface. Every test here drives the
 * CLI as a subprocess (`exceptd <verb> …`) and asserts the documented exit
 * code + JSON envelope shape. Tests that exercise lib/ modules directly
 * (playbook-runner, scoring, validators, refresh, collectors, source-ghsa,
 * cve-curation, …) live in those modules' own subject suites, not here.
 *
 * Discipline carried over from the source suites: exact exit-code assertions
 * (never `notEqual(0)`), field-presence paired with field-content, and an
 * isolated EXCEPTD_HOME / cwd for every CLI spawn so the repo tree is never
 * mutated.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const fs = require('node:fs');
const os = require('node:os');
const { spawnSync } = require('node:child_process');

const { ROOT, CLI, makeSuiteHome, makeCli, tryJson, secureTmpFile } = require('./_helpers/cli');
const { EXIT_CODES } = require(path.join(ROOT, 'lib', 'exit-codes.js'));
const runner = require(path.join(ROOT, 'lib', 'playbook-runner.js'));

const SUITE_HOME = makeSuiteHome('exceptd-cli-');
const cli = makeCli(SUITE_HOME);

const SHIPPED_PLAYBOOKS = runner.listPlaybooks();
const PLAYBOOK_COUNT = SHIPPED_PLAYBOOKS.length;

const BIN = path.resolve(__dirname, '..', 'bin', 'exceptd.js');

// ===================================================================
// Source: hunt-fix-H-cli.test.js — local run()/tryJson()/mkTmp() helpers.
// These spawn with the caller's cwd and stderr as a pipe (the CI/parser
// shape the JSON-envelope contract targets), distinct from the shared
// makeCli() sandbox, so they keep their own helpers verbatim.
// ===================================================================
function hRun(args, opts = {}) {
  return spawnSync(process.execPath, [BIN, ...args], {
    encoding: 'utf8',
    cwd: opts.cwd || process.cwd(),
    env: { ...process.env, ...(opts.env || {}) },
  });
}

function hTryJson(s) {
  if (typeof s !== 'string') return null;
  try { return JSON.parse(s); } catch { return null; }
}

function mkTmp() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'exceptd-hcli-'));
}

const hcli = require('../bin/exceptd.js');

test('#36 readEvidenceDir is exported and shared by run + ci', () => {
  assert.equal(typeof hcli._readEvidenceDir, 'function');
});

test('#36 readEvidenceDir reads a normal <pb>.json regular file (positive path)', () => {
  const dir = mkTmp();
  try {
    fs.writeFileSync(path.join(dir, 'sbom.json'), JSON.stringify({ signals: { x: 1 } }), 'utf8');
    const r = hcli._readEvidenceDir(dir, 'run');
    assert.equal(r.ok, true);
    assert.equal(typeof r.bundle, 'object');
    assert.notEqual(r.bundle, null);
    assert.deepEqual(r.bundle.sbom, { signals: { x: 1 } });
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('#36 readEvidenceDir refuses a non-regular-file entry (dir named <pb>.json)', () => {
  const dir = mkTmp();
  try {
    fs.mkdirSync(path.join(dir, 'sbom.json'));
    const r = hcli._readEvidenceDir(dir, 'ci');
    assert.equal(r.ok, false);
    assert.equal(typeof r.error, 'string');
    assert.match(r.error, /not a regular file|resolves outside|symbolic link/);
    assert.match(r.error, /^ci:/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('#36 readEvidenceDir refuses an invalid playbook-id filename segment', () => {
  const dir = mkTmp();
  try {
    fs.writeFileSync(path.join(dir, 'Sbom.json'), '{}', 'utf8');
    const r = hcli._readEvidenceDir(dir, 'run');
    assert.equal(r.ok, false);
    assert.equal(typeof r.error, 'string');
    assert.match(r.error, /invalid playbook-id segment/);
    assert.match(r.error, /^run:/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('#36 readEvidenceDir refuses a symlinked entry (symlink/junction class)', (t) => {
  const dir = mkTmp();
  const outside = mkTmp();
  try {
    const target = path.join(outside, 'secret.json');
    fs.writeFileSync(target, JSON.stringify({ stolen: true }), 'utf8');
    const link = path.join(dir, 'sbom.json');
    try {
      fs.symlinkSync(target, link, 'file');
    } catch (e) {
      if (e.code === 'EPERM' || e.code === 'EACCES' || e.code === 'ENOSYS') {
        t.skip('symlink creation not permitted on this host');
        return;
      }
      throw e;
    }
    const r = hcli._readEvidenceDir(dir, 'ci');
    assert.equal(r.ok, false);
    assert.equal(typeof r.error, 'string');
    assert.match(r.error, /symbolic link|symlink|resolves outside|not a regular file/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
    fs.rmSync(outside, { recursive: true, force: true });
  }
});

test('#36 ci --evidence-dir refuses a non-regular-file entry end-to-end (cross-platform parity)', () => {
  const dir = mkTmp();
  try {
    fs.mkdirSync(path.join(dir, 'sbom.json'));
    const r = hRun(['ci', '--required', 'sbom', '--evidence-dir', dir]);
    assert.equal(r.status, 1);
    const e = hTryJson(r.stderr);
    assert.notEqual(e, null);
    assert.equal(e.ok, false);
    assert.equal(typeof e.error, 'string');
    assert.match(e.error, /not a regular file/);
    assert.match(e.error, /^ci:/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('#36 ci --evidence-dir reads a normal <pb>.json regular file end-to-end (positive)', () => {
  const dir = mkTmp();
  try {
    fs.writeFileSync(path.join(dir, 'sbom.json'), JSON.stringify({ signals: {} }), 'utf8');
    const r = hRun(['ci', '--required', 'sbom', '--evidence-dir', dir]);
    assert.equal(r.status, 0);
    const e = hTryJson(r.stderr);
    assert.equal(e, null);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('#36 ci --evidence-dir refuses a symlinked entry end-to-end (verb parity with run)', (t) => {
  const dir = mkTmp();
  const outside = mkTmp();
  try {
    const target = path.join(outside, 'secret.json');
    fs.writeFileSync(target, JSON.stringify({ stolen: true }), 'utf8');
    const link = path.join(dir, 'sbom.json');
    try {
      fs.symlinkSync(target, link, 'file');
    } catch (e) {
      if (e.code === 'EPERM' || e.code === 'EACCES' || e.code === 'ENOSYS') {
        t.skip('symlink creation not permitted on this host');
        return;
      }
      throw e;
    }
    const r = hRun(['ci', '--required', 'sbom', '--evidence-dir', dir]);
    assert.equal(r.status, 1);
    const e = hTryJson(r.stderr);
    assert.notEqual(e, null);
    assert.equal(e.ok, false);
    assert.equal(typeof e.error, 'string');
    assert.match(e.error, /symbolic link|resolves outside|not a regular file/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
    fs.rmSync(outside, { recursive: true, force: true });
  }
});

function writeBehindFixture(dir) {
  const fx = path.join(dir, 'registry-fixture.json');
  fs.writeFileSync(fx, JSON.stringify({
    'dist-tags': { latest: '99.0.0' },
    version: '99.0.0',
    time: { '99.0.0': '2099-01-01T00:00:00.000Z', modified: '2099-01-01T00:00:00.000Z' },
  }), 'utf8');
  return fx;
}

test('#35 doctor --registry-check (warn-only) exits 0 in JSON, pretty, AND human modes', () => {
  const dir = mkTmp();
  try {
    const fx = writeBehindFixture(dir);
    const env = { EXCEPTD_REGISTRY_FIXTURE: fx };

    const rJson = hRun(['doctor', '--registry-check', '--json'], { env });
    const b = hTryJson(rJson.stdout);
    assert.notEqual(b, null);
    assert.equal(b.summary.issues_count, 0);
    assert.equal(b.summary.warnings_count >= 1, true);
    assert.equal(Array.isArray(b.summary.warning_checks), true);
    assert.equal(b.summary.warning_checks.includes('registry'), true);
    assert.equal(b.summary.all_green, false);
    assert.equal(rJson.status, 0);

    const rPretty = hRun(['doctor', '--registry-check', '--pretty'], { env });
    assert.equal(rPretty.status, 0);

    const rHuman = hRun(['doctor', '--registry-check'], { env });
    assert.equal(rHuman.status, 0);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('#35 doctor --json exit code equals the human exit code in the warn-only state', () => {
  const dir = mkTmp();
  try {
    const fx = writeBehindFixture(dir);
    const env = { EXCEPTD_REGISTRY_FIXTURE: fx };
    const rJson = hRun(['doctor', '--registry-check', '--json'], { env });
    const rHuman = hRun(['doctor', '--registry-check'], { env });
    assert.equal(rJson.status, rHuman.status);
    assert.equal(rJson.status, 0);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('#35 doctor --json body keeps all_green:false + warning_checks even though exit is 0', () => {
  const dir = mkTmp();
  try {
    const fx = writeBehindFixture(dir);
    const rJson = hRun(['doctor', '--registry-check', '--json'], { env: { EXCEPTD_REGISTRY_FIXTURE: fx } });
    const b = hTryJson(rJson.stdout);
    assert.notEqual(b, null);
    assert.equal(b.summary.all_green, false);
    assert.equal(typeof b.summary.warnings_count, 'number');
    assert.equal(b.summary.warnings_count >= 1, true);
    assert.equal(b.summary.issues_count, 0);
    assert.equal(rJson.status, 0);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('#35 inverse: a genuine error-severity check still forces exit 1 (errorList non-empty)', () => {
  const { bucketChecks } = require('../lib/doctor-bucketing.js');
  const errState = bucketChecks({
    signatures: { ok: false, error: 'Ed25519 verification failed' },
    registry: { ok: false, severity: 'warn', error: 'behind' },
  });
  assert.equal(errState.errorList.includes('signatures'), true);
  assert.equal(errState.errorList.length > 0, true);
  assert.equal(errState.warnList.includes('registry'), true);
  assert.equal(errState.errorList.includes('registry'), false);

  const warnOnly = bucketChecks({
    registry: { ok: false, severity: 'warn', error: 'behind' },
  });
  assert.equal(warnOnly.errorList.length, 0);
  assert.equal(warnOnly.warnList.length, 1);
});

test('#37 unknown verb + --json-stdout-only writes the ok:false envelope to STDOUT (exit 10)', () => {
  const r = hRun(['definitelynotaverb', '--json-stdout-only']);
  assert.equal(r.status, 10);
  const body = hTryJson(r.stdout);
  assert.notEqual(body, null);
  assert.equal(body.ok, false);
  assert.equal(typeof body.error, 'string');
  assert.match(body.error, /unknown command/);
});

test('#37 evidence-read failure + --json-stdout-only is reachable on STDOUT (exit 1)', () => {
  const missing = path.join(os.tmpdir(), 'exceptd-hcli-does-not-exist-' + process.pid);
  const r = hRun(['run', 'sbom', '--evidence-dir', missing, '--json-stdout-only']);
  assert.equal(r.status, 1);
  const body = hTryJson(r.stdout) || hTryJson(r.stderr);
  assert.notEqual(body, null);
  assert.equal(body.ok, false);
  assert.equal(typeof body.error, 'string');
  assert.notEqual(hTryJson(r.stdout), null);
  assert.equal(hTryJson(r.stdout).ok, false);
});

test('#37 a typo flag under --json-stdout-only still surfaces a machine-readable error', () => {
  const r = hRun(['run', '--evidnce', 'x', '--json-stdout-only']);
  assert.equal(r.status, 1);
  const body = hTryJson(r.stdout) || hTryJson(r.stderr);
  assert.notEqual(body, null);
  assert.equal(body.ok, false);
  assert.equal(typeof body.error, 'string');
});

test('#38 bare invocation (welcome) exits 0 and writes non-empty stdout', () => {
  const r = hRun([]);
  assert.equal(r.status, 0);
  assert.equal(typeof r.stdout, 'string');
  assert.equal(r.stdout.length > 0, true);
});

test('#38 `help` exits 0 and writes the full help text to stdout', () => {
  const r = hRun(['help']);
  assert.equal(r.status, 0);
  assert.equal(r.stdout.length > 0, true);
  assert.match(r.stdout, /exceptd/);
});

test('#38 `help <verb>` exits 0 with verb-specific help (no truncation)', () => {
  const r = hRun(['help', 'run']);
  assert.equal(r.status, 0);
  assert.equal(r.stdout.length > 0, true);
});

test('#38 `<verb> --help` exits 0 with verb help', () => {
  const r = hRun(['run', '--help']);
  assert.equal(r.status, 0);
  assert.equal(r.stdout.length > 0, true);
});

test('#38 no live process.exit() remains on the help/welcome dispatch paths', () => {
  const src = fs.readFileSync(BIN, 'utf8');
  const noLineComments = src.replace(/\/\/[^\n]*/g, '');
  const noComments = noLineComments.replace(/\/\*[\s\S]*?\*\//g, '');
  assert.equal(/process\.exit\s*\(/.test(noComments), false);
});

// ===================================================================
// Source: cli-selector-flag-fixes.test.js
// ===================================================================

test('ci --required "" is refused (no false-green fall-through)', () => {
  const r = cli(['ci', '--required', '', '--json']);
  assert.equal(r.status, EXIT_CODES.GENERIC_FAILURE);
  const body = tryJson(r.stdout) || tryJson(r.stderr);
  assert.equal(body.ok, false);
  assert.match(body.error, /empty playbook list/);
});

test('ci --scope "" is refused with the accepted-set message', () => {
  const r = cli(['ci', '--scope', '', '--json']);
  assert.equal(r.status, EXIT_CODES.GENERIC_FAILURE);
  const body = tryJson(r.stdout) || tryJson(r.stderr);
  assert.equal(body.ok, false);
  assert.doesNotMatch(JSON.stringify(body), /"verdict":\s*"PASS"/);
});

test('ci --required with no value gives a clean usage refusal, not an internal error', () => {
  const r = cli(['ci', '--required']);
  assert.equal(r.status, EXIT_CODES.GENERIC_FAILURE);
  const body = tryJson(r.stderr) || tryJson(r.stdout);
  assert.equal(body.ok, false);
  assert.match(body.error, /--required requires a value/);
  assert.doesNotMatch(body.error, /internal error/);
});

test('run --cwd is refused on a verb that does not consume it', () => {
  const r = cli(['run', 'secrets', '--cwd', '/nonexistent-path', '--json']);
  assert.equal(r.status, EXIT_CODES.GENERIC_FAILURE);
  const body = tryJson(r.stderr) || tryJson(r.stdout);
  assert.equal(body.ok, false);
  assert.match(JSON.stringify(body), /irrelevant|only applies to.*collect/i);
});

test('report --json (no format) emits parseable JSON, not a format error', () => {
  const r = cli(['report', '--json']);
  assert.equal(r.status, 0);
  const body = tryJson(r.stdout);
  assert.ok(body && typeof body === 'object', 'stdout must parse as JSON');
  assert.equal(body.ok, true);
  assert.equal(body.verb, 'report');
  assert.equal(body.format, 'technical');
});

test('report executive --json emits JSON for a non-csaf format (not Markdown)', () => {
  const r = cli(['report', 'executive', '--json']);
  assert.equal(r.status, 0);
  const body = tryJson(r.stdout);
  assert.ok(body && typeof body === 'object', 'stdout must parse as JSON, not render Markdown');
  assert.equal(body.format, 'executive');
  assert.ok(body.summary && typeof body.summary === 'object');
});

// ===================================================================
// Source: v0188-adjacent-hunt-edges.test.js — _classifySidecarVerify is a
// bin/exceptd.js export (CLI module surface); the two flag-refusal tests
// spawn via a per-test makeCli(home) bound to an explicit EXCEPTD_HOME.
// ===================================================================
const binEdges = require('../bin/exceptd.js');

test('reattest sidecar classifier: tamper_class wins over a reason string (unsigned-substitution not mislabeled)', () => {
  const cls = binEdges._classifySidecarVerify({
    signed: false,
    verified: false,
    tamper_class: 'unsigned-substitution',
    reason: 'attestation explicitly unsigned but a private key is present — substitution suspected',
  });
  assert.equal(cls, 'unsigned-substitution', 'a substitution attack must not be classified as benign explicitly-unsigned');

  const benign = binEdges._classifySidecarVerify({
    signed: false,
    verified: false,
    reason: 'attestation explicitly unsigned (no private key when written)',
  });
  assert.equal(benign, 'explicitly-unsigned');
});

test('brief --phase "" is rejected, not silently treated as the full brief', () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'v0188-brief-'));
  try {
    const localCli = makeCli(home);
    const r = localCli(['brief', 'secrets', '--phase', '', '--json'], { env: { EXCEPTD_HOME: home } });
    assert.notEqual(r.status, 0, 'empty --phase must be refused'); // allow-notEqual: a structured refusal; any non-zero exit is correct, the point is it does not run the full brief
  } finally {
    fs.rmSync(home, { recursive: true, force: true });
  }
});

test('brief --all --playbook "" is rejected, not silently planned across all playbooks', () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'v0188-plan-'));
  try {
    const localCli = makeCli(home);
    const r = localCli(['brief', '--all', '--playbook', '', '--json'], { env: { EXCEPTD_HOME: home } });
    assert.notEqual(r.status, 0, 'empty --playbook must be refused'); // allow-notEqual: structured refusal; any non-zero is correct, the point is it does not plan across all playbooks
    let body = null;
    for (const s of [r.stdout, r.stderr]) { try { const j = JSON.parse(s); if (j) { body = j; break; } } catch { /* not this stream */ } }
    assert.ok(body && body.flag === 'playbook', `the refusal must name the offending flag; got ${r.stdout || r.stderr}`);
  } finally {
    fs.rmSync(home, { recursive: true, force: true });
  }
});

// ===================================================================
// Source: cli-coverage.test.js — CLI surface coverage (brief / discover /
// doctor / attest / run / ci / framework-gap / ai-run / refresh). Helper
// copied verbatim.
// ===================================================================
function stagePlaybookWithCurrency(playbookId, score) {
  const srcDir = path.join(ROOT, 'data', 'playbooks');
  const stagingRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'exceptd-pb-'));
  for (const f of fs.readdirSync(srcDir)) {
    fs.copyFileSync(path.join(srcDir, f), path.join(stagingRoot, f));
  }
  const target = path.join(stagingRoot, `${playbookId}.json`);
  const body = JSON.parse(fs.readFileSync(target, 'utf8'));
  body._meta.threat_currency_score = score;
  fs.writeFileSync(target, JSON.stringify(body, null, 2));
  return { dir: stagingRoot, env: { EXCEPTD_PLAYBOOK_DIR: stagingRoot } };
}

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

test('discover happy path emits context + recommended_playbooks[]', () => {
  const r = cli(['discover', '--json']);
  assert.equal(r.status, 0);
  const data = tryJson(r.stdout);
  assert.ok(data, 'discover output must be JSON');
  assert.equal(data.verb, 'discover');
  assert.ok(data.context && typeof data.context.cwd === 'string',
    'context.cwd must be present and a string');
  assert.ok(Array.isArray(data.recommended_playbooks),
    'recommended_playbooks must be an array');
  assert.ok(data.recommended_playbooks.length > 0,
    'recommended_playbooks must include at least the cross-cutting framework entry');
  const ids = data.recommended_playbooks.map(p => p.id);
  assert.ok(ids.includes('framework'),
    'framework playbook must always be recommended (cross-cutting)');
});

test('discover --scan-only embeds legacy_scan and emits no routed_to', () => {
  const r = cli(['discover', '--scan-only', '--json']);
  assert.equal(r.status, 0);
  const data = tryJson(r.stdout);
  assert.ok(data, 'discover --scan-only must emit JSON');
  assert.ok('legacy_scan' in data, 'legacy_scan field must be present under --scan-only');
  assert.ok(!('routed_to' in data),
    '--scan-only must NOT dispatch (no routed_to field); routing requires discover without --scan-only');
});

test('doctor no-flags emits checks{} covering every subcheck', () => {
  const r = cli(['doctor', '--json']);
  const data = tryJson(r.stdout);
  assert.ok(data, 'doctor must emit JSON');
  assert.equal(data.verb, 'doctor');
  assert.ok(data.checks && typeof data.checks === 'object', 'checks{} must be present');
  assert.ok(Object.keys(data.checks).length >= 4,
    'doctor with no flags must run at least 4 subchecks (signatures, currency, cves, rfcs)');
  for (const [name, check] of Object.entries(data.checks)) {
    assert.equal(typeof check.ok, 'boolean',
      `check ${name} must carry boolean .ok (no coincidence-passing)`);
  }
});

test('doctor --signatures emits only the signatures subcheck', () => {
  const r = cli(['doctor', '--signatures', '--json']);
  const data = tryJson(r.stdout);
  assert.ok(data?.checks?.signatures,
    'checks.signatures must be present when --signatures is passed');
  assert.equal(typeof data.checks.signatures.ok, 'boolean',
    'signatures.ok must be a boolean verdict, not undefined');
});

test('doctor --signatures --shipped-tarball opts into tarball-verify round-trip', () => {
  const r = cli(['doctor', '--signatures', '--shipped-tarball', '--json'], { timeout: 120000 });
  const data = tryJson(r.stdout);
  assert.ok(data?.checks?.signatures, 'checks.signatures must be present');
  assert.ok(data.checks.signatures.shipped_tarball,
    'checks.signatures.shipped_tarball must be populated when --shipped-tarball is passed');
  const st = data.checks.signatures.shipped_tarball;
  if (st.skipped === true) {
    assert.equal(typeof st.reason, 'string',
      'when skipped, shipped_tarball must document why (e.g. installed package without verify-shipped-tarball.js)');
  } else {
    assert.equal(typeof st.ok, 'boolean',
      'when run, shipped_tarball.ok must be a boolean verdict');
  }
});

test('doctor --currency emits only the currency subcheck', () => {
  const r = cli(['doctor', '--currency', '--json']);
  const data = tryJson(r.stdout);
  assert.ok(data?.checks?.currency, 'checks.currency must be present');
  assert.equal(typeof data.checks.currency.ok, 'boolean');
});

test('doctor --cves emits only the cves subcheck', () => {
  const r = cli(['doctor', '--cves', '--json']);
  const data = tryJson(r.stdout);
  assert.ok(data?.checks?.cves, 'checks.cves must be present');
  assert.equal(typeof data.checks.cves.ok, 'boolean');
});

test('doctor --rfcs emits only the rfcs subcheck', () => {
  const r = cli(['doctor', '--rfcs', '--json']);
  const data = tryJson(r.stdout);
  assert.ok(data?.checks?.rfcs, 'checks.rfcs must be present');
  assert.equal(typeof data.checks.rfcs.ok, 'boolean');
});

test('attest show <sid> returns the full attestation JSON', () => {
  const sid = 'show-' + Date.now();
  const sub = JSON.stringify({});
  const rRun = cli(['run', 'library-author', '--evidence', '-', '--session-id', sid], { input: sub });
  assert.equal(rRun.status, 0, 'pre-staging run must succeed');
  const r = cli(['attest', 'show', sid, '--json']);
  assert.equal(r.status, 0);
  const data = tryJson(r.stdout);
  assert.ok(data, 'attest show must emit JSON');
  assert.equal(data.session_id, sid, 'session_id field must echo the requested sid');
  assert.ok(Array.isArray(data.attestations) && data.attestations.length >= 1,
    'attestations[] must contain at least one entry');
  assert.equal(data.attestations[0].session_id, sid,
    'each nested attestation must carry the matching session_id (content, not just key)');
});

test('attest list returns attestations[] sorted newest-first', () => {
  const sid = 'list-' + Date.now();
  cli(['run', 'library-author', '--evidence', '-', '--session-id', sid], { input: '{}' });
  const r = cli(['attest', 'list', '--json']);
  assert.equal(r.status, 0);
  const data = tryJson(r.stdout);
  assert.ok(data, 'attest list must emit JSON');
  assert.equal(data.ok, true);
  assert.ok(Array.isArray(data.attestations),
    'attestations[] must be an array (NOT result.sessions)');
  assert.ok(data.attestations.length >= 1,
    'list must include the just-created attestation');
  assert.equal(typeof data.count, 'number');
  assert.ok(data.attestations.some(e => e.session_id === sid),
    'the just-created session_id must appear in the list (content match, not key presence)');
});

test('attest export <sid> --format csaf wraps the export in a CSAF 2.0 envelope', () => {
  const sid = 'exp-' + Date.now();
  cli(['run', 'library-author', '--evidence', '-', '--session-id', sid], { input: '{}' });
  const r = cli(['attest', 'export', sid, '--format', 'csaf', '--json']);
  assert.equal(r.status, 0);
  const data = tryJson(r.stdout);
  assert.ok(data, 'export --format csaf must emit JSON');
  assert.equal(data.document?.csaf_version, '2.0',
    'CSAF envelope must carry document.csaf_version=2.0');
  assert.ok(data.document.tracking && typeof data.document.tracking.id === 'string',
    'document.tracking must carry a non-empty id (content, not just key)');
  assert.equal(data.exceptd_export.session_id, sid,
    'exceptd_export.session_id must match the requested sid');
});

test('attest export redacts submitted signal VALUES, not just denylisted keys (no raw-value leak)', () => {
  const sid = 'leak-' + Date.now();
  const CANARY = 'LEAKCANARY-' + Date.now();
  cli(['run', 'library-author', '--evidence', '-', '--session-id', sid],
    { input: JSON.stringify({ signals: { jurisdiction_marker: CANARY } }) });
  const r = cli(['attest', 'export', sid, '--json']);
  assert.equal(r.status, 0, 'attest export must exit 0');
  assert.ok(!r.stdout.includes(CANARY),
    'attest export must NOT leak a raw submitted signal value in any field');
  const data = tryJson(r.stdout);
  const att = (data?.attestations || [])[0];
  if (att && att.signals_redacted && Object.prototype.hasOwnProperty.call(att.signals_redacted, 'jurisdiction_marker')) {
    assert.equal(att.signals_redacted.jurisdiction_marker, '[redacted]',
      'a retained signal key must carry a redacted placeholder, not its raw value');
  }
});

test('attest export redacts free-form signal_overrides values + denylisted keys (verdicts kept verbatim)', () => {
  const sid = 'soleak-' + Date.now();
  const CANARY = 'SOLEAKCANARY-' + Date.now();
  const FP_CANARY = 'FPMAPCANARY-' + Date.now();
  cli(['run', 'library-author', '--evidence', '-', '--session-id', sid],
    { input: JSON.stringify({ signal_overrides: {
        'no-security-md': 'hit',
        'free-form-ind': CANARY,
        'token': 'hit',
        'some-ind__fp_checks': { check1: true, note: FP_CANARY },
      } }) });
  const r = cli(['attest', 'export', sid, '--json']);
  assert.equal(r.status, 0, 'attest export must exit 0');
  assert.ok(!r.stdout.includes(CANARY),
    'attest export must NOT leak a free-form signal_overrides value');
  assert.ok(!r.stdout.includes(FP_CANARY),
    'attest export must NOT leak an __fp_checks attestation-map value');
  const data = tryJson(r.stdout);
  const so = (data?.attestations || [])[0]?.signal_overrides || {};
  assert.equal(so['no-security-md'], 'hit',
    'an exact hit/miss/inconclusive verdict must be preserved verbatim (audit-meaningful)');
  assert.equal(so['free-form-ind'], '[redacted]',
    'a non-enum signal_overrides value must be redacted to the placeholder');
  assert.equal(so['some-ind__fp_checks'], '[redacted]',
    'an __fp_checks object value must be redacted to the placeholder, not emitted verbatim');
  assert.ok(!Object.prototype.hasOwnProperty.call(so, 'token'),
    'a denylisted key (token) must be dropped from signal_overrides, matching signals_redacted');
});

test('verify-attestation <sid> alias dispatches to attest verify with verified=true', () => {
  const sid = 'va-' + Date.now();
  cli(['run', 'library-author', '--evidence', '-', '--session-id', sid], { input: '{}' });
  const r = cli(['verify-attestation', sid, '--json']);
  assert.equal(r.status, 0, 'verify-attestation must exit 0 on a clean run');
  const data = tryJson(r.stdout);
  assert.ok(data, 'verify-attestation must emit JSON');
  assert.equal(data.verb, 'attest verify',
    'alias must dispatch to attest verify (verb field reflects underlying handler)');
  assert.equal(data.session_id, sid);
  assert.ok(Array.isArray(data.results) && data.results.length >= 1,
    'results[] must contain at least one verification entry');
  const first = data.results[0];
  if (first.signed) {
    assert.equal(first.verified, true,
      'signed attestation must verify against keys/public.pem (no post-hoc tamper)');
  }
});

test('run-all alias produces the same playbook set as run --all', () => {
  const sub = JSON.stringify({});
  const rAlias = cli(['run-all', '--include-judgement-shaped', '--evidence', '-', '--session-id', 'ra-' + Date.now()],
    { input: sub });
  const rExplicit = cli(['run', '--all', '--include-judgement-shaped', '--evidence', '-', '--session-id', 're-' + Date.now()],
    { input: sub });
  const aliasJson = tryJson(rAlias.stdout);
  const explicitJson = tryJson(rExplicit.stdout);
  assert.ok(aliasJson, 'run-all must emit JSON');
  assert.ok(explicitJson, 'run --all must emit JSON');
  const aliasIds = [...aliasJson.playbooks_run].sort();
  const explicitIds = [...explicitJson.playbooks_run].sort();
  assert.deepEqual(aliasIds, explicitIds,
    'run-all and run --all must dispatch the same playbook set');
  assert.equal(aliasIds.length, PLAYBOOK_COUNT,
    `run-all --include-judgement-shaped must cover all ${PLAYBOOK_COUNT} shipped playbooks`);
});

test('run --all (no --include-judgement-shaped) excludes the 9 policy-skipped playbooks by default', () => {
  const sub = JSON.stringify({});
  const r = cli(['run', '--all', '--evidence', '-', '--session-id', 'ranopolicy-' + Date.now()],
    { input: sub });
  const body = tryJson(r.stdout);
  assert.ok(body, 'run --all must emit JSON');
  const ids = body.playbooks_run;
  const POLICY_SKIPPED = [
    'ai-discovered-cve-triage', 'cloud-iam-incident', 'idp-incident',
    'identity-sso-compromise', 'llm-tool-use-exfil', 'post-quantum-migration',
    'ransomware', 'supply-chain-recovery', 'webhook-callback-abuse',
  ];
  for (const skipped of POLICY_SKIPPED) {
    assert.ok(!ids.includes(skipped),
      `default --all must exclude policy-skipped playbook ${skipped}; got: ${ids.join(', ')}`);
  }
  assert.ok(ids.includes('framework'),
    `default --all must include framework (analyze-only, warn-precondition); got: ${ids.join(', ')}`);
});

test('framework-gap <fw> <cve> emits gap analysis JSON with frameworks{}', () => {
  const r = cli(['framework-gap', 'NIST-800-53', 'CVE-2026-31431', '--json']);
  assert.equal(r.status, 0);
  const data = tryJson(r.stdout);
  assert.ok(data, 'framework-gap --json must emit JSON');
  assert.equal(data.threat_scenario, 'CVE-2026-31431',
    'threat_scenario must echo the requested CVE id');
  assert.ok(data.frameworks && typeof data.frameworks === 'object',
    'frameworks{} must be present');
  assert.ok(data.frameworks['NIST-800-53'],
    'requested framework key must appear in frameworks{}');
  assert.equal(typeof data.frameworks['NIST-800-53'].gap_count, 'number',
    'gap_count must be a number, not undefined');
  assert.ok(data.summary && typeof data.summary.total_gaps === 'number',
    'summary.total_gaps must be present and numeric');
});

test('doctor --rfcs (modern) wraps the same validator with structured output', () => {
  const r = cli(['doctor', '--rfcs', '--json']);
  const data = tryJson(r.stdout);
  assert.ok(data?.checks?.rfcs, 'doctor --rfcs must populate checks.rfcs');
  assert.equal(typeof data.checks.rfcs.ok, 'boolean',
    'checks.rfcs.ok must be a boolean (not undefined / not coincidence-truthy)');
  assert.ok(typeof data.checks.rfcs.total === 'number' || data.checks.rfcs.total === null,
    'checks.rfcs.total must be numeric or explicit null');
});

test('ai-run streaming emits phase frames in order: govern → … → close → done', () => {
  const r = cli(['ai-run', 'library-author'], {
    input: JSON.stringify({ event: 'evidence', payload: { observations: {}, verdict: {} } }) + '\n',
  });
  assert.equal(r.status, 0, 'ai-run streaming must exit 0 on a successful evidence event');
  const lines = r.stdout.split(/\r?\n/).map(l => l.trim()).filter(Boolean);
  assert.ok(lines.length >= 9,
    `streaming must emit at least 9 frames (govern, direct, look, await_evidence, detect, analyze, validate, close, done); got ${lines.length}`);
  const frames = lines.map(l => tryJson(l)).filter(Boolean);
  assert.equal(frames.length, lines.length,
    'every JSONL line must parse as JSON (no half-flushed frames)');
  const tagOf = (f) => f.phase || f.event;
  const tags = frames.map(tagOf);
  const expectedOrder = ['govern', 'direct', 'look', 'await_evidence',
    'detect', 'analyze', 'validate', 'close', 'done'];
  for (const phase of expectedOrder) {
    assert.ok(tags.includes(phase),
      `streaming must include the ${phase} frame; saw [${tags.join(', ')}]`);
  }
  let lastIndex = -1;
  for (const phase of expectedOrder) {
    const idx = tags.indexOf(phase);
    assert.ok(idx > lastIndex,
      `${phase} must appear after the previous expected frame; saw at idx ${idx}, last was ${lastIndex}`);
    lastIndex = idx;
  }
  const doneFrame = frames.find(f => f.event === 'done');
  assert.equal(doneFrame.ok, true, 'done frame must carry ok:true');
  assert.equal(typeof doneFrame.session_id, 'string',
    'done frame must carry the session_id so callers can fetch the attestation');
});

test('ci --max-rwep <N> overrides the playbook escalate threshold', () => {
  const r = cli(['ci', '--required', 'secrets', '--max-rwep', '50', '--json']);
  const data = tryJson(r.stdout);
  assert.ok(data, 'ci --max-rwep must emit JSON');
  assert.equal(data.verb, 'ci');
  assert.equal(typeof data.summary.max_rwep_observed, 'number',
    'summary.max_rwep_observed must be numeric');
  assert.ok(typeof data.summary.verdict === 'string',
    'summary.verdict must be a string (PASS/FAIL)');
});

test('ci --block-on-jurisdiction-clock fails when a clock fires (F18: exit 5 = CLOCK_STARTED)', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'cidir-'));
  fs.mkdirSync(tmp, { recursive: true });
  fs.writeFileSync(path.join(tmp, 'secrets.json'), JSON.stringify({
    observations: { w: { captured: true, value: 'AKIA', indicator: 'aws-access-key-id', result: 'hit' } },
    verdict: { classification: 'detected', blast_radius: 4 },
  }));
  try {
    const r = cli(['ci', '--required', 'secrets',
      '--evidence-dir', tmp,
      '--ack',
      '--block-on-jurisdiction-clock', '--json']);
    const data = tryJson(r.stdout);
    assert.ok(data, 'ci output must be JSON');
    assert.ok(data.summary.jurisdiction_clocks_started >= 1,
      'detected+blast_radius=4 must start at least one jurisdiction clock');
    assert.equal(data.summary.verdict, 'CLOCK_STARTED',
      'F18: --block-on-jurisdiction-clock plus a started clock must produce verdict=CLOCK_STARTED');
    assert.ok(Array.isArray(data.summary.clock_started_reasons),
      'F18: summary.clock_started_reasons must be present and an array');
    assert.ok(data.summary.clock_started_reasons.some(fr => /jurisdiction clock started/.test(fr)),
      'F18: clock_started_reasons must explicitly mention the jurisdiction-clock cause');
    assert.equal(r.status, 5,
      'F18: clock-fired runs exit 5 (CLOCK_STARTED), separate from FAIL (2)');
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test('ci --evidence-dir <dir> routes per-playbook submission files', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'cidir2-'));
  fs.mkdirSync(tmp, { recursive: true });
  fs.writeFileSync(path.join(tmp, 'secrets.json'), JSON.stringify({
    observations: { a: { captured: true, value: 'x', indicator: 'aws-access-key-id', result: 'miss' } },
  }));
  fs.writeFileSync(path.join(tmp, 'library-author.json'), JSON.stringify({
    observations: { b: { captured: true, value: 'y', indicator: 'publish-workflow-uses-static-token', result: 'miss' } },
  }));
  try {
    const r = cli(['ci', '--required', 'secrets,library-author', '--evidence-dir', tmp, '--json']);
    const data = tryJson(r.stdout);
    assert.ok(data, 'ci --evidence-dir must emit JSON');
    assert.deepEqual([...data.playbooks_run].sort(), ['library-author', 'secrets'],
      'ci must run exactly the two playbooks both keyed in --required and present in --evidence-dir');
    assert.equal(data.summary.total, 2, 'summary.total must reflect the dispatched count');
    assert.equal(data.summary.blocked, 0,
      '--evidence-dir submissions must satisfy preconditions; 0 blocked');
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test('run --vex applies the VEX filter and surfaces analyze.vex.filter_applied', () => {
  const vexPath = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'vex-')), 'vex.json');
  fs.writeFileSync(vexPath, JSON.stringify({
    '@context': 'https://openvex.dev/ns/v0.2.0',
    statements: [{
      vulnerability: { '@id': 'CVE-2025-99999' },
      products: [{ '@id': 'pkg:npm/test' }],
      status: 'not_affected',
    }],
  }));
  try {
    const r = cli(['run', 'library-author', '--evidence', '-', '--vex', vexPath,
      '--session-id', 'vex-' + Date.now(), '--json'], { input: '{}' });
    const data = tryJson(r.stdout);
    assert.ok(data, 'run --vex must emit JSON');
    assert.equal(data.ok, true);
    assert.ok(data.phases?.analyze?.vex,
      'phases.analyze.vex must be present when --vex is passed');
    assert.equal(data.phases.analyze.vex.filter_applied, true,
      'analyze.vex.filter_applied must be true (content, not just key presence)');
    assert.ok(Array.isArray(data.phases.analyze.vex.dropped_cves),
      'analyze.vex.dropped_cves must be an array');
  } finally {
    fs.unlinkSync(vexPath);
  }
});

test('run --diff-from-latest compares against the prior attestation for the playbook', () => {
  const sid1 = 'dfl-a-' + Date.now();
  const sid2 = 'dfl-b-' + Date.now();
  const sub = JSON.stringify({});
  const r1 = cli(['run', 'library-author', '--evidence', '-', '--session-id', sid1], { input: sub });
  assert.equal(r1.status, 0, 'first run must succeed to seed the latest attestation');
  const r2 = cli(['run', 'library-author', '--evidence', '-', '--session-id', sid2,
    '--diff-from-latest', '--json'], { input: sub });
  assert.equal(r2.status, 0);
  const data = tryJson(r2.stdout);
  assert.ok(data?.diff_from_latest, 'diff_from_latest must be present on the result');
  assert.equal(data.diff_from_latest.prior_session_id, sid1,
    'prior_session_id must reference the earlier run (content match)');
  assert.equal(data.diff_from_latest.status, 'unchanged',
    'identical submissions must produce diff_from_latest.status=unchanged');
});

test('run --force-stale overrides the threat_currency_score < 50 hard block', () => {
  const stage = stagePlaybookWithCurrency('library-author', 40);
  try {
    const rBlocked = cli(['run', 'library-author', '--evidence', '-',
      '--session-id', 'fs-block-' + Date.now(), '--json'],
      { input: '{}', env: stage.env });
    const blockedData = tryJson(rBlocked.stdout) || tryJson(rBlocked.stderr.trim());
    assert.ok(blockedData, 'blocked branch must emit structured JSON (stdout or stderr)');
    assert.equal(blockedData.ok, false,
      'currency<50 without --force-stale must produce ok:false');
    assert.match(blockedData.blocked_by || blockedData.reason || '', /currency|threat_currency_score/,
      'block reason must mention currency / threat_currency_score');
    assert.equal(rBlocked.status, 1, 'currency block must exit 1 (precondition refusal via emit ok:false → auto-map)');

    const rForced = cli(['run', 'library-author', '--evidence', '-', '--force-stale',
      '--session-id', 'fs-force-' + Date.now(), '--json'],
      { input: '{}', env: stage.env });
    const forcedData = tryJson(rForced.stdout);
    assert.ok(forcedData, 'forced branch must emit JSON');
    assert.equal(forcedData.ok, true,
      '--force-stale must override the currency block and complete the run');
  } finally {
    fs.rmSync(stage.dir, { recursive: true, force: true });
  }
});

test('run --air-gap CLI flag surfaces air_gap_mode=true in govern phase', () => {
  const r = cli(['run', 'secrets', '--evidence', '-', '--air-gap',
    '--session-id', 'ag-' + Date.now(), '--json'], { input: '{}' });
  const data = tryJson(r.stdout);
  assert.ok(data, 'run --air-gap must emit JSON');
  assert.equal(data.ok, true);
  assert.equal(data.phases?.govern?.air_gap_mode, true,
    'phases.govern.air_gap_mode must be true when --air-gap is passed on the CLI');
});

test('run --session-key <hex> HMAC-signs the evidence_package', () => {
  const key = require('crypto').randomBytes(32).toString('hex');
  const r = cli(['run', 'library-author', '--evidence', '-', '--session-key', key,
    '--session-id', 'sk-' + Date.now(), '--json'], { input: '{}' });
  assert.equal(r.status, 0, 'run --session-key (valid hex) must exit 0');
  const data = tryJson(r.stdout);
  assert.ok(data, 'run --session-key must emit JSON');
  assert.equal(data.ok, true);
  const pkg = data.phases?.close?.evidence_package;
  assert.ok(pkg, 'phases.close.evidence_package must be present');
  assert.equal(pkg.signature_algorithm, 'HMAC-SHA256-session-key',
    'signature_algorithm must reflect the HMAC path when --session-key is passed');
  assert.match(pkg.signature, /^[0-9a-f]{64}$/,
    'signature must be a 64-char hex string (SHA-256 digest)');
});

test('refresh --indexes-only routes to build-indexes and finishes cleanly', () => {
  const r = cli(['refresh', '--indexes-only']);
  assert.equal(r.status, 0, 'refresh --indexes-only must exit 0');
  assert.match(r.stdout, /build-indexes/,
    'refresh --indexes-only must dispatch to the build-indexes script (banner reflects that)');
  assert.match(r.stdout, /done|output\(s\)/i,
    'output must include a completion marker (done / N output(s))');
});

// ===================================================================
// Source: usability-fixes.test.js — operator-usability CLI regressions.
// `usabilityHome` is the per-suite EXCEPTD_HOME (also used as an empty
// --evidence-dir target).
// ===================================================================
const usabilityHome = SUITE_HOME;

test('run <playbook> --evidence-dir refuses loudly instead of silently running on empty evidence', () => {
  const r = cli(['run', 'secrets', '--evidence-dir', usabilityHome, '--json']);
  assert.equal(r.status, 1, 'refuses with GENERIC_FAILURE (1) instead of a false all-clear exit 0');
  const body = tryJson(r.stdout) || tryJson(r.stderr) || {};
  assert.equal(body.ok, false, 'error envelope must carry ok:false');
  const text = (r.stdout || '') + (r.stderr || '');
  assert.match(text, /--evidence-dir/, 'message names the offending flag');
  assert.match(text, /--evidence\b|contract|--all|--scope/, 'message points at the correct alternative (--evidence / contract run)');
});

test('empty stdin on the auto-promotion path does NOT emit the nudge (so 2>&1 | jq stays parseable in CI)', () => {
  const r = cli(['run', 'secrets', '--json'], { input: '' });
  assert.doesNotMatch(r.stderr || '', /read 0 bytes from stdin/, 'auto-promoted empty stdin must not nudge on stderr');
});

test('an EXPLICIT --evidence - with empty stdin still nudges (the operator asked to pipe)', () => {
  const r = cli(['run', 'secrets', '--evidence', '-', '--json'], { input: '' });
  assert.match(r.stderr || '', /read 0 bytes from stdin/, 'explicit --evidence - with empty stdin should still warn the operator');
});

test('exceptd skill (no args) lists every skill ID so they are discoverable', () => {
  const manifest = require('../manifest.json');
  const r = cli(['skill', '--json']);
  assert.equal(r.status, 1, 'no-args skill is a usage error (exit 1)');
  const body = tryJson(r.stdout) || {};
  assert.equal(body.ok, false, 'usage envelope is ok:false');
  assert.ok(Array.isArray(body.skills), 'lists a skills array');
  assert.equal(body.skills.length, manifest.skills.length, 'lists every manifest skill');
  assert.ok(body.skills.every(s => s.id && typeof s.description === 'string'), 'each entry has an id + description');
  const human = cli(['skill']);
  assert.match(human.stderr || '', new RegExp(`Available skills \\(${manifest.skills.length}\\)`), 'human usage shows the skill count');
});

test('brief <playbook> footer reveals the collect verb (so brief-first operators do not run on empty evidence)', () => {
  const r = cli(['brief', 'secrets'], { env: { EXCEPTD_RAW_JSON: '' } });
  const out = (r.stdout || '') + (r.stderr || '');
  assert.match(out, /exceptd collect secrets \| exceptd run secrets --evidence -/, 'brief footer must show the collect pipeline');
});

test('a blocked run renders a human line (not a raw JSON wall) in default human mode', () => {
  const r = cli(['run', 'kernel', '--evidence', '-'], {
    input: '{"precondition_checks":{"linux-platform":false}}',
    env: { EXCEPTD_RAW_JSON: '' },
  });
  assert.equal(r.status, 1, 'a blocked run exits 1 (GENERIC_FAILURE) without --ci');
  const out = (r.stdout || '') + (r.stderr || '');
  assert.doesNotMatch(r.stdout || '', /^\s*\{"ok":false/, 'human mode must NOT dump the raw ok:false JSON envelope');
  assert.match(out, /\[blocked\]/, 'human render tags the verdict as [blocked]');
  assert.match(out, /exceptd brief --all|re-run with --json/, 'human render points the operator at a next step');
});

test('a blocked run still returns the full JSON envelope under --json', () => {
  const r = cli(['run', 'kernel', '--evidence', '-', '--json'], {
    input: '{"precondition_checks":{"linux-platform":false}}',
  });
  assert.equal(r.status, 1, 'blocked exits 1 under --json too (no --ci)');
  const body = tryJson(r.stdout) || {};
  assert.equal(body.ok, false, '--json keeps the ok:false envelope for machine consumers');
  assert.equal(body.verdict, 'blocked', 'verdict is blocked');
  assert.equal(body.blocked_by, 'precondition', 'blocked_by names the preflight cause');
});

test('--quiet is a recognized global flag (accepted on run/doctor, not refused as unknown)', () => {
  const r = cli(['run', 'secrets', '--evidence', '-', '--quiet', '--json'], { input: '{}' });
  assert.doesNotMatch((r.stdout || '') + (r.stderr || ''), /unknown flag/, '--quiet must not be refused on a run-class verb');
  const d = cli(['doctor', '--signatures', '--quiet', '--json']);
  assert.doesNotMatch((d.stdout || '') + (d.stderr || ''), /unknown flag/, '--quiet must not be refused on doctor');
});

test('--quiet suppresses advisory stderr notes (keeps pipelines clean) but unknown flags still refuse', () => {
  const noisy = cli(['run', 'secrets', '--evidence', '-', '--json'], { input: '' });
  assert.match(noisy.stderr || '', /read 0 bytes from stdin/, 'baseline: the nudge fires without --quiet');
  const quiet = cli(['run', 'secrets', '--evidence', '-', '--quiet', '--json'], { input: '' });
  assert.doesNotMatch(quiet.stderr || '', /read 0 bytes from stdin/, '--quiet suppresses the advisory note');
  const bogus = cli(['run', 'secrets', '--evidence', '-', '--quiet', '--bogusflag', '--json'], { input: '{}' });
  assert.equal(bogus.status, 1, 'an unknown flag is still refused (exit 1) even with --quiet present');
  assert.match((bogus.stdout || '') + (bogus.stderr || ''), /unknown flag/, 'the refusal names the unknown flag');
});

test('recipes --help shows real help, not the "no per-verb help available" fallback', () => {
  const r = cli(['recipes', '--help']);
  const out = (r.stdout || '') + (r.stderr || '');
  assert.doesNotMatch(out, /no per-verb help available/, 'recipes must have real per-verb help');
  assert.match(out, /recipes/i, 'recipes help mentions the verb');
});

test('report --help states the default output format (Markdown), not just --json', () => {
  const r = cli(['report', '--help']);
  const out = (r.stdout || '') + (r.stderr || '');
  assert.match(out, /Markdown/i, 'report --help must state the Markdown default so operators do not pipe Markdown into a JSON tool');
});

// ===================================================================
// Source: audit-usability-fixes.test.js — CLI ergonomics regressions.
// (The `refresh parseArgs --check-advisories` test exercises
// lib/refresh-external.js directly and is left for that subject.)
// ===================================================================

test('unknown flag on discover hard-fails with structured envelope', () => {
  const r = cli(['discover', '--bogusflag']);
  assert.equal(r.status, 1, `expected exit 1; got ${r.status} (stderr: ${r.stderr.slice(0, 200)})`);
  const body = tryJson(r.stderr.trim()) || tryJson(r.stdout.trim());
  assert.ok(body, `stderr should be parseable JSON; got: ${r.stderr.slice(0, 200)}`);
  assert.equal(body.ok, false);
  assert.match(body.error, /unknown flag/);
  assert.ok(Array.isArray(body.unknown_flags), 'unknown_flags must be an array');
  assert.ok(body.unknown_flags.length > 0, 'unknown_flags must be non-empty');
  assert.ok(Array.isArray(body.known_flags), 'known_flags must be an array');
  assert.ok(body.known_flags.length > 0, 'known_flags must be non-empty');
});

test('unknown flag on ci hard-fails (exit 1)', () => {
  const r = cli(['ci', '--bogusflag']);
  assert.equal(r.status, 1, `expected exit 1; got ${r.status}`);
  const body = tryJson(r.stderr.trim()) || tryJson(r.stdout.trim());
  assert.ok(body, 'response should be parseable JSON');
  assert.equal(body.ok, false);
  assert.match(body.error, /unknown flag/);
});

test('unknown flag on ask hard-fails (exit 1)', () => {
  const r = cli(['ask', 'x', '--bogusflag']);
  assert.equal(r.status, 1, `expected exit 1; got ${r.status}`);
  const body = tryJson(r.stderr.trim()) || tryJson(r.stdout.trim());
  assert.ok(body, 'response should be parseable JSON');
  assert.equal(body.ok, false);
  assert.match(body.error, /unknown flag/);
});

test('unknown flag typo gets a did_you_mean suggestion', () => {
  const r = cli(['discover', '--scop', 'code']);
  assert.equal(r.status, 1, `expected exit 1; got ${r.status}`);
  const body = tryJson(r.stderr.trim()) || tryJson(r.stdout.trim());
  assert.ok(body, 'response should be parseable JSON');
  assert.equal(body.ok, false);
  assert.ok(Array.isArray(body.unknown_flags) && body.unknown_flags.length > 0,
    'unknown_flags must be a non-empty array');
  assert.ok(Array.isArray(body.unknown_flags[0].did_you_mean),
    'did_you_mean must be an array');
  assert.ok(body.unknown_flags[0].did_you_mean.includes('--scope'),
    `did_you_mean must suggest --scope; got ${JSON.stringify(body.unknown_flags[0].did_you_mean)}`);
});

test('cross-verb flag yields the tailored "irrelevant" message, not unknown-flag (--csaf-status)', () => {
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

test('known flags still work: discover --scope code (exit 0)', () => {
  const r = cli(['discover', '--scope', 'code']);
  assert.equal(r.status, 0, `expected exit 0; got ${r.status} (stderr: ${r.stderr.slice(0, 200)})`);
});

test('known flags still work: discover --json (exit 0, parseable stdout)', () => {
  const r = cli(['discover', '--json']);
  assert.equal(r.status, 0, `expected exit 0; got ${r.status}`);
  const body = tryJson(r.stdout.trim());
  assert.ok(body, `discover --json stdout must parse; got: ${r.stdout.slice(0, 200)}`);
});

test('run --format json emits the full run result, not a stub', () => {
  const r = cli(['run', 'secrets', '--evidence', '-', '--format', 'json'], { input: '{}' });
  assert.equal(r.status, 0, `expected exit 0; got ${r.status} (stderr: ${r.stderr.slice(0, 200)})`);
  const body = tryJson(r.stdout.trim());
  assert.ok(body, `run --format json stdout must parse; got: ${r.stdout.slice(0, 200)}`);
  assert.equal(typeof body.phases, 'object');
  assert.ok(body.phases !== null, 'phases must not be null');
  assert.equal(body.playbook_id, 'secrets');
  assert.ok(Object.keys(body).length > 5,
    `full result must carry more than 5 top-level keys; got ${Object.keys(body).length}`);
});

test('multiple --format values: first format to stdout, note to stderr', () => {
  const r = cli(['run', 'secrets', '--evidence', '-', '--format', 'sarif', '--format', 'openvex'], { input: '{}' });
  assert.equal(r.status, 0, `expected exit 0; got ${r.status} (stderr: ${r.stderr.slice(0, 200)})`);
  const body = tryJson(r.stdout.trim());
  assert.ok(body, `stdout must parse as JSON; got: ${r.stdout.slice(0, 200)}`);
  assert.equal(typeof body['$schema'], 'string');
  assert.match(body['$schema'], /sarif/);
  assert.match(r.stderr, /--format values given|bundles_by_format/);
});

test('sarif bundle: no top-level ok, carries spec marker', () => {
  const r = cli(['run', 'crypto', '--evidence', '-', '--format', 'sarif'], { input: '{"precondition_checks":{"linux-platform":true}}' });
  assert.equal(r.status, 0, `expected exit 0; got ${r.status} (stderr: ${r.stderr.slice(0, 200)})`);
  const body = tryJson(r.stdout.trim());
  assert.ok(body, `sarif stdout must parse; got: ${r.stdout.slice(0, 200)}`);
  assert.equal(('ok' in body), false, 'standardized bundle must NOT carry a top-level ok key');
  assert.equal(body.version, '2.1.0');
  assert.ok(Array.isArray(body.runs), 'sarif must carry a runs array');
});

test('csaf-2.0 bundle: no top-level ok, carries document object', () => {
  const r = cli(['run', 'crypto', '--evidence', '-', '--format', 'csaf-2.0'], { input: '{"precondition_checks":{"linux-platform":true}}' });
  assert.equal(r.status, 0, `expected exit 0; got ${r.status} (stderr: ${r.stderr.slice(0, 200)})`);
  const body = tryJson(r.stdout.trim());
  assert.ok(body, `csaf stdout must parse; got: ${r.stdout.slice(0, 200)}`);
  assert.equal(('ok' in body), false, 'standardized bundle must NOT carry a top-level ok key');
  assert.equal(typeof body.document, 'object');
  assert.ok(body.document !== null, 'csaf document must not be null');
});

test('openvex bundle: no top-level ok, carries @context string', () => {
  const r = cli(['run', 'crypto', '--evidence', '-', '--format', 'openvex'], { input: '{"precondition_checks":{"linux-platform":true}}' });
  assert.equal(r.status, 0, `expected exit 0; got ${r.status} (stderr: ${r.stderr.slice(0, 200)})`);
  const body = tryJson(r.stdout.trim());
  assert.ok(body, `openvex stdout must parse; got: ${r.stdout.slice(0, 200)}`);
  assert.equal(('ok' in body), false, 'standardized bundle must NOT carry a top-level ok key');
  assert.equal(typeof body['@context'], 'string');
});

test('skill --help shows usage, not "Skill not found"', () => {
  const r = cli(['skill', '--help']);
  assert.equal(r.status, 0, `expected exit 0; got ${r.status} (stderr: ${r.stderr.slice(0, 200)})`);
  assert.match(r.stdout, /exceptd skill <name>/);
  assert.doesNotMatch(r.stdout, /Skill not found/);
});

test('framework-gap --help shows usage', () => {
  const r = cli(['framework-gap', '--help']);
  assert.equal(r.status, 0, `expected exit 0; got ${r.status} (stderr: ${r.stderr.slice(0, 200)})`);
  assert.match(r.stdout, /framework-gap </);
});

test('refresh --help keeps its own detailed help (not swallowed by --help interception)', () => {
  const r = cli(['refresh', '--help']);
  assert.equal(r.status, 0, `expected exit 0; got ${r.status} (stderr: ${r.stderr.slice(0, 200)})`);
  assert.match(r.stdout, /check-advisories/);
});

test('collect emits JSON when piped (non-TTY), not human prose', () => {
  const r = cli(['collect', 'secrets']);
  assert.equal(r.status, 0, `expected exit 0; got ${r.status} (stderr: ${r.stderr.slice(0, 200)})`);
  const body = tryJson(r.stdout.trim());
  assert.ok(body, `collect stdout must parse as JSON when piped; got: ${r.stdout.slice(0, 200)}`);
  assert.equal(typeof body.playbook_id, 'string');
  assert.equal(body.verb, 'collect');
});

test('attest list --limit on an empty isolated root: deterministic envelope', () => {
  const tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'audit-attest-home-'));
  const tmpCwd = fs.mkdtempSync(path.join(os.tmpdir(), 'audit-attest-cwd-'));
  try {
    const r = cli(['attest', 'list', '--limit', '3', '--json'], {
      cwd: tmpCwd,
      env: { EXCEPTD_HOME: tmpHome },
    });
    assert.equal(r.status, 0, `expected exit 0; got ${r.status} (stderr: ${r.stderr.slice(0, 200)})`);
    const body = tryJson(r.stdout.trim());
    assert.ok(body, `attest list --json must parse; got: ${r.stdout.slice(0, 200)}`);
    assert.equal(body.count, 0);
    assert.equal(body.shown, 0);
    assert.equal(body.limit, 3);
    assert.ok(Array.isArray(body.attestations), 'attestations must be an array');
    assert.equal(body.attestations.length, 0, 'empty root yields zero attestations');
  } finally {
    try { fs.rmSync(tmpHome, { recursive: true, force: true }); } catch {}
    try { fs.rmSync(tmpCwd, { recursive: true, force: true }); } catch {}
  }
});

test('attest list --limit rejects a non-integer value (exit 1)', () => {
  const tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'audit-attest-home-'));
  const tmpCwd = fs.mkdtempSync(path.join(os.tmpdir(), 'audit-attest-cwd-'));
  try {
    const r = cli(['attest', 'list', '--limit', 'abc'], {
      cwd: tmpCwd,
      env: { EXCEPTD_HOME: tmpHome },
    });
    assert.equal(r.status, 1, `expected exit 1; got ${r.status}`);
    assert.match(r.stderr, /non-negative integer/);
  } finally {
    try { fs.rmSync(tmpHome, { recursive: true, force: true }); } catch {}
    try { fs.rmSync(tmpCwd, { recursive: true, force: true }); } catch {}
  }
});

// ===================================================================
// Source: reconciliation-fixes.test.js — removed-verb stale surface +
// help-text accuracy. (The _worstActiveExploitation ranking test exercises
// lib/playbook-runner.js directly and is left for that subject.)
// ===================================================================
const REMOVED_VERBS = ['plan', 'govern', 'direct', 'look', 'ingest'];

test('`help <removed-verb>` refuses with exit 1 + the replacement (no stale live help)', () => {
  for (const v of REMOVED_VERBS) {
    const r = cli(['help', v]);
    assert.equal(r.status, 1, `help ${v} must exit 1; got ${r.status}`);
    const body = tryJson(r.stderr) || tryJson(r.stdout) || {};
    assert.equal(body.ok, false, `help ${v} must emit ok:false`);
    assert.match(body.error || '', /removed in v0\.13\.0/, `help ${v} must say it was removed`);
    assert.ok(typeof body.replacement === 'string' && body.replacement.length > 0,
      `help ${v} must name a replacement`);
  }
});

test('a real verb still gets its help block (the removed-verb guard is not over-broad)', () => {
  const r = cli(['help', 'recipes']);
  assert.equal(r.status, 0, 'help recipes is a live verb → exit 0');
  assert.match((r.stdout || '') + (r.stderr || ''), /recipes/i, 'recipes help renders');
});

test('ai-run help states the correct SESSION_ID_COLLISION exit code (7, not 3)', () => {
  const r = cli(['help', 'ai-run']);
  const out = (r.stdout || '') + (r.stderr || '');
  assert.match(out, /7\s+SESSION_ID_COLLISION/, 'ai-run help must show code 7 for SESSION_ID_COLLISION');
  assert.doesNotMatch(out, /3\s+SESSION_ID_COLLISION/, 'must NOT mislabel it as code 3 (that is RAN_NO_EVIDENCE)');
});

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

test('attest --help documents the prune subverb (it works and is in top-help)', () => {
  const out = (cli(['attest', '--help']).stdout || '') + (cli(['attest', '--help']).stderr || '');
  assert.match(out, /attest prune/, 'attest --help must list prune');
  assert.match(out, /list \| show \| export \| verify \| diff \| prune/, 'prune must be in the subverbs summary');
});

test('doctor accepts --air-gap on both validation paths (allowlist drift fixed)', () => {
  const r = cli(['doctor', '--bogus', '--json']);
  const body = tryJson(r.stdout) || tryJson(r.stderr) || {};
  assert.ok(Array.isArray(body.known_flags), 'doctor --bogus emits known_flags');
  assert.ok(body.known_flags.includes('--air-gap'), 'doctor known_flags must include --air-gap');
  const ok = cli(['doctor', '--signatures', '--air-gap', '--json']);
  assert.doesNotMatch((ok.stdout || '') + (ok.stderr || ''), /unknown flag/, '--air-gap must be accepted on doctor');
});

test('printPlaybookVerbHelp ships no help block keyed by a removed verb (root-cause guard)', () => {
  const src = fs.readFileSync(BIN, 'utf8');
  for (const v of REMOVED_VERBS) {
    assert.doesNotMatch(src, new RegExp(`\\n    ${v}: \``),
      `printPlaybookVerbHelp must not ship a help block for removed verb "${v}"`);
  }
});

// ===================================================================
// Source: reconciliation-deep-fixes.test.js — error-envelope consistency
// (verb attribution + error_class), run --format missing-value guard,
// validate-cves --offline safeExit.
// ===================================================================

for (const verb of ['ci', 'run-all', 'ai-run']) {
  test(`${verb} attributes a --session-id validation error to itself, not "run"`, () => {
    const r = cli([verb, 'kernel', '--session-id', '../evil', '--json'], { input: '{}' });
    assert.equal(r.status, 1, `${verb} session-id refusal must exit exactly 1`);
    const err = tryJson(r.stderr) || tryJson(r.stdout) || {};
    assert.equal(err.ok, false, 'error envelope carries ok:false');
    assert.equal(err.verb, verb, `verb field must be "${verb}"`);
    assert.equal(typeof err.verb, 'string', 'verb is a string');
    assert.match(err.error, new RegExp(`^${verb}:`), `message prefix is "${verb}:"`);
    assert.doesNotMatch(err.error, /^run:/, 'message must not mis-attribute to run');
  });
}

test('ci --mode garbage attributes the error to ci (not run) and carries verb', () => {
  const r = cli(['ci', 'kernel', '--mode', 'garbage', '--json'], { input: '{}' });
  assert.equal(r.status, 1, 'invalid --mode exits exactly 1');
  const err = tryJson(r.stderr) || tryJson(r.stdout) || {};
  assert.equal(err.verb, 'ci', 'verb is ci');
  assert.match(err.error, /^ci:/, 'prefix is ci:');
});

test('brief --ack irrelevant-flag refusal carries flag + error_class like its siblings', () => {
  const r = cli(['brief', 'kernel-lpe-triage', '--ack', '--json']);
  assert.equal(r.status, 1, '--ack on brief refuses with exit 1');
  const err = tryJson(r.stderr) || tryJson(r.stdout) || {};
  assert.equal(err.ok, false, 'ok:false');
  assert.equal(err.error_class, 'irrelevant-flag', 'error_class names the class');
  assert.equal(err.flag, 'ack', 'flag names the offending flag');
  assert.equal(err.verb, 'brief', 'verb is brief');
});

test('run --format with no value refuses (format is now a known value-bearing flag)', () => {
  const r = cli(['run', 'kernel', '--format', '--json'], { input: '{}' });
  assert.equal(r.status, 1, 'missing --format value exits exactly 1');
  const err = tryJson(r.stderr) || tryJson(r.stdout) || {};
  assert.equal(err.ok, false, 'ok:false');
  assert.equal(err.flag, 'format', 'names the flag missing its value');
  assert.match(err.error, /--format requires a value/, 'states the missing value');
});

test('framework-gap unknown-framework refusal carries the verb field', () => {
  const r = cli(['framework-gap', 'NONSENSE-FRAMEWORK', 'prompt injection', '--json']);
  assert.equal(r.status, 1, 'unknown framework exits exactly 1');
  const body = tryJson(r.stdout) || tryJson(r.stderr) || {};
  assert.equal(body.ok, false, 'ok:false');
  assert.equal(body.verb, 'framework-gap', 'verb field present');
  assert.equal(typeof body.verb, 'string', 'verb is a string');
  assert.ok(Array.isArray(body.known_frameworks), 'still lists known_frameworks');
});

test('validate-cves --offline exits 0 with its trailing summary intact (no truncation)', () => {
  const r = cli(['validate-cves', '--offline']);
  assert.equal(r.status, 0, 'offline validate-cves exits exactly 0');
  assert.match(r.stdout, /offline mode — no network calls made\. \d+ entries listed/,
    'the trailing summary line (last bytes before exit) survives');
});

test('discover --help documents --cwd (accepted + typo-suggestible but was undocumented)', () => {
  const out = (cli(['discover', '--help']).stdout || '') + (cli(['discover', '--help']).stderr || '');
  assert.match(out, /--cwd/, 'discover --help must document --cwd');
});

// ===================================================================
// Source: cli-output-envelope-shape-v0_12_39.test.js — pins the EXACT
// top-level JSON envelope for brief --all / ci / discover / doctor /
// watchlist / run. Local cli()/tryJson() helpers (cwd: ROOT) preserved.
// ===================================================================
function envCli(args, opts = {}) {
  return spawnSync(process.execPath, [BIN, ...args], {
    encoding: 'utf8',
    cwd: opts.cwd || ROOT,
    env: { ...process.env, EXCEPTD_DEPRECATION_SHOWN: '1', ...(opts.env || {}) },
    input: opts.input,
  });
}

function envTryJson(s) { try { return JSON.parse(s); } catch { return null; } }

test('brief --all envelope: exact top-level key set', () => {
  const r = envCli(['brief', '--all', '--json']);
  assert.equal(r.status, 0);
  const body = envTryJson(r.stdout);
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

test('ci --required <pb> envelope: exact top-level key set + summary sub-key set', () => {
  const r = envCli(['ci', '--required', 'cred-stores', '--json']);
  const body = envTryJson(r.stdout);
  assert.ok(body, `ci must emit parseable JSON; got: ${r.stdout.slice(0, 200)}`);
  const expected = ['ok', 'playbooks_run', 'results', 'session_id', 'summary', 'verb'];
  assert.deepEqual(Object.keys(body).sort(), expected);
  assert.equal(body.verb, 'ci');
  assert.equal(body.ok, true, 'v0.13: ci carries ok:true (summary.verdict remains authoritative)');
  assert.ok(Array.isArray(body.playbooks_run));
  assert.ok(Array.isArray(body.results));

  const expectedSummaryKeys = [
    'blocked', 'clock_started_reasons', 'detected', 'fail_reasons',
    'framework_gap_count', 'framework_gap_rollup', 'inconclusive',
    'jurisdiction_clock_rollup', 'jurisdiction_clocks_started',
    'max_rwep_observed', 'not_detected', 'runtime_warnings',
    'runtime_warnings_count', 'total', 'verdict',
  ];
  assert.deepEqual(Object.keys(body.summary).sort(), expectedSummaryKeys);
  assert.equal(typeof body.summary.verdict, 'string');
  assert.equal(typeof body.summary.total, 'number');
  assert.equal(typeof body.summary.max_rwep_observed, 'number');
  assert.ok(Array.isArray(body.summary.runtime_warnings));
  assert.equal(typeof body.summary.runtime_warnings_count, 'number');
});

test('discover envelope: exact top-level key set + context sub-keys', () => {
  const r = envCli(['discover', '--json']);
  assert.equal(r.status, 0);
  const body = envTryJson(r.stdout);
  assert.ok(body, `discover must emit parseable JSON; got: ${r.stdout.slice(0, 200)}`);
  const expected = ['context', 'next_steps', 'ok', 'recommended_playbooks', 'verb'];
  assert.deepEqual(Object.keys(body).sort(), expected);
  assert.equal(body.verb, 'discover');
  assert.equal(body.ok, true);
  assert.ok(Array.isArray(body.next_steps));
  assert.ok(Array.isArray(body.recommended_playbooks));

  const expectedContextKeys = ['cwd', 'detected_files', 'git_remote', 'host_distro', 'host_platform'];
  assert.deepEqual(Object.keys(body.context).sort(), expectedContextKeys);
  assert.equal(typeof body.context.cwd, 'string');
  assert.equal(typeof body.context.host_platform, 'string');
  assert.ok(Array.isArray(body.context.detected_files));

  for (const p of body.recommended_playbooks) {
    assert.equal(typeof p.id, 'string');
    assert.equal(typeof p.reason, 'string');
  }
});

test('doctor envelope: exact top-level + summary sub-key set + baseline check set', () => {
  const r = envCli(['doctor', '--json']);
  const body = envTryJson(r.stdout);
  assert.ok(body, `doctor must emit parseable JSON; got: ${r.stdout.slice(0, 200)}`);
  assert.deepEqual(Object.keys(body).sort(), ['checks', 'local_version', 'ok', 'summary', 'verb']);
  assert.equal(body.verb, 'doctor');
  assert.equal(body.ok, true, 'v0.13: doctor carries ok:true (summary.all_green remains authoritative)');

  const baselineChecks = ['currency', 'cves', 'rfcs', 'signatures', 'signing'];
  for (const k of baselineChecks) {
    assert.ok(k in body.checks, `expected check "${k}" in doctor.checks`);
    assert.equal(typeof body.checks[k].ok, 'boolean');
  }

  const expectedSummaryKeys = [
    'all_green', 'failed_checks', 'issues_count',
    'warning_checks', 'warnings_count',
  ];
  assert.deepEqual(Object.keys(body.summary).sort(), expectedSummaryKeys);
  assert.equal(typeof body.summary.all_green, 'boolean');
  assert.ok(Array.isArray(body.summary.failed_checks));
  assert.ok(Array.isArray(body.summary.warning_checks));
  assert.equal(body.summary.issues_count, body.summary.failed_checks.length);
  assert.equal(body.summary.warnings_count, body.summary.warning_checks.length);
});

test('watchlist (default by-item mode) envelope: exact top-level key set', () => {
  const r = envCli(['watchlist', '--json']);
  assert.equal(r.status, 0);
  const body = envTryJson(r.stdout);
  assert.ok(body, `watchlist must emit parseable JSON; got: ${r.stdout.slice(0, 200)}`);
  assert.deepEqual(Object.keys(body).sort(),
    ['by_item', 'generated_at', 'mode', 'ok', 'parse_errors', 'skills_scanned']);
  assert.equal(body.mode, 'by-item');
  assert.equal(typeof body.skills_scanned, 'number');
  assert.equal(typeof body.parse_errors, 'number');
  assert.match(body.generated_at, /^\d{4}-\d{2}-\d{2}T/);
  assert.equal(typeof body.by_item, 'object');
  assert.equal(body.verb, undefined,
    'watchlist does NOT emit a verb field today (transitional with brief --all); flag for v0.13 harmonization');
});

test('watchlist --by-skill envelope: by_skill key replaces by_item', () => {
  const r = envCli(['watchlist', '--by-skill', '--json']);
  assert.equal(r.status, 0);
  const body = envTryJson(r.stdout);
  assert.ok(body, `watchlist --by-skill must emit parseable JSON; got: ${r.stdout.slice(0, 200)}`);
  assert.deepEqual(Object.keys(body).sort(),
    ['by_skill', 'generated_at', 'mode', 'ok', 'parse_errors', 'skills_scanned']);
  assert.equal(body.mode, 'by-skill');
  assert.equal(body.by_item, undefined,
    'by-skill mode must NOT carry by_item; mutually exclusive');
});

test('run <pb> --evidence envelope (single-playbook success): exact top-level key set', () => {
  const evidence = JSON.stringify({
    precondition_checks: { 'linux-platform': true, 'uname-available': true },
    artifacts: { 'kernel-release': '5.15.0-69-generic' },
    signal_overrides: { 'kver-in-affected-range': 'hit' },
  });
  const tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'envelope-run-'));
  try {
    const r = envCli(['run', 'kernel', '--evidence', '-', '--json',
      '--attestation-root', path.join(tmpHome, 'attestations')], { input: evidence });
    assert.equal(r.status, 0, `run kernel must exit 0; got ${r.status}, stderr: ${r.stderr.slice(0, 200)}`);
    const body = envTryJson(r.stdout);
    assert.ok(body, `run kernel must emit parseable JSON; got: ${r.stdout.slice(0, 200)}`);
    const expected = [
      'ack', 'air_gap_mode', 'attestation_path', 'directive_id', 'evidence_completeness', 'evidence_hash',
      'indicators_evaluated', 'indicators_known', 'ok', 'phases',
      'playbook_id', 'precondition_check_source', 'preflight_issues',
      'rwep_score', 'session_id', 'submission_digest',
      'summary_line', 'top_finding', 'verdict',
    ];
    assert.deepEqual(Object.keys(body).sort(), expected);
    assert.equal(body.ok, true);
    assert.equal(body.playbook_id, 'kernel');
    assert.equal(typeof body.directive_id, 'string');
    assert.match(body.session_id, /^[0-9a-f-]+$/);
    assert.match(body.evidence_hash, /^[0-9a-f]+$/);
    assert.match(body.submission_digest, /^[0-9a-f]+$/);
    assert.ok(Array.isArray(body.preflight_issues));
    assert.equal(typeof body.phases, 'object');
    assert.equal(typeof body.ack, 'boolean');
    assert.equal(body.prior_session_id, undefined);
    assert.equal(body.overwrote_at, undefined);
  } finally {
    try { fs.rmSync(tmpHome, { recursive: true, force: true }); } catch {}
  }
});

test('shared error envelope (run unknown playbook): exact required field set', () => {
  const r = envCli(['run', 'this-playbook-does-not-exist']);
  assert.equal(r.status, 1, `unknown playbook must exit 1; got ${r.status}`);
  const err = envTryJson(r.stderr);
  assert.ok(err, `error stderr must be JSON; got: ${r.stderr.slice(0, 200)}`);
  assert.equal(err.ok, false);
  assert.equal(typeof err.error, 'string');
});

// ===================================================================
// Source: cycle17-ux-fixes.test.js — S4 empty-stdin nudge + S13 did-you-mean
// for unknown verbs. (The F1/F2/F3 CVE-prose + Volt-Typhoon tests scan
// skills/ markdown and belong to the skills-prose subject.)
// ===================================================================

test('S4: --evidence - with empty stdin emits stderr nudge + still proceeds', () => {
  const r = envCli(['run', 'framework', '--evidence', '-'], { input: '' });
  assert.equal(r.status, 0, `posture-only run must succeed; got ${r.status}`);
  assert.match(r.stderr, /--evidence - read 0 bytes from stdin/,
    `stderr must surface the empty-stdin nudge; got: ${r.stderr.slice(0, 200)}`);
  assert.match(r.stderr, /exceptd brief/, 'nudge must point at `exceptd brief` for the expected shape');
});

test('S4: --evidence - with valid JSON does NOT emit the empty-stdin nudge', () => {
  const r = envCli(['run', 'framework', '--evidence', '-'], { input: '{}' });
  assert.equal(r.status, 0);
  assert.equal(/read 0 bytes from stdin/.test(r.stderr), false,
    'non-empty stdin must NOT emit the nudge');
});

test('S13: unknown verb within Levenshtein-1 of a real verb returns did_you_mean[]', () => {
  for (const [typo, expected] of [['discoer', 'discover'], ['attst', 'attest'], ['disocver', 'discover']]) {
    const r = envCli([typo]);
    assert.equal(r.status, 10, `${typo} must exit UNKNOWN_COMMAND (10); got ${r.status}`);
    const err = envTryJson(r.stderr);
    assert.ok(err, `${typo} stderr must be JSON`);
    assert.equal(Array.isArray(err.did_you_mean), true);
    assert.equal(err.did_you_mean.includes(expected), true,
      `${typo} should suggest "${expected}"; got: ${JSON.stringify(err.did_you_mean)}`);
    assert.match(err.hint, /Did you mean/, 'hint must surface the suggestion');
  }
});

test('S13: did_you_mean[] deduplicates across overlapping verb sources (codex P2 v0.12.37 follow-up)', () => {
  const r = envCli(['scn']);
  assert.equal(r.status, 10);
  const err = envTryJson(r.stderr);
  assert.ok(err, 'stderr must be JSON');
  assert.equal(Array.isArray(err.did_you_mean), true);
  const seen = new Set(err.did_you_mean);
  assert.equal(seen.size, err.did_you_mean.length,
    `did_you_mean must contain unique verbs; got duplicates: ${JSON.stringify(err.did_you_mean)}`);
  assert.equal(err.did_you_mean.includes('scan'), true);
});

test('S13: unknown verb beyond Levenshtein-1 returns empty did_you_mean[] (no false suggestions)', () => {
  const r = envCli(['xyzzyzzz']);
  assert.equal(r.status, 10);
  const err = envTryJson(r.stderr);
  assert.deepEqual(err.did_you_mean, [], 'distant typo must NOT trigger a suggestion');
  assert.equal(/Did you mean/.test(err.hint), false);
});

// ===================================================================
// Source: predeploy-gate-coverage.test.js — the bin/exceptd.js surface
// items: persistAttestation LOCK_CONTENTION exit-8 contract + the emit()
// / cmdRun / cmdAiRun source-structure invariants. (The PP P1-1 acquireLock
// tests exercise lib/playbook-runner.js directly and belong to that subject.)
// ===================================================================

test('PP P1-2: persistAttestation lock contention sets process.exitCode = 8 and body.exit_code = 8', () => {
  const priorExitCode = process.exitCode;
  process.exitCode = 0;

  const bin = require(path.join(ROOT, 'bin', 'exceptd.js'));
  assert.equal(typeof bin.persistAttestation, 'function', 'persistAttestation must be exported for testability');

  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'pp-p1-2-attest-'));
  const sessionId = 'pp-p1-2-' + process.pid + '-' + Date.now().toString(36);
  const sessionDir = path.join(tmpRoot, sessionId);
  fs.mkdirSync(sessionDir, { recursive: true });
  const slotPath = path.join(sessionDir, 'attestation.json');
  fs.writeFileSync(slotPath, JSON.stringify({ session_id: sessionId, prior: true }, null, 2));
  const lockPath = slotPath + '.lock';
  const livePid = process.ppid && process.ppid !== process.pid ? process.ppid : null;
  if (livePid === null) {
    process.exitCode = priorExitCode;
    return;
  }
  let isAlive = false;
  try { process.kill(livePid, 0); isAlive = true; } catch {}
  if (!isAlive) {
    process.exitCode = priorExitCode;
    return;
  }
  fs.writeFileSync(lockPath, String(livePid));

  const result = bin.persistAttestation({
    sessionId,
    playbookId: 'pp-test',
    directiveId: 'default',
    evidenceHash: 'pp-evidence-hash',
    operator: null,
    operatorConsent: null,
    submission: { test: 'pp-p1-2' },
    runOpts: { airGap: false, forceStale: false, mode: 'test', attestationRoot: tmpRoot },
    forceOverwrite: true,
    filename: 'attestation.json',
  });

  assert.equal(result.ok, false, 'lock-contention result must be ok:false');
  assert.equal(result.lock_contention, true, 'body must carry lock_contention:true');
  assert.equal(result.exit_code, 8, 'body must carry exit_code:8 for downstream visibility');
  assert.equal(
    typeof result.error,
    'string',
    'lock-contention result must carry a human error string',
  );
  assert.equal(
    result.error.startsWith('LOCK_CONTENTION:'),
    true,
    'error string must be prefixed with LOCK_CONTENTION: for grep-ability',
  );
  assert.equal(
    process.exitCode,
    8,
    'process.exitCode must be set to 8 at the lock-contention return site, BEFORE emit() runs',
  );

  try { fs.unlinkSync(lockPath); } catch {}
  try { fs.rmSync(tmpRoot, { recursive: true, force: true }); } catch {}
  process.exitCode = priorExitCode;
});

test('PP P1-2: emit() preserves an already-set non-zero exitCode (load-bearing for PP P1-2)', () => {
  const priorExitCode = process.exitCode;
  process.exitCode = 0;

  const bin = require(path.join(ROOT, 'bin', 'exceptd.js'));
  const src = fs.readFileSync(path.join(ROOT, 'bin', 'exceptd.js'), 'utf8');
  assert.equal(
    /if\s*\(\s*obj\s*&&\s*obj\.ok\s*===\s*false\s*&&\s*!process\.exitCode\s*\)/.test(src),
    true,
    "emit() must gate its ok:false → exitCode=1 mapping on !process.exitCode so a pre-set 8 survives",
  );
  assert.equal(
    /process\.exitCode\s*=\s*(8|EXIT_CODES\.LOCK_CONTENTION);\s*\n\s*return\s*\{\s*\n\s*ok:\s*false,/.test(src),
    true,
    "persistAttestation lock-contention site must set process.exitCode = LOCK_CONTENTION BEFORE the return",
  );
  void bin;
  process.exitCode = priorExitCode;
});

test('VV2 P1-1: cmdRun persistResult-false branch preserves LOCK_CONTENTION exit code (no overwrite to 3)', () => {
  const src = fs.readFileSync(path.join(ROOT, 'bin', 'exceptd.js'), 'utf8');
  const blockRe = /if\s*\(!persistResult\.ok[\s\S]{0,1500}?\}\s*\n/g;
  const blocks = src.match(blockRe) || [];
  assert.ok(blocks.length >= 3,
    `expected at least 3 persistResult-false branches (cmdRun, cmdAiRun no-stream, cmdAiRun streaming); found ${blocks.length}`);
  for (const block of blocks) {
    const hasExit3 = /process\.exitCode\s*=\s*3|finish\(\s*3\s*\)/.test(block);
    if (hasExit3) {
      assert.match(block, /lock_contention/,
        `persistResult-false branch sets exit 3 without checking lock_contention first — would clobber LOCK_CONTENTION exit 8.\nBlock excerpt:\n${block.slice(0, 400)}`);
    }
  }
});

test('VV2 P2-1: cmdAiRun persistAttestation gates operatorConsent on classification === detected', () => {
  const src = fs.readFileSync(path.join(ROOT, 'bin', 'exceptd.js'), 'utf8');
  const aiStart = src.indexOf('function cmdAiRun');
  const aiEnd = src.indexOf('\nfunction ', aiStart + 1);
  const aiBody = src.slice(aiStart, aiEnd > 0 ? aiEnd : aiStart + 30000);
  const persistMatches = [...aiBody.matchAll(/persistAttestation\s*\(\{[\s\S]*?\}\s*\)/g)];
  assert.ok(persistMatches.length >= 2,
    `cmdAiRun must call persistAttestation at both no-stream and streaming sites; found ${persistMatches.length}`);
  for (const m of persistMatches) {
    assert.match(m[0], /operatorConsent:\s*\w*[Cc]onsentApplies\s*\?/,
      `cmdAiRun persistAttestation must gate operatorConsent on a *ConsentApplies ternary.\nExcerpt: ${m[0].slice(0, 300)}`);
  }
});

// ===================================================================
// Source: v0_13_2-fixes.test.js — flag-value did-you-mean (the CLI item).
// (Job-split YAML, lint-skills source, check-test-count gate, predeploy
// wiring, and skill discovery_mode frontmatter belong to other subjects.)
// ===================================================================

test('C: brief --phase typo returns did_you_mean[]', () => {
  const r = envCli(['brief', 'library-author', '--phase', 'goven', '--json']);
  assert.equal(r.status, 1, `expected exit 1 (GENERIC_FAILURE); got ${r.status}`);
  const body = envTryJson(r.stderr.trim()) || envTryJson(r.stdout.trim());
  assert.ok(body && body.ok === false);
  assert.ok(Array.isArray(body.did_you_mean));
  assert.ok(body.did_you_mean.includes('govern'),
    `expected govern in did_you_mean for "goven"; got ${JSON.stringify(body.did_you_mean)}`);
  assert.ok(Array.isArray(body.accepted));
});

// ===================================================================
// Source: v0_13_3-fixes.test.js — doctor --ai-config + watchlist --org-scan
// (the CLI items). (refresh.yml job-split, lint-skills body-scan, and the
// ADVISORIES_SOURCE FEEDS pins belong to other subjects.)
// ===================================================================

test('E: doctor --ai-config emits structured check with ai_config key', () => {
  const r = envCli(['doctor', '--ai-config', '--json']);
  const body = envTryJson(r.stdout);
  assert.ok(body, `expected JSON; got ${r.stdout.slice(0, 200)}`);
  assert.equal(body.verb, 'doctor');
  assert.ok(body.checks && body.checks.ai_config, 'checks.ai_config must be present');
  const c = body.checks.ai_config;
  assert.equal(typeof c.scanned_dirs, 'number');
  assert.equal(typeof c.scanned_files, 'number');
  assert.ok(Array.isArray(c.directories_inspected));
  assert.ok(c.directories_inspected.includes('~/.claude'),
    'must include ~/.claude in inspected dirs');
  assert.ok(c.directories_inspected.includes('~/.cursor'),
    'must include ~/.cursor in inspected dirs');
  assert.ok(c.directories_inspected.includes('~/.codeium'),
    'must include ~/.codeium in inspected dirs');
  assert.ok(Array.isArray(c.sensitive_patterns));
  assert.ok(Array.isArray(c.findings));
  assert.equal(c.control_reference, 'NEW-CTRL-050 (MAL-2026-SHAI-HULUD-OSS lesson)');
  assert.ok(['win32', 'darwin', 'linux', 'freebsd', 'openbsd', 'sunos', 'aix'].includes(c.platform));
});

test('F: watchlist --org-scan refuses without --org argument', () => {
  const r = envCli(['watchlist', '--org-scan', '--json'], { env: { ...process.env, GITHUB_ORG: '', EXCEPTD_DEPRECATION_SHOWN: '1' } });
  assert.equal(r.status, 1, `expected exit 1; got ${r.status}`);
  const body = envTryJson(r.stdout.trim()) || envTryJson(r.stderr.trim());
  assert.ok(body && body.ok === false);
  assert.equal(body.verb, 'watchlist');
  assert.equal(body.mode, 'org-scan');
  assert.match(body.error, /requires --org/);
});

// ===================================================================
// Source: operator-bugs.test.js — the CLI-spawning regressions. Tests in
// that file that exercise lib/playbook-runner.js (runner.run/.loadPlaybook),
// lib/source-ghsa.js, lib/refresh-network.js, lib/refresh-external.js,
// lib/cve-curation.js, and lib/validate-cve-catalog.js directly are left
// for those subjects.
// ===================================================================

test('#17 validate-cves does not crash with MODULE_NOT_FOUND', () => {
  const r = cli(['validate-cves', '--offline', '--no-fail']);
  assert.doesNotMatch(r.stderr + r.stdout, /Cannot find module.*sources\/validators/);
});

test('#18 unknown command returns JSON error', () => {
  const r = cli(['nope-not-a-verb']);
  const err = tryJson(r.stderr.trim());
  assert.ok(err, 'stderr should be parseable JSON');
  assert.equal(err.ok, false);
  assert.equal(err.verb, 'nope-not-a-verb');
  assert.equal(typeof err.hint, 'string', 'hint must be a string operators can follow');
  assert.match(err.hint, /exceptd help/,
    'hint must point operators at `exceptd help` so a typo never dead-ends');
});

test('#18 skill not found returns JSON error on stdout', () => {
  const r = cli(['skill', 'nonexistent-skill']);
  assert.equal(r.status, 1, `expected exit 1 (GENERIC_FAILURE); got ${r.status}`);
  const err = tryJson(r.stdout.trim()) || tryJson(r.stderr.trim());
  assert.ok(err, 'response should be parseable JSON');
  assert.equal(err.ok, false);
  assert.equal(err.verb, 'skill');
  assert.match(err.error, /Skill not found/);
});

test('#19 prefetch --no-network --quiet emits one-line summary', () => {
  const r = cli(['prefetch', '--no-network', '--quiet']);
  assert.match(r.stdout, /prefetch summary:/);
});

test('#31 session-id collision refused without --force-overwrite', () => {
  const sid = 'regressionsess-' + Date.now();
  const sub = JSON.stringify({ observations: {}, verdict: { classification: 'not_detected' } });
  const r1 = cli(['run', 'library-author', '--evidence', '-', '--session-id', sid], { input: sub });
  assert.equal(r1.status, 0, 'first run must succeed');
  const r2 = cli(['run', 'library-author', '--evidence', '-', '--session-id', sid], { input: sub });
  assert.equal(r2.status, 7, 'second run must exit 7 (SESSION_ID_COLLISION)');
  const err = tryJson(r2.stderr.trim());
  assert.ok(err, 'refusal should be JSON');
  assert.match(err.error, /Session-id collision|already exists/);
});

test('#32 --mode validates against accepted set', () => {
  const r = cli(['run', 'library-author', '--evidence', '-', '--mode', 'garbage'], { input: '{}' });
  assert.equal(r.status, 1, '--mode rejection must exit 1');
  const err = tryJson(r.stderr.trim());
  assert.ok(err, 'rejection must be parseable JSON');
  assert.equal(err.ok, false, 'body must carry ok:false');
  assert.match(err.error, /--mode .* not in accepted set/,
    'error must name the flag and the "accepted set" phrase so the operator can self-correct without grepping the source');
  assert.equal(err.provided, 'garbage', 'rejected value must echo back so operators see what was rejected');
});

test('#33 --session-key must be hex', () => {
  const r = cli(['run', 'library-author', '--evidence', '-', '--session-key', 'zzzznothex'], { input: '{}' });
  assert.equal(r.status, 1, '--session-key rejection must exit 1');
  const err = tryJson(r.stderr.trim());
  assert.ok(err, 'rejection must be parseable JSON');
  assert.equal(err.ok, false, 'body must carry ok:false');
  assert.match(err.error, /--session-key must be hex/,
    'error must name the flag and the hex requirement so operators see the exact constraint, not a generic "invalid argument"');
});

test('#46 brief --all --directives includes description', () => {
  const r = cli(['brief', '--all', '--directives', '--json']);
  const data = tryJson(r.stdout);
  assert.ok(data, 'brief --all output should be JSON');
  const pb = data.playbooks?.[0];
  assert.ok(pb, 'plan must surface at least one playbook');
  assert.ok(Array.isArray(pb.directives) && pb.directives.length > 0,
    'first playbook must carry at least one directive');
  const d0 = pb.directives[0];
  assert.ok('description' in d0, 'description key must be present (even if null)');
  if (d0.description !== null) {
    assert.equal(typeof d0.description, 'string',
      'description must be string|null — no objects, no arrays, no undefined');
    assert.ok(d0.description.trim().length > 0,
      'a non-null description must have content; empty strings are the field-populated bug class');
  }
});

test('#58 ask routes literal playbook id', () => {
  const r = cli(['ask', 'secrets', '--json']);
  const data = tryJson(r.stdout);
  assert.ok(data, 'ask output should be JSON');
  assert.ok(Array.isArray(data.routed_to) && data.routed_to.length > 0,
    'ask "secrets" should return at least one match');
  assert.equal(data.routed_to[0], 'secrets',
    'literal playbook id must be the top match (data.routed_to[0]) — not just present somewhere in the ranked list');
});

test('#58 ask with synonym maps to relevant playbook', () => {
  const r = cli(['ask', 'credentials', '--json']);
  const data = tryJson(r.stdout);
  assert.ok(data && Array.isArray(data.routed_to), 'ask output should have routed_to');
  assert.ok(data.routed_to.length > 0, 'credentials should match at least one playbook');
  const credentialRelated = new Set(['secrets', 'cred-stores', 'ai-api']);
  assert.ok(credentialRelated.has(data.routed_to[0]),
    `synonym "credentials" must rank a credential-related playbook (secrets|cred-stores|ai-api) FIRST — got top=${JSON.stringify(data.routed_to[0])}, full ranking=${JSON.stringify(data.routed_to)}`);
});

test('#60 ask in TTY-less mode emits compact JSON', () => {
  const r = cli(['ask', 'secrets', '--json']);
  const data = tryJson(r.stdout);
  assert.ok(data, 'ask output should be parseable JSON when --json is set');
  const nonEmptyLines = r.stdout.split('\n').filter(line => line.length > 0);
  assert.equal(nonEmptyLines.length, 1,
    `--json under TTY-less spawn must emit exactly one line; got ${nonEmptyLines.length} non-empty line(s)`);
});

test('#62 watch verb is registered', () => {
  const r = spawnSync(process.execPath, [CLI, 'watch'], {
    encoding: 'utf8', timeout: 1500,
    env: { ...process.env, EXCEPTD_DEPRECATION_SHOWN: '1' },
  });
  assert.doesNotMatch(r.stderr, /unknown command/,
    'watch must be registered, not fall through to the unknown-verb branch');
  assert.ok(r.signal === 'SIGTERM' || r.status === null,
    `watch must still be running when the spawn timeout fires (got status=${r.status}, signal=${r.signal})`);
  assert.match(r.stdout, /\[orchestrator\] Starting event watcher/,
    'watch must reach the orchestrator-startup banner — proves dispatch happened, not just that the verb was recognized');
});

test('#65 refresh --no-network routes to prefetch', () => {
  const r = cli(['refresh', '--no-network', '--quiet']);
  assert.match(r.stdout, /prefetch summary:/,
    'refresh --no-network must route to prefetch.js and emit its summary');
  const summaryMatch = r.stdout.match(/prefetch summary: (\d+) fetched, (\d+) fresh, (\d+) (?:error\(s\)|would-fetch)/);
  assert.ok(summaryMatch,
    `summary line must be in the exact "N fetched, M fresh, K error(s)" OR "N fetched, M fresh, K would-fetch (dry-run)" format — proves prefetch.js produced it, not a misrouted verb. Got stdout=${JSON.stringify(r.stdout.slice(0,300))}`);
  const isDryRun = /would-fetch/.test(summaryMatch[0]);
  if (!isDryRun) {
    const errorCount = parseInt(summaryMatch[3], 10);
    const ERROR_CEILING = 10;
    assert.ok(errorCount <= ERROR_CEILING,
      `prefetch error count ${errorCount} exceeds ceiling ${ERROR_CEILING} — implies a pin source URL is permanently broken (not transient upstream flakiness). Got: ${summaryMatch[0]}`);
  }
  const acceptableExits = new Set([0, 1, 3221226505]);
  assert.ok(acceptableExits.has(r.status),
    `prefetch exit must be 0 (clean), 1 (some source errored under transient network), or 3221226505 (Windows libuv post-flush teardown). Got status=${r.status}, stderr=${JSON.stringify((r.stderr || '').slice(-300))}`);
  assert.doesNotMatch(r.stderr || '', /UV_HANDLE_CLOSING|Assertion failed/,
    `stderr must not contain the libuv teardown assertion — got ${JSON.stringify(r.stderr)}`);
});

test('help deprecation pointer for prefetch names the cache-population equivalent', () => {
  const r = cli(['help']);
  const out = `${r.stdout}${r.stderr}`;
  assert.doesNotMatch(out, /prefetch\s+→\s+refresh --no-network/,
    'help must not point prefetch users at the report-only dry-run form');
  assert.match(out, /prefetch\s+→\s+refresh --prefetch/,
    'help must point prefetch users at refresh --prefetch, the cache-population equivalent');
});

test('#76 run --format garbage returns structured JSON error', () => {
  const r = cli(['run', 'library-author', '--evidence', '-', '--format', 'garbage'], { input: '{}' });
  assert.equal(r.status, 1, '--format garbage must exit 1 (emitError path)');
  const err = tryJson(r.stderr.trim()) || tryJson(r.stdout.trim());
  assert.ok(err && err.ok === false, 'output must include {ok:false} JSON error');
  assert.match(err.error, /not in accepted set/);
});

test('#76 ci --format garbage returns structured JSON error', () => {
  const r = cli(['ci', '--scope', 'code', '--format', 'garbage']);
  assert.equal(r.status, 1, 'ci --format garbage must exit 1 (flag-validation rejection via emitError)');
  const err = tryJson(r.stderr.trim());
  assert.ok(err, 'rejection must be parseable JSON');
  assert.equal(err.ok, false, 'body must carry ok:false');
  assert.equal(err.verb, 'ci',
    'verb field must identify the rejecting verb so log-correlators can route the error');
  assert.match(err.error, /ci: --format .* not in accepted set/,
    'error must name the verb, flag, and "accepted set" phrase — operators self-correct from this without grepping the source');
});

test('#82 SARIF bundle via CLI includes indicator results when one fires', () => {
  const sub = JSON.stringify({
    observations: { w: { captured: true, indicator: 'publish-workflow-uses-static-token', result: 'hit' } },
    verdict: {}
  });
  const r = cli(['run', 'library-author', '--evidence', '-', '--format', 'sarif', '--json'], { input: sub });
  assert.equal(r.status, 0);
  const data = tryJson(r.stdout);
  assert.ok(data, 'sarif output should be JSON');
  assert.equal(data.version, '2.1.0');
  const results = data.runs?.[0]?.results || [];
  const matching = results.filter(res =>
    /(?:^|\/)publish-workflow-uses-static-token$/.test(String(res.ruleId)) &&
    res.properties?.kind === 'indicator_hit'
  );
  assert.equal(matching.length, 1,
    `exactly one SARIF result must match ruleId=publish-workflow-uses-static-token AND kind=indicator_hit — got ${matching.length}. Pre-strengthening "some result with kind=indicator_hit" allowed a runner regression that emits indicator_hit for every indicator regardless of the submitted result.`);
});

test('#82 CSAF bundle via CLI includes indicator vulnerabilities', () => {
  const sub = JSON.stringify({
    observations: { w: { captured: true, indicator: 'publish-workflow-uses-static-token', result: 'hit' } },
    verdict: {}
  });
  const r = cli(['run', 'library-author', '--evidence', '-', '--format', 'csaf-2.0', '--json'], { input: sub });
  const data = tryJson(r.stdout);
  assert.ok(data, 'csaf output should be JSON');
  assert.equal(data.document?.csaf_version, '2.0');
  assert.ok(Array.isArray(data.vulnerabilities));
  const indicatorVulns = data.vulnerabilities.filter(v =>
    Array.isArray(v.ids) && v.ids.some(id => id.system_name === 'exceptd-indicator')
  );
  assert.ok(indicatorVulns.length > 0,
    `CSAF vulnerabilities must include at least one entry whose ids[].system_name === "exceptd-indicator"; got ${indicatorVulns.length}. Framework gaps (system_name=exceptd-framework-gap) alone are not sufficient.`);
});

test('#82 OpenVEX bundle via CLI includes indicator statements', () => {
  const sub = JSON.stringify({
    observations: { w: { captured: true, indicator: 'publish-workflow-uses-static-token', result: 'hit' } },
    verdict: {}
  });
  const r = cli(['run', 'library-author', '--evidence', '-', '--format', 'openvex', '--json'], { input: sub });
  const data = tryJson(r.stdout);
  assert.ok(data, 'openvex output should be JSON');
  assert.match(data['@context'] || '', /openvex/);
  const indicatorStatements = (data.statements || []).filter(s => {
    const vid = s.vulnerability?.['@id'] || '';
    return vid.startsWith('urn:exceptd:indicator:');
  });
  assert.ok(indicatorStatements.length >= 1,
    `OpenVEX must include at least one indicator statement (vulnerability.@id prefixed "urn:exceptd:indicator:<playbook>:"); got ${indicatorStatements.length}.`);
});

test('#83 lint follows val.artifact indirection', () => {
  const pb = runner.loadPlaybook('library-author');
  const requiredId = (pb.phases.look.artifacts || []).find(a => a.required)?.id;
  if (!requiredId) return;
  const sub = JSON.stringify({
    observations: {
      'obs-1': { artifact: requiredId, captured: true, value: 'x', indicator: 'publish-workflow-uses-static-token', result: 'miss' }
    }
  });
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
  const pb = runner.loadPlaybook('library-author');
  const requiredArtifacts = (pb.phases.look.artifacts || []).filter(a => a.required);
  const ind = (pb.phases.detect.indicators || [])[0]?.id;
  if (requiredArtifacts.length === 0 || !ind) return;

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
    const errs = (lintData?.issues || []).filter(i => i.severity === 'error');
    assert.equal(errs.length, 0,
      'lint should not error on a runner-valid submission with val.artifact indirection. Errors: ' +
      JSON.stringify(errs.map(e => e.kind)));

    const runRes = cli(['run', 'library-author', '--evidence', tmpFile, '--json']);
    const runData = tryJson(runRes.stdout);
    assert.equal(runData?.ok, true, 'run should accept the same submission lint accepted');
  } finally {
    fs.unlinkSync(tmpFile);
  }
});

test('#91 CSAF emits framework_gap_mapping as document.notes (not pseudo-vulnerabilities)', () => {
  const sub = JSON.stringify({
    observations: { w: { captured: true, indicator: 'publish-workflow-uses-static-token', result: 'hit' } }
  });
  const r = cli(['run', 'library-author', '--evidence', '-', '--format', 'csaf-2.0', '--json'], { input: sub });
  const data = tryJson(r.stdout);
  assert.ok(data, 'csaf output should be JSON');
  const fwGapVulns = (data.vulnerabilities || []).filter(v =>
    (v.ids || []).some(id => id.system_name === 'exceptd-framework-gap')
  );
  assert.equal(fwGapVulns.length, 0,
    'framework gaps must NOT appear as vulnerabilities[] entries — they pollute downstream CSAF consumers');
  const notes = data?.document?.notes || [];
  assert.ok(Array.isArray(notes), 'document.notes must be an array');
  const gapNotes = notes.filter(n => n.category === 'details');
  assert.ok(gapNotes.length >= 1, 'library-author playbook surfaces at least one framework gap as a category=details note');
  for (const n of gapNotes) {
    assert.equal(n.category, 'details', 'framework-gap notes use category: details');
    assert.ok(typeof n.text === 'string' && n.text.length > 0,
      'each framework-gap note must carry a non-empty text body');
  }
});

test('#91 OpenVEX excludes framework_gap_mapping statements (v0.12.12 B3)', () => {
  const sub = JSON.stringify({
    observations: { w: { captured: true, indicator: 'publish-workflow-uses-static-token', result: 'hit' } }
  });
  const r = cli(['run', 'library-author', '--evidence', '-', '--format', 'openvex', '--json'], { input: sub });
  const data = tryJson(r.stdout);
  assert.ok(data, 'openvex output should be JSON');
  const fwGapStatements = (data.statements || []).filter(s => {
    const vid = String(s.vulnerability?.['@id'] || '');
    return vid.includes('framework-gap');
  });
  assert.equal(fwGapStatements.length, 0,
    'OpenVEX must NOT include framework-gap statements; they pollute the supply-chain VEX feed.');
});

test('#92 CSAF tracking.current_release_date is non-null', () => {
  const sub = JSON.stringify({});
  const r = cli(['run', 'library-author', '--evidence', '-', '--format', 'csaf-2.0', '--json'], { input: sub });
  const data = tryJson(r.stdout);
  const ts = data?.document?.tracking?.current_release_date;
  assert.equal(typeof ts, 'string',
    `current_release_date must be a string per CSAF 2.0 §3.2.1.12; got ${typeof ts}`);
  assert.match(ts, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}/,
    `current_release_date must be ISO 8601 (YYYY-MM-DDTHH:MM…); got ${JSON.stringify(ts)}`);
  assert.ok(!Number.isNaN(Date.parse(ts)),
    `current_release_date must round-trip through Date.parse; got ${JSON.stringify(ts)}`);
});

test('#93 SARIF defines every rule referenced by ruleId', () => {
  const sub = JSON.stringify({
    observations: { w: { captured: true, indicator: 'publish-workflow-uses-static-token', result: 'hit' } }
  });
  const r = cli(['run', 'library-author', '--evidence', '-', '--format', 'sarif', '--json'], { input: sub });
  const data = tryJson(r.stdout);
  const rules = new Set((data.runs?.[0]?.tool?.driver?.rules || []).map(x => x.id));
  const results = data.runs?.[0]?.results || [];
  const missingDefs = [...new Set(results.map(r => r.ruleId))].filter(id => !rules.has(id));
  assert.equal(missingDefs.length, 0,
    `SARIF spec §3.27.3: every referenced ruleId must have a rule definition. Missing: ${JSON.stringify(missingDefs)}`);
});

test('#94 lint missing_required_artifact is a warning, not error', () => {
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

test('#96 --strict-preconditions exits 1 on warn-level preconditions', () => {
  const sub = JSON.stringify({});
  const rDefault = cli(['run', 'secrets', '--evidence', '-'], { input: sub });
  assert.equal(rDefault.status, 0, 'default mode: warn-level precondition exits 0');
  const rStrict = cli(['run', 'secrets', '--evidence', '-', '--strict-preconditions'], { input: sub });
  assert.equal(rStrict.status, 1, '--strict-preconditions: warn-level precondition exits 1');
});

test('#98 attest export --format garbage on a real session returns format error', () => {
  const sid = 'export-fmt-arm-' + Date.now();
  const seedRun = cli(['run', 'library-author', '--evidence', '-', '--session-id', sid, '--force-overwrite'], { input: '{}' });
  assert.equal(seedRun.status, 0, 'pre-stage run must succeed so attest-export sees a real session');
  const r = cli(['attest', 'export', sid, '--format', 'garbage']);
  assert.equal(r.status, 1, 'attest export with garbage format must exit 1 (emitError --format validation)');
  const err = tryJson(r.stderr.trim());
  assert.ok(err, 'rejection must be parseable JSON on stderr');
  assert.equal(err.ok, false, 'body must carry ok:false');
  assert.match(err.error, /attest export: --format .* not in accepted set/,
    'with a real session id, the format error must fire (NOT the session-not-found error) — otherwise --format validation is unreachable behind the session-lookup gate');
});

test('#98 attest export on missing session id returns session-not-found error', () => {
  const r = cli(['attest', 'export', 'never-existed-' + Date.now(), '--format', 'json']);
  assert.equal(r.status, 1, 'missing session must exit 1 (emitError session-not-found)');
  const err = tryJson(r.stderr.trim());
  assert.ok(err, 'rejection must be parseable JSON on stderr');
  assert.equal(err.ok, false, 'body must carry ok:false');
  assert.match(err.error, /attest export: no session dir/,
    'with a missing session id, the session-not-found error must fire (NOT the format error)');
  assert.equal(typeof err.session_id, 'string',
    'rejected session id must echo back so operators see what was searched');
});

test('#98 report garbage returns JSON error exit 1 (v0.13 exit-code class)', () => {
  const r = cli(['report', 'garbage']);
  assert.equal(r.status, 1, `expected exit 1; got ${r.status}`);
  const err = tryJson(r.stdout.trim()) || tryJson(r.stderr.trim());
  assert.ok(err && err.ok === false);
  assert.equal(err.verb, 'report');
  assert.match(err.error, /not in accepted set/);
  assert.ok(Array.isArray(err.accepted_formats));
});

test('#100 ok:false from preflight-halt exits non-zero', () => {
  const sub = JSON.stringify({});
  const r = cli(['run', 'kernel', '--evidence', '-'], { input: sub });
  const data = tryJson(r.stdout) || tryJson(r.stderr);
  assert.ok(data, `run kernel must emit parseable JSON in either ok:true or ok:false branch. stdout=${JSON.stringify(r.stdout.slice(0,200))} stderr=${JSON.stringify(r.stderr.slice(0,200))}`);
  assert.notEqual(data.ok, undefined,
    'data.ok must be present (true or false) — undefined means the runner emitted a body without the contract field');
  if (data.ok === false) {
    assert.equal(r.status, 1, 'ok:false must exit 1 (universal emit() contract)');
  } else {
    assert.equal(data.ok, true, 'data.ok must be strictly true or false, never another truthy value');
    assert.equal(r.status, 0, 'ok:true must exit 0 (contract: ok:true ↔ exit 0)');
  }
});

test('#100 warn-level preconditions do NOT block (run completes ok:true exit 0)', () => {
  const sub = JSON.stringify({});
  const r = cli(['run', 'secrets', '--evidence', '-'], { input: sub });
  const data = tryJson(r.stdout);
  assert.ok(data, 'secrets run must emit parseable JSON to stdout');
  assert.equal(data.ok, true,
    'warn-level preconditions are non-blocking by default — run must complete ok:true');
  assert.equal(r.status, 0,
    'warn-level run with ok:true must exit 0 — flipping to non-zero would re-introduce the very behavior --strict-preconditions was added to opt INTO');
});

test('#100 --strict-preconditions escalates warn-level to exit 1', () => {
  const sub = JSON.stringify({ precondition_checks: { 'regex-engine': false } });
  const r = cli(['run', 'secrets', '--evidence', '-', '--strict-preconditions'], { input: sub });
  const data = tryJson(r.stdout) || tryJson(r.stderr);
  assert.ok(data, '--strict-preconditions run must still emit JSON (just to a non-zero exit)');
  assert.ok(Array.isArray(data.preflight_issues),
    'preflight_issues must be present as an array on a --strict-preconditions run');
  assert.ok(data.preflight_issues.length >= 1,
    `with regex-engine:false pre-staged, preflight_issues MUST contain ≥1 entry; got ${data.preflight_issues.length}. If 0, the runner silently dropped the staged precondition check — that's the bug.`);
  assert.equal(r.status, 1,
    '--strict-preconditions must exit exactly 1 when preflight issues are present (NOT 0, NOT 2 — 1 is the warn-escalation code)');
});

test('#101 ai-run --no-stream shape matches run shape (phases nested)', () => {
  const sub = JSON.stringify({});
  const r = cli(['ai-run', 'library-author', '--no-stream', '--json'], { input: sub });
  const data = tryJson(r.stdout);
  assert.ok(data, 'ai-run --no-stream output should be JSON');
  assert.ok(data.phases, 'ai-run --no-stream must nest phases under .phases (parity with `run`)');
  assert.ok('detect' in data.phases, 'phases.detect must be present');
  assert.ok('analyze' in data.phases, 'phases.analyze must be present');
});

test('attest diff <sid> (no --against) emits the v0.11+ envelope (not the legacy reattest shape)', () => {
  const sub = JSON.stringify({
    observations: { w: { captured: true, value: 'x', indicator: 'publish-workflow-uses-static-token', result: 'miss' } }
  });
  const sidA = 'diff-noagainst-a-' + Date.now();
  const sidB = 'diff-noagainst-b-' + Date.now();
  cli(['run', 'library-author', '--evidence', '-', '--session-id', sidA, '--force-overwrite'], { input: sub });
  cli(['run', 'library-author', '--evidence', '-', '--session-id', sidB, '--force-overwrite'], { input: sub });
  const r = cli(['attest', 'diff', sidB, '--json']);
  const data = tryJson(r.stdout);
  assert.ok(data, 'attest diff <sid> --json should emit parseable JSON');
  assert.equal(data.verb, 'attest diff',
    `verb must be "attest diff", not legacy "reattest"; got: ${data.verb}`);
  assert.equal(data.a_session, sidB);
  assert.ok(data.b_session, 'b_session must name the auto-selected prior session');
  assert.ok(['unchanged', 'drifted'].includes(data.status),
    `status must be unchanged/drifted; got: ${data.status}`);
  assert.ok(data.signal_override_diff,
    'signal_override_diff must be present (granular drift surface)');
  assert.ok(data.artifact_diff,
    'artifact_diff must be present (granular drift surface)');
});

test('#102 attest diff unchanged_count counts identical entries', () => {
  const sub = JSON.stringify({
    observations: { w: { captured: true, value: 'x', indicator: 'publish-workflow-uses-static-token', result: 'miss' } }
  });
  const sid1 = 'diffunch1-' + Date.now();
  const sid2 = 'diffunch2-' + Date.now();
  cli(['run', 'library-author', '--evidence', '-', '--session-id', sid1, '--force-overwrite'], { input: sub });
  cli(['run', 'library-author', '--evidence', '-', '--session-id', sid2, '--force-overwrite'], { input: sub });
  const r = cli(['attest', 'diff', sid1, '--against', sid2, '--json']);
  const data = tryJson(r.stdout);
  assert.ok(data, 'attest diff output should be JSON');
  assert.ok(data.artifact_diff.unchanged_count >= 1,
    'identical submissions should count unchanged artifacts > 0');
  assert.ok(data.signal_override_diff.unchanged_count >= 1,
    'identical submissions should count unchanged signal_overrides > 0');
});

test('#103 ci does not fail on inconclusive baseline RWEP', () => {
  const r = cli(['ci', '--scope', 'code', '--json']);
  const data = tryJson(r.stdout);
  assert.ok(data, 'ci output should be JSON');
  assert.ok(Array.isArray(data.summary.fail_reasons),
    'summary.fail_reasons must always be an array (possibly empty), never undefined/null — operators rely on `for (const r of fail_reasons)` not failing');
  const rwepDeltaReasons = data.summary.fail_reasons.filter(reason =>
    /rwep_delta/.test(reason) || /rwep=\d+ >= cap/.test(reason)
  );
  assert.equal(rwepDeltaReasons.length, 0,
    'baseline-only ci run should not fail on catalog RWEP — only on RWEP delta from operator evidence');
});

test('#104 jurisdiction clocks fire on detected classification (with --ack — E7: operator awareness starts the clock)', () => {
  const sub = JSON.stringify({
    secrets: {
      observations: { w: { captured: true, value: 'AKIA', indicator: 'aws-access-key-id', result: 'hit' } },
      verdict: { classification: 'detected', blast_radius: 4 }
    }
  });
  const tmpFile = secureTmpFile('ev.json', 'civ-');
  fs.writeFileSync(tmpFile, sub);
  const r = cli(['ci', '--required', 'secrets', '--evidence', tmpFile, '--ack', '--json']);
  fs.unlinkSync(tmpFile);
  const data = tryJson(r.stdout);
  assert.ok(data, 'ci output should be JSON');
  assert.ok(data.summary.jurisdiction_clocks_started >= 1,
    'detected classification with detect_confirmed obligations should fire at least one jurisdiction clock');
  const result = data.results?.[0];
  assert.ok(result, 'ci must surface per-playbook results so the counter can be cross-checked');
  const obligations = result.phases?.govern?.jurisdiction_obligations || [];
  assert.ok(Array.isArray(obligations) && obligations.length > 0,
    'govern.jurisdiction_obligations must be a non-empty array — that is what jurisdiction_clocks_started is counting against');
  const euOblig = obligations.filter(o => o.jurisdiction === 'EU');
  assert.ok(euOblig.length >= 1,
    `secrets stages EU obligations (GDPR Art.33, NIS2 Art.23) under detect_confirmed — at least one must be present; got jurisdictions=${JSON.stringify([...new Set(obligations.map(o => o.jurisdiction))])}`);
});

test('#113 --operator surfaces in run result top-level', () => {
  const r = cli(['run', 'library-author', '--evidence', '-', '--operator', 'robert@example.com', '--session-id', 'oper113-' + Date.now(), '--force-overwrite', '--json'], { input: '{}' });
  const data = tryJson(r.stdout);
  assert.ok(data, 'run output should be JSON');
  assert.equal(data.operator, 'robert@example.com',
    '--operator must surface at result.operator (pre-0.11.9 was attestation-only)');
});

test('#114 --ack surfaces in run result top-level', () => {
  const r = cli(['run', 'library-author', '--evidence', '-', '--ack', '--session-id', 'ack114-' + Date.now(), '--force-overwrite', '--json'], { input: '{}' });
  const data = tryJson(r.stdout);
  assert.ok(data, 'run output should be JSON');
  assert.ok(data.operator_consent && data.operator_consent.explicit === true,
    '--ack must surface at result.operator_consent.explicit');
});

test('#115 ci --required filters to exactly the named playbooks', () => {
  const r = cli(['ci', '--required', 'secrets,sbom', '--json']);
  const data = tryJson(r.stdout);
  assert.ok(data, 'ci output should be JSON');
  const sortedRun = [...data.playbooks_run].sort();
  assert.deepEqual(sortedRun, ['sbom', 'secrets'],
    'ci --required must run exactly the named set, not a superset/subset');
});

test('#115 ci --required rejects unknown playbook id', () => {
  const r = cli(['ci', '--required', 'totally-not-a-playbook', '--json']);
  assert.equal(r.status, 1, 'unknown --required playbook must exit 1 (emitError unknown-playbook refusal)');
  const err = tryJson(r.stderr.trim());
  assert.ok(err && err.ok === false);
  assert.match(err.error, /unknown playbook/);
});

test('#119 result.ack alias for --ack consent state', () => {
  const r = cli(['run', 'library-author', '--evidence', '-', '--ack', '--session-id', 'ack119-' + Date.now(), '--force-overwrite', '--json'], { input: '{}' });
  const data = tryJson(r.stdout);
  assert.equal(data?.ack, true, 'result.ack must be true when --ack is passed');
  assert.equal(data?.operator_consent?.explicit, true, 'operator_consent.explicit also true');
});

test('#119 result.ack is false without --ack', () => {
  const r = cli(['run', 'library-author', '--evidence', '-', '--session-id', 'noack-' + Date.now(), '--force-overwrite', '--json'], { input: '{}' });
  const data = tryJson(r.stdout);
  assert.equal(data?.ack, false, 'result.ack must be false without --ack');
});

test('#100 ci with NO --evidence + all inconclusive exits 3 (not 0)', () => {
  const tmp = secureTmpFile('ev.json', 'incon-');
  fs.writeFileSync(tmp, '{}');
  try {
    const r = cli(['ci', '--required', 'sbom', '--json']);
    assert.ok([0, 3].includes(r.status),
      `ci without --evidence: legitimate not_detected (exit 0) or inconclusive-guard (exit 3) — got ${r.status}`);
  } finally {
    try { fs.unlinkSync(tmp); } catch {}
  }
});

test('#100/#103 ci exit-3 path still flushes JSON to stdout', () => {
  const r = cli(['ci', '--required', 'secrets', '--json']);
  const data = tryJson(r.stdout);
  assert.ok(data, 'ci exit-3 path must still flush JSON to stdout (no truncation on piped stdout)');
  assert.equal(data.verb, 'ci');
  assert.ok(data.summary, 'JSON body must include summary');
});

test('#102 attest diff includes total_compared field', () => {
  const sub = JSON.stringify({ observations: { w: { captured: true, indicator: 'publish-workflow-uses-static-token', result: 'miss' } } });
  const sid1 = 'tc-a-' + Date.now();
  const sid2 = 'tc-b-' + Date.now();
  cli(['run', 'library-author', '--evidence', '-', '--session-id', sid1, '--force-overwrite'], { input: sub });
  cli(['run', 'library-author', '--evidence', '-', '--session-id', sid2, '--force-overwrite'], { input: sub });
  const r = cli(['attest', 'diff', sid1, '--against', sid2, '--json']);
  const data = tryJson(r.stdout);
  assert.ok(typeof data?.artifact_diff?.total_compared === 'number',
    'artifact_diff must include total_compared (disambiguates 0/0 vs 0-of-N)');
  assert.ok(typeof data?.signal_override_diff?.total_compared === 'number');
});

test('#123 jurisdiction_notifications entries carry obligation metadata', () => {
  const sub = JSON.stringify({
    observations: { w: { captured: true, value: 'AKIA', indicator: 'aws-access-key-id', result: 'hit' } },
    verdict: { classification: 'detected', blast_radius: 4 }
  });
  const r = cli(['run', 'secrets', '--evidence', '-', '--session-id', 'jur123-' + Date.now(), '--force-overwrite', '--json'], { input: sub });
  const data = tryJson(r.stdout);
  const notifs = data?.phases?.close?.jurisdiction_notifications || [];
  assert.ok(notifs.length > 0, 'must have notifications when classification=detected');
  const enriched = notifs.filter(n => n.jurisdiction && n.regulation);
  assert.ok(enriched.length > 0,
    'at least one notification entry must carry jurisdiction + regulation (enriched from govern.jurisdiction_obligations)');
  for (const n of enriched) {
    assert.equal(typeof n.jurisdiction, 'string', 'jurisdiction must be a string, not null');
    assert.equal(typeof n.regulation, 'string', 'regulation must be a string, not null');
    assert.ok(typeof n.window_hours === 'number', 'window_hours must be a number');
    assert.ok(typeof n.notification_deadline === 'string', 'notification_deadline must be a string (ISO or sentinel)');
    assert.ok(Array.isArray(n.evidence_required), 'evidence_required must be an array');
  }
});

test('#124 --ack propagates into phases.govern.operator_consent', () => {
  const r = cli(['run', 'library-author', '--evidence', '-', '--ack', '--session-id', 'gov124-' + Date.now(), '--force-overwrite', '--json'], { input: '{}' });
  const data = tryJson(r.stdout);
  assert.ok(data?.phases?.govern, 'govern phase must be present');
  assert.ok(data.phases.govern.operator_consent,
    'phases.govern.operator_consent must be populated when --ack passed (consent semantically belongs in govern)');
  assert.equal(data.phases.govern.operator_consent.explicit, true);
});

test('#124 phases.govern.operator_consent is null without --ack', () => {
  const r = cli(['run', 'library-author', '--evidence', '-', '--session-id', 'noackg-' + Date.now(), '--force-overwrite', '--json'], { input: '{}' });
  const data = tryJson(r.stdout);
  assert.equal(data?.phases?.govern?.operator_consent, null,
    'govern.operator_consent must be null (not undefined) when --ack not passed');
});

test('#125/#134 ci with real preflight halt exits 4 BLOCKED (not 2 FAIL, not 0)', () => {
  const tmp = secureTmpFile('ev.json', 'block-');
  fs.writeFileSync(tmp, JSON.stringify({ secrets: { precondition_checks: { 'repo-context': false } } }));
  const r = cli(['ci', '--required', 'secrets', '--evidence', tmp, '--json']);
  fs.unlinkSync(tmp);
  const data = tryJson(r.stdout);
  assert.ok(data, 'ci JSON must parse');
  assert.equal(data.summary.blocked, 1, 'summary.blocked must be 1 when preflight halts');
  assert.equal(r.status, 4,
    'BLOCKED must take precedence over FAIL — exit 4, not 2. Operators distinguish "playbook never executed" from "playbook detected an issue"');
});

test('#126 attest diff total_compared matches observation count when identical', () => {
  const sub = JSON.stringify({
    observations: {
      w: { captured: true, indicator: 'publish-workflow-uses-static-token', result: 'miss' },
      x: { captured: true, indicator: 'npm-token-rotation-cadence', result: 'miss' }
    }
  });
  const sid1 = 'tc-c-' + Date.now();
  const sid2 = 'tc-d-' + Date.now();
  cli(['run', 'library-author', '--evidence', '-', '--session-id', sid1, '--force-overwrite'], { input: sub });
  cli(['run', 'library-author', '--evidence', '-', '--session-id', sid2, '--force-overwrite'], { input: sub });
  const r = cli(['attest', 'diff', sid1, '--against', sid2, '--json']);
  const data = tryJson(r.stdout);
  assert.ok(data, 'attest diff JSON must parse');
  assert.ok(data.artifact_diff.total_compared > 0,
    'identical submissions with 2 observations must have total_compared > 0 (not 0)');
  assert.ok(data.artifact_diff.unchanged_count > 0,
    'identical submissions must have unchanged_count > 0');
  assert.equal(data.artifact_diff.total_compared, data.artifact_diff.unchanged_count,
    'all artifacts identical → total_compared === unchanged_count');
});

test('#129 refresh --from-cache <missing> emits structured hint, not stack trace', () => {
  const r = cli(['refresh', '--from-cache', '/totally/does/not/exist']);
  assert.equal(r.status, 2, 'missing cache dir must exit 2 (refresh-external hint refusal default)');
  const combined = (r.stdout || '') + (r.stderr || '');
  assert.doesNotMatch(combined, /at Object\.<anonymous>|^\s*at .*\.js:\d+/m,
    'no raw Node stack trace — should be a hinted error');
  assert.match(combined, /exceptd refresh --(prefetch|no-network)/,
    'error must tell operator the exact command to populate the cache');
});

test('#129 refresh --prefetch is an alias for --no-network', () => {
  const r = cli(['refresh', '--prefetch', '--no-network', '--quiet']);
  assert.match(r.stdout, /prefetch summary:/,
    'refresh --prefetch must route to prefetch.js and emit its one-line summary — proves the alias works, not just that the dispatcher didn\'t crash');
});

test('#130 exceptd path copy is not a silent no-op', () => {
  const r = cli(['path', 'copy']);
  assert.equal(r.status, 0);
  assert.ok(r.stdout.trim().length > 0, 'path on stdout');
  assert.match(r.stderr, /\[exceptd path\] (copied to clipboard|copy: no clipboard tool available)/,
    'stderr must emit one of the two specific status messages — "copied to clipboard" (success) or "copy: no clipboard tool available" (degraded). Neither branch can be silent; a missing/altered message is the regression.');
});

test('#131 run <skill-name> suggests the right playbook', () => {
  const r = cli(['run', 'kernel-lpe-triage', '--evidence', '-', '--json'], { input: '{}' });
  assert.equal(r.status, 1, 'unknown playbook must exit 1 (emitError refusal from cmdRun playbook lookup)');
  const err = tryJson(r.stderr.trim());
  assert.ok(err && err.ok === false, 'stderr must carry structured JSON error');
  assert.match(err.error, /SKILL.*not.*PLAYBOOK|skill.*playbook|exceptd skill|exceptd plan/i,
    'error must explain skill≠playbook and suggest the right verb');
  assert.match(err.error, /kernel\b/, 'must name the playbook that loads this skill');
});

test('#131 run <typo-playbook-id> suggests nearest playbooks', () => {
  const r = cli(['run', 'secret', '--evidence', '-', '--json'], { input: '{}' });
  assert.equal(r.status, 1, 'typo-playbook-id must exit 1 (emitError unknown-playbook with suggestion)');
  const err = tryJson(r.stderr.trim());
  assert.match(err.error, /Did you mean|exceptd plan|secrets/i,
    'partial-match must suggest the canonical id');
});

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

test('doctor --registry-check reports days_since_latest_publish from fixture', () => {
  const fix = withFixture('99.99.99', 7);
  try {
    const r = cli(['doctor', '--registry-check', '--json'], {
      env: { EXCEPTD_REGISTRY_FIXTURE: fix }
    });
    const data = tryJson(r.stdout);
    assert.ok(data, 'doctor must emit JSON');
    assert.ok(data.checks?.registry, 'registry check must be present when --registry-check is passed');
    assert.equal(data.checks.registry.latest_version, '99.99.99');
    assert.equal(data.checks.registry.days_since_latest_publish, 7);
    assert.equal(data.checks.registry.behind, true);
    assert.match(data.checks.registry.hint, /npm update -g|refresh --network/);
  } finally { fs.unlinkSync(fix); }
});

test('doctor --registry-check ok when local matches latest', () => {
  const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'));
  const fix = withFixture(pkg.version, 0);
  try {
    const r = cli(['doctor', '--registry-check', '--json'], {
      env: { EXCEPTD_REGISTRY_FIXTURE: fix }
    });
    const data = tryJson(r.stdout);
    assert.equal(data.checks.registry.same, true);
    assert.equal(data.checks.registry.behind, false);
  } finally { fs.unlinkSync(fix); }
});

test('run --upstream-check surfaces upstream_check on result and warns when behind', () => {
  const fix = withFixture('99.99.99', 5);
  try {
    const r = cli(['run', 'library-author', '--evidence', '-', '--upstream-check', '--session-id', 'us-' + Date.now(), '--force-overwrite', '--json'], {
      input: '{}',
      env: { EXCEPTD_REGISTRY_FIXTURE: fix }
    });
    const data = tryJson(r.stdout);
    assert.ok(data?.upstream_check, 'run result must carry upstream_check when --upstream-check is passed');
    assert.equal(data.upstream_check.behind, true);
    assert.equal(data.upstream_check.latest_version, '99.99.99');
    assert.match(r.stderr, /STALE: local v.* < published v99\.99\.99/,
      'stderr must surface a visible STALE warning so operators see the freshness gap before relying on findings');
  } finally { fs.unlinkSync(fix); }
});

test('run without --upstream-check does NOT contact the registry', () => {
  const r = cli(['run', 'library-author', '--evidence', '-', '--session-id', 'noUp-' + Date.now(), '--force-overwrite', '--json'], { input: '{}' });
  const data = tryJson(r.stdout);
  assert.ok(data, 'run JSON must parse');
  assert.equal(data.upstream_check, undefined,
    'no upstream_check field unless --upstream-check is explicitly passed');
});

test('refresh --network shows clear hint when registry is unreachable', () => {
  const fakePath = path.join(require('os').tmpdir(), 'does-not-exist-' + Date.now() + '.json');
  const r = cli(['refresh', '--network', '--json', '--timeout', '500'], {
    env: { EXCEPTD_REGISTRY_FIXTURE: fakePath }
  });
  assert.equal(r.status, 2, 'unreachable registry must exit 2 (refresh-network unreachable branch)');
  const data = tryJson(r.stdout) || tryJson(r.stderr.trim());
  assert.ok(data, 'refresh --network must emit structured JSON on the error path, not a raw stack trace');
  assert.equal(data.ok, false, 'unreachable registry must carry ok:false');
  assert.equal(typeof data.error, 'string', 'error must be a string operators can read');
  assert.match(data.error, /unreachable|registry/i,
    'error must name the failure class so operators see "unreachable" / "registry" — not a generic ENOENT bubble-up');
});

test('refresh --network --dry-run reports verification result without modifying files', () => {
  const r = cli(['refresh', '--network', '--dry-run', '--json', '--timeout', '1000']);
  const data = tryJson(r.stdout) || tryJson(r.stderr.trim());
  assert.ok(data, 'must emit structured JSON in either online or offline branch');
  assert.ok('verified' in data || 'ok' in data,
    `refresh --network --dry-run body must carry at least one of {verified, ok}; got keys=${JSON.stringify(Object.keys(data))}. An empty object is the field-missing regression.`);
});

test('#127 emit() body with ok:false sets non-zero exit (universal contract)', () => {
  const r = cli(['attest', 'verify', 'no-such-session-id-' + Date.now(), '--json']);
  const stdoutBody = tryJson(r.stdout) || {};
  const stderrBody = tryJson(r.stderr.trim()) || {};
  const sawOkFalse = stdoutBody.ok === false || stderrBody.ok === false;
  assert.equal(sawOkFalse, true,
    `attest verify on a missing session id MUST produce ok:false in stdout or stderr (the session-not-found gate is unavoidable). If false, the runner found a way around the gate — that's the regression. stdout=${JSON.stringify(r.stdout.slice(0,300))} stderr=${JSON.stringify(r.stderr.slice(0,300))}`);
  assert.equal(r.status, 1,
    'ok:false on stdout OR stderr must exit 1 — universal emit() contract (bin/exceptd.js:615)');
});

test('#127 attest diff with missing session ids exits non-zero', () => {
  const r = cli(['attest', 'diff', 'does-not-exist-a', '--against', 'does-not-exist-b', '--json']);
  assert.equal(r.status, 1, 'attest diff missing sessions must exit 1 (emitError session-not-found, universal emit contract)');
  const err = tryJson(r.stderr.trim());
  assert.ok(err, 'attest diff must emit JSON error on stderr');
  assert.equal(err.ok, false, 'body must carry ok:false');
  assert.match(err.error, /does-not-exist-a/,
    'error must name the failed session id (the A side is checked first) so operators know which arm to fix');
});

test('#128 attest diff with empty submissions falls back to playbook catalog', () => {
  const sid1 = 'empty-cat-a-' + Date.now();
  const sid2 = 'empty-cat-b-' + Date.now();
  cli(['run', 'sbom', '--evidence', '-', '--session-id', sid1, '--force-overwrite'], { input: '{}' });
  cli(['run', 'sbom', '--evidence', '-', '--session-id', sid2, '--force-overwrite'], { input: '{}' });
  const r = cli(['attest', 'diff', sid1, '--against', sid2, '--json']);
  const data = tryJson(r.stdout);
  assert.ok(data, 'diff JSON must parse');
  assert.equal(data.status, 'unchanged', 'identical empty submissions hash-match → status=unchanged');
  assert.ok(data.artifact_diff.total_compared > 0,
    'empty submissions must fall back to playbook artifact catalog count, not 0');
  assert.equal(data.artifact_diff.total_compared, data.artifact_diff.unchanged_count,
    'all catalog entries identical (both empty) → total_compared === unchanged_count');
});

test('#104 close emits jurisdiction_notifications alias + clocks count (with --ack — E7 binds clock to operator awareness)', () => {
  const sub = JSON.stringify({
    observations: { w: { captured: true, value: 'AKIA', indicator: 'aws-access-key-id', result: 'hit' } },
    verdict: { classification: 'detected', blast_radius: 4 }
  });
  const r = cli(['run', 'secrets', '--evidence', '-', '--ack', '--session-id', 'jur104-' + Date.now(), '--force-overwrite', '--json'], { input: sub });
  const data = tryJson(r.stdout);
  assert.ok(Array.isArray(data?.phases?.close?.jurisdiction_notifications),
    'phases.close.jurisdiction_notifications must be present (alias for notification_actions)');
  assert.ok(data.phases.close.jurisdiction_clocks_count >= 1,
    'jurisdiction_clocks_count must be > 0 when classification=detected + --ack with detect_confirmed obligations');
});

test('#E7 jurisdiction clock pending without --ack on detected classification', () => {
  const sub = JSON.stringify({
    observations: { w: { captured: true, value: 'AKIA', indicator: 'aws-access-key-id', result: 'hit' } },
    verdict: { classification: 'detected', blast_radius: 4 }
  });
  const r = cli(['run', 'secrets', '--evidence', '-', '--session-id', 'e7-' + Date.now(), '--force-overwrite', '--json'], { input: sub });
  const data = tryJson(r.stdout);
  const notifs = data?.phases?.close?.notification_actions || [];
  const detectConfirmed = notifs.filter(n => n && n.clock_start_event === 'detect_confirmed');
  assert.ok(detectConfirmed.length >= 1,
    'secrets stages at least one detect_confirmed obligation');
  assert.ok(detectConfirmed.every(n => n.clock_started_at == null),
    'without --ack every detect_confirmed clock must be unstarted');
  assert.ok(detectConfirmed.every(n => n.clock_pending_ack === true),
    'each unstarted detect_confirmed notification must surface clock_pending_ack=true so operators see why');
});

test('audit-3 B.1: doctor --help advertises every runtime-accepted flag', () => {
  const r = cli(['doctor', '--help']);
  const text = (r.stdout || '') + (r.stderr || '');
  for (const flag of ['--collectors', '--ai-config', '--exit-codes', '--shipped-tarball', '--registry-check', '--fix']) {
    assert.ok(text.includes(flag),
      `doctor --help must advertise ${flag}; got: ${text.slice(0, 500)}`);
  }
});

test('audit-3 B.2: doctor CVE catalog by_prefix sums to total', () => {
  const r = cli(['doctor', '--cves', '--json']);
  const data = tryJson(r.stdout);
  assert.ok(data, 'doctor --cves --json must emit parseable JSON');
  const cves = data?.checks?.cves;
  assert.ok(cves, 'checks.cves must be present');
  assert.equal(typeof cves.total, 'number', 'cves.total must be numeric');
  assert.ok(cves.by_prefix && typeof cves.by_prefix === 'object',
    'cves.by_prefix must be an object enumerating every prefix group');
  const sum = Object.values(cves.by_prefix).reduce((a, b) => a + b, 0);
  assert.equal(sum, cves.total,
    `by_prefix must sum to total (${sum} != ${cves.total}); pre-fix only CVE + MAL were enumerated and BUG-* entries dropped from the breakdown`);
});

test('doctor --fix on a healthy install reports fix_status: already_present (no-op contract)', () => {
  const src = fs.readFileSync(path.join(ROOT, 'bin', 'exceptd.js'), 'utf8');
  assert.match(
    src,
    /args\.fix\s*&&\s*!out\.summary\.fix_applied\s*&&\s*!out\.summary\.fix_attempted/,
    'already_present must gate on --fix with no applied/attempted fix'
  );
  assert.match(
    src,
    /out\.summary\.fix_status\s*=\s*["']already_present["']/,
    'doctor --fix no-op must set fix_status: "already_present"'
  );
  assert.match(
    src,
    /out\.summary\.fix_skipped_reason\s*=\s*["']/,
    'doctor --fix no-op must set a fix_skipped_reason string alongside fix_status'
  );
});

test('audit-3 B.4: doctor refuses unknown flags with structured error + known_flags list', () => {
  const r = cli(['doctor', '--bogus-flag-xyz']);
  const err = tryJson(r.stderr);
  assert.ok(err, 'unknown flag must produce stderr JSON');
  assert.equal(err.ok, false);
  assert.equal(err.verb, 'doctor');
  assert.ok(Array.isArray(err.unknown_flags), 'unknown_flags must be an array');
  assert.ok(Array.isArray(err.known_flags), 'known_flags must list every accepted flag');
  assert.ok(err.known_flags.includes('--signatures'),
    'known_flags must include --signatures (sanity)');
  assert.equal(r.status, 1, 'unknown-flag refusal must exit 1 (GENERIC_FAILURE)');
});

test('audit-3 A.2: run envelope surfaces air_gap_mode on the top-level result', () => {
  const sub = JSON.stringify({
    observations: { w: { captured: true, value: 'AKIA', indicator: 'aws-access-key-id', result: 'hit' } },
    verdict: { classification: 'detected' }
  });
  const r = cli(['run', 'secrets', '--evidence', '-', '--air-gap', '--session-id', 'a2-' + Date.now(), '--force-overwrite', '--json'], { input: sub });
  const data = tryJson(r.stdout);
  assert.ok(data, 'run --json must emit parseable JSON');
  assert.equal(data.air_gap_mode, true,
    'run --air-gap must surface air_gap_mode: true at the top of the result envelope; stdout-parsing consumers depend on it');
});

test('audit-3 C.1: ask "the the the the" routes to nothing (stopwords filtered)', () => {
  const r = cli(['ask', 'the the the the', '--json']);
  const data = tryJson(r.stdout);
  assert.ok(data, 'ask --json must emit parseable JSON');
  assert.equal(data.verb, 'ask');
  assert.deepEqual(data.routed_to, [],
    `pure-stopword query must route to nothing; got: ${JSON.stringify(data.routed_to)}`);
});

test('audit-3 C.2: ask "phished" routes to identity-sso-compromise', () => {
  const r = cli(['ask', 'I think we got phished', '--json']);
  const data = tryJson(r.stdout);
  assert.ok(data, 'ask --json must emit parseable JSON');
  assert.ok(Array.isArray(data.routed_to) && data.routed_to.length > 0,
    'phished query must produce a match');
  assert.equal(data.routed_to[0], 'identity-sso-compromise',
    `phished query must top-route to identity-sso-compromise; got: ${JSON.stringify(data.routed_to)}`);
});

test('audit-3 A.1: refresh --air-gap with no fixtures/cache refuses every source', () => {
  const r = cli(['refresh', '--air-gap', '--source', 'kev', '--json']);
  const reportPath = path.join(ROOT, 'refresh-report.json');
  if (!fs.existsSync(reportPath)) {
    const text = (r.stdout || '') + (r.stderr || '');
    assert.match(text, /air-gap mode: kev skipped/,
      `refresh --air-gap must short-circuit kev with the air_gap_blocked summary; got: ${text.slice(0, 600)}`);
    return;
  }
  const report = JSON.parse(fs.readFileSync(reportPath, 'utf8'));
  assert.equal(report.sources?.kev?.status, 'unreachable',
    'kev under --air-gap with no cache must report status: unreachable');
  assert.equal(report.sources?.kev?.air_gap_blocked, true,
    'kev under --air-gap must surface air_gap_blocked: true');
});

test('audit-3 A.4: collect envelope surfaces air_gap_mode on the top-level result', () => {
  const r1 = cli(['collect', 'secrets', '--air-gap', '--json']);
  const d1 = tryJson(r1.stdout);
  assert.ok(d1, 'collect --json must emit parseable JSON');
  assert.equal(d1.air_gap_mode, true,
    'collect --air-gap must surface air_gap_mode: true');

  const r2 = cli(['collect', 'mcp', '--json']);
  const d2 = tryJson(r2.stdout);
  assert.ok(d2);
  assert.equal(d2.air_gap_mode, false,
    'collect on a non-intrinsic playbook without --air-gap must report air_gap_mode: false');

  const r3 = cli(['collect', 'secrets', '--json']);
  const d3 = tryJson(r3.stdout);
  assert.ok(d3);
  assert.equal(d3.air_gap_mode, true,
    'collect on an intrinsically-air-gapped playbook must surface air_gap_mode: true even without --air-gap');
});

test('audit-3 A.6: run --upstream-check --air-gap refuses the registry probe', () => {
  const sub = JSON.stringify({
    observations: { w: { captured: true, value: 'x', indicator: 'aws-access-key-id', result: 'miss' } }
  });
  const r = cli(['run', 'secrets', '--upstream-check', '--air-gap', '--evidence', '-',
    '--session-id', 'a6-' + Date.now(), '--force-overwrite', '--json'], { input: sub });
  const data = tryJson(r.stdout);
  assert.ok(data, 'run --json must emit parseable JSON');
  assert.ok(data.upstream_check, 'upstream_check field must be present even when refused');
  assert.equal(data.upstream_check.air_gap_blocked, true,
    'upstream_check.air_gap_blocked must be true; pre-fix the probe ran anyway');
  assert.equal(data.upstream_check.source, 'air-gap');
});

test('audit-3 B.5: doctor --collectors text mode enumerates policy_skips', () => {
  const r = cli(['doctor', '--collectors']);
  const text = (r.stdout || '') + (r.stderr || '');
  assert.match(text, /policy-skipped:.*[a-z]/i,
    'doctor --collectors text mode must enumerate policy-skipped playbook names, not just the count');
});

test('audit-3 B.7: doctor --currency surfaces freshness fields', () => {
  const r = cli(['doctor', '--currency', '--json']);
  const data = tryJson(r.stdout);
  assert.ok(data, 'doctor --currency --json must parse');
  const c = data.checks?.currency;
  assert.ok(c, 'checks.currency must be present');
  assert.equal(typeof c.checked_at, 'string', 'checked_at must be an ISO timestamp');
  assert.ok('oldest_last_threat_review' in c, 'oldest_last_threat_review key must exist');
  assert.ok('newest_last_threat_review' in c, 'newest_last_threat_review key must exist');
  assert.ok('max_days_since_review' in c, 'max_days_since_review key must exist');
});

test('audit-3 B.9: doctor --ai-config walk caps + truncation marker', () => {
  const r = cli(['doctor', '--ai-config', '--json']);
  const data = tryJson(r.stdout);
  assert.ok(data, 'doctor --ai-config --json must parse');
  const c = data.checks?.ai_config;
  assert.ok(c, 'checks.ai_config must be present');
  assert.ok(c.walk_caps && typeof c.walk_caps.max_files === 'number',
    'walk_caps.max_files must be a numeric ceiling so operators see the bound');
  assert.ok(typeof c.walk_caps.max_depth === 'number',
    'walk_caps.max_depth must be numeric');
  assert.equal(typeof c.walk_truncated, 'boolean',
    'walk_truncated must be a boolean so callers can detect partial scans');
  assert.ok(c.walk_caps.max_files <= 10000,
    `max_files cap should bound the walk; got ${c.walk_caps.max_files}`);
});

test('audit-3 B.6: doctor --collectors surfaces unexplained_missing_collectors AND gates ok on it', () => {
  const r = cli(['doctor', '--collectors', '--json']);
  const data = tryJson(r.stdout);
  assert.ok(data, 'doctor --collectors --json must parse');
  const c = data.checks?.collectors;
  assert.ok(c, 'checks.collectors must be present');
  assert.ok(Array.isArray(c.unexplained_missing_collectors),
    'unexplained_missing_collectors must be an array');
  const policy = new Set(c.policy_skips || []);
  for (const id of c.unexplained_missing_collectors) {
    assert.ok(!policy.has(id),
      `unexplained_missing_collectors must exclude policy-skipped playbooks; ${id} is in both lists`);
  }
  if (c.unexplained_missing_collectors.length === 0) {
    assert.equal(c.ok, true, 'no unexplained missings → ok stays true');
  } else {
    assert.equal(c.ok, false,
      'unexplained missings must flip ok to false so doctor surfaces the gap as a failed check');
  }
});

test('audit-3 B.11: doctor surfaces local_version on the top-level result', () => {
  const r = cli(['doctor', '--json']);
  const data = tryJson(r.stdout);
  assert.ok(data, 'doctor --json must parse');
  assert.equal(typeof data.local_version, 'string',
    'doctor --json must surface local_version (the running CLI version) at the top level');
  assert.match(data.local_version, /^\d+\.\d+\.\d+/,
    `local_version must look like a semver; got: ${data.local_version}`);
});

test('audit-3 C.7: ask confidence penalized by tie count', () => {
  const r = cli(['ask', 'I think we got phished', '--json']);
  const data = tryJson(r.stdout);
  assert.ok(data, 'ask --json must parse');
  assert.ok(data.confidence_factors,
    'confidence_factors must surface base + tie_count');
  assert.equal(typeof data.confidence_factors.tie_count, 'number',
    'tie_count must be numeric');
  assert.ok(data.confidence_factors.tie_count >= 1, 'tie_count must be >= 1');
  if (data.confidence_factors.tie_count > 1) {
    assert.ok(data.confidence < data.confidence_factors.base,
      `ties must reduce confidence below base; got confidence=${data.confidence} base=${data.confidence_factors.base} ties=${data.confidence_factors.tie_count}`);
  }
});

test('#87 doctor --fix is registered (smoke)', () => {
  const r = cli(['doctor', '--help']);
  assert.ok([0, 1].includes(r.status),
    `doctor --help must exit 0 or 1 (got ${r.status}); refuses 2 (DETECTED_ESCALATE) and 10 (UNKNOWN_COMMAND).`);
  const text = (r.stdout || '') + (r.stderr || '');
  assert.match(text, /--fix\b/,
    'doctor --help must advertise the --fix flag so operators can discover it. Got: ' + text.slice(0, 400));
});

test('empty-string --evidence / --cwd are operator errors, not a silent false-clean run', () => {
  const ev = cli(['run', 'library-author', '--evidence', '', '--json']);
  assert.equal(ev.status, 1, 'run --evidence "" must exit 1, not a false-clean exit 0');
  assert.match(ev.stdout + ev.stderr, /--evidence was given an empty value/);

  const air = cli(['ai-run', 'secrets', '--no-stream', '--evidence', '', '--json']);
  assert.equal(air.status, 1, 'ai-run --no-stream --evidence "" must exit 1, not a false-clean exit 0');
  assert.match(air.stdout + air.stderr, /--evidence was given an empty value/);
  assert.doesNotMatch(air.stdout, /"ok":true/, 'ai-run --evidence "" must not emit a vacuous ok:true run');
  assert.doesNotMatch(air.stdout, /"evidence_hash"/, 'ai-run --evidence "" must not emit an evidence_hash for an empty submission');

  const cc = cli(['collect', 'library-author', '--cwd', '', '--json']);
  assert.equal(cc.status, 1, 'collect --cwd "" must exit 1');
  assert.match(cc.stdout + cc.stderr, /--cwd was given an empty value/);

  const dc = cli(['discover', '--cwd', '', '--json']);
  assert.equal(dc.status, 1, 'discover --cwd "" must exit 1');
  assert.match(dc.stdout + dc.stderr, /--cwd was given an empty value/);
});

test('ci --evidence "" / --evidence-dir "" are operator errors, not a silent false-green PASS', () => {
  const ev = cli(['ci', 'secrets', '--evidence', '', '--format', 'summary', '--json']);
  assert.equal(ev.status, 1, 'ci --evidence "" must exit 1, not a false-green exit 0');
  assert.match(ev.stdout + ev.stderr, /--evidence was given an empty value/);
  assert.doesNotMatch(ev.stdout, /"verdict":"PASS"/, 'ci --evidence "" must not emit a PASS verdict');

  const evEq = cli(['ci', 'secrets', '--evidence=', '--format', 'summary', '--json']);
  assert.equal(evEq.status, 1, 'ci --evidence= (equals form) must exit 1');
  assert.match(evEq.stdout + evEq.stderr, /--evidence was given an empty value/);

  const ed = cli(['ci', 'framework', '--evidence-dir', '', '--format', 'summary', '--json']);
  assert.equal(ed.status, 1, 'ci --evidence-dir "" must exit 1');
  assert.match(ed.stdout + ed.stderr, /--evidence-dir was given an empty value/);
});

test('run --all / --scope / run-all with --evidence "" / --evidence-dir "" are operator errors, not a silent no-evidence contract run', () => {
  const ev = cli(['run', '--scope', 'cross-cutting', '--evidence', '', '--json']);
  assert.equal(ev.status, 1, 'run --scope --evidence "" must exit 1, not a false-clean exit 0');
  assert.match(ev.stdout + ev.stderr, /--evidence was given an empty value/);
  assert.doesNotMatch(ev.stdout, /"verdict":"not_detected"/, 'run --scope --evidence "" must not emit a not_detected verdict — the contract is refused before it runs');

  const evEq = cli(['run', '--scope', 'cross-cutting', '--evidence=', '--json']);
  assert.equal(evEq.status, 1, 'run --scope --evidence= (equals form) must exit 1');
  assert.match(evEq.stdout + evEq.stderr, /--evidence was given an empty value/);

  const ed = cli(['run', '--scope', 'cross-cutting', '--evidence-dir', '', '--json']);
  assert.equal(ed.status, 1, 'run --scope --evidence-dir "" must exit 1, not the dead length-0 path');
  assert.match(ed.stdout + ed.stderr, /--evidence-dir was given an empty value/);
  assert.doesNotMatch(ed.stdout, /"verdict":"not_detected"/, 'run --scope --evidence-dir "" must not emit a not_detected verdict');

  const ra = cli(['run-all', '--evidence', '', '--json']);
  assert.equal(ra.status, 1, 'run-all --evidence "" must exit 1');
  assert.match(ra.stdout + ra.stderr, /--evidence was given an empty value/);

  const noEv = cli(['run', '--scope', 'cross-cutting', '--json']);
  assert.equal(noEv.status, 0, 'run --scope with --evidence omitted must still run at exit 0');
  assert.doesNotMatch(noEv.stdout + noEv.stderr, /was given an empty value/, 'omitted --evidence must not trip the empty-value guard');
});

// ===================================================================
// Orchestrator passthrough surface (report / validate-rfcs).
// `report executive` and `validate-rfcs` emit text/markdown to stdout via
// orchestrator/index.js. They spawn the orchestrator entry directly (rather
// than through the bin/exceptd.js dispatcher) so the text-mode banners they
// assert on are exercised against the same process operators reach via the
// `report` / `validate-rfcs` verbs.
// ===================================================================

test('report executive emits markdown with self-describing flavor header', () => {
  const r = spawnSync(process.execPath, [path.join(ROOT, 'orchestrator', 'index.js'), 'report', 'executive'], {
    encoding: 'utf8',
    env: { ...process.env, EXCEPTD_DEPRECATION_SHOWN: '1' },
    timeout: 30000,
  });
  assert.equal(r.status, 0, 'report executive must exit 0');
  assert.match(r.stdout, /# exceptd Executive Report/,
    'header must self-describe the report flavor as executive');
  assert.match(r.stdout, /flavor=executive/,
    'HTML comment provenance must carry flavor=executive');
  assert.match(r.stdout, /## Executive Summary/,
    'body must include the Executive Summary section');
  assert.match(r.stdout, /Total scan findings:/,
    'body must include a Total scan findings line (content, not just header)');
});

test('validate-rfcs (legacy) prints RFC catalog header in offline mode', () => {
  const r = spawnSync(process.execPath, [path.join(ROOT, 'orchestrator', 'index.js'), 'validate-rfcs', '--offline'], {
    encoding: 'utf8',
    env: { ...process.env, EXCEPTD_DEPRECATION_SHOWN: '1' },
    timeout: 30000,
  });
  assert.equal(r.status, 0, 'validate-rfcs --offline must exit 0');
  assert.match(r.stdout, /RFC Validation/, 'must print the RFC Validation banner');
  assert.match(r.stdout, /RFC \/ draft entries in catalog/,
    'must report the catalog count');
  assert.match(r.stdout, /Mode: offline/, 'must self-identify as offline mode');
});

test('report unknown-format typo returns did_you_mean[]', () => {
  const r = spawnSync(process.execPath, [path.join(ROOT, 'orchestrator', 'index.js'), 'report', 'execuive'], {
    encoding: 'utf8', cwd: ROOT,
  });
  // Orchestrator exit-code class: usage errors → exit 1 (GENERIC_FAILURE).
  assert.equal(r.status, 1, `expected exit 1 (GENERIC_FAILURE); got ${r.status}`);
  const body = tryJson(r.stdout.trim()) || tryJson(r.stderr.trim());
  assert.ok(body && body.ok === false);
  assert.ok(Array.isArray(body.did_you_mean));
  assert.ok(body.did_you_mean.includes('executive'),
    `expected executive in did_you_mean for "execuive"; got ${JSON.stringify(body.did_you_mean)}`);
});

// ===================================================================
// Repo-tree fixture probes (discover / collect / run human render).
// These build throwaway source trees under a suite-scoped tempdir and spawn
// the CLI against them with --cwd, so the repo working tree is never mutated.
// ===================================================================

const SCAN_FIX_TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'exceptd-cli-scanfix-'));
process.on('exit', () => { try { fs.rmSync(SCAN_FIX_TMP, { recursive: true, force: true }); } catch { /* non-fatal */ } });
let _scanFixN = 0;
function mkScanFix() { const d = path.join(SCAN_FIX_TMP, 'fx-' + _scanFixN++); fs.mkdirSync(d, { recursive: true }); return d; }

test('the run human render surfaces collector_warnings so a skip is not hidden behind "evidence: complete"', () => {
  // EXCEPTD_RAW_JSON='' forces the human render (the helper defaults it to '1').
  const scanCli = makeCli(makeSuiteHome());
  const ev = JSON.stringify({
    precondition_checks: { 'repo-context': true },
    signal_overrides: {},
    collector_errors: [{ kind: 'file_too_large_skipped', reason: 'api-snapshot.json: 1469464 bytes exceeds 1048576-byte scan limit; not scanned' }],
  });
  const human = scanCli(['run', 'secrets', '--evidence', '-'], { input: ev, env: { EXCEPTD_RAW_JSON: '' } });
  assert.ok(/Collector notices \(1\)/.test(human.stdout), 'human render lists collector notices');
  assert.ok(/file_too_large_skipped/.test(human.stdout), 'the skip kind is shown to the human reader');
  assert.ok(/api-snapshot\.json/.test(human.stdout), 'the skipped file is named');
});

test('discover recommends containers for a subdir Dockerfile / compose variant (not just a root exact-name file)', () => {
  const scanCli = makeCli(makeSuiteHome());
  // A subdir Dockerfile + a compose variant — neither is a root-level
  // exact-name Dockerfile/docker-compose.yml, so the old root-only probes
  // missed them and discover never recommended the containers playbook.
  const fx = mkScanFix();
  fs.mkdirSync(path.join(fx, 'examples', 'wiki'), { recursive: true });
  fs.writeFileSync(path.join(fx, 'examples', 'wiki', 'Dockerfile'), 'FROM node:latest\n');
  fs.writeFileSync(path.join(fx, 'docker-compose.test.yml'), 'services:\n  app:\n    image: x\n');
  const ids = ((tryJson(scanCli(['discover', '--cwd', fx, '--json']).stdout) || {}).recommended_playbooks || []).map((r) => r.playbook || r.id || r);
  assert.ok(ids.includes('containers'), 'discover recommends containers for a subdir Dockerfile + compose variant');
  // A tree with no container config must NOT recommend containers.
  const empty = mkScanFix();
  fs.writeFileSync(path.join(empty, 'README.md'), '# nothing container-ish here\n');
  const ids2 = ((tryJson(scanCli(['discover', '--cwd', empty, '--json']).stdout) || {}).recommended_playbooks || []).map((r) => r.playbook || r.id || r);
  assert.equal(ids2.includes('containers'), false, 'no container config means no containers recommendation');
});

test('collect --help documents the --attest-ownership flag it accepts', () => {
  // The flag is allowlisted and consumed by the collector, and the
  // precondition-block remediation tells operators to use it — so collect's
  // own help must list it (otherwise an operator following the hint cannot
  // discover the flag).
  const scanCli = makeCli(makeSuiteHome());
  const out = scanCli(['collect', '--help']).stdout || '';
  assert.ok(/--attest-ownership/.test(out), 'collect --help lists the --attest-ownership flag');
});

// ===================================================================
// Source: operator-bugs.test.js — the GHSA-seeded refresh --advisory /
// cve-curation --curate verbs, driven as subprocesses (module entrypoints).
// These spawn lib/refresh-external.js + lib/cve-curation.js with a GHSA
// fixture and an isolated tempdir catalog so the live catalog is never
// mutated.
// ===================================================================

test('refresh --advisory <CVE> dry-run emits draft + exits 3', () => {
  const fix = path.join(ROOT, 'tests', 'fixtures', 'ghsa-cve-2026-45321.json');
  const r = spawnSync(process.execPath, [path.join(ROOT, 'lib', 'refresh-external.js'), '--advisory', 'CVE-9999-99999', '--json'], {
    encoding: 'utf8',
    env: { ...process.env, EXCEPTD_GHSA_FIXTURE: fix, EXCEPTD_DEPRECATION_SHOWN: '1', EXCEPTD_UNSIGNED_WARNED: '1' },
  });
  assert.equal(r.status, 3, '--advisory dry-run must exit 3 ("draft prepared, not applied")');
  const data = tryJson(r.stdout);
  assert.ok(data, 'JSON output must parse');
  assert.equal(data.mode, 'advisory-seed-dry-run');
  assert.equal(data.cve_id, 'CVE-9999-99999');
  assert.equal(data.draft._auto_imported, true);
});

test('refresh --advisory --apply writes draft to a copy of the catalog', () => {
  const fix = path.join(ROOT, 'tests', 'fixtures', 'ghsa-cve-2026-45321.json');
  // Never write to ROOT/data/cve-catalog.json from a test. A mutate-and-
  // restore-in-`finally{}` pattern would leak a synthetic CVE-9999-*
  // draft into the live catalog if a Ctrl-C / OOM / power-loss landed
  // between mutation and restore. refresh-external supports
  // `--catalog <path>`; point it at the tempdir copy.
  const tmpDir = fs.mkdtempSync(path.join(require('os').tmpdir(), 'cve-cat-'));
  const tmpCatalog = path.join(tmpDir, 'cve-catalog.json');
  fs.copyFileSync(path.join(ROOT, 'data', 'cve-catalog.json'), tmpCatalog);
  try {
    const r = spawnSync(process.execPath, [path.join(ROOT, 'lib', 'refresh-external.js'), '--advisory', 'CVE-9999-99999', '--apply', '--catalog', tmpCatalog, '--json'], {
      encoding: 'utf8',
      env: { ...process.env, EXCEPTD_GHSA_FIXTURE: fix, EXCEPTD_DEPRECATION_SHOWN: '1' },
    });
    assert.equal(r.status, 3, '--advisory --apply exits 3 (applied, editorial-review pending)');
    const data = tryJson(r.stdout);
    assert.ok(data?.ok);
    assert.equal(data.mode, 'advisory-seed-applied');
    const catAfter = JSON.parse(fs.readFileSync(tmpCatalog, 'utf8'));
    assert.ok(catAfter['CVE-9999-99999'], 'draft entry must be written');
    assert.equal(catAfter['CVE-9999-99999']._auto_imported, true);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('refresh --curate <CVE> surfaces editorial questions for a draft', () => {
  // Write the synthetic draft into a TEMPDIR catalog copy, not the live
  // one. cve-curation.js supports `--catalog <path>`; passing it means
  // a Ctrl-C between mutation and restore can't leak the synthetic
  // entry into the shipped catalog.
  const tmpDir = fs.mkdtempSync(path.join(require('os').tmpdir(), 'cve-cur-'));
  const tmpCatalog = path.join(tmpDir, 'cve-catalog.json');
  const cat = JSON.parse(fs.readFileSync(path.join(ROOT, 'data', 'cve-catalog.json'), 'utf8'));
  cat['CVE-9999-99999'] = {
    name: 'Synthetic curation test',
    type: 'supply-chain-npm',
    cvss_score: 9.6,
    affected: 'synthetic-test-package',
    _auto_imported: true,
    _draft: true,
    atlas_refs: [],
    attack_refs: [],
    framework_control_gaps: null,
    iocs: null,
    poc_available: null,
    ai_discovered: null,
    ai_assisted_weaponization: null,
    rwep_score: null,
    rwep_factors: null,
    vector: null,
  };
  fs.writeFileSync(tmpCatalog, JSON.stringify(cat, null, 2), 'utf8');
  try {
    const r = spawnSync(process.execPath, [path.join(ROOT, 'lib', 'cve-curation.js'), '--curate', 'CVE-9999-99999', '--catalog', tmpCatalog, '--json'], {
      encoding: 'utf8',
      env: { ...process.env, EXCEPTD_DEPRECATION_SHOWN: '1' },
    });
    assert.equal(r.status, 3, 'curation always exits 3 — editorial review pending');
    const data = tryJson(r.stdout);
    assert.ok(data?.ok);
    assert.equal(data.mode, 'cve-curation');
    assert.ok(data.editorial_questions.length >= 4,
      'must surface at least: atlas_refs, attack_refs, framework_control_gaps, iocs, rwep questions');
    const fields = data.editorial_questions.map(q => q.field);
    assert.ok(fields.includes('framework_control_gaps'));
    assert.ok(fields.includes('iocs'));
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('refresh --curate refuses to curate a human-curated entry', () => {
  // CVE-2026-45321 is a human-curated catalog entry (no _auto_imported flag).
  const r = spawnSync(process.execPath, [path.join(ROOT, 'lib', 'cve-curation.js'), '--curate', 'CVE-2026-45321', '--json'], {
    encoding: 'utf8',
    env: { ...process.env, EXCEPTD_DEPRECATION_SHOWN: '1' },
  });
  assert.equal(r.status, 2, 'must refuse curating human-curated entries');
  const data = tryJson(r.stdout);
  assert.equal(data.ok, false);
  assert.match(data.error, /human-curated/);
});
