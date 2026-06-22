'use strict';

/**
 * Subject: the `exceptd attest` CLI verb family (verify / diff / prune) plus
 * `reattest`-adjacent attestation behaviour exercised through the CLI.
 *
 * Consolidated from the per-finding attest test files. Each source file's
 * contribution is wrapped in a describe() block carrying its original basename
 * so file-local helper/const names cannot collide across merged sources.
 */

const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const { spawnSync } = require('node:child_process');

const { ROOT, CLI, makeSuiteHome, makeCli, tryJson } = require('./_helpers/cli');
const { withFileSnapshot } = require('./_helpers/snapshot-restore');
const { EXIT_CODES } = require(path.join(ROOT, 'lib', 'exit-codes.js'));

test('attest CLI subject file loaded', () => {
  assert.ok(true);
});

// ===========================================================================
describe('attest-diff-against-empty', () => {
  const SUITE_HOME = makeSuiteHome('exceptd-attest-diff-against-empty-');
  const cli = makeCli(SUITE_HOME);

  const GENERIC_FAILURE = EXIT_CODES.GENERIC_FAILURE; // 1

  function stageSession(sid, playbookId) {
    const dir = path.join(SUITE_HOME, 'attestations', sid);
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(
      path.join(dir, 'attestation.json'),
      JSON.stringify({
        kind: 'attestation',
        playbook_id: playbookId,
        session_id: sid,
        captured_at: '2026-06-19T12:00:00.000Z',
        evidence_hash: 'hash-' + sid,
        submission: {},
      }, null, 2),
    );
    return dir;
  }

  function lastJson(s) {
    return tryJson((s || '').split('\n').filter((l) => l.trim().startsWith('{')).pop() || '') || {};
  }

  test('attest diff --against "" refuses with exit 1 and an empty-value message', () => {
    const sid = 'against-empty-self-' + Date.now();
    stageSession(sid, 'mcp-supply-chain');

    const r = cli(['attest', 'diff', sid, '--against', '', '--json']);
    assert.equal(r.status, GENERIC_FAILURE,
      `empty --against must exit ${GENERIC_FAILURE} (GENERIC_FAILURE), not fall through. Got ${r.status}. stderr=${r.stderr.slice(0, 400)}`);
    const body = lastJson([r.stdout, r.stderr].join('\n'));
    assert.equal(body.ok, false, 'refusal body must carry ok:false');
    assert.equal(body.verb, 'attest diff');
    assert.equal(body.flag, 'against', 'refusal must identify the offending flag');
    assert.match(body.error, /empty value/i, 'message must name the empty-value cause');
  });

  test('attest diff --against= (eq form) also refuses with exit 1', () => {
    const sid = 'against-eq-empty-self-' + (Date.now() + 1);
    stageSession(sid, 'mcp-supply-chain');

    const r = cli(['attest', 'diff', sid, '--against=', '--json']);
    assert.equal(r.status, GENERIC_FAILURE,
      `--against= must exit ${GENERIC_FAILURE}. Got ${r.status}. stderr=${r.stderr.slice(0, 400)}`);
    const body = lastJson([r.stdout, r.stderr].join('\n'));
    assert.equal(body.ok, false);
    assert.match(body.error, /empty value/i);
  });

  test('attest diff with NO --against still runs the auto-prior path (no false refusal)', () => {
    const sid = 'against-absent-self-' + (Date.now() + 2);
    stageSession(sid, 'kernel-lpe-unique-' + Date.now());

    const r = cli(['attest', 'diff', sid, '--json']);
    assert.equal(r.status, 0,
      `no --against with no prior must exit 0 (baseline), not refuse. Got ${r.status}. stderr=${r.stderr.slice(0, 400)}`);
    const body = lastJson(r.stdout);
    assert.equal(body.status, 'no-prior',
      'absent --against must reach the auto-prior branch (no-prior baseline), not the empty-value refusal');
  });
});

// ===========================================================================
describe('attest-diff-asymmetric-catalog-stub', () => {
  const SUITE_HOME = makeSuiteHome('exceptd-attest-diff-asym-');
  const cli = makeCli(SUITE_HOME);
  const HAS_PRIV_KEY = fs.existsSync(path.join(ROOT, '.keys', 'private.pem'));

  function lastJson(s) {
    return tryJson((s || '').split('\n').filter((l) => l.trim().startsWith('{')).pop() || '') || {};
  }

  function makeSession(sid, submission) {
    const r = cli(['run', 'secrets', '--evidence', '-', '--session-id', sid],
      { input: JSON.stringify(submission) });
    assert.equal(r.status, 0, `producer run failed for ${sid}: ${r.stderr.slice(0, 400)}`);
    return r;
  }

  test('real-submission-vs-empty diffs only the genuinely-differing keys (no catalog-stub phantoms)',
    { skip: !HAS_PRIV_KEY && 'producer run requires .keys/private.pem to produce a signed attestation' },
    () => {
      const a = 'asym-a-' + Date.now();
      const b = 'asym-b-' + Date.now();
      makeSession(a, {
        artifacts: { 'env-files': { captured: true, value: 'DB_PASSWORD=hunter2' } },
        signal_overrides: { 'aws-access-key-id': 'hit' },
        verdict: { classification: 'detected' },
      });
      makeSession(b, { observations: {}, verdict: { classification: 'not_detected' } });

      const r = cli(['attest', 'diff', a, '--against', b, '--json', '--force-replay']);
      assert.equal(r.status, 0, `diff must exit 0; stderr=${r.stderr.slice(0, 300)}`);
      const body = lastJson(r.stdout);

      const ad = body.artifact_diff || {};
      const movedIds = [...(ad.added || []), ...(ad.removed || []), ...(ad.changed || [])].map((x) => x.id);
      assert.deepEqual(movedIds, ['env-files'],
        `only env-files may differ; got ${JSON.stringify(movedIds)} — catalog-stub phantoms regressed`);
      assert.equal(ad.total_compared, 1,
        `total_compared must be 1 (the single real key), not the catalog size; got ${ad.total_compared}`);
      const PHANTOM_ARTIFACTS = ['repo-tree', 'auth-config-files', 'ssh-private-keys',
        'iac-credential-bearers', 'secret-regex-scan-text-files', 'world-writable-secret-files'];
      for (const id of PHANTOM_ARTIFACTS) {
        assert.ok(!movedIds.includes(id), `catalog id "${id}" must not be fabricated into the artifact diff`);
      }

      const sd = body.signal_override_diff || {};
      const sigIds = (sd.changed || []).map((x) => x.id);
      assert.deepEqual(sigIds, ['aws-access-key-id'],
        `only aws-access-key-id may differ; got ${JSON.stringify(sigIds)} — inconclusive-stub phantoms regressed`);
      assert.equal(sd.total_compared, 1,
        `signal total_compared must be 1, not the 13-indicator catalog; got ${sd.total_compared}`);
    });

  test('empty-vs-empty still uses the catalog stub uniformly (all-unchanged baseline preserved)',
    { skip: !HAS_PRIV_KEY && 'producer run requires .keys/private.pem to produce a signed attestation' },
    () => {
      const a = 'asym-e-a-' + Date.now();
      const b = 'asym-e-b-' + Date.now();
      const empty = { observations: {}, verdict: { classification: 'not_detected' } };
      makeSession(a, empty);
      makeSession(b, empty);

      const r = cli(['attest', 'diff', a, '--against', b, '--json', '--force-replay']);
      assert.equal(r.status, 0, `diff must exit 0; stderr=${r.stderr.slice(0, 300)}`);
      const body = lastJson(r.stdout);

      const ad = body.artifact_diff || {};
      assert.equal(ad.total_compared, 7, `empty-both artifact total_compared must equal the catalog size; got ${ad.total_compared}`);
      assert.equal((ad.added || []).length, 0, 'empty-both must report 0 added');
      assert.equal((ad.removed || []).length, 0, 'empty-both must report 0 removed');
      assert.equal((ad.changed || []).length, 0, 'empty-both must report 0 changed');
      assert.equal(ad.unchanged_count, 7, 'empty-both must report all catalog artifacts unchanged');

      const sd = body.signal_override_diff || {};
      assert.equal(sd.total_compared, 13, `empty-both signal total_compared must equal the indicator-catalog size; got ${sd.total_compared}`);
      assert.equal((sd.changed || []).length, 0, 'empty-both must report 0 signal changes');
      assert.equal(sd.unchanged_count, 13, 'empty-both must report all indicators unchanged');
    });

  test('real-vs-real artifact diff is a clean passthrough (no catalog ids injected)',
    { skip: !HAS_PRIV_KEY && 'producer run requires .keys/private.pem to produce a signed attestation' },
    () => {
      const a = 'asym-r-a-' + Date.now();
      const b = 'asym-r-b-' + Date.now();
      makeSession(a, { artifacts: { 'env-files': { captured: true, value: 'x' } }, verdict: { classification: 'detected' } });
      makeSession(b, { artifacts: { 'env-files': { captured: true, value: 'y' } }, verdict: { classification: 'detected' } });

      const r = cli(['attest', 'diff', a, '--against', b, '--json', '--force-replay']);
      assert.equal(r.status, 0, `diff must exit 0; stderr=${r.stderr.slice(0, 300)}`);
      const body = lastJson(r.stdout);
      const ad = body.artifact_diff || {};
      assert.equal(ad.total_compared, 1, `real-vs-real must compare only the submitted key; got ${ad.total_compared}`);
      assert.deepEqual((ad.changed || []).map((x) => x.id), ['env-files'], 'the one differing value must be the only change');
      assert.equal((ad.added || []).length, 0, 'real-vs-real must inject no catalog "added" entries');
    });
});

// ===========================================================================
describe('attest-diff-bside-sidecar', () => {
  const SUITE_HOME = makeSuiteHome('exceptd-attest-diff-bside-');
  const cli = makeCli(SUITE_HOME);
  const HAS_PRIV_KEY = fs.existsSync(path.join(ROOT, '.keys', 'private.pem'));

  function locate(sid) {
    const cands = [
      path.join(SUITE_HOME, 'attestations', sid),
      path.join(SUITE_HOME, '.exceptd', 'attestations', sid),
    ];
    const dir = cands.find((p) => fs.existsSync(p));
    if (!dir) return null;
    const f = fs.readdirSync(dir).filter((x) => x.endsWith('.json') && !x.endsWith('.sig'))[0];
    return f ? { dir, jsonFile: path.join(dir, f), sigFile: path.join(dir, f + '.sig') } : null;
  }

  function makeSession(sid) {
    const sub = JSON.stringify({ observations: {}, verdict: { classification: 'not_detected' } });
    const r = cli(['run', 'library-author', '--evidence', '-', '--session-id', sid], { input: sub });
    assert.equal(r.status, 0, `producer run failed: ${r.stderr.slice(0, 400)}`);
    const att = locate(sid);
    assert.ok(att, `attestation must exist after producer run for ${sid}`);
    return att;
  }

  function lastJson(s) {
    return tryJson((s || '').split('\n').filter((l) => l.trim().startsWith('{')).pop() || '') || {};
  }

  test('attest diff --against verifies the B-side sidecar and refuses a tampered comparison (exit 6)',
    { skip: !HAS_PRIV_KEY && 'producer run requires .keys/private.pem to produce a signed attestation' },
    () => {
      const a = 'adiff-a-' + Date.now();
      const b = 'adiff-b-' + Date.now();
      makeSession(a);
      const bAtt = makeSession(b);

      const ok = cli(['attest', 'diff', a, '--against', b, '--json']);
      assert.equal(ok.status, 0, `clean diff must exit 0; stderr=${ok.stderr.slice(0, 300)}`);
      const okBody = lastJson(ok.stdout);
      assert.ok(okBody.b_sidecar_verify && typeof okBody.b_sidecar_verify === 'object',
        'clean diff must surface a b_sidecar_verify object');
      assert.equal(okBody.b_sidecar_verify.verified, true, 'clean B-side sidecar must verify');

      const forged = JSON.parse(fs.readFileSync(bAtt.jsonFile, 'utf8'));
      forged.evidence_hash = 'forged000000000000000000000000000000000000000000000000000000000';
      fs.writeFileSync(bAtt.jsonFile, JSON.stringify(forged, null, 2));

      const r = cli(['attest', 'diff', a, '--against', b, '--json']);
      assert.equal(r.status, 6,
        `diff against a tampered B-side must exit 6 (TAMPERED), not 0. Got ${r.status}. stderr=${r.stderr.slice(0, 400)}`);
      const body = lastJson([r.stdout, r.stderr].join('\n'));
      assert.equal(body.ok, false, 'tamper refusal body must carry ok:false');
      assert.equal(body.verb, 'attest diff');
      assert.ok(body.b_sidecar_verify
        && body.b_sidecar_verify.signed === true
        && body.b_sidecar_verify.verified === false,
        'b_sidecar_verify must show the tampered B-side (signed:true, verified:false)');

      const f = cli(['attest', 'diff', a, '--against', b, '--force-replay', '--json']);
      assert.equal(f.status, 0, `--force-replay must override the B-side tamper refusal; got ${f.status}. stderr=${f.stderr.slice(0, 300)}`);
      const fBody = lastJson(f.stdout);
      assert.equal(fBody.b_sidecar_verify.verified, false,
        'force-replay output must still record the failed B-side verify for audit');
    });
});

// ===========================================================================
describe('attest-diff-multiplaybook-tamper', () => {
  const SUITE_HOME = makeSuiteHome('exceptd-attest-diff-multipb-');
  const cli = makeCli(SUITE_HOME);
  const HAS_PRIV_KEY = fs.existsSync(path.join(ROOT, '.keys', 'private.pem'));

  const TAMPERED = EXIT_CODES.TAMPERED; // 6

  function sessionDir(sid) {
    const cands = [
      path.join(SUITE_HOME, 'attestations', sid),
      path.join(SUITE_HOME, '.exceptd', 'attestations', sid),
    ];
    return cands.find((p) => fs.existsSync(p)) || null;
  }

  function lastJson(s) {
    return tryJson((s || '').split('\n').filter((l) => l.trim().startsWith('{')).pop() || '') || {};
  }

  function makeMultiPlaybookSession(sid, playbook) {
    const sub = JSON.stringify({ observations: {}, verdict: { classification: 'not_detected' } });
    const r = cli(['run', playbook, '--evidence', '-', '--session-id', sid], { input: sub });
    assert.equal(r.status, 0, `producer run failed: ${r.stderr.slice(0, 400)}`);
    const dir = sessionDir(sid);
    assert.ok(dir, `attestation dir must exist after producer run for ${sid}`);

    const canonical = path.join(dir, 'attestation.json');
    const canonicalSig = canonical + '.sig';
    assert.ok(fs.existsSync(canonical), 'producer run must write attestation.json');
    assert.ok(fs.existsSync(canonicalSig), 'producer run must write attestation.json.sig');

    const perPlaybook = path.join(dir, `${playbook}.json`);
    const perPlaybookSig = perPlaybook + '.sig';
    fs.copyFileSync(canonical, perPlaybook);
    fs.copyFileSync(canonicalSig, perPlaybookSig);
    fs.rmSync(canonical);
    fs.rmSync(canonicalSig);

    return { dir, jsonFile: perPlaybook, sigFile: perPlaybookSig };
  }

  function forgeEvidenceHash(jsonFile) {
    const doc = JSON.parse(fs.readFileSync(jsonFile, 'utf8'));
    doc.evidence_hash = 'forged000000000000000000000000000000000000000000000000000000000';
    fs.writeFileSync(jsonFile, JSON.stringify(doc, null, 2));
  }

  test('attest diff --against verifies a run-all A-side by its real file and refuses tamper (exit 6)',
    { skip: !HAS_PRIV_KEY && 'producer run requires .keys/private.pem to produce a signed attestation' },
    () => {
      const a = 'multipb-a-' + Date.now();
      const b = 'multipb-b-' + Date.now();
      const aSess = makeMultiPlaybookSession(a, 'library-author');
      makeMultiPlaybookSession(b, 'library-author');

      const ok = cli(['attest', 'diff', a, '--against', b, '--json']);
      assert.equal(ok.status, 0, `clean run-all diff must exit 0; stderr=${ok.stderr.slice(0, 300)}`);
      const okBody = lastJson(ok.stdout);
      assert.ok(okBody.a_sidecar_verify && typeof okBody.a_sidecar_verify === 'object',
        'clean diff must surface an a_sidecar_verify object');
      assert.equal(okBody.a_sidecar_verify.signed, true, 'A-side must be recognized as signed');
      assert.equal(okBody.a_sidecar_verify.verified, true,
        'untampered run-all A-side must VERIFY — pre-fix it reported no .sig sidecar');

      forgeEvidenceHash(aSess.jsonFile);

      const r = cli(['attest', 'diff', a, '--against', b, '--json']);
      assert.equal(r.status, TAMPERED,
        `forged run-all A-side must exit ${TAMPERED} (TAMPERED), not 0/drifted. Got ${r.status}. stderr=${r.stderr.slice(0, 400)}`);
      const body = lastJson([r.stdout, r.stderr].join('\n'));
      assert.equal(body.ok, false, 'tamper refusal body must carry ok:false');
      assert.equal(body.verb, 'attest diff');
      assert.ok(body.a_sidecar_verify
        && body.a_sidecar_verify.signed === true
        && body.a_sidecar_verify.verified === false,
        'a_sidecar_verify must show the tampered A-side (signed:true, verified:false) — NOT reason:"no .sig sidecar"');
      assert.notEqual(body.a_sidecar_verify.reason, 'no .sig sidecar',
        'the bug is the benign "no .sig sidecar" miss; the fix must report a real signature failure');
    });

  test('attest diff (no --against) verifies a run-all A-side by its real file and refuses tamper (exit 6)',
    { skip: !HAS_PRIV_KEY && 'producer run requires .keys/private.pem to produce a signed attestation' },
    () => {
      const prior = 'multipb-prior-' + Date.now();
      makeMultiPlaybookSession(prior, 'mcp');
      const a = 'multipb-self-' + (Date.now() + 1);
      const aSess = makeMultiPlaybookSession(a, 'mcp');

      const ok = cli(['attest', 'diff', a, '--json']);
      assert.equal(ok.status, 0, `clean no-against diff must exit 0; stderr=${ok.stderr.slice(0, 300)}`);
      const okBody = lastJson(ok.stdout);
      assert.ok(okBody.a_sidecar_verify, 'no-against clean diff must surface a_sidecar_verify');
      assert.equal(okBody.a_sidecar_verify.verified, true,
        'untampered run-all A-side must verify in the no-against branch too');

      forgeEvidenceHash(aSess.jsonFile);

      const r = cli(['attest', 'diff', a, '--json']);
      assert.equal(r.status, TAMPERED,
        `forged run-all A-side (no --against) must exit ${TAMPERED}. Got ${r.status}. stderr=${r.stderr.slice(0, 400)}`);
      const body = lastJson([r.stdout, r.stderr].join('\n'));
      assert.equal(body.ok, false, 'tamper refusal body must carry ok:false');
      assert.ok(body.a_sidecar_verify
        && body.a_sidecar_verify.signed === true
        && body.a_sidecar_verify.verified === false,
        'a_sidecar_verify must show the tampered A-side (signed:true, verified:false)');
      assert.notEqual(body.a_sidecar_verify.reason, 'no .sig sidecar',
        'must report a real signature failure, not the benign no-.sig miss');
    });
});

// ===========================================================================
describe('attest-diff-noagainst-prior-tamper', () => {
  const SUITE_HOME = makeSuiteHome('exceptd-attest-diff-noagainst-');
  const cli = makeCli(SUITE_HOME);
  const HAS_PRIV_KEY = fs.existsSync(path.join(ROOT, '.keys', 'private.pem'));

  const TAMPERED = EXIT_CODES.TAMPERED; // 6

  function locate(sid) {
    const cands = [
      path.join(SUITE_HOME, 'attestations', sid),
      path.join(SUITE_HOME, '.exceptd', 'attestations', sid),
    ];
    const dir = cands.find((p) => fs.existsSync(p));
    if (!dir) return null;
    const f = fs.readdirSync(dir).filter((x) => x.endsWith('.json') && !x.endsWith('.sig'))[0];
    return f ? { dir, jsonFile: path.join(dir, f), sigFile: path.join(dir, f + '.sig') } : null;
  }

  function makeSession(sid, playbook) {
    const sub = JSON.stringify({ precondition_checks: { 'linux-platform': true }, observations: {}, verdict: { classification: 'not_detected' } });
    const r = cli(['run', playbook, '--evidence', '-', '--session-id', sid], { input: sub });
    assert.equal(r.status, 0, `producer run failed: ${r.stderr.slice(0, 400)}`);
    const att = locate(sid);
    assert.ok(att, `attestation must exist after producer run for ${sid}`);
    return att;
  }

  function lastJson(s) {
    return tryJson((s || '').split('\n').filter((l) => l.trim().startsWith('{')).pop() || '') || {};
  }

  test('attest diff (no --against) verifies the auto-selected prior and refuses a tampered prior (exit 6)',
    { skip: !HAS_PRIV_KEY && 'producer run requires .keys/private.pem to produce a signed attestation' },
    () => {
      const prior = 'noagainst-prior-' + Date.now();
      const priorAtt = makeSession(prior, 'crypto');
      const a = 'noagainst-self-' + (Date.now() + 1);
      makeSession(a, 'crypto');

      const ok = cli(['attest', 'diff', a, '--json']);
      assert.equal(ok.status, 0, `clean no-against diff must exit 0; stderr=${ok.stderr.slice(0, 300)}`);
      const okBody = lastJson(ok.stdout);
      assert.ok(okBody.b_sidecar_verify && typeof okBody.b_sidecar_verify === 'object',
        'no-against clean diff must surface a b_sidecar_verify object (prior was never verified pre-fix)');
      assert.equal(okBody.b_sidecar_verify.verified, true,
        'untampered prior (B-side) must verify');

      const forged = JSON.parse(fs.readFileSync(priorAtt.jsonFile, 'utf8'));
      forged.evidence_hash = 'forged000000000000000000000000000000000000000000000000000000000';
      fs.writeFileSync(priorAtt.jsonFile, JSON.stringify(forged, null, 2));

      const r = cli(['attest', 'diff', a, '--json']);
      assert.equal(r.status, TAMPERED,
        `a tampered auto-selected prior must exit ${TAMPERED} (TAMPERED), not 0/drifted. Got ${r.status}. stderr=${r.stderr.slice(0, 400)}`);
      const body = lastJson([r.stdout, r.stderr].join('\n'));
      assert.equal(body.ok, false, 'tamper refusal body must carry ok:false');
      assert.equal(body.verb, 'attest diff');
      assert.ok(body.b_sidecar_verify
        && body.b_sidecar_verify.signed === true
        && body.b_sidecar_verify.verified === false,
        'b_sidecar_verify must show the tampered prior (signed:true, verified:false)');

      const f = cli(['attest', 'diff', a, '--force-replay', '--json']);
      assert.equal(f.status, 0, `--force-replay must override the prior tamper refusal; got ${f.status}. stderr=${f.stderr.slice(0, 300)}`);
      const fBody = lastJson(f.stdout);
      assert.equal(fBody.b_sidecar_verify.verified, false,
        'force-replay output must still record the failed prior verify for audit');
    });

  test('attest diff refuses a prior whose .sig was stripped — sidecar deletion is tamper (exit 6)',
    { skip: !HAS_PRIV_KEY && 'producer run requires .keys/private.pem to produce a signed attestation' },
    () => {
      const prior = 'noagainst-stripped-prior-' + Date.now();
      const priorAtt = makeSession(prior, 'crypto');
      const a = 'noagainst-stripped-self-' + (Date.now() + 1);
      makeSession(a, 'crypto');

      const forged = JSON.parse(fs.readFileSync(priorAtt.jsonFile, 'utf8'));
      forged.evidence_hash = 'stripped00000000000000000000000000000000000000000000000000000000';
      fs.writeFileSync(priorAtt.jsonFile, JSON.stringify(forged, null, 2));
      fs.rmSync(priorAtt.sigFile, { force: true });
      assert.equal(fs.existsSync(priorAtt.sigFile), false, 'the prior sidecar must be deleted for this case');

      const r = cli(['attest', 'diff', a, '--json']);
      assert.equal(r.status, TAMPERED,
        `a stripped-sidecar prior must exit ${TAMPERED} (TAMPERED), not 0/drifted. Got ${r.status}. stderr=${r.stderr.slice(0, 400)}`);
      const body = lastJson([r.stdout, r.stderr].join('\n'));
      assert.equal(body.ok, false, 'tamper refusal body must carry ok:false');
      assert.equal(body.b_sidecar_verify.tamper_class, 'sidecar-missing',
        'a deleted-but-expected sidecar must be classed sidecar-missing, not treated as benign');
    });
});

// ===========================================================================
describe('attest-human-renderers', () => {
  function cli(args, opts = {}) {
    return spawnSync(process.execPath, [CLI, ...args], {
      encoding: 'utf8',
      cwd: opts.cwd || ROOT,
      env: { ...process.env, EXCEPTD_DEPRECATION_SHOWN: '1', ...(opts.env || {}) },
      input: opts.input,
    });
  }

  function localTryJson(s) { try { return JSON.parse(s); } catch { return null; } }

  function setupSession() {
    const evidence = JSON.stringify({
      precondition_checks: { 'linux-platform': true, 'uname-available': true },
      artifacts: { 'kernel-release': '5.15.0-69-generic' },
      signal_overrides: { 'kver-in-affected-range': 'hit' },
    });
    const tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'attest-human-'));
    const env = { EXCEPTD_HOME: tmpHome };
    const r = cli(['run', 'kernel', '--evidence', '-', '--json'],
      { input: evidence, env });
    assert.equal(r.status, 0, `setup run failed: ${r.stderr.slice(0, 200)}`);
    const body = JSON.parse(r.stdout);
    return { tmpHome, env, sessionId: body.session_id };
  }

  test('attest verify default output is human text (not JSON)', () => {
    const { tmpHome, env, sessionId } = setupSession();
    try {
      const r = cli(['attest', 'verify', sessionId], { env });
      assert.equal(localTryJson(r.stdout), null,
        'default attest verify output must NOT be parseable JSON (operator-readable digest)');
      assert.match(r.stdout, new RegExp(`attest verify: ${sessionId}`),
        'header must echo the session id');
      assert.match(r.stdout, /\d+\/\d+ attestation\(s\) verified, \d+\/\d+ replay record\(s\) verified/,
        'verdict counts row must be present regardless of signing state');
      assert.match(r.stdout, /attestation\.json\s+—/,
        'per-file row must include filename + reason');
      assert.match(r.stdout, /→ next: exceptd attest/,
        'next-step block must point at another attest subverb (diff on clean, show/list on tamper)');
    } finally {
      try { fs.rmSync(tmpHome, { recursive: true, force: true }); } catch {}
    }
  });

  test('attest verify --json still emits parseable structured envelope', () => {
    const { tmpHome, env, sessionId } = setupSession();
    try {
      const r = cli(['attest', 'verify', sessionId, '--json'], { env });
      const body = localTryJson(r.stdout);
      assert.ok(body, 'attest verify --json must emit parseable JSON');
      assert.equal(body.verb, 'attest verify');
      assert.equal(body.session_id, sessionId);
      assert.ok(Array.isArray(body.results));
      assert.equal(typeof body.results[0].verified, 'boolean');
    } finally {
      try { fs.rmSync(tmpHome, { recursive: true, force: true }); } catch {}
    }
  });

  test('attest diff default output is human text with status row + sidecar verify class', () => {
    const { tmpHome, env, sessionId } = setupSession();
    try {
      const sid2 = sessionId + '-b';
      const evidence = JSON.stringify({
        precondition_checks: { 'linux-platform': true, 'uname-available': true },
        artifacts: { 'kernel-release': '5.15.0-69-generic' },
        signal_overrides: { 'kver-in-affected-range': 'hit' },
      });
      const setup = cli(['run', 'kernel', '--evidence', '-', '--session-id', sid2, '--force-overwrite'],
        { env, input: evidence });
      assert.equal(setup.status, 0, `second run setup failed: ${setup.stderr.slice(0, 200)}`);
      const r = cli(['attest', 'diff', sid2], { env });
      assert.equal(localTryJson(r.stdout), null,
        'default attest diff output must NOT be parseable JSON');
      assert.match(r.stdout, new RegExp(`attest diff: ${sid2} \\(kernel\\)`),
        'header must include session id + playbook id');
      assert.match(r.stdout, /\[ok\]\s+status=unchanged|\[!\]\s+status=drifted/,
        'status row must carry the verdict icon');
      assert.match(r.stdout, /sidecar verify: \w/,
        'sidecar verify class must appear on the human output');
    } finally {
      try { fs.rmSync(tmpHome, { recursive: true, force: true }); } catch {}
    }
  });
});

// ===========================================================================
describe('attest-prune-dryrun-matches-real', () => {
  function freshHome(prefix) {
    return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  }

  function stage(home, sid, capturedAt) {
    const sdir = path.join(home, 'attestations', sid);
    fs.mkdirSync(sdir, { recursive: true });
    fs.writeFileSync(
      path.join(sdir, 'attestation.json'),
      JSON.stringify({ kind: 'attestation', captured_at: capturedAt }),
    );
    return sdir;
  }

  function sessionDirs(home) {
    const root = path.join(home, 'attestations');
    try {
      return new Set(
        fs.readdirSync(root, { withFileTypes: true })
          .filter((d) => d.isDirectory())
          .map((d) => d.name),
      );
    } catch {
      return new Set();
    }
  }

  const OLD = '2020-01-01T00:00:00.000Z';
  const NEW = '2030-01-01T00:00:00.000Z';
  const CUTOFF = '2026-01-01';

  test('dry-run [would-delete] set equals the set a real run removes from disk', () => {
    const dryHome = freshHome('exceptd-prune-dry-');
    stage(dryHome, 'old-a', OLD);
    stage(dryHome, 'old-b', OLD);
    stage(dryHome, 'keep-c', NEW);
    const before = sessionDirs(dryHome);

    const dryCli = makeCli(dryHome);
    const dry = dryCli(['attest', 'prune', '--all-older-than', CUTOFF, '--dry-run', '--json'], { env: { EXCEPTD_HOME: dryHome } });
    assert.equal(dry.status, 0, `dry-run exit: ${dry.stderr.slice(0, 200)}`);
    const dryBody = tryJson(dry.stdout);
    assert.ok(dryBody && Array.isArray(dryBody.pruned), 'dry-run output carries pruned[]');
    const dryPruned = new Set(dryBody.pruned.map((p) => p.session_id));
    assert.deepEqual(sessionDirs(dryHome), before, 'dry-run must not delete any session');

    const realHome = freshHome('exceptd-prune-real-');
    stage(realHome, 'old-a', OLD);
    stage(realHome, 'old-b', OLD);
    stage(realHome, 'keep-c', NEW);
    const beforeReal = sessionDirs(realHome);

    const realCli = makeCli(realHome);
    const real = realCli(['attest', 'prune', '--all-older-than', CUTOFF, '--json'], { env: { EXCEPTD_HOME: realHome } });
    assert.equal(real.status, 0, `real exit: ${real.stderr.slice(0, 200)}`);
    const realBody = tryJson(real.stdout);
    assert.ok(realBody && Array.isArray(realBody.pruned), 'real output carries pruned[]');

    const afterReal = sessionDirs(realHome);
    const actuallyRemoved = new Set([...beforeReal].filter((s) => !afterReal.has(s)));

    assert.deepEqual(
      [...dryPruned].sort(),
      [...actuallyRemoved].sort(),
      'dry-run [would-delete] set must equal the set the real run actually removes',
    );
    assert.equal(
      realBody.pruned_count,
      actuallyRemoved.size,
      'pruned_count must equal the number of sessions actually removed from disk',
    );

    assert.deepEqual([...actuallyRemoved].sort(), ['old-a', 'old-b'], 'both old sessions removed');
    assert.ok(afterReal.has('keep-c'), 'the future-dated session is kept');
    assert.equal(realBody.kept, 1, 'exactly one session kept');
  });
});

// ===========================================================================
describe('attest-prune-replay-only', () => {
  const SUITE_HOME = makeSuiteHome('exceptd-prune-replay-');
  const cli = makeCli(SUITE_HOME);

  function stageReplayOnly(sid, replayedAt) {
    const sdir = path.join(SUITE_HOME, 'attestations', sid);
    fs.mkdirSync(sdir, { recursive: true });
    fs.writeFileSync(
      path.join(sdir, 'replay-secrets.json'),
      JSON.stringify({ kind: 'replay', replayed_at: replayedAt }),
    );
  }

  test('a replay-only session older than the cutoff is eligible for prune (dated by replayed_at)', () => {
    stageReplayOnly('replayonly-old', '2020-03-01T00:00:00.000Z');
    const r = cli(['attest', 'prune', '--all-older-than', '2026-01-01', '--dry-run', '--json']);
    assert.equal(r.status, 0);
    const body = tryJson(r.stdout);
    assert.ok(body && Array.isArray(body.pruned), 'output carries a pruned[] array');
    const hit = body.pruned.find((p) => p.session_id === 'replayonly-old');
    assert.ok(hit, 'replay-only session must be eligible for prune (was kept forever pre-fix)');
    assert.equal(hit.replayed_at, '2020-03-01T00:00:00.000Z', 'reports the fallback date used');
  });

  test('a replay-only session newer than the cutoff is kept', () => {
    stageReplayOnly('replayonly-recent', '2030-01-01T00:00:00.000Z');
    const r = cli(['attest', 'prune', '--all-older-than', '2026-01-01', '--dry-run', '--json']);
    const body = tryJson(r.stdout);
    assert.ok(
      !body.pruned.find((p) => p.session_id === 'replayonly-recent'),
      'a future-dated replay-only session must not be pruned',
    );
  });
});

// ===========================================================================
describe('attest-prune-root-dedup', () => {
  function prune(cwd, env) {
    return spawnSync(
      process.execPath,
      [CLI, 'attest', 'prune', '--all-older-than', '2026-01-01', '--dry-run', '--json'],
      {
        encoding: 'utf8',
        cwd,
        env: {
          ...process.env,
          EXCEPTD_DEPRECATION_SHOWN: '1',
          EXCEPTD_UNSIGNED_WARNED: '1',
          EXCEPTD_RAW_JSON: '1',
          EXCEPTD_LOCK_DIR: path.join(cwd, '_locks'),
          ...env,
        },
        timeout: 30000,
      },
    );
  }

  function stageSession(rootDir, sid, capturedAt) {
    const sdir = path.join(rootDir, sid);
    fs.mkdirSync(sdir, { recursive: true });
    fs.writeFileSync(
      path.join(sdir, 'attestation.json'),
      JSON.stringify({ session_id: sid, captured_at: capturedAt, kind: 'attestation' }),
    );
  }

  test('same dir reached via relative EXCEPTD_HOME + cwd literal is scanned ONCE, not twice', () => {
    const cwd = fs.mkdtempSync(path.join(os.tmpdir(), 'exceptd-prune-dedup-'));
    try {
      stageSession(path.join(cwd, '.exceptd', 'attestations'), 'sess-AAA', '2020-01-01T00:00:00Z');

      const r = prune(cwd, { EXCEPTD_HOME: '.exceptd' });
      assert.equal(r.status, 0, r.stderr);
      const body = tryJson(r.stdout);
      assert.ok(body && Array.isArray(body.pruned), 'output carries pruned[]');

      assert.equal(body.scanned, 1, 'one session must be scanned exactly once');
      assert.equal(body.pruned_count, 1, 'pruned_count must count the session once');

      const ids = body.pruned.map((p) => p.session_id);
      assert.deepEqual(ids, ['sess-AAA'], 'session listed exactly once (no duplicate)');
      assert.equal(new Set(ids).size, ids.length, 'no duplicate session_id in pruned[]');

      assert.equal(body.roots_searched.length, 1, 'same-dir roots collapse to one');
    } finally {
      fs.rmSync(cwd, { recursive: true, force: true });
    }
  });

  test('two genuinely distinct roots are BOTH still scanned (dedup must not over-collapse)', () => {
    const cwd = fs.mkdtempSync(path.join(os.tmpdir(), 'exceptd-prune-distinct-'));
    try {
      stageSession(path.join(cwd, '.exceptd', 'attestations'), 'sess-CWD', '2020-01-01T00:00:00Z');
      const homeAbs = path.join(cwd, 'fakehome');
      stageSession(path.join(homeAbs, 'attestations'), 'sess-HOME', '2020-01-01T00:00:00Z');

      const r = prune(cwd, { EXCEPTD_HOME: homeAbs });
      assert.equal(r.status, 0, r.stderr);
      const body = tryJson(r.stdout);

      assert.equal(body.scanned, 2, 'both distinct-dir sessions scanned');
      assert.equal(body.roots_searched.length, 2, 'two distinct roots remain two');
      const ids = body.pruned.map((p) => p.session_id).sort();
      assert.deepEqual(ids, ['sess-CWD', 'sess-HOME'], 'each distinct-root session listed once');
    } finally {
      fs.rmSync(cwd, { recursive: true, force: true });
    }
  });
});

// ===========================================================================
describe('attest-require-signed-and-prune', () => {
  function freshHome(prefix) {
    return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  }
  function findSig(home) {
    const stack = [home];
    while (stack.length) {
      const d = stack.pop();
      let ents;
      try { ents = fs.readdirSync(d, { withFileTypes: true }); } catch { continue; }
      for (const e of ents) {
        const full = path.join(d, e.name);
        if (e.isDirectory()) stack.push(full);
        else if (e.name === 'attestation.json.sig') return full;
      }
    }
    return null;
  }

  test('attest verify --require-signed rejects an unsigned/stripped attestation; lenient verify matches the host\'s signing state', () => {
    const home = freshHome('exceptd-reqsigned-');
    const cli = makeCli(home);
    const env = { EXCEPTD_HOME: home };
    try {
      const run = cli(['run', 'secrets', '--evidence', '-', '--session-id', 'rs1'], { input: '{"artifacts":{},"signals":{}}', env });
      assert.equal(run.status, 0, `setup run failed: ${run.stderr.slice(0, 200)}`);
      const sig = findSig(home);
      let wasSigned = false;
      if (sig) { try { wasSigned = JSON.parse(fs.readFileSync(sig, 'utf8')).algorithm === 'Ed25519'; } catch { /* unsigned */ } }
      if (sig) fs.rmSync(sig, { force: true });

      const lenient = cli(['attest', 'verify', 'rs1', '--json'], { env });
      if (wasSigned) {
        assert.equal(lenient.status, 6, 'stripping a SIGNED attestation\'s sidecar must be tamper (exit 6)');
      } else {
        assert.equal(lenient.status, 0, 'lenient verify of a genuinely-unsigned attestation exits 0');
      }

      const strict = cli(['attest', 'verify', 'rs1', '--require-signed', '--json'], { env });
      const body = tryJson(strict.stdout) || tryJson(strict.stderr);
      assert.ok(body && body.ok === false, 'strict verify of an unsigned/stripped attestation must fail');
      if (wasSigned) {
        assert.equal(strict.status, 6, 'stripped signed sidecar under --require-signed is still tamper (exit 6)');
      } else {
        assert.equal(strict.status, 1, '--require-signed on a genuinely-unsigned attestation must exit 1');
        assert.equal(body.require_signed, true);
      }
    } finally {
      fs.rmSync(home, { recursive: true, force: true });
    }
  });

  test('attest verify --require-signed rejects a session with no attestation (empty)', () => {
    const home = freshHome('exceptd-reqsigned-empty-');
    const cli = makeCli(home);
    const env = { EXCEPTD_HOME: home };
    try {
      assert.equal(cli(['run', 'secrets', '--evidence', '-', '--session-id', 'rsE'], { input: '{}', env }).status, 0);
      const sig = findSig(home);
      if (sig) {
        const att = sig.replace(/\.sig$/, '');
        fs.rmSync(att, { force: true });
      }
      const strict = cli(['attest', 'verify', 'rsE', '--require-signed', '--json'], { env });
      assert.equal(strict.status, 1, 'an empty session must fail --require-signed');
      const body = tryJson(strict.stdout) || tryJson(strict.stderr);
      assert.ok(body && body.ok === false && body.require_signed === true);
      assert.match(body.error, /no signed attestation present/);
    } finally {
      fs.rmSync(home, { recursive: true, force: true });
    }
  });

  test('attest prune --all-older-than previews with --dry-run, then deletes', () => {
    const home = freshHome('exceptd-prune-');
    const cli = makeCli(home);
    const env = { EXCEPTD_HOME: home };
    try {
      assert.equal(cli(['run', 'secrets', '--evidence', '-', '--session-id', 'p1'], { input: '{}', env }).status, 0);
      assert.equal(cli(['run', 'crypto', '--evidence', '-', '--session-id', 'p2'], { input: '{"precondition_checks":{"linux-platform":true}}', env }).status, 0);

      const dry = cli(['attest', 'prune', '--all-older-than', '2099-01-01', '--dry-run', '--json'], { env });
      assert.equal(dry.status, 0);
      const dbody = tryJson(dry.stdout);
      assert.ok(dbody && dbody.dry_run === true);
      assert.equal(dbody.pruned_count, 2);
      const listAfterDry = tryJson(cli(['attest', 'list', '--json'], { env }).stdout);
      assert.equal(listAfterDry.count, 2, 'dry-run must not delete');

      const real = cli(['attest', 'prune', '--all-older-than', '2099-01-01', '--json'], { env });
      assert.equal(real.status, 0);
      const rbody = tryJson(real.stdout);
      assert.equal(rbody.dry_run, false);
      assert.equal(rbody.pruned_count, 2);
      const listAfter = tryJson(cli(['attest', 'list', '--json'], { env }).stdout);
      assert.equal(listAfter.count, 0, 'real prune must delete the aged sessions');
    } finally {
      fs.rmSync(home, { recursive: true, force: true });
    }
  });

  test('attest diff --against validates the id with the same gate as the primary sid', () => {
    const home = freshHome('exceptd-against-');
    const cli = makeCli(home);
    const env = { EXCEPTD_HOME: home };
    try {
      assert.equal(cli(['run', 'secrets', '--evidence', '-', '--session-id', 'd1'], { input: '{}', env }).status, 0);
      const r = cli(['attest', 'diff', 'd1', '--against', '../../etc/passwd', '--json'], { env });
      assert.equal(r.status, 1);
      const body = tryJson(r.stderr) || tryJson(r.stdout);
      assert.ok(body && body.ok === false);
      assert.match(body.error, /Invalid session-id/);
      assert.doesNotMatch(body.error, /no session dir found/);
    } finally {
      fs.rmSync(home, { recursive: true, force: true });
    }
  });

  test('attest prune requires --all-older-than', () => {
    const home = freshHome('exceptd-prune2-');
    const cli = makeCli(home);
    try {
      const r = cli(['attest', 'prune', '--json'], { env: { EXCEPTD_HOME: home } });
      assert.equal(r.status, 1);
      const body = tryJson(r.stderr);
      assert.ok(body && body.ok === false);
      assert.match(body.error, /--all-older-than .* is required/);
    } finally {
      fs.rmSync(home, { recursive: true, force: true });
    }
  });

  test('attest prune invalid-date error names --all-older-than, not --since', () => {
    const home = freshHome('exceptd-prune3-');
    const cli = makeCli(home);
    try {
      const r = cli(['attest', 'prune', '--all-older-than', '99', '--json'], { env: { EXCEPTD_HOME: home } });
      assert.equal(r.status, 1);
      const body = tryJson(r.stderr);
      assert.ok(body && body.ok === false);
      assert.match(body.error, /--all-older-than must be a parseable ISO-8601/);
      assert.doesNotMatch(body.error, /--since/);
    } finally {
      fs.rmSync(home, { recursive: true, force: true });
    }
  });
});

// ===========================================================================
describe('attest-verify-replay-isolation', () => {
  const SUITE_HOME = makeSuiteHome('exceptd-attest-verify-replay-');
  const cli = makeCli(SUITE_HOME);

  const PKG_PRIV_KEY = path.join(ROOT, '.keys', 'private.pem');
  const HAS_PRIV_KEY = fs.existsSync(PKG_PRIV_KEY);

  function locateSessionDir(sid) {
    const a = path.join(SUITE_HOME, 'attestations', sid);
    if (fs.existsSync(a)) return a;
    const b = path.join(SUITE_HOME, '.exceptd', 'attestations', sid);
    if (fs.existsSync(b)) return b;
    return null;
  }

  function listSigs(dir) {
    return fs.readdirSync(dir).filter((f) => f.endsWith('.sig'));
  }

  function seedReplayRecord(dir, isoStamp) {
    const body = {
      kind: 'replay',
      session_id: path.basename(dir),
      replayed_at: isoStamp,
    };
    const fname = `replay-${isoStamp.replace(/[:.]/g, '-')}.json`;
    fs.writeFileSync(path.join(dir, fname), JSON.stringify(body) + '\n');
    fs.writeFileSync(path.join(dir, fname + '.sig'), JSON.stringify({ algorithm: 'unsigned' }) + '\n');
    return fname;
  }

  test('case 1: clean session (1 attestation, 0 replays) — exit 0, no replay_tamper',
    { skip: !HAS_PRIV_KEY && 'producer run requires .keys/private.pem' },
    () => {
      const sid = 'replay-iso-clean-' + Date.now();
      const r1 = cli(['run', 'library-author', '--evidence', '-', '--session-id', sid], {
        input: JSON.stringify({ observations: {}, verdict: { classification: 'not_detected' } }),
      });
      assert.equal(r1.status, 0, `producer run must succeed; stderr=${r1.stderr.slice(0, 300)}`);

      const r = cli(['attest', 'verify', sid, '--json']);
      assert.equal(r.status, 0, `verify of clean session must exit 0; got ${r.status}; stderr=${r.stderr.slice(0,300)}`);
      const body = tryJson(r.stdout) || tryJson(r.stderr);
      assert.ok(body, 'verify must emit parseable JSON');
      assert.ok(Array.isArray(body.results), 'results array must be present');
      assert.equal(body.results.length, 1, `clean session has exactly 1 attestation; got ${body.results.length}`);
      assert.ok(Array.isArray(body.replay_results), 'replay_results array must be present even when empty');
      assert.equal(body.replay_results.length, 0, 'clean session has zero replay records');
      assert.notEqual(body.replay_tamper, true, 'replay_tamper must not be set on a clean session');
    });

  test('case 2: 1 attestation + N pre-staged replay records — partitioned cleanly',
    { skip: !HAS_PRIV_KEY && 'producer run requires .keys/private.pem' },
    () => {
      const sid = 'replay-iso-staged-' + Date.now();
      const r1 = cli(['run', 'library-author', '--evidence', '-', '--session-id', sid], {
        input: JSON.stringify({ observations: {}, verdict: { classification: 'not_detected' } }),
      });
      assert.equal(r1.status, 0);
      const dir = locateSessionDir(sid);
      assert.ok(dir, 'session dir must exist post-run');

      seedReplayRecord(dir, '2026-01-01T00-00-00.001Z');
      seedReplayRecord(dir, '2026-01-01T00-00-00.002Z');
      seedReplayRecord(dir, '2026-01-01T00-00-00.003Z');

      const r = cli(['attest', 'verify', sid, '--json']);
      const body = tryJson(r.stdout) || tryJson(r.stderr) || {};
      assert.ok(Array.isArray(body.results), 'results array must be present');
      assert.ok(Array.isArray(body.replay_results), 'replay_results array must be present');
      assert.equal(body.results.length, 1, `exactly 1 primary attestation expected; got ${body.results.length}`);
      assert.equal(body.replay_results.length, 3,
        `exactly 3 replay records expected after seeding; got ${body.replay_results.length}`);
      assert.equal(r.status, 0, `replay-only tamper preserves exit 0; got ${r.status}`);
      assert.equal(body.replay_tamper, true, 'unsigned-substitution replay sidecars must set replay_tamper=true');
      assert.ok(Array.isArray(body.warnings) && body.warnings.length > 0,
        'replay tamper must surface warnings explaining the audit-trail corruption');
      assert.equal(body.results[0].verified, true,
        'primary attestation must still verify even when replays are tampered');
    });

  test('case 3: tampered replay record alone → exit 0 + replay_tamper:true + warnings',
    { skip: !HAS_PRIV_KEY && 'producer run requires .keys/private.pem' },
    () => {
      const sid = 'replay-iso-tampered-replay-' + Date.now();
      const r1 = cli(['run', 'library-author', '--evidence', '-', '--session-id', sid], {
        input: JSON.stringify({ observations: {}, verdict: { classification: 'not_detected' } }),
      });
      assert.equal(r1.status, 0);
      const dir = locateSessionDir(sid);
      assert.ok(dir);
      const fname = seedReplayRecord(dir, '2026-02-01T00-00-00.000Z');

      fs.writeFileSync(path.join(dir, fname + '.sig'),
        JSON.stringify({ algorithm: 'unsigned' }) + '\n');

      const r = cli(['attest', 'verify', sid, '--json']);
      assert.equal(r.status, 0,
        `replay tamper alone must leave exit at 0 (audit-trail signal, not attestation tamper); got ${r.status}`);
      const body = tryJson(r.stdout) || tryJson(r.stderr) || {};
      assert.equal(body.replay_tamper, true, 'replay_tamper must surface true on tampered replay');
      assert.ok(Array.isArray(body.warnings) && body.warnings.length > 0,
        'warnings array must be non-empty when replay is tampered');
      assert.equal(body.results[0].verified, true,
        'attestation itself must still pass when only the replay is tampered');
    });

  test('case 4: tampered attestation → exit 6 (TAMPERED) regardless of replay state',
    { skip: !HAS_PRIV_KEY && 'producer run requires .keys/private.pem' },
    () => {
      const sid = 'replay-iso-tampered-att-' + Date.now();
      const r1 = cli(['run', 'library-author', '--evidence', '-', '--session-id', sid], {
        input: JSON.stringify({ observations: {}, verdict: { classification: 'not_detected' } }),
      });
      assert.equal(r1.status, 0);
      const dir = locateSessionDir(sid);
      assert.ok(dir);
      const primarySig = listSigs(dir).find((f) => !f.startsWith('replay-'));
      assert.ok(primarySig, 'primary attestation sidecar must exist');
      const primarySigPath = path.join(dir, primarySig);

      return withFileSnapshot([primarySigPath], async () => {
        fs.writeFileSync(primarySigPath, JSON.stringify({ algorithm: 'unsigned' }) + '\n');
        seedReplayRecord(dir, '2026-03-01T00-00-00.000Z');

        const r = cli(['attest', 'verify', sid, '--json']);
        assert.equal(r.status, 6,
          `tampered attestation must exit 6 (TAMPERED); got ${r.status}; stderr=${r.stderr.slice(0,300)}`);
        const body = tryJson(r.stdout) || tryJson(r.stderr) || {};
        assert.equal(body.ok, false, 'tampered attestation must surface ok:false');
        assert.notEqual(body.replay_tamper, true,
          'when attestation tamper fires, replay_tamper is not the load-bearing signal — exit-6 carries it');
      });
    });
});

// ===========================================================================
// attest verify contributions split out of mixed source files.
// ===========================================================================
describe('attestation-durability (attest verify slice)', () => {
  function freshHome(prefix) {
    return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  }
  function sessionDir(home, sid) { return path.join(home, 'attestations', sid); }

  test('attest verify flags a deleted sidecar as tamper when one was expected (matches reattest)', () => {
    const home = freshHome('exceptd-sigdel-');
    try {
      const cli = makeCli(home);
      const env = { EXCEPTD_HOME: home };
      const run = cli(['run', 'secrets', '--evidence', '-', '--session-id', 'sd1'], { input: '{}', env });
      assert.equal(run.status, 0, `setup run failed: ${run.stderr.slice(0, 160)}`);
      const dir = sessionDir(home, 'sd1');
      const sigPath = path.join(dir, 'attestation.json.sig');
      const wasSigned = (() => { try { return JSON.parse(fs.readFileSync(sigPath, 'utf8')).algorithm === 'Ed25519'; } catch { return false; } })();
      fs.rmSync(sigPath, { force: true });
      const v = cli(['attest', 'verify', 'sd1', '--json'], { env });
      if (wasSigned) {
        assert.equal(v.status, 6, 'a deleted sidecar where one was expected must be tamper (exit 6)');
        const body = tryJson(v.stdout) || tryJson(v.stderr);
        assert.ok(body, 'must emit a structured verify result');
      } else {
        assert.equal(v.status, 0, 'keyless-host stripped sidecar stays benign');
      }
    } finally {
      fs.rmSync(home, { recursive: true, force: true });
    }
  });
});

// ===========================================================================
describe('attestation-signature-roundtrip (attest verify slice)', () => {
  const SUITE_HOME = makeSuiteHome('exceptd-audit-vv-trust-attest-');
  const cli = makeCli(SUITE_HOME);

  const PKG_PRIV_KEY = path.join(ROOT, '.keys', 'private.pem');
  const HAS_PRIV_KEY = fs.existsSync(PKG_PRIV_KEY);

  function locateAttestationFiles(sid) {
    const candidates = [
      path.join(SUITE_HOME, 'attestations', sid),
      path.join(SUITE_HOME, '.exceptd', 'attestations', sid),
    ];
    const attRoot = candidates.find((p) => fs.existsSync(p));
    if (!attRoot) return null;
    const files = fs.readdirSync(attRoot);
    const jsonFiles = files.filter((f) => f.endsWith('.json') && !f.endsWith('.sig'));
    return {
      dir: attRoot,
      files: jsonFiles,
      primaryJson: jsonFiles.includes('attestation.json')
        ? path.join(attRoot, 'attestation.json')
        : path.join(attRoot, jsonFiles[0]),
      primarySig: jsonFiles.includes('attestation.json')
        ? path.join(attRoot, 'attestation.json.sig')
        : path.join(attRoot, jsonFiles[0] + '.sig'),
    };
  }

  test('KK P1-1 — sidecar shape no longer carries signed_at / signs_path / signs_sha256',
    { skip: !HAS_PRIV_KEY && 'producer run requires .keys/private.pem' },
    () => {
      const sid = 'vv-trust-shape-' + Date.now();
      const sub = JSON.stringify({ observations: {}, verdict: { classification: 'not_detected' } });
      const r1 = cli(['run', 'library-author', '--evidence', '-', '--session-id', sid], { input: sub });
      assert.equal(r1.status, 0, `producer run must succeed; stderr=${r1.stderr.slice(0, 400)}`);

      const att = locateAttestationFiles(sid);
      assert.ok(att, 'attestation must exist after producer run');
      const sigDoc = JSON.parse(fs.readFileSync(att.primarySig, 'utf8'));

      assert.equal(sigDoc.signed_at, undefined,
        `signed_at MUST be absent from the sidecar. Got ${JSON.stringify(sigDoc.signed_at)}`);
      assert.equal(sigDoc.signs_path, undefined,
        `signs_path MUST be absent from the sidecar. Got ${JSON.stringify(sigDoc.signs_path)}`);
      assert.equal(sigDoc.signs_sha256, undefined,
        `signs_sha256 MUST be absent from the sidecar. Got ${JSON.stringify(sigDoc.signs_sha256)}`);

      assert.equal(sigDoc.algorithm, 'Ed25519', 'sidecar.algorithm must be exactly "Ed25519"');
      assert.equal(typeof sigDoc.signature_base64, 'string',
        'sidecar.signature_base64 must be a string (the actual Ed25519 sig)');
      assert.ok(sigDoc.signature_base64.length > 40,
        'sidecar.signature_base64 must be a non-trivial base64 string');
    });

  test('KK P1-1 — rewriting a legacy signed_at on a legacy sidecar is a verify no-op (forwards-compat)',
    { skip: !HAS_PRIV_KEY && 'producer run requires .keys/private.pem' },
    () => {
      const sid = 'vv-trust-legacy-signed-at-' + Date.now();
      const sub = JSON.stringify({ observations: {}, verdict: { classification: 'not_detected' } });
      const r1 = cli(['run', 'library-author', '--evidence', '-', '--session-id', sid], { input: sub });
      assert.equal(r1.status, 0);

      const att = locateAttestationFiles(sid);
      assert.ok(att);
      const sigDoc = JSON.parse(fs.readFileSync(att.primarySig, 'utf8'));
      sigDoc.signed_at = '1970-01-01T00:00:00.000Z';
      sigDoc.signs_path = 'this-file-does-not-exist.json';
      sigDoc.signs_sha256 = 'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=';
      fs.writeFileSync(att.primarySig, JSON.stringify(sigDoc, null, 2));

      const r = cli(['attest', 'verify', sid, '--json']);
      assert.equal(r.status, 0,
        `verify must still succeed (exit 0) after rewriting unsigned legacy fields. Got status=${r.status}. stderr=${r.stderr.slice(0, 400)}`);
      const body = tryJson(r.stdout) || {};
      assert.equal(body.verb, 'attest verify');
      assert.ok(Array.isArray(body.results), 'verify must emit a results array');
      const verified = body.results.find((x) => x.verified === true);
      assert.ok(verified,
        'at least one result must be verified:true (signed_at/signs_path/signs_sha256 are NOT part of the signed message)');
    });

  test('KK P1-1 — rewriting attestation.captured_at INVALIDATES the signature (exit 6)',
    { skip: !HAS_PRIV_KEY && 'producer run requires .keys/private.pem' },
    () => {
      const sid = 'vv-trust-captured-at-' + Date.now();
      const sub = JSON.stringify({ observations: {}, verdict: { classification: 'not_detected' } });
      const r1 = cli(['run', 'library-author', '--evidence', '-', '--session-id', sid], { input: sub });
      assert.equal(r1.status, 0);

      const att = locateAttestationFiles(sid);
      assert.ok(att);
      const att0 = fs.readFileSync(att.primaryJson, 'utf8');
      const tampered = att0.replace(/"captured_at"\s*:\s*"[^"]+"/, '"captured_at": "1970-01-01T00:00:00.000Z"');
      assert.notEqual(tampered, att0, 'captured_at rewrite must actually change the file');
      fs.writeFileSync(att.primaryJson, tampered);

      const r = cli(['attest', 'verify', sid, '--json']);
      assert.equal(r.status, 6,
        `rewriting captured_at on the SIGNED attestation file must exit 6 (TAMPERED). Got status=${r.status}. stderr=${r.stderr.slice(0, 400)}`);
      const body = tryJson(r.stdout) || tryJson(r.stderr) || {};
      assert.equal(body.ok, false, 'tamper body must carry ok:false');
      const failed = body.results.find((x) => x.signed === true && x.verified === false);
      assert.ok(failed,
        'at least one result must classify as signed-but-invalid (the captured_at rewrite broke the Ed25519 signature)');
    });

  test('KK P1-2 — attest verify surfaces both the original attestation AND the replay in results',
    { skip: !HAS_PRIV_KEY && 'producer run requires .keys/private.pem' },
    () => {
      const sid = 'vv-trust-replay-listed-' + Date.now();
      const sub = JSON.stringify({ observations: {}, verdict: { classification: 'not_detected' } });
      const r1 = cli(['run', 'library-author', '--evidence', '-', '--session-id', sid], { input: sub });
      assert.equal(r1.status, 0);

      const att = locateAttestationFiles(sid);
      assert.ok(att);

      fs.writeFileSync(att.primarySig, JSON.stringify({
        algorithm: 'unsigned',
        signed: false,
      }, null, 2));

      const r2 = cli(['reattest', sid, '--force-replay', '--json']);
      assert.equal(r2.status, 0);
      const replayBody = tryJson(r2.stdout) || {};
      assert.ok(replayBody.replay_persisted && replayBody.replay_persisted.path);

      const refreshed = locateAttestationFiles(sid);
      assert.ok(refreshed);
      assert.ok(refreshed.files.length >= 2,
        `session dir must contain >= 2 .json files after force-replay (original + replay). Got ${refreshed.files.length}: ${refreshed.files.join(',')}`);
      const replayFile = refreshed.files.find((f) => f.startsWith('replay-'));
      assert.ok(replayFile,
        `session dir must contain a replay-*.json file. Got: ${refreshed.files.join(',')}`);

      const r = cli(['attest', 'verify', sid, '--json']);
      assert.equal(r.status, 6,
        `attest verify after a substituted-original force-replay must surface tamper class via exit 6. Got status=${r.status}.`);
      const body = tryJson(r.stdout) || tryJson(r.stderr) || {};
      assert.ok(Array.isArray(body.results), 'verify must emit a results array');
      assert.ok(Array.isArray(body.replay_results), 'verify must emit a replay_results array');
      const replayResult = body.replay_results.find((x) => x.file && x.file.startsWith('replay-'));
      assert.ok(replayResult,
        `verify replay_results must include the replay-*.json file. Got files: ${body.replay_results.map((x) => x.file).join(',')}`);
    });

  test('KK P1-3 — attest verify refuses sidecar with algorithm:"RSA-PSS" (exit 6, algorithm-unsupported)',
    { skip: !HAS_PRIV_KEY && 'producer run requires .keys/private.pem' },
    () => {
      const sid = 'vv-trust-algo-rsa-' + Date.now();
      const sub = JSON.stringify({ observations: {}, verdict: { classification: 'not_detected' } });
      const r1 = cli(['run', 'library-author', '--evidence', '-', '--session-id', sid], { input: sub });
      assert.equal(r1.status, 0);

      const att = locateAttestationFiles(sid);
      assert.ok(att);
      const sigDoc = JSON.parse(fs.readFileSync(att.primarySig, 'utf8'));
      sigDoc.algorithm = 'RSA-PSS';
      fs.writeFileSync(att.primarySig, JSON.stringify(sigDoc, null, 2));

      const r = cli(['attest', 'verify', sid, '--json']);
      assert.equal(r.status, 6,
        `attest verify must exit 6 (TAMPERED) on a downgrade-bait algorithm field. Got status=${r.status}. stderr=${r.stderr.slice(0, 400)}`);
      const body = tryJson(r.stdout) || tryJson(r.stderr) || {};
      assert.equal(body.ok, false);
      assert.equal(body.verb, 'attest verify');
      const algResult = body.results.find((x) => x.tamper_class === 'algorithm-unsupported');
      assert.ok(algResult,
        `at least one result must classify as tamper_class:"algorithm-unsupported". Got: ${JSON.stringify(body.results)}`);
      assert.equal(algResult.signed, false, 'algorithm-unsupported result must carry signed:false');
      assert.equal(algResult.verified, false, 'algorithm-unsupported result must carry verified:false');
      assert.match(algResult.reason, /unsupported algorithm:/,
        'reason must start with "unsupported algorithm:" for log scrapers');
    });

  test('KK P1-3 — attest verify refuses sidecar with algorithm:null (exit 6, algorithm-unsupported)',
    { skip: !HAS_PRIV_KEY && 'producer run requires .keys/private.pem' },
    () => {
      const sid = 'vv-trust-algo-null-' + Date.now();
      const sub = JSON.stringify({ observations: {}, verdict: { classification: 'not_detected' } });
      const r1 = cli(['run', 'library-author', '--evidence', '-', '--session-id', sid], { input: sub });
      assert.equal(r1.status, 0);

      const att = locateAttestationFiles(sid);
      assert.ok(att);
      const sigDoc = JSON.parse(fs.readFileSync(att.primarySig, 'utf8'));
      sigDoc.algorithm = null;
      fs.writeFileSync(att.primarySig, JSON.stringify(sigDoc, null, 2));

      const r = cli(['attest', 'verify', sid, '--json']);
      assert.equal(r.status, 6,
        `attest verify must exit 6 (TAMPERED) on algorithm:null. Got status=${r.status}. stderr=${r.stderr.slice(0, 400)}`);
      const body = tryJson(r.stdout) || tryJson(r.stderr) || {};
      const algResult = body.results.find((x) => x.tamper_class === 'algorithm-unsupported');
      assert.ok(algResult,
        `algorithm:null must classify as algorithm-unsupported. Got: ${JSON.stringify(body.results)}`);
      assert.equal(algResult.signed, false);
      assert.equal(algResult.verified, false);
    });
});

// ===========================================================================
describe('attestation-trust-boundary (attest verify slice)', () => {
  const SUITE_HOME = makeSuiteHome('exceptd-audit-aa-trust-attest-');
  const cli = makeCli(SUITE_HOME);

  const PKG_PRIV_KEY = path.join(ROOT, '.keys', 'private.pem');
  const HAS_PRIV_KEY = fs.existsSync(PKG_PRIV_KEY);

  function locateAttestation(sid) {
    const candidates = [
      path.join(SUITE_HOME, 'attestations', sid),
      path.join(SUITE_HOME, '.exceptd', 'attestations', sid),
    ];
    const attRoot = candidates.find(p => fs.existsSync(p));
    if (!attRoot) return null;
    const files = fs.readdirSync(attRoot).filter(f => f.endsWith('.json') && !f.endsWith('.sig'));
    if (files.length === 0) return null;
    return {
      dir: attRoot,
      jsonFile: path.join(attRoot, files[0]),
      sigFile: path.join(attRoot, files[0] + '.sig'),
    };
  }

  test('Fix 2(b) — attest verify exits 6 with structured body on corrupt sidecar (not generic exit 1)',
    { skip: !HAS_PRIV_KEY && 'producer run requires .keys/private.pem' },
    () => {
      const sid = 'aa-trust-verify-corrupt-' + Date.now();
      const sub = JSON.stringify({ observations: {}, verdict: { classification: 'not_detected' } });
      const r1 = cli(['run', 'library-author', '--evidence', '-', '--session-id', sid], { input: sub });
      assert.equal(r1.status, 0);

      const att = locateAttestation(sid);
      assert.ok(att);
      fs.writeFileSync(att.sigFile, '{"algorithm":"Ed25519"');  // unterminated JSON

      const r = cli(['attest', 'verify', sid, '--json']);
      assert.equal(r.status, 6,
        `attest verify on a corrupt sidecar must exit 6 (TAMPERED), not 1 (generic). Got status=${r.status}. stderr=${r.stderr.slice(0, 400)}`);
      const body = tryJson(r.stdout) || tryJson(r.stderr) || {};
      assert.equal(body.ok, false, 'corrupt-sidecar verify body must carry ok:false');
      assert.equal(body.verb, 'attest verify');
      assert.ok(Array.isArray(body.results),
        'verify must still emit a results array on corrupt sidecar (no unhandled throw)');
      assert.ok(body.results.length >= 1, 'results must be non-empty');
      const corruptResult = body.results.find(x => x.tamper_class === 'sidecar-corrupt');
      assert.ok(corruptResult, 'at least one result must classify as tamper_class:"sidecar-corrupt"');
      assert.equal(corruptResult.verified, false, 'corrupt-sidecar result must explicitly carry verified:false');
      assert.equal(corruptResult.signed, false, 'corrupt-sidecar result must explicitly carry signed:false');
      assert.equal(typeof corruptResult.reason, 'string',
        'corrupt-sidecar result must carry a human-readable reason string');
      assert.match(corruptResult.reason, /sidecar parse error:/,
        'reason must start with "sidecar parse error:" for log scrapers');
    });

  test('Fix 3 — attest verify exits 6 when an unsigned sidecar is substituted on a host WITH .keys/private.pem',
    { skip: !HAS_PRIV_KEY && 'substitution detection requires .keys/private.pem on the verifying host (see R-F1 skip pattern)' },
    () => {
      const sid = 'aa-trust-subst-' + Date.now();
      const sub = JSON.stringify({ observations: {}, verdict: { classification: 'not_detected' } });
      const r1 = cli(['run', 'library-author', '--evidence', '-', '--session-id', sid], { input: sub });
      assert.equal(r1.status, 0, `producer run must succeed; stderr=${r1.stderr.slice(0, 400)}`);

      const att = locateAttestation(sid);
      assert.ok(att);

      const orig = fs.readFileSync(att.jsonFile, 'utf8');
      fs.writeFileSync(att.jsonFile, orig.replace(/\}\s*$/, ', "__tampered": true }'));
      fs.writeFileSync(att.sigFile, JSON.stringify({
        algorithm: 'unsigned',
        signed: false,
        reason: 'attestation explicitly unsigned',
        signs_path: path.basename(att.jsonFile),
      }, null, 2));

      const r = cli(['attest', 'verify', sid, '--json']);
      assert.equal(r.status, 6,
        `attest verify on an unsigned-substituted sidecar must exit 6 (TAMPERED) when .keys/private.pem is present. Got status=${r.status}. stderr=${r.stderr.slice(0, 400)}`);
      const body = tryJson(r.stdout) || tryJson(r.stderr) || {};
      assert.equal(body.ok, false, 'substitution body must carry ok:false');
      assert.equal(body.verb, 'attest verify');
      assert.ok(Array.isArray(body.results), 'verify must emit a results array');
      const substResult = body.results.find(x => x.tamper_class === 'unsigned-substitution');
      assert.ok(substResult, 'at least one result must classify as tamper_class:"unsigned-substitution"');
      assert.equal(substResult.verified, false, 'substitution result must carry verified:false');
      assert.equal(substResult.signed, false, 'substitution result must carry signed:false');
    });
});

// ===========================================================================
describe('cli-coverage', () => {
  const SUITE_HOME = makeSuiteHome('exceptd-cli-cov-attest-');
  const cli = makeCli(SUITE_HOME);

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
});

// ===========================================================================
describe('cli-exit-codes', () => {
  const SUITE_HOME = makeSuiteHome('exceptd-audit-r-attest-');
  const cli = makeCli(SUITE_HOME);

  test('R-F1: attest verify on a tampered attestation exits 6 with ok:false', { skip: !fs.existsSync(path.join(ROOT, '.keys', 'private.pem')) && 'private key absent — signed-tamper path cannot be exercised without .keys/private.pem' }, () => {
    const sid = 'rf1-tamper-' + Date.now();
    const sub = JSON.stringify({ observations: {}, verdict: { classification: 'not_detected' } });
    const r1 = cli(['run', 'library-author', '--evidence', '-', '--session-id', sid], { input: sub });
    assert.equal(r1.status, 0, 'pre-tamper run must succeed; stderr=' + r1.stderr.slice(0, 400));

    const candidates = [
      path.join(SUITE_HOME, 'attestations', sid),
      path.join(SUITE_HOME, '.exceptd', 'attestations', sid),
    ];
    const attRoot = candidates.find(p => fs.existsSync(p));
    assert.ok(attRoot, 'attestation directory must exist after run; tried: ' + JSON.stringify(candidates));
    const files = fs.readdirSync(attRoot).filter(f => f.endsWith('.json') && !f.endsWith('.sig'));
    assert.ok(files.length >= 1, 'at least one attestation .json must exist; found: ' + JSON.stringify(files));
    const target = path.join(attRoot, files[0]);

    const rOk = cli(['attest', 'verify', sid, '--json']);
    const okBody = tryJson(rOk.stdout) || tryJson(rOk.stderr) || {};
    assert.ok(okBody.results && okBody.results.length >= 1, 'pre-tamper verify must emit results');

    const orig = fs.readFileSync(target, 'utf8');
    const tampered = orig.replace(/\}\s*$/, ', "__tampered": true }');
    assert.notEqual(tampered, orig, 'tamper transform must alter bytes');
    fs.writeFileSync(target, tampered, 'utf8');

    const r = cli(['attest', 'verify', sid, '--json']);
    assert.equal(r.status, 6,
      `attest verify on a tampered attestation must exit 6 (TAMPERED). Got status=${r.status}. stdout=${r.stdout.slice(0,400)} stderr=${r.stderr.slice(0,400)}`);
    const body = tryJson(r.stdout) || tryJson(r.stderr) || {};
    assert.equal(body.ok, false, 'tampered verify body must carry ok:false');
    assert.ok(Array.isArray(body.results), 'verify result must include results array');
    assert.ok(body.results.some(x => x.signed === true && x.verified === false),
      'at least one result must report signed:true verified:false');
  });

  test('R-F7: attest show rejects path-traversal session-id with validation error (not "no session dir")', () => {
    const r = cli(['attest', 'show', '../../..', '--json']);
    assert.equal(r.status, 1, 'path-traversal session-id must exit 1 (validation refusal). status=' + r.status);
    const err = tryJson(r.stderr.trim()) || {};
    assert.equal(err.ok, false);
    assert.match(err.error || '', /Invalid session-id|Must match/,
      'attest <verb> with a traversal-shaped id must surface the validation error, not the lookup-miss error. Got: ' + (err.error || ''));
    assert.doesNotMatch(err.error || '', /no session dir for/,
      'pre-fix: findSessionDir collapsed validation failure to the not-found path. Got: ' + (err.error || ''));
  });

  test('R-F7: attest show with a valid-shape but missing session id still emits the not-found error', () => {
    const r = cli(['attest', 'show', 'definitely-not-a-real-session-' + Date.now(), '--json']);
    assert.equal(r.status, 1, 'valid-shape but missing session-id must exit 1 (not-found). status=' + r.status);
    const err = tryJson(r.stderr.trim()) || {};
    assert.equal(err.ok, false);
    assert.match(err.error || '', /no session dir for/,
      'a valid-shape id that simply does not exist must still emit the not-found message');
  });

  test('R-F10: attest list --since 99 is refused (regex check before Date.parse)', () => {
    const r = cli(['attest', 'list', '--since', '99', '--json']);
    assert.equal(r.status, 1,
      'attest list --since 99 must exit 1 (regex refusal — Date.parse silently maps "99" to 1999-12-01). status=' + r.status);
    const err = tryJson(r.stderr.trim()) || {};
    assert.equal(err.ok, false);
    assert.match(err.error || '', /ISO-8601 calendar timestamp/,
      'error must name the ISO-8601-calendar requirement so the operator knows what shape to use. Got: ' + (err.error || ''));
  });

  test('R-F10: reattest --since 99 is refused (same regex contract)', () => {
    const r = cli(['reattest', 'somesid', '--since', '99', '--json']);
    assert.equal(r.status, 1,
      'reattest --since 99 must exit 1 (regex refusal). status=' + r.status);
    const err = tryJson(r.stderr.trim()) || {};
    assert.equal(err.ok, false);
    assert.match(err.error || '', /ISO-8601 calendar timestamp/,
      'reattest must enforce the same regex contract as attest list. Got: ' + (err.error || ''));
  });

  test('R-F10 positive: --since 2026-05-01 is accepted (regex still passes legitimate inputs)', () => {
    const r = cli(['attest', 'list', '--since', '2026-05-01', '--json']);
    const out = tryJson(r.stdout) || tryJson(r.stderr.trim()) || {};
    if (out.error) {
      assert.doesNotMatch(out.error, /ISO-8601 calendar timestamp/,
        'a real ISO-8601 date must not be rejected by the regex gate. Got: ' + out.error);
    }
  });
});

// ===========================================================================
describe('cli-output-envelope-shape', () => {
  function cliEnv(args, opts = {}) {
    return spawnSync(process.execPath, [CLI, ...args], {
      encoding: 'utf8',
      cwd: opts.cwd || ROOT,
      env: { ...process.env, ...(opts.env || {}), EXCEPTD_DEPRECATION_SHOWN: '1' },
    });
  }

  test('attest list --json envelope: exact top-level key set', () => {
    const tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'envelope-home-'));
    const tmpCwd = fs.mkdtempSync(path.join(os.tmpdir(), 'envelope-cwd-'));
    try {
      const r = cliEnv(['attest', 'list', '--json'], {
        cwd: tmpCwd,
        env: { EXCEPTD_HOME: tmpHome },
      });
      assert.equal(r.status, 0);
      const body = tryJson(r.stdout);
      assert.ok(body, `attest list --json must parse; got: ${r.stdout.slice(0, 200)}`);
      const keys = Object.keys(body).sort();
      assert.deepEqual(keys, [
        'attestations', 'count', 'filter', 'limit', 'ok',
        'roots_evaluated', 'roots_searched', 'shown',
      ]);
    } finally {
      try { fs.rmSync(tmpHome, { recursive: true, force: true }); } catch {}
      try { fs.rmSync(tmpCwd, { recursive: true, force: true }); } catch {}
    }
  });

  test('attest verify (no session) envelope: exact top-level key set on error path', () => {
    const tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'envelope-home-'));
    try {
      const r = cliEnv(['attest', 'verify', 'this-session-does-not-exist', '--json'], {
        env: { EXCEPTD_HOME: tmpHome },
      });
      const body = tryJson(r.stderr) || tryJson(r.stdout);
      assert.ok(body, `attest verify error envelope must parse; got stderr: ${r.stderr.slice(0, 200)} stdout: ${r.stdout.slice(0, 200)}`);
      assert.equal(body.ok, false);
      assert.equal(typeof body.error, 'string');
    } finally {
      try { fs.rmSync(tmpHome, { recursive: true, force: true }); } catch {}
    }
  });

  test('attest list (human renderer, empty state) names every candidate root', () => {
    const tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'envelope-home-'));
    const tmpCwd = fs.mkdtempSync(path.join(os.tmpdir(), 'envelope-cwd-'));
    try {
      const r = cliEnv(['attest', 'list'], { cwd: tmpCwd, env: { EXCEPTD_HOME: tmpHome } });
      assert.equal(r.status, 0);
      assert.match(r.stdout, /candidate roots evaluated:/);
      assert.match(r.stdout, /\[scanned-empty\]|\[not-present\]/);
    } finally {
      try { fs.rmSync(tmpHome, { recursive: true, force: true }); } catch {}
      try { fs.rmSync(tmpCwd, { recursive: true, force: true }); } catch {}
    }
  });
});

// ===========================================================================
describe('cli-surface-drift', () => {
  const SUITE_HOME = makeSuiteHome('exceptd-surface-drift-attest-');
  const cli = makeCli(SUITE_HOME);
  const runner = require('../lib/playbook-runner.js');
  const SIGNAL_PB = 'secrets'; // cross-platform; detect.indicators non-empty

  test('attest diff signal_override_diff.total_compared reflects detect.indicators for empty-both submissions', () => {
    const pb = runner.loadPlaybook(SIGNAL_PB);
    const indicatorCount = (pb.phases?.detect?.indicators || []).filter(i => i && i.id).length;
    assert.ok(indicatorCount > 0, 'fixture playbook must have detect.indicators');

    const a = cli(['run', SIGNAL_PB, '--evidence', '-', '--session-id', 'sigdrift-a'], { input: '{"artifacts":{},"signals":{}}' });
    assert.equal(a.status, 0, `setup run a failed: ${a.stderr.slice(0, 200)}`);
    const b = cli(['run', SIGNAL_PB, '--evidence', '-', '--session-id', 'sigdrift-b'], { input: '{"artifacts":{},"signals":{}}' });
    assert.equal(b.status, 0, `setup run b failed: ${b.stderr.slice(0, 200)}`);

    const d = cli(['attest', 'diff', 'sigdrift-a', '--against', 'sigdrift-b', '--json']);
    assert.equal(d.status, 0, `attest diff failed: ${d.stderr.slice(0, 200)}`);
    const body = tryJson(d.stdout) || tryJson(d.stderr);
    assert.ok(body && body.signal_override_diff, `attest diff must carry signal_override_diff; got ${d.stdout.slice(0, 200)}`);
    assert.equal(body.signal_override_diff.total_compared, indicatorCount);
    assert.equal(body.signal_override_diff.unchanged_count, indicatorCount);
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
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});


// ---- routed from help-verb-attest-list-deprecation ----
require("node:test").describe("help-verb-attest-list-deprecation", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
/**
 * tests/help-verb-attest-list-deprecation.test.js
 *
 * Cycle 11 P2/P3 fixes (v0.12.32):
 *
 *   F4 — `exceptd help <verb>` now routes through printPlaybookVerbHelp()
 *        so operators get verb-specific help regardless of whether they
 *        type `exceptd help run` or `exceptd run --help`. Pre-fix it
 *        dropped the verb argument and printed the top-level help.
 *
 *   F5 — `attest list` empty-state human renderer surfaces `roots_evaluated`
 *        showing every candidate root + whether it existed (`[scanned-empty]`
 *        vs `[not-present]`). Pre-fix it said `(no attestations under )`
 *        with an empty path list when no roots existed at all. JSON output
 *        also carries a structured `roots_evaluated[]` array.
 *
 *   F7 — Legacy-verb deprecation banner now persists suppression across
 *        invocations via an OS-tempdir marker keyed by exceptd version.
 *        Pre-fix the env-var guard reset on every fresh node process so
 *        operators saw the same banner on every `exceptd plan` invocation.
 *
 * Per the anti-coincidence rule, every assertion checks an EXACT
 * value (status code, string presence/absence, array shape).
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const fs = require('node:fs');
const os = require('node:os');
const { spawnSync } = require('node:child_process');

const ROOT = path.join(__dirname, '..');
const CLI = path.join(ROOT, 'bin', 'exceptd.js');

function cli(args, opts = {}) {
  return spawnSync(process.execPath, [CLI, ...args], {
    encoding: 'utf8',
    cwd: opts.cwd || ROOT,
    env: { ...process.env, ...(opts.env || {}) },
  });
}

function tryJson(s) {
  try { return JSON.parse(s); } catch { return null; }
}

// F4 ------------------------------------------------------------------------



// F5 ------------------------------------------------------------------------



// F7 v0.13.0 update --------------------------------------------------------
//
// v0.13.0 honored the long-advertised legacy-verb removal. The pre-v0.13
// deprecation-banner mechanism (soft banner + tempdir marker for once-per-
// version display) was replaced by a hard refusal with a replacement hint.
// The two prior F7 tests asserted banner+suppress semantics; both are
// replaced with refusal-shape assertions below.

test('F5: `attest list --json` carries roots_evaluated[] with per-root exists flag', () => {
  // Force a synthetic EXCEPTD_HOME so the test is deterministic regardless
  // of what's on the host. Run in a tempdir so the cwd-relative
  // `.exceptd/attestations/` path is also empty.
  const tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'exceptd-test-home-'));
  const tmpCwd = fs.mkdtempSync(path.join(os.tmpdir(), 'exceptd-test-cwd-'));
  try {
    const r = cli(['attest', 'list', '--json'], {
      cwd: tmpCwd,
      env: { EXCEPTD_HOME: tmpHome, EXCEPTD_DEPRECATION_SHOWN: '1' },
    });
    assert.equal(r.status, 0);
    const body = tryJson(r.stdout);
    assert.ok(body, `attest list --json must parse; got: ${r.stdout.slice(0, 200)}`);
    assert.equal(body.ok, true);
    assert.equal(body.count, 0);
    assert.equal(Array.isArray(body.roots_evaluated), true);
    assert.equal(body.roots_evaluated.length >= 1, true);
    for (const r of body.roots_evaluated) {
      assert.equal(typeof r.root, 'string');
      assert.equal(typeof r.exists, 'boolean');
    }
  } finally {
    try { fs.rmSync(tmpHome, { recursive: true, force: true }); } catch {}
    try { fs.rmSync(tmpCwd, { recursive: true, force: true }); } catch {}
  }
});

test('F5: `attest list` empty-state human output names each candidate root', () => {
  const tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'exceptd-test-home-'));
  const tmpCwd = fs.mkdtempSync(path.join(os.tmpdir(), 'exceptd-test-cwd-'));
  try {
    const r = cli(['attest', 'list'], {
      cwd: tmpCwd,
      env: { EXCEPTD_HOME: tmpHome, EXCEPTD_DEPRECATION_SHOWN: '1' },
    });
    assert.equal(r.status, 0);
    // Pre-fix output: "  (no attestations under )" — empty path.
    // Post-fix output: candidate roots block with [scanned-empty] / [not-present] markers.
    assert.match(r.stdout, /candidate roots evaluated:/);
    assert.match(r.stdout, /\[scanned-empty\]|\[not-present\]/);
  } finally {
    try { fs.rmSync(tmpHome, { recursive: true, force: true }); } catch {}
    try { fs.rmSync(tmpCwd, { recursive: true, force: true }); } catch {}
  }
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

test('#98 attest export --format garbage on a real session returns format error', () => {
  // Pre-strengthening this combined two distinct errors under one regex:
  //  - "no session dir" (the session-id arm)
  //  - "not in accepted set" (the format-rejection arm)
  // The regression class was that EITHER message satisfied the test, so a
  // bug that flipped session-not-found and format-validation back and forth
  // wouldn't be caught. Split into two tests, each pinning exactly one
  // error path.
  //
  // Arm A: real session id (we just wrote one via `run`) + garbage format.
  // The error must be the FORMAT error, not the session-not-found error —
  // otherwise format validation never ran against a real session.
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
  // Arm B: garbage session id + valid format. The error must be the
  // SESSION-NOT-FOUND error so operators get the right diagnostic for the
  // arm they hit. Pre-strengthening one regex matched both messages, so
  // the runner could have flipped the arms and the test wouldn't notice.
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

test('attest diff <sid> (no --against) emits the v0.11+ envelope (not the legacy reattest shape)', () => {
  // Before this fix, `attest diff <sid>` without --against fell through
  // to cmdReattest which emitted `verb: "reattest"` + the legacy
  // {status, prior_evidence_hash, replay_evidence_hash} envelope.
  // The pure-comparison path now finds the most-recent prior
  // attestation for the same playbook and emits the v0.11+ envelope
  // (verb: "attest diff", a_session/b_session, artifact_diff,
  // signal_override_diff).
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
  // Run twice with the same flat-shape submission. Diff should report
  // unchanged_count >= 1 for the artifact and signal_override.
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

test('#127 emit() body with ok:false sets non-zero exit (universal contract)', () => {
  // The class of bug: any verb that emits a result with ok:false to stdout
  // must not return exit 0. Pre-0.11.13 several paths leaked through.
  // attest verify on a non-existent session id is GUARANTEED to produce
  // ok:false (the session lookup is the first gate and there's no way
  // around it). Pre-strengthening, this test guarded the assertion under
  // `if (sawOkFalse) { assert(...) }` — so a regression that ran the verb
  // through some other path without ok:false would have silently passed
  // (the `if` never fired, the assertion was a no-op). Hard-assert that
  // ok:false IS observed AND the exit is non-zero, unconditionally.
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
  // Pre-strengthening, only the exit code was checked — a regression that
  // exited non-zero for an UNRELATED reason (e.g. CLI crashed before
  // session lookup) would have passed. Drill into stderr and confirm the
  // specific missing session id is named, so operators see which one
  // failed lookup (the diff has two arms, A and B).
  const err = tryJson(r.stderr.trim());
  assert.ok(err, 'attest diff must emit JSON error on stderr');
  assert.equal(err.ok, false, 'body must carry ok:false');
  assert.match(err.error, /does-not-exist-a/,
    'error must name the failed session id (the A side is checked first) so operators know which arm to fix');
});

test('#128 attest diff with empty submissions falls back to playbook catalog', () => {
  // Both runs use empty {} submission; identical evidence hashes. The diff
  // should count the playbook's artifact catalog so operators see
  // "N artifacts, all uniform on both sides" rather than 0/0.
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
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});


// ---- routed from runtime-errors-and-vex-disposition ----
require("node:test").describe("runtime-errors-and-vex-disposition", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
/**
 * Tests for the audit-AA P1 closures:
 *
 *   AA P1-1  `algorithm: "unsigned"` sidecar substitution is now detected
 *            by both `attest verify` (exit 6 when private key present) and
 *            `cmdReattest` (requires --force-replay regardless).
 *   AA P1-2  Corrupt-JSON .sig sidecar surfaces as a structured tamper-class
 *            result rather than throwing through the dispatcher. Both
 *            `attest verify` and `cmdReattest` exit 6.
 *   AA P1-3  `lib/verify.js verifyManifestSignature()` consults
 *            `keys/EXPECTED_FINGERPRINT` BEFORE crypto.verify. Library
 *            callers (refresh-network, verify-shipped-tarball, downstream
 *            consumers) can no longer bypass the pin.
 *
 * Per the "coincidence-passing tests" rule: every exit-code assertion
 * is EXACT (assert.equal(r.status, 6)), never notEqual(0).
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');

const { ROOT, makeSuiteHome, makeCli, tryJson } = require('./_helpers/cli');

const SUITE_HOME = makeSuiteHome('exceptd-audit-aa-');
const cli = makeCli(SUITE_HOME);

const PKG_PRIV_KEY = path.join(ROOT, '.keys', 'private.pem');
const HAS_PRIV_KEY = fs.existsSync(PKG_PRIV_KEY);

function locateAttestation(sid) {
  const candidates = [
    path.join(SUITE_HOME, 'attestations', sid),
    path.join(SUITE_HOME, '.exceptd', 'attestations', sid),
  ];
  const attRoot = candidates.find(p => fs.existsSync(p));
  if (!attRoot) return null;
  const files = fs.readdirSync(attRoot).filter(f => f.endsWith('.json') && !f.endsWith('.sig'));
  if (files.length === 0) return null;
  return { dir: attRoot, jsonFile: path.join(attRoot, files[0]), sigFile: path.join(attRoot, files[0] + '.sig') };
}

// ---------------------------------------------------------------------------
// AA P1-1 — `algorithm: "unsigned"` substitution detection
// ---------------------------------------------------------------------------

test('AA P1-1: attest verify exits 6 when an unsigned sidecar is substituted on a host WITH a private key',
  { skip: !HAS_PRIV_KEY && 'private key absent — substitution path requires .keys/private.pem on the verifying host' },
  () => {
    // Produce a real (signed) attestation, then substitute the .sig with the
    // unsigned stub. Pre-fix: `attest verify` reported signed:false and
    // exited 0 — the tamper predicate `r.signed && !r.verified` never fired.
    // Post-fix: substitution is detected because .keys/private.pem exists on
    // the verifying host, and verify exits 6.
    const sid = 'aa-p11-subst-' + Date.now();
    const sub = JSON.stringify({ observations: {}, verdict: { classification: 'not_detected' } });
    const r1 = cli(['run', 'library-author', '--evidence', '-', '--session-id', sid], { input: sub });
    assert.equal(r1.status, 0, 'pre-substitution run must succeed; stderr=' + r1.stderr.slice(0, 400));

    const att = locateAttestation(sid);
    assert.ok(att, 'attestation must exist');

    // Tamper attestation.json AND substitute the .sig with the unsigned stub.
    const orig = fs.readFileSync(att.jsonFile, 'utf8');
    fs.writeFileSync(att.jsonFile, orig.replace(/\}\s*$/, ', "__tampered": true }'));
    fs.writeFileSync(att.sigFile, JSON.stringify({
      algorithm: 'unsigned',
      signed: false,
      reason: 'attestation explicitly unsigned',
      signs_path: path.basename(att.jsonFile),
    }, null, 2));

    const r = cli(['attest', 'verify', sid, '--json']);
    assert.equal(r.status, 6,
      `attest verify on unsigned-substituted sidecar must exit 6 (TAMPERED) when private key is present. Got status=${r.status}. stderr=${r.stderr.slice(0,400)}`);
    const body = tryJson(r.stdout) || tryJson(r.stderr) || {};
    assert.equal(body.ok, false, 'substitution body must carry ok:false');
    assert.ok(Array.isArray(body.results), 'verify must emit results array');
    assert.ok(
      body.results.some(x => x.tamper_class === 'unsigned-substitution'),
      'at least one result must classify as tamper_class:"unsigned-substitution"'
    );
  });

test('AA P1-1: a legitimately-unsigned attestation on a host WITHOUT a private key is allowed (no substitution signal)', () => {
  // Source-level assertion: the unsigned-substitution branch in
  // verifyAttestationSidecar checks `fs.existsSync(privKeyPath)`. When the
  // private key is absent, the function returns the original explicitly-
  // unsigned reason (no tamper_class). The legitimately-unsigned path
  // remains usable for operators who have never run generate-keypair.
  const src = fs.readFileSync(path.join(ROOT, 'bin', 'exceptd.js'), 'utf8');
  const fnStart = src.indexOf('function verifyAttestationSidecar(attFile)');
  const fnEnd = src.indexOf('function cmdReattest', fnStart);
  const block = src.slice(fnStart, fnEnd);
  // Two unsigned-return shapes must coexist: one with tamper_class
  // (substitution path) and one without (legitimate path).
  assert.match(block, /tamper_class:\s*["']unsigned-substitution["']/,
    'verifyAttestationSidecar must classify substitution');
  // The legitimate-unsigned return is the one whose reason starts with
  // "attestation explicitly unsigned (no private key when written)" AND
  // does NOT carry tamper_class.
  const legitMatch = block.match(/return\s*\{\s*file:\s*attFile,\s*signed:\s*false,\s*verified:\s*false,\s*reason:\s*"attestation explicitly unsigned \(no private key when written\)"\s*\}/);
  assert.ok(legitMatch,
    'verifyAttestationSidecar must retain the legitimate-unsigned return path (no tamper_class) for hosts without a private key');
});

// ---------------------------------------------------------------------------
// AA P1-2 — Corrupt-JSON sidecar refusal
// ---------------------------------------------------------------------------

test('AA P1-2: attest verify exits 6 (not 1) when the .sig sidecar is corrupt JSON',
  { skip: !HAS_PRIV_KEY && 'producer run requires private key' },
  () => {
    // Pre-fix: JSON.parse threw into the outer dispatcher catch → exit 1
    // (generic). Post-fix: wrapped parse returns a tamper-class result and
    // the per-result reduce promotes to exit 6.
    const sid = 'aa-p12-corrupt-' + Date.now();
    const sub = JSON.stringify({ observations: {}, verdict: { classification: 'not_detected' } });
    const r1 = cli(['run', 'library-author', '--evidence', '-', '--session-id', sid], { input: sub });
    assert.equal(r1.status, 0);

    const att = locateAttestation(sid);
    assert.ok(att);
    // Write truncated / malformed JSON.
    fs.writeFileSync(att.sigFile, '{"algorithm":"Ed25');

    const r = cli(['attest', 'verify', sid, '--json']);
    assert.equal(r.status, 6,
      `attest verify on a corrupt .sig must exit 6 (TAMPERED), not 1 (generic). Got status=${r.status}. stderr=${r.stderr.slice(0,400)}`);
    const body = tryJson(r.stdout) || tryJson(r.stderr) || {};
    assert.equal(body.ok, false, 'corrupt-sidecar verify body must carry ok:false');
    assert.ok(Array.isArray(body.results), 'verify must still emit results array even on corrupt sidecar (no unhandled throw)');
    assert.ok(
      body.results.some(x => x.tamper_class === 'sidecar-corrupt'),
      'at least one result must classify as tamper_class:"sidecar-corrupt"'
    );
  });

test('AA P1-2: reattest exits 6 when the .sig sidecar is corrupt JSON',
  { skip: !HAS_PRIV_KEY && 'producer run requires private key' },
  () => {
    const sid = 'aa-p12-corrupt-reattest-' + Date.now();
    const sub = JSON.stringify({ observations: {}, verdict: { classification: 'not_detected' } });
    const r1 = cli(['run', 'library-author', '--evidence', '-', '--session-id', sid], { input: sub });
    assert.equal(r1.status, 0);

    const att = locateAttestation(sid);
    assert.ok(att);
    fs.writeFileSync(att.sigFile, 'not-valid-json{{{');

    const r = cli(['reattest', sid, '--json']);
    assert.equal(r.status, 6,
      `reattest against a corrupt .sig must exit 6, not fall through to the benign NOTE branch. Got status=${r.status}. stderr=${r.stderr.slice(0,400)}`);
  });

// ---------------------------------------------------------------------------
// AA P1-3 — EXPECTED_FINGERPRINT pin consulted in verifyManifestSignature
// ---------------------------------------------------------------------------

test('AA P1-3: verifyManifestSignature accepts the live manifest (pin matches keys/public.pem)', () => {
  // Sanity-check: the live manifest must still verify after the pin gate
  // was added. This protects against accidentally regressing the live
  // verify path while wiring the new check.
  const verifyMod = require(path.join(ROOT, 'lib', 'verify.js'));
  const manifest = JSON.parse(fs.readFileSync(path.join(ROOT, 'manifest.json'), 'utf8'));
  const r = verifyMod.verifyManifestSignature(manifest);
  assert.equal(r.status, 'valid', `live manifest must still verify post-pin-gate; got ${JSON.stringify(r)}`);
});

test('AA P1-3: verifyManifestSignature refuses when keys/public.pem diverges from keys/EXPECTED_FINGERPRINT', () => {
  // Simulate the divergence by patching checkExpectedFingerprint via a
  // sandbox: load lib/verify.js fresh under a tempdir-rooted PKG layout
  // where keys/public.pem is a freshly-generated attacker key and
  // keys/EXPECTED_FINGERPRINT pins the LEGITIMATE key. The library must
  // refuse to verify under the attacker key.
  //
  // Easiest implementation: spawn a sub-test in a tempdir that mirrors the
  // repo structure for keys/, manifest.json, and lib/. Rather than copy
  // lib/verify.js (which would diverge), we re-require it under a
  // pinPath-substituted shim using its exported checkExpectedFingerprint
  // primitive — verifyManifestSignature internally calls
  // checkExpectedFingerprint(liveFp) with the default pin path, so we patch
  // EXPECTED_FINGERPRINT_PATH by tampering with the OS environment we
  // control.
  //
  // The clean approach: bypass the library wrapper and exercise the policy
  // primitive directly. checkExpectedFingerprint is the public surface; if
  // the library uses it correctly the policy is enforced. We assert both:
  //   1. The primitive returns "mismatch" on a divergent fingerprint
  //      without KEYS_ROTATED.
  //   2. The library function verifyManifestSignature() body references
  //      checkExpectedFingerprint before crypto.verify.
  const verifyMod = require(path.join(ROOT, 'lib', 'verify.js'));

  // (1) Primitive-level: a divergent pin fails without KEYS_ROTATED.
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'aa-p13-pin-'));
  const pinPath = path.join(tmp, 'EXPECTED_FINGERPRINT');
  fs.writeFileSync(pinPath, 'SHA256:DEADBEEFnotTheActualKeyJustATestPin12345678=');
  const fakeFp = { sha256: 'SHA256:totally-different-fingerprint-value' };
  const result = verifyMod.checkExpectedFingerprint(fakeFp, pinPath);
  assert.equal(result.status, 'mismatch');
  assert.equal(result.rotationOverride, false,
    'KEYS_ROTATED unset → rotationOverride must be false (caller must refuse)');

  // (2) Source-level: verifyManifestSignature() body calls
  // checkExpectedFingerprint BEFORE crypto.verify. Without this ordering,
  // a tampered public.pem could verify before the pin gate fires.
  const src = fs.readFileSync(path.join(ROOT, 'lib', 'verify.js'), 'utf8');
  const fnStart = src.indexOf('function verifyManifestSignature(manifest)');
  assert.ok(fnStart > 0, 'verifyManifestSignature must be present in lib/verify.js');
  // Slice to the actual function boundary, not a fixed char window — the body
  // grows as guards are added (e.g. the no-pin rejection), and a too-small
  // window would push crypto.verify out of view and false-fail this ordering
  // check.
  const fnEnd = src.indexOf('\nfunction ', fnStart + 1);
  const fnBlock = src.slice(fnStart, fnEnd > fnStart ? fnEnd : fnStart + 4000);
  const pinIdx = fnBlock.indexOf('checkExpectedFingerprint(');
  const verifyIdx = fnBlock.indexOf('crypto.verify(');
  assert.ok(pinIdx > 0,
    'verifyManifestSignature must call checkExpectedFingerprint() per AA P1-3');
  assert.ok(verifyIdx > pinIdx,
    'checkExpectedFingerprint() must be called BEFORE crypto.verify() — otherwise an attacker-rotated public.pem can authenticate before the pin gate fires');
});

test('AA P1-3: verifyManifestSignature returns structured fingerprint-mismatch error (not a generic invalid)', () => {
  // A library-caller (refresh-network, verify-shipped-tarball, etc.) must
  // be able to distinguish "wrong key" from "tampered manifest". The
  // mismatch return carries explicit fingerprint_mismatch / expected /
  // actual fields so downstream code can present the operator-actionable
  // rotation guidance rather than a generic tamper message.
  const src = fs.readFileSync(path.join(ROOT, 'lib', 'verify.js'), 'utf8');
  const fnStart = src.indexOf('function verifyManifestSignature(manifest)');
  const fnEnd = src.indexOf('function loadManifestValidated', fnStart);
  const block = src.slice(fnStart, fnEnd > 0 ? fnEnd : fnStart + 3000);
  assert.match(block, /fingerprint_mismatch:\s*true/,
    'verifyManifestSignature must emit fingerprint_mismatch:true on pin divergence');
  assert.match(block, /fingerprint-mismatch/,
    'verifyManifestSignature must surface "fingerprint-mismatch" in the reason string for log scrapers');
});

test('AA P1-3: verifyManifestSignature honors KEYS_ROTATED=1 for legitimate rotations', () => {
  // The override env must be respected at the library layer. Operators
  // rotating keys/public.pem set KEYS_ROTATED=1, re-sign, then commit the
  // new EXPECTED_FINGERPRINT. Refusing to verify during that window would
  // brick `node lib/verify.js update` (which signs against the new key).
  const verifyMod = require(path.join(ROOT, 'lib', 'verify.js'));
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'aa-p13-rot-'));
  const pinPath = path.join(tmp, 'EXPECTED_FINGERPRINT');
  fs.writeFileSync(pinPath, 'SHA256:somethingElse=');
  const prev = process.env.KEYS_ROTATED;
  try {
    process.env.KEYS_ROTATED = '1';
    const result = verifyMod.checkExpectedFingerprint({ sha256: 'SHA256:newKey=' }, pinPath);
    assert.equal(result.status, 'mismatch');
    assert.equal(result.rotationOverride, true,
      'KEYS_ROTATED=1 must surface rotationOverride:true so callers can accept the rotation');
  } finally {
    if (prev === undefined) delete process.env.KEYS_ROTATED;
    else process.env.KEYS_ROTATED = prev;
  }
});

;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});
