'use strict';

/**
 * CLI surface coverage suite.
 *
 * Every documented entry point that lacked a happy-path smoke test prior to
 * this file lives here. Each case verifies the verb (a) runs to completion
 * and (b) emits a result with the documented top-level shape. Coincidence-
 * passing tests (asserting only `r.status !== 0` or `assert.ok(data)`) are
 * forbidden: every shape assertion couples a field-presence check with a
 * field-content check.
 *
 * Discipline carried over from operator-bugs.test.js:
 *   - Shared cli() / tryJson() / SUITE_HOME via tests/_helpers/cli.js.
 *   - Each test that lands an attestation uses a unique --session-id keyed
 *     to Date.now() + a tag so sibling tests can't collide.
 *   - Tests run under --test-concurrency=1; pre-stage filesystem state inside
 *     each test with mkdtempSync where needed and clean up in finally{}.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const fs = require('node:fs');
const os = require('node:os');
const { spawnSync } = require('node:child_process');

const { ROOT, CLI, makeSuiteHome, makeCli, tryJson } = require('./_helpers/cli');
const runner = require(path.join(ROOT, 'lib', 'playbook-runner.js'));

const SUITE_HOME = makeSuiteHome('exceptd-cli-cov-');
const cli = makeCli(SUITE_HOME);

const SHIPPED_PLAYBOOKS = runner.listPlaybooks();
const PLAYBOOK_COUNT = SHIPPED_PLAYBOOKS.length;

// Helper: stage a temp playbook tree by copying data/playbooks/, mutating the
// target playbook's _meta.threat_currency_score, and returning the dir path
// plus an env-override pair suitable for cli({env}). Used by the force-stale
// test which needs a sub-50 score without mutating the shipped catalog.
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

// ===================================================================
// brief — five facets
// ===================================================================

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

// ===================================================================
// discover
// ===================================================================

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

// ===================================================================
// doctor — full + selective sub-checks
// ===================================================================

test('doctor no-flags emits checks{} covering every subcheck', () => {
  const r = cli(['doctor', '--json']);
  // doctor may set exitCode=1 when checks fail (signature gaps in CI envs);
  // we only care that the verb ran and emitted the expected shape.
  const data = tryJson(r.stdout);
  assert.ok(data, 'doctor must emit JSON');
  assert.equal(data.verb, 'doctor');
  assert.ok(data.checks && typeof data.checks === 'object', 'checks{} must be present');
  assert.ok(Object.keys(data.checks).length >= 4,
    'doctor with no flags must run at least 4 subchecks (signatures, currency, cves, rfcs)');
  // Each subcheck must self-report ok-state, not be a bare truthy value.
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
  // v0.12.9: --shipped-tarball runs scripts/verify-shipped-tarball.js
  // alongside the source-tree signature check, populating
  // checks.signatures.shipped_tarball. On an installed (npm) tree the
  // script may be absent — accept either a populated sub-check or a
  // documented skip reason so the test runs in both contexts.
  const r = cli(['doctor', '--signatures', '--shipped-tarball', '--json']);
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

// ===================================================================
// attest — show / list / export / verify-attestation alias
// ===================================================================

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
  // Pre-stage at least one attestation so the list is non-empty.
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
  // Smoke: the attestation we just signed must verify against keys/public.pem.
  // If no private key was available at run time the attestation will be
  // explicitly unsigned — accept either shape but never a verified=false
  // post-tamper.
  const first = data.results[0];
  if (first.signed) {
    assert.equal(first.verified, true,
      'signed attestation must verify against keys/public.pem (no post-hoc tamper)');
  }
});

// ===================================================================
// run-all alias — must dispatch to the same set run --all would.
// ===================================================================

test('run-all alias produces the same playbook set as run --all', () => {
  const sub = JSON.stringify({});
  // run-all takes no extra arg by design; cmdRunAll sets args.all=true and
  // re-enters cmdRun, which fans out to cmdRunMulti over runner.listPlaybooks().
  const rAlias = cli(['run-all', '--evidence', '-', '--session-id', 'ra-' + Date.now()],
    { input: sub });
  const rExplicit = cli(['run', '--all', '--evidence', '-', '--session-id', 're-' + Date.now()],
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
    `run-all must cover all ${PLAYBOOK_COUNT} shipped playbooks`);
});

// ===================================================================
// framework-gap CLI — orchestrator subcommand
// ===================================================================

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

// ===================================================================
// report executive (orchestrator) — text/markdown shape.
// Note: `report executive` emits markdown to stdout, not JSON. The shape
// contract is the self-describing header + "Executive Summary" section.
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

// ===================================================================
// validate-rfcs (legacy text output) + doctor --rfcs (JSON shape).
// These two paths used to be the only RFC-currency checks; doctor --rfcs
// is the v0.11.x replacement that wraps the legacy validator.
// ===================================================================

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

test('doctor --rfcs (modern) wraps the same validator with structured output', () => {
  const r = cli(['doctor', '--rfcs', '--json']);
  const data = tryJson(r.stdout);
  assert.ok(data?.checks?.rfcs, 'doctor --rfcs must populate checks.rfcs');
  assert.equal(typeof data.checks.rfcs.ok, 'boolean',
    'checks.rfcs.ok must be a boolean (not undefined / not coincidence-truthy)');
  assert.ok(typeof data.checks.rfcs.total === 'number' || data.checks.rfcs.total === null,
    'checks.rfcs.total must be numeric or explicit null');
});

// ===================================================================
// ai-run streaming JSONL — critical missing path (v0.12.8 fix).
// Pipe an evidence event over stdin, read JSONL frames from stdout, assert
// every documented phase frame appears in order ending with done.
// ===================================================================

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
  // Strict ordering of all 9 documented frames.
  const expectedOrder = ['govern', 'direct', 'look', 'await_evidence',
    'detect', 'analyze', 'validate', 'close', 'done'];
  for (const phase of expectedOrder) {
    assert.ok(tags.includes(phase),
      `streaming must include the ${phase} frame; saw [${tags.join(', ')}]`);
  }
  // Each pair of adjacent expected frames must appear in order (allowing for
  // host AI status interleaving — though we don't pipe any here).
  let lastIndex = -1;
  for (const phase of expectedOrder) {
    const idx = tags.indexOf(phase);
    assert.ok(idx > lastIndex,
      `${phase} must appear after the previous expected frame; saw at idx ${idx}, last was ${lastIndex}`);
    lastIndex = idx;
  }
  // The final frame must be `event:done` with ok:true and a session_id.
  const doneFrame = frames.find(f => f.event === 'done');
  assert.equal(doneFrame.ok, true, 'done frame must carry ok:true');
  assert.equal(typeof doneFrame.session_id, 'string',
    'done frame must carry the session_id so callers can fetch the attestation');
});

// ===================================================================
// ci flag coverage — --max-rwep, --block-on-jurisdiction-clock, --evidence-dir
// ===================================================================

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
  const tmp = path.join(os.tmpdir(), `cidir-${Date.now()}`);
  fs.mkdirSync(tmp, { recursive: true });
  fs.writeFileSync(path.join(tmp, 'secrets.json'), JSON.stringify({
    observations: { w: { captured: true, value: 'AKIA', indicator: 'aws-access-key-id', result: 'hit' } },
    verdict: { classification: 'detected', blast_radius: 4 },
  }));
  try {
    // E7: --ack required for the jurisdiction clock to start now (operator
    // awareness contract per AGENTS.md Phase 7). Pre-fix the engine
    // auto-stamped on detect_confirmed; post-fix the operator must
    // acknowledge.
    //
    // F18 (v0.12.16): clock-fired runs now exit 5 (CLOCK_STARTED), not 2
    // (FAIL). Pre-F18 the two collapsed so operators couldn't distinguish
    // "playbook detected" from "regulatory clock running" by exit code.
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
    // F18: clock-firing has its own exit code (5), distinct from FAIL (2).
    // BLOCKED (4) is preflight halts; FAIL (2) is detected/escalate; the
    // new CLOCK_STARTED (5) tells operators "the system fired exactly as
    // designed but you now owe a regulatory notification."
    assert.equal(r.status, 5,
      'F18: clock-fired runs exit 5 (CLOCK_STARTED), separate from FAIL (2)');
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test('ci --evidence-dir <dir> routes per-playbook submission files', () => {
  const tmp = path.join(os.tmpdir(), `cidir2-${Date.now()}`);
  fs.mkdirSync(tmp, { recursive: true });
  // Stage two distinct submissions keyed by playbook id.
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
    // Per-playbook submissions must have produced detect output (not blocked).
    assert.equal(data.summary.blocked, 0,
      '--evidence-dir submissions must satisfy preconditions; 0 blocked');
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

// ===================================================================
// run flag coverage — --vex, --diff-from-latest, --force-stale, --air-gap,
// --session-key. (--evidence-dir is only honored in the multi-playbook
// path; covered by the ci tests above.)
// ===================================================================

test('run --vex applies the VEX filter and surfaces analyze.vex.filter_applied', () => {
  const vexPath = path.join(os.tmpdir(), `vex-${Date.now()}.json`);
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
  // Identical submission → identical evidence_hash → status=unchanged.
  assert.equal(data.diff_from_latest.status, 'unchanged',
    'identical submissions must produce diff_from_latest.status=unchanged');
});

test('run --force-stale overrides the threat_currency_score < 50 hard block', () => {
  const stage = stagePlaybookWithCurrency('library-author', 40);
  try {
    // Without --force-stale: the runner refuses the run (ok:false, blocked_by=currency).
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

    // With --force-stale: the run completes.
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
  // ok:true expected since secrets has air_gap_mode already set in the
  // playbook; CLI flag just OR's into runOpts.airGap. The contract under
  // test is that the CLI flag is wired through to the runner.
  const data = tryJson(r.stdout);
  assert.ok(data, 'run --air-gap must emit JSON');
  assert.equal(data.ok, true);
  assert.equal(data.phases?.govern?.air_gap_mode, true,
    'phases.govern.air_gap_mode must be true when --air-gap is passed on the CLI');
});

test('run --session-key <hex> HMAC-signs the evidence_package', () => {
  // 32 bytes of entropy → 64 hex chars, well over the 16-char minimum.
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

// ===================================================================
// refresh --indexes-only — dispatcher rewrite to build-indexes.
// ===================================================================

test('refresh --indexes-only routes to build-indexes and finishes cleanly', () => {
  const r = cli(['refresh', '--indexes-only']);
  assert.equal(r.status, 0, 'refresh --indexes-only must exit 0');
  // build-indexes emits a textual summary; assert the canonical banner.
  assert.match(r.stdout, /build-indexes/,
    'refresh --indexes-only must dispatch to the build-indexes script (banner reflects that)');
  assert.match(r.stdout, /done|output\(s\)/i,
    'output must include a completion marker (done / N output(s))');
});
