'use strict';

/**
 * tests/dogfood-blamejs-fixes.test.js
 *
 * Pins the fixes a dogfood scan of a sibling repo surfaced:
 *  - playbooks that declare bundle_format "json" (secrets / cred-stores /
 *    runtime / citation-hygiene) now build a real structured-JSON evidence
 *    bundle instead of falling through to the "Unknown format" placeholder;
 *  - the crypto-codebase collector attests the playbook's own
 *    `repo-has-source-tree` gate (it previously emitted a `repo-context` key
 *    the playbook never references, so a source repo got a spurious
 *    precondition_unverified warning).
 * Exact-value pins, with content paired to presence per the project's
 * field-present-vs-field-populated rule.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const runner = require('../lib/playbook-runner.js');
const cryptoCodebase = require('../lib/collectors/crypto-codebase.js');
const { makeSuiteHome, makeCli, tryJson } = require('./_helpers/cli');

const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'exceptd-dogfix2-'));
process.on('exit', () => { try { fs.rmSync(TMP, { recursive: true, force: true }); } catch { /* non-fatal */ } });
let _n = 0;
function mkfx() { const d = path.join(TMP, 'fx-' + _n++); fs.mkdirSync(d, { recursive: true }); return d; }

test('a playbook declaring bundle_format "json" builds a populated json bundle, not the Unknown-format placeholder', () => {
  const res = runner.run(
    'secrets',
    'full-repo-secret-scan',
    { precondition_checks: { 'repo-context': true }, signal_overrides: {} },
    { force_replay: true, mode: 'test' }
  );
  assert.equal(res.ok, true, 'a clean secrets run must succeed');
  const ep = res.phases && res.phases.close && res.phases.close.evidence_package;
  assert.ok(ep, 'close phase must carry an evidence_package');
  const body = ep.bundle_body;
  assert.ok(body, 'evidence_package must carry a bundle_body');
  // Presence: the declared format is honored.
  assert.equal(body.format, 'json', 'bundle_body.format must be the declared json, not a fallback');
  assert.equal('note' in body, false, 'a real json bundle must NOT carry the Unknown-format note');
  // Content: the bundle is populated, not an empty shell.
  assert.equal(body.playbook, 'secrets', 'bundle records its playbook id');
  assert.equal(typeof body.session_id, 'string', 'bundle records the session id');
  assert.equal(typeof body.verdict, 'string', 'bundle carries a string verdict');
  assert.ok(Array.isArray(body.matched_cves), 'bundle carries a matched_cves array');
  assert.equal(typeof body.rwep_adjusted, 'number', 'bundle carries a numeric adjusted rwep');
  // The primary format is keyed under json and is the same record.
  assert.ok(ep.bundles_by_format && ep.bundles_by_format.json, 'bundles_by_format keys the json primary');
  assert.equal(ep.bundles_by_format.json.format, 'json', 'bundles_by_format.json is the json bundle');
});

test('top_finding names the dominant fired indicator (not the verdict string), and summary_line states the verdict once', () => {
  const res = runner.run(
    'library-author',
    'published-artifact-audit',
    { signal_overrides: { 'release-workflow-non-frozen-install': 'hit' } },
    { force_replay: true, mode: 'test' }
  );
  assert.equal(res.verdict, 'detected', 'a forced indicator hit drives a detected verdict');
  // top_finding must name the indicator that fired, not echo the verdict word.
  assert.equal(res.top_finding, 'release-workflow-non-frozen-install', 'top_finding is the dominant fired indicator id');
  // The verdict word appears exactly once in the summary line — no
  // "detected (rwep=…, detected, …)" duplication.
  assert.equal((res.summary_line.match(/detected/g) || []).length, 1, 'summary_line states the verdict once, not duplicated');

  // Gate: a non-detection verdict must NOT advertise a top_finding (the
  // indicator branch is gated on a real detection classification, so a stray
  // hit on an inconclusive / not-detected run cannot leak a finding).
  const miss = runner.run(
    'library-author',
    'published-artifact-audit',
    { signal_overrides: { 'release-workflow-non-frozen-install': 'miss' } },
    { force_replay: true, mode: 'test' }
  );
  assert.equal(miss.verdict, 'not_detected', 'all-miss drives a not_detected verdict');
  assert.equal(miss.top_finding, null, 'a non-detection verdict carries no top_finding');
});

test('top_finding prefers the indicator that drove the RWEP score (and falls back to the dominant hit when none is weighted)', () => {
  // Both a weighted rwep-input (sbom-absent-or-unsigned, weight 10) and a
  // higher-confidence-but-unweighted hit fire: top_finding must name the
  // weighted driver so the headline explains the rwep number beside it.
  const driven = runner.run(
    'library-author',
    'published-artifact-audit',
    { signal_overrides: { 'sbom-absent-or-unsigned': 'hit', 'release-workflow-non-frozen-install': 'hit' } },
    { force_replay: true, mode: 'test' }
  );
  assert.equal(driven.verdict, 'detected');
  assert.equal(driven.rwep_score, 10, 'the weighted signal sets rwep=10');
  assert.equal(driven.top_finding, 'sbom-absent-or-unsigned', 'top_finding names the rwep driver, not the higher-confidence unweighted hit');
  // When only a non-weighted hit fires (rwep=0), fall back to that indicator.
  const fallback = runner.run(
    'library-author',
    'published-artifact-audit',
    { signal_overrides: { 'release-workflow-non-frozen-install': 'hit' } },
    { force_replay: true, mode: 'test' }
  );
  assert.equal(fallback.rwep_score, 0, 'the unweighted hit leaves rwep at 0');
  assert.equal(fallback.top_finding, 'release-workflow-non-frozen-install', 'with no weighted driver, top_finding falls back to the dominant hit');
});

test('run() surfaces collector_errors as an advisory collector_warnings field (and omits it when there are none)', () => {
  const warned = runner.run(
    'secrets',
    'full-repo-secret-scan',
    {
      precondition_checks: { 'repo-context': true },
      signal_overrides: {},
      collector_errors: [{ kind: 'file_too_large_skipped', reason: 'big.json: exceeds limit' }],
    },
    { force_replay: true, mode: 'test' }
  );
  assert.ok(Array.isArray(warned.collector_warnings), 'collector_warnings is present when the collector skipped something');
  assert.equal(warned.collector_warnings.length, 1);
  assert.equal(warned.collector_warnings[0].kind, 'file_too_large_skipped', 'the skip reason is carried through verbatim');
  // Advisory only — the run still completes and the verdict is unaffected.
  assert.equal(warned.ok, true);
  // No collector_errors submitted -> no collector_warnings key (not an empty array).
  const clean = runner.run(
    'secrets',
    'full-repo-secret-scan',
    { precondition_checks: { 'repo-context': true }, signal_overrides: {} },
    { force_replay: true, mode: 'test' }
  );
  assert.equal('collector_warnings' in clean, false, 'collector_warnings is omitted when the collector reported nothing');
});

test('regression_event_triggers carry the condition string (not null) from a playbook keyed on `condition`', () => {
  const res = runner.run(
    'ai-api',
    'all-ai-api-and-credential-exposure',
    { signal_overrides: {} },
    { force_replay: true, mode: 'test' }
  );
  const triggers = res.phases.validate.regression_event_triggers || [];
  assert.ok(triggers.length >= 1, 'the playbook declares on_event regression triggers');
  assert.ok(triggers.every((t) => typeof t.trigger === 'string' && t.trigger.length > 0), 'every on_event trigger carries its condition string, not null');
  assert.equal(triggers[0].trigger, 'new_ai_vendor_added_to_allowlist', 'the first trigger is the playbook condition verbatim');
});

test('selected_remediation prefers the path that addresses a fired signal (and falls back to priority-1 when none is linked)', () => {
  // Only the FIPS-claim indicator fired: the recommendation must be the
  // remediation that addresses it (for_signals linkage), NOT the unrelated
  // priority-1 PQC migration.
  const fips = runner.run(
    'crypto-codebase',
    'weak-primitive-inventory',
    { signal_overrides: { 'fips-claim-without-runtime-activation': 'hit' } },
    { force_replay: true, mode: 'test' }
  );
  const sel = fips.phases.validate.selected_remediation;
  assert.equal(sel.id, 'activate-fips-provider-or-retract-claim', 'the fired-signal-linked remediation is selected, not priority-1');
  const fipsPath = fips.phases.validate.remediation_options_considered.find((c) => c.id === 'activate-fips-provider-or-retract-claim');
  assert.equal(fipsPath.addresses_fired_signal, true, 'the considered trace flags the path as addressing a fired signal');
  // Backward-compat: with no fired signal (no for_signals match), the
  // priority-1 path is the fallback — unchanged from prior behavior.
  const none = runner.run(
    'crypto-codebase',
    'weak-primitive-inventory',
    { signal_overrides: {} },
    { force_replay: true, mode: 'test' }
  );
  assert.equal(none.phases.validate.selected_remediation.id, 'rotate-to-pqc-hybrid-kem', 'no fired signal falls back to priority-1');

  // A fired-signal-relevant path must win over a satisfied-but-UNRELATED path:
  // here rotate-to-pqc-hybrid-kem's preconditions are satisfied, but the FIPS
  // finding is what fired, so activate-fips (which addresses it) is selected
  // rather than the ready-but-irrelevant priority-1 path.
  const satisfiedUnrelated = runner.run(
    'crypto-codebase',
    'weak-primitive-inventory',
    {
      signal_overrides: { 'fips-claim-without-runtime-activation': 'hit' },
      signals: { ml_kem_implementation_available_for_language: true, api_stability_promise_permits_default_change: true },
    },
    { force_replay: true, mode: 'test' }
  );
  assert.equal(satisfiedUnrelated.phases.validate.selected_remediation.id, 'activate-fips-provider-or-retract-claim', 'relevance outranks a satisfied-but-unrelated path');
});

test('the run human render surfaces collector_warnings so a skip is not hidden behind "evidence: complete"', () => {
  // EXCEPTD_RAW_JSON='' forces the human render (the helper defaults it to '1').
  const cli = makeCli(makeSuiteHome());
  const ev = JSON.stringify({
    precondition_checks: { 'repo-context': true },
    signal_overrides: {},
    collector_errors: [{ kind: 'file_too_large_skipped', reason: 'api-snapshot.json: 1469464 bytes exceeds 1048576-byte scan limit; not scanned' }],
  });
  const human = cli(['run', 'secrets', '--evidence', '-'], { input: ev, env: { EXCEPTD_RAW_JSON: '' } });
  assert.ok(/Collector notices \(1\)/.test(human.stdout), 'human render lists collector notices');
  assert.ok(/file_too_large_skipped/.test(human.stdout), 'the skip kind is shown to the human reader');
  assert.ok(/api-snapshot\.json/.test(human.stdout), 'the skipped file is named');
});

test('discover recommends containers for a subdir Dockerfile / compose variant (not just a root exact-name file)', () => {
  const cli = makeCli(makeSuiteHome());
  // A subdir Dockerfile + a compose variant — neither is a root-level
  // exact-name Dockerfile/docker-compose.yml, so the old root-only probes
  // missed them and discover never recommended the containers playbook.
  const fx = mkfx();
  fs.mkdirSync(path.join(fx, 'examples', 'wiki'), { recursive: true });
  fs.writeFileSync(path.join(fx, 'examples', 'wiki', 'Dockerfile'), 'FROM node:latest\n');
  fs.writeFileSync(path.join(fx, 'docker-compose.test.yml'), 'services:\n  app:\n    image: x\n');
  const ids = ((tryJson(cli(['discover', '--cwd', fx, '--json']).stdout) || {}).recommended_playbooks || []).map((r) => r.playbook || r.id || r);
  assert.ok(ids.includes('containers'), 'discover recommends containers for a subdir Dockerfile + compose variant');
  // A tree with no container config must NOT recommend containers.
  const empty = mkfx();
  fs.writeFileSync(path.join(empty, 'README.md'), '# nothing container-ish here\n');
  const ids2 = ((tryJson(cli(['discover', '--cwd', empty, '--json']).stdout) || {}).recommended_playbooks || []).map((r) => r.playbook || r.id || r);
  assert.equal(ids2.includes('containers'), false, 'no container config means no containers recommendation');
});

test('collect --help documents the --attest-ownership flag it accepts', () => {
  // The flag is allowlisted and consumed by the collector, and the
  // precondition-block remediation tells operators to use it — so collect's
  // own help must list it (otherwise an operator following the hint cannot
  // discover the flag).
  const cli = makeCli(makeSuiteHome());
  const out = cli(['collect', '--help']).stdout || '';
  assert.ok(/--attest-ownership/.test(out), 'collect --help lists the --attest-ownership flag');
});

test('a blocked-preflight summary_line truncates on a word boundary with an ellipsis, not mid-token', () => {
  const res = runner.run(
    'cicd-pipeline-compromise',
    'all-pipelines-and-runners',
    { precondition_checks: { 'operator-owns-ci-fleet': false } },
    { force_replay: true, mode: 'test' }
  );
  const sl = res.summary_line;
  assert.ok(sl.length <= 240, 'summary stays within the 240-char cap');
  assert.equal(sl.endsWith('…'), true, 'a truncated summary is marked with an ellipsis');
  assert.equal(/[A-Za-z0-9]$/.test(sl), false, 'the cut does not split a word mid-token');
});

test("crypto-codebase collector attests repo-has-source-tree from the gate's own markers (not just source-file extensions)", () => {
  // A manifest marker -> true.
  const withManifest = mkfx();
  fs.writeFileSync(path.join(withManifest, 'package.json'), '{"name":"x","version":"1.0.0"}');
  const m = cryptoCodebase.collect({ cwd: withManifest }).precondition_checks;
  assert.equal(m['repo-has-source-tree'], true, 'a package manifest marker attests the gate true');
  assert.equal('repo-context' in m, false, 'the playbook-unknown repo-context key must not be emitted');

  // An src/ directory marker (no manifest, no extension-matched files yet) -> true.
  const withSrcDir = mkfx();
  fs.mkdirSync(path.join(withSrcDir, 'src'), { recursive: true });
  assert.equal(
    cryptoCodebase.collect({ cwd: withSrcDir }).precondition_checks['repo-has-source-tree'],
    true,
    'an src/ directory marker attests the gate true even before any source file exists'
  );

  // Source files by extension but NONE of the gate's markers -> false: the
  // attestation mirrors the gate's exists_any(markers) predicate, not the
  // collector's SOURCE_EXTS file count.
  const looseSourceOnly = mkfx();
  fs.writeFileSync(path.join(looseSourceOnly, 'script.py'), 'import hashlib\n');
  assert.equal(
    cryptoCodebase.collect({ cwd: looseSourceOnly }).precondition_checks['repo-has-source-tree'],
    false,
    'a loose source file with no source-tree marker attests false, matching the gate'
  );

  // No markers at all -> false.
  const empty = mkfx();
  assert.equal(
    cryptoCodebase.collect({ cwd: empty }).precondition_checks['repo-has-source-tree'],
    false,
    'an empty tree attests the gate false'
  );
});
