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
