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

test('crypto-codebase collector attests repo-has-source-tree from a walked source file (and false on an empty tree)', () => {
  const withSrc = mkfx();
  fs.writeFileSync(path.join(withSrc, 'index.js'), 'const crypto = require("crypto"); crypto.createHash("sha256");\n');
  const got = cryptoCodebase.collect({ cwd: withSrc }).precondition_checks;
  assert.equal(got['repo-has-source-tree'], true, 'a repo with source files attests the gate true');
  assert.equal('repo-context' in got, false, 'the playbook-unknown repo-context key must not be emitted');

  const empty = mkfx();
  assert.equal(
    cryptoCodebase.collect({ cwd: empty }).precondition_checks['repo-has-source-tree'],
    false,
    'an empty tree attests the gate false'
  );
});
