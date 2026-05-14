'use strict';

/**
 * Bundle-emit correctness checks against the canonical schemas of:
 *   - CSAF 2.0 (csaf_security_advisory category)
 *   - SARIF 2.1.0
 *   - OpenVEX 0.2.0
 *
 * v0.12.12 (B1-B7 audit): the bundle emitters were structurally
 * non-conformant against each of the three downstream specs. These tests
 * pin the conformant shape so regressions surface on every test run.
 *
 * Run under: node --test --test-concurrency=1 tests/
 * (concurrency=1 matters — the runner is module-scope and reads
 * EXCEPTD_PLAYBOOK_DIR once per process.)
 */

const test = require('node:test');
const { describe, it, before } = test;
const assert = require('node:assert/strict');
const path = require('node:path');

const RUNNER_PATH = path.resolve(__dirname, '..', 'lib', 'playbook-runner.js');
const REAL_PLAYBOOK_DIR = path.resolve(__dirname, '..', 'data', 'playbooks');

function loadRunner() {
  delete require.cache[RUNNER_PATH];
  process.env.EXCEPTD_PLAYBOOK_DIR = REAL_PLAYBOOK_DIR;
  return require(RUNNER_PATH);
}

// Detect → analyze → validate → close against kernel playbook with one
// indicator forced to hit, producing CVE matches + indicator hit + framework
// gap mapping in a single bundle build.
function emitBundles() {
  const runner = loadRunner();
  const detRes = runner.detect('kernel', 'all-catalogued-kernel-cves', {
    signal_overrides: { 'kver-in-affected-range': 'hit' }
  });
  const an = runner.analyze('kernel', 'all-catalogued-kernel-cves', detRes, {
    patch_available: false, blast_radius_score: 3
  });
  const v = runner.validate('kernel', 'all-catalogued-kernel-cves', an, {});
  const c = runner.close('kernel', 'all-catalogued-kernel-cves', an, v, {
    _bundle_formats: ['csaf-2.0', 'sarif-2.1.0', 'openvex-0.2.0']
  }, { session_id: 'bundlecorrectnesstest' });
  return c.evidence_package.bundles_by_format;
}

describe('CSAF 2.0 — B5 (product_tree mandatory for security_advisory)', () => {
  let bundle;
  before(() => { bundle = emitBundles()['csaf-2.0']; });

  it('document.category is csaf_security_advisory', () => {
    assert.equal(bundle.document.category, 'csaf_security_advisory');
    assert.equal(bundle.document.csaf_version, '2.0');
  });

  it('product_tree.full_product_names is non-empty', () => {
    assert.ok(bundle.product_tree, 'product_tree must exist');
    assert.ok(Array.isArray(bundle.product_tree.full_product_names));
    assert.ok(bundle.product_tree.full_product_names.length >= 1);
    const fp = bundle.product_tree.full_product_names[0];
    assert.equal(typeof fp.product_id, 'string');
    assert.ok(fp.product_id.startsWith('exceptd-target-'));
    assert.equal(typeof fp.name, 'string');
    assert.ok(fp.product_identification_helper?.purl);
  });

  it('every vulnerability references product_tree via product_status', () => {
    assert.ok(bundle.vulnerabilities.length > 0);
    const knownProductIds = new Set(
      bundle.product_tree.full_product_names.map(p => p.product_id)
    );
    for (const v of bundle.vulnerabilities) {
      assert.ok(v.product_status, `vulnerability missing product_status: ${JSON.stringify(v).slice(0, 80)}`);
      const refIds = [
        ...(v.product_status.known_affected || []),
        ...(v.product_status.fixed || []),
        ...(v.product_status.under_investigation || []),
        ...(v.product_status.not_affected || [])
      ];
      assert.ok(refIds.length >= 1, 'product_status must reference at least one product');
      for (const id of refIds) {
        assert.ok(knownProductIds.has(id), `unknown product_id ${id} referenced by vulnerability`);
      }
    }
  });
});

describe('SARIF 2.1.0 — B6 (locations) + B7 (null property bag)', () => {
  let bundle;
  before(() => { bundle = emitBundles()['sarif-2.1.0']; });

  it('$schema + version pinned', () => {
    assert.equal(bundle.version, '2.1.0');
    assert.match(bundle.$schema, /sarif-schema-2\.1\.0\.json$/);
  });

  it('indicator-hit results include locations when artifact paths exist', () => {
    const results = bundle.runs[0].results;
    const indicatorResults = results.filter(r => r.properties?.kind === 'indicator_hit');
    assert.ok(indicatorResults.length >= 1, 'kernel playbook should emit at least one indicator hit');
    for (const r of indicatorResults) {
      // kernel playbook has look-phase artifacts → locations MUST be present.
      assert.ok(Array.isArray(r.locations), `indicator result ${r.ruleId} missing locations`);
      assert.ok(r.locations[0].physicalLocation?.artifactLocation?.uri, 'physicalLocation.artifactLocation.uri must be populated');
    }
  });

  it('property bags omit null keys (B7)', () => {
    const results = bundle.runs[0].results;
    for (const r of results) {
      for (const [k, v] of Object.entries(r.properties || {})) {
        assert.notEqual(v, null, `result ${r.ruleId} has null property ${k}`);
      }
    }
  });

  it('framework-gap results carry kind: informational (B3 SARIF analogue)', () => {
    const gapResults = bundle.runs[0].results.filter(r => String(r.ruleId).startsWith('framework-gap-'));
    if (gapResults.length === 0) return; // playbook has none — skip
    for (const r of gapResults) {
      assert.equal(r.kind, 'informational', 'framework-gap results must declare kind: informational');
    }
  });
});

describe('OpenVEX 0.2.0 — B1 (products) + B2 (status) + B3 (no framework gaps) + B4 (URN IRI)', () => {
  let bundle;
  before(() => { bundle = emitBundles()['openvex-0.2.0']; });

  it('@context + version pinned', () => {
    assert.equal(bundle['@context'], 'https://openvex.dev/ns/v0.2.0');
    assert.equal(bundle.version, 1);
  });

  it('every statement has products (B1)', () => {
    assert.ok(Array.isArray(bundle.statements));
    assert.ok(bundle.statements.length > 0);
    for (const s of bundle.statements) {
      assert.ok(Array.isArray(s.products), `statement missing products: ${JSON.stringify(s.vulnerability)}`);
      assert.ok(s.products.length >= 1);
      assert.ok(s.products[0]['@id'], 'product entry missing @id');
      assert.ok(s.products[0]['@id'].startsWith('pkg:exceptd/'), 'product @id should be a pkg:exceptd/ purl');
    }
  });

  it('indicator-hit statements emit status:affected with action_statement (B2)', () => {
    const indicatorStatements = bundle.statements.filter(s =>
      String(s.vulnerability['@id']).startsWith('urn:exceptd:indicator:')
    );
    assert.ok(indicatorStatements.length >= 1, 'must contain at least one indicator statement');
    const hits = indicatorStatements.filter(s => s.status === 'affected');
    assert.ok(hits.length >= 1, 'forced indicator hit must produce status: affected');
    for (const s of hits) {
      assert.equal(typeof s.action_statement, 'string', 'affected statements must carry action_statement');
      assert.ok(s.action_statement.length > 0);
    }
  });

  it('no framework-gap statements pollute the VEX feed (B3)', () => {
    for (const s of bundle.statements) {
      const id = String(s.vulnerability['@id']);
      assert.ok(!id.includes('framework-gap'), `framework-gap statement leaked into OpenVEX: ${id}`);
    }
  });

  it('every @id is a valid URN (B4)', () => {
    // CVE statements: urn:cve:<id>
    // Indicator statements: urn:exceptd:indicator:<playbook>:<indicator-id>
    const urnRe = /^urn:[a-z][a-z0-9-]*:[a-z0-9_-]+(?::[a-z0-9_-]+)*$/;
    for (const s of bundle.statements) {
      const id = String(s.vulnerability['@id']);
      assert.match(id, urnRe, `vulnerability @id is not a valid URN: ${id}`);
      // No literal spaces, no unregistered exceptd: prefix
      assert.ok(!id.includes(' '), `@id has literal space: ${id}`);
      assert.ok(!id.startsWith('exceptd:'), `@id uses unregistered exceptd: scheme: ${id}`);
    }
  });

  it('valid OpenVEX status values only', () => {
    const validStatuses = new Set(['not_affected', 'affected', 'fixed', 'under_investigation']);
    for (const s of bundle.statements) {
      assert.ok(validStatuses.has(s.status), `invalid OpenVEX status: ${s.status}`);
      if (s.status === 'not_affected') {
        assert.ok(s.justification, 'not_affected status requires justification');
      }
      if (s.status === 'affected') {
        assert.ok(s.action_statement, 'affected status requires action_statement');
      }
      if (s.status === 'under_investigation') {
        assert.equal(s.action_statement, undefined, 'under_investigation must not include action_statement');
      }
    }
  });
});
