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

// ----- audit W (v0.12.20) regression coverage -----

function emitBundlesWith(opts = {}) {
  const runner = loadRunner();
  const detRes = runner.detect('kernel', 'all-catalogued-kernel-cves', {
    signal_overrides: { 'kver-in-affected-range': 'hit' }
  });
  const an = runner.analyze('kernel', 'all-catalogued-kernel-cves', detRes, {
    patch_available: false, blast_radius_score: 3,
    ...(opts.vex_fixed ? { vex_fixed: opts.vex_fixed } : {}),
  });
  const v = runner.validate('kernel', 'all-catalogued-kernel-cves', an, {});
  const c = runner.close('kernel', 'all-catalogued-kernel-cves', an, v, {
    _bundle_formats: ['csaf-2.0', 'sarif-2.1.0', 'openvex-0.2.0']
  }, { session_id: 'bundlecorrectnesstest' });
  return { bundles: c.evidence_package.bundles_by_format, body: c.evidence_package.bundle_body, analyze: an };
}

describe('audit W P1-A — fixed status gated on vex_status, not live_patch_available', () => {
  it('CSAF: live-patchable CVE without operator VEX disposition stays known_affected', () => {
    const { bundles, analyze } = emitBundlesWith();
    // The kernel playbook surfaces Copy Fail (live_patch_available=true) but
    // no operator-supplied VEX disposition is present in this run.
    const livePatchableMatched = analyze.matched_cves.filter(c => c.live_patch_available === true);
    assert.ok(livePatchableMatched.length >= 1, 'fixture: at least one matched CVE must be live-patchable');
    for (const matched of livePatchableMatched) {
      const vuln = bundles['csaf-2.0'].vulnerabilities.find(v => v.cve === matched.cve_id);
      assert.ok(vuln, `csaf vuln missing for ${matched.cve_id}`);
      assert.ok(vuln.product_status.known_affected, `${matched.cve_id} must remain known_affected absent vex_status:fixed`);
      assert.ok(!vuln.product_status.fixed, `${matched.cve_id} must NOT be reported as fixed based on live_patch_available alone`);
    }
  });

  it('CSAF: operator vex_status=fixed promotes to product_status.fixed', () => {
    // Pick the first live-patchable CVE the kernel playbook surfaces and
    // mark it as fixed via the vex_fixed set.
    const baseline = emitBundlesWith();
    const target = baseline.analyze.matched_cves.find(c => c.live_patch_available === true);
    assert.ok(target, 'fixture: need a live-patchable matched CVE to test promotion');
    const { bundles } = emitBundlesWith({ vex_fixed: new Set([target.cve_id]) });
    const vuln = bundles['csaf-2.0'].vulnerabilities.find(v => v.cve === target.cve_id);
    assert.ok(vuln.product_status.fixed, 'operator vex_status:fixed must drive product_status.fixed');
    assert.ok(!vuln.product_status.known_affected);
  });

  it('OpenVEX: live-patchable without vex_status:fixed stays affected', () => {
    const { bundles, analyze } = emitBundlesWith();
    const livePatchableMatched = analyze.matched_cves.filter(c => c.live_patch_available === true);
    for (const matched of livePatchableMatched) {
      const stmt = bundles['openvex-0.2.0'].statements.find(s => s.vulnerability.name === matched.cve_id);
      assert.ok(stmt, `openvex stmt missing for ${matched.cve_id}`);
      assert.equal(stmt.status, 'affected', `${matched.cve_id} must NOT be reported fixed based on live_patch_available alone`);
      assert.ok(stmt.action_statement, 'affected statement requires action_statement');
    }
  });

  it('OpenVEX: operator vex_status=fixed produces status:fixed', () => {
    const baseline = emitBundlesWith();
    const target = baseline.analyze.matched_cves.find(c => c.live_patch_available === true);
    const { bundles } = emitBundlesWith({ vex_fixed: new Set([target.cve_id]) });
    const stmt = bundles['openvex-0.2.0'].statements.find(s => s.vulnerability.name === target.cve_id);
    assert.equal(stmt.status, 'fixed');
    assert.equal(stmt.action_statement, undefined, 'fixed statement must not carry action_statement');
  });
});

describe('audit W P2-A — SARIF artifactLocation rejects shell commands', () => {
  it('locations[].physicalLocation.artifactLocation.uri is path-shaped', () => {
    const { bundles } = emitBundlesWith();
    const sarif = bundles['sarif-2.1.0'];
    const withLocs = sarif.runs[0].results.filter(r => Array.isArray(r.locations));
    assert.ok(withLocs.length >= 1, 'fixture: at least one result must carry locations');
    for (const r of withLocs) {
      const uri = r.locations[0].physicalLocation.artifactLocation.uri;
      // Must not contain whitespace (commands like `uname -r`).
      assert.ok(!/\s/.test(uri), `artifactLocation.uri has whitespace: ${uri}`);
      // Must not contain shell-pipe / sentence punctuation.
      assert.ok(!/[|;&]/.test(uri), `artifactLocation.uri has shell metacharacters: ${uri}`);
      // Must look like a path or file URI.
      assert.match(uri, /^(?:[/~]|[A-Za-z]:[/\\]|\.\.?[/\\]|file:|[A-Za-z0-9_.+-]+[/\\][^\s]+)/,
        `artifactLocation.uri not path-shaped: ${uri}`);
    }
  });
});

describe('audit W P2-B — bundle_body and bundles_by_format share timestamps', () => {
  it('CSAF tracking dates align between bundle_body and bundles_by_format[primary]', () => {
    const { bundles, body } = emitBundlesWith();
    // bundle_body for kernel playbook (default csaf-2.0 primary) must
    // share identity with bundles_by_format['csaf-2.0'] (same object).
    assert.equal(body, bundles['csaf-2.0'], 'bundle_body must be the same object reference as bundles_by_format[primary]');
  });

  it('multi-format emit produces a single issuedAt across all formats', () => {
    const { bundles } = emitBundlesWith();
    const csafIssued = bundles['csaf-2.0'].document.tracking.initial_release_date;
    const vexIssued = bundles['openvex-0.2.0'].timestamp;
    assert.equal(csafIssued, vexIssued, 'CSAF initial_release_date and OpenVEX timestamp must use the same issuedAt');
    // Also: current_release_date and revision_history[0].date must match.
    assert.equal(bundles['csaf-2.0'].document.tracking.current_release_date, csafIssued);
    assert.equal(bundles['csaf-2.0'].document.tracking.revision_history[0].date, csafIssued);
  });
});

describe('audit W P2-D — CSAF framework gaps move from vulnerabilities[] to document.notes[]', () => {
  it('vulnerabilities[] contains no exceptd-framework-gap ids', () => {
    const { bundles } = emitBundlesWith();
    const csaf = bundles['csaf-2.0'];
    for (const v of csaf.vulnerabilities) {
      const ids = v.ids || [];
      for (const idEntry of ids) {
        assert.notEqual(idEntry.system_name, 'exceptd-framework-gap',
          'framework gaps must not ride in vulnerabilities[]; they belong in document.notes[]');
      }
    }
  });

  it('document.notes[] surfaces framework gaps when analyze produced any', () => {
    const { bundles, analyze } = emitBundlesWith();
    const csaf = bundles['csaf-2.0'];
    const gapCount = (analyze.framework_gap_mapping || []).length;
    const notes = csaf.document.notes || [];
    assert.equal(notes.length, gapCount, 'document.notes[] count must match framework_gap_mapping.length');
    for (const n of notes) {
      assert.equal(n.category, 'details', 'framework-gap notes use category: details');
      assert.ok(typeof n.text === 'string' && n.text.length > 0);
    }
  });
});

describe('audit W P3-A — SARIF invocations.properties strips null values', () => {
  it('invocations[0].properties has no null-valued keys', () => {
    const { bundles } = emitBundlesWith();
    const props = bundles['sarif-2.1.0'].runs[0].invocations[0].properties;
    for (const [k, v] of Object.entries(props)) {
      assert.notEqual(v, null, `invocations.properties.${k} must be omitted when null`);
    }
  });
});
