'use strict';

/**
 * Tests for the close-phase evidence-bundle identifier handling in
 * lib/playbook-runner.js.
 *
 * Runs under: node --test --test-concurrency=1
 *
 * Two behaviors are covered:
 *
 *   1. CSAF product_tree product_name comes from the package, never from a
 *      version-range operator. The catalog's dominant affected_versions shape
 *      is `package OP version` (e.g. a package name, an operator such as '>=',
 *      then a bound); naively splitting on whitespace named the product after
 *      the operator ('>=', '<', '==') instead of the package.
 *
 *   2. SARIF rule helpUri routes by issuing authority. CVE ids keep the NVD
 *      detail URL; non-CVE matched ids (MAL-/GHSA-/OSV-/RUSTSEC-/SNYK-) get the
 *      correct authority URL or no helpUri at all — never a nvd.nist.gov link
 *      that 404s and mislabels the id as an NVD CVE.
 */

const test = require('node:test');
const { describe, it } = test;
const assert = require('node:assert/strict');
const path = require('node:path');

const runner = require(path.resolve(__dirname, '..', 'lib', 'playbook-runner.js'));

const OPERATOR_ONLY = /^(<|<=|>|>=|==|=|!=|~|\^|~>)$/;

describe('CSAF product_tree — package name, never the range operator', () => {
  const shapes = [
    { affected: 'linux-kernel >= 4.14', pkg: 'linux-kernel' },
    { affected: 'runc <= 1.1.11', pkg: 'runc' },
    { affected: 'litellm < 1.83.7', pkg: 'litellm' },
    { affected: 'elementary-data == 2.23.3', pkg: 'elementary-data' },
  ];

  it('names the product after the package for each range-operator shape', () => {
    const cves = shapes.map((s, i) => ({ cve_id: `CVE-2026-100${i}`, affected_versions: [s.affected] }));
    const { branches } = runner._buildCsafBranches(cves, { _runErrors: [] });
    const byPkg = new Map();
    for (const v of branches) {
      for (const p of v.branches) {
        byPkg.set(p.name, p);
        assert.ok(!OPERATOR_ONLY.test(p.name), `product_name is a bare operator: ${p.name}`);
      }
    }
    for (const s of shapes) {
      const p = byPkg.get(s.pkg);
      assert.ok(p, `product_name "${s.pkg}" present in product_tree`);
      // The operator is carried into the version qualifier, not lost and not
      // promoted to the product name.
      const versionName = p.branches[0].name;
      assert.match(versionName, new RegExp(`^(<|<=|>|>=|==|=)\\s`), `version qualifier keeps the operator: ${versionName}`);
      // Leaf product.name is package/package@<version-range>, never operator-named.
      assert.ok(!/\/(<|<=|>|>=|==|=)@/.test(p.branches[0].product.name),
        `leaf product name embeds an operator: ${p.branches[0].product.name}`);
    }
  });

  it('end-to-end close() emits a CSAF product_tree free of operator-named products', () => {
    const pb = runner.loadPlaybook('sbom');
    const directiveId = pb.directives[0].id;
    const analyzeResult = {
      matched_cves: [
        { cve_id: 'CVE-2026-9999', rwep: 95, cisa_kev: true, active_exploitation: 'confirmed', cvss_score: null, cvss_vector: null, affected_versions: ['linux-kernel >= 4.14'] },
      ],
      rwep: { adjusted: 95 }, blast_radius_score: 4, framework_gap_mapping: [],
      _detect_indicators: [], _detect_classification: 'detected',
      compliance_theater_check: { verdict: 'present' },
    };
    const out = runner.close('sbom', directiveId, analyzeResult, { regression_next_run: null, selected_remediation: { id: 'rem-1', description: 'patch' } },
      { _bundle_formats: ['csaf-2.0'] }, { session_id: 'abcdef0123456789' });
    const csaf = out.evidence_package.bundles_by_format['csaf-2.0'];
    const branches = (csaf.product_tree && csaf.product_tree.branches) || [];
    let count = 0;
    for (const v of branches) {
      for (const p of (v.branches || [])) {
        count++;
        assert.ok(!OPERATOR_ONLY.test(p.name), `product_name is a bare operator in close() output: ${p.name}`);
      }
    }
    assert.ok(count > 0, 'product_tree contains at least one product branch');
    const linux = branches.find(v => v.name === 'linux-kernel');
    assert.ok(linux, 'linux-kernel vendor branch present');
    assert.equal(linux.branches[0].name, 'linux-kernel');
  });
});

describe('SARIF rule helpUri — authority routing, not a hardcoded NVD link', () => {
  function sarifRulesFor(matched) {
    const pb = runner.loadPlaybook('sbom');
    const directiveId = pb.directives[0].id;
    const analyzeResult = {
      matched_cves: matched,
      rwep: { adjusted: 95 }, blast_radius_score: 4, framework_gap_mapping: [],
      _detect_indicators: [], _detect_classification: 'detected',
      compliance_theater_check: { verdict: 'present' },
    };
    const out = runner.close('sbom', directiveId, analyzeResult, { regression_next_run: null, selected_remediation: { id: 'rem-1', description: 'patch' } },
      { _bundle_formats: ['sarif'] }, { session_id: 'abcdef0123456789' });
    const sarif = out.evidence_package.bundles_by_format['sarif'];
    return sarif.runs[0].tool.driver.rules;
  }

  it('a CVE rule keeps the NVD detail helpUri and a bare CVE short description', () => {
    const rules = sarifRulesFor([
      { cve_id: 'CVE-2026-43284', rwep: 90, cisa_kev: false, active_exploitation: 'none', cvss_score: null, cvss_vector: null, affected_versions: [] },
    ]);
    const cveRule = rules.find(r => r.id.endsWith('CVE-2026-43284'));
    assert.ok(cveRule, 'CVE rule present');
    assert.equal(cveRule.helpUri, 'https://nvd.nist.gov/vuln/detail/CVE-2026-43284');
    assert.equal(cveRule.shortDescription.text, 'CVE-2026-43284');
  });

  it('a MAL- rule carries no nvd.nist.gov helpUri and labels its authority', () => {
    const rules = sarifRulesFor([
      { cve_id: 'CVE-2026-43284', rwep: 90, cisa_kev: false, active_exploitation: 'none', cvss_score: null, cvss_vector: null, affected_versions: [] },
      { cve_id: 'MAL-2026-MOIKA-DEPCONFUSION', rwep: 88, cisa_kev: false, active_exploitation: 'none', cvss_score: null, cvss_vector: null, affected_versions: [] },
    ]);
    const malRule = rules.find(r => r.id.endsWith('MAL-2026-MOIKA-DEPCONFUSION'));
    assert.ok(malRule, 'MAL rule present');
    // Malicious-Package ids have no canonical per-id advisory page: helpUri is
    // omitted entirely rather than pointing at NVD.
    assert.equal(malRule.helpUri, undefined);
    // The short description must not present the MAL id as a bare NVD CVE.
    assert.equal(malRule.shortDescription.text, 'MAL-2026-MOIKA-DEPCONFUSION (Malicious-Package)');
  });

  it('advisoryAuthorityFor routes each registry prefix to its own authority', () => {
    const a = runner._advisoryAuthorityFor;
    assert.deepEqual(a('CVE-2026-43284'), { system_name: 'NVD', helpUri: 'https://nvd.nist.gov/vuln/detail/CVE-2026-43284' });
    assert.deepEqual(a('GHSA-abcd-1234-wxyz'), { system_name: 'GHSA', helpUri: 'https://github.com/advisories/GHSA-abcd-1234-wxyz' });
    assert.deepEqual(a('OSV-2026-1'), { system_name: 'OSV', helpUri: 'https://osv.dev/vulnerability/OSV-2026-1' });
    assert.deepEqual(a('RUSTSEC-2026-0001'), { system_name: 'RUSTSEC', helpUri: 'https://rustsec.org/advisories/RUSTSEC-2026-0001.html' });
    assert.deepEqual(a('SNYK-JS-FOO-1'), { system_name: 'Snyk', helpUri: 'https://security.snyk.io/vuln/SNYK-JS-FOO-1' });
    assert.deepEqual(a('MAL-2026-X'), { system_name: 'Malicious-Package', helpUri: null });
    // A genuinely-unknown prefix gets no fabricated link.
    assert.deepEqual(a('WEIRD-1'), { system_name: 'exceptd-unknown', helpUri: null });
  });
});
