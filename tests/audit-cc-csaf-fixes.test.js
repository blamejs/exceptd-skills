'use strict';

/**
 * audit CC — CSAF / SARIF / bundles-by-format correctness against the strict
 * downstream validators (BSI CSAF validator, GitHub Code Scanning).
 *
 *   P1-1: tracking.status defaults to 'interim' (CSAF §3.1.11.3.5.1).
 *   P1-2: non-CVE identifiers (MAL-, GHSA-, OSV-) route to vulnerabilities[].ids[]
 *         with a real system_name, NOT to vulnerabilities[].cve.
 *   P1-3: document.publisher.namespace is supplied by the operator running the
 *         scan, not the tooling vendor.
 *   P1-4: --operator threads into tracking.generator.engine and
 *         publisher.contact_details.
 *   P2-1: bundles_by_format is always { [primaryFormat]: body } even without
 *         additional --format flags.
 *   P2-2: cvss_v3 block carries vectorString (CSAF §3.2.1.5); block is dropped
 *         when score is unset.
 *   P2-6: SARIF ruleId carries a playbook prefix so cross-playbook merges in
 *         a single sarif-log don't dedupe rules.
 *
 * Run under: node --test --test-concurrency=1 tests/
 */

const test = require('node:test');
const { describe, it } = test;
const assert = require('node:assert/strict');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const RUNNER_PATH = path.resolve(__dirname, '..', 'lib', 'playbook-runner.js');
const CLI_PATH = path.resolve(__dirname, '..', 'bin', 'exceptd.js');
const REAL_PLAYBOOK_DIR = path.resolve(__dirname, '..', 'data', 'playbooks');

function loadRunner() {
  delete require.cache[RUNNER_PATH];
  process.env.EXCEPTD_PLAYBOOK_DIR = REAL_PLAYBOOK_DIR;
  return require(RUNNER_PATH);
}

// Build a real kernel close() result with `_bundle_formats` and the given
// runOpts. The kernel playbook has matched_cves (real CVE-XXXX-YYYY ids) and
// framework_gap_mapping entries, so the CSAF emitter exercises both the
// CVE-routing and notes paths.
function closeKernel(runOpts = {}, agentSignalsExtra = {}) {
  const runner = loadRunner();
  const det = runner.detect('kernel', 'all-catalogued-kernel-cves', {
    signal_overrides: { 'kver-in-affected-range': 'hit' }
  });
  const an = runner.analyze('kernel', 'all-catalogued-kernel-cves', det, {
    patch_available: false, blast_radius_score: 3
  });
  const v = runner.validate('kernel', 'all-catalogued-kernel-cves', an, {});
  const c = runner.close('kernel', 'all-catalogued-kernel-cves', an, v, {
    _bundle_formats: ['csaf-2.0', 'sarif-2.1.0', 'openvex-0.2.0'],
    ...agentSignalsExtra,
  }, { session_id: 'auditcccsaffixestest', ...runOpts });
  return { close: c, analyze: an, validate: v };
}

// Build a CSAF bundle directly against a synthesized analyze result whose
// matched_cves carries a MAL- identifier. The buildEvidenceBundle path is
// what matters for CC P1-2; we drive it via close() so the public surface
// is exercised end-to-end. The runner exports its internal pipeline via
// detect/analyze/close — to inject a non-CVE matched id we patch
// analyze.matched_cves between analyze and close (same shape as v0.12.14's
// vex_fixed tests).
function closeWithSyntheticMatchedId(matchedId, opts = {}) {
  const runner = loadRunner();
  const det = runner.detect('kernel', 'all-catalogued-kernel-cves', {
    signal_overrides: { 'kver-in-affected-range': 'hit' }
  });
  const an = runner.analyze('kernel', 'all-catalogued-kernel-cves', det, {
    patch_available: false, blast_radius_score: 3
  });
  // Replace matched_cves with one synthetic entry that has the target id.
  an.matched_cves = [{
    cve_id: matchedId,
    rwep: 80, cvss_score: 9.3,
    cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    cisa_kev: false, active_exploitation: 'confirmed',
    ai_discovered: false, live_patch_available: false,
    patch_available: true, vex_status: null, correlated_via: ['synthetic'],
  }];
  const v = runner.validate('kernel', 'all-catalogued-kernel-cves', an, {});
  const c = runner.close('kernel', 'all-catalogued-kernel-cves', an, v, {
    _bundle_formats: ['csaf-2.0'],
  }, { session_id: 'auditccsynthetictest', ...opts });
  return c.evidence_package.bundles_by_format['csaf-2.0'];
}

// ---------- P1-1 ----------

describe('audit CC P1-1 — CSAF tracking.status defaults to interim', () => {
  it('runtime emit with no --csaf-status sets status to interim', () => {
    const { close: c } = closeKernel();
    const csaf = c.evidence_package.bundles_by_format['csaf-2.0'];
    assert.equal(csaf.document.tracking.status, 'interim',
      'CSAF §3.1.11.3.5.1: runtime detection is not an immutable advisory; runtime emit defaults to interim');
  });

  it('runOpts.csafStatus=final promotes to final', () => {
    const { close: c } = closeKernel({ csafStatus: 'final' });
    const csaf = c.evidence_package.bundles_by_format['csaf-2.0'];
    assert.equal(csaf.document.tracking.status, 'final');
  });

  it('runOpts.csafStatus=draft is accepted', () => {
    const { close: c } = closeKernel({ csafStatus: 'draft' });
    const csaf = c.evidence_package.bundles_by_format['csaf-2.0'];
    assert.equal(csaf.document.tracking.status, 'draft');
  });

  it('unknown csafStatus value silently falls back to interim (defence-in-depth — CLI rejects upstream)', () => {
    const { close: c } = closeKernel({ csafStatus: 'finel' });
    const csaf = c.evidence_package.bundles_by_format['csaf-2.0'];
    assert.equal(csaf.document.tracking.status, 'interim');
  });
});

// ---------- P1-2 ----------

describe('audit CC P1-2 — non-CVE ids route to ids[] with proper system_name', () => {
  it('CVE-shaped id stays in vulnerabilities[].cve', () => {
    const csaf = closeWithSyntheticMatchedId('CVE-2026-31431');
    const vuln = csaf.vulnerabilities.find(v => v.cve === 'CVE-2026-31431');
    assert.ok(vuln, 'CVE-shaped id must remain in `cve` field');
    assert.equal(vuln.ids, undefined,
      'CVE-shaped id must NOT also emit an ids[] entry — pre-fix never did and validators dedupe');
  });

  it('MAL-2026-3083 emits via ids[] with system_name: Malicious-Package', () => {
    const csaf = closeWithSyntheticMatchedId('MAL-2026-3083');
    const malVuln = csaf.vulnerabilities.find(v =>
      Array.isArray(v.ids) && v.ids.some(idEntry => idEntry.text === 'MAL-2026-3083')
    );
    assert.ok(malVuln, `MAL- id must appear under ids[]; got: ${JSON.stringify(csaf.vulnerabilities[0]).slice(0, 200)}`);
    assert.equal(malVuln.cve, undefined,
      'MAL- id must NOT be placed under `cve` (CSAF §3.2.1.2 regex rejects it)');
    const entry = malVuln.ids.find(e => e.text === 'MAL-2026-3083');
    assert.equal(entry.system_name, 'Malicious-Package',
      'MAL- ids carry system_name: Malicious-Package');
    assert.equal(entry.text, 'MAL-2026-3083');
  });

  it('GHSA-xxxx-xxxx-xxxx emits with system_name: GHSA', () => {
    const csaf = closeWithSyntheticMatchedId('GHSA-4xqg-gf5c-ghwq');
    const v = csaf.vulnerabilities.find(x =>
      Array.isArray(x.ids) && x.ids.some(e => e.text === 'GHSA-4xqg-gf5c-ghwq')
    );
    assert.ok(v);
    assert.equal(v.cve, undefined);
    const entry = v.ids.find(e => e.text === 'GHSA-4xqg-gf5c-ghwq');
    assert.equal(entry.system_name, 'GHSA');
  });

  it('OSV-2026-1 emits with system_name: OSV', () => {
    const csaf = closeWithSyntheticMatchedId('OSV-2026-1');
    const v = csaf.vulnerabilities.find(x =>
      Array.isArray(x.ids) && x.ids.some(e => e.text === 'OSV-2026-1')
    );
    assert.ok(v);
    const entry = v.ids.find(e => e.text === 'OSV-2026-1');
    assert.equal(entry.system_name, 'OSV');
  });

  it('unknown-prefix id falls back to OSV system_name (never to `cve`)', () => {
    const csaf = closeWithSyntheticMatchedId('PYSEC-2026-99');
    const v = csaf.vulnerabilities.find(x =>
      Array.isArray(x.ids) && x.ids.some(e => e.text === 'PYSEC-2026-99')
    );
    assert.ok(v, 'unknown-prefix id must still surface via ids[], not be silently dropped');
    assert.equal(v.cve, undefined, 'unknown-prefix id must NOT be placed under `cve`');
  });
});

// ---------- P1-3 ----------

describe('audit CC P1-3 — publisher.namespace from operator, not tooling vendor', () => {
  it('default emit (no operator, no namespace) falls back to urn:exceptd:operator:unknown with explanatory note', () => {
    const { close: c } = closeKernel();
    const csaf = c.evidence_package.bundles_by_format['csaf-2.0'];
    assert.equal(csaf.document.publisher.namespace, 'urn:exceptd:operator:unknown');
    assert.equal(csaf.exceptd_extension.publisher_namespace_source, 'fallback');
    // The notes[] array MUST include the explanatory note category=general so
    // operators see why the fallback is in place.
    const notes = csaf.document.notes || [];
    const fallbackNote = notes.find(n => n.category === 'general' && /Publisher namespace not supplied/i.test(n.title));
    assert.ok(fallbackNote, 'fallback emit must surface a general note explaining the missing publisher namespace');
  });

  it('runOpts.publisherNamespace lands in document.publisher.namespace', () => {
    const { close: c } = closeKernel({ publisherNamespace: 'https://operator.example' });
    const csaf = c.evidence_package.bundles_by_format['csaf-2.0'];
    assert.equal(csaf.document.publisher.namespace, 'https://operator.example');
    assert.equal(csaf.exceptd_extension.publisher_namespace_source, 'runOpts.publisherNamespace');
  });

  it('URL-shaped --operator (no explicit namespace) is used as fallback publisher namespace', () => {
    const { close: c } = closeKernel({ operator: 'https://alice.example' });
    const csaf = c.evidence_package.bundles_by_format['csaf-2.0'];
    assert.equal(csaf.document.publisher.namespace, 'https://alice.example');
    assert.equal(csaf.exceptd_extension.publisher_namespace_source, 'runOpts.operator');
  });

  it('explicit publisherNamespace wins over URL-shaped operator', () => {
    const { close: c } = closeKernel({
      publisherNamespace: 'https://org.example',
      operator: 'https://individual.example',
    });
    const csaf = c.evidence_package.bundles_by_format['csaf-2.0'];
    assert.equal(csaf.document.publisher.namespace, 'https://org.example');
  });

  it('fallback emit also surfaces bundle_publisher_unclaimed in runOpts._runErrors', () => {
    // Direct buildEvidenceBundle exercises the bundle path with a real
    // _runErrors accumulator (close() doesn't pre-seed one for direct callers,
    // but the orchestrator does — we mimic that here).
    const runOpts = { session_id: 'auditccrunerrtest', _runErrors: [] };
    const runner = loadRunner();
    const det = runner.detect('kernel', 'all-catalogued-kernel-cves', {
      signal_overrides: { 'kver-in-affected-range': 'hit' }
    }, runOpts);
    const an = runner.analyze('kernel', 'all-catalogued-kernel-cves', det,
      { patch_available: false, blast_radius_score: 3 }, runOpts);
    const v = runner.validate('kernel', 'all-catalogued-kernel-cves', an, {}, runOpts);
    runner.close('kernel', 'all-catalogued-kernel-cves', an, v, {
      _bundle_formats: ['csaf-2.0'],
    }, runOpts);
    const unclaimed = runOpts._runErrors.filter(e => e && e.kind === 'bundle_publisher_unclaimed');
    assert.equal(unclaimed.length, 1,
      `fallback emit must push exactly one bundle_publisher_unclaimed entry; got ${unclaimed.length}: ${JSON.stringify(runOpts._runErrors)}`);
    const entry = unclaimed[0];
    assert.equal(typeof entry.reason, 'string');
    assert.ok(entry.reason.length > 0, 'bundle_publisher_unclaimed must carry a non-empty reason string');
    assert.match(String(entry.remediation || ''), /publisher-namespace/i,
      'remediation field must point operators at the --publisher-namespace flag');
  });

  it('supplied --publisher-namespace does NOT push bundle_publisher_unclaimed', () => {
    const runOpts = { session_id: 'auditcchappytest', _runErrors: [], publisherNamespace: 'https://operator.example' };
    const runner = loadRunner();
    const det = runner.detect('kernel', 'all-catalogued-kernel-cves', {
      signal_overrides: { 'kver-in-affected-range': 'hit' }
    }, runOpts);
    const an = runner.analyze('kernel', 'all-catalogued-kernel-cves', det,
      { patch_available: false, blast_radius_score: 3 }, runOpts);
    const v = runner.validate('kernel', 'all-catalogued-kernel-cves', an, {}, runOpts);
    runner.close('kernel', 'all-catalogued-kernel-cves', an, v, {
      _bundle_formats: ['csaf-2.0'],
    }, runOpts);
    const unclaimed = runOpts._runErrors.filter(e => e && e.kind === 'bundle_publisher_unclaimed');
    assert.deepEqual(unclaimed, [],
      'no bundle_publisher_unclaimed entry should appear when namespace was supplied');
  });
});

// ---------- P1-4 ----------

describe('audit CC P1-4 — --operator threads into tracking.generator and publisher.contact_details', () => {
  it('tracking.generator.engine names exceptd + a real version', () => {
    const { close: c } = closeKernel({ operator: 'alice' });
    const tracking = c.evidence_package.bundles_by_format['csaf-2.0'].document.tracking;
    assert.ok(tracking.generator, 'tracking.generator must be present');
    assert.ok(tracking.generator.engine, 'tracking.generator.engine must be present');
    assert.equal(tracking.generator.engine.name, 'exceptd');
    assert.equal(typeof tracking.generator.engine.version, 'string');
    assert.ok(tracking.generator.engine.version.length > 0,
      'tracking.generator.engine.version must be populated, not empty string');
    assert.match(tracking.generator.engine.version, /^\d+\.\d+\.\d+/,
      'tracking.generator.engine.version must be SemVer-shaped');
    assert.equal(typeof tracking.generator.date, 'string');
  });

  it('publisher.contact_details carries the operator value', () => {
    const { close: c } = closeKernel({ operator: 'alice' });
    const publisher = c.evidence_package.bundles_by_format['csaf-2.0'].document.publisher;
    assert.equal(publisher.contact_details, 'alice');
  });

  it('publisher.contact_details is omitted (not null) when --operator is absent', () => {
    const { close: c } = closeKernel();
    const publisher = c.evidence_package.bundles_by_format['csaf-2.0'].document.publisher;
    assert.equal(publisher.contact_details, undefined,
      'contact_details must be omitted entirely rather than carry a misleading null');
  });
});

// ---------- P2-1 ----------

describe('audit CC P2-1 — bundles_by_format is always populated', () => {
  it('single-format emit produces { [primaryFormat]: bundle }', () => {
    const runner = loadRunner();
    const det = runner.detect('kernel', 'all-catalogued-kernel-cves', {
      signal_overrides: { 'kver-in-affected-range': 'hit' }
    });
    const an = runner.analyze('kernel', 'all-catalogued-kernel-cves', det, {
      patch_available: false, blast_radius_score: 3
    });
    const v = runner.validate('kernel', 'all-catalogued-kernel-cves', an, {});
    const c = runner.close('kernel', 'all-catalogued-kernel-cves', an, v,
      {} /* no _bundle_formats */,
      { session_id: 'auditccp21test' }
    );
    const byFormat = c.evidence_package.bundles_by_format;
    assert.notEqual(byFormat, null, 'bundles_by_format must never be null (pre-fix was null for single-format)');
    assert.equal(typeof byFormat, 'object');
    assert.ok(byFormat['csaf-2.0'], 'bundles_by_format must carry the primary format key');
    assert.equal(byFormat['csaf-2.0'], c.evidence_package.bundle_body,
      'bundles_by_format[primary] is the same object as bundle_body');
  });
});

// ---------- P2-2 ----------

describe('audit CC P2-2 — cvss_v3 block carries vectorString or is dropped entirely', () => {
  it('matched CVE with cvss_score + cvss_vector emits full cvss_v3 block', () => {
    const { close: c, analyze: an } = closeKernel();
    const csaf = c.evidence_package.bundles_by_format['csaf-2.0'];
    // Find a CVE that actually has a cvss_vector in the catalog.
    const withVector = an.matched_cves.find(x => typeof x.cvss_vector === 'string' && x.cvss_vector.length > 0);
    assert.ok(withVector, 'fixture: at least one matched CVE must have a cvss_vector in the catalog');
    const vuln = csaf.vulnerabilities.find(v => v.cve === withVector.cve_id);
    assert.ok(vuln);
    assert.ok(Array.isArray(vuln.scores) && vuln.scores.length === 1);
    const score = vuln.scores[0];
    assert.ok(score.cvss_v3, 'cvss_v3 block must be present when score + vector are populated');
    assert.equal(typeof score.cvss_v3.vectorString, 'string');
    assert.match(score.cvss_v3.vectorString, /^CVSS:\d+\.\d+\//,
      'cvss_v3.vectorString must match the CSAF §3.2.1.5 prefix');
    assert.equal(score.cvss_v3.baseScore, withVector.cvss_score);
    assert.equal(typeof score.cvss_v3.version, 'string');
    assert.match(score.cvss_v3.baseSeverity, /^(NONE|LOW|MEDIUM|HIGH|CRITICAL)$/);
  });

  it('vulns with no cvss data emit scores: [] rather than a truncated cvss_v3 block', () => {
    const runner = loadRunner();
    const det = runner.detect('kernel', 'all-catalogued-kernel-cves', {
      signal_overrides: { 'kver-in-affected-range': 'hit' }
    });
    const an = runner.analyze('kernel', 'all-catalogued-kernel-cves', det, {
      patch_available: false, blast_radius_score: 3
    });
    // Strip cvss data from one matched entry to exercise the empty-score path.
    if (an.matched_cves.length > 0) {
      an.matched_cves[0].cvss_score = null;
      an.matched_cves[0].cvss_vector = null;
    }
    const v = runner.validate('kernel', 'all-catalogued-kernel-cves', an, {});
    const c = runner.close('kernel', 'all-catalogued-kernel-cves', an, v, {
      _bundle_formats: ['csaf-2.0']
    }, { session_id: 'auditccp22test' });
    const csaf = c.evidence_package.bundles_by_format['csaf-2.0'];
    const target = csaf.vulnerabilities.find(x => x.cve === an.matched_cves[0].cve_id);
    assert.ok(target);
    assert.deepEqual(target.scores, [],
      'no-CVSS-data vuln must emit scores: [] — truncated cvss_v3 blocks are rejected by strict validators');
  });
});

// ---------- P2-6 ----------

describe('audit CC P2-6 — SARIF ruleId carries playbook prefix', () => {
  it('every result.ruleId starts with `<playbook-slug>/`', () => {
    const { close: c } = closeKernel();
    const sarif = c.evidence_package.bundles_by_format['sarif-2.1.0'];
    const results = sarif.runs[0].results;
    assert.ok(results.length > 0, 'fixture: SARIF must have results');
    for (const r of results) {
      assert.match(String(r.ruleId), /^kernel\//,
        `result.ruleId must carry playbook prefix; got ${r.ruleId}`);
    }
  });

  it('every rule.id has a matching result.ruleId (SARIF §3.27.3 closure)', () => {
    const { close: c } = closeKernel();
    const sarif = c.evidence_package.bundles_by_format['sarif-2.1.0'];
    const ruleIds = new Set((sarif.runs[0].tool.driver.rules || []).map(r => r.id));
    const resultIds = (sarif.runs[0].results || []).map(r => r.ruleId);
    const missing = resultIds.filter(id => !ruleIds.has(id));
    assert.deepEqual(missing, [],
      `every result.ruleId must have a corresponding rule.id in tool.driver.rules; missing: ${JSON.stringify(missing)}`);
  });

  it('no cross-playbook collision when two playbook bundles are merged in one sarif-log', () => {
    // Run kernel and mcp end-to-end and check that the union of ruleIds has
    // no duplicates — pre-fix `framework-gap-0` collided across every
    // playbook that produced framework gaps.
    const runner = loadRunner();
    const kernelDet = runner.detect('kernel', 'all-catalogued-kernel-cves', {
      signal_overrides: { 'kver-in-affected-range': 'hit' }
    });
    const kernelAn = runner.analyze('kernel', 'all-catalogued-kernel-cves', kernelDet, {
      patch_available: false, blast_radius_score: 3
    });
    const kernelV = runner.validate('kernel', 'all-catalogued-kernel-cves', kernelAn, {});
    const kernelClose = runner.close('kernel', 'all-catalogued-kernel-cves', kernelAn, kernelV, {
      _bundle_formats: ['sarif-2.1.0']
    }, { session_id: 'auditccp26kerneltest' });

    // Use the framework playbook — same shape, different slug, both produce
    // framework_gap_mapping entries.
    const fwDet = runner.detect('framework', 'baseline-framework-gap-inventory',
      { signal_overrides: {} });
    const fwAn = runner.analyze('framework', 'baseline-framework-gap-inventory', fwDet, {});
    const fwV = runner.validate('framework', 'baseline-framework-gap-inventory', fwAn, {});
    const fwClose = runner.close('framework', 'baseline-framework-gap-inventory', fwAn, fwV, {
      _bundle_formats: ['sarif-2.1.0']
    }, { session_id: 'auditccp26fwtest' });

    const kernelIds = (kernelClose.evidence_package.bundles_by_format['sarif-2.1.0'].runs[0].results || [])
      .map(r => r.ruleId);
    const fwIds = (fwClose.evidence_package.bundles_by_format['sarif-2.1.0'].runs[0].results || [])
      .map(r => r.ruleId);
    const inter = kernelIds.filter(id => fwIds.includes(id));
    assert.deepEqual(inter, [],
      `kernel and framework SARIF ruleIds must not collide; pre-fix bare ids like framework-gap-0 collided. Overlap: ${JSON.stringify(inter)}`);
  });
});

// ---------- CLI end-to-end coverage for the two new flags ----------

function tryJson(s) { try { return JSON.parse(s); } catch { return null; } }

function cli(argv, opts = {}) {
  const env = { ...process.env };
  delete env.EXCEPTD_PLAYBOOK_DIR;
  return spawnSync(process.execPath, [CLI_PATH, ...argv], {
    input: opts.input,
    encoding: 'utf8',
    env,
    cwd: path.resolve(__dirname, '..'),
  });
}

describe('audit CC — CLI flag plumbing', () => {
  // library-author has no platform precondition; its `publish-workflow-uses-
  // static-token` indicator is the same fixture #93 uses for SARIF CLI
  // coverage.
  const submissionFor = () => JSON.stringify({
    observations: { w: { captured: true, indicator: 'publish-workflow-uses-static-token', result: 'hit' } },
    verdict: {}
  });

  it('--publisher-namespace lands in CSAF document.publisher.namespace', () => {
    const r = cli([
      'run', 'library-author', '--evidence', '-',
      '--format', 'csaf-2.0',
      '--publisher-namespace', 'https://operator.example',
      '--json',
    ], { input: submissionFor() });
    const data = tryJson(r.stdout);
    assert.ok(data, `csaf via CLI must emit JSON; stderr: ${r.stderr}`);
    assert.equal(data.document?.publisher?.namespace, 'https://operator.example');
  });

  it('--operator lands in tracking.generator.engine AND publisher.contact_details', () => {
    const r = cli([
      'run', 'library-author', '--evidence', '-',
      '--format', 'csaf-2.0',
      '--operator', 'alice',
      '--ack',
      '--json',
    ], { input: submissionFor() });
    const data = tryJson(r.stdout);
    assert.ok(data, `csaf via CLI must emit JSON; stderr: ${r.stderr}`);
    assert.equal(data.document?.publisher?.contact_details, 'alice');
    assert.equal(data.document?.tracking?.generator?.engine?.name, 'exceptd');
    assert.match(String(data.document?.tracking?.generator?.engine?.version || ''), /^\d+\.\d+\.\d+/);
  });

  it('--csaf-status final promotes tracking.status to final', () => {
    const r = cli([
      'run', 'library-author', '--evidence', '-',
      '--format', 'csaf-2.0',
      '--csaf-status', 'final',
      '--json',
    ], { input: submissionFor() });
    const data = tryJson(r.stdout);
    assert.ok(data, `csaf via CLI must emit JSON; stderr: ${r.stderr}`);
    assert.equal(data.document?.tracking?.status, 'final');
  });

  it('default --csaf-status (omitted) yields interim', () => {
    const r = cli([
      'run', 'library-author', '--evidence', '-',
      '--format', 'csaf-2.0',
      '--json',
    ], { input: submissionFor() });
    const data = tryJson(r.stdout);
    assert.ok(data, `csaf via CLI must emit JSON; stderr: ${r.stderr}`);
    assert.equal(data.document?.tracking?.status, 'interim');
  });

  it('invalid --csaf-status value is rejected at input', () => {
    const sub = JSON.stringify({ observations: {}, verdict: {} });
    const r = cli([
      'run', 'library-author', '--evidence', '-',
      '--csaf-status', 'finel',
      '--json',
    ], { input: sub });
    assert.notEqual(r.status, 0,
      '--csaf-status finel must exit non-zero (rejected at CLI input)');
    const err = tryJson(r.stderr) || tryJson(r.stdout);
    assert.ok(err && err.ok === false,
      `must emit an ok:false body; got stderr=${r.stderr.slice(0, 200)}`);
    assert.match(String(err.error || ''), /csaf-status/i);
  });

  it('invalid --publisher-namespace (non-URL) is rejected', () => {
    const sub = JSON.stringify({ observations: {}, verdict: {} });
    const r = cli([
      'run', 'library-author', '--evidence', '-',
      '--publisher-namespace', 'not-a-url',
      '--json',
    ], { input: sub });
    assert.notEqual(r.status, 0);
    const err = tryJson(r.stderr) || tryJson(r.stdout);
    assert.ok(err && err.ok === false);
    assert.match(String(err.error || ''), /publisher-namespace/i);
  });
});
