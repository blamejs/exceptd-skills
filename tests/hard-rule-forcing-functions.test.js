'use strict';

/**
 * tests/hard-rule-forcing-functions.test.js
 *
 * Cycle 16 audit fix (v0.12.36): closes 3 gaps in AGENTS.md Hard Rule
 * forcing-function coverage. Without these tests the rules were
 * policy-only — a future PR could violate them and the CI gate would
 * stay green.
 *
 *   Rule #3 (no CVSS-only risk scoring): every non-draft CVE in
 *     data/cve-catalog.json must declare rwep_score + rwep_factors.
 *
 *   Rule #5 (global-first, not US-centric): the framework-control-gaps
 *     catalog must carry entries for EU + UK + AU + INTL alongside US.
 *
 *   Rule #8 (Pinned ATLAS version): manifest.json's atlas_version field
 *     must equal data/atlas-ttps.json._meta.atlas_version exactly, and
 *     same for attack_version. Pre-cycle-9 these drifted silently.
 *
 *   Cross-format CVE consistency: CSAF + OpenVEX + SARIF emitters must
 *     agree on the catalogued-CVE set per playbook run.
 *
 * Per CLAUDE.md anti-coincidence rule, every assertion checks an EXACT
 * value (deep-equality or specific count).
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');
const manifest = JSON.parse(fs.readFileSync(path.join(ROOT, 'manifest.json'), 'utf8'));
const cve = JSON.parse(fs.readFileSync(path.join(ROOT, 'data', 'cve-catalog.json'), 'utf8'));
const gaps = JSON.parse(fs.readFileSync(path.join(ROOT, 'data', 'framework-control-gaps.json'), 'utf8'));
const atlas = JSON.parse(fs.readFileSync(path.join(ROOT, 'data', 'atlas-ttps.json'), 'utf8'));
const attack = JSON.parse(fs.readFileSync(path.join(ROOT, 'data', 'attack-techniques.json'), 'utf8'));

test('Hard Rule #3 — every non-draft CVE entry declares rwep_score + rwep_factors (no CVSS-only)', () => {
  const violations = [];
  for (const [id, entry] of Object.entries(cve)) {
    if (id === '_meta') continue;
    if (!entry || typeof entry !== 'object') continue;
    if (entry._draft === true) continue;
    if (typeof entry.rwep_score !== 'number') {
      violations.push({ id, why: 'rwep_score missing or non-numeric' });
      continue;
    }
    if (!entry.rwep_factors || typeof entry.rwep_factors !== 'object') {
      violations.push({ id, why: 'rwep_factors missing or non-object' });
      continue;
    }
  }
  assert.deepEqual(violations, [],
    `Rule #3 violations: ${violations.length} non-draft CVE entries need RWEP. ${JSON.stringify(violations.slice(0, 10), null, 2)}`);
});

function frameworkRegion(frameworkText) {
  if (!frameworkText) return 'OTHER';
  if (/NIST|FedRAMP|CMMC|HIPAA|HITRUST|PCI|SOC|CIS Controls|OFAC|SEC|NYDFS|CIRCIA/i.test(frameworkText)) return 'US';
  if (/NIS2|DORA|GDPR|^EU |EU-|ENISA|CRA |AI Act|EU 2014\/833/i.test(frameworkText)) return 'EU';
  if (/^UK|CAF|Ofcom|NCSC|OFSI|UK-GDPR/i.test(frameworkText)) return 'UK';
  if (/^AU|ACSC|ISM|Essential 8|APRA|eSafety|AU NDB/i.test(frameworkText)) return 'AU';
  if (/^ISO|IEC \d|3GPP|GSMA|ITU|FCC|TSA |OWASP|SLSA|CycloneDX|SPDX/i.test(frameworkText)) return 'INTL';
  return 'OTHER';
}

test('Hard Rule #5 — framework-control-gaps covers EU + UK + AU + INTL alongside US (global-first)', () => {
  const buckets = {};
  for (const [id, entry] of Object.entries(gaps)) {
    if (id === '_meta') continue;
    if (!entry || typeof entry !== 'object') continue;
    const region = frameworkRegion(entry.framework);
    buckets[region] = (buckets[region] || 0) + 1;
  }
  const required = ['US', 'EU', 'UK', 'AU', 'INTL'];
  for (const r of required) {
    assert.ok((buckets[r] || 0) > 0,
      `Rule #5 violation: region ${r} has zero framework-gap entries. Catalog buckets: ${JSON.stringify(buckets)}`);
  }
  const total = Object.values(buckets).reduce((a, b) => a + b, 0);
  for (const [region, count] of Object.entries(buckets)) {
    if (region === 'OTHER') continue;
    const pct = count / total;
    assert.ok(pct < 0.70,
      `Rule #5 skew warning: region ${region} carries ${count}/${total} = ${(pct * 100).toFixed(1)}% of catalog. Threshold 70%.`);
  }
});

test('Hard Rule #8 — manifest.atlas_version matches data/atlas-ttps.json._meta.atlas_version exactly', () => {
  const manifestPin = manifest.atlas_version;
  const catalogPin = atlas._meta.atlas_version;
  assert.equal(typeof manifestPin, 'string', 'manifest.atlas_version must be set');
  assert.equal(typeof catalogPin, 'string', 'atlas-ttps._meta.atlas_version must be set');
  assert.equal(manifestPin, catalogPin,
    `Rule #8 violation: manifest pins ATLAS v${manifestPin} but catalog meta is v${catalogPin}. Pre-cycle-9 silent-drift class re-introduced.`);
});

test('Hard Rule #8 — manifest.attack_version matches data/attack-techniques.json._meta.attack_version exactly', () => {
  const manifestPin = manifest.attack_version;
  const catalogPin = attack._meta.attack_version;
  assert.equal(typeof manifestPin, 'string', 'manifest.attack_version must be set');
  assert.equal(typeof catalogPin, 'string', 'attack-techniques._meta.attack_version must be set');
  const manifestCanonical = manifestPin.includes('.') ? manifestPin : `${manifestPin}.0`;
  const catalogCanonical = catalogPin.includes('.') ? catalogPin : `${catalogPin}.0`;
  assert.equal(manifestCanonical, catalogCanonical,
    `Rule #8 violation: manifest pins ATT&CK v${manifestPin} but catalog meta is v${catalogPin}. Pre-cycle-9 silent-drift class re-introduced.`);
});

test('Cross-format CVE consistency — CSAF + OpenVEX + SARIF agree on the catalogued-CVE set per playbook run', () => {
  const { spawnSync } = require('node:child_process');
  const os = require('node:os');
  const evidence = JSON.stringify({
    precondition_checks: { 'linux-platform': true, 'uname-available': true },
    artifacts: { 'kernel-release': '5.15.0-69-generic' },
    signal_overrides: { 'kver-in-affected-range': 'hit' },
  });
  const evFile = path.join(os.tmpdir(), `cycle16-${Date.now()}-${Math.random().toString(16).slice(2, 8)}.json`);
  fs.writeFileSync(evFile, evidence);
  try {
    const CLI = path.join(ROOT, 'bin', 'exceptd.js');
    function runFmt(fmt) {
      const r = spawnSync(process.execPath, [CLI, 'run', 'kernel', '--evidence', evFile, '--format', fmt], {
        encoding: 'utf8', cwd: ROOT,
        env: { ...process.env, EXCEPTD_DEPRECATION_SHOWN: '1' },
      });
      assert.equal(r.status, 0, `${fmt} run must exit 0; got ${r.status}, stderr: ${r.stderr.slice(0, 200)}`);
      return JSON.parse(r.stdout);
    }
    const csaf = runFmt('csaf');
    const openvex = runFmt('openvex');
    const sarif = runFmt('sarif');

    const csafCves = new Set((csaf.vulnerabilities || []).map(v => v.cve).filter(Boolean));
    const openvexCves = new Set(
      (openvex.statements || [])
        .map(s => s?.vulnerability?.['@id'])
        .filter((id) => typeof id === 'string' && id.startsWith('urn:cve:'))
        .map((id) => id.replace(/^urn:cve:/, '').toUpperCase()),
    );
    const sarifCves = new Set(
      (sarif.runs || []).flatMap(r => (r.results || []).map(rr => rr.ruleId).filter(Boolean))
        .filter((rid) => /CVE-/.test(rid))
        .map((rid) => rid.replace(/^kernel\//, '')),
    );

    assert.deepEqual([...csafCves].sort(), [...openvexCves].sort(),
      `CSAF vs OpenVEX CVE set divergence. CSAF: ${[...csafCves].sort().join(',')} | OpenVEX: ${[...openvexCves].sort().join(',')}`);
    assert.deepEqual([...csafCves].sort(), [...sarifCves].sort(),
      `CSAF vs SARIF CVE set divergence. CSAF: ${[...csafCves].sort().join(',')} | SARIF: ${[...sarifCves].sort().join(',')}`);
  } finally {
    try { fs.unlinkSync(evFile); } catch {}
  }
});
