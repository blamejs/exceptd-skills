"use strict";
/**
 * tests/playbook-log-injection-telemetry.test.js
 *
 * Structure + cross-ref coverage for the log-injection-telemetry playbook
 * (telemetry-pipeline integrity) and its companion skill, plus the catalog
 * weakness it adds (CWE-117). References every look-artifact id and
 * detect-indicator id (diff-coverage), and asserts the seven-phase shape, the
 * TTP/CWE/framework mapping, and per-indicator FP checks.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');
const PB = JSON.parse(fs.readFileSync(path.join(ROOT, 'data/playbooks/log-injection-telemetry.json'), 'utf8'));
const MANIFEST = JSON.parse(fs.readFileSync(path.join(ROOT, 'manifest.json'), 'utf8'));
const CWE = JSON.parse(fs.readFileSync(path.join(ROOT, 'data/cwe-catalog.json'), 'utf8'));

test('log-injection-telemetry has the seven-phase contract + cloud-misconfig class', () => {
  assert.equal(PB._meta.id, 'log-injection-telemetry');
  assert.equal(PB._meta.scope, 'service');
  assert.equal(PB.domain.attack_class, 'cloud-misconfig');
  for (const ph of ['govern', 'direct', 'look', 'detect', 'analyze', 'validate', 'close']) assert.ok(PB.phases[ph], `phase ${ph}`);
});

test('CWE-117 added to the catalog and referenced by the playbook', () => {
  assert.ok(CWE['CWE-117'], 'CWE-117 present');
  assert.match(CWE['CWE-117'].name, /Logs/i);
  assert.ok(PB.domain.cwe_refs.includes('CWE-117'), 'domain cwe_refs includes CWE-117');
});

test('domain maps to real ATT&CK + present CWEs + global-first frameworks (UK+AU)', () => {
  for (const t of ['T1565.001', 'T1530', 'T1213']) assert.ok(PB.domain.attack_refs.includes(t), `attack_ref ${t}`);
  for (const w of ['CWE-117', 'CWE-532', 'CWE-918', 'CWE-200']) assert.ok(PB.domain.cwe_refs.includes(w), `cwe ${w}`);
  for (const f of ['uk-caf', 'au-ism']) assert.ok(PB.domain.frameworks_in_scope.includes(f), `framework ${f} (Hard Rule #5)`);
});

test('every look artifact has an air_gap_alternative + the telemetry surface is covered', () => {
  const ids = PB.phases.look.artifacts.map((a) => a.id);
  for (const need of ['log-write-path', 'telemetry-exporter-config', 'metrics-and-debug-endpoints', 'secret-and-pii-redaction']) {
    assert.ok(ids.includes(need), `artifact ${need} present`);
  }
  for (const a of PB.phases.look.artifacts) assert.ok(typeof a.air_gap_alternative === 'string' && a.air_gap_alternative.length > 0, `artifact ${a.id} air_gap_alternative`);
});

test('all seven telemetry-integrity indicators present, each with FP checks + a domain TTP', () => {
  const ids = PB.phases.detect.indicators.map((i) => i.id);
  for (const need of [
    'crlf-log-injection-unsanitized',
    'metrics-endpoint-unauthenticated',
    'secrets-or-pii-logged-without-redaction',
    'telemetry-egress-endpoints-not-inventoried',
    'telemetry-sink-credentials-embedded',
    'telemetry-egress-tls-relaxed',
    'webhook-log-sink-ssrf-unguarded',
  ]) {
    assert.ok(ids.includes(need), `indicator ${need} present`);
  }
  for (const ind of PB.phases.detect.indicators) {
    assert.ok(Array.isArray(ind.false_positive_checks_required) && ind.false_positive_checks_required.length >= 1, `${ind.id} FP checks`);
    assert.ok(PB.domain.attack_refs.includes(ind.attack_ref), `${ind.id} attack_ref in domain`);
  }
});

test('remediation for_signals reference real indicators; companion skill registered + signed', () => {
  const ids = new Set(PB.phases.detect.indicators.map((i) => i.id));
  for (const rp of PB.phases.validate.remediation_paths) for (const s of (rp.for_signals || [])) assert.ok(ids.has(s), `remediation ${rp.id} for_signals ${s}`);
  const skill = MANIFEST.skills.find((s) => s.name === 'log-injection-telemetry');
  assert.ok(skill && skill.signature, 'log-injection-telemetry skill registered + signed');
  assert.ok(fs.existsSync(path.join(ROOT, skill.path)), 'skill.md exists');
});
