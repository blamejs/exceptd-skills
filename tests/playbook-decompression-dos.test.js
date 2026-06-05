"use strict";
/**
 * tests/playbook-decompression-dos.test.js
 *
 * Structure + cross-ref coverage for the decompression-dos playbook
 * (decompression bomb / parser-DoS / ReDoS) and its companion skill, plus the
 * two catalog weaknesses it adds (CWE-409, CWE-1333). References every
 * look-artifact id and detect-indicator id (diff-coverage), and asserts the
 * seven-phase shape, the TTP/CWE/framework mapping, and per-indicator FP checks.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');
const PB = JSON.parse(fs.readFileSync(path.join(ROOT, 'data/playbooks/decompression-dos.json'), 'utf8'));
const MANIFEST = JSON.parse(fs.readFileSync(path.join(ROOT, 'manifest.json'), 'utf8'));
const CWE = JSON.parse(fs.readFileSync(path.join(ROOT, 'data/cwe-catalog.json'), 'utf8'));

test('decompression-dos has the seven-phase contract + webapp-exploit class (code scope)', () => {
  assert.equal(PB._meta.id, 'decompression-dos');
  assert.equal(PB._meta.scope, 'code');
  assert.equal(PB.domain.attack_class, 'webapp-exploit');
  for (const ph of ['govern', 'direct', 'look', 'detect', 'analyze', 'validate', 'close']) assert.ok(PB.phases[ph], `phase ${ph}`);
});

test('CWE-409 + CWE-1333 added to the catalog and referenced by the playbook', () => {
  assert.ok(CWE['CWE-409'], 'CWE-409 (data amplification) present');
  assert.match(CWE['CWE-409'].name, /amplification|compressed/i);
  assert.ok(CWE['CWE-1333'], 'CWE-1333 (ReDoS) present');
  assert.match(CWE['CWE-1333'].name, /Regular Expression/i);
  for (const w of ['CWE-409', 'CWE-1333']) assert.ok(PB.domain.cwe_refs.includes(w), `domain cwe_refs includes ${w}`);
});

test('domain maps to real ATT&CK + present CWEs + global-first frameworks (UK+AU)', () => {
  for (const t of ['T1499', 'T1499.001', 'T1059']) assert.ok(PB.domain.attack_refs.includes(t), `attack_ref ${t}`);
  for (const w of ['CWE-409', 'CWE-1333', 'CWE-400', 'CWE-776', 'CWE-22', 'CWE-834', 'CWE-770']) assert.ok(PB.domain.cwe_refs.includes(w), `cwe ${w}`);
  for (const f of ['uk-caf', 'au-ism']) assert.ok(PB.domain.frameworks_in_scope.includes(f), `framework ${f} (Hard Rule #5)`);
});

test('every look artifact has an air_gap_alternative + the parser surface is covered', () => {
  const ids = PB.phases.look.artifacts.map((a) => a.id);
  for (const need of ['decompression-config', 'archive-extraction-paths', 'xml-and-parser-config', 'regex-and-recursion-config']) {
    assert.ok(ids.includes(need), `artifact ${need} present`);
  }
  for (const a of PB.phases.look.artifacts) assert.ok(typeof a.air_gap_alternative === 'string' && a.air_gap_alternative.length > 0, `artifact ${a.id} air_gap_alternative`);
});

test('all seven amplification indicators present, each with FP checks + a domain TTP', () => {
  const ids = PB.phases.detect.indicators.map((i) => i.id);
  for (const need of [
    'archive-decompression-unbounded',
    'zip-slip-path-traversal',
    'xml-entity-expansion-enabled',
    'redos-catastrophic-backtracking',
    'recursive-parse-no-depth-limit',
    'length-field-unbounded-allocation',
    'nested-archive-bomb-uncapped',
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
  const skill = MANIFEST.skills.find((s) => s.name === 'decompression-dos');
  assert.ok(skill && skill.signature, 'decompression-dos skill registered + signed');
  assert.ok(fs.existsSync(path.join(ROOT, skill.path)), 'skill.md exists');
});
