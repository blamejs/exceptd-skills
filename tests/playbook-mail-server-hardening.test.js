"use strict";
/**
 * tests/playbook-mail-server-hardening.test.js
 *
 * Structure + cross-ref coverage for the mail-server-hardening playbook
 * (inbound mail-protocol hardening) and its companion skill. References every
 * look-artifact id and detect-indicator id (diff-coverage), and asserts the
 * seven-phase shape, the TTP/CWE mapping, and the per-indicator FP checks.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');
const PB = JSON.parse(fs.readFileSync(path.join(ROOT, 'data/playbooks/mail-server-hardening.json'), 'utf8'));
const MANIFEST = JSON.parse(fs.readFileSync(path.join(ROOT, 'manifest.json'), 'utf8'));

test('mail-server-hardening has the seven-phase contract + email-phishing class', () => {
  assert.equal(PB._meta.id, 'mail-server-hardening');
  assert.equal(PB._meta.scope, 'service');
  assert.equal(PB.domain.attack_class, 'email-phishing');
  for (const ph of ['govern', 'direct', 'look', 'detect', 'analyze', 'validate', 'close']) {
    assert.ok(PB.phases[ph], `phase ${ph} present`);
  }
});

test('domain maps to real ATT&CK + present CWEs + the smuggling/STARTTLS CVE families', () => {
  for (const t of ['T1190', 'T1071.003', 'T1557', 'T1040', 'T1110']) assert.ok(PB.domain.attack_refs.includes(t), `attack_ref ${t}`);
  for (const w of ['CWE-77', 'CWE-93', 'CWE-22', 'CWE-611', 'CWE-863', 'CWE-400']) assert.ok(PB.domain.cwe_refs.includes(w), `cwe ${w}`);
  for (const c of ['CVE-2023-51764', 'CVE-2021-38371']) assert.ok(PB.domain.cve_refs.includes(c), `cve ${c}`);
});

test('every look artifact has an air_gap_alternative + the inbound surface is covered', () => {
  const ids = PB.phases.look.artifacts.map((a) => a.id);
  for (const need of [
    'mail-listener-inventory',
    'smtp-command-guard',
    'imap-pop3-managesieve-guards',
    'starttls-and-auth-config',
    'sieve-and-dav-config',
    'mail-abuse-controls',
  ]) {
    assert.ok(ids.includes(need), `artifact ${need} present`);
  }
  for (const a of PB.phases.look.artifacts) {
    assert.ok(typeof a.air_gap_alternative === 'string' && a.air_gap_alternative.length > 0, `artifact ${a.id} air_gap_alternative`);
  }
});

test('all ten protocol-hardening indicators present, each with FP checks + a domain TTP', () => {
  const ids = PB.phases.detect.indicators.map((i) => i.id);
  for (const need of [
    'smtp-smuggling-end-of-data-accepted',
    'starttls-receive-buffer-not-drained',
    'imap-command-literal-injection',
    'managesieve-putscript-unbounded',
    'sieve-redirect-uncapped',
    'inbound-open-relay',
    'pop3-command-injection',
    'mailbox-dav-path-traversal-xxe',
    'cleartext-auth-before-starttls',
    'mail-auth-no-rate-limit',
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
  for (const rp of PB.phases.validate.remediation_paths) {
    for (const s of (rp.for_signals || [])) assert.ok(ids.has(s), `remediation ${rp.id} for_signals ${s}`);
  }
  const skill = MANIFEST.skills.find((s) => s.name === 'mail-server-hardening');
  assert.ok(skill && skill.signature, 'mail-server-hardening skill registered + signed');
  assert.ok(fs.existsSync(path.join(ROOT, skill.path)), 'skill.md exists');
});
