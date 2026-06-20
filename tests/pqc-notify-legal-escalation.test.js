'use strict';

/**
 * post-quantum-migration: the notify_legal escalation gated on an EU
 * jurisdiction obligation must actually fire.
 *
 * The condition read `jurisdiction_obligations contains NIS2-Art21-2h` — an
 * unquoted literal that no obligation field equals (the regulation field is
 * "NIS2 Art.21(2)(h)"). The clause parsed cleanly and returned a legitimate
 * false with no diagnostic, so the escalation was permanently dead. It now
 * gates on `contains 'EU'`, the jurisdiction dimension the other playbooks use.
 *
 * Asserts the exact firing condition (signal fired AND EU obligation present)
 * and that it stays quiet without the signal — a coincidence-passing
 * truthiness check would miss the dead-literal regression this guards.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const runner = require('../lib/playbook-runner.js');

const PB = 'post-quantum-migration';
const DIR = 'full-programme-audit';

test('PQC notify_legal escalation fires when the asset-register gap is found under an EU obligation', () => {
  const det = runner.detect(PB, DIR, {});
  const an = runner.analyze(PB, DIR, det, { 'no-cryptographic-asset-register': 'fired' });
  const esc = (an.escalations || []).find((e) => e.action === 'notify_legal');
  assert.ok(esc, 'the notify_legal escalation must fire when no-cryptographic-asset-register is fired and the govern phase carries an EU obligation');
  assert.match(esc.condition, /jurisdiction_obligations contains 'EU'/,
    'the escalation must gate on the EU jurisdiction obligation, not an unmatchable literal');
});

test('PQC notify_legal escalation stays quiet when the asset-register signal is not fired', () => {
  const det = runner.detect(PB, DIR, {});
  const an = runner.analyze(PB, DIR, det, {});
  const esc = (an.escalations || []).find((e) => e.action === 'notify_legal');
  assert.ok(!esc, 'notify_legal must not fire without the no-cryptographic-asset-register signal');
});
