'use strict';

/**
 * tests/j-blast-radius-doc-weight.test.js
 *
 * The blast_radius RWEP factor weight is documented on three operator-facing
 * surfaces (README, ARCHITECTURE, the exploit-scoring skill). These pin each
 * documented ceiling to the live RWEP_WEIGHTS.blast_radius so the docs cannot
 * drift to half the real weight again. The scoring engine is the source of
 * truth; the docs must follow it.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');
const { RWEP_WEIGHTS } = require('../lib/scoring.js');
const WEIGHT = RWEP_WEIGHTS.blast_radius;

test('the live blast_radius weight is a positive integer', () => {
  assert.ok(Number.isInteger(WEIGHT) && WEIGHT > 0);
});

test('README documents the blast radius weight as the live RWEP weight', () => {
  const readme = fs.readFileSync(path.join(ROOT, 'README.md'), 'utf8');
  // The factor list renders the weight as a 0.NN fraction (weight / 100).
  const fraction = '0.' + String(WEIGHT).padStart(2, '0');
  assert.match(
    readme,
    new RegExp('blast radius \\(' + fraction.replace('.', '\\.') + '\\)'),
    `README must list "blast radius (${fraction})"`
  );
});

test('ARCHITECTURE documents the blast_radius weight and scale as the live RWEP weight', () => {
  const arch = fs.readFileSync(path.join(ROOT, 'ARCHITECTURE.md'), 'utf8');
  const m = arch.match(/blast_radius\s+\+(\d+)\s+\(0[–-](\d+) scaled\)/);
  assert.ok(m, 'ARCHITECTURE.md is missing the blast_radius weight line');
  assert.equal(Number(m[1]), WEIGHT);
  assert.equal(Number(m[2]), WEIGHT);
});

test('exploit-scoring skill formula and scale use the live blast_radius ceiling', () => {
  const skill = fs.readFileSync(
    path.join(ROOT, 'skills', 'exploit-scoring', 'skill.md'),
    'utf8'
  );
  // Formula term: (blast_radius × <weight>)
  assert.match(
    skill,
    new RegExp('blast_radius\\s+×\\s+' + WEIGHT + '\\b'),
    `skill formula must read "(blast_radius × ${WEIGHT})"`
  );
  // Scale wording: "scaled to 0–<weight>"
  assert.match(
    skill,
    new RegExp('scaled to 0[–-]' + WEIGHT + '\\b'),
    `skill scale must read "scaled to 0–${WEIGHT}"`
  );
  // Output template row ceiling: [0-<weight>]
  assert.match(
    skill,
    new RegExp('\\[0-' + WEIGHT + '\\]'),
    `skill output row must read "[0-${WEIGHT}]"`
  );
  // No stale half-weight ceiling should remain in the formula/scale wording.
  const halfFraction = '0–15';
  assert.ok(
    !new RegExp('blast_radius\\s+×\\s+15\\b').test(skill),
    'skill formula still multiplies blast_radius by the stale half-weight 15'
  );
  assert.ok(
    !skill.includes('scaled to ' + halfFraction),
    'skill scale still references the stale half-weight range 0–15'
  );
});
