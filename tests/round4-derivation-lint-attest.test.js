'use strict';

/**
 * Round-4 correctness regressions:
 *   - diffSignalOverrides must deep-compare (signal_overrides hold object
 *     `*__fp_checks` values; a reference-strict !== reports false drift)
 *   - the skill-section linter must not count headings inside fenced code
 *     blocks, and must not let a deeper heading (H3+) satisfy a top-level
 *     required-section (H2) requirement
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');

const cli = require(path.resolve(__dirname, '..', 'bin', 'exceptd.js'));
const lint = require(path.resolve(__dirname, '..', 'lib', 'lint-skills.js'));

const diffSignalOverrides = cli._diffSignalOverrides;
const findMissingSections = lint.findMissingSections;

test('diffSignalOverrides reports object-valued overrides with identical content as unchanged', () => {
  // Two distinct object references with byte-identical content (the
  // `<id>__fp_checks` shape) must NOT be flagged as changed.
  const a = { 'x__fp_checks': { vendor_advisory: true, poc_seen: false } };
  const b = { 'x__fp_checks': { poc_seen: false, vendor_advisory: true } }; // key order swapped
  const r = diffSignalOverrides(a, b);
  assert.equal(r.changed.length, 0, 'identical FP-check content must not be "changed"');
  assert.equal(r.unchanged_count, 1);
});

test('diffSignalOverrides still detects a real content change in an object override', () => {
  const a = { 'x__fp_checks': { vendor_advisory: true } };
  const b = { 'x__fp_checks': { vendor_advisory: false } };
  const r = diffSignalOverrides(a, b);
  assert.equal(r.changed.length, 1);
  assert.equal(r.changed[0].id, 'x__fp_checks');
});

test('diffSignalOverrides detects added / removed overrides', () => {
  const r = diffSignalOverrides({ a: 1 }, { a: 1, b: 2 });
  assert.equal(r.changed.length, 1, 'b is present on only one side -> changed');
});

const REQUIRED = ['Threat Context', 'Compliance Theater Check'];

test('a required section that exists ONLY inside a fenced code block is reported missing', () => {
  const body = [
    '# Skill',
    '## Threat Context',
    'Real threat context body with more than the minimum number of words here to satisfy the body length check easily.',
    '',
    '```markdown',
    '## Compliance Theater Check',
    'This heading is inside a fence — it is documentation, not a real section, so it must not count.',
    '```',
  ].join('\n');
  const { missing } = findMissingSections(body, REQUIRED);
  assert.ok(missing.includes('Compliance Theater Check'),
    'fenced heading must not satisfy the requirement');
  assert.ok(!missing.includes('Threat Context'), 'the real H2 section still counts');
});

test('a deeper H3 heading does not satisfy a top-level H2 required section', () => {
  const body = [
    '# Skill',
    '## Threat Context',
    'Real threat context body with plenty of words to clear the minimum body length requirement without trouble at all.',
    '',
    '## Output Format',
    '### Compliance Theater Check Result',
    'An H3 result sub-heading must not satisfy the standalone Compliance Theater Check section requirement.',
  ].join('\n');
  const { missing } = findMissingSections(body, REQUIRED);
  assert.ok(missing.includes('Compliance Theater Check'),
    'an H3 must not satisfy the H2 requirement');
});

test('a genuine H2 section (with a trailing qualifier) still satisfies the requirement', () => {
  const body = [
    '# Skill',
    '## Threat Context (mid-2026)',
    'Body with enough words to clear the minimum section body length requirement comfortably for this test case here.',
    '## Compliance Theater Check',
    'Body with enough words to clear the minimum section body length requirement comfortably for this test case here.',
  ].join('\n');
  const { missing } = findMissingSections(body, REQUIRED);
  assert.deepEqual(missing, [], 'real H2 sections (incl. a qualifier) must pass');
});
