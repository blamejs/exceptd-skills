'use strict';

/**
 * Coverage for the derived-index builders and the operator-facing report
 * surfaces they feed.
 *
 * - section-offsets: h3_count must skip "### " lines that live inside fenced
 *   code blocks, the same way the H2 section detector does. Output templates
 *   embedded in ```...``` are not real sub-sections.
 * - cwe-chains: the emitted chain must carry every dimension the module's
 *   own docstring promises, including dlp_refs.
 * - token-budget: the output shape must match the documented contract —
 *   corpus totals live under _meta, with no top-level by_recipe block.
 * - zero-day-response template: the blast-radius point range must match the
 *   live RWEP weight ceiling so a filled-in report does not undercount.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');
const { buildSectionOffsets } = require(path.join(ROOT, 'scripts', 'builders', 'section-offsets.js'));
const { buildCweChains } = require(path.join(ROOT, 'scripts', 'builders', 'cwe-chains.js'));
const { buildTokenBudget } = require(path.join(ROOT, 'scripts', 'builders', 'token-budget.js'));

test('section-offsets: h3_count ignores "### " headers inside fenced code blocks', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'exceptd-secoff-'));
  try {
    const rel = path.join('skills', 'fixture', 'skill.md');
    const abs = path.join(dir, rel);
    fs.mkdirSync(path.dirname(abs), { recursive: true });
    // One real H3, then a fenced output template carrying two fake H3 lines.
    const body = [
      '---',
      'name: fixture',
      '---',
      '',
      '## Output Format',
      '',
      '### Real Subsection',
      '',
      'Some prose.',
      '',
      '```markdown',
      '### Template Heading One',
      '### Template Heading Two',
      '```',
      '',
    ].join('\n');
    fs.writeFileSync(abs, body);

    const result = buildSectionOffsets({ root: dir, skills: [{ name: 'fixture', path: rel }] });
    const sections = result.skills.fixture.sections;
    const outputFmt = sections.find((s) => s.name === 'Output Format');
    assert.ok(outputFmt, 'Output Format section must be present');
    // Only the real "### Real Subsection" counts; the two fenced ones do not.
    assert.equal(outputFmt.h3_count, 1, 'fenced ### lines must not inflate h3_count');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('cwe-chains: emitted chain carries dlp_refs aggregated from referencing skills', () => {
  const skills = [
    {
      name: 'fixture-skill',
      cwe_refs: ['CWE-200'],
      atlas_refs: [],
      attack_refs: [],
      framework_gaps: [],
      d3fend_refs: [],
      rfc_refs: [],
      dlp_refs: ['DLP-EXFIL', 'DLP-EMAIL'],
    },
  ];
  const out = buildCweChains({
    skills,
    cweCatalog: { 'CWE-200': { name: 'Information Exposure', category: 'disclosure' } },
    atlasTtps: {},
    cveCatalog: {},
    frameworkGaps: {},
    d3fendCatalog: {},
    rfcCatalog: {},
  });
  const chain = out['CWE-200'].chain;
  // Presence paired with content shape: dlp_refs is an array carrying the
  // aggregated, sorted control ids — not merely defined.
  assert.ok(Array.isArray(chain.dlp_refs), 'chain.dlp_refs must be an array');
  assert.deepEqual(chain.dlp_refs, ['DLP-EMAIL', 'DLP-EXFIL'], 'dlp_refs aggregated + sorted');
});

test('token-budget: output matches the documented shape (totals under _meta, no by_recipe)', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'exceptd-tokbud-'));
  try {
    const rel = path.join('skills', 'fixture', 'skill.md');
    const abs = path.join(dir, rel);
    fs.mkdirSync(path.dirname(abs), { recursive: true });
    fs.writeFileSync(abs, '# Fixture\n\nSome body text for the budget.\n');

    const out = buildTokenBudget({
      root: dir,
      skills: [{ name: 'fixture', path: rel }],
      sectionOffsets: { skills: {} },
    });

    // Totals are nested under _meta, never at the top level.
    assert.equal(typeof out._meta, 'object', '_meta block present');
    assert.equal(typeof out._meta.total_chars, 'number', 'total_chars under _meta');
    assert.equal(typeof out._meta.total_approx_tokens, 'number', 'total_approx_tokens under _meta');
    assert.equal(out.total_chars, undefined, 'no top-level total_chars');
    assert.equal(out.total_approx_tokens, undefined, 'no top-level total_approx_tokens');
    // by_recipe is documented nowhere and emitted nowhere.
    assert.equal(out.by_recipe, undefined, 'no top-level by_recipe');
    assert.equal(out._meta.by_recipe, undefined, 'no by_recipe under _meta');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('zero-day-response template: blast-radius range matches the live RWEP weight ceiling', () => {
  const tmplPath = path.join(ROOT, 'reports', 'templates', 'zero-day-response.md');
  const text = fs.readFileSync(tmplPath, 'utf8');
  const { RWEP_WEIGHTS } = require(path.join(ROOT, 'lib', 'scoring.js'));
  const ceiling = RWEP_WEIGHTS.blast_radius;
  assert.equal(ceiling, 30, 'guard: this test assumes the blast_radius weight is 30');
  assert.ok(
    text.includes(`| Blast Radius | [description] | [0-${ceiling}] |`),
    `template must document blast radius as [0-${ceiling}]`,
  );
  assert.ok(!/Blast Radius \| \[description\] \| \[0-15\]/.test(text), 'stale [0-15] range must be gone');
});
