'use strict';

// build-indexes derives its cross-reference data from the authoritative skill
// frontmatter, not from the manifest cache (which can drift). These tests
// guard that source-of-truth wiring without regenerating the shared
// data/_indexes outputs: loadSources() only reads files, and the dep checks
// inspect the OUTPUTS registry in memory.

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const lint = require('../lib/lint-skills.js');
const { OUTPUTS, loadSources } = require('../scripts/build-indexes.js');

// Fields the indexes key on that the skill frontmatter owns. Mirrors the
// overlay set in build-indexes.js loadSources().
const ARRAY_FIELDS = [
  'framework_gaps', 'd3fend_refs', 'cwe_refs', 'atlas_refs',
  'attack_refs', 'rfc_refs', 'triggers', 'data_deps',
];

function frontmatterOf(skillPath) {
  const content = fs.readFileSync(path.join(ROOT, skillPath), 'utf8');
  const { frontmatter } = lint.extractFrontmatterBlock(content);
  return lint.parseFrontmatter(frontmatter);
}

test('loadSources overlays every skill cross-reference array from its frontmatter', () => {
  const ctx = loadSources();
  assert.ok(ctx.skills.length > 0, 'expected at least one skill');
  for (const s of ctx.skills) {
    const fm = frontmatterOf(s.path);
    for (const field of ARRAY_FIELDS) {
      if (!Array.isArray(fm[field])) continue; // skill omits the field
      assert.ok(Array.isArray(s[field]), `${s.name}.${field} should be an array`);
      assert.deepEqual(
        s[field],
        fm[field],
        `${s.name}.${field} must mirror frontmatter (manifest cache drifted)`,
      );
    }
  }
});

test('loadSources overlays the skill description from frontmatter', () => {
  const ctx = loadSources();
  for (const s of ctx.skills) {
    const fm = frontmatterOf(s.path);
    if (typeof fm.description !== 'string') continue;
    assert.equal(typeof s.description, 'string');
    assert.equal(s.description, fm.description, `${s.name}.description must mirror frontmatter`);
  }
});

test('the UK/AU global-first control mappings survive into the loaded skill record', () => {
  // kernel-lpe-triage declares UK-CAF-D1 + AU-Essential-8-Patch framework gaps,
  // D3-PA + D3-SCP d3fend refs, and the fragnesia / cve-2026-46300 triggers in
  // its frontmatter. The manifest cache historically dropped them; the loaded
  // record must carry them.
  const ctx = loadSources();
  const k = ctx.skills.find((s) => s.name === 'kernel-lpe-triage');
  assert.ok(k, 'kernel-lpe-triage skill present');
  for (const gap of ['UK-CAF-D1', 'AU-Essential-8-Patch']) {
    assert.ok(k.framework_gaps.includes(gap), `framework_gaps should include ${gap}`);
  }
  for (const d3 of ['D3-PA', 'D3-SCP']) {
    assert.ok(k.d3fend_refs.includes(d3), `d3fend_refs should include ${d3}`);
  }
  for (const trig of ['fragnesia', 'cve-2026-46300']) {
    assert.ok(k.triggers.includes(trig), `triggers should include ${trig}`);
  }
});

test('a frontmatter-absent field is not synthesized onto the loaded record', () => {
  // dlp_refs lives only in index consumers (defaulted to []), never in skill
  // frontmatter or the manifest skill records. The overlay must not invent it.
  const ctx = loadSources();
  for (const s of ctx.skills) {
    const fm = frontmatterOf(s.path);
    if (!('dlp_refs' in fm)) {
      assert.equal('dlp_refs' in s, false, `${s.name}.dlp_refs must not be synthesized`);
    }
  }
});

test('outputs that consume frontmatter-overlaid fields declare a skill-body dependency', () => {
  // Any output whose content now derives from skill frontmatter must rebuild
  // when a skill body changes, or --changed would silently ship stale data.
  const SAMPLE_SKILL = 'skills/kernel-lpe-triage/skill.md';
  const needsSkillBodyDep = ['xref', 'trigger-table', 'chains', 'frequency', 'activity-feed', 'summary-cards'];
  for (const name of needsSkillBodyDep) {
    const o = OUTPUTS.find((x) => x.name === name);
    assert.ok(o, `output ${name} registered`);
    const matches = o.deps.some((dep) => dep(SAMPLE_SKILL));
    assert.ok(matches, `output ${name} must declare a skill-body dependency`);
  }
});
