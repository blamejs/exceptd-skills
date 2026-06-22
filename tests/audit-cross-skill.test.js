'use strict';

/**
 * tests/audit-cross-skill.test.js
 *
 * Subject coverage for scripts/audit-cross-skill.js — the cross-skill accuracy
 * audit that surfaces manifest/disk/frontmatter/version/snapshot/sbom/ref-graph
 * drift and exits non-zero on any finding.
 *
 * The script runs entirely at module load and calls process.exit(), so it is
 * NOT require()-able. It reads a fixed ROOT (__dirname/..) and never WRITES, so
 * behaviour is exercised two ways:
 *   1. against the real repo via subprocess: the run prints the audit header +
 *      an "ISSUES (N)" tally and its exit code is 0 iff N === 0 (the pass/fail
 *      contract on real data);
 *   2. against a self-contained fixture repo: a clean fixture audits to ZERO
 *      issues + exit 0, and a single targeted tamper of one input flips the
 *      audit to a SPECIFIC finding + exit 1 (the negative path).
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const ROOT = path.join(__dirname, '..');
const SCRIPT_SRC = path.join(ROOT, 'scripts', 'audit-cross-skill.js');
const SCRIPT_BODY = fs.readFileSync(SCRIPT_SRC, 'utf8');

// ---------------------------------------------------------------------------
// 1. Real-repo subprocess: pass/fail contract on live data.
// ---------------------------------------------------------------------------

test('real repo: audit prints header + issue tally, exit code matches the count', () => {
  const r = spawnSync(process.execPath, [SCRIPT_SRC], { encoding: 'utf8', cwd: ROOT });
  assert.match(r.stdout, /=== CROSS-SKILL AUDIT ===/);
  assert.match(r.stdout, /Skills: \d+/);
  const m = r.stdout.match(/=== ISSUES \((\d+)\) ===/);
  assert.ok(m, 'expected an ISSUES (N) tally in the output');
  const n = Number(m[1]);
  // The load-bearing contract: exit 0 iff zero issues, exit 1 otherwise.
  if (n === 0) {
    assert.match(r.stdout, /zero issues/);
    assert.equal(r.status, 0);
  } else {
    assert.equal(r.status, 1, `N=${n} findings must produce exit 1`);
  }
});

// ---------------------------------------------------------------------------
// 2. Fixture repo: clean -> 0 issues / exit 0, tamper -> targeted finding.
// ---------------------------------------------------------------------------

// Catalogs the ref-resolution checks read. Each gets one entry so a skill can
// cite a resolvable ref (and a tamper can introduce an unresolvable one).
const DATA_FILES = {
  'cwe-catalog.json': { _meta: {}, 'CWE-79': { name: 'XSS' } },
  'd3fend-catalog.json': { _meta: {}, 'D3-PA': { name: 'PA' } },
  'framework-control-gaps.json': { _meta: {}, 'UK-CAF-D1': { framework: 'UK CAF' } },
  'atlas-ttps.json': { _meta: {}, 'AML.T0001': { name: 'ttp' } },
  'rfc-references.json': { _meta: {}, 'RFC9999': { title: 'x', skills_referencing: ['kernel-lpe-triage'] } },
  'dlp-controls.json': { _meta: {}, 'DLP-1': { name: 'dlp' } },
  'global-frameworks.json': { _meta: {}, _notification_summary: {}, US: {}, EU: {}, GLOBAL: {} },
  // three more so liveCatalogs (every data/*.json) is a known, stable count
  'cve-catalog.json': { _meta: {} },
  'zeroday-lessons.json': { _meta: {} },
  'exploit-availability.json': { _meta: {} },
};
const DATA_COUNT = Object.keys(DATA_FILES).length; // sbom catalog:count must equal this
const LIVE_JURS = 3; // US, EU, GLOBAL (non-_ keys in global-frameworks.json)

function skillFrontmatter(name) {
  return [
    '---',
    `name: ${name}`,
    'version: 1.0.0',
    '---',
    '',
    `# ${name}`,
    '',
    'body',
    '',
  ].join('\n');
}

function buildFixture() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'exceptd-xskill-'));
  fs.mkdirSync(path.join(root, 'scripts'), { recursive: true });
  fs.mkdirSync(path.join(root, 'data'), { recursive: true });
  fs.writeFileSync(path.join(root, 'scripts', 'audit-cross-skill.js'), SCRIPT_BODY);

  const skills = [
    { name: 'researcher', path: 'skills/researcher/skill.md' },
    { name: 'skill-update-loop', path: 'skills/skill-update-loop/skill.md' },
    {
      name: 'kernel-lpe-triage',
      path: 'skills/kernel-lpe-triage/skill.md',
      cwe_refs: ['CWE-79'],
      d3fend_refs: ['D3-PA'],
      framework_gaps: ['UK-CAF-D1'],
      atlas_refs: ['AML.T0001'],
      rfc_refs: ['RFC9999'],
      dlp_refs: ['DLP-1'],
      triggers: ['fragnesia'],
    },
  ];

  for (const s of skills) {
    const dir = path.join(root, path.dirname(s.path));
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(root, s.path), skillFrontmatter(s.name));
  }

  // researcher dispatch must mention every other skill in backticks + carry the
  // "<N> specialized skills downstream" claim (N = skills.length - 1).
  const others = skills.filter((s) => s.name !== 'researcher').map((s) => '`' + s.name + '`').join(', ');
  fs.writeFileSync(
    path.join(root, 'skills', 'researcher', 'skill.md'),
    [
      '---', 'name: researcher', 'version: 1.0.0', '---', '',
      '# researcher', '',
      `Dispatches to ${skills.length - 1} specialized skills downstream: ${others}.`,
      '',
    ].join('\n'),
  );

  // skill-update-loop: an Affected-skills block referencing only a real skill.
  fs.writeFileSync(
    path.join(root, 'skills', 'skill-update-loop', 'skill.md'),
    [
      '---', 'name: skill-update-loop', 'version: 1.0.0', '---', '',
      '# skill-update-loop', '',
      '**Affected skills:** kernel-lpe-triage',
      '',
    ].join('\n'),
  );

  // manifest.json
  fs.writeFileSync(path.join(root, 'manifest.json'), JSON.stringify({ version: '1.2.3', skills }, null, 2));
  // package.json + CHANGELOG (version triple)
  fs.writeFileSync(path.join(root, 'package.json'), JSON.stringify({ version: '1.2.3' }, null, 2));
  fs.writeFileSync(path.join(root, 'CHANGELOG.md'), '# Changelog\n\n## 1.2.3\n\nfixture.\n');
  // manifest-snapshot.json
  fs.writeFileSync(path.join(root, 'manifest-snapshot.json'), JSON.stringify({
    skill_count: skills.length,
    skills: skills.map((s) => ({ name: s.name })),
  }, null, 2));
  // sbom.cdx.json
  fs.writeFileSync(path.join(root, 'sbom.cdx.json'), JSON.stringify({
    metadata: {
      properties: [
        { name: 'exceptd:skill:count', value: String(skills.length) },
        { name: 'exceptd:catalog:count', value: String(DATA_COUNT) },
      ],
    },
  }, null, 2));
  // AGENTS.md Quick Skill Reference — a table row per skill.
  fs.writeFileSync(path.join(root, 'AGENTS.md'),
    ['# AGENTS', '', ...skills.map((s) => `| ${s.name} | desc |`), ''].join('\n'));
  // README badges
  fs.writeFileSync(path.join(root, 'README.md'),
    `# readme\n\n![skills](skills-${skills.length}-blue) ![jur](jurisdictions-${LIVE_JURS}-blue)\n`);
  // other tracked docs the stale-rename check reads (must exist or be skipped)
  fs.writeFileSync(path.join(root, 'CONTEXT.md'), '# context\n');
  fs.writeFileSync(path.join(root, 'ARCHITECTURE.md'), '# arch\n');
  fs.writeFileSync(path.join(root, 'MAINTAINERS.md'), '# maint\n');

  for (const [name, obj] of Object.entries(DATA_FILES)) {
    fs.writeFileSync(path.join(root, 'data', name), JSON.stringify(obj, null, 2));
  }
  return { root };
}

function run(root) {
  return spawnSync(process.execPath, [path.join(root, 'scripts', 'audit-cross-skill.js')], { encoding: 'utf8', cwd: root });
}
function cleanup(root) {
  try { fs.rmSync(root, { recursive: true, force: true }); } catch { /* non-fatal */ }
}

test('fixture: a consistent repo audits to ZERO issues and exits 0', () => {
  const { root } = buildFixture();
  try {
    const r = run(root);
    assert.match(r.stdout, /=== ISSUES \(0\) ===/, `unexpected findings:\n${r.stdout}`);
    assert.match(r.stdout, /zero issues/);
    assert.equal(r.status, 0, `stdout=${r.stdout}\nstderr=${r.stderr}`);
  } finally { cleanup(root); }
});

test('fixture tamper: manifest-snapshot skill_count drift is reported (exit 1)', () => {
  const { root } = buildFixture();
  try {
    const sPath = path.join(root, 'manifest-snapshot.json');
    const snap = JSON.parse(fs.readFileSync(sPath, 'utf8'));
    snap.skill_count = 99;
    fs.writeFileSync(sPath, JSON.stringify(snap, null, 2));
    const r = run(root);
    assert.equal(r.status, 1);
    assert.match(r.stdout, /SNAPSHOT DRIFT: snapshot 99 vs manifest 3/);
  } finally { cleanup(root); }
});

test('fixture tamper: a frontmatter name that drifts from the manifest is reported (exit 1)', () => {
  const { root } = buildFixture();
  try {
    // Rewrite the kernel skill body with a mismatched frontmatter `name:`.
    fs.writeFileSync(path.join(root, 'skills', 'kernel-lpe-triage', 'skill.md'),
      skillFrontmatter('WRONG-NAME'));
    const r = run(root);
    assert.equal(r.status, 1);
    assert.match(r.stdout, /NAME DRIFT: manifest "kernel-lpe-triage" vs frontmatter "WRONG-NAME"/);
  } finally { cleanup(root); }
});

test('fixture tamper: version drift between manifest and package is reported (exit 1)', () => {
  const { root } = buildFixture();
  try {
    fs.writeFileSync(path.join(root, 'package.json'), JSON.stringify({ version: '9.9.9' }, null, 2));
    const r = run(root);
    assert.equal(r.status, 1);
    assert.match(r.stdout, /VERSION DRIFT: manifest\.json 1\.2\.3 vs package\.json 9\.9\.9/);
  } finally { cleanup(root); }
});

test('fixture tamper: an unresolvable cwe_ref is reported as a BAD CWE_REF (exit 1)', () => {
  const { root } = buildFixture();
  try {
    const mPath = path.join(root, 'manifest.json');
    const m = JSON.parse(fs.readFileSync(mPath, 'utf8'));
    m.skills[2].cwe_refs = ['CWE-99999'];
    fs.writeFileSync(mPath, JSON.stringify(m, null, 2));
    const r = run(root);
    assert.equal(r.status, 1);
    assert.match(r.stdout, /BAD CWE_REF: kernel-lpe-triage cites "CWE-99999"/);
  } finally { cleanup(root); }
});

test('fixture tamper: a disk skill dir with no manifest entry is an ORPHAN (exit 1)', () => {
  const { root } = buildFixture();
  try {
    const orphan = path.join(root, 'skills', 'ghost-skill');
    fs.mkdirSync(orphan, { recursive: true });
    fs.writeFileSync(path.join(orphan, 'skill.md'), skillFrontmatter('ghost-skill'));
    const r = run(root);
    assert.equal(r.status, 1);
    assert.match(r.stdout, /ORPHAN SKILL FILE: skills\/ghost-skill\/skill\.md/);
  } finally { cleanup(root); }
});

test('fixture tamper: a README skills-badge count mismatch is reported (exit 1)', () => {
  const { root } = buildFixture();
  try {
    fs.writeFileSync(path.join(root, 'README.md'),
      `# readme\n\n![skills](skills-99-blue) ![jur](jurisdictions-${LIVE_JURS}-blue)\n`);
    const r = run(root);
    assert.equal(r.status, 1);
    assert.match(r.stdout, /README BADGE DRIFT: shows skills-99- but manifest has 3/);
  } finally { cleanup(root); }
});
