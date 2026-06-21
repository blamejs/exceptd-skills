'use strict';

/**
 * Routing / collector / scoring correctness from the adjacent-area hunt:
 *  - dispatcher must preserve distinct findings that route to the same skill
 *    (de-dupe by skill+finding, not skill alone) so per-CVE evidence survives;
 *  - scanner's mcp_config_parse_error finding carries a skill_hint so it routes
 *    directly, not only via the brittle domain table;
 *  - library-author's action-ref scan flags a floating ref even with a trailing
 *    YAML comment (the `$`-anchored pattern silently missed those);
 *  - scoring.validate() honors the reboot_required alias when recomputing the
 *    expected RWEP, so a top-level reboot_required does not create false drift.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');

test('dispatcher preserves two distinct CVEs that route to the same skill (no dedupe-by-skill data loss)', () => {
  const { dispatch } = require('../orchestrator/dispatcher.js');
  const findings = [
    { domain: 'kernel', signal: 'kernel_cve', severity: 'critical', skill_hint: 'kernel-lpe-triage', cve_id: 'CVE-2026-31431', rwep_score: 90 },
    { domain: 'kernel', signal: 'kernel_cve', severity: 'critical', skill_hint: 'kernel-lpe-triage', cve_id: 'CVE-2025-53773', rwep_score: 80 },
  ];
  const { plan } = dispatch(findings);
  const kernelEntries = plan.filter((p) => p.skill_name === 'kernel-lpe-triage');
  assert.equal(kernelEntries.length, 2, 'both distinct CVEs routing to the same skill must produce a plan entry each');
  const cveIds = kernelEntries.map((p) => p.evidence && p.evidence.cve_id).sort();
  assert.deepEqual(cveIds, ['CVE-2025-53773', 'CVE-2026-31431'], 'each entry carries its own CVE evidence');

  // A genuine duplicate (same skill + same CVE) is still folded to one entry.
  const dup = dispatch([findings[0], findings[0]]);
  assert.equal(dup.plan.filter((p) => p.skill_name === 'kernel-lpe-triage').length, 1, 'a true duplicate is still deduped');
});

test('scanner mcp_config_parse_error finding carries a direct skill_hint', () => {
  // Behavioral routing: a parse-error finding shaped like the scanner emits must
  // route directly to mcp-agent-trust via skill_hint, independent of the domain
  // table.
  const { dispatch } = require('../orchestrator/dispatcher.js');
  const { plan } = dispatch([{ domain: 'mcp', signal: 'mcp_config_parse_error', severity: 'low', skill_hint: 'mcp-agent-trust', action_required: 'x' }]);
  assert.ok(plan.some((p) => p.skill_name === 'mcp-agent-trust'), 'parse-error must route to mcp-agent-trust via skill_hint');
  // And the scanner source actually sets that skill_hint on the finding.
  const SRC = fs.readFileSync(path.join(ROOT, 'orchestrator', 'scanner.js'), 'utf8');
  const block = SRC.slice(SRC.indexOf('mcp_config_parse_error'), SRC.indexOf('mcp_config_parse_error') + 400);
  assert.match(block, /skill_hint:\s*'mcp-agent-trust'/, 'the parse-error finding literal must set skill_hint');
});

test('library-author flags a floating action ref that carries a trailing YAML comment', () => {
  const { collect } = require('../lib/collectors/library-author.js');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'libauth-'));
  try {
    const wfDir = path.join(dir, '.github', 'workflows');
    fs.mkdirSync(wfDir, { recursive: true });
    // A publish-shaped workflow with a floating (non-SHA) ref AND a trailing
    // comment — the case the `$`-anchored regex used to miss entirely.
    fs.writeFileSync(path.join(wfDir, 'release.yml'), [
      'name: release',
      'on: { push: { tags: ["v*"] } }',
      'jobs:',
      '  publish:',
      '    runs-on: ubuntu-latest',
      '    steps:',
      '      - uses: actions/checkout@v4  # pin this eventually',
      '      - run: npm publish',
    ].join('\n'));
    const res = collect({ cwd: dir });
    assert.equal(
      res.signal_overrides['publish-workflow-action-refs-mutable'],
      'hit',
      `a floating ref with a trailing comment must register a hit; signal_overrides=${JSON.stringify(res.signal_overrides)}`,
    );
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('scoreCustom honors the reboot alias identically — the property scoring.validate() now mirrors', () => {
  const { scoreCustom } = require('../lib/scoring.js');
  // A base where the reboot factor is observable (not clamped at 0 or 100).
  const base = {
    cisa_kev: true, poc_available: true, ai_assisted_weapon: false, ai_discovered: false,
    active_exploitation: 'none', blast_radius: 3, patch_available: false, live_patch_available: false,
  };
  const viaReboot = scoreCustom({ ...base, reboot_required: true });
  const viaPatchReboot = scoreCustom({ ...base, patch_required_reboot: true });
  const noReboot = scoreCustom({ ...base });
  assert.equal(viaReboot, viaPatchReboot, 'reboot_required and patch_required_reboot must score identically (the alias)');
  assert.notEqual(viaReboot, noReboot, 'the reboot factor must be non-zero, else the alias is moot'); // allow-notEqual: proves the alias is meaningful, not vacuous

  // validate() previously passed only `entry.patch_required_reboot` to its
  // recompute, dropping a top-level reboot_required and computing a divergent
  // expected RWEP. It now passes `reboot_required || patch_required_reboot`,
  // mirroring the equivalence asserted above.
  const fs = require('node:fs'); const path = require('node:path');
  const SRC = fs.readFileSync(path.join(__dirname, '..', 'lib', 'scoring.js'), 'utf8');
  assert.match(SRC, /reboot_required:\s*entry\.reboot_required\s*\|\|\s*entry\.patch_required_reboot/,
    'validate() must recompute with the reboot alias, not patch_required_reboot alone');
});
