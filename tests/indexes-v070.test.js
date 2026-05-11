'use strict';

/**
 * tests/indexes-v070.test.js
 *
 * Verifies the v0.7.0 derived-index additions:
 *   - summary-cards.json
 *   - section-offsets.json
 *   - chains.json (CWE half)
 *   - token-budget.json
 *   - recipes.json
 *   - jurisdiction-clocks.json
 *   - did-ladders.json
 *   - theater-fingerprints.json
 *   - currency.json
 *   - frequency.json
 *   - activity-feed.json
 *   - catalog-summaries.json
 *   - stale-content.json
 *
 * Every file must (a) load as valid JSON, (b) reference only known skill /
 * catalog entries, (c) be byte-stable across rebuilds for deterministic
 * outputs.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const IDX = path.join(ROOT, 'data', '_indexes');

const manifest = require(path.join(ROOT, 'manifest.json'));
const skillNames = new Set(manifest.skills.map((s) => s.name));

function load(name) {
  return JSON.parse(fs.readFileSync(path.join(IDX, name), 'utf8'));
}

test('summary-cards.json has one card per manifest skill', () => {
  const j = load('summary-cards.json');
  assert.equal(Object.keys(j.skills).length, manifest.skills.length);
  for (const name of skillNames) {
    const card = j.skills[name];
    assert.ok(card, `missing card for ${name}`);
    assert.equal(typeof card.description, 'string');
    assert.ok(Array.isArray(card.handoff_targets));
    assert.ok(typeof card.trigger_count === 'number');
    for (const t of card.handoff_targets) assert.ok(skillNames.has(t), `unknown handoff target ${t} in card ${name}`);
  }
});

test('summary-cards.json threat-context excerpt avoids leading H3 / metadata', () => {
  const j = load('summary-cards.json');
  // kernel-lpe-triage's Threat Context begins with "### Copy Fail" — the
  // extractor should skip that and land on the prose paragraph beneath it.
  const card = j.skills['kernel-lpe-triage'];
  assert.ok(card.threat_context_excerpt, 'kernel-lpe-triage card missing threat_context_excerpt');
  assert.ok(
    !/^### /.test(card.threat_context_excerpt) && !card.threat_context_excerpt.startsWith('---'),
    `expected prose, got: ${card.threat_context_excerpt.slice(0, 80)}`
  );
});

test('section-offsets.json: every skill has at least one H2 section + valid byte ranges', () => {
  const j = load('section-offsets.json');
  assert.equal(Object.keys(j.skills).length, manifest.skills.length);
  for (const [name, info] of Object.entries(j.skills)) {
    assert.ok(skillNames.has(name));
    assert.ok(info.sections.length > 0, `${name} has no sections`);
    assert.ok(info.total_bytes > 0);
    for (const sec of info.sections) {
      assert.ok(sec.byte_start >= 0);
      assert.ok(sec.byte_end > sec.byte_start);
      assert.ok(sec.byte_end <= info.total_bytes);
    }
  }
});

test('section-offsets.json: code-fenced fake H2 lines are NOT counted as sections', () => {
  const j = load('section-offsets.json');
  // kernel-lpe-triage has a code block beginning with "## Kernel LPE Exposure
  // Assessment" inside an Output Format fence. That string is a fake header
  // for the rendered output, not a real section. The fence-aware parser
  // should ignore it.
  const sections = j.skills['kernel-lpe-triage'].sections.map((s) => s.name);
  assert.ok(
    !sections.includes('Kernel LPE Exposure Assessment'),
    `kernel-lpe-triage incorrectly counts a code-fenced line as a section: ${sections.join(' | ')}`
  );
});

test('chains.json contains CVE + CWE chains with the expected shape', () => {
  const j = load('chains.json');
  const cveIds = Object.keys(j).filter((k) => k.startsWith('CVE-'));
  const cweIds = Object.keys(j).filter((k) => k.startsWith('CWE-'));
  assert.ok(cveIds.length >= 1, 'expected at least one CVE chain');
  assert.ok(cweIds.length >= 1, 'expected at least one CWE chain');
  for (const id of cweIds) {
    const c = j[id];
    assert.ok(Array.isArray(c.referencing_skills));
    assert.ok(Array.isArray(c.related_cves));
    assert.ok(c.chain);
  }
});

test('token-budget.json: per-skill totals are integers + reasonable', () => {
  const j = load('token-budget.json');
  assert.ok(j._meta.total_approx_tokens > 50_000, 'corpus should be > 50K approx tokens');
  for (const [name, b] of Object.entries(j.skills)) {
    assert.ok(skillNames.has(name));
    assert.ok(Number.isInteger(b.approx_tokens));
    assert.ok(b.approx_tokens >= 0);
    for (const [sec, info] of Object.entries(b.sections)) {
      assert.ok(Number.isInteger(info.approx_tokens));
      assert.ok(info.bytes >= 0);
    }
  }
});

test('recipes.json: every step references a real skill', () => {
  const j = load('recipes.json');
  assert.ok(j.recipes.length >= 5);
  for (const r of j.recipes) {
    assert.equal(typeof r.id, 'string');
    assert.equal(typeof r.name, 'string');
    assert.ok(Array.isArray(r.skill_chain));
    for (const sn of r.skill_chain) {
      assert.ok(skillNames.has(sn), `recipe ${r.id}: unknown skill ${sn}`);
    }
  }
});

test('jurisdiction-clocks.json: every entry has hours as a number or null', () => {
  const j = load('jurisdiction-clocks.json');
  for (const [code, info] of Object.entries(j.by_jurisdiction)) {
    assert.equal(typeof code, 'string');
    for (const [fwName, fw] of Object.entries(info.frameworks)) {
      if (fw.breach_notification) {
        assert.ok(fw.breach_notification.hours === null || typeof fw.breach_notification.hours === 'number');
      }
      if (fw.patch_sla) {
        assert.ok(typeof fw.patch_sla.hours === 'number', `${code}/${fwName} patch_sla.hours must be number`);
      }
    }
  }
  // Cross-jurisdiction roll-ups must be sorted ascending by hours.
  for (let i = 1; i < j.sorted_by_breach_notification_hours.length; i++) {
    assert.ok(j.sorted_by_breach_notification_hours[i].hours >= j.sorted_by_breach_notification_hours[i - 1].hours);
  }
});

test('did-ladders.json: every source_skill + D3FEND ref is real', () => {
  const j = load('did-ladders.json');
  const d3 = require(path.join(ROOT, 'data', 'd3fend-catalog.json'));
  const d3Ids = new Set(Object.keys(d3).filter((k) => !k.startsWith('_')));
  for (const ladder of j.ladders) {
    for (const layer of ladder.layers) {
      assert.ok(skillNames.has(layer.source_skill), `ladder ${ladder.id}: unknown skill ${layer.source_skill}`);
      for (const ref of layer.d3fend || []) {
        assert.ok(d3Ids.has(ref), `ladder ${ladder.id}: unknown D3FEND ref ${ref}`);
      }
    }
  }
});

test('theater-fingerprints.json: every pattern populates required fields', () => {
  const j = load('theater-fingerprints.json');
  assert.equal(Object.keys(j.patterns).length, 7);
  for (const [pid, p] of Object.entries(j.patterns)) {
    assert.match(pid, /^pattern-\d+$/);
    assert.equal(typeof p.pattern_name, 'string');
    assert.ok(Array.isArray(p.controls));
    assert.ok(Array.isArray(p.ttps));
    assert.equal(p.source_skill, 'compliance-theater');
    // Claim / audit_evidence / reality / why_its_theater come from prose
    // extraction — at least one should be populated for each pattern.
    assert.ok(p.claim || p.reality, `pattern ${pid} missing prose fields`);
  }
});

test('currency.json: every skill row is present and deterministic against threat_review_date', () => {
  const j = load('currency.json');
  assert.equal(j.skills.length, manifest.skills.length);
  assert.equal(j._meta.reference_date, manifest.threat_review_date);
  for (const row of j.skills) {
    assert.ok(skillNames.has(row.skill));
    assert.ok(['current', 'acceptable', 'stale', 'critical_stale'].includes(row.currency_label));
  }
});

test('frequency.json: top_cited entries reference real catalog ids', () => {
  const j = load('frequency.json');
  for (const [field, rows] of Object.entries(j.top_cited)) {
    for (const r of rows) {
      assert.equal(typeof r.id, 'string');
      assert.ok(r.count >= 1);
      for (const s of r.skills) assert.ok(skillNames.has(s), `frequency.top_cited.${field}: ${s}`);
    }
  }
});

test('activity-feed.json: events sorted descending by date', () => {
  const j = load('activity-feed.json');
  for (let i = 1; i < j.events.length; i++) {
    assert.ok(j.events[i - 1].date >= j.events[i].date);
  }
});

test('catalog-summaries.json: covers every data/*.json (excluding _indexes/)', () => {
  const j = load('catalog-summaries.json');
  const live = fs
    .readdirSync(path.join(ROOT, 'data'))
    .filter((f) => f.endsWith('.json'));
  assert.equal(Object.keys(j.catalogs).length, live.length);
  for (const f of live) assert.ok(j.catalogs[f], `missing catalog summary for ${f}`);
});

test('stale-content.json: by_severity counts match findings array', () => {
  const j = load('stale-content.json');
  const counts = { high: 0, medium: 0, low: 0 };
  for (const f of j.findings) counts[f.severity] = (counts[f.severity] || 0) + 1;
  assert.equal(j._meta.finding_count, j.findings.length);
  for (const sev of Object.keys(counts)) {
    assert.equal(counts[sev], j._meta.by_severity[sev] || 0);
  }
});

test('build-indexes is idempotent — re-running produces identical output', () => {
  const { execFileSync } = require('child_process');
  // Snapshot existing index hashes.
  const filesBefore = fs.readdirSync(IDX);
  const hashesBefore = Object.fromEntries(
    filesBefore.map((f) => [f, require('crypto').createHash('sha256').update(fs.readFileSync(path.join(IDX, f))).digest('hex')])
  );
  // Rebuild.
  execFileSync(process.execPath, [path.join(ROOT, 'scripts', 'build-indexes.js')], { stdio: 'ignore', cwd: ROOT });
  // Recompute hashes — every file except _meta.json (which has generated_at)
  // should be byte-identical.
  const filesAfter = fs.readdirSync(IDX);
  assert.deepEqual(filesAfter.sort(), filesBefore.sort());
  for (const f of filesAfter) {
    if (f === '_meta.json') continue;
    const liveHash = require('crypto').createHash('sha256').update(fs.readFileSync(path.join(IDX, f))).digest('hex');
    assert.equal(liveHash, hashesBefore[f], `index ${f} not byte-stable across rebuilds`);
  }
});
