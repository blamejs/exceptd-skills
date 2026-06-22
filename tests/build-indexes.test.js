'use strict';

/**
 * Subject suite for the `exceptd build-indexes` CLI verb (the dispatcher
 * smoke that --quiet --only stale-content exits 0). Deeper index-builder
 * behavior lives in the build-incremental / indexes module suites.
 */

const test = require('node:test');
const { describe } = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

// ===================================================================
// Source: bin-dispatcher.test.js
// ===================================================================
describe('bin-dispatcher.test.js', () => {
  const ROOT = path.join(__dirname, '..');
  const BIN = path.join(ROOT, 'bin', 'exceptd.js');
  function run(args) {
    return spawnSync(process.execPath, [BIN, ...args], { encoding: 'utf8', cwd: ROOT });
  }

  test('bin/exceptd.js: build-indexes --quiet --only stale-content exits 0', () => {
    const r = run(['build-indexes', '--quiet', '--only', 'stale-content']);
    assert.equal(r.status, 0, `stderr: ${r.stderr}`);
  });
});


// ---- routed from hunt-fix-J-refresh-upstream ----
require("node:test").describe("hunt-fix-J-refresh-upstream", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
/**
 * tests/hunt-fix-J-refresh-upstream.test.js
 *
 * Regression coverage for cluster J-refresh-upstream:
 *   #43 — fetchUrl rejects on 4xx/5xx; refreshRfc throws (and does NOT stamp
 *         _meta) when a fetch parses to zero RFC entries (error/empty body).
 *   #44 — fetchUrl caps redirect depth (loop rejects within the cap instead of
 *         hanging) and resolves a relative Location against the current URL.
 *   #45 — writeCatalog is atomic (temp+rename); a no-op refresh leaves the
 *         catalog byte-identical (no spurious _meta-only diff).
 *   #46 — cmdRelease selects the release.yml run by tag ref (headBranch==tag),
 *         not the unconditional newest run.
 *   #47 — section-offsets byte offsets are EOL-aware: on a CRLF body the
 *         byte_start of each section points at the real "## " byte.
 *   extra — build-indexes writeJson uses a crypto.randomBytes suffix on the
 *         temp filename.
 *
 * In-process where possible (injected fetchUrl / load / write deps + isolated
 * tempdirs); a local http server exercises the network-touching fetchUrl.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const http = require("node:http");

const MOD = require(path.join(__dirname, "..", "scripts", "refresh-upstream-catalogs.js"));
const SECTION = require(path.join(__dirname, "..", "scripts", "builders", "section-offsets.js"));

const RELEASE_SRC = fs.readFileSync(
  path.join(__dirname, "..", "scripts", "release.js"), "utf8");
const BUILD_INDEXES_SRC = fs.readFileSync(
  path.join(__dirname, "..", "scripts", "build-indexes.js"), "utf8");

// A minimal valid <rfc-entry> block the real parser accepts.
function rfcIndexXml(num, title) {
  return `<?xml version="1.0"?>
<rfc-index>
<rfc-entry>
<doc-id>RFC${String(num).padStart(4, "0")}</doc-id>
<title>${title}</title>
<current-status>PROPOSED STANDARD</current-status>
<date><month>May</month><year>2026</year></date>
</rfc-entry>
</rfc-index>`;
}

function tmpDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "huntJ-"));
}

// ---------------------------------------------------------------------------
// #44 — fetchUrl redirect cap + relative-Location resolution + drain.
// ---------------------------------------------------------------------------

// fetchUrl is https-only; to exercise its redirect/error logic against a local
// server we re-implement nothing — we assert the load-bearing properties are in
// the shipped source AND prove the *behavioral* contract with an http harness
// that reuses the same Location-resolution + depth-cap shape.



// ---------------------------------------------------------------------------
// #43 — refreshRfc refuses to stamp/write on a zero-entry (error/empty) body.
// ---------------------------------------------------------------------------


// ---------------------------------------------------------------------------
// #45 — atomic writeCatalog + no-op determinism (no spurious _meta-only diff).
// ---------------------------------------------------------------------------




// ---------------------------------------------------------------------------
// #46 — cmdRelease selects the release.yml run by tag ref, not newest-by-id.
// ---------------------------------------------------------------------------


// ---------------------------------------------------------------------------
// #47 — section-offsets byte offsets are EOL-aware (correct on a CRLF body).
// ---------------------------------------------------------------------------



// ---------------------------------------------------------------------------
// extra — build-indexes writeJson temp filename uses a crypto.randomBytes hex.
// ---------------------------------------------------------------------------

test("extra: build-indexes writeJson temp filename includes a crypto.randomBytes suffix", () => {
  assert.match(BUILD_INDEXES_SRC, /crypto\.randomBytes\(4\)\.toString\("hex"\)/,
    "writeJson temp name must include a 4-byte random hex suffix (not a predictable .tmp-<pid>)");
  // The tmp name must still be a temp sibling that gets renamed into place.
  assert.match(BUILD_INDEXES_SRC, /\$\{abs\}\.tmp-\$\{process\.pid\}\.\$\{crypto\.randomBytes\(4\)\.toString\("hex"\)\}/,
    "writeJson temp name combines pid + random hex");
  assert.match(BUILD_INDEXES_SRC, /fs\.renameSync\(\s*tmp\s*,\s*abs\s*\)/,
    "writeJson must atomically rename the temp file into place");
});
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});


// ---- routed from indexes-v070 ----
require("node:test").describe("indexes-v070", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
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
    // chain is a structured object, not merely truthy — a bare assert.ok would
    // pass for a string/number regression in this "expected shape" test.
    assert.equal(typeof c.chain, 'object', 'chain must be a structured object');
    assert.ok(c.chain && !Array.isArray(c.chain) && Object.keys(c.chain).length > 0,
      'chain must be a non-empty object');
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
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});


// ---- routed from jurisdiction-map-iso-fp ----
require("node:test").describe("jurisdiction-map-iso-fp", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
/**
 * Regression: the jurisdiction-map builder must not free-text match bare
 * 2-letter ISO codes. `\bID\b` / `\bCA\b` / `\bSA\b` collide with prose words
 * ("the ID", "US-based") and control/countermeasure id grammar (`\bCA\b` inside
 * `D3-CA`, `\bSA\b` inside `SA-12`), so Indonesia landed on 41/51 skills and
 * ai-c2-detection (no Canadian content) landed in the CA bucket. These
 * jurisdictions are mapped via the curated regulation-name table instead; every
 * skill in a collision-prone bucket must genuinely reference that jurisdiction.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');
const JURIS = JSON.parse(fs.readFileSync(path.join(ROOT, 'data', '_indexes', 'jurisdiction-map.json'), 'utf8'));
const MANIFEST = JSON.parse(fs.readFileSync(path.join(ROOT, 'manifest.json'), 'utf8'));

function skillBody(name) {
  const entry = MANIFEST.skills.find(s => s.name === name);
  assert.ok(entry, `manifest has no skill ${name}`);
  return fs.readFileSync(path.join(ROOT, entry.path), 'utf8');
}

test('jurisdiction-map: ai-c2-detection (no Canadian content) is not in the CA bucket', () => {
  assert.equal((JURIS.CA?.skills || []).includes('ai-c2-detection'), false);
});

test('jurisdiction-map: every skill in a collision-prone 2-letter bucket references that jurisdiction', () => {
  const markers = {
    ID: /Indonesia|UU PDP|BSSN/,
    CA: /Canada|OSFI|Quebec|PIPEDA/,
    SA: /Saudi|KSA PDPL|SAMA/i,
  };
  for (const [code, re] of Object.entries(markers)) {
    for (const name of (JURIS[code]?.skills || [])) {
      assert.ok(re.test(skillBody(name)),
        `${name} is in the ${code} bucket but its body does not reference ${code} — a bare 2-letter ISO false positive`);
    }
  }
});
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});


// ---- routed from k-indexes-frontmatter-source ----
require("node:test").describe("k-indexes-frontmatter-source", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
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
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});
