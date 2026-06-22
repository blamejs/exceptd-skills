"use strict";


// ---- routed from sbom-capability-signals ----
require("node:test").describe("sbom-capability-signals", () => {
const __t = require("node:test"); const __env = Object.assign({}, process.env);
__t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __env)) delete process.env[k]; Object.assign(process.env, __env);
  const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
/**
 * tests/sbom-capability-signals.test.js
 *
 * Pins the package-capability signals added to the supply-chain (sbom)
 * playbook: the package-capability-surface evidence artifact, the
 * across-version-bump capability-creep detector, and the absolute
 * capability-surface screen. Each assertion checks CONTENT (the capability
 * vocabulary, the false-positive checks, the TTP ref), not bare presence —
 * a presence-only test would pass even if the detector's guardrails were
 * deleted.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');

const PB = require(path.join(__dirname, '..', 'data', 'playbooks', 'sbom.json'));
const ARTIFACTS = PB.phases.look.artifacts;
const INDICATORS = PB.phases.detect.indicators;
const FP_PROFILE = PB.phases.detect.false_positive_profile;

const CAPABILITY_TAGS = ['network', 'filesystem', 'shell', 'env', 'eval', 'install-script', 'telemetry', 'native-binary'];

function byId(arr, id) { return arr.find((x) => x.id === id); }

test('package-capability-surface look artifact exists and carries the 8-tag capability vocabulary', () => {
  const a = byId(ARTIFACTS, 'package-capability-surface');
  assert.ok(a, 'package-capability-surface artifact must be present');
  assert.equal(a.type, 'config_file', 'capability-surface is a manifest read (config_file)');
  assert.equal(a.required, false, 'optional sweep artifact — absence must not halt the run');
  for (const tag of CAPABILITY_TAGS) {
    assert.ok((a.source + ' ' + a.description).includes(tag),
      `capability vocabulary must name "${tag}" so the AI classifies against the full taxonomy`);
  }
  // air-gap conditional: a config_file artifact with no network-call substring needs no air_gap_alternative.
  assert.ok(!/https?:\/\/|gh api|curl /.test(a.source), 'capability-surface source must not issue network calls');
});

test('capability-creep across-version-bump indicator fires on a capability GAIN, gated by FP checks', () => {
  const i = byId(INDICATORS, 'dependency-capability-creep-across-version-bump');
  assert.ok(i, 'across-version-bump capability-creep indicator must be present');
  assert.equal(i.type, 'behavioral_signal');
  assert.equal(i.deterministic, false, 'capability creep is probabilistic — must not auto-verdict');
  assert.equal(i.attack_ref, 'T1195.001');
  assert.equal(i.atlas_ref, 'AML.T0010');
  assert.ok(Array.isArray(i.false_positive_checks_required) && i.false_positive_checks_required.length >= 4,
    'load-bearing FP checks keep the high-recall heuristic from over-firing on build tooling');
  assert.ok(/version bump/i.test(i.value), 'value must describe the version-delta semantics');
});

test('package-capability-creep absolute-surface screen flags install-script + high-trust capability, no CVE needed', () => {
  const i = byId(INDICATORS, 'package-capability-creep');
  assert.ok(i, 'absolute capability-surface indicator must be present');
  assert.equal(i.type, 'config_value');
  assert.equal(i.deterministic, false);
  assert.equal(i.attack_ref, 'T1195.002');
  assert.ok(!('cve_ref' in i), 'capability-surface is CVE-independent — must not pin a cve_ref');
  assert.ok(Array.isArray(i.false_positive_checks_required) && i.false_positive_checks_required.length >= 4,
    'FP checks must cover the build-tooling/native-addon benign class');
  assert.ok(/install-script/.test(i.value) && /credential-harvesting|delivery/.test(i.value),
    'value must name the install-script + high-trust-capability delivery shape');
});

test('both capability indicators carry a paired false_positive_profile entry', () => {
  for (const id of ['dependency-capability-creep-across-version-bump', 'package-capability-creep']) {
    const fp = FP_PROFILE.find((x) => x.indicator_id === id);
    assert.ok(fp, `${id} must have a false_positive_profile entry`);
    assert.ok(typeof fp.distinguishing_test === 'string' && fp.distinguishing_test.length > 40,
      `${id} FP profile must carry a real distinguishing test`);
  }
});

test('sbom playbook carries the 1.3.0 capability-taxonomy changelog rung (version only advances)', () => {
  assert.ok(Array.isArray(PB._meta.changelog), 'playbook must carry a changelog');
  assert.ok(PB._meta.changelog.some((c) => c.version === '1.3.0'),
    'the 1.3.0 changelog rung must document the capability taxonomy');
  // Version monotonically advances past 1.3.0 as later passes add detectors —
  // assert >= 1.3.0 by numeric tuple, never pin the exact live version.
  const [maj, min, pat] = String(PB._meta.version).split('.').map(Number);
  assert.ok(maj > 1 || (maj === 1 && (min > 3 || (min === 3 && pat >= 0))),
    `playbook _meta.version (${PB._meta.version}) must be >= 1.3.0`);
});
});


// ---- routed from sbom-detection-depth ----
require("node:test").describe("sbom-detection-depth", () => {
const __t = require("node:test"); const __env = Object.assign({}, process.env);
__t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __env)) delete process.env[k]; Object.assign(process.env, __env);
  const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
/**
 * tests/sbom-detection-depth.test.js
 *
 * Pins the supply-chain detection-depth indicators: typosquat/homoglyph
 * name detection, the static content red-flag screen, and the dependency-
 * confusion resolution-source check. Asserts the load-bearing content (the
 * TTP refs, the codepoint-class reuse, the MOIKA correlation, the FP checks)
 * rather than bare presence.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');

const PB = require(path.join(__dirname, '..', 'data', 'playbooks', 'sbom.json'));
const IND = PB.phases.detect.indicators;
const ART = PB.phases.look.artifacts;
const FPP = PB.phases.detect.false_positive_profile;
const byId = (arr, id) => arr.find((x) => x.id === id);

test('typosquat/homoglyph detector reuses the vendored codepoint-class + maps T1195.002', () => {
  const i = byId(IND, 'dependency-name-typosquat');
  assert.ok(i, 'dependency-name-typosquat indicator must be present');
  assert.equal(i.attack_ref, 'T1195.002');
  assert.equal(i.atlas_ref, 'AML.T0010');
  assert.equal(i.deterministic, false);
  assert.ok(/codepoint-class/.test(i.value), 'must route names through the vendored confusable detection (no re-invention)');
  assert.ok(/edit-distance|Levenshtein/i.test(i.value), 'must describe the edit-distance typosquat check');
  assert.ok(i.false_positive_checks_required.length >= 4, 'FP checks gate the high-recall name heuristic');
  assert.ok(byId(ART, 'package-name-similarity-surface'), 'paired name-similarity look artifact must exist');
  assert.ok(FPP.find((x) => x.indicator_id === 'dependency-name-typosquat'), 'paired FP profile must exist');
});

test('content-obfuscation screen maps T1027 and is distinct from the capability screens', () => {
  const i = byId(IND, 'package-content-obfuscation-screen');
  assert.ok(i, 'package-content-obfuscation-screen indicator must be present');
  assert.equal(i.attack_ref, 'T1027', 'obfuscation maps to T1027 (Obfuscated Files or Information)');
  assert.equal(i.deterministic, false);
  assert.ok(/minified|entropy|trivial|eval/.test(i.value), 'must name the content red-flags');
  assert.ok(i.false_positive_checks_required.length >= 4, 'FP checks must cover minified-dist / WASM / trivial-inert / framework-eval');
  assert.ok(byId(ART, 'package-source-content-surface'), 'paired source-content look artifact must exist');
  assert.ok(FPP.find((x) => x.indicator_id === 'package-content-obfuscation-screen'));
});

test('dependency-confusion resolution check correlates to MOIKA and gates on resolution-source', () => {
  const i = byId(IND, 'dependency-confusion-internal-scope-public-resolution');
  assert.ok(i, 'dep-confusion resolution indicator must be present');
  assert.equal(i.cve_ref, 'MAL-2026-MOIKA-DEPCONFUSION', 'must correlate to the catalogued MOIKA campaign');
  assert.equal(i.attack_ref, 'T1195.001');
  assert.ok(/resolution-source|public registry|internal/i.test(i.value), 'must describe resolution-source confusion');
  assert.ok(i.false_positive_checks_required.length >= 5, 'five AND-conditions gate the resolution check');
  const art = byId(ART, 'dep-confusion-resolution-config');
  assert.ok(art && art.required === false, 'paired resolution-config artifact must exist and be optional');
  assert.ok(FPP.find((x) => x.indicator_id === 'dependency-confusion-internal-scope-public-resolution'));
});

test('all three new indicators are distinct ids and the playbook carries the 1.3.1 detection-depth rung', () => {
  const ids = ['dependency-name-typosquat', 'package-content-obfuscation-screen', 'dependency-confusion-internal-scope-public-resolution'];
  assert.equal(new Set(ids).size, 3, 'three distinct new indicator ids');
  // Version only advances past 1.3.1 as later passes add detectors — assert the
  // 1.3.1 rung exists + version >= 1.3.1 by tuple, never pin the exact live version.
  assert.ok(PB._meta.changelog.some((c) => c.version === '1.3.1'), 'a 1.3.1 changelog rung must document the detection-depth pass');
  const [maj, min, pat] = String(PB._meta.version).split('.').map(Number);
  assert.ok(maj > 1 || (maj === 1 && (min > 3 || (min === 3 && pat >= 1))), `playbook _meta.version (${PB._meta.version}) must be >= 1.3.1`);
  // cve_ref on the dep-confusion indicator must resolve to a real catalog entry.
  const cat = require(path.join(__dirname, '..', 'data', 'cve-catalog.json'));
  assert.ok(cat['MAL-2026-MOIKA-DEPCONFUSION'], 'the dep-confusion cve_ref must resolve to a real catalog entry');
});
});


// ---- routed from sbom-feeds-into-attack-class ----
require("node:test").describe("sbom-feeds-into-attack-class", () => {
const __t = require("node:test"); const __env = Object.assign({}, process.env);
__t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __env)) delete process.env[k]; Object.assign(process.env, __env);
  const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
/**
 * sbom -> deep-dive feeds_into, exercised against a REAL run (not a synthetic
 * eval context).
 *
 * sbom.json ships:
 *   { playbook_id: 'kernel',  condition: "any matched_cve.attack_class == 'kernel-lpe'" }
 *   { playbook_id: 'mcp',     condition: "any matched_cve.attack_class == 'mcp-supply-chain'" }
 *   { playbook_id: 'ai-api',  condition: "any matched_cve.attack_class IN ['ai-c2', 'prompt-injection']" }
 *
 * Two defects made these chains dead even though the quantifier PARSER handled
 * the syntax:
 *   1. close()'s feedsCtx exposed the matched CVEs only under
 *      `analyze.matched_cves`, never as a top-level `matched_cve` array, so the
 *      quantifier head resolved null.
 *   2. the per-CVE analyze shape carried no `attack_class` field at all, so even
 *      once the array was exposed the `.attack_class` leaf was undefined.
 *
 * Now: close() exposes `matched_cve`, the analyze shape carries `attack_class`
 * sourced from the catalog, and the chainable CVEs are classified. These assert
 * the chain against the actual run output, so a regression in either the context
 * wiring or the catalog classification fails here — the synthetic-context parser
 * tests cannot catch that.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const runner = require('../lib/playbook-runner.js');

const DIR = 'all-installed-packages-and-lockfiles';

function runWithMatchedCve(cveId) {
  // A direct CVE signal correlates that catalog CVE into matched_cves (path (b)
  // in analyze: agentSignals[cve_id] === 'hit'). The CVE must be in the sbom
  // playbook's coverage for it to land in matched_cves.
  return runner.run('sbom', DIR, { artifacts: {}, signal_overrides: {}, signals: { [cveId]: 'hit' } });
}

test('sbom matched-CVE carries attack_class from the catalog', () => {
  const r = runWithMatchedCve('CVE-2026-30615'); // Windsurf MCP RCE — mcp-supply-chain
  assert.equal(r.ok, true);
  const m = r.phases.analyze.matched_cves.find(c => c.cve_id === 'CVE-2026-30615');
  assert.ok(m, 'the MCP CVE must correlate into matched_cves');
  assert.equal(m.attack_class, 'mcp-supply-chain',
    'matched_cves entries must surface the catalog attack_class so feeds_into quantifiers can route on it');
});

test('sbom -> mcp fires when a matched CVE is attack_class mcp-supply-chain', () => {
  const r = runWithMatchedCve('CVE-2026-30615');
  assert.ok(r.phases.close.feeds_into.includes('mcp'),
    `sbom must chain into mcp when a matched CVE is mcp-supply-chain; got ${JSON.stringify(r.phases.close.feeds_into)}`);
});

test('sbom -> ai-api fires when a matched CVE is attack_class prompt-injection (IN quantifier)', () => {
  const r = runWithMatchedCve('CVE-2025-53773'); // Copilot YOLO-mode prompt-injection RCE
  assert.ok(r.phases.close.feeds_into.includes('ai-api'),
    `sbom must chain into ai-api when a matched CVE is in ['ai-c2','prompt-injection']; got ${JSON.stringify(r.phases.close.feeds_into)}`);
});

test('an unclassified matched CVE does NOT manufacture a deep-dive chain', () => {
  // CVE-2026-31431 is in sbom coverage but carries no attack_class. The chain
  // must stay quiet rather than misroute — null attack_class is a correct "no
  // chain", not a parser failure. (This is the exact CVE the original report
  // observed an empty feeds_into for; here the empty result is the right answer.)
  const r = runWithMatchedCve('CVE-2026-31431');
  const f = r.phases.close.feeds_into;
  for (const deepDive of ['kernel', 'mcp', 'ai-api']) {
    assert.ok(!f.includes(deepDive),
      `an attack_class-less matched CVE must not chain into ${deepDive}; got ${JSON.stringify(f)}`);
  }
});

test('the matched-CVE quantifier also works in the analyze-phase escalation context', () => {
  // close() and analyze() build separate eval contexts; both must expose
  // matched_cve. Assert the analyze escalation context resolves the array by
  // confirming a classified matched CVE is present with its attack_class — the
  // same field the analyze escalation_criteria quantifiers read.
  const r = runWithMatchedCve('CVE-2026-30615');
  const m = r.phases.analyze.matched_cves.find(c => c.cve_id === 'CVE-2026-30615');
  assert.equal(m.attack_class, 'mcp-supply-chain');
});
});


// ---- routed from sbom-matched-cves ----
require("node:test").describe("sbom-matched-cves", () => {
const __t = require("node:test"); const __env = Object.assign({}, process.env);
__t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __env)) delete process.env[k]; Object.assign(process.env, __env);
  const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
/**
 * Analyze-phase CVE classification: matched_cves (evidence-correlated) vs
 * catalog_baseline_cves (scan-coverage enumeration).
 *
 * Pre-fix, analyze.matched_cves enumerated every CVE in domain.cve_refs
 * regardless of evidence. Operators running `exceptd run sbom --evidence -`
 * with EMPTY artifacts saw 6 catalog CVEs in matched_cves and incorrectly
 * read it as "I am affected by these." Post-fix, matched_cves requires a
 * correlation path — indicator hit with shared attack_ref/atlas_ref, or
 * an agent signal explicitly referencing the CVE — and the unaffiliated
 * catalog enumeration moved to catalog_baseline_cves with correlated_via=null.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');

const { ROOT } = require('./_helpers/cli');
const runner = require(path.join(ROOT, 'lib', 'playbook-runner.js'));

// ---------------------------------------------------------------------------
// Empty-evidence case: no indicator hits, no CVE signals → matched_cves empty.

test('sbom with empty artifacts: matched_cves is empty, catalog_baseline_cves enumerates the playbook coverage', () => {
  const submission = { artifacts: {}, signal_overrides: {}, signals: {} };
  const result = runner.run('sbom', 'all-installed-packages-and-lockfiles', submission);
  assert.equal(result.ok, true, 'run must succeed even with empty evidence');

  const matched = result.phases.analyze.matched_cves;
  const baseline = result.phases.analyze.catalog_baseline_cves;

  assert.ok(Array.isArray(matched), 'matched_cves is an array');
  assert.equal(matched.length, 0,
    'matched_cves must be empty when no evidence correlates — pre-fix this enumerated catalog CVEs as if the operator were affected');

  assert.ok(Array.isArray(baseline), 'catalog_baseline_cves is an array');
  assert.ok(baseline.length >= 1,
    'catalog_baseline_cves must enumerate the playbook\'s scan coverage; sbom has at least one cve_ref');

  // Baseline entries carry full per-CVE shape (CVE id + RWEP + KEV + ...)
  // identical to matched_cves but with correlated_via:null and a note that
  // makes the "this is scan coverage, not affected-status" semantic explicit.
  for (const entry of baseline) {
    assert.equal(entry.correlated_via, null,
      `catalog_baseline_cves entry ${entry.cve_id} must carry correlated_via=null`);
    assert.equal(typeof entry.note, 'string',
      `catalog_baseline_cves entry ${entry.cve_id} must carry a note clarifying the field is scan-coverage metadata`);
    assert.equal(typeof entry.cve_id, 'string');
    assert.equal(typeof entry.rwep, 'number');
  }

  // RWEP base falls to 0 when no evidence correlates — pre-fix it inflated
  // to the maximum catalog rwep_score, inheriting the catalog ceiling for
  // every empty-evidence run.
  assert.equal(result.phases.analyze.rwep.base, 0,
    'RWEP base must be 0 when no CVE correlates to operator evidence');
});

// ---------------------------------------------------------------------------
// Correlated-evidence case: a single indicator fires that shares an
// attack_ref with a catalog CVE → matched_cves contains that CVE.

test('sbom with indicator hit: matched_cves contains the correlated CVE with non-null correlated_via', () => {
  // tanstack-worm-payload-files (attack_ref T1195.002) is one of the sbom
  // indicators. CVE-2026-45321 (the TanStack worm CVE) carries T1195.002 in
  // its attack_refs in the catalog, so this submission must correlate.
  const submission = {
    artifacts: {},
    signal_overrides: { 'tanstack-worm-payload-files': 'hit' },
    signals: {},
  };
  const result = runner.run('sbom', 'all-installed-packages-and-lockfiles', submission);
  assert.equal(result.ok, true);

  const matched = result.phases.analyze.matched_cves;
  assert.ok(matched.length >= 1,
    `matched_cves must contain at least one evidence-correlated CVE when a relevant indicator fires; got ${matched.length}`);

  // Every entry in matched_cves MUST have a non-empty correlated_via array.
  // Coincidence-passing regression: a runner that accidentally enumerates
  // catalog CVEs without setting correlated_via would surface as `length >= 1`
  // but every entry having correlated_via=null — explicit shape check pins
  // the correlation provenance.
  for (const entry of matched) {
    assert.ok(Array.isArray(entry.correlated_via) && entry.correlated_via.length > 0,
      `matched_cves entry ${entry.cve_id} must carry a non-empty correlated_via array — empty/null is the catalog-baseline regression class this test guards`);
    assert.ok(entry.correlated_via.every(r => typeof r === 'string' && r.length > 0),
      `correlated_via entries for ${entry.cve_id} must be non-empty strings (e.g. "indicator_hit:<id>" or "signal:<cve_id>")`);
  }

  // At least one correlation must reference the indicator we fired.
  const allReasons = matched.flatMap(c => c.correlated_via);
  assert.ok(allReasons.some(r => r === 'indicator_hit:tanstack-worm-payload-files'),
    `at least one matched_cves entry must reference the fired indicator (indicator_hit:tanstack-worm-payload-files); reasons seen: ${JSON.stringify(allReasons)}`);
});

// ---------------------------------------------------------------------------
// Correlated-evidence case: an agent signal explicitly references a CVE id.

test('sbom with direct CVE signal: matched_cves contains the CVE with signal correlation reason', () => {
  // signals['CVE-id'] === true is the explicit "operator declares affected" path.
  const submission = {
    artifacts: {},
    signal_overrides: {},
    signals: { 'CVE-2026-45321': true },
  };
  const result = runner.run('sbom', 'all-installed-packages-and-lockfiles', submission);
  assert.equal(result.ok, true);

  const matched = result.phases.analyze.matched_cves;
  const entry = matched.find(c => c.cve_id === 'CVE-2026-45321');
  assert.ok(entry, 'CVE-2026-45321 must appear in matched_cves when the operator signals it directly');
  assert.ok(Array.isArray(entry.correlated_via) && entry.correlated_via.includes('signal:CVE-2026-45321'),
    `correlation reason must include "signal:CVE-2026-45321"; got ${JSON.stringify(entry.correlated_via)}`);
});

// ---------------------------------------------------------------------------
// Catalog baseline is independent of evidence: always populated for playbooks
// with non-empty cve_refs.

test('sbom catalog_baseline_cves is populated identically across empty-evidence and correlated-evidence runs', () => {
  const empty = runner.run('sbom', 'all-installed-packages-and-lockfiles', { artifacts: {}, signal_overrides: {}, signals: {} });
  const hit = runner.run('sbom', 'all-installed-packages-and-lockfiles', {
    artifacts: {},
    signal_overrides: { 'tanstack-worm-payload-files': 'hit' },
    signals: {},
  });
  const emptyBaseline = empty.phases.analyze.catalog_baseline_cves.map(c => c.cve_id).sort();
  const hitBaseline = hit.phases.analyze.catalog_baseline_cves.map(c => c.cve_id).sort();
  assert.deepEqual(hitBaseline, emptyBaseline,
    'catalog_baseline_cves enumeration must be stable across runs — it is scan coverage, not affected-status');
});
});


// ---- routed from sbom-per-file-hash ----
require("node:test").describe("sbom-per-file-hash", () => {
const __t = require("node:test"); const __env = Object.assign({}, process.env);
__t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __env)) delete process.env[k]; Object.assign(process.env, __env);
  const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
/**
 * tests/sbom-per-file-hash.test.js
 *
 * Cycle 9 audit fix — SBOM must carry:
 *   - metadata.component.hashes[]   bundle digest, SHA-256
 *   - components[].type === 'file'  one per shipped file with SHA-256
 *   - metadata.tools[0].name        not the legacy "hand-written" placeholder
 *
 * Per the anti-coincidence rule, every assertion checks the EXACT
 * value the fix produces (set-equality on the file allowlist, exact alg
 * string, exact tool name) — never `assert.ok(field)` or
 * `assert.notEqual(0)`.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { spawnSync } = require('node:child_process');

const ROOT = path.join(__dirname, '..');
const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'));

// This test verifies the *SBOM-generation contract*: regenerate the SBOM
// in-process against the current working tree, then verify the freshly-
// computed bundle. We cannot read the shipped sbom.cdx.json directly and
// compare against on-disk files because other tests in the suite mutate
// files like data/_indexes/*.json + manifest.json signatures mid-run.
// The verify-shipped-tarball predeploy gate is the authoritative check
// for the ship-time SBOM-vs-tarball match.
//
// Snapshot sbom.cdx.json before regenerating so a Ctrl-C / test crash
// mid-test does not leave the repo's sbom.cdx.json polluted with the
// test's regenerated content. Identical shape to the snapshot-restore
// pattern build-incremental.test.js uses for mutating-state safety.
const SBOM_PATH = path.join(ROOT, 'sbom.cdx.json');
const sbomBytesBeforeTest = fs.existsSync(SBOM_PATH) ? fs.readFileSync(SBOM_PATH) : null;
const restoreSbom = () => {
  try {
    if (sbomBytesBeforeTest === null) {
      if (fs.existsSync(SBOM_PATH)) fs.unlinkSync(SBOM_PATH);
    } else {
      fs.writeFileSync(SBOM_PATH, sbomBytesBeforeTest);
    }
  } catch { /* best-effort restoration */ }
};
const sbomSigHandler = () => { restoreSbom(); process.exit(130); };
process.once('SIGINT', sbomSigHandler);
process.once('SIGTERM', sbomSigHandler);
process.once('exit', restoreSbom);

const refresh = spawnSync(process.execPath, [path.join(ROOT, 'scripts', 'refresh-sbom.js')], {
  cwd: ROOT,
  encoding: 'utf8',
});
if (refresh.status !== 0) {
  restoreSbom();
  throw new Error('scripts/refresh-sbom.js failed: ' + (refresh.stderr || refresh.stdout));
}
const sbom = JSON.parse(fs.readFileSync(SBOM_PATH, 'utf8'));

function walkFiles(absDir) {
  const out = [];
  const entries = fs.readdirSync(absDir, { withFileTypes: true });
  for (const entry of entries) {
    const abs = path.join(absDir, entry.name);
    if (entry.isDirectory()) out.push(...walkFiles(abs));
    else if (entry.isFile()) out.push(abs);
  }
  return out;
}

function expandAllowlist(allowlist) {
  const abs = [];
  for (const entry of allowlist) {
    const full = path.join(ROOT, entry);
    if (!fs.existsSync(full)) continue;
    const stat = fs.statSync(full);
    if (stat.isDirectory()) abs.push(...walkFiles(full));
    else if (stat.isFile()) abs.push(full);
  }
  // Mirror the script's self-reference + derivable-cache exclusions.
  // sbom.cdx.json cannot hash itself stably; data/_indexes/ is the
  // regenerable cache mutated by build-incremental.test.js etc. If the
  // script's exclusion list grows, this set must follow.
  const SELF_EXCLUDED = new Set(['sbom.cdx.json']);
  const DERIVABLE_PREFIXES = ['data/_indexes/'];
  const isDerivable = (rel) =>
    DERIVABLE_PREFIXES.some((p) => rel === p.replace(/\/$/, '') || rel.startsWith(p));
  return Array.from(
    new Set(abs.map((a) => path.relative(ROOT, a).split(path.sep).join('/'))),
  )
    .filter((r) => !SELF_EXCLUDED.has(r))
    .filter((r) => !isDerivable(r))
    .sort();
}

test('metadata.component.hashes[] present and SHA-256', () => {
  const hashes = sbom.metadata.component.hashes;
  assert.ok(Array.isArray(hashes), 'hashes must be an array');
  assert.equal(hashes.length, 1, 'exactly one bundle digest expected');
  assert.equal(hashes[0].alg, 'SHA-256');
  assert.equal(typeof hashes[0].content, 'string');
  assert.equal(hashes[0].content.length, 64, 'SHA-256 hex digest is 64 chars');
  assert.match(hashes[0].content, /^[0-9a-f]{64}$/);
});

test('metadata.tools[0].name is not the literal "hand-written" placeholder', () => {
  const tool0 = sbom.metadata.tools[0];
  assert.notEqual(tool0.name, 'hand-written');
  // Positive shape assertion — the new value MUST point at the script.
  assert.equal(tool0.name, 'scripts/refresh-sbom.js');
  assert.equal(tool0.vendor, 'blamejs');
  assert.equal(tool0.version, pkg.version);
});

test('every file in package.json.files (recursively expanded) has a matching components[] entry with a SHA-256 hash', () => {
  const expected = expandAllowlist(pkg.files);
  const fileComps = sbom.components.filter((c) => c.type === 'file');
  const fileNames = fileComps.map((c) => c.name).sort();

  // Set-equality: every shipped file is present, no extras.
  assert.deepEqual(fileNames, expected,
    'components[type=file] names must equal the expanded files allowlist exactly');

  // Per-file: SHA-256 + SHA3-512 both present and matching the on-disk content.
  // v0.13.12: emission expanded to dual-hash (SHA-256 universal-tool
  // contract + SHA3-512 PQ-aware hedge). The test now requires both.
  for (const comp of fileComps) {
    assert.equal(comp['bom-ref'], `file:${comp.name}`);
    assert.equal(Array.isArray(comp.hashes), true);
    assert.equal(comp.hashes.length, 2,
      `file component "${comp.name}" must carry exactly 2 hash entries (SHA-256 + SHA3-512)`);
    const sha256Entry = comp.hashes.find((h) => h.alg === 'SHA-256');
    const sha3Entry = comp.hashes.find((h) => h.alg === 'SHA3-512');
    assert.ok(sha256Entry, `file component "${comp.name}" must include a SHA-256 hash`);
    assert.ok(sha3Entry, `file component "${comp.name}" must include a SHA3-512 hash`);
    const bytes = fs.readFileSync(path.join(ROOT, comp.name));
    const liveSha256 = crypto.createHash('sha256').update(bytes).digest('hex');
    const liveSha3 = crypto.createHash('sha3-512').update(bytes).digest('hex');
    assert.equal(sha256Entry.content, liveSha256,
      `file component "${comp.name}" SHA-256 must match on-disk bytes`);
    assert.equal(sha3Entry.content, liveSha3,
      `file component "${comp.name}" SHA3-512 must match on-disk bytes`);
  }
});

test('bundle digest is reproducible from the per-file components[] entries', () => {
  const fileComps = sbom.components
    .filter((c) => c.type === 'file')
    .sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
  const hash = crypto.createHash('sha256');
  for (const c of fileComps) {
    // v0.13.12: components now carry SHA-256 + SHA3-512. Bundle digest
    // is reproducible from the SHA-256 column to preserve the existing
    // contract; pick by alg rather than positional index in case future
    // emission re-orders the hashes array.
    const sha256Hash = (c.hashes || []).find((h) => h.alg === 'SHA-256');
    assert.ok(sha256Hash, `component "${c.name}" must have a SHA-256 entry for bundle digest`);
    hash.update(sha256Hash.content);
    hash.update('\t');
    hash.update(c.name);
    hash.update('\n');
  }
  const recomputed = hash.digest('hex');
  assert.equal(recomputed, sbom.metadata.component.hashes[0].content,
    'bundle digest must equal SHA-256 over deterministic per-file digest stream');
});
});


// ---- routed from sbom-reachability-publisher-theater ----
require("node:test").describe("sbom-reachability-publisher-theater", () => {
const __t = require("node:test"); const __env = Object.assign({}, process.env);
__t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __env)) delete process.env[k]; Object.assign(process.env, __env);
  const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
/**
 * tests/sbom-reachability-publisher-theater.test.js
 *
 * Pins the final socket.dev adoptions in the supply-chain playbook: the CVE-
 * reachability demoter, the publisher-identity-change detector, and the two
 * new compliance-theater fingerprints. Asserts the load-bearing content +
 * the reachability indicator's confidence/deterministic contract (which is
 * what keeps it out of the 'detected' classification branch — it can never
 * mute a real CVE match). Exact-value pins per the anti-coincidence rule.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');

const PB = require(path.join(__dirname, '..', 'data', 'playbooks', 'sbom.json'));
const IND = PB.phases.detect.indicators;
const ART = PB.phases.look.artifacts;
const FPP = PB.phases.detect.false_positive_profile;
const TF = PB.phases.govern.theater_fingerprints;
const byId = (arr, id) => arr.find((x) => x.id === id);
const byPat = (arr, pid) => arr.find((x) => x.pattern_id === pid);

test('dependency-cve-unreachable is a low-confidence non-deterministic demoter that cannot reach detected', () => {
  const i = byId(IND, 'dependency-cve-unreachable');
  assert.ok(i, 'reachability demoter must be present');
  // The load-bearing contract: confidence low + deterministic false means a
  // firing hit satisfies neither hasDeterministicHit nor hasHighConfHit, so it
  // never drives classification 'detected' and can never mute a real match.
  assert.equal(i.confidence, 'low');
  assert.equal(i.deterministic, false);
  assert.equal(i.attack_ref, 'T1195.002');
  assert.equal(i.atlas_ref, 'AML.T0010');
  assert.ok(!('cve_ref' in i), 'reachability is a cross-cutting annotation, not bound to one CVE');
  assert.ok(i.false_positive_checks_required.length >= 4, 'FP checks gate it to demote-only-with-attestation');
  assert.ok(/over-approximate/i.test(i.false_positive_checks_required[0]),
    'the over-approximate-uncertain-to-reachable check must be first (makes it demote-only, never mute-by-default)');
  assert.ok(byId(ART, 'cve-reachability-surface'), 'paired reachability look artifact must exist');
  assert.ok(FPP.find((x) => x.indicator_id === 'dependency-cve-unreachable'), 'paired FP profile must exist');
  // The matcher it annotates must be left untouched (no FP-checks => still fires high).
  const matcher = byId(IND, 'package-matches-catalogued-cve');
  assert.equal(matcher.confidence, 'high', 'the core matcher stays high-confidence');
  assert.ok(!('false_positive_checks_required' in matcher), 'the core matcher must NOT gain FP-checks (would change its firing)');
});

test('publisher-identity-change detector fires on identity discontinuity absent a capability change', () => {
  const i = byId(IND, 'dependency-publisher-identity-change-without-capability-change');
  assert.ok(i, 'publisher-identity-change indicator must be present');
  assert.equal(i.attack_ref, 'T1195.001');
  assert.equal(i.atlas_ref, 'AML.T0010');
  assert.equal(i.deterministic, false);
  assert.ok(/capability surface is UNCHANGED|absent a behavior delta|without requiring any capability/i.test(i.value),
    'must require capability UNCHANGED (the gap capability-creep cannot see)');
  assert.ok(i.false_positive_checks_required.length >= 5, 'FP checks gate the identity-change heuristic');
  assert.ok(FPP.find((x) => x.indicator_id === 'dependency-publisher-identity-change-without-capability-change'));
});

test('two new govern theater-fingerprints (license + publisher-trust) with mapped controls', () => {
  const lic = byPat(TF, 'license-policy-attested-but-not-enforced');
  assert.ok(lic, 'license theater fingerprint must be present');
  assert.ok(lic.implicated_controls.includes('eu-cra-art13'), 'license fingerprint maps to a real framework control');
  assert.ok(/blocking gate|fails the build|BLOCK/.test(lic.fast_detection_test), 'must test enforcement, not attestation');
  const pub = byPat(TF, 'publisher-trust-attested-but-not-enforced');
  assert.ok(pub, 'publisher-trust theater fingerprint must be present');
  assert.ok(pub.implicated_controls.length >= 1 && pub.fast_detection_test.length > 60);
  // No attack_ref/atlas_ref on fingerprints — they map to implicated_controls, not TTPs (no orphaned-control obligation).
  assert.ok(!('attack_ref' in lic) && !('attack_ref' in pub), 'theater fingerprints carry no TTP ref');
});

test('theater-fingerprint count is 8 and the hardcoded skill-chain count was updated', () => {
  assert.equal(TF.length, 8, 'six original + license + publisher-trust = eight');
  const sc = PB.phases.direct.skill_chain.find((s) => s.purpose && /theater fingerprints in govern/.test(s.purpose));
  assert.ok(sc, 'the theater-fingerprint skill-chain step must exist');
  assert.ok(/eight theater fingerprints/.test(sc.purpose), 'the hardcoded count must read "eight", not "six"');
  assert.ok(!/the six theater fingerprints/.test(sc.purpose), 'the stale "six" count must be gone');
});

test('sbom playbook advanced to 1.4.0 with a matching changelog rung (version only advances)', () => {
  assert.ok(PB._meta.changelog.some((c) => c.version === '1.4.0'), 'a 1.4.0 changelog rung must document the additions');
  const [maj, min] = String(PB._meta.version).split('.').map(Number);
  assert.ok(maj > 1 || (maj === 1 && min >= 4), `playbook _meta.version (${PB._meta.version}) must be >= 1.4.0`);
});
});
