'use strict';
/**
 * tests/hunt-fix-D-validators.test.js
 *
 * Regression locks for five confirmed validator bugs (cluster D-validators):
 *
 *   #17 validate-catalog-meta: validateMeta returned a bare string[] on the
 *       missing-_meta early path while the includeWarnings caller read
 *       result.errors — main() crashed with an uncaught TypeError on the first
 *       no-_meta file, aborting the whole gate. Now the early return honors the
 *       caller's requested shape and the loop continues to later files.
 *
 *   #18 validate-cve-catalog: additionalChecks dereferenced entry.poc_available
 *       before any null guard — a null catalog entry crashed main(). Guarded at
 *       the top; the malformed-entry FAIL still originates in validate().
 *
 *   #19 validate-catalog-meta: the freshness gate silently SKIPPED when
 *       last_updated was unparseable (fail-open). A malformed/impossible date
 *       is now an error under --strict / warning by default; a valid-but-old
 *       date still reports stale.
 *
 *   #20 validate-playbooks: checkCrossRefs read playbook._meta before any null
 *       guard — a literal-null playbook file crashed main(). Guarded at the top.
 *
 *   #21 validate-playbooks: the air-gap network-source detector missed
 *       API-verb-phrased sources ("GET /... via Graph", "Entra ID", "Okta",
 *       "Microsoft Graph"); broadened so such a source under air_gap_mode with
 *       no air_gap_alternative is flagged at error severity — without
 *       over-firing on the shipped corpus.
 *
 * Each case fails on the pre-fix behavior and passes after. CLI-level cases use
 * a copied-into-tempdir mini-repo (validator + exit-codes + schemas + the data
 * it reads) so the real on-disk catalogs are never mutated.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const { spawnSync } = require('node:child_process');

const ROOT = path.join(__dirname, '..');

const catalogMeta = require(path.join(ROOT, 'lib', 'validate-catalog-meta.js'));
const cveCatalog = require(path.join(ROOT, 'lib', 'validate-cve-catalog.js'));
const playbooksMod = require(path.join(ROOT, 'lib', 'validate-playbooks.js'));

const { validateMeta, parseIsoDateStrict } = catalogMeta;
const { additionalChecks } = cveCatalog;
const { checkCrossRefs, loadContext, loadPlaybooks } = playbooksMod;

// --- tempdir mini-repo helpers ---------------------------------------------

function mkTmp(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

function writeJson(p, obj) {
  fs.mkdirSync(path.dirname(p), { recursive: true });
  // String content for the literal-null case is passed through verbatim.
  fs.writeFileSync(p, typeof obj === 'string' ? obj : JSON.stringify(obj));
}

function copyInto(dst, relPath) {
  const target = path.join(dst, relPath);
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.copyFileSync(path.join(ROOT, relPath), target);
}

function runNode(scriptPath, args) {
  return spawnSync(process.execPath, [scriptPath, ...args], { encoding: 'utf8' });
}

// ===========================================================================
// #17 — validate-catalog-meta missing-_meta early return honors both contracts
// ===========================================================================

test('#17 validateMeta(includeWarnings) on a no-_meta file returns {errors,warnings}, not a bare array', () => {
  const tmp = mkTmp('hfd17-direct-');
  try {
    const p = path.join(tmp, 'no-meta.json');
    writeJson(p, { some: 'data' });
    const r = validateMeta(p, { includeWarnings: true, strict: true });
    // Pre-fix this was a bare ['missing _meta block'] — r.errors was undefined.
    assert.equal(typeof r, 'object');
    assert.ok(Array.isArray(r.errors), 'r.errors must be an array under includeWarnings');
    assert.ok(Array.isArray(r.warnings), 'r.warnings must be an array under includeWarnings');
    assert.equal(r.errors.length, 1);
    assert.equal(r.errors[0], 'missing _meta block');
    assert.equal(r.warnings.length, 0);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test('#17 validateMeta() with no opts still returns a non-empty string[] for a no-_meta file', () => {
  const tmp = mkTmp('hfd17-noopts-');
  try {
    const p = path.join(tmp, 'no-meta.json');
    writeJson(p, { some: 'data' });
    const r = validateMeta(p, {});
    assert.ok(Array.isArray(r));
    assert.equal(r.length, 1);
    assert.equal(r[0], 'missing _meta block');
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test('#17 CLI: a no-_meta file sorted BEFORE a second invalid file FAILs cleanly and the loop continues', () => {
  const tmp = mkTmp('hfd17-cli-');
  try {
    copyInto(tmp, path.join('lib', 'validate-catalog-meta.js'));
    copyInto(tmp, path.join('lib', 'exit-codes.js'));
    // aaa.json lacks _meta (sorts first); zzz.json has a _meta block that fails
    // a downstream check (bad tlp) — its FAIL line appearing proves the loop did
    // not abort after the first file.
    writeJson(path.join(tmp, 'data', 'aaa.json'), { some: 'data' });
    writeJson(path.join(tmp, 'data', 'zzz.json'), { _meta: { tlp: 'BOGUS' } });

    const r = runNode(path.join(tmp, 'lib', 'validate-catalog-meta.js'), ['--strict']);
    // Exact exit code.
    assert.equal(r.status, 1);
    // No stack trace masking the failure (the pre-fix crash printed a TypeError
    // to stderr and produced empty stdout).
    assert.equal(r.stderr, '');
    assert.doesNotMatch(r.stdout, /TypeError|Cannot read properties of undefined/);
    assert.doesNotMatch(r.stderr, /TypeError|Cannot read properties of undefined/);
    // First file reported the clean failure...
    assert.match(r.stdout, /FAIL {2}aaa\.json/);
    assert.match(r.stdout, /missing _meta block/);
    // ...AND the loop continued to the second file (the load-bearing assertion).
    assert.match(r.stdout, /FAIL {2}zzz\.json/);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

// ===========================================================================
// #19 — freshness gate fails closed on a malformed last_updated
// ===========================================================================

function freshMeta(lastUpdated) {
  return {
    _meta: {
      tlp: 'CLEAR',
      source_confidence: { scheme: 'Admiralty', default: 'B2', note: 'curated catalog' },
      freshness_policy: {
        default_review_cadence_days: 30,
        stale_after_days: 90,
        rebuild_after_days: 180,
        note: 'review cadence for this catalog',
        ...(lastUpdated !== undefined ? {} : {}),
      },
      last_updated: lastUpdated,
    },
  };
}

function validateMetaObj(metaObj, opts) {
  // validateMeta reads from disk; stage a one-off file so we exercise the real
  // code path (including the JSON parse) without touching the repo tree.
  const tmp = mkTmp('hfd19-');
  try {
    const p = path.join(tmp, 'catalog.json');
    writeJson(p, metaObj);
    return validateMeta(p, opts);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
}

for (const bad of ['2026-13-99', '2026-04-31', 'unknown', 'soon', '2026/01/01', 123]) {
  test(`#19 malformed last_updated ${JSON.stringify(bad)} is an ERROR under --strict (was silently skipped)`, () => {
    const r = validateMetaObj(freshMeta(bad), { includeWarnings: true, strict: true });
    const hit = r.errors.filter((e) => /last_updated.*not a valid ISO date/.test(e));
    assert.equal(hit.length, 1, `expected exactly one date-validity error, got: ${JSON.stringify(r.errors)}`);
    // It must NOT have also produced a staleness finding for the same field.
    assert.equal(r.errors.filter((e) => /freshness:.*days old/.test(e)).length, 0);
  });

  test(`#19 malformed last_updated ${JSON.stringify(bad)} is a WARNING in default mode (observable, not silent)`, () => {
    const r = validateMetaObj(freshMeta(bad), { includeWarnings: true });
    assert.equal(r.errors.length, 0, `default mode must not error: ${JSON.stringify(r.errors)}`);
    const hit = r.warnings.filter((w) => /last_updated.*not a valid ISO date/.test(w));
    assert.equal(hit.length, 1, `expected exactly one date-validity warning, got: ${JSON.stringify(r.warnings)}`);
  });
}

test('#19 a valid-but-old last_updated still reports STALE (fix does not suppress real staleness)', () => {
  const r = validateMetaObj(freshMeta('1900-01-01'), { includeWarnings: true, strict: true });
  // The old date is a real calendar date, so it must reach the staleness branch,
  // NOT the date-validity branch.
  assert.equal(r.errors.filter((e) => /last_updated.*not a valid ISO date/.test(e)).length, 0);
  const stale = r.errors.filter((e) => /freshness:.*days old/.test(e));
  assert.equal(stale.length, 1, `expected the stale finding, got: ${JSON.stringify(r.errors)}`);
});

test('#19 a fresh (today) last_updated produces neither a validity nor a staleness finding', () => {
  const today = new Date().toISOString().slice(0, 10);
  const r = validateMetaObj(freshMeta(today), { includeWarnings: true, strict: true });
  assert.equal(r.errors.length, 0, `expected clean, got: ${JSON.stringify(r.errors)}`);
  assert.equal(r.warnings.length, 0, `expected clean, got: ${JSON.stringify(r.warnings)}`);
});

test('#19 parseIsoDateStrict rejects impossible dates and accepts real ones (no year floor)', () => {
  assert.equal(parseIsoDateStrict('2026-13-99'), null);
  assert.equal(parseIsoDateStrict('2026-04-31'), null);
  assert.equal(parseIsoDateStrict('2025-02-29'), null); // non-leap-year Feb 29
  assert.equal(parseIsoDateStrict('unknown'), null);
  assert.equal(parseIsoDateStrict('2026/01/01'), null);
  assert.equal(parseIsoDateStrict(123), null);
  assert.equal(parseIsoDateStrict(null), null);
  // Real dates round-trip; deliberately NO 1990 floor so old dates stay valid.
  assert.ok(parseIsoDateStrict('1900-01-01') instanceof Date);
  assert.ok(parseIsoDateStrict('2024-02-29') instanceof Date); // valid leap day
  assert.equal(parseIsoDateStrict('2024-01-15').getUTCFullYear(), 2024);
});

// ===========================================================================
// #18 — validate-cve-catalog additionalChecks null-entry guard
// ===========================================================================

test('#18 additionalChecks does not throw on a null entry and returns []', () => {
  const ctx = { atlasKeys: new Set(), cweKeys: new Set(), attackKeys: null, d3fendKeys: null, frameworkKeys: null };
  assert.doesNotThrow(() => additionalChecks('CVE-2026-00001', null, ctx));
  assert.deepEqual(additionalChecks('CVE-2026-00001', null, ctx), []);
  // Defense-in-depth: array / primitive entries also return [] (no checkable sub-fields).
  assert.deepEqual(additionalChecks('CVE-X', [], ctx), []);
  assert.deepEqual(additionalChecks('CVE-X', 'str', ctx), []);
  assert.deepEqual(additionalChecks('CVE-X', 42, ctx), []);
});

test('#18 additionalChecks still fires the Hard Rule #14 IoC warning for a real object entry', () => {
  const ctx = { atlasKeys: new Set(), cweKeys: new Set(), attackKeys: null, d3fendKeys: null, frameworkKeys: null };
  const entry = {
    poc_available: true,
    verification_sources: ['https://www.exploit-db.com/exploits/12345'],
    // no iocs -> Hard Rule #14 warning expected
  };
  const w = additionalChecks('CVE-2026-99999', entry, ctx);
  assert.ok(Array.isArray(w));
  assert.equal(w.filter((m) => /Hard Rule #14/.test(m)).length, 1, `expected the IoC warning, got: ${JSON.stringify(w)}`);
});

test('#18 CLI: a null catalog entry FAILs with the type error and does not crash', () => {
  const tmp = mkTmp('hfd18-cli-');
  try {
    copyInto(tmp, path.join('lib', 'validate-cve-catalog.js'));
    copyInto(tmp, path.join('lib', 'exit-codes.js'));
    copyInto(tmp, path.join('lib', 'schemas', 'cve-catalog.schema.json'));
    writeJson(path.join(tmp, 'data', 'cve-catalog.json'), { 'CVE-2026-00001': null });
    writeJson(path.join(tmp, 'data', 'zeroday-lessons.json'), {});

    const r = runNode(path.join(tmp, 'lib', 'validate-cve-catalog.js'), []);
    assert.equal(r.status, 1);
    assert.match(r.stdout, /expected type "object", got null/);
    assert.doesNotMatch(r.stdout, /TypeError|Cannot read properties of null/);
    assert.doesNotMatch(r.stderr, /TypeError|Cannot read properties of null/);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

// ===========================================================================
// #20 — validate-playbooks checkCrossRefs null-playbook guard
// ===========================================================================

test('#20 checkCrossRefs does not throw on a null playbook and returns []', () => {
  const ctx = loadContext();
  const ids = new Set(loadPlaybooks().filter((p) => p.data).map((p) => p.data._meta.id));
  assert.doesNotThrow(() => checkCrossRefs(null, ctx, ids));
  assert.deepEqual(checkCrossRefs(null, ctx, ids), []);
  // Array / primitive playbooks are also no-ops.
  assert.deepEqual(checkCrossRefs([], ctx, ids), []);
  assert.deepEqual(checkCrossRefs('nope', ctx, ids), []);
});

test('#20 CLI: a literal-null playbook file FAILs with the type error and does not crash', () => {
  const tmp = mkTmp('hfd20-cli-');
  try {
    copyInto(tmp, path.join('lib', 'validate-playbooks.js'));
    copyInto(tmp, path.join('lib', 'exit-codes.js'));
    copyInto(tmp, path.join('lib', 'schemas', 'playbook.schema.json'));
    copyInto(tmp, 'manifest.json');
    for (const f of ['atlas-ttps.json', 'cve-catalog.json', 'cwe-catalog.json', 'd3fend-catalog.json', 'attack-techniques.json']) {
      copyInto(tmp, path.join('data', f));
    }
    // The crashing input: a playbook file whose JSON content is literally null.
    writeJson(path.join(tmp, 'data', 'playbooks', 'synthetic.json'), 'null');

    const r = runNode(path.join(tmp, 'lib', 'validate-playbooks.js'), []);
    assert.equal(r.status, 1);
    assert.match(r.stdout, /expected type "object", got null/);
    assert.doesNotMatch(r.stdout, /TypeError|Cannot read properties of null/);
    assert.doesNotMatch(r.stderr, /TypeError|Cannot read properties of null/);
    // The summary line printed (process did not abort before the tail).
    assert.match(r.stdout, /playbooks validated/);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

// ===========================================================================
// #21 — air-gap network-source detector flags API-verb-phrased sources
// ===========================================================================

function minimalAirGapPlaybook(source, withAlt) {
  // Smallest playbook shape that exercises the air-gap completeness check in
  // checkCrossRefs. It needs a TTP mapping (atlas_refs) to avoid the unrelated
  // TTP-floor error muddying the assertion; we use the live atlas key set.
  const atlasKey = '__will_be_filled__';
  const art = { source };
  if (withAlt) art.air_gap_alternative = 'Local file already staged in cwd; read it directly.';
  return {
    _meta: { id: 'synthetic-airgap', air_gap_mode: true, scope: 'cross-cutting' },
    domain: {},
    phases: { look: { artifacts: [art] } },
    __atlasKey: atlasKey,
  };
}

function airGapFindings(source, withAlt) {
  const ctx = loadContext();
  const ids = new Set(['synthetic-airgap']);
  const pb = minimalAirGapPlaybook(source, withAlt);
  delete pb.__atlasKey;
  return checkCrossRefs(pb, ctx, ids).filter((f) => /air_gap_mode is true and source/.test(f.message));
}

test('#21 an API-verb-phrased source under air_gap_mode with no alternative is flagged at error severity', () => {
  const findings = airGapFindings('Entra ID: GET /directoryRoles via Graph', false);
  assert.equal(findings.length, 1, `expected exactly one air-gap finding, got: ${JSON.stringify(findings)}`);
  assert.equal(findings[0].severity, 'error');
  assert.match(findings[0].message, /air_gap_mode is true and source .* makes a network call/);
});

test('#21 the same API-verb source WITH an air_gap_alternative is silent', () => {
  const findings = airGapFindings('Entra ID: GET /directoryRoles via Graph', true);
  assert.deepEqual(findings, []);
});

test('#21 a purely-local source under air_gap_mode is silent (no over-firing)', () => {
  assert.deepEqual(airGapFindings('~/.ssh/config', false), []);
  assert.deepEqual(airGapFindings('Walk cwd for *.env files', false), []);
  // "api/v\\d" deliberately NOT a token: a local artifact referencing an API
  // path must not be misclassified as a network call.
  assert.deepEqual(airGapFindings('Code-scan: grep for /api/v2 callback handlers', false), []);
});

test('#21 the full shipped corpus still produces zero air-gap findings under the broadened regex', () => {
  const ctx = loadContext();
  const playbooks = loadPlaybooks();
  const ids = new Set(playbooks.filter((p) => p.data).map((p) => p.data._meta.id));
  const airGapHits = [];
  for (const pb of playbooks) {
    if (!pb.data) continue;
    const hits = checkCrossRefs(pb.data, ctx, ids).filter((f) =>
      /air_gap_mode is true and source/.test(f.message),
    );
    for (const h of hits) airGapHits.push(`${pb.file}: ${h.message}`);
  }
  assert.deepEqual(airGapHits, [], `broadened regex must not over-fire on the shipped corpus:\n${airGapHits.join('\n')}`);
});
