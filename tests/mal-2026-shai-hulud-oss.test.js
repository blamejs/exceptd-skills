'use strict';

/**
 * tests/mal-2026-shai-hulud-oss.test.js
 *
 * Per-subject coverage for MAL-2026-SHAI-HULUD-OSS (the Shai-Hulud OSS
 * supply-chain wave). Combines: the doctor --ai-config control_reference
 * (NEW-CTRL-050 lesson), the watchlist --org-scan control_reference
 * (NEW-CTRL-052 lesson) + default-pattern count, the watchlist --alerts
 * supply_chain_family surfacing, the Package-Confidence Score invariants, the
 * lightning/PyPI sub-incident enrichment, and the offline alias resolution of
 * the folded-in CVE-2026-44484.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const ROOT = path.join(__dirname, '..');
const CLI = path.join(ROOT, 'bin', 'exceptd.js');
const scoring = require(path.join(ROOT, 'lib', 'scoring.js'));
const CAT = require(path.join(ROOT, 'data', 'cve-catalog.json'));
const { resolveCve } = require(path.join(ROOT, 'lib', 'citation-resolve.js'));

const ID = 'MAL-2026-SHAI-HULUD-OSS';

function cli(args, opts = {}) {
  return spawnSync(process.execPath, [CLI, ...args], {
    encoding: 'utf8',
    cwd: ROOT,
    timeout: 30000,
    env: { ...process.env, EXCEPTD_DEPRECATION_SHOWN: '1', ...(opts.env || {}) },
    input: opts.input,
  });
}
function tryJson(s) { try { return JSON.parse(s); } catch { return null; } }

// ---------------------------------------------------------------------------
// doctor --ai-config control_reference (cli / v0_13_3-fixes)
// ---------------------------------------------------------------------------

test('doctor --ai-config control_reference cites the MAL-2026-SHAI-HULUD-OSS lesson', () => {
  const r = cli(['doctor', '--ai-config', '--json']);
  const body = tryJson(r.stdout);
  assert.ok(body, `expected JSON; got ${r.stdout.slice(0, 200)}`);
  assert.equal(body.verb, 'doctor');
  assert.ok(body.checks && body.checks.ai_config, 'checks.ai_config must be present');
  const c = body.checks.ai_config;
  assert.equal(typeof c.scanned_dirs, 'number');
  assert.equal(typeof c.scanned_files, 'number');
  assert.ok(Array.isArray(c.directories_inspected));
  assert.ok(c.directories_inspected.includes('~/.claude'), 'must include ~/.claude in inspected dirs');
  assert.ok(c.directories_inspected.includes('~/.cursor'), 'must include ~/.cursor in inspected dirs');
  assert.ok(c.directories_inspected.includes('~/.codeium'), 'must include ~/.codeium in inspected dirs');
  assert.ok(Array.isArray(c.sensitive_patterns));
  assert.ok(Array.isArray(c.findings));
  assert.equal(c.control_reference, 'NEW-CTRL-050 (MAL-2026-SHAI-HULUD-OSS lesson)');
  assert.ok(['win32', 'darwin', 'linux', 'freebsd', 'openbsd', 'sunos', 'aix'].includes(c.platform));
});

// ---------------------------------------------------------------------------
// watchlist --org-scan control_reference + default-pattern count
// ---------------------------------------------------------------------------

test('watchlist --org-scan: NEW-CTRL-052 control_reference cites the Shai-Hulud lesson', () => {
  const r = cli(['watchlist', '--org-scan', '--org', 'exceptd-test-ctrl-ref', '--json'], {
    env: { ...process.env, GITHUB_TOKEN: '', EXCEPTD_DEPRECATION_SHOWN: '1' },
  });
  const body = tryJson(r.stdout.trim());
  assert.ok(body);
  assert.equal(body.control_reference, 'NEW-CTRL-052 (MAL-2026-SHAI-HULUD-OSS lesson)');
});

test('watchlist --org-scan: --pattern extends the default shai-hulud pattern set to 4', () => {
  const r = cli(['watchlist', '--org-scan', '--org', 'exceptd-test-pattern', '--pattern', 'custom-marker', '--json'], {
    env: { ...process.env, GITHUB_TOKEN: '', EXCEPTD_DEPRECATION_SHOWN: '1' },
  });
  const body = tryJson(r.stdout.trim());
  assert.ok(body);
  // The default set is 3 (shai-hulud-classic / teampcp-gift / teampcp-bare);
  // 1 custom pattern brings it to 4.
  assert.equal(body.patterns_evaluated, 4,
    `expected 4 patterns evaluated (3 defaults + 1 custom); got ${body.patterns_evaluated}`);
});

// ---------------------------------------------------------------------------
// watchlist --alerts: MAL-2026-SHAI-HULUD-OSS surfaces under supply_chain_family
// ---------------------------------------------------------------------------

test('watchlist --alerts: MAL-2026-SHAI-HULUD-OSS surfaces under supply_chain_family', () => {
  const r = cli(['watchlist', '--alerts', '--json']);
  const body = tryJson(r.stdout);
  assert.ok(body, `must emit parseable JSON; got: ${r.stdout.slice(0, 300)}`);
  const a = body.alerts.find((x) => x.cve_id === 'MAL-2026-SHAI-HULUD-OSS');
  assert.ok(a, 'MAL-2026-SHAI-HULUD-OSS must surface in alerts');
  const patternIds = a.patterns.map((p) => p.id);
  assert.ok(patternIds.includes('supply_chain_family'),
    `MAL-2026-SHAI-HULUD-OSS must match supply_chain_family; matched: ${patternIds.join(', ')}`);
});

// ---------------------------------------------------------------------------
// Package-Confidence Score (package-confidence)
// ---------------------------------------------------------------------------

test('MAL-2026-SHAI-HULUD-OSS carries a valid trust-polarity PCS that matches its inputs', () => {
  const e = CAT[ID];
  const pc = e.package_confidence;
  assert.ok(pc, `${ID} must carry package_confidence`);
  assert.equal(pc.polarity, 'trust', 'polarity const guards against summing with RWEP');
  assert.ok(Number.isInteger(pc.score) && pc.score >= 0 && pc.score <= 100, 'score is an integer in [0,100]');
  assert.equal(pc.score, scoring.packageConfidence(pc.inputs), `${ID} score must equal packageConfidence(inputs)`);
});

test('PCS does not perturb RWEP — MAL-2026-SHAI-HULUD-OSS still has rwep_score == sum(rwep_factors)', () => {
  const e = CAT[ID];
  const sum = Object.values(e.rwep_factors).reduce((a, b) => a + b, 0);
  assert.equal(e.rwep_score, sum, `${ID}: PCS must not change the RWEP sum invariant`);
});

test('resolveCve resolves a folded-in CVE alias to the Shai-Hulud campaign entry offline', async () => {
  const r = await resolveCve('CVE-2026-44484', { airGap: true });
  assert.equal(r.from, 'catalog-alias', 'must resolve via the alias index, not fall through to offline/unknown');
  assert.equal(r.aliased_to, 'MAL-2026-SHAI-HULUD-OSS');
  assert.equal(r.status, 'published', 'a catalogued-by-alias id resolves with the campaign status, not offline/unknown');
});

test('Shai-Hulud entry covers the PyPI lightning sub-incident', () => {
  const sh = CAT[ID];
  assert.ok(Array.isArray(sh.aliases) && sh.aliases.includes('CVE-2026-44484'),
    'lightning PyPI compromise (CVE-2026-44484) recorded as an alias of this wave');
  assert.ok(sh.affected_versions.some((v) => /lightning/i.test(v) && /2\.6\.2/.test(v)),
    'affected_versions must name lightning 2.6.2/2.6.3');
  assert.ok(sh.iocs && Array.isArray(sh.iocs.pypi_lightning_subincident),
    'iocs must carry the lightning sub-incident block (Bun-runtime infostealer)');
  assert.ok(sh.verification_sources.some((u) => /MAL-2026-3201/.test(u)),
    'verification_sources must cite the OSV lightning record');
});
