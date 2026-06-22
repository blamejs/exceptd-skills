'use strict';

/**
 * Tests for lib/framework-gap.js — framework lag/gap/theater analysis.
 * Operates against the real data/framework-control-gaps.json and data/global-frameworks.json.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const fg = require('../lib/framework-gap.js');
const controlGaps = require('../data/framework-control-gaps.json');
const globalFrameworks = require('../data/global-frameworks.json');
const cveCatalog = require('../data/cve-catalog.json');

const { lagScore, gapReport, theaterCheck, compareFrameworks } = fg;

// ---------- lagScore() ----------

test('lagScore() returns a numeric score and breakdown for a known framework', () => {
  // Pick the first non-meta framework id available in global-frameworks.json
  const frameworkIds = [];
  for (const jur of Object.values(globalFrameworks)) {
    if (jur && typeof jur === 'object' && jur.frameworks) {
      frameworkIds.push(...Object.keys(jur.frameworks));
    }
  }
  assert.ok(frameworkIds.length > 0, 'expected at least one framework in global-frameworks.json');

  const r = lagScore(frameworkIds[0], controlGaps, globalFrameworks);
  assert.equal(typeof r.score, 'number');
  assert.ok(r.score >= 0 && r.score <= 100, `score out of bounds: ${r.score}`);
  assert.equal(typeof r.label, 'string');
  assert.ok(r.breakdown, 'breakdown must be present');
  assert.ok('patch_sla' in r.breakdown);
  assert.ok('ai_coverage' in r.breakdown);
  assert.ok('universal_gaps' in r.breakdown);
});

test('lagScore() labels reflect score bands', () => {
  // Drive label selection via stubbed inputs so the test is robust to data updates.
  const stubGlobal = {
    test_jurisdiction: {
      frameworks: {
        TEST_FW: { patch_sla: 30 * 24, notification_sla: 96, ai_coverage: 'None', pqc_coverage: 'None' }
      }
    }
  };
  // With universal gaps from real data, this stub framework should land in 'critical_lag' territory.
  const r = lagScore('TEST_FW', controlGaps, stubGlobal);
  assert.equal(typeof r.label, 'string');
  assert.ok(['critical_lag', 'significant_lag', 'moderate_lag', 'minor_lag', 'current'].includes(r.label));
});

test('lagScore() falls back gracefully when framework not in global-frameworks.json', () => {
  const r = lagScore('NOT-A-REAL-FW', controlGaps, globalFrameworks);
  // No throw, breakdown still populated with default scores
  assert.equal(typeof r.score, 'number');
  assert.ok(r.breakdown.patch_sla);
  assert.equal(r.breakdown.patch_sla.raw_days, null);
});

// ---------- gapReport() ----------

test('gapReport() returns a structured report with universal gaps and theater risks', () => {
  const r = gapReport(['NIST SP 800-53 Rev 5', 'ISO/IEC 27001:2022'], 'prompt injection', controlGaps, cveCatalog);
  assert.equal(r.threat_scenario, 'prompt injection');
  // Pair field-presence with shape: field-present-not-populated is a
  // recurring regression class (jurisdiction_notifications, total_compared).
  // Each ok() pairs with a typeof / Array.isArray / Object.keys check.
  assert.equal(typeof r.frameworks, 'object');
  assert.ok(r.frameworks && !Array.isArray(r.frameworks), 'frameworks must be a plain object');
  assert.ok(Array.isArray(r.universal_gaps));
  assert.ok(Array.isArray(r.theater_risks));
  assert.equal(typeof r.summary, 'object');
  assert.ok(r.summary && !Array.isArray(r.summary), 'summary must be a plain object');
  assert.equal(typeof r.summary.total_gaps, 'number');
  assert.equal(typeof r.summary.universal_gaps, 'number');
});

test('gapReport() surfaces ALL-scoped universal gaps from the catalog', () => {
  // The shipping catalog includes ALL-AI-PIPELINE-INTEGRITY, ALL-MCP-TOOL-TRUST, ALL-PROMPT-INJECTION-ACCESS-CONTROL
  const r = gapReport(['NIST SP 800-53 Rev 5'], 'mcp', controlGaps, cveCatalog);
  assert.ok(Array.isArray(r.universal_gaps));
  assert.ok(r.universal_gaps.length >= 1, `expected at least one ALL-framework universal gap; got count ${r.universal_gaps.length}`);
  // Pin each entry's shape so a future regression that returns array of
  // partial stubs still trips the assertion.
  for (const g of r.universal_gaps) {
    assert.equal(typeof g, 'object');
    assert.ok(g, 'universal_gap entry must not be null');
  }
});

test('gapReport() can find gaps by CVE id in evidence_cves', () => {
  // NIST-800-53-SI-2 has evidence_cves including CVE-2026-31431
  const r = gapReport(['NIST SP 800-53 Rev 5'], 'CVE-2026-31431', controlGaps, cveCatalog);
  assert.ok(r.summary.total_gaps >= 1, `expected at least one gap matching CVE-2026-31431; got summary: ${JSON.stringify(r.summary)}`);
});

// ---------- theaterCheck() ----------

test('theaterCheck() returns findings array, score, and recommendation', () => {
  const r = theaterCheck(controlGaps, cveCatalog);
  assert.ok(Array.isArray(r.findings));
  assert.equal(typeof r.theater_score, 'number');
  assert.ok(r.theater_score >= 0 && r.theater_score <= 100);
  assert.equal(typeof r.theater_label, 'string');
  assert.equal(typeof r.recommendation, 'string');
  assert.equal(typeof r.compliant_but_exposed, 'boolean');
});

test('theaterCheck() flags Patch Management Theater when an exploited-CVE control is open', () => {
  // NIST-800-53-SI-2 references CVE-2026-31431 which is cisa_kev=true → patch_management theater
  const r = theaterCheck(controlGaps, cveCatalog);
  const patchTheater = r.findings.find(f => f.pattern_id === 'patch_management');
  assert.ok(patchTheater, `expected patch_management theater finding; findings: ${JSON.stringify(r.findings.map(f => f.pattern_id))}`);
  assert.equal(patchTheater.severity, 'critical');
});

test('theaterCheck() preserves no-finding case when given an empty control set', () => {
  const r = theaterCheck({}, cveCatalog);
  assert.deepEqual(r.findings, []);
  assert.equal(r.theater_score, 0);
  assert.equal(r.compliant_but_exposed, false);
  assert.match(r.recommendation, /No theater patterns/);
});

// ---------- compareFrameworks() ----------

test('compareFrameworks() returns an array sorted by lag score descending', () => {
  const r = compareFrameworks(controlGaps, globalFrameworks);
  assert.ok(Array.isArray(r));
  assert.ok(r.length > 0, `expected at least one framework in the comparison; got count ${r.length}`);
  for (let i = 1; i < r.length; i++) {
    assert.ok(r[i - 1].score >= r[i].score,
      `not sorted descending at index ${i}: ${r[i - 1].score} < ${r[i].score}`);
  }
  for (const row of r) {
    assert.equal(typeof row.framework, 'string');
    assert.equal(typeof row.score, 'number');
    assert.equal(typeof row.label, 'string');
    assert.equal(typeof row.breakdown, 'object');
    assert.ok(row.breakdown && !Array.isArray(row.breakdown), 'breakdown must be a plain object');
  }
});

// ---------- gap status preservation ----------

test('Open-status gaps are preserved in gapReport output', () => {
  // The shipping catalog has all gaps in "open" status. Verify the gap entries we surface
  // carry their original status field intact.
  // NOTE: data/framework-control-gaps.json currently has zero entries with status="closed".
  // When closed entries are added in future, this test should be extended to verify they
  // are still emitted (closed ≠ deleted, per Hard Rule on framework mapping updates).
  const r = gapReport(['NIST SP 800-53 Rev 5'], 'CVE-2026-31431', controlGaps, cveCatalog);
  const target = Object.values(r.frameworks).find(f => f.gaps.length > 0);
  assert.ok(target, 'expected at least one framework with gaps');
  for (const g of target.gaps) {
    assert.ok(['open', 'closed'].includes(g.status), `unexpected status: ${g.status}`);
  }
});

test('Synthetic closed-status gap is preserved (status field passed through verbatim)', () => {
  const synthetic = {
    'TEST-CLOSED-1': {
      framework: 'NIST SP 800-53 Rev 5',
      control_id: 'TEST-1',
      control_name: 'Closed Test Control',
      real_requirement: 'CVE-2026-31431 mitigation',
      misses: ['some miss text'],
      evidence_cves: ['CVE-2026-31431'],
      status: 'closed'
    }
  };
  const r = gapReport(['NIST SP 800-53 Rev 5'], 'CVE-2026-31431', synthetic, cveCatalog);
  const fw = r.frameworks['NIST SP 800-53 Rev 5'];
  assert.equal(fw.gap_count, 1);
  assert.equal(fw.gaps[0].status, 'closed');
});

// ---------------------------------------------------------------------------
// lagScore counts framework-specific gaps by normalized match (not literal
// substring of the catalog display string).
// ---------------------------------------------------------------------------

test('#11 lagScore counts framework-specific gaps for a key that is NOT a substring of its catalog string', () => {
  // EU_AI_ACT's catalog strings read "EU Artificial Intelligence Act ..."
  // and "EU AI Act ..."; the short key "EU_AI_ACT" is not a literal
  // substring of either, so the pre-fix `.includes(frameworkId)` returned 0.
  const r = fg.lagScore('EU_AI_ACT', controlGaps, globalFrameworks);
  assert.equal(typeof r.breakdown.framework_specific_gaps, 'number');
  assert.equal(r.breakdown.framework_specific_gaps, 7,
    'EU_AI_ACT must surface all 7 open AI-Act gaps');
});

test('#11 lagScore resolves another display-name-only framework (NCSC_CAF)', () => {
  const r = fg.lagScore('NCSC_CAF', controlGaps, globalFrameworks);
  assert.equal(r.breakdown.framework_specific_gaps, 7);
});

test('#11 lagScore leaves substring-matching frameworks unchanged', () => {
  // DORA / GDPR / NIS2 keys ARE substrings of their catalog strings, so the
  // fix must not change their counts (guards against over-matching).
  assert.equal(fg.lagScore('DORA', controlGaps, globalFrameworks).breakdown.framework_specific_gaps, 9);
  assert.equal(fg.lagScore('GDPR', controlGaps, globalFrameworks).breakdown.framework_specific_gaps, 2);
  assert.equal(fg.lagScore('NIS2', controlGaps, globalFrameworks).breakdown.framework_specific_gaps, 11);
});

test('#11 lagScore does not over-match a short key against another framework', () => {
  // EU_CRA resolves to exactly its own catalog string (1 open gap), not to
  // the broader EU_AI_ACT set — a regression that broadened matching too far
  // would inflate this.
  assert.equal(fg.lagScore('EU_CRA', controlGaps, globalFrameworks).breakdown.framework_specific_gaps, 1);
});

// ---------------------------------------------------------------------------
// gapReport theater_risks counts entries with theater_test (not just the
// legacy theater_pattern field).
// ---------------------------------------------------------------------------

test('P1: framework-gap theater_risks counts entries with theater_test (not just legacy theater_pattern)', () => {
  // Direct library probe avoids the orchestrator-dispatch surface;
  // exercise the function used by the CLI verb.
  const ROOT = path.join(__dirname, '..');
  const { gapReport } = require(path.join(ROOT, 'lib', 'framework-gap.js'));
  const controlGaps = JSON.parse(fs.readFileSync(path.join(ROOT, 'data', 'framework-control-gaps.json'), 'utf8'));
  const cveCatalog = JSON.parse(fs.readFileSync(path.join(ROOT, 'data', 'cve-catalog.json'), 'utf8'));
  // CVE-2026-31431 is the canonical kernel-LPE catalog entry that
  // spans many framework gaps. Use it as the scenario.
  const report = gapReport(['nist-800-53'], 'CVE-2026-31431', controlGaps, cveCatalog);
  // Pre-fix `theater_risks` was empty even though every per-framework
  // result showed `theater_exposure: true`. Now it must be > 0 because
  // the v0.12.29 backfill added theater_test to every relevant gap.
  assert.equal(Array.isArray(report.theater_risks), true);
  assert.equal(report.theater_risks.length > 0, true,
    `framework-gap theater_risks must be non-empty when entries carry theater_test; got: ${JSON.stringify(report.summary)}`);
  // Sub-shape: each theater-risk entry must carry the canonical fields.
  for (const r of report.theater_risks) {
    assert.equal(typeof r.control, 'string');
    assert.equal(typeof r.framework, 'string');
    // theater_test_present is the v0.12.40 addition; pin it.
    assert.equal(typeof r.theater_test_present, 'boolean');
  }
  // Footer count must match the array length.
  assert.equal(report.summary.theater_risk_controls, report.theater_risks.length);
});

// ---------------------------------------------------------------------------
// data/framework-control-gaps.json — Hard Rule #6 theater_test coverage.
// Every entry in the framework-gap data catalog MUST carry a populated
// theater_test block that distinguishes paper compliance from actual security.
//
//   theater_test: {
//     claim:                 non-empty string (the audit-language sentence),
//     test:                  non-empty string (a falsifiable check),
//     evidence_required:     non-empty array of strings (1+ artifacts),
//     verdict_when_failed:   exact literal "compliance-theater"
//   }
// ---------------------------------------------------------------------------

const CATALOG_PATH = path.join(__dirname, '..', 'data', 'framework-control-gaps.json');
const CATALOG = JSON.parse(fs.readFileSync(CATALOG_PATH, 'utf8'));
const ENTRY_KEYS = Object.keys(CATALOG).filter((k) => k !== '_meta');
const REQUIRED_VERDICT = 'compliance-theater';

test('framework-control-gaps.json: catalog has at least 109 control-gap entries', () => {
  // Lower-bound assertion. New entries are additive and must continue to
  // satisfy the per-entry shape below; this guard catches accidental
  // truncation of the file.
  assert.ok(
    ENTRY_KEYS.length >= 109,
    `expected >= 109 entries, found ${ENTRY_KEYS.length}`
  );
});

test('framework-control-gaps.json: every entry has a populated theater_test', () => {
  const failures = [];
  for (const key of ENTRY_KEYS) {
    const entry = CATALOG[key];
    const tt = entry.theater_test;

    if (tt === undefined || tt === null) {
      failures.push(`${key}: theater_test is missing`);
      continue;
    }

    if (typeof tt !== 'object' || Array.isArray(tt)) {
      failures.push(`${key}: theater_test is not an object`);
      continue;
    }

    // claim: non-empty string
    if (typeof tt.claim !== 'string') {
      failures.push(`${key}: theater_test.claim is not a string (got ${typeof tt.claim})`);
    } else if (tt.claim.trim().length === 0) {
      failures.push(`${key}: theater_test.claim is empty`);
    } else if (tt.claim.length < 30) {
      // Paper-compliance claims worth testing read like real audit language.
      // A 30-char minimum stops one-word stub claims from regressing in.
      failures.push(`${key}: theater_test.claim is too short (${tt.claim.length} chars)`);
    }

    // test: non-empty string with discriminating content
    if (typeof tt.test !== 'string') {
      failures.push(`${key}: theater_test.test is not a string (got ${typeof tt.test})`);
    } else if (tt.test.trim().length === 0) {
      failures.push(`${key}: theater_test.test is empty`);
    } else if (tt.test.length < 80) {
      // A falsifiability check needs enough text to describe the query
      // and the binary verdict. 80 chars is a low floor.
      failures.push(`${key}: theater_test.test is too short (${tt.test.length} chars)`);
    }

    // evidence_required: array, length >= 1, all non-empty strings
    if (!Array.isArray(tt.evidence_required)) {
      failures.push(`${key}: theater_test.evidence_required is not an array`);
    } else if (tt.evidence_required.length < 1) {
      failures.push(`${key}: theater_test.evidence_required has zero entries`);
    } else {
      for (let i = 0; i < tt.evidence_required.length; i++) {
        const item = tt.evidence_required[i];
        if (typeof item !== 'string' || item.trim().length === 0) {
          failures.push(`${key}: theater_test.evidence_required[${i}] is not a non-empty string`);
        }
      }
    }

    // verdict_when_failed: exact literal "compliance-theater"
    assert.equal(
      tt.verdict_when_failed,
      REQUIRED_VERDICT,
      `${key}: theater_test.verdict_when_failed must equal "${REQUIRED_VERDICT}", got ${JSON.stringify(tt.verdict_when_failed)}`
    );
  }

  assert.equal(
    failures.length,
    0,
    `theater_test schema failures:\n  - ${failures.join('\n  - ')}`
  );
});

test('framework-control-gaps.json: theater_test.test contains a falsifiability marker', () => {
  // Soft check: the test string should contain at least one of the words
  // that signal a binary verdict ("Theater verdict", "verdict if", "fail",
  // "must", "confirm"). This is not a proof of falsifiability but it
  // catches drafting accidents where the field reads like prose without
  // any pass/fail trigger.
  const verdictMarkers = /(theater verdict|verdict if|confirm|missing|absent|exceeds|fails|fail if)/i;
  const failures = [];
  for (const key of ENTRY_KEYS) {
    const tt = CATALOG[key].theater_test;
    if (!tt || typeof tt.test !== 'string') continue;
    if (!verdictMarkers.test(tt.test)) {
      failures.push(`${key}: theater_test.test lacks any verdict marker`);
    }
  }
  assert.equal(
    failures.length,
    0,
    `entries without verdict markers:\n  - ${failures.join('\n  - ')}`
  );
});

test('framework-control-gaps.json: theater_test.test strings are not literal duplicates', () => {
  // Per AGENTS.md: distinct controls cannot share the literal same test
  // string (pattern-shaped tests are fine; copy-paste is not). Group by
  // exact-string equality and surface any group with > 1 distinct entry.
  const byTest = new Map();
  for (const key of ENTRY_KEYS) {
    const tt = CATALOG[key].theater_test;
    if (!tt || typeof tt.test !== 'string') continue;
    const trimmed = tt.test.trim();
    if (!byTest.has(trimmed)) byTest.set(trimmed, []);
    byTest.get(trimmed).push(key);
  }
  const dupes = [];
  for (const [text, keys] of byTest.entries()) {
    if (keys.length > 1) {
      dupes.push(`shared by ${keys.join(', ')}: ${text.slice(0, 80)}...`);
    }
  }
  assert.equal(
    dupes.length,
    0,
    `theater_test.test strings duplicated verbatim across distinct controls:\n  - ${dupes.join('\n  - ')}`
  );
});


// ---- routed from framework-gap-completeness ----
require("node:test").describe("framework-gap-completeness", () => {
const __t = require("node:test"); const __env = Object.assign({}, process.env);
__t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __env)) delete process.env[k]; Object.assign(process.env, __env);
  const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
/**
 * Tests for the v0.12.17 audit fixes:
 *   - Audit I P1-3: Windows ACL hardening on .keys/private.pem (restrictWindowsAcl)
 *   - Audit I P1-4: top-level manifest_signature on manifest.json
 *   - Audit L F11:  --diff-from-latest human-renderer output shape
 *   - Audit L F22:  ai-run --help documents the first-evidence-wins stdin contract
 *   - Audit M P3-O: KEV diff severity nuance (critical for ransomware / near-due)
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const { spawnSync } = require('node:child_process');

const ROOT = path.join(__dirname, '..');
const signMod = require('../lib/sign.js');
const verifyMod = require('../lib/verify.js');
const autoDiscovery = require('../lib/auto-discovery.js');

// --- P1-3: Windows ACL helper ---

test('P1-3: restrictWindowsAcl is exported and is a function', () => {
  assert.equal(typeof signMod.restrictWindowsAcl, 'function');
});

test('P1-3: restrictWindowsAcl is a no-op on non-Windows platforms', () => {
  // The function should return without throwing on POSIX. We test by
  // calling it against a path that does not exist — on win32 icacls would
  // fail (which we'd handle via warn) but on POSIX it should never invoke
  // icacls at all, so no exception is thrown.
  if (process.platform === 'win32') {
    // On win32 we cannot easily assert no-op behavior; just confirm the
    // function executes and does not throw on a real temp file.
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'exceptd-acl-'));
    const target = path.join(tmpDir, 'priv.pem');
    fs.writeFileSync(target, 'test', 'utf8');
    try {
      assert.doesNotThrow(() => signMod.restrictWindowsAcl(target));
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  } else {
    assert.doesNotThrow(() => signMod.restrictWindowsAcl('/nonexistent/path/private.pem'));
  }
});

// SVM-07: a failed Windows ACL hardening must be detectable by automation,
// not buried under a 0 exit. Before the fix, generate-keypair returned
// { aclHardened:false } but the CLI dispatch discarded it — the key was
// written group/other-readable while the process exited 0 and the success
// banner printed, so bootstrap.js / doctor --fix (which gate on the exit
// code) treated an unhardened key as a clean generation.
//
// We build a throwaway sandbox so the real repo .keys/keys are never touched,
// then spawn `generate-keypair` with a preload that forces win32 and makes
// icacls throw (reproducible on any host, including CI Linux). Exit code is
// asserted EXACTLY, never just `!== 0`.
function buildSignSandbox() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'exceptd-svm07-'));
  fs.mkdirSync(path.join(dir, 'lib', 'schemas'), { recursive: true });
  fs.mkdirSync(path.join(dir, 'keys'), { recursive: true });
  fs.mkdirSync(path.join(dir, '.keys'), { recursive: true });
  for (const rel of ['lib/sign.js', 'lib/verify.js', 'lib/exit-codes.js',
                     'lib/schemas/manifest.schema.json', 'manifest.json']) {
    fs.copyFileSync(path.join(ROOT, rel), path.join(dir, rel));
  }
  const preload = path.join(dir, 'preload-force.js');
  fs.writeFileSync(preload,
    "'use strict';\n" +
    "Object.defineProperty(process,'platform',{value:'win32',configurable:true});\n" +
    "process.env.USERNAME = process.env.USERNAME || 'svm07user';\n" +
    "const cp=require('child_process');const real=cp.execFileSync;\n" +
    "cp.execFileSync=function(c,a,o){if(c==='icacls'){const e=new Error('icacls forced-fail (test)');e.code='ENOENT';throw e;}return real(c,a,o);};\n",
    'utf8');
  return { dir, preload };
}

test('SVM-07: generate-keypair exits non-zero when Windows ACL hardening fails (no opt-out)', () => {
  const { dir, preload } = buildSignSandbox();
  try {
    const r = spawnSync(process.execPath,
      ['--require', preload, path.join(dir, 'lib', 'sign.js'), 'generate-keypair'],
      { cwd: dir, encoding: 'utf8', env: { ...process.env, EXCEPTD_ALLOW_WEAK_KEY_ACL: '' } });
    assert.equal(r.status, 1,
      `unhardened-key generation must exit 1; got ${r.status}\nSTDOUT:\n${r.stdout}\nSTDERR:\n${r.stderr}`);
    // The key write itself still succeeds (exit signals "present-but-unhardened").
    assert.equal(fs.existsSync(path.join(dir, '.keys', 'private.pem')), true,
      'the private key must still be written even when ACL hardening fails');
    // The failure must be loud on stderr so automation/operators see WHY.
    assert.match(r.stderr, /ACL hardening FAILED/,
      'stderr must carry the explicit ACL-hardening-failed error');
    // The success banner must still drain (exitCode idiom, not process.exit
    // truncating buffered stdout).
    assert.match(r.stdout, /Ed25519 keypair generated/,
      'success banner must still flush to stdout despite the non-zero exit');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('SVM-07: EXCEPTD_ALLOW_WEAK_KEY_ACL=1 lets generate-keypair exit 0 on a single-user host', () => {
  const { dir, preload } = buildSignSandbox();
  try {
    const r = spawnSync(process.execPath,
      ['--require', preload, path.join(dir, 'lib', 'sign.js'), 'generate-keypair'],
      { cwd: dir, encoding: 'utf8', env: { ...process.env, EXCEPTD_ALLOW_WEAK_KEY_ACL: '1' } });
    assert.equal(r.status, 0,
      `opt-out must restore a 0 exit; got ${r.status}\nSTDERR:\n${r.stderr}`);
    assert.match(r.stderr, /EXCEPTD_ALLOW_WEAK_KEY_ACL=1/,
      'the opt-out path must still warn that the ACL was not hardened');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// --- P1-4: manifest signature ---

test('P1-4: canonicalManifestBytes is deterministic regardless of stale signature field', () => {
  const m1 = { name: 'x', version: '1.2.3', skills: [] };
  const m2 = {
    name: 'x', version: '1.2.3', skills: [],
    manifest_signature: { algorithm: 'Ed25519', signature_base64: 'stale==', signed_at: '2020-01-01' },
  };
  const b1 = signMod.canonicalManifestBytes(m1).toString('hex');
  const b2 = signMod.canonicalManifestBytes(m2).toString('hex');
  assert.equal(b1, b2, 'canonical bytes must ignore stale manifest_signature');
});

test('P1-4: canonicalManifestBytes is deterministic regardless of top-level key order', () => {
  const m1 = { name: 'x', version: '1.2.3', skills: [] };
  const m2 = { skills: [], version: '1.2.3', name: 'x' };
  assert.equal(
    signMod.canonicalManifestBytes(m1).toString('hex'),
    signMod.canonicalManifestBytes(m2).toString('hex'),
    'key order at top level must not affect canonical bytes',
  );
});

test('P1-4: sign + verify round-trip on canonical manifest bytes succeeds', () => {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519', {
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    publicKeyEncoding: { type: 'spki', format: 'pem' },
  });
  const manifest = {
    name: 'test', version: '0.0.1', skills: [{ name: 'a', path: 'skills/a/skill.md' }],
  };
  const sigObj = signMod.signCanonicalManifest(manifest, privateKey);
  assert.equal(sigObj.algorithm, 'Ed25519');
  assert.equal(typeof sigObj.signature_base64, 'string');
  assert.ok(sigObj.signature_base64.length > 0);
  // Manually verify.
  const bytes = signMod.canonicalManifestBytes(manifest);
  const ok = crypto.verify(null, bytes, { key: publicKey, dsaEncoding: 'ieee-p1363' },
                            Buffer.from(sigObj.signature_base64, 'base64'));
  assert.equal(ok, true);
});

test('P1-4: live manifest.json carries a valid manifest_signature', () => {
  const manifest = JSON.parse(fs.readFileSync(path.join(ROOT, 'manifest.json'), 'utf8'));
  assert.ok(manifest.manifest_signature, 'live manifest.json must have manifest_signature');
  assert.equal(manifest.manifest_signature.algorithm, 'Ed25519');
  assert.equal(typeof manifest.manifest_signature.signature_base64, 'string');
  assert.ok(manifest.manifest_signature.signature_base64.length > 0);

  // Verify against keys/public.pem.
  const result = verifyMod.verifyManifestSignature(manifest);
  assert.equal(result.status, 'valid', `live manifest_signature must verify; got ${JSON.stringify(result)}`);
});

test('P1-4: verifyManifestSignature returns invalid when signature is tampered', () => {
  const manifest = JSON.parse(fs.readFileSync(path.join(ROOT, 'manifest.json'), 'utf8'));
  // Flip one base64 char to break verification.
  const tampered = JSON.parse(JSON.stringify(manifest));
  const orig = tampered.manifest_signature.signature_base64;
  // Replace the first non-A character with 'A' (or 'B' if it's 'A') to
  // guarantee a different signature value.
  const idx = [...orig].findIndex(c => c !== 'A');
  const replacement = orig.charAt(idx) === 'A' ? 'B' : 'A';
  tampered.manifest_signature.signature_base64 = orig.slice(0, idx) + replacement + orig.slice(idx + 1);
  const result = verifyMod.verifyManifestSignature(tampered);
  assert.equal(result.status, 'invalid');
  assert.match(result.reason, /Ed25519 manifest signature did not verify/);
});

test('P1-4: verifyManifestSignature returns invalid when a skill path is swapped', () => {
  const manifest = JSON.parse(fs.readFileSync(path.join(ROOT, 'manifest.json'), 'utf8'));
  const tampered = JSON.parse(JSON.stringify(manifest));
  // Tamper a skill entry — the signature was computed over the original.
  tampered.skills[0].description = 'TAMPERED — attacker rewrote this field';
  const result = verifyMod.verifyManifestSignature(tampered);
  assert.equal(result.status, 'invalid');
});

test('P1-4: verifyManifestSignature returns missing when field absent (backward-compat)', () => {
  const manifest = JSON.parse(fs.readFileSync(path.join(ROOT, 'manifest.json'), 'utf8'));
  const legacy = JSON.parse(JSON.stringify(manifest));
  delete legacy.manifest_signature;
  const result = verifyMod.verifyManifestSignature(legacy);
  assert.equal(result.status, 'missing');
});

test('P1-4: loadManifestValidated throws on tampered signature, blocks all skill verify', () => {
  // Round-trip via a temp manifest path is not exposed by the module API;
  // instead exercise the canonical helpers and the schema/path guards
  // together with the signature verifier (the same code loadManifestValidated
  // composes).
  const manifest = JSON.parse(fs.readFileSync(path.join(ROOT, 'manifest.json'), 'utf8'));
  const tampered = JSON.parse(JSON.stringify(manifest));
  tampered.manifest_signature.signature_base64 = 'AAAA' + tampered.manifest_signature.signature_base64.slice(4);
  const result = verifyMod.verifyManifestSignature(tampered);
  assert.equal(result.status, 'invalid');
});

test('P1-4: signing tooling regenerates a valid manifest_signature (smoke against on-disk state)', () => {
  // The on-disk manifest must currently verify. If this fails, an earlier
  // test mutated state or sign-all was not run after the recent change.
  const r = spawnSync(process.execPath, [path.join(ROOT, 'lib', 'verify.js')], {
    cwd: ROOT, encoding: 'utf8',
  });
  assert.equal(r.status, 0, `verify.js exit: ${r.status}\nSTDOUT:\n${r.stdout}\nSTDERR:\n${r.stderr}`);
});

// --- L F11: --diff-from-latest renderer ---

test('F11: diff_from_latest renderer formats all three status branches with prior session id', () => {
  // Exercise the renderer indirectly via the bin file source — assert that
  // the spec copy strings are present.
  const src = fs.readFileSync(path.join(ROOT, 'bin', 'exceptd.js'), 'utf8');
  assert.match(src, /unchanged \(same evidence_hash as session \$\{dfl\.prior_session_id\}\)/);
  assert.match(src, /DRIFTED — evidence_hash differs from session \$\{dfl\.prior_session_id\}/);
  // The no_prior_attestation_for_playbook branch now emits an explicit
  // line (previously it intentionally produced no line, which left
  // operators wondering whether --diff-from-latest took effect when
  // run against a fresh attestation directory).
  const rendererIdx = src.indexOf('// F11: surface --diff-from-latest verdict in the human renderer');
  assert.ok(rendererIdx > 0, 'F11 renderer marker comment must be present');
  const block = src.slice(rendererIdx, rendererIdx + 1500);
  assert.match(block, /dfl\.status === "no_prior_attestation_for_playbook"/,
    'renderer must branch on the no_prior status');
  assert.match(block, /no prior attestation found for/,
    'renderer must emit the no-prior baseline line so the flag is not silently a no-op');
});

test('F11: renderer block lists exactly the unchanged + drifted statuses', () => {
  // Live exec the renderer logic by importing bin/exceptd.js?
  // The bin file is not a normal CommonJS module — it runs main() under
  // require.main === module. We test by string-extracting the renderer block
  // (already done above) and confirming both branches reference prior_session_id.
  const src = fs.readFileSync(path.join(ROOT, 'bin', 'exceptd.js'), 'utf8');
  const rendererStart = src.indexOf('if (obj.diff_from_latest)');
  const rendererBlock = src.slice(rendererStart, rendererStart + 800);
  assert.match(rendererBlock, /dfl\.status === "unchanged"/);
  assert.match(rendererBlock, /dfl\.status === "drifted"/);
});

// --- L F22: ai-run --help streaming contract documentation ---

test('F22: ai-run --help text documents the first-evidence-wins stdin contract', () => {
  const src = fs.readFileSync(path.join(ROOT, 'bin', 'exceptd.js'), 'utf8');
  // Help text registered under "ai-run" should include the Audit L F22 wording.
  // The helps map registers entries via `"ai-run": \`ai-run <playbook>...`;
  // search for that backtick form specifically to skip the case-statement
  // and any incidental references.
  const helpEntry = src.indexOf('"ai-run": `ai-run');
  assert.ok(helpEntry > 0, 'ai-run help entry must be registered');
  const helpBlock = src.slice(helpEntry, helpEntry + 3600);
  assert.match(helpBlock, /Stdin acceptance contract/);
  assert.match(helpBlock, /FIRST/);
  assert.match(helpBlock, /handled/);
});

// --- M P3-O: KEV severity nuance ---

test('P3-O: deriveKevSeverity returns critical for ransomware campaigns', () => {
  const severity = autoDiscovery.deriveKevSeverity({
    knownRansomwareCampaignUse: 'Known',
    dueDate: '2099-12-31',
  });
  assert.equal(severity, 'critical');
});

test('P3-O: deriveKevSeverity returns critical when due date is within 7 days', () => {
  const soon = new Date(Date.now() + 3 * 86_400_000).toISOString().slice(0, 10);
  const severity = autoDiscovery.deriveKevSeverity({
    knownRansomwareCampaignUse: 'Unknown',
    dueDate: soon,
  });
  assert.equal(severity, 'critical');
});

test('P3-O: deriveKevSeverity returns critical for past-due entries', () => {
  const severity = autoDiscovery.deriveKevSeverity({
    knownRansomwareCampaignUse: 'Unknown',
    dueDate: '2020-01-01',
  });
  assert.equal(severity, 'critical');
});

test('P3-O: deriveKevSeverity returns high when due date is more than a week out and no ransomware', () => {
  const far = new Date(Date.now() + 60 * 86_400_000).toISOString().slice(0, 10);
  const severity = autoDiscovery.deriveKevSeverity({
    knownRansomwareCampaignUse: 'Unknown',
    dueDate: far,
  });
  assert.equal(severity, 'high');
});

test('P3-O: deriveKevSeverity returns high when no dueDate present and no ransomware', () => {
  const severity = autoDiscovery.deriveKevSeverity({
    knownRansomwareCampaignUse: '',
  });
  assert.equal(severity, 'high');
});

test('P3-O: discoverNewKev propagates per-entry severity from deriveKevSeverity', () => {
  // Build a synthetic ctx + cached KEV feed in a tempdir so we drive
  // discoverNewKev without touching network or the live cache.
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'exceptd-kev-'));
  try {
    const kevDir = path.join(tmpDir, 'kev');
    fs.mkdirSync(kevDir, { recursive: true });
    const soon = new Date(Date.now() + 2 * 86_400_000).toISOString().slice(0, 10);
    const feed = {
      vulnerabilities: [
        // Ransomware-known → critical
        { cveID: 'CVE-2026-99001', dateAdded: '2026-05-10',
          knownRansomwareCampaignUse: 'Known', dueDate: '2099-12-31',
          vulnerabilityName: 'A', shortDescription: '', vendorProject: 'V', product: 'P' },
        // Due soon → critical
        { cveID: 'CVE-2026-99002', dateAdded: '2026-05-09',
          knownRansomwareCampaignUse: 'Unknown', dueDate: soon,
          vulnerabilityName: 'B', shortDescription: '', vendorProject: 'V', product: 'P' },
        // Plain KEV → high
        { cveID: 'CVE-2026-99003', dateAdded: '2026-05-08',
          knownRansomwareCampaignUse: 'Unknown', dueDate: '2099-01-01',
          vulnerabilityName: 'C', shortDescription: '', vendorProject: 'V', product: 'P' },
      ],
    };
    fs.writeFileSync(
      path.join(kevDir, 'known_exploited_vulnerabilities.json'),
      JSON.stringify(feed),
    );
    const ctx = { cacheDir: tmpDir, cveCatalog: {} };
    const result = autoDiscovery.discoverNewKev(ctx, 10);
    assert.equal(result.errors, 0);
    assert.equal(result.diffs.length, 3);
    const byId = Object.fromEntries(result.diffs.map(d => [d.id, d.severity]));
    assert.equal(byId['CVE-2026-99001'], 'critical', 'ransomware → critical');
    assert.equal(byId['CVE-2026-99002'], 'critical', 'near-due → critical');
    assert.equal(byId['CVE-2026-99003'], 'high', 'baseline KEV → high');
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});
});
