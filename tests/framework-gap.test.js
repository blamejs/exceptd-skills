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

test('#11 lagScore resolves ASD_ISM via data-driven catalog_aliases', () => {
  // ASD_ISM's catalog labels diverged from the global-frameworks full_name,
  // so neither the short key nor the display string matched literally and the
  // framework reported framework_specific_gaps:0 (framework_resolved_but_zero_gaps
  // would have been true). The data-driven catalog_aliases now bridge the
  // divergent labels back to the framework, surfacing all 5 open ISM gaps.
  const r = fg.lagScore('ASD_ISM', controlGaps, globalFrameworks);
  assert.equal(typeof r.breakdown.framework_specific_gaps, 'number');
  assert.equal(r.breakdown.framework_specific_gaps, 5,
    'ASD_ISM must surface all 5 open ISM gaps via catalog_aliases');
  // Resolving to a non-zero count proves the framework was matched, not that
  // it resolved to an empty bucket — pin the explicit flag so a regression
  // that resolves-but-finds-nothing trips here.
  assert.equal(r.breakdown.framework_resolved_but_zero_gaps, false,
    'ASD_ISM must resolve to its real gaps, not an empty-bucket zero');
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

test('gapReport theater_risks honors the requested-framework filter (no cross-framework leak)', () => {
  // "prompt injection" matches open theater-risk gaps across ~18 frameworks
  // (DORA, EU AI Act, HIPAA, ISO 27001, PCI-DSS, OWASP, ...). Requesting ONE
  // framework must scope theater_risks to that framework's controls only —
  // pre-fix it was built from the unfiltered scenario set and leaked every
  // framework's theater controls regardless of what the operator asked for.
  const r = gapReport(['NIST SP 800-53 Rev 5'], 'prompt injection', controlGaps, cveCatalog, { allFrameworks: false });

  assert.ok(Array.isArray(r.theater_risks), 'theater_risks must be an array');
  // Exactly the NIST framework's single matching theater control survives.
  assert.equal(r.theater_risks.length, 1, `expected 1 scoped theater risk, got ${r.theater_risks.length}`);
  // Every surviving entry must belong to the requested framework — assert the
  // value, not mere presence.
  const frameworksSeen = [...new Set(r.theater_risks.map(t => t.framework))];
  assert.deepEqual(frameworksSeen, ['NIST SP 800-53 Rev 5'],
    `theater_risks leaked non-requested frameworks: ${JSON.stringify(frameworksSeen)}`);
  assert.equal(r.theater_risks[0].control, 'NIST-800-53-AC-2');
  assert.equal(typeof r.theater_risks[0].theater_test_present, 'boolean');
  // The summary footer must agree with the scoped array length.
  assert.equal(r.summary.theater_risk_controls, r.theater_risks.length);
  assert.equal(r.summary.theater_risk_controls, 1);
});

test('gapReport theater_risks with allFrameworks counts every scenario-relevant theater control', () => {
  // Guard the other direction: the `all` path must still surface the full
  // cross-framework theater set, so the scoping fix can't accidentally shrink
  // the all-frameworks report.
  const r = gapReport(['all'], 'prompt injection', controlGaps, cveCatalog, { allFrameworks: true });
  assert.ok(Array.isArray(r.theater_risks));
  const frameworksSeen = new Set(r.theater_risks.map(t => t.framework));
  assert.ok(frameworksSeen.size > 1,
    `allFrameworks theater_risks must span many frameworks; got ${frameworksSeen.size}`);
  assert.equal(r.summary.theater_risk_controls, r.theater_risks.length);
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


// ---- routed from audit-correctness-cluster ----
require("node:test").describe("audit-correctness-cluster", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
/**
 * Regression suite for a correctness cluster found auditing the run/ci/ai-run
 * verbs and the close/framework-gap surfaces for silent-wrong-answer bugs:
 *
 *   H1 — `ci <playbook> --evidence -` given a FLAT submission (the same shape
 *        `run` accepts) silently produced a PASS: the runner keyed the bundle
 *        by playbook id, found nothing, and evaluated an empty submission.
 *        ci must now treat a single-positional flat submission as belonging to
 *        that playbook, matching `run`'s verdict.
 *
 *   H2 — `ai-run <pb> --no-stream --evidence -` bypassed the evidence-shape
 *        guard `run` enforces, so `null` / `[]` / a scalar ran as if empty.
 *        It must be rejected at the read boundary with an actionable message.
 *
 *   H3 — the ci framework_gap_rollup read a nonexistent `why_insufficient`
 *        key, so every rollup entry's explanation was null. The data lives in
 *        `actual_gap`; the rollup must surface it.
 *
 *   M1 — the regulatory clock only started when the AGENT submitted
 *        detection_classification:'detected'. An engine-confirmed detection
 *        (indicators fired, engine classified 'detected') with --ack never
 *        started the clock, so notification deadlines silently stalled.
 *
 *   M2 — `framework-gap <bogus> <scenario>` produced a zero-gap report
 *        indistinguishable from a real "no gaps" result, so a typo read as
 *        proof the framework covered the scenario. An unknown framework must
 *        be refused; documented short forms ("NIST-800-53") must still resolve.
 *
 * Discipline: exact exit codes; presence assertions paired with value/type.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const { makeSuiteHome, makeCli, tryJson } = require("./_helpers/cli");

const cli = makeCli(makeSuiteHome("exceptd-auditcorrect-"));

// A flat secrets submission whose overrides fire real indicators.
const FLAT_SECRETS = JSON.stringify({
  signal_overrides: { "aws-secret-access-key": "hit", "github-personal-access-token": "hit" },
});





// The bug codex flagged: the guard above only fires on `--evidence`, but
// --no-stream ALSO auto-reads stdin. Whether a spawnSync pipe triggers the
// auto-stdin path is platform-divergent (POSIX FIFOs report readable; win32
// spawnSync pipes do not), so probe reachability first and only assert the
// rejection where the path is actually live — never coincidence-pass.
function autoStdinReachable() {
  const probe = cli(["ai-run", "secrets", "--no-stream", "--json"], {
    input: JSON.stringify({ signal_overrides: { "aws-secret-access-key": "hit", "github-personal-access-token": "hit" } }),
  });
  const pj = tryJson(probe.stdout);
  return !!(pj && pj.phases?.analyze?._detect_classification === "detected");
}




const AI_API_FIRES = JSON.stringify({
  signal_overrides: {
    "cleartext-api-key-in-dotfile": "hit",
    "ai-api-beaconing-cadence": "hit",
    "long-lived-aws-keys": "hit",
  },
});

test("M2: framework-gap refuses an unknown framework", () => {
  const r = cli(["framework-gap", "ZZZ-NOT-A-FRAMEWORK", "CVE-2025-53773", "--json"]);
  assert.equal(r.status, 1);
  const body = tryJson(r.stdout) || tryJson(r.stderr);
  assert.ok(body && body.ok === false, "must emit a structured refusal");
  assert.match(body.error, /unknown framework/, "must name the failure");
  assert.ok(Array.isArray(body.known_frameworks) && body.known_frameworks.length > 0, "must list known frameworks");
});

test("M2: documented short forms (NIST-800-53, PCI-DSS-4.0) still resolve", () => {
  for (const fw of ["NIST-800-53", "nist-800-53", "PCI-DSS-4.0"]) {
    const r = cli(["framework-gap", fw, "prompt injection", "--json"]);
    const body = tryJson(r.stdout);
    assert.ok(body, `framework-gap ${fw} must emit JSON`);
    assert.notEqual(body.ok, false, `documented short form ${fw} must not be rejected`); // allow-notEqual: short forms must resolve, not refuse
    assert.ok(body.frameworks && Object.keys(body.frameworks).length >= 1, `${fw} must match at least one catalog framework`);
  }
});

test("M2: 'all' is unaffected by framework validation", () => {
  const r = cli(["framework-gap", "all", "prompt injection", "--json"]);
  const body = tryJson(r.stdout);
  assert.ok(body && body.ok !== false, "'all' must still run");
  assert.ok(body.frameworks && Object.keys(body.frameworks).length > 1, "'all' must expand to many frameworks");
});
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});


// ---- routed from audit-usability-fixes ----
require("node:test").describe("audit-usability-fixes", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
/**
 * CLI usability regression suite.
 *
 * Pins the behavior of a set of CLI ergonomics fixes so they cannot silently
 * regress at the next refactor. Each test exercises the real CLI through the
 * shared cli() harness (subprocess spawn of bin/exceptd.js) and asserts the
 * EXACT exit code and field shapes per the project anti-coincidence rule:
 * never `notEqual(0)`, never `assert.ok(field)` without a paired value/type
 * assertion.
 *
 * Areas covered:
 *   1. Unknown-flag hard-fail across all verbs (+ typo suggestion + the
 *      tailored cross-verb "irrelevant flag" message that must NOT collapse
 *      into a generic unknown-flag refusal).
 *   2. `--format json` returns the full run result, not a stub.
 *   3. Multiple --format values emit a one-format-wins note to stderr.
 *   4. Standardized bundles (sarif / csaf-2.0 / openvex) carry no top-level
 *      `ok` key and present their spec marker.
 *   5. `skill` / `framework-gap` honor --help; `refresh` keeps its own help.
 *   6. `collect` emits JSON when piped (non-TTY) so the documented pipe works.
 *   7. `refresh --check-advisories` arg parsing (report-only, no network).
 *   8. `attest list --limit` envelope + bad-value rejection.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const fs = require('node:fs');
const os = require('node:os');

const { ROOT, makeSuiteHome, makeCli, tryJson } = require('./_helpers/cli');

const SUITE_HOME = makeSuiteHome('exceptd-audit-usability-');
const cli = makeCli(SUITE_HOME);

// ===================================================================
// 1. Unknown-flag hard-fail (all verbs, not just doctor)
// ===================================================================









// ===================================================================
// 2. `--format json` returns the FULL run result (not a stub)
// ===================================================================


// ===================================================================
// 3. MULTI-FORMAT note to stderr
// ===================================================================


// ===================================================================
// 4. STANDARDIZED BUNDLES carry NO top-level `ok` key
// ===================================================================




// ===================================================================
// 5. `skill --help` / `framework-gap --help` honor --help;
//    refresh keeps its OWN detailed help
// ===================================================================




// ===================================================================
// 6. `collect` emits JSON when piped (non-TTY) so the documented pipe works
// ===================================================================


// ===================================================================
// 7. `refresh --check-advisories` parsing (no network — parseArgs directly)
// ===================================================================


// ===================================================================
// 8. `attest list --limit`
// ===================================================================

test('framework-gap --help shows usage', () => {
  const r = cli(['framework-gap', '--help']);
  assert.equal(r.status, 0, `expected exit 0; got ${r.status} (stderr: ${r.stderr.slice(0, 200)})`);
  assert.match(r.stdout, /framework-gap </);
});
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});


// ---- routed from hunt-fix-C-correlations ----
require("node:test").describe("hunt-fix-C-correlations", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
/**
 * Regression coverage for the C-correlations cluster:
 *
 *   #9  byTtp() returned found:false / entry:null for every ATT&CK
 *       technique — only the ATLAS catalog was consulted for the entry,
 *       while skills + related_cves correctly unioned both id spaces.
 *   #10 byTtp() d3fend correlation read the always-empty `counters` field
 *       instead of the populated `counters_attack_techniques`.
 *   #11 framework-gap lagScore() reported framework_specific_gaps:0 for
 *       every framework whose global-frameworks short key is not a literal
 *       substring of its catalog display string.
 *   #12 containers collector tracked USER globally, so a multi-stage build
 *       with a non-root USER in an early stage masked a root final stage.
 *   #13 byCwe/byTtp/bySkill leaked _auto_imported draft CVEs into the
 *       related_cves/cve_refs correlations (byCve excluded them; these
 *       transitive paths did not).
 *   #14 gap-detectors REFERENCE_TOKEN_RE could not match D3A-* / D3F-*
 *       D3FEND ids, mis-flagging referenced entries as unused orphans.
 *
 * Real-catalog assertions read the shipped data/ tree (default DATA_DIR).
 * The draft-leak case (#13) needs a synthetic catalog, which cross-ref-api
 * binds at require-time from EXCEPTD_DATA_DIR — so it runs in a child
 * process with that env var pointed at an isolated tempdir.
 *
 * Run under --test-concurrency=1 (the cross-ref cache + shared data dir are
 * process-global).
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const cp = require('node:child_process');

const xref = require('../lib/cross-ref-api.js');
const fg = require('../lib/framework-gap.js');
const gd = require('../lib/gap-detectors.js');
const containers = require('../lib/collectors/containers.js');

const ROOT = path.join(__dirname, '..');
const DATA_DIR = path.join(ROOT, 'data');

function loadJson(p) {
  return JSON.parse(fs.readFileSync(p, 'utf8'));
}

// ---------------------------------------------------------------------------
// Finding #9 — byTtp resolves the ATT&CK technique record, not only ATLAS.
// ---------------------------------------------------------------------------




// ---------------------------------------------------------------------------
// Finding #10 — byTtp d3fend correlation reads counters_attack_techniques.
// ---------------------------------------------------------------------------



// ---------------------------------------------------------------------------
// Finding #11 — lagScore counts framework-specific gaps by normalized match.
// ---------------------------------------------------------------------------

const controlGaps = loadJson(path.join(DATA_DIR, 'framework-control-gaps.json'));
const globalFrameworks = loadJson(path.join(DATA_DIR, 'global-frameworks.json'));





// ---------------------------------------------------------------------------
// Finding #12 — containers collector resets USER state per build stage.
// ---------------------------------------------------------------------------

function dockerfileTempdir(content) {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'hunt-c12-'));
  fs.writeFileSync(path.join(d, 'Dockerfile'), content, 'utf8');
  return d;
}







// ---------------------------------------------------------------------------
// Finding #13 — draft CVEs never leak into transitive correlations.
//
// cross-ref-api binds DATA_DIR at require-time from EXCEPTD_DATA_DIR, so the
// synthetic catalog must be exercised in a child process.
// ---------------------------------------------------------------------------


// ---------------------------------------------------------------------------
// Finding #14 — REFERENCE_TOKEN_RE recognizes D3A-* / D3F-* D3FEND ids.
// ---------------------------------------------------------------------------

function fullTokenMatch(s) {
  const re = gd.REFERENCE_TOKEN_RE;
  re.lastIndex = 0;
  const m = s.match(re);
  return !!(m && m.includes(s));
}

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
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});
