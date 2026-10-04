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
  assert.equal(r.breakdown.framework_specific_gaps, 8);
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
  // divergent labels back to the framework, surfacing every open ISM gap. The
  // expected count comes from the registry keys, so an entry whose framework
  // label the aliases miss still fails here.
  const openIsm = Object.entries(controlGaps)
    .filter(([k, v]) => k.startsWith('AU-ISM-') && v && v.status === 'open').length;
  assert.ok(openIsm >= 5, 'the registry carries the open ISM gaps this test counts');
  const r = fg.lagScore('ASD_ISM', controlGaps, globalFrameworks);
  assert.equal(typeof r.breakdown.framework_specific_gaps, 'number');
  assert.equal(r.breakdown.framework_specific_gaps, openIsm,
    `ASD_ISM must surface all ${openIsm} open ISM gaps via catalog_aliases`);
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

test("M2: framework-gap refuses a filter that only the registry's _meta block would match", () => {
  for (const fw of ["meta", "met"]) {
    const r = cli(["framework-gap", fw, "CVE-2025-53773", "--json"]);
    assert.equal(r.status, 1, `${fw} must be refused`);
    const body = tryJson(r.stdout) || tryJson(r.stderr);
    assert.ok(body && body.ok === false, `${fw} must emit a structured refusal`);
    assert.match(body.error, /unknown framework/);
  }
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
  assert.equal(r.breakdown.framework_specific_gaps, 8);
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

require("node:test").describe("new-control requirements reach the report", () => {
  const test = require("node:test");
  const assert = require("node:assert/strict");
  const { gapReport } = require("../lib/framework-gap.js");
  const controlGaps = require("../data/framework-control-gaps.json");
  const cveCatalog = require("../data/cve-catalog.json");
  const lessons = require("../data/zeroday-lessons.json");

  // A CVE whose lesson records new controls. Resolved from the data rather than
  // hard-coded, so curation churn cannot silently turn this into a test of an
  // absent entry that passes because both sides are empty.
  const withControls = Object.entries(lessons).find(
    ([id, l]) => id.startsWith("CVE-") && Array.isArray(l.new_control_requirements) && l.new_control_requirements.length > 0
  );

  test("a CVE whose lesson records new controls reports them", () => {
    assert.ok(withControls, "the lessons catalog must contain at least one entry with new_control_requirements");
    const [cveId, lesson] = withControls;
    const r = gapReport(["all"], cveId, controlGaps, cveCatalog, { allFrameworks: true, lessons });
    assert.equal(r.new_control_requirements.length, lesson.new_control_requirements.length);
    assert.equal(r.summary.new_control_requirements, lesson.new_control_requirements.length);
    // Presence is not content: the entries must carry the real identifier and
    // requirement text, not empty placeholders shaped like the right thing.
    const first = r.new_control_requirements[0];
    assert.equal(first.id, lesson.new_control_requirements[0].id);
    assert.match(first.id, /^NEW-CTRL-/);
    assert.ok(typeof first.requirement === "string" && first.requirement.length > 20,
      "a control with no requirement text tells the operator nothing");
  });

  test("each new control names the framework controls it closes", () => {
    // Without this the control reads as free-floating advice instead of an
    // answer to one of the insufficient controls listed in the same report.
    const [cveId] = withControls;
    const r = gapReport(["all"], cveId, controlGaps, cveCatalog, { allFrameworks: true, lessons });
    assert.ok(r.new_control_requirements.some((c) => Array.isArray(c.closes) && c.closes.length > 0),
      "at least one new control must declare which framework gaps it closes");
    for (const c of r.new_control_requirements) {
      assert.ok(Array.isArray(c.closes), `${c.id} must expose closes[] as an array, got ${typeof c.closes}`);
    }
  });

  test("a free-text scenario resolves to no new controls rather than guessing", () => {
    // Anti-coincidence for the cases above: the field is CVE-keyed, so a prose
    // scenario legitimately matches nothing. If this returned entries, the
    // lookup would be matching something other than the CVE id.
    const r = gapReport(["all"], "prompt injection", controlGaps, cveCatalog, { allFrameworks: true, lessons });
    assert.deepEqual(r.new_control_requirements, []);
    assert.equal(r.summary.new_control_requirements, 0);
  });

  test("omitting the lessons catalog degrades to an empty section, not a throw", () => {
    // The parameter is optional so existing callers keep working; a missing
    // catalog must not take the whole gap report down with it.
    const [cveId] = withControls;
    const r = gapReport(["all"], cveId, controlGaps, cveCatalog, { allFrameworks: true });
    assert.deepEqual(r.new_control_requirements, []);
    assert.equal(r.summary.new_control_requirements, 0);
    // The rest of the report must still be populated — proving the empty
    // section above is the lessons lookup, not a broken report.
    assert.ok(Object.keys(r.frameworks).length > 0);
  });
});

require("node:test").describe("malformed controls never reach the renderer", () => {
  const test = require("node:test");
  const assert = require("node:assert/strict");
  const { gapReport } = require("../lib/framework-gap.js");
  const controlGaps = require("../data/framework-control-gaps.json");
  const cveCatalog = require("../data/cve-catalog.json");

  const CVE = "CVE-2026-11645";
  const report = (ncr) =>
    gapReport(["all"], CVE, controlGaps, cveCatalog, {
      allFrameworks: true,
      lessons: { [CVE]: { new_control_requirements: ncr } },
    });

  const WELL_FORMED = {
    id: "NEW-CTRL-001", name: "CISA-KEV-RESPONSE-SLA",
    description: "d", evidence: "e", gap_closes: ["NIST-800-53-SI-2"],
  };

  test("a bare string is dropped", () => {
    // The original defect: three entries held a string here, and the report
    // printed "- undefined undefined:".
    const r = report(["Enforce timely remediation of ..."]);
    assert.deepEqual(r.new_control_requirements, []);
    assert.equal(r.summary.new_control_requirements, 0);
  });

  test("an object missing the fields the renderer prints is dropped", () => {
    // Guarding the id alone let this through as "NEW-X undefined:" — the guard
    // covered the case that prompted it and nothing else.
    for (const partial of [
      { id: "NEW-X" },
      { id: "NEW-X", name: "N" },
      { id: "NEW-X", name: "", description: "d" },
      { id: "", name: "N", description: "d" },
      { id: "NEW-X", name: "N", description: "   " },
    ]) {
      const r = report([partial]);
      assert.deepEqual(r.new_control_requirements, [],
        `expected ${JSON.stringify(partial)} to be dropped`);
    }
  });

  test("a well-formed control alongside a malformed one still reports", () => {
    // Anti-coincidence: a filter that dropped everything would pass every
    // assertion above while silently removing real controls from the report.
    const r = report(["a bare string", { id: "NEW-Y" }, WELL_FORMED]);
    assert.equal(r.new_control_requirements.length, 1);
    assert.equal(r.new_control_requirements[0].id, "NEW-CTRL-001");
    assert.equal(r.summary.new_control_requirements, 1);
  });
});

require("node:test").describe("a CVE's per-control statements and lesson verdicts reach cve_analysis", () => {
  const test = require("node:test");
  const assert = require("node:assert/strict");
  const { gapReport } = require("../lib/framework-gap.js");
  const controlGaps = require("../data/framework-control-gaps.json");
  const cveCatalog = require("../data/cve-catalog.json");
  const lessons = require("../data/zeroday-lessons.json");

  // Resolved from the data so curation churn cannot turn these into tests of an
  // absent entry: a CVE carrying an AU-Essential-8 statement and at least one
  // statement under another framework, with lesson coverage and gap text for
  // that AU key. The AU key the tests read is the one the predicate checked.
  const auKey = (e, cov) => Object.keys((e && e.framework_control_gaps) || {}).find((k) =>
    k.startsWith("AU-Essential-8") && cov[k] && typeof cov[k].adequate === "boolean" &&
    typeof cov[k].gap === "string" && cov[k].gap.trim() !== "");
  const [CVE, entry] = Object.entries(cveCatalog).find(([id, e]) => {
    const keys = Object.keys((e && e.framework_control_gaps) || {});
    const cov = (lessons[id] && lessons[id].framework_coverage) || {};
    return id.startsWith("CVE-") && !e._auto_imported && !!auKey(e, cov) &&
      keys.some((k) => !k.startsWith("AU-Essential-8"));
  });
  const AU = auKey(entry, lessons[CVE].framework_coverage);

  test("with every framework, each statement and each coverage key reaches the report with its text", () => {
    const r = gapReport(["all"], CVE, controlGaps, cveCatalog, { allFrameworks: true, lessons });
    const cov = lessons[CVE].framework_coverage;
    const expected = [...new Set([...Object.keys(entry.framework_control_gaps), ...Object.keys(cov)])].sort();
    assert.equal(r.cve_analysis.cve_id, CVE);
    assert.deepEqual(r.cve_analysis.controls.map((c) => c.control), expected);
    assert.equal(r.summary.cve_controls, expected.length);
    const au = r.cve_analysis.controls.find((c) => c.control === AU);
    assert.equal(au.statement, entry.framework_control_gaps[AU]);
    assert.equal(au.covered, cov[AU].covered);
    assert.equal(au.adequate, cov[AU].adequate);
    assert.equal(au.framework, controlGaps[AU].framework);
    assert.equal(au.control_name, controlGaps[AU].control_name);
    assert.ok(typeof au.statement === "string" && au.statement.length > 40,
      "a record without the statement text tells the operator nothing");
  });

  test("a framework filter keeps only that framework's controls", () => {
    const one = gapReport(["au-essential-8"], CVE, controlGaps, cveCatalog, { lessons });
    const all = gapReport(["all"], CVE, controlGaps, cveCatalog, { allFrameworks: true, lessons });
    assert.ok(one.cve_analysis.controls.length > 0);
    for (const c of one.cve_analysis.controls) assert.match(c.control, /^AU-Essential-8/);
    // Anti-coincidence: the unfiltered report carries more, so the filter did work.
    assert.ok(all.cve_analysis.controls.length > one.cve_analysis.controls.length);
    // A display-name filter matches through the registry's framework field.
    const byName = gapReport([controlGaps[AU].framework], CVE, controlGaps, cveCatalog, { lessons });
    assert.deepEqual(byName.cve_analysis.controls.map((c) => c.control), one.cve_analysis.controls.map((c) => c.control));
  });

  test("a free-text scenario, an id the catalog does not carry, and the catalog's _meta key resolve to null", () => {
    // The last scenario carries a catalog id inside free text; only an exact id resolves.
    for (const scenario of ["prompt injection", "CVE-1999-99999", "_meta", `${CVE} exploitation`]) {
      const r = gapReport(["all"], scenario, controlGaps, cveCatalog, { allFrameworks: true, lessons });
      assert.equal(r.cve_analysis, null, scenario);
      assert.equal(r.summary.cve_controls, 0, scenario);
    }
  });

  test("an id with an underscore inside it resolves; only a leading underscore marks a non-entry key", () => {
    const ID = "VENDOR_ADV-2099-0001";
    const cat = { [ID]: { framework_control_gaps: { "ZZ-SYNTHETIC-UNDERSCORE": "statement" } } };
    const r = gapReport(["all"], ID, controlGaps, cat, { allFrameworks: true });
    assert.equal(r.cve_analysis.cve_id, ID);
    assert.equal(r.cve_analysis.controls.length, 1);
  });

  test("the CVE id matches case-insensitively", () => {
    const r = gapReport(["all"], CVE.toLowerCase(), controlGaps, cveCatalog, { allFrameworks: true, lessons });
    assert.equal(r.cve_analysis.cve_id, CVE);
  });

  test("an auto-imported draft reports no statements", () => {
    const draft = { "CVE-2099-0001": { _auto_imported: true, framework_control_gaps: { [AU]: "placeholder" } } };
    const r = gapReport(["all"], "CVE-2099-0001", controlGaps, draft, { allFrameworks: true });
    assert.equal(r.cve_analysis, null);
  });

  test("a key outside the registry matches a filter on its prefix and appears with every framework", () => {
    const KEY = "ZZ-SYNTHETIC-CONTROL-1";
    assert.equal(controlGaps[KEY], undefined, "the fixture key must not exist in the registry");
    const cat = { "CVE-2099-0002": { framework_control_gaps: { [KEY]: "statement text" } } };
    const les = { "CVE-2099-0002": { framework_coverage: { [KEY]: { covered: true, adequate: false, gap: "g" } } } };
    const all = gapReport(["all"], "CVE-2099-0002", controlGaps, cat, { allFrameworks: true, lessons: les });
    assert.deepEqual(all.cve_analysis.controls, [{
      control: KEY, framework: null, control_name: null,
      statement: "statement text", covered: true, adequate: false, coverage_gap: "g",
    }]);
    assert.equal(gapReport(["zz-synthetic"], "CVE-2099-0002", controlGaps, cat, { lessons: les }).cve_analysis.controls.length, 1);
    assert.equal(gapReport(["nist-800-53"], "CVE-2099-0002", controlGaps, cat, { lessons: les }).cve_analysis.controls.length, 0);
  });

  test("a key only the lesson carries and a key only the catalog carries both reach the report", () => {
    const STATEMENT_ONLY = "ZZ-SYNTHETIC-STATEMENT-ONLY";
    const COVERAGE_ONLY = "ZZ-SYNTHETIC-COVERAGE-ONLY";
    const cat = { "CVE-2099-0004": { framework_control_gaps: { [STATEMENT_ONLY]: "statement text" } } };
    const les = { "CVE-2099-0004": { framework_coverage: { [COVERAGE_ONLY]: { covered: false, adequate: false, gap: "lesson gap" } } } };
    const r = gapReport(["all"], "CVE-2099-0004", controlGaps, cat, { allFrameworks: true, lessons: les });
    assert.deepEqual(r.cve_analysis.controls, [
      { control: COVERAGE_ONLY, framework: null, control_name: null, statement: null, covered: false, adequate: false, coverage_gap: "lesson gap" },
      { control: STATEMENT_ONLY, framework: null, control_name: null, statement: "statement text", covered: null, adequate: null, coverage_gap: null },
    ]);
  });

  test("a key the registry lacks matches a key-prefix filter, all, and the framework name of its nearest registry key", () => {
    const NIST = "NIST-800-53-SI-2";
    assert.ok(controlGaps[NIST] && controlGaps[NIST].framework, "the registry must carry NIST-800-53-SI-2");
    const KEY = "NIST-800-53-ZZ-99";
    assert.equal(controlGaps[KEY], undefined, "the fixture key must not exist in the registry");
    const cat = { "CVE-2099-0005": { framework_control_gaps: { [NIST]: "registry statement" } } };
    const les = { "CVE-2099-0005": { framework_coverage: { [KEY]: { covered: true, adequate: false, gap: "lesson-only" } } } };
    const keysFor = (fw, opts = {}) => gapReport([fw], "CVE-2099-0005", controlGaps, cat, { lessons: les, ...opts }).cve_analysis.controls.map((c) => c.control);
    assert.deepEqual(keysFor("nist-800-53"), [NIST, KEY].sort());
    assert.deepEqual(keysFor("all", { allFrameworks: true }), [NIST, KEY].sort());
    // The display name reaches the lesson-only key through the registry keys it
    // shares NIST-800-53 with.
    assert.deepEqual(keysFor(controlGaps[NIST].framework), [NIST, KEY].sort());
    // Case, spaces, hyphens and underscores are ignored; the filter must be a
    // prefix, so a fragment from the middle of the key does not match it.
    assert.deepEqual(keysFor("nist_800_53"), keysFor("nist-800-53"));
    assert.deepEqual(keysFor("NIST 800 53"), keysFor("nist-800-53"));
    // A fragment from the middle of the key that names no framework does not select it.
    assert.ok(!keysFor("zz-99").includes(KEY), "a filter that is neither a key prefix nor a framework name does not select it");
  });

  test("a lesson-only key takes the framework of the registry keys sharing the most leading segments, at least two", () => {
    const registry = {
      "AA-BB-C1": { framework: "Framework One" },
      "AA-BB-C2": { framework: "Framework Two" },
      "AA-BB-C2-X": { framework: "Framework Five" },
      "AA-ZZ": { framework: "Framework Three" },
      "QQ-RR": { framework: "Framework Four" },
      "AA-BB-NONAME": { control_name: "no framework" },
      "DD-EE-1": { framework: "Doc D" },
      // Contains "Doc D" only once case, spaces and hyphens are ignored, and not
      // at its start.
      "DD-EE-2": { framework: "Updated DOC-D (2024 edition)" },
      "DD-EE-FF": { control_name: "no framework" },
    };
    const les = { "CVE-2099-0016": { framework_coverage: {
      // Two segments shared with keys of three different frameworks: ambiguous.
      "AA-BB-C9": { covered: true, adequate: false, gap: "two segments, several frameworks" },
      // Three segments shared with AA-BB-C2 and AA-BB-C2-X.
      "AA-BB-C2-Y": { covered: true, adequate: false, gap: "three segments shared" },
      "AA-QQ": { covered: true, adequate: false, gap: "one segment shared" },
      // Segments compare without case: three shared with AA-BB-C1.
      "aa-bb-c1-lower": { covered: true, adequate: false, gap: "lower case" },
      // A case variant of a registry key shares every segment with it.
      "aa-bb-c1": { covered: true, adequate: false, gap: "case variant of AA-BB-C1" },
      // Two segments shared with two names of one framework.
      "DD-EE-9": { covered: true, adequate: false, gap: "two segments, one framework" },
      // Three segments shared with the entry that has no framework name, which is
      // skipped, so the match falls back to DD-EE-1 and DD-EE-2.
      "DD-EE-FF-1": { covered: true, adequate: false, gap: "nearest named keys share two" },
    } } };
    // A catalog statement on a registry key, which matches only its own framework.
    const cat = { "CVE-2099-0016": { framework_control_gaps: { "AA-BB-C2": "registry statement" } } };
    const keysFor = (fw) => gapReport([fw], "CVE-2099-0016", registry, cat, { lessons: les }).cve_analysis.controls.map((c) => c.control);
    assert.deepEqual(keysFor("Framework One"), ["aa-bb-c1", "aa-bb-c1-lower"]);
    assert.deepEqual(keysFor("framework two"), ["AA-BB-C2", "AA-BB-C2-Y"]);
    assert.deepEqual(keysFor("Framework Five"), ["AA-BB-C2-Y"]);
    assert.deepEqual(keysFor("Doc D"), ["DD-EE-9", "DD-EE-FF-1"]);
    assert.deepEqual(keysFor("Updated DOC-D (2024 edition)"), ["DD-EE-9", "DD-EE-FF-1"]);
    // A single shared segment is not enough, and an unrelated framework selects nothing.
    assert.deepEqual(keysFor("Framework Three"), []);
    assert.deepEqual(keysFor("Framework Four"), []);
  });

  test("a two-segment stem shared by several documents attributes a key to none of them", () => {
    // NIST-800 starts the registry keys of several NIST 800 documents, and
    // ISO-IEC those of several ISO/IEC standards.
    const les = { "CVE-2099-0018": { framework_coverage: {
      "NIST-800-171-3.14.1": { covered: true, adequate: false, gap: "g" },
      "ISO-IEC-27001-2022-A.8.8": { covered: true, adequate: false, gap: "g" },
    } } };
    const keysFor = (fw) => gapReport([fw], "CVE-2099-0018", controlGaps, { "CVE-2099-0018": {} }, { lessons: les }).cve_analysis.controls.map((c) => c.control);
    assert.equal(controlGaps["NIST-800-171-3.14.1"], undefined);
    assert.deepEqual(keysFor("nist-800-53"), []);
    assert.deepEqual(keysFor(controlGaps["NIST-800-53-SI-2"].framework), []);
    const iso42001 = Object.keys(controlGaps).find((k) => /^ISO-IEC-42001/.test(k));
    assert.ok(iso42001, "the registry must carry an ISO-IEC-42001 key");
    assert.deepEqual(keysFor(controlGaps[iso42001].framework), []);
    // `all` still lists both.
    assert.equal(gapReport(["all"], "CVE-2099-0018", controlGaps, { "CVE-2099-0018": {} }, { allFrameworks: true, lessons: les }).cve_analysis.controls.length, 2);
  });

  test("a full framework name and its short form select the same lesson-only ISO control", () => {
    const KEY = "ISO-27001-2022-A.99.99";
    assert.equal(controlGaps[KEY], undefined, "the fixture key must not exist in the registry");
    const les = { "CVE-2099-0017": { framework_coverage: { [KEY]: { covered: true, adequate: false, gap: "g" } } } };
    const keysFor = (fw) => gapReport([fw], "CVE-2099-0017", controlGaps, { "CVE-2099-0017": {} }, { lessons: les }).cve_analysis.controls.map((c) => c.control);
    assert.deepEqual(keysFor("ISO/IEC 27001:2022"), [KEY]);
    assert.deepEqual(keysFor("iso-27001-2022"), [KEY]);
    // A filter contained in the nearest key's framework name, and no key prefix.
    assert.deepEqual(keysFor("ISO/IEC 27001"), [KEY]);
    // ISO/IEC 27017 shares only the ISO segment with it.
    const other = Object.keys(controlGaps).find((k) => /^ISO-27017-/.test(k));
    assert.ok(other, "the registry must carry an ISO-27017 key");
    assert.deepEqual(keysFor(controlGaps[other].framework), []);
  });

  test("several filters select the union of what each selects alone", () => {
    const NIST = "NIST-800-53-SI-2";
    const AU = "AU-Essential-8-Patch";
    assert.ok(controlGaps[NIST] && controlGaps[AU], "the registry must carry both fixture keys");
    const cat = { "CVE-2099-0011": { framework_control_gaps: { [NIST]: "s1", [AU]: "s2", "ISO-27001-2022-A.8.8": "s3" } } };
    const keysFor = (ids) => gapReport(ids, "CVE-2099-0011", controlGaps, cat, {}).cve_analysis.controls.map((c) => c.control);
    assert.deepEqual(keysFor(["nist-800-53"]), [NIST]);
    assert.deepEqual(keysFor(["au-essential-8"]), [AU]);
    assert.deepEqual(keysFor(["nist-800-53", "au-essential-8"]), [AU, NIST]);
    assert.deepEqual(keysFor([controlGaps[NIST].framework, controlGaps[AU].framework]), [AU, NIST]);
    assert.equal(gapReport(["nist-800-53", "au-essential-8"], "CVE-2099-0011", controlGaps, cat, {}).summary.cve_controls, 2);
  });

  test("a registry key matches a filter its framework name contains once normalized", () => {
    // "essential-eight" reaches "ASD Essential Eight (AU)" only after case,
    // spaces and hyphens are ignored; the key does not start with it.
    const KEY = "AU-Essential-8-Patch";
    assert.equal(controlGaps[KEY].framework, "ASD Essential Eight (AU)");
    const cat = { "CVE-2099-0012": { framework_control_gaps: { [KEY]: "statement" } } };
    assert.deepEqual(gapReport(["essential-eight"], "CVE-2099-0012", controlGaps, cat, {}).cve_analysis.controls.map((c) => c.control), [KEY]);
  });

  test("a registry entry with no framework name matches no filter, as in the registry-gap section", () => {
    const registry = { "ZZ-NOFW-1": { control_name: "No framework", status: "open", evidence_cves: ["CVE-2099-0015"] } };
    const cat = { "CVE-2099-0015": { framework_control_gaps: { "ZZ-NOFW-1": "statement" } } };
    const report = (fw, opts = {}) => gapReport([fw], "CVE-2099-0015", registry, cat, opts);
    for (const fw of ["zz-nofw", "defined"]) {
      assert.deepEqual(report(fw).cve_analysis.controls, [], fw);
      assert.equal(report(fw).frameworks[fw].gap_count, 0, `${fw}: the registry-gap section skips it too`);
    }
    // `all` still lists it.
    assert.deepEqual(report("all", { allFrameworks: true }).cve_analysis.controls.map((c) => c.control), ["ZZ-NOFW-1"]);
  });

  test("only an exact catalog id resolves, not one that a longer id starts with or contains", () => {
    const ids = Object.keys(cveCatalog).filter((k) => k.startsWith("CVE-") && !cveCatalog[k]._auto_imported);
    const set = new Set(ids);
    // A catalog id that is a proper prefix of another catalog id listed before it,
    // so a lookup that matches by prefix or substring would return the longer id.
    const shorter = ids.find((a) => ids.some((b) => b !== a && b.startsWith(a) && ids.indexOf(b) < ids.indexOf(a)));
    assert.ok(shorter, "the catalog must carry an id that a longer, earlier-listed id starts with");
    assert.equal(gapReport(["all"], shorter, controlGaps, cveCatalog, { allFrameworks: true, lessons }).cve_analysis.cve_id, shorter);
    // A truncated id that is not itself a catalog id.
    const truncated = ids.map((b) => b.slice(0, -1)).find((t) => !set.has(t) && ids.some((b) => b.startsWith(t)));
    const r = gapReport(["all"], truncated, controlGaps, cveCatalog, { allFrameworks: true, lessons });
    assert.equal(r.cve_analysis, null, truncated);
    assert.equal(r.summary.cve_controls, 0);
  });

  test("a registry key matches a filter its framework name contains", () => {
    // AU-ISM-1546's framework name contains "ISM"; its key does not start with it.
    const KEY = "AU-ISM-1546";
    assert.ok(controlGaps[KEY] && /\bISM\b/.test(controlGaps[KEY].framework), "the registry must carry AU-ISM-1546 under an ISM framework name");
    const cat = { "CVE-2099-0006": { framework_control_gaps: { [KEY]: "statement" } } };
    const r = gapReport(["ism"], "CVE-2099-0006", controlGaps, cat, {});
    assert.deepEqual(r.cve_analysis.controls.map((c) => c.control), [KEY]);
    assert.equal(r.summary.cve_controls, 1);
  });

  test("an entry or coverage value of the wrong shape is read as empty", () => {
    const KEY = "ZZ-SYNTHETIC-SHAPE";
    assert.equal(gapReport(["all"], "CVE-2099-0007", controlGaps, { "CVE-2099-0007": "not an object" }, { allFrameworks: true }).cve_analysis, null);
    // An array entry is not an entry either, even with lesson coverage beside it.
    const arrLes = { "CVE-2099-0007": { framework_coverage: { [KEY]: { covered: true, adequate: false, gap: "g" } } } };
    assert.equal(gapReport(["all"], "CVE-2099-0007", controlGaps, { "CVE-2099-0007": [] }, { allFrameworks: true, lessons: arrLes }).cve_analysis, null);
    const cat = { "CVE-2099-0008": { framework_control_gaps: ["not", "an", "object"] } };
    const les = { "CVE-2099-0008": { framework_coverage: { [KEY]: "not an object" } } };
    assert.deepEqual(gapReport(["all"], "CVE-2099-0008", controlGaps, cat, { allFrameworks: true, lessons: les }).cve_analysis.controls, []);
    const cat2 = { "CVE-2099-0009": { framework_control_gaps: { [KEY]: "statement" } } };
    const les2 = { "CVE-2099-0009": { framework_coverage: [{ covered: true, adequate: true, gap: "array element" }] } };
    assert.deepEqual(gapReport(["all"], "CVE-2099-0009", controlGaps, cat2, { allFrameworks: true, lessons: les2 }).cve_analysis.controls, [
      { control: KEY, framework: null, control_name: null, statement: "statement", covered: null, adequate: null, coverage_gap: null },
    ]);
    // JSON null in each position reads as empty rather than throwing.
    assert.deepEqual(gapReport(["all"], "CVE-2099-0013", controlGaps, { "CVE-2099-0013": { framework_control_gaps: null } }, { allFrameworks: true }).cve_analysis.controls, []);
    const stmtOnly = { "CVE-2099-0014": { framework_control_gaps: { [KEY]: "statement" } } };
    const expected = [{ control: KEY, framework: null, control_name: null, statement: "statement", covered: null, adequate: null, coverage_gap: null }];
    for (const coverage of [null, { [KEY]: null }]) {
      const les3 = { "CVE-2099-0014": { framework_coverage: coverage } };
      assert.deepEqual(gapReport(["all"], "CVE-2099-0014", controlGaps, stmtOnly, { allFrameworks: true, lessons: les3 }).cve_analysis.controls, expected, JSON.stringify(coverage));
    }
  });

  test("the text section prints each control's statement and lesson line, and nothing for an empty section", () => {
    const { cveAnalysisLines, frameworkGapSummaryLine } = require("../orchestrator/index.js");
    assert.deepEqual(cveAnalysisLines(null), []);
    assert.deepEqual(cveAnalysisLines({ cve_id: "CVE-2099-0010", controls: [] }), []);
    const rec = (o) => ({ control: "K", framework: null, control_name: null, statement: null, covered: null, adequate: null, coverage_gap: null, ...o });
    assert.deepEqual(cveAnalysisLines({ cve_id: "CVE-2099-0010", controls: [
      rec({ control: "A", control_name: "Name A", statement: "stmt A", covered: true, adequate: false, coverage_gap: "gap A" }),
      rec({ control: "B", covered: false, adequate: true }),
      rec({ control: "C", coverage_gap: "gap only" }),
      rec({ control: "D", statement: "stmt only" }),
    ] }), [
      "### CVE-2099-0010 against each control: 4 record(s)",
      "  - A (Name A)",
      "    statement: stmt A",
      "    lesson: covered, not adequate. gap A",
      "  - B",
      "    lesson: not covered, adequate",
      "  - C",
      "    lesson: gap only",
      "  - D",
      "    statement: stmt only",
      "",
    ]);
    // Five distinct counts, so a count printed in another count's slot fails.
    assert.equal(
      frameworkGapSummaryLine({ total_gaps: 1, universal_gaps: 2, new_control_requirements: 3, cve_controls: 4, theater_risk_controls: 5 }),
      "Summary: 1 matching gaps, 2 universal, 3 new controls required, 4 CVE control records, 5 theater-risk controls",
    );
  });

  test("a malformed value becomes null, and a record with nothing printable is dropped", () => {
    const cat = { "CVE-2099-0003": { framework_control_gaps: { [AU]: { text: "not a string" }, "X-EMPTY": "   " } } };
    const les = { "CVE-2099-0003": { framework_coverage: {
      [AU]: { covered: "yes", adequate: "partial", gap: "the gap" },
      "X-EMPTY": {},
      "X-FALSE-ONLY": { covered: false, adequate: false },
      "X-COVERED-ONLY": { covered: true },
      "X-ADEQUATE-ONLY": { adequate: false },
    } } };
    const r = gapReport(["all"], "CVE-2099-0003", controlGaps, cat, { allFrameworks: true, lessons: les });
    assert.deepEqual(r.cve_analysis.controls, [
      {
        control: AU, framework: controlGaps[AU].framework, control_name: controlGaps[AU].control_name,
        statement: null, covered: null, adequate: null, coverage_gap: "the gap",
      },
      // A record with any one verdict, true or false, has something to print and is kept.
      { control: "X-ADEQUATE-ONLY", framework: null, control_name: null, statement: null, covered: null, adequate: false, coverage_gap: null },
      { control: "X-COVERED-ONLY", framework: null, control_name: null, statement: null, covered: true, adequate: null, coverage_gap: null },
      { control: "X-FALSE-ONLY", framework: null, control_name: null, statement: null, covered: false, adequate: false, coverage_gap: null },
    ]);
  });

  test("every lesson coverage verdict is boolean, and a gap, when present, is non-empty text", () => {
    // The report prints covered/adequate as words; a string verdict such as
    // "partial" would be dropped to null and the operator would lose it.
    const bad = [];
    for (const [id, l] of Object.entries(lessons)) {
      for (const [k, v] of Object.entries((l && l.framework_coverage) || {})) {
        if (!v || typeof v !== "object" || typeof v.covered !== "boolean" || typeof v.adequate !== "boolean") bad.push(`${id} ${k}: ${JSON.stringify(v).slice(0, 80)}`);
        else if ("gap" in v && (typeof v.gap !== "string" || v.gap.trim() === "")) bad.push(`${id} ${k}: empty gap`);
      }
    }
    assert.deepEqual(bad, []);
    // Positive control: the sweep read real coverage entries.
    assert.ok(Object.values(lessons).filter((l) => l && l.framework_coverage && Object.keys(l.framework_coverage).length).length > 1000);
  });

  test("the CLI prints the statement and the lesson verdict, and --json carries cve_analysis", () => {
    const { makeSuiteHome, makeCli, tryJson } = require("./_helpers/cli");
    const cli = makeCli(makeSuiteHome("exceptd-cve-analysis-"));
    const cov = lessons[CVE].framework_coverage[AU];

    const text = cli(["framework-gap", "au-essential-8", CVE]);
    assert.equal(text.status, 0, text.stderr.slice(0, 300));
    assert.ok(text.stdout.includes(`### ${CVE} against each control:`), "the section heading must print");
    assert.ok(text.stdout.includes(`    statement: ${entry.framework_control_gaps[AU]}`), "the full statement must print, not a truncation");
    const verdict = `${cov.covered ? "covered" : "not covered"}, ${cov.adequate ? "adequate" : "not adequate"}`;
    assert.ok(text.stdout.includes(`    lesson: ${verdict}. ${cov.gap}`), `the lesson verdict and its reason must print as "${verdict}. <gap>"`);

    const json = cli(["framework-gap", "au-essential-8", CVE, "--json"]);
    assert.equal(json.status, 0);
    const body = tryJson(json.stdout);
    assert.ok(body && body.cve_analysis, "--json must carry cve_analysis");
    const au = body.cve_analysis.controls.find((c) => c.control === AU);
    assert.equal(au.statement, entry.framework_control_gaps[AU]);
    assert.equal(au.adequate, cov.adequate);
    assert.equal(body.summary.cve_controls, body.cve_analysis.controls.length);
    assert.ok(text.stdout.includes(`### ${CVE} against each control: ${body.cve_analysis.controls.length} record(s)`));
  });

  test("the CLI prints the CVE record count in its summary slot and in the section heading", () => {
    const { makeSuiteHome, makeCli, tryJson } = require("./_helpers/cli");
    const cli = makeCli(makeSuiteHome("exceptd-cve-analysis-counts-"));
    // A CVE whose cve_controls count differs from every other summary count, so
    // the CVE record count printed in another slot fails. The order of the other
    // counts is pinned by the frameworkGapSummaryLine test above.
    const distinct = (s) => [s.total_gaps, s.universal_gaps, s.new_control_requirements, s.theater_risk_controls].every((n) => n !== s.cve_controls);
    const id = Object.keys(cveCatalog).find((k) => k.startsWith("CVE-") && !cveCatalog[k]._auto_imported &&
      distinct(gapReport(["all"], k, controlGaps, cveCatalog, { allFrameworks: true, lessons }).summary));
    assert.ok(id, "a CVE whose cve_controls count differs from the other summary counts must exist");
    const body = tryJson(cli(["framework-gap", "all", id, "--json"]).stdout);
    const s = body.summary;
    const out = cli(["framework-gap", "all", id]).stdout;
    assert.equal(s.cve_controls, body.cve_analysis.controls.length);
    assert.ok(out.includes(`### ${id} against each control: ${s.cve_controls} record(s)`), "the section heading carries the record count");
    assert.ok(out.includes(`Summary: ${s.total_gaps} matching gaps, ${s.universal_gaps} universal, ${s.new_control_requirements} new controls required, ${s.cve_controls} CVE control records, ${s.theater_risk_controls} theater-risk controls`),
      "the summary line carries the CVE record count in its own slot");
  });

  test("the CLI prints no CVE section for a free-text scenario or an id the catalog does not carry", () => {
    const { makeSuiteHome, makeCli } = require("./_helpers/cli");
    const cli = makeCli(makeSuiteHome("exceptd-cve-analysis-free-"));
    for (const scenario of ["prompt injection", "CVE-1999-99999"]) {
      const r = cli(["framework-gap", "all", scenario]);
      assert.equal(r.status, 0, `${scenario}: ${r.stderr.slice(0, 300)}`);
      assert.ok(!r.stdout.includes("against each control"), `${scenario}: no CVE section`);
      assert.match(r.stdout, /, 0 CVE control records, /, scenario);
    }
  });

  test("the CLI prints no lesson line for a control the lesson does not cover", () => {
    const { makeSuiteHome, makeCli } = require("./_helpers/cli");
    const cli = makeCli(makeSuiteHome("exceptd-cve-analysis-nolesson-"));
    // A registry control with a catalog statement and no lesson coverage entry.
    let key;
    const id = Object.keys(cveCatalog).find((k) => {
      if (!k.startsWith("CVE-") || cveCatalog[k]._auto_imported) return false;
      const cov = (lessons[k] && lessons[k].framework_coverage) || {};
      key = Object.keys(cveCatalog[k].framework_control_gaps || {}).find((c) => controlGaps[c] && !(c in cov) &&
        typeof cveCatalog[k].framework_control_gaps[c] === "string" && cveCatalog[k].framework_control_gaps[c].trim() !== "");
      return !!key;
    });
    assert.ok(id, "a catalog control with no lesson coverage must exist");
    const lines = cli(["framework-gap", "all", id]).stdout.split(/\r?\n/);
    const section = lines.findIndex((l) => l.startsWith(`### ${id} against each control:`));
    assert.ok(section >= 0, `${id}: the CVE section must print`);
    const at = lines.findIndex((l, i) => i > section && (l === `  - ${key}` || l.startsWith(`  - ${key} (`)));
    assert.ok(at > section, `${id} ${key} must print in the CVE section`);
    assert.ok(lines[at + 1].startsWith("    statement: "), "its statement prints");
    assert.ok(!(lines[at + 2] || "").startsWith("    lesson:"), "no lesson line prints for a control the lesson does not cover");
  });

  test("the CLI prints each verdict word, and omits a missing statement and control name", () => {
    const { makeSuiteHome, makeCli } = require("./_helpers/cli");
    const cli = makeCli(makeSuiteHome("exceptd-cve-analysis-verdicts-"));
    const hasGap = (v) => v && typeof v.gap === "string" && v.gap.trim() !== "";
    // First lesson coverage record that satisfies `want`, on a non-draft catalog CVE.
    const pick = (want) => {
      for (const [id, l] of Object.entries(lessons)) {
        const e = cveCatalog[id];
        if (!id.startsWith("CVE-") || !e || e._auto_imported) continue;
        for (const [k, v] of Object.entries((l && l.framework_coverage) || {})) if (want(k, v, e)) return { id, k, v };
      }
      return null;
    };
    const verdictLine = (v) => `    lesson: ${v.covered ? "covered" : "not covered"}, ${v.adequate ? "adequate" : "not adequate"}. ${v.gap}`;
    const blockFor = (id, k) => {
      const lines = cli(["framework-gap", "all", id]).stdout.split(/\r?\n/);
      const section = lines.findIndex((l) => l.startsWith(`### ${id} against each control:`));
      const at = lines.findIndex((l, i) => i > section && (l === `  - ${k}` || l.startsWith(`  - ${k} (`)));
      assert.ok(section >= 0 && at > section, `${id} ${k} must print in the CVE section`);
      return lines.slice(at, at + 3);
    };

    // A control only the lesson records, which the registry does not list: no
    // control name and no statement, so its lesson line follows its name.
    const bare = pick((k, v, e) => !controlGaps[k] && !(k in (e.framework_control_gaps || {})) && v.covered === false && hasGap(v));
    assert.ok(bare, "a coverage-only, non-registry record with covered false must exist");
    const [bareName, bareNext] = blockFor(bare.id, bare.k);
    assert.equal(bareName, `  - ${bare.k}`);
    assert.equal(bareNext, verdictLine(bare.v));

    // An adequate verdict.
    const ok = pick((k, v) => v.covered === true && v.adequate === true && hasGap(v));
    assert.ok(ok, "a covered and adequate record must exist");
    assert.ok(blockFor(ok.id, ok.k).includes(verdictLine(ok.v)), `${ok.id} ${ok.k}: "covered, adequate" must print`);
  });
});

// ---------- gapReport()'s fourth parameter feeds cve_analysis only ----------

/**
 * gapReport(frameworkIds, threatScenario, controlGaps, cveCatalog, opts) resolves
 * the scenario against controlGaps alone, matching `misses`, `real_requirement`
 * and `evidence_cves`. cveCatalog supplies only `cve_analysis` and its summary
 * count. Pinned in both directions: an empty catalog changes nothing else, and
 * the real catalog does fill cve_analysis, so the parameter is neither ignored
 * nor allowed to leak into the registry matching.
 */

test('gapReport() reads cveCatalog only for cve_analysis; the rest of the report is identical for {} and the real catalog', () => {
  const withCatalog = gapReport(['NIST SP 800-53 Rev 5'], 'CVE-2026-31431', controlGaps, cveCatalog);
  const withoutCatalog = gapReport(['NIST SP 800-53 Rev 5'], 'CVE-2026-31431', controlGaps, {});
  const strip = (r) => ({ ...r, cve_analysis: undefined, summary: { ...r.summary, cve_controls: undefined } });
  assert.deepEqual(strip(withoutCatalog), strip(withCatalog),
    'the catalog must not change which registry gaps, universal gaps or theater risks the report lists');
  assert.equal(withoutCatalog.cve_analysis, null);
  assert.equal(withoutCatalog.summary.cve_controls, 0);
  assert.ok(withCatalog.cve_analysis && withCatalog.cve_analysis.controls.length > 0,
    'with the real catalog the CVE record must reach the report');
  assert.equal(withCatalog.summary.cve_controls, withCatalog.cve_analysis.controls.length);
  // Anti-coincidence: the scenario really does resolve to gaps, so the deepEqual
  // above is not two identical empty reports.
  assert.ok(
    withCatalog.frameworks['NIST SP 800-53 Rev 5'].gap_count > 0,
    'the fixture scenario must match at least one gap for the comparison to mean anything',
  );
});

test('gapReport() keeps opts in the fifth position, so allFrameworks still reaches it', () => {
  // If cveCatalog were dropped from the signature, this opts object would bind
  // to the fourth parameter and allFrameworks would silently stop applying.
  assert.equal(gapReport.length, 3, 'three required params; cveCatalog and opts are defaulted');
  const scoped = gapReport(['NIST SP 800-53 Rev 5'], 'prompt injection', controlGaps, cveCatalog, { allFrameworks: false });
  const all = gapReport(['all'], 'prompt injection', controlGaps, cveCatalog, { allFrameworks: true });
  assert.equal(typeof scoped.summary.total_gaps, 'number');
  assert.equal(typeof all.summary.total_gaps, 'number');
  assert.ok(
    all.summary.total_gaps > scoped.summary.total_gaps,
    `allFrameworks must widen the scope; got all=${all.summary.total_gaps} scoped=${scoped.summary.total_gaps} — equal counts would mean opts never arrived`,
  );
});

// ---------- registry framework names ----------

test('each framework family names one canonical framework string', () => {
  const exact = [
    [/^NIST-800-53-/, 'NIST SP 800-53 Rev 5'],
    [/^NIS2-/, 'EU NIS2 Directive (Directive (EU) 2022/2555)'],
    [/^NIST-800-218-/, 'NIST SP 800-218 (Secure Software Development Framework v1.1)'],
  ];
  for (const [re, name] of exact) {
    const off = Object.entries(controlGaps).filter(([k, g]) => re.test(k) && g.framework !== name).map(([k, g]) => `${k}: ${g.framework}`);
    assert.deepEqual(off, [], name);
  }
  // UK CAF keys may add a version and DORA keys a sub-instrument after the canonical name.
  for (const [re, prefix] of [[/^UK-CAF-/, 'UK NCSC Cyber Assessment Framework'], [/^DORA-/, 'EU DORA (Regulation 2022/2554)']]) {
    const off = Object.entries(controlGaps).filter(([k, g]) => re.test(k) && !String(g.framework).startsWith(prefix)).map(([k, g]) => `${k}: ${g.framework}`);
    assert.deepEqual(off, [], prefix);
  }
});

test('a canonical full name passed to gapReport reaches every key in its family', () => {
  const families = [
    ['NIST SP 800-53 Rev 5', /^NIST-800-53-/],
    ['UK NCSC Cyber Assessment Framework', /^UK-CAF-/],
    ['EU NIS2 Directive (Directive (EU) 2022/2555)', /^NIS2-/],
    ['EU DORA (Regulation 2022/2554)', /^DORA-/],
    ['PCI DSS v4.0.1', /^PCI-DSS-4\.0(?:\.1)?-(?!6\.3\.3$)/],
  ];
  for (const [name, re] of families) {
    const want = Object.keys(controlGaps).filter((k) => re.test(k)).sort();
    const got = gapReport([name], '', controlGaps).frameworks[name].gaps.map((g) => g.id).filter((k) => re.test(k)).sort();
    assert.ok(want.length > 0, `${name}: the family is not empty`);
    assert.deepEqual(got, want, name);
  }
});

test('lagScore for NCSC CAF counts every open UK CAF key', () => {
  const open = Object.entries(controlGaps).filter(([k, g]) => /^UK-CAF-/.test(k) && g.status === 'open').length;
  assert.equal(lagScore('NCSC_CAF', controlGaps, globalFrameworks).breakdown.framework_specific_gaps, open);
});
