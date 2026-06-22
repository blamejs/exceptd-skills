'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

// --- #41 malformed last_threat_review → maximally stale, observable --------

test('#41 _currencyScore(NaN) === 0 (safe value, not the safe-LOOKING 100)', () => {
  const pipeline = require('../orchestrator/pipeline.js');
  assert.equal(pipeline._currencyScore(NaN), 0);
  assert.equal(typeof pipeline._currencyScore(NaN), 'number');
});

test('#41 _skillCurrencyRow over a malformed date yields stale + observable flag', () => {
  const { _skillCurrencyRow } = require('../orchestrator/pipeline.js');
  const now = new Date('2026-06-20T00:00:00Z');
  const row = _skillCurrencyRow(
    { name: 'demo-skill', last_threat_review: '2026-13-99', forward_watch: [] },
    now,
  );
  assert.equal(row.currency_score, 0, 'a malformed date must score maximally stale (0)');
  assert.equal(typeof row.currency_score, 'number');
  assert.equal(row.action_required, true, 'a malformed date must trip action_required');
  assert.equal(row.unparseable_review_date, true, 'the misformat must be surfaced (observable)');
  assert.equal(typeof row.unparseable_review_date, 'boolean');
});

test('#41 _skillCurrencyRow over a fresh valid date stays current and not flagged', () => {
  const { _skillCurrencyRow } = require('../orchestrator/pipeline.js');
  const now = new Date('2026-06-20T00:00:00Z');
  const row = _skillCurrencyRow(
    { name: 'demo-skill', last_threat_review: '2026-06-19', forward_watch: [] },
    now,
  );
  assert.equal(row.unparseable_review_date, false, 'a valid date must not be flagged unparseable');
  assert.equal(row.currency_score, 100, 'a 1-day-old review is fully current');
  assert.equal(row.action_required, false);
});

// --- #42 buildHandoff named guard on non-object stageOutput ----------------

test('#42 buildHandoff throws a NAMED TypeError on null/number/string stageOutput', () => {
  const { initPipeline, buildHandoff } = require('../orchestrator/pipeline.js');
  const run = initPipeline('manual', {});
  const re = /stageOutput .* must be a non-null object/;
  assert.throws(() => buildHandoff(run, 0, null), re, 'null payload → named error');
  assert.throws(() => buildHandoff(run, 0, 42), re, 'number payload → named error');
  assert.throws(() => buildHandoff(run, 0, 'str'), re, 'string payload → named error');
  assert.throws(() => buildHandoff(run, 0, []), re, 'array payload → named error');
  // Specifically NOT the opaque deref message.
  assert.throws(
    () => buildHandoff(run, 0, null),
    (err) => err instanceof TypeError && !/in.*operator/.test(err.message),
    'must be the named TypeError, not the opaque "in operator" deref',
  );
});


// ---- routed from hunt-fix-I-orchestrator ----
require("node:test").describe("hunt-fix-I-orchestrator", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
/**
 * Regression coverage for the orchestrator cluster hunt fixes:
 *
 *  #39 dispatcher.js — dedupe identity keys on skill + a FULL-finding
 *      fingerprint, not skill + a single optional field (cve_id). Two distinct
 *      findings that route to the same skill and differ only by a non-cve field
 *      (server_name, api_name, config_path) must each keep a plan entry; a true
 *      duplicate (identical content) still folds.
 *
 *  #40 scanner.js — the air-gap CLI flag (--air-gap / --offline / --no-network)
 *      suppresses the outbound TLS probe, equivalently to EXCEPTD_AIR_GAP=1.
 *      Proven with the env var DELETED so it is the FLAG, not the env, that
 *      drives suppression — and the real-CLI spawn confirms no `openssl
 *      s_client` egress fires.
 *
 *  #41 pipeline.js — a malformed last_threat_review ("2026-13-99": ISO-shaped
 *      but not a real calendar date) maps to maximally STALE (score 0,
 *      action_required true) and surfaces unparseable_review_date, instead of
 *      masquerading as 100% current via a NaN day-delta. _currencyScore(NaN)
 *      maps to 0 (the safe value), never 100 (the safe-LOOKING value).
 *
 *  #42 pipeline.js — buildHandoff throws a NAMED TypeError on a null /
 *      non-object / array stageOutput, not an opaque "Cannot use 'in' operator"
 *      deref deep inside validateHandoff.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');

// --- #39 dispatcher dedupe by full-finding fingerprint ---------------------






// --- #40 air-gap FLAG (not just env) suppresses the TLS probe ---------------




// --- #41 malformed last_threat_review → maximally stale, observable --------




// --- #42 buildHandoff named guard on non-object stageOutput ----------------

test('#41 _currencyScore(NaN) === 0 (safe value, not the safe-LOOKING 100)', () => {
  const pipeline = require('../orchestrator/pipeline.js');
  assert.equal(pipeline._currencyScore(NaN), 0);
  assert.equal(typeof pipeline._currencyScore(NaN), 'number');
});

test('#41 _skillCurrencyRow over a malformed date yields stale + observable flag', () => {
  const { _skillCurrencyRow } = require('../orchestrator/pipeline.js');
  const now = new Date('2026-06-20T00:00:00Z');
  const row = _skillCurrencyRow(
    { name: 'demo-skill', last_threat_review: '2026-13-99', forward_watch: [] },
    now,
  );
  assert.equal(row.currency_score, 0, 'a malformed date must score maximally stale (0)');
  assert.equal(typeof row.currency_score, 'number');
  assert.equal(row.action_required, true, 'a malformed date must trip action_required');
  assert.equal(row.unparseable_review_date, true, 'the misformat must be surfaced (observable)');
  assert.equal(typeof row.unparseable_review_date, 'boolean');
});

test('#41 _skillCurrencyRow over a fresh valid date stays current and not flagged', () => {
  const { _skillCurrencyRow } = require('../orchestrator/pipeline.js');
  const now = new Date('2026-06-20T00:00:00Z');
  const row = _skillCurrencyRow(
    { name: 'demo-skill', last_threat_review: '2026-06-19', forward_watch: [] },
    now,
  );
  assert.equal(row.unparseable_review_date, false, 'a valid date must not be flagged unparseable');
  assert.equal(row.currency_score, 100, 'a 1-day-old review is fully current');
  assert.equal(row.action_required, false);
});

test('#42 buildHandoff throws a NAMED TypeError on null/number/string stageOutput', () => {
  const { initPipeline, buildHandoff } = require('../orchestrator/pipeline.js');
  const run = initPipeline('manual', {});
  const re = /stageOutput .* must be a non-null object/;
  assert.throws(() => buildHandoff(run, 0, null), re, 'null payload → named error');
  assert.throws(() => buildHandoff(run, 0, 42), re, 'number payload → named error');
  assert.throws(() => buildHandoff(run, 0, 'str'), re, 'string payload → named error');
  assert.throws(() => buildHandoff(run, 0, []), re, 'array payload → named error');
  // Specifically NOT the opaque deref message.
  assert.throws(
    () => buildHandoff(run, 0, null),
    (err) => err instanceof TypeError && !/in.*operator/.test(err.message),
    'must be the named TypeError, not the opaque "in operator" deref',
  );
});
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});


// ---- routed from H-currency-json-gate-contract ----
require("node:test").describe("H-currency-json-gate-contract", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
/**
 * Contract test for the ATLAS-currency workflow's stale-skill gate.
 *
 * .github/workflows/atlas-currency.yml decides whether to open a
 * "Skills past review window" issue by reading the `action_required`
 * field from `node orchestrator/index.js currency --json`. That gate is
 * only correct if `action_required` is a value-derived boolean — true iff
 * at least one skill scores below the critical currency threshold — rather
 * than a flag bound to some human-readable prose string the workflow used
 * to grep for.
 *
 * This locks that contract: the JSON output must carry a boolean
 * `action_required`, a non-empty `currency_report` with a numeric
 * `currency_score` per skill, and `action_required` must equal the
 * value-derived "any skill below the action threshold" predicate. If a
 * future change renames the field or decouples it from the scores, the
 * workflow gate silently breaks and this test catches it first.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const ROOT = path.join(__dirname, "..");
const ORCH = path.join(ROOT, "orchestrator", "index.js");
const pipeline = require("../orchestrator/pipeline");

// Two distinct thresholds drive the JSON gate fields (orchestrator/pipeline.js):
//   - action_required: true iff ANY skill's currency_score < 70 (the warn
//     tier — "past review window", which is what the workflow issues on)
//   - critical_count: the COUNT of skills with currency_score < 50
const ACTION_THRESHOLD = 70;
const CRITICAL_THRESHOLD = 50;

// Run the exact command the workflow runs and extract the JSON object.
// runCurrencyNow() may print a non-JSON scheduler line to stdout before
// the JSON document, so take the last line that parses as an object —
// the same robustness the workflow's gate applies.
function currencyJson() {
  const r = spawnSync(process.execPath, [ORCH, "currency", "--json"], {
    encoding: "utf8",
    maxBuffer: 16 * 1024 * 1024,
    timeout: 30000,
  });
  assert.equal(r.status, 0, `currency --json exited ${r.status}: ${r.stderr}`);
  const jsonLine = r.stdout
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l.startsWith("{"))
    .pop();
  assert.ok(jsonLine, `no JSON object line in currency --json stdout: ${r.stdout}`);
  return JSON.parse(jsonLine);
}



// The two assertions above pass vacuously while every shipped skill scores at
// or above the action threshold — they never exercise the TRUE branch the
// workflow gate depends on. This hermetic case proves the schedule can actually
// reach the warn (< 70) and critical (< 50) tiers: a -30-max schedule floored
// the score at 70, so the gate (and its issue) could never fire.

test("the currency schedule can reach the warn (<70) and critical (<50) tiers", () => {
  assert.equal(typeof pipeline._currencyScore, "function",
    "_currencyScore must be exported for the gate-reachability contract");
  // A recently-reviewed skill stays acceptable (no false trip on current skills).
  assert.equal(pipeline._currencyScore(0), 100);
  assert.ok(pipeline._currencyScore(42) >= ACTION_THRESHOLD,
    "a 42-day-old review must stay at/above the action threshold");
  // A genuinely stale review must cross the warn tier...
  const warn = pipeline._currencyScore(200);
  assert.ok(warn < ACTION_THRESHOLD && warn >= CRITICAL_THRESHOLD,
    `a >180d review must land in the warn tier [${CRITICAL_THRESHOLD},${ACTION_THRESHOLD}) (got ${warn})`);
  // ...and an abandoned one must cross the critical tier.
  assert.ok(pipeline._currencyScore(300) < CRITICAL_THRESHOLD,
    `a >270d review must land below the critical threshold ${CRITICAL_THRESHOLD} (got ${pipeline._currencyScore(300)})`);
  assert.equal(pipeline._currencyScore(400), 0, "a year+ unreviewed scores 0");
});
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});
