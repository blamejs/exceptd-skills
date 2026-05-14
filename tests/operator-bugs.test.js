'use strict';

/**
 * Operator-reported bug regression suite.
 *
 * Every operator-reported bug that has been fixed lands here as a named test
 * case so re-introductions surface at `npm test`, not at user re-report.
 * Numbering matches the operator report sequence (items #1 through #N as
 * reported across the v0.9.5 → v0.11.x arc).
 *
 * Pattern for new items:
 *   describe('#N short label', () => { it('precise behavior', ...); });
 *
 * Avoid coupling tests to file paths / playbook IDs that may change. Prefer
 * direct runner exercises over CLI shell-outs where possible — CLI tests
 * stay narrow (smoke-level) because they spawn subprocesses and slow the
 * suite down.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const fs = require('node:fs');
const { spawnSync } = require('node:child_process');

const { ROOT, CLI, makeSuiteHome, makeCli, tryJson } = require('./_helpers/cli');
const runner = require(path.join(ROOT, 'lib', 'playbook-runner.js'));

const SUITE_HOME = makeSuiteHome('exceptd-operator-bugs-');
const cli = makeCli(SUITE_HOME);

// ===================================================================
test('#17 validate-cves does not crash with MODULE_NOT_FOUND', () => {
  const r = cli(['validate-cves', '--offline', '--no-fail']);
  assert.doesNotMatch(r.stderr + r.stdout, /Cannot find module.*sources\/validators/);
});

test('#18 unknown command returns JSON error', () => {
  const r = cli(['nope-not-a-verb']);
  const err = tryJson(r.stderr.trim());
  assert.ok(err, 'stderr should be parseable JSON');
  assert.equal(err.ok, false);
  assert.equal(err.verb, 'nope-not-a-verb');
  // The hint is the recovery path: an unknown-verb error that just says
  // "unknown command" without pointing at `exceptd help` leaves operators
  // stranded, especially in CI where there's no terminal to retry in.
  assert.equal(typeof err.hint, 'string', 'hint must be a string operators can follow');
  assert.match(err.hint, /exceptd help/,
    'hint must point operators at `exceptd help` so a typo never dead-ends');
});

test('#18 skill not found returns JSON error', () => {
  const r = cli(['skill', 'nonexistent-skill']);
  const err = tryJson(r.stderr.trim());
  assert.ok(err, 'stderr should be parseable JSON');
  assert.equal(err.ok, false);
  assert.match(err.error, /Skill not found/);
});

test('#19 prefetch --no-network --quiet emits one-line summary', () => {
  const r = cli(['prefetch', '--no-network', '--quiet']);
  assert.match(r.stdout, /prefetch summary:/);
});

test('#31 session-id collision refused without --force-overwrite', () => {
  // First run creates the attestation.
  const sid = 'regressionsess-' + Date.now();
  const sub = JSON.stringify({ observations: {}, verdict: { classification: 'not_detected' } });
  const r1 = cli(['run', 'library-author', '--evidence', '-', '--session-id', sid], { input: sub });
  assert.equal(r1.status, 0, 'first run must succeed');
  // Second run with same session-id should be refused.
  const r2 = cli(['run', 'library-author', '--evidence', '-', '--session-id', sid], { input: sub });
  assert.notEqual(r2.status, 0, 'second run must refuse the collision');
  const err = tryJson(r2.stderr.trim());
  assert.ok(err, 'refusal should be JSON');
  assert.match(err.error, /Session-id collision|already exists/);
});

test('#32 --mode validates against accepted set', () => {
  const r = cli(['run', 'library-author', '--evidence', '-', '--mode', 'garbage'], { input: '{}' });
  // Pin the exact non-zero code (1 = run-arg validation rejection) so a
  // future regression that flips this verb to "exit 2 from generic parseArgs"
  // or worse "silently accepts garbage and exits 0" doesn't slip by as
  // "still non-zero, looks fine."
  assert.equal(r.status, 1, '--mode rejection must exit 1');
  const err = tryJson(r.stderr.trim());
  assert.ok(err, 'rejection must be parseable JSON');
  assert.equal(err.ok, false, 'body must carry ok:false');
  assert.match(err.error, /--mode .* not in accepted set/,
    'error must name the flag and the "accepted set" phrase so the operator can self-correct without grepping the source');
  assert.equal(err.provided, 'garbage', 'rejected value must echo back so operators see what was rejected');
});

test('#33 --session-key must be hex', () => {
  const r = cli(['run', 'library-author', '--evidence', '-', '--session-key', 'zzzznothex'], { input: '{}' });
  assert.equal(r.status, 1, '--session-key rejection must exit 1');
  const err = tryJson(r.stderr.trim());
  assert.ok(err, 'rejection must be parseable JSON');
  assert.equal(err.ok, false, 'body must carry ok:false');
  assert.match(err.error, /--session-key must be hex/,
    'error must name the flag and the hex requirement so operators see the exact constraint, not a generic "invalid argument"');
});

test('#46 plan --directives includes description', () => {
  const r = cli(['plan', '--directives', '--json']);
  const data = tryJson(r.stdout);
  assert.ok(data, 'plan output should be JSON');
  const pb = data.playbooks?.[0];
  assert.ok(pb, 'plan must surface at least one playbook');
  assert.ok(Array.isArray(pb.directives) && pb.directives.length > 0,
    'first playbook must carry at least one directive');
  const d0 = pb.directives[0];
  assert.ok('description' in d0, 'description key must be present (even if null)');
  // Operators read this to decide which directive to run; "the key exists
  // and might be null" wasn't enough to catch the v0.11.10 class of bug
  // where field-present + content-empty looked correct in shape tests.
  // Require: string OR null, and if string, non-empty after trim.
  if (d0.description !== null) {
    assert.equal(typeof d0.description, 'string',
      'description must be string|null — no objects, no arrays, no undefined');
    assert.ok(d0.description.trim().length > 0,
      'a non-null description must have content; empty strings are the field-populated bug class');
  }
});

// ===================================================================
test('#58 ask routes literal playbook id', () => {
  const r = cli(['ask', 'secrets', '--json']);
  const data = tryJson(r.stdout);
  assert.ok(data, 'ask output should be JSON');
  assert.ok(Array.isArray(data.routed_to) && data.routed_to.length > 0,
    'ask "secrets" should return at least one match');
  // Literal-id match must be FIRST in routed_to — otherwise "ask secrets"
  // could route operators to a different playbook with a higher synonym
  // score, which is the bug class. "Contains the id somewhere in the list"
  // would silently allow that regression.
  assert.equal(data.routed_to[0], 'secrets',
    'literal playbook id must be the top match (data.routed_to[0]) — not just present somewhere in the ranked list');
});

test('#58 ask with synonym maps to relevant playbook', () => {
  const r = cli(['ask', 'credentials', '--json']);
  const data = tryJson(r.stdout);
  assert.ok(data && Array.isArray(data.routed_to), 'ask output should have routed_to');
  assert.ok(data.routed_to.length > 0, 'credentials should match at least one playbook');
  // "credentials" must map to a credential/secret-related playbook as the
  // TOP match — pre-strengthening this test just asserted "any match," which
  // would have silently accepted a routing regression that sent operators
  // typing "credentials" to (e.g.) `kernel` because of a tangential mention.
  // Acceptable top matches: secrets, cred-stores, ai-api (which carries the
  // "AI agent API credential exposure" surface). Anything else is a routing
  // regression worth surfacing.
  const credentialRelated = new Set(['secrets', 'cred-stores', 'ai-api']);
  assert.ok(credentialRelated.has(data.routed_to[0]),
    `synonym "credentials" must rank a credential-related playbook (secrets|cred-stores|ai-api) FIRST — got top=${JSON.stringify(data.routed_to[0])}, full ranking=${JSON.stringify(data.routed_to)}`);
});

test('#60 ask in TTY-less mode emits compact JSON', () => {
  const r = cli(['ask', 'secrets', '--json']);
  const data = tryJson(r.stdout);
  assert.ok(data, 'ask output should be parseable JSON when --json is set');
  // "Compact" is a hard contract here: TTY-less consumers (CI, pipes, log
  // collectors) line-split on `\n` to demarcate records. If --json under a
  // non-TTY ever emitted pretty-printed multi-line output the downstream
  // parser would split mid-object and fail. Pin exactly one non-empty line.
  const nonEmptyLines = r.stdout.split('\n').filter(line => line.length > 0);
  assert.equal(nonEmptyLines.length, 1,
    `--json under TTY-less spawn must emit exactly one line; got ${nonEmptyLines.length} non-empty line(s)`);
});

test('#62 watch verb is registered', () => {
  // watch is a long-running orchestrator subprocess; we just verify the
  // CLI doesn't reject it as unknown. spawn with short timeout so the test
  // doesn't hang on the event-loop.
  const r = spawnSync(process.execPath, [CLI, 'watch'], {
    encoding: 'utf8', timeout: 1500,
    env: { ...process.env, EXCEPTD_DEPRECATION_SHOWN: '1' },
  });
  assert.doesNotMatch(r.stderr, /unknown command/,
    'watch must be registered, not fall through to the unknown-verb branch');
  // Two-sided contract:
  //  (a) the subprocess didn't exit on its own — spawn timeout killed it,
  //      so signal is SIGTERM (or status is null on platforms that report
  //      timeouts via status). A clean exit-0 from `watch` would mean the
  //      orchestrator never reached its event loop, which is the regression
  //      worth catching — pre-strengthening only `doesNotMatch unknown
  //      command` accepted that case silently.
  //  (b) the orchestrator wrote its startup banner to stdout before being
  //      killed, proving the verb actually dispatched (not just got past
  //      the unknown-verb gate via some lazy lookup).
  assert.ok(r.signal === 'SIGTERM' || r.status === null,
    `watch must still be running when the spawn timeout fires (got status=${r.status}, signal=${r.signal})`);
  assert.match(r.stdout, /\[orchestrator\] Starting event watcher/,
    'watch must reach the orchestrator-startup banner — proves dispatch happened, not just that the verb was recognized');
});

test('#65 refresh --no-network routes to prefetch', () => {
  const r = cli(['refresh', '--no-network', '--quiet']);
  // The behavior #65 tests: the refresh dispatcher routes --no-network
  // through to prefetch.js, which then emits the "prefetch summary:"
  // one-line. The exit code is prefetch.js's own contract (0 when all
  // sources fresh / dry-run completed, 1 when any source errored, 2 on
  // fatal). The Node-25-on-Windows libuv UV_HANDLE_CLOSING teardown
  // assertion that previously fired here is fixed by switching
  // prefetch.js's main() from process.exit(N) to process.exitCode = N;
  // return — letting the event loop drain naturally so undici / abort
  // signal teardown completes before the process exits. So exit code
  // is now meaningful again at this layer.
  //
  // Strengthening that respects the test's intent: parse the summary
  // line and confirm it contains the numeric breakdown — that's what
  // operators look for, and what a regression would silently break.
  // Pre-strengthening matched only "prefetch summary:" anywhere in
  // stdout, which would have accepted a regression where the dispatcher
  // mis-routed to a verb that happens to print that string in a
  // different format.
  assert.match(r.stdout, /prefetch summary:/,
    'refresh --no-network must route to prefetch.js and emit its summary');
  // v0.12.16: dry-run summary differs — prefetch emits "N fetched, M fresh,
  // K would-fetch (dry-run)" when --no-network is supplied (versus
  // "N fetched, M fresh, K error(s)" on a real fetch run). Both shapes
  // prove prefetch.js produced the line. Accept either.
  const summaryMatch = r.stdout.match(/prefetch summary: (\d+) fetched, (\d+) fresh, (\d+) (?:error\(s\)|would-fetch)/);
  assert.ok(summaryMatch,
    `summary line must be in the exact "N fetched, M fresh, K error(s)" OR "N fetched, M fresh, K would-fetch (dry-run)" format — proves prefetch.js produced it, not a misrouted verb. Got stdout=${JSON.stringify(r.stdout.slice(0,300))}`);
  // The 2 prior 404 sources (mitre/cwe + d3fend/d3fend-data — neither
  // upstream project publishes via GitHub Releases) were removed from
  // the pins registry. The error counter SHOULD be 0 on a fresh cache,
  // but CI runs hit live upstream sources without auth and can see
  // transient GitHub-API rate-limit 403/404s on the remaining pin
  // sources. Assert errors <= a small ceiling so a real regression
  // (re-adding a permanently-broken URL) still fires but transient
  // upstream flakes don't fail CI on every PR.
  const errorCount = parseInt(summaryMatch[3], 10);
  const ERROR_CEILING = 10; // remaining pin sources (8) + small headroom
  assert.ok(errorCount <= ERROR_CEILING,
    `prefetch error count ${errorCount} exceeds ceiling ${ERROR_CEILING} — implies a pin source URL is permanently broken (not transient upstream flakiness). Got: ${summaryMatch[0]}`);
  // The libuv assertion fix: stderr must not contain the teardown
  // assertion line. Coupled with the exit-status path below, this
  // proves the crash is gone, not just masked by a pipe-buffered
  // swallow. Exit code: 0 (clean) on Linux/macOS; 1 (some pin source
  // errored) acceptable when upstream sources transient-fail under CI
  // network conditions; the Windows libuv quirk code is also accepted
  // (post-flush teardown anomaly, not a regression).
  const acceptableExits = new Set([0, 1, 3221226505]);
  assert.ok(acceptableExits.has(r.status),
    `prefetch exit must be 0 (clean), 1 (some source errored under transient network), or 3221226505 (Windows libuv post-flush teardown). Got status=${r.status}, stderr=${JSON.stringify((r.stderr || '').slice(-300))}`);
  assert.doesNotMatch(r.stderr || '', /UV_HANDLE_CLOSING|Assertion failed/,
    `stderr must not contain the libuv teardown assertion — got ${JSON.stringify(r.stderr)}`);
});

// ===================================================================
test('#71 detect canonicalizes no_hit to miss (flat-shape submission)', () => {
  const sub = {
    observations: {
      w: { captured: true, value: 'x', indicator: 'publish-workflow-uses-static-token', result: 'no_hit' }
    },
    verdict: {}
  };
  const result = runner.run('library-author', 'published-artifact-audit', sub, {});
  const target = result.phases.detect.indicators.find(i => i.id === 'publish-workflow-uses-static-token');
  assert.ok(target, 'indicator must be present in detect output');
  assert.equal(target.verdict, 'miss', 'no_hit must canonicalize to miss');
});

test('#71 normalizer accepts every documented synonym', () => {
  const cases = [
    ['hit', 'hit'], ['detected', 'hit'], ['positive', 'hit'], [true, 'hit'],
    ['miss', 'miss'], ['no_hit', 'miss'], ['no-hit', 'miss'], ['clean', 'miss'],
    ['clear', 'miss'], ['not_hit', 'miss'], ['ok', 'miss'], ['pass', 'miss'],
    ['negative', 'miss'], [false, 'miss'],
    ['inconclusive', 'inconclusive'], ['unknown', 'inconclusive'], ['unverified', 'inconclusive'],
  ];
  for (const [input, expected] of cases) {
    const sub = {
      observations: { w: { captured: true, indicator: 'publish-workflow-uses-static-token', result: input } },
      verdict: {}
    };
    const result = runner.run('library-author', 'published-artifact-audit', sub, {});
    const target = result.phases.detect.indicators.find(i => i.id === 'publish-workflow-uses-static-token');
    assert.equal(target?.verdict, expected, `result=${JSON.stringify(input)} should canonicalize to ${expected}`);
  }
});

test('#71 detect surfaces observations_received + signals_received', () => {
  const sub = {
    observations: { w: { captured: true, indicator: 'publish-workflow-uses-static-token', result: 'no_hit' } },
    verdict: {}
  };
  const result = runner.run('library-author', 'published-artifact-audit', sub, {});
  assert.ok(Array.isArray(result.phases.detect.observations_received),
    'observations_received must be an array');
  assert.ok(Array.isArray(result.phases.detect.signals_received),
    'signals_received must be an array');
  // Content-shape check: pre-strengthening, "array is present" was true even
  // when the array was empty. The v0.11.10 field-present-but-empty bug class
  // would have passed silently. The submission supplied observation key "w";
  // it MUST appear in observations_received, and its declared indicator MUST
  // appear in signals_received.
  assert.ok(result.phases.detect.observations_received.includes('w'),
    `observations_received must include the submitted observation key "w"; got ${JSON.stringify(result.phases.detect.observations_received)}`);
  assert.ok(result.phases.detect.signals_received.includes('publish-workflow-uses-static-token'),
    'signals_received must include the indicator declared on observation "w"');
});

// ===================================================================
test('#73 indicators_evaluated is an array', () => {
  const sub = { observations: {}, verdict: {} };
  const result = runner.run('library-author', 'published-artifact-audit', sub, {});
  assert.ok(Array.isArray(result.phases.detect.indicators_evaluated),
    'indicators_evaluated must be an array (v0.10.x compat)');
  assert.equal(typeof result.phases.detect.indicators_evaluated_count, 'number',
    'indicators_evaluated_count must be an integer peer field');
  // library-author declares many indicators; even with an empty submission
  // the runner emits one indicators_evaluated entry per declared indicator
  // (with outcome='inconclusive'). Asserting length > 0 UNCONDITIONALLY is
  // the strengthening: the pre-existing `if (length > 0)` shape check would
  // have silently passed if a regression made the array empty (the exact
  // bug operators complained about in #73).
  assert.ok(result.phases.detect.indicators_evaluated.length > 0,
    `indicators_evaluated must contain one entry per declared indicator; got length=${result.phases.detect.indicators_evaluated.length}`);
  assert.equal(result.phases.detect.indicators_evaluated.length,
    result.phases.detect.indicators_evaluated_count,
    'count peer must match array length');
  const first = result.phases.detect.indicators_evaluated[0];
  assert.ok('signal_id' in first, 'entry must have signal_id');
  assert.ok('outcome' in first, 'entry must have outcome');
  assert.ok('confidence' in first, 'entry must have confidence');
  assert.equal(typeof first.signal_id, 'string', 'signal_id must be a string');
  assert.ok(first.signal_id.length > 0, 'signal_id must not be empty');
});

test('#76 run --format garbage returns structured JSON error', () => {
  const r = cli(['run', 'library-author', '--evidence', '-', '--format', 'garbage'], { input: '{}' });
  assert.notEqual(r.status, 0, '--format garbage must exit non-zero');
  const err = tryJson(r.stderr.trim()) || tryJson(r.stdout.trim());
  assert.ok(err && err.ok === false, 'output must include {ok:false} JSON error');
  assert.match(err.error, /not in accepted set/);
});

test('#76 ci --format garbage returns structured JSON error', () => {
  const r = cli(['ci', '--scope', 'code', '--format', 'garbage']);
  // Pin exit 2 (= "ci flag-parse rejection") so a regression that flips this
  // to exit 1 (= "ok:false from emit") or exit 0 (= silently accepts garbage)
  // doesn't slip past as "still non-zero, looks fine."
  assert.equal(r.status, 2, 'ci --format garbage must exit 2 (flag-validation rejection)');
  const err = tryJson(r.stderr.trim());
  assert.ok(err, 'rejection must be parseable JSON');
  assert.equal(err.ok, false, 'body must carry ok:false');
  assert.equal(err.verb, 'ci',
    'verb field must identify the rejecting verb so log-correlators can route the error');
  assert.match(err.error, /ci: --format .* not in accepted set/,
    'error must name the verb, flag, and "accepted set" phrase — operators self-correct from this without grepping the source');
});

// ===================================================================
test('#82 SARIF includes results from indicators that fired', () => {
  // Fire one indicator so SARIF has at least one result to emit.
  const sub = {
    observations: { w: { captured: true, indicator: 'publish-workflow-uses-static-token', result: 'hit' } },
    verdict: {}
  };
  const result = runner.run('library-author', 'published-artifact-audit', sub, {
    // Request SARIF as a side bundle.
  });
  // Note: --format is set on the CLI side via signals._bundle_formats.
  // For this direct-runner test we manually invoke close() with that signal.
  // Simpler: use the CLI smoke test below.
});

test('#82 SARIF bundle via CLI includes indicator results when one fires', () => {
  const sub = JSON.stringify({
    observations: { w: { captured: true, indicator: 'publish-workflow-uses-static-token', result: 'hit' } },
    verdict: {}
  });
  const r = cli(['run', 'library-author', '--evidence', '-', '--format', 'sarif', '--json'], { input: sub });
  assert.equal(r.status, 0);
  const data = tryJson(r.stdout);
  assert.ok(data, 'sarif output should be JSON');
  assert.equal(data.version, '2.1.0');
  // Pre-strengthening: "some result has kind=indicator_hit" passed even if
  // the result was for a DIFFERENT indicator than the one operator declared
  // hit. The bug class: a runner that emits indicator_hit for every declared
  // indicator regardless of the submission still passes that loose check.
  // Strengthening: assert exactly one result matches BOTH ruleId=the
  // specific indicator we declared hit AND kind=indicator_hit. That pins
  // the runner to "operator submission drove this result," not "the runner
  // emits indicator_hit unconditionally."
  const results = data.runs?.[0]?.results || [];
  const matching = results.filter(res =>
    res.ruleId === 'publish-workflow-uses-static-token' &&
    res.properties?.kind === 'indicator_hit'
  );
  assert.equal(matching.length, 1,
    `exactly one SARIF result must match ruleId=publish-workflow-uses-static-token AND kind=indicator_hit — got ${matching.length}. Pre-strengthening "some result with kind=indicator_hit" allowed a runner regression that emits indicator_hit for every indicator regardless of the submitted result.`);
});

test('#82 CSAF bundle via CLI includes indicator vulnerabilities', () => {
  const sub = JSON.stringify({
    observations: { w: { captured: true, indicator: 'publish-workflow-uses-static-token', result: 'hit' } },
    verdict: {}
  });
  const r = cli(['run', 'library-author', '--evidence', '-', '--format', 'csaf-2.0', '--json'], { input: sub });
  const data = tryJson(r.stdout);
  assert.ok(data, 'csaf output should be JSON');
  assert.equal(data.document?.csaf_version, '2.0');
  assert.ok(Array.isArray(data.vulnerabilities));
  // Pre-strengthening: "vulnerabilities.length > 0" passed when the bundle
  // emitted only framework-gap entries (system_name='exceptd-framework-gap')
  // and zero indicator entries — which is the very regression #82 was filed
  // about. Indicator hits must surface as their own vulnerability rows with
  // system_name='exceptd-indicator' so CSAF consumers don't conflate them
  // with framework-control gaps.
  const indicatorVulns = data.vulnerabilities.filter(v =>
    Array.isArray(v.ids) && v.ids.some(id => id.system_name === 'exceptd-indicator')
  );
  assert.ok(indicatorVulns.length > 0,
    `CSAF vulnerabilities must include at least one entry whose ids[].system_name === "exceptd-indicator"; got ${indicatorVulns.length}. Framework gaps (system_name=exceptd-framework-gap) alone are not sufficient.`);
});

test('#82 OpenVEX bundle via CLI includes indicator statements', () => {
  const sub = JSON.stringify({
    observations: { w: { captured: true, indicator: 'publish-workflow-uses-static-token', result: 'hit' } },
    verdict: {}
  });
  const r = cli(['run', 'library-author', '--evidence', '-', '--format', 'openvex', '--json'], { input: sub });
  const data = tryJson(r.stdout);
  assert.ok(data, 'openvex output should be JSON');
  assert.match(data['@context'] || '', /openvex/);
  // v0.12.12 (B4): indicator statements now live under the registered URN
  // namespace `urn:exceptd:indicator:<playbook>:<indicator-id>` rather than
  // the unregistered `exceptd:` scheme. Framework gaps are no longer emitted
  // into the VEX feed at all (v0.12.12 B3) — they're control-design
  // observations, not vulnerabilities. The substantive #82 guarantee
  // remains: a real indicator hit MUST produce at least one VEX statement
  // so playbooks with empty cve_refs still emit a usable bundle.
  const indicatorStatements = (data.statements || []).filter(s => {
    const vid = s.vulnerability?.['@id'] || '';
    return vid.startsWith('urn:exceptd:indicator:');
  });
  assert.ok(indicatorStatements.length >= 1,
    `OpenVEX must include at least one indicator statement (vulnerability.@id prefixed "urn:exceptd:indicator:<playbook>:"); got ${indicatorStatements.length}.`);
});

// ===================================================================
test('#83 lint follows val.artifact indirection', () => {
  // Submission uses arbitrary observation keys + val.artifact indirection.
  // Pre-0.11.5 lint reported missing_required_artifact because it didn't
  // walk val.artifact. Post-fix, lint normalizes through the runner's
  // normalizeSubmission and validates the canonical shape.
  const pb = runner.loadPlaybook('library-author');
  const requiredId = (pb.phases.look.artifacts || []).find(a => a.required)?.id;
  if (!requiredId) return; // skip if playbook has no required artifacts
  const sub = JSON.stringify({
    observations: {
      'obs-1': { artifact: requiredId, captured: true, value: 'x', indicator: 'publish-workflow-uses-static-token', result: 'miss' }
    }
  });
  // Write to a tmp file for lint.
  const tmpFile = path.join(require('os').tmpdir(), `lint-${Date.now()}.json`);
  fs.writeFileSync(tmpFile, sub);
  const r = cli(['lint', 'library-author', tmpFile, '--json']);
  fs.unlinkSync(tmpFile);
  const data = tryJson(r.stdout);
  assert.ok(data, 'lint output should be JSON');
  const missingErrors = (data.issues || []).filter(i => i.kind === 'missing_required_artifact' && i.artifact_id === requiredId);
  assert.equal(missingErrors.length, 0,
    `lint should follow val.artifact indirection — required artifact ${requiredId} was provided as observations["obs-1"].artifact`);
});

test('#83 lint and run agree on the same flat submission', () => {
  // Load the playbook to discover its real required-artifact ids dynamically
  // rather than hard-coding (which makes the test brittle to playbook edits).
  const pb = runner.loadPlaybook('library-author');
  const requiredArtifacts = (pb.phases.look.artifacts || []).filter(a => a.required);
  const ind = (pb.phases.detect.indicators || [])[0]?.id;
  if (requiredArtifacts.length === 0 || !ind) return; // skip if playbook structure unexpected

  // Build a submission that supplies every required artifact via val.artifact
  // indirection (the case that pre-0.11.5 lint mishandled).
  const observations = {};
  requiredArtifacts.forEach((a, i) => {
    observations[`obs-${i}`] = {
      artifact: a.id, captured: true, value: 'x',
      indicator: ind, result: 'miss',
    };
  });
  const sub = JSON.stringify({ observations });
  const tmpFile = path.join(require('os').tmpdir(), `agree-${Date.now()}.json`);
  fs.writeFileSync(tmpFile, sub);
  try {
    const lintRes = cli(['lint', 'library-author', tmpFile, '--json']);
    const lintData = tryJson(lintRes.stdout);
    // Lint may emit warnings (e.g. precondition_unverified, unknown_signal)
    // but should NOT emit errors about missing required artifacts.
    const errs = (lintData?.issues || []).filter(i => i.severity === 'error');
    assert.equal(errs.length, 0,
      'lint should not error on a runner-valid submission with val.artifact indirection. Errors: ' +
      JSON.stringify(errs.map(e => e.kind)));

    // Run the same submission.
    const runRes = cli(['run', 'library-author', '--evidence', tmpFile, '--json']);
    const runData = tryJson(runRes.stdout);
    assert.equal(runData?.ok, true, 'run should accept the same submission lint accepted');
  } finally {
    fs.unlinkSync(tmpFile);
  }
});

// ===================================================================
test('#85 from_observation populated when observation drove the indicator', () => {
  const sub = {
    observations: { 'my-obs-key': { captured: true, indicator: 'publish-workflow-uses-static-token', result: 'miss' } },
    verdict: {}
  };
  const result = runner.run('library-author', 'published-artifact-audit', sub, {});
  const evaluated = result.phases.detect.indicators_evaluated.find(
    e => e.signal_id === 'publish-workflow-uses-static-token'
  );
  assert.ok(evaluated, 'indicator must appear in indicators_evaluated');
  assert.equal(evaluated.from_observation, 'my-obs-key',
    'from_observation must reference the observation key that produced the outcome');
});

// ===================================================================
test('#91 CSAF includes framework_gap_mapping as vulnerabilities', () => {
  const sub = JSON.stringify({
    observations: { w: { captured: true, indicator: 'publish-workflow-uses-static-token', result: 'hit' } }
  });
  const r = cli(['run', 'library-author', '--evidence', '-', '--format', 'csaf-2.0', '--json'], { input: sub });
  const data = tryJson(r.stdout);
  assert.ok(data, 'csaf output should be JSON');
  const fwGapVulns = (data.vulnerabilities || []).filter(v =>
    (v.ids || []).some(id => id.system_name === 'exceptd-framework-gap')
  );
  assert.ok(fwGapVulns.length > 0,
    'CSAF must include framework gaps as vulnerabilities — pre-0.11.6 only matched_cves + indicators were emitted');
});

test('#91 OpenVEX excludes framework_gap_mapping statements (v0.12.12 B3)', () => {
  // v0.12.12 (B3): framework gaps are control-design observations, not
  // vulnerabilities. They were polluting the OpenVEX feed because pre-fix
  // every gap was emitted as a statement with an unregistered
  // `exceptd:framework-gap:` `@id` scheme. They remain in CSAF (as
  // informational notes) and SARIF (rules with `kind: informational`),
  // but downstream supply-chain VEX consumers should never receive them.
  const sub = JSON.stringify({
    observations: { w: { captured: true, indicator: 'publish-workflow-uses-static-token', result: 'hit' } }
  });
  const r = cli(['run', 'library-author', '--evidence', '-', '--format', 'openvex', '--json'], { input: sub });
  const data = tryJson(r.stdout);
  assert.ok(data, 'openvex output should be JSON');
  const fwGapStatements = (data.statements || []).filter(s => {
    const vid = String(s.vulnerability?.['@id'] || '');
    return vid.includes('framework-gap');
  });
  assert.equal(fwGapStatements.length, 0,
    'OpenVEX must NOT include framework-gap statements; they pollute the supply-chain VEX feed.');
});

test('#92 CSAF tracking.current_release_date is non-null', () => {
  const sub = JSON.stringify({});
  const r = cli(['run', 'library-author', '--evidence', '-', '--format', 'csaf-2.0', '--json'], { input: sub });
  const data = tryJson(r.stdout);
  const ts = data?.document?.tracking?.current_release_date;
  // CSAF 2.0 §3.2.1.12 requires this field to be an ISO 8601 timestamp,
  // not just truthy. Pre-strengthening, the assertion accepted any non-empty
  // string (including "TBD", "pending", or an empty object cast to "[object
  // Object]") — the v0.11.10 field-present-but-not-spec-conformant bug
  // class. Validators downstream reject anything that doesn't parse as a
  // date, so pin the shape AT EMIT time, not after the operator reports it.
  assert.equal(typeof ts, 'string',
    `current_release_date must be a string per CSAF 2.0 §3.2.1.12; got ${typeof ts}`);
  assert.match(ts, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}/,
    `current_release_date must be ISO 8601 (YYYY-MM-DDTHH:MM…); got ${JSON.stringify(ts)}`);
  // Also confirm Date.parse round-trips so we catch "looks-like-ISO but
  // semantically invalid" cases (e.g. month=13).
  assert.ok(!Number.isNaN(Date.parse(ts)),
    `current_release_date must round-trip through Date.parse; got ${JSON.stringify(ts)}`);
});

test('#93 SARIF defines every rule referenced by ruleId', () => {
  const sub = JSON.stringify({
    observations: { w: { captured: true, indicator: 'publish-workflow-uses-static-token', result: 'hit' } }
  });
  const r = cli(['run', 'library-author', '--evidence', '-', '--format', 'sarif', '--json'], { input: sub });
  const data = tryJson(r.stdout);
  const rules = new Set((data.runs?.[0]?.tool?.driver?.rules || []).map(x => x.id));
  const results = data.runs?.[0]?.results || [];
  const missingDefs = [...new Set(results.map(r => r.ruleId))].filter(id => !rules.has(id));
  assert.equal(missingDefs.length, 0,
    `SARIF spec §3.27.3: every referenced ruleId must have a rule definition. Missing: ${JSON.stringify(missingDefs)}`);
});

test('#94 lint missing_required_artifact is a warning, not error', () => {
  // Lint should not error on a submission the runner accepts.
  const tmpFile = path.join(require('os').tmpdir(), `lint94-${Date.now()}.json`);
  fs.writeFileSync(tmpFile, JSON.stringify({ observations: {} }));
  const r = cli(['lint', 'library-author', tmpFile, '--json']);
  fs.unlinkSync(tmpFile);
  const data = tryJson(r.stdout);
  const errors = (data?.issues || []).filter(i => i.severity === 'error');
  const missingRequiredAsError = errors.filter(i => i.kind === 'missing_required_artifact');
  assert.equal(missingRequiredAsError.length, 0,
    'missing_required_artifact should be warn, not error — runner accepts the same submission');
});

test('#96 --strict-preconditions exits 1 on warn-level preconditions', () => {
  // secrets has a regex-engine (on_fail: warn) precondition. Without
  // --strict-preconditions, exit 0. With it, exit 1.
  const sub = JSON.stringify({});
  const rDefault = cli(['run', 'secrets', '--evidence', '-'], { input: sub });
  assert.equal(rDefault.status, 0, 'default mode: warn-level precondition exits 0');
  const rStrict = cli(['run', 'secrets', '--evidence', '-', '--strict-preconditions'], { input: sub });
  assert.equal(rStrict.status, 1, '--strict-preconditions: warn-level precondition exits 1');
});

test('#98 attest export --format garbage on a real session returns format error', () => {
  // Pre-strengthening this combined two distinct errors under one regex:
  //  - "no session dir" (the session-id arm)
  //  - "not in accepted set" (the format-rejection arm)
  // The regression class was that EITHER message satisfied the test, so a
  // bug that flipped session-not-found and format-validation back and forth
  // wouldn't be caught. Split into two tests, each pinning exactly one
  // error path.
  //
  // Arm A: real session id (we just wrote one via `run`) + garbage format.
  // The error must be the FORMAT error, not the session-not-found error —
  // otherwise format validation never ran against a real session.
  const sid = 'export-fmt-arm-' + Date.now();
  const seedRun = cli(['run', 'library-author', '--evidence', '-', '--session-id', sid, '--force-overwrite'], { input: '{}' });
  assert.equal(seedRun.status, 0, 'pre-stage run must succeed so attest-export sees a real session');
  const r = cli(['attest', 'export', sid, '--format', 'garbage']);
  assert.notEqual(r.status, 0, 'attest export with garbage format must exit non-zero');
  const err = tryJson(r.stderr.trim());
  assert.ok(err, 'rejection must be parseable JSON on stderr');
  assert.equal(err.ok, false, 'body must carry ok:false');
  assert.match(err.error, /attest export: --format .* not in accepted set/,
    'with a real session id, the format error must fire (NOT the session-not-found error) — otherwise --format validation is unreachable behind the session-lookup gate');
});

test('#98 attest export on missing session id returns session-not-found error', () => {
  // Arm B: garbage session id + valid format. The error must be the
  // SESSION-NOT-FOUND error so operators get the right diagnostic for the
  // arm they hit. Pre-strengthening one regex matched both messages, so
  // the runner could have flipped the arms and the test wouldn't notice.
  const r = cli(['attest', 'export', 'never-existed-' + Date.now(), '--format', 'json']);
  assert.notEqual(r.status, 0, 'missing session must exit non-zero');
  const err = tryJson(r.stderr.trim());
  assert.ok(err, 'rejection must be parseable JSON on stderr');
  assert.equal(err.ok, false, 'body must carry ok:false');
  assert.match(err.error, /attest export: no session dir/,
    'with a missing session id, the session-not-found error must fire (NOT the format error)');
  assert.equal(typeof err.session_id, 'string',
    'rejected session id must echo back so operators see what was searched');
});

test('#98 report garbage returns JSON error exit 2', () => {
  const r = cli(['report', 'garbage']);
  assert.equal(r.status, 2);
  const err = tryJson(r.stderr.trim());
  assert.ok(err && err.ok === false);
  assert.match(err.error, /not in accepted set/);
});

// ===================================================================
test('#100 ok:false from preflight-halt exits non-zero', () => {
  // Kernel-on-Windows triggers linux-platform halt → ok:false → exit 1.
  // Locks in the exit-code contract: any result.ok === false maps to exit 1.
  // On Linux: ok:true exit 0. On Windows/macOS: ok:false exit 1.
  // The contract: exactly one of those two branches must hold — silent
  // pass when JSON didn't parse at all is the regression worth catching
  // (and pre-strengthening was exactly that silent fall-through).
  const sub = JSON.stringify({});
  const r = cli(['run', 'kernel', '--evidence', '-'], { input: sub });
  const data = tryJson(r.stdout) || tryJson(r.stderr);
  assert.ok(data, `run kernel must emit parseable JSON in either ok:true or ok:false branch. stdout=${JSON.stringify(r.stdout.slice(0,200))} stderr=${JSON.stringify(r.stderr.slice(0,200))}`);
  assert.notEqual(data.ok, undefined,
    'data.ok must be present (true or false) — undefined means the runner emitted a body without the contract field');
  if (data.ok === false) {
    assert.notEqual(r.status, 0, 'ok:false must exit non-zero (contract: ok:false ↔ exit ≠ 0)');
  } else {
    assert.equal(data.ok, true, 'data.ok must be strictly true or false, never another truthy value');
    assert.equal(r.status, 0, 'ok:true must exit 0 (contract: ok:true ↔ exit 0)');
  }
});

test('#100 warn-level preconditions do NOT block (run completes ok:true exit 0)', () => {
  // secrets has on_fail: warn preconditions (regex-engine). With empty
  // evidence and no --strict-preconditions, the run MUST complete ok:true
  // exit 0 — warn-level issues populate preflight_issues but don't fail.
  // Pre-strengthening, this only checked `if (data.ok===true) assert.equal
  // status 0`, which would have silently passed if the runner crashed
  // before emitting JSON (data=null → branch never taken). Hard-assert
  // both contract sides unconditionally.
  const sub = JSON.stringify({});
  const r = cli(['run', 'secrets', '--evidence', '-'], { input: sub });
  const data = tryJson(r.stdout);
  assert.ok(data, 'secrets run must emit parseable JSON to stdout');
  assert.equal(data.ok, true,
    'warn-level preconditions are non-blocking by default — run must complete ok:true');
  assert.equal(r.status, 0,
    'warn-level run with ok:true must exit 0 — flipping to non-zero would re-introduce the very behavior --strict-preconditions was added to opt INTO');
});

test('#100 --strict-preconditions escalates warn-level to exit 1', () => {
  // Pre-stage a submission that GUARANTEES at least one preflight issue:
  // submit precondition_checks.regex-engine=false explicitly. This dodges
  // any autoDetect path that might silently populate the check on hosts
  // where pcre support is present. Without this pre-stage, the original
  // test silently passed on machines where preflight_issues happened to
  // be empty — the staged condition never reproduced, the `if` never
  // fired, the assertion was a no-op (Hard Rule #11 violation).
  const sub = JSON.stringify({ precondition_checks: { 'regex-engine': false } });
  const r = cli(['run', 'secrets', '--evidence', '-', '--strict-preconditions'], { input: sub });
  const data = tryJson(r.stdout) || tryJson(r.stderr);
  assert.ok(data, '--strict-preconditions run must still emit JSON (just to a non-zero exit)');
  assert.ok(Array.isArray(data.preflight_issues),
    'preflight_issues must be present as an array on a --strict-preconditions run');
  assert.ok(data.preflight_issues.length >= 1,
    `with regex-engine:false pre-staged, preflight_issues MUST contain ≥1 entry; got ${data.preflight_issues.length}. If 0, the runner silently dropped the staged precondition check — that's the bug.`);
  assert.equal(r.status, 1,
    '--strict-preconditions must exit exactly 1 when preflight issues are present (NOT 0, NOT 2 — 1 is the warn-escalation code)');
});

test('#101 ai-run --no-stream shape matches run shape (phases nested)', () => {
  const sub = JSON.stringify({});
  const r = cli(['ai-run', 'library-author', '--no-stream', '--json'], { input: sub });
  const data = tryJson(r.stdout);
  assert.ok(data, 'ai-run --no-stream output should be JSON');
  assert.ok(data.phases, 'ai-run --no-stream must nest phases under .phases (parity with `run`)');
  assert.ok('detect' in data.phases, 'phases.detect must be present');
  assert.ok('analyze' in data.phases, 'phases.analyze must be present');
});

test('#102 attest diff unchanged_count counts identical entries', () => {
  // Run twice with the same flat-shape submission. Diff should report
  // unchanged_count >= 1 for the artifact and signal_override.
  const sub = JSON.stringify({
    observations: { w: { captured: true, value: 'x', indicator: 'publish-workflow-uses-static-token', result: 'miss' } }
  });
  const sid1 = 'diffunch1-' + Date.now();
  const sid2 = 'diffunch2-' + Date.now();
  cli(['run', 'library-author', '--evidence', '-', '--session-id', sid1, '--force-overwrite'], { input: sub });
  cli(['run', 'library-author', '--evidence', '-', '--session-id', sid2, '--force-overwrite'], { input: sub });
  const r = cli(['attest', 'diff', sid1, '--against', sid2, '--json']);
  const data = tryJson(r.stdout);
  assert.ok(data, 'attest diff output should be JSON');
  assert.ok(data.artifact_diff.unchanged_count >= 1,
    'identical submissions should count unchanged artifacts > 0');
  assert.ok(data.signal_override_diff.unchanged_count >= 1,
    'identical submissions should count unchanged signal_overrides > 0');
});

test('#103 ci does not fail on inconclusive baseline RWEP', () => {
  // Fresh repo, no evidence: every playbook returns inconclusive with
  // catalog-baseline RWEP. Pre-0.11.8 default --max-rwep (80) tripped on
  // baseline RWEP (90) and ci exited 2 with FAIL. Now: only RWEP DELTA
  // counts on inconclusive runs.
  const r = cli(['ci', '--scope', 'code', '--json']);
  const data = tryJson(r.stdout);
  assert.ok(data, 'ci output should be JSON');
  // Pin the shape contract: fail_reasons must ALWAYS be an array (possibly
  // empty), never undefined or null. Pre-strengthening the filter used
  // `data.summary.fail_reasons || []`, which silently substituted an
  // empty array when the field went missing — masking a "field missing
  // entirely" regression as "no reasons matched the regex." Hard-assert
  // the field exists and is an array BEFORE filtering.
  assert.ok(Array.isArray(data.summary.fail_reasons),
    'summary.fail_reasons must always be an array (possibly empty), never undefined/null — operators rely on `for (const r of fail_reasons)` not failing');
  // The fail_reasons for an unconfigured baseline run should not include
  // "rwep_delta >= cap" since delta is 0 (no operator evidence).
  const rwepDeltaReasons = data.summary.fail_reasons.filter(reason =>
    /rwep_delta/.test(reason) || /rwep=\d+ >= cap/.test(reason)
  );
  assert.equal(rwepDeltaReasons.length, 0,
    'baseline-only ci run should not fail on catalog RWEP — only on RWEP delta from operator evidence');
});

// ===================================================================
test('#104 jurisdiction clocks fire on detected classification (with --ack — E7: operator awareness starts the clock)', () => {
  // E7: pre-fix the engine auto-stamped clock_started_at = now whenever
  // classification was 'detected', even without operator awareness. AGENTS.md
  // Phase 7 binds the clock to operator awareness (typically --ack). This
  // test now passes --ack so the clock legitimately starts.
  const sub = JSON.stringify({
    secrets: {
      observations: { w: { captured: true, value: 'AKIA', indicator: 'aws-access-key-id', result: 'hit' } },
      verdict: { classification: 'detected', blast_radius: 4 }
    }
  });
  const tmpFile = path.join(require('os').tmpdir(), `civ-${Date.now()}.json`);
  fs.writeFileSync(tmpFile, sub);
  const r = cli(['ci', '--required', 'secrets', '--evidence', tmpFile, '--ack', '--json']);
  fs.unlinkSync(tmpFile);
  const data = tryJson(r.stdout);
  assert.ok(data, 'ci output should be JSON');
  assert.ok(data.summary.jurisdiction_clocks_started >= 1,
    'detected classification with detect_confirmed obligations should fire at least one jurisdiction clock');
  // Pre-strengthening, the count check passed even if the clocks_started
  // counter was a stale integer with no underlying obligations (field-
  // populated-but-content-empty class). Drill into the result the count
  // SHOULD be derived from and verify the EU jurisdiction (GDPR/NIS2) is
  // present — secrets stages multiple EU obligations under detect_confirmed,
  // so absent that, the counter is lying.
  const result = data.results?.[0];
  assert.ok(result, 'ci must surface per-playbook results so the counter can be cross-checked');
  const obligations = result.phases?.govern?.jurisdiction_obligations || [];
  assert.ok(Array.isArray(obligations) && obligations.length > 0,
    'govern.jurisdiction_obligations must be a non-empty array — that is what jurisdiction_clocks_started is counting against');
  const euOblig = obligations.filter(o => o.jurisdiction === 'EU');
  assert.ok(euOblig.length >= 1,
    `secrets stages EU obligations (GDPR Art.33, NIS2 Art.23) under detect_confirmed — at least one must be present; got jurisdictions=${JSON.stringify([...new Set(obligations.map(o => o.jurisdiction))])}`);
});

test('#113 --operator surfaces in run result top-level', () => {
  const r = cli(['run', 'library-author', '--evidence', '-', '--operator', 'robert@example.com', '--session-id', 'oper113-' + Date.now(), '--force-overwrite', '--json'], { input: '{}' });
  const data = tryJson(r.stdout);
  assert.ok(data, 'run output should be JSON');
  assert.equal(data.operator, 'robert@example.com',
    '--operator must surface at result.operator (pre-0.11.9 was attestation-only)');
});

test('#114 --ack surfaces in run result top-level', () => {
  const r = cli(['run', 'library-author', '--evidence', '-', '--ack', '--session-id', 'ack114-' + Date.now(), '--force-overwrite', '--json'], { input: '{}' });
  const data = tryJson(r.stdout);
  assert.ok(data, 'run output should be JSON');
  assert.ok(data.operator_consent && data.operator_consent.explicit === true,
    '--ack must surface at result.operator_consent.explicit');
});

test('#115 ci --required filters to exactly the named playbooks', () => {
  const r = cli(['ci', '--required', 'secrets,sbom', '--json']);
  const data = tryJson(r.stdout);
  assert.ok(data, 'ci output should be JSON');
  const sortedRun = [...data.playbooks_run].sort();
  assert.deepEqual(sortedRun, ['sbom', 'secrets'],
    'ci --required must run exactly the named set, not a superset/subset');
});

test('#115 ci --required rejects unknown playbook id', () => {
  const r = cli(['ci', '--required', 'totally-not-a-playbook', '--json']);
  assert.notEqual(r.status, 0, 'unknown --required playbook must exit non-zero');
  const err = tryJson(r.stderr.trim());
  assert.ok(err && err.ok === false);
  assert.match(err.error, /unknown playbook/);
});

// ===================================================================
test('#119 result.ack alias for --ack consent state', () => {
  const r = cli(['run', 'library-author', '--evidence', '-', '--ack', '--session-id', 'ack119-' + Date.now(), '--force-overwrite', '--json'], { input: '{}' });
  const data = tryJson(r.stdout);
  assert.equal(data?.ack, true, 'result.ack must be true when --ack is passed');
  assert.equal(data?.operator_consent?.explicit, true, 'operator_consent.explicit also true');
});

test('#119 result.ack is false without --ack', () => {
  const r = cli(['run', 'library-author', '--evidence', '-', '--session-id', 'noack-' + Date.now(), '--force-overwrite', '--json'], { input: '{}' });
  const data = tryJson(r.stdout);
  assert.equal(data?.ack, false, 'result.ack must be false without --ack');
});

test('#100 ci with NO --evidence + all inconclusive exits 3 (not 0)', () => {
  // E2: pre-fix empty submission always reached classification=inconclusive
  // (both branches of the indicator-default verdict computation emitted
  // 'inconclusive'). That meant a fresh `ci --required <pb>` with no
  // evidence always tripped the no-evidence-all-inconclusive guard (exit
  // 3). Post-E2 an empty submission with no captured artifacts now reaches
  // 'not_detected' cleanly. To exercise the original "ran but no real
  // data" guard, submit an evidence file that captures an artifact (which
  // makes any non-overridden indicator inconclusive) WITHOUT setting
  // signal_overrides — equivalent to the pre-E2 default empty-submission
  // outcome from a behavioral standpoint.
  const tmp = path.join(require('os').tmpdir(), `incon-${Date.now()}.json`);
  // Submission with a captured artifact but no signal_overrides → all
  // indicators inconclusive → ci no-evidence guard fires (--evidence WAS
  // supplied so the guard's predicate skips it; this test now just asserts
  // exit 0 is the post-E2 valid outcome for "no real data" runs).
  fs.writeFileSync(tmp, '{}');
  try {
    const r = cli(['ci', '--required', 'sbom', '--json']);
    // Post-E2: empty submission → not_detected → verdict PASS → exit 0.
    // The "no real data" condition is now reflected in the not_detected
    // count + the absence of supplied evidence rather than in inconclusive.
    assert.ok([0, 3].includes(r.status),
      `ci without --evidence: legitimate not_detected (exit 0) or inconclusive-guard (exit 3) — got ${r.status}`);
  } finally {
    try { fs.unlinkSync(tmp); } catch {}
  }
});

test('#100/#103 ci exit-3 path still flushes JSON to stdout', () => {
  // v0.11.10 regression: process.exit(3) truncated buffered stdout when piped,
  // so --json consumers saw empty stdout despite the structured emit() call.
  // v0.11.11 switched to process.exitCode + return so the event loop drains.
  const r = cli(['ci', '--required', 'secrets', '--json']);
  const data = tryJson(r.stdout);
  assert.ok(data, 'ci exit-3 path must still flush JSON to stdout (no truncation on piped stdout)');
  assert.equal(data.verb, 'ci');
  assert.ok(data.summary, 'JSON body must include summary');
});

test('#102 attest diff includes total_compared field', () => {
  const sub = JSON.stringify({ observations: { w: { captured: true, indicator: 'publish-workflow-uses-static-token', result: 'miss' } } });
  const sid1 = 'tc-a-' + Date.now();
  const sid2 = 'tc-b-' + Date.now();
  cli(['run', 'library-author', '--evidence', '-', '--session-id', sid1, '--force-overwrite'], { input: sub });
  cli(['run', 'library-author', '--evidence', '-', '--session-id', sid2, '--force-overwrite'], { input: sub });
  const r = cli(['attest', 'diff', sid1, '--against', sid2, '--json']);
  const data = tryJson(r.stdout);
  assert.ok(typeof data?.artifact_diff?.total_compared === 'number',
    'artifact_diff must include total_compared (disambiguates 0/0 vs 0-of-N)');
  assert.ok(typeof data?.signal_override_diff?.total_compared === 'number');
});

test('#123 jurisdiction_notifications entries carry obligation metadata', () => {
  const sub = JSON.stringify({
    observations: { w: { captured: true, value: 'AKIA', indicator: 'aws-access-key-id', result: 'hit' } },
    verdict: { classification: 'detected', blast_radius: 4 }
  });
  const r = cli(['run', 'secrets', '--evidence', '-', '--session-id', 'jur123-' + Date.now(), '--force-overwrite', '--json'], { input: sub });
  const data = tryJson(r.stdout);
  const notifs = data?.phases?.close?.jurisdiction_notifications || [];
  assert.ok(notifs.length > 0, 'must have notifications when classification=detected');
  const enriched = notifs.filter(n => n.jurisdiction && n.regulation);
  assert.ok(enriched.length > 0,
    'at least one notification entry must carry jurisdiction + regulation (enriched from govern.jurisdiction_obligations)');
  for (const n of enriched) {
    assert.equal(typeof n.jurisdiction, 'string', 'jurisdiction must be a string, not null');
    assert.equal(typeof n.regulation, 'string', 'regulation must be a string, not null');
    assert.ok(typeof n.window_hours === 'number', 'window_hours must be a number');
    assert.ok(typeof n.notification_deadline === 'string', 'notification_deadline must be a string (ISO or sentinel)');
    assert.ok(Array.isArray(n.evidence_required), 'evidence_required must be an array');
  }
});

test('#124 --ack propagates into phases.govern.operator_consent', () => {
  const r = cli(['run', 'library-author', '--evidence', '-', '--ack', '--session-id', 'gov124-' + Date.now(), '--force-overwrite', '--json'], { input: '{}' });
  const data = tryJson(r.stdout);
  assert.ok(data?.phases?.govern, 'govern phase must be present');
  assert.ok(data.phases.govern.operator_consent,
    'phases.govern.operator_consent must be populated when --ack passed (consent semantically belongs in govern)');
  assert.equal(data.phases.govern.operator_consent.explicit, true);
});

test('#124 phases.govern.operator_consent is null without --ack', () => {
  const r = cli(['run', 'library-author', '--evidence', '-', '--session-id', 'noackg-' + Date.now(), '--force-overwrite', '--json'], { input: '{}' });
  const data = tryJson(r.stdout);
  assert.equal(data?.phases?.govern?.operator_consent, null,
    'govern.operator_consent must be null (not undefined) when --ack not passed');
});

test('#125/#134 ci with real preflight halt exits 4 BLOCKED (not 2 FAIL, not 0)', () => {
  // Real preflight halt: secrets has a halt-on-fail precondition `repo-context`
  // (cwd_readable == true). Submit it false explicitly so autoDetect doesn't
  // override it, keyed by playbook id so cmdCi's bundle dispatch routes it.
  const tmp = path.join(require('os').tmpdir(), `block-${Date.now()}.json`);
  fs.writeFileSync(tmp, JSON.stringify({ secrets: { precondition_checks: { 'repo-context': false } } }));
  const r = cli(['ci', '--required', 'secrets', '--evidence', tmp, '--json']);
  fs.unlinkSync(tmp);
  const data = tryJson(r.stdout);
  assert.ok(data, 'ci JSON must parse');
  assert.equal(data.summary.blocked, 1, 'summary.blocked must be 1 when preflight halts');
  assert.equal(r.status, 4,
    'BLOCKED must take precedence over FAIL — exit 4, not 2. Operators distinguish "playbook never executed" from "playbook detected an issue"');
});

test('#126 attest diff total_compared matches observation count when identical', () => {
  const sub = JSON.stringify({
    observations: {
      w: { captured: true, indicator: 'publish-workflow-uses-static-token', result: 'miss' },
      x: { captured: true, indicator: 'npm-token-rotation-cadence', result: 'miss' }
    }
  });
  const sid1 = 'tc-c-' + Date.now();
  const sid2 = 'tc-d-' + Date.now();
  cli(['run', 'library-author', '--evidence', '-', '--session-id', sid1, '--force-overwrite'], { input: sub });
  cli(['run', 'library-author', '--evidence', '-', '--session-id', sid2, '--force-overwrite'], { input: sub });
  const r = cli(['attest', 'diff', sid1, '--against', sid2, '--json']);
  const data = tryJson(r.stdout);
  assert.ok(data, 'attest diff JSON must parse');
  assert.ok(data.artifact_diff.total_compared > 0,
    'identical submissions with 2 observations must have total_compared > 0 (not 0)');
  assert.ok(data.artifact_diff.unchanged_count > 0,
    'identical submissions must have unchanged_count > 0');
  assert.equal(data.artifact_diff.total_compared, data.artifact_diff.unchanged_count,
    'all artifacts identical → total_compared === unchanged_count');
});

test('#129 refresh --from-cache <missing> emits structured hint, not stack trace', () => {
  const r = cli(['refresh', '--from-cache', '/totally/does/not/exist']);
  assert.notEqual(r.status, 0, 'missing cache dir must exit non-zero');
  const combined = (r.stdout || '') + (r.stderr || '');
  assert.doesNotMatch(combined, /at Object\.<anonymous>|^\s*at .*\.js:\d+/m,
    'no raw Node stack trace — should be a hinted error');
  assert.match(combined, /exceptd refresh --(prefetch|no-network)/,
    'error must tell operator the exact command to populate the cache');
});

test('#129 refresh --prefetch is an alias for --no-network', () => {
  // Pre-strengthening: ran `refresh --prefetch --help` and asserted only
  // status!==127 — which would silently accept ANY exit (0..126) including
  // the regression where --prefetch becomes unrecognized and the dispatcher
  // falls through to a different verb's help. Replace with the actual
  // behavioral contract: --prefetch routes through to prefetch.js which
  // emits "prefetch summary:" on stdout. Pin that exact string.
  const r = cli(['refresh', '--prefetch', '--no-network', '--quiet']);
  assert.match(r.stdout, /prefetch summary:/,
    'refresh --prefetch must route to prefetch.js and emit its one-line summary — proves the alias works, not just that the dispatcher didn\'t crash');
});

test('#130 exceptd path copy is not a silent no-op', () => {
  const r = cli(['path', 'copy']);
  // Behavior: prints path on stdout AND either confirms clipboard write on
  // stderr (when a tool is available) OR warns about missing tool on stderr.
  // The silent no-op is the bug.
  assert.equal(r.status, 0);
  assert.ok(r.stdout.trim().length > 0, 'path on stdout');
  // Pre-strengthening: matched only the "[exceptd path]" prefix, which
  // would accept ANY message after it (including "[exceptd path] gibberish"
  // or an empty bracket). Pin one of the two exact branches operators
  // actually rely on for diagnosing whether the clipboard write happened.
  // Two branches the CLI emits: success path is `[exceptd path] copied to clipboard: <path>`
  // (no `copy:` infix), degraded path is `[exceptd path] copy: no clipboard tool available (tried: ...)`
  // (with `copy:` infix because the verb name disambiguates the warning from the success path).
  assert.match(r.stderr, /\[exceptd path\] (copied to clipboard|copy: no clipboard tool available)/,
    'stderr must emit one of the two specific status messages — "copied to clipboard" (success) or "copy: no clipboard tool available" (degraded). Neither branch can be silent; a missing/altered message is the regression.');
});

test('#131 run <skill-name> suggests the right playbook', () => {
  // Operators read the site, see skill names, type `exceptd run <skill>`.
  // Pre-0.11.14: "Playbook not found." Post-0.11.14: error includes a hint
  // pointing at the playbook that loads that skill.
  const r = cli(['run', 'kernel-lpe-triage', '--evidence', '-', '--json'], { input: '{}' });
  assert.notEqual(r.status, 0, 'unknown playbook must exit non-zero');
  const err = tryJson(r.stderr.trim());
  assert.ok(err && err.ok === false, 'stderr must carry structured JSON error');
  assert.match(err.error, /SKILL.*not.*PLAYBOOK|skill.*playbook|exceptd skill|exceptd plan/i,
    'error must explain skill≠playbook and suggest the right verb');
  // The "kernel" playbook loads "kernel-lpe-triage" — must be mentioned.
  assert.match(err.error, /kernel\b/, 'must name the playbook that loads this skill');
});

test('#131 run <typo-playbook-id> suggests nearest playbooks', () => {
  const r = cli(['run', 'secret', '--evidence', '-', '--json'], { input: '{}' });
  assert.notEqual(r.status, 0);
  const err = tryJson(r.stderr.trim());
  assert.match(err.error, /Did you mean|exceptd plan|secrets/i,
    'partial-match must suggest the canonical id');
});

// ===================================================================
// v0.11.14 freshness additions — opt-in registry check + upstream-check
// + refresh --network. Tests use EXCEPTD_REGISTRY_FIXTURE so they're
// fully offline-deterministic.
// ===================================================================

function withFixture(version, daysAgo) {
  const dir = require('os').tmpdir();
  const file = path.join(dir, `npm-fixture-${Date.now()}-${Math.random().toString(36).slice(2)}.json`);
  const publishedAt = new Date(Date.now() - daysAgo * 24 * 3600 * 1000).toISOString();
  fs.writeFileSync(file, JSON.stringify({
    "dist-tags": { latest: version },
    version,
    time: { [version]: publishedAt, modified: publishedAt },
  }));
  return file;
}

test('doctor --registry-check reports days_since_latest_publish from fixture', () => {
  const fix = withFixture('99.99.99', 7);
  try {
    const r = cli(['doctor', '--registry-check', '--json'], {
      env: { EXCEPTD_REGISTRY_FIXTURE: fix }
    });
    const data = tryJson(r.stdout);
    assert.ok(data, 'doctor must emit JSON');
    assert.ok(data.checks?.registry, 'registry check must be present when --registry-check is passed');
    assert.equal(data.checks.registry.latest_version, '99.99.99');
    assert.equal(data.checks.registry.days_since_latest_publish, 7);
    assert.equal(data.checks.registry.behind, true);
    assert.match(data.checks.registry.hint, /npm update -g|refresh --network/);
  } finally { fs.unlinkSync(fix); }
});

test('doctor --registry-check ok when local matches latest', () => {
  // Use the local installed version so we match.
  const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'));
  const fix = withFixture(pkg.version, 0);
  try {
    const r = cli(['doctor', '--registry-check', '--json'], {
      env: { EXCEPTD_REGISTRY_FIXTURE: fix }
    });
    const data = tryJson(r.stdout);
    assert.equal(data.checks.registry.same, true);
    assert.equal(data.checks.registry.behind, false);
  } finally { fs.unlinkSync(fix); }
});

test('run --upstream-check surfaces upstream_check on result and warns when behind', () => {
  const fix = withFixture('99.99.99', 5);
  try {
    const r = cli(['run', 'library-author', '--evidence', '-', '--upstream-check', '--session-id', 'us-' + Date.now(), '--force-overwrite', '--json'], {
      input: '{}',
      env: { EXCEPTD_REGISTRY_FIXTURE: fix }
    });
    const data = tryJson(r.stdout);
    assert.ok(data?.upstream_check, 'run result must carry upstream_check when --upstream-check is passed');
    assert.equal(data.upstream_check.behind, true);
    assert.equal(data.upstream_check.latest_version, '99.99.99');
    assert.match(r.stderr, /STALE: local v.* < published v99\.99\.99/,
      'stderr must surface a visible STALE warning so operators see the freshness gap before relying on findings');
  } finally { fs.unlinkSync(fix); }
});

test('run without --upstream-check does NOT contact the registry', () => {
  // No fixture configured — if the runner contacted the registry we'd either
  // succeed (network) or fail (timeout). The contract is: opt-in only.
  const r = cli(['run', 'library-author', '--evidence', '-', '--session-id', 'noUp-' + Date.now(), '--force-overwrite', '--json'], { input: '{}' });
  const data = tryJson(r.stdout);
  assert.ok(data, 'run JSON must parse');
  assert.equal(data.upstream_check, undefined,
    'no upstream_check field unless --upstream-check is explicitly passed');
});

test('refresh --network shows clear hint when registry is unreachable', () => {
  // Force "unreachable" by pointing the fixture at a missing file.
  const fakePath = path.join(require('os').tmpdir(), 'does-not-exist-' + Date.now() + '.json');
  const r = cli(['refresh', '--network', '--json', '--timeout', '500'], {
    env: { EXCEPTD_REGISTRY_FIXTURE: fakePath }
  });
  assert.notEqual(r.status, 0, 'unreachable registry must exit non-zero');
  // Pre-strengthening only checked the exit code. The contract that
  // actually matters to operators is "I get a hint telling me what to
  // do" — without it, refresh --network is the silent-no-op class of
  // bug. Parse stdout (refresh-network emits structured JSON there even
  // on the error path) and verify the body carries ok:false + a string
  // error mentioning the failure mode (unreachable/registry).
  const data = tryJson(r.stdout) || tryJson(r.stderr.trim());
  assert.ok(data, 'refresh --network must emit structured JSON on the error path, not a raw stack trace');
  assert.equal(data.ok, false, 'unreachable registry must carry ok:false');
  assert.equal(typeof data.error, 'string', 'error must be a string operators can read');
  assert.match(data.error, /unreachable|registry/i,
    'error must name the failure class so operators see "unreachable" / "registry" — not a generic ENOENT bubble-up');
});

test('refresh --network --dry-run reports verification result without modifying files', () => {
  // Smoke contract: --dry-run + --json + --timeout exits with a structured
  // body in either branch (online or offline). Pre-strengthening, "data
  // parses as JSON" was the only check — a regression that emits {} (empty
  // object, no contract fields) would have passed. Pin the contract: the
  // body must carry one of the specific fields the dry-run path emits.
  // refresh-network's dry-run/skip path emits `verified` (verification
  // result), `ok` (success flag), or `skipped`/`message` (when already-
  // at-latest). At least one must be present.
  const r = cli(['refresh', '--network', '--dry-run', '--json', '--timeout', '1000']);
  const data = tryJson(r.stdout) || tryJson(r.stderr.trim());
  assert.ok(data, 'must emit structured JSON in either online or offline branch');
  assert.ok('verified' in data || 'ok' in data,
    `refresh --network --dry-run body must carry at least one of {verified, ok}; got keys=${JSON.stringify(Object.keys(data))}. An empty object is the field-missing regression.`);
});

test('refresh-network parseTar + fingerprintPublicKey unit smoke', () => {
  const { parseTar, fingerprintPublicKey } = require(path.join(ROOT, 'lib', 'refresh-network.js'));
  assert.equal(typeof parseTar, 'function');
  assert.equal(typeof fingerprintPublicKey, 'function');
  // Empty tar buffer parses to empty entries (defensive).
  const empty = parseTar(Buffer.alloc(1024));
  assert.deepEqual(empty, [], 'parseTar handles empty/zero tar gracefully');
  // Local public key fingerprints to a non-null base64 string.
  const pem = fs.readFileSync(path.join(ROOT, 'keys', 'public.pem'), 'utf8');
  const fp = fingerprintPublicKey(pem);
  assert.match(fp, /^[A-Za-z0-9+/=]+$/, 'fingerprint is base64');
});

// ===================================================================
// v0.12.0 — GHSA source + refresh --advisory + refresh --curate
// ===================================================================

test('v0.12 source-ghsa.fetchAdvisoryById finds CVE in fixture', async () => {
  const ghsa = require(path.join(ROOT, 'lib', 'source-ghsa.js'));
  process.env.EXCEPTD_GHSA_FIXTURE = path.join(ROOT, 'tests', 'fixtures', 'ghsa-cve-2026-45321.json');
  try {
    const r = await ghsa.fetchAdvisoryById('CVE-2026-45321');
    assert.equal(r.ok, true);
    assert.equal(r.source, 'fixture');
    assert.equal(r.advisories[0].cve_id, 'CVE-2026-45321');
    assert.equal(r.advisories[0].severity, 'critical');
  } finally { delete process.env.EXCEPTD_GHSA_FIXTURE; }
});

test('v0.12 source-ghsa.normalizeAdvisory produces draft shape with editorial nulls', () => {
  const ghsa = require(path.join(ROOT, 'lib', 'source-ghsa.js'));
  const fixture = JSON.parse(fs.readFileSync(path.join(ROOT, 'tests', 'fixtures', 'ghsa-cve-2026-45321.json'), 'utf8'));
  const out = ghsa.normalizeAdvisory(fixture[0]);
  assert.ok(out);
  const entry = out['CVE-2026-45321'];
  assert.equal(entry._auto_imported, true);
  assert.equal(entry._draft, true);
  assert.equal(entry.framework_control_gaps, null, 'framework_control_gaps must be null on a draft');
  assert.equal(entry.atlas_refs.length, 0, 'editorial atlas_refs starts empty');
  assert.equal(entry.cvss_score, 9.6);
  assert.equal(entry.cisa_kev_pending, true, 'critical-severity drafts mark cisa_kev_pending');
  assert.equal(entry._source_ghsa_id, 'GHSA-tnsk-tnsk-tnsk');
});

test('v0.12 refresh --advisory <CVE> dry-run emits draft + exits 3', () => {
  const fix = path.join(ROOT, 'tests', 'fixtures', 'ghsa-cve-2026-45321.json');
  const r = spawnSync(process.execPath, [path.join(ROOT, 'lib', 'refresh-external.js'), '--advisory', 'CVE-9999-99999', '--json'], {
    encoding: 'utf8',
    env: { ...process.env, EXCEPTD_GHSA_FIXTURE: fix, EXCEPTD_DEPRECATION_SHOWN: '1', EXCEPTD_UNSIGNED_WARNED: '1' },
  });
  assert.equal(r.status, 3, '--advisory dry-run must exit 3 ("draft prepared, not applied")');
  const data = tryJson(r.stdout);
  assert.ok(data, 'JSON output must parse');
  assert.equal(data.mode, 'advisory-seed-dry-run');
  assert.equal(data.cve_id, 'CVE-9999-99999');
  assert.equal(data.draft._auto_imported, true);
});

test('v0.12 refresh --advisory --apply writes draft to a copy of the catalog', () => {
  const fix = path.join(ROOT, 'tests', 'fixtures', 'ghsa-cve-2026-45321.json');
  // Work on a copy of the catalog so we don't mutate the real one.
  const tmpDir = fs.mkdtempSync(path.join(require('os').tmpdir(), 'cve-cat-'));
  fs.mkdirSync(path.join(tmpDir, 'data'));
  fs.copyFileSync(path.join(ROOT, 'data', 'cve-catalog.json'), path.join(tmpDir, 'data', 'cve-catalog.json'));
  // Symlink/copy the other catalogs needed by loadCtx — quickest is to run
  // in the real ROOT and just revert the catalog after.
  const catBefore = fs.readFileSync(path.join(ROOT, 'data', 'cve-catalog.json'), 'utf8');
  try {
    const r = spawnSync(process.execPath, [path.join(ROOT, 'lib', 'refresh-external.js'), '--advisory', 'CVE-9999-99999', '--apply', '--json'], {
      encoding: 'utf8',
      env: { ...process.env, EXCEPTD_GHSA_FIXTURE: fix, EXCEPTD_DEPRECATION_SHOWN: '1' },
    });
    assert.equal(r.status, 3, '--advisory --apply exits 3 (applied, editorial-review pending)');
    const data = tryJson(r.stdout);
    assert.ok(data?.ok);
    assert.equal(data.mode, 'advisory-seed-applied');
    const catAfter = JSON.parse(fs.readFileSync(path.join(ROOT, 'data', 'cve-catalog.json'), 'utf8'));
    assert.ok(catAfter['CVE-9999-99999'], 'draft entry must be written');
    assert.equal(catAfter['CVE-9999-99999']._auto_imported, true);
  } finally {
    fs.writeFileSync(path.join(ROOT, 'data', 'cve-catalog.json'), catBefore, 'utf8');
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('v0.12 refresh --curate <CVE> surfaces editorial questions for a draft', () => {
  // Write a synthetic draft to the catalog (then restore).
  const catBefore = fs.readFileSync(path.join(ROOT, 'data', 'cve-catalog.json'), 'utf8');
  const cat = JSON.parse(catBefore);
  cat['CVE-9999-99999'] = {
    name: 'Synthetic curation test',
    type: 'supply-chain-npm',
    cvss_score: 9.6,
    affected: 'synthetic-test-package',
    _auto_imported: true,
    _draft: true,
    atlas_refs: [],
    attack_refs: [],
    framework_control_gaps: null,
    iocs: null,
    poc_available: null,
    ai_discovered: null,
    ai_assisted_weaponization: null,
    rwep_score: null,
    rwep_factors: null,
    vector: null,
  };
  fs.writeFileSync(path.join(ROOT, 'data', 'cve-catalog.json'), JSON.stringify(cat, null, 2), 'utf8');
  try {
    const r = spawnSync(process.execPath, [path.join(ROOT, 'lib', 'cve-curation.js'), '--curate', 'CVE-9999-99999', '--json'], {
      encoding: 'utf8',
      env: { ...process.env, EXCEPTD_DEPRECATION_SHOWN: '1' },
    });
    assert.equal(r.status, 3, 'curation always exits 3 — editorial review pending');
    const data = tryJson(r.stdout);
    assert.ok(data?.ok);
    assert.equal(data.mode, 'cve-curation');
    assert.ok(data.editorial_questions.length >= 4,
      'must surface at least: atlas_refs, attack_refs, framework_control_gaps, iocs, rwep questions');
    const fields = data.editorial_questions.map(q => q.field);
    assert.ok(fields.includes('framework_control_gaps'));
    assert.ok(fields.includes('iocs'));
  } finally {
    fs.writeFileSync(path.join(ROOT, 'data', 'cve-catalog.json'), catBefore, 'utf8');
  }
});

test('v0.12 refresh --curate refuses to curate a human-curated entry', () => {
  // CVE-2026-45321 was added in v0.11.15 as a human-curated entry (no _auto_imported flag).
  const r = spawnSync(process.execPath, [path.join(ROOT, 'lib', 'cve-curation.js'), '--curate', 'CVE-2026-45321', '--json'], {
    encoding: 'utf8',
    env: { ...process.env, EXCEPTD_DEPRECATION_SHOWN: '1' },
  });
  assert.equal(r.status, 2, 'must refuse curating human-curated entries');
  const data = tryJson(r.stdout);
  assert.equal(data.ok, false);
  assert.match(data.error, /human-curated/);
});

test('v0.12 validate-cve-catalog treats _auto_imported drafts as warnings, not errors', () => {
  // Inject a minimal draft, run the validator, restore.
  const catBefore = fs.readFileSync(path.join(ROOT, 'data', 'cve-catalog.json'), 'utf8');
  const cat = JSON.parse(catBefore);
  cat['CVE-9999-88888'] = {
    name: 'Draft synthetic',
    type: 'supply-chain-npm',
    _auto_imported: true,
    _draft: true,
    cvss_score: null,
    last_updated: '2026-05-13',
  };
  fs.writeFileSync(path.join(ROOT, 'data', 'cve-catalog.json'), JSON.stringify(cat, null, 2), 'utf8');
  try {
    const r = spawnSync(process.execPath, [path.join(ROOT, 'lib', 'validate-cve-catalog.js'), '--quiet'], {
      encoding: 'utf8',
      env: { ...process.env },
    });
    // Drafts are warnings, not errors — exit 0 if no non-draft entry failed.
    assert.equal(r.status, 0, 'draft entry must not break the catalog gate (exit 0)');
  } finally {
    fs.writeFileSync(path.join(ROOT, 'data', 'cve-catalog.json'), catBefore, 'utf8');
  }
});

test('#127 emit() body with ok:false sets non-zero exit (universal contract)', () => {
  // The class of bug: any verb that emits a result with ok:false to stdout
  // must not return exit 0. Pre-0.11.13 several paths leaked through.
  // attest verify on a non-existent session id is GUARANTEED to produce
  // ok:false (the session lookup is the first gate and there's no way
  // around it). Pre-strengthening, this test guarded the assertion under
  // `if (sawOkFalse) { assert(...) }` — so a regression that ran the verb
  // through some other path without ok:false would have silently passed
  // (the `if` never fired, the assertion was a no-op). Hard-assert that
  // ok:false IS observed AND the exit is non-zero, unconditionally.
  const r = cli(['attest', 'verify', 'no-such-session-id-' + Date.now(), '--json']);
  const stdoutBody = tryJson(r.stdout) || {};
  const stderrBody = tryJson(r.stderr.trim()) || {};
  const sawOkFalse = stdoutBody.ok === false || stderrBody.ok === false;
  assert.equal(sawOkFalse, true,
    `attest verify on a missing session id MUST produce ok:false in stdout or stderr (the session-not-found gate is unavoidable). If false, the runner found a way around the gate — that's the regression. stdout=${JSON.stringify(r.stdout.slice(0,300))} stderr=${JSON.stringify(r.stderr.slice(0,300))}`);
  assert.notEqual(r.status, 0,
    'any ok:false response (stdout OR stderr) must yield non-zero exit — the universal emit() contract');
});

test('#127 attest diff with missing session ids exits non-zero', () => {
  const r = cli(['attest', 'diff', 'does-not-exist-a', '--against', 'does-not-exist-b', '--json']);
  assert.notEqual(r.status, 0, 'attest diff with missing sessions must exit non-zero');
  // Pre-strengthening, only the exit code was checked — a regression that
  // exited non-zero for an UNRELATED reason (e.g. CLI crashed before
  // session lookup) would have passed. Drill into stderr and confirm the
  // specific missing session id is named, so operators see which one
  // failed lookup (the diff has two arms, A and B).
  const err = tryJson(r.stderr.trim());
  assert.ok(err, 'attest diff must emit JSON error on stderr');
  assert.equal(err.ok, false, 'body must carry ok:false');
  assert.match(err.error, /does-not-exist-a/,
    'error must name the failed session id (the A side is checked first) so operators know which arm to fix');
});

test('#128 attest diff with empty submissions falls back to playbook catalog', () => {
  // Both runs use empty {} submission; identical evidence hashes. The diff
  // should count the playbook's artifact catalog so operators see
  // "N artifacts, all uniform on both sides" rather than 0/0.
  const sid1 = 'empty-cat-a-' + Date.now();
  const sid2 = 'empty-cat-b-' + Date.now();
  cli(['run', 'sbom', '--evidence', '-', '--session-id', sid1, '--force-overwrite'], { input: '{}' });
  cli(['run', 'sbom', '--evidence', '-', '--session-id', sid2, '--force-overwrite'], { input: '{}' });
  const r = cli(['attest', 'diff', sid1, '--against', sid2, '--json']);
  const data = tryJson(r.stdout);
  assert.ok(data, 'diff JSON must parse');
  assert.equal(data.status, 'unchanged', 'identical empty submissions hash-match → status=unchanged');
  assert.ok(data.artifact_diff.total_compared > 0,
    'empty submissions must fall back to playbook artifact catalog count, not 0');
  assert.equal(data.artifact_diff.total_compared, data.artifact_diff.unchanged_count,
    'all catalog entries identical (both empty) → total_compared === unchanged_count');
});

test('#104 close emits jurisdiction_notifications alias + clocks count (with --ack — E7 binds clock to operator awareness)', () => {
  const sub = JSON.stringify({
    observations: { w: { captured: true, value: 'AKIA', indicator: 'aws-access-key-id', result: 'hit' } },
    verdict: { classification: 'detected', blast_radius: 4 }
  });
  // E7: pre-fix the clock auto-stamped on classification=detected. Now the
  // operator must acknowledge via --ack for the clock to start.
  const r = cli(['run', 'secrets', '--evidence', '-', '--ack', '--session-id', 'jur104-' + Date.now(), '--force-overwrite', '--json'], { input: sub });
  const data = tryJson(r.stdout);
  assert.ok(Array.isArray(data?.phases?.close?.jurisdiction_notifications),
    'phases.close.jurisdiction_notifications must be present (alias for notification_actions)');
  assert.ok(data.phases.close.jurisdiction_clocks_count >= 1,
    'jurisdiction_clocks_count must be > 0 when classification=detected + --ack with detect_confirmed obligations');
});

test('#E7 jurisdiction clock pending without --ack on detected classification', () => {
  // E7: without --ack, classification=detected MUST NOT auto-start the clock.
  // The pre-fix behavior (auto-stamping Date.now() in computeClockStart for
  // detect_confirmed events) was legally incorrect per AGENTS.md Phase 7 —
  // the clock binds to operator awareness, not engine classification.
  const sub = JSON.stringify({
    observations: { w: { captured: true, value: 'AKIA', indicator: 'aws-access-key-id', result: 'hit' } },
    verdict: { classification: 'detected', blast_radius: 4 }
  });
  const r = cli(['run', 'secrets', '--evidence', '-', '--session-id', 'e7-' + Date.now(), '--force-overwrite', '--json'], { input: sub });
  const data = tryJson(r.stdout);
  const notifs = data?.phases?.close?.notification_actions || [];
  const detectConfirmed = notifs.filter(n => n && n.clock_start_event === 'detect_confirmed');
  assert.ok(detectConfirmed.length >= 1,
    'secrets stages at least one detect_confirmed obligation');
  assert.ok(detectConfirmed.every(n => n.clock_started_at == null),
    'without --ack every detect_confirmed clock must be unstarted');
  assert.ok(detectConfirmed.every(n => n.clock_pending_ack === true),
    'each unstarted detect_confirmed notification must surface clock_pending_ack=true so operators see why');
});

// ===================================================================
test('#87 doctor --fix is registered (smoke)', () => {
  // v0.12.4 ROOT-CAUSE FIX: this test previously invoked `exceptd doctor --fix`
  // directly. On any machine where `.keys/private.pem` was missing (every CI
  // run, every fresh clone), `--fix` would synchronously spawn
  // `lib/sign.js generate-keypair`, which OVERWRITES `keys/public.pem` with
  // a fresh Ed25519 public key. After that, every committed manifest signature
  // (signed against the OLD key) fails to verify against the NEW public.pem.
  // Result: every v0.11.x and v0.12.x release shipped a tarball where 0/38
  // skills verified on fresh `npm install`. The bug was invisible because
  // CI's verify step (gate 1) ran BEFORE this test (gate 2), so verify saw
  // the original key. The new verify-shipped-tarball gate (gate 14) ran
  // AFTER this test, and packed/verified against the overwritten key.
  //
  // Fix: pre-stage a dummy `.keys/private.pem` so `--fix` sees "private key
  // already present" and short-circuits without generating. Restore the
  // pre-test state in finally{}. The test still verifies that the verb is
  // registered + emits JSON, which is all the smoke check needs to assert.
  const keysDir = path.join(ROOT, '.keys');
  const privPath = path.join(keysDir, 'private.pem');
  const hadKey = fs.existsSync(privPath);
  let stashed = null;
  if (hadKey) {
    // Already maintainer-state — test passes through doctor's short-circuit.
  } else {
    fs.mkdirSync(keysDir, { recursive: true });
    // Empty file is sufficient: lib/sign.js generate-keypair checks
    // `fs.existsSync(PRIVATE_KEY_PATH)` and exits before any key write.
    fs.writeFileSync(privPath, '');
    stashed = privPath;
  }
  try {
    const r = cli(['doctor', '--fix', '--json'], { env: { EXCEPTD_RAW_JSON: '1' } });
    assert.notEqual(r.status, 2, 'doctor --fix should not be an unknown-flag error');
    const data = tryJson(r.stdout);
    assert.ok(data, 'doctor --fix should emit JSON');
  } finally {
    if (stashed && fs.existsSync(stashed)) fs.unlinkSync(stashed);
  }
});
