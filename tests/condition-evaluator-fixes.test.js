'use strict';

/**
 * Regression for the condition mini-language (lib/playbook-runner.js
 * evalCondition). Conditions gate escalation_criteria, feeds_into chains, and
 * remediation preconditions across the catalog; a silently-false condition
 * disables its rule.
 *
 *   - hyphenated signal/indicator ids (the catalog naming convention) must
 *     parse, not fall through to false
 *   - severity comparison is by the low<medium<high<critical ladder, not
 *     lexicographic string order (so 'critical' >= 'high' is true)
 *   - `contains` is a synonym for `includes`
 *   - an operator-submitted signal cannot override an engine-computed value
 *   - an unparseable condition surfaces a condition_unparsed runtime error
 *   - a contains/IN clause whose LHS path is absent surfaces a
 *     condition_path_unresolved runtime error (a parsed-but-dead clause), while a
 *     present-but-empty collection stays a silent legitimate false
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');

const runner = require(path.resolve(__dirname, '..', 'lib', 'playbook-runner.js'));
const evalCondition = runner._evalCondition;

test('hyphenated LHS evaluates against the matching ctx key (not silently false)', () => {
  assert.equal(evalCondition('no-security-md == true', { 'no-security-md': true }), true);
  assert.equal(evalCondition('no-security-md == true', { 'no-security-md': false }), false);
  assert.equal(evalCondition('kver-in-affected-range == true AND kaslr-disabled == true',
    { 'kver-in-affected-range': true, 'kaslr-disabled': true }), true);
});

test('severity comparison uses the ordinal ladder, not lexicographic order', () => {
  assert.equal(evalCondition("finding.severity >= high", { finding: { severity: 'critical' } }), true);
  assert.equal(evalCondition("finding.severity >= high", { finding: { severity: 'high' } }), true);
  assert.equal(evalCondition("finding.severity >= high", { finding: { severity: 'medium' } }), false);
  assert.equal(evalCondition("finding.severity >= high", { finding: { severity: 'low' } }), false);
  // numeric comparison still works (regression guard)
  assert.equal(evalCondition('rwep >= 90', { rwep: 100 }), true);
  assert.equal(evalCondition('rwep >= 90', { rwep: 50 }), false);
});

test('`contains` is accepted as a synonym for `includes`', () => {
  assert.equal(evalCondition('scope.targets contains named-remote', { scope: { targets: ['named-remote'] } }), true);
  assert.equal(evalCondition('scope.targets includes named-remote', { scope: { targets: ['named-remote'] } }), true);
  assert.equal(evalCondition('scope.targets contains named-remote', { scope: { targets: ['local'] } }), false);
});

test('`matches` accepts both the slash and the quote delimiter (mcp feeds_into uses the quoted form)', () => {
  // The catalog authors both forms; mcp.json's feeds_into matches the CI-platform
  // OR-branch with the quoted form. A delimiter-specific parser silently disabled
  // it (returned false + a condition_unparsed runtime error) for every input.
  const slashErrs = [];
  assert.equal(evalCondition("finding.x matches /(a|b)/", { finding: { x: 'a' }, _runErrors: slashErrs }), true);
  assert.equal(slashErrs.length, 0, 'slash form parses, no condition_unparsed');

  const quoteErrs = [];
  assert.equal(evalCondition("finding.x matches '(a|b)'", { finding: { x: 'a' }, _runErrors: quoteErrs }), true);
  assert.equal(quoteErrs.length, 0, 'single-quote form parses, no condition_unparsed');

  // double-quote form also parses
  assert.equal(evalCondition('finding.x matches "(a|b)"', { finding: { x: 'b' } }), true);

  // a non-match is false (not a parse failure)
  assert.equal(evalCondition("finding.x matches '(a|b)'", { finding: { x: 'c' } }), false);

  // the exact mcp.json feeds_into condition fires via the regex OR-branch alone,
  // with the other two OR-branches false (pre-fix the whole OR collapsed to false)
  const mcpCond = "finding.mcp_server_location matches '(github_actions|gitlab_runner|jenkins|buildkite|circleci)'"
    + " OR finding.tool_invoked_from == 'ci_pipeline'"
    + " OR analyze.blast_radius_score >= 4 AND finding.pipeline_credentials_in_scope == true";
  assert.equal(evalCondition(mcpCond, {
    finding: { mcp_server_location: 'buildkite', tool_invoked_from: 'manual', pipeline_credentials_in_scope: false },
    analyze: { blast_radius_score: 0 },
  }), true);
});

test('an unparseable (prose) condition pushes a condition_unparsed runtime error (not a silent false)', () => {
  const errs = [];
  // A genuine prose sentence the mini-language can't evaluate. (The `any … ==`
  // quantifier form below is now PARSED — see the quantifier test — so a prose
  // clause is what should still surface the diagnostic.)
  const r = evalCondition('a single compromised identity can rewrite the trail', { _runErrors: errs });
  assert.equal(r, false, 'unparseable still returns false');
  assert.equal(errs.length, 1, 'a runtime error is recorded');
  assert.equal(errs[0].kind, 'condition_unparsed');
});

test('`any`/`all` quantifier prefix parses and fires (not condition_unparsed)', () => {
  // Scalar LHS — the quantifier is prose emphasis; the scalar comparison is the
  // test. framework.json's feeds_into to sbom is exactly this shape. Pre-fix the
  // `any ` leaf fell through to condition_unparsed → false, disabling BOTH paths
  // by which framework chains into sbom.
  const cond = "any compliance_theater_check.verdict == 'theater' AND blast_radius_score >= 4";
  const errs = [];
  assert.equal(
    evalCondition(cond, { compliance_theater_check: { verdict: 'theater' }, blast_radius_score: 5, _runErrors: errs }),
    true,
    'theater verdict + blast_radius 5 fires the framework→sbom chain'
  );
  assert.equal(errs.filter((e) => e.kind === 'condition_unparsed').length, 0,
    'the any-prefixed leaf parses — no condition_unparsed');
  // Negatives: each conjunct gates independently.
  assert.equal(evalCondition(cond, { compliance_theater_check: { verdict: 'clear' }, blast_radius_score: 5 }), false,
    'non-theater verdict does not chain');
  assert.equal(evalCondition(cond, { compliance_theater_check: { verdict: 'theater' }, blast_radius_score: 2 }), false,
    'blast_radius below 4 does not chain');

  // Array LHS — existential / universal over members. sbom.json's feeds_into
  // uses `any matched_cve.attack_class == 'kernel-lpe'`.
  const hit = { matched_cve: [{ attack_class: 'mcp-supply-chain' }, { attack_class: 'kernel-lpe' }] };
  const miss = { matched_cve: [{ attack_class: 'mcp-supply-chain' }] };
  assert.equal(evalCondition("any matched_cve.attack_class == 'kernel-lpe'", hit), true,
    'any matches when one array element satisfies the predicate');
  assert.equal(evalCondition("any matched_cve.attack_class == 'kernel-lpe'", miss), false,
    'any is false when no element satisfies the predicate');
  assert.equal(evalCondition("all matched_cve.attack_class == 'kernel-lpe'", hit), false,
    'all is false when only some elements satisfy the predicate');
  assert.equal(evalCondition("all matched_cve.attack_class == 'kernel-lpe'",
    { matched_cve: [{ attack_class: 'kernel-lpe' }, { attack_class: 'kernel-lpe' }] }), true,
    'all is true when every element satisfies the predicate');
});

test('`any`/`all` quantifier re-roots EVERY operator over an array element, not just comparisons (IN/contains/matches)', () => {
  // sbom.json's feeds_into into ai-api is `any matched_cve.attack_class IN
  // ['ai-c2', 'prompt-injection']`. `IN` is not a comparison operator, so the
  // quantifier branch used to skip the per-element re-root and evaluate the
  // clause against the whole ctx — where `matched_cve.attack_class` resolves to
  // undefined on the array — leaving the sbom→ai-api chain permanently dead while
  // the `== 'kernel-lpe'` / `== 'mcp-supply-chain'` siblings fired.
  const cves = [{ attack_class: 'supply-chain' }, { attack_class: 'ai-c2' }];
  assert.equal(
    evalCondition("any matched_cve.attack_class IN ['ai-c2', 'prompt-injection']", { matched_cve: cves }),
    true,
    'any … IN [...] fires when one array element is in the list');
  assert.equal(
    evalCondition("any matched_cve.attack_class IN ['kernel-lpe']", { matched_cve: cves }),
    false,
    'any … IN [...] is false when no element is in the list');
  assert.equal(
    evalCondition("all matched_cve.attack_class IN ['supply-chain', 'ai-c2']", { matched_cve: cves }),
    true,
    'all … IN [...] is true when every element is in the list');
  assert.equal(
    evalCondition("all matched_cve.attack_class IN ['supply-chain']", { matched_cve: cves }),
    false,
    'all … IN [...] is false when one element is outside the list');
  // `all` over an empty array is false (vacuous-truth guard preserved).
  assert.equal(
    evalCondition("all matched_cve.attack_class IN ['ai-c2']", { matched_cve: [] }),
    false,
    'all … over an empty array is false, not vacuously true');

  // contains under a quantifier (array element holds its own array field).
  assert.equal(
    evalCondition("any finding.tags contains 'eu'", { finding: [{ tags: ['us'] }, { tags: ['eu', 'jp'] }] }),
    true,
    'any … contains fires existentially across array elements');

  // matches under a quantifier (slash + quote delimiters, the only forms the
  // leaf parser accepts).
  assert.equal(
    evalCondition('any matched_cve.vector matches /userns/', { matched_cve: [{ vector: 'remote' }, { vector: 'local-userns-bpf' }] }),
    true,
    'any … matches /re/ fires existentially across array elements');
  assert.equal(
    evalCondition("any matched_cve.vector matches 'kptr'", { matched_cve: [{ vector: 'remote' }, { vector: 'local-userns-bpf' }] }),
    false,
    "any … matches 're' is false when no element matches");

  // The scalar-object head (framework theater prose-quantifier) is unaffected —
  // a non-array head still routes to the bare inner comparison.
  assert.equal(
    evalCondition("any compliance_theater_check.verdict == 'theater'", { compliance_theater_check: { verdict: 'theater' } }),
    true,
    'a scalar-object head still evaluates the inner comparison directly');
});

test('bare `any <path>` / `all <path>` is a non-emptiness test, not condition_unparsed', () => {
  // `any X` with no comparison operator means "at least one X exists" — a
  // non-emptiness / existence test. Pre-fix the operator-less inner token had no
  // comparison branch to parse it and fell through to condition_unparsed → false,
  // so it returned false even for a populated array. sbom.json's EU CRA Art.14
  // (24h) notify_legal escalation `any actively_exploited_match AND …` was dead.
  let errs = [];
  assert.equal(evalCondition('any actively_exploited_match',
    { actively_exploited_match: [{ id: 'x' }], _runErrors: errs }), true,
    'any over a non-empty array is true');
  assert.equal(errs.filter((e) => e.kind === 'condition_unparsed').length, 0,
    'no condition_unparsed for the bare non-emptiness form');

  errs = [];
  assert.equal(evalCondition('any actively_exploited_match',
    { actively_exploited_match: [], _runErrors: errs }), false,
    'any over an empty array is false');
  assert.equal(errs.filter((e) => e.kind === 'condition_unparsed').length, 0,
    'empty-array path is parsed, not unparsed');

  // missing path / falsy scalar → false; truthy scalar → true.
  assert.equal(evalCondition('any nonexistent', {}), false, 'missing path is false');
  assert.equal(evalCondition('any kev_listed', { kev_listed: true }), true, 'truthy scalar is true');
  assert.equal(evalCondition('any kev_listed', { kev_listed: false }), false, 'falsy scalar is false');

  // `all <path>`: non-empty AND every element truthy.
  assert.equal(evalCondition('all flags', { flags: [true, true] }), true, 'all-truthy non-empty array');
  assert.equal(evalCondition('all flags', { flags: [true, false] }), false, 'a falsy element fails all');
  assert.equal(evalCondition('all flags', { flags: [] }), false, 'empty array fails all');

  // The exact sbom.json:1250 condition fires when both conjuncts hold, with zero
  // condition_unparsed runtime errors.
  errs = [];
  const sbomCond = "any actively_exploited_match AND jurisdiction_obligations contains 'EU/EU CRA Art.14 24h'";
  assert.equal(evalCondition(sbomCond, {
    actively_exploited_match: [{ id: 'CVE-x' }],
    jurisdiction_obligations: ['EU/EU CRA Art.14 24h'],
    _runErrors: errs,
  }), true, 'the EU CRA Art.14 notify_legal escalation fires when both conjuncts hold');
  assert.equal(errs.filter((e) => e.kind === 'condition_unparsed').length, 0,
    'the full sbom:1250 condition is fully parsed');
  // First conjunct gates: an empty actively_exploited_match array keeps it false.
  assert.equal(evalCondition(sbomCond, {
    actively_exploited_match: [],
    jurisdiction_obligations: ['EU/EU CRA Art.14 24h'],
  }), false, 'no active-exploitation matches → escalation does not fire');

  // A genuinely malformed inner clause (operator-like garbage) must still surface
  // condition_unparsed — the bare-path handler must not swallow it.
  errs = [];
  assert.equal(evalCondition('any foo ~~ bar', { foo: [1], _runErrors: errs }), false,
    'malformed inner clause stays false');
  assert.equal(errs.filter((e) => e.kind === 'condition_unparsed').length, 1,
    'malformed inner clause is still observable as condition_unparsed');
});

test('`IN [...]` member parsing is quote-aware — a comma inside a quoted member stays one member', () => {
  // A naive `.split(',')` is quote-unaware, so a quoted member that itself
  // contains a comma (`'EU, US'`) was torn into two members (`EU`, `US`),
  // neither equal to the author's whole member. The clause then evaluated false
  // with no diagnostic — the regex still matched the bracket, so condition_unparsed
  // never fired. The list is now split tracking quote state.
  assert.equal(evalCondition("x IN ['EU, US', 'AU']", { x: 'EU, US' }), true,
    "a comma inside a quoted member does not split the member");
  assert.equal(evalCondition("x IN ['a,b']", { x: 'a,b' }), true,
    "a single quoted member containing a comma matches the whole member");
  // The sibling member is still independently selectable.
  assert.equal(evalCondition("x IN ['EU, US', 'AU']", { x: 'AU' }), true,
    "the second member after a comma-bearing first member is still a member");
  // A value equal to only a comma-split FRAGMENT must NOT match (proves the
  // member is whole, not the broken 'EU' / 'US' fragments).
  assert.equal(evalCondition("x IN ['EU, US', 'AU']", { x: 'EU' }), false,
    "a fragment of a comma-bearing quoted member is not itself a member");
  assert.equal(evalCondition("x IN ['EU, US', 'AU']", { x: 'US' }), false,
    "the trailing fragment of a comma-bearing quoted member is not a member");
  // Double-quoted members behave identically.
  assert.equal(evalCondition('x IN ["EU, US", "AU"]', { x: 'EU, US' }), true,
    "double-quoted comma-bearing member stays whole");

  // No condition_unparsed is recorded — this was a parsed-but-wrong path, and
  // the fix must keep it parsed (not regress into the unparsed diagnostic).
  const errs = [];
  evalCondition("x IN ['EU, US', 'AU']", { x: 'EU, US', _runErrors: errs });
  assert.equal(errs.filter((e) => e.kind === 'condition_unparsed').length, 0,
    'a quoted comma member is parsed, not surfaced as condition_unparsed');

  // Regression guards: the catalog's actual `IN` forms still evaluate correctly.
  // sbom.json:101 — the quoted multi-member form with hyphenated members.
  assert.equal(
    evalCondition("matched_cve.attack_class IN ['ai-c2', 'prompt-injection']",
      { matched_cve: { attack_class: 'ai-c2' } }), true,
    'the shipped quoted multi-member IN list still matches');
  assert.equal(
    evalCondition("matched_cve.attack_class IN ['ai-c2', 'prompt-injection']",
      { matched_cve: { attack_class: 'kernel-lpe' } }), false,
    'a non-member still returns false');
  // Bare (unquoted) members still parse.
  assert.equal(evalCondition('x IN [ai-c2, prompt-injection]', { x: 'prompt-injection' }), true,
    'bare unquoted members still parse');
  // Array LHS intersection still works.
  assert.equal(
    evalCondition("x IN ['EU, US', 'AU']", { x: ['JP', 'EU, US'] }), true,
    'array LHS intersects the comma-bearing member list');
  // Quantifier-prefixed IN still re-roots over array elements.
  assert.equal(evalCondition("any tags IN ['EU, US', 'AU']", { tags: ['EU, US'] }), true,
    'any … IN [...] with a comma-bearing member fires existentially');
});

test('`IN [...]` closing bracket is quote-aware — a `]` inside a quoted member does not terminate the list', () => {
  // A `[^\]]*]$` capture stops at the FIRST `]`, so a quoted member that itself
  // contains a literal `]` (`'a]b'`) truncated the bracket early and left trailing
  // text (`, 'c']`) the `$` anchor couldn't match — the WHOLE clause then fell
  // through to condition_unparsed and returned false for every input, including a
  // value that IS in the list. The closing bracket is now located at quote-depth 0.
  assert.equal(evalCondition("x IN ['a]b', 'c']", { x: 'a]b' }), true,
    "a quoted member containing a literal ']' matches its whole value");
  assert.equal(evalCondition("x IN ['a]b', 'c']", { x: 'c' }), true,
    "the sibling member after a ']'-bearing member is still selectable");
  assert.equal(evalCondition("x IN ['a]b', 'c']", { x: 'a' }), false,
    "a fragment of the ']'-bearing member is not itself a member");
  // Double-quoted members behave identically.
  assert.equal(evalCondition('x IN ["a]b", "c"]', { x: 'a]b' }), true,
    "double-quoted ']'-bearing member stays whole");
  // Array LHS intersection over a ']'-bearing list.
  assert.equal(evalCondition("x IN ['a]b', 'rce']", { x: ['z', 'a]b'] }), true,
    "array LHS intersects a ']'-bearing member list");
  // Quantifier-prefixed form (the catalog's `any … IN [...]` shape) re-roots too.
  assert.equal(
    evalCondition("any matched_cve.attack_class IN ['a]b', 'rce']",
      { matched_cve: [{ attack_class: 'a]b' }, { attack_class: 'x' }] }), true,
    "any … IN ['a]b', …] fires when one array element equals the ']'-bearing member");

  // This was a parsed-as-unparsed path (the regex never matched), so the fix must
  // NOT surface condition_unparsed for the now-valid clause.
  const errs = [];
  evalCondition("x IN ['a]b', 'c']", { x: 'c', _runErrors: errs });
  assert.equal(errs.filter((e) => e.kind === 'condition_unparsed').length, 0,
    "a quoted ']'-bearing member is parsed, not surfaced as condition_unparsed");

  // Genuinely malformed lists stay observable: an unterminated bracket and
  // trailing text after the closing bracket both surface condition_unparsed
  // (the fix must not start silently accepting these).
  const badErrs = [];
  assert.equal(evalCondition("x IN ['a', 'b'", { x: 'a', _runErrors: badErrs }), false,
    'an unterminated IN list does not match');
  assert.equal(badErrs.filter((e) => e.kind === 'condition_unparsed').length, 1,
    'an unterminated IN list is observable as condition_unparsed');
  const junkErrs = [];
  assert.equal(evalCondition("x IN ['a', 'b'] extra", { x: 'a', _runErrors: junkErrs }), false,
    'trailing text after the closing bracket does not match');
  assert.equal(junkErrs.filter((e) => e.kind === 'condition_unparsed').length, 1,
    'trailing text after the closing bracket is observable as condition_unparsed');
});

test('AND/OR splitting and outer-paren stripping are quote-aware — a quoted member is not torn at an inner AND/OR or an unbalanced paren', () => {
  // splitAtTopLevel counted `(`/`)` and split on ` AND `/` OR ` at depth 0 with
  // no awareness of quotes; stripOuterParens scanned parens the same way. Two
  // failure modes followed:
  //   (a) an UNBALANCED paren inside a quoted member (a regex literal like
  //       `matches 'foo('`) left depth=1, so the real top-level OR/AND never
  //       split — silently disabling the surrounding disjunct/conjunct;
  //   (b) a quoted member containing ` AND `/` OR ` (e.g. `contains 'EU AND US'`)
  //       was torn at the inner keyword as if it were a boolean operator, leaving
  //       two unparseable atoms that both evaluated false.
  // Both are now scanned tracking single/double quote state.

  // (a) The unbalanced `(` inside the quote must NOT swallow the top-level OR.
  // The first disjunct is false (a !== 'foo(' here) but the second (b == 1) is
  // true, so the OR must be true. Pre-fix this returned false.
  assert.equal(evalCondition("a matches 'foo(' OR b == 1", { a: 'fooX', b: 1 }), true,
    'an unbalanced ( inside a quoted regex member does not disable the top-level OR');
  // …and the OR is genuinely short-circuiting, not coincidentally true: with
  // b != 1 and a not matching, the whole thing is false.
  assert.equal(evalCondition("a matches 'foo(' OR b == 1", { a: 'fooX', b: 2 }), false,
    'both disjuncts false → false (the OR is really evaluating each side)');
  // A trailing unbalanced `)` inside a quote is handled symmetrically.
  assert.equal(evalCondition("a matches 'bar)' OR b == 1", { a: 'whatever', b: 1 }), true,
    'an unbalanced ) inside a quoted member does not disable the top-level OR');

  // (b) ` AND `/` OR ` inside a quoted member is literal text, not an operator.
  // `o contains 'EU AND US'` must match an array member equal to the whole
  // string. Pre-fix it split into `o contains 'EU` AND `US'` (both unparseable
  // → false).
  assert.equal(evalCondition("o contains 'EU AND US'", { o: ['EU AND US'] }), true,
    'an inner AND inside a quoted contains-member is not split as a conjunction');
  assert.equal(evalCondition("o contains 'x OR y'", { o: ['x OR y'] }), true,
    'an inner OR inside a quoted contains-member is not split as a disjunction');
  // And it is genuinely the whole member, not a coincidental fragment match.
  assert.equal(evalCondition("o contains 'EU AND US'", { o: ['EU'] }), false,
    'a fragment of the quoted member does not satisfy the whole-member contains');

  // No condition_unparsed is recorded for any of the above — these are
  // parsed-correctly paths now, not the unparsed diagnostic.
  const errs = [];
  evalCondition("a matches 'foo(' OR b == 1", { a: 'fooX', b: 1, _runErrors: errs });
  evalCondition("o contains 'EU AND US'", { o: ['EU AND US'], _runErrors: errs });
  assert.equal(errs.filter((e) => e.kind === 'condition_unparsed').length, 0,
    'a quote-aware split leaves no condition_unparsed residue');

  // Regression guards: real (depth-0, outside-quote) boolean structure still
  // splits, and outer parens still strip.
  assert.equal(evalCondition('a == 1 OR b == 2', { a: 0, b: 2 }), true, 'plain OR still splits');
  assert.equal(evalCondition('a == 1 AND b == 2', { a: 1, b: 2 }), true, 'plain AND still splits');
  assert.equal(evalCondition('(a == 1 OR b == 2)', { a: 0, b: 2 }), true, 'outer parens still strip');
  assert.equal(evalCondition('a == 1 OR (b == 2 AND c == 3)', { a: 0, b: 2, c: 3 }), true,
    'a depth-0 OR with a parenthesised AND group still parses');
  assert.equal(evalCondition('a == 1 OR (b == 2 AND c == 3)', { a: 0, b: 2, c: 0 }), false,
    'the parenthesised AND group gates the OR correctly');

  // The exact mcp.json condition (balanced-paren regex member + a real top-level
  // OR/AND) keeps firing — the one paren-bearing machine-evaluated condition in
  // the shipped catalog. Fires via the regex OR-branch alone.
  const mcpCond = "finding.mcp_server_location matches '(github_actions|gitlab_runner|jenkins|buildkite|circleci)'"
    + " OR finding.tool_invoked_from == 'ci_pipeline'"
    + " OR analyze.blast_radius_score >= 4 AND finding.pipeline_credentials_in_scope == true";
  assert.equal(evalCondition(mcpCond, {
    finding: { mcp_server_location: 'buildkite', tool_invoked_from: 'manual', pipeline_credentials_in_scope: false },
    analyze: { blast_radius_score: 0 },
  }), true, 'the shipped mcp.json balanced-paren-regex condition still fires via its OR-branch');
  assert.equal(evalCondition(mcpCond, {
    finding: { mcp_server_location: 'desktop', tool_invoked_from: 'manual', pipeline_credentials_in_scope: false },
    analyze: { blast_radius_score: 0 },
  }), false, 'no branch satisfied → the mcp condition is false');
});

test('a submitted signal cannot override an engine-computed value in an escalation condition', () => {
  // ai-api declares escalations gated on engine values. Run it with detection
  // confirmed so the engine computes a high rwep, then try to suppress the
  // escalation by submitting signals.rwep:0 — the engine value must win.
  const base = runner.run('ai-api', 'all-ai-api-and-credential-exposure',
    { signals: { detection_classification: 'detected' }, artifacts: {} },
    { operator_consent: { explicit: true } });
  const poisoned = runner.run('ai-api', 'all-ai-api-and-credential-exposure',
    { signals: { detection_classification: 'detected', rwep: 0, finding: { severity: 'low' } }, artifacts: {} },
    { operator_consent: { explicit: true } });
  const esc = (res) => JSON.stringify((res.phases.analyze.escalations || []).map((e) => e.action).sort());
  assert.equal(esc(poisoned), esc(base),
    'submitted signals.rwep / finding must not change which escalations fire');
});

test('framework chains into sbom when the theater verdict + blast radius gate is met', () => {
  // framework.json declares the same chain on TWO paths: a feeds_into entry and
  // a trigger_playbook escalation, both targeting sbom. Both previously used an
  // `any `-prefixed, bare-path condition that resolved to false for every input,
  // so neither chain could ever fire. Run the playbook with a theater verdict +
  // a blast radius above the gate and assert both surfaces name sbom.
  const out = runner.run('framework', 'correlate-all-upstream-findings',
    { signals: { theater_verdict: 'theater', blast_radius_score: 5 }, artifacts: {} },
    { operator_consent: { explicit: true } });

  assert.deepEqual(out.phases.close.feeds_into, ['sbom'],
    'feeds_into chains framework → sbom on a theater verdict + blast_radius >= 4');

  const escTargets = (out.phases.analyze.escalations || [])
    .filter((e) => e.action === 'trigger_playbook')
    .map((e) => e.target_playbook);
  assert.ok(escTargets.includes('sbom'),
    'the trigger_playbook escalation fires framework → sbom on a theater verdict + blast_radius >= 3');

  // Neither chain's condition is left dead (the bug signature was a silent
  // condition_unparsed on the framework→sbom clauses specifically).
  const allErrs = (out.phases.analyze.runtime_errors || []).concat(out.phases.close.runtime_errors || []);
  const deadFrameworkSbom = allErrs.filter((e) =>
    e.kind === 'condition_unparsed' && /compliance_theater_check\.verdict/.test(e.condition || ''));
  assert.equal(deadFrameworkSbom.length, 0,
    'the framework→sbom theater conditions parse — no condition_unparsed on them');
});

test('a non-theater framework run does NOT chain into sbom', () => {
  const out = runner.run('framework', 'correlate-all-upstream-findings',
    { signals: { theater_verdict: 'clear', blast_radius_score: 5 }, artifacts: {} },
    { operator_consent: { explicit: true } });
  assert.deepEqual(out.phases.close.feeds_into, [],
    'a clear verdict does not chain framework → sbom');
});

test('contains matches an obligation jurisdiction field via a quoted member; IN list membership works; string-array contains is unaffected', () => {
  const obligations = [
    { jurisdiction: 'EU', regulation: 'NIS2 Art.21', window_hours: 720 },
    { jurisdiction: 'US', regulation: 'SEC', window_hours: 96 },
  ];
  const ctx = { compliance_theater_check: { verdict: 'theater' }, jurisdiction_obligations: obligations };
  // Previously-dead theater + EU-jurisdiction escalation/feeds_into atom now resolves.
  assert.equal(evalCondition("compliance_theater_check.verdict == 'theater' AND jurisdiction_obligations contains 'EU'", ctx, {}), true);
  assert.equal(evalCondition("jurisdiction_obligations contains 'EU'", ctx, {}), true);
  assert.equal(evalCondition("jurisdiction_obligations contains 'JP'", ctx, {}), false);
  // .length on the same array still works.
  assert.equal(evalCondition('jurisdiction_obligations.length == 0', { jurisdiction_obligations: [] }, {}), true);
  // IN [...] membership (matched_cve.attack_class IN [...]).
  assert.equal(evalCondition("x.attack_class IN ['kernel-lpe', 'rce']", { x: { attack_class: 'rce' } }, {}), true);
  assert.equal(evalCondition("x.attack_class IN ['kernel-lpe']", { x: { attack_class: 'rce' } }, {}), false);
  // The pre-existing string-array contains shape is unaffected.
  assert.equal(evalCondition('scope.targets contains named-remote', { scope: { targets: ['named-remote', 'local'] } }, {}), true);
});

test('object-array contains is field-targeted: a non-jurisdiction field equal to the member does NOT match', () => {
  // `jurisdiction_obligations contains 'EU'` means "the obligation is for
  // jurisdiction EU" — NOT "some field of the obligation equals 'EU'". An
  // unscoped Object.values().includes() over-matched: a non-jurisdiction field
  // (a tag, the obligation name, clock_starts) that happened to equal the member
  // forced the predicate true, which could fire a notify_legal escalation via a
  // non-jurisdiction field, and made the match order-insensitive across fields.

  // Over-match via an unrelated tag field: jurisdiction is US, only some_tag == 'EU'.
  assert.equal(
    evalCondition("jurisdiction_obligations contains 'EU'",
      { jurisdiction_obligations: [{ jurisdiction: 'US', some_tag: 'EU' }] }, {}),
    false,
    "a non-jurisdiction field equal to 'EU' must NOT satisfy contains 'EU'");

  // Over-match via clock_starts: 'detect_confirmed' is a real shipped field value
  // on EU obligations; matching it via contains is a field-agnostic accident.
  assert.equal(
    evalCondition("jurisdiction_obligations contains 'detect_confirmed'",
      { jurisdiction_obligations: [{ jurisdiction: 'EU', clock_starts: 'detect_confirmed' }] }, {}),
    false,
    "the clock_starts field value must NOT satisfy a jurisdiction-membership test");

  // Over-match via the obligation name field.
  assert.equal(
    evalCondition("jurisdiction_obligations contains 'notify_regulator'",
      { jurisdiction_obligations: [{ jurisdiction: 'EU', obligation: 'notify_regulator' }] }, {}),
    false,
    "the obligation name field must NOT satisfy a jurisdiction-membership test");

  // The legitimate jurisdiction match still fires (positive path preserved).
  assert.equal(
    evalCondition("jurisdiction_obligations contains 'EU'",
      { jurisdiction_obligations: [{ jurisdiction: 'EU', regulation: 'NIS2 Art.21', clock_starts: 'detect_confirmed' }] }, {}),
    true,
    "an obligation whose jurisdiction IS 'EU' still matches");

  // The full catalog escalation atom: theater verdict + EU jurisdiction. The
  // EU conjunct must come from the jurisdiction field, not a field collision.
  assert.equal(
    evalCondition("compliance_theater_check.verdict == 'theater' AND jurisdiction_obligations contains 'EU'",
      { compliance_theater_check: { verdict: 'theater' },
        jurisdiction_obligations: [{ jurisdiction: 'US', obligation: 'EU' }] }, {}),
    false,
    "the notify_legal escalation must NOT fire when only a non-jurisdiction field equals 'EU'");

  // String-array membership is still matched by element value (no object scoping).
  assert.equal(
    evalCondition("jurisdiction_obligations contains 'EU/EU CRA Art.14 24h'",
      { jurisdiction_obligations: ['EU/EU CRA Art.14 24h'] }, {}),
    true,
    "a plain string-array element still matches by value");
});

test('contains/IN against an absent LHS path surfaces condition_path_unresolved (not an invisible false)', () => {
  // A contains/IN clause PARSES, then resolves its LHS to a collection. When the
  // LHS path is absent (an authoring typo in the token, or a ctx that never
  // populated the collection) the branch returns a silent false that disables
  // the escalation/feeds_into it gates — with no signal, because the clause
  // parsed, so condition_unparsed never fires. A distinct condition_path_unresolved
  // diagnostic makes the dead clause observable. A present-but-empty array (or a
  // present scalar simply not in the list) is a LEGITIMATE false and pushes nothing.

  // contains: absent LHS → diagnostic, still false.
  const absent = [];
  assert.equal(evalCondition("jurisdiction_obligations contains 'EU'", { _runErrors: absent }, {}), false,
    'absent LHS contains is still false');
  assert.equal(absent.length, 1, 'exactly one runtime error recorded');
  assert.equal(absent[0].kind, 'condition_path_unresolved', 'it is the path-unresolved diagnostic, not condition_unparsed');
  assert.equal(absent[0].condition, "jurisdiction_obligations contains 'EU'", 'the dead condition string is captured');

  // The finding's typo example: a misspelled LHS path is now observable.
  const typo = [];
  assert.equal(
    evalCondition("juristiction_obligations contains 'EU'",
      { jurisdiction_obligations: [{ jurisdiction: 'EU' }], _runErrors: typo }, {}),
    false, 'typo LHS contains is false');
  assert.equal(typo.length, 1, 'the LHS-token typo surfaces a diagnostic');
  assert.equal(typo[0].kind, 'condition_path_unresolved');

  // Present-but-empty array → legitimate false, NO diagnostic.
  const empty = [];
  assert.equal(evalCondition("jo contains 'EU'", { jo: [], _runErrors: empty }, {}), false,
    'empty-array contains is false');
  assert.equal(empty.length, 0, 'present-but-empty array pushes no diagnostic');

  // The engine-supplied escalation context always passes jurisdiction_obligations
  // as at least [] (never null), so a real notify_legal eval does NOT spuriously
  // fire this diagnostic — guard the regression at the catalog default.
  const engineDefault = [];
  assert.equal(
    evalCondition("compliance_theater_check.verdict == 'theater' AND jurisdiction_obligations contains 'EU'",
      { compliance_theater_check: { verdict: 'theater' }, jurisdiction_obligations: [], _runErrors: engineDefault }, {}),
    false, 'non-EU run is false');
  assert.equal(engineDefault.length, 0, 'the engine-default [] obligations array fires no path-unresolved diagnostic');

  // IN: absent LHS → diagnostic, still false.
  const inAbsent = [];
  assert.equal(evalCondition("matched_cve.attack_class IN ['kernel-lpe']", { _runErrors: inAbsent }, {}), false,
    'absent LHS IN is still false');
  assert.equal(inAbsent.length, 1, 'IN absent LHS surfaces a diagnostic');
  assert.equal(inAbsent[0].kind, 'condition_path_unresolved');

  // IN: present scalar simply not in the list → legitimate false, NO diagnostic.
  const inMiss = [];
  assert.equal(evalCondition("x IN ['kernel-lpe']", { x: 'rce', _runErrors: inMiss }, {}), false,
    'present scalar not in list is false');
  assert.equal(inMiss.length, 0, 'a present-but-non-matching scalar pushes no diagnostic');

  // A correct, resolving condition fires true with no diagnostic.
  const ok = [];
  assert.equal(
    evalCondition("jurisdiction_obligations contains 'EU'",
      { jurisdiction_obligations: [{ jurisdiction: 'EU' }], _runErrors: ok }, {}),
    true, 'correct contains fires true');
  assert.equal(ok.length, 0, 'a resolving condition records no diagnostic');

  // Dedupe: the same dead condition evaluated repeatedly records ONE diagnostic.
  const dup = [];
  evalCondition("missing_path contains 'EU'", { _runErrors: dup }, {});
  evalCondition("missing_path contains 'EU'", { _runErrors: dup }, {});
  assert.equal(dup.length, 1, 'the path-unresolved diagnostic dedupes on the condition string');
});
