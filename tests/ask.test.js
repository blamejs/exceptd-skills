'use strict';

/**
 * Subject coverage for the `ask` CLI verb (bin/exceptd.js cmdAsk): natural-
 * language question routing, synonym handling, and stopword filtering so a
 * nonsense query does not confidently route.
 *
 * Each contributing source file's tests are wrapped in a describe() block named
 * for that source so the per-source requires/consts/helpers stay isolated.
 */

const test = require('node:test');
const assert = require('node:assert/strict');

// ===========================================================================
test.describe('ask-routing-and-recipe-cleanup', () => {
  const { makeSuiteHome, makeCli, tryJson } = require('./_helpers/cli');

  const cli = makeCli(makeSuiteHome('exceptd-askroute-'));

  function routedTop(question) {
    const r = cli(['ask', question, '--json']);
    const j = tryJson(r.stdout);
    return j && Array.isArray(j.routed_to) ? j.routed_to[0] : undefined;
  }

  test('ask: a CI/OIDC question routes to cicd-pipeline-compromise', () => {
    assert.equal(routedTop('my CI runner leaked an OIDC token'), 'cicd-pipeline-compromise');
  });

  test("ask: an 'AI command and control' question routes to ai-api", () => {
    assert.equal(routedTop('detect AI used as command and control'), 'ai-api');
  });

  test('ask: a nonsense English question does not confidently route (stopword filtering)', () => {
    const r = cli(['ask', 'how do I bake bread', '--json']);
    const j = tryJson(r.stdout);
    assert.ok(j, 'ask must emit JSON');
    if (Array.isArray(j.routed_to) && j.routed_to.length > 0) {
      assert.ok((j.confidence ?? 0) < 0.1, `a nonsense query must not route confidently; got confidence ${j.confidence}`);
    } else {
      assert.deepEqual(j.routed_to, [], 'no match expected for a nonsense query');
    }
  });

  test('ask: existing routes are unregressed', () => {
    assert.equal(routedTop('post-quantum crypto migration'), 'crypto');
    assert.equal(routedTop('kernel privilege escalation'), 'kernel');
    assert.equal(routedTop('secret leaked in repo'), 'secrets');
  });
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

test('unknown flag on ask hard-fails (exit 1)', () => {
  const r = cli(['ask', 'x', '--bogusflag']);
  assert.equal(r.status, 1, `expected exit 1; got ${r.status}`);
  const body = tryJson(r.stderr.trim()) || tryJson(r.stdout.trim());
  assert.ok(body, 'response should be parseable JSON');
  assert.equal(body.ok, false);
  assert.match(body.error, /unknown flag/);
});
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});


// ---- routed from error-ux-hardening ----
require("node:test").describe("error-ux-hardening", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
/**
 * Error-UX hardening regression suite.
 *
 * Pins the operator-facing error improvements: a case-only playbook typo gets a
 * suggestion, input-validation errors are not mislabeled "internal error", the
 * `ask` verb points a CVE/RFC question at the resolver, and the CVE
 * malformed-id message is accurate for a short year (not just a non-numeric
 * tail). All offline + deterministic.
 *
 * Discipline: exact exit codes; value/type assertions paired with presence.
 */

const test = require("node:test");
const assert = require("node:assert/strict");

const { makeSuiteHome, makeCli, tryJson } = require("./_helpers/cli");
const SUITE_HOME = makeSuiteHome("exceptd-erruxe-");
const cli = makeCli(SUITE_HOME);

test("ask with a CVE identifier points at `exceptd cve` on stderr", () => {
  const r = cli(["ask", "is CVE-2017-9006 a real cve"]);
  assert.equal(r.status, 0);
  assert.match(r.stderr, /exceptd cve CVE-2017-9006/);
});

test("ask with an RFC number points at `exceptd rfc` on stderr", () => {
  const r = cli(["ask", "what is RFC 9404 about"]);
  assert.equal(r.status, 0);
  assert.match(r.stderr, /exceptd rfc 9404/);
});
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});


// ---- routed from operator-bugs ----
require("node:test").describe("operator-bugs", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
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

const { ROOT, CLI, makeSuiteHome, makeCli, tryJson, secureTmpFile } = require('./_helpers/cli');
const runner = require(path.join(ROOT, 'lib', 'playbook-runner.js'));

const SUITE_HOME = makeSuiteHome('exceptd-operator-bugs-');
const cli = makeCli(SUITE_HOME);

// ===================================================================








// ===================================================================





// ===================================================================

// ===================================================================



// ===================================================================



// ===================================================================




// ===================================================================


// ===================================================================

// ===================================================================
// CSAF framework gaps emit as `document.notes[]` with `category: details`,
// not as `vulnerabilities[]` entries with `ids: [{system_name:
// 'exceptd-framework-gap'}]`. The `system_name` slot is reserved for
// recognised vulnerability tracking authorities (CVE, GHSA, etc.); the
// custom string is rejected by NVD / ENISA / Red Hat dashboards. Notes
// are the right home for advisory context, not pseudo-CVEs. The test
// asserts the notes-based shape and anti-asserts the pseudo-vulnerability
// shape.









// ===================================================================







// ===================================================================





// ===================================================================















// ===================================================================
// v0.11.14 freshness additions — opt-in registry check + upstream-check
// + refresh --network. Tests use EXCEPTD_REGISTRY_FIXTURE so they're
// fully offline-deterministic.
// ===================================================================

function withFixture(version, daysAgo) {
  const file = secureTmpFile('npm-fixture.json', 'npm-fixture-');
  const publishedAt = new Date(Date.now() - daysAgo * 24 * 3600 * 1000).toISOString();
  fs.writeFileSync(file, JSON.stringify({
    "dist-tags": { latest: version },
    version,
    time: { [version]: publishedAt, modified: publishedAt },
  }));
  return file;
}








// ===================================================================
// v0.12.0 — GHSA source + refresh --advisory + refresh --curate
// ===================================================================













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
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});


// ---- routed from recipes-verb-and-ask-skill-fallback ----
require("node:test").describe("recipes-verb-and-ask-skill-fallback", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
/**
 * Regression suite for the `recipes` verb + the `ask` skill-only-domain
 * suggestion:
 *
 *   recipes — lists the curated multi-skill workflows; `recipes <id>` expands
 *     one; an unknown id is refused. (Previously the curated recipes had no
 *     CLI surface at all.)
 *   ask — a question in a domain covered by a SKILL rather than a playbook
 *     (email-auth/DMARC, child-safety, HIPAA, DLP) surfaces a skill_suggestion
 *     pointing at the real skill, instead of only a confident wrong playbook.
 *
 * Discipline: exact field/exit assertions; each suggested skill must exist.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const { makeSuiteHome, makeCli, tryJson } = require("./_helpers/cli");

const cli = makeCli(makeSuiteHome("exceptd-recipesask-"));

test("ask surfaces the right skill for skill-only domains (no playbook home)", () => {
  const cases = [
    ["DMARC email spoofing", "email-security-anti-phishing"],
    ["child safety age gate", "age-gates-child-safety"],
    ["HIPAA PHI healthcare security", "sector-healthcare"],
    ["data loss prevention policy", "dlp-gap-analysis"],
  ];
  const manifest = require("../manifest.json");
  const skillExists = (n) => manifest.skills.some(s => (s.name || s.id) === n);
  for (const [q, skill] of cases) {
    const j = tryJson(cli(["ask", q, "--json"]).stdout);
    assert.equal(j.skill_suggestion, skill, `"${q}" must suggest the ${skill} skill`);
    assert.ok(skillExists(skill), `${skill} must be a real skill`);
  }
});

test("ask does not attach a skill_suggestion to a genuine playbook query", () => {
  for (const q of ["kernel privilege escalation", "post-quantum crypto migration", "MCP server trust"]) {
    const j = tryJson(cli(["ask", q, "--json"]).stdout);
    assert.equal(j.skill_suggestion, undefined, `"${q}" routes to a playbook; no skill_suggestion expected`);
  }
});
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});
