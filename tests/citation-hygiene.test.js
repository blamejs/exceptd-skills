"use strict";


// ---- routed from resolver-trust-and-flag-hardening ----
require("node:test").describe("resolver-trust-and-flag-hardening", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
/**
 * Resolver-trust + flag-hardening regression suite.
 *
 * Pins three independently-exploitable contracts so they can't silently
 * regress:
 *
 *   1. Resolved-cache integrity (lib/citation-resolve.js). A resolved record is
 *      only trusted when it carries a sha256 `_digest` over its own canonical
 *      bytes AND its embedded `resolved_at` is inside the freshness window.
 *      A poisoned/tampered/stale/future-dated file cannot launder a verdict —
 *      it reads back as a cache miss and the resolver falls through to
 *      offline/unknown. This is the security headline: an operator-writable
 *      cache directory can never turn a rejected/fabricated citation into a
 *      "published" one.
 *
 *   2. Unknown-flag rejection on the cve/rfc resolvers. A swallowed `--josn`
 *      would emit human text into a pipe that asked for JSON and defeat a CI
 *      gate, so an unrecognized flag is a hard exit 1 with an ok:false envelope.
 *
 *   3. Evidence-shape / --max-rwep / --format guards on run + ci. `null`, an
 *      array, or a scalar parse as valid JSON but are not a submission; a
 *      non-numeric or negative cap would degenerate the gate; `--format`
 *      explicitly overrides `--json`.
 *
 * Plus the applyResolution RFC-flip contract (a cited RFC number that resolves
 * to nothing is a bad citation; an obsoleted-but-real RFC is not).
 *
 * Discipline (project anti-coincidence rules): assert EXACT exit codes (never
 * notEqual(0)); pair every field-presence check with a value/type assertion;
 * never weaken a test to make it pass. Every test is deterministic and offline:
 * cache tests inject a per-suite EXCEPTD_RESOLVE_CACHE_DIR and a tiny catalog
 * fixture WITHOUT the test ids (so the resolver reaches the cache path), and
 * pass { noNetwork: true } so no network is touched.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const fs = require('node:fs');
const os = require('node:os');
const crypto = require('node:crypto');

const { makeSuiteHome, makeCli, tryJson } = require('./_helpers/cli');

// --- isolated resolved-cache dir + a tiny catalog fixture that deliberately
//     does NOT contain the ids these tests resolve, so resolveCve falls past
//     the catalog branch into the cache branch. Both env vars are set BEFORE
//     require('../lib/citation-resolve.js') — the catalog path is read +
//     memoized at module-require time; the cache dir is read at call time but
//     is set here too to be safe. --------------------------------------------
const CACHE_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'exceptd-resolver-trust-cache-'));
const FIXTURE_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'exceptd-resolver-trust-fixture-'));
const CVE_FIXTURE = path.join(FIXTURE_DIR, 'cve-catalog.json');

// A catalog hit for the CLI fixture-id test, but NONE of the cache-integrity
// test ids, so those reach the cache path rather than short-circuiting here.
const CVE_FIXTURE_DATA = {
  'CVE-2030-0001': {
    cvss_score: 9.8,
    cisa_kev: true,
    name: 'FixtureVuln',
    status: 'published',
  },
};
fs.writeFileSync(CVE_FIXTURE, JSON.stringify(CVE_FIXTURE_DATA, null, 2));

process.on('exit', () => {
  try { fs.rmSync(CACHE_DIR, { recursive: true, force: true }); } catch { /* non-fatal */ }
  try { fs.rmSync(FIXTURE_DIR, { recursive: true, force: true }); } catch { /* non-fatal */ }
});

process.env.EXCEPTD_CVE_CATALOG = CVE_FIXTURE;
process.env.EXCEPTD_RESOLVE_CACHE_DIR = CACHE_DIR;

const { resolveCve } = require('../lib/citation-resolve.js');
const citationHygiene = require('../lib/collectors/citation-hygiene.js');

// Spawned-CLI harness. Pass the fixture catalog + isolated cache dir as env
// overrides so subprocesses resolve offline against them, not the network.
const SUITE_HOME = makeSuiteHome('exceptd-resolver-trust-');
const baseCli = makeCli(SUITE_HOME);
const RESOLVER_ENV = {
  EXCEPTD_CVE_CATALOG: CVE_FIXTURE,
  EXCEPTD_RESOLVE_CACHE_DIR: CACHE_DIR,
};
function cli(args, opts = {}) {
  return baseCli(args, { ...opts, env: { ...RESOLVER_ENV, ...(opts.env || {}) } });
}

// --- digest helper: replicate lib/citation-resolve.js recordDigest exactly so
//     a test can write a VALID (trusted) cache record. sha256 over the record's
//     canonical JSON: keys sorted, `_digest` excluded. ------------------------
function recordDigest(rec) {
  const canon = {};
  for (const k of Object.keys(rec).sort()) {
    if (k === '_digest') continue;
    canon[k] = rec[k];
  }
  return crypto.createHash('sha256').update(JSON.stringify(canon)).digest('hex');
}
function writeRawCveCache(id, rec) {
  const dir = path.join(CACHE_DIR, 'cve');
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, `${id}.json`), JSON.stringify(rec));
  return path.join(dir, `${id}.json`);
}
function writeDigestedCveCache(id, rec) {
  const signed = { ...rec };
  signed._digest = recordDigest(signed);
  return writeRawCveCache(id, signed);
}

// ===================================================================
// 1. Resolved-cache integrity
// ===================================================================








// ===================================================================
// 2. cve / rfc unknown-flag rejection (spawned CLIs)
// ===================================================================




// ===================================================================
// 3. run evidence-shape guard
// ===================================================================

for (const bad of [
  { label: 'null', input: 'null' },
  { label: 'array', input: '[]' },
  { label: 'string', input: '"astring"' },
  { label: 'number', input: '123' },
]) {
  test(`run CLI: --evidence - with ${bad.label} exits 1 with "evidence must be a JSON object"`, () => {
    const r = cli(['run', 'secrets', '--evidence', '-'], { input: bad.input });
    assert.equal(r.status, 1, `expected exit 1; got ${r.status} (stderr: ${r.stderr.slice(0, 200)})`);
    const body = tryJson(r.stderr.trim());
    assert.ok(body, `stderr should be parseable JSON; got: ${r.stderr.slice(0, 200)}`);
    assert.equal(body.ok, false);
    assert.match(body.error, /evidence must be a JSON object/);
  });
}


// ===================================================================
// 4. applyResolution RFC flip
// ===================================================================



// ===================================================================
// 5. ci --max-rwep validation
// ===================================================================




// ===================================================================
// 6. --format overrides --json (note on stderr, markdown on stdout)
// ===================================================================


// ===================================================================
// 7. help lists the cve / rfc / collect verbs
// ===================================================================

test('applyResolution: a nonexistent RFC citation flips rfc-number-title-mismatch to hit', async () => {
  const submission = {
    signal_overrides: {},
    needs_verification: { cve_not_in_catalog: [], rfc_not_in_index: [{ file: 'x', citation: 'RFC 88888' }] },
    artifacts: {},
  };
  const out = await citationHygiene.applyResolution(submission, {
    _resolveCve: async () => ({}),
    _resolveRfc: async () => ({ status: 'nonexistent', found: false }),
  });
  assert.equal(out.signal_overrides['rfc-number-title-mismatch'], 'hit');
});

test('applyResolution: an obsoleted-but-real RFC does NOT flip rfc-number-title-mismatch to hit', async () => {
  const submission = {
    signal_overrides: {},
    needs_verification: { cve_not_in_catalog: [], rfc_not_in_index: [{ file: 'x', citation: 'RFC 88888' }] },
    artifacts: {},
  };
  const out = await citationHygiene.applyResolution(submission, {
    _resolveCve: async () => ({}),
    _resolveRfc: async () => ({ status: 'obsoleted-or-historic', found: true }),
  });
  assert.notEqual(out.signal_overrides['rfc-number-title-mismatch'], 'hit');
});
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});


// ---- routed from collectors-fp-fixes ----
require("node:test").describe("collectors-fp-fixes", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
/**
 * tests/collectors-fp-fixes.test.js
 *
 * Regression tests for a batch of collector false-positive / completeness
 * fixes:
 *   1. sbom: lockfile-no-integrity must NOT fire on a clean npm 7+ lockfile
 *      whose `""` root entry carries name+version but no integrity. It must
 *      still fire when a REMOTE-tarball entry (one with `resolved`) is missing
 *      integrity.
 *   2. secrets: a text file over the 1 MB scan limit is no longer silently
 *      dropped — the skip is recorded in collector_errors.
 *   3. secrets: the AWS-published example access-key id AKIAIOSFODNN7EXAMPLE
 *      does not flip aws-access-key-id.
 *   4. cicd-pipeline-compromise: an OIDC trust JSON under a build-output dir
 *      (dist/) is excluded from the scan via the shared code-exclude set.
 *   5. content-regex collectors (secrets / crypto-codebase / citation-hygiene)
 *      attach a 1-based startLine to their evidence_locations.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const os = require("node:os");

const ROOT = path.join(__dirname, "..");

const sbomCollector = require(path.join(ROOT, "lib", "collectors", "sbom.js"));
const secretsCollector = require(path.join(ROOT, "lib", "collectors", "secrets.js"));
const cryptoCollector = require(path.join(ROOT, "lib", "collectors", "crypto-codebase.js"));
const citationCollector = require(path.join(ROOT, "lib", "collectors", "citation-hygiene.js"));
const cicdCollector = require(path.join(ROOT, "lib", "collectors", "cicd-pipeline-compromise.js"));
const { lineFromOffset } = require(path.join(ROOT, "lib", "collectors", "scan-excludes.js"));

function mkTmp(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

// ---------------------------------------------------------------------------
// Finding 1 — sbom lockfile-no-integrity
// ---------------------------------------------------------------------------



// ---------------------------------------------------------------------------
// Finding 2 — secrets >1 MB skip is recorded
// ---------------------------------------------------------------------------


// ---------------------------------------------------------------------------
// Finding 3 — AWS doc example key demotion
// ---------------------------------------------------------------------------



// ---------------------------------------------------------------------------
// Finding 4 — cicd OIDC scan honors code-exclude set (dist/)
// ---------------------------------------------------------------------------

const WILDCARD_OIDC = JSON.stringify({
  Statement: [{
    Effect: "Allow",
    Principal: { Federated: "token.actions.githubusercontent.com" },
    Condition: {
      StringLike: {
        "token.actions.githubusercontent.com:sub": "repo:acme/*:*",
      },
    },
  }],
}, null, 2);



// ---------------------------------------------------------------------------
// Finding 5 — evidence_locations carry startLine
// ---------------------------------------------------------------------------

test("citation-hygiene: fabricated-cve-id evidence_locations carry a startLine", () => {
  const tmp = mkTmp("fp-cite-line-");
  try {
    // Malformed (non-canonical) CVE on line 2 of a doc file.
    fs.writeFileSync(path.join(tmp, "NOTES.md"),
      "# Security notes\nWe patched CVE-2024-XXXX last week.\n");
    const r = citationCollector.collect({ cwd: tmp });
    assert.equal(r.signal_overrides["fabricated-cve-id"], "hit");
    const locs = r.evidence_locations["fabricated-cve-id"];
    assert.ok(Array.isArray(locs) && locs.length === 1);
    assert.equal(locs[0].uri, "NOTES.md");
    assert.equal(locs[0].startLine, 2, "startLine must point at the bad citation");
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});
