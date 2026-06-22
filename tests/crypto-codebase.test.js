"use strict";


// ---- routed from blamejs-scan-fixes ----
require("node:test").describe("blamejs-scan-fixes", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
/**
 * tests/blamejs-scan-fixes.test.js
 *
 * Pins the fixes a scan of the sibling blamejs repo surfaced:
 *  - playbooks that declare bundle_format "json" (secrets / cred-stores /
 *    runtime / citation-hygiene) now build a real structured-JSON evidence
 *    bundle instead of falling through to the "Unknown format" placeholder;
 *  - the crypto-codebase collector attests the playbook's own
 *    `repo-has-source-tree` gate (it previously emitted a `repo-context` key
 *    the playbook never references, so a source repo got a spurious
 *    precondition_unverified warning).
 * Exact-value pins, with content paired to presence per the project's
 * field-present-vs-field-populated rule.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const runner = require('../lib/playbook-runner.js');
const cryptoCodebase = require('../lib/collectors/crypto-codebase.js');
const containersCollector = require('../lib/collectors/containers.js');
const { makeSuiteHome, makeCli, tryJson } = require('./_helpers/cli');

const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'exceptd-dogfix2-'));
process.on('exit', () => { try { fs.rmSync(TMP, { recursive: true, force: true }); } catch { /* non-fatal */ } });
let _n = 0;
function mkfx() { const d = path.join(TMP, 'fx-' + _n++); fs.mkdirSync(d, { recursive: true }); return d; }

test("crypto-codebase collector attests repo-has-source-tree from the gate's own markers (not just source-file extensions)", () => {
  // A manifest marker -> true.
  const withManifest = mkfx();
  fs.writeFileSync(path.join(withManifest, 'package.json'), '{"name":"x","version":"1.0.0"}');
  const m = cryptoCodebase.collect({ cwd: withManifest }).precondition_checks;
  assert.equal(m['repo-has-source-tree'], true, 'a package manifest marker attests the gate true');
  assert.equal('repo-context' in m, false, 'the playbook-unknown repo-context key must not be emitted');

  // An src/ directory marker (no manifest, no extension-matched files yet) -> true.
  const withSrcDir = mkfx();
  fs.mkdirSync(path.join(withSrcDir, 'src'), { recursive: true });
  assert.equal(
    cryptoCodebase.collect({ cwd: withSrcDir }).precondition_checks['repo-has-source-tree'],
    true,
    'an src/ directory marker attests the gate true even before any source file exists'
  );

  // Source files by extension but NONE of the gate's markers -> false: the
  // attestation mirrors the gate's exists_any(markers) predicate, not the
  // collector's SOURCE_EXTS file count.
  const looseSourceOnly = mkfx();
  fs.writeFileSync(path.join(looseSourceOnly, 'script.py'), 'import hashlib\n');
  assert.equal(
    cryptoCodebase.collect({ cwd: looseSourceOnly }).precondition_checks['repo-has-source-tree'],
    false,
    'a loose source file with no source-tree marker attests false, matching the gate'
  );

  // No markers at all -> false.
  const empty = mkfx();
  assert.equal(
    cryptoCodebase.collect({ cwd: empty }).precondition_checks['repo-has-source-tree'],
    false,
    'an empty tree attests the gate false'
  );
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

test("crypto-codebase: evidence_locations for bcrypt-cost-low carry a startLine", () => {
  const tmp = mkTmp("fp-crypto-line-");
  try {
    // bcrypt call with cost 4 (<12) on line 3.
    const src = [
      "const bcrypt = require('bcrypt');",
      "async function hash(pw) {",
      "  return bcrypt.hash(pw, 4);",
      "}",
      "",
    ].join("\n");
    fs.writeFileSync(path.join(tmp, "auth.js"), src);
    const r = cryptoCollector.collect({ cwd: tmp });
    assert.equal(r.signal_overrides["bcrypt-cost-low"], "hit");
    const locs = r.evidence_locations["bcrypt-cost-low"];
    assert.ok(Array.isArray(locs) && locs.length >= 1);
    assert.equal(locs[0].uri, "auth.js");
    assert.equal(locs[0].startLine, 3, "startLine must point at the bcrypt call");
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
