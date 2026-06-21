'use strict';

/**
 * tests/collectors-crypto-codebase.test.js
 *
 * Subject coverage for lib/collectors/crypto-codebase.js:
 *  - evidence_locations for bcrypt-cost-low carry a 1-based startLine;
 *  - the collector attests the playbook's own `repo-has-source-tree` gate from
 *    the gate's own markers (manifest / src dir), mirroring the gate's
 *    exists_any(markers) predicate rather than the collector's SOURCE_EXTS file
 *    count, and never emits the playbook-unknown `repo-context` key.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');

const cryptoCollector = require(path.join(ROOT, 'lib', 'collectors', 'crypto-codebase.js'));
const cryptoCodebase = cryptoCollector;

const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'exceptd-crypto-coll-'));
process.on('exit', () => { try { fs.rmSync(TMP, { recursive: true, force: true }); } catch { /* non-fatal */ } });
let _n = 0;
function mkfx() { const d = path.join(TMP, 'fx-' + _n++); fs.mkdirSync(d, { recursive: true }); return d; }

function mkTmp(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

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
