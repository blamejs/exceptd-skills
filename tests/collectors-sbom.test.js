'use strict';

/**
 * tests/collectors-sbom.test.js
 *
 * Subject coverage for lib/collectors/sbom.js:
 *  - the collector auto-attests the `any-package-manager-present` precondition
 *    it can verify from a collected lockfile (false without one);
 *  - lockfile-no-integrity must NOT fire on a clean npm 7+ lockfile whose `""`
 *    root entry carries name+version but no integrity, yet must still fire when
 *    a REMOTE-tarball entry (one with `resolved`) is missing integrity.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const sbom = require('../lib/collectors/sbom.js');
const sbomCollector = sbom;

const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'exceptd-sbom-coll-'));
process.on('exit', () => { try { fs.rmSync(TMP, { recursive: true, force: true }); } catch { /* non-fatal */ } });
let _n = 0;
function mkfx() { const d = path.join(TMP, 'fx-' + _n++); fs.mkdirSync(d, { recursive: true }); return d; }

function mkTmp(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

test('sbom collector attests any-package-manager-present from a collected lockfile (and false without one)', () => {
  const withLock = mkfx();
  fs.writeFileSync(path.join(withLock, 'package-lock.json'), '{"lockfileVersion":3,"packages":{"":{}}}');
  assert.equal(sbom.collect({ cwd: withLock }).precondition_checks['any-package-manager-present'], true);
  assert.equal(sbom.collect({ cwd: mkfx() }).precondition_checks['any-package-manager-present'], false);
});

test("sbom: clean npm 7+ lockfile (root entry has name+version, no integrity) is a MISS", () => {
  const tmp = mkTmp("fp-sbom-clean-");
  try {
    fs.writeFileSync(path.join(tmp, "package-lock.json"), JSON.stringify({
      name: "my-project",
      version: "1.0.0",
      lockfileVersion: 3,
      packages: {
        "": { name: "my-project", version: "1.0.0" },
        "node_modules/foo": { version: "1.2.3", resolved: "https://registry.npmjs.org/foo/-/foo-1.2.3.tgz", integrity: "sha512-deadbeef" },
      },
    }, null, 2));
    const r = sbomCollector.collect({ cwd: tmp });
    assert.equal(r.signal_overrides["lockfile-no-integrity"], "miss",
      "root entry without integrity must not trip the indicator");
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("sbom: remote-tarball entry missing integrity is still a HIT", () => {
  const tmp = mkTmp("fp-sbom-bad-");
  try {
    fs.writeFileSync(path.join(tmp, "package-lock.json"), JSON.stringify({
      name: "my-project",
      version: "1.0.0",
      lockfileVersion: 3,
      packages: {
        "": { name: "my-project", version: "1.0.0" },
        "node_modules/good": { version: "1.0.0", resolved: "https://registry.npmjs.org/good/-/good-1.0.0.tgz", integrity: "sha512-abc" },
        // resolved to a remote tarball but no integrity hash -> the real bug
        "node_modules/evil": { version: "2.0.0", resolved: "https://evil.example/evil-2.0.0.tgz" },
      },
    }, null, 2));
    const r = sbomCollector.collect({ cwd: tmp });
    assert.equal(r.signal_overrides["lockfile-no-integrity"], "hit",
      "a resolved remote entry without integrity must fire the indicator");
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});
