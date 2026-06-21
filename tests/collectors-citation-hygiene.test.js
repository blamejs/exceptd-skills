'use strict';

/**
 * tests/collectors-citation-hygiene.test.js
 *
 * Subject coverage for lib/collectors/citation-hygiene.js:
 *  - fabricated-cve-id evidence_locations carry a 1-based startLine pointing at
 *    the bad citation.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');

const ROOT = path.join(__dirname, '..');

const citationCollector = require(path.join(ROOT, 'lib', 'collectors', 'citation-hygiene.js'));

function mkTmp(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

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
