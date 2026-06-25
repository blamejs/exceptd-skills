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

// ---------------------------------------------------------------------------
// rejected-or-disputed-cve fires ONLY on a record-level reject/dispute of the
// CVE's OWN id — not on a CVSS scoring dispute, a disclosure-coordination
// dispute, or a reject/dispute word that refers to a DIFFERENT cross-referenced
// CVE. This is a catalog-level guard: the collector's internal record-level
// check is not unit-testable in isolation, so we replicate it verbatim against
// the REAL data/cve-catalog.json and assert exactly one entry (CVE-2023-48022)
// is record-level disputed while the six prior false positives are not.
//
// Without the qualifier-window + adjacent-id + self-id checks, the naive
// `/reject|dispute|withdrawn/` scan flips on entries whose notes discuss a
// CVSS-scoring dispute, a disclosure-coordination dispute, or the rejection of
// a DIFFERENT (cross-referenced) CVE — six such false positives lived in the
// catalog. This test pins them shut.
// ---------------------------------------------------------------------------

test("citation-hygiene: rejected-or-disputed-cve is record-level — only CVE-2023-48022, not the 6 prior false positives", () => {
  const cat = JSON.parse(
    fs.readFileSync(path.join(ROOT, "data", "cve-catalog.json"), "utf8"),
  );

  // The note-text surface the record-level check reads (mirrors the collector).
  function note(v) {
    return [
      v.cvss_note,
      v.active_exploitation_notes,
      v.vector,
      v.discovery_attribution_note,
      v.ai_discovery_notes,
      v._kev_short_description,
    ]
      .filter(Boolean)
      .join(" • ");
  }

  // The REAL exported collector function — not a replica — so this test tracks
  // the collector's actual record-level reject/dispute logic.
  const recordRejectedOrDisputed = citationCollector.recordRejectedOrDisputed;

  const flagged = Object.keys(cat).filter((id) =>
    recordRejectedOrDisputed(note(cat[id]), id),
  );

  // Exactly one record-level dispute in the whole catalog: CVE-2023-48022.
  assert.deepEqual(
    flagged,
    ["CVE-2023-48022"],
    `expected exactly CVE-2023-48022 to be record-level disputed; got ${JSON.stringify(flagged)}`,
  );

  // And the six prior false positives are individually NOT flagged. (If any id
  // is absent from the catalog, skip that id's assertion but keep the rest.)
  const FALSE_POSITIVES = [
    "CVE-2024-50050",
    "CVE-2026-24206",
    "CVE-2023-6019",
    "CVE-2023-6021",
    "CVE-2025-55182",
    "CVE-2025-31161",
  ];
  for (const id of FALSE_POSITIVES) {
    if (!cat[id]) continue; // id absent — nothing to assert for it
    assert.equal(
      recordRejectedOrDisputed(note(cat[id]), id),
      false,
      `${id} must NOT be flagged as record-level rejected/disputed`,
    );
  }
});

test("citation-hygiene: a record rejected AS A DUPLICATE of another CVE stays flagged (replacement target ≠ subject)", () => {
  const rec = citationCollector.recordRejectedOrDisputed;
  // THIS record is the rejected one; the other CVE is the replacement target.
  assert.equal(rec("This record was REJECTED as a duplicate of CVE-2025-99999.", "CVE-2025-00001"), true,
    "rejected-as-a-duplicate-of names the replacement, but THIS record is the rejected one");
  assert.equal(rec("Withdrawn; superseded by CVE-2030-11111.", "CVE-2030-00002"), true,
    "superseded-by also leaves THIS record as the withdrawn one");
  // But a DIFFERENT CVE that is itself the rejected subject still suppresses.
  assert.equal(rec("CVE-2025-66478 has been rejected by NVD.", "CVE-2025-55182"), false,
    "a different CVE that is the rejection subject is about THAT record, not this one");
  // And a CVSS scoring dispute is still not a record rejection.
  assert.equal(rec("Carries a documented CVSS scoring dispute.", "CVE-2024-50050"), false,
    "a CVSS scoring dispute is a severity disagreement, not a record rejection");
});
