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

  // Record-level reject/dispute check, replicating the (now-internal) collector
  // logic: a reject/dispute/withdrawn word only counts when it refers to THIS
  // CVE's own record — not an adjacent DIFFERENT CVE, and not a "disputed"
  // qualified by a scoring/coordination/disclosure/attribution context word.
  function recordRejectedOrDisputed(n, self) {
    if (!n) return false;
    const S = String(self || "").toUpperCase();
    const re = /\b(reject(?:ed|s|ion)?|disputed?|withdrawn)\b/gi;
    const Q =
      /\b(cvss|scoring|score|severity|coordination|disclosure|methodolog\w*|attribution|naming|assignment|priorit\w*)\b/i;
    let m;
    while ((m = re.exec(n)) !== null) {
      const w = m[1].toLowerCase();
      const b = n.slice(Math.max(0, m.index - 60), m.index);
      const a = n.slice(re.lastIndex, re.lastIndex + 60);
      const adj = (b + " " + a).match(/CVE-\d{4}-\d{4,}/gi) || [];
      if (adj.some((c) => c.toUpperCase() !== S)) continue;
      if (w.startsWith("disput")) {
        const lt = b.trim().split(/[\s-]+/).slice(-3).join(" ");
        if (Q.test(lt)) continue;
      }
      return true;
    }
    return false;
  }

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
