#!/usr/bin/env node
"use strict";

/**
 * EPSS score/percentile consistency gate.
 *
 * EPSS publishes a score and a percentile for every CVE, refreshed daily. The
 * percentile is the score's RANK within that day's publication: if A scores
 * higher than B on a given day, A's percentile is at least B's. That makes the
 * pair self-checking with no network access — sort a day's entries by score and
 * the percentiles must come out sorted too.
 *
 * The failure this catches is updating one field without the other. A refresh
 * that writes a new score but keeps yesterday's percentile leaves a plausible
 * entry: both numbers are in range, both look like EPSS values, and nothing
 * downstream can tell they describe different days. The result is a CVE ranked
 * as top-decile urgency on a score that no longer supports it, which is exactly
 * the input the prioritisation model trusts most.
 *
 * What the ordering check does and does not establish. Monotonicity is a
 * necessary condition, not a sufficient one: it catches a stale percentile that
 * contradicts the new score's rank, which is what a partial refresh usually
 * produces, but a stale value that happens to preserve the ordering passes.
 * Proving two fields share a publication would require the fetched row, and
 * that is not recoverable from the catalog offline. So this is a corruption
 * detector, not a provenance proof — the provenance guarantee has to come from
 * the write side, by fetching and writing score, percentile and date together.
 *
 * Three checks run:
 *   - within each epss_date, sorting by score must sort by percentile;
 *   - an entry carries both numeric fields or neither;
 *   - epss_note, which is derived text, must restate the current fields.
 *
 * Entries are grouped by epss_date so each publication is checked against
 * itself; comparing across days is meaningless because the whole distribution
 * shifts.
 *
 * Exit codes: 0 consistent, 1 inconsistent.
 */

const fs = require("node:fs");
const path = require("node:path");

const ROOT = path.resolve(__dirname, "..");

/**
 * Percentiles are published rounded to five decimals, so two scores that are
 * adjacent in the ranking can round to percentiles that invert by a hair. That
 * is arithmetic, not drift. Real mismatches are pairs pulled from different
 * days, which land orders of magnitude above this: the widest rounding artifact
 * observed in the catalog is 8e-5, while a stale-field mismatch runs 0.05-0.9.
 * The threshold sits between the two, far enough from each that neither
 * classification is a close call.
 */
const ROUNDING_TOLERANCE = 1e-3;

function loadCatalog(file) {
  return JSON.parse(fs.readFileSync(file, "utf8"));
}

function ordinal(n) {
  const suffixes = ["th", "st", "nd", "rd"];
  const v = n % 100;
  return `${n}${suffixes[(v - 20) % 10] || suffixes[v] || suffixes[0]}`;
}

/**
 * The operator-readable restatement of an entry's EPSS fields. Entries carry it
 * as `epss_note`, and it is derived, not authored — so it must be rebuilt
 * whenever the numbers move.
 */
function renderNote(entry) {
  const pct = Math.round(entry.epss_percentile * 100);
  return `FIRST EPSS ${entry.epss_score} (${ordinal(pct)} percentile) as of ${entry.epss_date}.`;
}

/**
 * Group entries by publication date. Entries missing either field are reported
 * separately rather than skipped — a half-populated pair is its own defect, and
 * silently ignoring it would let the gate pass on the very shape it exists to
 * catch.
 */
function cohorts(catalog) {
  const groups = new Map();
  const incomplete = [];

  for (const [id, entry] of Object.entries(catalog)) {
    const hasScore = typeof entry.epss_score === "number";
    const hasPercentile = typeof entry.epss_percentile === "number";

    if (!hasScore && !hasPercentile) continue;
    if (!hasScore || !hasPercentile) {
      incomplete.push({
        id,
        missing: hasScore ? "epss_percentile" : "epss_score",
      });
      continue;
    }

    const date = entry.epss_date || "(no epss_date)";
    if (!groups.has(date)) groups.set(date, []);
    groups.get(date).push({ id, score: entry.epss_score, percentile: entry.epss_percentile });
  }

  return { groups, incomplete };
}

/**
 * Sort a cohort by score and report every place the percentile goes backwards
 * by more than rounding can explain.
 */
function inversions(rows) {
  const sorted = [...rows].sort((a, b) => a.score - b.score);
  const found = [];

  for (let i = 1; i < sorted.length; i++) {
    const prev = sorted[i - 1];
    const cur = sorted[i];
    const delta = prev.percentile - cur.percentile;
    if (delta > ROUNDING_TOLERANCE) {
      found.push({ lower: cur, higher: prev, delta });
    }
  }

  return found;
}

function check(catalogFile) {
  const catalog = loadCatalog(catalogFile);
  const { groups, incomplete } = cohorts(catalog);
  const failures = [];

  for (const [date, rows] of groups) {
    for (const bad of inversions(rows)) {
      failures.push(
        `${date}: ${bad.lower.id} scores ${bad.lower.score} but ranks ` +
          `${bad.lower.percentile}, below ${bad.higher.id} which scores ` +
          `${bad.higher.score} at ${bad.higher.percentile} ` +
          `(gap ${bad.delta.toFixed(5)}) — the two fields are from different publications`
      );
    }
  }

  for (const row of incomplete) {
    failures.push(`${row.id}: has one EPSS field but not ${row.missing} — write both together or neither`);
  }

  // The prose restatement drifts the same way the percentile does: a refresh
  // moves the numbers and leaves the sentence describing the previous
  // publication, so the entry states two different scores as of two different
  // dates. It is derived text, so it can be checked exactly.
  for (const [id, entry] of Object.entries(catalog)) {
    if (typeof entry.epss_note !== "string") continue;
    if (typeof entry.epss_score !== "number" || typeof entry.epss_percentile !== "number") continue;
    const expected = renderNote(entry);
    if (entry.epss_note !== expected) {
      failures.push(
        `${id}: epss_note reads ${JSON.stringify(entry.epss_note)} but the fields say ` +
          `${JSON.stringify(expected)} — regenerate the note when the numbers move`
      );
    }
  }

  return { failures, cohortCount: groups.size, entryCount: [...groups.values()].reduce((n, r) => n + r.length, 0) };
}

function main() {
  const file = process.argv[2] || path.join(ROOT, "data", "cve-catalog.json");
  const { failures, cohortCount, entryCount } = check(file);

  if (failures.length) {
    console.error("EPSS consistency: FAIL");
    for (const f of failures) console.error(`  ${f}`);
    console.error(
      `\n${failures.length} inconsistent ${failures.length === 1 ? "entry" : "entries"}. ` +
        `Re-fetch score and percentile together from api.first.org and write them in one pass.`
    );
    process.exitCode = 1;
    return;
  }

  console.log(
    `EPSS consistency: PASS — ${entryCount} entries across ${cohortCount} publication ${cohortCount === 1 ? "date" : "dates"}, every cohort ranks monotonically`
  );
}

if (require.main === module) main();

module.exports = { check, cohorts, inversions, renderNote, ROUNDING_TOLERANCE };
