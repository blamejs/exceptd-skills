#!/usr/bin/env node
"use strict";

/**
 * EPSS score/percentile consistency gate. Exit 0 consistent, 1 inconsistent.
 *
 * The percentile is the score's rank within one publication, so a cohort must
 * sort the same way by both. Monotonicity is necessary, not sufficient.
 */

const fs = require("node:fs");
const path = require("node:path");

const ROOT = path.resolve(__dirname, "..");

/**
 * Percentiles publish rounded to five decimals, so adjacent scores can invert by
 * a hair. Rounding artifacts reach 8e-5; a stale-field mismatch runs 0.05-0.9.
 */
const ROUNDING_TOLERANCE = 1e-3;

function loadCatalog(file) {
  return JSON.parse(fs.readFileSync(file, "utf8"));
}

/** Shared with the refresh writer so gate and writer cannot disagree on wording. */
const { renderEpssNote: renderNote } = require("../lib/cve-enrich.js");

/** Group entries by publication date; a half-populated pair is reported, not skipped. */
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

/** Sort by score; report every percentile step backwards that rounding cannot explain. */
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

  // epss_note is derived text, so it can be checked exactly against the fields.
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
