'use strict';

/**
 * sources/validators/index.js — barrel export.
 *
 * Re-exports:
 *   - validateCve(cveId, localEntry)         — NVD + CISA KEV cross-check (per CVE)
 *   - validateAtlasVersion()                 — Confirm pinned ATLAS version matches upstream
 *   - validateAllCves(catalog, opts?)        — Aggregate CVE validation across the local catalog
 *
 * Aggregate report shape:
 *   {
 *     generated_at: ISO timestamp,
 *     total: number,
 *     by_status: { match, drift, unreachable, missing },
 *     drift_count: number,
 *     results: ValidationResult[]  // see cve-validator.js
 *   }
 */

const { validateCve, getKevCache, resetKevCache } = require('./cve-validator');
const { validateAtlasVersion } = require('./atlas-validator');
const { validateRfc, validateAllRfcs } = require('./rfc-validator');
const { cveLookupTargets } = require('../../lib/catalog-ids');

/**
 * @param {object} catalog - parsed data/cve-catalog.json (the whole object incl. _meta)
 * @param {object} [opts]
 * @param {number} [opts.concurrency=4] - parallel NVD lookups (NVD allows 5 rps anonymously)
 * @returns {Promise<object>} aggregate report
 */
async function validateAllCves(catalog, opts = {}) {
  const concurrency = Math.max(1, Math.min(8, opts.concurrency || 4));
  if (!catalog || typeof catalog !== 'object') {
    throw new TypeError('validateAllCves: catalog must be an object');
  }

  // Each tracked CVE id is checked against the entry that holds it; an id an entry
  // lists in aliases[] carries that entry's key as `catalog_key`.
  const targets = cveLookupTargets(catalog);
  const ids = targets.map((t) => t.cveId);
  const results = [];
  const by_status = { match: 0, drift: 0, unreachable: 0, missing: 0 };

  // Simple windowed concurrency — no extra deps.
  let cursor = 0;
  async function worker() {
    while (cursor < ids.length) {
      const idx = cursor++;
      const id = ids[idx];
      const key = targets[idx].key;
      try {
        const res = await validateCve(id, catalog[key]);
        res.catalog_key = key;
        results[idx] = res;
        by_status[res.status] = (by_status[res.status] || 0) + 1;
      } catch (err) {
        // Defensive: validateCve already swallows network errors; this is a logic error.
        results[idx] = {
          cve_id: id,
          catalog_key: key,
          status: 'unreachable',
          discrepancies: [],
          fetched: { sources: { nvd: null, kev: null } },
          local: catalog[key] || null,
          error: err.message,
        };
        by_status.unreachable++;
      }
    }
  }

  const workers = Array.from({ length: Math.min(concurrency, ids.length) }, () => worker());
  await Promise.all(workers);

  return {
    generated_at: new Date().toISOString(),
    total: ids.length,
    by_status,
    drift_count: by_status.drift,
    results,
  };
}

module.exports = {
  validateCve,
  validateAtlasVersion,
  validateAllCves,
  validateRfc,
  validateAllRfcs,
  getKevCache,
  resetKevCache,
};
