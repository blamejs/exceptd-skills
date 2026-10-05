'use strict';

/**
 * The upstream CVE ids the catalog tracks, and the entry that holds each one's data.
 *
 * An entry keyed by a CVE id tracks that id. An entry keyed by another identifier
 * (`BUG-*`, `MAL-*`, a suffixed key such as `CVE-2020-17103-REREGRESSION-2026`) tracks
 * each CVE id in its `aliases[]` that no entry is keyed by. Refresh, prefetch, KEV
 * discovery and `validate-cves` read upstream feeds by these ids.
 */

const CVE_ID_RE = /^CVE-\d{4}-\d{4,7}$/;

/**
 * @param {object} catalog - parsed data/cve-catalog.json
 * @returns {{cveId: string, key: string, alias: boolean}[]} one target per tracked CVE
 *   id: `key` is the catalog entry that holds its data, and `alias` is true when that
 *   entry lists the id in `aliases[]` rather than being keyed by it. Own keys come
 *   first, in catalog order, then alias targets in catalog order.
 */
function cveLookupTargets(catalog) {
  if (!catalog || typeof catalog !== 'object') return [];
  const keys = Object.keys(catalog);
  const own = new Set(keys.filter((k) => CVE_ID_RE.test(k)));
  const targets = [...own].map((k) => ({ cveId: k, key: k, alias: false }));
  const seen = new Set(own);
  for (const k of keys) {
    if (own.has(k) || k.startsWith('_')) continue;
    const e = catalog[k];
    if (!e || typeof e !== 'object' || !Array.isArray(e.aliases)) continue;
    for (const a of e.aliases) {
      if (typeof a !== 'string' || !CVE_ID_RE.test(a) || seen.has(a)) continue;
      seen.add(a);
      targets.push({ cveId: a, key: k, alias: true });
    }
  }
  return targets;
}

/**
 * @param {object} catalog - parsed data/cve-catalog.json
 * @returns {Set<string>} every CVE id the catalog tracks, own keys and aliases
 */
function trackedCveIds(catalog) {
  return new Set(cveLookupTargets(catalog).map((t) => t.cveId));
}

module.exports = { CVE_ID_RE, cveLookupTargets, trackedCveIds };
