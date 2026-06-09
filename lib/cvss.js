"use strict";
/**
 * lib/cvss.js
 *
 * Shared CVSS metric-selection and vector-normalization helpers for every
 * site that ingests NIST NVD scoring (the cache-backed refresh diff, the
 * live per-CVE validator, and the KEV auto-discovery importer).
 *
 * Two properties of NVD's data make naive ingestion lossy:
 *
 *   1. NVD tags the legacy CVSS v2 metric as `type: "Primary"` on pre-v3
 *      CVEs, while a modern v3.1 re-score (often supplied by a CNA) rides as
 *      `type: "Secondary"`. Selecting a metric by `type === "Primary"` alone
 *      therefore picks the *older* v2 score over a newer v3.1 one — silently
 *      downgrading a curated v3.1 entry to v2 on every refresh.
 *
 *   2. NVD's `cvssMetricV2` entries carry a bare base vector
 *      ("AV:N/AC:L/Au:N/C:C/I:C/A:C") with no "CVSS:2.0/" prefix, whereas
 *      v3.x/v4.0 carry the prefix. The catalog schema (and
 *      validate-cve-catalog --strict) require the canonical "CVSS:<x.y>/"
 *      prefix, so writing a bare v2 vector produces an invalid entry.
 *
 * `selectNvdCvss` resolves (1) by preferring the newest CVSS version present
 * and choosing Primary only *within* that version; it resolves (2) by
 * normalizing the returned vector. Callers additionally guard against
 * cross-version downgrades using `cvssVersionOf` on the locally-curated
 * vector.
 *
 * Zero npm deps. Node stdlib only.
 */

// A bare (unprefixed) CVSS v2 base vector. v2 is the only version NVD emits
// without a "CVSS:x/" prefix, and its grammar carries the Au: (Authentication)
// metric that v3/v4 dropped — the unambiguous discriminator for a bare v2.
const BARE_V2_RE = /^AV:[NAL]\/AC:[HML]\/Au:[MSN]\//;

// The four canonical version prefixes the catalog accepts (mirrors
// validate-cve-catalog.js STRICT_CVSS_PATTERN).
const PREFIXED_RE = /^CVSS:(2\.0|3\.0|3\.1|4\.0)\//;

/**
 * The CVSS version a vector declares, as a comparable number (2.0 < 3.0 < 3.1
 * < 4.0). Recognizes the four canonical "CVSS:x.y/" prefixes plus NVD's bare
 * v2 base vector. Returns null for anything unrecognized so callers can treat
 * an unknown version as "do not block" rather than mis-suppressing a diff.
 *
 * @param {string} vector
 * @returns {number|null}
 */
function cvssVersionOf(vector) {
  if (typeof vector !== "string" || vector.length === 0) return null;
  const m = vector.match(PREFIXED_RE);
  if (m) return Number(m[1]);
  if (BARE_V2_RE.test(vector)) return 2.0;
  return null;
}

/**
 * Ensure a vector carries a canonical "CVSS:x.y/" prefix. A bare v2 base
 * vector is prefixed with "CVSS:2.0/"; already-prefixed vectors (and anything
 * unrecognized) pass through unchanged. The output of a recognized vector
 * always satisfies validate-cve-catalog --strict.
 *
 * @param {string} vector
 * @returns {string}
 */
function normalizeCvssVector(vector) {
  if (typeof vector !== "string" || vector.length === 0) return vector;
  if (PREFIXED_RE.test(vector)) return vector;
  if (BARE_V2_RE.test(vector)) return `CVSS:2.0/${vector}`;
  return vector;
}

/**
 * Select the most authoritative CVSS metric from an NVD `metrics` object.
 * Prefers the newest CVSS version present (4.0 > 3.1 > 3.0 > 2.0); within the
 * chosen version prefers NVD's "Primary" analyst score over a "Secondary"
 * (CNA) one, falling back to the first entry when no Primary exists in that
 * version. The returned vector is normalized to the canonical prefix form.
 *
 * @param {object} metrics  The `vulnerabilities[0].cve.metrics` object.
 * @returns {{version:number|null, baseScore:number|null, vector:string|null, source:string|null}|null}
 */
function selectNvdCvss(metrics) {
  const m = metrics || {};
  const buckets = [
    [4.0, m.cvssMetricV40],
    [3.1, m.cvssMetricV31],
    [3.0, m.cvssMetricV30],
    [2.0, m.cvssMetricV2],
  ];
  for (const [bucketVersion, bucket] of buckets) {
    const arr = Array.isArray(bucket) ? bucket : [];
    if (arr.length === 0) continue;
    const chosen = arr.find((x) => x && x.type === "Primary") || arr[0];
    const data = chosen && chosen.cvssData ? chosen.cvssData : null;
    const declared = data && data.version != null ? Number(data.version) : null;
    return {
      version: Number.isFinite(declared) ? declared : bucketVersion,
      baseScore: typeof data?.baseScore === "number" ? data.baseScore : null,
      vector: data?.vectorString ? normalizeCvssVector(data.vectorString) : null,
      source: chosen && chosen.source ? chosen.source : null,
    };
  }
  return null;
}

module.exports = { cvssVersionOf, normalizeCvssVector, selectNvdCvss };
