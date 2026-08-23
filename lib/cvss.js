"use strict";
/**
 * CVSS metric selection and vector normalization for NVD ingestion. NVD tags
 * its legacy v2 metric `type: "Primary"` on pre-v3 CVEs while a newer v3.1
 * re-score rides as "Secondary", so selecting on `type` alone downgrades a
 * curated entry to v2. `cvssMetricV2` also omits the "CVSS:2.0/" prefix the
 * catalog schema requires.
 */

// A bare (unprefixed) CVSS v2 base vector; Au: is the metric v3/v4 dropped.
const BARE_V2_RE = /^AV:[NAL]\/AC:[HML]\/Au:[MSN]\//;

// Version prefixes the catalog accepts; mirrors STRICT_CVSS_PATTERN in validate-cve-catalog.js.
const PREFIXED_RE = /^CVSS:(2\.0|3\.0|3\.1|4\.0)\//;

/**
 * The CVSS version a vector declares, as a comparable number. Null when
 * unrecognized, so callers treat an unknown version as "do not block".
 */
function cvssVersionOf(vector) {
  if (typeof vector !== "string" || vector.length === 0) return null;
  const m = vector.match(PREFIXED_RE);
  if (m) return Number(m[1]);
  if (BARE_V2_RE.test(vector)) return 2.0;
  return null;
}

/**
 * Prefixes a bare v2 base vector with "CVSS:2.0/"; already-prefixed and
 * unrecognized vectors pass through unchanged.
 */
function normalizeCvssVector(vector) {
  if (typeof vector !== "string" || vector.length === 0) return vector;
  if (PREFIXED_RE.test(vector)) return vector;
  if (BARE_V2_RE.test(vector)) return `CVSS:2.0/${vector}`;
  return vector;
}

/**
 * The most authoritative metric from an NVD `metrics` object: newest version
 * wins, "Primary" beats "Secondary". Null when no CVSS metric is present.
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
