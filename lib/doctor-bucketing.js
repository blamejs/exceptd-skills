"use strict";

/**
 * Buckets `exceptd doctor` per-check results into warning and error lists.
 *
 * Severity decides the bucket, not `ok`: `severity: "warn"` routes to warnings
 * and `severity: "info"` routes to neither list, whatever `ok` says.
 */

function bucketChecks(checks) {
  const warnList = [];
  const errorList = [];
  for (const [k, v] of Object.entries(checks || {})) {
    if (!v || typeof v !== "object") continue;
    if (v.severity === "info") continue;
    if (v.severity === "warn") {
      warnList.push(k);
    } else if (v.ok === false) {
      errorList.push(k);
    }
  }
  return { warnList, errorList };
}

module.exports = { bucketChecks };
