"use strict";

/**
 * lib/doctor-bucketing.js
 *
 * Pure function used by the `exceptd doctor` verb to bucket per-check
 * results into "errors" vs "warnings" lists.
 *
 * v0.13.11 — extracted from bin/exceptd.js so the bucketing rule is
 * testable in isolation. The bug it fixes: severity governs bucketing,
 * not the `ok` field alone. A check that sets `ok: false` with
 * `severity: "warn"` (the signing-status check on a non-contributor
 * install — a nudge that the operator can enable signing if they want,
 * not a release-blocker) was previously routed to `failed_checks` and
 * tripped `all_green: false` with `issues_count: 1`, contradicting the
 * `[!! warn]` icon shown in the human-readable text mode. The fix:
 * `severity === "warn"` always wins, regardless of `ok`.
 */

function bucketChecks(checks) {
  const warnList = [];
  const errorList = [];
  for (const [k, v] of Object.entries(checks || {})) {
    if (!v || typeof v !== "object") continue;
    // v0.13.13: severity:info is informational only — never routes to
    // either bucket regardless of `ok`. Lets a check report ok:false +
    // severity:info to mean "this surface is intentionally not enabled
    // here, not a problem" (consumer install with no private key, an
    // air-gap probe deliberately skipped, etc.) without polluting
    // warning or failure counts.
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
