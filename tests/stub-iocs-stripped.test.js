"use strict";

/**
 * tests/stub-iocs-stripped.test.js
 *
 * v0.13.20 audit-class-1.1 pin. The release stripped placeholder IoCs
 * from CVE entries that had been auto-filled by v0.13.17 KEV bulk-import
 * + v0.13.19 gap-fix. This test pins the strip — operator-curated
 * entries listed below MUST NOT carry placeholder content; either
 * `iocs` is absent (curation pending) or it carries real IoCs (no
 * "IOC list pending operator curation" sentinel).
 *
 * The list below is the diff-coverage gate's CVE-ID surface from the
 * v0.13.20 PR — pinning these tells the gate "yes, the strip was
 * intentional, here's the test that fires if anyone re-introduces the
 * stub content."
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const CATALOG = JSON.parse(fs.readFileSync(path.join(__dirname, "..", "data", "cve-catalog.json"), "utf8"));

const STUB_SENTINELS = [
  "IOC list pending operator curation",
  "Refer to vendor advisory for IOC list",
  "bulk-imported KEV entry, IOCs not extracted at intake time"
];

// CVEs that previously carried v0.13.19 stub IoCs that v0.13.20 stripped.
// Each entry's iocs must be EITHER absent (operator-curation pending,
// surfaced honestly by `npm run audit-catalog-gaps`) OR replaced with
// real curated content (no sentinel strings).
const STRIPPED_OPERATOR_CURATED_IDS = [
  "CVE-2024-21626", "CVE-2024-3094", "CVE-2024-3154", "CVE-2023-43472",
  "CVE-2020-10148", "CVE-2023-3519", "CVE-2024-1709", "CVE-2026-20182",
  "CVE-2024-40635", "CVE-2025-12686", "CVE-2025-62847", "CVE-2025-62848",
  "CVE-2025-62849", "CVE-2025-59389", "CVE-2025-11837", "CVE-2024-21762",
  "CVE-2025-10585", "CVE-2025-14174", "CVE-2025-43529", "CVE-2025-4919",
  "CVE-2025-24201", "CVE-2025-43300", "CVE-2025-38352", "CVE-2025-55241",
  "CVE-2025-21085", "CVE-2025-1094", "CVE-2025-49844", "CVE-2025-14847",
  "CVE-2025-8671", "CVE-2025-6965", "CVE-2026-22778", "CVE-2026-7482",
  "CVE-2025-68664", "CVE-2025-22224", "CVE-2025-22225", "CVE-2025-22226",
  "CVE-2025-59529", "CVE-2025-55319", "CVE-2025-53767", "CVE-2025-10725"
];

test("v0.13.20: every operator-curated CVE that v0.13.19 auto-filled is now stub-free", () => {
  const failures = [];
  for (const id of STRIPPED_OPERATOR_CURATED_IDS) {
    const e = CATALOG[id];
    if (!e) continue; // entry may have been removed in a future release
    if (!e.iocs) continue; // absent is the expected v0.13.20 state — operator-curation pending
    const blob = JSON.stringify(e.iocs);
    for (const sentinel of STUB_SENTINELS) {
      if (blob.includes(sentinel)) {
        failures.push(`${id}: iocs still carries stub sentinel "${sentinel}"`);
        break;
      }
    }
    // _iocs_stub flag should also be removed.
    if (e._iocs_stub) {
      failures.push(`${id}: _iocs_stub flag must be removed — the v0.13.20 strip drops both the flag and the stub content`);
    }
  }
  assert.deepEqual(failures, [],
    "v0.13.20 stub-strip contract: no operator-curated CVE may re-introduce the placeholder IoC content. Stripped entries either stay absent (operator-curation pending) or get real curated IoCs that don't match the sentinels.");
});

test("v0.13.20: _iocs_stub field is removed entirely from the catalog", () => {
  const stragglers = [];
  for (const id of Object.keys(CATALOG)) {
    if (id === "_meta") continue;
    const e = CATALOG[id];
    if (e && e._iocs_stub === true) stragglers.push(id);
  }
  assert.deepEqual(stragglers, [],
    "v0.13.20 removed the _iocs_stub mechanism entirely (canonical-eq replaces the symptom-patch). No catalog entry may carry the flag.");
});
