"use strict";

/**
 * tests/jurisdiction-clocks.test.js
 *
 * Behavioral coverage for scripts/builders/jurisdiction-clocks.js
 * (buildJurisdictionClocks) — flattens data/global-frameworks.json into a
 * jurisdiction × obligation × clock matrix (breach_notification / patch_sla),
 * computes per-jurisdiction fastest-* rollups, and emits cross-jurisdiction
 * sorted slices.
 *
 * Strategy: hand-craft a globalFrameworks fixture with known SLA numbers so the
 * flattening, the fastest-* selection, the GLOBAL/_meta exclusion, the
 * empty-jurisdiction drop, and the sort order are each asserted exactly; then
 * smoke against the live catalog for shape stability.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const { buildJurisdictionClocks } = require("../scripts/builders/jurisdiction-clocks.js");

const ROOT = path.join(__dirname, "..");

function fixture() {
  return {
    _meta: { schema_version: "x" }, // must be excluded from jurisdictions
    GLOBAL: { jurisdiction: "Global", frameworks: { ISO27001: { patch_sla: 9999 } } }, // excluded
    EU: {
      jurisdiction: "European Union",
      frameworks: {
        GDPR: {
          authority: "EDPB",
          source: "eur-lex",
          notification_sla: 72,
          notification_trigger: "personal data breach",
          patch_sla: null, // not a number -> no patch_sla entry
        },
        NIS2: {
          authority: "ENISA",
          notification_sla: 24, // faster than GDPR's 72
          notification_trigger: "significant incident",
          notification_stages: ["early warning 24h", "report 72h"],
          patch_sla: 48,
          patch_sla_note: "critical CVEs",
        },
      },
    },
    AU: {
      jurisdiction: "Australia",
      frameworks: {
        // Discretionary trigger, no numeric SLA -> breach_notification.hours null.
        PrivacyAct: { authority: "OAIC", notification_trigger: "eligible data breach" },
        Ess8: { authority: "ACSC", patch_sla: 48 },
      },
    },
    XX: {
      jurisdiction: "Empty Land",
      // No obligations at all -> jurisdiction must be dropped entirely.
      frameworks: { Nothing: { authority: "none" } },
    },
  };
}

test("module contract: exports buildJurisdictionClocks as a function", () => {
  assert.equal(typeof buildJurisdictionClocks, "function");
});

test("envelope shape + _meta jurisdiction_count matches by_jurisdiction size", () => {
  const out = buildJurisdictionClocks({ globalFrameworks: fixture() });
  assert.equal(out._meta.schema_version, "1.0.0");
  assert.equal(typeof out._meta.note, "string");
  assert.equal(out._meta.jurisdiction_count, Object.keys(out.by_jurisdiction).length);
  assert.ok(Array.isArray(out.sorted_by_breach_notification_hours));
  assert.ok(Array.isArray(out.sorted_by_patch_sla_hours));
});

test("GLOBAL and _meta are excluded; a jurisdiction with no obligations is dropped", () => {
  const out = buildJurisdictionClocks({ globalFrameworks: fixture() });
  const codes = Object.keys(out.by_jurisdiction);
  assert.ok(!codes.includes("GLOBAL"), "GLOBAL must be excluded");
  assert.ok(!codes.includes("_meta"), "_meta must be excluded");
  assert.ok(!codes.includes("XX"), "obligation-free jurisdiction must be dropped");
  assert.deepEqual(codes.sort(), ["AU", "EU"]);
});

test("breach_notification: numeric SLA carries hours; discretionary trigger yields null hours", () => {
  const out = buildJurisdictionClocks({ globalFrameworks: fixture() });
  const eu = out.by_jurisdiction.EU;
  assert.equal(eu.jurisdiction_name, "European Union");
  assert.equal(eu.frameworks.GDPR.breach_notification.hours, 72);
  assert.equal(eu.frameworks.GDPR.breach_notification.trigger, "personal data breach");
  // GDPR patch_sla was null -> no patch_sla entry on the framework.
  assert.equal("patch_sla" in eu.frameworks.GDPR, false);

  // AU PrivacyAct has a trigger but no numeric SLA -> hours null, still present.
  const au = out.by_jurisdiction.AU;
  assert.equal(au.frameworks.PrivacyAct.breach_notification.hours, null);
  assert.equal(au.frameworks.PrivacyAct.breach_notification.trigger, "eligible data breach");
});

test("notification_stages and authority are threaded through", () => {
  const out = buildJurisdictionClocks({ globalFrameworks: fixture() });
  const nis2 = out.by_jurisdiction.EU.frameworks.NIS2;
  assert.deepEqual(nis2.breach_notification.stages, ["early warning 24h", "report 72h"]);
  assert.equal(nis2.breach_notification.authority, "ENISA");
  assert.equal(nis2.authority, "ENISA");
  assert.equal(nis2.patch_sla.hours, 48);
  assert.equal(nis2.patch_sla.note, "critical CVEs");
});

test("fastest_breach_notification picks the lowest numeric SLA within a jurisdiction", () => {
  const out = buildJurisdictionClocks({ globalFrameworks: fixture() });
  // EU: GDPR 72 vs NIS2 24 -> 24 (NIS2) wins.
  assert.deepEqual(out.by_jurisdiction.EU.fastest_breach_notification, { hours: 24, framework: "NIS2" });
  // AU has no numeric notification SLA -> fastest_breach_notification null.
  assert.equal(out.by_jurisdiction.AU.fastest_breach_notification, null);
});

test("fastest_patch_sla picks the lowest patch SLA; absent -> null", () => {
  const out = buildJurisdictionClocks({ globalFrameworks: fixture() });
  // EU only NIS2 has a patch_sla (48).
  assert.deepEqual(out.by_jurisdiction.EU.fastest_patch_sla, { hours: 48, framework: "NIS2" });
  // AU only Ess8 has 48.
  assert.deepEqual(out.by_jurisdiction.AU.fastest_patch_sla, { hours: 48, framework: "Ess8" });
});

test("cross-jurisdiction slices are sorted ascending and exclude null-hour rows", () => {
  const out = buildJurisdictionClocks({ globalFrameworks: fixture() });
  const notif = out.sorted_by_breach_notification_hours;
  // Numeric notifs: NIS2 24, GDPR 72. AU PrivacyAct (null) excluded.
  assert.deepEqual(notif.map((n) => n.hours), [24, 72]);
  assert.equal(notif[0].framework, "NIS2");
  assert.ok(!notif.some((n) => n.hours == null), "null-hour rows must be excluded");

  const patch = out.sorted_by_patch_sla_hours;
  assert.deepEqual(patch.map((p) => p.hours), [48, 48]);
  for (let i = 1; i < patch.length; i++) {
    assert.ok(patch[i].hours >= patch[i - 1].hours, "patch slice must be ascending");
  }
});

test("zero-hour breach SLA is preserved (not coerced to null by a truthiness test)", () => {
  const gf = {
    ZZ: {
      jurisdiction: "Zeroland",
      frameworks: { Instant: { authority: "x", notification_sla: 0, notification_trigger: "any" } },
    },
  };
  const out = buildJurisdictionClocks({ globalFrameworks: gf });
  assert.equal(out.by_jurisdiction.ZZ.frameworks.Instant.breach_notification.hours, 0);
  assert.deepEqual(out.by_jurisdiction.ZZ.fastest_breach_notification, { hours: 0, framework: "Instant" });
  assert.deepEqual(out.sorted_by_breach_notification_hours.map((n) => n.hours), [0]);
});

test("empty input produces an empty matrix, not an error", () => {
  const out = buildJurisdictionClocks({ globalFrameworks: { _meta: {}, GLOBAL: {} } });
  assert.deepEqual(out.by_jurisdiction, {});
  assert.equal(out._meta.jurisdiction_count, 0);
  assert.deepEqual(out.sorted_by_breach_notification_hours, []);
  assert.deepEqual(out.sorted_by_patch_sla_hours, []);
});

test("smoke against live global-frameworks.json: every patch_sla.hours is numeric and slices sorted", () => {
  const gf = JSON.parse(fs.readFileSync(path.join(ROOT, "data", "global-frameworks.json"), "utf8"));
  const out = buildJurisdictionClocks({ globalFrameworks: gf });
  assert.ok(out._meta.jurisdiction_count > 0, "live catalog should yield at least one jurisdiction");
  for (const [code, j] of Object.entries(out.by_jurisdiction)) {
    assert.equal(typeof j.jurisdiction_name, "string");
    for (const [fwName, fw] of Object.entries(j.frameworks)) {
      if (fw.breach_notification) {
        assert.ok(
          fw.breach_notification.hours === null || typeof fw.breach_notification.hours === "number",
          `${code}/${fwName} breach hours must be number|null`
        );
      }
      if (fw.patch_sla) {
        assert.equal(typeof fw.patch_sla.hours, "number", `${code}/${fwName} patch hours must be number`);
      }
    }
  }
  for (let i = 1; i < out.sorted_by_breach_notification_hours.length; i++) {
    assert.ok(out.sorted_by_breach_notification_hours[i].hours >= out.sorted_by_breach_notification_hours[i - 1].hours);
  }
  for (let i = 1; i < out.sorted_by_patch_sla_hours.length; i++) {
    assert.ok(out.sorted_by_patch_sla_hours[i].hours >= out.sorted_by_patch_sla_hours[i - 1].hours);
  }
});
