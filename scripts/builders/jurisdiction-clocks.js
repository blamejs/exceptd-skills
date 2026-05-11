"use strict";
/**
 * scripts/builders/jurisdiction-clocks.js
 *
 * Builds `data/_indexes/jurisdiction-clocks.json` — the normalized
 * jurisdiction × obligation × clock matrix. Today consumers asking
 * "what's the breach-notification clock in jurisdiction X?" have to
 * scan `data/global-frameworks.json` and pull `notification_sla` off
 * specific framework entries. This index flattens the dimension.
 *
 * Obligation types covered:
 *   - breach_notification (hours from awareness)
 *   - patch_sla            (hours from disclosure for Critical/High)
 *   - incident_reporting   (regulator + clock + trigger)
 *
 * Per-jurisdiction shape:
 *   {
 *     jurisdiction_name:
 *     frameworks: {
 *       <fwName>: {
 *         authority,
 *         breach_notification: { hours, trigger, stages?, source }
 *         patch_sla: { hours, note?, source }
 *         incident_reporting: { hours, trigger, source }
 *       }
 *     }
 *     fastest_breach_notification: { hours, framework }   // null when none specified
 *     fastest_patch_sla:           { hours, framework }
 *   }
 */

function buildJurisdictionClocks({ globalFrameworks }) {
  const out = {};
  const jurisdictionCodes = Object.keys(globalFrameworks).filter(
    (k) => !k.startsWith("_") && k !== "GLOBAL"
  );

  for (const code of jurisdictionCodes) {
    const j = globalFrameworks[code];
    const frameworks = j.frameworks || {};
    const flat = {};
    let fastestNotif = null;
    let fastestPatch = null;

    for (const [fwName, fw] of Object.entries(frameworks)) {
      const entry = {};
      if (typeof fw.notification_sla === "number" || fw.notification_trigger) {
        entry.breach_notification = {
          hours: typeof fw.notification_sla === "number" ? fw.notification_sla : null,
          trigger: fw.notification_trigger || null,
          stages: fw.notification_stages || null,
          source: fw.source || null,
          authority: fw.authority || null,
        };
        if (typeof fw.notification_sla === "number") {
          if (!fastestNotif || fw.notification_sla < fastestNotif.hours) {
            fastestNotif = { hours: fw.notification_sla, framework: fwName };
          }
        }
      }
      if (typeof fw.patch_sla === "number") {
        entry.patch_sla = {
          hours: fw.patch_sla,
          note: fw.patch_sla_note || null,
          source: fw.source || null,
          authority: fw.authority || null,
        };
        if (!fastestPatch || fw.patch_sla < fastestPatch.hours) {
          fastestPatch = { hours: fw.patch_sla, framework: fwName };
        }
      }
      if (Object.keys(entry).length > 0) {
        entry.authority = fw.authority || null;
        flat[fwName] = entry;
      }
    }

    if (Object.keys(flat).length === 0) continue;

    out[code] = {
      jurisdiction_name: j.jurisdiction || code,
      frameworks: flat,
      fastest_breach_notification: fastestNotif,
      fastest_patch_sla: fastestPatch,
    };
  }

  // Cross-jurisdiction summary slices for quick consumer lookups.
  const allNotifs = [];
  const allPatch = [];
  for (const [code, j] of Object.entries(out)) {
    for (const [fwName, fw] of Object.entries(j.frameworks)) {
      if (fw.breach_notification?.hours != null) {
        allNotifs.push({
          jurisdiction: code,
          framework: fwName,
          hours: fw.breach_notification.hours,
          trigger: fw.breach_notification.trigger,
        });
      }
      if (fw.patch_sla?.hours != null) {
        allPatch.push({
          jurisdiction: code,
          framework: fwName,
          hours: fw.patch_sla.hours,
          note: fw.patch_sla.note,
        });
      }
    }
  }
  allNotifs.sort((a, b) => a.hours - b.hours);
  allPatch.sort((a, b) => a.hours - b.hours);

  return {
    _meta: {
      schema_version: "1.0.0",
      note: "Normalized obligation matrix derived from data/global-frameworks.json. All times in hours. breach_notification.hours is null for jurisdictions that require notification only on a discretionary trigger.",
      jurisdiction_count: Object.keys(out).length,
    },
    by_jurisdiction: out,
    sorted_by_breach_notification_hours: allNotifs,
    sorted_by_patch_sla_hours: allPatch,
  };
}

module.exports = { buildJurisdictionClocks };
