"use strict";
/**
 * scripts/builders/activity-feed.js
 *
 * Builds `data/_indexes/activity-feed.json` — a "what changed when" feed
 * across skills and catalogs, sorted by date. Lightweight RSS for the
 * skill corpus that consumers can poll without diff-ing the manifest.
 *
 * Combines:
 *   - per-skill last_threat_review
 *   - per-catalog _meta.last_updated
 *   - manifest threat_review_date + atlas_version_date when present
 *
 * Output sorted descending by date.
 */

const fs = require("fs");
const path = require("path");

function buildActivityFeed({ root, manifest, skills, catalogFiles }) {
  const events = [];

  for (const s of skills) {
    if (s.last_threat_review) {
      events.push({
        date: s.last_threat_review,
        type: "skill_review",
        artifact: s.name,
        path: s.path,
        note: s.description || null,
      });
    }
  }

  for (const f of catalogFiles) {
    const abs = path.join(root, f);
    try {
      const j = JSON.parse(fs.readFileSync(abs, "utf8"));
      const meta = j._meta || {};
      const when = meta.last_updated || meta.last_verified || null;
      if (when) {
        events.push({
          date: when,
          type: "catalog_update",
          artifact: f,
          path: f,
          schema_version: meta.schema_version || null,
          entry_count: Object.keys(j).filter((k) => !k.startsWith("_")).length,
        });
      }
    } catch {
      // skip non-JSON or malformed; build-indexes runs after lint so this
      // is unlikely.
    }
  }

  if (manifest.threat_review_date) {
    events.push({
      date: manifest.threat_review_date,
      type: "manifest_review",
      artifact: "manifest.json",
      path: "manifest.json",
      note: `manifest threat_review_date — ${manifest.skills.length} skills, ${catalogFiles.length} catalogs`,
    });
  }

  events.sort((a, b) => (b.date || "").localeCompare(a.date || ""));

  return {
    _meta: {
      schema_version: "1.0.0",
      note: "Per-artifact 'last changed' feed sorted descending by date. Skill events from manifest.last_threat_review; catalog events from data/<catalog>.json _meta.last_updated.",
      event_count: events.length,
    },
    events,
  };
}

module.exports = { buildActivityFeed };
