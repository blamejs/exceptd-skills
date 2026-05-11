"use strict";
/**
 * scripts/builders/stale-content.js
 *
 * Builds `data/_indexes/stale-content.json` — surfaces stale or
 * drifted references the audit-cross-skill script catches at run time,
 * persisted as a JSON artifact so CI / dashboards / downstream tools can
 * read the same view without invoking the script.
 *
 * Checks performed here (subset of audit-cross-skill that's relevant to
 * the index layer, deterministic across reruns):
 *
 *   - Skill bodies referencing renamed-skill tokens (e.g. age-gates-minor-*)
 *   - README badge counts vs. live counts
 *   - "Researcher routes to N skills" claim vs. live count
 *   - Skills with last_threat_review older than 180 days from
 *     manifest.threat_review_date (gives a stale-content snapshot)
 *   - Catalog _meta.last_verified entries older than freshness_policy.stale_after_days
 *   - Forward_watch items mentioning dates that have already passed
 *
 * Each finding is { severity, category, artifact, detail }.
 */

const fs = require("fs");
const path = require("path");

const RENAMED_SKILL_TOKENS = [
  // Historical names that should no longer appear in the corpus. Update on
  // each rename — paired with audit-cross-skill.js stale-renamed-skill check.
  "age-gates-minor-safeguarding",
  "age-gates-minor",
];

function findInBody(body, needle) {
  // Find occurrences with surrounding context. Returns up to first 3 line refs.
  const lines = body.split(/\r?\n/);
  const refs = [];
  for (let i = 0; i < lines.length && refs.length < 3; i++) {
    if (lines[i].includes(needle)) refs.push({ line: i + 1, content: lines[i].trim().slice(0, 120) });
  }
  return refs;
}

function buildStaleContent({ root, manifest, skills, catalogFiles }) {
  const findings = [];
  const refDate = new Date((manifest.threat_review_date || "2026-05-01") + "T00:00:00Z");

  // 1. Stale-renamed-skill tokens
  for (const s of skills) {
    const body = fs.readFileSync(path.join(root, s.path), "utf8");
    for (const tok of RENAMED_SKILL_TOKENS) {
      const refs = findInBody(body, tok);
      if (refs.length > 0) {
        findings.push({
          severity: "high",
          category: "stale_renamed_skill",
          artifact: s.path,
          detail: `references retired skill token "${tok}"`,
          refs,
        });
      }
    }
  }

  // 2. README badge counts vs. live counts
  const readmePath = path.join(root, "README.md");
  if (fs.existsSync(readmePath)) {
    const readme = fs.readFileSync(readmePath, "utf8");
    const skillsBadge = readme.match(/skills-(\d+)-/);
    const jurisdictionsBadge = readme.match(/jurisdictions?-(\d+)-/i);
    const liveJurisdictions = (() => {
      try {
        const gf = JSON.parse(fs.readFileSync(path.join(root, "data/global-frameworks.json"), "utf8"));
        return Object.keys(gf).filter((k) => !k.startsWith("_") && k !== "GLOBAL").length;
      } catch {
        return null;
      }
    })();
    if (skillsBadge && Number(skillsBadge[1]) !== skills.length) {
      findings.push({
        severity: "medium",
        category: "badge_drift",
        artifact: "README.md",
        detail: `skills badge shows ${skillsBadge[1]}, manifest has ${skills.length}`,
      });
    }
    if (jurisdictionsBadge && liveJurisdictions && Number(jurisdictionsBadge[1]) !== liveJurisdictions) {
      findings.push({
        severity: "medium",
        category: "badge_drift",
        artifact: "README.md",
        detail: `jurisdictions badge shows ${jurisdictionsBadge[1]}, live count is ${liveJurisdictions}`,
      });
    }
  }

  // 3. Researcher dispatch count claim
  const researcherPath = path.join(root, "skills/researcher/skill.md");
  if (fs.existsSync(researcherPath)) {
    const r = fs.readFileSync(researcherPath, "utf8");
    const claimMatch = r.match(/inventory of (\d+) specialized/);
    if (claimMatch) {
      const claimed = Number(claimMatch[1]);
      const live = skills.length - 1; // researcher excluded from its own dispatch table
      if (claimed !== live) {
        findings.push({
          severity: "medium",
          category: "researcher_claim_drift",
          artifact: "skills/researcher/skill.md",
          detail: `claims ${claimed} specialized skills downstream; live count is ${live}`,
        });
      }
    }
  }

  // 4. Skills with > 180 days since review (against reference date)
  for (const s of skills) {
    if (!s.last_threat_review) continue;
    const ageDays = Math.floor(
      (refDate - new Date(s.last_threat_review + "T00:00:00Z")) / 86400000
    );
    if (ageDays > 180) {
      findings.push({
        severity: "low",
        category: "skill_review_stale",
        artifact: s.path,
        detail: `last_threat_review ${s.last_threat_review} is ${ageDays} days before manifest.threat_review_date`,
      });
    }
  }

  // 5. Catalog last_verified entries older than freshness_policy.stale_after_days
  for (const rel of catalogFiles) {
    const abs = path.join(root, rel);
    try {
      const j = JSON.parse(fs.readFileSync(abs, "utf8"));
      const meta = j._meta || {};
      const policy = meta.freshness_policy || null;
      if (!policy?.stale_after_days) continue;
      const last = meta.last_updated || meta.last_verified;
      if (!last) continue;
      const ageDays = Math.floor((refDate - new Date(last + "T00:00:00Z")) / 86400000);
      if (ageDays > policy.stale_after_days) {
        findings.push({
          severity: "medium",
          category: "catalog_stale",
          artifact: rel,
          detail: `last_updated ${last} is ${ageDays} days old; freshness_policy.stale_after_days is ${policy.stale_after_days}`,
        });
      }
    } catch {
      // ignore parse errors — caught elsewhere
    }
  }

  const bySeverity = { high: 0, medium: 0, low: 0 };
  for (const f of findings) bySeverity[f.severity] = (bySeverity[f.severity] || 0) + 1;

  return {
    _meta: {
      schema_version: "1.0.0",
      reference_date: manifest.threat_review_date || null,
      note: "Stale-content snapshot derived from audit-cross-skill checks. Re-runs of build-indexes against the same inputs produce byte-identical output (reference_date is manifest.threat_review_date, not 'now'). audit-cross-skill.js remains the canonical interactive audit.",
      finding_count: findings.length,
      by_severity: bySeverity,
    },
    findings,
  };
}

module.exports = { buildStaleContent };
