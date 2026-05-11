"use strict";
/**
 * scripts/check-manifest-snapshot.js
 *
 * CI gate. Captures the current public skill surface (skill name +
 * version + triggers + data_deps + atlas_refs + attack_refs +
 * framework_gaps) from manifest.json and compares it to the committed
 * manifest-snapshot.json baseline.
 *
 * The skill surface is the public contract this repo offers downstream
 * AI assistants: skill names that downstream prompts may reference,
 * trigger keywords that downstream skill-matchers index on, and the
 * data files that skills rely on. Removing a skill or trigger keyword
 * silently breaks every consumer that pinned that surface.
 *
 * Exit codes:
 *   0  — no breaking changes (additive changes printed but not failing)
 *   1  — breaking changes detected
 *   2  — script-level error (missing baseline, IO failure, etc.)
 *
 * Operators see this gate in SECURITY.md / CONTRIBUTING.md as a CI
 * promise: "removed skills, removed triggers, or removed data deps fail
 * the build before they reach main."
 *
 * Usage:
 *   node scripts/check-manifest-snapshot.js
 *
 * Regenerate the baseline after an intentional removal:
 *   node scripts/refresh-manifest-snapshot.js
 *   git add manifest-snapshot.json && git commit
 */

const fs = require("fs");
const path = require("path");

const ROOT = path.join(__dirname, "..");
const MANIFEST_PATH = path.join(ROOT, "manifest.json");
const SNAPSHOT_PATH = path.join(ROOT, "manifest-snapshot.json");

function captureSurface(manifest) {
  // Public surface = the set of facts downstream consumers may have
  // pinned against. NOT included: sha256 / signature / signed_at —
  // those change every commit and are not a public contract.
  const skills = (manifest.skills || []).map(s => ({
    name: s.name,
    version: s.version || null,
    triggers: [...(s.triggers || [])].sort(),
    data_deps: [...(s.data_deps || [])].sort(),
    atlas_refs: [...(s.atlas_refs || [])].sort(),
    attack_refs: [...(s.attack_refs || [])].sort(),
    framework_gaps: [...(s.framework_gaps || [])].sort(),
    rfc_refs: [...(s.rfc_refs || [])].sort(),
    cwe_refs: [...(s.cwe_refs || [])].sort(),
    d3fend_refs: [...(s.d3fend_refs || [])].sort(),
    dlp_refs: [...(s.dlp_refs || [])].sort(),
  })).sort((a, b) => a.name.localeCompare(b.name));

  return {
    atlas_version: manifest.atlas_version || null,
    skill_count: skills.length,
    skills,
  };
}

function diff(baseline, current) {
  const breaking = [];
  const additive = [];

  const bSkills = new Map(baseline.skills.map(s => [s.name, s]));
  const cSkills = new Map(current.skills.map(s => [s.name, s]));

  // Removed skills are breaking.
  for (const name of bSkills.keys()) {
    if (!cSkills.has(name)) {
      breaking.push(`removed skill: ${name}`);
    }
  }

  // Added skills are additive.
  for (const name of cSkills.keys()) {
    if (!bSkills.has(name)) {
      additive.push(`added skill: ${name}`);
    }
  }

  // For each skill present in both, diff the pinned facts.
  for (const [name, b] of bSkills) {
    const c = cSkills.get(name);
    if (!c) continue;

    // version downgrades are breaking; bumps are additive.
    if (b.version && c.version && b.version !== c.version) {
      // Use a simple lexicographic compare — semver isn't enforced
      // upstream and the manifest version field is informational. The
      // operator should bump, not unbump.
      if (c.version < b.version) {
        breaking.push(`${name}: version downgraded ${b.version} -> ${c.version}`);
      } else {
        additive.push(`${name}: version bumped ${b.version} -> ${c.version}`);
      }
    }

    // Removed trigger keywords break downstream skill matchers.
    const removedTriggers = b.triggers.filter(t => !c.triggers.includes(t));
    if (removedTriggers.length > 0) {
      breaking.push(`${name}: removed trigger keywords: ${removedTriggers.join(", ")}`);
    }
    const addedTriggers = c.triggers.filter(t => !b.triggers.includes(t));
    if (addedTriggers.length > 0) {
      additive.push(`${name}: added trigger keywords: ${addedTriggers.join(", ")}`);
    }

    // Removed data deps break the skill at load time. Additions are fine.
    const removedDeps = b.data_deps.filter(d => !c.data_deps.includes(d));
    if (removedDeps.length > 0) {
      breaking.push(`${name}: removed data deps: ${removedDeps.join(", ")}`);
    }
    const addedDeps = c.data_deps.filter(d => !b.data_deps.includes(d));
    if (addedDeps.length > 0) {
      additive.push(`${name}: added data deps: ${addedDeps.join(", ")}`);
    }

    // Removed ATLAS/ATT&CK/framework refs are surface narrowing.
    // Per AGENTS.md rule #4 (no orphaned controls) and #12 (external
    // data version pinning), narrowing the cited surface is a
    // deliberate decision worth surfacing in CI. Treat as breaking;
    // the operator can refresh the baseline alongside the intent.
    for (const field of ["atlas_refs", "attack_refs", "framework_gaps", "rfc_refs", "cwe_refs", "d3fend_refs", "dlp_refs"]) {
      const removed = b[field].filter(r => !c[field].includes(r));
      if (removed.length > 0) {
        breaking.push(`${name}: removed ${field}: ${removed.join(", ")}`);
      }
      const added = c[field].filter(r => !b[field].includes(r));
      if (added.length > 0) {
        additive.push(`${name}: added ${field}: ${added.join(", ")}`);
      }
    }
  }

  // ATLAS pinned-version change is breaking per AGENTS.md rule #12
  // (never silently inherit version changes). The operator must update
  // the baseline alongside the audit of TTP ID changes.
  if (baseline.atlas_version && current.atlas_version &&
      baseline.atlas_version !== current.atlas_version) {
    breaking.push(
      `atlas_version changed ${baseline.atlas_version} -> ${current.atlas_version} ` +
      `(per AGENTS.md rule #12, audit TTP IDs and refresh baseline together)`
    );
  }

  return { breaking, additive };
}

function formatDiff(result) {
  const lines = [];
  if (result.breaking.length === 0 && result.additive.length === 0) {
    lines.push("[check-manifest-snapshot] surface unchanged.");
    return lines.join("\n");
  }

  if (result.breaking.length > 0) {
    lines.push(`[check-manifest-snapshot] ${result.breaking.length} breaking change(s):`);
    for (const b of result.breaking) lines.push(`  ! ${b}`);
  }
  if (result.additive.length > 0) {
    lines.push(`[check-manifest-snapshot] ${result.additive.length} additive change(s):`);
    for (const a of result.additive) lines.push(`  + ${a}`);
  }
  return lines.join("\n");
}

module.exports = { captureSurface, diff, formatDiff };

if (require.main === module) {
  try {
    let baseline;
    try {
      baseline = JSON.parse(fs.readFileSync(SNAPSHOT_PATH, "utf8"));
    } catch (e) {
      console.error(
        "[check-manifest-snapshot] baseline missing or unreadable: " +
        ((e && e.message) || String(e))
      );
      console.error(
        "[check-manifest-snapshot] generate one with " +
        "`node scripts/refresh-manifest-snapshot.js` and commit it."
      );
      process.exit(2);
    }

    const manifest = JSON.parse(fs.readFileSync(MANIFEST_PATH, "utf8"));
    const current = captureSurface(manifest);
    const result = diff(baseline, current);

    console.log(formatDiff(result));

    if (result.breaking.length > 0) {
      console.error(
        "[check-manifest-snapshot] BREAKING changes detected. If intentional, " +
        "regenerate the baseline with `node scripts/refresh-manifest-snapshot.js` " +
        "and commit it alongside the change."
      );
      process.exit(1);
    }

    if (result.additive.length > 0) {
      console.log(
        "[check-manifest-snapshot] additive changes only — refresh the baseline " +
        "(`node scripts/refresh-manifest-snapshot.js`) so the new surface is tracked."
      );
    }
    process.exit(0);
  } catch (e) {
    console.error("[check-manifest-snapshot] error: " + ((e && e.stack) || e));
    process.exit(2);
  }
}
