"use strict";
/**
 * CI gate: diffs the public skill surface in manifest.json — name, version,
 * triggers, data_deps, ref arrays — against the committed manifest-snapshot.json.
 * Exit 0 when nothing broke (additive changes print and still pass), 1 on a
 * breaking change, 2 on a script-level error such as a missing baseline.
 */

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const ROOT = path.join(__dirname, "..");
const MANIFEST_PATH = path.join(ROOT, "manifest.json");
const SNAPSHOT_PATH = path.join(ROOT, "manifest-snapshot.json");

function captureSurface(manifest) {
  // Only what a consumer pins against: sha256, signature and signed_at change every commit.
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

// Absent and corrupt are different states and must not collapse into one.
//
// ABSENT (key not in the object) is the stale baseline this gate exists to
// report on: a snapshot committed before a surface field existed carries no key
// for it, and an absent field is an empty surface, not a crash. Reading it
// unguarded threw a TypeError that the CLI's outer catch turned into exit 2 with
// a stack trace instead of an additive-change report.
//
// PRESENT-BUT-NOT-AN-ARRAY (a string, an object, null) is corruption. Coercing
// it to [] would report every live entry as additive and exit 0 — a gate that
// passes without checking anything. It raises instead, and the outer catch turns
// that into exit 2 naming the skill and the field.
function asArray(value, skillName, field) {
  if (value === undefined) return [];
  if (Array.isArray(value)) return value;
  throw new Error(
    `${skillName}: ${field} is ${value === null ? "null" : typeof value}, not an array. ` +
    "The baseline or manifest is corrupt, not merely stale — regenerate the baseline " +
    "with `node scripts/refresh-manifest-snapshot.js` and re-check the manifest."
  );
}

// captureSurface() always writes `skills`, so unlike the per-field case above
// there is no legitimate historical baseline without it: absent and non-array
// are both corruption here, and treating either as [] would report every skill
// as added and exit 0.
function skillList(surface, which) {
  const skills = surface && surface.skills;
  if (Array.isArray(skills)) return skills;
  throw new Error(
    `${which}.skills is ${skills === null ? "null" : typeof skills}, not an array. ` +
    "Regenerate the baseline with `node scripts/refresh-manifest-snapshot.js`."
  );
}

function diff(baseline, current) {
  const breaking = [];
  const additive = [];

  const bSkills = new Map(skillList(baseline, "baseline").map(s => [s.name, s]));
  const cSkills = new Map(skillList(current, "current").map(s => [s.name, s]));

  for (const name of bSkills.keys()) {
    if (!cSkills.has(name)) {
      breaking.push(`removed skill: ${name}`);
    }
  }

  for (const name of cSkills.keys()) {
    if (!bSkills.has(name)) {
      additive.push(`added skill: ${name}`);
    }
  }

  for (const [name, b] of bSkills) {
    const c = cSkills.get(name);
    if (!c) continue;

    if (b.version && c.version && b.version !== c.version) {
      // Lexicographic, not semver: nothing upstream enforces a semver shape.
      if (c.version < b.version) {
        breaking.push(`${name}: version downgraded ${b.version} -> ${c.version}`);
      } else {
        additive.push(`${name}: version bumped ${b.version} -> ${c.version}`);
      }
    }

    // Removed trigger keywords break downstream skill matchers.
    const bTriggers = asArray(b.triggers, name, "baseline triggers");
    const cTriggers = asArray(c.triggers, name, "triggers");
    const removedTriggers = bTriggers.filter(t => !cTriggers.includes(t));
    if (removedTriggers.length > 0) {
      breaking.push(`${name}: removed trigger keywords: ${removedTriggers.join(", ")}`);
    }
    const addedTriggers = cTriggers.filter(t => !bTriggers.includes(t));
    if (addedTriggers.length > 0) {
      additive.push(`${name}: added trigger keywords: ${addedTriggers.join(", ")}`);
    }

    // Removed data deps break the skill at load time.
    const bDeps = asArray(b.data_deps, name, "baseline data_deps");
    const cDeps = asArray(c.data_deps, name, "data_deps");
    const removedDeps = bDeps.filter(d => !cDeps.includes(d));
    if (removedDeps.length > 0) {
      breaking.push(`${name}: removed data deps: ${removedDeps.join(", ")}`);
    }
    const addedDeps = cDeps.filter(d => !bDeps.includes(d));
    if (addedDeps.length > 0) {
      additive.push(`${name}: added data deps: ${addedDeps.join(", ")}`);
    }

    // Narrowing the cited surface is deliberate (AGENTS.md #4, #12), so removal is breaking.
    for (const field of ["atlas_refs", "attack_refs", "framework_gaps", "rfc_refs", "cwe_refs", "d3fend_refs", "dlp_refs"]) {
      const bRefs = asArray(b[field], name, `baseline ${field}`);
      const cRefs = asArray(c[field], name, field);
      const removed = bRefs.filter(r => !cRefs.includes(r));
      if (removed.length > 0) {
        breaking.push(`${name}: removed ${field}: ${removed.join(", ")}`);
      }
      const added = cRefs.filter(r => !bRefs.includes(r));
      if (added.length > 0) {
        additive.push(`${name}: added ${field}: ${added.join(", ")}`);
      }
    }
  }

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

/**
 * Verify the snapshot still hashes to its .sha256 sidecar. The surface diff
 * alone is defeated by editing manifest.json and the baseline in lockstep; the
 * sidecar pins the baseline's exact bytes so that pair no longer matches.
 */
function checkSnapshotIntegrity(root) {
  const snapshotPath = path.join(root, "manifest-snapshot.json");
  const shaPath = path.join(root, "manifest-snapshot.sha256");

  if (!fs.existsSync(snapshotPath)) {
    // Nothing to anchor against; the caller's baseline read reports this.
    return { ok: true, error: null };
  }

  if (!fs.existsSync(shaPath)) {
    return {
      ok: false,
      error:
        "manifest-snapshot.sha256 missing while manifest-snapshot.json is present — " +
        "the integrity sidecar that detects a hand-edited baseline is gone. " +
        "The two ship as a pair (package.json `files`) and refresh-manifest-snapshot.js " +
        "always writes both; an absent sidecar next to a present snapshot is the " +
        "integrity-evasion shape, not a benign state. " +
        "Re-run `node scripts/refresh-manifest-snapshot.js --commit-only` to regenerate it.",
    };
  }

  const expectedLine = fs.readFileSync(shaPath, "utf8").trim();
  const expectedSha = expectedLine.split(/\s+/)[0];
  const liveSha = crypto
    .createHash("sha256")
    .update(fs.readFileSync(snapshotPath))
    .digest("hex");
  if (expectedSha !== liveSha) {
    return {
      ok: false,
      error:
        `manifest-snapshot.json integrity check FAILED ` +
        `(expected ${expectedSha.slice(0, 12)}…, live ${liveSha.slice(0, 12)}…). ` +
        "Someone edited manifest-snapshot.json without running refresh-manifest-snapshot.js. " +
        "Re-run `node scripts/refresh-manifest-snapshot.js --commit-only` to regenerate.",
    };
  }

  return { ok: true, error: null };
}

module.exports = { captureSurface, diff, formatDiff, checkSnapshotIntegrity };

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

    // Before the diff: a tampered baseline must not be diffed as though trustworthy.
    const integrity = checkSnapshotIntegrity(ROOT);
    if (!integrity.ok) {
      console.error("[check-manifest-snapshot] " + integrity.error);
      process.exit(1);
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
