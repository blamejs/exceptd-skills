"use strict";

/**
 * lib/collectors/sbom.js
 *
 * Companion collector for the `sbom` playbook. Identifies the lockfile
 * fingerprint of the cwd (npm / yarn / pnpm / pip / cargo / go / ruby /
 * composer) so the runner can correlate against the SBOM-currency +
 * supply-chain integrity indicators. Counts components per lockfile
 * for a coarse SBOM-presence signal.
 *
 * Scope: any cwd with a recognizable lockfile. Multi-ecosystem repos
 * report every detected lockfile.
 *
 * Interface: see lib/collectors/README.md
 */

const fs = require("node:fs");
const path = require("node:path");
const { buildEvidenceLocations } = require("./scan-excludes");

const COLLECTOR_ID = "sbom";

// Lockfile fingerprints. Each entry: { file: <basename>, ecosystem,
// parser: <function(content) -> { component_count, top_level_count }> }.
const LOCKFILES = [
  {
    file: "package-lock.json",
    ecosystem: "npm",
    parser: (content) => {
      try {
        const j = JSON.parse(content);
        const components = j.packages ? Object.keys(j.packages).filter(k => k !== "").length
                          : (j.dependencies ? Object.keys(j.dependencies).length : 0);
        const topLevel = j.packages ? Object.keys(j.packages || {}).filter(k => /^node_modules\/[^/]+$/.test(k)).length
                          : (j.dependencies ? Object.keys(j.dependencies).length : 0);
        return { component_count: components, top_level_count: topLevel, lockfile_version: j.lockfileVersion };
      } catch (e) { return { error: e.message }; }
    },
  },
  {
    file: "yarn.lock",
    ecosystem: "yarn",
    parser: (content) => {
      // yarn.lock isn't JSON. Coarse count: each block starts with `"<spec>":` at column 0.
      const blocks = content.match(/^[^\s#].*:$/gm) || [];
      return { component_count: blocks.length, top_level_count: null, lockfile_version: null };
    },
  },
  {
    file: "pnpm-lock.yaml",
    ecosystem: "pnpm",
    parser: (content) => {
      const packages = (content.match(/^\s+\/[a-zA-Z0-9@_\-/.]+/gm) || []).length;
      return { component_count: packages, top_level_count: null, lockfile_version: null };
    },
  },
  {
    file: "requirements.txt",
    ecosystem: "pip",
    parser: (content) => {
      const lines = content.split(/\r?\n/).filter(l => l && !l.startsWith("#") && !l.startsWith("-"));
      return { component_count: lines.length, top_level_count: lines.length, lockfile_version: null };
    },
  },
  {
    file: "Pipfile.lock",
    ecosystem: "pipenv",
    parser: (content) => {
      try {
        const j = JSON.parse(content);
        const def = Object.keys(j.default || {}).length;
        const dev = Object.keys(j.develop || {}).length;
        return { component_count: def + dev, top_level_count: def, lockfile_version: j._meta?.["pipfile-spec"] };
      } catch (e) { return { error: e.message }; }
    },
  },
  {
    file: "poetry.lock",
    ecosystem: "poetry",
    parser: (content) => {
      const packages = (content.match(/^\[\[package\]\]/gm) || []).length;
      return { component_count: packages, top_level_count: null, lockfile_version: null };
    },
  },
  {
    file: "Cargo.lock",
    ecosystem: "cargo",
    parser: (content) => {
      const packages = (content.match(/^\[\[package\]\]/gm) || []).length;
      return { component_count: packages, top_level_count: null, lockfile_version: null };
    },
  },
  {
    file: "go.sum",
    ecosystem: "go",
    parser: (content) => {
      const modules = new Set(content.split(/\r?\n/).map(l => l.split(/\s+/)[0]).filter(Boolean));
      return { component_count: modules.size, top_level_count: null, lockfile_version: null };
    },
  },
  {
    file: "Gemfile.lock",
    ecosystem: "rubygems",
    parser: (content) => {
      const match = content.match(/GEM\s+remote:[\s\S]*?specs:([\s\S]*?)(?:\n\n|\nPLATFORMS)/);
      if (!match) return { component_count: 0, top_level_count: null, lockfile_version: null };
      const specs = match[1].split(/\r?\n/).filter(l => /^\s+[a-z0-9_-]+\s*\(/.test(l));
      return { component_count: specs.length, top_level_count: null, lockfile_version: null };
    },
  },
  {
    file: "composer.lock",
    ecosystem: "composer",
    parser: (content) => {
      try {
        const j = JSON.parse(content);
        return {
          component_count: (j.packages || []).length + (j["packages-dev"] || []).length,
          top_level_count: (j.packages || []).length,
          lockfile_version: j["content-hash"] ? "content-hash" : null,
        };
      } catch (e) { return { error: e.message }; }
    },
  },
  // Python dependency MANIFEST (not strictly a lockfile but the
  // canonical project file for modern Python projects). Counted as
  // a Python ecosystem dependency source so projects with only a
  // pyproject.toml + no requirements.txt are recognized.
  {
    file: "pyproject.toml",
    ecosystem: "python",
    parser: (content) => {
      // Count entries in [project.dependencies] / [project.optional-
      // dependencies.*] / [tool.poetry.dependencies] / [tool.poetry
      // .dev-dependencies]. Coarse line-based count — the TOML parser
      // would pull a dep into the stdlib-only contract.
      const depBlocks = content.match(/^\[(?:project\.(?:dependencies|optional-dependencies)|tool\.poetry\.(?:dependencies|dev-dependencies|group\.[a-z0-9_-]+\.dependencies))[^\]]*\][\s\S]*?(?=^\[|$)/gm) || [];
      let count = 0;
      for (const block of depBlocks) {
        // count "name = ..." lines (excluding the block header)
        const lines = block.split(/\r?\n/).slice(1);
        for (const line of lines) {
          if (/^\s*[A-Za-z][A-Za-z0-9._\-]*\s*=/.test(line)) count++;
        }
      }
      // Also handle the PEP 621 array-style:
      //   [project]
      //   dependencies = [ "a", "b", ... ]
      const arrMatch = content.match(/^\s*dependencies\s*=\s*\[([\s\S]*?)\]/m);
      if (arrMatch) {
        const entries = arrMatch[1].match(/"([^"]+)"|'([^']+)'/g) || [];
        count += entries.length;
      }
      return { component_count: count, top_level_count: count, lockfile_version: null };
    },
  },
];

// Python requirements*.txt glob. Variants include requirements-dev
// .txt, requirements-prod.txt, dev-requirements.txt. The
// requirements.txt entry above covers the canonical name; this
// glob extends coverage to the common variants.
const REQUIREMENTS_GLOB_RE = /^(?:[a-z0-9_-]+-)?requirements(?:-[a-z0-9_-]+)?\.txt$/i;
const REQUIREMENTS_LF = {
  ecosystem: "pip",
  parser: (content) => {
    const lines = content.split(/\r?\n/).filter(l => l && !l.startsWith("#") && !l.startsWith("-"));
    return { component_count: lines.length, top_level_count: lines.length, lockfile_version: null };
  },
};

// Subdirectory probe paths — one level deep, hand-listed to keep
// the walk bounded. Covers the common monorepo / docs-subdir / iac
// layouts: docs/ (requirements.txt for sphinx-style docs builds),
// packages/* (monorepo workspaces), backend/ + frontend/ +
// infra/ + iac/ (split-stack repos).
const SUBDIR_PROBE_PATHS = ["docs", "packages", "backend", "frontend", "infra", "iac", "src", "app"];

const SBOM_FORMATS = [
  { file: "sbom.cdx.json", format: "cyclonedx-1.x" },
  { file: "bom.json", format: "cyclonedx-1.x" },
  { file: "sbom.json", format: "unknown" },
  { file: "sbom.spdx.json", format: "spdx-2.x" },
  { file: "sbom.cdx.xml", format: "cyclonedx-xml" },
];

function captureLockfile(p, ecosystem, parser, label) {
  try {
    const content = fs.readFileSync(p, "utf8");
    const stats = parser(content);
    return {
      file: label,
      ecosystem,
      path: p,
      size_bytes: Buffer.byteLength(content, "utf8"),
      ...stats,
    };
  } catch (e) {
    return { file: label, ecosystem, path: p, error: e.message };
  }
}

function findLockfiles(cwd) {
  const found = [];
  // Canonical names at cwd root.
  for (const lf of LOCKFILES) {
    const p = path.join(cwd, lf.file);
    if (fs.existsSync(p)) {
      found.push(captureLockfile(p, lf.ecosystem, lf.parser, lf.file));
    }
  }
  // requirements*.txt glob at cwd root — covers requirements-dev.txt,
  // dev-requirements.txt, etc. The exact-name `requirements.txt`
  // already lands via LOCKFILES; skip it here.
  try {
    for (const entry of fs.readdirSync(cwd)) {
      if (entry === "requirements.txt") continue; // captured above
      if (REQUIREMENTS_GLOB_RE.test(entry)) {
        const p = path.join(cwd, entry);
        if (fs.statSync(p).isFile()) {
          found.push(captureLockfile(p, REQUIREMENTS_LF.ecosystem, REQUIREMENTS_LF.parser, entry));
        }
      }
    }
  } catch { /* swallow */ }

  // One-level subdirectory probe for canonical-name lockfiles. The
  // common pattern: docs/requirements.txt (sphinx builds),
  // packages/*/package.json (monorepo workspaces), backend/Gemfile
  // .lock (split-stack repos). Capped depth (1 level only) and
  // pre-listed subdirs to keep the walk bounded.
  for (const sub of SUBDIR_PROBE_PATHS) {
    const subDir = path.join(cwd, sub);
    let entries;
    try {
      if (!fs.statSync(subDir).isDirectory()) continue;
      entries = fs.readdirSync(subDir, { withFileTypes: true });
    } catch { continue; }
    for (const e of entries) {
      if (e.isDirectory()) {
        // For packages/* etc. — probe ONE level deeper for canonical
        // names. (Doesn't recurse further; monorepo workspaces are
        // the only common case.)
        if (sub === "packages") {
          for (const lf of LOCKFILES) {
            const p = path.join(subDir, e.name, lf.file);
            if (fs.existsSync(p)) {
              const rel = path.relative(cwd, p).replace(/\\/g, "/");
              found.push(captureLockfile(p, lf.ecosystem, lf.parser, rel));
            }
          }
        }
        continue;
      }
      if (!e.isFile()) continue;
      // Try canonical LOCKFILES name match first; if it matches, the
      // file is captured there. The requirements glob below catches
      // ONLY non-canonical names (e.g. requirements-dev.txt) so
      // exact `requirements.txt` doesn't double-fire.
      let captured = false;
      for (const lf of LOCKFILES) {
        if (e.name === lf.file) {
          const p = path.join(subDir, e.name);
          const rel = path.relative(cwd, p).replace(/\\/g, "/");
          found.push(captureLockfile(p, lf.ecosystem, lf.parser, rel));
          captured = true;
          break;
        }
      }
      if (!captured && REQUIREMENTS_GLOB_RE.test(e.name) && e.name !== "requirements.txt") {
        const p = path.join(subDir, e.name);
        const rel = path.relative(cwd, p).replace(/\\/g, "/");
        found.push(captureLockfile(p, REQUIREMENTS_LF.ecosystem, REQUIREMENTS_LF.parser, rel));
      }
    }
  }

  return found;
}

function findSbomDocuments(cwd) {
  const found = [];
  for (const s of SBOM_FORMATS) {
    const p = path.join(cwd, s.file);
    let fd;
    // Open once and fstat the descriptor instead of existsSync→statSync→read:
    // an absent file (ENOENT) is skipped just as the existsSync(false) path did,
    // but there is no TOCTOU window between the check, the size stat, and the read.
    try { fd = fs.openSync(p, "r"); }
    catch (e) { if (e.code === "ENOENT") continue; found.push({ file: s.file, format: s.format, error: e.message }); continue; }
    try {
      const stat = fs.fstatSync(fd);
      let content;
      try {
        const buf = Buffer.alloc(stat.size);
        fs.readSync(fd, buf, 0, stat.size, 0);
        content = buf.toString("utf8");
      } catch { content = null; }
      let component_count = null;
      if (content && s.format === "cyclonedx-1.x") {
        try {
          const j = JSON.parse(content);
          component_count = (j.components || []).length;
        } catch {}
      }
      found.push({ file: s.file, format: s.format, size_bytes: stat.size, component_count });
    } catch (e) {
      found.push({ file: s.file, format: s.format, error: e.message });
    } finally {
      if (fd !== undefined) { try { fs.closeSync(fd); } catch { /* non-fatal */ } }
    }
  }
  return found;
}

function collect({ cwd = process.cwd(), env = process.env, args = {} } = {}) {
  const errors = [];
  const startTime = Date.now();
  const root = path.resolve(cwd);

  // Precondition: sbom-tool-available — the runner / playbook treats
  // this as "an operator has SOME way to produce an SBOM". For the
  // collector, "we found a lockfile or an SBOM" is a sufficient proxy.
  const lockfiles = findLockfiles(root);
  const sbomDocuments = findSbomDocuments(root);
  const hasAnything = lockfiles.length > 0 || sbomDocuments.length > 0;

  const artifacts = {
    "lockfile-inventory": {
      value: lockfiles.length
        ? lockfiles.map(l => `${l.ecosystem}:${l.file} (${l.component_count ?? "?"} components${l.lockfile_version ? `, v${l.lockfile_version}` : ""})`).join("; ")
        : "no lockfile found",
      captured: true,
    },
    "sbom-document": {
      value: sbomDocuments.length
        ? sbomDocuments.map(s => `${s.format}:${s.file} (${s.size_bytes} bytes${s.component_count != null ? `, ${s.component_count} components` : ""})`).join("; ")
        : "no SBOM document at cwd root",
      captured: true,
    },
  };

  // The sbom playbook's detect indicators (package-matches-catalogued-cve,
  // lockfile-no-integrity, transitive-deps-incomplete-sbom,
  // matched-cve-without-vex, ai-code-no-provenance, ...) require
  // catalog cross-referencing the collector does not have — that's
  // the runner's job. The collector's role here is to surface the
  // artifacts (lockfile-inventory + sbom-document) and let the
  // runner evaluate the indicators against them. Emitting
  // signal_overrides for keys that don't exist in the playbook
  // would be silently ignored; surfacing the artifacts honestly
  // is the contract.
  //
  // One indicator the collector CAN decide deterministically:
  // lockfile-no-integrity — true when an npm package-lock.json
  // exists but has zero `integrity` entries (lockfileVersion 1
  // legacy) OR when the dependency list contains entries lacking
  // `integrity` strings.
  const npmLockfile = lockfiles.find(l => l.file === "package-lock.json");
  const signal_overrides = {};
  if (npmLockfile && !npmLockfile.error) {
    try {
      const j = JSON.parse(fs.readFileSync(npmLockfile.path, "utf8"));
      let withIntegrity = 0;
      let withoutIntegrity = 0;
      // Track whether any integrity-less entry is a local-path / workspace /
      // git ref. lockfile-no-integrity FP[0] demotes those — they legitimately
      // have no registry integrity hash. A remote-registry tarball without
      // integrity is the genuine finding.
      let withoutIntegrityLocalOnly = true;
      const LOCAL_REF_RE = /^(?:file:|link:|workspace:|git\+ssh:|git\+https:|git:|github:|portal:)/i;
      const walk = (obj) => {
        if (!obj || typeof obj !== "object") return;
        // Only remote-tarball entries (those with a `resolved` URL) are
        // expected to carry an `integrity` hash. The npm 7+ root entry
        // `"": { name, version }` legitimately has no `resolved` and no
        // `integrity`, so keying off `version` would false-positive on
        // every clean lockfile. Mirror library-author.js's guard.
        if (obj.resolved != null) {
          if (obj.integrity != null) {
            withIntegrity++;
          } else {
            withoutIntegrity++;
            if (!LOCAL_REF_RE.test(String(obj.resolved))) withoutIntegrityLocalOnly = false;
          }
        }
        for (const v of Object.values(obj)) if (v && typeof v === "object") walk(v);
      };
      walk(j.packages || j.dependencies || {});
      // Fire only if integrity is missing on ANY package entry that
      // resolves to a remote tarball — the indicator captures the
      // class, not full coverage.
      if (withoutIntegrity > 0) {
        signal_overrides["lockfile-no-integrity"] = "hit";
        // __fp_checks attestation. [0]: at least one integrity-less entry is a
        // remote-registry tarball (not exclusively local-path/workspace/git
        // refs). [1]: the lockfile is the canonical root package-lock.json the
        // build consumes, not a stale copy under archive/ pre-migration/.
        const att = {};
        if (!withoutIntegrityLocalOnly) att["0"] = true;
        const rel = (npmLockfile.path || "").replace(/\\/g, "/");
        if (!/\/(?:archive|pre-migration|old|backup|legacy)\//i.test(rel)) att["1"] = true;
        if (Object.keys(att).length) signal_overrides["lockfile-no-integrity__fp_checks"] = att;
      } else if (withIntegrity > 0) {
        signal_overrides["lockfile-no-integrity"] = "miss";
      }
      // Stash diagnostic counts on collector_meta further below.
      npmLockfile.integrity_present_count = withIntegrity;
      npmLockfile.integrity_missing_count = withoutIntegrity;
    } catch {
      // Malformed lockfile — leave the indicator unflipped so the
      // runner returns inconclusive rather than a forced miss.
    }
  }

  // Per-indicator file location for the one deterministically-decided
  // indicator: a lockfile-no-integrity hit points at the npm lockfile that
  // carries integrity-less entries. File-level (the gap is spread across
  // many entries, not one line).
  const evidence_locations = {};
  if (signal_overrides["lockfile-no-integrity"] === "hit" && npmLockfile) {
    const locs = buildEvidenceLocations([{ file: npmLockfile.file }]);
    if (locs.length) evidence_locations["lockfile-no-integrity"] = locs;
  }

  return {
    precondition_checks: {
      "sbom-tool-available": hasAnything,
      // Auto-attest the playbook's any-package-manager-present gate from what
      // we actually collected: the runner's autoDetectPreconditions can't probe
      // the scanned --cwd (it sees the run process cwd, not the collected repo),
      // so a lockfile we found here would otherwise surface a spurious
      // precondition_unverified warning on a repo that clearly has one.
      "any-package-manager-present": lockfiles.length > 0,
    },
    artifacts,
    signal_overrides,
    ...(Object.keys(evidence_locations).length ? { evidence_locations } : {}),
    collector_meta: {
      collector_id: COLLECTOR_ID,
      collector_version: "2026-05-20",
      platform: process.platform,
      captured_at: new Date().toISOString(),
      cwd: root,
      duration_ms: Date.now() - startTime,
      lockfiles_found: lockfiles.length,
      sbom_documents_found: sbomDocuments.length,
      ecosystems_detected: [...new Set(lockfiles.map(l => l.ecosystem))],
    },
    collector_errors: errors,
  };
}

module.exports = { playbook_id: COLLECTOR_ID, collect };
