"use strict";

/**
 * Companion collector for the `sbom` playbook. Fingerprints the lockfiles in the
 * cwd (npm, yarn, pnpm, pip, cargo, go, ruby, composer) and counts components
 * per lockfile as a coarse SBOM-presence signal.
 *
 * Interface: see lib/collectors/README.md
 */

const fs = require("node:fs");
const path = require("node:path");
const { buildEvidenceLocations } = require("./scan-excludes");

const COLLECTOR_ID = "sbom";

// Each parser takes the file content and returns
// { component_count, top_level_count, lockfile_version } or { error }.
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
  // A manifest, not a lockfile: a pyproject-only project is still recognized.
  {
    file: "pyproject.toml",
    ecosystem: "python",
    parser: (content) => {
      // Line-based, not parsed: the collector contract is stdlib-only.
      const depBlocks = content.match(/^\[(?:project\.(?:dependencies|optional-dependencies)|tool\.poetry\.(?:dependencies|dev-dependencies|group\.[a-z0-9_-]+\.dependencies))[^\]]*\][\s\S]*?(?=^\[|$)/gm) || [];
      let count = 0;
      for (const block of depBlocks) {
        const lines = block.split(/\r?\n/).slice(1);
        for (const line of lines) {
          if (/^\s*[A-Za-z][A-Za-z0-9._\-]*\s*=/.test(line)) count++;
        }
      }
      // PEP 621 array style: `dependencies = [ "a", "b" ]` under [project].
      const arrMatch = content.match(/^\s*dependencies\s*=\s*\[([\s\S]*?)\]/m);
      if (arrMatch) {
        const entries = arrMatch[1].match(/"([^"]+)"|'([^']+)'/g) || [];
        count += entries.length;
      }
      return { component_count: count, top_level_count: count, lockfile_version: null };
    },
  },
];

// requirements*.txt variants; the canonical name is a LOCKFILES entry above.
const REQUIREMENTS_GLOB_RE = /^(?:[a-z0-9_-]+-)?requirements(?:-[a-z0-9_-]+)?\.txt$/i;
const REQUIREMENTS_LF = {
  ecosystem: "pip",
  parser: (content) => {
    const lines = content.split(/\r?\n/).filter(l => l && !l.startsWith("#") && !l.startsWith("-"));
    return { component_count: lines.length, top_level_count: lines.length, lockfile_version: null };
  },
};

// Probed one level deep and hand-listed so the walk stays bounded.
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
  for (const lf of LOCKFILES) {
    const p = path.join(cwd, lf.file);
    if (fs.existsSync(p)) {
      found.push(captureLockfile(p, lf.ecosystem, lf.parser, lf.file));
    }
  }
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

  for (const sub of SUBDIR_PROBE_PATHS) {
    const subDir = path.join(cwd, sub);
    let entries;
    try {
      if (!fs.statSync(subDir).isDirectory()) continue;
      entries = fs.readdirSync(subDir, { withFileTypes: true });
    } catch { continue; }
    for (const e of entries) {
      if (e.isDirectory()) {
        // packages/* gets one more level for monorepo workspaces, no deeper.
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
      // A canonical name wins, so `requirements.txt` cannot double-fire below.
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
    // Open once and fstat the descriptor rather than existsSync→statSync→read:
    // ENOENT still skips, and there is no TOCTOU window.
    try { fd = fs.openSync(p, "r"); }
    catch (e) { if (e.code === "ENOENT") continue; found.push({ file: s.file, format: s.format, error: e.message }); continue; }
    try {
      const stat = fs.fstatSync(fd);
      let content;
      // Read from the open descriptor, never by path again. readFileSync(fd) loops
      // to EOF; a single readSync can return short on a network or FUSE mount,
      // NUL-padding the buffer and truncating otherwise-valid JSON.
      try { content = fs.readFileSync(fd, "utf8"); } catch { content = null; }
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

  // sbom-tool-available: a lockfile or an SBOM document is a sufficient proxy.
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

  // lockfile-no-integrity is the one indicator decidable here: an npm
  // package-lock.json with entries carrying no `integrity`. The rest need catalog
  // cross-referencing, which the runner does against the artifacts above.
  const npmLockfile = lockfiles.find(l => l.file === "package-lock.json");
  const signal_overrides = {};
  if (npmLockfile && !npmLockfile.error) {
    try {
      const j = JSON.parse(fs.readFileSync(npmLockfile.path, "utf8"));
      let withIntegrity = 0;
      let withoutIntegrity = 0;
      // A local-path, workspace or git ref legitimately has no integrity hash, so
      // FP check [0] demotes those; a remote-registry tarball is the finding.
      let withoutIntegrityLocalOnly = true;
      const LOCAL_REF_RE = /^(?:file:|link:|workspace:|git\+ssh:|git\+https:|git:|github:|portal:)/i;
      const walk = (obj) => {
        if (!obj || typeof obj !== "object") return;
        // Only entries with a `resolved` URL are expected to carry `integrity`.
        // The npm 7+ root entry `"": { name, version }` has neither, so keying off
        // `version` false-positives. library-author.js guards the same way.
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
      // Any single integrity-less resolved entry fires it: the class, not coverage.
      if (withoutIntegrity > 0) {
        signal_overrides["lockfile-no-integrity"] = "hit";
        // __fp_checks attestation — [0]: an integrity-less entry is a remote
        // tarball, not only local, workspace or git refs. [1]: this is the root
        // lockfile the build consumes, not a stale archived copy.
        const att = {};
        if (!withoutIntegrityLocalOnly) att["0"] = true;
        const rel = (npmLockfile.path || "").replace(/\\/g, "/");
        if (!/\/(?:archive|pre-migration|old|backup|legacy)\//i.test(rel)) att["1"] = true;
        if (Object.keys(att).length) signal_overrides["lockfile-no-integrity__fp_checks"] = att;
      } else if (withIntegrity > 0) {
        signal_overrides["lockfile-no-integrity"] = "miss";
      }
      npmLockfile.integrity_present_count = withIntegrity;
      npmLockfile.integrity_missing_count = withoutIntegrity;
    } catch {
      // A malformed lockfile leaves the indicator unflipped: inconclusive, not miss.
    }
  }

  // File-level: the gap is spread across entries rather than sitting on one line.
  const evidence_locations = {};
  if (signal_overrides["lockfile-no-integrity"] === "hit" && npmLockfile) {
    const locs = buildEvidenceLocations([{ file: npmLockfile.file }]);
    if (locs.length) evidence_locations["lockfile-no-integrity"] = locs;
  }

  return {
    precondition_checks: {
      "sbom-tool-available": hasAnything,
      // Attested from what was collected: autoDetectPreconditions sees the run
      // process cwd, not the scanned --cwd, so this would warn as unverified.
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
