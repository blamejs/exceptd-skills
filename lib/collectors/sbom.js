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
];

const SBOM_FORMATS = [
  { file: "sbom.cdx.json", format: "cyclonedx-1.x" },
  { file: "bom.json", format: "cyclonedx-1.x" },
  { file: "sbom.json", format: "unknown" },
  { file: "sbom.spdx.json", format: "spdx-2.x" },
  { file: "sbom.cdx.xml", format: "cyclonedx-xml" },
];

function findLockfiles(cwd) {
  const found = [];
  for (const lf of LOCKFILES) {
    const p = path.join(cwd, lf.file);
    if (fs.existsSync(p)) {
      try {
        const content = fs.readFileSync(p, "utf8");
        const stats = lf.parser(content);
        found.push({
          file: lf.file,
          ecosystem: lf.ecosystem,
          path: p,
          size_bytes: Buffer.byteLength(content, "utf8"),
          ...stats,
        });
      } catch (e) {
        found.push({ file: lf.file, ecosystem: lf.ecosystem, path: p, error: e.message });
      }
    }
  }
  return found;
}

function findSbomDocuments(cwd) {
  const found = [];
  for (const s of SBOM_FORMATS) {
    const p = path.join(cwd, s.file);
    if (fs.existsSync(p)) {
      try {
        const stat = fs.statSync(p);
        let content;
        try { content = fs.readFileSync(p, "utf8"); } catch { content = null; }
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
      }
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

  const signal_overrides = {
    // Operator has a lockfile but no SBOM document → "missing
    // declarative SBOM" finding (sbom playbook's
    // sbom-document-absent indicator).
    "sbom-document-absent": (lockfiles.length > 0 && sbomDocuments.length === 0) ? "hit" : "miss",
    // No lockfile + no SBOM → not really a software project, indicator
    // returns inconclusive.
    "lockfile-absent": (lockfiles.length === 0) ? "hit" : "miss",
  };

  return {
    precondition_checks: {
      "sbom-tool-available": hasAnything,
    },
    artifacts,
    signal_overrides,
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
