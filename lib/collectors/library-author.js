"use strict";

/**
 * lib/collectors/library-author.js
 *
 * Companion collector for the `library-author` playbook. Audits a
 * publisher-side repository for supply-chain posture markers:
 * SECURITY.md / security.txt presence, sbom + signature pair,
 * publish-workflow shape (id-token write, action-ref pinning, frozen
 * install), package.json provenance opt-in, vendor-tree provenance,
 * lockfile integrity.
 *
 * Skipped indicators (require external API or runtime data, left
 * unflipped so the runner returns inconclusive rather than a forced
 * miss):
 *
 *   tag-protection-absent           GitHub branch-protection API
 *   private-vuln-reporting-disabled GitHub repo-settings API
 *   no-rekor-entry-for-latest-release  sigstore lookup
 *   release-tag-not-signed          git tag --verify on each release
 *   release-signed-with-personal-gpg-key  GPG identity policy
 *   sbom-regenerated-at-request-time     timing-based; needs build
 *                                        pipeline trace
 *   skill-signing-but-verification-not-gated  project-internal CI
 *                                              gate inspection
 *   ssdf-claimed-cra-not-ready      operator interview shape
 *   gha-workflow-script-injection-sink  complex pattern; future pass
 *
 * Interface: see lib/collectors/README.md
 */

const fs = require("node:fs");
const path = require("node:path");

const COLLECTOR_ID = "library-author";

const DEFAULT_MAX_DEPTH = 6;
const DEFAULT_EXCLUDES = new Set([
  "node_modules", ".git", "dist", "build", "out",
  ".venv", "venv", "__pycache__", ".pytest_cache",
  "target", ".idea", ".vscode",
]);

function readSafe(full, max = 512 * 1024) {
  try {
    const s = fs.statSync(full);
    if (s.size > max) return null;
    return fs.readFileSync(full, "utf8");
  } catch { return null; }
}

function walkWorkflows(root) {
  const dir = path.join(root, ".github", "workflows");
  if (!fs.existsSync(dir)) return [];
  const out = [];
  let entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); }
  catch { return []; }
  for (const e of entries) {
    if (!e.isFile()) continue;
    if (!/\.(ya?ml)$/i.test(e.name)) continue;
    const full = path.join(dir, e.name);
    out.push({ full, name: e.name, rel: path.relative(root, full) });
  }
  return out;
}

function looksLikePublishWorkflow(name, content) {
  // Heuristic: filename starts with a publish-prefix, OR the body
  // invokes a publish command. Conservative — broad signals like
  // `id-token: write`, bare `sigstore/cosign-installer`, or `cosign
  // sign-blob` (commonly used in test workflows) DO NOT count; they
  // produced false positives on verification + e2e workflows that
  // happen to share signing infrastructure.
  const lower = name.toLowerCase();

  // Verification / test / e2e workflows are never publish, regardless
  // of body content. Hard demotion.
  if (/^(test|verify|validate|e2e|kind|check|conformance|coverage)/.test(lower)) return false;

  // Filename prefix signals: only the canonical publish words.
  if (/^(release|publish|deploy|promote|tag-and-release)/.test(lower)) return true;

  // Explicit publish-shape commands — these are commitments to push
  // artifacts, not setup / scaffolding.
  if (/\bnpm\s+publish\b/.test(content)) return true;
  if (/pypa\/gh-action-pypi-publish/.test(content)) return true;
  if (/\bcargo\s+publish\b/.test(content)) return true;
  if (/goreleaser/.test(content)) return true;
  if (/softprops\/action-gh-release/.test(content)) return true;
  // `ko build` builds AND pushes container images by default (unless
  // --push=false). All four sub-commands push to a registry.
  if (/\bko\s+(?:publish|build|apply|resolve)\b/.test(content)) return true;
  // `cosign sign` (container signing — publish-shape). Exclude
  // `cosign sign-blob` which signs arbitrary artifacts and shows
  // up in verification / e2e tests as often as in publishes.
  if (/\bcosign\s+sign\b(?!-)/.test(content)) return true;
  if (/\bcrane\s+(?:push|copy|append)\b/.test(content)) return true;
  if (/\boras\s+(?:push|copy)\b/.test(content)) return true;
  if (/docker\/build-push-action/.test(content)) return true;
  if (/\bdocker\s+push\b/.test(content)) return true;

  // Registry login actions — when a workflow logs into a registry,
  // it's almost certainly publishing. Picks up Makefile / opaque
  // publish paths (cosign's build.yaml uses make sign-ci-containers
  // after docker/login-action). Does NOT match verification tests
  // because those don't authenticate to a registry.
  if (/docker\/login-action/.test(content)) return true;
  if (/google-github-actions\/auth/.test(content) && /gcloud auth configure-docker/.test(content)) return true;
  if (/aws-actions\/configure-aws-credentials/.test(content) && /amazon-ecr/.test(content)) return true;

  return false;
}

function scanPublishWorkflow(content, rel) {
  const hits = {
    "publish-workflow-uses-static-token": [],
    "publish-workflow-no-id-token-write": [],
    "publish-workflow-action-refs-mutable": [],
    "release-workflow-non-frozen-install": [],
    "publish-workflow-runs-on-self-hosted": [],
  };

  // static-token: workflow references a publish-credential secret
  // without a corresponding `permissions: id-token: write`. The
  // predicate (per data/playbooks/library-author.json) lists
  // NPM_TOKEN / PYPI_TOKEN / CARGO_TOKEN / RUBYGEMS_API_KEY /
  // GEM_HOST_API_KEY; expand to cover the common variants for each
  // ecosystem.
  const usesStaticToken = /\bsecrets\.(NPM_TOKEN|PYPI_TOKEN|PYPI_API_TOKEN|CARGO_TOKEN|CARGO_REGISTRY_TOKEN|RUBYGEMS_API_KEY|GEM_HOST_API_KEY|MAVEN_TOKEN|MAVEN_CENTRAL_TOKEN|GH_TOKEN)\b/.test(content);
  const hasIdTokenWrite = /\bid-token:\s*write\b/.test(content);
  if (usesStaticToken && !hasIdTokenWrite) {
    hits["publish-workflow-uses-static-token"].push({ file: rel, line: 0, snippet: "publish workflow uses a static long-lived token (NPM_TOKEN / PYPI / Cargo / Maven) without id-token: write for OIDC" });
  }
  if (!hasIdTokenWrite) {
    hits["publish-workflow-no-id-token-write"].push({ file: rel, line: 0, snippet: "permissions block lacks id-token: write — npm provenance / sigstore signing unavailable" });
  }

  // action-refs-mutable: any `uses: <action>@<ref>` where ref is NOT
  // a 40-char hex sha. Excludes `uses: ./local-action`.
  const lines = content.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    // Allow optional leading `-` from a YAML list item: `- uses: ...`.
    const m = line.match(/^\s*-?\s*uses:\s*['"]?([^'"\s]+)['"]?\s*$/);
    if (!m) continue;
    const ref = m[1];
    if (ref.startsWith("./") || ref.startsWith("./.github/")) continue; // local
    const atIdx = ref.lastIndexOf("@");
    if (atIdx === -1) continue;
    const rev = ref.slice(atIdx + 1);
    if (!/^[0-9a-f]{40}$/i.test(rev)) {
      hits["publish-workflow-action-refs-mutable"].push({ file: rel, line: i + 1, snippet: line.trim() });
    }
  }

  // non-frozen-install: workflow uses `npm install` instead of `npm ci`,
  // or `pip install <pkg>` without `--require-hashes`, or `cargo
  // install` without `--locked`.
  if (/\bnpm\s+install\b/.test(content) && !/\bnpm\s+ci\b/.test(content)) {
    hits["release-workflow-non-frozen-install"].push({ file: rel, line: 0, snippet: "publish workflow uses `npm install` rather than `npm ci` — lockfile is not enforced" });
  }
  if (/\bcargo\s+(?:build|install)\b/.test(content) && !/--locked\b/.test(content) && !/--frozen\b/.test(content)) {
    hits["release-workflow-non-frozen-install"].push({ file: rel, line: 0, snippet: "cargo build/install without --locked / --frozen" });
  }

  // runs-on-self-hosted: any `runs-on: self-hosted` line.
  if (/runs-on:\s*['"]?(?:self-hosted|\[?\s*self-hosted)/i.test(content)) {
    hits["publish-workflow-runs-on-self-hosted"].push({ file: rel, line: 0, snippet: "publish workflow runs on a self-hosted runner — non-ephemeral execution context" });
  }

  return hits;
}

function collect({ cwd = process.cwd(), env = process.env, args = {} } = {}) {
  const errors = [];
  const startTime = Date.now();
  const root = path.resolve(cwd);

  // package-manifest detection.
  const manifests = [];
  const manifestFiles = [
    "package.json", "pyproject.toml", "Cargo.toml", "go.mod",
    "composer.json", "build.gradle", "build.gradle.kts", "pom.xml",
    "Gemfile",
  ];
  for (const f of manifestFiles) {
    const p = path.join(root, f);
    if (fs.existsSync(p)) {
      manifests.push({ file: f, path: p, content: readSafe(p) });
    }
  }
  // *.gemspec — glob at root only.
  try {
    for (const e of fs.readdirSync(root)) {
      if (e.endsWith(".gemspec")) {
        const p = path.join(root, e);
        manifests.push({ file: e, path: p, content: readSafe(p) });
      }
    }
  } catch {}

  // Release / publish workflows.
  const workflows = walkWorkflows(root).map(w => ({ ...w, content: readSafe(w.full) || "" }));
  const publishWorkflows = workflows.filter(w => looksLikePublishWorkflow(w.name, w.content));

  // Aggregate publish-workflow indicator hits.
  const workflowHits = {
    "publish-workflow-uses-static-token": [],
    "publish-workflow-no-id-token-write": [],
    "publish-workflow-action-refs-mutable": [],
    "release-workflow-non-frozen-install": [],
    "publish-workflow-runs-on-self-hosted": [],
  };
  for (const w of publishWorkflows) {
    const h = scanPublishWorkflow(w.content, w.rel);
    for (const [id, list] of Object.entries(h)) workflowHits[id].push(...list);
  }

  // package.json provenance: per playbook, the indicator fires
  // when EITHER the manifest opts in (`publishConfig.provenance:
  // true`) is missing AND the publish workflow does not invoke
  // `npm publish --provenance`. Repos that flip provenance on at
  // the workflow level (the modern path) should not be flagged.
  // We need the workflow inventory above this point.
  let provenanceMissing = "miss";
  const pkgManifest = manifests.find(m => m.file === "package.json");
  if (pkgManifest && pkgManifest.content) {
    try {
      const j = JSON.parse(pkgManifest.content);
      const manifestOptIn = j?.publishConfig?.provenance === true;
      const workflowOptIn = publishWorkflows.some(w => /npm\s+publish[^\n]*--provenance\b/.test(w.content));
      provenanceMissing = (manifestOptIn || workflowOptIn) ? "miss" : "hit";
    } catch (e) {
      errors.push({ artifact_id: "package-manifest", kind: "parse_failed", reason: `package.json: ${e.message}` });
    }
  }

  // lockfile-missing-integrity (per playbook): "any pinned entry
  // in walked lockfiles lacks an integrity field (sha512/sha384/
  // sha256, sri-integrity, go.sum h1: hash)". The predicate
  // covers every ecosystem's lockfile shape, not just npm. Walk
  // each supported lockfile and flip the indicator if any one of
  // them has a missing-integrity entry. When NO lockfile is
  // present, leave the indicator unflipped (undefined) so the
  // runner returns inconclusive — a no-lockfile repo is not
  // evidence of "no missing integrity"; it's evidence we can't
  // tell, and the playbook covers that case as inconclusive.
  let lockfileMissingIntegrity = undefined;
  const lockfilesChecked = [];
  const lockfileScans = [
    {
      file: "package-lock.json",
      scan: (text) => {
        const j = JSON.parse(text);
        let missing = 0;
        const walkObj = (obj) => {
          if (!obj || typeof obj !== "object") return;
          if (obj.resolved && obj.integrity == null) missing++;
          for (const v of Object.values(obj)) if (v && typeof v === "object") walkObj(v);
        };
        walkObj(j.packages || j.dependencies || {});
        return missing;
      },
    },
    {
      file: "yarn.lock",
      scan: (text) => {
        // yarn.lock entries: a `resolved "https://..."` line should be
        // followed within ~5 lines by an `integrity sha512-...` line.
        const lines = text.split(/\r?\n/);
        let missing = 0;
        for (let i = 0; i < lines.length; i++) {
          if (!/^\s*resolved\s+/.test(lines[i])) continue;
          const window = lines.slice(i + 1, Math.min(lines.length, i + 8)).join("\n");
          if (!/integrity\s+sha\d{3}-/.test(window)) missing++;
        }
        return missing;
      },
    },
    {
      file: "pnpm-lock.yaml",
      scan: (text) => {
        // pnpm entries have an `integrity:` field. Count entries
        // with `resolution: { tarball: ... }` lines whose nearby
        // block lacks `integrity:`.
        const blocks = text.split(/\n(?=\s+\/)/);
        let missing = 0;
        for (const b of blocks) {
          if (!/resolution:/.test(b)) continue;
          if (!/integrity:/.test(b)) missing++;
        }
        return missing;
      },
    },
    {
      file: "Cargo.lock",
      scan: (text) => {
        // Cargo.lock entries have `checksum = "..."` per [[package]]
        // (registry deps only — path / git deps legitimately have
        // none, so count only registry packages).
        const packages = text.split(/^\[\[package\]\]/m).slice(1);
        let missing = 0;
        for (const p of packages) {
          // Skip path / git deps — they have a `source = "<...>"`
          // line; registry deps have `source = "registry+..."`.
          const sourceMatch = p.match(/^source\s*=\s*"([^"]+)"/m);
          if (!sourceMatch) continue; // path dep, no integrity expected
          if (!sourceMatch[1].startsWith("registry+")) continue;
          if (!/^checksum\s*=\s*"/m.test(p)) missing++;
        }
        return missing;
      },
    },
    {
      file: "go.sum",
      scan: (text) => {
        // go.sum entries are `<module> <version> h1:<hash>=`.
        // Missing-integrity = a line without `h1:` (rare; malformed).
        const lines = text.split(/\r?\n/).filter(Boolean);
        let missing = 0;
        for (const l of lines) {
          if (!/\bh1:[A-Za-z0-9+/=]+\b/.test(l)) missing++;
        }
        return missing;
      },
    },
  ];
  for (const { file, scan } of lockfileScans) {
    const p = path.join(root, file);
    if (!fs.existsSync(p)) continue;
    lockfilesChecked.push(file);
    try {
      const text = fs.readFileSync(p, "utf8");
      const missing = scan(text);
      if (missing > 0) {
        lockfileMissingIntegrity = "hit";
        break;
      }
      // If at least one lockfile scanned cleanly, the indicator
      // moves to miss — we have evidence of integrity coverage.
      if (lockfileMissingIntegrity === undefined) lockfileMissingIntegrity = "miss";
    } catch (e) {
      errors.push({
        artifact_id: "lockfile",
        kind: "lockfile_scan_failed",
        reason: `${file}: ${e.message}`,
      });
    }
  }
  // If no supported lockfile was present, leave the indicator
  // unflipped (undefined). The runner returns inconclusive.

  // SECURITY.md presence (root + .github/SECURITY.md).
  const securityMdPresent =
    fs.existsSync(path.join(root, "SECURITY.md")) ||
    fs.existsSync(path.join(root, ".github", "SECURITY.md"));

  // security.txt presence (.well-known/security.txt + security.txt).
  const securityTxtPresent =
    fs.existsSync(path.join(root, ".well-known", "security.txt")) ||
    fs.existsSync(path.join(root, "security.txt"));

  // sbom-absent-or-unsigned: no sbom file at root, OR sbom file
  // present but no matching .sig sidecar.
  let sbomFile = null;
  for (const f of ["sbom.cdx.json", "sbom.json", "bom.json", "sbom.spdx.json", "sbom.cdx.xml"]) {
    if (fs.existsSync(path.join(root, f))) { sbomFile = f; break; }
  }
  let sbomAbsentOrUnsigned = "hit";
  if (sbomFile) {
    const sigPath = path.join(root, `${sbomFile}.sig`);
    sbomAbsentOrUnsigned = fs.existsSync(sigPath) ? "miss" : "hit";
  }

  // vendored-no-provenance: vendor/ directory exists without a
  // _PROVENANCE.json at any level inside it.
  let vendoredNoProvenance = "miss";
  const vendorDir = path.join(root, "vendor");
  if (fs.existsSync(vendorDir)) {
    let foundProvenance = false;
    const walkVendor = (dir, depth) => {
      if (depth > 3 || foundProvenance) return;
      let entries;
      try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
      for (const e of entries) {
        if (e.name === "_PROVENANCE.json") { foundProvenance = true; return; }
        if (e.isDirectory()) walkVendor(path.join(dir, e.name), depth + 1);
      }
    };
    walkVendor(vendorDir, 0);
    vendoredNoProvenance = foundProvenance ? "miss" : "hit";
  }

  const signal_overrides = {
    "publish-workflow-uses-static-token": workflowHits["publish-workflow-uses-static-token"].length > 0 ? "hit" : "miss",
    "publish-workflow-no-id-token-write": workflowHits["publish-workflow-no-id-token-write"].length > 0 ? "hit" : "miss",
    "publish-workflow-action-refs-mutable": workflowHits["publish-workflow-action-refs-mutable"].length > 0 ? "hit" : "miss",
    "release-workflow-non-frozen-install": workflowHits["release-workflow-non-frozen-install"].length > 0 ? "hit" : "miss",
    "publish-workflow-runs-on-self-hosted": workflowHits["publish-workflow-runs-on-self-hosted"].length > 0 ? "hit" : "miss",
    "package-json-provenance-missing": provenanceMissing,
    "sbom-absent-or-unsigned": sbomAbsentOrUnsigned,
    "no-security-md": securityMdPresent ? "miss" : "hit",
    "no-security-txt": securityTxtPresent ? "miss" : "hit",
    "vendored-no-provenance": vendoredNoProvenance,
  };
  // Conditionally include lockfile-missing-integrity — leave it
  // out (so the runner returns inconclusive) when no supported
  // lockfile was present to scan.
  if (lockfileMissingIntegrity !== undefined) {
    signal_overrides["lockfile-missing-integrity"] = lockfileMissingIntegrity;
  }

  const artifacts = {
    "release-workflows": {
      value: publishWorkflows.length
        ? publishWorkflows.map(w => w.rel).join(", ") + ` (${publishWorkflows.length}/${workflows.length} workflows recognised as publish-related)`
        : `${workflows.length} workflow(s); 0 recognised as publish-related`,
      captured: true,
    },
    "package-manifest": {
      value: manifests.length
        ? manifests.map(m => m.file).join(", ")
        : "no manifest file found at cwd root",
      captured: manifests.length > 0,
      reason: manifests.length === 0 ? "no package.json / Cargo.toml / pyproject.toml / etc. at cwd root" : undefined,
    },
    "supply-chain-posture-files": {
      value: [
        `SECURITY.md=${securityMdPresent}`,
        `security.txt=${securityTxtPresent}`,
        `sbom=${sbomFile || "(none)"}`,
        `sbom_signed=${sbomFile && fs.existsSync(path.join(root, `${sbomFile}.sig`))}`,
        `vendor_provenance=${vendoredNoProvenance === "miss" ? "present-or-no-vendor" : "missing"}`,
      ].join("; "),
      captured: true,
    },
  };

  return {
    precondition_checks: {
      "publisher-context": manifests.length > 0,
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
      manifests_found: manifests.map(m => m.file),
      workflows_total: workflows.length,
      publish_workflows: publishWorkflows.map(w => w.name),
    },
    collector_errors: errors,
  };
}

module.exports = { playbook_id: COLLECTOR_ID, collect };
