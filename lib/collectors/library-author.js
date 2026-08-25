"use strict";

/**
 * Companion collector for the `library-author` playbook: audits a publisher-side
 * repository for supply-chain posture markers. Indicators needing an external API
 * or a build-pipeline trace are left unflipped, so the runner returns
 * inconclusive rather than a forced miss.
 * Interface: see lib/collectors/README.md
 */

const fs = require("node:fs");
const path = require("node:path");
const { codeExcludeSet, isLinkedWorktreeDir, buildEvidenceLocations } = require("./scan-excludes");

const COLLECTOR_ID = "library-author";

// Applied to the vendor-tree walk, so a cache nested under `vendor/` is not
// mistaken for vendored provenance state.
const DEFAULT_EXCLUDES = codeExcludeSet();

function readSafe(full, max = 512 * 1024) {
  let fd;
  try {
    fd = fs.openSync(full, "r");
    const s = fs.fstatSync(fd);
    if (s.size > max) return null;
    // readFileSync(fd), never a single readSync: a short read on a network fd
    // NUL-fills the tail. Reading the open fd is also TOCTOU-free.
    return fs.readFileSync(fd, "utf8");
  } catch { return null; }
  finally { if (fd !== undefined) { try { fs.closeSync(fd); } catch { /* non-fatal */ } } }
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
  // Broad signals — `id-token: write`, a cosign installer — must not count:
  // verification and e2e workflows share the same signing infrastructure.
  const lower = name.toLowerCase();

  if (/^(test|verify|validate|e2e|kind|check|conformance|coverage)/.test(lower)) return false;

  if (/^(release|publish|deploy|promote|tag-and-release)/.test(lower)) return true;

  // Comment-stripped, so a `#` line mentioning a publish verb cannot masquerade
  // as one. Stripping can only remove text, never create a match.
  const code = stripYamlComments(content);

  if (/\bnpm\s+publish\b/.test(code)) return true;
  if (/pypa\/gh-action-pypi-publish/.test(code)) return true;
  if (/\bcargo\s+publish\b/.test(code)) return true;
  if (/goreleaser/.test(code)) return true;
  if (/softprops\/action-gh-release/.test(code)) return true;
  // All four `ko` sub-commands push to a registry by default, `build` included.
  if (/\bko\s+(?:publish|build|apply|resolve)\b/.test(code)) return true;
  // The `(?!-)` keeps out `cosign sign-blob`, as common in verification workflows.
  if (/\bcosign\s+sign\b(?!-)/.test(code)) return true;
  if (/\bcrane\s+(?:push|copy|append)\b/.test(code)) return true;
  if (/\boras\s+(?:push|copy)\b/.test(code)) return true;
  if (/docker\/build-push-action/.test(code)) return true;
  if (/\bdocker\s+push\b/.test(code)) return true;

  // Registry login stands in for opaque publish paths (a Makefile target run
  // after docker/login-action); verification workflows never authenticate.
  if (/docker\/login-action/.test(code)) return true;
  if (/google-github-actions\/auth/.test(code) && /gcloud auth configure-docker/.test(code)) return true;
  if (/aws-actions\/configure-aws-credentials/.test(code) && /amazon-ecr/.test(code)) return true;

  return false;
}

// `id-token: write` is valid at workflow OR job scope, so any occurrence counts.
// Scoped to the one file passed in: a sibling workflow's OIDC does not grant it.
function hasIdTokenWriteAnyScope(content) {
  return /\bid-token:\s*write\b/.test(content);
}

// Every probe that reads workflow bodies must use this view: a commented publish
// token otherwise produces a false hit, and a commented `--provenance` hides a gap.
function stripYamlComments(content) {
  return content.replace(/#.*$/gm, "");
}

// Splits comment-stripped workflow text into individual shell commands, so a
// flag on one install cannot vouch for another. A workflow that hash-pins its
// build requirements and then resolves its runtime ones must still report the
// unpinned command, which a whole-file flag test would suppress.
function shellCommands(code) {
  const out = [];
  const lines = code.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    // A real `run:` line is never KBs long; skipping overlong ones keeps a
    // crafted whitespace run from driving regex backtracking.
    if (lines[i].length > 4096) continue;
    // A backslash-continued command is ONE command: a `pip install \` whose
    // `-r` sits on the next line is otherwise two fragments that each match
    // nothing. The continuation lines are consumed, never re-emitted.
    const startLine = i + 1;
    let raw = lines[i];
    while (/\\[ \t]*$/.test(raw) && i + 1 < lines.length &&
           lines[i + 1].length <= 4096 && raw.length <= 8192) {
      raw = `${raw.replace(/\\[ \t]*$/, " ")}${lines[i + 1].trim()}`;
      i++;
    }
    for (const seg of raw.split(/&&|\|\||[;|]/)) {
      const cmd = seg.trim();
      // Comment stripping preserves line breaks, so the index still addresses
      // the line the command STARTS on in the file an operator opens.
      if (cmd) out.push({ cmd, line: startLine });
    }
  }
  return out;
}

// Evidence snippets are read in a report, so a pathological one-line script
// cannot be pasted in whole.
function snippetOf(cmd, max = 200) {
  return cmd.length > max ? `${cmd.slice(0, max)}…` : cmd;
}

// pip enters hash-checking mode as soon as ONE requirement carries a hash, so
// `pip install -r <file>` against a `pip-compile --generate-hashes` output is
// already reproducible. Resolves the named file one level only: a nested `-r`
// include is not followed, and an unreadable path counts as unhashed.
// pip accepts the requirement file attached (`-rreq.txt`) as well as separated
// (`-r req.txt`, `--requirement=req.txt`). One definition for both the detection
// predicate and the hash lookup: two regexes for one flag drift, and the pair
// that drifts silently is a command examined by neither.
// `(?:^|\s)-r` rather than `\b-r` so the `-r` inside `--requirement` is not read
// as the short form with `equirement...` as its filename.
const PIP_REQUIREMENT_RE = /(?:^|\s)(?:-r\s*=?\s*|--requirement[=\s]*)['"]?([^'"\s]+)/;

function pipRequirementTarget(cmd) {
  const m = cmd.match(PIP_REQUIREMENT_RE);
  return m ? m[1] : null;
}

// `working-directory:`, at job defaults or on a single step, is what a `run:`
// command resolves its relative paths against. Collected as a set of candidate
// bases rather than bound to the step that declared it: the scanner is
// line-based, so attributing one to a specific command would need the step
// nesting it does not track.
// Matches the block form and the flow form (`{ run: { working-directory: x } }`)
// alike. A key-shaped string inside a `run:` command matches too; that only adds
// a base that does not resolve, and an unresolvable base is skipped.
function workingDirectories(code) {
  const dirs = [];
  for (const m of code.matchAll(/working-directory:\s*['"]?([^'"\n,}]+?)['"]?\s*(?=$|[,}])/gm)) {
    const d = m[1].trim();
    if (d && d !== "." && !path.isAbsolute(d)) dirs.push(d);
  }
  return dirs;
}

// True only when every candidate that EXISTS is hash-pinned, and at least one
// does. Requiring all of them keeps a hashed copy in one working directory from
// vouching for an unhashed copy in another — over-suppression here reports an
// unpinned release as reproducible, which is the direction that costs something.
// A target that resolves nowhere stays unproven, so the caller still reports it.
function requirementsFileIsHashed(cmd, root, extraBases = []) {
  if (!root) return false;
  const target = pipRequirementTarget(cmd);
  if (!target) return false;
  if (path.isAbsolute(target)) return false;

  let found = 0;
  for (const base of [root, ...extraBases.map((d) => path.resolve(root, d))]) {
    // Never read outside the scanned tree, whatever `../` the workflow names —
    // for the base itself as well as the target resolved against it.
    if (base !== root && !base.startsWith(root + path.sep)) continue;
    const full = path.resolve(base, target);
    if (full !== root && !full.startsWith(root + path.sep)) continue;
    const body = readSafe(full);
    if (body === null) continue;
    found++;
    if (!/--hash=/.test(body)) return false;
  }
  return found > 0;
}

function scanPublishWorkflow(content, rel, root) {
  // Whole-content probes read `code`; the `uses:` scan below stays on raw lines.
  const code = stripYamlComments(content);
  const hits = {
    "publish-workflow-uses-static-token": [],
    "publish-workflow-no-id-token-write": [],
    "publish-workflow-action-refs-mutable": [],
    "release-workflow-non-frozen-install": [],
    "publish-workflow-runs-on-self-hosted": [],
  };

  // Widens the predicate in data/playbooks/library-author.json to the common
  // token-name variant per ecosystem.
  const usesStaticToken = /\bsecrets\.(NPM_TOKEN|PYPI_TOKEN|PYPI_API_TOKEN|CARGO_TOKEN|CARGO_REGISTRY_TOKEN|RUBYGEMS_API_KEY|GEM_HOST_API_KEY|MAVEN_TOKEN|MAVEN_CENTRAL_TOKEN|GH_TOKEN)\b/.test(code);
  // Comment-stripped: a commented `id-token: write` would suppress the finding.
  const hasIdTokenWrite = hasIdTokenWriteAnyScope(code);
  if (usesStaticToken && !hasIdTokenWrite) {
    hits["publish-workflow-uses-static-token"].push({ file: rel, line: 0, snippet: "publish workflow uses a static long-lived token (NPM_TOKEN / PYPI / Cargo / Maven) without id-token: write for OIDC" });
  }
  if (!hasIdTokenWrite) {
    hits["publish-workflow-no-id-token-write"].push({ file: rel, line: 0, snippet: "no id-token: write at any scope (workflow or job) — npm provenance / sigstore signing unavailable" });
  }

  // Mutable = any `uses: <action>@<ref>` whose ref is not a 40-char hex sha.
  const lines = content.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    // A real `uses:` line is never KBs long; skipping overlong ones keeps a
    // crafted whitespace run from driving regex backtracking.
    if (line.length > 4096) continue;
    // No end anchor and `#` excluded from the capture, so `uses: x@v1  # comment`
    // still matches. The indent and `- ` marker are each anchored once.
    const m = line.match(/^[ \t]*(?:-[ \t]*)?uses:\s*['"]?([^'"\s#]+)['"]?/);
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

  // npm alone stays a whole-file test, because its suppressor is a DIFFERENT
  // command rather than a flag: `npm ci` elsewhere in the workflow is the
  // frozen install, and the `npm install` line beside it is usually tooling.
  if (/\bnpm\s+install\b/.test(code) && !/\bnpm\s+ci\b/.test(code)) {
    hits["release-workflow-non-frozen-install"].push({ file: rel, line: 0, snippet: "publish workflow uses `npm install` rather than `npm ci` — lockfile is not enforced" });
  }

  // Bundler's frozen mode can be set once for the job rather than per command
  // (`bundle config set frozen/deployment`, or the BUNDLE_ env equivalents), so
  // that suppressor is genuinely file-scoped; the flags below are not.
  // The setting has to be turned ON. `bundle config set frozen false` names the
  // key and disables it, so matching the key alone reads an explicit opt-out as
  // the protection it opts out of — the env form already required a value.
  const bundlerFrozenConfig =
    /\bbundle\s+config\b[^\n]*\b(?:frozen|deployment)\s+['"]?(?:true|1)\b/.test(code) ||
    /\bBUNDLE_(?:FROZEN|DEPLOYMENT)\s*[:=]\s*['"]?(?:true|1)\b/i.test(code);

  const runBases = workingDirectories(code);

  // Every remaining ecosystem is probed one command at a time. The playbook
  // indicator names npm / pnpm / pip -r / bundle; cargo is probed on the same
  // --locked / --frozen predicate.
  for (const { cmd, line } of shellCommands(code)) {
    if (/\bcargo\s+(?:build|install)\b/.test(cmd) && !/--locked\b/.test(cmd) && !/--frozen\b/.test(cmd)) {
      hits["release-workflow-non-frozen-install"].push({ file: rel, line, snippet: `cargo build/install without --locked / --frozen: ${snippetOf(cmd)}` });
    }
    // Without --require-hashes the requirement set resolves at release time, so
    // the artifact is not reproducible — unless the named file is hash-pinned,
    // which switches pip into hash-checking mode on its own.
    if (/\b(?:pip3?|python3?\s+-m\s+pip)\s+install\b/.test(cmd) &&
        pipRequirementTarget(cmd) !== null &&
        !/--require-hashes\b/.test(cmd) &&
        !requirementsFileIsHashed(cmd, root, runBases)) {
      hits["release-workflow-non-frozen-install"].push({ file: rel, line, snippet: `pip install -r without --require-hashes — requirements are resolved at release time: ${snippetOf(cmd)}` });
    }
    // pnpm defaults to --frozen-lockfile when CI is set, which GitHub Actions
    // always sets — so a bare `pnpm install` here is already frozen and only an
    // explicit opt-out resolves at release time.
    if (/\bpnpm\s+(?:install|i)\b/.test(cmd) &&
        /--no-frozen-lockfile\b|--frozen-lockfile[=\s]+false\b/.test(cmd)) {
      hits["release-workflow-non-frozen-install"].push({ file: rel, line, snippet: `pnpm install opts out of the frozen lockfile: ${snippetOf(cmd)}` });
    }
    if (/\bbundle\s+install\b/.test(cmd) && !/--deployment\b/.test(cmd) && !/--frozen\b/.test(cmd) && !bundlerFrozenConfig) {
      hits["release-workflow-non-frozen-install"].push({ file: rel, line, snippet: `bundle install without --deployment / --frozen: ${snippetOf(cmd)}` });
    }
  }

  if (/runs-on:\s*['"]?(?:self-hosted|\[?\s*self-hosted)/i.test(code)) {
    hits["publish-workflow-runs-on-self-hosted"].push({ file: rel, line: 0, snippet: "publish workflow runs on a self-hosted runner — non-ephemeral execution context" });
  }

  return hits;
}

function collect({ cwd = process.cwd(), env = process.env, args = {} } = {}) {
  const errors = [];
  const startTime = Date.now();
  const root = path.resolve(cwd);

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
  try {
    for (const e of fs.readdirSync(root)) {
      if (e.endsWith(".gemspec")) {
        const p = path.join(root, e);
        manifests.push({ file: e, path: p, content: readSafe(p) });
      }
    }
  } catch {}

  const workflows = walkWorkflows(root).map(w => ({ ...w, content: readSafe(w.full) || "" }));
  const publishWorkflows = workflows.filter(w => looksLikePublishWorkflow(w.name, w.content));

  const workflowHits = {
    "publish-workflow-uses-static-token": [],
    "publish-workflow-no-id-token-write": [],
    "publish-workflow-action-refs-mutable": [],
    "release-workflow-non-frozen-install": [],
    "publish-workflow-runs-on-self-hosted": [],
  };
  // OIDC capability is evaluated per publish workflow, never repo-wide: a sibling
  // workflow's `id-token: write` gives nothing to a job using a static token.
  for (const w of publishWorkflows) {
    const h = scanPublishWorkflow(w.content, w.rel, root);
    for (const [id, list] of Object.entries(h)) workflowHits[id].push(...list);
  }

  // Fires only when neither `publishConfig.provenance: true` nor a workflow
  // `npm publish --provenance` opts in. Needs the workflow inventory above.
  let provenanceMissing = "miss";
  const pkgManifest = manifests.find(m => m.file === "package.json");
  if (pkgManifest && pkgManifest.content) {
    try {
      const j = JSON.parse(pkgManifest.content);
      const manifestOptIn = j?.publishConfig?.provenance === true;
      const workflowOptIn = publishWorkflows.some(w => /npm\s+publish[^\n]*--provenance\b/.test(stripYamlComments(w.content)));
      provenanceMissing = (manifestOptIn || workflowOptIn) ? "miss" : "hit";
    } catch (e) {
      errors.push({ artifact_id: "package-manifest", kind: "parse_failed", reason: `package.json: ${e.message}` });
    }
  }

  // Any one lockfile with a missing-integrity entry flips the indicator. With no
  // lockfile it stays undefined: a repo without one is not evidence of integrity.
  let lockfileMissingIntegrity = undefined;
  const lockfilesChecked = [];
  const lockfileScans = [
    {
      file: "package-lock.json",
      scan: (text) => {
        const j = JSON.parse(text);
        let missing = 0;
        // Only a remote-tarball entry (`resolved` is an http(s)/git URL) owes an
        // integrity hash; a workspace link and file:/link:/workspace: refs have
        // none by nature, and counting them false-hits every workspaces monorepo.
        const walkObj = (obj) => {
          if (!obj || typeof obj !== "object") return;
          if (
            obj.resolved &&
            obj.integrity == null &&
            obj.link !== true &&
            /^(?:https?:|git\+|git:|ssh:)/i.test(String(obj.resolved))
          ) missing++;
          for (const v of Object.values(obj)) if (v && typeof v === "object") walkObj(v);
        };
        walkObj(j.packages || j.dependencies || {});
        return missing;
      },
    },
    {
      file: "yarn.lock",
      scan: (text) => {
        // A `resolved "https://..."` line owes an `integrity sha512-...` nearby.
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
        // A pnpm block carrying `resolution:` owes an `integrity:` field.
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
        // `checksum` is owed per [[package]] by registry deps only.
        const packages = text.split(/^\[\[package\]\]/m).slice(1);
        let missing = 0;
        for (const p of packages) {
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
        // A go.sum line is `<module> <version> h1:<hash>=`; one without `h1:` is malformed.
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
      if (lockfileMissingIntegrity === undefined) lockfileMissingIntegrity = "miss";
    } catch (e) {
      errors.push({
        artifact_id: "lockfile",
        kind: "lockfile_scan_failed",
        reason: `${file}: ${e.message}`,
      });
    }
  }
  const securityMdPresent =
    fs.existsSync(path.join(root, "SECURITY.md")) ||
    fs.existsSync(path.join(root, ".github", "SECURITY.md"));

  const securityTxtPresent =
    fs.existsSync(path.join(root, ".well-known", "security.txt")) ||
    fs.existsSync(path.join(root, "security.txt"));

  // Fires when there is no root SBOM, or one with no matching .sig sidecar.
  let sbomFile = null;
  for (const f of ["sbom.cdx.json", "sbom.json", "bom.json", "sbom.spdx.json", "sbom.cdx.xml"]) {
    if (fs.existsSync(path.join(root, f))) { sbomFile = f; break; }
  }
  // An SBOM generated and signed at release time never lands in the committed
  // tree, so the capability is detected in the publish workflows instead.
  const releaseSbomCapable = publishWorkflows.some(w => {
    const c = stripYamlComments(w.content);
    return (
      /cyclonedx/i.test(c) ||
      /\bsyft\b/i.test(c) ||
      /anchore\/sbom-action/i.test(c) ||
      /\btrivy\b[^\n]*\bsbom\b/i.test(c) ||
      /\bnpm\s+sbom\b/.test(c) ||
      /spdx-sbom-generator/i.test(c) ||
      /npm\s+publish[^\n]*--provenance\b/.test(c) ||
      /\bcosign\s+(?:sign|attest)\b/.test(c) ||
      /sigstore\//i.test(c) ||
      /gh-action-sigstore-python/i.test(c)
    );
  });
  // The manifest opt-in likewise produces a signed provenance attestation.
  const manifestProvenanceOptIn = (() => {
    if (!pkgManifest || !pkgManifest.content) return false;
    try { return JSON.parse(pkgManifest.content)?.publishConfig?.provenance === true; }
    catch { return false; }
  })();
  let sbomAbsentOrUnsigned = "hit";
  if (sbomFile) {
    const sigPath = path.join(root, `${sbomFile}.sig`);
    sbomAbsentOrUnsigned = fs.existsSync(sigPath) ? "miss" : "hit";
  } else if (releaseSbomCapable || manifestProvenanceOptIn) {
    sbomAbsentOrUnsigned = "miss";
  }

  // Fires when vendor/ exists with no _PROVENANCE.json at any level inside it.
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
        if (e.isDirectory()) {
          if (DEFAULT_EXCLUDES.has(e.name)) continue;
          const sub = path.join(dir, e.name);
          // A linked worktree under vendor/ is a separate repo copy.
          if (isLinkedWorktreeDir(sub)) continue;
          walkVendor(sub, depth + 1);
        }
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
  // Omitted when no lockfile was there to scan, so the runner reads inconclusive.
  if (lockfileMissingIntegrity !== undefined) {
    signal_overrides["lockfile-missing-integrity"] = lockfileMissingIntegrity;
  }

  // The keys "0" and "1" are positional indexes into the indicator's
  // false_positive_checks_required list: [0] Dependabot on github-actions demotes,
  // [1] all-github-owned refs are lower risk. Reordering that list mis-attests.
  if (signal_overrides["publish-workflow-action-refs-mutable"] === "hit") {
    let dependabotActions = false;
    try {
      const dbContent =
        readSafe(path.join(root, ".github", "dependabot.yml")) ||
        readSafe(path.join(root, ".github", "dependabot.yaml")) || "";
      dependabotActions = /package-ecosystem:\s*['"]?github-actions/i.test(dbContent) &&
        /\binterval:\s*['"]?(?:daily|weekly)/i.test(dbContent);
    } catch { /* no dependabot config */ }
    const mutableRefSnippets = (workflowHits["publish-workflow-action-refs-mutable"] || []).map(h => h.snippet || "");
    const refOf = (s) => {
      const m = s.match(/uses:\s*['"]?([^'"\s]+)/);
      return m ? m[1] : "";
    };
    const anyThirdParty = mutableRefSnippets.some(s => {
      const r = refOf(s);
      return r && !/^(?:actions|github)\//i.test(r);
    });
    const att = {};
    if (!dependabotActions) att["0"] = true;
    if (anyThirdParty) att["1"] = true;
    if (Object.keys(att).length) signal_overrides["publish-workflow-action-refs-mutable__fp_checks"] = att;
  }

  // Only the workflow indicators get locations, so a SARIF result can point at the
  // offending `uses:` line; the rest are whole-repo presence or absence.
  const evidence_locations = {};
  for (const id of Object.keys(workflowHits)) {
    if (signal_overrides[id] === "hit") {
      const locs = buildEvidenceLocations(workflowHits[id]);
      if (locs.length) evidence_locations[id] = locs;
    }
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
      // Attested here because the runner cannot probe the scanned --cwd. The
      // repo-walk-access HALT gate must not be attested from the collector: it is
      // resolved host-side, and attesting it turns a passing run into a halt.
      "publishable-artifact-evidence": manifests.length > 0 || publishWorkflows.length > 0,
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
      manifests_found: manifests.map(m => m.file),
      workflows_total: workflows.length,
      publish_workflows: publishWorkflows.map(w => w.name),
    },
    collector_errors: errors,
  };
}

module.exports = { playbook_id: COLLECTOR_ID, collect };
