"use strict";

/**
 * lib/collectors/containers.js
 *
 * Companion collector for the `containers` playbook. Walks the cwd
 * for Dockerfile / Containerfile, docker-compose, and k8s manifest
 * files; applies the catalogued indicator predicates against their
 * contents.
 *
 * YAML parsing strategy: heuristic line-scanning, not a full YAML
 * parser. The catalogued indicators (privileged: true, hostNetwork:
 * true, runAsUser: 0, etc.) are well-known text patterns whose
 * misuse is unambiguous at the line level. False positives are rare
 * — e.g. `# privileged: true` in a comment would match, but those
 * are also worth surfacing.
 *
 * Interface: see lib/collectors/README.md
 */

const fs = require("node:fs");
const path = require("node:path");
const { codeExcludeSet, isLinkedWorktreeDir } = require("./scan-excludes");

const COLLECTOR_ID = "containers";

const DEFAULT_MAX_DEPTH = 6;
// Shared code-scope exclusions (dependency caches, build output, VCS +
// agent/editor scratch including `.claude/`); no container-specific extras.
const DEFAULT_EXCLUDES = codeExcludeSet();

const DOCKERFILE_NAMES = new Set(["Dockerfile", "Containerfile"]);
const DOCKERFILE_EXTS = new Set([".dockerfile", ".containerfile"]);
const COMPOSE_NAMES = new Set([
  "docker-compose.yml", "docker-compose.yaml",
  "compose.yml", "compose.yaml",
]);
const COMPOSE_PREFIX = "docker-compose.";   // docker-compose.override.yml etc.

function walkTree(root, opts = {}) {
  const maxDepth = opts.maxDepth ?? DEFAULT_MAX_DEPTH;
  const excludes = opts.excludes ?? DEFAULT_EXCLUDES;
  const out = [];
  const seen = new Set();
  function walk(dir, depth) {
    if (depth > maxDepth) return;
    let entries;
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
    for (const entry of entries) {
      if (excludes.has(entry.name)) continue;
      const full = path.join(dir, entry.name);
      let real;
      try { real = fs.realpathSync(full); } catch { continue; }
      if (seen.has(real)) continue;
      seen.add(real);
      if (entry.isDirectory()) {
        // Skip linked git worktrees (their `.git` is a gitdir pointer
        // file) — e.g. agent-created repo copies under
        // `.claude/worktrees/<id>/`. Walking them rescans the same
        // Dockerfiles / compose / k8s manifests as the host tree.
        if (isLinkedWorktreeDir(full)) continue;
        walk(full, depth + 1);
      } else if (entry.isFile()) out.push({ full, rel: path.relative(root, full), name: entry.name });
    }
  }
  walk(root, 0);
  return out;
}

function classify(file) {
  const name = file.name;
  const ext = path.extname(name).toLowerCase();
  const lower = name.toLowerCase();
  const isDockerfile =
    DOCKERFILE_NAMES.has(name) ||
    name.endsWith(".Dockerfile") || name.endsWith(".dockerfile") ||
    DOCKERFILE_EXTS.has(ext) ||
    lower === "dockerfile" || lower.endsWith(".dockerfile");
  const isCompose =
    COMPOSE_NAMES.has(name) ||
    (lower.startsWith(COMPOSE_PREFIX) && (ext === ".yml" || ext === ".yaml"));
  const isYaml = ext === ".yml" || ext === ".yaml";
  return { isDockerfile, isCompose, isYaml };
}

function readSafe(full, max = 512 * 1024) {
  try {
    const s = fs.statSync(full);
    if (s.size > max) return null;
    return fs.readFileSync(full, "utf8");
  } catch { return null; }
}

/**
 * Recognise a YAML document as a k8s resource by `apiVersion: ...` +
 * `kind: ...` lines. Doesn't require full parsing — the two lines
 * appear at top-level indent.
 */
function looksLikeK8sManifest(content) {
  if (!/^apiVersion:\s+\S/m.test(content)) return false;
  if (!/^kind:\s+\S/m.test(content)) return false;
  return true;
}

function extractKind(content) {
  const m = content.match(/^kind:\s+([A-Za-z][A-Za-z0-9]*)/m);
  return m ? m[1] : null;
}

/**
 * Dockerfile pattern matchers. Returns { id, hits: [{line, snippet}] }.
 */
function scanDockerfile(content, rel) {
  const lines = content.split(/\r?\n/);
  const hits = {
    "dockerfile-from-latest": [],
    "dockerfile-no-digest-pin": [],
    "dockerfile-runs-as-root": [],
    "dockerfile-curl-pipe-bash": [],
  };

  // Metadata-only Dockerfile heuristic — when the file has a FROM
  // line but no RUN / COPY / ADD / CMD / ENTRYPOINT / EXPOSE / VOLUME
  // / WORKDIR / USER directives, it's not a runtime image. Examples:
  // the go-version-scraping Dockerfile (cosign style) or a base-image-
  // probe used only by `docker build` to extract a version label.
  // The runs-as-root predicate is meaningless on those — demote.
  const isMetadataOnly = (() => {
    let sawFrom = false;
    let sawBuildOrRuntime = false;
    for (const raw of lines) {
      const t = raw.trim();
      if (!t || t.startsWith("#")) continue;
      if (/^FROM\b/i.test(t)) { sawFrom = true; continue; }
      if (/^(RUN|COPY|ADD|CMD|ENTRYPOINT|EXPOSE|VOLUME|WORKDIR|USER|HEALTHCHECK|ONBUILD|STOPSIGNAL|SHELL|ARG|ENV|LABEL)\b/i.test(t)) {
        // ARG / ENV / LABEL alone aren't enough to make this a runtime
        // image — only the directives that define execution shape do.
        if (/^(RUN|COPY|ADD|CMD|ENTRYPOINT|EXPOSE|VOLUME|WORKDIR|USER|HEALTHCHECK|ONBUILD|SHELL)\b/i.test(t)) {
          sawBuildOrRuntime = true;
          break;
        }
      }
    }
    return sawFrom && !sawBuildOrRuntime;
  })();

  let sawNonRootUser = false;
  let sawAnyUser = false;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;

    // FROM <image>:latest  OR  FROM <image>  (no tag)  → from-latest
    // FROM <image>:<tag>  (no @sha256:digest)         → no-digest-pin
    const fromMatch = trimmed.match(/^FROM\s+(\S+)(?:\s+AS\s+\S+)?/i);
    if (fromMatch) {
      const ref = fromMatch[1];
      // scratch is a special base; skip both checks.
      if (ref !== "scratch") {
        const hasDigest = /@sha256:[0-9a-f]{64}/i.test(ref);
        if (!hasDigest) {
          hits["dockerfile-no-digest-pin"].push({ file: rel, line: i + 1, snippet: trimmed.slice(0, 120) });
        }
        // latest tag check: either explicit :latest OR no tag at all
        // (Docker defaults to :latest when omitted).
        const tagMatch = ref.match(/:([^@]+)(?:@|$)/);
        const tag = tagMatch ? tagMatch[1] : null;
        if (tag === "latest" || tag === null) {
          hits["dockerfile-from-latest"].push({ file: rel, line: i + 1, snippet: trimmed.slice(0, 120) });
        }
      }
      continue;
    }

    // USER directive — looks for explicit non-root user.
    // Recognises USER <uid>, USER <uid>:<gid>, USER <name>, USER <name>:<group>.
    // Root forms (all count as root): "root", "0", "root:<anything>",
    // "0:<anything>". Any other UID/name is non-root.
    const userMatch = trimmed.match(/^USER\s+(\S+)/i);
    if (userMatch) {
      sawAnyUser = true;
      const u = userMatch[1];
      const userPart = u.split(":")[0]; // strip optional :group
      if (userPart !== "0" && userPart !== "root") sawNonRootUser = true;
      continue;
    }

    // curl|wget | sh|bash pattern
    if (
      /\b(?:curl|wget)\b[^|]*\|\s*(?:sh|bash|zsh)\b/.test(trimmed) ||
      /\b(?:curl|wget)\b[^&|;]*\s+&&\s+(?:sh|bash)\b/.test(trimmed)
    ) {
      hits["dockerfile-curl-pipe-bash"].push({ file: rel, line: i + 1, snippet: trimmed.slice(0, 120) });
    }
  }

  // runs-as-root indicator: file fires if NO non-root USER directive
  // was seen anywhere. (sawAnyUser=false also counts — image defaults
  // to root.) Demoted on metadata-only Dockerfiles (FROM-only, no
  // execution-shape directives) — those aren't runtime images.
  if (!sawNonRootUser && !isMetadataOnly) {
    hits["dockerfile-runs-as-root"].push({ file: rel, line: 0, snippet: sawAnyUser ? "USER directive sets root/0" : "no USER directive (defaults to root)" });
  }

  return hits;
}

/**
 * docker-compose pattern matchers. Heuristic: match `key: true` /
 * `key: <value>` lines, capturing the service block path where
 * possible.
 */
function scanCompose(content, rel) {
  const lines = content.split(/\r?\n/);
  const hits = {
    "compose-privileged": [],
    "compose-cap-add-sys-admin": [],
    "compose-host-network": [],
    "compose-docker-sock-mount": [],
  };

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (/^\s*#/.test(line)) continue;
    if (/^\s*privileged:\s*true\b/i.test(line)) hits["compose-privileged"].push({ file: rel, line: i + 1, snippet: line.trim() });
    // compose-host-network: per playbook, fires on any of
    // network_mode: host, pid: host, ipc: host.
    if (/^\s*network_mode:\s*['"]?host\b/i.test(line) ||
        /^\s*pid:\s*['"]?host['"]?\s*$/i.test(line) ||
        /^\s*ipc:\s*['"]?host['"]?\s*$/i.test(line)) {
      hits["compose-host-network"].push({ file: rel, line: i + 1, snippet: line.trim() });
    }
    // compose-cap-add-sys-admin: per playbook, fires on
    // SYS_ADMIN, SYS_PTRACE, or SYS_MODULE under cap_add. Either
    // inline (cap_add: [SYS_ADMIN, SYS_PTRACE]) or multi-line
    // (cap_add:\n  - SYS_PTRACE).
    const RISKY_CAPS_RE = /\b(?:CAP_)?(?:SYS_ADMIN|SYS_PTRACE|SYS_MODULE)\b/i;
    if (/cap_add:.*\[/i.test(line) && RISKY_CAPS_RE.test(line)) {
      hits["compose-cap-add-sys-admin"].push({ file: rel, line: i + 1, snippet: line.trim() });
    } else if (/^\s*-\s*['"]?(?:CAP_)?(?:SYS_ADMIN|SYS_PTRACE|SYS_MODULE)\b/i.test(line) &&
               lines.slice(Math.max(0, i - 5), i).some(l => /cap_add:/i.test(l))) {
      hits["compose-cap-add-sys-admin"].push({ file: rel, line: i + 1, snippet: line.trim() });
    }
    // docker-sock mount: /var/run/docker.sock anywhere in the value
    if (/\/var\/run\/docker\.sock/.test(line)) {
      hits["compose-docker-sock-mount"].push({ file: rel, line: i + 1, snippet: line.trim() });
    }
  }
  return hits;
}

/**
 * k8s manifest pattern matchers. Heuristic line-scanning + kind-
 * level guards (e.g. ClusterRoleBinding for cluster-admin check).
 */
function scanK8s(content, rel) {
  const lines = content.split(/\r?\n/);
  const kind = extractKind(content);
  const hits = {
    "k8s-privileged": [],
    "k8s-host-namespaces": [],
    "k8s-run-as-root": [],
    "k8s-hostpath-sensitive": [],
    "k8s-image-latest": [],
    "k8s-cluster-admin-binding": [],
  };

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (/^\s*#/.test(line)) continue;
    if (/^\s*privileged:\s*true\b/i.test(line)) hits["k8s-privileged"].push({ file: rel, line: i + 1, snippet: line.trim() });
    if (/^\s*(hostNetwork|hostPID|hostIPC):\s*true\b/.test(line)) hits["k8s-host-namespaces"].push({ file: rel, line: i + 1, snippet: line.trim() });
    // k8s-run-as-root: per playbook, fires on runAsUser: 0 OR
    // runAsNonRoot: false. (The "runAsUser unset AND image runs as
    // root" clause requires image inspection the collector can't do
    // without a container runtime; leave that to the runner when
    // operator-supplied image-inspection evidence is available.)
    if (/^\s*runAsUser:\s*0\b/.test(line) ||
        /^\s*runAsNonRoot:\s*false\b/.test(line)) {
      hits["k8s-run-as-root"].push({ file: rel, line: i + 1, snippet: line.trim() });
    }
    // hostPath sensitive: /, /etc, /var/lib/docker, /proc, /sys
    const hpMatch = line.match(/^\s*path:\s*['"]?(\/(?:etc|proc|sys|var\/lib\/docker|var\/run|root|home)?\/?)['"]?\s*$/);
    if (hpMatch && lines.slice(Math.max(0, i - 3), i).some(l => /hostPath:/i.test(l))) {
      hits["k8s-hostpath-sensitive"].push({ file: rel, line: i + 1, snippet: line.trim() });
    }
    // image: ...:latest OR image: ... (no tag, defaults to latest)
    // Allow optional leading `-` from a YAML list item: `- image: ...`.
    const imageMatch = line.match(/^\s*-?\s*image:\s*['"]?([^'"@\s]+)(?:@[^'"]+)?['"]?\s*$/);
    if (imageMatch) {
      const ref = imageMatch[1];
      const tagMatch = ref.match(/:([^/]+)$/);
      const tag = tagMatch ? tagMatch[1] : null;
      // Skip if @sha256:... pinned (the full regex captured ref without @-suffix).
      const hasDigest = /@sha256:[0-9a-f]{64}/.test(line);
      if (!hasDigest && (tag === "latest" || tag === null)) {
        hits["k8s-image-latest"].push({ file: rel, line: i + 1, snippet: line.trim() });
      }
    }
  }

  // ClusterRoleBinding referencing cluster-admin
  if (kind === "ClusterRoleBinding" || kind === "RoleBinding") {
    if (/name:\s*['"]?cluster-admin['"]?/m.test(content)) {
      hits["k8s-cluster-admin-binding"].push({ file: rel, line: 0, snippet: `${kind} binds cluster-admin` });
    }
  }

  return hits;
}

function collect({ cwd = process.cwd(), env = process.env, args = {} } = {}) {
  const errors = [];
  const startTime = Date.now();
  const root = path.resolve(cwd);

  let files;
  try { files = walkTree(root); }
  catch (e) { errors.push({ kind: "walk_failed", reason: e.message }); files = []; }

  const dockerfiles = [];
  const composeFiles = [];
  const k8sManifests = [];
  for (const f of files) {
    const c = classify(f);
    if (c.isDockerfile) dockerfiles.push(f);
    if (c.isCompose) composeFiles.push(f);
    if (c.isYaml && !c.isCompose) {
      const content = readSafe(f.full);
      if (content && looksLikeK8sManifest(content)) k8sManifests.push({ ...f, content });
    }
  }

  // Aggregate hits per indicator.
  const allHits = {};
  for (const id of [
    "dockerfile-from-latest", "dockerfile-no-digest-pin", "dockerfile-runs-as-root", "dockerfile-curl-pipe-bash",
    "compose-privileged", "compose-cap-add-sys-admin", "compose-host-network", "compose-docker-sock-mount",
    "k8s-privileged", "k8s-host-namespaces", "k8s-run-as-root", "k8s-hostpath-sensitive",
    "k8s-image-latest", "k8s-cluster-admin-binding",
  ]) allHits[id] = [];

  for (const f of dockerfiles) {
    const content = readSafe(f.full);
    if (!content) {
      errors.push({ artifact_id: "dockerfile-content", kind: "read_failed", reason: `${f.rel}: read returned null` });
      continue;
    }
    const fileHits = scanDockerfile(content, f.rel);
    for (const [id, list] of Object.entries(fileHits)) allHits[id].push(...list);
  }
  for (const f of composeFiles) {
    const content = readSafe(f.full);
    if (!content) {
      errors.push({ artifact_id: "compose-files", kind: "read_failed", reason: `${f.rel}: read returned null` });
      continue;
    }
    const fileHits = scanCompose(content, f.rel);
    for (const [id, list] of Object.entries(fileHits)) allHits[id].push(...list);
  }
  for (const f of k8sManifests) {
    const fileHits = scanK8s(f.content, f.rel);
    for (const [id, list] of Object.entries(fileHits)) allHits[id].push(...list);
  }

  // signal_overrides — flip every indicator the collector can decide
  // deterministically. (k8s-no-seccomp-profile / psa-policy-* /
  // network-policies-absent require cluster-API access the collector
  // doesn't have; leave them unflipped so the runner returns
  // inconclusive rather than a forced miss.)
  const signal_overrides = {};
  for (const [id, list] of Object.entries(allHits)) {
    signal_overrides[id] = list.length > 0 ? "hit" : "miss";
  }

  const summarize = (list, limit = 5) => {
    if (list.length === 0) return "0 hits";
    const sample = list.slice(0, limit).map(h => `${h.file}:${h.line}`).join(", ");
    return `${list.length} hit(s): ${sample}${list.length > limit ? ", …" : ""}`;
  };

  const artifacts = {
    "dockerfile-inventory": {
      value: dockerfiles.length ? dockerfiles.map(f => f.rel).join(", ") : "no Dockerfiles found",
      captured: true,
    },
    "dockerfile-content": {
      value: dockerfiles.length
        ? `${dockerfiles.length} file(s) scanned; per-indicator hits: ` +
          [
            `from-latest=${summarize(allHits["dockerfile-from-latest"])}`,
            `no-digest-pin=${summarize(allHits["dockerfile-no-digest-pin"])}`,
            `runs-as-root=${summarize(allHits["dockerfile-runs-as-root"])}`,
            `curl-pipe-bash=${summarize(allHits["dockerfile-curl-pipe-bash"])}`,
          ].join("; ")
        : "no Dockerfile content to scan",
      captured: true,
    },
    "compose-files": {
      value: composeFiles.length ? composeFiles.map(f => f.rel).join(", ") : "no docker-compose files found",
      captured: true,
    },
    "k8s-manifests": {
      value: k8sManifests.length
        ? k8sManifests.map(f => `${f.rel} (kind=${extractKind(f.content) || "?"})`).join(", ")
        : "no k8s manifests found",
      captured: true,
    },
  };

  return {
    precondition_checks: {
      "container-tooling-available": true,
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
      files_walked: files.length,
      dockerfiles_found: dockerfiles.length,
      compose_files_found: composeFiles.length,
      k8s_manifests_found: k8sManifests.length,
    },
    collector_errors: errors,
  };
}

module.exports = { playbook_id: COLLECTOR_ID, collect };
