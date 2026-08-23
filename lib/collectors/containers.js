"use strict";

/**
 * Companion collector for the `containers` playbook: walks the cwd for
 * Dockerfile / Containerfile, compose and k8s manifest files and applies the
 * catalogued indicator predicates. YAML is line-scanned, never parsed — every
 * catalogued indicator is an unambiguous single-line pattern.
 *
 * Interface: see lib/collectors/README.md
 */

const fs = require("node:fs");
const path = require("node:path");
const { codeExcludeSet, walkTree, buildEvidenceLocations } = require("./scan-excludes");

const COLLECTOR_ID = "containers";

const DEFAULT_MAX_DEPTH = 6;
// Shared code-scope exclusions; no container-specific extras.
const DEFAULT_EXCLUDES = codeExcludeSet();

const DOCKERFILE_NAMES = new Set(["Dockerfile", "Containerfile"]);
const DOCKERFILE_EXTS = new Set([".dockerfile", ".containerfile"]);
const COMPOSE_NAMES = new Set([
  "docker-compose.yml", "docker-compose.yaml",
  "compose.yml", "compose.yaml",
]);
const COMPOSE_PREFIX = "docker-compose.";   // docker-compose.override.yml etc.

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
    // Byte-based cap on Buffer.length: oversized files are rejected before decode.
    const raw = fs.readFileSync(full);
    if (raw.length > max) return null;
    return raw.toString("utf8");
  } catch { return null; }
}

// Top-level `apiVersion:` + `kind:` is enough to recognise one without parsing.
function looksLikeK8sManifest(content) {
  if (!/^apiVersion:\s+\S/m.test(content)) return false;
  if (!/^kind:\s+\S/m.test(content)) return false;
  return true;
}

function extractKind(content) {
  const m = content.match(/^kind:\s+([A-Za-z][A-Za-z0-9]*)/m);
  return m ? m[1] : null;
}

// Returns { <indicator id>: [{ file, line, snippet }] }; line 0 means the hit
// is whole-file rather than a specific line.
function scanDockerfile(content, rel) {
  const lines = content.split(/\r?\n/);
  const hits = {
    "dockerfile-from-latest": [],
    "dockerfile-no-digest-pin": [],
    "dockerfile-runs-as-root": [],
    "dockerfile-curl-pipe-bash": [],
  };

  // A FROM line with no execution-shape directive is a build-time probe, not a
  // runtime image; the runs-as-root predicate means nothing there.
  const isMetadataOnly = (() => {
    let sawFrom = false;
    let sawBuildOrRuntime = false;
    for (const raw of lines) {
      const t = raw.trim();
      if (!t || t.startsWith("#")) continue;
      if (/^FROM\b/i.test(t)) { sawFrom = true; continue; }
      if (/^(RUN|COPY|ADD|CMD|ENTRYPOINT|EXPOSE|VOLUME|WORKDIR|USER|HEALTHCHECK|ONBUILD|STOPSIGNAL|SHELL|ARG|ENV|LABEL)\b/i.test(t)) {
        // ARG / ENV / LABEL alone do not make a runtime image.
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
  // Aliases from `FROM <image> AS <alias>`. A later `FROM <alias>` is an internal
  // multi-stage reference, not a registry image, and owes no tag or digest.
  const stageAliases = new Set();
  // ARG defaults, used to resolve `FROM node:${NODE_VERSION}`. A digest pinned
  // through one is real pinning, and an unresolvable interpolation cannot be
  // proven to be `:latest`, so neither may be flagged from raw text.
  const argDefaults = new Map();
  const resolveArgs = (s) => {
    let interpolatedUnresolved = false;
    const out = s.replace(/\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)/g, (m, a, b) => {
      const name = a || b;
      const val = argDefaults.get(name);
      if (val !== undefined && val !== null) return val;
      interpolatedUnresolved = true;
      return m;
    });
    return { resolved: out, interpolatedUnresolved };
  };
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;

    // `ARG NAME=default` and bare `ARG NAME`; quotes come off the default.
    const argMatch = trimmed.match(/^ARG\s+([A-Za-z_][A-Za-z0-9_]*)(?:=(.*))?\s*$/i);
    if (argMatch) {
      const name = argMatch[1];
      if (argMatch[2] !== undefined) {
        argDefaults.set(name, argMatch[2].trim().replace(/^["']|["']$/g, ""));
      } else if (!argDefaults.has(name)) {
        argDefaults.set(name, undefined);
      }
      continue;
    }

    const fromMatch = trimmed.match(/^FROM\s+(\S+)(?:\s+AS\s+(\S+))?/i);
    if (fromMatch) {
      const rawRef = fromMatch[1];
      const alias = fromMatch[2];
      const { resolved: ref, interpolatedUnresolved } = resolveArgs(rawRef);
      // `scratch` and stage aliases are not registry images.
      if (ref !== "scratch" && !stageAliases.has(ref.toLowerCase())) {
        const hasDigest = /@sha256:[0-9a-f]{64}/i.test(ref);
        // An unresolved interpolation may carry a `--build-arg` digest: stay silent.
        if (!hasDigest && !interpolatedUnresolved) {
          hits["dockerfile-no-digest-pin"].push({ file: rel, line: i + 1, snippet: trimmed.slice(0, 120) });
        }
        // No tag counts as :latest — that is Docker's default.
        const tagMatch = ref.match(/:([^@]+)(?:@|$)/);
        const tag = tagMatch ? tagMatch[1] : null;
        if (!interpolatedUnresolved && (tag === "latest" || tag === null)) {
          hits["dockerfile-from-latest"].push({ file: rel, line: i + 1, snippet: trimmed.slice(0, 120) });
        }
      }
      // USER does not carry across build stages: a stage runs as its base image's
      // user (root) until its own USER directive, so an external FROM resets the
      // tracking. A `FROM <prior-stage-alias>` inherits and must not reset. Both
      // tests read the ARG-resolved `ref`, before this stage's alias is recorded.
      const isInternalStageRef = stageAliases.has(ref.toLowerCase());
      if (!isInternalStageRef) {
        sawNonRootUser = false;
        sawAnyUser = false;
      }
      if (alias) stageAliases.add(alias.toLowerCase());
      continue;
    }

    // Root is "root" or "0", with any group suffix; every other uid is non-root.
    const userMatch = trimmed.match(/^USER\s+(\S+)/i);
    if (userMatch) {
      sawAnyUser = true;
      const u = userMatch[1];
      const userPart = u.split(":")[0]; // strip optional :group
      if (userPart !== "0" && userPart !== "root") sawNonRootUser = true;
      continue;
    }

    if (
      /\b(?:curl|wget)\b[^|]*\|\s*(?:sh|bash|zsh)\b/.test(trimmed) ||
      /\b(?:curl|wget)\b[^&|;]*\s+&&\s+(?:sh|bash)\b/.test(trimmed)
    ) {
      hits["dockerfile-curl-pipe-bash"].push({ file: rel, line: i + 1, snippet: trimmed.slice(0, 120) });
    }
  }

  // Fires when the final stage carries no non-root USER; none defaults to root.
  if (!sawNonRootUser && !isMetadataOnly) {
    hits["dockerfile-runs-as-root"].push({ file: rel, line: 0, snippet: sawAnyUser ? "USER directive sets root/0" : "no USER directive (defaults to root)" });
  }

  return hits;
}

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
    // Skipping overlong lines keeps a crafted whitespace run from backtracking.
    if (line.length > 4096) continue;
    if (/^\s*#/.test(line)) continue;
    if (/^\s*privileged:\s*true\b/i.test(line)) hits["compose-privileged"].push({ file: rel, line: i + 1, snippet: line.trim() });
    // Per the playbook, any of network_mode / pid / ipc set to host.
    if (/^\s*network_mode:\s*['"]?host\b/i.test(line) ||
        /^\s*pid:\s*['"]?host['"]?\s*$/i.test(line) ||
        /^\s*ipc:\s*['"]?host['"]?\s*$/i.test(line)) {
      hits["compose-host-network"].push({ file: rel, line: i + 1, snippet: line.trim() });
    }
    // Per the playbook: risky caps under cap_add, inline list or `- ` items.
    const RISKY_CAPS_RE = /\b(?:CAP_)?(?:SYS_ADMIN|SYS_PTRACE|SYS_MODULE)\b/i;
    if (/cap_add:.*\[/i.test(line) && RISKY_CAPS_RE.test(line)) {
      hits["compose-cap-add-sys-admin"].push({ file: rel, line: i + 1, snippet: line.trim() });
    } else if (/^\s*-\s*['"]?(?:CAP_)?(?:SYS_ADMIN|SYS_PTRACE|SYS_MODULE)\b/i.test(line) &&
               lines.slice(Math.max(0, i - 5), i).some(l => /cap_add:/i.test(l))) {
      hits["compose-cap-add-sys-admin"].push({ file: rel, line: i + 1, snippet: line.trim() });
    }
    if (/\/var\/run\/docker\.sock/.test(line)) {
      hits["compose-docker-sock-mount"].push({ file: rel, line: i + 1, snippet: line.trim() });
    }
  }
  return hits;
}

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
    // Skipping overlong lines keeps a crafted whitespace run from backtracking.
    if (line.length > 4096) continue;
    if (/^\s*#/.test(line)) continue;
    if (/^\s*privileged:\s*true\b/i.test(line)) hits["k8s-privileged"].push({ file: rel, line: i + 1, snippet: line.trim() });
    if (/^\s*(hostNetwork|hostPID|hostIPC):\s*true\b/.test(line)) hits["k8s-host-namespaces"].push({ file: rel, line: i + 1, snippet: line.trim() });
    // Only the two clauses visible in the manifest; the playbook's third needs a
    // container runtime, so it stays with the runner.
    if (/^\s*runAsUser:\s*0\b/.test(line) ||
        /^\s*runAsNonRoot:\s*false\b/.test(line)) {
      hits["k8s-run-as-root"].push({ file: rel, line: i + 1, snippet: line.trim() });
    }
    const hpMatch = line.match(/^\s*path:\s*['"]?(\/(?:etc|proc|sys|var\/lib\/docker|var\/run|root|home)?\/?)['"]?\s*$/);
    if (hpMatch && lines.slice(Math.max(0, i - 3), i).some(l => /hostPath:/i.test(l))) {
      hits["k8s-hostpath-sensitive"].push({ file: rel, line: i + 1, snippet: line.trim() });
    }
    // Indentation and the `- ` marker are anchored once each: no overlapping runs.
    const imageMatch = line.match(/^[ \t]*(?:-[ \t]*)?image:\s*['"]?([^'"@\s]+)(?:@[^'"]+)?['"]?\s*$/);
    if (imageMatch) {
      const ref = imageMatch[1];
      const tagMatch = ref.match(/:([^/]+)$/);
      const tag = tagMatch ? tagMatch[1] : null;
      // Tested against the whole line: the capture above drops the @-suffix.
      const hasDigest = /@sha256:[0-9a-f]{64}/.test(line);
      if (!hasDigest && (tag === "latest" || tag === null)) {
        hits["k8s-image-latest"].push({ file: rel, line: i + 1, snippet: line.trim() });
      }
    }
  }

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
  try { files = walkTree(root, { maxDepth: DEFAULT_MAX_DEPTH, excludes: DEFAULT_EXCLUDES }); }
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

  // Only the indicators decidable from files on disk; the ones needing
  // cluster-API access stay unflipped, so the runner returns inconclusive.
  const signal_overrides = {};
  for (const [id, list] of Object.entries(allHits)) {
    signal_overrides[id] = list.length > 0 ? "hit" : "miss";
  }

  // Line 0 surfaces as a file-level SARIF location rather than a startLine.
  const evidence_locations = {};
  for (const [id, list] of Object.entries(allHits)) {
    if (signal_overrides[id] === "hit") {
      const locs = buildEvidenceLocations(list);
      if (locs.length) evidence_locations[id] = locs;
    }
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
    ...(Object.keys(evidence_locations).length ? { evidence_locations } : {}),
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

// `discover` calls this to decide whether to recommend `containers`, so it walks
// the same bounded tree and classifier the collector does. Filenames only,
// capped, and swallows a walk error so discovery cannot break on one.
function hasContainerArtifacts(cwd, { cap = 8 } = {}) {
  let files;
  try { files = walkTree(path.resolve(cwd || "."), { maxDepth: DEFAULT_MAX_DEPTH, excludes: DEFAULT_EXCLUDES }); }
  catch { return []; }
  const out = [];
  for (const f of files) {
    const c = classify(f);
    if (c.isDockerfile || c.isCompose) {
      out.push(f.rel);
      if (out.length >= cap) break;
    }
  }
  return out;
}

module.exports = { playbook_id: COLLECTOR_ID, collect, hasContainerArtifacts };
