"use strict";

/**
 * Companion collector for the `secrets` playbook: walks the cwd tree, classifies
 * artifact files, regex-scans text content, and stats permission posture on the
 * carriers (POSIX only). Interface: lib/collectors/README.md
 */

const fs = require("node:fs");
const path = require("node:path");
const { codeExcludeSet, walkTree, buildEvidenceLocations, lineFromOffset } = require("./scan-excludes");

const COLLECTOR_ID = "secrets";

// Depth and exclusions mirror the secrets playbook's `look.artifacts[repo-tree]`;
// the exclusions come from the shared code-scope policy.
const DEFAULT_MAX_DEPTH = 6;
const DEFAULT_EXCLUDES = codeExcludeSet();

// Hits confined to these paths are downgraded; one hit outside them still fires.
// Mirrors the crypto-codebase collector's isTestPath.
const TEST_PATH_SEGMENTS = [
  "/test/", "/tests/", "/spec/", "/specs/", "/__tests__/",
  "/fixtures/", "/fixture/", "/examples/", "/example/",
  "/sample/", "/samples/", "/demo/", "/demos/",
  "/testdata/", "/test-data/", "/test_data/",
];

function isTestPath(rel) {
  const norm = "/" + rel.replace(/\\/g, "/").toLowerCase() + "/";
  for (const seg of TEST_PATH_SEGMENTS) {
    if (norm.includes(seg)) return true;
  }
  if (/\.(test|spec)\.[a-z]+$/i.test(rel)) return true;
  if (/(?:^|[\\/])[^\\/]+_test\.[a-z]+$/i.test(rel)) return true;
  // "test" inside the name itself: cosign-test.key, github-test-token.json.
  if (/-test[-.][^\\/]*$/i.test(rel)) return true;
  return false;
}

const ENV_FILE_PREDICATE = (name) => {
  if (name === ".env" || name === ".envrc") return true;
  if (name.startsWith(".env.")) return true;
  if (name.endsWith(".env")) return true;
  return false;
};

const AUTH_CONFIG_FILES = new Set([
  ".npmrc", ".pypirc", ".netrc", ".git-credentials",
  "config.json",   // .docker/config.json — caller checks parent dir
  ".yarnrc.yml", ".yarnrc",
  "settings.xml", "gradle.properties",
]);

const SSH_PRIVATE_KEY_FILES = new Set(["id_rsa", "id_ed25519", "id_ecdsa", "id_dsa"]);
const SSH_PRIVATE_KEY_EXTS = new Set([".pem", ".key", ".p12", ".pfx"]);
// `.pem` / `.key` are ambiguous — a cert chain is conventionally `.pem` — so only
// those two are content-gated; `.p12` / `.pfx` and id_* are private by nature.
const PEM_PRIVATE_KEY_MARKER = /-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----/;
const CONTENT_GATED_KEY_EXTS = new Set([".pem", ".key"]);
function carriesPrivateKey(file) {
  const ext = path.extname(file.name).toLowerCase();
  if (!CONTENT_GATED_KEY_EXTS.has(ext)) return true; // .p12/.pfx/id_* → private by nature
  let fd;
  try {
    fd = fs.openSync(file.full, "r");
    const st = fs.fstatSync(fd); // fstat on the open fd — no stat-then-read race
    if (st.size > MAX_FILE_BYTES) return true; // too big to scan → conservative
    // readFileSync on the open fd, never readSync: a short read NUL-pads the tail,
    // and a BEGIN marker past that boundary (a .pem with a leading `Bag Attributes`
    // header) would test false and drop a real key. Also preserves open→fstat order.
    const content = fs.readFileSync(fd, "utf8");
    return PEM_PRIVATE_KEY_MARKER.test(content);
  } catch {
    return true; // unreadable → conservative (treat as a key)
  } finally {
    if (fd !== undefined) { try { fs.closeSync(fd); } catch { /* non-fatal */ } }
  }
}

const IAC_EXTS = new Set([".tf", ".tfvars", ".bicep"]);
const IAC_EXACT = new Set(["terraform.tfstate", "values.yaml", "secret.yaml"]);
const IAC_GLOB_PREFIX = ["pulumi.", "arm."];

// The patterns and demotions below mirror data/playbooks/secrets.json's
// detect.indicators[] — the playbook is the source of truth for what counts as a hit.
// AWS's published example access-key ID appears verbatim across docs and READMEs;
// `cred-stores` demotes the same value in its FP[0].
const AWS_EXAMPLE_ACCESS_KEY_IDS = new Set([
  "AKIAIOSFODNN7EXAMPLE",
]);

// AWS's published sample secret key; aws-secret-access-key FP[1] demotes it.
const AWS_EXAMPLE_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

// Substrings the API-key indicators' FP[0] checks demote as documentation material.
const PLACEHOLDER_RE = /placeholder|example|redacted|dummy|x{4,}|0{6,}|1234567890/i;

// Documentation paths the FP checks treat as fixture material, atop TEST_PATH_SEGMENTS.
const DOC_PATH_SEGMENTS = [
  "/docs/", "/doc/", "/sdk-quickstart/", "/quickstart/", "/docs-snippet/",
];

function isDocOrTestPath(rel) {
  if (isTestPath(rel)) return true;
  const norm = "/" + rel.replace(/\\/g, "/").toLowerCase() + "/";
  return DOC_PATH_SEGMENTS.some((seg) => norm.includes(seg));
}

// The false_positive_checks_required indices (as strings) this hit survives. Indices
// needing network reachability or operator judgement are omitted, so the runner
// downgrades to inconclusive rather than over-attesting. `window` is a context slice.
function fpIndicesSatisfied(indicatorId, value, file, window) {
  const sat = new Set();
  const notDocPath = !isDocOrTestPath(file);
  switch (indicatorId) {
    case "aws-secret-access-key": {
      // [0] co-occurrence with an AKIA*/ASIA*/AGPA*/AIDA* id in a 10-line window
      if (/\b(?:AKIA|ASIA|AGPA|AIDA)[0-9A-Z]{12,}\b/.test(window)) sat.add("0");
      if (value !== AWS_EXAMPLE_SECRET_KEY) sat.add("1");
      if (notDocPath) sat.add("2");
      break;
    }
    case "slack-bot-or-user-token": {
      if (!PLACEHOLDER_RE.test(value)) sat.add("0");
      // [1] current Slack shape: 3+ dash-separated segments after the prefix
      if (value.split("-").length >= 4) sat.add("1");
      if (notDocPath) sat.add("2");
      break;
    }
    case "stripe-secret-key": {
      // [0] not a published sk_test_ sample; live keys fall to [2]
      if (!(value.startsWith("sk_test_") && PLACEHOLDER_RE.test(value))) sat.add("0");
      if (notDocPath) sat.add("1");
      // [2] live-validity probe is moot for a test key; sk_live_* needs operator auth
      if (value.startsWith("sk_test_") || value.startsWith("rk_test_")) sat.add("2");
      break;
    }
    case "openai-api-key": {
      if (!PLACEHOLDER_RE.test(value) && !/^sk-(?:test|dummy)-/i.test(value)) sat.add("0");
      // [1] post-prefix length meets the entropy floor
      if (value.replace(/^sk-(?:proj-|svcacct-|admin-)?/, "").length >= 48) sat.add("1");
      // [2] vendor disambiguation — sk-ant-* is Anthropic, not OpenAI
      if (!/^sk-ant-/i.test(value)) sat.add("2");
      break;
    }
    case "anthropic-api-key": {
      if (!PLACEHOLDER_RE.test(value) && !/^sk-ant-test-/i.test(value)) sat.add("0");
      if (notDocPath) sat.add("1");
      // [2] post-prefix length meets the entropy floor
      if (value.replace(/^sk-ant-(?:api03|admin01)-/, "").length >= 80) sat.add("2");
      break;
    }
    default:
      break;
  }
  return sat;
}

const INDICATOR_PATTERNS = [
  { id: "aws-access-key-id",          re: /\bAKIA[0-9A-Z]{16}\b/g },
  { id: "aws-secret-access-key",      re: /\baws_secret_access_key\s*[=:]\s*['"]?([A-Za-z0-9/+=]{40})['"]?/gi },
  // A full PEM block, not just the BEGIN header, so a doc placeholder or a DLP
  // library's own detection pattern does not register. The body class admits
  // backslash for JSON `\n` escapes and excludes `-` so the run halts — ReDoS-safe.
  { id: "gcp-service-account-json",   re: /"type"\s*:\s*"service_account"[\s\S]{0,1200}?"private_key"\s*:\s*"-----BEGIN PRIVATE KEY-----[A-Za-z0-9+/=\s\\]{40,4000}-----END/g },
  { id: "github-personal-access-token", re: /\bghp_[A-Za-z0-9]{36}\b/g },
  { id: "github-fine-grained-pat",    re: /\bgithub_pat_[A-Za-z0-9_]{82}\b/g },
  { id: "slack-bot-or-user-token",    re: /\bxox[abposr]-[A-Za-z0-9-]{10,}\b/g },
  { id: "stripe-secret-key",          re: /\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{24,}\b/g },
  { id: "jwt-token-with-secret-context", re: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g },
  // A complete PEM block, so a bare BEGIN header used as a DLP library's own
  // detection pattern does not register. `-` excluded from the body class halts
  // the run at `-----END` — no backtracking. Key *files* are found by presence.
  { id: "ssh-private-key-block",      re: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED |)PRIVATE KEY-----[A-Za-z0-9+/=\s]{20,4000}-----END/g },
  // `(?!ant-)` stops an Anthropic key double-firing as openai-api-key too. The
  // optional prefix group still admits every real OpenAI shape, including the bare
  // legacy `sk-` key; the lookahead is anchored, so no ReDoS.
  { id: "openai-api-key",             re: /\bsk-(?!ant-)(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}\b/g },
  { id: "anthropic-api-key",          re: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/g },
];

const TEXT_EXTENSIONS = new Set([
  ".env", ".envrc", ".txt", ".md", ".json", ".yaml", ".yml", ".toml",
  ".tf", ".tfvars", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx",
  ".py", ".rb", ".go", ".rs", ".java", ".cs", ".php", ".sh", ".bash",
  ".zsh", ".fish", ".ps1", ".psm1", ".bicep", ".html", ".xml", ".ini",
  ".conf", ".cfg", ".properties", ".gradle", ".sql", ".dockerfile",
]);
const TEXT_EXACT = new Set(["Dockerfile", "Makefile", "Procfile", ".env", ".envrc"]);
const MAX_FILE_BYTES = 1024 * 1024; // 1 MB per file content scan

function classify(file) {
  const name = file.name;
  const ext = path.extname(name).toLowerCase();
  const rel = file.rel;
  const isDockerConfig = /(^|\/|\\)\.docker\/config\.json$/.test(rel.replace(/\\/g, "/"));
  const isHelmValues = name === "values.yaml" || rel.toLowerCase().includes("/helm/");
  const isAnsible = (ext === ".yml" || ext === ".yaml") &&
    /(roles|group_vars|host_vars)\//.test(rel.replace(/\\/g, "/"));

  return {
    isEnv: ENV_FILE_PREDICATE(name),
    isAuthConfig: AUTH_CONFIG_FILES.has(name) || isDockerConfig,
    isSshKey:
      (SSH_PRIVATE_KEY_FILES.has(name) ||
        (SSH_PRIVATE_KEY_EXTS.has(ext) && !name.endsWith(".pub"))),
    isIac:
      IAC_EXTS.has(ext) || IAC_EXACT.has(name) || isHelmValues || isAnsible ||
      IAC_GLOB_PREFIX.some(p => name.startsWith(p) && (name.endsWith(".yaml") || name.endsWith(".yml") || name.endsWith(".json"))),
    isText: TEXT_EXACT.has(name) || TEXT_EXTENSIONS.has(ext) || name.endsWith(".env"),
  };
}

function statPosture(full) {
  try {
    const s = fs.statSync(full);
    const mode = s.mode & 0o777;
    return {
      mode,
      mode_octal: "0" + mode.toString(8),
      world_writable: (mode & 0o002) !== 0,
      world_readable: (mode & 0o004) !== 0,
      group_writable: (mode & 0o020) !== 0,
      group_readable: (mode & 0o040) !== 0,
    };
  } catch (e) {
    return { error: e.message };
  }
}

function redactMatch(literal) {
  if (literal.length <= 6) return "<redacted:" + literal.length + "ch>";
  return literal.slice(0, 4) + "…[" + (literal.length - 4) + "ch-redacted]";
}

function scanContent(full, rel) {
  let buf;
  try {
    // The cap is a byte limit, so measure the Buffer rather than stat first —
    // byte-accurate, and oversize is rejected before any UTF-8 decode.
    const raw = fs.readFileSync(full);
    if (raw.length > MAX_FILE_BYTES) return { skipped: "file_too_large", bytes: raw.length, hits: [] };
    buf = raw.toString("utf8");
  } catch (e) {
    return { skipped: "read_error", reason: e.message, hits: [] };
  }
  const hits = [];
  for (const p of INDICATOR_PATTERNS) {
    const matches = buf.matchAll(p.re);
    let count = 0;
    for (const m of matches) {
      // A README quoting the AWS docs must not hit.
      if (p.id === "aws-access-key-id" && AWS_EXAMPLE_ACCESS_KEY_IDS.has(m[0])) continue;
      // Group 1 when the pattern brackets the credential; else the whole match.
      const value = m[1] != null ? m[1] : m[0];
      // ±600 bytes — a deterministic proxy for "nearby lines" in the FP check.
      const winStart = Math.max(0, m.index - 600);
      const window = buf.slice(winStart, m.index + 600);
      hits.push({
        indicator_id: p.id,
        file: rel,
        offset: m.index,
        // 1-based, so buildEvidenceLocations emits a SARIF startLine region.
        line: lineFromOffset(buf, m.index),
        redacted_match: redactMatch(m[0]),
        // Attested so the runner does not downgrade hit → inconclusive.
        fp_satisfied: fpIndicesSatisfied(p.id, value, rel, window),
      });
      if (++count >= 5) break; // cap per-indicator-per-file
    }
  }
  return { hits };
}

function collect({ cwd = process.cwd(), env = process.env, args = {} } = {}) {
  const errors = [];
  const startTime = Date.now();
  const root = path.resolve(cwd);

  let files;
  const truncations = [];
  try {
    files = walkTree(root, { maxDepth: DEFAULT_MAX_DEPTH, excludes: DEFAULT_EXCLUDES, truncations });
  } catch (e) {
    errors.push({ kind: "walk_failed", reason: e.message });
    files = [];
  }
  // Subtrees pruned at the depth cap are NOT scanned; surface them so an unscanned
  // deep .env or id_rsa is an observable gap, not a silent miss.
  if (truncations.length) {
    errors.push({
      artifact_id: "repo-tree",
      kind: "depth_capped",
      reason: `${truncations.length} subtree(s) beyond depth ${DEFAULT_MAX_DEPTH} not scanned for secrets: ${truncations.slice(0, 20).map(t => t.rel).join(", ")}${truncations.length > 20 ? ", …" : ""}`,
      truncated_paths: truncations.slice(0, 50).map(t => t.rel),
      truncated_count: truncations.length,
    });
  }
  if (files.length > 50000) {
    errors.push({
      kind: "file_count_capped",
      reason: `walked ${files.length} files; capping content scan at 50000. Narrow the cwd or raise the cap explicitly.`,
    });
    files = files.slice(0, 50000);
  }

  const envFiles = [];
  const authConfigFiles = [];
  const sshPrivateKeys = [];
  const iacFiles = [];
  const textFiles = [];
  for (const f of files) {
    const c = classify(f);
    if (c.isEnv) envFiles.push(f);
    if (c.isAuthConfig) authConfigFiles.push(f);
    if (c.isSshKey && carriesPrivateKey(f)) sshPrivateKeys.push(f);
    if (c.isIac) iacFiles.push(f);
    if (c.isText) textFiles.push(f);
  }

  const worldWritablePosture = [];
  if (process.platform !== "win32") {
    const carriers = [...new Set([...envFiles, ...authConfigFiles, ...sshPrivateKeys].map(f => f.full))]
      .map(p => files.find(f => f.full === p))
      .filter(Boolean);
    for (const f of carriers) {
      const p = statPosture(f.full);
      if (p.world_writable || p.world_readable) {
        worldWritablePosture.push({ file: f.rel, ...p });
      }
    }
  }

  const allHits = [];
  for (const f of textFiles) {
    const r = scanContent(f.full, f.rel);
    if (r.hits) allHits.push(...r.hits);
    if (r.skipped === "read_error") {
      errors.push({ artifact_id: "secret-regex-scan-text-files", kind: "read_failed", reason: `${f.rel}: ${r.reason}` });
    } else if (r.skipped === "file_too_large") {
      // Record the skip, or a secret in an oversized file is dropped silently.
      errors.push({
        artifact_id: "secret-regex-scan-text-files",
        kind: "file_too_large_skipped",
        reason: `${f.rel}: ${r.bytes} bytes exceeds ${MAX_FILE_BYTES}-byte scan limit; not scanned for secrets`,
      });
    }
  }

  // The indicator fires only on a PROD hit; test-path hits stay in the artifact.
  const hitsByIndicator = {};
  const prodHitsByIndicator = {};
  for (const h of allHits) {
    (hitsByIndicator[h.indicator_id] = hitsByIndicator[h.indicator_id] || []).push(h);
    if (!isTestPath(h.file)) {
      (prodHitsByIndicator[h.indicator_id] = prodHitsByIndicator[h.indicator_id] || []).push(h);
    }
  }
  // The same split for the file-presence indicators, so a fixture key raises neither.
  const prodSshPrivateKeys = sshPrivateKeys.filter(f => !isTestPath(f.rel));

  const signal_overrides = {};
  for (const p of INDICATOR_PATTERNS) {
    signal_overrides[p.id] = prodHitsByIndicator[p.id] && prodHitsByIndicator[p.id].length > 0 ? "hit" : "miss";
  }
  // For each fired indicator, attest the FP indices EVERY surviving hit satisfies —
  // the intersection, since an index is universally true only if no hit fails it.
  // Without this, a real secret found by `collect` is downgraded after `run`.
  for (const p of INDICATOR_PATTERNS) {
    if (signal_overrides[p.id] !== "hit") continue;
    const hits = prodHitsByIndicator[p.id] || [];
    if (!hits.length || !hits[0].fp_satisfied) continue;
    let common = null;
    for (const h of hits) {
      const s = h.fp_satisfied || new Set();
      if (common === null) { common = new Set(s); continue; }
      for (const idx of [...common]) if (!s.has(idx)) common.delete(idx);
    }
    if (common && common.size) {
      const att = {};
      for (const idx of common) att[idx] = true;
      signal_overrides[`${p.id}__fp_checks`] = att;
    }
  }
  // Also flipped by file presence: a binary-only key format has no content match.
  if (prodSshPrivateKeys.length > 0) signal_overrides["ssh-private-key-block"] = "hit";
  // Per the playbook: any env-files entry with the group-write or world-write bit set.
  const envFilePostures = process.platform === "win32" ? [] : envFiles.map(f => ({ file: f.rel, ...statPosture(f.full) }));
  // POSIX mode bits are unreadable on win32, so the signal is OMITTED there — the
  // runner returns `inconclusive`, not a false `miss`. Same as cred-stores' bad-perms.
  if (process.platform !== "win32") {
    signal_overrides["world-writable-env-file"] = envFilePostures.some(p => p.error == null && (p.mode & 0o022) !== 0) ? "hit" : "miss";
  }

  // Per the playbook: any private key whose mode is not exactly 0600. ~/.ssh lies
  // outside the cwd walk root, so only keys discovered here are checked.
  const sshKeyPostures = process.platform === "win32" ? [] : prodSshPrivateKeys.map(f => ({ file: f.rel, ...statPosture(f.full) }));
  // Omitted on win32 for the same reason as world-writable-env-file.
  if (process.platform !== "win32") {
    signal_overrides["ssh-key-bad-perms"] = sshKeyPostures.some(p => p.error == null && p.mode !== 0o600) ? "hit" : "miss";
  }

  // Locations for every indicator flipped to "hit", so a SARIF result points at the
  // carrying file. A content hit carries a line and becomes a region.
  const evidence_locations = {};
  for (const p of INDICATOR_PATTERNS) {
    if (signal_overrides[p.id] === "hit") {
      const locs = buildEvidenceLocations(prodHitsByIndicator[p.id] || []);
      if (locs.length) evidence_locations[p.id] = locs;
    }
  }
  // Fold the discovered key files in alongside content hits, de-duplicated.
  if (signal_overrides["ssh-private-key-block"] === "hit") {
    const locs = buildEvidenceLocations([
      ...(prodHitsByIndicator["ssh-private-key-block"] || []),
      ...prodSshPrivateKeys,
    ]);
    if (locs.length) evidence_locations["ssh-private-key-block"] = locs;
  }
  if (signal_overrides["world-writable-env-file"] === "hit") {
    const locs = buildEvidenceLocations(
      envFilePostures.filter(p => p.error == null && (p.mode & 0o022) !== 0),
    );
    if (locs.length) evidence_locations["world-writable-env-file"] = locs;
  }
  if (signal_overrides["ssh-key-bad-perms"] === "hit") {
    const locs = buildEvidenceLocations(
      sshKeyPostures.filter(p => p.error == null && p.mode !== 0o600),
    );
    if (locs.length) evidence_locations["ssh-key-bad-perms"] = locs;
  }

  const summarizeFiles = (list) => list.map(f => f.rel).join(", ");
  const artifacts = {
    "repo-tree": {
      value: `${files.length} file(s) walked (depth ≤ ${DEFAULT_MAX_DEPTH}, exclude ${[...DEFAULT_EXCLUDES].slice(0, 8).join("/")}/…)`,
      captured: true,
    },
    "env-files": {
      value: envFiles.length ? summarizeFiles(envFiles) : "none found",
      captured: true,
    },
    "auth-config-files": {
      value: authConfigFiles.length ? summarizeFiles(authConfigFiles) : "none found",
      captured: true,
    },
    "ssh-private-keys": {
      value: sshPrivateKeys.length ? summarizeFiles(sshPrivateKeys) : "none found",
      captured: true,
    },
    "iac-credential-bearers": {
      value: iacFiles.length ? summarizeFiles(iacFiles) : "none found",
      captured: true,
    },
    "secret-regex-scan-text-files": {
      value: allHits.length
        ? `${allHits.length} hit(s): ` + allHits.slice(0, 20).map(h => `${h.indicator_id}@${h.file}:${h.offset} ${h.redacted_match}`).join("; ") + (allHits.length > 20 ? "; …" : "")
        : `scanned ${textFiles.length} text file(s); 0 hits`,
      captured: true,
    },
    "world-writable-secret-files": {
      value: process.platform === "win32"
        ? "skipped on win32 (POSIX mode bits not load-bearing)"
        : (worldWritablePosture.length
          ? worldWritablePosture.map(p => `${p.file} (mode ${p.mode_octal}, wr=${p.world_writable}, rd=${p.world_readable})`).join("; ")
          : "scanned for world-writable; 0 carriers above 0644"),
      captured: process.platform !== "win32",
      reason: process.platform === "win32" ? "POSIX mode bits not meaningful on Windows; ACL audit out of scope" : undefined,
    },
  };

  return {
    precondition_checks: {
      "repo-context": true,
      "regex-engine": true,
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
      text_files_scanned: textFiles.length,
      hits_total: allHits.length,
    },
    collector_errors: errors,
  };
}

module.exports = { playbook_id: COLLECTOR_ID, collect };
