"use strict";

/**
 * lib/collectors/secrets.js
 *
 * Companion collector for the `secrets` playbook. Walks the cwd
 * tree, identifies the artifact files (env / auth-config / ssh-keys /
 * iac-credential-bearers), runs the catalogued regex set against text
 * file contents, and stats permission posture on secret-carrier
 * files. Emits a submission with deterministic signal_overrides per
 * indicator that fired.
 *
 * Scope: any cwd. Cross-platform (Windows / macOS / Linux).
 * Permission-posture indicator only meaningful on POSIX hosts.
 *
 * Interface: see lib/collectors/README.md
 */

const fs = require("node:fs");
const path = require("node:path");
const { codeExcludeSet, isLinkedWorktreeDir, buildEvidenceLocations, lineFromOffset } = require("./scan-excludes");

const COLLECTOR_ID = "secrets";

// Walk depth + exclusion list mirrors the secrets playbook's
// `look.artifacts[repo-tree].source` declaration. Exclusions come from
// the shared code-scope policy (dependency caches, build output, VCS +
// agent/editor scratch including `.claude/`); no secrets-specific extras.
const DEFAULT_MAX_DEPTH = 6;
const DEFAULT_EXCLUDES = codeExcludeSet();

// Path segments that denote test / fixture / example material. Hits
// scoped exclusively to these paths are downgraded — a private-key
// block in `cosign-test.key` or a JWT literal in `_test.go` is
// expected test material, not a real secret. If at least one hit
// exists outside these paths, the indicator still fires. Mirrors
// the crypto-codebase collector's isTestPath shape.
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
  // foo.test.js / bar.spec.py — dot-separated convention.
  if (/\.(test|spec)\.[a-z]+$/i.test(rel)) return true;
  // foo_test.go (Go) / bar_test.py (some Python) — underscore convention.
  if (/(?:^|[\\/])[^\\/]+_test\.[a-z]+$/i.test(rel)) return true;
  // Files whose name itself includes the substring "test" before a
  // key extension (e.g. cosign-test.key, github-test-token.json).
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

const IAC_EXTS = new Set([".tf", ".tfvars", ".bicep"]);
const IAC_EXACT = new Set(["terraform.tfstate", "values.yaml", "secret.yaml"]);
const IAC_GLOB_PREFIX = ["pulumi.", "arm."];

// Indicator regex set — must mirror data/playbooks/secrets.json's
// detect.indicators[].value embedded patterns. The playbook is the
// source of truth for what counts as a hit; the collector
// implements the same patterns so its signal_overrides match what
// the runner would compute.
// AWS-published documentation/example access-key IDs. These appear verbatim
// throughout AWS docs, SDK samples, and countless READMEs, so a literal match
// is example material, not a leaked credential. `cred-stores` demotes the same
// value (its FP[0]); secrets.js must too or it false-positives on any README
// that quotes the AWS docs. The 40-char example secret
// (`wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY`) carries the literal `EXAMPLE`
// token, which the AWS-secret-access-key pattern already requires elsewhere;
// the access-key ID is the one that needs an explicit allowlist.
const AWS_EXAMPLE_ACCESS_KEY_IDS = new Set([
  "AKIAIOSFODNN7EXAMPLE",
]);

const INDICATOR_PATTERNS = [
  { id: "aws-access-key-id",          re: /\bAKIA[0-9A-Z]{16}\b/g },
  { id: "aws-secret-access-key",      re: /\baws_secret_access_key\s*[=:]\s*['"]?([A-Za-z0-9/+=]{40})['"]?/gi },
  { id: "gcp-service-account-json",   re: /"type"\s*:\s*"service_account"[\s\S]{0,1200}?"private_key"\s*:\s*"-----BEGIN PRIVATE KEY-----/g },
  { id: "github-personal-access-token", re: /\bghp_[A-Za-z0-9]{36}\b/g },
  { id: "github-fine-grained-pat",    re: /\bgithub_pat_[A-Za-z0-9_]{82}\b/g },
  { id: "slack-bot-or-user-token",    re: /\bxox[abposr]-[A-Za-z0-9-]{10,}\b/g },
  { id: "stripe-secret-key",          re: /\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{24,}\b/g },
  { id: "jwt-token-with-secret-context", re: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g },
  { id: "ssh-private-key-block",      re: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED |)PRIVATE KEY-----/g },
  { id: "openai-api-key",             re: /\bsk-(?:proj-|svcacct-|admin-|)[A-Za-z0-9_-]{20,}\b/g },
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

function walkTree(root, opts = {}) {
  const maxDepth = opts.maxDepth ?? DEFAULT_MAX_DEPTH;
  const excludes = opts.excludes ?? DEFAULT_EXCLUDES;
  const out = [];
  const seen = new Set();

  function walk(dir, depth) {
    if (depth > maxDepth) return;
    let entries;
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); }
    catch { return; }
    for (const entry of entries) {
      if (excludes.has(entry.name)) continue;
      const full = path.join(dir, entry.name);
      let real;
      try { real = fs.realpathSync(full); } catch { continue; }
      if (seen.has(real)) continue;
      seen.add(real);
      if (entry.isDirectory()) {
        // Skip linked git worktrees (their `.git` is a gitdir pointer
        // file). Agent tooling stamps full repo copies under
        // `.claude/worktrees/<id>/`; descending into them rescans the
        // same files and inflates secret-carrier hit counts.
        if (isLinkedWorktreeDir(full)) continue;
        walk(full, depth + 1);
      } else if (entry.isFile()) {
        out.push({ full, rel: path.relative(root, full), name: entry.name });
      }
    }
  }
  walk(root, 0);
  return out;
}

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
    const s = fs.statSync(full);
    if (s.size > MAX_FILE_BYTES) return { skipped: "file_too_large", bytes: s.size, hits: [] };
    buf = fs.readFileSync(full, "utf8");
  } catch (e) {
    return { skipped: "read_error", reason: e.message, hits: [] };
  }
  const hits = [];
  for (const p of INDICATOR_PATTERNS) {
    const matches = buf.matchAll(p.re);
    let count = 0;
    for (const m of matches) {
      // Demote AWS-published example access-key IDs (e.g. the docs' canonical
      // AKIAIOSFODNN7EXAMPLE). A README quoting the AWS docs must not hit.
      if (p.id === "aws-access-key-id" && AWS_EXAMPLE_ACCESS_KEY_IDS.has(m[0])) continue;
      hits.push({
        indicator_id: p.id,
        file: rel,
        offset: m.index,
        // 1-based line of the match so buildEvidenceLocations emits a region
        // (SARIF startLine) instead of a bare file-level location.
        line: lineFromOffset(buf, m.index),
        redacted_match: redactMatch(m[0]),
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
  try {
    files = walkTree(root);
  } catch (e) {
    errors.push({ kind: "walk_failed", reason: e.message });
    files = [];
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
    if (c.isSshKey) sshPrivateKeys.push(f);
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
      // A secret in the first bytes of a large file would otherwise be
      // dropped silently. Record the skip so the operator knows this file
      // was NOT scanned (mirrors crypto-codebase's >1 MB read_failed entry).
      errors.push({
        artifact_id: "secret-regex-scan-text-files",
        kind: "file_too_large_skipped",
        reason: `${f.rel}: ${r.bytes} bytes exceeds ${MAX_FILE_BYTES}-byte scan limit; not scanned for secrets`,
      });
    }
  }

  // Split hits into production vs test-path. The indicator fires
  // only when at least one PROD hit exists. Test-only hits stay in
  // the artifact for operator inspection but don't flip the signal.
  const hitsByIndicator = {};
  const prodHitsByIndicator = {};
  for (const h of allHits) {
    (hitsByIndicator[h.indicator_id] = hitsByIndicator[h.indicator_id] || []).push(h);
    if (!isTestPath(h.file)) {
      (prodHitsByIndicator[h.indicator_id] = prodHitsByIndicator[h.indicator_id] || []).push(h);
    }
  }
  // Same split for the file-presence indicators (ssh-private-keys
  // artifact backs the ssh-private-key-block content scan AND the
  // ssh-key-bad-perms posture check below). Filter out test-named
  // private-key files (e.g. cosign-test.key) for the signal too.
  const prodSshPrivateKeys = sshPrivateKeys.filter(f => !isTestPath(f.rel));

  const signal_overrides = {};
  for (const p of INDICATOR_PATTERNS) {
    signal_overrides[p.id] = prodHitsByIndicator[p.id] && prodHitsByIndicator[p.id].length > 0 ? "hit" : "miss";
  }
  // ssh-private-key-block is also flipped by file presence (a private
  // key file with the matching magic bytes counts even without a
  // content scan match — e.g. binary-only key formats). Re-flip when
  // any non-test private-key file was discovered.
  if (prodSshPrivateKeys.length > 0) signal_overrides["ssh-private-key-block"] = "hit";
  // world-writable-env-file predicate (per data/playbooks/secrets.json):
  //   restricted to env-files artifact entries
  //   any .env / .env.* / .envrc with mode 0666 or 0664 (group/world writable)
  // i.e. group-write OR world-write bit set (mode & 0o022).
  const envFilePostures = process.platform === "win32" ? [] : envFiles.map(f => ({ file: f.rel, ...statPosture(f.full) }));
  signal_overrides["world-writable-env-file"] = envFilePostures.some(p => p.error == null && (p.mode & 0o022) !== 0) ? "hit" : "miss";

  // ssh-key-bad-perms predicate (per playbook):
  //   restricted to ssh-private-keys artifact + ~/.ssh/id_* paths
  //   any private-key file with mode != 0600
  // The collector scope is the cwd; ~/.ssh enumeration is outside this
  // walk root. Within cwd, flag any discovered private key whose mode
  // is anything other than 0600 (strict).
  const sshKeyPostures = process.platform === "win32" ? [] : sshPrivateKeys.map(f => ({ file: f.rel, ...statPosture(f.full) }));
  signal_overrides["ssh-key-bad-perms"] = sshKeyPostures.some(p => p.error == null && p.mode !== 0o600) ? "hit" : "miss";

  // Per-indicator file locations for every indicator flipped to "hit", so
  // a SARIF result points at the file carrying the secret / bad posture.
  // Content-regex hits carry a 1-based `line` (derived from the match offset),
  // so these locations include a startLine region. The file-presence and
  // posture indicators contribute the carrier file path directly (file-level,
  // no line).
  const evidence_locations = {};
  for (const p of INDICATOR_PATTERNS) {
    if (signal_overrides[p.id] === "hit") {
      const locs = buildEvidenceLocations(prodHitsByIndicator[p.id] || []);
      if (locs.length) evidence_locations[p.id] = locs;
    }
  }
  // ssh-private-key-block also fires on private-key file presence — fold in
  // the discovered key files alongside any content-scan hits, de-duplicated.
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
