"use strict";

/**
 * lib/collectors/ai-api.js
 *
 * Companion collector for the `ai-api` playbook. Scans shell rc
 * files for cleartext AI API key exports, plus the standard
 * credential carriers (~/.aws, ~/.kube, ~/.config/gcloud) for
 * long-lived credentials likely to authenticate against AI APIs.
 *
 * Non-deterministic indicators (ai-api-egress-from-unexpected-
 * process, ai-api-anomalous-volume, ai-api-beaconing-cadence,
 * base64-or-encoded-payload-in-prompts) require ss/netstat/auditd
 * traces and process-list correlation that fall outside the
 * stdlib-only collector contract. They stay unflipped — the runner
 * returns inconclusive and operator-supplied evidence completes
 * the verdict.
 *
 * Interface: see lib/collectors/README.md
 */

const fs = require("node:fs");
const path = require("node:path");
const os = require("node:os");

const COLLECTOR_ID = "ai-api";

function readSafe(full, max = 256 * 1024) {
  try {
    const s = fs.statSync(full);
    if (s.size > max) return null;
    return fs.readFileSync(full, "utf8");
  } catch { return null; }
}

function fileExists(full) {
  try { return fs.statSync(full).isFile(); } catch { return false; }
}

// Cleartext AI-API-key export patterns. Matches the standard
// `export VAR=value` and `VAR=value` shell shapes plus fish-style
// `set -gx VAR value`.
const AI_KEY_PATTERNS = [
  { id: "openai",       re: /(?:^|\n)\s*(?:export\s+|set\s+-gx\s+)?OPENAI_API_KEY\s*[= ]\s*['"]?sk-[A-Za-z0-9_-]{20,}/m },
  { id: "anthropic",    re: /(?:^|\n)\s*(?:export\s+|set\s+-gx\s+)?ANTHROPIC_API_KEY\s*[= ]\s*['"]?sk-ant-[A-Za-z0-9_-]{20,}/m },
  { id: "azure",        re: /(?:^|\n)\s*(?:export\s+|set\s+-gx\s+)?AZURE_OPENAI(?:_API)?_KEY\s*[= ]\s*['"]?[A-Za-z0-9]{20,}/m },
  { id: "google",       re: /(?:^|\n)\s*(?:export\s+|set\s+-gx\s+)?(?:GOOGLE_API_KEY|GOOGLE_GENAI_API_KEY|GEMINI_API_KEY)\s*[= ]\s*['"]?[A-Za-z0-9_-]{20,}/m },
  { id: "huggingface",  re: /(?:^|\n)\s*(?:export\s+|set\s+-gx\s+)?(?:HUGGINGFACE_TOKEN|HF_TOKEN)\s*[= ]\s*['"]?hf_[A-Za-z0-9]{20,}/m },
  { id: "cohere",       re: /(?:^|\n)\s*(?:export\s+|set\s+-gx\s+)?COHERE_API_KEY\s*[= ]\s*['"]?[A-Za-z0-9-]{30,}/m },
];

function scanShellRc(content) {
  if (!content) return [];
  const hits = [];
  for (const p of AI_KEY_PATTERNS) {
    if (p.re.test(content)) hits.push(p.id);
  }
  return hits;
}

function parseAwsCredentials(content) {
  if (!content) return { staticProfiles: [] };
  const lines = content.split(/\r?\n/);
  const profiles = {};
  let current = null;
  for (const raw of lines) {
    const line = raw.replace(/[#;].*$/, "").trim();
    if (!line) continue;
    const sec = line.match(/^\[([^\]]+)\]$/);
    if (sec) { current = sec[1].trim(); profiles[current] = {}; continue; }
    if (!current) continue;
    const kv = line.match(/^([A-Za-z0-9_-]+)\s*=\s*(.*)$/);
    if (!kv) continue;
    profiles[current][kv[1].trim().toLowerCase()] = kv[2].trim();
  }
  const staticProfiles = [];
  for (const [name, kv] of Object.entries(profiles)) {
    // long-lived-aws-keys: aws_access_key_id present AND no
    // aws_session_token sibling (STS temporary creds carry the
    // session token; IAM-user long-lived keys do not).
    if (kv["aws_access_key_id"] && !kv["aws_session_token"]) {
      staticProfiles.push(name);
    }
  }
  return { staticProfiles };
}

function parseGcloudAdc(content) {
  if (!content) return { hasServiceAccount: false };
  try {
    const j = JSON.parse(content);
    return { hasServiceAccount: j?.type === "service_account" };
  } catch { return { hasServiceAccount: false }; }
}

function parseKubeStaticToken(content) {
  if (!content) return false;
  // Same shape as cred-stores: token under user:, not auth-provider.
  const userKvRe = /^(\s+)(token|token-data)\s*:\s*(\S[^\n]*)/gm;
  let staticFound = false;
  for (const m of content.matchAll(userKvRe)) {
    const upto = content.slice(0, m.index);
    const lastUserAt = upto.lastIndexOf("\n  user:");
    const lastAuthProviderAt = upto.lastIndexOf("auth-provider:");
    if (lastAuthProviderAt > lastUserAt) continue;
    const value = m[3];
    if (!value || value.startsWith("null")) continue;
    staticFound = true;
    break;
  }
  return staticFound;
}

function collect({ cwd = process.cwd(), env = process.env, args = {} } = {}) {
  const errors = [];
  const startTime = Date.now();
  const root = path.resolve(cwd);
  const home = (env && env.HOME) || (env && env.USERPROFILE) || os.homedir();

  // Shell rc + dotfile candidates.
  const shellRcs = [
    ".bashrc", ".bash_profile", ".zshrc", ".zprofile", ".profile",
    path.join(".config", "fish", "config.fish"),
  ].map(rel => path.join(home, rel));
  // Glob fish/conf.d/*.
  try {
    const fishConfD = path.join(home, ".config", "fish", "conf.d");
    for (const e of fs.readdirSync(fishConfD)) {
      if (e.endsWith(".fish")) shellRcs.push(path.join(fishConfD, e));
    }
  } catch { /* fish not present */ }

  const dotfileKeys = [
    ".openai", ".anthropic",
    path.join(".config", "anthropic"), path.join(".config", "openai"),
    ".gemini",
    path.join(".config", "google-genai"),
    path.join(".config", "azure-openai"),
  ].map(rel => path.join(home, rel));

  const allKeyCarriers = [...shellRcs, ...dotfileKeys];
  const cleartextHitsByFile = {};
  for (const p of allKeyCarriers) {
    if (!fileExists(p)) continue;
    const c = readSafe(p);
    if (c == null) continue;
    const hits = scanShellRc(c);
    if (hits.length > 0) {
      cleartextHitsByFile[path.relative(home, p)] = hits;
    }
  }
  const cleartextAnyHit = Object.keys(cleartextHitsByFile).length > 0;

  // AWS / GCP / kube reuse.
  const awsCredsPath = path.join(home, ".aws", "credentials");
  const awsCredsContent = fileExists(awsCredsPath) ? readSafe(awsCredsPath) : null;
  const awsParsed = parseAwsCredentials(awsCredsContent);
  const longLivedAws = awsParsed.staticProfiles.length > 0;

  const gcloudAdcPath = path.join(home, ".config", "gcloud", "application_default_credentials.json");
  const gcloudContent = fileExists(gcloudAdcPath) ? readSafe(gcloudAdcPath) : null;
  const gcloudParsed = parseGcloudAdc(gcloudContent);

  const kubeCfgPath = (env && env.KUBECONFIG) || path.join(home, ".kube", "config");
  const kubeContent = fileExists(kubeCfgPath) ? readSafe(kubeCfgPath) : null;
  const kubeStaticToken = parseKubeStaticToken(kubeContent);

  const signal_overrides = {
    "cleartext-api-key-in-dotfile": cleartextAnyHit ? "hit" : "miss",
    "long-lived-aws-keys": longLivedAws ? "hit" : "miss",
    "gcp-service-account-json": gcloudParsed.hasServiceAccount ? "hit" : "miss",
    "kubeconfig-with-static-token": kubeStaticToken ? "hit" : "miss",
  };

  const artifacts = {
    "shell-rc-files": {
      value: cleartextAnyHit
        ? Object.entries(cleartextHitsByFile).map(([f, ids]) => `${f}: ${ids.join(",")}`).join("; ")
        : `scanned ${shellRcs.length} shell rc + ${dotfileKeys.length} dotfile path(s); no cleartext AI API key exports`,
      captured: true,
    },
    "dotfile-api-keys": {
      value: dotfileKeys.filter(p => fileExists(p)).map(p => path.relative(home, p)).join(", ") || "no AI vendor dotfile carriers found at the canonical paths",
      captured: true,
    },
    "aws-credentials": awsCredsContent
      ? { value: `${awsParsed.staticProfiles.length} long-lived profile(s): ${awsParsed.staticProfiles.join(", ") || "none"}`, captured: true }
      : { value: "~/.aws/credentials absent", captured: true },
    "gcp-credentials": gcloudContent
      ? { value: `application_default_credentials.json present; service_account=${gcloudParsed.hasServiceAccount}`, captured: true }
      : { value: "no gcloud ADC at the canonical path", captured: true, reason: "credentials.db / legacy_credentials/*/adc.json inspection deferred (no stdlib SQLite reader)" },
    "kube-config": kubeContent
      ? { value: `kubeconfig present; static_token=${kubeStaticToken}`, captured: true }
      : { value: "no kubeconfig at the canonical path", captured: true },
    "ai-sdk-inventory": {
      value: "skipped — npm/pip global listing deferred to operator/AI evidence",
      captured: false,
      reason: "spawning npm ls / pip list out of stdlib collector contract; operator should run those and submit as evidence",
    },
    "ai-api-egress-baseline": {
      value: "skipped — ss/netstat capture deferred to operator/AI evidence",
      captured: false,
      reason: "live socket / process correlation needs ss / netstat / auditd traces; operator-supplied evidence completes the verdict",
    },
    "process-list": {
      value: "skipped — ps -ef capture deferred to operator/AI evidence",
      captured: false,
      reason: "process-list correlation tied to network egress + behavioral signals out of stdlib collector scope",
    },
  };

  return {
    precondition_checks: {
      "home-dir-readable": fs.existsSync(home),
    },
    artifacts,
    signal_overrides,
    collector_meta: {
      collector_id: COLLECTOR_ID,
      collector_version: "2026-05-20",
      platform: process.platform,
      captured_at: new Date().toISOString(),
      cwd: root,
      home,
      duration_ms: Date.now() - startTime,
    },
    collector_errors: errors,
  };
}

module.exports = { playbook_id: COLLECTOR_ID, collect };
