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
  let fd;
  try {
    fd = fs.openSync(full, "r");
    const s = fs.fstatSync(fd);
    if (s.size > max) return null;
    const buf = Buffer.alloc(s.size);
    fs.readSync(fd, buf, 0, s.size, 0);
    return buf.toString("utf8");
  } catch { return null; }
  finally { if (fd !== undefined) { try { fs.closeSync(fd); } catch { /* non-fatal */ } } }
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

// Capture the exported value so the false_positive_checks_required entries
// (placeholder demotion, entropy floor) can be evaluated. The export
// patterns above end at the prefix; widen to grab the trailing token.
const AI_KEY_VALUE_RE = {
  openai: /OPENAI_API_KEY\s*[= ]\s*['"]?(sk-[A-Za-z0-9_-]+)/,
  anthropic: /ANTHROPIC_API_KEY\s*[= ]\s*['"]?(sk-ant-[A-Za-z0-9_-]+)/,
  huggingface: /(?:HUGGINGFACE_TOKEN|HF_TOKEN)\s*[= ]\s*['"]?(hf_[A-Za-z0-9]+)/,
};
const PLACEHOLDER_RE = /placeholder|example|redacted|dummy|x{4,}|0{6,}|test-/i;

function scanShellRc(content) {
  if (!content) return [];
  const hits = [];
  for (const p of AI_KEY_PATTERNS) {
    if (p.re.test(content)) hits.push(p.id);
  }
  return hits;
}

// Deterministic false_positive_checks_required evaluation for
// cleartext-api-key-in-dotfile. Returns the satisfiable indices for the
// exports found across the canonical dotfiles (intersection — an index is
// only attested if every export satisfies it). Canonical home rc / dotfile
// paths are never under examples/tests/fixtures, so the path check [1] is
// always satisfied here.
function cleartextFpIndices(content) {
  const sat = new Set(["0", "1", "2"]);
  let sawAny = false;
  for (const [vendor, re] of Object.entries(AI_KEY_VALUE_RE)) {
    const m = content.match(re);
    if (!m) continue;
    sawAny = true;
    const value = m[1];
    // [0] not a documented placeholder / sk-test- fixture
    if (PLACEHOLDER_RE.test(value)) sat.delete("0");
    // [2] entropy floor: OpenAI sk-* >= 48 post-prefix, Anthropic sk-ant-* >= 40,
    //     HuggingFace hf_* >= 30.
    const floor = vendor === "openai" ? 48 : vendor === "anthropic" ? 40 : 30;
    const body = value.replace(/^sk-ant-(?:api03|admin01)-|^sk-(?:proj-|svcacct-|admin-)?|^hf_/, "");
    if (body.length < floor) sat.delete("2");
  }
  return sawAny ? sat : new Set();
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
  const accessKeyIds = [];
  for (const [name, kv] of Object.entries(profiles)) {
    // long-lived-aws-keys: aws_access_key_id present AND no
    // aws_session_token sibling (STS temporary creds carry the
    // session token; IAM-user long-lived keys do not).
    if (kv["aws_access_key_id"] && !kv["aws_session_token"]) {
      staticProfiles.push(name);
      accessKeyIds.push(kv["aws_access_key_id"]);
    }
  }
  return { staticProfiles, accessKeyIds };
}

// AWS-published sample credential pair — long-lived-aws-keys FP[0] demotes it.
const AWS_EXAMPLE_KEY_PARTS = new Set([
  "AKIAIOSFODNN7EXAMPLE",
  "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
]);

function parseGcloudAdc(content) {
  if (!content) return { hasServiceAccount: false };
  try {
    const j = JSON.parse(content);
    const hasServiceAccount = j?.type === "service_account";
    return {
      hasServiceAccount,
      privateKey: typeof j?.private_key === "string" ? j.private_key : "",
      clientEmail: typeof j?.client_email === "string" ? j.client_email : "",
    };
  } catch { return { hasServiceAccount: false }; }
}

function parseKubeStaticToken(content) {
  if (!content) return { found: false };
  // Same shape as cred-stores: token under user:, not auth-provider.
  const userKvRe = /^(\s+)(token|token-data)\s*:\s*(\S[^\n]*)/gm;
  let tokenValue = null;
  for (const m of content.matchAll(userKvRe)) {
    const upto = content.slice(0, m.index);
    const lastUserAt = upto.lastIndexOf("\n  user:");
    const lastAuthProviderAt = upto.lastIndexOf("auth-provider:");
    if (lastAuthProviderAt > lastUserAt) continue;
    const value = m[3];
    if (!value || value.startsWith("null")) continue;
    tokenValue = value.trim();
    break;
  }
  // Cluster server URL — FP[0] demotes local-only clusters.
  const serverM = content.match(/^\s*server:\s*(\S+)/m);
  return { found: tokenValue !== null, tokenValue, serverUrl: serverM ? serverM[1] : "" };
}

const LOCAL_CLUSTER_RE = /https?:\/\/(?:127\.0\.0\.1|localhost|\[::1\])[:/]|\.kind\b|minikube|k3d|docker-for-desktop|docker-desktop/i;
const CI_RUNNER_PATH_RE = /(?:^|[\\/])(?:home[\\/]runner|github[\\/]workspace|builds|workspace)[\\/]/i;

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
  let cleartextFp = null;
  for (const p of allKeyCarriers) {
    if (!fileExists(p)) continue;
    const c = readSafe(p);
    if (c == null) continue;
    const hits = scanShellRc(c);
    if (hits.length > 0) {
      cleartextHitsByFile[path.relative(home, p)] = hits;
      const fp = cleartextFpIndices(c);
      if (fp.size) {
        if (cleartextFp === null) cleartextFp = new Set(fp);
        else for (const idx of [...cleartextFp]) if (!fp.has(idx)) cleartextFp.delete(idx);
      }
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
  const kubeParsed = parseKubeStaticToken(kubeContent);
  const kubeStaticToken = kubeParsed.found;

  const signal_overrides = {
    "cleartext-api-key-in-dotfile": cleartextAnyHit ? "hit" : "miss",
    "long-lived-aws-keys": longLivedAws ? "hit" : "miss",
    "gcp-service-account-json": gcloudParsed.hasServiceAccount ? "hit" : "miss",
    "kubeconfig-with-static-token": kubeStaticToken ? "hit" : "miss",
  };

  // Per-indicator __fp_checks attestation. Each canonical-path credential
  // store the collector reads is never under an examples/tests/fixtures path,
  // so the path-based FP checks are satisfied; value-based checks (placeholder,
  // entropy, sample-credential, cluster-locality) are evaluated deterministically.
  // Network / sts-validity checks are left unattested so the runner still
  // downgrades those. Without this, a real cleartext key or static token
  // surfaced by `collect` is downgraded to inconclusive after `run`.
  if (cleartextAnyHit && cleartextFp && cleartextFp.size) {
    const att = {};
    for (const idx of cleartextFp) att[idx] = true;
    signal_overrides["cleartext-api-key-in-dotfile__fp_checks"] = att;
  }
  if (longLivedAws) {
    const att = {};
    // [0] none of the access-key ids are the AWS-published sample pair
    if (!(awsParsed.accessKeyIds || []).some((k) => AWS_EXAMPLE_KEY_PARTS.has(k))) att["0"] = true;
    // [1] ~/.aws/credentials is a canonical home path, not an examples/test path
    att["1"] = true;
    // [2] sts get-caller-identity needs network — left unattested.
    if (Object.keys(att).length) signal_overrides["long-lived-aws-keys__fp_checks"] = att;
  }
  if (gcloudParsed.hasServiceAccount) {
    const att = {};
    // [0] private_key is a real PEM body (>= 1000 chars), not PLACEHOLDER/REDACTED
    const pk = gcloudParsed.privateKey || "";
    if (pk.length >= 1000 && !/PLACEHOLDER|REDACTED/i.test(pk)) att["0"] = true;
    // [1] client_email is a real *@*.gserviceaccount.com (not example/test)
    const ce = gcloudParsed.clientEmail || "";
    if (/@[^@\s]+\.gserviceaccount\.com$/i.test(ce) && !/@example\.com$|@test\./i.test(ce)) att["1"] = true;
    // [2] canonical ADC path (not under examples/) AND no GOOGLE_APPLICATION_CREDENTIALS
    //     redirecting away from it
    if (!(env && env.GOOGLE_APPLICATION_CREDENTIALS)) att["2"] = true;
    if (Object.keys(att).length) signal_overrides["gcp-service-account-json__fp_checks"] = att;
  }
  if (kubeStaticToken) {
    const att = {};
    // [0] cluster server URL is not a local-only dev cluster
    if (kubeParsed.serverUrl && !LOCAL_CLUSTER_RE.test(kubeParsed.serverUrl)) att["0"] = true;
    // [1] token is not a short kind/minikube bootstrap-token shape
    if (kubeParsed.tokenValue && kubeParsed.tokenValue.length >= 40 && !/^[a-z0-9]{6}\.[a-z0-9]{16}$/.test(kubeParsed.tokenValue)) att["1"] = true;
    // [2] kubeconfig is not inside a CI runner workspace
    if (!CI_RUNNER_PATH_RE.test(kubeCfgPath)) att["2"] = true;
    if (Object.keys(att).length) signal_overrides["kubeconfig-with-static-token__fp_checks"] = att;
  }

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
