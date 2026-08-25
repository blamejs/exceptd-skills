"use strict";

/**
 * Companion collector for the `ai-api` playbook: scans shell rc files for
 * cleartext AI API key exports, plus ~/.aws, ~/.kube and ~/.config/gcloud for
 * long-lived credentials likely to authenticate against AI APIs.
 * Interface: see lib/collectors/README.md
 */

const fs = require("node:fs");
const path = require("node:path");
const os = require("node:os");

const COLLECTOR_ID = "ai-api";

// One definition, named at every call site. Written as a literal in both the
// default and the callers, the two drift apart the moment the cap is raised,
// and the only symptom is a credential store that quietly stops being scanned
// at the old size.
const SCAN_CAP_BYTES = 256 * 1024;

// `skip` routes a non-read onto the collector_errors channel:
// { errors, artifact_id, label }. A null return is indistinguishable between
// "over the cap" and "unreadable", and both mean the file went unscanned — a
// clean verdict over an unscanned credential store is the failure mode, so the
// reason travels with the submission. `label` is home-relative: the absolute
// path is operator-identifying and collector_meta already carries `home`.
function readSafe(full, max = SCAN_CAP_BYTES, skip = null) {
  const note = (kind, reason) => {
    if (!skip || !Array.isArray(skip.errors)) return;
    const entry = { kind, reason: `${skip.label || path.basename(full)}: ${reason}` };
    if (skip.artifact_id) entry.artifact_id = skip.artifact_id;
    skip.errors.push(entry);
  };
  let fd;
  try {
    fd = fs.openSync(full, "r");
    const s = fs.fstatSync(fd);
    if (s.size > max) {
      note("file_too_large_skipped", `${s.size} bytes exceeds ${max}-byte scan limit; not scanned`);
      return null;
    }
    // readFileSync(fd) loops to EOF; a single readSync can return short on a
    // network or FUSE fd. Reading the open fd keeps fstat-then-read TOCTOU-free.
    return fs.readFileSync(fd, "utf8");
  } catch (e) {
    note("read_failed", e.message);
    return null;
  }
  finally { if (fd !== undefined) { try { fs.closeSync(fd); } catch { /* non-fatal */ } } }
}

function fileExists(full) {
  try { return fs.statSync(full).isFile(); } catch { return false; }
}

// A credential store is one of three things, and only "absent" is a negative
// finding. Truthiness collapses the other two: an empty file reads as "" and is
// a completed scan, not a skipped one, while readSafe signals a skip with null.
// The distinction is null-vs-string, and it drives the artifact's captured flag
// and the indicator's verdict together so the two cannot disagree.
const ABSENT = "absent";
const UNREAD = "unread";
const READ = "read";
function storeState(exists, content) {
  if (!exists) return ABSENT;
  return content === null ? UNREAD : READ;
}

// A store that was never read cannot answer the question its indicator asks.
// `miss` there is a clean bill of health over an unscanned file; a hit stands
// on its own evidence and is unaffected by a sibling going unread.
function verdict(found, undetermined) {
  if (found) return "hit";
  return undetermined ? "inconclusive" : "miss";
}

// Cleartext key exports: `export VAR=value`, `VAR=value`, fish `set -gx VAR value`.
const AI_KEY_PATTERNS = [
  { id: "openai",       re: /(?:^|\n)\s*(?:export\s+|set\s+-gx\s+)?OPENAI_API_KEY\s*[= ]\s*['"]?sk-[A-Za-z0-9_-]{20,}/m },
  { id: "anthropic",    re: /(?:^|\n)\s*(?:export\s+|set\s+-gx\s+)?ANTHROPIC_API_KEY\s*[= ]\s*['"]?sk-ant-[A-Za-z0-9_-]{20,}/m },
  { id: "azure",        re: /(?:^|\n)\s*(?:export\s+|set\s+-gx\s+)?AZURE_OPENAI(?:_API)?_KEY\s*[= ]\s*['"]?[A-Za-z0-9]{20,}/m },
  { id: "google",       re: /(?:^|\n)\s*(?:export\s+|set\s+-gx\s+)?(?:GOOGLE_API_KEY|GOOGLE_GENAI_API_KEY|GEMINI_API_KEY)\s*[= ]\s*['"]?[A-Za-z0-9_-]{20,}/m },
  { id: "huggingface",  re: /(?:^|\n)\s*(?:export\s+|set\s+-gx\s+)?(?:HUGGINGFACE_TOKEN|HF_TOKEN)\s*[= ]\s*['"]?hf_[A-Za-z0-9]{20,}/m },
  { id: "cohere",       re: /(?:^|\n)\s*(?:export\s+|set\s+-gx\s+)?COHERE_API_KEY\s*[= ]\s*['"]?[A-Za-z0-9-]{30,}/m },
];

// The patterns above end at the prefix; these capture the exported value so
// the placeholder and entropy-floor FP checks have something to evaluate.
const AI_KEY_VALUE_RE = {
  openai: /OPENAI_API_KEY\s*[= ]\s*['"]?(sk-[A-Za-z0-9_-]+)/,
  anthropic: /ANTHROPIC_API_KEY\s*[= ]\s*['"]?(sk-ant-[A-Za-z0-9_-]+)/,
  huggingface: /(?:HUGGINGFACE_TOKEN|HF_TOKEN)\s*[= ]\s*['"]?(hf_[A-Za-z0-9]+)/,
  // Azure, Google and Cohere keys carry no vendor prefix, so the captured value
  // IS the entropy body. Drop one of these and cleartextFpIndices attests nothing
  // for such a dotfile, downgrading a real hit to inconclusive.
  azure: /AZURE_OPENAI(?:_API)?_KEY\s*[= ]\s*['"]?([A-Za-z0-9]{20,})/,
  google: /(?:GOOGLE_API_KEY|GOOGLE_GENAI_API_KEY|GEMINI_API_KEY)\s*[= ]\s*['"]?([A-Za-z0-9_-]{20,})/,
  cohere: /COHERE_API_KEY\s*[= ]\s*['"]?([A-Za-z0-9-]{30,})/,
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

// The satisfiable false_positive_checks_required indices for
// cleartext-api-key-in-dotfile, intersected across every export found. Canonical
// home dotfiles are never under examples/tests/fixtures, so [1] always holds.
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
    // [2] entropy floor, post-prefix: OpenAI 48, Anthropic 40, others 30.
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
    // Long-lived means an access key id with no session-token sibling: STS
    // temporary credentials always carry one, IAM-user keys never do.
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
  } catch (e) {
    // Unparseable ADC is NOT evidence the file holds no service account; the
    // parse failure travels so `gcp-service-account-json: miss` is not read as
    // a clean bill of health.
    return { hasServiceAccount: false, parse_error: e.message };
  }
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

  const shellRcs = [
    ".bashrc", ".bash_profile", ".zshrc", ".zprofile", ".profile",
    path.join(".config", "fish", "config.fish"),
  ].map(rel => path.join(home, rel));
  try {
    const fishConfD = path.join(home, ".config", "fish", "conf.d");
    for (const e of fs.readdirSync(fishConfD)) {
      if (e.endsWith(".fish")) shellRcs.push(path.join(fishConfD, e));
    }
  } catch (e) {
    // No fish conf.d is the normal case. A permission or I/O failure on one that
    // IS there means those fragments went unscanned for key exports.
    if (e.code !== "ENOENT") {
      errors.push({
        artifact_id: "shell-rc-files",
        kind: "readdir_failed",
        reason: `.config/fish/conf.d: ${e.message} — fragments not scanned`,
      });
    }
  }

  const dotfileKeys = [
    ".openai", ".anthropic",
    path.join(".config", "anthropic"), path.join(".config", "openai"),
    ".gemini",
    path.join(".config", "google-genai"),
    path.join(".config", "azure-openai"),
  ].map(rel => path.join(home, rel));

  // Two artifacts share one scan loop. The carrier's own artifact_id travels
  // with it so a skipped `~/.anthropic` is reported against dotfile-api-keys
  // rather than pointing the operator at the shell-rc row.
  const allKeyCarriers = [
    ...shellRcs.map(p => ({ path: p, artifact_id: "shell-rc-files" })),
    ...dotfileKeys.map(p => ({ path: p, artifact_id: "dotfile-api-keys" })),
  ];
  const cleartextHitsByFile = {};
  const cleartextUnread = [];
  let cleartextFp = null;
  for (const { path: p, artifact_id } of allKeyCarriers) {
    if (!fileExists(p)) continue;
    const c = readSafe(p, SCAN_CAP_BYTES, {
      errors, artifact_id, label: path.relative(home, p),
    });
    // Present but unread: the file could still hold a key, so it is a gap in
    // the scan rather than a carrier with nothing in it.
    if (c === null) { cleartextUnread.push(path.relative(home, p)); continue; }
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

  const awsCredsPath = path.join(home, ".aws", "credentials");
  const awsCredsExists = fileExists(awsCredsPath);
  const awsCredsContent = awsCredsExists
    ? readSafe(awsCredsPath, SCAN_CAP_BYTES, {
      errors, artifact_id: "aws-credentials", label: path.relative(home, awsCredsPath),
    })
    : null;
  const awsParsed = parseAwsCredentials(awsCredsContent);
  const longLivedAws = awsParsed.staticProfiles.length > 0;

  const gcloudAdcPath = path.join(home, ".config", "gcloud", "application_default_credentials.json");
  const gcloudAdcExists = fileExists(gcloudAdcPath);
  const gcloudContent = gcloudAdcExists
    ? readSafe(gcloudAdcPath, SCAN_CAP_BYTES, {
      errors, artifact_id: "gcp-credentials", label: path.relative(home, gcloudAdcPath),
    })
    : null;
  const gcloudParsed = parseGcloudAdc(gcloudContent);
  if (gcloudParsed.parse_error) {
    errors.push({
      artifact_id: "gcp-credentials",
      kind: "parse_failed",
      reason: `${path.relative(home, gcloudAdcPath)}: ${gcloudParsed.parse_error} — service-account presence undetermined, not absent`,
    });
  }

  const kubeCfgPath = (env && env.KUBECONFIG) || path.join(home, ".kube", "config");
  // KUBECONFIG can point outside $HOME, where a home-relative label degrades to
  // a `..` chain; the basename is enough to name the file that went unread.
  // The separator is required: a bare prefix test also matches a SIBLING whose
  // name merely starts with $HOME ("/home/rob" vs "/home/robert-backup"), which
  // produces exactly the `../…` chain this branch exists to avoid — and leaks
  // another account's directory name into the warning.
  const kubeInHome = kubeCfgPath === home || kubeCfgPath.startsWith(home + path.sep);
  const kubeLabel = kubeInHome ? path.relative(home, kubeCfgPath) : path.basename(kubeCfgPath);
  const kubeCfgExists = fileExists(kubeCfgPath);
  const kubeContent = kubeCfgExists
    ? readSafe(kubeCfgPath, SCAN_CAP_BYTES, {
      errors, artifact_id: "kube-config", label: kubeLabel,
    })
    : null;
  const kubeParsed = parseKubeStaticToken(kubeContent);
  const kubeStaticToken = kubeParsed.found;

  const awsState = storeState(awsCredsExists, awsCredsContent);
  const gcloudState = storeState(gcloudAdcExists, gcloudContent);
  const kubeState = storeState(kubeCfgExists, kubeContent);

  const signal_overrides = {
    "cleartext-api-key-in-dotfile": verdict(cleartextAnyHit, cleartextUnread.length > 0),
    "long-lived-aws-keys": verdict(longLivedAws, awsState === UNREAD),
    // Unread and unparseable are the same answer here: nothing in the file was
    // validated, so its service-account presence is undetermined rather than
    // absent. JSON.parse never runs on an unread store, so the state carries it.
    "gcp-service-account-json": verdict(
      gcloudParsed.hasServiceAccount,
      gcloudState === UNREAD || Boolean(gcloudParsed.parse_error),
    ),
    "kubeconfig-with-static-token": verdict(kubeStaticToken, kubeState === UNREAD),
  };

  // Per-indicator __fp_checks attestation. Path checks hold because every store
  // read here is a canonical home path; network and STS-validity checks stay
  // unattested. With no attestation at all, a real hit downgrades to inconclusive.
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
    // [2] canonical ADC path, with no GOOGLE_APPLICATION_CREDENTIALS redirect
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
    // A null content is two different worlds: the store is not there, or it IS
    // there and went unread (over the scan cap, permissions, I/O). Only the
    // first is an absence. The second is captured:false with the reason on
    // collector_errors — asserting "absent" over a credential file that exists
    // is the same clean-verdict-over-an-unscanned-store failure the error
    // channel was added to close.
    "aws-credentials": awsState === READ
      ? { value: `${awsParsed.staticProfiles.length} long-lived profile(s): ${awsParsed.staticProfiles.join(", ") || "none"}`, captured: true }
      : awsState === UNREAD
        ? { value: "~/.aws/credentials present but unread — profile inventory undetermined, not absent", captured: false, reason: "read skipped or failed; see collector_errors for the reason" }
        : { value: "~/.aws/credentials absent", captured: true },
    // Read-but-unparseable is a fourth outcome, distinct from read, unread and
    // absent: the bytes arrived and nothing in them was validated. Reporting
    // captured:true there states service_account=false about a file never parsed.
    "gcp-credentials": gcloudState === READ && !gcloudParsed.parse_error
      ? { value: `application_default_credentials.json present; service_account=${gcloudParsed.hasServiceAccount}`, captured: true }
      : gcloudState === READ
        ? { value: "application_default_credentials.json present but unparseable — service-account presence undetermined, not absent", captured: false, reason: "JSON parse failed; see collector_errors for the reason" }
        : gcloudState === UNREAD
          ? { value: "application_default_credentials.json present but unread — service-account presence undetermined, not absent", captured: false, reason: "read skipped or failed; see collector_errors for the reason" }
          : { value: "no gcloud ADC at the canonical path", captured: true, reason: "credentials.db / legacy_credentials/*/adc.json inspection deferred (no stdlib SQLite reader)" },
    "kube-config": kubeState === READ
      ? { value: `kubeconfig present; static_token=${kubeStaticToken}`, captured: true }
      : kubeState === UNREAD
        ? { value: "kubeconfig present but unread — static-token presence undetermined, not absent", captured: false, reason: "read skipped or failed; see collector_errors for the reason" }
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
