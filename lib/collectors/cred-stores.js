"use strict";

/**
 * lib/collectors/cred-stores.js
 *
 * Companion collector for the `cred-stores` playbook. Inspects local
 * credential carriers (~/.aws/credentials, ~/.kube/config, ~/.docker/
 * config.json, ~/.npmrc, ~/.pypirc, ~/.config/gcloud/application_
 * default_credentials.json, project-level .npmrc / .pypirc), and
 * flips signal_overrides for the deterministic indicators. Defers
 * non-deterministic indicators (ssh-key-rsa-short-bits, ssh-key-old,
 * gpg-key-old-or-weak, all-stores-empty-or-federated) so the runner
 * returns inconclusive rather than a forced miss.
 *
 * Scope: $HOME credential dotfiles + project-level .npmrc / .pypirc
 * under cwd. Posix-mode-bits indicators are skipped on win32 (ACL
 * audit out of scope).
 *
 * Interface: see lib/collectors/README.md
 */

const fs = require("node:fs");
const path = require("node:path");
const os = require("node:os");

const COLLECTOR_ID = "cred-stores";

function readSafe(full, max = 512 * 1024) {
  try {
    const s = fs.statSync(full);
    if (s.size > max) return null;
    return fs.readFileSync(full, "utf8");
  } catch { return null; }
}

function statSafe(full) {
  try { return fs.statSync(full); } catch { return null; }
}

function modeOf(full) {
  const s = statSafe(full);
  if (!s) return null;
  return s.mode & 0o777;
}

function fileExists(full) {
  try { return fs.statSync(full).isFile(); } catch { return false; }
}

// AWS credentials INI: any [profile] block carrying
// `aws_access_key_id` AND no `sso_session` / `credential_process`.
function parseAwsCredentials(content) {
  if (!content) return { staticProfiles: [], federatedProfiles: [] };
  const lines = content.split(/\r?\n/);
  const profiles = {};
  let current = null;
  for (const raw of lines) {
    const line = raw.replace(/[#;].*$/, "").trim();
    if (!line) continue;
    const sec = line.match(/^\[([^\]]+)\]$/);
    if (sec) {
      current = sec[1].trim();
      profiles[current] = {};
      continue;
    }
    if (!current) continue;
    const kv = line.match(/^([A-Za-z0-9_-]+)\s*=\s*(.*)$/);
    if (!kv) continue;
    profiles[current][kv[1].trim().toLowerCase()] = kv[2].trim();
  }
  const staticProfiles = [];
  const federatedProfiles = [];
  for (const [name, kv] of Object.entries(profiles)) {
    const hasKey = !!kv["aws_access_key_id"];
    const hasFederation = !!(kv["sso_session"] || kv["credential_process"] || kv["role_arn"]);
    if (hasKey && !hasFederation) staticProfiles.push(name);
    if (hasFederation) federatedProfiles.push(name);
  }
  return { staticProfiles, federatedProfiles };
}

// kubeconfig: users[].user.token field present (non-empty) with no
// users[].user.exec sibling. Use a tolerant line-based scan rather
// than pulling a YAML parser into the stdlib-only contract.
function parseKubeConfig(content) {
  if (!content) return { hasStaticToken: false, hasExec: false };
  // Find every users: block + each `- name: ...` user entry and
  // its sub-keys. The kubeconfig schema is regular enough that a
  // line-window scan is reliable.
  const lines = content.split(/\r?\n/);
  let inUsers = false;
  let userIndent = -1;
  let blocks = [];
  let buf = [];
  let blockIndent = -1;
  for (const raw of lines) {
    if (/^users:\s*$/.test(raw)) { inUsers = true; userIndent = -1; continue; }
    if (inUsers) {
      const m = raw.match(/^(\s*)-\s+name:/);
      if (m) {
        if (buf.length) { blocks.push(buf.join("\n")); buf = []; }
        userIndent = m[1].length;
        blockIndent = userIndent;
        buf.push(raw);
        continue;
      }
      if (buf.length) {
        // If we leave the users list (dedent), close current block.
        if (raw.trim() === "" || /^\S/.test(raw)) {
          if (/^\S/.test(raw) && !/^users:/.test(raw)) {
            blocks.push(buf.join("\n")); buf = [];
            inUsers = false;
            continue;
          }
        }
        buf.push(raw);
      }
    }
  }
  if (buf.length) blocks.push(buf.join("\n"));

  let hasStaticToken = false;
  let hasExec = false;
  for (const block of blocks) {
    const tokenMatch = block.match(/\btoken\s*:\s*(\S[^\n]*)/);
    const tokenDataMatch = block.match(/\btoken-data\s*:\s*(\S[^\n]*)/);
    const execPresent = /\bexec\s*:\s*\n/.test(block) || /\bexec\s*:\s*$/m.test(block);
    if (execPresent) hasExec = true;
    if ((tokenMatch && tokenMatch[1] && !tokenMatch[1].startsWith("null")) ||
        (tokenDataMatch && tokenDataMatch[1] && !tokenDataMatch[1].startsWith("null"))) {
      if (!execPresent) hasStaticToken = true;
    }
  }
  return { hasStaticToken, hasExec };
}

function parseGcloudAdc(content) {
  if (!content) return { hasServiceAccount: false };
  try {
    const j = JSON.parse(content);
    return { hasServiceAccount: j?.type === "service_account" };
  } catch {
    return { hasServiceAccount: false };
  }
}

function parseDockerConfig(content) {
  if (!content) return { hasCleartext: false, hasCredHelper: false, registriesWithCleartext: [] };
  let j;
  try { j = JSON.parse(content); } catch { return { hasCleartext: false, hasCredHelper: false, registriesWithCleartext: [] }; }
  const auths = (j && typeof j.auths === "object") ? j.auths : {};
  const credHelpers = (j && typeof j.credHelpers === "object") ? j.credHelpers : {};
  const credsStore = typeof j?.credsStore === "string" ? j.credsStore : "";
  const registriesWithCleartext = [];
  for (const [registry, entry] of Object.entries(auths)) {
    if (!entry || typeof entry !== "object") continue;
    const hasAuth = typeof entry.auth === "string" && entry.auth.length > 0;
    if (!hasAuth) continue;
    if (credsStore || credHelpers[registry]) continue;
    registriesWithCleartext.push(registry);
  }
  return {
    hasCleartext: registriesWithCleartext.length > 0,
    hasCredHelper: !!credsStore || Object.keys(credHelpers).length > 0,
    registriesWithCleartext,
  };
}

const NPM_PAT_RE = /:_authToken\s*=\s*npm_[A-Za-z0-9]{36,}/;
const PYPI_TOKEN_RE = /password\s*=\s*pypi-[A-Za-z0-9_-]{40,}/;

function collect({ cwd = process.cwd(), env = process.env, args = {} } = {}) {
  const errors = [];
  const startTime = Date.now();
  const root = path.resolve(cwd);
  const home = (env && env.HOME) || (env && env.USERPROFILE) || os.homedir();
  const isPosix = process.platform !== "win32";

  const carriers = {
    "aws-credentials": path.join(home, ".aws", "credentials"),
    "aws-config": path.join(home, ".aws", "config"),
    "kube-config": path.join(home, ".kube", "config"),
    "docker-config": path.join(home, ".docker", "config.json"),
    "npmrc-home": path.join(home, ".npmrc"),
    "pypirc-home": path.join(home, ".pypirc"),
    "gcloud-adc": path.join(home, ".config", "gcloud", "application_default_credentials.json"),
    "npmrc-project": path.join(root, ".npmrc"),
    "pypirc-project": path.join(root, ".pypirc"),
  };
  const ssoCacheDir = path.join(home, ".aws", "sso", "cache");

  const presence = {};
  for (const [id, p] of Object.entries(carriers)) presence[id] = fileExists(p);

  // Read carriers we care about.
  const awsCredsContent = presence["aws-credentials"] ? readSafe(carriers["aws-credentials"]) : null;
  const awsCfgContent = presence["aws-config"] ? readSafe(carriers["aws-config"]) : null;
  const kubeContent = presence["kube-config"] ? readSafe(carriers["kube-config"]) : null;
  const dockerContent = presence["docker-config"] ? readSafe(carriers["docker-config"]) : null;
  const npmrcHomeContent = presence["npmrc-home"] ? readSafe(carriers["npmrc-home"]) : null;
  const pypirHomeContent = presence["pypirc-home"] ? readSafe(carriers["pypirc-home"]) : null;
  const npmrcProjContent = presence["npmrc-project"] ? readSafe(carriers["npmrc-project"]) : null;
  const pypirProjContent = presence["pypirc-project"] ? readSafe(carriers["pypirc-project"]) : null;
  const gcloudAdcContent = presence["gcloud-adc"] ? readSafe(carriers["gcloud-adc"]) : null;

  // Indicator predicates.
  const awsCredsParsed = parseAwsCredentials(awsCredsContent);
  const awsCfgParsed = parseAwsCredentials(awsCfgContent);
  const ssoCacheFiles = (() => {
    try { return fs.readdirSync(ssoCacheDir).filter(f => f.endsWith(".json")); }
    catch { return []; }
  })();
  // aws-static-key-present: any AKIA* key with no federation. The
  // cross-reference predicate ("sso-cache empty") elevates to a
  // higher-severity finding in the runner — we always emit the
  // primary hit when a static key exists.
  const awsStaticKey = awsCredsParsed.staticProfiles.length > 0;

  const kubeParsed = parseKubeConfig(kubeContent);
  const gcloudParsed = parseGcloudAdc(gcloudAdcContent);
  const dockerParsed = parseDockerConfig(dockerContent);

  const npmPatPresent =
    (npmrcHomeContent && NPM_PAT_RE.test(npmrcHomeContent)) ||
    (npmrcProjContent && NPM_PAT_RE.test(npmrcProjContent));
  const pypiTokenPresent =
    (pypirHomeContent && PYPI_TOKEN_RE.test(pypirHomeContent)) ||
    (pypirProjContent && PYPI_TOKEN_RE.test(pypirProjContent));

  // credentials-file-bad-perms: POSIX only. Any of the listed
  // carriers with mode != 0600.
  let credsFileBadPerms;
  const permViolations = [];
  if (isPosix) {
    const permTargets = [
      ["aws-credentials", carriers["aws-credentials"]],
      ["kube-config", carriers["kube-config"]],
      ["docker-config", carriers["docker-config"]],
      ["npmrc-home", carriers["npmrc-home"]],
      ["pypirc-home", carriers["pypirc-home"]],
    ];
    for (const [id, p] of permTargets) {
      if (!presence[id]) continue;
      const m = modeOf(p);
      if (m == null) continue;
      if (m !== 0o600) {
        permViolations.push({ id, mode_octal: "0" + m.toString(8) });
      }
    }
    credsFileBadPerms = permViolations.length > 0 ? "hit" : "miss";
  }

  const signal_overrides = {
    "aws-static-key-present": awsStaticKey ? "hit" : "miss",
    "kube-static-token": kubeParsed.hasStaticToken ? "hit" : "miss",
    "gcp-service-account-json-adc": gcloudParsed.hasServiceAccount ? "hit" : "miss",
    "docker-cleartext-auth": dockerParsed.hasCleartext ? "hit" : "miss",
    "npm-pat-present": npmPatPresent ? "hit" : "miss",
    "pypi-token-present": pypiTokenPresent ? "hit" : "miss",
  };
  if (credsFileBadPerms !== undefined) {
    signal_overrides["credentials-file-bad-perms"] = credsFileBadPerms;
  }

  // Artifact-level captures (one entry per artifact id in
  // data/playbooks/cred-stores.json look.artifacts[]). We only
  // populate the ones the collector actually reads; the rest are
  // marked captured=false with a "reason" so the runner records
  // partial-evidence coverage rather than a phantom miss.
  const artifacts = {
    "aws-credentials": presence["aws-credentials"]
      ? { value: `present (${awsCredsParsed.staticProfiles.length} static profile(s), ${awsCredsParsed.federatedProfiles.length} federated)`, captured: true }
      : { value: "absent", captured: true },
    "aws-sso-cache": {
      value: ssoCacheFiles.length > 0 ? `${ssoCacheFiles.length} cached SSO session(s)` : "empty",
      captured: true,
    },
    "kube-config": presence["kube-config"]
      ? { value: `present; static_token=${kubeParsed.hasStaticToken}; exec_provider=${kubeParsed.hasExec}`, captured: true }
      : { value: "absent", captured: true },
    "gcloud-credentials": presence["gcloud-adc"]
      ? { value: `application_default_credentials.json present; service_account=${gcloudParsed.hasServiceAccount}`, captured: true }
      : { value: "absent", captured: true, reason: "application_default_credentials.json not found; credentials.db SQLite inspection skipped (no stdlib SQLite reader)" },
    "docker-config": presence["docker-config"]
      ? { value: `auths_present=${Object.keys(dockerParsed.registriesWithCleartext).length > 0 || dockerParsed.hasCredHelper}; cleartext_registries=[${dockerParsed.registriesWithCleartext.join(", ")}]; cred_helper=${dockerParsed.hasCredHelper}`, captured: true }
      : { value: "absent", captured: true },
    "npmrc": {
      value: [
        presence["npmrc-home"] ? "~/.npmrc=present" : "~/.npmrc=absent",
        presence["npmrc-project"] ? "project .npmrc=present" : "project .npmrc=absent",
        `_authToken_present=${!!npmPatPresent}`,
      ].join("; "),
      captured: true,
    },
    "pypirc": {
      value: [
        presence["pypirc-home"] ? "~/.pypirc=present" : "~/.pypirc=absent",
        presence["pypirc-project"] ? "project .pypirc=present" : "project .pypirc=absent",
        `token_present=${!!pypiTokenPresent}`,
      ].join("; "),
      captured: true,
    },
    "gpg-keys": {
      value: "skipped — gpg CLI invocation deferred to operator/AI evidence",
      captured: false,
      reason: "deterministic gpg-key-old-or-weak parsing requires gpg --list-secret-keys; left to operator-supplied evidence",
    },
    "ssh-keys-inventory": {
      value: "skipped — ssh-keygen invocation deferred to operator/AI evidence",
      captured: false,
      reason: "ssh-key-rsa-short-bits / ssh-key-old need ssh-keygen output + mtime correlation with ssh-config; left to operator-supplied evidence",
    },
    "ssh-config": {
      value: "skipped — ssh-config inspection deferred to operator/AI evidence",
      captured: false,
      reason: "ssh-config CertificateFile / ProxyJump correlation is judgement-shaped; collector leaves it to operator",
    },
    "keychain-inventory": {
      value: "skipped — host keychain access deferred to operator/AI evidence",
      captured: false,
      reason: "secret-tool / security dump-keychain require interactive auth or platform-specific binaries; out of stdlib collector scope",
    },
  };

  if (permViolations.length > 0) {
    artifacts["credentials-file-perms"] = {
      value: permViolations.map(v => `${v.id} (${v.mode_octal})`).join("; "),
      captured: true,
    };
  }

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
      carriers_present: Object.entries(presence).filter(([_, v]) => v).map(([k]) => k),
    },
    collector_errors: errors,
  };
}

module.exports = { playbook_id: COLLECTOR_ID, collect };
