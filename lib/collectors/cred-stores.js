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

  // Match `token:` / `token-data:` ONLY at the user-block indent level
  // (i.e. inside `user:`). Auth-provider blocks carry sub-keys like
  // `access-token`, `id-token`, `refresh-token` which are dynamic /
  // cached tokens, not static-credential evidence. Use a line-prefix
  // anchor + auth-provider-vs-user proximity check to refuse those.
  let hasStaticToken = false;
  let hasExec = false;
  const userKvRe = /^(\s+)(token|token-data)\s*:\s*(\S[^\n]*)/gm;
  for (const block of blocks) {
    const execPresent = /^\s+exec\s*:\s*(?:\n|$)/m.test(block);
    if (execPresent) hasExec = true;
    let blockHasStatic = false;
    for (const m of block.matchAll(userKvRe)) {
      const upto = block.slice(0, m.index);
      const lastUserAt = upto.lastIndexOf("\n  user:");
      const lastAuthProviderAt = upto.lastIndexOf("auth-provider:");
      // Reject when the closest enclosing key is auth-provider rather
      // than user — those are dynamic tokens, not static credentials.
      if (lastAuthProviderAt > lastUserAt) continue;
      const value = m[3];
      if (!value || value.startsWith("null")) continue;
      blockHasStatic = true;
      break;
    }
    if (blockHasStatic && !execPresent) hasStaticToken = true;
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
  // aws-static-key-present: any AKIA* key with no federation. Apply
  // the playbook's catalogued FP[0] (AWS-published doc-fixture key)
  // and FP[2] (break-glass profile-name pattern) directly in the
  // collector — they're deterministic and the collector has the
  // evidence locally. FP[1] requires `aws sts get-caller-identity`
  // which is out of stdlib scope, so the collector cannot attest it;
  // the runner downgrades hit → inconclusive with that one
  // unsatisfied, which is the honest outcome.
  const AWS_DOC_FIXTURE_KEY = "AKIAIOSFODNN7EXAMPLE";
  const realAwsProfiles = awsCredsParsed.staticProfiles.filter(p => {
    // Parse the raw INI again for this profile's key value + name.
    // For doc-fixture demotion (FP[0]) we look up the key value; for
    // break-glass demotion (FP[2]) we check the profile name pattern.
    const block = (awsCredsContent || "").split(/^\[/m).find(b => b.startsWith(p + "]"));
    if (!block) return true;
    if (block.includes(AWS_DOC_FIXTURE_KEY)) return false; // FP[0]
    if (/^breakglass-/i.test(p) || /^break-glass-/i.test(p)) return false; // FP[2]
    return true;
  });
  const awsStaticKey = realAwsProfiles.length > 0;

  const kubeParsed = parseKubeConfig(kubeContent);
  const gcloudParsed = parseGcloudAdc(gcloudAdcContent);
  const dockerParsed = parseDockerConfig(dockerContent);

  // docker-cleartext-auth FP checks (per playbook):
  //   FP[0] — vendor-token user pattern (decoded `user:pass`) is
  //           `<token>` / `AWS` / `oauth2accesstoken` / a zero-UUID;
  //           treat as a deliberately published convention, demote.
  //   FP[1] — local-only registry (loopback IP, *.local, *.svc.
  //           cluster.local, kind.local) on a dev workstation, demote.
  //   FP[2] — global credsStore overrides per-registry omission —
  //           the collector already accounts for this via
  //           parseDockerConfig.hasCredHelper.
  const VENDOR_TOKEN_USERS = new Set([
    "<token>", "AWS", "oauth2accesstoken",
    "00000000-0000-0000-0000-000000000000",
  ]);
  function isLocalOnlyRegistry(registry) {
    return /^(?:127\.0\.0\.1|localhost)(?::\d+)?$/.test(registry) ||
           /\.local(?::\d+)?$/.test(registry) ||
           /\.svc\.cluster\.local(?::\d+)?$/.test(registry) ||
           /^kind\.local(?::\d+)?$/.test(registry);
  }
  function dockerAuthDemoted(registry, entry) {
    // FP[1]: local-only registry → demote.
    if (isLocalOnlyRegistry(registry)) return true;
    // FP[0]: decode `auth` base64 and check for vendor-token user.
    try {
      const decoded = Buffer.from(entry.auth, "base64").toString("utf8");
      const [user] = decoded.split(":", 1);
      if (VENDOR_TOKEN_USERS.has(user)) return true;
    } catch { /* unparseable, treat as real */ }
    return false;
  }
  const realCleartextRegistries = dockerParsed.registriesWithCleartext.filter(reg => {
    const entry = (() => { try { return JSON.parse(dockerContent || "{}").auths[reg]; } catch { return null; } })();
    if (!entry) return false;
    return !dockerAuthDemoted(reg, entry);
  });
  const dockerCleartext = realCleartextRegistries.length > 0;

  const npmPatPresent =
    (npmrcHomeContent && NPM_PAT_RE.test(npmrcHomeContent)) ||
    (npmrcProjContent && NPM_PAT_RE.test(npmrcProjContent));
  const pypiTokenPresent =
    (pypirHomeContent && PYPI_TOKEN_RE.test(pypirHomeContent)) ||
    (pypirProjContent && PYPI_TOKEN_RE.test(pypirProjContent));

  // credentials-file-bad-perms: POSIX only. Any of the listed
  // carriers with mode != 0600. Per playbook the indicator covers
  // `~/.config/gcloud/*` too, so include the gcloud ADC file (and
  // its parent dir mode != 0700 expectation per the spec).
  let credsFileBadPerms;
  const permViolations = [];
  if (isPosix) {
    const permTargets = [
      ["aws-credentials", carriers["aws-credentials"], 0o600],
      ["aws-config", carriers["aws-config"], 0o600],
      ["kube-config", carriers["kube-config"], 0o600],
      ["docker-config", carriers["docker-config"], 0o600],
      ["npmrc-home", carriers["npmrc-home"], 0o600],
      ["pypirc-home", carriers["pypirc-home"], 0o600],
      ["gcloud-adc", carriers["gcloud-adc"], 0o600],
    ];
    for (const [id, p, expectedMode] of permTargets) {
      if (!presence[id]) continue;
      // FP[1]: 0-byte placeholder OR symlink to broker socket / tmpfs —
      // mode bits don't carry the same blast radius. Skip these.
      let lstat;
      try { lstat = fs.lstatSync(p); } catch { continue; }
      if (lstat.size === 0) continue;
      if (lstat.isSymbolicLink()) continue;
      const m = modeOf(p);
      if (m == null) continue;
      if (m !== expectedMode) {
        permViolations.push({ id, mode_octal: "0" + m.toString(8) });
      }
    }
    // Also check the gcloud directory itself (expected 0700 per spec).
    const gcloudDir = path.join(home, ".config", "gcloud");
    try {
      const gs = fs.statSync(gcloudDir);
      if (gs.isDirectory()) {
        const dm = gs.mode & 0o777;
        if (dm !== 0o700) {
          permViolations.push({ id: "gcloud-dir", mode_octal: "0" + dm.toString(8) });
        }
      }
    } catch { /* not present, no violation */ }
    credsFileBadPerms = permViolations.length > 0 ? "hit" : "miss";
  }

  const signal_overrides = {
    "aws-static-key-present": awsStaticKey ? "hit" : "miss",
    "kube-static-token": kubeParsed.hasStaticToken ? "hit" : "miss",
    "gcp-service-account-json-adc": gcloudParsed.hasServiceAccount ? "hit" : "miss",
    "docker-cleartext-auth": dockerCleartext ? "hit" : "miss",
    "npm-pat-present": npmPatPresent ? "hit" : "miss",
    "pypi-token-present": pypiTokenPresent ? "hit" : "miss",
  };
  if (credsFileBadPerms !== undefined) {
    signal_overrides["credentials-file-bad-perms"] = credsFileBadPerms;
  }

  // Per-indicator __fp_checks attestation. The runner gates a 'hit'
  // verdict on false_positive_checks_required[] entries; an
  // unsatisfied check downgrades to 'inconclusive'. Attest exactly
  // the checks the collector itself ran (don't attest network /
  // operator-judgement checks). Use the index-keyed form because
  // false_positive_checks_required entries are free-text prose, not
  // ids — the index is the stable cross-reference.
  //
  //   aws-static-key-present:
  //     [0] doc-fixture demotion (AKIAIOSFODNN7EXAMPLE) — DONE
  //     [1] live-key sts check — NOT DONE (needs network)
  //     [2] break-glass profile-name pattern — DONE
  //
  //   docker-cleartext-auth:
  //     [0] vendor-token user pattern — DONE
  //     [1] local-only registry — DONE
  //     [2] global credsStore — DONE
  //
  //   credentials-file-bad-perms:
  //     [0] Windows / WSL skip — DONE (POSIX guard)
  //     [1] 0-byte / symlink skip — DONE
  //     [2] ACL-by-design (operator interview) — NOT DONE
  if (awsStaticKey) {
    signal_overrides["aws-static-key-present__fp_checks"] = { "0": true, "2": true };
  }
  if (dockerCleartext) {
    signal_overrides["docker-cleartext-auth__fp_checks"] = { "0": true, "1": true, "2": true };
  }
  if (credsFileBadPerms === "hit") {
    signal_overrides["credentials-file-bad-perms__fp_checks"] = { "0": true, "1": true };
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
