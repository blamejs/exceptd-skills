"use strict";


// ---- routed from w-collectors-fp-attestation ----
require("node:test").describe("w-collectors-fp-attestation", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
/**
 * tests/w-collectors-fp-attestation.test.js
 *
 * Every collector that flips an indicator carrying
 * false_positive_checks_required to "hit" must also emit the sibling
 * "<id>__fp_checks" attestation for the checks it deterministically ran.
 * Without it, the runner downgrades a real `collect`-surfaced hit to
 * inconclusive when the same submission is piped into `run`, silently
 * masking the finding.
 *
 * This pins the class for the whole collector set:
 *
 *   1. Parametric source guard — for every collector module, derive its
 *      FP-gated indicator ids from the playbook JSON and confirm that an
 *      indicator the collector decides deterministically either references
 *      __fp_checks in its source or is in an explicit "no deterministic FP
 *      index" allowlist (with the reason recorded here). A new collector
 *      that flips an FP-gated indicator without attesting cannot pass.
 *
 *   2. Behavioural round-trips — for the collectors triggerable from a
 *      staged tempdir fixture, drive a real hit and assert the emitted
 *      attestation has the shape run() requires (object, index-keyed,
 *      values === true), and that the collect -> run pipeline reaches
 *      `detected` (not inconclusive) for at least one indicator whose FP
 *      checks are all deterministic, while honestly leaving indicators
 *      that carry a network/operator-judgement check at inconclusive.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const os = require("node:os");

const ROOT = path.join(__dirname, "..");

function loadPlaybook(id) {
  return JSON.parse(fs.readFileSync(path.join(ROOT, "data", "playbooks", `${id}.json`), "utf8"));
}

function fpGatedIndicatorIds(playbook) {
  const inds = (playbook.phases && playbook.phases.detect && playbook.phases.detect.indicators) || [];
  return inds
    .filter((i) => Array.isArray(i.false_positive_checks_required) && i.false_positive_checks_required.length > 0)
    .map((i) => i.id);
}

function allPreconditions(playbook) {
  const out = {};
  for (const p of (playbook._meta && playbook._meta.preconditions) || []) out[p.id] = true;
  return out;
}

// Every collector under lib/collectors that maps to a shipped playbook.
// `__`-prefixed files are a reserved test-fixture/scaffolding prefix (no real
// collector uses it — the AGENTS.md enumeration regex is [a-z0-9-]+), so they
// are excluded here too; this keeps a stray fixture from ever poisoning the
// mapping/attestation checks.
const COLLECTOR_FILES = fs
  .readdirSync(path.join(ROOT, "lib", "collectors"))
  .filter((f) => f.endsWith(".js") && !f.startsWith("__") && f !== "README.md" && f !== "scan-excludes.js");

// Collectors whose FP-gated indicators have NO deterministic FP-check index a
// stdlib collector can satisfy (every required check is network reachability,
// live-process inspection, package-signature lookup, or pure operator
// judgement). These correctly emit no attestation — the runner's honest
// downgrade to inconclusive is the intended behaviour. Recorded explicitly so
// the source guard distinguishes "correctly abstains" from "forgot to attest".
const NO_DETERMINISTIC_FP_INDEX = {
  // crypto interrogates the live openssl/sshd surface; oqsprovider listing,
  // static-link/libcrypto inspection, distro-backport lookup, and lsof all sit
  // outside what it captures.
  crypto: ["ml-dsa-slh-dsa-absent", "openssl-pre-3-5"],
  // mcp's FP checks are tool-purpose / publisher-signature / field-position
  // judgements not derivable from the response-log bytes alone.
  mcp: ["mcp-response-ansi-escape", "mcp-response-unicode-tag-smuggling",
    "mcp-server-running-as-root", "mcp-server-invoked-from-ci-pipeline"],
  // containers' FP checks are base-image-provenance / cluster-spec /
  // org-allowlist judgements; the line-scanner does not resolve them.
  containers: ["dockerfile-runs-as-root", "dockerfile-curl-pipe-bash",
    "compose-cap-add-sys-admin", "compose-host-network"],
  // cicd: every FP check retains a runner-privilege / secret-sensitivity /
  // role-permission-scope judgement the static workflow scan cannot decide, so
  // each indicator correctly stays inconclusive regardless of attestation.
  "cicd-pipeline-compromise": ["workflow-injection-sink",
    "pull-request-target-with-pr-checkout", "wildcarded-oidc-sub-claim",
    "actions-floating-tag-pin", "secret-exposed-to-fork-pr"],
  // hardening: kptr-restrict-disabled is attested (kallsyms cross-check);
  // the rest need operator MAC-profile / single-tenant judgement or a
  // root-only dmesg read the collector cannot perform.
  hardening: ["yama-ptrace-permissive", "kaslr-disabled-at-boot", "mitigations-off"],
  // runtime: world-writable-in-trusted-path is attested (sticky-bit /
  // special-file stat); the other two need /etc/shadow lock state, binary
  // checksum allowlists, or process-launch provenance — operator judgement.
  runtime: ["duplicate-uid-zero", "orphan-privileged-process"],
  // citation-hygiene: fabricated-cve-id / rejected-or-disputed-cve /
  // rfc-number-title-mismatch are attested. cve-citation-needs-external-
  // verification only ever resolves to inconclusive (its FP[0] is an NVD
  // network lookup), so the collector never flips it to a hit to attest.
  "citation-hygiene": ["cve-citation-needs-external-verification"],
};

test("every collector maps to a shipped playbook and exports the contract", () => {
  for (const file of COLLECTOR_FILES) {
    const mod = require(path.join(ROOT, "lib", "collectors", file));
    assert.equal(typeof mod.playbook_id, "string", `${file} must export playbook_id`);
    assert.equal(typeof mod.collect, "function", `${file} must export collect()`);
    const pbPath = path.join(ROOT, "data", "playbooks", `${mod.playbook_id}.json`);
    assert.ok(fs.existsSync(pbPath), `${file} -> ${mod.playbook_id}.json must exist`);
  }
});

test("collectors attest (or explicitly abstain from) every FP-gated indicator they can flip", () => {
  for (const file of COLLECTOR_FILES) {
    const mod = require(path.join(ROOT, "lib", "collectors", file));
    const pb = loadPlaybook(mod.playbook_id);
    const gated = fpGatedIndicatorIds(pb);
    if (!gated.length) continue;
    const src = fs.readFileSync(path.join(ROOT, "lib", "collectors", file), "utf8");
    const abstain = new Set(NO_DETERMINISTIC_FP_INDEX[mod.playbook_id] || []);
    // A collector may build the attestation key dynamically inside a loop
    // (`signal_overrides[`${id}__fp_checks`] = ...`) rather than as a literal.
    // Recognise that form so a dynamically-attesting collector isn't flagged.
    const attestsDynamic = /`\$\{[^`]*\}__fp_checks`/.test(src);
    for (const id of gated) {
      // Does the collector even reference this indicator id at all? If it
      // never names it, the collector defers the indicator (leaves it
      // unflipped) and there is nothing to attest.
      if (!src.includes(`"${id}"`)) continue;
      const attests = src.includes(`"${id}__fp_checks"`) || attestsDynamic;
      const declaredAbstain = abstain.has(id);
      assert.ok(
        attests || declaredAbstain,
        `${file}: flips FP-gated indicator "${id}" but emits no "${id}__fp_checks" ` +
        `attestation and is not in the documented no-deterministic-FP-index allowlist. ` +
        `A real hit will be downgraded to inconclusive by run().`,
      );
      // Guard the allowlist against drift: an indicator can't be BOTH attested
      // and declared as abstaining.
      assert.ok(!(attests && declaredAbstain),
        `${file}: "${id}" both attests and is in the abstain allowlist — remove it from NO_DETERMINISTIC_FP_INDEX.`);
    }
  }
});

// ---- behavioural round-trips -------------------------------------------

// Assert an attestation object is the exact shape run()'s FP gate consumes:
// a plain object (NOT an array) whose keys map to === true.
function assertAttestationShape(att, label) {
  assert.equal(typeof att, "object", `${label}: attestation must be an object`);
  assert.ok(att !== null && !Array.isArray(att), `${label}: attestation must not be null/array`);
  const keys = Object.keys(att);
  assert.ok(keys.length > 0, `${label}: attestation must carry at least one index`);
  for (const k of keys) {
    assert.match(k, /^\d+$/, `${label}: attestation key "${k}" must be a numeric index`);
    assert.equal(att[k], true, `${label}: attestation index "${k}" must be true`);
  }
}

function runRoundTrip(playbookId, submission) {
  const runner = require(path.join(ROOT, "lib", "playbook-runner.js"));
  const pb = loadPlaybook(playbookId);
  const directive = runner.run(playbookId, null, submission, {}).valid_directives[0];
  const res = runner.run(playbookId, directive, submission, { precondition_checks: allPreconditions(pb) });
  return (res.phases && res.phases.detect) || {};
}

function indicatorVerdict(detect, id) {
  const ind = (detect.indicators || []).find((i) => i.id === id);
  return ind ? ind.verdict : undefined;
}

function mkTmp(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

// Fixture tokens are assembled at runtime so the committed source never
// contains a contiguous secret-shaped string — secret scanners (including
// push protection) would otherwise flag the test file itself. The assembled
// values land only in per-test tempdir fixtures.
const SLACK_FIXTURE = ["xoxb", "1111111111", "2222222222", "AbCdEfGhIjKlMnOp"].join("-");
const STRIPE_FIXTURE = "sk_test_" + ["4eC39HqLyjW", "DarjtT1zdp7dc"].join("");

test("secrets: collect -> run reaches detected for all-deterministic FP indicators", () => {
  const secrets = require(path.join(ROOT, "lib", "collectors", "secrets.js"));
  const tmp = mkTmp("w-fp-secrets-");
  try {
    // The OpenAI regex also matches sk-ant-* keys, so keep the anthropic key
    // out of this fixture; the dedicated openai case below isolates it.
    fs.writeFileSync(path.join(tmp, "slack.env"), "SLACK_BOT_TOKEN=" + SLACK_FIXTURE + "\n");
    fs.writeFileSync(path.join(tmp, "stripe.env"), "STRIPE_KEY=" + STRIPE_FIXTURE + "\n");
    fs.writeFileSync(path.join(tmp, "aws.env"),
      "aws_access_key_id = AKIASYNTHREALKEY01\naws_secret_access_key = " + "b".repeat(40) + "\n");

    const sub = secrets.collect({ cwd: tmp });
    const detected = ["slack-bot-or-user-token", "stripe-secret-key", "aws-secret-access-key"];
    for (const id of detected) {
      assert.equal(sub.signal_overrides[id], "hit", `secrets ${id} should flip to hit`);
      assertAttestationShape(sub.signal_overrides[`${id}__fp_checks`], `secrets ${id}`);
    }
    const det = runRoundTrip("secrets", sub);
    assert.equal(det.classification, "detected");
    for (const id of detected) {
      assert.equal(indicatorVerdict(det, id), "hit",
        `secrets ${id} must stay hit (not downgraded) after run`);
    }
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("secrets: isolated openai/anthropic keys each reach detected", () => {
  const secrets = require(path.join(ROOT, "lib", "collectors", "secrets.js"));
  for (const [id, line] of [
    ["openai-api-key", "OPENAI_API_KEY=sk-proj-" + "A1b2C3d4".repeat(7)],
    ["anthropic-api-key", "ANTHROPIC_API_KEY=sk-ant-api03-" + "Z9y8X7w6".repeat(11)],
  ]) {
    const tmp = mkTmp("w-fp-secrets-iso-");
    try {
      fs.writeFileSync(path.join(tmp, "k.env"), line + "\n");
      const sub = secrets.collect({ cwd: tmp });
      assert.equal(sub.signal_overrides[id], "hit", `secrets ${id} should flip to hit`);
      assertAttestationShape(sub.signal_overrides[`${id}__fp_checks`], `secrets ${id}`);
      const det = runRoundTrip("secrets", sub);
      assert.equal(indicatorVerdict(det, id), "hit", `secrets ${id} must stay hit after run`);
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  }
});

test("secrets: a real-shaped key under a docs path is not falsely attested (run downgrades it)", () => {
  const secrets = require(path.join(ROOT, "lib", "collectors", "secrets.js"));
  const tmp = mkTmp("w-fp-secrets-doc-");
  try {
    // The hit still flips (docs/ is not in the prod-vs-test split), but the
    // path-based FP check is unsatisfied, so the collector must NOT attest it
    // and run() must downgrade to inconclusive rather than detected.
    fs.mkdirSync(path.join(tmp, "docs"), { recursive: true });
    fs.writeFileSync(path.join(tmp, "docs", "guide.md"), "SLACK_BOT_TOKEN=" + SLACK_FIXTURE + "\n");
    const sub = secrets.collect({ cwd: tmp });
    assert.equal(sub.signal_overrides["slack-bot-or-user-token"], "hit", "the regex still matches under docs/");
    const att = sub.signal_overrides["slack-bot-or-user-token__fp_checks"];
    // The path index (FP[2]) must be absent — the hit is under a docs path.
    assert.ok(!att || att["2"] === undefined, "must not attest the path FP check for a docs-path hit");
    const det = runRoundTrip("secrets", sub);
    assert.equal(indicatorVerdict(det, "slack-bot-or-user-token"), "inconclusive",
      "a docs-path hit must downgrade to inconclusive, not detected");
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("ai-api: collect -> run reaches detected; network-gated indicator stays inconclusive", () => {
  const aiApi = require(path.join(ROOT, "lib", "collectors", "ai-api.js"));
  const home = mkTmp("w-fp-aiapi-");
  try {
    fs.writeFileSync(path.join(home, ".bashrc"), "export OPENAI_API_KEY=sk-proj-" + "A1b2C3d4".repeat(7) + "\n");
    fs.mkdirSync(path.join(home, ".aws"), { recursive: true });
    fs.writeFileSync(path.join(home, ".aws", "credentials"),
      "[default]\naws_access_key_id = AKIAREALKEY1234567\naws_secret_access_key = " + "q".repeat(40) + "\n");
    fs.mkdirSync(path.join(home, ".config", "gcloud"), { recursive: true });
    fs.writeFileSync(path.join(home, ".config", "gcloud", "application_default_credentials.json"),
      JSON.stringify({
        type: "service_account",
        private_key: "-----BEGIN PRIVATE KEY-----\n" + "M".repeat(1100) + "\n-----END PRIVATE KEY-----\n",
        client_email: "svc@my-proj.iam.gserviceaccount.com",
      }));
    fs.mkdirSync(path.join(home, ".kube"), { recursive: true });
    fs.writeFileSync(path.join(home, ".kube", "config"),
      ["apiVersion: v1", "clusters:", "- cluster:", "    server: https://prod.example.com:6443",
        "users:", "- name: admin", "  user:", "    token: " + "t".repeat(64)].join("\n"));

    const sub = aiApi.collect({ cwd: ROOT, env: { HOME: home, USERPROFILE: home } });
    const reachable = ["cleartext-api-key-in-dotfile", "gcp-service-account-json", "kubeconfig-with-static-token"];
    for (const id of reachable) {
      assert.equal(sub.signal_overrides[id], "hit", `ai-api ${id} should flip to hit`);
      assertAttestationShape(sub.signal_overrides[`${id}__fp_checks`], `ai-api ${id}`);
    }
    // long-lived-aws-keys carries the sts-network FP[2]; attest the
    // deterministic subset but never the network index.
    assert.equal(sub.signal_overrides["long-lived-aws-keys"], "hit");
    assertAttestationShape(sub.signal_overrides["long-lived-aws-keys__fp_checks"], "ai-api long-lived-aws-keys");

    const det = runRoundTrip("ai-api", sub);
    assert.equal(det.classification, "detected");
    for (const id of reachable) {
      assert.equal(indicatorVerdict(det, id), "hit", `ai-api ${id} must stay hit after run`);
    }
    assert.equal(indicatorVerdict(det, "long-lived-aws-keys"), "inconclusive",
      "long-lived-aws-keys must stay inconclusive — its live-key check is network-gated");
  } finally {
    fs.rmSync(home, { recursive: true, force: true });
  }
});

test("crypto-codebase: collect -> run attests the deterministic FP indices it ran", () => {
  const cc = require(path.join(ROOT, "lib", "collectors", "crypto-codebase.js"));
  const tmp = mkTmp("w-fp-cc-");
  try {
    fs.writeFileSync(path.join(tmp, "package.json"), "{}");
    fs.writeFileSync(path.join(tmp, "auth.js"),
      "const crypto=require('crypto');\nfunction sign(token){return crypto.createHash('md5').update(token).digest('hex');}\n");
    const sub = cc.collect({ cwd: tmp });
    assert.equal(sub.signal_overrides["weak-hash-import"], "hit");
    assertAttestationShape(sub.signal_overrides["weak-hash-import__fp_checks"], "crypto-codebase weak-hash-import");
    // weak-hash-import retains FP[1] (legacy-protocol-shim, operator), so the
    // honest verdict is inconclusive — the attestation records {0,2} only.
    const det = runRoundTrip("crypto-codebase", sub);
    const att = sub.signal_overrides["weak-hash-import__fp_checks"];
    assert.equal(att["0"], true);
    assert.equal(att["2"], true);
    assert.equal(att["1"], undefined, "must not attest the operator-judgement legacy-shim check");
    assert.equal(indicatorVerdict(det, "weak-hash-import"), "inconclusive");
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("runtime: world-writable-in-trusted-path reaches detected; benign carriers demoted", () => {
  const runtime = require(path.join(ROOT, "lib", "collectors", "runtime.js"));
  const tmp = mkTmp("w-fp-runtime-");
  try {
    const tp = path.join(tmp, "opt");
    fs.mkdirSync(tp, { recursive: true });
    // genuine hit: regular non-empty world-writable file
    const f = path.join(tp, "hijackme.sh");
    fs.writeFileSync(f, "#!/bin/sh\necho x\n");
    try { fs.chmodSync(f, 0o666); } catch { /* chmod is a no-op on some hosts */ }
    // benign per FP[1]: 0-byte stamp
    const z = path.join(tp, "stamp");
    fs.writeFileSync(z, "");
    try { fs.chmodSync(z, 0o666); } catch { /* */ }

    const sub = runtime.collect({
      cwd: ROOT,
      args: {
        forceLinux: true,
        paths: {
          trustedPaths: [tp],
          sudoers: path.join(tmp, "none"),
          sudoersD: path.join(tmp, "none.d"),
          passwd: path.join(tmp, "none"),
          procRoot: path.join(tmp, "noproc"),
        },
      },
    });
    // If the host honoured chmod the indicator fires; if chmod was a no-op
    // (rare CI), skip the behavioural half — the source guard still covers it.
    if (sub.signal_overrides["world-writable-in-trusted-path"] === "hit") {
      assertAttestationShape(sub.signal_overrides["world-writable-in-trusted-path__fp_checks"], "runtime world-writable");
      const det = runRoundTrip("runtime", sub);
      assert.equal(indicatorVerdict(det, "world-writable-in-trusted-path"), "hit",
        "a genuine world-writable hit must stay hit after run");
    }
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("sbom: lockfile-no-integrity reaches detected for a remote-registry entry missing integrity", () => {
  const sbom = require(path.join(ROOT, "lib", "collectors", "sbom.js"));
  const tmp = mkTmp("w-fp-sbom-");
  try {
    fs.writeFileSync(path.join(tmp, "package-lock.json"), JSON.stringify({
      name: "x", lockfileVersion: 3,
      packages: { "node_modules/lodash": { version: "4.17.21", resolved: "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz" } },
    }));
    const sub = sbom.collect({ cwd: tmp });
    assert.equal(sub.signal_overrides["lockfile-no-integrity"], "hit");
    assertAttestationShape(sub.signal_overrides["lockfile-no-integrity__fp_checks"], "sbom lockfile-no-integrity");
    const det = runRoundTrip("sbom", sub);
    assert.equal(indicatorVerdict(det, "lockfile-no-integrity"), "hit");
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("sbom: an integrity-less local-path entry is not falsely attested as a registry finding", () => {
  const sbom = require(path.join(ROOT, "lib", "collectors", "sbom.js"));
  const tmp = mkTmp("w-fp-sbom-local-");
  try {
    // Only a file:/workspace ref lacks integrity — FP[0] (remote-registry)
    // must NOT be attested, so the runner keeps it inconclusive.
    fs.writeFileSync(path.join(tmp, "package-lock.json"), JSON.stringify({
      name: "x", lockfileVersion: 3,
      packages: { "node_modules/local": { version: "1.0.0", resolved: "file:../local" } },
    }));
    const sub = sbom.collect({ cwd: tmp });
    if (sub.signal_overrides["lockfile-no-integrity"] === "hit") {
      const att = sub.signal_overrides["lockfile-no-integrity__fp_checks"] || {};
      assert.equal(att["0"], undefined, "must not attest the registry FP check for a file:-only gap");
      const det = runRoundTrip("sbom", sub);
      assert.equal(indicatorVerdict(det, "lockfile-no-integrity"), "inconclusive");
    }
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("library-author: a third-party mutable action ref with no Dependabot reaches detected", () => {
  const la = require(path.join(ROOT, "lib", "collectors", "library-author.js"));
  const tmp = mkTmp("w-fp-la-");
  try {
    fs.writeFileSync(path.join(tmp, "package.json"), JSON.stringify({ name: "x", version: "1.0.0" }));
    fs.mkdirSync(path.join(tmp, ".github", "workflows"), { recursive: true });
    fs.writeFileSync(path.join(tmp, ".github", "workflows", "publish.yml"),
      ["name: publish", "on:", "  release:", "    types: [published]", "jobs:", "  pub:",
        "    runs-on: ubuntu-latest", "    steps:", "      - uses: actions/checkout@v4",
        "      - uses: thirdparty/some-action@main", "      - run: npm publish"].join("\n"));
    const sub = la.collect({ cwd: tmp });
    assert.equal(sub.signal_overrides["publish-workflow-action-refs-mutable"], "hit");
    assertAttestationShape(sub.signal_overrides["publish-workflow-action-refs-mutable__fp_checks"], "library-author action-refs-mutable");
    const det = runRoundTrip("library-author", sub);
    assert.equal(indicatorVerdict(det, "publish-workflow-action-refs-mutable"), "hit");
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("library-author: github-owned mutable refs + Dependabot leave the indicator inconclusive (honest abstain)", () => {
  const la = require(path.join(ROOT, "lib", "collectors", "library-author.js"));
  const tmp = mkTmp("w-fp-la-clean-");
  try {
    fs.writeFileSync(path.join(tmp, "package.json"), JSON.stringify({ name: "x", version: "1.0.0" }));
    fs.mkdirSync(path.join(tmp, ".github", "workflows"), { recursive: true });
    fs.writeFileSync(path.join(tmp, ".github", "dependabot.yml"),
      ["version: 2", "updates:", "  - package-ecosystem: github-actions", "    directory: \"/\"", "    schedule:", "      interval: weekly"].join("\n"));
    // Only github-owned mutable refs -> FP[1] not survived.
    fs.writeFileSync(path.join(tmp, ".github", "workflows", "publish.yml"),
      ["name: publish", "on:", "  release:", "    types: [published]", "jobs:", "  pub:",
        "    runs-on: ubuntu-latest", "    steps:", "      - uses: actions/checkout@v4", "      - run: npm publish"].join("\n"));
    const sub = la.collect({ cwd: tmp });
    if (sub.signal_overrides["publish-workflow-action-refs-mutable"] === "hit") {
      const att = sub.signal_overrides["publish-workflow-action-refs-mutable__fp_checks"];
      // Neither FP index should be attested: Dependabot present AND all refs github-owned.
      assert.ok(!att || (att["0"] === undefined && att["1"] === undefined));
      const det = runRoundTrip("library-author", sub);
      assert.equal(indicatorVerdict(det, "publish-workflow-action-refs-mutable"), "inconclusive");
    }
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("citation-hygiene: a fabricated CVE in non-illustrative prose reaches detected", () => {
  const ch = require(path.join(ROOT, "lib", "collectors", "citation-hygiene.js"));
  const tmp = mkTmp("w-fp-ch-");
  try {
    // A well-shaped CVE citation (4-digit year) whose sequence number is too
    // short to be canonical — recognised as a citation, flagged as fabricated.
    fs.writeFileSync(path.join(tmp, "notes.md"), "Tracking CVE-2025-1 in the changelog.\n");
    const sub = ch.collect({ cwd: tmp });
    assert.equal(sub.signal_overrides["fabricated-cve-id"], "hit");
    assertAttestationShape(sub.signal_overrides["fabricated-cve-id__fp_checks"], "citation-hygiene fabricated-cve-id");
    const det = runRoundTrip("citation-hygiene", sub);
    assert.equal(indicatorVerdict(det, "fabricated-cve-id"), "hit");
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("kernel: source attests the deterministic CONFIG_* FP index for the userns/bpf indicators", () => {
  // /proc and /boot/config are not stageable in a tempdir, so this is the
  // structural fallback: the collector must reference __fp_checks for the
  // FP-gated indicators it flips off the sysctl snapshot.
  const src = fs.readFileSync(path.join(ROOT, "lib", "collectors", "kernel.js"), "utf8");
  for (const id of ["unpriv-userns-enabled", "unpriv-bpf-allowed"]) {
    assert.ok(src.includes(`"${id}__fp_checks"`),
      `kernel.js must attest "${id}__fp_checks" for the checks it ran against /boot/config`);
  }
});
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});
