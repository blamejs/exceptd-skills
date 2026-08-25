"use strict";


// ---- routed from collectors-short-read-no-truncation ----
require("node:test").describe("collectors-short-read-no-truncation", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
/**
 * tests/collectors-short-read-no-truncation.test.js
 *
 * Regression coverage for a silent scan miss in the collectors' file-read
 * helpers. The helpers opened a descriptor, fstat'd it for the size, allocated
 * a size-exact buffer, and issued a SINGLE `fs.readSync(fd, buf, 0, size, 0)`
 * whose byte-count return was discarded. read()/readSync are not guaranteed to
 * fill the buffer in one call: a short read (network / FUSE / sync-backed fd,
 * or a file that shrank between fstat and read) returns fewer than `size` bytes
 * and leaves the buffer tail NUL-filled, so everything past the short-read
 * boundary was dropped from the decoded string — a private key / API-key export
 * sitting past that boundary went unmatched and the scan reported clean.
 *
 * The fix reads the whole descriptor with `fs.readFileSync(fd, "utf8")`, which
 * loops read() to EOF internally while keeping the open->fstat ordering
 * TOCTOU-free (no second path resolution).
 *
 * This pins the fix two ways that are deterministic on every platform (a
 * forced-short-read stub is unreliable: fs.readFileSync(fd) reads through the
 * binding, not the JS fs.readSync wrapper, so a stub on the wrapper need not
 * affect it, and the result then varies by Node version):
 *   1. Structural: every collector read helper reads its descriptor to EOF and
 *      carries no discard-the-return single-readSync left.
 *   2. Behavioral: the real collectors flip their key/secret signals for a key
 *      whose marker sits well past the first read chunk.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const os = require("node:os");

const ROOT = path.join(__dirname, "..");
const secrets = require(path.join(ROOT, "lib", "collectors", "secrets.js"));
const aiApi = require(path.join(ROOT, "lib", "collectors", "ai-api.js"));

function mkTmp(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

// The collector read helpers + the CVE cache reader that were converted to the
// fd-based read. Each must read to EOF and must not carry the discard-return
// single-readSync pattern that truncates on a short read.
const FD_READERS = [
  "lib/collectors/ai-api.js",
  "lib/collectors/cicd-pipeline-compromise.js",
  "lib/collectors/cred-stores.js",
  "lib/collectors/crypto.js",
  "lib/collectors/hardening.js",
  "lib/collectors/library-author.js",
  "lib/collectors/mcp.js",
  "lib/collectors/runtime.js",
  "lib/collectors/secrets.js",
  "lib/collectors/sbom.js",
  "lib/validate-indexes.js",
  "orchestrator/index.js",
];

test("collector + cache read helpers read the descriptor to EOF (no discard-return single readSync)", () => {
  for (const rel of FD_READERS) {
    const src = fs.readFileSync(path.join(ROOT, rel), "utf8");
    // The EOF-looping fd read must be present...
    assert.match(src, /readFileSync\(\s*fd\b/,
      `${rel} must read its descriptor to EOF via readFileSync(fd, ...)`);
    // ...and the buggy "alloc a size-exact buffer then one readSync whose
    // return is ignored" shape must be gone. A bare `readSync(fd, buf, 0,
    // <size>, 0)` whose result is not consumed is the truncation hazard.
    assert.doesNotMatch(src, /fs\.readSync\(\s*fd\s*,\s*\w+\s*,\s*0\s*,\s*[^,]+,\s*0\s*\)/,
      `${rel} must not issue a single discard-return fs.readSync(fd, buf, 0, size, 0)`);
  }
});

test("ai-api.collect flips cleartext-api-key-in-dotfile for an rc whose export sits past the first read chunk", () => {
  const dir = mkTmp("short-read-ai-");
  try {
    const rc =
      "# user shell rc — environment bootstrap and PATH setup\n".repeat(40) +
      'export OPENAI_API_KEY="sk-' + "A".repeat(40) + '"\n';
    assert.ok(rc.indexOf("OPENAI_API_KEY") > 2000, "export must sit past the file start");
    fs.writeFileSync(path.join(dir, ".bashrc"), rc);

    const out = aiApi.collect({ cwd: dir, env: { HOME: dir, USERPROFILE: dir } });
    assert.equal(
      out.signal_overrides["cleartext-api-key-in-dotfile"],
      "hit",
      "the cleartext OPENAI_API_KEY export past the first read chunk must be detected"
    );
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("readFileSync(fd) invariant: full content for a multi-chunk file, size cap preserved", () => {
  const dir = mkTmp("short-read-inv-");
  try {
    const f = path.join(dir, "x.txt");
    const content = "HEAD" + "z".repeat(200 * 1024) + "TAILMARKER";
    fs.writeFileSync(f, content);

    // Replicate the shipped helper shape exactly: open, fstat for the size cap,
    // read the descriptor to EOF.
    function readSafe(full, max) {
      let fd;
      try {
        fd = fs.openSync(full, "r");
        const s = fs.fstatSync(fd);
        if (s.size > max) return null;
        return fs.readFileSync(fd, "utf8");
      } catch { return null; }
      finally { if (fd !== undefined) { try { fs.closeSync(fd); } catch { /* non-fatal */ } } }
    }

    const got = readSafe(f, 256 * 1024 * 1024);
    assert.equal(got.length, content.length, "full file length read");
    assert.ok(got.endsWith("TAILMARKER"), "tail content past the first chunk is present");

    // Size cap still fires.
    assert.equal(readSafe(f, 1024), null, "a file over the cap returns null");
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});


// ---- routed from collectors-ai-api-vendor-fp-attestation ----
require("node:test").describe("collectors-ai-api-vendor-fp-attestation", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
/**
 * tests/collectors-ai-api-vendor-fp-attestation.test.js
 *
 * Regression coverage for a present-but-empty attestation that vanished a real
 * cleartext-key hit for half the supported vendors. The ai-api collector's
 * AI_KEY_VALUE_RE table (which cleartextFpIndices uses to capture the exported
 * value and evaluate the false_positive_checks_required entries) only carried
 * value regexes for openai/anthropic/huggingface. An azure/google/cohere-only
 * dotfile therefore produced NO captured value, cleartextFpIndices returned an
 * EMPTY attestation set, and the runner — seeing the indicator fire with no
 * __fp_checks attestation — downgraded the real cleartext-key hit to
 * inconclusive. The indicator surfaced from collect() then silently vanished
 * after run() for azure/google/cohere.
 *
 * The fix adds azure/google/cohere value regexes (the value IS the entropy body
 * since these vendors carry no `sk-`/`hf_` prefix), so a single azure/google
 * export now yields `cleartext-api-key-in-dotfile`:"hit" AND the populated
 * `__fp_checks` attestation {0:true,1:true,2:true} — placeholder[0], canonical
 * path[1], and the 30-char entropy floor[2] are all satisfied for a high-entropy
 * key on a canonical home rc path. Asserting the attestation CONTENT (not just
 * its presence) is the point: an empty `{}` would still be "present" but is the
 * exact shape that triggered the downgrade.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const os = require("node:os");

const ROOT = path.join(__dirname, "..");
const aiApi = require(path.join(ROOT, "lib", "collectors", "ai-api.js"));

// Collect against an isolated $HOME whose .bashrc carries a single cleartext
// export. The collector reads the canonical home dotfiles relative to env.HOME.
function collectWithBashrc(rcLine) {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "ai-fp-"));
  try {
    fs.writeFileSync(path.join(home, ".bashrc"), rcLine);
    return aiApi.collect({ env: { HOME: home } }).signal_overrides;
  } finally {
    fs.rmSync(home, { recursive: true, force: true });
  }
}

test("ai-api: azure cleartext key emits hit + populated {0,1,2} __fp_checks attestation (not empty)", () => {
  const ov = collectWithBashrc(
    'export AZURE_OPENAI_KEY="a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6"\n'
  );
  assert.equal(
    ov["cleartext-api-key-in-dotfile"],
    "hit",
    "an AZURE_OPENAI_KEY cleartext export must flip the indicator to hit"
  );
  assert.deepEqual(
    ov["cleartext-api-key-in-dotfile__fp_checks"],
    { "0": true, "1": true, "2": true },
    "the azure value regex must let cleartextFpIndices attest all three deterministic FP checks — an empty {} here re-introduces the runner downgrade"
  );
});

test("ai-api: google cleartext key emits hit + populated {0,1,2} __fp_checks attestation (not empty)", () => {
  const ov = collectWithBashrc(
    // Synthetic high-entropy value WITHOUT the real "AIzaSy" Google-key prefix:
    // the collector only requires GOOGLE_API_KEY=<20+ chars>, so a non-prefixed
    // value exercises the same path without a test fixture that looks like a
    // live credential to secret scanners.
    'export GOOGLE_API_KEY="7Hq2Wp9Kx4Tz6Rn1Yb3Vc8Df5Gj0Lm2Qs4Uw"\n'
  );
  assert.equal(
    ov["cleartext-api-key-in-dotfile"],
    "hit",
    "a GOOGLE_API_KEY cleartext export must flip the indicator to hit"
  );
  assert.deepEqual(
    ov["cleartext-api-key-in-dotfile__fp_checks"],
    { "0": true, "1": true, "2": true },
    "the google value regex must let cleartextFpIndices attest all three deterministic FP checks — an empty {} here re-introduces the runner downgrade"
  );
});

/**
 * collector_errors reachability.
 *
 * The ai-api collector declared `collector_errors: []` and never pushed to it.
 * Every credential-store read failure was swallowed by readSafe returning null,
 * and an unparseable gcloud ADC returned `{ hasServiceAccount: false }` — which
 * the collector renders as `gcp-service-account-json: "miss"`. A file that
 * could not be read and a file that was read and holds nothing therefore
 * produced byte-identical output: a clean bill of health over an unscanned
 * store. The reason now travels on the submission, which bin/exceptd.js prints
 * as "Collector warnings" and the runner forwards as collector_warnings.
 */

function mkTmpHome(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

test("ai-api: an unparseable gcloud ADC reports inconclusive and an uncaptured artifact, not a clean scan", () => {
  const home = mkTmpHome("ai-err-adc-");
  try {
    const adcDir = path.join(home, ".config", "gcloud");
    fs.mkdirSync(adcDir, { recursive: true });
    fs.writeFileSync(path.join(adcDir, "application_default_credentials.json"), '{"type":"service_account"', "utf8");

    const r = aiApi.collect({ cwd: home, env: { HOME: home } });

    assert.ok(Array.isArray(r.collector_errors), "collector_errors must be an array");
    const hit = r.collector_errors.find(
      (e) => e.artifact_id === "gcp-credentials" && e.kind === "parse_failed",
    );
    assert.ok(
      hit,
      `expected a gcp-credentials/parse_failed entry; got ${JSON.stringify(r.collector_errors)}`,
    );
    assert.equal(typeof hit.reason, "string");
    assert.match(hit.reason, /application_default_credentials\.json/);
    // A file whose contents were never validated cannot answer the question the
    // indicator asks, so it reports inconclusive. `miss` would state that no
    // service account is present on the strength of a parse that failed.
    assert.equal(r.signal_overrides["gcp-service-account-json"], "inconclusive");
    // Read-but-unparseable is not capture: the bytes arrived and told us
    // nothing, so the artifact must not claim service_account=false.
    const art = r.artifacts["gcp-credentials"];
    assert.equal(art.captured, false);
    assert.match(art.value, /unparseable/);
    assert.equal(typeof art.reason, "string");
  } finally {
    fs.rmSync(home, { recursive: true, force: true });
  }
});

test("ai-api: a shell rc over the scan cap is recorded as file_too_large_skipped, not silently unscanned", () => {
  const home = mkTmpHome("ai-err-big-");
  try {
    // Over the 256 KB readSafe cap, with a real export inside: the collector
    // cannot see the key, so the operator has to be told the file was skipped.
    const rc =
      "# padding\n".repeat(30000) +
      'export OPENAI_API_KEY="sk-' + "A".repeat(48) + '"\n';
    assert.ok(Buffer.byteLength(rc, "utf8") > 256 * 1024, "fixture must exceed the scan cap");
    fs.writeFileSync(path.join(home, ".bashrc"), rc, "utf8");

    const r = aiApi.collect({ cwd: home, env: { HOME: home } });

    const hit = r.collector_errors.find((e) => e.kind === "file_too_large_skipped");
    assert.ok(
      hit,
      `expected a file_too_large_skipped entry; got ${JSON.stringify(r.collector_errors)}`,
    );
    assert.equal(hit.artifact_id, "shell-rc-files");
    assert.equal(typeof hit.reason, "string");
    // Home-relative, never the absolute path: collector_meta already carries
    // `home`, and the absolute path is operator-identifying.
    assert.match(hit.reason, /^\.bashrc: \d+ bytes exceeds \d+-byte scan limit/);
    assert.equal(
      hit.reason.includes(home),
      false,
      "the skip reason must not embed the absolute home path",
    );
    // The key inside the skipped file was NOT seen — which is the point, and
    // is why the verdict cannot be `miss`. This fixture holds a real key the
    // collector never read, so reporting no cleartext key would be a clean
    // bill of health over the one file that carries one.
    assert.equal(r.signal_overrides["cleartext-api-key-in-dotfile"], "inconclusive");
  } finally {
    fs.rmSync(home, { recursive: true, force: true });
  }
});

test("ai-api: an unread credential store reports inconclusive, never a clean miss", () => {
  const home = mkTmpHome("ai-err-unread-");
  try {
    // Over the scan cap, so readSafe returns null for a file that exists. The
    // store could hold a long-lived key or a static token; nothing in it was
    // read, so neither indicator may answer for it.
    const big = "#".repeat(300 * 1024) + "\n";
    fs.mkdirSync(path.join(home, ".aws"), { recursive: true });
    fs.writeFileSync(path.join(home, ".aws", "credentials"), big, "utf8");
    fs.mkdirSync(path.join(home, ".kube"), { recursive: true });
    fs.writeFileSync(path.join(home, ".kube", "config"), big, "utf8");

    const r = aiApi.collect({ cwd: home, env: { HOME: home } });

    assert.equal(r.signal_overrides["long-lived-aws-keys"], "inconclusive");
    assert.equal(r.signal_overrides["kubeconfig-with-static-token"], "inconclusive");
    assert.equal(r.artifacts["aws-credentials"].captured, false);
    assert.equal(r.artifacts["kube-config"].captured, false);
  } finally {
    fs.rmSync(home, { recursive: true, force: true });
  }
});

test("ai-api: a credential store read as empty is a scanned miss, not an unread gap", () => {
  const home = mkTmpHome("ai-err-empty-");
  try {
    // An empty file reads as "" — a completed scan that found nothing. Testing
    // content truthiness routes it to the unread branch and reports a
    // visibility gap that does not exist, with no reason on collector_errors.
    fs.mkdirSync(path.join(home, ".aws"), { recursive: true });
    fs.writeFileSync(path.join(home, ".aws", "credentials"), "", "utf8");
    fs.mkdirSync(path.join(home, ".kube"), { recursive: true });
    fs.writeFileSync(path.join(home, ".kube", "config"), "", "utf8");

    const r = aiApi.collect({ cwd: home, env: { HOME: home } });

    assert.equal(r.signal_overrides["long-lived-aws-keys"], "miss");
    assert.equal(r.signal_overrides["kubeconfig-with-static-token"], "miss");
    assert.equal(r.artifacts["aws-credentials"].captured, true);
    assert.equal(r.artifacts["kube-config"].captured, true);
    assert.deepEqual(r.collector_errors, []);
  } finally {
    fs.rmSync(home, { recursive: true, force: true });
  }
});

test("ai-api: a clean home leaves collector_errors empty", () => {
  const home = mkTmpHome("ai-err-clean-");
  try {
    fs.writeFileSync(path.join(home, ".bashrc"), "# nothing interesting here\n", "utf8");
    const r = aiApi.collect({ cwd: home, env: { HOME: home } });
    assert.deepEqual(r.collector_errors, [], "an absent store is not an error — the channel must not over-report");
  } finally {
    fs.rmSync(home, { recursive: true, force: true });
  }
});

/** Over the readSafe scan cap, with a plausible key export inside. */
function oversizedKeyFile() {
  return "# padding\n".repeat(30000) + 'export OPENAI_API_KEY="sk-' + "A".repeat(48) + '"\n';
}

test("ai-api: a skipped dotfile carrier is reported against dotfile-api-keys, not the shell-rc row", () => {
  const home = mkTmpHome("ai-err-dotfile-");
  try {
    // `~/.anthropic` is a dotfile carrier, and the collector declares
    // dotfile-api-keys as its own artifact. Routing its read failure to
    // shell-rc-files points the operator at a file that scanned fine.
    fs.writeFileSync(path.join(home, ".anthropic"), oversizedKeyFile(), "utf8");
    // A shell rc that reads cleanly, so a wrong attribution is unambiguous.
    fs.writeFileSync(path.join(home, ".bashrc"), "# nothing interesting here\n", "utf8");

    const r = aiApi.collect({ cwd: home, env: { HOME: home } });

    const hit = r.collector_errors.find((e) => e.kind === "file_too_large_skipped");
    assert.ok(hit, `expected a file_too_large_skipped entry; got ${JSON.stringify(r.collector_errors)}`);
    assert.equal(
      hit.artifact_id,
      "dotfile-api-keys",
      "the carrier's own artifact owns the failure — shell-rc-files scanned without incident",
    );
    assert.equal(typeof hit.reason, "string");
    assert.match(hit.reason, /^\.anthropic: \d+ bytes exceeds \d+-byte scan limit/);
    assert.equal(
      r.collector_errors.some((e) => e.artifact_id === "shell-rc-files"),
      false,
      "no shell rc failed to read, so nothing may be attributed to shell-rc-files",
    );
  } finally {
    fs.rmSync(home, { recursive: true, force: true });
  }
});

test("ai-api: a KUBECONFIG in a home-prefixed SIBLING directory is labelled by basename, with no ../ chain", () => {
  // "/home/rob" is a string prefix of "/home/robert-backup", so a bare
  // startsWith() treats a sibling account's kubeconfig as home-relative and
  // labels it "../robert-backup/.kube/config" — the `..` chain the basename
  // branch exists to avoid, carrying another account's directory name into an
  // operator-visible warning.
  const base = mkTmpHome("ai-err-kube-sib-");
  try {
    const home = path.join(base, "rob");
    const sibling = path.join(base, "robert-backup", ".kube");
    fs.mkdirSync(home, { recursive: true });
    fs.mkdirSync(sibling, { recursive: true });
    const kubeCfg = path.join(sibling, "config");
    fs.writeFileSync(kubeCfg, "# padding\n".repeat(30000), "utf8");
    assert.ok(
      kubeCfg.startsWith(home),
      "the fixture must reproduce the sibling-prefix shape a bare startsWith() accepts",
    );

    const r = aiApi.collect({ cwd: home, env: { HOME: home, KUBECONFIG: kubeCfg } });

    const hit = r.collector_errors.find((e) => e.artifact_id === "kube-config");
    assert.ok(hit, `expected a kube-config entry; got ${JSON.stringify(r.collector_errors)}`);
    assert.equal(hit.kind, "file_too_large_skipped");
    assert.equal(typeof hit.reason, "string");
    assert.match(hit.reason, /^config: \d+ bytes exceeds \d+-byte scan limit/);
    assert.equal(hit.reason.includes(".."), false, "a sibling path must not degrade to a ../ chain");
    assert.equal(
      hit.reason.includes("robert-backup"),
      false,
      "the label must not leak the sibling directory name",
    );
  } finally {
    fs.rmSync(base, { recursive: true, force: true });
  }
});

test("ai-api: a credential store that exists but went unread reports captured:false, never 'absent'", () => {
  const home = mkTmpHome("ai-err-unread-");
  try {
    // Every one of the three canonical stores exists and is over the scan cap,
    // so each is present-and-unread. Rendering "absent" here is a positive
    // claim about a file the collector never opened past its size.
    const big = "# padding\n".repeat(30000);
    fs.mkdirSync(path.join(home, ".aws"), { recursive: true });
    fs.writeFileSync(path.join(home, ".aws", "credentials"), big, "utf8");
    fs.mkdirSync(path.join(home, ".config", "gcloud"), { recursive: true });
    fs.writeFileSync(path.join(home, ".config", "gcloud", "application_default_credentials.json"), big, "utf8");
    fs.mkdirSync(path.join(home, ".kube"), { recursive: true });
    fs.writeFileSync(path.join(home, ".kube", "config"), big, "utf8");

    const r = aiApi.collect({ cwd: home, env: { HOME: home } });

    // The exact strings the collector emits when the store really is missing.
    // The unread rendering must be none of them.
    const ABSENCE_CLAIM = {
      "aws-credentials": "~/.aws/credentials absent",
      "gcp-credentials": "no gcloud ADC at the canonical path",
      "kube-config": "no kubeconfig at the canonical path",
    };
    for (const [id, absent] of Object.entries(ABSENCE_CLAIM)) {
      const a = r.artifacts[id];
      assert.equal(typeof a.value, "string", `${id}: value must be a string`);
      assert.notEqual(a.value, absent, `${id}: "${absent}" asserts absence for a file that exists`);
      assert.match(a.value, /present but unread/, `${id}: must say the store was not read`);
      assert.match(a.value, /undetermined, not absent/, `${id}: must not claim absence`);
      assert.equal(a.captured, false, `${id}: an unread store is not captured`);
      assert.equal(typeof a.reason, "string", `${id}: captured:false requires a reason`);
      assert.ok(
        r.collector_errors.some((e) => e.artifact_id === id),
        `${id}: the unread store must also appear on collector_errors`,
      );
    }
  } finally {
    fs.rmSync(home, { recursive: true, force: true });
  }
});

test("ai-api: a genuinely absent store still reports absent and captured:true", () => {
  const home = mkTmpHome("ai-err-absent-");
  try {
    fs.writeFileSync(path.join(home, ".bashrc"), "# nothing interesting here\n", "utf8");
    const r = aiApi.collect({ cwd: home, env: { HOME: home } });

    assert.equal(r.artifacts["aws-credentials"].value, "~/.aws/credentials absent");
    assert.equal(r.artifacts["aws-credentials"].captured, true);
    assert.equal(r.artifacts["gcp-credentials"].value, "no gcloud ADC at the canonical path");
    assert.equal(r.artifacts["gcp-credentials"].captured, true);
    assert.equal(r.artifacts["kube-config"].value, "no kubeconfig at the canonical path");
    assert.equal(r.artifacts["kube-config"].captured, true);
    assert.deepEqual(r.collector_errors, []);
  } finally {
    fs.rmSync(home, { recursive: true, force: true });
  }
});
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});
