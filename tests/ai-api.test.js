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
    'export GOOGLE_API_KEY="AIzaSyA1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q"\n'
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
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});
