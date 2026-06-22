"use strict";


// ---- routed from collector-scan-excludes ----
require("node:test").describe("collector-scan-excludes", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
/**
 * tests/collector-scan-excludes.test.js
 *
 * Pins the shared directory-walk exclusion policy used by every
 * code-scope collector (lib/collectors/scan-excludes.js):
 *
 *   - `.claude` (agent/editor scratch) is in the default exclude set,
 *     so collectors never descend into it.
 *   - isLinkedWorktreeDir() distinguishes a linked git worktree (its
 *     `.git` is a gitdir-pointer FILE) from a real repo root (its
 *     `.git` is a DIRECTORY).
 *   - A collector walk skips a `.claude/worktrees/<id>/` repo copy so
 *     duplicated source files don't inflate hit counts.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const os = require("node:os");

const ROOT = path.join(__dirname, "..");
const {
  DEFAULT_CODE_EXCLUDES,
  codeExcludeSet,
  isLinkedWorktreeDir,
} = require(path.join(ROOT, "lib", "collectors", "scan-excludes.js"));
const secretsCollector = require(path.join(ROOT, "lib", "collectors", "secrets.js"));

function mkTmp(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

test("(a) .claude is in the shared default code-scope exclude set", () => {
  assert.ok(DEFAULT_CODE_EXCLUDES.includes(".claude"),
    ".claude must be excluded so agent/editor scratch is never walked");
  // codeExcludeSet() must carry the default forward and merge extras.
  const set = codeExcludeSet(["my-extra"]);
  assert.ok(set.has(".claude"), "codeExcludeSet() must retain .claude");
  assert.ok(set.has("node_modules"), "codeExcludeSet() must retain shared defaults");
  assert.ok(set.has("my-extra"), "codeExcludeSet(extra) must merge collector-specific extras");
});

test("(b) isLinkedWorktreeDir: true for a .git-FILE dir, false for a .git-DIR", () => {
  const tmp = mkTmp("scan-excl-wt-");
  try {
    // Linked worktree: `.git` is a gitdir-pointer FILE.
    const linked = path.join(tmp, "linked");
    fs.mkdirSync(linked);
    fs.writeFileSync(path.join(linked, ".git"), "gitdir: /somewhere/.git/worktrees/x\n");
    assert.equal(isLinkedWorktreeDir(linked), true,
      "a directory whose .git is a FILE is a linked worktree");

    // Normal repo root: `.git` is a DIRECTORY.
    const repo = path.join(tmp, "repo");
    fs.mkdirSync(repo);
    fs.mkdirSync(path.join(repo, ".git"));
    assert.equal(isLinkedWorktreeDir(repo), false,
      "a directory whose .git is a DIRECTORY is a normal repo root, not a linked worktree");

    // No .git at all: not a worktree.
    const plain = path.join(tmp, "plain");
    fs.mkdirSync(plain);
    assert.equal(isLinkedWorktreeDir(plain), false,
      "a directory with no .git entry is not a linked worktree");
  } finally {
    try { fs.rmSync(tmp, { recursive: true, force: true }); } catch {}
  }
});

test("(c) collector walk skips a .claude/worktrees copy (no duplicate hits)", () => {
  const tmp = mkTmp("scan-excl-claude-");
  try {
    // Host-tree source carrying a recognisable secret. Use a real-shaped
    // GitHub PAT, not the AWS doc example key (which the collector demotes).
    const src = 'const token = "ghp_' + "A".repeat(36) + '";\n';
    fs.writeFileSync(path.join(tmp, "keys.js"), src);

    // Full repo copy under .claude/worktrees/<id>/ with a gitfile.
    const wt = path.join(tmp, ".claude", "worktrees", "x");
    fs.mkdirSync(wt, { recursive: true });
    fs.writeFileSync(path.join(wt, "keys.js"), src);
    fs.writeFileSync(path.join(wt, ".git"), "gitdir: /elsewhere/.git/worktrees/x\n");

    const r = secretsCollector.collect({ cwd: tmp });
    const blob = JSON.stringify(r.artifacts);
    assert.equal(/worktrees/.test(blob), false,
      ".claude/worktrees copy must not appear in the secrets scan evidence");
    // The single host-tree keys.js is the only carrier counted.
    assert.equal((blob.match(/keys\.js/g) || []).length, 1,
      "only the host-tree keys.js should be counted, not the worktree duplicate");
  } finally {
    try { fs.rmSync(tmp, { recursive: true, force: true }); } catch {}
  }
});

test("(c2) worktree guard skips a linked worktree even outside an excluded dir name", () => {
  // Proves the guard is independent of the `.claude` name exclusion:
  // a linked worktree under any directory name is skipped, while a
  // normal nested repo (real `.git` directory) is still walked.
  // Real-shaped GitHub PAT (not the demoted AWS doc example key).
  const src = 'const token = "ghp_' + "A".repeat(36) + '";\n';

  // Linked worktree under a non-excluded dir name -> skipped.
  const a = mkTmp("scan-excl-linked-");
  try {
    fs.writeFileSync(path.join(a, "keys.js"), src);
    const wt = path.join(a, "wtcopy");
    fs.mkdirSync(wt);
    fs.writeFileSync(path.join(wt, "keys.js"), src);
    fs.writeFileSync(path.join(wt, ".git"), "gitdir: /elsewhere\n");
    const ra = secretsCollector.collect({ cwd: a });
    assert.equal(/wtcopy/.test(JSON.stringify(ra.artifacts)), false,
      "a linked worktree (gitfile) must be skipped regardless of its directory name");
  } finally {
    try { fs.rmSync(a, { recursive: true, force: true }); } catch {}
  }

  // Normal nested repo (real .git directory) under the same name -> walked.
  const b = mkTmp("scan-excl-repo-");
  try {
    fs.writeFileSync(path.join(b, "keys.js"), src);
    const nested = path.join(b, "wtcopy");
    fs.mkdirSync(nested);
    fs.writeFileSync(path.join(nested, "keys.js"), src);
    fs.mkdirSync(path.join(nested, ".git"));
    const rb = secretsCollector.collect({ cwd: b });
    assert.equal(/wtcopy/.test(JSON.stringify(rb.artifacts)), true,
      "a normal nested repo (real .git directory) must still be walked");
  } finally {
    try { fs.rmSync(b, { recursive: true, force: true }); } catch {}
  }
});
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});


// ---- routed from collector-walk-symlink-cycle ----
require("node:test").describe("collector-walk-symlink-cycle", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
/**
 * tests/collector-walk-symlink-cycle.test.js
 *
 * Guards the shared cwd-tree walker (lib/collectors/scan-excludes.js
 * walkTree), which realpaths only directories and symlinks — never regular
 * files — for its symlink-cycle `seen` set. This test pins the two
 * properties that reduction must never break:
 *
 *   (a) A symlink CYCLE (a directory symlink pointing back at an ancestor)
 *       is handled safely: the walk terminates, returns a finite file list,
 *       and never throws. A regression that dropped directory realpath would
 *       loop forever / overflow the stack here.
 *   (b) A planted secret in a DEEP directory is still discovered. A
 *       regression that broke traversal (e.g. realpath-on-files removal
 *       skipping the file emit) would lose the deep hit.
 *
 * No wall-clock assertion — timing is flaky across CI hosts. Gross
 * slowdowns are already guarded by the redos-whitespace-line suite.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const os = require("node:os");

const ROOT = path.join(__dirname, "..");
const { walkTree } = require(path.join(ROOT, "lib", "collectors", "scan-excludes.js"));
const secretsCollector = require(path.join(ROOT, "lib", "collectors", "secrets.js"));

function mkTmp(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

// Real-shaped GitHub PAT — the AWS doc example key is demoted by the
// collector, so use a token literal that genuinely fires.
const SECRET = 'const token = "ghp_' + "A".repeat(36) + '";\n';

// Create a directory symlink, returning false if the platform refuses
// (Windows without the privilege). Tests that depend on a symlink skip
// themselves rather than fail on such hosts.
function trySymlinkDir(target, linkPath) {
  try {
    fs.symlinkSync(target, linkPath, "dir");
    return true;
  } catch {
    return false;
  }
}

test("(a) walkTree terminates on a directory symlink cycle without throwing", () => {
  const tmp = mkTmp("walk-cycle-");
  try {
    // a/b/c real directory chain with a file at the bottom.
    const a = path.join(tmp, "a");
    const b = path.join(a, "b");
    const c = path.join(b, "c");
    fs.mkdirSync(c, { recursive: true });
    fs.writeFileSync(path.join(c, "leaf.txt"), "leaf\n");

    // Cycle: a/b/c/loop -> a  (points back at an ancestor).
    const made = trySymlinkDir(a, path.join(c, "loop"));
    if (!made) {
      // Platform refuses directory symlinks — nothing to assert here.
      return;
    }

    let files;
    assert.doesNotThrow(() => {
      files = walkTree(tmp, { maxDepth: 8 });
    }, "walkTree must not throw / loop forever on a symlink cycle");

    // Finite, and the real leaf file is present exactly once.
    assert.ok(Array.isArray(files), "walkTree returns an array");
    const leaves = files.filter((f) => f.name === "leaf.txt");
    assert.equal(leaves.length, 1, "the real leaf file is emitted exactly once despite the cycle");
    // The directory symlink itself is never traversed nor emitted as a file.
    assert.equal(files.some((f) => f.name === "loop"), false, "the directory symlink is not emitted as a file");
  } finally {
    try { fs.rmSync(tmp, { recursive: true, force: true }); } catch {}
  }
});

test("(b) a planted secret in a deep directory is still discovered", () => {
  const tmp = mkTmp("walk-deep-secret-");
  try {
    // Deep nest within the secrets collector's depth budget (<= 6).
    const deep = path.join(tmp, "src", "app", "config", "env");
    fs.mkdirSync(deep, { recursive: true });
    fs.writeFileSync(path.join(deep, "creds.js"), SECRET);

    const r = secretsCollector.collect({ cwd: tmp });
    assert.equal(
      r.signal_overrides["github-personal-access-token"],
      "hit",
      "a GitHub PAT planted in a deep directory must still flip the indicator to hit",
    );
    const blob = JSON.stringify(r.artifacts);
    assert.equal(/creds\.js/.test(blob), true, "the deep secret-carrier file appears in the evidence");
  } finally {
    try { fs.rmSync(tmp, { recursive: true, force: true }); } catch {}
  }
});

test("(c) walkTree skips a directory symlink cycle yet still finds a secret beyond it", () => {
  // Combined: a cycle near the root must not prevent discovery of a real
  // secret in a sibling deep directory.
  const tmp = mkTmp("walk-cycle-secret-");
  try {
    const loopHost = path.join(tmp, "loophost");
    fs.mkdirSync(loopHost, { recursive: true });
    const made = trySymlinkDir(tmp, path.join(loopHost, "back")); // back -> root: cycle

    const deep = path.join(tmp, "lib", "secrets");
    fs.mkdirSync(deep, { recursive: true });
    // Use a non-.env carrier: a .env file is legitimately recorded in TWO
    // artifact categories (general scan + env-file carrier), which would make
    // a raw filename-occurrence count 2 even with no symlink at all. A .js
    // carrier is recorded once, so an occurrence count > 1 genuinely indicates
    // the cycle re-walked the file via a second path.
    fs.writeFileSync(path.join(deep, "leak_carrier.js"), 'const t = "ghp_' + "B".repeat(36) + '";\n');

    let r;
    assert.doesNotThrow(() => {
      r = secretsCollector.collect({ cwd: tmp });
    }, "collect must terminate even with a root-pointing symlink cycle present");

    // Whether or not the platform created the symlink, the real secret fires.
    assert.equal(
      r.signal_overrides["github-personal-access-token"],
      "hit",
      "the real secret beyond the cycle is still discovered",
    );
    if (!made) return; // symlink not created — cycle-specific check skipped
    // The cycle did not duplicate the carrier into a second walked path.
    const occurrences = (JSON.stringify(r.artifacts).match(/leak_carrier\.js/g) || []).length;
    assert.equal(occurrences, 1, "the secret carrier is counted once, not duplicated via the cycle");
  } finally {
    try { fs.rmSync(tmp, { recursive: true, force: true }); } catch {}
  }
});
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});


// ---- routed from collectors-fp-fixes ----
require("node:test").describe("collectors-fp-fixes", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
/**
 * tests/collectors-fp-fixes.test.js
 *
 * Regression tests for a batch of collector false-positive / completeness
 * fixes:
 *   1. sbom: lockfile-no-integrity must NOT fire on a clean npm 7+ lockfile
 *      whose `""` root entry carries name+version but no integrity. It must
 *      still fire when a REMOTE-tarball entry (one with `resolved`) is missing
 *      integrity.
 *   2. secrets: a text file over the 1 MB scan limit is no longer silently
 *      dropped — the skip is recorded in collector_errors.
 *   3. secrets: the AWS-published example access-key id AKIAIOSFODNN7EXAMPLE
 *      does not flip aws-access-key-id.
 *   4. cicd-pipeline-compromise: an OIDC trust JSON under a build-output dir
 *      (dist/) is excluded from the scan via the shared code-exclude set.
 *   5. content-regex collectors (secrets / crypto-codebase / citation-hygiene)
 *      attach a 1-based startLine to their evidence_locations.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const os = require("node:os");

const ROOT = path.join(__dirname, "..");

const sbomCollector = require(path.join(ROOT, "lib", "collectors", "sbom.js"));
const secretsCollector = require(path.join(ROOT, "lib", "collectors", "secrets.js"));
const cryptoCollector = require(path.join(ROOT, "lib", "collectors", "crypto-codebase.js"));
const citationCollector = require(path.join(ROOT, "lib", "collectors", "citation-hygiene.js"));
const cicdCollector = require(path.join(ROOT, "lib", "collectors", "cicd-pipeline-compromise.js"));
const { lineFromOffset } = require(path.join(ROOT, "lib", "collectors", "scan-excludes.js"));

function mkTmp(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

// ---------------------------------------------------------------------------
// Finding 1 — sbom lockfile-no-integrity
// ---------------------------------------------------------------------------



// ---------------------------------------------------------------------------
// Finding 2 — secrets >1 MB skip is recorded
// ---------------------------------------------------------------------------


// ---------------------------------------------------------------------------
// Finding 3 — AWS doc example key demotion
// ---------------------------------------------------------------------------



// ---------------------------------------------------------------------------
// Finding 4 — cicd OIDC scan honors code-exclude set (dist/)
// ---------------------------------------------------------------------------

const WILDCARD_OIDC = JSON.stringify({
  Statement: [{
    Effect: "Allow",
    Principal: { Federated: "token.actions.githubusercontent.com" },
    Condition: {
      StringLike: {
        "token.actions.githubusercontent.com:sub": "repo:acme/*:*",
      },
    },
  }],
}, null, 2);



// ---------------------------------------------------------------------------
// Finding 5 — evidence_locations carry startLine
// ---------------------------------------------------------------------------

test("lineFromOffset maps byte offset to 1-based line", () => {
  const content = "line1\nline2\nline3";
  assert.equal(lineFromOffset(content, 0), 1);
  assert.equal(lineFromOffset(content, 6), 2);   // start of line2
  assert.equal(lineFromOffset(content, 12), 3);  // start of line3
  assert.equal(lineFromOffset(content, -5), 1);  // fallback
  assert.equal(lineFromOffset(content, 99999), 3); // clamped to content end
});
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});
