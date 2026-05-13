"use strict";
/**
 * Diff-coverage analyzer tests.
 *
 * Every test builds a throwaway git repo under mkdtempSync, stages or
 * commits a synthetic diff, then invokes the analyzer against that repo.
 * Nothing here mutates the real project's git state.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const os = require("node:os");
const childProc = require("node:child_process");

const ANALYZER = path.join(__dirname, "..", "scripts", "check-test-coverage.js");

function sh(cmd, args, cwd, env) {
  const r = childProc.spawnSync(cmd, args, {
    cwd, encoding: "utf8",
    env: env || { ...process.env, GIT_AUTHOR_NAME: "t", GIT_AUTHOR_EMAIL: "t@t",
                  GIT_COMMITTER_NAME: "t", GIT_COMMITTER_EMAIL: "t@t" },
  });
  return r;
}

function mkRepo() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "diff-cov-"));
  const r = sh("git", ["init", "-q", "-b", "main"], dir);
  assert.equal(r.status, 0, "git init failed: " + r.stderr);
  sh("git", ["config", "user.email", "t@t"], dir);
  sh("git", ["config", "user.name", "t"], dir);
  sh("git", ["config", "commit.gpgsign", "false"], dir);
  return dir;
}

function write(repo, rel, content) {
  const abs = path.join(repo, rel);
  fs.mkdirSync(path.dirname(abs), { recursive: true });
  fs.writeFileSync(abs, content);
}

function commit(repo, message) {
  sh("git", ["add", "-A"], repo);
  const r = sh("git", ["commit", "-q", "--no-gpg-sign", "-m", message], repo);
  assert.equal(r.status, 0, "git commit failed: " + r.stderr);
}

function runAnalyzer(repo, extraArgs) {
  // Default: compare HEAD vs HEAD~1 (single-commit diff against parent).
  const args = [ANALYZER, "--repo", repo, "--base", "HEAD~1", "--json"]
    .concat(extraArgs || []);
  const r = sh(process.execPath, args, repo);
  let parsed = null;
  try { parsed = JSON.parse(r.stdout); } catch { /* leave null */ }
  return { status: r.status, stdout: r.stdout, stderr: r.stderr, json: parsed };
}

// Seed a baseline commit: bare bin/exceptd.js with two verbs + a tests/ tree.
function seedBaseline(repo) {
  write(repo, "bin/exceptd.js",
    'const COMMANDS = {\n  ping: () => "lib/ping.js",\n  pong: () => "lib/pong.js",\n};\n' +
    'const PLAYBOOK_VERBS = new Set([\n  "run",\n]);\n');
  write(repo, "tests/baseline.test.js",
    "// references: 'ping' 'pong' 'run'\n" +
    "// flag: --base\n");
  write(repo, "data/playbooks/example.json", JSON.stringify({
    phases: { detect: { indicators: [{ id: "old-indicator" }] },
              look:   { artifacts:  [{ id: "old-artifact"  }] } },
  }, null, 2));
  write(repo, "data/cve-catalog.json", JSON.stringify({
    "CVE-2026-00001": { iocs: { ip: ["1.1.1.1"] } },
  }, null, 2));
  write(repo, "lib/scoring.js", "function score(){} module.exports = { score };\n");
  // Reference the existing surface in baseline so it counts as covered.
  fs.appendFileSync(path.join(repo, "tests/baseline.test.js"),
    "// 'old-indicator' 'old-artifact'\n" +
    "// CVE-2026-00001 iocs\n" +
    "// require('../lib/scoring') score\n");
  commit(repo, "baseline");
}

test("docs-only change → green", () => {
  const repo = mkRepo();
  seedBaseline(repo);
  write(repo, "README.md", "# hello\n");
  write(repo, "CHANGELOG.md", "## next\n");
  commit(repo, "docs");

  const r = runAnalyzer(repo);
  assert.equal(r.status, 0, "expected exit 0, got " + r.status + " stderr=" + r.stderr);
  assert.equal(r.json.ok, true);
  assert.equal(r.json.findings.length, 0);
});

test("new CLI verb added without test → red with the verb name", () => {
  const repo = mkRepo();
  seedBaseline(repo);
  write(repo, "bin/exceptd.js",
    'const COMMANDS = {\n  ping: () => "lib/ping.js",\n  pong: () => "lib/pong.js",\n  newverb: () => "lib/newverb.js",\n};\n' +
    'const PLAYBOOK_VERBS = new Set([\n  "run",\n]);\n');
  commit(repo, "add newverb");

  const r = runAnalyzer(repo);
  assert.equal(r.status, 1);
  assert.equal(r.json.ok, false);
  const f = r.json.findings.find(x => x.surface === "newverb");
  assert.ok(f, "expected finding for newverb in " + JSON.stringify(r.json.findings));
  assert.equal(f.kind, "cli-verb");
  assert.equal(f.change, "added");
});

test("new playbook indicator without an e2e scenario → red with indicator id", () => {
  const repo = mkRepo();
  seedBaseline(repo);
  write(repo, "data/playbooks/example.json", JSON.stringify({
    phases: {
      detect: { indicators: [{ id: "old-indicator" }, { id: "fresh-indicator" }] },
      look:   { artifacts:  [{ id: "old-artifact" }] },
    },
  }, null, 2));
  commit(repo, "new indicator");

  const r = runAnalyzer(repo);
  assert.equal(r.status, 1);
  const f = r.json.findings.find(x => x.surface === "fresh-indicator");
  assert.ok(f, "expected finding for fresh-indicator");
  assert.equal(f.kind, "playbook-indicator");
  assert.equal(f.change, "added");
});

test("new CVE iocs field without test → red", () => {
  const repo = mkRepo();
  seedBaseline(repo);
  write(repo, "data/cve-catalog.json", JSON.stringify({
    "CVE-2026-00001": { iocs: { ip: ["1.1.1.1"] } },
    "CVE-2026-99999": { iocs: { ip: ["2.2.2.2"] } },
  }, null, 2));
  commit(repo, "add cve");

  const r = runAnalyzer(repo);
  assert.equal(r.status, 1);
  const f = r.json.findings.find(x => x.surface === "CVE-2026-99999");
  assert.ok(f);
  assert.equal(f.kind, "cve-ioc");
  assert.equal(f.change, "iocs-modified");
});

test("removed CLI flag while test still references it → red (orphaned test)", () => {
  const repo = mkRepo();
  // Seed with --foobar flag in CLI + test reference.
  write(repo, "bin/exceptd.js",
    'const COMMANDS = {\n  ping: () => "x",\n};\n' +
    'const PLAYBOOK_VERBS = new Set([\n  "run",\n]);\n' +
    '// handler reads --foobar\n');
  write(repo, "tests/uses.test.js", "// cli expects '--foobar'\n// 'ping' 'run'\n");
  commit(repo, "baseline");
  write(repo, "bin/exceptd.js",
    'const COMMANDS = {\n  ping: () => "x",\n};\n' +
    'const PLAYBOOK_VERBS = new Set([\n  "run",\n]);\n' +
    '// flag removed\n');
  commit(repo, "remove flag");

  const r = runAnalyzer(repo);
  assert.equal(r.status, 1);
  const f = r.json.findings.find(x => x.surface === "--foobar");
  assert.ok(f, "expected orphan finding for --foobar; got " + JSON.stringify(r.json.findings));
  assert.equal(f.kind, "cli-flag");
  assert.equal(f.change, "removed-but-test-remains");
});

test("--warn-only flips fail to pass with the finding still surfaced", () => {
  const repo = mkRepo();
  seedBaseline(repo);
  write(repo, "bin/exceptd.js",
    'const COMMANDS = {\n  ping: () => "x",\n  pong: () => "y",\n  warned: () => "z",\n};\n' +
    'const PLAYBOOK_VERBS = new Set([\n  "run",\n]);\n');
  commit(repo, "warn case");

  const r = runAnalyzer(repo, ["--warn-only"]);
  assert.equal(r.status, 0, "warn-only must exit zero");
  assert.equal(r.json.ok, false);
  assert.equal(r.json.findings.length >= 1, true);
  assert.equal(r.json.findings.some(f => f.surface === "warned"), true);
});

test("--staged operates on the index against HEAD", () => {
  const repo = mkRepo();
  seedBaseline(repo);
  // Modify file but only stage, do not commit.
  write(repo, "bin/exceptd.js",
    'const COMMANDS = {\n  ping: () => "x",\n  pong: () => "y",\n  stagedverb: () => "z",\n};\n' +
    'const PLAYBOOK_VERBS = new Set([\n  "run",\n]);\n');
  sh("git", ["add", "bin/exceptd.js"], repo);
  // Run with --staged (no --base / parent comparison).
  const r = sh(process.execPath,
    [ANALYZER, "--repo", repo, "--staged", "--json"], repo);
  const j = JSON.parse(r.stdout);
  assert.equal(r.status, 1);
  assert.equal(j.findings.some(f => f.surface === "stagedverb" && f.change === "added"), true);
});

test("--json output shape matches contract", () => {
  const repo = mkRepo();
  seedBaseline(repo);
  write(repo, "README.md", "# touch\n");
  commit(repo, "docs only");

  const r = runAnalyzer(repo);
  assert.equal(r.status, 0);
  const j = r.json;
  assert.equal(typeof j.ok, "boolean");
  assert.equal(typeof j.total_changed, "number");
  assert.ok(Array.isArray(j.findings));
  assert.ok(Array.isArray(j.allowlisted));
  assert.ok(Array.isArray(j.manual_review));
  // README.md must be allowlisted as docs.
  assert.equal(j.allowlisted.some(a => a.file === "README.md" && a.reason === "docs"), true);
});

test("whitespace-only change is allowlisted", () => {
  const repo = mkRepo();
  seedBaseline(repo);
  // Add trailing spaces only.
  const p = path.join(repo, "lib/scoring.js");
  const before = fs.readFileSync(p, "utf8");
  fs.writeFileSync(p, before.replace("score };\n", "score };  \n"));
  commit(repo, "whitespace");

  const r = runAnalyzer(repo);
  assert.equal(r.status, 0);
  assert.equal(r.json.findings.length, 0);
  assert.equal(r.json.allowlisted.some(a => a.file === "lib/scoring.js" && a.reason === "whitespace-only"), true);
});

test("workflow yml change is surfaced for manual review, not a finding", () => {
  const repo = mkRepo();
  seedBaseline(repo);
  write(repo, ".github/workflows/ci.yml", "name: ci\non: push\n");
  commit(repo, "workflow");

  const r = runAnalyzer(repo);
  assert.equal(r.status, 0);
  assert.equal(r.json.findings.length, 0);
  assert.equal(r.json.manual_review.some(m => m.file === ".github/workflows/ci.yml"), true);
});

test("test file changes do not recurse", () => {
  const repo = mkRepo();
  seedBaseline(repo);
  write(repo, "tests/new.test.js", "// adds coverage for nothing\n");
  commit(repo, "tests only");

  const r = runAnalyzer(repo);
  assert.equal(r.status, 0);
  assert.equal(r.json.findings.length, 0);
  assert.equal(r.json.allowlisted.some(a => a.file === "tests/new.test.js" && a.reason === "test"), true);
});

test("new lib export without test → red", () => {
  const repo = mkRepo();
  seedBaseline(repo);
  write(repo, "lib/scoring.js",
    "function score(){} function newApi(){} module.exports = { score, newApi };\n");
  commit(repo, "new export");

  const r = runAnalyzer(repo);
  assert.equal(r.status, 1);
  const f = r.json.findings.find(x => x.surface === "newApi");
  assert.ok(f);
  assert.equal(f.kind, "lib-export");
  assert.equal(f.change, "added");
  assert.equal(f.file, "lib/scoring.js");
});
