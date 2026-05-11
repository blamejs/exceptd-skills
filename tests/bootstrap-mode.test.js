"use strict";
/**
 * Bootstrap mode-detection regression test.
 *
 * The bootstrap script is the single command a contributor runs on a fresh
 * clone. It MUST distinguish three states without misclassifying:
 *
 *   - Downstream consumer state:  keys/public.pem present, .keys/private.pem
 *     missing → VERIFY ONLY. Generating a new keypair here would silently
 *     overwrite the maintainer's shipped public key and re-sign every skill
 *     with the consumer's local private key, invalidating the upstream
 *     signing chain from the consumer's tree-state perspective.
 *
 *   - Maintainer re-sign state:  .keys/private.pem present → SIGN + VERIFY.
 *     Re-sign every skill against current content.
 *
 *   - First-maintainer init state:  neither key present, OR --init explicitly
 *     passed → GENERATE + SIGN + VERIFY.
 *
 * This file tests the mode-detection logic by inspecting the bootstrap
 * script's source. It does NOT spawn the script (that would touch real
 * filesystem state). The test verifies the logic is structurally present —
 * a stronger guarantee than nothing, weaker than an integration test.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const ROOT = path.join(__dirname, "..");
const BOOTSTRAP = path.join(ROOT, "scripts", "bootstrap.js");

function read() {
  return fs.readFileSync(BOOTSTRAP, "utf8");
}

test("bootstrap.js defines three modes: verify-only, resign, init", () => {
  const src = read();
  assert.match(src, /verify-only/, "verify-only mode must be referenced");
  assert.match(src, /\bresign\b/, "resign mode must be referenced");
  assert.match(src, /\binit\b/, "init mode must be referenced");
});

test("bootstrap.js mode detection prefers verify-only when public key is present and private key is absent", () => {
  const src = read();
  // Structural assertion: the detectMode function returns 'verify-only'
  // when hasPublic && !hasPrivate.
  assert.match(
    src,
    /detectMode[\s\S]*?if\s*\(hasPrivate\)\s*return\s*['"]resign['"]/,
    "detectMode must return 'resign' when private key is present"
  );
  assert.match(
    src,
    /detectMode[\s\S]*?if\s*\(hasPublic\)\s*return\s*['"]verify-only['"]/,
    "detectMode must return 'verify-only' when public key is present (and no private key)"
  );
});

test("bootstrap.js verify-only mode does NOT call generate-keypair or sign-all", () => {
  const src = read();
  // Extract the verify-only branch and assert it only runs VERIFY_SCRIPT.
  const branch = src.match(
    /if\s*\(mode\s*===\s*['"]verify-only['"]\)\s*{[\s\S]*?return;\s*}/
  );
  assert.ok(branch, "verify-only branch must exist");
  const body = branch[0];
  assert.doesNotMatch(
    body,
    /generate-keypair/,
    "verify-only mode MUST NOT call generate-keypair"
  );
  assert.doesNotMatch(
    body,
    /sign-all/,
    "verify-only mode MUST NOT call sign-all"
  );
  assert.match(
    body,
    /VERIFY_SCRIPT/,
    "verify-only mode MUST call VERIFY_SCRIPT"
  );
});

test("bootstrap.js --init flag forces init mode even when keys exist", () => {
  const src = read();
  // detectMode must check args.init first, before the hasPrivate / hasPublic
  // branches. If a maintainer rotates keys, --init is the override.
  assert.match(
    src,
    /detectMode[\s\S]*?if\s*\(args\.init\)\s*return\s*['"]init['"]/,
    "--init must short-circuit to init mode regardless of existing key state"
  );
});

test("bootstrap.js accepts --init, --force, --help; rejects unknown args", () => {
  const src = read();
  assert.match(src, /['"]--init['"]/);
  assert.match(src, /['"]--force['"]/);
  assert.match(src, /['"]--help['"]|['"]-h['"]/);
  assert.match(
    src,
    /Unknown argument/,
    "must reject unknown arguments with a clear message"
  );
});

test("bootstrap.js writes the .bootstrap-complete marker in every mode", () => {
  // The marker is what enables the idempotency short-circuit. Every mode
  // (including verify-only) must write it on success so re-runs don't
  // repeat the work.
  const src = read();
  // Each branch must call writeMarker at least once.
  const branches = ["verify-only", "resign"];
  for (const mode of branches) {
    const branch = src.match(
      new RegExp(`if\\s*\\(mode\\s*===\\s*['"]${mode}['"]\\)\\s*{[\\s\\S]*?return;\\s*}`)
    );
    assert.ok(branch, `${mode} branch must exist`);
    assert.match(
      branch[0],
      /writeMarker\(\)/,
      `${mode} mode must call writeMarker() on success`
    );
  }
  // init mode is the fall-through — must also call writeMarker before exiting.
  assert.match(src, /writeMarker\(\)/);
});

test("README.md quickstart points at the canonical blamejs/exceptd-skills repo", () => {
  const readme = fs.readFileSync(path.join(ROOT, "README.md"), "utf8");
  assert.match(
    readme,
    /github\.com\/blamejs\/exceptd-skills/,
    "README must reference the canonical blamejs/exceptd-skills repo"
  );
  assert.doesNotMatch(
    readme,
    /github\.com\/exceptd\/security/,
    "README must NOT reference the placeholder exceptd/security path"
  );
});

test("package.json, manifest.json, and CHANGELOG.md all agree on the current release version", () => {
  const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, "package.json"), "utf8"));
  const manifest = JSON.parse(fs.readFileSync(path.join(ROOT, "manifest.json"), "utf8"));
  const changelog = fs.readFileSync(path.join(ROOT, "CHANGELOG.md"), "utf8");

  const topHeading = changelog.match(/^## (\d+\.\d+\.\d+)/m);
  assert.ok(topHeading, "CHANGELOG.md must have a top-of-file ## X.Y.Z heading");
  const changelogVersion = topHeading[1];

  assert.equal(
    pkg.version,
    changelogVersion,
    `package.json version (${pkg.version}) must match the latest CHANGELOG entry (${changelogVersion})`
  );
  assert.equal(
    manifest.version,
    changelogVersion,
    `manifest.json version (${manifest.version}) must match the latest CHANGELOG entry (${changelogVersion})`
  );
});

test("AGENTS.md Quick Skill Reference table lists every skill in the manifest", () => {
  const manifest = JSON.parse(fs.readFileSync(path.join(ROOT, "manifest.json"), "utf8"));
  const skillNames = manifest.skills.map((s) => s.name);

  const body = fs.readFileSync(path.join(ROOT, "AGENTS.md"), "utf8");
  assert.match(
    body,
    /## Quick Skill Reference/,
    `AGENTS.md must contain a "## Quick Skill Reference" section`
  );
  for (const name of skillNames) {
    assert.ok(
      body.includes(`| ${name} |`),
      `AGENTS.md Quick Skill Reference must list ${name}`
    );
  }
});

test("AGENTS.md is the single source of truth — no tool-specific mirror files are tracked in the repo", () => {
  // The project ships AGENTS.md only. Tool-specific auto-load files (e.g.
  // a CLAUDE.md mirror) are intentionally NOT shipped — they either
  // duplicate content that drifts, or they reproduce vendor-specific
  // filenames in the repo that other tools don't auto-load. Tool users
  // configure their tool to point at AGENTS.md instead.
  //
  // This test catches a future regression where a maintainer re-adds a
  // CLAUDE.md / GEMINI.md / AGENTS_FOR_X.md mirror file.
  const bannedMirrors = ["CLAUDE.md", "GEMINI.md", "AGENT.md"];
  for (const name of bannedMirrors) {
    assert.ok(
      !fs.existsSync(path.join(ROOT, name)),
      `${name} must not exist — AGENTS.md is the single source of truth. ` +
        `Tool users should configure their tool to load AGENTS.md instead of shipping a per-tool mirror.`
    );
  }
});

test("no tracked file cites CLAUDE.md as if it were a real file in the repo", () => {
  // CLAUDE.md was removed when the project consolidated on AGENTS.md as
  // the single agent-agnostic source. Stale citations to CLAUDE.md (in
  // workflows, schemas, skill bodies, etc.) would mislead contributors
  // into thinking the mirror still exists.
  //
  // Allowed mentions: this test file (which documents the removal),
  // README.md (which explains to Claude Code users how to load
  // AGENTS.md), CHANGELOG.md (history), and AGENTS.md (preamble
  // explaining the consolidation).
  const allowedFiles = new Set([
    "README.md",
    "CHANGELOG.md",
    "AGENTS.md",
    path.join("tests", "bootstrap-mode.test.js"),
    path.join("tests", "check-manifest-snapshot.test.js"),
    path.join("tests", "governance.test.js"),
    path.join("tests", "scoring.test.js"),
  ]);

  const filesToScan = [
    ".github/dependabot.yml",
    ".github/PULL_REQUEST_TEMPLATE.md",
    ".github/ISSUE_TEMPLATE/cve-addition.md",
    ".github/ISSUE_TEMPLATE/feature_request.md",
    ".github/ISSUE_TEMPLATE/skill-request.md",
    ".github/workflows/ci.yml",
    ".github/workflows/atlas-currency.yml",
    ".gitleaks.toml",
    "lib/lint-skills.js",
    "lib/validate-cve-catalog.js",
    "lib/schemas/cve-catalog.schema.json",
    "lib/schemas/skill-frontmatter.schema.json",
    "scripts/check-manifest-snapshot.js",
    "skills/researcher/skill.md",
    "skills/exploit-scoring/skill.md",
    "skills/security-maturity-tiers/skill.md",
    "skills/zeroday-gap-learn/skill.md",
    "skills/skill-update-loop/skill.md",
  ];

  const offenders = [];
  for (const rel of filesToScan) {
    if (allowedFiles.has(rel)) continue;
    const p = path.join(ROOT, rel);
    if (!fs.existsSync(p)) continue;
    const body = fs.readFileSync(p, "utf8");
    if (body.includes("CLAUDE.md")) {
      offenders.push(rel);
    }
  }

  assert.deepEqual(
    offenders,
    [],
    "These files reference CLAUDE.md but the file was removed when the project " +
      "consolidated on AGENTS.md. Update each citation to AGENTS.md:\n  " +
      offenders.join("\n  ")
  );
});
