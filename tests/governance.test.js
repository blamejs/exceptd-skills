"use strict";
/**
 * Governance-files regression test.
 *
 * Asserts the presence and minimal shape of the repo-hygiene files
 * GitHub surfaces in its UI (license, code of conduct, contributing
 * guide, security policy, codeowners, funding, dependabot config,
 * issue + PR templates, maintainers list). A missing or empty file
 * silently degrades GitHub's repo-quality signals (the "Community
 * Standards" page) and can break the Sponsor / Security buttons.
 *
 * The test does not enforce content — it enforces presence and
 * non-emptiness. Content review happens in PRs.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const ROOT = path.join(__dirname, "..");

const REQUIRED_FILES = [
  "LICENSE",
  "NOTICE",
  "README.md",
  "CHANGELOG.md",
  "CODE_OF_CONDUCT.md",
  "CONTRIBUTING.md",
  "SECURITY.md",
  "MAINTAINERS.md",
  "AGENTS.md",
  "CONTEXT.md",
  "ARCHITECTURE.md",
  ".gitignore",
  ".gitattributes",
  ".gitleaks.toml",
  ".npmrc",
  ".dockerignore",
  ".cursorrules",
  ".windsurfrules",
  "manifest.json",
  "manifest-snapshot.json",
  "package.json",
];

const REQUIRED_GITHUB_FILES = [
  ".github/CODEOWNERS",
  ".github/FUNDING.yml",
  ".github/dependabot.yml",
  ".github/PULL_REQUEST_TEMPLATE.md",
  ".github/ISSUE_TEMPLATE/config.yml",
  ".github/ISSUE_TEMPLATE/bug_report.md",
  ".github/ISSUE_TEMPLATE/feature_request.md",
  ".github/ISSUE_TEMPLATE/skill-request.md",
  ".github/ISSUE_TEMPLATE/cve-addition.md",
  ".github/workflows/ci.yml",
  ".github/workflows/scorecard.yml",
  ".github/workflows/atlas-currency.yml",
];

const REQUIRED_DOCS = ["docs/REPO-SETTINGS.md", "docker/README.md", "docker/test.Dockerfile"];

const REQUIRED_SCRIPTS = [
  "scripts/bootstrap.js",
  "scripts/predeploy.js",
  "scripts/check-manifest-snapshot.js",
  "scripts/refresh-manifest-snapshot.js",
];

test("every required top-level governance file exists and is non-empty", () => {
  for (const f of REQUIRED_FILES) {
    const p = path.join(ROOT, f);
    assert.ok(fs.existsSync(p), `required file missing: ${f}`);
    const stat = fs.statSync(p);
    assert.ok(stat.size > 0, `required file is empty: ${f}`);
  }
});

test("every required .github file exists and is non-empty", () => {
  for (const f of REQUIRED_GITHUB_FILES) {
    const p = path.join(ROOT, f);
    assert.ok(fs.existsSync(p), `required GitHub file missing: ${f}`);
    const stat = fs.statSync(p);
    assert.ok(stat.size > 0, `required GitHub file is empty: ${f}`);
  }
});

test("every required docs/ file exists and is non-empty", () => {
  for (const f of REQUIRED_DOCS) {
    const p = path.join(ROOT, f);
    assert.ok(fs.existsSync(p), `required docs file missing: ${f}`);
    const stat = fs.statSync(p);
    assert.ok(stat.size > 0, `required docs file is empty: ${f}`);
  }
});

test("every required script exists and is non-empty", () => {
  for (const f of REQUIRED_SCRIPTS) {
    const p = path.join(ROOT, f);
    assert.ok(fs.existsSync(p), `required script missing: ${f}`);
    const stat = fs.statSync(p);
    assert.ok(stat.size > 0, `required script is empty: ${f}`);
  }
});

test("FUNDING.yml declares both GitHub Sponsors and Ko-fi entries", () => {
  const funding = fs.readFileSync(path.join(ROOT, ".github", "FUNDING.yml"), "utf8");
  assert.match(funding, /^github:\s*\[dotCooCoo\]\s*$/m, "GitHub Sponsors entry");
  assert.match(funding, /^ko_fi:\s*dotcoocoo\s*$/m, "Ko-fi entry");
});

test("LICENSE is Apache-2.0", () => {
  const license = fs.readFileSync(path.join(ROOT, "LICENSE"), "utf8");
  assert.match(
    license,
    /Apache License[\s\S]+Version 2\.0/,
    "LICENSE must be Apache 2.0"
  );
});

test("package.json carries the canonical repository + bugs URLs for the blamejs org", () => {
  const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, "package.json"), "utf8"));
  assert.ok(pkg.repository, "package.json declares repository");
  assert.match(
    pkg.repository.url || "",
    /github\.com\/blamejs\/exceptd-skills/,
    "repository URL points at blamejs/exceptd-skills"
  );
  assert.ok(pkg.bugs, "package.json declares bugs");
  assert.match(
    pkg.bugs.url,
    /github\.com\/blamejs\/exceptd-skills\/issues/,
    "bugs URL points at the blamejs org's issue tracker"
  );
  assert.equal(pkg.license, "Apache-2.0");
});

test(".gitignore allows keys/public.pem to be tracked", () => {
  // The signing-verification public key MUST be committable; the
  // catch-all `*.pem` rule otherwise gitignores it. AGENTS.md hard
  // rule #13 + scripts/bootstrap.js depend on the explicit exception.
  const gi = fs.readFileSync(path.join(ROOT, ".gitignore"), "utf8");
  assert.match(
    gi,
    /^!keys\/public\.pem\s*$/m,
    ".gitignore must include `!keys/public.pem` exception"
  );
});

test(".gitleaks.toml allowlists keys/public.pem and manifest.json", () => {
  // Both files legitimately contain high-entropy content (PEM block,
  // Ed25519 base64 signatures) that the default gitleaks rules flag.
  // Without these allowlists, the secret-scan CI job fails on every
  // run.
  const toml = fs.readFileSync(path.join(ROOT, ".gitleaks.toml"), "utf8");
  assert.match(toml, /keys\/public\\\.pem/);
  assert.match(toml, /manifest\\\.json/);
});

test("CODEOWNERS declares @dotCooCoo as the catch-all owner", () => {
  const owners = fs.readFileSync(path.join(ROOT, ".github", "CODEOWNERS"), "utf8");
  assert.match(
    owners,
    /^\*\s+@dotCooCoo\s*$/m,
    "CODEOWNERS must have `* @dotCooCoo` catch-all"
  );
});

test("dependabot.yml watches github-actions ecosystem", () => {
  const deps = fs.readFileSync(path.join(ROOT, ".github", "dependabot.yml"), "utf8");
  assert.match(deps, /package-ecosystem:\s*"github-actions"/);
});

test("manifest-snapshot.json matches the current manifest.json public surface", () => {
  // If a maintainer landed a manifest change without refreshing the
  // snapshot, this test fails locally before they push. CI would catch
  // it too via the snapshot gate, but failing inside the test runner
  // gives a faster signal.
  const {
    captureSurface,
    diff,
  } = require(path.join(ROOT, "scripts", "check-manifest-snapshot.js"));

  const manifest = JSON.parse(
    fs.readFileSync(path.join(ROOT, "manifest.json"), "utf8")
  );
  const baseline = JSON.parse(
    fs.readFileSync(path.join(ROOT, "manifest-snapshot.json"), "utf8")
  );
  const current = captureSurface(manifest);
  const result = diff(baseline, current);

  assert.equal(
    result.breaking.length,
    0,
    `manifest-snapshot.json is out of sync (breaking): ${result.breaking.join("; ")}. ` +
      `Run \`npm run refresh-snapshot\` and commit the result.`
  );
});
