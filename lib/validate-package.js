"use strict";
/**
 * lib/validate-package.js
 *
 * Predeploy + prepublishOnly gate. Runs `npm pack --dry-run --json` and
 * asserts the publish tarball is what we expect:
 *
 *   - includes every required file from package.json `files`
 *   - excludes every forbidden file (secrets, tests, caches, dev artifacts)
 *   - is under the size budget (currently 5 MB)
 *   - `bin/exceptd.js` has the expected shebang
 *   - the bin target listed in package.json exists on disk
 *
 * Exit 0 on success, 1 on any violation.
 *
 * Zero npm deps. Node 24 stdlib.
 */

const fs = require("fs");
const path = require("path");
const { spawnSync } = require("child_process");

const ROOT = path.join(__dirname, "..");
const ABS = (p) => path.join(ROOT, p);
const SIZE_BUDGET_BYTES = 5 * 1024 * 1024;          // 5 MB published-tarball cap

const REQUIRED_PATHS = [
  "package.json",
  "README.md",
  "LICENSE",
  "NOTICE",
  "AGENTS.md",
  "manifest.json",
  "manifest-snapshot.json",
  "sbom.cdx.json",
  "bin/exceptd.js",
  "lib/refresh-external.js",
  "lib/job-queue.js",
  "lib/prefetch.js",
  "lib/worker-pool.js",
  "lib/verify.js",
  "vendor/blamejs/retry.js",
  "vendor/blamejs/worker-pool.js",
  "vendor/blamejs/_PROVENANCE.json",
  "vendor/blamejs/LICENSE",
  "data/_indexes/_meta.json",
  "keys/public.pem",
];

// File / directory prefixes that MUST NOT appear in the publish tarball.
const FORBIDDEN_PATTERNS = [
  /(^|\/)\.keys(\/|$)/,                              // private signing key
  /(^|\/)\.cache(\/|$)/,                             // local upstream cache
  /(^|\/)tests(\/|$)/,                               // test sources + fixtures
  /(^|\/)refresh-report\.json$/,                     // runtime artifact
  /(^|\/)\.env(\b|\.)/,                              // any env file
  /(^|\/)\.git(\/|$|hub\/)/,                         // git internals — but allow .github/workflows in repo,
                                                     // it's already excluded by .npmignore semantics for files[]
  /(^|\/)\.DS_Store$/,
  /(^|\/)node_modules(\/|$)/,
  /\.pem$/,                                          // catches .keys/private.pem if it sneaks in;
                                                     // keys/public.pem is whitelisted below
];

const PEM_ALLOWLIST = new Set(["keys/public.pem"]);

function runNpmPack() {
  // `npm pack --dry-run --json` writes a JSON array to stdout describing
  // what would be in the tarball without actually creating it.
  const res = spawnSync("npm", ["pack", "--dry-run", "--json"], { cwd: ROOT, encoding: "utf8", shell: process.platform === "win32" });
  if (res.status !== 0) {
    process.stderr.write(`[validate-package] npm pack failed (exit ${res.status}): ${res.stderr || res.stdout}\n`);
    process.exit(1);
  }
  let parsed;
  try {
    parsed = JSON.parse(res.stdout);
  } catch (err) {
    process.stderr.write(`[validate-package] could not parse npm pack output: ${err.message}\n`);
    process.exit(1);
  }
  const first = Array.isArray(parsed) ? parsed[0] : parsed;
  if (!first || !Array.isArray(first.files)) {
    process.stderr.write(`[validate-package] unexpected npm pack output shape\n`);
    process.exit(1);
  }
  return first;
}

function main() {
  const issues = [];

  const pkg = JSON.parse(fs.readFileSync(ABS("package.json"), "utf8"));

  // package.json sanity
  if (pkg.private === true) issues.push(`package.json "private" is true — npm publish will fail`);
  if (!pkg.bin || !pkg.bin.exceptd) issues.push(`package.json missing bin.exceptd`);
  if (!Array.isArray(pkg.files) || pkg.files.length === 0) issues.push(`package.json missing files[] whitelist`);
  if (!pkg.publishConfig || pkg.publishConfig.access !== "public") {
    issues.push(`package.json missing publishConfig.access: public (scoped package needs explicit access)`);
  }

  // bin target exists + has a shebang
  if (pkg.bin && pkg.bin.exceptd) {
    const binPath = ABS(pkg.bin.exceptd);
    if (!fs.existsSync(binPath)) {
      issues.push(`bin target ${pkg.bin.exceptd} does not exist`);
    } else {
      const head = fs.readFileSync(binPath, "utf8").slice(0, 64);
      if (!head.startsWith("#!/usr/bin/env node") && !head.startsWith("#!/usr/bin/node")) {
        issues.push(`bin/${path.basename(binPath)} missing #!/usr/bin/env node shebang`);
      }
    }
  }

  // npm pack dry-run
  const packInfo = runNpmPack();
  const filePaths = packInfo.files.map((f) => f.path.replace(/\\/g, "/"));
  const fileSet = new Set(filePaths);

  // Required files present
  for (const r of REQUIRED_PATHS) {
    if (!fileSet.has(r)) {
      issues.push(`required file missing from publish tarball: ${r}`);
    }
  }

  // Forbidden files absent
  for (const p of filePaths) {
    if (PEM_ALLOWLIST.has(p)) continue;
    for (const re of FORBIDDEN_PATTERNS) {
      if (re.test(p)) {
        issues.push(`forbidden file in publish tarball: ${p} (matched ${re})`);
        break;
      }
    }
  }

  // Size budget
  if (typeof packInfo.size === "number" && packInfo.size > SIZE_BUDGET_BYTES) {
    issues.push(`tarball size ${(packInfo.size / 1024 / 1024).toFixed(2)} MB exceeds budget ${(SIZE_BUDGET_BYTES / 1024 / 1024).toFixed(0)} MB`);
  }

  if (issues.length === 0) {
    const sizeMB = (packInfo.size / 1024 / 1024).toFixed(2);
    const unpackedMB = (packInfo.unpackedSize / 1024 / 1024).toFixed(2);
    process.stdout.write(
      `[validate-package] OK — ${pkg.name}@${pkg.version}, ` +
      `${packInfo.files.length} files, ` +
      `${sizeMB} MB packed / ${unpackedMB} MB unpacked.\n`
    );
    process.exit(0);
  }

  process.stderr.write(`[validate-package] FAILED — ${issues.length} issue(s):\n`);
  for (const i of issues) process.stderr.write(`  • ${i}\n`);
  process.exit(1);
}

if (require.main === module) main();

module.exports = { main, REQUIRED_PATHS, FORBIDDEN_PATTERNS, SIZE_BUDGET_BYTES };
