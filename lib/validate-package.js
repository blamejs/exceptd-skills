"use strict";
/**
 * Predeploy + prepublishOnly gate: runs `npm pack --dry-run --json` and asserts
 * the publish tarball holds every required file, no forbidden one, a bin target
 * that exists and carries a shebang, and a size under SIZE_BUDGET_BYTES — never
 * restated in prose, which goes stale at every raise of it.
 */

const fs = require("fs");
const path = require("path");
const { spawnSync } = require("child_process");
const { safeExit } = require("./exit-codes");

const ROOT = path.join(__dirname, "..");
const ABS = (p) => path.join(ROOT, p);
// Sized to catch a gross-bloat accident — a vendored node_modules, a committed
// binary — not the curated data that legitimately grows each release.
const SIZE_BUDGET_BYTES = 13 * 1024 * 1024;

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
  // require()d at the top of bin/exceptd.js: dropping one bricks the CLI at launch.
  "lib/exit-codes.js",
  "lib/id-validation.js",
  "lib/flag-suggest.js",
  "vendor/blamejs/codepoint-class.js",
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
  // --dry-run --json describes the tarball on stdout without creating it.
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

/* SBOM coverage of the ACTUAL tarball. The SBOM's own completeness gate expands
 * package.json `files`, but npm ships more than that, so a generator and its
 * checker can agree on the same incomplete question; `npm pack` is the only
 * authority on what ships. Exclusions come from the SBOM's own declared
 * properties rather than a second copy of the list; the structural exception is
 * the SBOM, which cannot hash itself.
 */
function sbomCoverageIssues(filePaths, sbom) {
  const props = (sbom && sbom.metadata && sbom.metadata.properties) || [];
  const uncoveredProp = props.find((p) => p && p.name === "exceptd:integrity:uncovered:prefix");
  const uncoveredPrefixes = uncoveredProp
    ? String(uncoveredProp.value).split(",").map((s) => s.trim()).filter(Boolean)
    : [];
  const hashed = new Set(
    ((sbom && sbom.components) || [])
      .filter((c) => c && typeof c["bom-ref"] === "string" && c["bom-ref"].startsWith("file:"))
      .map((c) => c.name)
  );
  return filePaths
    .filter(
      (p) =>
        p !== "sbom.cdx.json" &&
        !hashed.has(p) &&
        !uncoveredPrefixes.some((u) => p.startsWith(u))
    )
    .map(
      (p) =>
        `shipped file has no SHA in sbom.cdx.json and is not a declared exclusion: ${p} — ` +
        `add it to ALWAYS_SHIPPED in scripts/refresh-sbom.js (and its mirror in ` +
        `scripts/check-sbom-currency.js), then \`npm run refresh-sbom\``
    );
}

function main() {
  const issues = [];

  const pkg = JSON.parse(fs.readFileSync(ABS("package.json"), "utf8"));

  if (pkg.private === true) issues.push(`package.json "private" is true — npm publish will fail`);
  if (!pkg.bin || !pkg.bin.exceptd) issues.push(`package.json missing bin.exceptd`);
  if (!Array.isArray(pkg.files) || pkg.files.length === 0) issues.push(`package.json missing files[] whitelist`);
  if (!pkg.publishConfig || pkg.publishConfig.access !== "public") {
    issues.push(`package.json missing publishConfig.access: public (scoped package needs explicit access)`);
  }

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

  const packInfo = runNpmPack();
  const filePaths = packInfo.files.map((f) => f.path.replace(/\\/g, "/"));
  const fileSet = new Set(filePaths);

  for (const r of REQUIRED_PATHS) {
    if (!fileSet.has(r)) {
      issues.push(`required file missing from publish tarball: ${r}`);
    }
  }

  for (const p of filePaths) {
    if (PEM_ALLOWLIST.has(p)) continue;
    for (const re of FORBIDDEN_PATTERNS) {
      if (re.test(p)) {
        issues.push(`forbidden file in publish tarball: ${p} (matched ${re})`);
        break;
      }
    }
  }

  try {
    const sbom = JSON.parse(fs.readFileSync(ABS("sbom.cdx.json"), "utf8"));
    issues.push(...sbomCoverageIssues(filePaths, sbom));
  } catch (err) {
    issues.push(`could not read sbom.cdx.json to check tarball coverage: ${err.message}`);
  }

  // An absent or non-numeric `size` is a failure, not a pass: a change in npm
  // pack's output shape must not turn the budget into a silent no-op.
  if (typeof packInfo.size !== "number") {
    issues.push(`npm pack output missing numeric size — cannot enforce size budget`);
  } else if (packInfo.size > SIZE_BUDGET_BYTES) {
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
    safeExit(0);
    return;
  }

  process.stderr.write(`[validate-package] FAILED — ${issues.length} issue(s):\n`);
  for (const i of issues) process.stderr.write(`  • ${i}\n`);
  safeExit(1);
  return;
}

if (require.main === module) main();

module.exports = { main, REQUIRED_PATHS, FORBIDDEN_PATTERNS, SIZE_BUDGET_BYTES, sbomCoverageIssues };
