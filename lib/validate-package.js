"use strict";
/**
 * lib/validate-package.js
 *
 * Predeploy + prepublishOnly gate. Runs `npm pack --dry-run --json` and
 * asserts the publish tarball is what we expect:
 *
 *   - includes every required file from package.json `files`
 *   - excludes every forbidden file (secrets, tests, caches, dev artifacts)
 *   - is under the size budget (SIZE_BUDGET_BYTES below — do not restate the
 *     figure here; this line said 7 MB through three raises of it)
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
const { safeExit } = require("./exit-codes");

const ROOT = path.join(__dirname, "..");
const ABS = (p) => path.join(ROOT, p);
// Published-tarball cap. Guards against accidental bloat (a vendored
// node_modules, a committed binary — tens of MB), not the curated data that
// legitimately grows each release: the CVE catalog gains entries and the RFC
// index spans the full series. Packed size crossed 5 MB through that gradual
// growth; 7 MB restored headroom. Completing five-jurisdiction framework-gap
// coverage across the whole catalog added ~1,100 curated statements plus their
// reverse-reference index, crossing 7 MB; 8 MB restored headroom. Curating a
// further hundred KEV CVEs — each with its indicators, five framework-gap
// statements and a paired zero-day lesson — crossed 8 MB; 9 MB restored
// headroom. Recording the controls each CVE requires, across most of the
// catalog, adds several hundred words per entry and crossed 9 MB; 11 MB
// restores headroom through the remainder of that work while still catching a
// gross-bloat accident. Two further hundred-CVE curation passes took the
// catalog past 1,300 entries and crossed 11 MB; 13 MB restores headroom for
// roughly two more passes at the current per-entry size, which is where the
// next deliberate look at what ships in the tarball belongs.
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
  // Modules require()d at the top of bin/exceptd.js on every invocation —
  // dropping any of these from the tarball bricks the CLI at launch with a
  // module-not-found, so they are pinned explicitly rather than relied on via
  // the directory-level files[] entries.
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

/* SBOM coverage of the ACTUAL tarball.
 *
 * The SBOM's own completeness gate expands package.json `files`, but npm ships
 * more than `files` names — package.json unconditionally, plus README files it
 * collects itself. Those extras shipped unhashed and nothing noticed, because
 * the generator and its checker both asked `files`: two sides agreeing on the
 * same incomplete question. `npm pack` is the only authority on what actually
 * ships, and this is the one gate holding its output, so the comparison belongs
 * here.
 *
 * Exclusions are read from the SBOM's own declared properties instead of a
 * second copy of the list, so a file can only be uncovered when the published
 * artifact says out loud that it is. The single structural exception is the
 * SBOM itself, which cannot contain its own hash.
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

  try {
    const sbom = JSON.parse(fs.readFileSync(ABS("sbom.cdx.json"), "utf8"));
    issues.push(...sbomCoverageIssues(filePaths, sbom));
  } catch (err) {
    issues.push(`could not read sbom.cdx.json to check tarball coverage: ${err.message}`);
  }

  // Size budget. An absent/non-numeric `size` field is NOT a pass — it means
  // the gate cannot evaluate the budget at all. Fail loudly instead of
  // silently skipping (the absent-field-fails-open class, symmetric with the
  // license_sha256 / vendored_sha256 guards in validate-vendor.js): a future
  // npm-pack output shape change that drops or renames `size` must not turn the
  // size budget into a no-op.
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
