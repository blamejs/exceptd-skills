"use strict";
/**
 * scripts/predeploy.js
 *
 * Local mirror of the CI pre-deployment gate sequence. Runs every gate
 * the `.github/workflows/ci.yml` workflow runs, in order. Each gate is
 * isolated — a failure does not short-circuit the rest, so a single run
 * surfaces all problems instead of just the first one (matches the CI
 * shape where each job runs independently).
 *
 * Run before pushing to main or opening a PR:
 *   npm run predeploy
 *
 * Exit code:
 *   0  — all gates passed
 *   1  — one or more gates failed (per-gate output already printed)
 *   2  — runner-level error (missing script, fork failure, etc.)
 *
 * Single-source-of-truth: the GATES list below mirrors the job sequence
 * in .github/workflows/ci.yml. Test coverage in tests/predeploy.test.js
 * asserts the two stay in sync.
 */

const { execFileSync } = require("child_process");
const path = require("path");
const fs = require("fs");

const ROOT = path.join(__dirname, "..");

// Ordered list of CI gates. Each entry: { name, command, args, ciJobName }.
// ciJobName matches the `name:` field of the corresponding job in
// .github/workflows/ci.yml (or scorecard.yml). Used by the workflow-sync
// test to assert the two never drift.
const GATES = [
  {
    name: "Verify skill signatures (Ed25519)",
    command: process.execPath,
    args: [path.join(ROOT, "lib", "verify.js")],
    ciJobName: "Verify skill signatures (Ed25519)",
    requiresKeys: true,
  },
  {
    name: "Run tests (node:test)",
    command: process.execPath,
    // Glob form rather than a directory arg: Node 25.x on Windows
    // resolves a bare directory path through the module loader before
    // the test runner sees it, which fails for a working dir that
    // sits inside a path containing parentheses (e.g. Dropbox).
    args: ["--test", "tests/*.test.js"],
    ciJobName: "Tests",
  },
  {
    name: "Validate CVE catalog schema + zero-day learning coverage",
    command: process.execPath,
    args: [path.join(ROOT, "lib", "validate-cve-catalog.js")],
    ciJobName: "Data integrity (catalog + manifest snapshot)",
  },
  {
    name: "Validate offline CVE catalog state",
    command: process.execPath,
    args: [
      path.join(ROOT, "orchestrator", "index.js"),
      "validate-cves",
      "--offline",
      "--no-fail",
    ],
    ciJobName: "Data integrity (catalog + manifest snapshot)",
  },
  {
    name: "Validate offline RFC catalog state",
    command: process.execPath,
    args: [
      path.join(ROOT, "orchestrator", "index.js"),
      "validate-rfcs",
      "--offline",
      "--no-fail",
    ],
    ciJobName: "Data integrity (catalog + manifest snapshot)",
  },
  {
    name: "Manifest snapshot gate (breaking-change detector)",
    command: process.execPath,
    args: [path.join(ROOT, "scripts", "check-manifest-snapshot.js")],
    ciJobName: "Data integrity (catalog + manifest snapshot)",
  },
  {
    name: "Lint skill files",
    command: process.execPath,
    args: [path.join(ROOT, "lib", "lint-skills.js")],
    ciJobName: "Lint skill files",
  },
  {
    // Informational only — surfaces the forward_watch horizon across all
    // skills as a sanity signal. Emits the count but never fails the run;
    // a parse problem is reported, not blocking.
    name: "Forward-watch aggregator (informational)",
    command: process.execPath,
    args: [
      path.join(ROOT, "orchestrator", "index.js"),
      "watchlist",
    ],
    ciJobName: "Data integrity (catalog + manifest snapshot)",
    informational: true,
  },
  {
    name: "Validate catalog _meta (tlp + source_confidence + freshness_policy)",
    command: process.execPath,
    args: [path.join(ROOT, "lib", "validate-catalog-meta.js")],
    ciJobName: "Data integrity (catalog + manifest snapshot)",
  },
  {
    name: "SBOM currency check (sbom.cdx.json vs. live surface)",
    command: process.execPath,
    args: ["-e", sbomCurrencyChecker()],
    ciJobName: "Data integrity (catalog + manifest snapshot)",
  },
  {
    name: "Pre-computed indexes freshness (data/_indexes/ vs. live sources)",
    command: process.execPath,
    args: [path.join(ROOT, "lib", "validate-indexes.js")],
    ciJobName: "Data integrity (catalog + manifest snapshot)",
  },
];

/* Inline checker, run as `node -e`, so the predeploy gate stays one
 * file and the SBOM regen logic stays in scripts/refresh-sbom.js
 * (single source of truth). Compares the persisted sbom.cdx.json
 * against the live skill_count + catalog_count derived from
 * manifest.json + data/. Exits nonzero on drift, with a hint to run
 * `npm run refresh-sbom`. */
function sbomCurrencyChecker() {
  return [
    "const fs=require('fs');const path=require('path');",
    "const root=" + JSON.stringify(ROOT) + ";",
    "const sbomPath=path.join(root,'sbom.cdx.json');",
    "if(!fs.existsSync(sbomPath)){console.error('sbom.cdx.json not found — run `npm run refresh-sbom`.');process.exit(1);}",
    "const sbom=JSON.parse(fs.readFileSync(sbomPath,'utf8'));",
    "const manifest=JSON.parse(fs.readFileSync(path.join(root,'manifest.json'),'utf8'));",
    "const dataDir=path.join(root,'data');",
    "const liveCatalogs=fs.readdirSync(dataDir).filter(f=>f.endsWith('.json')).length;",
    "const liveSkills=Array.isArray(manifest.skills)?manifest.skills.length:0;",
    "const props=Object.fromEntries((sbom.metadata&&sbom.metadata.properties||[]).map(p=>[p.name,p.value]));",
    "const sbomCatalogs=Number(props['exceptd:catalog:count']);",
    "const sbomSkills=Number(props['exceptd:skill:count']);",
    "let drift=false;",
    "if(sbomCatalogs!==liveCatalogs){console.error(`SBOM catalog count ${sbomCatalogs} != live ${liveCatalogs}`);drift=true;}",
    "if(sbomSkills!==liveSkills){console.error(`SBOM skill count ${sbomSkills} != live ${liveSkills}`);drift=true;}",
    "if(sbom.bomFormat!=='CycloneDX'||sbom.specVersion!=='1.6'){console.error('SBOM is not CycloneDX 1.6');drift=true;}",
    "if(drift){console.error('Run `npm run refresh-sbom` to regenerate sbom.cdx.json.');process.exit(1);}",
    "console.log(`SBOM current — ${sbomSkills} skills, ${sbomCatalogs} catalogs.`);",
  ].join("");
}

function runGate(gate) {
  if (gate.requiresKeys) {
    const pubKey = path.join(ROOT, "keys", "public.pem");
    if (!fs.existsSync(pubKey)) {
      return {
        status: "skipped",
        reason:
          "keys/public.pem missing — run `npm run bootstrap` to generate keys + sign skills.",
      };
    }
  }
  try {
    execFileSync(gate.command, gate.args, { stdio: "inherit", cwd: ROOT });
    return { status: "passed" };
  } catch (e) {
    if (gate.informational) {
      return {
        status: "informational",
        exitCode: e.status ?? null,
        message: e.message,
      };
    }
    return {
      status: "failed",
      exitCode: e.status ?? null,
      message: e.message,
    };
  }
}

function main() {
  const results = [];
  for (const gate of GATES) {
    process.stdout.write(`\n=== ${gate.name} ===\n`);
    const outcome = runGate(gate);
    results.push({ gate, outcome });
    if (outcome.status === "skipped") {
      process.stdout.write(`  ⊘ skipped — ${outcome.reason}\n`);
    } else if (outcome.status === "passed") {
      process.stdout.write(`  ✓ passed\n`);
    } else if (outcome.status === "informational") {
      process.stdout.write(
        `  ℹ informational (exit ${outcome.exitCode ?? "?"}) — not failing the run\n`
      );
    } else {
      process.stdout.write(
        `  ✗ failed (exit ${outcome.exitCode ?? "?"}): ${outcome.message}\n`
      );
    }
  }

  // Summary table.
  process.stdout.write("\n=== Pre-deploy summary ===\n");
  const widest = results.reduce(
    (n, r) => Math.max(n, r.gate.name.length),
    0
  );
  for (const { gate, outcome } of results) {
    const icon =
      outcome.status === "passed"
        ? "✓"
        : outcome.status === "skipped"
        ? "⊘"
        : outcome.status === "informational"
        ? "ℹ"
        : "✗";
    process.stdout.write(
      `  ${icon} ${gate.name.padEnd(widest)}  ${outcome.status}\n`
    );
  }

  const failures = results.filter((r) => r.outcome.status === "failed");
  const skipped = results.filter((r) => r.outcome.status === "skipped");
  const info = results.filter((r) => r.outcome.status === "informational");
  process.stdout.write(
    `\n${results.length - failures.length - skipped.length - info.length}/${results.length} gates passed` +
      (skipped.length ? ` (${skipped.length} skipped)` : "") +
      (info.length ? ` (${info.length} informational)` : "") +
      (failures.length ? `, ${failures.length} failed` : "") +
      ".\n"
  );

  process.exit(failures.length > 0 ? 1 : 0);
}

module.exports = { GATES };

if (require.main === module) {
  try {
    main();
  } catch (e) {
    console.error("[predeploy] runner error: " + ((e && e.stack) || e));
    process.exit(2);
  }
}
