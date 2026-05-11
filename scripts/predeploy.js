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
];

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
        : "✗";
    process.stdout.write(
      `  ${icon} ${gate.name.padEnd(widest)}  ${outcome.status}\n`
    );
  }

  const failures = results.filter((r) => r.outcome.status === "failed");
  const skipped = results.filter((r) => r.outcome.status === "skipped");
  process.stdout.write(
    `\n${results.length - failures.length - skipped.length}/${results.length} gates passed` +
      (skipped.length ? ` (${skipped.length} skipped)` : "") +
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
