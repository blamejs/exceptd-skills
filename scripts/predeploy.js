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
 *
 * Audit G F5 — when the manifest-snapshot gate fails, the fix is NOT to
 * run `npm run refresh-snapshot` blindly. The refresh script now refuses
 * unless the operator passes `--commit-only` or sets
 * EXCEPTD_SNAPSHOT_AUDIT_ACK=1. This is intentional: a failing snapshot
 * gate means a breaking change was detected, and an accidental refresh
 * would silently rewrite the baseline. Read the breaking-change list
 * first, then run `node scripts/refresh-manifest-snapshot.js --commit-only`
 * if the change is intentional.
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
    //
    // --test-concurrency=1 forces sequential file execution. Several
    // test files (build-incremental, indexes-v070, refresh-*) touch
    // shared filesystem state under data/_indexes/ + refresh-report.json
    // + skill bodies; running in parallel produces flaky races. Sequential
    // is ~1.5s slower locally but eliminates the false negative we hit
    // on the Linux CI runner in the v0.9.0 release attempt.
    args: ["--test", "--test-concurrency=1", "tests/*.test.js"],
    ciJobName: "Tests",
  },
  {
    name: "Validate CVE catalog schema + zero-day learning coverage",
    command: process.execPath,
    args: [path.join(ROOT, "lib", "validate-cve-catalog.js")],
    ciJobName: "Data integrity (catalog + manifest snapshot)",
  },
  // Audit G F13 — the "validate-cves --offline --no-fail" and
  // "validate-rfcs --offline --no-fail" gates were enumeration-only sanity
  // checks: `--no-fail` forced them to always exit 0, so they never blocked
  // a release on a real catalog problem. The deep catalog validation is
  // already performed by the gate above (`lib/validate-cve-catalog.js`),
  // including cross-catalog reference resolution after this same audit.
  // Keeping the no-op gates as predeploy steps inflated the gate count for
  // no marginal value and risked false confidence ("X gates passed"). They
  // are removed in v0.12.14; document the removal in CHANGELOG.
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
    // Informational — surfaces the forward_watch horizon across all skills.
    // Audit G F12: an exit code of 0 means "ok", 1 means "items present
    // (informational)", 2+ means a runtime error in the gate itself.
    // The runner now distinguishes the two: 0/1 stay informational, 2+
    // surface as a real failure. Pre-fix, any non-zero exit was rolled up
    // as informational, which hid crashes (a 137 OOM looked the same as
    // "found 12 items to review").
    name: "Forward-watch aggregator (informational)",
    command: process.execPath,
    args: [
      path.join(ROOT, "orchestrator", "index.js"),
      "watchlist",
    ],
    ciJobName: "Data integrity (catalog + manifest snapshot)",
    informational: true,
    informationalMaxExitCode: 1,
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
    args: [path.join(ROOT, "scripts", "check-sbom-currency.js")],
    ciJobName: "Data integrity (catalog + manifest snapshot)",
  },
  {
    name: "Pre-computed indexes freshness (data/_indexes/ vs. live sources)",
    command: process.execPath,
    args: [path.join(ROOT, "lib", "validate-indexes.js")],
    ciJobName: "Data integrity (catalog + manifest snapshot)",
  },
  {
    name: "Vendor tree integrity (vendor/blamejs/ vs. _PROVENANCE.json)",
    command: process.execPath,
    args: [path.join(ROOT, "lib", "validate-vendor.js")],
    ciJobName: "Data integrity (catalog + manifest snapshot)",
  },
  {
    name: "Publish tarball shape (npm pack --dry-run + file allowlist)",
    command: process.execPath,
    args: [path.join(ROOT, "lib", "validate-package.js")],
    ciJobName: "Data integrity (catalog + manifest snapshot)",
  },
  {
    // v0.12.3 — packs the tarball, extracts it, runs Ed25519 verify on the
    // EXTRACTED tree. Catches the class of bug where verify-on-source-tree
    // passes (38/38) but verify-on-shipped-tarball fails (0/38) because
    // something between sign and pack swapped keys/public.pem. Every release
    // v0.11.x through v0.12.2 shipped this regression invisibly.
    name: "Verify shipped tarball (sign + pack + extract + verify round-trip)",
    command: process.execPath,
    args: [path.join(ROOT, "scripts", "verify-shipped-tarball.js")],
    ciJobName: "Data integrity (catalog + manifest snapshot)",
    requiresKeys: true,
  },
  {
    // AGENTS.md hard rule #15 (e2e no-MVP). Every diff that touches a
    // CLI verb, CLI flag, lib/orchestrator/scripts export, playbook
    // indicator, or CVE iocs field must land with a covering test
    // reference in the same PR. The analyzer parses git diff against
    // origin/main, classifies each change shape, and fails if a covered
    // surface lacks a test literal anywhere under tests/. Blocking — a
    // covered surface change without a covering test fails the gate.
    name: "Diff coverage (feature changes require test coverage)",
    command: process.execPath,
    args: [path.join(ROOT, "scripts", "check-test-coverage.js")],
    ciJobName: "Diff coverage",
  },
  {
    // v0.12.12 — Validate every playbook in data/playbooks/ against the
    // JSON schema + cross-playbook + cross-catalog references. Runs as
    // informational (warnings, not failures) for v0.12.12 so the patch-
    // class release can land without retroactively breaking schema-drift
    // cases that operators have not yet reconciled. v0.13.0 will flip
    // `informational: false`.
    name: "Validate playbooks (schema + cross-refs, informational)",
    command: process.execPath,
    args: [path.join(ROOT, "lib", "validate-playbooks.js")],
    ciJobName: "Validate playbooks",
    informational: true,
    // audit Y F30: cap informational acceptance at exit 1 so a CRASH (137 OOM,
    // 139 SIGSEGV, 134 SIGABRT, etc.) surfaces as a real failure instead of
    // being absorbed under the informational bucket. Matches the
    // forward-watch gate (line ~111) which already pins the same ceiling.
    informationalMaxExitCode: 1,
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
        durationMs: 0,
      };
    }
  }
  const t0 = Date.now();
  // Audit G F21 — spawn the child with piped stdio + tee to the parent so we
  // can count `WARN ` lines for the summary table. We still want the live
  // output, so each chunk is forwarded as it arrives.
  const { spawnSync } = require("child_process");
  const r = spawnSync(gate.command, gate.args, {
    cwd: ROOT,
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
  });
  const durationMs = Date.now() - t0;
  if (r.stdout) process.stdout.write(r.stdout);
  if (r.stderr) process.stderr.write(r.stderr);
  // Count WARN-labelled lines in the combined stream so the summary table
  // can surface them. Lint / validate output uses "WARN  " at line start;
  // count both the table form and an inline "[warn]" form.
  const combined = (r.stdout || "") + (r.stderr || "");
  const warnCount = (
    combined.match(/^WARN\b/gm) || []
  ).length + (
    combined.match(/\[warn\]/g) || []
  ).length;
  if (r.status === 0) {
    return { status: "passed", durationMs, warnCount };
  }
  // Audit G F12 — gates may declare informationalMaxExitCode to distinguish
  // "soft signal" (exit codes 0..N) from "crash" (> N). Default behaviour
  // for an informational gate without that field stays the same.
  if (gate.informational) {
    const ceil = typeof gate.informationalMaxExitCode === "number"
      ? gate.informationalMaxExitCode
      : Infinity;
    if (r.status !== null && r.status > ceil) {
      return {
        status: "failed",
        exitCode: r.status,
        message: `informational gate crashed (exit ${r.status} > informationalMaxExitCode=${ceil})`,
        durationMs,
        warnCount,
      };
    }
    return {
      status: "informational",
      exitCode: r.status ?? null,
      durationMs,
      warnCount,
    };
  }
  return {
    status: "failed",
    exitCode: r.status ?? null,
    message: r.error ? r.error.message : `exit ${r.status}`,
    durationMs,
    warnCount,
  };
}

function fmtMs(ms) {
  if (typeof ms !== "number" || !Number.isFinite(ms)) return "";
  return `${ms} ms`;
}

function main() {
  const results = [];
  for (const gate of GATES) {
    process.stdout.write(`\n=== ${gate.name} ===\n`);
    const outcome = runGate(gate);
    results.push({ gate, outcome });
    const timing = fmtMs(outcome.durationMs);
    const timingSuffix = timing ? ` (${timing})` : "";
    if (outcome.status === "skipped") {
      process.stdout.write(`  ⊘ skipped — ${outcome.reason}\n`);
    } else if (outcome.status === "passed") {
      process.stdout.write(`  ✓ passed${timingSuffix}\n`);
    } else if (outcome.status === "informational") {
      process.stdout.write(
        `  ℹ informational (exit ${outcome.exitCode ?? "?"})${timingSuffix} — not failing the run\n`
      );
    } else {
      process.stdout.write(
        `  ✗ failed (exit ${outcome.exitCode ?? "?"})${timingSuffix}: ${outcome.message}\n`
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
    const timing = fmtMs(outcome.durationMs);
    const timingSuffix = timing ? `  (${timing})` : "";
    // F21 — surface WARN counts so a gate that "passed (3 warnings)" is
    // distinguishable from one that passed cleanly. Pre-fix, warnings
    // printed by individual gates (validate-cve-catalog, lint-skills,
    // validate-playbooks) scrolled past invisible in the summary.
    const warnSuffix =
      outcome.warnCount && outcome.warnCount > 0
        ? ` (${outcome.warnCount} warning${outcome.warnCount === 1 ? "" : "s"})`
        : "";
    process.stdout.write(
      `  ${icon} ${gate.name.padEnd(widest)}  ${outcome.status}${warnSuffix}${timingSuffix}\n`
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
