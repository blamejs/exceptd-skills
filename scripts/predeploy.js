"use strict";
/**
 * Local mirror of the CI pre-deployment gate sequence. Gates are isolated, so one
 * failure does not short-circuit the rest and a single run surfaces every problem.
 * Exit 0 all passed, 1 one or more failed, 2 runner-level error.
 */

const { execFileSync } = require("child_process");
const path = require("path");
const fs = require("fs");

const ROOT = path.join(__dirname, "..");

// Ordered CI gates; `ciJobName` matches the job `name:` in .github/workflows/ci.yml.
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
    // Glob, not a directory arg: on Windows a bare directory resolves through the
    // module loader and fails under a path containing parentheses. --test-concurrency=1
    // is required — build-incremental, indexes-v070 and refresh-* share state.
    args: ["--test", "--test-concurrency=1", "tests/*.test.js"],
    ciJobName: "Tests",
  },
  {
    name: "Validate CVE catalog schema + zero-day learning coverage",
    command: process.execPath,
    // --strict promotes deferred warnings to hard failures; drafts stay exempt.
    args: [path.join(ROOT, "lib", "validate-cve-catalog.js"), "--strict"],
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
    args: [path.join(ROOT, "lib", "lint-skills.js"), "--strict"],
    ciJobName: "Lint skill files",
  },
  {
    // Exit 0 ok, 1 "items present"; 2+ is a gate runtime error and fails the run.
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
    args: [path.join(ROOT, "lib", "validate-catalog-meta.js"), "--strict"],
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
    // Verifies the EXTRACTED tarball: a step between sign and pack can swap keys/public.pem.
    name: "Verify shipped tarball (sign + pack + extract + verify round-trip)",
    command: process.execPath,
    args: [path.join(ROOT, "scripts", "verify-shipped-tarball.js")],
    ciJobName: "Data integrity (catalog + manifest snapshot)",
    requiresKeys: true,
  },
  {
    // AGENTS.md Hard Rule #15: a CLI/export/indicator/iocs diff lands with a covering test.
    name: "Diff coverage (feature changes require test coverage)",
    command: process.execPath,
    args: [path.join(ROOT, "scripts", "check-test-coverage.js")],
    ciJobName: "Diff coverage",
  },
  {
    name: "Validate playbooks (schema + cross-refs)",
    command: process.execPath,
    args: [path.join(ROOT, "lib", "validate-playbooks.js"), "--strict"],
    ciJobName: "Validate playbooks",
  },
  {
    // Refuses silent test-set shrinkage: a deleted file, a skip-all or a misnamed
    // file cannot pass. --update-baseline rewrites the pinned baseline.
    name: "Test-count baseline (no silent shrinkage)",
    command: process.execPath,
    args: [path.join(ROOT, "scripts", "check-test-count.js")],
    ciJobName: "Data integrity (catalog + manifest snapshot)",
  },
  {
    // Fails if a detection class regresses past its budget. The same budget is in
    // tests/shipped-catalog-integrity.test.js; the two must not drift.
    name: "Catalog-gap budget (v0.13.21 extended detection classes)",
    command: process.execPath,
    args: [path.join(ROOT, "scripts", "check-catalog-gap-budget.js")],
    ciJobName: "Data integrity (catalog + manifest snapshot)",
  },
  {
    // AGENTS.md Hard Rule #5: every curated CVE declares framework_control_gaps for
    // all five jurisdiction buckets (NIST, EU, UK, AU, ISO). Drafts exempt.
    name: "Framework-gap jurisdiction coverage (Hard Rule #5)",
    command: process.execPath,
    args: [path.join(ROOT, "scripts", "check-framework-gap-coverage.js")],
    ciJobName: "Data integrity (catalog + manifest snapshot)",
  },
  {
    // MITRE retires and renumbers technique ids, and a reference outside the two
    // pinned catalogs is never dereferenced at runtime, orphaning its control.
    name: "TTP reference integrity (no orphaned technique ids)",
    command: process.execPath,
    args: [path.join(ROOT, "scripts", "check-ttp-references.js")],
    ciJobName: "Data integrity (catalog + manifest snapshot)",
  },
  {
    // epss_percentile is the score's rank within one daily publication, so a
    // publication's entries must sort the same way by both.
    name: "EPSS score/percentile consistency",
    command: process.execPath,
    args: [path.join(ROOT, "scripts", "check-epss-consistency.js")],
    ciJobName: "Data integrity (catalog + manifest snapshot)",
  },
  {
    // Fails on NEW `// vX.Y.Z` comments and `*-vX_Y_Z.test.js` filenames: versions
    // live in package.json, manifest.json, CHANGELOG headings and git tags.
    name: "Version-tag drift (no new phase residue)",
    command: process.execPath,
    args: [path.join(ROOT, "scripts", "check-version-tags.js")],
    ciJobName: "Data integrity (catalog + manifest snapshot)",
  },
  {
    // Keeps lib/collectors/ and AGENTS.md's collector-enumeration paragraph in step.
    name: "AGENTS.md collector enumeration drift",
    command: process.execPath,
    args: [path.join(ROOT, "scripts", "check-agents-md-collectors.js")],
    ciJobName: "Data integrity (catalog + manifest snapshot)",
  },
  {
    // Blocks a library-callable function that writes to stdout then calls
    // process.exit(), and an orphaned allow marker. Dynamic RegExp is warn-only.
    name: "Codebase-pattern gates (stdout-flush, dynamic RegExp, bidi codepoints, orphan markers)",
    command: process.execPath,
    args: [path.join(ROOT, "scripts", "check-codebase-patterns.js")],
    ciJobName: "Data integrity (catalog + manifest snapshot)",
  },
  {
    // Bidirectional: every tests/<x>.test.js names a real subject, and every subject
    // has a test. Derived from the source tree, never hand-maintained.
    name: "Test-subject coverage (every test maps to a subject; every subject has a test)",
    command: process.execPath,
    args: [path.join(ROOT, "scripts", "check-test-subjects.js")],
    ciJobName: "Data integrity (catalog + manifest snapshot)",
  },
  {
    // Runs the same `## <version>` CHANGELOG extraction the release workflow
    // publishes, then lints it, so a bad section fails here rather than publicly.
    name: "Release-notes extract + operator-facing lint (CHANGELOG section)",
    command: process.execPath,
    args: [path.join(ROOT, "scripts", "check-changelog-extract.js")],
    ciJobName: "Data integrity (catalog + manifest snapshot)",
  },
  {
    // Patch is the ONLY default bump; a minor or major needs a committed
    // tests/.version-bump-ack.json naming the exact target version.
    name: "Version-bump cadence (patch-only default)",
    command: process.execPath,
    args: [path.join(ROOT, "scripts", "check-version-bump.js")],
    ciJobName: "Data integrity (catalog + manifest snapshot)",
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
  // Piped stdio, forwarded on: the summary needs a WARN count from the output.
  const { spawnSync } = require("child_process");
  const r = spawnSync(gate.command, gate.args, {
    cwd: ROOT,
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
  });
  const durationMs = Date.now() - t0;
  if (r.stdout) process.stdout.write(r.stdout);
  if (r.stderr) process.stderr.write(r.stderr);
  // Both forms count: "WARN" at line start, and an inline "[warn]".
  const combined = (r.stdout || "") + (r.stderr || "");
  const warnCount = (
    combined.match(/^WARN\b/gm) || []
  ).length + (
    combined.match(/\[warn\]/g) || []
  ).length;
  if (r.status === 0) {
    return { status: "passed", durationMs, warnCount };
  }
  // informationalMaxExitCode separates a soft signal (0..N) from a crash; absent = any.
  if (gate.informational) {
    const ceil = typeof gate.informationalMaxExitCode === "number"
      ? gate.informationalMaxExitCode
      : Infinity;
    // A gate that never ran cleanly is a crash, not a soft signal: spawn failure,
    // a signal kill (137 OOM), and a status above the ceiling all fail here.
    const spawnFailed = !!r.error || (r.status === null && !r.signal);
    if (r.error || r.signal || spawnFailed || (r.status !== null && r.status > ceil)) {
      return {
        status: "failed",
        exitCode: r.status ?? null,
        message: r.error
          ? `informational gate failed to spawn (treated as a crash): ${r.error.message}`
          : r.signal
          ? `informational gate killed by signal ${r.signal} (treated as a crash)`
          : r.status === null
          ? `informational gate did not exit cleanly (no exit code, no signal) — treated as a crash`
          : `informational gate crashed (exit ${r.status} > informationalMaxExitCode=${ceil})`,
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
    // A gate that "passed (3 warnings)" must be distinguishable from a clean pass.
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

  process.exit(failures.length > 0 ? 1 : 0); // allow:process-exit-after-stdout-write — local-only gate runner; output is the human/CI summary written synchronously above, never a piped --json result channel
}

module.exports = { GATES, runGate };

if (require.main === module) {
  try {
    main();
  } catch (e) {
    console.error("[predeploy] runner error: " + ((e && e.stack) || e));
    process.exit(2);
  }
}
