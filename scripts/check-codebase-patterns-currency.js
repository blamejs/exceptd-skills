#!/usr/bin/env node
"use strict";
/**
 * check-codebase-patterns-currency.js — advisory drift detector between
 * exceptd's adopted codebase-pattern classes and the upstream catalog they
 * were derived from (the sibling blamejs codebase-patterns test).
 *
 * exceptd's grep gate (scripts/check-codebase-patterns.js) ships a scoped
 * subset of the upstream pattern classes; the rest were triaged as either
 * already-owned by another exceptd gate, helper-dependent, or out of scope
 * for a local-file-read security CLI. UPSTREAM_TRIAGED below records every
 * class that triage covered. When upstream grows a NEW class not in that set,
 * this check flags it so the maintainer can decide whether to adopt it — the
 * same forcing function the GitHub-actions / vendored-bundle currency checks
 * provide for those surfaces.
 *
 * Advisory by design: it never fails a release. It exits 0 and prints a
 * NOTICE when upstream has drifted, and exits 0 silently when the sibling
 * repo is not present (a fresh clone / CI runner without the sibling). Point
 * it elsewhere with EXCEPTD_UPSTREAM_PATTERNS env var if the sibling lives at
 * a non-default path.
 */

const fs = require("node:fs");
const path = require("node:path");

const ROOT = path.resolve(__dirname, "..");

// The upstream allow-class registry as triaged during the codebase-patterns adoption.
// Every key here was classified (adopted / already-owned / helper-dependent /
// out-of-scope). A class appearing upstream but absent here is NEW and wants
// triage. Refresh this list (and re-triage the delta) when this check fires.
const UPSTREAM_TRIAGED = Object.freeze([ // keep-sorted
  "ai-disclosure-on-request-without-requested-gate",
  "archive-gz-without-safedecompress",
  "archive-wrap-partial-recipient",
  "backup-adapter-storage-without-posture-check",
  "bare-canonicalize-walk",
  "bare-error-throw",
  "bare-json-parse",
  "bare-split-on-quoted-header",
  "console-direct",
  "deny-path-hardcoded-response",
  "duplicate-regex",
  "dynamic-regex",
  "dynamic-require",
  "from-base64url-untrapped",
  "fs-path-from-operator-identifier-without-traversal-refusal",
  "gitleaks-entropy",
  "hand-rolled-sql",
  "handrolled-buffer-collect",
  "handrolled-debounce",
  "hostname-compare-trailing-dot",
  "inline-numeric-bounds-cascade",
  "inline-require",
  "inline-require-non-empty-string-validation",
  "internal-binding-in-prose",
  "internal-narrative-comment",
  "list-without-pagination",
  "math-random-noncrypto",
  "nfinity",
  "no-number-money-arithmetic",
  "primitive-unreachable",
  "process-exit",
  "raw-byte-literal",
  "raw-hash-compare",
  "raw-new-url",
  "raw-outbound-http",
  "raw-process-env",
  "raw-randombytes-token",
  "raw-time-literal",
  "raw-timing-safe-equal",
  "regex-no-length-cap",
  "seal-without-aad",
  "silent-catch",
  "slsa-framework-action-not-sha-pinned",
  "timer-no-unref",
  "wildcard-suffix-match-without-single-label-check",
]);

function upstreamPatternsPath() {
  if (process.env.EXCEPTD_UPSTREAM_PATTERNS) return process.env.EXCEPTD_UPSTREAM_PATTERNS;
  return path.resolve(ROOT, "..", "blamejs", "test", "layer-0-primitives", "codebase-patterns.test.js");
}

// Extract the allow-class keys from the upstream VALID_ALLOW_CLASSES literal.
function upstreamClasses(src) {
  const m = src.match(/VALID_ALLOW_CLASSES\s*=\s*(?:Object\.freeze\()?\{([\s\S]*?)\}/);
  if (!m) return null;
  const keys = [];
  const re = /["']?([a-z0-9][a-z0-9-]+)["']?\s*:/g;
  let g;
  while ((g = re.exec(m[1])) !== null) keys.push(g[1]);
  return keys;
}

function main() {
  const p = upstreamPatternsPath();
  if (!fs.existsSync(p)) {
    console.log(`[check-codebase-patterns-currency] sibling upstream not present (${path.relative(ROOT, p)}) — skipping (advisory).`);
    process.exitCode = 0;
    return;
  }
  let src;
  try { src = fs.readFileSync(p, "utf8"); }
  catch (e) {
    console.log(`[check-codebase-patterns-currency] could not read upstream (${e.message}) — skipping (advisory).`);
    process.exitCode = 0;
    return;
  }
  const live = upstreamClasses(src);
  if (!live) {
    console.log("[check-codebase-patterns-currency] could not parse upstream VALID_ALLOW_CLASSES — skipping (advisory).");
    process.exitCode = 0;
    return;
  }
  const triaged = new Set(UPSTREAM_TRIAGED);
  const liveSet = new Set(live);
  const added = live.filter((c) => !triaged.has(c)).sort();
  const removed = UPSTREAM_TRIAGED.filter((c) => !liveSet.has(c)).sort();

  if (added.length === 0 && removed.length === 0) {
    console.log(`[check-codebase-patterns-currency] ok — upstream catalog (${live.length} classes) matches the triaged set.`);
    process.exitCode = 0;
    return;
  }
  if (added.length) {
    console.log(`[check-codebase-patterns-currency] NOTICE — upstream added ${added.length} pattern class(es) not yet triaged:`);
    for (const c of added) console.log(`    + ${c}`);
    console.log("    -> Triage each (adopt into scripts/check-codebase-patterns.js, or record as out-of-scope), then add it to UPSTREAM_TRIAGED here.");
  }
  if (removed.length) {
    console.log(`[check-codebase-patterns-currency] NOTICE — ${removed.length} triaged class(es) no longer present upstream (renamed/removed):`);
    for (const c of removed) console.log(`    - ${c}`);
  }
  // Advisory only — never fail the release on drift.
  process.exitCode = 0;
}

module.exports = { UPSTREAM_TRIAGED, upstreamClasses, upstreamPatternsPath };

if (require.main === module) main();
