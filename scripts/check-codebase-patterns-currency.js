#!/usr/bin/env node
"use strict";
/**
 * Advisory drift detector between exceptd's adopted codebase-pattern classes
 * and the sibling blamejs codebase-patterns test they derive from. A class
 * present upstream but absent from UPSTREAM_TRIAGED is new and wants triage.
 *
 * Always exits 0 — it prints a NOTICE on drift and exits silently when the
 * sibling repo is absent. EXCEPTD_UPSTREAM_PATTERNS overrides its path.
 */

const fs = require("node:fs");
const path = require("node:path");

const ROOT = path.resolve(__dirname, "..");

// Refresh this list, re-triaging the delta, when this check fires.
const UPSTREAM_TRIAGED = Object.freeze([ // keep-sorted
  "aad-external-store-table-without-rotation",
  "ai-disclosure-on-request-without-requested-gate",
  "ai-output-url-ssrf-gate",
  "ai-prompt-template-fixed-delimiter",
  "applydefaults-dropped-opt",
  "archive-gz-without-safedecompress",
  "archive-wrap-partial-recipient",
  "backup-adapter-storage-without-posture-check",
  "bare-canonicalize-walk",
  "bare-error-throw",
  "bare-split-on-quoted-header-token-grammar",
  "bdat-last-double-reply",
  "bool-string-coerce-shape",
  "bot-challenge-secret-in-audit",
  "british-spelling-in-doc-prose",
  "buffer-from-no-encoding",
  "build-profile-base",
  "calendar-bysetpos-start-gate",
  "calendar-typeof-object-accepts-null",
  "calendar-utc-roundtrip-loss",
  "catenate-parens-order",
  "ci-test-job-missing-timeout",
  "cluster-vault-key-drift-without-rotation-accept-gate",
  "compliance-posture-coverage-drift",
  "condstore-implicit-engage-missing",
  "console-direct",
  "date-utc-round-trip",
  "db-collection-like-escapes-wildcards",
  "define-class-error-arg-order",
  "dense-wildcard",
  "documented-opt-never-read",
  "duplicate-block",
  "duplicate-regex",
  "dynamic-regex",
  "dynamic-require-operator-module",
  "enum-rank-without-validation",
  "error-code-namespace-kebab",
  "esbuild-pin-cross-artifact-drift",
  "from-base64url-untrapped",
  "fs-path-from-operator-identifier-without-traversal-refusal",
  "fsm-define-no-clone-before-freeze",
  "fuzz-build-jazzer-runtime",
  "gitleaks-entropy",
  "gitleaks-entropy-unallowed",
  "gpai-adherence-declaration-must-be-signed",
  "gunzip-bomb-conflated",
  "hand-rolled-sql",
  "handrolled-buffer-collect-bounded-framing",
  "handrolled-debounce-oneshot-connect-deadline",
  "handrolled-debounce-oneshot-grace-clear",
  "handrolled-debounce-stream-idle",
  "handrolled-deep-clone",
  "handrolled-race-timeout",
  "handrolled-retry-loop",
  "handrolled-sleep",
  "handrolled-url-build",
  "hardcoded-auth-mech",
  "hardcoded-framework-file-name",
  "hex-sha-compare-equals",
  "hostname-compare-trailing-dot-pre-split-refused",
  "http2-bare-close",
  "info-label-empty-omit-mismatch",
  "inline-require",
  "inline-require-in-deferred",
  "internal-binding-in-prose",
  "internal-narrative-comment",
  "jmap-eventsource-ping-shape",
  "jmap-id-undersized-cap",
  "leftmost-domain-informational",
  "legacy-url-format",
  "list-without-pagination",
  "listen-port-default",
  "literal-size-zero",
  "mail-direct-node-dns",
  "mail-store-fts-untransacted",
  "manual-byte-compare",
  "math-random-in-policy",
  "math-random-noncrypto-jitter-sampling",
  "mtls-ca-adopt-commit-pin-journal-divergence",
  "mtls-ca-commit-missing-rollback-journal",
  "mtls-ca-fingerprint-hashes-pem-not-der",
  "mtls-ca-generatecrl-persist-races-revocation",
  "mtls-ca-issuance-generation-zero-on-undeterminable",
  "mtls-ca-issuance-ledger-silent-empty-on-corrupt",
  "mtls-ca-leaf-algorithm-reads-mutable-pin",
  "mtls-ca-reconcile-silent-on-corrupt-journal",
  "mtls-ca-trust-bundle-unstable-snapshot",
  "naive-suffix-alignment",
  "nav-category-allowlist-drift",
  "nfinity-intentional",
  "no-number-money-arithmetic",
  "node-builtin-prefix",
  "noncestore-sync-treatment",
  "number-env-coerce",
  "objectstore-notfound-parity",
  "open-coded-lazy-require",
  "opts-block-without-opts-parameter",
  "orchestrator-registry-tenant-scope",
  "outbound-tls-posture",
  "outcome-branch-fallthrough-to-failed",
  "parseint-no-radix",
  "process-exit-operator-optin",
  "rag-source-classify-without-classifywithsources",
  "raw-byte-literal",
  "raw-hash-compare-nonsecret-tag",
  "raw-headers-distinct",
  "raw-mib-literal",
  "raw-new-url-parse-only",
  "raw-outbound-http-framework-internal",
  "raw-process-env-bootstrap",
  "raw-randombytes-token-mime-boundary",
  "raw-remote-addr",
  "raw-time-literal",
  "raw-timing-safe-equal-boot-prechecked",
  "raw-xff",
  "raw-xfp-telemetry-only",
  "regex-no-length-cap",
  "regex-superlinear-by-design",
  "release-push-path-missing-live-integration",
  "release-script-capture-status-unchecked",
  "release-unresolved-threads-cap-fail-open",
  "require-binding-name",
  "require-mtls-revocation-source-returns-boolean",
  "resolver-querymx-shape-assumed",
  "root-prefix-family-without-reseal",
  "scoped-context-binding-unused",
  "seal-without-aad-by-design",
  "secure-context-cert-compression",
  "serializer-realm-bound-instanceof",
  "session-updatedata-merges-one-level-deep",
  "sfv-citation-must-match-referencing-protocol",
  "shape-file-inline-opts-validation",
  "silent-catch-stream-teardown",
  "slsa-framework-action-not-sha-pinned",
  "smtp-linebuffer-utf8-roundtrip",
  "smtp-transport-hostname-local-typo",
  "sql-where-delegator-fixed-signature",
  "tenant-scope-shape-not-validated",
  "test-detached-async-iife-legacy",
  "tier-terminology",
  "timer-no-unref-process-pinning",
  "timer-no-unref-unrefed-below",
  "trim-before-validate",
  "truncated-comment-block",
  "uncapped-searchparams-object",
  "unresolved-marker",
  "url-path-unbounded-regex",
  "validateopts-key-never-read",
  "vendor-deny",
  "wiki-lockfile-file-link",
  "wiki-port-cross-artifact-drift",
  "wiki-stop-grace-below-shutdown-budget",
  "wildcard-suffix-match-without-single-label-check",
  "wrapped-aad-seal-needs-reseal-path",
]);

function upstreamPatternsPath() {
  if (process.env.EXCEPTD_UPSTREAM_PATTERNS) return process.env.EXCEPTD_UPSTREAM_PATTERNS;
  return path.resolve(ROOT, "..", "blamejs", "test", "layer-0-primitives", "codebase-patterns.test.js");
}

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
