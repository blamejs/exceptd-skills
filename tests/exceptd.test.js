"use strict";

// ---- routed from attestation-signature-roundtrip ----
;(() => {
/**
 * Audit-VV trust-boundary fixes (KK P1-1..P1-5 + MM P1-D).
 *
 * Each test pins an EXACT exit code (assert.equal(r.status, N)) and pairs
 * every field-presence check with a content-shape check, per the project's
 * coincidence-passing-tests rule. notEqual(r.status, 0) is forbidden — a
 * coincidence-passing test blocks future regressions while letting the
 * current one through.
 *
 * Fixes covered:
 *   KK P1-1  Sidecar shape no longer carries `signed_at` / `signs_path` /
 *            `signs_sha256`. The Ed25519 signature covers ONLY the
 *            attestation file bytes — fields in the sidecar that aren't in
 *            the signed message are replay-rewrite trivial.
 *   KK P1-2  cmdReattest persists `replay-<isoZ>.json` under the session
 *            directory whenever a replay produced a verdict (force-replay
 *            or otherwise). `attest verify <sid>` surfaces both the
 *            original + the replay in its results array.
 *   KK P1-3  Sidecar verifier rejects any algorithm field that isn't
 *            exactly "Ed25519" or "unsigned" (downgrade-bait substitution)
 *            with tamper_class:"algorithm-unsupported" and exit 6.
 *   KK P1-4  hasReadableStdin Windows fallback requires isTTY === false
 *            STRICTLY — not falsy. isTTY === undefined no longer routes
 *            through readFileSync(0) and blocks on wrapped duplexer test
 *            harnesses.
 *   KK P1-5  Pin loader strips leading UTF-8 BOM (Notepad with
 *            files.encoding=utf8bom) + ignores comment / empty lines.
 *            All four sites converge on the shared helper.
 *   MM P1-D  sanitizeOperatorText (library-side guard for direct
 *            buildEvidenceBundle callers) NFC-normalises, strips \p{C}
 *            (Cc/Cf/Cs/Co/Cn), caps at 256 codepoints, returns null on
 *            empty-after-strip so callers route through the
 *            bundle_publisher_unclaimed fallback.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');

const { ROOT, makeSuiteHome, makeCli, tryJson } = require('./_helpers/cli');

const SUITE_HOME = makeSuiteHome('exceptd-audit-vv-trust-');
const cli = makeCli(SUITE_HOME);

const PKG_PRIV_KEY = path.join(ROOT, '.keys', 'private.pem');
const HAS_PRIV_KEY = fs.existsSync(PKG_PRIV_KEY);

function locateAttestationFiles(sid) {
  const candidates = [
    path.join(SUITE_HOME, 'attestations', sid),
    path.join(SUITE_HOME, '.exceptd', 'attestations', sid),
  ];
  const attRoot = candidates.find((p) => fs.existsSync(p));
  if (!attRoot) return null;
  const files = fs.readdirSync(attRoot);
  const jsonFiles = files.filter((f) => f.endsWith('.json') && !f.endsWith('.sig'));
  return {
    dir: attRoot,
    files: jsonFiles,
    primaryJson: jsonFiles.includes('attestation.json')
      ? path.join(attRoot, 'attestation.json')
      : path.join(attRoot, jsonFiles[0]),
    primarySig: jsonFiles.includes('attestation.json')
      ? path.join(attRoot, 'attestation.json.sig')
      : path.join(attRoot, jsonFiles[0] + '.sig'),
  };
}

// ---------------------------------------------------------------------------
// KK P1-1 — sidecar `signed_at` is no longer present; rewriting it is a
// no-op for verify. Conversely the attestation file `captured_at` is
// signed; rewriting that field invalidates the signature.
// ---------------------------------------------------------------------------




// ---------------------------------------------------------------------------
// KK P1-2 — force-replay persists a replay-*.json record on disk.
// ---------------------------------------------------------------------------



// ---------------------------------------------------------------------------
// KK P1-3 — strict algorithm check.
// ---------------------------------------------------------------------------




// ---------------------------------------------------------------------------
// KK P1-4 — hasReadableStdin Windows fallback strict isTTY===false.
// ---------------------------------------------------------------------------



// ---------------------------------------------------------------------------
// KK P1-5 — pin loader strips BOM + tolerates CRLF + comments.
// ---------------------------------------------------------------------------







// ---------------------------------------------------------------------------
// MM P1-D — sanitizeOperatorText library-side guard.
// ---------------------------------------------------------------------------

test('KK P1-4 — hasReadableStdin source guards on strict isTTY===false on win32', () => {
  // The function isn't a CommonJS export (bin/exceptd.js dispatches under
  // require.main === module). Verify the source-level invariant directly:
  // the win32 fallback MUST require `process.stdin.isTTY === false`
  // strictly (not falsy), so isTTY===undefined no longer routes through
  // readFileSync(0) on a wrapped duplexer.
  const src = fs.readFileSync(path.join(ROOT, 'bin', 'exceptd.js'), 'utf8');
  const m = src.match(/function hasReadableStdin\(\)\s*\{([\s\S]*?)\n\}/);
  assert.ok(m, 'hasReadableStdin must exist in bin/exceptd.js');
  const body = m[1];
  // Negative — the legacy `!process.stdin.isTTY` truthy fallback in a
  // win32 conditional is forbidden. (Equivalent test: ensure no return
  // line in the win32 conditional uses the bare-not form.)
  assert.ok(
    !/win32[\s\S]*return\s+!process\.stdin\.isTTY\s*;/.test(body),
    'win32 fallback must NOT return `!process.stdin.isTTY` (returns true on isTTY===undefined → blocks readFileSync on wrapped duplexers)'
  );
  // Positive — the strict equality form MUST be present in the win32 path.
  assert.match(
    body,
    /win32[\s\S]*process\.stdin\.isTTY\s*===\s*false/,
    'win32 fallback must guard on `process.stdin.isTTY === false` strictly'
  );
});
})();

// ---- routed from attestation-mode-0600 ----
;(() => {
/**
 * tests/attestation-mode-0600.test.js
 *
 * Cycle 18 P1 F2 fix (v0.12.38): attestation files were written with the
 * umask-derived mode (typically 0o644 — group/world readable). On
 * multi-tenant shared hosts a different user account could read the
 * operator's evidence submission, jurisdiction obligations, and consent
 * records. Fix: mirror the existing private-key handling in lib/sign.js
 * (`fs.writeFileSync(path, content, { mode: 0o600 })` + restrictWindowsAcl
 * for Windows ACL inheritance stripping).
 *
 * Per the anti-coincidence rule, every assertion checks an EXACT
 * mode value (0o600) — not "less permissive than 0o644".
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const { spawnSync } = require('node:child_process');

const ROOT = path.join(__dirname, '..');
const CLI = path.join(ROOT, 'bin', 'exceptd.js');

function cli(args, opts = {}) {
  return spawnSync(process.execPath, [CLI, ...args], {
    encoding: 'utf8',
    cwd: opts.cwd || ROOT,
    env: { ...process.env, EXCEPTD_DEPRECATION_SHOWN: '1', ...(opts.env || {}) },
    input: opts.input,
  });
}

function findAttestation(rootDir) {
  // resolveAttestationRoot returns $EXCEPTD_HOME/attestations/. The
  // persist layer writes to <root>/<session-id>/attestation.json (one
  // level deep). Some CI shapes wrap with an extra run-tag dir; walk
  // both 1-level and 2-level structures to be robust across platforms.
  if (!fs.existsSync(rootDir)) return null;
  for (const ent of fs.readdirSync(rootDir, { withFileTypes: true })) {
    if (!ent.isDirectory()) continue;
    const level1 = path.join(rootDir, ent.name);
    // Try 1-level (session at this depth).
    const direct = path.join(level1, 'attestation.json');
    if (fs.existsSync(direct)) return direct;
    // Try 2-level (run-tag wrapper).
    for (const inner of fs.readdirSync(level1, { withFileTypes: true })) {
      if (!inner.isDirectory()) continue;
      const att = path.join(level1, inner.name, 'attestation.json');
      if (fs.existsSync(att)) return att;
    }
  }
  return null;
}

test('EXCEPTD_HOME override documented in README', () => {
  const readme = fs.readFileSync(path.join(ROOT, 'README.md'), 'utf8');
  // Pre-v0.12.38 the env var was only mentioned in inline help text.
  // Cycle 18 P2 F6 surfaced this gap: multi-tenant operators had no way
  // to discover the override without grepping the binary.
  assert.match(readme, /EXCEPTD_HOME/,
    'README must document EXCEPTD_HOME env var for multi-tenant attestation-root override');
});
})();
