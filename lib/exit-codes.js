'use strict';

/**
 * Canonical exit-code constants for every CLI verb.
 *
 * Every `process.exitCode = N` / `process.exit(N)` site in `bin/exceptd.js`
 * (and any library that wants to set an exit code via emit() ok:false bodies)
 * should reference one of these constants rather than a bare number literal.
 * The map is the source of truth for help text — `exceptd doctor --exit-codes`
 * dumps it as JSON so operator-facing docs cannot drift from runtime.
 *
 * History: prior to v0.12.24 codes were bare magic numbers scattered across
 * ~30 sites. Code 3 in particular meant both "session-id collision" (cmdRun)
 * and "ran-but-no-evidence" (cmdCi) — two semantics, one code, no doc surface.
 * v0.12.24 splits them and centralises so a new verb cannot regress by typo.
 */

const EXIT_CODES = Object.freeze({
  SUCCESS: 0,
  GENERIC_FAILURE: 1,
  DETECTED_ESCALATE: 2,
  RAN_NO_EVIDENCE: 3,
  BLOCKED: 4,
  JURISDICTION_CLOCK_STARTED: 5,
  TAMPERED: 6,
  SESSION_ID_COLLISION: 7,
  LOCK_CONTENTION: 8,
  STORAGE_EXHAUSTED: 9,
});

/**
 * Human-readable + machine-stable description per code. Source for the
 * `exceptd doctor --exit-codes` dump and for help-text rendering.
 */
const EXIT_CODE_DESCRIPTIONS = Object.freeze({
  0: { name: 'SUCCESS', summary: 'Verb completed successfully.' },
  1: { name: 'GENERIC_FAILURE', summary: 'Unhandled error or validation failure.' },
  2: { name: 'DETECTED_ESCALATE', summary: 'CI gate: classification === detected, operator action required.' },
  3: { name: 'RAN_NO_EVIDENCE', summary: 'CI gate: verb ran but produced no actionable evidence.' },
  4: { name: 'BLOCKED', summary: 'CI gate: ok:false body — precondition refusal or hard error.' },
  5: { name: 'JURISDICTION_CLOCK_STARTED', summary: 'Jurisdictional notification window opened (e.g. NIS2 24h, DORA 4h, GDPR 72h).' },
  6: { name: 'TAMPERED', summary: 'Attestation sidecar verification failed (signed-but-invalid, corrupt, unsigned-substitution, algorithm-unsupported).' },
  7: { name: 'SESSION_ID_COLLISION', summary: 'Persisting attestation would overwrite an existing session; pass --force-overwrite to replace or supply a fresh --session-id.' },
  8: { name: 'LOCK_CONTENTION', summary: 'Concurrent invocation holds the per-playbook attestation lock; retry after the busy run releases.' },
  9: { name: 'STORAGE_EXHAUSTED', summary: 'Disk full, quota exceeded, or read-only filesystem prevented attestation write (ENOSPC, EDQUOT, EROFS).' },
});

/**
 * Return the human-readable name for a numeric exit code.
 */
function exitCodeName(code) {
  const e = EXIT_CODE_DESCRIPTIONS[code];
  return e ? e.name : 'UNKNOWN';
}

/**
 * Return all exit codes as a stable-shape array suitable for JSON dump.
 */
function listExitCodes() {
  return Object.entries(EXIT_CODE_DESCRIPTIONS).map(([code, info]) => ({
    code: Number(code),
    name: info.name,
    summary: info.summary,
  }));
}

module.exports = {
  EXIT_CODES,
  EXIT_CODE_DESCRIPTIONS,
  exitCodeName,
  listExitCodes,
};
