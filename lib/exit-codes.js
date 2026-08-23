'use strict';

/**
 * Canonical exit-code constants for every CLI verb. Exit sites reference a
 * constant, not a literal; `exceptd doctor --exit-codes` dumps this map as
 * JSON, so help text cannot drift from runtime.
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
  UNKNOWN_COMMAND: 10,
  WATCH_LOCK_CONTENTION: 75,
});

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
  10: { name: 'UNKNOWN_COMMAND', summary: 'Unknown verb / dispatcher refused the requested command. Distinct from DETECTED_ESCALATE (2) which means a verb ran and detected an escalation-worthy finding.' },
  75: { name: 'WATCH_LOCK_CONTENTION', summary: 'Watch daemon lock is held by a live process; retry after it exits (sysexits EX_TEMPFAIL). Distinct from LOCK_CONTENTION (8), the per-playbook attestation lock.' },
});

function exitCodeName(code) {
  const e = EXIT_CODE_DESCRIPTIONS[code];
  return e ? e.name : 'UNKNOWN';
}

function listExitCodes() {
  return Object.entries(EXIT_CODE_DESCRIPTIONS).map(([code, info]) => ({
    code: Number(code),
    name: info.name,
    summary: info.summary,
  }));
}

/**
 * Set the process exit code WITHOUT calling process.exit(), so buffered
 * stdout drains on natural event-loop shutdown; process.exit() terminates
 * synchronously and truncates a piped stdout write. Use on any
 * exit-after-stdout-write path — daemons and tests that need synchronous
 * termination still call process.exit() directly.
 */
function safeExit(code) {
  // A non-zero code already set wins: emit()'s ok:false fallback must not
  // overwrite a caller's BLOCKED (4) with GENERIC_FAILURE (1).
  if (!process.exitCode || process.exitCode === 0) {
    process.exitCode = code;
  }
}

module.exports = {
  EXIT_CODES,
  EXIT_CODE_DESCRIPTIONS,
  exitCodeName,
  listExitCodes,
  safeExit,
};
