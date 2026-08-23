'use strict';

/**
 * Levenshtein-distance flag-typo suggestions against a verb-scoped allowlist.
 *
 * The allowlists are the canonical CLI surface: a new flag must be appended
 * here AND to the printPlaybookVerbHelp block, and VERB_FLAG_ALLOWLIST.doctor
 * must stay aligned with KNOWN_DOCTOR_FLAGS in bin/exceptd.js.
 */

function editDistance(a, b) {
  if (a === b) return 0;
  if (a.length === 0) return b.length;
  if (b.length === 0) return a.length;
  const prev = new Array(b.length + 1);
  const curr = new Array(b.length + 1);
  for (let j = 0; j <= b.length; j++) prev[j] = j;
  for (let i = 1; i <= a.length; i++) {
    curr[0] = i;
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      curr[j] = Math.min(
        curr[j - 1] + 1,
        prev[j] + 1,
        prev[j - 1] + cost,
      );
    }
    for (let j = 0; j <= b.length; j++) prev[j] = curr[j];
  }
  return prev[b.length];
}

/**
 * The closest allowlisted flag, or null when none is close. `flag` is the
 * operator-supplied name WITHOUT the leading `--`.
 */
function suggestFlag(flag, allowlist) {
  if (typeof flag !== 'string' || flag.length === 0) return null;
  if (!Array.isArray(allowlist) || allowlist.length === 0) return null;
  const probe = flag.toLowerCase();
  const cap = Math.min(2, Math.floor(flag.length / 2));
  let bestDist = Infinity;
  let best = null;
  for (const candidate of allowlist) {
    const d = editDistance(probe, candidate.toLowerCase());
    if (d < bestDist && d <= cap) {
      bestDist = d;
      best = candidate;
    }
  }
  return best;
}

/** Flags accepted by every verb live under '_global'. */
const VERB_FLAG_ALLOWLIST = Object.freeze({
  _global: ['help', 'pretty', 'json', 'verbose', 'quiet'],
  run: [
    'evidence', 'evidence-dir', 'session-id', 'force-overwrite', 'attestation-root',
    'mode', 'air-gap', 'force-stale', 'operator', 'ack', 'csaf-status',
    'publisher-namespace', 'vex', 'diff-from-latest', 'all', 'scope',
    'strict-preconditions', 'ci', 'block-on-jurisdiction-clock', 'upstream-check',
    'session-key', 'tlp', 'bundle-deterministic', 'bundle-epoch',
    'include-judgement-shaped', 'format', 'directive', 'explain', 'signal-list',
  ],
  ci: [
    'evidence', 'evidence-dir', 'session-id', 'force-overwrite', 'attestation-root',
    'mode', 'air-gap', 'force-stale', 'operator', 'ack', 'csaf-status',
    'publisher-namespace', 'vex', 'all', 'scope', 'required', 'format',
    'strict-preconditions', 'block-on-jurisdiction-clock', 'tlp',
    'bundle-deterministic', 'bundle-epoch',
    'include-judgement-shaped',
  ],
  'run-all': [
    'evidence', 'evidence-dir', 'session-id', 'force-overwrite', 'attestation-root',
    'mode', 'air-gap', 'force-stale', 'operator', 'ack', 'csaf-status',
    'publisher-namespace', 'vex', 'scope', 'strict-preconditions', 'tlp',
    'bundle-deterministic', 'bundle-epoch',
    'include-judgement-shaped',
  ],
  'ai-run': [
    'evidence', 'no-stream', 'session-id', 'force-overwrite', 'attestation-root',
    'operator', 'ack', 'csaf-status', 'publisher-namespace', 'air-gap',
    'mode', 'force-stale', 'tlp',
    'bundle-deterministic', 'bundle-epoch',
  ],
  brief: ['all', 'scope', 'directives', 'flat', 'phase'],
  discover: ['scan-only', 'scope', 'cwd'],
  ask: [],
  attest: [
    'against', 'playbook', 'since', 'latest', 'format', 'force', 'dry-run',
    'all-older-than', 'limit', 'require-signed',
  ],
  reattest: [
    'playbook', 'since', 'latest', 'force-replay', 'attestation-root',
  ],
  doctor: ['signatures', 'cves', 'rfcs', 'fix', 'registry-check', 'exit-codes', 'shipped-tarball', 'ai-config', 'currency', 'collectors', 'air-gap'],
  lint: ['evidence'],
  collect: ['cwd', 'attest-ownership', 'resolve', 'air-gap'],
  refresh: [
    'apply', 'dry-run', 'from-cache', 'from-fixture', 'network', 'source',
    'advisory', 'check-advisories', 'force-stale', 'force-stale-acked', 'air-gap', 'swarm',
  ],
  prefetch: ['source', 'cache-dir', 'max-age', 'force', 'no-network'],
});

function flagsFor(verb) {
  const verbFlags = VERB_FLAG_ALLOWLIST[verb] || [];
  return [...VERB_FLAG_ALLOWLIST._global, ...verbFlags];
}

module.exports = {
  editDistance,
  suggestFlag,
  flagsFor,
  VERB_FLAG_ALLOWLIST,
};
