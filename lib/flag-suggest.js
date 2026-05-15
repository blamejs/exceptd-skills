'use strict';

/**
 * Levenshtein-distance flag-typo suggestions.
 *
 * Operator typos `--evidnce` / `--csaf-stats` / `--bundle-epohc` were silently
 * absorbed by the argv parser, falling through as boolean true flags with no
 * value, then producing cryptic downstream errors. This helper compares an
 * unknown flag to a verb-scoped allowlist and returns the closest match at
 * distance ≤ 2 AND ≤ floor(flag.length / 2).
 *
 * Per-verb allowlists are the canonical CLI surface. Adding a new flag to a
 * verb means appending to the allowlist here AND updating the printPlaybookVerbHelp
 * block; a test asserts the two sets agree.
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
 * Suggest the closest allowlisted flag to a given unknown flag.
 *
 * @param {string} flag - operator-supplied flag name without leading --
 * @param {string[]} allowlist - known flag names for the active verb
 * @returns {string|null} the suggested flag name or null when no close match
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

/**
 * Per-verb known-flag allowlist. Every operator-facing flag should appear
 * exactly once per verb where it is consumed. Flags consumed by every verb
 * (e.g. `pretty`, `json`, `help`) live under '_global'.
 */
const VERB_FLAG_ALLOWLIST = Object.freeze({
  _global: ['help', 'pretty', 'json', 'verbose'],
  run: [
    'evidence', 'evidence-dir', 'session-id', 'force-overwrite', 'attestation-root',
    'mode', 'air-gap', 'force-stale', 'operator', 'ack', 'csaf-status',
    'publisher-namespace', 'vex', 'diff-from-latest', 'all', 'scope',
    'strict-preconditions', 'ci', 'block-on-jurisdiction-clock', 'upstream-check',
    'session-key', 'tlp', 'bundle-deterministic', 'bundle-epoch',
  ],
  ci: [
    'evidence', 'evidence-dir', 'session-id', 'force-overwrite', 'attestation-root',
    'mode', 'air-gap', 'force-stale', 'operator', 'ack', 'csaf-status',
    'publisher-namespace', 'vex', 'all', 'scope', 'required', 'format',
    'strict-preconditions', 'block-on-jurisdiction-clock', 'tlp',
  ],
  'run-all': [
    'evidence', 'evidence-dir', 'session-id', 'force-overwrite', 'attestation-root',
    'mode', 'air-gap', 'force-stale', 'operator', 'ack', 'csaf-status',
    'publisher-namespace', 'vex', 'scope', 'strict-preconditions', 'tlp',
  ],
  'ai-run': [
    'evidence', 'no-stream', 'session-id', 'force-overwrite', 'attestation-root',
    'operator', 'ack', 'csaf-status', 'publisher-namespace', 'air-gap',
    'mode', 'force-stale', 'tlp',
  ],
  ingest: [
    'evidence', 'session-id', 'force-overwrite', 'attestation-root', 'operator',
    'ack', 'csaf-status', 'publisher-namespace', 'air-gap', 'force-stale',
    'strict-preconditions',
  ],
  brief: ['all', 'scope', 'directives', 'flat', 'phase'],
  discover: ['scan-only', 'scope'],
  ask: [],
  attest: [
    'against', 'playbook', 'since', 'latest', 'format', 'force', 'dry-run',
    'all-older-than',
  ],
  reattest: [
    'playbook', 'since', 'latest', 'force-replay', 'attestation-root',
  ],
  doctor: ['signatures', 'cves', 'rfcs', 'fix', 'registry-check', 'exit-codes'],
  lint: ['evidence'],
  refresh: [
    'apply', 'dry-run', 'from-cache', 'from-fixture', 'network', 'source',
    'advisory', 'force-stale', 'force-stale-acked', 'air-gap', 'swarm',
  ],
  prefetch: ['source', 'cache-dir', 'max-age', 'force', 'no-network', 'quiet'],
});

/**
 * Return the allowlist for a verb (global flags always included).
 */
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
