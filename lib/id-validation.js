'use strict';

/**
 * Shared validation for path-component-shaped operator inputs.
 *
 * Six sites in `bin/exceptd.js` previously hand-rolled regexes of the form
 * /^[A-Za-z0-9._-]{1,64}$/ for `--session-id`, `--playbook`, attestation
 * filenames, and `--evidence-dir` filenames. Each regex was slightly
 * different in character class ordering; each grew its own follow-on checks
 * (all-dots refusal, length cap, leading-dot refusal) at different rates.
 *
 * This module is the single source of truth. Adding a new path-component
 * input means calling `validateIdComponent(value, role)` and propagating
 * the returned {ok, reason} pair to the caller's emit-error path.
 *
 * Three role types, three character classes:
 *   - 'session'  — sessions live under `.exceptd/attestations/<sid>/`. Allow
 *                  lower+upper alpha, digit, dot, underscore, hyphen, 1-64
 *                  chars. Refuse all-dots.
 *   - 'playbook' — playbook ids index `data/playbooks/<id>.json`. Stricter:
 *                  lowercase-only, must start with a letter, no dots (all
 *                  catalogued playbook ids match `/^[a-z][a-z0-9-]{0,63}$/`).
 *   - 'filename' — attestation filename inside a session directory. Same
 *                  charset as 'session' but length cap reflects filename
 *                  policy (no path separators ever).
 *
 * The function never reads the filesystem; combine with realpathSync at
 * the caller for full path-traversal defense.
 */

const SESSION_RE = /^[A-Za-z0-9._-]{1,64}$/;
const PLAYBOOK_RE = /^[a-z][a-z0-9-]{0,63}$/;
const FILENAME_RE = /^[A-Za-z0-9._-]{1,80}$/;
const ALL_DOTS_RE = /^\.+$/;

function validateIdComponent(value, role) {
  if (typeof value !== 'string') {
    return { ok: false, reason: `expected string, got ${typeof value}` };
  }
  if (value.length === 0) {
    return { ok: false, reason: 'must not be empty' };
  }
  let re;
  let constraint;
  switch (role) {
    case 'session':
      re = SESSION_RE;
      constraint = '^[A-Za-z0-9._-]{1,64}$';
      break;
    case 'playbook':
      re = PLAYBOOK_RE;
      constraint = '^[a-z][a-z0-9-]{0,63}$ (lowercase, starts with letter, no dots)';
      break;
    case 'filename':
      re = FILENAME_RE;
      constraint = '^[A-Za-z0-9._-]{1,80}$';
      break;
    default:
      return { ok: false, reason: `unknown role: ${role}` };
  }
  if (!re.test(value)) {
    return { ok: false, reason: `must match ${constraint}` };
  }
  // All-dots refusal applies after the character-class regex because the
  // session/filename classes admit any string of dots (`.`, `..`, `...`),
  // each of which path-resolves into or above the intended directory.
  if (ALL_DOTS_RE.test(value)) {
    return { ok: false, reason: 'must not consist entirely of dots' };
  }
  return { ok: true };
}

/**
 * Cheap typed-throw wrapper for callers that prefer exceptions over result
 * objects (lib/playbook-runner.js uses this shape for loadPlaybook).
 */
function assertIdComponent(value, role) {
  const r = validateIdComponent(value, role);
  if (!r.ok) {
    const err = new Error(`invalid ${role} id (${r.reason}): ${typeof value === 'string' ? value.slice(0, 80) : typeof value}`);
    err.code = 'EXCEPTD_INVALID_ID';
    err.role = role;
    err.reason = r.reason;
    throw err;
  }
  return value;
}

module.exports = {
  validateIdComponent,
  assertIdComponent,
  SESSION_RE,
  PLAYBOOK_RE,
  FILENAME_RE,
};
