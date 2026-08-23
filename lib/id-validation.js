'use strict';

/**
 * Validation for path-component-shaped operator inputs — `--session-id`,
 * `--playbook`, attestation and `--evidence-dir` filenames. The one definition
 * for every such site in `bin/exceptd.js`; a second copy drifts. Callers
 * propagate the returned {ok, reason} pair to their emit-error path.
 *
 * Never reads the filesystem — pair it with realpathSync at the caller for
 * full path-traversal defense.
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
  // The session/filename classes admit any string of dots (`.`, `..`, `...`),
  // each of which path-resolves into or above the intended directory.
  if (ALL_DOTS_RE.test(value)) {
    return { ok: false, reason: 'must not consist entirely of dots' };
  }
  return { ok: true };
}

// Throwing counterpart to validateIdComponent; the error carries
// code `EXCEPTD_INVALID_ID`.
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
