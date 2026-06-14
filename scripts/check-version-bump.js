#!/usr/bin/env node
'use strict';

/**
 * scripts/check-version-bump.js — patch-only-cadence predeploy gate.
 *
 * Why this exists. The project cadence is "patch is the only default bump; a
 * minor or major requires explicit human authorization." That rule lived in
 * the contributor guide and in maintainer memory — and was violated anyway
 * (two releases shipped as minors that should have been patches). A written
 * rule the tooling does not enforce is one a tired/automated contributor will
 * eventually skip. This gate makes the rule mechanical: an unauthorized
 * minor/major version bump fails predeploy and cannot ship.
 *
 * Hermetic by design. Authorization is a COMMITTED artifact
 * (tests/.version-bump-ack.json), not an environment variable, because
 * `npm run predeploy` runs in the release.yml validate job as well as locally.
 * An env-var scheme would either false-fail a legitimately-authorized minor in
 * CI or require per-release CI config. A committed ack file travels with the
 * checkout, so the gate enforces identically everywhere — and a minor bump
 * becomes a loud, reviewable line in the PR diff instead of a silent change to
 * a version string.
 *
 * Mechanism:
 *   prev = the most recent OTHER `## X.Y.Z` heading in CHANGELOG.md
 *   cur  = package.json version (== the top CHANGELOG heading; the version-sync
 *          gate enforces that match separately)
 *   classify prev -> cur as patch | minor | major | none | downgrade
 *     - patch / none      -> pass (the default; zero ceremony)
 *     - downgrade / bad   -> fail (versions only move forward)
 *     - minor / major     -> pass ONLY if tests/.version-bump-ack.json names
 *                            the exact `cur` version with the matching type;
 *                            otherwise fail with remediation.
 *
 * To authorize a minor (only after the user explicitly asks for one):
 *   echo '{"version":"0.19.0","type":"minor"}' > tests/.version-bump-ack.json
 * and commit it. The ack is version-specific, so a stale ack cannot authorize
 * a different future bump.
 *
 * Output:
 *   stdout: structured JSON when --json, else a one-line summary
 *   exit 0: patch/none, or an authorized minor/major
 *   exit 1: unauthorized minor/major, downgrade, or unparseable version
 */

const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const CHANGELOG_PATH = path.join(ROOT, 'CHANGELOG.md');
const PKG_PATH = path.join(ROOT, 'package.json');
const ACK_PATH = path.join(ROOT, 'tests', '.version-bump-ack.json');

function parseSemver(v) {
  const m = /^(\d+)\.(\d+)\.(\d+)/.exec(String(v == null ? '' : v).trim());
  if (!m) return null;
  return { major: Number(m[1]), minor: Number(m[2]), patch: Number(m[3]) };
}

// Classify the transition prev -> cur. Pure; exported for unit tests.
function classifyBump(prev, cur) {
  const a = parseSemver(prev);
  const b = parseSemver(cur);
  if (!a || !b) return 'unknown';
  if (b.major !== a.major) return b.major > a.major ? 'major' : 'downgrade';
  if (b.minor !== a.minor) return b.minor > a.minor ? 'minor' : 'downgrade';
  if (b.patch !== a.patch) return b.patch > a.patch ? 'patch' : 'downgrade';
  return 'none';
}

// Decide whether a bump is allowed given the committed ack (or null). Pure;
// exported for unit tests. ack = { version, type } | null.
function checkBump(prev, cur, ack) {
  if (!prev) return { ok: true, bump: 'initial', reason: 'no previous version recorded' };
  const bump = classifyBump(prev, cur);
  if (bump === 'unknown') {
    return { ok: false, bump, reason: `unparseable version (${prev} -> ${cur})` };
  }
  if (bump === 'downgrade') {
    return { ok: false, bump, reason: `version went backwards (${prev} -> ${cur}); versions only move forward` };
  }
  if (bump === 'patch' || bump === 'none') {
    return { ok: true, bump, reason: `${bump} bump (${prev} -> ${cur})` };
  }
  // minor or major — requires explicit committed authorization for this exact version.
  if (ack && ack.version === cur && ack.type === bump) {
    return { ok: true, bump, reason: `${bump} bump authorized for ${cur} via tests/.version-bump-ack.json` };
  }
  return {
    ok: false,
    bump,
    reason: `${bump} bump (${prev} -> ${cur}) is not the patch-only default and is not authorized`,
  };
}

// Extract `## X.Y.Z` version headings from CHANGELOG.md, in document order.
function changelogVersions(text) {
  const out = [];
  const re = /^##\s+(\d+\.\d+\.\d+)\b/gm;
  let m;
  while ((m = re.exec(text)) !== null) out.push(m[1]);
  return out;
}

function suggestPatch(prev) {
  const a = parseSemver(prev);
  return a ? `${a.major}.${a.minor}.${a.patch + 1}` : null;
}

function readAck() {
  if (!fs.existsSync(ACK_PATH)) return null;
  try {
    const j = JSON.parse(fs.readFileSync(ACK_PATH, 'utf8'));
    if (j && typeof j.version === 'string' && typeof j.type === 'string') return j;
    return null;
  } catch (_e) {
    return null;
  }
}

function main() {
  const wantJson = process.argv.includes('--json');

  let pkg;
  try { pkg = JSON.parse(fs.readFileSync(PKG_PATH, 'utf8')); }
  catch (e) {
    process.stderr.write(`[check-version-bump] cannot read package.json: ${e.message}\n`);
    process.exitCode = 1;
    return;
  }
  const cur = pkg.version;

  let changelog = '';
  try { changelog = fs.readFileSync(CHANGELOG_PATH, 'utf8'); } catch (_e) { changelog = ''; }
  const versions = changelogVersions(changelog);
  // prev = the most recent heading that differs from the current version.
  const prev = versions.find((v) => v !== cur) || null;

  const ack = readAck();
  const res = checkBump(prev, cur, ack);

  if (wantJson) {
    process.stdout.write(JSON.stringify({
      ok: res.ok,
      verb: 'check-version-bump',
      previous: prev,
      current: cur,
      bump: res.bump,
      authorized: !!(ack && ack.version === cur),
      reason: res.reason,
    }) + '\n');
  } else {
    process.stdout.write(`[check-version-bump] ${prev || '(none)'} -> ${cur}: ${res.bump} — ${res.ok ? 'ok' : 'BLOCKED'}\n`);
  }

  if (!res.ok) {
    process.stderr.write(`[check-version-bump] FAIL — ${res.reason}.\n`);
    if (res.bump === 'minor' || res.bump === 'major') {
      const patch = suggestPatch(prev);
      process.stderr.write('[check-version-bump] Patch is the only default bump. A minor/major needs explicit user authorization.\n');
      if (patch) process.stderr.write(`[check-version-bump] If this should be a patch, set the version to ${patch}.\n`);
      process.stderr.write(`[check-version-bump] If the user explicitly authorized a ${res.bump}, commit tests/.version-bump-ack.json = {"version":"${cur}","type":"${res.bump}"}.\n`);
    }
    // process.exitCode (not process.exit) so the buffered stdout write above
    // is not truncated when stdout is piped (the stdout-flush-truncation class).
    process.exitCode = 1;
    return;
  }
}

if (require.main === module) main();

module.exports = { classifyBump, checkBump, changelogVersions, parseSemver };
