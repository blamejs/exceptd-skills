#!/usr/bin/env node
'use strict';

/**
 * Patch-only-cadence gate. A minor or major fails unless the committed
 * tests/.version-bump-ack.json names that exact version, so an ack travels with
 * the checkout and a stale one cannot authorize a later bump.
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

function classifyBump(prev, cur) {
  const a = parseSemver(prev);
  const b = parseSemver(cur);
  if (!a || !b) return 'unknown';
  if (b.major !== a.major) return b.major > a.major ? 'major' : 'downgrade';
  if (b.minor !== a.minor) return b.minor > a.minor ? 'minor' : 'downgrade';
  if (b.patch !== a.patch) return b.patch > a.patch ? 'patch' : 'downgrade';
  return 'none';
}

// `ack` is { version, type } or null.
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
  if (ack && ack.version === cur && ack.type === bump) {
    return { ok: true, bump, reason: `${bump} bump authorized for ${cur} via tests/.version-bump-ack.json` };
  }
  return {
    ok: false,
    bump,
    reason: `${bump} bump (${prev} -> ${cur}) is not the patch-only default and is not authorized`,
  };
}

// Document order — newest first, which determinePrevious relies on.
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

// Fails closed: an unreadable or heading-less CHANGELOG must not look like a
// first release, because checkBump(null, ...) then authorizes any bump.
function determinePrevious(text, cur) {
  if (text == null) {
    return { ok: false, reason: 'CHANGELOG.md could not be read' };
  }
  const versions = changelogVersions(text);
  if (versions.length === 0) {
    return { ok: false, reason: 'no `## X.Y.Z` headings found in CHANGELOG.md — cannot determine previous version' };
  }
  return { ok: true, prev: versions.find((v) => v !== cur) || null };
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

  // null on a read failure, never '' — determinePrevious fails closed on null.
  let changelogText = null;
  try { changelogText = fs.readFileSync(CHANGELOG_PATH, 'utf8'); } catch (_e) { changelogText = null; }
  const prevRes = determinePrevious(changelogText, cur);
  if (!prevRes.ok) {
    process.stderr.write(`[check-version-bump] FAIL — ${prevRes.reason}; failing closed (cannot validate cadence).\n`);
    process.exitCode = 1;
    return;
  }
  const prev = prevRes.prev;

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
    // `process.exitCode`, not process.exit(): exit truncates the buffered stdout write.
    process.exitCode = 1;
    return;
  }
}

if (require.main === module) main();

module.exports = { classifyBump, checkBump, changelogVersions, determinePrevious };
