'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

const ROOT = path.join(__dirname, '..');
const BIN = path.join(ROOT, 'bin', 'exceptd.js');

function run(args) {
  return spawnSync(process.execPath, [BIN, ...args], { encoding: 'utf8', cwd: ROOT });
}

test('bin/exceptd.js: help exits 0 and lists the documented subcommands', () => {
  const r = run(['help']);
  assert.equal(r.status, 0);
  assert.match(r.stdout, /exceptd —/);
  for (const cmd of ['path', 'prefetch', 'refresh', 'build-indexes', 'scan', 'currency', 'validate-cves', 'validate-rfcs', 'verify']) {
    assert.match(r.stdout, new RegExp('\\b' + cmd + '\\b'), `help is missing "${cmd}"`);
  }
});

test('bin/exceptd.js: version prints the package.json version', () => {
  const r = run(['version']);
  assert.equal(r.status, 0);
  const pkgVersion = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8')).version;
  assert.equal(r.stdout.trim(), pkgVersion);
});

test('bin/exceptd.js: path prints an absolute, readable directory', () => {
  const r = run(['path']);
  assert.equal(r.status, 0);
  const printed = r.stdout.trim();
  assert.ok(path.isAbsolute(printed), `expected absolute path, got "${printed}"`);
  assert.ok(fs.existsSync(path.join(printed, 'AGENTS.md')), `path output should contain AGENTS.md`);
});

test('bin/exceptd.js: --help and -h aliases work', () => {
  for (const flag of ['--help', '-h']) {
    const r = run([flag]);
    assert.equal(r.status, 0, `${flag} should exit 0`);
    assert.match(r.stdout, /exceptd —/);
  }
});

test('bin/exceptd.js: --version and -v aliases work', () => {
  for (const flag of ['--version', '-v']) {
    const r = run([flag]);
    assert.equal(r.status, 0, `${flag} should exit 0`);
    const v = r.stdout.trim();
    assert.match(v, /^\d+\.\d+\.\d+/, `${flag} should print a semver, got "${v}"`);
  }
});

test('bin/exceptd.js: unknown command exits with EXIT_CODES.UNKNOWN_COMMAND (10) + helpful stderr', () => {
  // Cycle 9 B1 (v0.12.29): unknown-command was previously code 2 which
  // collided with EXIT_CODES.DETECTED_ESCALATE. The split moves dispatcher
  // refusals to code 10 so operators wiring `case 2)` only see escalations.
  const r = run(['totally-not-real']);
  assert.equal(r.status, 10);
  assert.match(r.stderr, /unknown command/);
  assert.match(r.stderr, /exceptd help/);
});

test('bin/exceptd.js: orchestrator passthrough preserves the subcommand', () => {
  // `currency` is one of the orchestrator passthroughs. Run it and check it
  // produces the orchestrator's currency-report header.
  const r = run(['currency']);
  assert.equal(r.status, 0, `stderr: ${r.stderr}`);
  assert.match(r.stdout, /Skill currency check/);
});

test('bin/exceptd.js: build-indexes --quiet --only stale-content exits 0', () => {
  const r = run(['build-indexes', '--quiet', '--only', 'stale-content']);
  assert.equal(r.status, 0, `stderr: ${r.stderr}`);
});

test('bin/exceptd.js: package.json bin.exceptd points at this file', () => {
  const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'));
  assert.ok(pkg.bin && pkg.bin.exceptd, 'package.json must declare bin.exceptd');
  const expected = path.normalize(BIN);
  const actual = path.normalize(path.join(ROOT, pkg.bin.exceptd));
  assert.equal(actual, expected);
});

test('package.json: publish-readiness invariants', () => {
  const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'));
  assert.notEqual(pkg.private, true, '"private": true blocks npm publish');
  assert.equal(pkg.name, '@blamejs/exceptd-skills');
  assert.ok(Array.isArray(pkg.files) && pkg.files.length > 0, 'files[] whitelist required for clean publish');
  assert.ok(pkg.publishConfig, 'publishConfig required for scoped public publish');
  assert.equal(pkg.publishConfig.access, 'public');
  assert.equal(pkg.publishConfig.provenance, true, 'provenance must be true for OIDC attestation');
});
