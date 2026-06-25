'use strict';

/**
 * tests/collectors-mcp.test.js
 *
 * Subject coverage for lib/collectors/mcp.js:
 *  - the collector attests `any-ai-coding-assistant-installed` from a vendor
 *    config file OR an install directory, and omits the key (never submits
 *    false) when nothing is present, leaving the skip_phase gate to the
 *    host-side resolver rather than force-skipping the detect phase.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const mcp = require('../lib/collectors/mcp.js');

const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'exceptd-mcp-coll-'));
process.on('exit', () => { try { fs.rmSync(TMP, { recursive: true, force: true }); } catch { /* non-fatal */ } });
let _n = 0;
function mkfx() { const d = path.join(TMP, 'fx-' + _n++); fs.mkdirSync(d, { recursive: true }); return d; }

test('mcp collector attests any-ai-coding-assistant-installed from a config OR an install dir, and never submits false', () => {
  // (a) a vendor config FILE present -> true
  const cfg = mkfx();
  fs.mkdirSync(path.join(cfg, '.cursor'), { recursive: true });
  fs.writeFileSync(path.join(cfg, '.cursor', 'mcp.json'), '{}');
  assert.equal(mcp.collect({ env: { HOME: cfg, USERPROFILE: cfg } }).precondition_checks['any-ai-coding-assistant-installed'], true);
  // (b) an install DIRECTORY present but NO config file yet -> still true
  //     (the precondition treats the dir as satisfying the gate; submitting
  //     false here would wrongly skip the detect phase — codex P2).
  const dirOnly = mkfx();
  fs.mkdirSync(path.join(dirOnly, '.config', 'Code'), { recursive: true });
  assert.equal(mcp.collect({ env: { HOME: dirOnly, USERPROFILE: dirOnly } }).precondition_checks['any-ai-coding-assistant-installed'], true);
  // (c) nothing present -> the key is OMITTED (never false), leaving the
  //     skip_phase gate to the host-side resolver rather than force-skipping.
  const bare = mkfx();
  assert.equal('any-ai-coding-assistant-installed' in mcp.collect({ env: { HOME: bare, USERPROFILE: bare } }).precondition_checks, false);
});

test('mcp collector flags a single-token "pip install <pkg>==X.Y.Z" launch command as pinned-without-integrity, but not a bare "pip install <pkg>"', () => {
  // A single-token launch command carries the whole pip invocation in one
  // token (`sh -c "pip install some-mcp==1.2.3"`). The `==version` pin with
  // no integrity is the python analog of an unhashed npm `pkg@version`; it
  // must surface mcp-version-without-integrity = "hit". A previous dead
  // `pip install` continue-clause skipped the `==version` check for exactly
  // this shape.
  const pinned = mkfx();
  fs.mkdirSync(path.join(pinned, '.cursor'), { recursive: true });
  fs.writeFileSync(
    path.join(pinned, '.cursor', 'mcp.json'),
    JSON.stringify({ mcpServers: { foo: { command: 'sh', args: ['-c', 'pip install some-mcp==1.2.3'] } } }),
  );
  assert.equal(
    mcp.collect({ env: { HOME: pinned, USERPROFILE: pinned } }).signal_overrides['mcp-version-without-integrity'],
    'hit',
  );

  // Negative: a benign `pip install requests` (no ==version pin) cannot match
  // the pin regex, so the signal must stay "miss" — not flag every pip call.
  const benign = mkfx();
  fs.mkdirSync(path.join(benign, '.cursor'), { recursive: true });
  fs.writeFileSync(
    path.join(benign, '.cursor', 'mcp.json'),
    JSON.stringify({ mcpServers: { foo: { command: 'sh', args: ['-c', 'pip install requests'] } } }),
  );
  assert.equal(
    mcp.collect({ env: { HOME: benign, USERPROFILE: benign } }).signal_overrides['mcp-version-without-integrity'],
    'miss',
  );
});
