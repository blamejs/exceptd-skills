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
