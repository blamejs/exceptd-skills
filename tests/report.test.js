'use strict';

/**
 * Subject coverage for the `report` CLI verb (bin/exceptd.js cmdRecipes-
 * adjacent report dispatch + orchestrator report): the executive markdown
 * flavor header, --json output for non-csaf formats (technical / executive),
 * and the --help default-format documentation.
 *
 * Each contributing source file's tests are wrapped in a describe() block named
 * for that source so the per-source requires/consts/helpers stay isolated.
 */

const test = require('node:test');
const assert = require('node:assert/strict');

// ===========================================================================
test.describe('cli-coverage', () => {
  const path = require('node:path');
  const { spawnSync } = require('node:child_process');
  const { ROOT } = require('./_helpers/cli');

  test('report executive emits markdown with self-describing flavor header', () => {
    const r = spawnSync(process.execPath, [path.join(ROOT, 'orchestrator', 'index.js'), 'report', 'executive'], {
      encoding: 'utf8',
      env: { ...process.env, EXCEPTD_DEPRECATION_SHOWN: '1' },
      timeout: 30000,
    });
    assert.equal(r.status, 0, 'report executive must exit 0');
    assert.match(r.stdout, /# exceptd Executive Report/,
      'header must self-describe the report flavor as executive');
    assert.match(r.stdout, /flavor=executive/,
      'HTML comment provenance must carry flavor=executive');
    assert.match(r.stdout, /## Executive Summary/,
      'body must include the Executive Summary section');
    assert.match(r.stdout, /Total scan findings:/,
      'body must include a Total scan findings line (content, not just header)');
  });
});

// ===========================================================================
test.describe('cli-selector-flag-fixes', () => {
  const { makeSuiteHome, makeCli, tryJson } = require('./_helpers/cli');

  const SUITE_HOME = makeSuiteHome('exceptd-selector-fix-report-');
  const cli = makeCli(SUITE_HOME);

  test('report --json (no format) emits parseable JSON, not a format error', () => {
    const r = cli(['report', '--json']);
    assert.equal(r.status, 0);
    const body = tryJson(r.stdout);
    assert.ok(body && typeof body === 'object', 'stdout must parse as JSON');
    assert.equal(body.ok, true);
    assert.equal(body.verb, 'report');
    assert.equal(body.format, 'technical');
  });

  test('report executive --json emits JSON for a non-csaf format (not Markdown)', () => {
    const r = cli(['report', 'executive', '--json']);
    assert.equal(r.status, 0);
    const body = tryJson(r.stdout);
    assert.ok(body && typeof body === 'object', 'stdout must parse as JSON, not render Markdown');
    assert.equal(body.format, 'executive');
    assert.ok(body.summary && typeof body.summary === 'object');
  });
});

// ===========================================================================
test.describe('usability-fixes', () => {
  const { makeSuiteHome, makeCli } = require('./_helpers/cli');

  const home = makeSuiteHome('exceptd-usability-report-');
  const cli = makeCli(home);

  test('report --help states the default output format (Markdown), not just --json', () => {
    const r = cli(['report', '--help']);
    const out = (r.stdout || '') + (r.stderr || '');
    assert.match(out, /Markdown/i, 'report --help must state the Markdown default so operators do not pipe Markdown into a JSON tool');
  });
});
