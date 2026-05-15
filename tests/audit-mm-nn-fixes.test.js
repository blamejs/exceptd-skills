'use strict';

/**
 * audit MM / NN — CSAF id-routing + CVSS version gating + UTF-16BE
 * uninitialised-memory disclosure on odd-length payloads.
 *
 *   MM P1-A  RUSTSEC- ids route to system_name: 'RUSTSEC' (not 'OSV')
 *   MM P1-B  null / non-string cve_id is skipped + surfaces runtime_error
 *            `bundle_cve_id_missing` (pre-fix emitted literal text "null")
 *   MM P1-C  catalog vectors with CVSS:2.0 / CVSS:4.0 prefix do NOT emit a
 *            cvss_v3 score block (CSAF 2.0 schema enum is ['3.0','3.1']);
 *            runtime_error `bundle_cvss_v3_version_unsupported` surfaces
 *   MM P3-B  unknown-prefix ids fall back to system_name 'exceptd-unknown'
 *   NN P1-3  UTF-16BE readJsonFile:
 *            - odd-length payload after BOM throws a clean message
 *            - even-length payload decodes correctly
 *            - Buffer.alloc (zero-init) replaces Buffer.allocUnsafe so an
 *              unexpected loop bound never lets uninitialised heap bytes
 *              leak through the swapped buffer.
 *
 * Run under: node --test --test-concurrency=1 tests/
 */

const test = require('node:test');
const { describe, it } = test;
const assert = require('node:assert/strict');
const path = require('node:path');
const fs = require('node:fs');
const os = require('node:os');

const RUNNER_PATH = path.resolve(__dirname, '..', 'lib', 'playbook-runner.js');
const REAL_PLAYBOOK_DIR = path.resolve(__dirname, '..', 'data', 'playbooks');

function loadRunner() {
  delete require.cache[RUNNER_PATH];
  process.env.EXCEPTD_PLAYBOOK_DIR = REAL_PLAYBOOK_DIR;
  return require(RUNNER_PATH);
}

// ---------------------------------------------------------------------------
// Test harness: build a CSAF bundle against a synthesized matched_cves entry.
// Mirrors closeWithSyntheticMatchedId() from audit-cc-csaf-fixes.test.js so
// the two suites exercise the same code path.
// ---------------------------------------------------------------------------

function buildCsafWithSyntheticEntry(entryOverrides, runOpts = {}) {
  const runner = loadRunner();
  const det = runner.detect('kernel', 'all-catalogued-kernel-cves', {
    signal_overrides: { 'kver-in-affected-range': 'hit' }
  });
  const an = runner.analyze('kernel', 'all-catalogued-kernel-cves', det, {
    patch_available: false, blast_radius_score: 3
  });
  // Replace matched_cves with the synthesized entry so we control id + vector.
  an.matched_cves = [{
    cve_id: 'CVE-2026-31431',
    rwep: 80,
    cvss_score: 9.3,
    cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    cisa_kev: false,
    active_exploitation: 'confirmed',
    ai_discovered: false,
    live_patch_available: false,
    patch_available: true,
    vex_status: null,
    correlated_via: ['synthetic'],
    ...entryOverrides,
  }];
  const v = runner.validate('kernel', 'all-catalogued-kernel-cves', an, {}, runOpts);
  const c = runner.close('kernel', 'all-catalogued-kernel-cves', an, v, {
    _bundle_formats: ['csaf-2.0'],
  }, { session_id: 'auditmmnntest', _runErrors: [], ...runOpts });
  return {
    csaf: c.evidence_package.bundles_by_format['csaf-2.0'],
    runOpts,
    analyze: an,
  };
}

// ---------- MM P1-A ----------

describe('audit MM P1-A — RUSTSEC- ids route to system_name: RUSTSEC', () => {
  it('RUSTSEC-2024-0001 emits via ids[] with system_name: RUSTSEC (not OSV)', () => {
    const runOpts = { _runErrors: [] };
    const { csaf } = buildCsafWithSyntheticEntry({ cve_id: 'RUSTSEC-2024-0001' }, runOpts);
    const rustsecVuln = csaf.vulnerabilities.find(v =>
      Array.isArray(v.ids) && v.ids.some(e => e.text === 'RUSTSEC-2024-0001')
    );
    assert.ok(rustsecVuln, 'RUSTSEC- id must appear under ids[]');
    assert.equal(rustsecVuln.cve, undefined,
      'RUSTSEC- id must NOT be placed under `cve` (CSAF §3.2.1.2 regex rejects it)');
    const entry = rustsecVuln.ids.find(e => e.text === 'RUSTSEC-2024-0001');
    assert.deepEqual(entry, { system_name: 'RUSTSEC', text: 'RUSTSEC-2024-0001' },
      'RUSTSEC- ids carry system_name: RUSTSEC verbatim');
  });
});

// ---------- MM P3-B ----------

describe('audit MM P3-B — unknown-prefix ids fall back to exceptd-unknown', () => {
  it('PYSEC-2026-99 (unrecognised prefix) emits system_name: exceptd-unknown', () => {
    const runOpts = { _runErrors: [] };
    const { csaf } = buildCsafWithSyntheticEntry({ cve_id: 'PYSEC-2026-99' }, runOpts);
    const vuln = csaf.vulnerabilities.find(v =>
      Array.isArray(v.ids) && v.ids.some(e => e.text === 'PYSEC-2026-99')
    );
    assert.ok(vuln, 'unknown-prefix id must still surface via ids[], not be silently dropped');
    const entry = vuln.ids.find(e => e.text === 'PYSEC-2026-99');
    assert.equal(entry.system_name, 'exceptd-unknown',
      'unknown-prefix ids carry system_name: exceptd-unknown so downstream ingesters know the authority was not recognised');
  });
});

// ---------- MM P1-B ----------

describe('audit MM P1-B — null / non-string cve_id is omitted with runtime_error', () => {
  it('null cve_id: vuln entry omitted AND runtime_errors[] carries bundle_cve_id_missing', () => {
    const runOpts = { _runErrors: [] };
    const { csaf } = buildCsafWithSyntheticEntry({ cve_id: null }, runOpts);
    // Pre-fix the vuln entry was present with ids[0].text === 'null' literal.
    const literalNullVuln = csaf.vulnerabilities.find(v =>
      Array.isArray(v.ids) && v.ids.some(e => e.text === 'null' || e.text === 'undefined')
    );
    assert.equal(literalNullVuln, undefined,
      'no vuln entry may carry literal "null" / "undefined" text under ids[]');
    // And the only matched_cves entry had cve_id: null, so cveVulns should
    // have been filtered down to zero entries. indicator hits may still
    // populate vulnerabilities[], but no CSAF-CVE-shape entry should exist.
    const cveShapedVuln = csaf.vulnerabilities.find(v => typeof v.cve === 'string');
    assert.equal(cveShapedVuln, undefined,
      'null cve_id must NOT produce a CSAF `cve` field entry');
    // runtime_error must surface.
    const missing = runOpts._runErrors.filter(e => e && e.kind === 'bundle_cve_id_missing');
    assert.equal(missing.length, 1,
      `bundle_cve_id_missing must surface exactly once; got ${missing.length}: ${JSON.stringify(runOpts._runErrors)}`);
    assert.equal(typeof missing[0].reason, 'string');
    assert.ok(missing[0].reason.length > 0,
      'bundle_cve_id_missing must carry a non-empty reason string');
  });

  it('undefined cve_id: same shape — entry omitted + runtime_error fires', () => {
    const runOpts = { _runErrors: [] };
    const { csaf } = buildCsafWithSyntheticEntry({ cve_id: undefined }, runOpts);
    const literalUndef = csaf.vulnerabilities.find(v =>
      Array.isArray(v.ids) && v.ids.some(e => e.text === 'undefined')
    );
    assert.equal(literalUndef, undefined);
    const missing = runOpts._runErrors.filter(e => e && e.kind === 'bundle_cve_id_missing');
    assert.equal(missing.length, 1);
  });
});

// ---------- MM P1-C ----------

describe('audit MM P1-C — cvss_v3 block dropped for 2.0 / 4.0 vectors', () => {
  it('CVSS:4.0 vector: scores[] omits cvss_v3 block + runtime_error surfaces', () => {
    const runOpts = { _runErrors: [] };
    const v40Vector = 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N';
    const { csaf } = buildCsafWithSyntheticEntry({
      cve_id: 'CVE-2026-31431',
      cvss_score: 9.3,
      cvss_vector: v40Vector,
    }, runOpts);
    const vuln = csaf.vulnerabilities.find(x => x.cve === 'CVE-2026-31431');
    assert.ok(vuln);
    // The block must be omitted entirely — pre-fix it emitted version: '4.0'
    // which BSI CSAF Validator rejects (enum: ['3.0','3.1']).
    const hasCvssV3 = Array.isArray(vuln.scores) && vuln.scores.some(s => s && s.cvss_v3);
    assert.equal(hasCvssV3, false,
      'CVSS:4.0 vector must not produce a cvss_v3 block (CSAF 2.0 enum allows only 3.0 / 3.1)');
    // runtime_error must surface so operators see the gap.
    const unsupported = runOpts._runErrors.filter(e => e && e.kind === 'bundle_cvss_v3_version_unsupported');
    assert.equal(unsupported.length, 1,
      `bundle_cvss_v3_version_unsupported must surface exactly once; got ${unsupported.length}`);
    assert.match(String(unsupported[0].reason || ''), /4\.0/,
      'runtime_error reason must name the unsupported version explicitly');
  });

  it('CVSS:2.0 vector: scores[] omits cvss_v3 block + runtime_error surfaces', () => {
    const runOpts = { _runErrors: [] };
    const v20Vector = 'CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P';
    const { csaf } = buildCsafWithSyntheticEntry({
      cve_id: 'CVE-2026-31431',
      cvss_score: 7.5,
      cvss_vector: v20Vector,
    }, runOpts);
    const vuln = csaf.vulnerabilities.find(x => x.cve === 'CVE-2026-31431');
    assert.ok(vuln);
    const hasCvssV3 = Array.isArray(vuln.scores) && vuln.scores.some(s => s && s.cvss_v3);
    assert.equal(hasCvssV3, false,
      'CVSS:2.0 vector must not produce a cvss_v3 block');
    const unsupported = runOpts._runErrors.filter(e => e && e.kind === 'bundle_cvss_v3_version_unsupported');
    assert.equal(unsupported.length, 1);
  });

  it('CVSS:3.1 vector: cvss_v3 block IS emitted (positive control)', () => {
    const runOpts = { _runErrors: [] };
    const { csaf } = buildCsafWithSyntheticEntry({
      cve_id: 'CVE-2026-31431',
      cvss_score: 9.3,
      cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    }, runOpts);
    const vuln = csaf.vulnerabilities.find(x => x.cve === 'CVE-2026-31431');
    assert.ok(vuln);
    assert.ok(Array.isArray(vuln.scores) && vuln.scores.length === 1,
      'CVSS:3.1 vector must produce exactly one score entry');
    const cvssV3 = vuln.scores[0].cvss_v3;
    assert.ok(cvssV3, 'cvss_v3 block must be present for 3.1 vector');
    assert.equal(cvssV3.version, '3.1');
    assert.equal(cvssV3.baseScore, 9.3);
    // No runtime_error should fire for the supported version.
    const unsupported = runOpts._runErrors.filter(e => e && e.kind === 'bundle_cvss_v3_version_unsupported');
    assert.deepEqual(unsupported, []);
  });

  it('CVSS:3.0 vector: cvss_v3 block IS emitted', () => {
    const runOpts = { _runErrors: [] };
    const { csaf } = buildCsafWithSyntheticEntry({
      cve_id: 'CVE-2026-31431',
      cvss_score: 7.5,
      cvss_vector: 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
    }, runOpts);
    const vuln = csaf.vulnerabilities.find(x => x.cve === 'CVE-2026-31431');
    assert.ok(vuln);
    assert.ok(Array.isArray(vuln.scores) && vuln.scores.length === 1);
    assert.equal(vuln.scores[0].cvss_v3.version, '3.0');
  });
});

// ---------- NN P1-3 ----------
//
// readJsonFile is not exported from bin/exceptd.js (its public surface is the
// CLI itself), so we exercise it through writing a minimal harness that
// requires the file in a child process. The simplest, isolated approach is
// to spawn `node -e ...` and feed it the test buffer, since direct require()
// of bin/exceptd.js executes the CLI entry point on load.

describe('audit NN P1-3 — UTF-16BE odd-length payload refused; even-length parses', () => {
  function writeUtf16BeRaw(filePath, byteArray) {
    fs.writeFileSync(filePath, Buffer.from(byteArray));
  }

  // Run a tiny Node script that loads bin/exceptd.js's readJsonFile
  // indirectly via `--evidence` and surfaces the error in stderr. This is
  // the exact path operators hit, so testing through it covers both the
  // alloc + length checks.
  const { ROOT, makeSuiteHome, makeCli, tryJson } = require('./_helpers/cli');
  const SUITE_HOME = makeSuiteHome('audit-mm-nn-utf16-');
  const cli = makeCli(SUITE_HOME);

  it('UTF-16BE odd-length payload (BOM + 1 byte) is refused with a clear message', () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'audit-nn-p13-odd-'));
    try {
      const evPath = path.join(tmp, 'odd-utf16be.json');
      // 0xFE 0xFF (BOM) + 5 single bytes => 7 total, 5-byte payload (odd).
      writeUtf16BeRaw(evPath, [0xFE, 0xFF, 0x00, 0x7B, 0x00, 0x7D, 0x41]);
      const r = cli(['run', 'library-author', '--evidence', evPath]);
      assert.equal(r.status, 1, 'odd-length UTF-16BE input must exit 1 (readJsonFile refusal → dispatcher catch → emitError)');
      const errBody = tryJson(r.stderr.trim()) || {};
      const msg = String(errBody.error || r.stderr);
      assert.match(msg, /UTF-16BE payload must have an even byte count/i,
        'refusal message must name the byte-count constraint explicitly');
      assert.match(msg, /file may be truncated/i,
        'refusal message must hint at the most likely root cause (truncation)');
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  it('UTF-16BE even-length payload decodes correctly via --evidence', () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'audit-nn-p13-even-'));
    try {
      const evPath = path.join(tmp, 'even-utf16be.json');
      // "{}" in UTF-16BE: 0x00 0x7B 0x00 0x7D — even (4 bytes after 2-byte BOM).
      // Plus an object that the runner accepts: { "observations": {}, "verdict": {} }
      const json = '{"observations":{},"verdict":{}}';
      // Encode as UTF-16LE then byte-swap to UTF-16BE.
      const le = Buffer.from(json, 'utf16le');
      const be = Buffer.alloc(le.length);
      for (let i = 0; i < le.length - 1; i += 2) {
        be[i] = le[i + 1];
        be[i + 1] = le[i];
      }
      fs.writeFileSync(evPath, Buffer.concat([Buffer.from([0xFE, 0xFF]), be]));
      const r = cli(['run', 'library-author', '--evidence', evPath]);
      // Don't pin status — the run may exit 0 (clean) or with another
      // legitimate non-zero code — but the read must not refuse on the
      // byte-count check.
      const errBody = tryJson(r.stderr.trim()) || {};
      const msg = String(errBody.error || r.stderr);
      assert.doesNotMatch(msg, /UTF-16BE payload must have an even byte count/i,
        'even-length UTF-16BE payload must NOT trip the odd-length guard');
      assert.doesNotMatch(msg, /Unexpected token|invalid JSON/i,
        'even-length UTF-16BE payload must decode + parse cleanly; got: ' + msg);
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  it('source no longer uses Buffer.allocUnsafe in the UTF-16BE branch', () => {
    // Belt-and-braces: lock in the alloc semantics at the source level so a
    // future refactor doesn't silently regress to allocUnsafe and reopen
    // the information-disclosure path.
    const src = fs.readFileSync(path.join(ROOT, 'bin', 'exceptd.js'), 'utf8');
    // Locate the readJsonFile function and confirm Buffer.allocUnsafe is
    // not invoked anywhere. A comment-mention is fine — we strip line
    // comments and JSDoc bodies before scanning. The pattern is the call
    // form `Buffer.allocUnsafe(` with no preceding `//` on the same line.
    const lines = src.split(/\r?\n/);
    const callLines = lines.filter(line => {
      const ix = line.indexOf('Buffer.allocUnsafe(');
      if (ix < 0) return false;
      // Strip leading whitespace + `//` / `*` / `* ` for comment context.
      const before = line.slice(0, ix).trimStart();
      if (before.startsWith('//')) return false;
      if (before.startsWith('*')) return false;
      return true;
    });
    assert.deepEqual(callLines, [],
      'Buffer.allocUnsafe must not be invoked in bin/exceptd.js — use Buffer.alloc for zero-init guarantee. Offending lines: ' + JSON.stringify(callLines));
  });
});
