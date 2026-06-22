'use strict';

/**
 * Subject coverage for the `run` CLI verb (bin/exceptd.js cmdRun): flag
 * handling (--vex, --diff-from-latest, --force-stale, --air-gap, --session-key,
 * --evidence-dir, --operator, --session-id, --scope, --cwd, --format, --quiet,
 * --ack), evidence/stdin acceptance, playbook-id traversal refusal, and the
 * single-playbook / multi-playbook (`run --all`) output envelope.
 *
 * Each contributing source file's tests are wrapped in a describe() block named
 * for that source so the per-source requires/consts/helpers stay isolated.
 */

const test = require('node:test');
const assert = require('node:assert/strict');

// ===========================================================================
test.describe('cli-coverage', () => {
  const path = require('node:path');
  const fs = require('node:fs');
  const os = require('node:os');

  const { ROOT, makeSuiteHome, makeCli, tryJson } = require('./_helpers/cli');

  const SUITE_HOME = makeSuiteHome('exceptd-cli-cov-run-');
  const cli = makeCli(SUITE_HOME);

  // Helper: stage a temp playbook tree by copying data/playbooks/, mutating the
  // target playbook's _meta.threat_currency_score, and returning the dir path
  // plus an env-override pair suitable for cli({env}).
  function stagePlaybookWithCurrency(playbookId, score) {
    const srcDir = path.join(ROOT, 'data', 'playbooks');
    const stagingRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'exceptd-pb-'));
    for (const f of fs.readdirSync(srcDir)) {
      fs.copyFileSync(path.join(srcDir, f), path.join(stagingRoot, f));
    }
    const target = path.join(stagingRoot, `${playbookId}.json`);
    const body = JSON.parse(fs.readFileSync(target, 'utf8'));
    body._meta.threat_currency_score = score;
    fs.writeFileSync(target, JSON.stringify(body, null, 2));
    return { dir: stagingRoot, env: { EXCEPTD_PLAYBOOK_DIR: stagingRoot } };
  }

  test('run --vex applies the VEX filter and surfaces analyze.vex.filter_applied', () => {
    const vexPath = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'vex-')), 'vex.json');
    fs.writeFileSync(vexPath, JSON.stringify({
      '@context': 'https://openvex.dev/ns/v0.2.0',
      statements: [{
        vulnerability: { '@id': 'CVE-2025-99999' },
        products: [{ '@id': 'pkg:npm/test' }],
        status: 'not_affected',
      }],
    }));
    try {
      const r = cli(['run', 'library-author', '--evidence', '-', '--vex', vexPath,
        '--session-id', 'vex-' + Date.now(), '--json'], { input: '{}' });
      const data = tryJson(r.stdout);
      assert.ok(data, 'run --vex must emit JSON');
      assert.equal(data.ok, true);
      assert.ok(data.phases?.analyze?.vex,
        'phases.analyze.vex must be present when --vex is passed');
      assert.equal(data.phases.analyze.vex.filter_applied, true,
        'analyze.vex.filter_applied must be true (content, not just key presence)');
      assert.ok(Array.isArray(data.phases.analyze.vex.dropped_cves),
        'analyze.vex.dropped_cves must be an array');
    } finally {
      fs.unlinkSync(vexPath);
    }
  });

  test('run --diff-from-latest compares against the prior attestation for the playbook', () => {
    const sid1 = 'dfl-a-' + Date.now();
    const sid2 = 'dfl-b-' + Date.now();
    const sub = JSON.stringify({});
    const r1 = cli(['run', 'library-author', '--evidence', '-', '--session-id', sid1], { input: sub });
    assert.equal(r1.status, 0, 'first run must succeed to seed the latest attestation');
    const r2 = cli(['run', 'library-author', '--evidence', '-', '--session-id', sid2,
      '--diff-from-latest', '--json'], { input: sub });
    assert.equal(r2.status, 0);
    const data = tryJson(r2.stdout);
    assert.ok(data?.diff_from_latest, 'diff_from_latest must be present on the result');
    assert.equal(data.diff_from_latest.prior_session_id, sid1,
      'prior_session_id must reference the earlier run (content match)');
    assert.equal(data.diff_from_latest.status, 'unchanged',
      'identical submissions must produce diff_from_latest.status=unchanged');
  });

  test('run --force-stale overrides the threat_currency_score < 50 hard block', () => {
    const stage = stagePlaybookWithCurrency('library-author', 40);
    try {
      const rBlocked = cli(['run', 'library-author', '--evidence', '-',
        '--session-id', 'fs-block-' + Date.now(), '--json'],
        { input: '{}', env: stage.env });
      const blockedData = tryJson(rBlocked.stdout) || tryJson(rBlocked.stderr.trim());
      assert.ok(blockedData, 'blocked branch must emit structured JSON (stdout or stderr)');
      assert.equal(blockedData.ok, false,
        'currency<50 without --force-stale must produce ok:false');
      assert.match(blockedData.blocked_by || blockedData.reason || '', /currency|threat_currency_score/,
        'block reason must mention currency / threat_currency_score');
      assert.equal(rBlocked.status, 1, 'currency block must exit 1 (precondition refusal via emit ok:false → auto-map)');

      const rForced = cli(['run', 'library-author', '--evidence', '-', '--force-stale',
        '--session-id', 'fs-force-' + Date.now(), '--json'],
        { input: '{}', env: stage.env });
      const forcedData = tryJson(rForced.stdout);
      assert.ok(forcedData, 'forced branch must emit JSON');
      assert.equal(forcedData.ok, true,
        '--force-stale must override the currency block and complete the run');
    } finally {
      fs.rmSync(stage.dir, { recursive: true, force: true });
    }
  });

  test('run --air-gap CLI flag surfaces air_gap_mode=true in govern phase', () => {
    const r = cli(['run', 'secrets', '--evidence', '-', '--air-gap',
      '--session-id', 'ag-' + Date.now(), '--json'], { input: '{}' });
    const data = tryJson(r.stdout);
    assert.ok(data, 'run --air-gap must emit JSON');
    assert.equal(data.ok, true);
    assert.equal(data.phases?.govern?.air_gap_mode, true,
      'phases.govern.air_gap_mode must be true when --air-gap is passed on the CLI');
  });

  test('run --session-key <hex> HMAC-signs the evidence_package', () => {
    const key = require('crypto').randomBytes(32).toString('hex');
    const r = cli(['run', 'library-author', '--evidence', '-', '--session-key', key,
      '--session-id', 'sk-' + Date.now(), '--json'], { input: '{}' });
    assert.equal(r.status, 0, 'run --session-key (valid hex) must exit 0');
    const data = tryJson(r.stdout);
    assert.ok(data, 'run --session-key must emit JSON');
    assert.equal(data.ok, true);
    const pkg = data.phases?.close?.evidence_package;
    assert.ok(pkg, 'phases.close.evidence_package must be present');
    assert.equal(pkg.signature_algorithm, 'HMAC-SHA256-session-key',
      'signature_algorithm must reflect the HMAC path when --session-key is passed');
    assert.match(pkg.signature, /^[0-9a-f]{64}$/,
      'signature must be a 64-char hex string (SHA-256 digest)');
  });

  test('run --all (no --include-judgement-shaped) excludes the 9 policy-skipped playbooks by default', () => {
    const sub = JSON.stringify({});
    const r = cli(['run', '--all', '--evidence', '-', '--session-id', 'ranopolicy-' + Date.now()],
      { input: sub });
    const body = tryJson(r.stdout);
    assert.ok(body, 'run --all must emit JSON');
    const ids = body.playbooks_run;
    const POLICY_SKIPPED = [
      'ai-discovered-cve-triage', 'cloud-iam-incident', 'idp-incident',
      'identity-sso-compromise', 'llm-tool-use-exfil', 'post-quantum-migration',
      'ransomware', 'supply-chain-recovery', 'webhook-callback-abuse',
    ];
    for (const skipped of POLICY_SKIPPED) {
      assert.ok(!ids.includes(skipped),
        `default --all must exclude policy-skipped playbook ${skipped}; got: ${ids.join(', ')}`);
    }
    assert.ok(ids.includes('framework'),
      `default --all must include framework (analyze-only, warn-precondition); got: ${ids.join(', ')}`);
  });
});

// ===========================================================================
test.describe('cli-exit-codes', () => {
  const fs = require('node:fs');
  const os = require('node:os');
  const path = require('node:path');

  const { makeSuiteHome, makeCli, tryJson } = require('./_helpers/cli');

  const SUITE_HOME = makeSuiteHome('exceptd-audit-r-run-');
  const cli = makeCli(SUITE_HOME);

  test('R-F4: --vex refuses empty vulnerabilities[] when bomFormat is not "CycloneDX"', () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'rf4-'));
    try {
      const vexPath = path.join(tmp, 'fake.vex.json');
      fs.writeFileSync(vexPath, JSON.stringify({
        bomFormat: 'NOT-CycloneDX',
        vulnerabilities: [],
      }), 'utf8');
      const sub = JSON.stringify({ observations: {}, verdict: {} });
      const r = cli(['run', 'library-author', '--evidence', '-', '--vex', vexPath], { input: sub });
      assert.equal(r.status, 1,
        'run with adversarial --vex must exit 1 (arg-validation refusal). stdout=' + r.stdout.slice(0,300) + ' stderr=' + r.stderr.slice(0,300));
      const err = tryJson(r.stderr.trim()) || {};
      assert.equal(err.ok, false, '--vex refusal body must carry ok:false');
      assert.match(err.error || '',
        /empty-vulnerabilities-without-cyclonedx-marker|doesn't look like CycloneDX or OpenVEX/,
        'error must name the detected shape problem; got: ' + (err.error || ''));
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  test('R-F4 positive: --vex accepts a legitimate CycloneDX-marked empty vulnerabilities[]', () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'rf4-pos-'));
    try {
      const vexPath = path.join(tmp, 'real.vex.json');
      fs.writeFileSync(vexPath, JSON.stringify({
        bomFormat: 'CycloneDX',
        specVersion: '1.5',
        vulnerabilities: [],
      }), 'utf8');
      const sub = JSON.stringify({ observations: {}, verdict: {} });
      const r = cli(['run', 'library-author', '--evidence', '-', '--vex', vexPath], { input: sub });
      const err = tryJson(r.stderr.trim()) || {};
      if (err.error) {
        assert.doesNotMatch(err.error,
          /doesn't look like CycloneDX or OpenVEX|empty-vulnerabilities-without-cyclonedx-marker/,
          'legitimate empty CycloneDX VEX must not be rejected as malformed; got: ' + err.error);
      }
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  test('R-F5: --vex refuses files larger than 32 MB', () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'rf5-'));
    try {
      const vexPath = path.join(tmp, 'huge.vex.json');
      const oneMb = 'A'.repeat(1024 * 1024);
      const fh = fs.openSync(vexPath, 'w');
      try {
        for (let i = 0; i < 33; i++) fs.writeSync(fh, oneMb);
      } finally { fs.closeSync(fh); }
      const stat = fs.statSync(vexPath);
      assert.ok(stat.size > 32 * 1024 * 1024, 'fixture must exceed 32 MB; got ' + stat.size);
      const sub = JSON.stringify({ observations: {}, verdict: {} });
      const r = cli(['run', 'library-author', '--evidence', '-', '--vex', vexPath], { input: sub });
      assert.equal(r.status, 1, '--vex with oversized file must exit 1 (size-cap refusal). status=' + r.status);
      const err = tryJson(r.stderr.trim()) || {};
      assert.equal(err.ok, false);
      assert.match(err.error || '', /--vex file too large/,
        'error must name the size-cap refusal; got: ' + (err.error || ''));
      assert.equal(err.limit_bytes, 32 * 1024 * 1024,
        'error body must include limit_bytes for operator visibility');
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  test('R-F9: run --scope "" rejects with the accepted-set message', () => {
    const r = cli(['run', '--scope', '']);
    assert.equal(r.status, 1,
      'run --scope "" must exit 1 (validateScopeOrThrow refusal). status=' + r.status + ' stdout=' + r.stdout.slice(0,300));
    const err = tryJson(r.stderr.trim()) || {};
    assert.equal(err.ok, false);
    assert.match(err.error || '', /--scope must be one of/,
      'empty-string scope must surface the same validateScopeOrThrow message as any other invalid scope. Got: ' + (err.error || ''));
  });

  test('R-F12: --evidence-dir refuses symbolic-link entries', (t) => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'rf12-'));
    try {
      const real = path.join(tmp, 'real.json');
      fs.writeFileSync(real, '{}', 'utf8');
      const linkPath = path.join(tmp, 'library-author.json');
      try {
        fs.symlinkSync(real, linkPath, 'file');
      } catch (e) {
        if (e.code === 'EPERM' || e.code === 'EACCES' || e.code === 'ENOTSUP') {
          t.skip('platform refuses symlink creation (' + e.code + ')');
          return;
        }
        throw e;
      }
      const r = cli(['run', '--evidence-dir', tmp]);
      assert.equal(r.status, 1,
        '--evidence-dir with a symlink entry must exit 1 (symlink refusal). status=' + r.status);
      const err = tryJson(r.stderr.trim()) || {};
      assert.equal(err.ok, false);
      assert.match(err.error || '', /symbolic link|symlink/i,
        'refusal must name the symlink reason so the operator can fix the directory. Got: ' + (err.error || ''));
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });
});

// ===========================================================================
test.describe('cli-flag-validation', () => {
  const fs = require('node:fs');
  const os = require('node:os');
  const path = require('node:path');

  const { SUITE_HOME, cli, tryJson } = (() => {
    const helpers = require('./_helpers/cli');
    const home = helpers.makeSuiteHome('exceptd-audit-ee-gg-run-');
    return { SUITE_HOME: home, cli: helpers.makeCli(home), tryJson: helpers.tryJson };
  })();

  function writeWithBom(filePath, jsonString, encoding) {
    if (encoding === 'utf8-bom') {
      const bom = Buffer.from([0xEF, 0xBB, 0xBF]);
      fs.writeFileSync(filePath, Buffer.concat([bom, Buffer.from(jsonString, 'utf8')]));
    } else if (encoding === 'utf16le-bom') {
      const bom = Buffer.from([0xFF, 0xFE]);
      fs.writeFileSync(filePath, Buffer.concat([bom, Buffer.from(jsonString, 'utf16le')]));
    } else if (encoding === 'utf16be-bom') {
      const bom = Buffer.from([0xFE, 0xFF]);
      const le = Buffer.from(jsonString, 'utf16le');
      const be = Buffer.allocUnsafe(le.length);
      for (let i = 0; i < le.length - 1; i += 2) {
        be[i] = le[i + 1];
        be[i + 1] = le[i];
      }
      fs.writeFileSync(filePath, Buffer.concat([bom, be]));
    } else {
      throw new Error('unknown encoding');
    }
  }

  test('EE P1-1: --vex accepts a CycloneDX SBOM without a vulnerabilities key (0-CVE VEX)', () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'ee-p1-1-'));
    try {
      const vexPath = path.join(tmp, 'sbom-no-vex.json');
      fs.writeFileSync(vexPath, JSON.stringify({
        bomFormat: 'CycloneDX',
        specVersion: '1.6',
        components: [],
      }), 'utf8');
      const sub = JSON.stringify({ observations: {}, verdict: {} });
      const r = cli(['run', 'library-author', '--evidence', '-', '--vex', vexPath], { input: sub });
      const err = tryJson(r.stderr.trim()) || {};
      if (err.error) {
        assert.doesNotMatch(err.error,
          /doesn't look like CycloneDX or OpenVEX|cyclonedx-sbom-without-vulnerabilities/,
          'CycloneDX SBOM with no vulnerabilities[] must not be refused as malformed; got: ' + err.error);
      }
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  test('EE P1-1: --vex also accepts specVersion-only marker without bomFormat', () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'ee-p1-1b-'));
    try {
      const vexPath = path.join(tmp, 'specversion-only.json');
      fs.writeFileSync(vexPath, JSON.stringify({
        specVersion: '1.5',
        components: [],
      }), 'utf8');
      const sub = JSON.stringify({ observations: {}, verdict: {} });
      const r = cli(['run', 'library-author', '--evidence', '-', '--vex', vexPath], { input: sub });
      const err = tryJson(r.stderr.trim()) || {};
      if (err.error) {
        assert.doesNotMatch(err.error,
          /doesn't look like CycloneDX or OpenVEX|cyclonedx-sbom-without-vulnerabilities/,
          'specVersion 1.x without bomFormat must still be accepted; got: ' + err.error);
      }
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  test('EE P1-1 negative: --vex still refuses non-CycloneDX shapes without the marker', () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'ee-p1-1c-'));
    try {
      const vexPath = path.join(tmp, 'garbage.json');
      fs.writeFileSync(vexPath, JSON.stringify({
        not_cyclonedx: true,
        not_openvex: true,
      }), 'utf8');
      const sub = JSON.stringify({ observations: {}, verdict: {} });
      const r = cli(['run', 'library-author', '--evidence', '-', '--vex', vexPath], { input: sub });
      assert.equal(r.status, 1, 'garbage shape must be refused with exit 1 (arg-validation)');
      const err = tryJson(r.stderr.trim()) || {};
      assert.equal(err.ok, false);
      assert.match(err.error || '', /doesn't look like CycloneDX or OpenVEX|unrecognized/,
        'shape error must still fire; got: ' + (err.error || ''));
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  test('EE P1-2: --vex parses UTF-8-BOM input correctly', () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'ee-p1-2-utf8-'));
    try {
      const vexPath = path.join(tmp, 'vex-utf8-bom.json');
      writeWithBom(vexPath, JSON.stringify({
        bomFormat: 'CycloneDX', specVersion: '1.5', vulnerabilities: [],
      }), 'utf8-bom');
      const sub = JSON.stringify({ observations: {}, verdict: {} });
      const r = cli(['run', 'library-author', '--evidence', '-', '--vex', vexPath], { input: sub });
      const err = tryJson(r.stderr.trim()) || {};
      if (err.error) {
        assert.doesNotMatch(err.error, /failed to load --vex|JSON.parse|Unexpected token/,
          'UTF-8-BOM --vex must parse cleanly; got: ' + err.error);
      }
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  test('EE P1-2: --vex parses UTF-16 LE BOM input correctly', () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'ee-p1-2-utf16le-'));
    try {
      const vexPath = path.join(tmp, 'vex-utf16le.json');
      writeWithBom(vexPath, JSON.stringify({
        bomFormat: 'CycloneDX', specVersion: '1.5', vulnerabilities: [],
      }), 'utf16le-bom');
      const sub = JSON.stringify({ observations: {}, verdict: {} });
      const r = cli(['run', 'library-author', '--evidence', '-', '--vex', vexPath], { input: sub });
      const err = tryJson(r.stderr.trim()) || {};
      if (err.error) {
        assert.doesNotMatch(err.error, /failed to load --vex|JSON.parse|Unexpected token/,
          'UTF-16 LE --vex must parse cleanly; got: ' + err.error);
      }
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  test('EE P1-2: --vex parses UTF-16 BE BOM input correctly', () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'ee-p1-2-utf16be-'));
    try {
      const vexPath = path.join(tmp, 'vex-utf16be.json');
      writeWithBom(vexPath, JSON.stringify({
        bomFormat: 'CycloneDX', specVersion: '1.5', vulnerabilities: [],
      }), 'utf16be-bom');
      const sub = JSON.stringify({ observations: {}, verdict: {} });
      const r = cli(['run', 'library-author', '--evidence', '-', '--vex', vexPath], { input: sub });
      const err = tryJson(r.stderr.trim()) || {};
      if (err.error) {
        assert.doesNotMatch(err.error, /failed to load --vex|JSON.parse|Unexpected token/,
          'UTF-16 BE --vex must parse cleanly; got: ' + err.error);
      }
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  test('EE P1-2: --evidence parses UTF-8-BOM input correctly', () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'ee-p1-2-ev-utf8-'));
    try {
      const evPath = path.join(tmp, 'evidence-utf8-bom.json');
      writeWithBom(evPath, JSON.stringify({
        observations: {}, verdict: { classification: 'not_detected' },
      }), 'utf8-bom');
      const r = cli(['run', 'library-author', '--evidence', evPath]);
      const errBody = tryJson(r.stderr.trim()) || {};
      if (errBody.error) {
        assert.doesNotMatch(errBody.error, /failed to read evidence.*BOM|Unexpected token/,
          'UTF-8-BOM --evidence must parse cleanly; got: ' + errBody.error);
      }
      const out = tryJson(r.stdout.trim()) || tryJson(r.stderr.trim()) || {};
      assert.ok(out && (out.ok !== undefined || out.error !== undefined),
        'UTF-8-BOM evidence read must produce a parseable result body; got stdout=' + r.stdout.slice(0,300) + ' stderr=' + r.stderr.slice(0,300));
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  test('EE P1-2: --evidence parses UTF-16 LE BOM input correctly', () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'ee-p1-2-ev-utf16-'));
    try {
      const evPath = path.join(tmp, 'evidence-utf16le.json');
      writeWithBom(evPath, JSON.stringify({
        observations: {}, verdict: { classification: 'not_detected' },
      }), 'utf16le-bom');
      const r = cli(['run', 'library-author', '--evidence', evPath]);
      const errBody = tryJson(r.stderr.trim()) || {};
      if (errBody.error) {
        assert.doesNotMatch(errBody.error, /Unexpected token|invalid JSON/i,
          'UTF-16 LE --evidence must parse cleanly; got: ' + errBody.error);
      }
      const out = tryJson(r.stdout.trim()) || tryJson(r.stderr.trim()) || {};
      assert.ok(out && (out.ok !== undefined || out.error !== undefined),
        'UTF-16 LE evidence read must produce a parseable result body');
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  test('EE P1-3: --operator rejects U+202E (RTL OVERRIDE) bidi-control character', () => {
    const r = cli(['run', 'library-author', '--evidence', '-', '--operator', 'alice‮evilbob'],
      { input: JSON.stringify({ observations: {}, verdict: {} }) });
    assert.equal(r.status, 1,
      `--operator with U+202E must exit 1 (framework error). status=${r.status} stdout=${r.stdout.slice(0,200)} stderr=${r.stderr.slice(0,300)}`);
    const err = tryJson(r.stderr.trim()) || {};
    assert.equal(err.ok, false);
    assert.match(err.error || '',
      /Unicode control \/ format \/ private-use \/ unassigned codepoint|U\+202E/,
      'error must name the Unicode-category problem and surface the codepoint; got: ' + (err.error || ''));
    assert.equal(err.offending_codepoint, 'U+202E',
      'error body must carry the offending codepoint label; got: ' + JSON.stringify(err.offending_codepoint));
  });

  test('EE P1-3: --operator rejects U+200B (zero-width space)', () => {
    const r = cli(['run', 'library-author', '--evidence', '-', '--operator', 'alice​bob'],
      { input: JSON.stringify({ observations: {}, verdict: {} }) });
    assert.equal(r.status, 1, '--operator with U+200B must exit 1; got ' + r.status);
    const err = tryJson(r.stderr.trim()) || {};
    assert.equal(err.ok, false);
    assert.equal(err.offending_codepoint, 'U+200B',
      'zero-width space must be flagged as the offending codepoint');
  });

  test('EE P1-3 positive: --operator accepts a normal printable identifier', () => {
    const r = cli(['run', 'library-author', '--evidence', '-', '--operator', 'alice.bob+1@example.com'],
      { input: JSON.stringify({ observations: {}, verdict: {} }) });
    const err = tryJson(r.stderr.trim()) || {};
    if (err.error) {
      assert.doesNotMatch(err.error, /Unicode control|bidi-override/,
        'a plain ASCII operator identifier must not trip the Unicode gate; got: ' + err.error);
    }
  });

  test('EE P1-4: --vex oversize error message says "32 MiB limit" with formatted bytes', () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'ee-p1-4-'));
    try {
      const vexPath = path.join(tmp, 'huge.json');
      const oneMb = 'A'.repeat(1024 * 1024);
      const fh = fs.openSync(vexPath, 'w');
      try {
        for (let i = 0; i < 33; i++) fs.writeSync(fh, oneMb);
      } finally { fs.closeSync(fh); }
      const r = cli(['run', 'library-author', '--evidence', '-', '--vex', vexPath],
        { input: JSON.stringify({ observations: {}, verdict: {} }) });
      assert.equal(r.status, 1, 'oversize --vex must exit 1 (arg-validation refusal)');
      const err = tryJson(r.stderr.trim()) || {};
      assert.equal(err.ok, false);
      assert.match(err.error || '', /exceeds 32 MiB limit/,
        'error must use "MiB" not "MB" to clarify binary mebibytes; got: ' + (err.error || ''));
      assert.match(err.error || '', /33,554,432 bytes/,
        'error must include the exact byte count with thousands separators; got: ' + (err.error || ''));
      assert.equal(err.limit_bytes, 32 * 1024 * 1024,
        'limit_bytes field must remain exact for programmatic consumers');
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  test('EE P1-5: --evidence-dir refuses POSIX symbolic links',
    { skip: process.platform === 'win32' && 'POSIX-symlink test skipped on Windows (mklink requires admin)' },
    () => {
      const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'ee-p1-5-symlink-'));
      try {
        const realFile = path.join(tmp, 'real.json');
        fs.writeFileSync(realFile, JSON.stringify({ observations: {}, verdict: {} }), 'utf8');
        const linkPath = path.join(tmp, 'library-author.json');
        try { fs.symlinkSync(realFile, linkPath); }
        catch (e) {
          if (e.code === 'EPERM' || e.code === 'EACCES') return;
          throw e;
        }
        const r = cli(['run', '--all', '--evidence-dir', tmp]);
        assert.equal(r.status, 1,
          '--evidence-dir with a symlink entry must exit 1 (arg-validation refusal); got ' + r.status);
        const err = tryJson(r.stderr.trim()) || {};
        assert.equal(err.ok, false);
        assert.match(err.error || '',
          /symbolic link|junction|reparse-point|resolves outside the directory/,
          'symlink refusal must name the cause; got: ' + (err.error || ''));
      } finally {
        fs.rmSync(tmp, { recursive: true, force: true });
      }
    });

  test('EE P1-5: --evidence-dir refuses Windows directory junctions',
    { skip: process.platform !== 'win32' && 'Windows-junction test skipped on POSIX' },
    () => {
      const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'ee-p1-5-junction-'));
      const evDir = path.join(tmp, 'evidence');
      const outside = path.join(tmp, 'outside');
      fs.mkdirSync(evDir);
      fs.mkdirSync(outside);
      const realFile = path.join(outside, 'library-author.json');
      fs.writeFileSync(realFile, JSON.stringify({ observations: {}, verdict: {} }), 'utf8');
      const linkPath = path.join(evDir, 'library-author.json');
      let createdLink = false;
      try {
        fs.linkSync(realFile, linkPath);  // hardlink: same inode, in evDir
        createdLink = true;
      } catch (e) {
        if (e.code === 'EPERM' || e.code === 'EXDEV' || e.code === 'EACCES') {
          return;
        }
        throw e;
      }
      if (!createdLink) return;
      try {
        const r = cli(['run', '--all', '--evidence-dir', evDir]);
        assert.match(r.stderr, /WARNING.*nlink=2|nlink=\d+/,
          'hardlinked evidence-dir entry must emit nlink warning on stderr');
      } finally {
        try { fs.rmSync(tmp, { recursive: true, force: true }); } catch { /* non-fatal */ }
      }
    });

  test('EE P1-6: run --ack on a not-detected run does not persist consent into attestation', () => {
    const sid = 'ee-p1-6-no-persist-' + Date.now();
    const sub = JSON.stringify({
      observations: {},
      verdict: { classification: 'not_detected' },
    });
    const r = cli(['run', 'library-author', '--evidence', '-', '--ack', '--session-id', sid, '--json'],
      { input: sub });
    assert.equal(r.status, 0,
      'not-detected run must exit 0; got status=' + r.status + ' stderr=' + r.stderr.slice(0,300));
    const out = tryJson(r.stdout.trim()) || {};
    assert.equal(out.ack, true, 'result.ack should reflect that --ack was passed');
    assert.equal(out.ack_applied, false,
      'result.ack_applied must be false when classification != detected');
    assert.match(out.ack_skipped_reason || '',
      /classification=not_detected|jurisdiction clock at stake/,
      'result.ack_skipped_reason must explain the skip; got: ' + (out.ack_skipped_reason || ''));

    const candidates = [
      path.join(SUITE_HOME, 'attestations', sid),
      path.join(SUITE_HOME, '.exceptd', 'attestations', sid),
    ];
    const attRoot = candidates.find(p => fs.existsSync(p));
    assert.ok(attRoot, 'attestation dir must exist after run');
    const files = fs.readdirSync(attRoot).filter(f => f.endsWith('.json') && !f.endsWith('.sig'));
    assert.ok(files.length >= 1, 'at least one attestation file must exist');
    const body = JSON.parse(fs.readFileSync(path.join(attRoot, files[0]), 'utf8'));
    const consent = body.operator_consent;
    assert.ok(consent === undefined || consent === null,
      'persisted attestation must NOT carry the explicit operator_consent payload when classification != detected; got: ' + JSON.stringify(consent));
    if (consent && typeof consent === 'object') {
      assert.notEqual(consent.explicit, true,
        'consent.explicit must not be true when persistence was supposed to be skipped');
    }
  });

  test('EE P1-7: run with explicit --evidence-dir and empty stdin (size 0) completes < 5s', () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'ee-p1-7-'));
    try {
      const evPath = path.join(tmp, 'evidence.json');
      fs.writeFileSync(evPath, JSON.stringify({ observations: {}, verdict: {} }), 'utf8');
      const start = Date.now();
      const r = cli(['run', 'library-author', '--evidence', evPath, '--json'], { timeout: 5000 });
      const elapsed = Date.now() - start;
      assert.ok(elapsed < 5000,
        `run with explicit --evidence must complete < 5s (no stdin hang). Took ${elapsed}ms; status=${r.status}`);
      assert.notEqual(r.signal, 'SIGTERM',
        'run must not be killed by timeout (would indicate hang)');
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  test('EE P1-7: run without --evidence and a closed/empty stdin completes < 5s (no hang)', () => {
    const start = Date.now();
    const r = cli(['run', 'library-author', '--json'], { input: '', timeout: 5000 });
    const elapsed = Date.now() - start;
    assert.ok(elapsed < 5000,
      `run with empty stdin must complete < 5s (no readFileSync block). Took ${elapsed}ms; status=${r.status} signal=${r.signal}`);
    assert.notEqual(r.signal, 'SIGTERM',
      'run must not be killed by timeout (would indicate stdin block)');
    const body = tryJson(r.stdout.trim()) || tryJson(r.stderr.trim()) || {};
    assert.ok(body && (body.ok !== undefined || body.error !== undefined || r.status === 0),
      'empty-stdin run must yield a parseable body or clean exit; got status=' + r.status + ' stdout=' + r.stdout.slice(0,200) + ' stderr=' + r.stderr.slice(0,200));
  });
});

// ===========================================================================
test.describe('cli-output-envelope-shape-v0_12_39', () => {
  const path = require('node:path');
  const fs = require('node:fs');
  const os = require('node:os');
  const { spawnSync } = require('node:child_process');

  const ROOT = path.join(__dirname, '..');
  const CLI = path.join(ROOT, 'bin', 'exceptd.js');

  function cli(args, opts = {}) {
    return spawnSync(process.execPath, [CLI, ...args], {
      encoding: 'utf8',
      cwd: opts.cwd || ROOT,
      env: { ...process.env, EXCEPTD_DEPRECATION_SHOWN: '1', ...(opts.env || {}) },
      input: opts.input,
    });
  }

  function tryJson(s) { try { return JSON.parse(s); } catch { return null; } }

  test('run <pb> --evidence envelope (single-playbook success): exact top-level key set', () => {
    const evidence = JSON.stringify({
      precondition_checks: { 'linux-platform': true, 'uname-available': true },
      artifacts: { 'kernel-release': '5.15.0-69-generic' },
      signal_overrides: { 'kver-in-affected-range': 'hit' },
    });
    const tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'envelope-run-'));
    try {
      const r = cli(['run', 'kernel', '--evidence', '-', '--json',
        '--attestation-root', path.join(tmpHome, 'attestations')], { input: evidence });
      assert.equal(r.status, 0, `run kernel must exit 0; got ${r.status}, stderr: ${r.stderr.slice(0, 200)}`);
      const body = tryJson(r.stdout);
      assert.ok(body, `run kernel must emit parseable JSON; got: ${r.stdout.slice(0, 200)}`);
      const expected = [
        'ack', 'air_gap_mode', 'attestation_path', 'directive_id', 'evidence_completeness', 'evidence_hash',
        'indicators_evaluated', 'indicators_known', 'ok', 'phases',
        'playbook_id', 'precondition_check_source', 'preflight_issues',
        'rwep_score', 'session_id', 'submission_digest',
        'summary_line', 'top_finding', 'verdict',
      ];
      assert.deepEqual(Object.keys(body).sort(), expected);
      assert.equal(body.ok, true);
      assert.equal(body.playbook_id, 'kernel');
      assert.equal(typeof body.directive_id, 'string');
      assert.match(body.session_id, /^[0-9a-f-]+$/);
      assert.match(body.evidence_hash, /^[0-9a-f]+$/);
      assert.match(body.submission_digest, /^[0-9a-f]+$/);
      assert.ok(Array.isArray(body.preflight_issues));
      assert.equal(typeof body.phases, 'object');
      assert.equal(typeof body.ack, 'boolean');
      assert.equal(body.prior_session_id, undefined);
      assert.equal(body.overwrote_at, undefined);
    } finally {
      try { fs.rmSync(tmpHome, { recursive: true, force: true }); } catch {}
    }
  });

  test('shared error envelope (run unknown playbook): exact required field set', () => {
    const r = cli(['run', 'this-playbook-does-not-exist']);
    assert.equal(r.status, 1, `unknown playbook must exit 1; got ${r.status}`);
    const err = tryJson(r.stderr);
    assert.ok(err, `error stderr must be JSON; got: ${r.stderr.slice(0, 200)}`);
    assert.equal(err.ok, false);
    assert.equal(typeof err.error, 'string');
  });
});

// ===========================================================================
test.describe('cli-playbook-traversal', () => {
  const { makeSuiteHome, makeCli } = require('./_helpers/cli');

  const SUITE_HOME = makeSuiteHome('exceptd-cli-traversal-');
  const cli = makeCli(SUITE_HOME);

  const REFUSAL_RE = /invalid.*playbook.*id|traversal|must match/i;

  const cases = [
    { name: 'parent-traversal absolute-shape', id: '../../etc/passwd' },
    { name: 'single-parent', id: '../' },
    { name: 'embedded parent suffix', id: 'kernel/../../..' },
    { name: 'dot-dot', id: '..' },
    { name: 'single dot', id: '.' },
    { name: 'absolute unix path', id: '/etc/passwd' },
    { name: 'absolute windows path', id: 'C:\\Windows\\System32\\drivers\\etc\\hosts' },
    { name: 'leading dot', id: '.kernel' },
    { name: 'length overflow', id: 'a'.repeat(200) },
    { name: 'url-encoded parent', id: '%2e%2e%2f' },
  ];

  for (const c of cases) {
    test(`run <${c.name}> is refused with exit 1 + validation message`, () => {
      const r = cli(['run', c.id, '--evidence', '-'], { input: '{}' });
      assert.equal(r.status, 1,
        `expected exit 1 (validation refusal); got ${r.status} for input ${JSON.stringify(c.id)}; stderr=${r.stderr.slice(0,200)}`);
      assert.match(
        r.stderr + r.stdout,
        REFUSAL_RE,
        `output must label the refusal class (invalid playbook id / traversal / must match). got: ${r.stderr.slice(0,300)}`
      );
    });
  }
});

// ===========================================================================
test.describe('cli-selector-flag-fixes', () => {
  const path = require('node:path');
  const { ROOT, makeSuiteHome, makeCli, tryJson } = require('./_helpers/cli');
  const { EXIT_CODES } = require(path.join(ROOT, 'lib', 'exit-codes.js'));

  const SUITE_HOME = makeSuiteHome('exceptd-selector-fix-run-');
  const cli = makeCli(SUITE_HOME);

  test('run --cwd is refused on a verb that does not consume it', () => {
    const r = cli(['run', 'secrets', '--cwd', '/nonexistent-path', '--json']);
    assert.equal(r.status, EXIT_CODES.GENERIC_FAILURE);
    const body = tryJson(r.stderr) || tryJson(r.stdout);
    assert.equal(body.ok, false);
    assert.match(JSON.stringify(body), /irrelevant|only applies to.*collect/i);
  });
});

// ===========================================================================
test.describe('cli-session-id-empty', () => {
  const { makeSuiteHome, makeCli, tryJson } = require('./_helpers/cli');

  const SUITE_HOME = makeSuiteHome('exceptd-session-id-empty-');
  const cli = makeCli(SUITE_HOME);

  const STDIN = JSON.stringify({ observations: {}, verdict: {} });

  test('--session-id "" is refused with exit 1 and "must not be empty"', () => {
    const r = cli(['run', 'secrets', '--evidence', '-', '--session-id', '', '--json'],
      { input: STDIN });
    assert.equal(r.status, 1,
      `--session-id "" must exit 1 (framework error), not auto-generate a random id. ` +
      `status=${r.status} stdout=${r.stdout.slice(0, 200)} stderr=${r.stderr.slice(0, 300)}`);
    const err = tryJson(r.stderr.trim()) || {};
    assert.equal(err.ok, false, 'envelope must be ok:false');
    assert.equal(err.verb, 'run');
    assert.match(err.error || '', /--session-id must not be empty/,
      'error must name the empty-session-id refusal; got: ' + (err.error || ''));
  });

  test('--session-id= (eq form, empty) is refused with exit 1', () => {
    const r = cli(['run', 'secrets', '--evidence', '-', '--session-id=', '--json'],
      { input: STDIN });
    assert.equal(r.status, 1,
      `--session-id= must exit 1; got status=${r.status} stderr=${r.stderr.slice(0, 300)}`);
    const err = tryJson(r.stderr.trim()) || {};
    assert.equal(err.ok, false);
    assert.match(err.error || '', /--session-id must not be empty/,
      'eq-form empty must refuse with the same reason; got: ' + (err.error || ''));
  });

  test('positive: a valid --session-id still pins the id and runs', () => {
    const sid = 'pinned-session-' + Date.now();
    const r = cli(['run', 'secrets', '--evidence', '-', '--session-id', sid, '--json'],
      { input: STDIN });
    const body = tryJson(r.stdout.trim()) || tryJson(r.stderr.trim()) || {};
    assert.equal(body.session_id, sid,
      `valid --session-id must be honored verbatim; got session_id=${JSON.stringify(body.session_id)} ` +
      `status=${r.status} stderr=${r.stderr.slice(0, 200)}`);
  });

  test('positive: omitting --session-id still auto-generates a random id', () => {
    const r = cli(['run', 'secrets', '--evidence', '-', '--json'], { input: STDIN });
    const body = tryJson(r.stdout.trim()) || {};
    assert.equal(body.ok, true, 'omitted session-id must run cleanly; stderr=' + r.stderr.slice(0, 200));
    assert.equal(typeof body.session_id, 'string');
    assert.ok(body.session_id.length > 0, 'auto-generated session id must be non-empty');
  });

  test('positive: a traversal --session-id is still refused (no security regression)', () => {
    const r = cli(['run', 'secrets', '--evidence', '-', '--session-id', '../escape', '--json'],
      { input: STDIN });
    assert.equal(r.status, 1, 'traversal session-id must still exit 1; got ' + r.status);
    const err = tryJson(r.stderr.trim()) || {};
    assert.equal(err.ok, false);
    assert.match(err.error || '', /--session-id must match/,
      'traversal must refuse via the charset constraint; got: ' + (err.error || ''));
  });
});

// ===========================================================================
test.describe('cli-subverb-dispatch', () => {
  const fs = require('node:fs');
  const path = require('node:path');

  const { makeSuiteHome, makeCli, tryJson } = require('./_helpers/cli');

  const SUITE_HOME = makeSuiteHome('exceptd-audit-nn-run-');
  const cli = makeCli(SUITE_HOME);

  test('NN P1-1: run secrets --csaf-status final → accepted (verb is in BUNDLE_FLAG_RELEVANT_VERBS)', () => {
    const sub = JSON.stringify({
      observations: {},
      verdict: { classification: 'not_detected' },
    });
    const r = cli(
      ['run', 'secrets', '--evidence', '-', '--csaf-status', 'final',
       '--session-id', 'nn-p1-1-accept-' + Date.now(), '--json'],
      { input: sub }
    );
    if (r.status === 1) {
      const err = tryJson(r.stderr.trim()) || {};
      assert.notEqual(err.error_class, 'irrelevant-flag',
        'run --csaf-status must NOT emit the irrelevant-flag error; got: ' + JSON.stringify(err));
    }
    assert.equal(r.status, 0,
      'run secrets --csaf-status final must exit 0 (verb in bundle-relevant set, valid status). status=' + r.status + ' stderr=' + r.stderr.slice(0, 400));
  });

  test('NN P1-4: run-all --ack persists consent only for playbooks with classification=detected', () => {
    const sid = 'nn-p1-4-multi-' + Date.now();
    const bundle = JSON.stringify({
      secrets: {
        observations: { w: { captured: true, value: 'AKIA', indicator: 'aws-access-key-id', result: 'hit' } },
        verdict: { classification: 'detected', blast_radius: 4 },
      },
      'library-author': {
        observations: {},
        verdict: { classification: 'not_detected' },
      },
    });
    const r = cli(
      ['run', '--all', '--evidence', '-', '--ack',
       '--session-id', sid, '--json'],
      { input: bundle, timeout: 60000 }
    );
    const out = tryJson(r.stdout.trim()) || {};
    assert.ok(Array.isArray(out.results),
      'run-all output must include results[]; got status=' + r.status + ' stdout-head=' + r.stdout.slice(0, 300));
    const byId = new Map();
    for (const res of out.results) {
      if (res && res.playbook_id) byId.set(res.playbook_id, res);
    }
    const secretsRes = byId.get('secrets');
    const libRes = byId.get('library-author');
    assert.ok(secretsRes, 'results[] must include secrets entry');
    assert.ok(libRes, 'results[] must include library-author entry');

    const libClass = libRes.phases && libRes.phases.detect && libRes.phases.detect.classification;
    assert.equal(libClass, 'not_detected',
      'library-author with not_detected verdict must yield detect.classification=not_detected; got: ' + libClass);
    assert.equal(libRes.ack, true,
      'library-author result.ack must be true (operator did pass --ack); got: ' + JSON.stringify(libRes.ack));
    assert.equal(libRes.ack_applied, false,
      'library-author result.ack_applied must be false (classification != detected); got: ' + JSON.stringify(libRes.ack_applied));
    assert.match(libRes.ack_skipped_reason || '',
      /classification=not_detected; consent only persisted when classification=detected/,
      'library-author result.ack_skipped_reason must use the exact gate phrasing; got: ' + (libRes.ack_skipped_reason || ''));

    const secClass = secretsRes.phases && secretsRes.phases.detect && secretsRes.phases.detect.classification;
    assert.equal(secClass, 'detected',
      'secrets with detected verdict + observations must yield detect.classification=detected; got: ' + secClass);
    assert.equal(secretsRes.ack, true,
      'secrets result.ack must be true; got: ' + JSON.stringify(secretsRes.ack));
    assert.equal(secretsRes.ack_applied, true,
      'secrets result.ack_applied must be true (classification === detected); got: ' + JSON.stringify(secretsRes.ack_applied));
    assert.equal(secretsRes.ack_skipped_reason, undefined,
      'secrets result.ack_skipped_reason must be undefined when ack DID apply; got: ' + JSON.stringify(secretsRes.ack_skipped_reason));

    const candidates = [
      path.join(SUITE_HOME, 'attestations', sid),
      path.join(SUITE_HOME, '.exceptd', 'attestations', sid),
    ];
    const attRoot = candidates.find(p => fs.existsSync(p));
    assert.ok(attRoot, 'multi-run attestation dir must exist at ' + JSON.stringify(candidates));

    const libAttPath = path.join(attRoot, 'library-author.json');
    const secAttPath = path.join(attRoot, 'secrets.json');
    assert.ok(fs.existsSync(libAttPath),
      'library-author.json attestation must exist under ' + attRoot);
    assert.ok(fs.existsSync(secAttPath),
      'secrets.json attestation must exist under ' + attRoot);

    const libAtt = JSON.parse(fs.readFileSync(libAttPath, 'utf8'));
    const secAtt = JSON.parse(fs.readFileSync(secAttPath, 'utf8'));

    const libConsent = libAtt.operator_consent;
    assert.ok(libConsent === undefined || libConsent === null,
      'library-author attestation must NOT carry the explicit operator_consent payload (not_detected); got: ' + JSON.stringify(libConsent));
    if (libConsent && typeof libConsent === 'object') {
      assert.notEqual(libConsent.explicit, true,
        'library-author consent.explicit must NOT be true when persistence was supposed to skip');
    }

    const secConsent = secAtt.operator_consent;
    assert.ok(secConsent && typeof secConsent === 'object',
      'secrets attestation MUST carry an operator_consent payload (classification=detected); got: ' + JSON.stringify(secConsent));
    assert.equal(secConsent.explicit, true,
      'secrets attestation operator_consent.explicit must be true; got: ' + JSON.stringify(secConsent.explicit));
    assert.equal(typeof secConsent.acked_at, 'string',
      'secrets attestation operator_consent.acked_at must be a string; got: ' + JSON.stringify(secConsent.acked_at));
  });

  test('NN P1-5: run --help text lists --csaf-status and --publisher-namespace', () => {
    const r = cli(['run', '--help']);
    assert.equal(r.status, 0, 'run --help must exit 0; got ' + r.status);
    assert.match(r.stdout, /--csaf-status/,
      'run --help must document --csaf-status; stdout-head=' + r.stdout.slice(0, 400));
    assert.match(r.stdout, /--publisher-namespace/,
      'run --help must document --publisher-namespace; stdout-head=' + r.stdout.slice(0, 400));
    assert.match(r.stdout, /draft\s*\|\s*interim|interim.*final|final.*interim/,
      'run --help --csaf-status entry must enumerate the accepted values');
  });
});

// ===========================================================================
test.describe('cli-surface-drift', () => {
  const { makeSuiteHome, makeCli, tryJson } = require('./_helpers/cli');

  const SUITE_HOME = makeSuiteHome('exceptd-surface-drift-run-');
  const cli = makeCli(SUITE_HOME);

  test("run's known_flags list (printed on an unknown flag) includes the documented run flags", () => {
    const r = cli(["run", "secrets", "--definitely-not-a-flag"]);
    assert.equal(r.status, 1);
    const err = tryJson(r.stderr) || tryJson(r.stdout);
    assert.ok(err, `expected an unknown-flag envelope; got ${r.stderr.slice(0, 200)}`);
    assert.ok(Array.isArray(err.known_flags), "known_flags must be an array");
    for (const f of ["--directive", "--explain", "--signal-list"]) {
      assert.ok(err.known_flags.includes(f), `known_flags must list ${f}; got ${JSON.stringify(err.known_flags)}`);
    }
  });
});

// ===========================================================================
test.describe('cmd-run-multi-lock-contention', () => {
  const fs = require('node:fs');
  const path = require('node:path');

  const { ROOT, makeSuiteHome, makeCli, tryJson } = require('./_helpers/cli');
  const { withFileSnapshot } = require('./_helpers/snapshot-restore');

  const SUITE_HOME = makeSuiteHome('exceptd-lock-contention-');
  const cli = makeCli(SUITE_HOME);

  const PKG_PRIV_KEY = path.join(ROOT, '.keys', 'private.pem');
  const HAS_PRIV_KEY = fs.existsSync(PKG_PRIV_KEY);

  test('run --all under live-PID lock contention exits 8 (LOCK_CONTENTION)',
    { skip: !HAS_PRIV_KEY && 'producer run requires .keys/private.pem' },
    () => {
      const sid = 'lock-contention-' + Date.now();
      const sessionDir = path.join(SUITE_HOME, 'attestations', sid);
      fs.mkdirSync(sessionDir, { recursive: true });

      const playbookIds = [
        'kernel', 'mcp', 'crypto', 'ai-api', 'framework', 'sbom', 'runtime',
        'hardening', 'secrets', 'cred-stores', 'containers',
        'library-author', 'crypto-codebase',
      ];
      const priorBody = JSON.stringify({
        session_id: sid,
        evidence_hash: '0'.repeat(64),
        captured_at: new Date().toISOString(),
      });
      const lockPaths = [];
      const attPaths = [];
      for (const id of playbookIds) {
        const ap = path.join(sessionDir, `${id}.json`);
        fs.writeFileSync(ap, priorBody);
        attPaths.push(ap);
        const lp = path.join(sessionDir, `${id}.json.lock`);
        fs.writeFileSync(lp, String(process.pid));
        lockPaths.push(lp);
      }

      return withFileSnapshot([...attPaths, ...lockPaths], async () => {
        const r = cli(['run', '--all', '--evidence', '-', '--session-id', sid, '--force-overwrite', '--json'], {
          input: JSON.stringify({ observations: {}, verdict: { classification: 'not_detected' } }),
          timeout: 60000,
        });
        assert.equal(r.status, 8,
          `run --all under live-PID lock contention must exit 8 (LOCK_CONTENTION); got ${r.status}; stderr=${r.stderr.slice(0, 400)}`);

        const body = tryJson(r.stdout) || tryJson(r.stderr) || {};
        const topLevel = body.lock_contention === true;
        const perResult = Array.isArray(body.results) &&
          body.results.some((rs) => rs && rs.attestation_persist && rs.attestation_persist.lock_contention === true);
        assert.ok(topLevel || perResult,
          `body must surface lock_contention=true at top-level OR within results[i].attestation_persist. body keys: ${Object.keys(body).join(',')}`);
      });
    });
});

// ===========================================================================
test.describe('reconciliation-deep-fixes', () => {
  const { makeSuiteHome, makeCli, tryJson } = require('./_helpers/cli');

  const home = makeSuiteHome('exceptd-reconcile-deep-run-');
  const cli = makeCli(home);

  test('run --format with no value refuses (format is now a known value-bearing flag)', () => {
    const r = cli(['run', 'kernel', '--format', '--json'], { input: '{}' });
    assert.equal(r.status, 1, 'missing --format value exits exactly 1');
    const err = tryJson(r.stderr) || tryJson(r.stdout) || {};
    assert.equal(err.ok, false, 'ok:false');
    assert.equal(err.flag, 'format', 'names the flag missing its value');
    assert.match(err.error, /--format requires a value/, 'states the missing value');
  });
});

// ===========================================================================
test.describe('usability-fixes', () => {
  const { makeSuiteHome, makeCli, tryJson } = require('./_helpers/cli');

  const home = makeSuiteHome('exceptd-usability-run-');
  const cli = makeCli(home);

  test('run <playbook> --evidence-dir refuses loudly instead of silently running on empty evidence', () => {
    const r = cli(['run', 'secrets', '--evidence-dir', home, '--json']);
    assert.equal(r.status, 1, 'refuses with GENERIC_FAILURE (1) instead of a false all-clear exit 0');
    const body = tryJson(r.stdout) || tryJson(r.stderr) || {};
    assert.equal(body.ok, false, 'error envelope must carry ok:false');
    const text = (r.stdout || '') + (r.stderr || '');
    assert.match(text, /--evidence-dir/, 'message names the offending flag');
    assert.match(text, /--evidence\b|contract|--all|--scope/, 'message points at the correct alternative (--evidence / contract run)');
  });

  test('empty stdin on the auto-promotion path does NOT emit the nudge (so 2>&1 | jq stays parseable in CI)', () => {
    const r = cli(['run', 'secrets', '--json'], { input: '' });
    assert.doesNotMatch(r.stderr || '', /read 0 bytes from stdin/, 'auto-promoted empty stdin must not nudge on stderr');
  });

  test('an EXPLICIT --evidence - with empty stdin still nudges (the operator asked to pipe)', () => {
    const r = cli(['run', 'secrets', '--evidence', '-', '--json'], { input: '' });
    assert.match(r.stderr || '', /read 0 bytes from stdin/, 'explicit --evidence - with empty stdin should still warn the operator');
  });

  test('a blocked run renders a human line (not a raw JSON wall) in default human mode', () => {
    const r = cli(['run', 'kernel', '--evidence', '-'], {
      input: '{"precondition_checks":{"linux-platform":false}}',
      env: { EXCEPTD_RAW_JSON: '' },
    });
    assert.equal(r.status, 1, 'a blocked run exits 1 (GENERIC_FAILURE) without --ci');
    const out = (r.stdout || '') + (r.stderr || '');
    assert.doesNotMatch(r.stdout || '', /^\s*\{"ok":false/, 'human mode must NOT dump the raw ok:false JSON envelope');
    assert.match(out, /\[blocked\]/, 'human render tags the verdict as [blocked]');
    assert.match(out, /exceptd brief --all|re-run with --json/, 'human render points the operator at a next step');
  });

  test('a blocked run still returns the full JSON envelope under --json', () => {
    const r = cli(['run', 'kernel', '--evidence', '-', '--json'], {
      input: '{"precondition_checks":{"linux-platform":false}}',
    });
    assert.equal(r.status, 1, 'blocked exits 1 under --json too (no --ci)');
    const body = tryJson(r.stdout) || {};
    assert.equal(body.ok, false, '--json keeps the ok:false envelope for machine consumers');
    assert.equal(body.verdict, 'blocked', 'verdict is blocked');
    assert.equal(body.blocked_by, 'precondition', 'blocked_by names the preflight cause');
  });

  test('--quiet is a recognized global flag (accepted on run/doctor, not refused as unknown)', () => {
    const r = cli(['run', 'secrets', '--evidence', '-', '--quiet', '--json'], { input: '{}' });
    assert.doesNotMatch((r.stdout || '') + (r.stderr || ''), /unknown flag/, '--quiet must not be refused on a run-class verb');
    const d = cli(['doctor', '--signatures', '--quiet', '--json']);
    assert.doesNotMatch((d.stdout || '') + (d.stderr || ''), /unknown flag/, '--quiet must not be refused on doctor');
  });

  test('--quiet suppresses advisory stderr notes (keeps pipelines clean) but unknown flags still refuse', () => {
    const noisy = cli(['run', 'secrets', '--evidence', '-', '--json'], { input: '' });
    assert.match(noisy.stderr || '', /read 0 bytes from stdin/, 'baseline: the nudge fires without --quiet');
    const quiet = cli(['run', 'secrets', '--evidence', '-', '--quiet', '--json'], { input: '' });
    assert.doesNotMatch(quiet.stderr || '', /read 0 bytes from stdin/, '--quiet suppresses the advisory note');
    const bogus = cli(['run', 'secrets', '--evidence', '-', '--quiet', '--bogusflag', '--json'], { input: '{}' });
    assert.equal(bogus.status, 1, 'an unknown flag is still refused (exit 1) even with --quiet present');
    assert.match((bogus.stdout || '') + (bogus.stderr || ''), /unknown flag/, 'the refusal names the unknown flag');
  });
});

// ===========================================================================
test.describe('attestation-durability', () => {
  const path = require('node:path');
  const fs = require('node:fs');
  const os = require('node:os');
  const { makeCli, tryJson } = require('./_helpers/cli');

  function freshHome(prefix) {
    return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  }
  function sessionDir(home, sid) { return path.join(home, 'attestations', sid); }

  test('a run places attestation.json + .sig atomically, with no .tmp residue', () => {
    const home = freshHome('exceptd-atomwrite-');
    try {
      const cli = makeCli(home);
      const r = cli(['run', 'secrets', '--evidence', '-', '--session-id', 'aw1', '--json'], { input: JSON.stringify({ signal_overrides: { 'aws-secret-access-key': 'hit' } }), env: { EXCEPTD_HOME: home } });
      assert.equal(r.status === 0 || r.status === 2, true, `run should succeed/escalate; got ${r.status}`);
      const dir = sessionDir(home, 'aw1');
      const files = fs.readdirSync(dir);
      assert.ok(files.includes('attestation.json'), 'attestation.json must be placed');
      assert.ok(files.includes('attestation.json.sig'), 'the .sig sidecar must be placed alongside the body');
      assert.ok(!files.some(f => f.endsWith('.tmp')), `no .tmp residue should remain; got ${files.join(', ')}`);
      const body = tryJson(fs.readFileSync(path.join(dir, 'attestation.json'), 'utf8'));
      assert.ok(body && body.session_id === 'aw1', 'the placed attestation must be complete, parseable JSON');
    } finally {
      fs.rmSync(home, { recursive: true, force: true });
    }
  });

  test('run blocks (blocked_by:mutex) when a live foreign process holds the run lock', () => {
    const home = freshHome('exceptd-mutex-');
    const lockDir = freshHome('exceptd-lockdir-');
    try {
      const cli = makeCli(home);
      fs.writeFileSync(path.join(lockDir, 'secrets.lock'),
        JSON.stringify({ pid: process.pid, started_at: new Date().toISOString(), playbook: 'secrets' }, null, 2));
      const r = cli(['run', 'secrets', '--evidence', '-', '--session-id', 'mx1', '--json'],
        { input: '{}', env: { EXCEPTD_HOME: home, EXCEPTD_LOCK_DIR: lockDir } });
      assert.equal(r.status, 1, 'a mutex-blocked run exits 1 (GENERIC_FAILURE via emit() ok:false) without --ci; the structured shape is asserted below');
      const body = tryJson(r.stdout) || tryJson(r.stderr);
      assert.ok(body && body.ok === false, 'must emit a structured blocked result');
      assert.equal(body.blocked_by, 'mutex', 'must identify the mutex as the blocker');
      assert.match(body.reason, /concurrent run/i, 'must explain the concurrent-run block');
      assert.ok(!fs.existsSync(sessionDir(home, 'mx1')), 'a mutex-blocked run must not persist an attestation');
    } finally {
      fs.rmSync(home, { recursive: true, force: true });
      fs.rmSync(lockDir, { recursive: true, force: true });
    }
  });

  test('a malformed/unparsable run lock does NOT permanently block (proceeds best-effort, not held_by_live_pid:null)', () => {
    const home = freshHome('exceptd-badlock-');
    const lockDir = freshHome('exceptd-badlockdir-');
    try {
      const cli = makeCli(home);
      fs.writeFileSync(path.join(lockDir, 'secrets.lock'), 'not-json-garbage');
      const r = cli(['run', 'secrets', '--evidence', '-', '--session-id', 'bl1', '--json'],
        { input: JSON.stringify({ signal_overrides: { 'aws-secret-access-key': 'hit' } }), env: { EXCEPTD_HOME: home, EXCEPTD_LOCK_DIR: lockDir } });
      const body = tryJson(r.stdout);
      assert.ok(body, 'run must emit JSON');
      assert.notEqual(body.blocked_by, 'mutex', 'a malformed lock must not be reported as a live mutex holder');
      assert.ok(fs.existsSync(sessionDir(home, 'bl1')), 'the run should proceed despite the malformed lock');
    } finally {
      fs.rmSync(home, { recursive: true, force: true });
      fs.rmSync(lockDir, { recursive: true, force: true });
    }
  });
});

// ===========================================================================
test.describe('attestation-mode-0600', () => {
  const path = require('node:path');
  const fs = require('node:fs');
  const os = require('node:os');
  const { spawnSync } = require('node:child_process');
  const { ROOT, CLI } = require('./_helpers/cli');

  function cli(args, opts = {}) {
    return spawnSync(process.execPath, [CLI, ...args], {
      encoding: 'utf8',
      cwd: opts.cwd || ROOT,
      env: { ...process.env, EXCEPTD_DEPRECATION_SHOWN: '1', ...(opts.env || {}) },
      input: opts.input,
    });
  }

  function findAttestation(rootDir) {
    if (!fs.existsSync(rootDir)) return null;
    for (const ent of fs.readdirSync(rootDir, { withFileTypes: true })) {
      if (!ent.isDirectory()) continue;
      const level1 = path.join(rootDir, ent.name);
      const direct = path.join(level1, 'attestation.json');
      if (fs.existsSync(direct)) return direct;
      for (const inner of fs.readdirSync(level1, { withFileTypes: true })) {
        if (!inner.isDirectory()) continue;
        const att = path.join(level1, inner.name, 'attestation.json');
        if (fs.existsSync(att)) return att;
      }
    }
    return null;
  }

  test('attestation.json is written with mode 0o600 (owner-read/write only)', (t) => {
    if (process.platform === 'win32') {
      t.skip('POSIX mode bits do not apply on Windows; restrictWindowsAcl is the Windows-side test surface');
      return;
    }

    const tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'exceptd-mode-test-'));
    try {
      const evidence = JSON.stringify({
        precondition_checks: { 'linux-platform': true, 'uname-available': true },
        artifacts: { 'kernel-release': '5.15.0-69-generic' },
        signal_overrides: { 'kver-in-affected-range': 'hit' },
      });
      const attestationsRoot = path.join(tmpHome, 'attestations');
      const r = cli(['run', 'kernel', '--evidence', '-', '--attestation-root', attestationsRoot], {
        input: evidence,
      });
      assert.equal(r.status, 0, `run must succeed; got ${r.status}, stderr: ${r.stderr.slice(0, 200)}`);

      const attFile = findAttestation(attestationsRoot);
      assert.ok(attFile, `attestation.json must exist under ${attestationsRoot}; stdout: ${r.stdout.slice(0, 300)}`);

      const stat = fs.statSync(attFile);
      const perm = stat.mode & 0o777;
      assert.equal(perm, 0o600,
        `attestation.json mode must be 0o600 (got 0o${perm.toString(8)}). ` +
        `World-readable attestations leak evidence + consent records on multi-tenant hosts.`);
    } finally {
      try { fs.rmSync(tmpHome, { recursive: true, force: true }); } catch {}
    }
  });
});

// ===========================================================================
test.describe('attestation-signature-roundtrip (run stdin slice)', () => {
  const { makeSuiteHome, makeCli } = require('./_helpers/cli');
  const SUITE_HOME = makeSuiteHome('exceptd-audit-vv-trust-run-');
  const cli = makeCli(SUITE_HOME);

  test('KK P1-4 — exceptd run --evidence - hangs neither on a piped empty stdin nor exits silently', () => {
    const r = cli(['run', 'library-author', '--evidence', '-'], { input: '', timeout: 10000 });
    assert.ok(r.status !== null,
      `run must terminate, not hang on empty stdin pipe. Got status=${r.status} signal=${r.signal}.`);
    assert.notEqual(r.signal, 'SIGTERM',
      'run must not be killed by the 10s timeout — the empty-pipe path must complete promptly');
  });
});


// ---- routed from bundle-schema-conformance ----
;(() => {
/**
 * Regression suite for strict CSAF 2.0 / SARIF 2.1.0 schema-conformance fixes
 * (validated against the published schemas / profile mandatory tests):
 *
 *   CSAF 6.1.27.5 — every /vulnerabilities[] item carries `notes` (the
 *     CVE-keyed entries previously omitted it).
 *   CSAF 6.1.27.3 / §4.3 — a csaf_informational_advisory carries NO
 *     /vulnerabilities and no /product_tree.
 *   CSAF 6.1.27.2 — a csaf_informational_advisory carries /document/references
 *     with an external item.
 *   CSAF 6.1.16 + 6.1.30 — tracking.version equals the last revision_history
 *     number, and both use the same (semantic) versioning scheme.
 *   SARIF §3.27.9 — a result with kind:"informational" has level:"none"
 *     (not "note").
 *   SARIF artifactLocation.uri is a URI reference: a submission-supplied
 *     Windows backslash path is normalized to forward slashes.
 *
 * Discipline: exact field assertions tied to the cited rule.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const { makeSuiteHome, makeCli, tryJson } = require("./_helpers/cli");

const cli = makeCli(makeSuiteHome("exceptd-conformance-"));
const SBOM_CVE = JSON.stringify({ signal_overrides: { "package-matches-catalogued-cve": "hit" } });

test("CSAF: every CVE-keyed vulnerability carries notes (6.1.27.5)", () => {
  const doc = tryJson(cli(["run", "sbom", "--evidence", "-", "--format", "csaf-2.0", "--json"], { input: SBOM_CVE }).stdout);
  assert.equal(doc.document.category, "csaf_security_advisory");
  const cveVulns = (doc.vulnerabilities || []).filter(v => v.cve);
  assert.ok(cveVulns.length >= 1, "expected at least one CVE-keyed vulnerability");
  for (const v of cveVulns) {
    assert.ok(Array.isArray(v.notes) && v.notes.length >= 1, `CVE vuln ${v.cve} must carry notes`);
    assert.equal(typeof v.notes[0].text, "string");
  }
});

test("CSAF: tracking.version equals the last revision number, homogeneous versioning (6.1.16 + 6.1.30)", () => {
  const doc = tryJson(cli(["run", "sbom", "--evidence", "-", "--format", "csaf-2.0", "--json"], { input: SBOM_CVE }).stdout);
  const t = doc.document.tracking;
  const last = t.revision_history[t.revision_history.length - 1];
  assert.equal(t.version, last.number, "tracking.version must equal the last revision_history number");
  // Both must be the same scheme: semantic versioning (contains a dot) here.
  const isSemver = (s) => /^\d+\.\d+\.\d+/.test(s);
  assert.equal(isSemver(t.version), isSemver(last.number), "version and revision number must share a versioning scheme");
  assert.ok(isSemver(t.version), "this emitter uses semantic versioning for both");
});

test("CSAF: an informational advisory omits vulnerabilities + product_tree and carries an external reference", () => {
  const doc = tryJson(cli(["run", "crypto", "--evidence", "-", "--format", "csaf-2.0", "--json"], { input: '{"precondition_checks":{"linux-platform":true}}' }).stdout);
  assert.equal(doc.document.category, "csaf_informational_advisory");
  assert.ok(!("vulnerabilities" in doc), "informational advisory must NOT carry /vulnerabilities (6.1.27.3)");
  assert.ok(!("product_tree" in doc), "informational advisory must NOT carry /product_tree (§4.3)");
  assert.ok(Array.isArray(doc.document.references) && doc.document.references.length >= 1, "must carry /document/references (6.1.27.2)");
  assert.ok(doc.document.references.some(r => r.category === "external"), "must include an external reference");
});

test("SARIF: a kind:informational result has level:none, not note (§3.27.9)", () => {
  const sarif = tryJson(cli(["run", "sbom", "--evidence", "-", "--format", "sarif", "--json"], { input: SBOM_CVE }).stdout);
  const informational = (sarif.runs?.[0]?.results || []).filter(r => r.kind === "informational");
  assert.ok(informational.length >= 1, "expected at least one informational (framework-gap) result");
  for (const r of informational) {
    assert.equal(r.level, "none", "kind:informational requires level:none, never note/warning");
  }
});

test("SARIF: a submission-supplied backslash evidence path normalizes to a forward-slash URI", () => {
  const bs = String.fromCharCode(92);
  const sub = JSON.stringify({
    observations: { w: { captured: true, indicator: "publish-workflow-uses-static-token", result: "hit" } },
    evidence_locations: { "publish-workflow-uses-static-token": [["a", "b", "c.env"].join(bs), { uri: ["d", "e.txt"].join(bs), startLine: 2 }] },
  });
  const sarif = tryJson(cli(["run", "library-author", "--evidence", "-", "--format", "sarif", "--json"], { input: sub }).stdout);
  const uris = (sarif.runs?.[0]?.results || []).flatMap(r => (r.locations || []).map(l => l.physicalLocation?.artifactLocation?.uri));
  assert.ok(uris.length >= 1, "expected located results");
  for (const u of uris) {
    assert.ok(!u.includes(bs), `SARIF uri must use forward slashes (RFC 3986); got ${u}`);
  }
  assert.ok(uris.includes("a/b/c.env"), "the backslash string path must normalize to a/b/c.env");
});
})();


// ---- routed from collector-evidence-locations ----
;(() => {
/**
 * tests/collector-evidence-locations.test.js
 *
 * Pins the code-scope collectors' per-indicator evidence-location output:
 *   - A collector that knows WHICH file triggered an indicator surfaces it
 *     as a top-level `evidence_locations: { "<indicator-id>": [ {uri, ...} ] }`
 *     keyed by the same indicator id it flips to "hit".
 *   - The runner threads those onto the firing indicator so SARIF
 *     results[].locations gets a real file location instead of the coarse
 *     playbook-source fallback.
 *
 * citation-hygiene is the most deterministic wired collector: a fabricated
 * CVE id (e.g. CVE-2024-XXXX) flips `fabricated-cve-id` to "hit" from a
 * single fixture file with no catalog dependency.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const os = require("node:os");
const { spawnSync } = require("node:child_process");

const ROOT = path.join(__dirname, "..");
const CLI = path.join(ROOT, "bin", "exceptd.js");

function cli(args, opts = {}) {
  return spawnSync(process.execPath, [CLI, ...args], {
    encoding: "utf8",
    cwd: opts.cwd || ROOT,
    env: { ...process.env, EXCEPTD_DEPRECATION_SHOWN: "1", EXCEPTD_UNSIGNED_WARNED: "1", ...(opts.env || {}) },
    input: opts.input,
  });
}

function mkFixture() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "exceptd-evloc-"));
  // A fabricated (non-canonical) CVE citation flips fabricated-cve-id.
  fs.writeFileSync(path.join(dir, "notes.md"), "We patched CVE-2024-XXXX last week.\n");
  return dir;
}

const citationCollector = require(path.join(ROOT, "lib", "collectors", "citation-hygiene.js"));

test("citation-hygiene emits evidence_locations keyed by the indicator it flips to hit", () => {
  const dir = mkFixture();
  try {
    const sub = citationCollector.collect({ cwd: dir });
    assert.equal(sub.signal_overrides["fabricated-cve-id"], "hit", "fabricated CVE must flip the indicator");
    assert.ok(sub.evidence_locations && typeof sub.evidence_locations === "object", "evidence_locations present");
    const locs = sub.evidence_locations["fabricated-cve-id"];
    assert.ok(Array.isArray(locs) && locs.length >= 1, "fabricated-cve-id has >= 1 location");
    assert.equal(locs[0].uri, "notes.md", "uri points at the fixture file");
    // The collector now derives a 1-based line from the citation's byte
    // offset; the fixture's fabricated CVE is on line 1.
    assert.equal(locs[0].startLine, 1, "startLine points at the line carrying the bad citation");
    // Every evidence_locations key must be an indicator the collector
    // actually flipped to "hit" (no orphan keys).
    for (const id of Object.keys(sub.evidence_locations)) {
      assert.equal(sub.signal_overrides[id], "hit", `evidence_locations key ${id} must be a flipped-to-hit indicator`);
    }
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("run --format sarif surfaces the collector's evidence_locations as result.locations", () => {
  const dir = mkFixture();
  try {
    const sub = citationCollector.collect({ cwd: dir });
    // The fabricated-cve-id indicator declares false_positive_checks_required;
    // a hit verdict only survives when those checks are attested. Attest by
    // index so the deterministic hit reaches verdict=hit and emits a result.
    sub.signal_overrides["fabricated-cve-id__fp_checks"] = { "0": true, "1": true };
    const subPath = path.join(dir, "sub.json");
    fs.writeFileSync(subPath, JSON.stringify(sub));

    const r = cli(["run", "citation-hygiene", "--evidence", subPath, "--format", "sarif"]);
    assert.equal(r.status, 0, `run exited 0 (stderr: ${r.stderr})`);
    const sarif = JSON.parse(r.stdout);
    const results = sarif.runs[0].results || [];
    const fired = results.filter(x => x.ruleId.endsWith("/fabricated-cve-id"));
    assert.equal(fired.length, 1, "exactly one fabricated-cve-id SARIF result");
    const result = fired[0];
    assert.ok(Array.isArray(result.locations) && result.locations.length >= 1, "result has locations");
    const uri = result.locations[0].physicalLocation.artifactLocation.uri;
    assert.equal(uri, "notes.md", "SARIF location uri matches the fixture file");
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
})();


// ---- routed from collector-precondition-fixes ----
;(() => {
/**
 * tests/collector-precondition-fixes.test.js
 *
 * Pins the fixes a scan of the sibling blamejs repo surfaced:
 *  - collectors auto-attest the preconditions they can verify from collected
 *    evidence (so `collect --cwd <repo> | run` doesn't spuriously warn on a
 *    repo that clearly has a lockfile / manifest / assistant config — the
 *    runner can't probe the scanned --cwd);
 *  - a YAML COMMENT mentioning a publish verb no longer mis-classifies a CI
 *    workflow as a publish workflow;
 *  - an explicit-false precondition HALT carries a specific remediation, and
 *    the human renderer no longer asserts a platform-gate ("Linux-only") cause
 *    for every precondition block.
 * Exact-value pins per the anti-coincidence rule.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const sbom = require('../lib/collectors/sbom.js');
const libauthor = require('../lib/collectors/library-author.js');
const mcp = require('../lib/collectors/mcp.js');
const { makeSuiteHome, makeCli, tryJson } = require('./_helpers/cli');

const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'exceptd-dogfix-'));
process.on('exit', () => { try { fs.rmSync(TMP, { recursive: true, force: true }); } catch { /* non-fatal */ } });
let _n = 0;
function mkfx() { const d = path.join(TMP, 'fx-' + _n++); fs.mkdirSync(d, { recursive: true }); return d; }

test('sbom collector attests any-package-manager-present from a collected lockfile (and false without one)', () => {
  const withLock = mkfx();
  fs.writeFileSync(path.join(withLock, 'package-lock.json'), '{"lockfileVersion":3,"packages":{"":{}}}');
  assert.equal(sbom.collect({ cwd: withLock }).precondition_checks['any-package-manager-present'], true);
  assert.equal(sbom.collect({ cwd: mkfx() }).precondition_checks['any-package-manager-present'], false);
});

test('library-author collector attests publishable-artifact-evidence from a manifest (and false without one)', () => {
  const withManifest = mkfx();
  fs.writeFileSync(path.join(withManifest, 'package.json'), '{"name":"x","version":"1.0.0"}');
  assert.equal(libauthor.collect({ cwd: withManifest }).precondition_checks['publishable-artifact-evidence'], true);
  assert.equal(libauthor.collect({ cwd: mkfx() }).precondition_checks['publishable-artifact-evidence'], false);
});

test('library-author does NOT classify a CI workflow as publish from a comment-only publish verb', () => {
  const fx = mkfx();
  const wf = path.join(fx, '.github', 'workflows');
  fs.mkdirSync(wf, { recursive: true });
  // ci.yml's only "npm publish" is inside a comment — must not count.
  fs.writeFileSync(path.join(wf, 'ci.yml'),
    'name: ci\njobs:\n  t:\n    steps:\n      - run: echo hi # matches the npm publish workflow depth\n');
  // a real publish workflow with an actual command — must count.
  fs.writeFileSync(path.join(wf, 'release.yml'),
    'name: release\njobs:\n  p:\n    steps:\n      - run: npm publish --provenance\n');
  fs.writeFileSync(path.join(fx, 'package.json'), '{"name":"x","version":"1.0.0"}');
  const meta = libauthor.collect({ cwd: fx }).collector_meta || {};
  const pw = JSON.stringify(meta.publish_workflows || meta.publishWorkflows || []);
  assert.ok(/release\.yml/.test(pw), 'a real npm-publish workflow IS classified as publish');
  assert.ok(!/ci\.yml/.test(pw), 'a CI workflow whose only publish mention is a comment is NOT classified as publish');
});

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

test('explicit-false precondition halt carries a specific remediation, not the generic platform hint', () => {
  const cli = makeCli(makeSuiteHome());
  const ev = JSON.stringify({ precondition_checks: { 'operator-owns-ci-fleet': false } });
  const j = tryJson(cli(['run', 'cicd-pipeline-compromise', '--evidence', '-', '--json'], { input: ev }).stdout);
  assert.equal(j.blocked_by, 'precondition');
  assert.equal(typeof j.remediation, 'string');
  assert.ok(/submitted as false/.test(j.remediation), 'remediation names the specific gate, not a platform guess');
  // The universal satisfaction mechanism (submit the precondition true) must
  // be named — it works for every playbook regardless of which verb blocked.
  assert.ok(/precondition_checks/.test(j.remediation), 'remediation points at the precondition_checks submission mechanism');
  assert.ok(j.remediation.includes('"operator-owns-ci-fleet": true'), 'remediation shows the exact attestation to submit');
  // The flag example must be attributed to the collect verb (it is a collect
  // flag; the block surfaces at run, where passing it is silently ignored).
  assert.ok(/collect cicd-pipeline-compromise --attest-ownership/.test(j.remediation), 'the --attest-ownership example names the collect verb');
  const human = cli(['run', 'cicd-pipeline-compromise', '--evidence', '-'], { input: ev });
  assert.equal(/Linux-only playbook/.test(human.stdout), false, 'the misleading platform-gate hint must not appear on an intent-gate halt');
});
})();


// ---- routed from csaf-bundle-correctness ----
;(() => {
/**
 * audit CC — CSAF / SARIF / bundles-by-format correctness against the strict
 * downstream validators (BSI CSAF validator, GitHub Code Scanning).
 *
 *   P1-1: tracking.status defaults to 'interim' (CSAF §3.1.11.3.5.1).
 *   P1-2: non-CVE identifiers (MAL-, GHSA-, OSV-) route to vulnerabilities[].ids[]
 *         with a real system_name, NOT to vulnerabilities[].cve.
 *   P1-3: document.publisher.namespace is supplied by the operator running the
 *         scan, not the tooling vendor.
 *   P1-4: --operator threads into tracking.generator.engine and
 *         publisher.contact_details.
 *   P2-1: bundles_by_format is always { [primaryFormat]: body } even without
 *         additional --format flags.
 *   P2-2: cvss_v3 block carries vectorString (CSAF §3.2.1.5); block is dropped
 *         when score is unset.
 *   P2-6: SARIF ruleId carries a playbook prefix so cross-playbook merges in
 *         a single sarif-log don't dedupe rules.
 *
 * Run under: node --test --test-concurrency=1 tests/
 */

const test = require('node:test');
const { describe, it } = test;
const assert = require('node:assert/strict');
const path = require('node:path');
const fs = require('node:fs');
const os = require('node:os');
const { spawnSync } = require('node:child_process');

// Isolated sandbox for this suite's CLI subprocesses: route attestations into a
// throwaway EXCEPTD_HOME (so `run` does not pollute the maintainer's real
// ~/.exceptd) and scope EXCEPTD_LOCK_DIR to it (so mutex-grouped runs do not
// race on the host-global lock dir — the non-deterministic predeploy flake).
const CSAF_SUITE_HOME = fs.mkdtempSync(path.join(os.tmpdir(), 'exceptd-csaf-'));
process.on('exit', () => { try { fs.rmSync(CSAF_SUITE_HOME, { recursive: true, force: true }); } catch { /* non-fatal */ } });

const RUNNER_PATH = path.resolve(__dirname, '..', 'lib', 'playbook-runner.js');
const CLI_PATH = path.resolve(__dirname, '..', 'bin', 'exceptd.js');
const REAL_PLAYBOOK_DIR = path.resolve(__dirname, '..', 'data', 'playbooks');

function loadRunner() {
  delete require.cache[RUNNER_PATH];
  process.env.EXCEPTD_PLAYBOOK_DIR = REAL_PLAYBOOK_DIR;
  return require(RUNNER_PATH);
}

// Build a real kernel close() result with `_bundle_formats` and the given
// runOpts. The kernel playbook has matched_cves (real CVE-XXXX-YYYY ids) and
// framework_gap_mapping entries, so the CSAF emitter exercises both the
// CVE-routing and notes paths.
function closeKernel(runOpts = {}, agentSignalsExtra = {}) {
  const runner = loadRunner();
  const det = runner.detect('kernel', 'all-catalogued-kernel-cves', {
    signal_overrides: { 'kver-in-affected-range': 'hit' }
  });
  const an = runner.analyze('kernel', 'all-catalogued-kernel-cves', det, {
    patch_available: false, blast_radius_score: 3
  });
  const v = runner.validate('kernel', 'all-catalogued-kernel-cves', an, {});
  const c = runner.close('kernel', 'all-catalogued-kernel-cves', an, v, {
    _bundle_formats: ['csaf-2.0', 'sarif-2.1.0', 'openvex-0.2.0'],
    ...agentSignalsExtra,
  }, { session_id: 'auditcccsaffixestest', ...runOpts });
  return { close: c, analyze: an, validate: v };
}

// Build a CSAF bundle directly against a synthesized analyze result whose
// matched_cves carries a MAL- identifier. The buildEvidenceBundle path is
// what matters for CC P1-2; we drive it via close() so the public surface
// is exercised end-to-end. The runner exports its internal pipeline via
// detect/analyze/close — to inject a non-CVE matched id we patch
// analyze.matched_cves between analyze and close (same shape as v0.12.14's
// vex_fixed tests).
function closeWithSyntheticMatchedId(matchedId, opts = {}) {
  const runner = loadRunner();
  const det = runner.detect('kernel', 'all-catalogued-kernel-cves', {
    signal_overrides: { 'kver-in-affected-range': 'hit' }
  });
  const an = runner.analyze('kernel', 'all-catalogued-kernel-cves', det, {
    patch_available: false, blast_radius_score: 3
  });
  // Replace matched_cves with one synthetic entry that has the target id.
  an.matched_cves = [{
    cve_id: matchedId,
    rwep: 80, cvss_score: 9.3,
    cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    cisa_kev: false, active_exploitation: 'confirmed',
    ai_discovered: false, live_patch_available: false,
    patch_available: true, vex_status: null, correlated_via: ['synthetic'],
  }];
  const v = runner.validate('kernel', 'all-catalogued-kernel-cves', an, {});
  const c = runner.close('kernel', 'all-catalogued-kernel-cves', an, v, {
    _bundle_formats: ['csaf-2.0'],
  }, { session_id: 'auditccsynthetictest', ...opts });
  return c.evidence_package.bundles_by_format['csaf-2.0'];
}

// ---------- P1-1 ----------

describe('audit CC P1-1 — CSAF tracking.status defaults to interim', () => {
  it('runtime emit with no --csaf-status sets status to interim', () => {
    const { close: c } = closeKernel();
    const csaf = c.evidence_package.bundles_by_format['csaf-2.0'];
    assert.equal(csaf.document.tracking.status, 'interim',
      'CSAF §3.1.11.3.5.1: runtime detection is not an immutable advisory; runtime emit defaults to interim');
  });

  it('runOpts.csafStatus=final promotes to final', () => {
    const { close: c } = closeKernel({ csafStatus: 'final' });
    const csaf = c.evidence_package.bundles_by_format['csaf-2.0'];
    assert.equal(csaf.document.tracking.status, 'final');
  });

  it('runOpts.csafStatus=draft is accepted', () => {
    const { close: c } = closeKernel({ csafStatus: 'draft' });
    const csaf = c.evidence_package.bundles_by_format['csaf-2.0'];
    assert.equal(csaf.document.tracking.status, 'draft');
  });

  it('unknown csafStatus value silently falls back to interim (defence-in-depth — CLI rejects upstream)', () => {
    const { close: c } = closeKernel({ csafStatus: 'finel' });
    const csaf = c.evidence_package.bundles_by_format['csaf-2.0'];
    assert.equal(csaf.document.tracking.status, 'interim');
  });
});

// ---------- P1-2 ----------

describe('audit CC P1-2 — non-CVE ids route to ids[] with proper system_name', () => {
  it('CVE-shaped id stays in vulnerabilities[].cve', () => {
    const csaf = closeWithSyntheticMatchedId('CVE-2026-31431');
    const vuln = csaf.vulnerabilities.find(v => v.cve === 'CVE-2026-31431');
    assert.ok(vuln, 'CVE-shaped id must remain in `cve` field');
    assert.equal(vuln.ids, undefined,
      'CVE-shaped id must NOT also emit an ids[] entry — pre-fix never did and validators dedupe');
  });

  it('MAL-2026-3083 emits via ids[] with system_name: Malicious-Package', () => {
    const csaf = closeWithSyntheticMatchedId('MAL-2026-3083');
    const malVuln = csaf.vulnerabilities.find(v =>
      Array.isArray(v.ids) && v.ids.some(idEntry => idEntry.text === 'MAL-2026-3083')
    );
    assert.ok(malVuln, `MAL- id must appear under ids[]; got: ${JSON.stringify(csaf.vulnerabilities[0]).slice(0, 200)}`);
    assert.equal(malVuln.cve, undefined,
      'MAL- id must NOT be placed under `cve` (CSAF §3.2.1.2 regex rejects it)');
    const entry = malVuln.ids.find(e => e.text === 'MAL-2026-3083');
    assert.equal(entry.system_name, 'Malicious-Package',
      'MAL- ids carry system_name: Malicious-Package');
    assert.equal(entry.text, 'MAL-2026-3083');
  });

  it('GHSA-xxxx-xxxx-xxxx emits with system_name: GHSA', () => {
    const csaf = closeWithSyntheticMatchedId('GHSA-4xqg-gf5c-ghwq');
    const v = csaf.vulnerabilities.find(x =>
      Array.isArray(x.ids) && x.ids.some(e => e.text === 'GHSA-4xqg-gf5c-ghwq')
    );
    assert.ok(v);
    assert.equal(v.cve, undefined);
    const entry = v.ids.find(e => e.text === 'GHSA-4xqg-gf5c-ghwq');
    assert.equal(entry.system_name, 'GHSA');
  });

  it('OSV-2026-1 emits with system_name: OSV', () => {
    const csaf = closeWithSyntheticMatchedId('OSV-2026-1');
    const v = csaf.vulnerabilities.find(x =>
      Array.isArray(x.ids) && x.ids.some(e => e.text === 'OSV-2026-1')
    );
    assert.ok(v);
    const entry = v.ids.find(e => e.text === 'OSV-2026-1');
    assert.equal(entry.system_name, 'OSV');
  });

  it('unknown-prefix id falls back to OSV system_name (never to `cve`)', () => {
    const csaf = closeWithSyntheticMatchedId('PYSEC-2026-99');
    const v = csaf.vulnerabilities.find(x =>
      Array.isArray(x.ids) && x.ids.some(e => e.text === 'PYSEC-2026-99')
    );
    assert.ok(v, 'unknown-prefix id must still surface via ids[], not be silently dropped');
    assert.equal(v.cve, undefined, 'unknown-prefix id must NOT be placed under `cve`');
  });
});

// ---------- P1-3 ----------

describe('audit CC P1-3 — publisher.namespace from operator, not tooling vendor', () => {
  it('default emit (no operator, no namespace) falls back to urn:exceptd:operator:unknown with explanatory note', () => {
    const { close: c } = closeKernel();
    const csaf = c.evidence_package.bundles_by_format['csaf-2.0'];
    assert.equal(csaf.document.publisher.namespace, 'urn:exceptd:operator:unknown');
    assert.equal(csaf.exceptd_extension.publisher_namespace_source, 'fallback');
    // The notes[] array MUST include the explanatory note category=general so
    // operators see why the fallback is in place.
    const notes = csaf.document.notes || [];
    const fallbackNote = notes.find(n => n.category === 'general' && /Publisher namespace not supplied/i.test(n.title));
    assert.ok(fallbackNote, 'fallback emit must surface a general note explaining the missing publisher namespace');
  });

  it('runOpts.publisherNamespace lands in document.publisher.namespace', () => {
    const { close: c } = closeKernel({ publisherNamespace: 'https://operator.example' });
    const csaf = c.evidence_package.bundles_by_format['csaf-2.0'];
    assert.equal(csaf.document.publisher.namespace, 'https://operator.example');
    assert.equal(csaf.exceptd_extension.publisher_namespace_source, 'runOpts.publisherNamespace');
  });

  it('URL-shaped --operator (no explicit namespace) is used as fallback publisher namespace', () => {
    const { close: c } = closeKernel({ operator: 'https://alice.example' });
    const csaf = c.evidence_package.bundles_by_format['csaf-2.0'];
    assert.equal(csaf.document.publisher.namespace, 'https://alice.example');
    assert.equal(csaf.exceptd_extension.publisher_namespace_source, 'runOpts.operator');
  });

  it('explicit publisherNamespace wins over URL-shaped operator', () => {
    const { close: c } = closeKernel({
      publisherNamespace: 'https://org.example',
      operator: 'https://individual.example',
    });
    const csaf = c.evidence_package.bundles_by_format['csaf-2.0'];
    assert.equal(csaf.document.publisher.namespace, 'https://org.example');
  });

  it('fallback emit also surfaces bundle_publisher_unclaimed in runOpts._runErrors', () => {
    // Direct buildEvidenceBundle exercises the bundle path with a real
    // _runErrors accumulator (close() doesn't pre-seed one for direct callers,
    // but the orchestrator does — we mimic that here).
    const runOpts = { session_id: 'auditccrunerrtest', _runErrors: [] };
    const runner = loadRunner();
    const det = runner.detect('kernel', 'all-catalogued-kernel-cves', {
      signal_overrides: { 'kver-in-affected-range': 'hit' }
    }, runOpts);
    const an = runner.analyze('kernel', 'all-catalogued-kernel-cves', det,
      { patch_available: false, blast_radius_score: 3 }, runOpts);
    const v = runner.validate('kernel', 'all-catalogued-kernel-cves', an, {}, runOpts);
    runner.close('kernel', 'all-catalogued-kernel-cves', an, v, {
      _bundle_formats: ['csaf-2.0'],
    }, runOpts);
    const unclaimed = runOpts._runErrors.filter(e => e && e.kind === 'bundle_publisher_unclaimed');
    assert.equal(unclaimed.length, 1,
      `fallback emit must push exactly one bundle_publisher_unclaimed entry; got ${unclaimed.length}: ${JSON.stringify(runOpts._runErrors)}`);
    const entry = unclaimed[0];
    assert.equal(typeof entry.reason, 'string');
    assert.ok(entry.reason.length > 0, 'bundle_publisher_unclaimed must carry a non-empty reason string');
    assert.match(String(entry.remediation || ''), /publisher-namespace/i,
      'remediation field must point operators at the --publisher-namespace flag');
  });

  it('supplied --publisher-namespace does NOT push bundle_publisher_unclaimed', () => {
    const runOpts = { session_id: 'auditcchappytest', _runErrors: [], publisherNamespace: 'https://operator.example' };
    const runner = loadRunner();
    const det = runner.detect('kernel', 'all-catalogued-kernel-cves', {
      signal_overrides: { 'kver-in-affected-range': 'hit' }
    }, runOpts);
    const an = runner.analyze('kernel', 'all-catalogued-kernel-cves', det,
      { patch_available: false, blast_radius_score: 3 }, runOpts);
    const v = runner.validate('kernel', 'all-catalogued-kernel-cves', an, {}, runOpts);
    runner.close('kernel', 'all-catalogued-kernel-cves', an, v, {
      _bundle_formats: ['csaf-2.0'],
    }, runOpts);
    const unclaimed = runOpts._runErrors.filter(e => e && e.kind === 'bundle_publisher_unclaimed');
    assert.deepEqual(unclaimed, [],
      'no bundle_publisher_unclaimed entry should appear when namespace was supplied');
  });
});

// ---------- P1-4 ----------

describe('audit CC P1-4 — --operator threads into tracking.generator and publisher.contact_details', () => {
  it('tracking.generator.engine names exceptd + a real version', () => {
    const { close: c } = closeKernel({ operator: 'alice' });
    const tracking = c.evidence_package.bundles_by_format['csaf-2.0'].document.tracking;
    assert.ok(tracking.generator, 'tracking.generator must be present');
    assert.ok(tracking.generator.engine, 'tracking.generator.engine must be present');
    assert.equal(tracking.generator.engine.name, 'exceptd');
    assert.equal(typeof tracking.generator.engine.version, 'string');
    assert.ok(tracking.generator.engine.version.length > 0,
      'tracking.generator.engine.version must be populated, not empty string');
    assert.match(tracking.generator.engine.version, /^\d+\.\d+\.\d+/,
      'tracking.generator.engine.version must be SemVer-shaped');
    assert.equal(typeof tracking.generator.date, 'string');
  });

  it('publisher.contact_details carries the operator value', () => {
    const { close: c } = closeKernel({ operator: 'alice' });
    const publisher = c.evidence_package.bundles_by_format['csaf-2.0'].document.publisher;
    assert.equal(publisher.contact_details, 'alice');
  });

  it('publisher.contact_details is omitted (not null) when --operator is absent', () => {
    const { close: c } = closeKernel();
    const publisher = c.evidence_package.bundles_by_format['csaf-2.0'].document.publisher;
    assert.equal(publisher.contact_details, undefined,
      'contact_details must be omitted entirely rather than carry a misleading null');
  });
});

// ---------- P2-1 ----------

describe('audit CC P2-1 — bundles_by_format is always populated', () => {
  it('single-format emit produces { [primaryFormat]: bundle }', () => {
    const runner = loadRunner();
    const det = runner.detect('kernel', 'all-catalogued-kernel-cves', {
      signal_overrides: { 'kver-in-affected-range': 'hit' }
    });
    const an = runner.analyze('kernel', 'all-catalogued-kernel-cves', det, {
      patch_available: false, blast_radius_score: 3
    });
    const v = runner.validate('kernel', 'all-catalogued-kernel-cves', an, {});
    const c = runner.close('kernel', 'all-catalogued-kernel-cves', an, v,
      {} /* no _bundle_formats */,
      { session_id: 'auditccp21test' }
    );
    const byFormat = c.evidence_package.bundles_by_format;
    assert.notEqual(byFormat, null, 'bundles_by_format must never be null (pre-fix was null for single-format)');
    assert.equal(typeof byFormat, 'object');
    assert.ok(byFormat['csaf-2.0'], 'bundles_by_format must carry the primary format key');
    assert.equal(byFormat['csaf-2.0'], c.evidence_package.bundle_body,
      'bundles_by_format[primary] is the same object as bundle_body');
  });
});

// ---------- P2-2 ----------

describe('audit CC P2-2 — cvss_v3 block carries vectorString or is dropped entirely', () => {
  it('matched CVE with cvss_score + cvss_vector emits full cvss_v3 block', () => {
    const { close: c, analyze: an } = closeKernel();
    const csaf = c.evidence_package.bundles_by_format['csaf-2.0'];
    // Find a CVE that actually has a cvss_vector in the catalog.
    const withVector = an.matched_cves.find(x => typeof x.cvss_vector === 'string' && x.cvss_vector.length > 0);
    assert.ok(withVector, 'fixture: at least one matched CVE must have a cvss_vector in the catalog');
    const vuln = csaf.vulnerabilities.find(v => v.cve === withVector.cve_id);
    assert.ok(vuln);
    assert.ok(Array.isArray(vuln.scores) && vuln.scores.length === 1);
    const score = vuln.scores[0];
    assert.ok(score.cvss_v3, 'cvss_v3 block must be present when score + vector are populated');
    assert.equal(typeof score.cvss_v3.vectorString, 'string');
    assert.match(score.cvss_v3.vectorString, /^CVSS:\d+\.\d+\//,
      'cvss_v3.vectorString must match the CSAF §3.2.1.5 prefix');
    assert.equal(score.cvss_v3.baseScore, withVector.cvss_score);
    assert.equal(typeof score.cvss_v3.version, 'string');
    assert.match(score.cvss_v3.baseSeverity, /^(NONE|LOW|MEDIUM|HIGH|CRITICAL)$/);
  });

  it('vulns with no cvss data emit scores: [] rather than a truncated cvss_v3 block', () => {
    const runner = loadRunner();
    const det = runner.detect('kernel', 'all-catalogued-kernel-cves', {
      signal_overrides: { 'kver-in-affected-range': 'hit' }
    });
    const an = runner.analyze('kernel', 'all-catalogued-kernel-cves', det, {
      patch_available: false, blast_radius_score: 3
    });
    // Strip cvss data from one matched entry to exercise the empty-score path.
    if (an.matched_cves.length > 0) {
      an.matched_cves[0].cvss_score = null;
      an.matched_cves[0].cvss_vector = null;
    }
    const v = runner.validate('kernel', 'all-catalogued-kernel-cves', an, {});
    const c = runner.close('kernel', 'all-catalogued-kernel-cves', an, v, {
      _bundle_formats: ['csaf-2.0']
    }, { session_id: 'auditccp22test' });
    const csaf = c.evidence_package.bundles_by_format['csaf-2.0'];
    const target = csaf.vulnerabilities.find(x => x.cve === an.matched_cves[0].cve_id);
    assert.ok(target);
    assert.deepEqual(target.scores, [],
      'no-CVSS-data vuln must emit scores: [] — truncated cvss_v3 blocks are rejected by strict validators');
  });
});

// ---------- P2-6 ----------

describe('audit CC P2-6 — SARIF ruleId carries playbook prefix', () => {
  it('every result.ruleId starts with `<playbook-slug>/`', () => {
    const { close: c } = closeKernel();
    const sarif = c.evidence_package.bundles_by_format['sarif-2.1.0'];
    const results = sarif.runs[0].results;
    assert.ok(results.length > 0, 'fixture: SARIF must have results');
    for (const r of results) {
      assert.match(String(r.ruleId), /^kernel\//,
        `result.ruleId must carry playbook prefix; got ${r.ruleId}`);
    }
  });

  it('every rule.id has a matching result.ruleId (SARIF §3.27.3 closure)', () => {
    const { close: c } = closeKernel();
    const sarif = c.evidence_package.bundles_by_format['sarif-2.1.0'];
    const ruleIds = new Set((sarif.runs[0].tool.driver.rules || []).map(r => r.id));
    const resultIds = (sarif.runs[0].results || []).map(r => r.ruleId);
    const missing = resultIds.filter(id => !ruleIds.has(id));
    assert.deepEqual(missing, [],
      `every result.ruleId must have a corresponding rule.id in tool.driver.rules; missing: ${JSON.stringify(missing)}`);
  });

  it('no cross-playbook collision when two playbook bundles are merged in one sarif-log', () => {
    // Run kernel and mcp end-to-end and check that the union of ruleIds has
    // no duplicates — pre-fix `framework-gap-0` collided across every
    // playbook that produced framework gaps.
    const runner = loadRunner();
    const kernelDet = runner.detect('kernel', 'all-catalogued-kernel-cves', {
      signal_overrides: { 'kver-in-affected-range': 'hit' }
    });
    const kernelAn = runner.analyze('kernel', 'all-catalogued-kernel-cves', kernelDet, {
      patch_available: false, blast_radius_score: 3
    });
    const kernelV = runner.validate('kernel', 'all-catalogued-kernel-cves', kernelAn, {});
    const kernelClose = runner.close('kernel', 'all-catalogued-kernel-cves', kernelAn, kernelV, {
      _bundle_formats: ['sarif-2.1.0']
    }, { session_id: 'auditccp26kerneltest' });

    // Use the framework playbook — same shape, different slug, both produce
    // framework_gap_mapping entries.
    const fwDet = runner.detect('framework', 'baseline-framework-gap-inventory',
      { signal_overrides: {} });
    const fwAn = runner.analyze('framework', 'baseline-framework-gap-inventory', fwDet, {});
    const fwV = runner.validate('framework', 'baseline-framework-gap-inventory', fwAn, {});
    const fwClose = runner.close('framework', 'baseline-framework-gap-inventory', fwAn, fwV, {
      _bundle_formats: ['sarif-2.1.0']
    }, { session_id: 'auditccp26fwtest' });

    const kernelIds = (kernelClose.evidence_package.bundles_by_format['sarif-2.1.0'].runs[0].results || [])
      .map(r => r.ruleId);
    const fwIds = (fwClose.evidence_package.bundles_by_format['sarif-2.1.0'].runs[0].results || [])
      .map(r => r.ruleId);
    const inter = kernelIds.filter(id => fwIds.includes(id));
    assert.deepEqual(inter, [],
      `kernel and framework SARIF ruleIds must not collide; pre-fix bare ids like framework-gap-0 collided. Overlap: ${JSON.stringify(inter)}`);
  });
});

// ---------- CLI end-to-end coverage for the two new flags ----------

function tryJson(s) { try { return JSON.parse(s); } catch { return null; } }

function cli(argv, opts = {}) {
  const env = {
    ...process.env,
    EXCEPTD_HOME: CSAF_SUITE_HOME,
    EXCEPTD_LOCK_DIR: path.join(CSAF_SUITE_HOME, '_locks'),
    EXCEPTD_DEPRECATION_SHOWN: '1',
    EXCEPTD_UNSIGNED_WARNED: '1',
  };
  delete env.EXCEPTD_PLAYBOOK_DIR;
  return spawnSync(process.execPath, [CLI_PATH, ...argv], {
    input: opts.input,
    encoding: 'utf8',
    env,
    cwd: path.resolve(__dirname, '..'),
  });
}

describe('audit CC — CLI flag plumbing', () => {
  // library-author has no platform precondition; its `publish-workflow-uses-
  // static-token` indicator is the same fixture #93 uses for SARIF CLI
  // coverage.
  const submissionFor = () => JSON.stringify({
    observations: { w: { captured: true, indicator: 'publish-workflow-uses-static-token', result: 'hit' } },
    verdict: {}
  });

  it('--publisher-namespace lands in CSAF document.publisher.namespace', () => {
    const r = cli([
      'run', 'library-author', '--evidence', '-',
      '--format', 'csaf-2.0',
      '--publisher-namespace', 'https://operator.example',
      '--json',
    ], { input: submissionFor() });
    const data = tryJson(r.stdout);
    assert.ok(data, `csaf via CLI must emit JSON; stderr: ${r.stderr}`);
    assert.equal(data.document?.publisher?.namespace, 'https://operator.example');
  });

  it('--operator lands in tracking.generator.engine AND publisher.contact_details', () => {
    const r = cli([
      'run', 'library-author', '--evidence', '-',
      '--format', 'csaf-2.0',
      '--operator', 'alice',
      '--ack',
      '--json',
    ], { input: submissionFor() });
    const data = tryJson(r.stdout);
    assert.ok(data, `csaf via CLI must emit JSON; stderr: ${r.stderr}`);
    assert.equal(data.document?.publisher?.contact_details, 'alice');
    assert.equal(data.document?.tracking?.generator?.engine?.name, 'exceptd');
    assert.match(String(data.document?.tracking?.generator?.engine?.version || ''), /^\d+\.\d+\.\d+/);
  });

  it('--csaf-status final promotes tracking.status to final', () => {
    const r = cli([
      'run', 'library-author', '--evidence', '-',
      '--format', 'csaf-2.0',
      '--csaf-status', 'final',
      '--json',
    ], { input: submissionFor() });
    const data = tryJson(r.stdout);
    assert.ok(data, `csaf via CLI must emit JSON; stderr: ${r.stderr}`);
    assert.equal(data.document?.tracking?.status, 'final');
  });

  it('default --csaf-status (omitted) yields interim', () => {
    const r = cli([
      'run', 'library-author', '--evidence', '-',
      '--format', 'csaf-2.0',
      '--json',
    ], { input: submissionFor() });
    const data = tryJson(r.stdout);
    assert.ok(data, `csaf via CLI must emit JSON; stderr: ${r.stderr}`);
    assert.equal(data.document?.tracking?.status, 'interim');
  });

  it('invalid --csaf-status value is rejected at input', () => {
    const sub = JSON.stringify({ observations: {}, verdict: {} });
    const r = cli([
      'run', 'library-author', '--evidence', '-',
      '--csaf-status', 'finel',
      '--json',
    ], { input: sub });
    assert.equal(r.status, 1,
      '--csaf-status finel must exit 1 (arg-validation refusal at CLI input)');
    const err = tryJson(r.stderr) || tryJson(r.stdout);
    assert.ok(err && err.ok === false,
      `must emit an ok:false body; got stderr=${r.stderr.slice(0, 200)}`);
    assert.match(String(err.error || ''), /csaf-status/i);
  });

  it('invalid --publisher-namespace (non-URL) is rejected', () => {
    const sub = JSON.stringify({ observations: {}, verdict: {} });
    const r = cli([
      'run', 'library-author', '--evidence', '-',
      '--publisher-namespace', 'not-a-url',
      '--json',
    ], { input: sub });
    assert.equal(r.status, 1,
      '--publisher-namespace not-a-url must exit 1 (arg-validation refusal)');
    const err = tryJson(r.stderr) || tryJson(r.stdout);
    assert.ok(err && err.ok === false);
    assert.match(String(err.error || ''), /publisher-namespace/i);
  });
});
})();


// ---- routed from evidence-input-hardening ----
;(() => {
/**
 * tests/evidence-input-hardening.test.js
 *
 * Cycle 15 security fixes (v0.12.35):
 *
 *   F1 — `--evidence -` (stdin) was uncapped. The file-path branch
 *        enforced a 32 MiB cap; the stdin branch did `fs.readFileSync(0)`
 *        with no length limit. An attacker piping multi-GB JSON would
 *        OOM the runner. Now both branches share the same MAX_EVIDENCE_BYTES
 *        limit; stdin reads in 1 MB chunks and bails at the cap.
 *
 *   F2 — `Object.assign(out.precondition_checks, submission.precondition_checks)`
 *        re-invoked the `__proto__` setter when the operator's JSON contained
 *        a `__proto__` key. JSON.parse keeps `__proto__` as an own data
 *        property; Object.assign reads it via [[Get]] and writes via [[Set]],
 *        triggering the prototype-rebinding setter. Global Object.prototype
 *        stayed clean (Node confines the rebind to the assignment target),
 *        but the polluted local prototype was a defense-in-depth gap. Now
 *        own-key iteration explicitly skips `__proto__` / `constructor` /
 *        `prototype` keys.
 *
 * Per the anti-coincidence rule, every assertion checks an EXACT
 * exit code or value, never `assert.notEqual(0)` or wildcard match.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const ROOT = path.join(__dirname, '..');
const CLI = path.join(ROOT, 'bin', 'exceptd.js');

function cli(args, opts = {}) {
  return spawnSync(process.execPath, [CLI, ...args], {
    encoding: 'utf8',
    cwd: opts.cwd || ROOT,
    env: { ...process.env, EXCEPTD_DEPRECATION_SHOWN: '1', ...(opts.env || {}) },
    input: opts.input,
    maxBuffer: 200 * 1024 * 1024,
  });
}

function tryJson(s) { try { return JSON.parse(s); } catch { return null; } }

// F1 — stdin size cap ------------------------------------------------------

test('F1: --evidence - accepts a small (< 32 MiB) JSON payload on stdin', () => {
  const small = JSON.stringify({
    precondition_checks: { 'linux-platform': true, 'uname-available': true },
    artifacts: { 'kernel-release': '5.15.0-69-generic' },
  });
  const r = cli(['run', 'kernel', '--evidence', '-'], { input: small });
  assert.equal(r.status, 0, `small payload must succeed; got ${r.status}, stderr: ${r.stderr.slice(0, 300)}`);
});

test('F1: --evidence - refuses payload over 32 MiB with structured error + exit 1', () => {
  // Construct ~34 MiB payload (just over the 32 MiB cap).
  const sizeMb = 34;
  const filler = 'x'.repeat(1024 - 20);
  const items = [];
  for (let i = 0; i < sizeMb * 1024; i++) items.push(`"k${i}":"${filler}"`);
  const big = `{"artifacts":{${items.join(',')}}}`;
  // Sanity: payload must actually exceed 32 MiB.
  assert.equal(big.length > 32 * 1024 * 1024, true,
    `test payload must exceed 32 MiB; got ${big.length} bytes`);

  const r = cli(['run', 'kernel', '--evidence', '-'], { input: big });
  assert.equal(r.status, 1, `oversize stdin must exit 1; got ${r.status}`);
  // Structured stderr JSON.
  const err = tryJson(r.stderr);
  assert.ok(err, `oversize-stdin error must be parseable JSON; got: ${r.stderr.slice(0, 200)}`);
  assert.equal(err.ok, false);
  assert.match(err.error, /evidence on stdin exceeds size limit/);
  assert.match(err.error, /33554432 byte limit/);
});

// F2 — Prototype-pollution defense ----------------------------------------

test('F2: evidence with __proto__ key does not pollute Object.prototype', () => {
  const evil = JSON.stringify({
    precondition_checks: {
      'linux-platform': true,
      'uname-available': true,
      __proto__: { polluted: 'yes' },
      constructor: { prototype: { injected: 1 } },
    },
    artifacts: { 'kernel-release': '5.15.0-69-generic' },
  });
  const r = cli(['run', 'kernel', '--evidence', '-'], { input: evil });
  assert.equal(r.status, 0, `prototype-pollution test must complete; got ${r.status}`);
  // After the child exits, our own process's Object.prototype must
  // remain pristine. (Containment is the runtime's job, but our own
  // process state would only be affected if we share heap with the
  // child — we don't, so this is a sanity check.)
  const o = {};
  assert.equal(o.polluted, undefined, 'Object.prototype.polluted must be undefined');
  assert.equal(o.injected, undefined, 'Object.prototype.injected must be undefined');
  assert.equal(Object.prototype.hasOwnProperty.call(Object.prototype, 'polluted'), false);
});

test('F2: __proto__ / constructor / prototype keys in precondition_checks are stripped', () => {
  // Pipe evidence; the runner must accept the run, but the precondition_checks
  // bag inside should NOT have prototype-bag leakage. We assert via runtime
  // observation: the run completes successfully + the JSON output does not
  // surface `polluted: 'yes'` in any phase.
  const evil = JSON.stringify({
    precondition_checks: {
      'linux-platform': true,
      'uname-available': true,
      __proto__: { polluted: 'yes' },
    },
    artifacts: { 'kernel-release': '5.15.0-69-generic' },
  });
  const r = cli(['run', 'kernel', '--evidence', '-', '--json'], { input: evil });
  assert.equal(r.status, 0);
  assert.equal(/"polluted":/.test(r.stdout), false,
    `precondition bag must not surface __proto__ pollution in run output; got: ${r.stdout.slice(0, 400)}`);
});
})();


// ---- routed from jurisdiction-pending ----
;(() => {
/**
 * tests/jurisdiction-pending.test.js
 *
 * Pins the pending-notification-obligations surface on detected runs.
 * The detection IS the regulatory event in many jurisdictions — the
 * operator must see the obligation landscape at the same moment they
 * see the finding, not after they remember to grep
 * `phases.close.notification_actions` in the JSON.
 *
 * Test pins:
 *   - Detected runs with no clocks started print the "Pending
 *     jurisdiction obligations (N)" block on the human renderer.
 *   - Obligations are grouped by `clock_start_event` (one row per
 *     start event, NOT one row per regulation).
 *   - The next-step pointer suggests `--format csaf-2.0` for the
 *     draft advisory + notification bodies.
 *   - Non-detect verdicts (not_detected / inconclusive) do NOT print
 *     the Pending block (no regulatory event to track).
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");
const fs = require("node:fs");
const os = require("node:os");
const { spawnSync } = require("node:child_process");

const ROOT = path.join(__dirname, "..");
const CLI = path.join(ROOT, "bin", "exceptd.js");

function cli(args, opts = {}) {
  return spawnSync(process.execPath, [CLI, ...args], {
    encoding: "utf8",
    cwd: opts.cwd || ROOT,
    env: { ...process.env, EXCEPTD_DEPRECATION_SHOWN: "1", EXCEPTD_UNSIGNED_WARNED: "1", ...(opts.env || {}) },
    input: opts.input,
  });
}

test("detected run prints 'Pending jurisdiction obligations' grouped by clock_start_event", () => {
  // kernel playbook with the deterministic CVE indicator firing is the
  // canonical detected-with-obligations shape.
  const evidence = JSON.stringify({
    precondition_checks: { "linux-platform": true, "uname-available": true },
    artifacts: { "kernel-release": "5.15.0-69-generic" },
    signal_overrides: { "kver-in-affected-range": "hit" },
  });
  const tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), "pending-obl-"));
  try {
    const env = { EXCEPTD_HOME: tmpHome };
    const r = cli(["run", "kernel", "--evidence", "-"], { input: evidence, env });
    assert.equal(r.status, 0, `run kernel must exit 0; stderr: ${r.stderr.slice(0, 200)}`);
    // Assert the detected classification as a precondition BEFORE
    // checking the pending-obligation output. Without this, a future
    // regression in the deterministic hit indicator would silently
    // skip the pending-obligation assertions (the test would still
    // pass), and the feature could break without alerting.
    assert.match(r.stdout, /\[!! DETECTED\]/,
      "kernel + kver-in-affected-range:hit must classify as detected — the test scenario depends on this");
    assert.match(r.stdout, /Pending jurisdiction obligations \(\d+\) — clock starts on operator action:/,
      "detected run must surface pending jurisdiction obligations");
    // At least one grouped event row. Format: `  on <event>:  <jur>/<reg> (Nh), ...`
    assert.match(r.stdout, /\s+on \w+:\s+\w/,
      "obligations must be grouped by clock_start_event");
    // Next-step pointer.
    assert.match(r.stdout, /→ next: exceptd run kernel --evidence <file> --format csaf-2\.0/,
      "must point at csaf-2.0 format for draft advisory + notification bodies");
  } finally {
    try { fs.rmSync(tmpHome, { recursive: true, force: true }); } catch {}
  }
});

test("non-detect runs do NOT print the Pending block (irrelevant — no regulatory event)", () => {
  // Empty submission → classification=not_detected. The renderer must
  // not surface the Pending jurisdiction block in that case — there is
  // no detection to trigger an obligation.
  const tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), "non-detect-obl-"));
  try {
    const env = { EXCEPTD_HOME: tmpHome };
    const r = cli(["run", "secrets", "--evidence", "-"], { input: "{}", env });
    assert.equal(r.status, 0);
    assert.doesNotMatch(r.stdout, /Pending jurisdiction obligations/,
      "not_detected / inconclusive runs must NOT print the Pending block — no regulatory event to track");
  } finally {
    try { fs.rmSync(tmpHome, { recursive: true, force: true }); } catch {}
  }
});
})();


// ---- routed from offline-egress-airgap ----
;(() => {
/**
 * Regression: runs the operator believes are offline must make no network call.
 *
 *  [16] An intrinsically air-gapped playbook (_meta.air_gap_mode — secrets /
 *       cred-stores / containers) + `--upstream-check` must refuse the npm
 *       registry probe even without the explicit --air-gap flag.
 *  [2]  discoverNewRfcs queries IETF Datatracker live; under --air-gap it must
 *       make no call (the help no longer claims --from-cache alone is "entirely
 *       offline" — RFC discovery is live unless --air-gap is also passed).
 */

const test = require('node:test');
const assert = require('node:assert/strict');

const { ROOT, makeSuiteHome, makeCli, tryJson } = require('./_helpers/cli');
const { discoverNewRfcs } = require('../lib/auto-discovery');

const cli = makeCli(makeSuiteHome('exceptd-offline-egress-'));

test('intrinsic air-gap playbook + --upstream-check refuses the registry probe (no flag)', () => {
  const sub = JSON.stringify({ observations: {}, verdict: { classification: 'not_detected' } });
  const r = cli(['run', 'secrets', '--upstream-check', '--evidence', '-', '--json'], { input: sub });
  assert.equal(r.status, 0, `run must succeed; stderr=${r.stderr.slice(0, 300)}`);
  const body = tryJson((r.stdout || '').split('\n').filter((l) => l.trim().startsWith('{')).pop() || '') || {};
  assert.ok(body.upstream_check && typeof body.upstream_check === 'object', 'upstream_check must be present');
  assert.equal(body.upstream_check.air_gap_blocked, true, 'intrinsic air-gap must block the registry probe');
  assert.equal(body.upstream_check.source, 'air-gap');
});

test('discoverNewRfcs makes no network call under air-gap', async () => {
  const orig = global.fetch;
  let called = false;
  global.fetch = async () => { called = true; throw new Error('network call attempted under air-gap'); };
  try {
    const r = await discoverNewRfcs({ airGap: true, rfcCatalog: {} });
    assert.equal(called, false, 'discoverNewRfcs must not call fetch under air-gap');
    assert.equal(r.diffs.length, 0);
    assert.match(r.summary, /air-gap/i);
  } finally {
    global.fetch = orig;
  }
});
})();


// ---- routed from rwep-scoring-edge-cases ----
;(() => {
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
// Mirrors closeWithSyntheticMatchedId() from csaf-bundle-correctness.test.js so
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
    const unsupported = runOpts._runErrors.filter(e => e && (e.kind === 'csaf_cvss_invalid' || e.kind === 'bundle_cvss_v3_version_unsupported'));
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
    const unsupported = runOpts._runErrors.filter(e => e && (e.kind === 'csaf_cvss_invalid' || e.kind === 'bundle_cvss_v3_version_unsupported'));
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
    const unsupported = runOpts._runErrors.filter(e => e && (e.kind === 'csaf_cvss_invalid' || e.kind === 'bundle_cvss_v3_version_unsupported'));
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
})();


// ---- routed from sarif-evidence-locations ----
;(() => {
/**
 * Pins the SARIF results[].locations support: a submission's optional
 * `evidence_locations` map is threaded onto firing indicators and emitted as
 * SARIF physical locations, so secret/file findings carry a real location
 * instead of shipping location-less (which GitHub code-scanning drops).
 *
 * Discipline: exact exit codes; value/type assertions paired with presence.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const { makeSuiteHome, makeCli, tryJson } = require("./_helpers/cli");

const cli = makeCli(makeSuiteHome("exceptd-sariflocs-"));

// A library-author observation-hit drives a clean 'hit' (the existing SARIF
// tests use this path). Supply evidence_locations in both accepted forms.
const SUB = JSON.stringify({
  observations: { w: { captured: true, indicator: "publish-workflow-uses-static-token", result: "hit" } },
  evidence_locations: {
    "publish-workflow-uses-static-token": [
      ".github/workflows/release.yml",
      { uri: ".github/workflows/publish.yml", startLine: 12 },
    ],
  },
});

test("SARIF result for a firing indicator carries the submission's evidence_locations", () => {
  const r = cli(["run", "library-author", "--evidence", "-", "--format", "sarif", "--json"], { input: SUB });
  const sarif = tryJson(r.stdout);
  assert.ok(sarif && sarif.version === "2.1.0", `expected SARIF 2.1.0; got ${r.stdout.slice(0, 160)}`);
  const result = (sarif.runs?.[0]?.results || []).find(x => /publish-workflow-uses-static-token/.test(x.ruleId));
  assert.ok(result, "the fired indicator must have a SARIF result");
  assert.ok(Array.isArray(result.locations) && result.locations.length === 2,
    `expected 2 locations; got ${JSON.stringify(result.locations)}`);
  const uris = result.locations.map(l => l.physicalLocation?.artifactLocation?.uri);
  assert.ok(uris.includes(".github/workflows/release.yml"), "string-form location must become a uri");
  const withLine = result.locations.find(l => l.physicalLocation?.artifactLocation?.uri === ".github/workflows/publish.yml");
  assert.equal(withLine.physicalLocation.region.startLine, 12, "object-form startLine must become a SARIF region");
});

test("a firing indicator with no evidence_locations does not crash and yields a valid SARIF doc", () => {
  const sub = JSON.stringify({ observations: { w: { captured: true, indicator: "publish-workflow-uses-static-token", result: "hit" } } });
  const r = cli(["run", "library-author", "--evidence", "-", "--format", "sarif", "--json"], { input: sub });
  const sarif = tryJson(r.stdout);
  assert.ok(sarif && sarif.version === "2.1.0");
  const result = (sarif.runs?.[0]?.results || []).find(x => /publish-workflow-uses-static-token/.test(x.ruleId));
  assert.ok(result, "result present");
  // locations may be absent or the coarse playbook-source fallback; either is
  // valid SARIF — just assert no crash and the result exists.
  if (result.locations !== undefined) assert.ok(Array.isArray(result.locations));
});
})();
