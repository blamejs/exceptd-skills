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


// ---- routed from audit-correctness-cluster ----
require("node:test").describe("audit-correctness-cluster", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
/**
 * Regression suite for a correctness cluster found auditing the run/ci/ai-run
 * verbs and the close/framework-gap surfaces for silent-wrong-answer bugs:
 *
 *   H1 — `ci <playbook> --evidence -` given a FLAT submission (the same shape
 *        `run` accepts) silently produced a PASS: the runner keyed the bundle
 *        by playbook id, found nothing, and evaluated an empty submission.
 *        ci must now treat a single-positional flat submission as belonging to
 *        that playbook, matching `run`'s verdict.
 *
 *   H2 — `ai-run <pb> --no-stream --evidence -` bypassed the evidence-shape
 *        guard `run` enforces, so `null` / `[]` / a scalar ran as if empty.
 *        It must be rejected at the read boundary with an actionable message.
 *
 *   H3 — the ci framework_gap_rollup read a nonexistent `why_insufficient`
 *        key, so every rollup entry's explanation was null. The data lives in
 *        `actual_gap`; the rollup must surface it.
 *
 *   M1 — the regulatory clock only started when the AGENT submitted
 *        detection_classification:'detected'. An engine-confirmed detection
 *        (indicators fired, engine classified 'detected') with --ack never
 *        started the clock, so notification deadlines silently stalled.
 *
 *   M2 — `framework-gap <bogus> <scenario>` produced a zero-gap report
 *        indistinguishable from a real "no gaps" result, so a typo read as
 *        proof the framework covered the scenario. An unknown framework must
 *        be refused; documented short forms ("NIST-800-53") must still resolve.
 *
 * Discipline: exact exit codes; presence assertions paired with value/type.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const { makeSuiteHome, makeCli, tryJson } = require("./_helpers/cli");

const cli = makeCli(makeSuiteHome("exceptd-auditcorrect-"));

// A flat secrets submission whose overrides fire real indicators.
const FLAT_SECRETS = JSON.stringify({
  signal_overrides: { "aws-secret-access-key": "hit", "github-personal-access-token": "hit" },
});





// The bug codex flagged: the guard above only fires on `--evidence`, but
// --no-stream ALSO auto-reads stdin. Whether a spawnSync pipe triggers the
// auto-stdin path is platform-divergent (POSIX FIFOs report readable; win32
// spawnSync pipes do not), so probe reachability first and only assert the
// rejection where the path is actually live — never coincidence-pass.
function autoStdinReachable() {
  const probe = cli(["ai-run", "secrets", "--no-stream", "--json"], {
    input: JSON.stringify({ signal_overrides: { "aws-secret-access-key": "hit", "github-personal-access-token": "hit" } }),
  });
  const pj = tryJson(probe.stdout);
  return !!(pj && pj.phases?.analyze?._detect_classification === "detected");
}




const AI_API_FIRES = JSON.stringify({
  signal_overrides: {
    "cleartext-api-key-in-dotfile": "hit",
    "ai-api-beaconing-cadence": "hit",
    "long-lived-aws-keys": "hit",
  },
});

test("M1: an engine-confirmed detection starts the clock with --ack (no agent classification submitted)", () => {
  const r = cli(["run", "ai-api", "--evidence", "-", "--ack", "--json"], { input: AI_API_FIRES });
  const j = tryJson(r.stdout);
  assert.ok(j, "run must emit JSON");
  assert.equal(j.phases.analyze._detect_classification, "detected", "engine must classify detected from the fired signals");
  const notifs = j.phases.close?.jurisdiction_notifications || j.phases.close?.notification_actions || [];
  // The detect_confirmed obligations must have a real ISO deadline, not the
  // pending sentinel — the engine classification started the clock.
  const started = notifs.filter(n => (n.deadline || n.notification_deadline) && (n.deadline || n.notification_deadline) !== "pending_clock_start_event");
  assert.ok(started.length >= 1, "at least one obligation's clock must start from the engine-confirmed detection + --ack");
  for (const n of started) {
    assert.match(n.deadline || n.notification_deadline, /^\d{4}-\d{2}-\d{2}T/, "a started clock yields an ISO deadline");
  }
});

test("M1: without --ack an engine-confirmed detection leaves the clock pending", () => {
  const r = cli(["run", "ai-api", "--evidence", "-", "--json"], { input: AI_API_FIRES });
  const j = tryJson(r.stdout);
  assert.ok(j, "run must emit JSON");
  const notifs = j.phases.close?.jurisdiction_notifications || j.phases.close?.notification_actions || [];
  const detectConfirmed = notifs.filter(n => n.clock_pending_ack === true);
  assert.ok(detectConfirmed.length >= 1, "detect_confirmed obligations must surface clock_pending_ack without --ack");
  for (const n of detectConfirmed) {
    assert.equal(n.deadline || n.notification_deadline, "pending_clock_start_event", "pending obligations carry the sentinel, not an ISO date");
  }
});
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});


// ---- routed from audit-usability-fixes ----
require("node:test").describe("audit-usability-fixes", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
/**
 * CLI usability regression suite.
 *
 * Pins the behavior of a set of CLI ergonomics fixes so they cannot silently
 * regress at the next refactor. Each test exercises the real CLI through the
 * shared cli() harness (subprocess spawn of bin/exceptd.js) and asserts the
 * EXACT exit code and field shapes per the project anti-coincidence rule:
 * never `notEqual(0)`, never `assert.ok(field)` without a paired value/type
 * assertion.
 *
 * Areas covered:
 *   1. Unknown-flag hard-fail across all verbs (+ typo suggestion + the
 *      tailored cross-verb "irrelevant flag" message that must NOT collapse
 *      into a generic unknown-flag refusal).
 *   2. `--format json` returns the full run result, not a stub.
 *   3. Multiple --format values emit a one-format-wins note to stderr.
 *   4. Standardized bundles (sarif / csaf-2.0 / openvex) carry no top-level
 *      `ok` key and present their spec marker.
 *   5. `skill` / `framework-gap` honor --help; `refresh` keeps its own help.
 *   6. `collect` emits JSON when piped (non-TTY) so the documented pipe works.
 *   7. `refresh --check-advisories` arg parsing (report-only, no network).
 *   8. `attest list --limit` envelope + bad-value rejection.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const fs = require('node:fs');
const os = require('node:os');

const { ROOT, makeSuiteHome, makeCli, tryJson } = require('./_helpers/cli');

const SUITE_HOME = makeSuiteHome('exceptd-audit-usability-');
const cli = makeCli(SUITE_HOME);

// ===================================================================
// 1. Unknown-flag hard-fail (all verbs, not just doctor)
// ===================================================================









// ===================================================================
// 2. `--format json` returns the FULL run result (not a stub)
// ===================================================================


// ===================================================================
// 3. MULTI-FORMAT note to stderr
// ===================================================================


// ===================================================================
// 4. STANDARDIZED BUNDLES carry NO top-level `ok` key
// ===================================================================




// ===================================================================
// 5. `skill --help` / `framework-gap --help` honor --help;
//    refresh keeps its OWN detailed help
// ===================================================================




// ===================================================================
// 6. `collect` emits JSON when piped (non-TTY) so the documented pipe works
// ===================================================================


// ===================================================================
// 7. `refresh --check-advisories` parsing (no network — parseArgs directly)
// ===================================================================


// ===================================================================
// 8. `attest list --limit`
// ===================================================================

test('run --format json emits the full run result, not a stub', () => {
  const r = cli(['run', 'secrets', '--evidence', '-', '--format', 'json'], { input: '{}' });
  assert.equal(r.status, 0, `expected exit 0; got ${r.status} (stderr: ${r.stderr.slice(0, 200)})`);
  const body = tryJson(r.stdout.trim());
  assert.ok(body, `run --format json stdout must parse; got: ${r.stdout.slice(0, 200)}`);
  assert.equal(typeof body.phases, 'object');
  assert.ok(body.phases !== null, 'phases must not be null');
  assert.equal(body.playbook_id, 'secrets');
  assert.ok(Object.keys(body).length > 5,
    `full result must carry more than 5 top-level keys; got ${Object.keys(body).length}`);
});

test('multiple --format values: first format to stdout, note to stderr', () => {
  const r = cli(['run', 'secrets', '--evidence', '-', '--format', 'sarif', '--format', 'openvex'], { input: '{}' });
  assert.equal(r.status, 0, `expected exit 0; got ${r.status} (stderr: ${r.stderr.slice(0, 200)})`);
  const body = tryJson(r.stdout.trim());
  assert.ok(body, `stdout must parse as JSON; got: ${r.stdout.slice(0, 200)}`);
  // First format wins on stdout → SARIF carries a $schema.
  assert.equal(typeof body['$schema'], 'string');
  assert.match(body['$schema'], /sarif/);
  assert.match(r.stderr, /--format values given|bundles_by_format/);
});

test('sarif bundle: no top-level ok, carries spec marker', () => {
  // crypto gates on a Linux-platform precondition; satisfy it so the run
  // proceeds to emit a bundle regardless of the test host's OS.
  const r = cli(['run', 'crypto', '--evidence', '-', '--format', 'sarif'], { input: '{"precondition_checks":{"linux-platform":true}}' });
  assert.equal(r.status, 0, `expected exit 0; got ${r.status} (stderr: ${r.stderr.slice(0, 200)})`);
  const body = tryJson(r.stdout.trim());
  assert.ok(body, `sarif stdout must parse; got: ${r.stdout.slice(0, 200)}`);
  assert.equal(('ok' in body), false, 'standardized bundle must NOT carry a top-level ok key');
  assert.equal(body.version, '2.1.0');
  assert.ok(Array.isArray(body.runs), 'sarif must carry a runs array');
});

test('csaf-2.0 bundle: no top-level ok, carries document object', () => {
  const r = cli(['run', 'crypto', '--evidence', '-', '--format', 'csaf-2.0'], { input: '{"precondition_checks":{"linux-platform":true}}' });
  assert.equal(r.status, 0, `expected exit 0; got ${r.status} (stderr: ${r.stderr.slice(0, 200)})`);
  const body = tryJson(r.stdout.trim());
  assert.ok(body, `csaf stdout must parse; got: ${r.stdout.slice(0, 200)}`);
  assert.equal(('ok' in body), false, 'standardized bundle must NOT carry a top-level ok key');
  assert.equal(typeof body.document, 'object');
  assert.ok(body.document !== null, 'csaf document must not be null');
});

test('openvex bundle: no top-level ok, carries @context string', () => {
  const r = cli(['run', 'crypto', '--evidence', '-', '--format', 'openvex'], { input: '{"precondition_checks":{"linux-platform":true}}' });
  assert.equal(r.status, 0, `expected exit 0; got ${r.status} (stderr: ${r.stderr.slice(0, 200)})`);
  const body = tryJson(r.stdout.trim());
  assert.ok(body, `openvex stdout must parse; got: ${r.stdout.slice(0, 200)}`);
  assert.equal(('ok' in body), false, 'standardized bundle must NOT carry a top-level ok key');
  assert.equal(typeof body['@context'], 'string');
});
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});


// ---- routed from blamejs-scan-fixes ----
require("node:test").describe("blamejs-scan-fixes", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
/**
 * tests/blamejs-scan-fixes.test.js
 *
 * Pins the fixes a scan of the sibling blamejs repo surfaced:
 *  - playbooks that declare bundle_format "json" (secrets / cred-stores /
 *    runtime / citation-hygiene) now build a real structured-JSON evidence
 *    bundle instead of falling through to the "Unknown format" placeholder;
 *  - the crypto-codebase collector attests the playbook's own
 *    `repo-has-source-tree` gate (it previously emitted a `repo-context` key
 *    the playbook never references, so a source repo got a spurious
 *    precondition_unverified warning).
 * Exact-value pins, with content paired to presence per the project's
 * field-present-vs-field-populated rule.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const runner = require('../lib/playbook-runner.js');
const cryptoCodebase = require('../lib/collectors/crypto-codebase.js');
const containersCollector = require('../lib/collectors/containers.js');
const { makeSuiteHome, makeCli, tryJson } = require('./_helpers/cli');

const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'exceptd-dogfix2-'));
process.on('exit', () => { try { fs.rmSync(TMP, { recursive: true, force: true }); } catch { /* non-fatal */ } });
let _n = 0;
function mkfx() { const d = path.join(TMP, 'fx-' + _n++); fs.mkdirSync(d, { recursive: true }); return d; }

test('the run human render surfaces collector_warnings so a skip is not hidden behind "evidence: complete"', () => {
  // EXCEPTD_RAW_JSON='' forces the human render (the helper defaults it to '1').
  const cli = makeCli(makeSuiteHome());
  const ev = JSON.stringify({
    precondition_checks: { 'repo-context': true },
    signal_overrides: {},
    collector_errors: [{ kind: 'file_too_large_skipped', reason: 'api-snapshot.json: 1469464 bytes exceeds 1048576-byte scan limit; not scanned' }],
  });
  const human = cli(['run', 'secrets', '--evidence', '-'], { input: ev, env: { EXCEPTD_RAW_JSON: '' } });
  assert.ok(/Collector notices \(1\)/.test(human.stdout), 'human render lists collector notices');
  assert.ok(/file_too_large_skipped/.test(human.stdout), 'the skip kind is shown to the human reader');
  assert.ok(/api-snapshot\.json/.test(human.stdout), 'the skipped file is named');
});
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});


// ---- routed from bundle-and-doctor-correctness ----
require("node:test").describe("bundle-and-doctor-correctness", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
/**
 * Regression suite for a cluster found auditing the structured-bundle emitters
 * and the doctor subchecks:
 *
 *   CSAF threats text hard-coded "(CISA KEV)" for any confirmed-exploitation
 *     CVE, even when cisa_kev is false — operator-facing misattribution.
 *   SARIF/OpenVEX rendered the literal "null" for an unassessed blast_radius.
 *   SARIF cve_match results carried no locations, so GitHub Code Scanning
 *     silently dropped the highest-severity result class.
 *   An empty-vulnerabilities run emitted a csaf_security_advisory (Profile 4,
 *     where empty vulnerabilities is wrong) instead of csaf_informational.
 *   ci --format csaf/sarif/openvex wrapped documents in an exceptd envelope
 *     carrying a top-level `ok` key — invalid in all three standard formats.
 *   doctor --rfcs scraped table rows and undercounted the catalog, dropping
 *     non-RFC families; its freshness fields statted a nonexistent file.
 *
 * Discipline: exact values + types; presence paired with content.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");
const { ROOT, makeSuiteHome, makeCli, tryJson } = require("./_helpers/cli");

const cli = makeCli(makeSuiteHome("exceptd-bundledoc-"));

// sbom + package-matches-catalogued-cve fires CVE-2026-45321. The CSAF
// threats text once hard-coded "(CISA KEV)" for any confirmed-exploitation
// CVE; the invariant under test is that the attribution tracks the entry's
// live cisa_kev flag. The flag itself churns with reality (the automated
// KEV refresh flips it when CISA lists the CVE), so the assertion reads the
// catalog instead of pinning one value — pinning false broke the day CISA
// added the CVE to KEV.
const SBOM_CVE = JSON.stringify({ signal_overrides: { "package-matches-catalogued-cve": "hit" } });
const CVE_CATALOG = require(path.join(ROOT, "data", "cve-catalog.json"));
const MATCHED_ENTRY = CVE_CATALOG["CVE-2026-45321"];

test("CSAF threats text attributes '(CISA KEV)' if and only if the entry's cisa_kev flag is set", () => {
  const r = cli(["run", "sbom", "--evidence", "-", "--format", "csaf-2.0", "--json"], { input: SBOM_CVE });
  const doc = tryJson(r.stdout);
  assert.ok(doc && doc.document, "expected a CSAF document");
  const v = (doc.vulnerabilities || [])[0];
  assert.ok(v, "expected a vulnerability for the matched CVE");
  const details = (v.threats || []).map(t => t.details).join(" | ");
  if (MATCHED_ENTRY.active_exploitation === "confirmed") {
    assert.match(details, /Active exploitation confirmed/, "must state confirmed exploitation");
  }
  if (MATCHED_ENTRY.cisa_kev === true) {
    assert.match(details, /CISA KEV/, "must attribute to CISA KEV when cisa_kev is true");
  } else {
    assert.doesNotMatch(details, /CISA KEV/, "must NOT attribute to CISA KEV when cisa_kev is false");
  }
});

test("SARIF cve_match result carries locations and renders 'not assessed' for null blast_radius", () => {
  const r = cli(["run", "sbom", "--evidence", "-", "--format", "sarif", "--json"], { input: SBOM_CVE });
  const sarif = tryJson(r.stdout);
  assert.ok(sarif && sarif.version === "2.1.0", "expected SARIF 2.1.0");
  const results = sarif.runs?.[0]?.results || [];
  const cve = results.filter(x => x.properties?.kind === "cve_match");
  assert.ok(cve.length >= 1, "expected at least one cve_match result");
  for (const c of cve) {
    assert.ok(Array.isArray(c.locations) && c.locations.length >= 1, "cve_match result must carry locations (else GitHub Code Scanning drops it)");
    assert.ok(c.locations[0].physicalLocation?.artifactLocation?.uri, "location must have an artifact uri");
  }
  const withBlast = cve.find(c => /blast_radius/.test(c.message.text));
  assert.match(withBlast.message.text, /blast_radius not assessed/, "null blast_radius must render 'not assessed', not 'null'");
});

test("OpenVEX impact_statement renders 'not assessed' for null blast_radius (not 'null/5')", () => {
  const r = cli(["run", "sbom", "--evidence", "-", "--format", "openvex", "--json"], { input: SBOM_CVE });
  const vex = tryJson(r.stdout);
  assert.ok(vex && vex["@context"], "expected an OpenVEX document");
  const stmt = (vex.statements || []).find(s => /Blast radius/.test(s.impact_statement || ""));
  if (stmt) {
    assert.match(stmt.impact_statement, /Blast radius not assessed/, "null blast_radius must render 'not assessed'");
    assert.doesNotMatch(stmt.impact_statement, /null\/5/, "must not render 'null/5'");
  }
});

test("an empty-evidence run emits a csaf_informational_advisory, not a security_advisory with empty vulnerabilities", () => {
  const r = cli(["run", "crypto", "--evidence", "-", "--format", "csaf-2.0", "--json"], { input: '{"precondition_checks":{"linux-platform":true}}' });
  const doc = tryJson(r.stdout);
  assert.ok(doc && doc.document, "expected a CSAF document");
  assert.equal((doc.vulnerabilities || []).length, 0, "this run has no vulnerabilities");
  assert.equal(doc.document.category, "csaf_informational_advisory", "empty advisory must use the informational category");
});

test("a firing run still emits csaf_security_advisory", () => {
  const r = cli(["run", "sbom", "--evidence", "-", "--format", "csaf-2.0", "--json"], { input: SBOM_CVE });
  const doc = tryJson(r.stdout);
  assert.equal(doc.document.category, "csaf_security_advisory", "a run with vulnerabilities keeps the security-advisory category");
});
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});


// ---- routed from engine-hardening-and-help ----
require("node:test").describe("engine-hardening-and-help", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
/**
 * Regression suite for an engine-hardening + UX cluster:
 *
 *   Deeply-nested evidence overflowed the stack (canonicalStringify recursion
 *     runs on every run via evidence_hash) with an opaque "internal error";
 *     it is now rejected at a bounded depth with an actionable message.
 *   --strict-preconditions missed a false skip_phase precondition (verdict
 *     skipped, exit 0) — a CI gate silently passed. It now fails (exit 1).
 *   A signal_overrides value that doesn't canonicalize (e.g. "maybe") was
 *     silently dropped; it now surfaces a runtime_error.
 *   A not_detected/clean classification override that would bury a
 *     DETERMINISTIC hit is refused (substituted inconclusive) and no longer
 *     reported as classification_override_applied. A probabilistic hit's
 *     confirm-benign override is still honored.
 *   run --all swallowed a mid-batch session-id collision (exit 0); it now
 *     surfaces exit 7 like the single-run path.
 *   watch --help started the blocking daemon (hung the terminal); collect
 *     --help had no content. Both now print usage.
 *
 * Discipline: exact exit codes; value + type assertions.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { makeSuiteHome, makeCli, tryJson } = require("./_helpers/cli");

const cli = makeCli(makeSuiteHome("exceptd-enginehard-"));

test("deeply-nested evidence is rejected with an actionable message, not a stack overflow", () => {
  let o = { x: 1 };
  for (let i = 0; i < 3000; i++) o = { n: o };
  const r = cli(["run", "secrets", "--evidence", "-", "--json"], { input: JSON.stringify({ signal_overrides: { "aws-access-key-id": o } }) });
  const body = tryJson(r.stdout) || tryJson(r.stderr);
  assert.ok(body && body.ok === false, "must reject, not crash");
  assert.match(body.error, /nesting exceeds the maximum depth/, "must name the depth limit");
});

test("--strict-preconditions fails (exit 1) on a false skip_phase precondition", () => {
  const r = cli(["run", "mcp", "--evidence", "-", "--strict-preconditions", "--json"],
    { input: JSON.stringify({ precondition_checks: { "any-ai-coding-assistant-installed": false } }) });
  assert.equal(r.status, 1, "a false skip precondition under --strict-preconditions must fail");
  const body = tryJson(r.stdout);
  assert.ok(body && Array.isArray(body.strict_preconditions_violated), "must surface the violation list");
  assert.ok(body.strict_preconditions_violated.some(v => v.kind === "precondition_skip"), "the skip must be in the violation list");
});

test("an unrecognized signal_overrides value surfaces a runtime_error (not silently dropped)", () => {
  const r = cli(["run", "secrets", "--evidence", "-", "--json"], { input: JSON.stringify({ signal_overrides: { "aws-access-key-id": "maybe" } }) });
  const j = tryJson(r.stdout);
  const kinds = (j.phases.analyze.runtime_errors || []).map(e => e.kind);
  assert.ok(kinds.includes("signal_override_unrecognized"), `expected signal_override_unrecognized; got ${JSON.stringify(kinds)}`);
});

test("a not_detected override is refused when it would mask a deterministic hit", () => {
  const r = cli(["run", "secrets", "--evidence", "-", "--json"], { input: JSON.stringify({ signal_overrides: { "aws-access-key-id": "hit" }, signals: { detection_classification: "not_detected" } }) });
  const j = tryJson(r.stdout);
  assert.equal(j.phases.analyze._detect_classification, "inconclusive", "deterministic hit must not be downgraded to not_detected");
  assert.equal(j.phases.detect.classification_override_applied, null, "a refused override must not be reported as applied");
  const kinds = (j.phases.analyze.runtime_errors || []).map(e => e.kind);
  assert.ok(kinds.includes("classification_override_masks_deterministic_hit"), "must explain the refusal");
});

test("a probabilistic hit's not_detected confirm-benign override is still honored", () => {
  const r = cli(["run", "secrets", "--evidence", "-", "--json"], { input: JSON.stringify({ signal_overrides: { "jwt-token-with-secret-context": "hit" }, signals: { detection_classification: "not_detected" } }) });
  const j = tryJson(r.stdout);
  assert.equal(j.phases.analyze._detect_classification, "not_detected", "a probabilistic hit remains overridable");
  assert.equal(j.phases.detect.classification_override_applied, "not_detected", "the honored override is reported as applied");
});

test("run --all surfaces exit 7 when a reused --session-id collides across the whole batch", () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "exceptd-batchcol-"));
  try {
    const env = { EXCEPTD_HOME: home };
    const first = cli(["run", "--scope", "code", "--evidence", "-", "--session-id", "fixedsid123", "--json"], { input: "{}", env });
    // first run persists; some playbooks may be clean — that's fine.
    assert.ok(first.status === 0 || first.status === 2, `first run should succeed/escalate; got ${first.status}`);
    const second = cli(["run", "--scope", "code", "--evidence", "-", "--session-id", "fixedsid123", "--json"], { input: "{}", env });
    assert.equal(second.status, 7, "a batch re-run with a reused session-id must exit 7 (session-id collision), not 0");
  } finally {
    fs.rmSync(home, { recursive: true, force: true });
  }
});
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});


// ---- routed from error-ux-hardening ----
require("node:test").describe("error-ux-hardening", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
/**
 * Error-UX hardening regression suite.
 *
 * Pins the operator-facing error improvements: a case-only playbook typo gets a
 * suggestion, input-validation errors are not mislabeled "internal error", the
 * `ask` verb points a CVE/RFC question at the resolver, and the CVE
 * malformed-id message is accurate for a short year (not just a non-numeric
 * tail). All offline + deterministic.
 *
 * Discipline: exact exit codes; value/type assertions paired with presence.
 */

const test = require("node:test");
const assert = require("node:assert/strict");

const { makeSuiteHome, makeCli, tryJson } = require("./_helpers/cli");
const SUITE_HOME = makeSuiteHome("exceptd-erruxe-");
const cli = makeCli(SUITE_HOME);

test("run SECRETS (case-only typo) → invalid-id error WITH a did-you-mean suggestion", () => {
  const r = cli(["run", "SECRETS"]);
  assert.equal(r.status, 1);
  const body = tryJson(r.stderr);
  assert.ok(body && body.ok === false, `expected ok:false body; got ${r.stderr.slice(0, 200)}`);
  assert.match(body.error, /invalid <playbook> id/);
  assert.match(body.error, /Did you mean: secrets\?/);
  assert.ok(Array.isArray(body.did_you_mean) && body.did_you_mean.includes("secrets"));
});
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});


// ---- routed from hard-rule-forcing-functions ----
require("node:test").describe("hard-rule-forcing-functions", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
/**
 * tests/hard-rule-forcing-functions.test.js
 *
 * Cycle 16 audit fix (v0.12.36): closes 3 gaps in AGENTS.md Hard Rule
 * forcing-function coverage. Without these tests the rules were
 * policy-only — a future PR could violate them and the CI gate would
 * stay green.
 *
 *   Rule #3 (no CVSS-only risk scoring): every non-draft CVE in
 *     data/cve-catalog.json must declare rwep_score + rwep_factors.
 *
 *   Rule #5 (global-first, not US-centric): the framework-control-gaps
 *     catalog must carry entries for EU + UK + AU + INTL alongside US.
 *
 *   Rule #8 (Pinned ATLAS version): manifest.json's atlas_version field
 *     must equal data/atlas-ttps.json._meta.atlas_version exactly, and
 *     same for attack_version. Pre-cycle-9 these drifted silently.
 *
 *   Cross-format CVE consistency: CSAF + OpenVEX + SARIF emitters must
 *     agree on the catalogued-CVE set per playbook run.
 *
 * Per the anti-coincidence rule, every assertion checks an EXACT
 * value (deep-equality or specific count).
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');
const manifest = JSON.parse(fs.readFileSync(path.join(ROOT, 'manifest.json'), 'utf8'));
const cve = JSON.parse(fs.readFileSync(path.join(ROOT, 'data', 'cve-catalog.json'), 'utf8'));
const gaps = JSON.parse(fs.readFileSync(path.join(ROOT, 'data', 'framework-control-gaps.json'), 'utf8'));
const atlas = JSON.parse(fs.readFileSync(path.join(ROOT, 'data', 'atlas-ttps.json'), 'utf8'));
const attack = JSON.parse(fs.readFileSync(path.join(ROOT, 'data', 'attack-techniques.json'), 'utf8'));


function frameworkRegion(frameworkText) {
  if (!frameworkText) return 'OTHER';
  if (/NIST|FedRAMP|CMMC|HIPAA|HITRUST|PCI|SOC|CIS Controls|OFAC|SEC|NYDFS|CIRCIA/i.test(frameworkText)) return 'US';
  if (/NIS2|DORA|GDPR|^EU |EU-|ENISA|CRA |AI Act|EU 2014\/833/i.test(frameworkText)) return 'EU';
  if (/\b(?:UK|CAF|Ofcom|NCSC|OFSI|UK-GDPR)\b/i.test(frameworkText)) return 'UK';
  if (/\b(?:AU|ACSC|ISM|Essential 8|APRA|eSafety|AU NDB)\b/i.test(frameworkText)) return 'AU';
  if (/\b(?:ISO|IEC \d|3GPP|GSMA|ITU|FCC|TSA|OWASP|SLSA|CycloneDX|SPDX)\b/i.test(frameworkText)) return 'INTL';
  return 'OTHER';
}

test('Cross-format CVE consistency — CSAF + OpenVEX + SARIF agree on the catalogued-CVE set per playbook run', () => {
  const { spawnSync } = require('node:child_process');
  const os = require('node:os');
  const evidence = JSON.stringify({
    precondition_checks: { 'linux-platform': true, 'uname-available': true },
    artifacts: { 'kernel-release': '5.15.0-69-generic' },
    signal_overrides: { 'kver-in-affected-range': 'hit' },
  });
  const evFile = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'cycle16-')), 'ev.json');
  fs.writeFileSync(evFile, evidence);
  try {
    const CLI = path.join(ROOT, 'bin', 'exceptd.js');
    function runFmt(fmt) {
      const r = spawnSync(process.execPath, [CLI, 'run', 'kernel', '--evidence', evFile, '--format', fmt], {
        encoding: 'utf8', cwd: ROOT,
        env: { ...process.env, EXCEPTD_DEPRECATION_SHOWN: '1' },
      });
      assert.equal(r.status, 0, `${fmt} run must exit 0; got ${r.status}, stderr: ${r.stderr.slice(0, 200)}`);
      return JSON.parse(r.stdout);
    }
    const csaf = runFmt('csaf');
    const openvex = runFmt('openvex');
    const sarif = runFmt('sarif');

    const csafCves = new Set((csaf.vulnerabilities || []).map(v => v.cve).filter(Boolean));
    const openvexCves = new Set(
      (openvex.statements || [])
        .map(s => s?.vulnerability?.['@id'])
        .filter((id) => typeof id === 'string' && id.startsWith('urn:cve:'))
        .map((id) => id.replace(/^urn:cve:/, '').toUpperCase()),
    );
    const sarifCves = new Set(
      (sarif.runs || []).flatMap(r => (r.results || []).map(rr => rr.ruleId).filter(Boolean))
        .filter((rid) => /CVE-/.test(rid))
        .map((rid) => rid.replace(/^kernel\//, '')),
    );

    assert.deepEqual([...csafCves].sort(), [...openvexCves].sort(),
      `CSAF vs OpenVEX CVE set divergence. CSAF: ${[...csafCves].sort().join(',')} | OpenVEX: ${[...openvexCves].sort().join(',')}`);
    assert.deepEqual([...csafCves].sort(), [...sarifCves].sort(),
      `CSAF vs SARIF CVE set divergence. CSAF: ${[...csafCves].sort().join(',')} | SARIF: ${[...sarifCves].sort().join(',')}`);
  } finally {
    try { fs.unlinkSync(evFile); } catch {}
  }
});

;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});


// ---- routed from operator-bugs ----
require("node:test").describe("operator-bugs", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
/**
 * Operator-reported bug regression suite.
 *
 * Every operator-reported bug that has been fixed lands here as a named test
 * case so re-introductions surface at `npm test`, not at user re-report.
 * Numbering matches the operator report sequence (items #1 through #N as
 * reported across the v0.9.5 → v0.11.x arc).
 *
 * Pattern for new items:
 *   describe('#N short label', () => { it('precise behavior', ...); });
 *
 * Avoid coupling tests to file paths / playbook IDs that may change. Prefer
 * direct runner exercises over CLI shell-outs where possible — CLI tests
 * stay narrow (smoke-level) because they spawn subprocesses and slow the
 * suite down.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const fs = require('node:fs');
const { spawnSync } = require('node:child_process');

const { ROOT, CLI, makeSuiteHome, makeCli, tryJson, secureTmpFile } = require('./_helpers/cli');
const runner = require(path.join(ROOT, 'lib', 'playbook-runner.js'));

const SUITE_HOME = makeSuiteHome('exceptd-operator-bugs-');
const cli = makeCli(SUITE_HOME);

// ===================================================================








// ===================================================================





// ===================================================================

// ===================================================================



// ===================================================================



// ===================================================================




// ===================================================================


// ===================================================================

// ===================================================================
// CSAF framework gaps emit as `document.notes[]` with `category: details`,
// not as `vulnerabilities[]` entries with `ids: [{system_name:
// 'exceptd-framework-gap'}]`. The `system_name` slot is reserved for
// recognised vulnerability tracking authorities (CVE, GHSA, etc.); the
// custom string is rejected by NVD / ENISA / Red Hat dashboards. Notes
// are the right home for advisory context, not pseudo-CVEs. The test
// asserts the notes-based shape and anti-asserts the pseudo-vulnerability
// shape.









// ===================================================================







// ===================================================================





// ===================================================================















// ===================================================================
// v0.11.14 freshness additions — opt-in registry check + upstream-check
// + refresh --network. Tests use EXCEPTD_REGISTRY_FIXTURE so they're
// fully offline-deterministic.
// ===================================================================

function withFixture(version, daysAgo) {
  const file = secureTmpFile('npm-fixture.json', 'npm-fixture-');
  const publishedAt = new Date(Date.now() - daysAgo * 24 * 3600 * 1000).toISOString();
  fs.writeFileSync(file, JSON.stringify({
    "dist-tags": { latest: version },
    version,
    time: { [version]: publishedAt, modified: publishedAt },
  }));
  return file;
}








// ===================================================================
// v0.12.0 — GHSA source + refresh --advisory + refresh --curate
// ===================================================================













// ===================================================================

test('#31 session-id collision refused without --force-overwrite', () => {
  // First run creates the attestation.
  const sid = 'regressionsess-' + Date.now();
  const sub = JSON.stringify({ observations: {}, verdict: { classification: 'not_detected' } });
  const r1 = cli(['run', 'library-author', '--evidence', '-', '--session-id', sid], { input: sub });
  assert.equal(r1.status, 0, 'first run must succeed');
  // Second run with same session-id should be refused.
  const r2 = cli(['run', 'library-author', '--evidence', '-', '--session-id', sid], { input: sub });
  // Session-id collision without --force-overwrite sets
  // process.exitCode = EXIT_CODES.SESSION_ID_COLLISION (= 7) in cmdRun.
  // Pre-v0.12.24 this was 3, but exit 3 also meant "ran-but-no-evidence"
  // in cmdCi — two semantics for one code. v0.12.24 split them so callers
  // can distinguish collision (retry with fresh --session-id) from missing
  // evidence (retry with stdin).
  assert.equal(r2.status, 7, 'second run must exit 7 (SESSION_ID_COLLISION)');
  const err = tryJson(r2.stderr.trim());
  assert.ok(err, 'refusal should be JSON');
  assert.match(err.error, /Session-id collision|already exists/);
});

test('#32 --mode validates against accepted set', () => {
  const r = cli(['run', 'library-author', '--evidence', '-', '--mode', 'garbage'], { input: '{}' });
  // Pin the exact non-zero code (1 = run-arg validation rejection) so a
  // future regression that flips this verb to "exit 2 from generic parseArgs"
  // or worse "silently accepts garbage and exits 0" doesn't slip by as
  // "still non-zero, looks fine."
  assert.equal(r.status, 1, '--mode rejection must exit 1');
  const err = tryJson(r.stderr.trim());
  assert.ok(err, 'rejection must be parseable JSON');
  assert.equal(err.ok, false, 'body must carry ok:false');
  assert.match(err.error, /--mode .* not in accepted set/,
    'error must name the flag and the "accepted set" phrase so the operator can self-correct without grepping the source');
  assert.equal(err.provided, 'garbage', 'rejected value must echo back so operators see what was rejected');
});

test('#33 --session-key must be hex', () => {
  const r = cli(['run', 'library-author', '--evidence', '-', '--session-key', 'zzzznothex'], { input: '{}' });
  assert.equal(r.status, 1, '--session-key rejection must exit 1');
  const err = tryJson(r.stderr.trim());
  assert.ok(err, 'rejection must be parseable JSON');
  assert.equal(err.ok, false, 'body must carry ok:false');
  assert.match(err.error, /--session-key must be hex/,
    'error must name the flag and the hex requirement so operators see the exact constraint, not a generic "invalid argument"');
});

test('help deprecation pointer for prefetch names the cache-population equivalent', () => {
  // `prefetch.js --no-network` is a report-only dry run, so a deprecation
  // pointer reading `prefetch → refresh --no-network` sent operators to a
  // command that populates nothing. The behavior-equivalent replacement is
  // `refresh --prefetch` (dispatch strips the alias flag and runs the same
  // cache population as bare `prefetch`). Pin the corrected pointer so a
  // future help-text edit can't reintroduce the dry-run pointer.
  const r = cli(['help']);
  const out = `${r.stdout}${r.stderr}`;
  assert.doesNotMatch(out, /prefetch\s+→\s+refresh --no-network/,
    'help must not point prefetch users at the report-only dry-run form');
  assert.match(out, /prefetch\s+→\s+refresh --prefetch/,
    'help must point prefetch users at refresh --prefetch, the cache-population equivalent');
});

test('#76 run --format garbage returns structured JSON error', () => {
  const r = cli(['run', 'library-author', '--evidence', '-', '--format', 'garbage'], { input: '{}' });
  // emitError() sets process.exitCode = 1 universally (bin/exceptd.js:640).
  // Pinning to 1 catches the regression where this verb starts routing
  // through a path that exits 2 (unknown-verb) or 0 (silent acceptance).
  assert.equal(r.status, 1, '--format garbage must exit 1 (emitError path)');
  const err = tryJson(r.stderr.trim()) || tryJson(r.stdout.trim());
  assert.ok(err && err.ok === false, 'output must include {ok:false} JSON error');
  assert.match(err.error, /not in accepted set/);
});

test('#82 SARIF bundle via CLI includes indicator results when one fires', () => {
  const sub = JSON.stringify({
    observations: { w: { captured: true, indicator: 'publish-workflow-uses-static-token', result: 'hit' } },
    verdict: {}
  });
  const r = cli(['run', 'library-author', '--evidence', '-', '--format', 'sarif', '--json'], { input: sub });
  assert.equal(r.status, 0);
  const data = tryJson(r.stdout);
  assert.ok(data, 'sarif output should be JSON');
  assert.equal(data.version, '2.1.0');
  // Pre-strengthening: "some result has kind=indicator_hit" passed even if
  // the result was for a DIFFERENT indicator than the one operator declared
  // hit. The bug class: a runner that emits indicator_hit for every declared
  // indicator regardless of the submission still passes that loose check.
  // Strengthening: assert exactly one result matches BOTH ruleId=the
  // specific indicator we declared hit AND kind=indicator_hit. That pins
  // the runner to "operator submission drove this result," not "the runner
  // emits indicator_hit unconditionally."
  const results = data.runs?.[0]?.results || [];
  // SARIF ruleIds are playbook-prefixed (`<playbook-slug>/<rule>`) so
  // cross-playbook merges don't dedupe by ruleId. Match on the suffix
  // instead of an exact equality.
  const matching = results.filter(res =>
    /(?:^|\/)publish-workflow-uses-static-token$/.test(String(res.ruleId)) &&
    res.properties?.kind === 'indicator_hit'
  );
  assert.equal(matching.length, 1,
    `exactly one SARIF result must match ruleId=publish-workflow-uses-static-token AND kind=indicator_hit — got ${matching.length}. Pre-strengthening "some result with kind=indicator_hit" allowed a runner regression that emits indicator_hit for every indicator regardless of the submitted result.`);
});

test('#82 CSAF bundle via CLI includes indicator vulnerabilities', () => {
  const sub = JSON.stringify({
    observations: { w: { captured: true, indicator: 'publish-workflow-uses-static-token', result: 'hit' } },
    verdict: {}
  });
  const r = cli(['run', 'library-author', '--evidence', '-', '--format', 'csaf-2.0', '--json'], { input: sub });
  const data = tryJson(r.stdout);
  assert.ok(data, 'csaf output should be JSON');
  assert.equal(data.document?.csaf_version, '2.0');
  assert.ok(Array.isArray(data.vulnerabilities));
  // Pre-strengthening: "vulnerabilities.length > 0" passed when the bundle
  // emitted only framework-gap entries (system_name='exceptd-framework-gap')
  // and zero indicator entries — which is the very regression #82 was filed
  // about. Indicator hits must surface as their own vulnerability rows with
  // system_name='exceptd-indicator' so CSAF consumers don't conflate them
  // with framework-control gaps.
  const indicatorVulns = data.vulnerabilities.filter(v =>
    Array.isArray(v.ids) && v.ids.some(id => id.system_name === 'exceptd-indicator')
  );
  assert.ok(indicatorVulns.length > 0,
    `CSAF vulnerabilities must include at least one entry whose ids[].system_name === "exceptd-indicator"; got ${indicatorVulns.length}. Framework gaps (system_name=exceptd-framework-gap) alone are not sufficient.`);
});

test('#82 OpenVEX bundle via CLI includes indicator statements', () => {
  const sub = JSON.stringify({
    observations: { w: { captured: true, indicator: 'publish-workflow-uses-static-token', result: 'hit' } },
    verdict: {}
  });
  const r = cli(['run', 'library-author', '--evidence', '-', '--format', 'openvex', '--json'], { input: sub });
  const data = tryJson(r.stdout);
  assert.ok(data, 'openvex output should be JSON');
  assert.match(data['@context'] || '', /openvex/);
  // v0.12.12 (B4): indicator statements now live under the registered URN
  // namespace `urn:exceptd:indicator:<playbook>:<indicator-id>` rather than
  // the unregistered `exceptd:` scheme. Framework gaps are no longer emitted
  // into the VEX feed at all (v0.12.12 B3) — they're control-design
  // observations, not vulnerabilities. The substantive #82 guarantee
  // remains: a real indicator hit MUST produce at least one VEX statement
  // so playbooks with empty cve_refs still emit a usable bundle.
  const indicatorStatements = (data.statements || []).filter(s => {
    const vid = s.vulnerability?.['@id'] || '';
    return vid.startsWith('urn:exceptd:indicator:');
  });
  assert.ok(indicatorStatements.length >= 1,
    `OpenVEX must include at least one indicator statement (vulnerability.@id prefixed "urn:exceptd:indicator:<playbook>:"); got ${indicatorStatements.length}.`);
});

test('#91 CSAF emits framework_gap_mapping as document.notes (not pseudo-vulnerabilities)', () => {
  const sub = JSON.stringify({
    observations: { w: { captured: true, indicator: 'publish-workflow-uses-static-token', result: 'hit' } }
  });
  const r = cli(['run', 'library-author', '--evidence', '-', '--format', 'csaf-2.0', '--json'], { input: sub });
  const data = tryJson(r.stdout);
  assert.ok(data, 'csaf output should be JSON');
  // Anti-assertion: gaps no longer ride in vulnerabilities[].
  const fwGapVulns = (data.vulnerabilities || []).filter(v =>
    (v.ids || []).some(id => id.system_name === 'exceptd-framework-gap')
  );
  assert.equal(fwGapVulns.length, 0,
    'framework gaps must NOT appear as vulnerabilities[] entries — they pollute downstream CSAF consumers');
  // Positive assertion: gaps land in document.notes[].
  // A separate `category: general` note may also appear when no
  // --publisher-namespace was supplied. Filter to category=details
  // before counting + asserting the framework-gap content shape.
  const notes = data?.document?.notes || [];
  assert.ok(Array.isArray(notes), 'document.notes must be an array');
  const gapNotes = notes.filter(n => n.category === 'details');
  assert.ok(gapNotes.length >= 1, 'library-author playbook surfaces at least one framework gap as a category=details note');
  for (const n of gapNotes) {
    assert.equal(n.category, 'details', 'framework-gap notes use category: details');
    assert.ok(typeof n.text === 'string' && n.text.length > 0,
      'each framework-gap note must carry a non-empty text body');
  }
});

test('#91 OpenVEX excludes framework_gap_mapping statements (v0.12.12 B3)', () => {
  // v0.12.12 (B3): framework gaps are control-design observations, not
  // vulnerabilities. They were polluting the OpenVEX feed because pre-fix
  // every gap was emitted as a statement with an unregistered
  // `exceptd:framework-gap:` `@id` scheme. They remain in CSAF (as
  // informational notes) and SARIF (rules with `kind: informational`),
  // but downstream supply-chain VEX consumers should never receive them.
  const sub = JSON.stringify({
    observations: { w: { captured: true, indicator: 'publish-workflow-uses-static-token', result: 'hit' } }
  });
  const r = cli(['run', 'library-author', '--evidence', '-', '--format', 'openvex', '--json'], { input: sub });
  const data = tryJson(r.stdout);
  assert.ok(data, 'openvex output should be JSON');
  const fwGapStatements = (data.statements || []).filter(s => {
    const vid = String(s.vulnerability?.['@id'] || '');
    return vid.includes('framework-gap');
  });
  assert.equal(fwGapStatements.length, 0,
    'OpenVEX must NOT include framework-gap statements; they pollute the supply-chain VEX feed.');
});

test('#92 CSAF tracking.current_release_date is non-null', () => {
  const sub = JSON.stringify({});
  const r = cli(['run', 'library-author', '--evidence', '-', '--format', 'csaf-2.0', '--json'], { input: sub });
  const data = tryJson(r.stdout);
  const ts = data?.document?.tracking?.current_release_date;
  // CSAF 2.0 §3.2.1.12 requires this field to be an ISO 8601 timestamp,
  // not just truthy. Pre-strengthening, the assertion accepted any non-empty
  // string (including "TBD", "pending", or an empty object cast to "[object
  // Object]") — the v0.11.10 field-present-but-not-spec-conformant bug
  // class. Validators downstream reject anything that doesn't parse as a
  // date, so pin the shape AT EMIT time, not after the operator reports it.
  assert.equal(typeof ts, 'string',
    `current_release_date must be a string per CSAF 2.0 §3.2.1.12; got ${typeof ts}`);
  assert.match(ts, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}/,
    `current_release_date must be ISO 8601 (YYYY-MM-DDTHH:MM…); got ${JSON.stringify(ts)}`);
  // Also confirm Date.parse round-trips so we catch "looks-like-ISO but
  // semantically invalid" cases (e.g. month=13).
  assert.ok(!Number.isNaN(Date.parse(ts)),
    `current_release_date must round-trip through Date.parse; got ${JSON.stringify(ts)}`);
});

test('#93 SARIF defines every rule referenced by ruleId', () => {
  const sub = JSON.stringify({
    observations: { w: { captured: true, indicator: 'publish-workflow-uses-static-token', result: 'hit' } }
  });
  const r = cli(['run', 'library-author', '--evidence', '-', '--format', 'sarif', '--json'], { input: sub });
  const data = tryJson(r.stdout);
  const rules = new Set((data.runs?.[0]?.tool?.driver?.rules || []).map(x => x.id));
  const results = data.runs?.[0]?.results || [];
  const missingDefs = [...new Set(results.map(r => r.ruleId))].filter(id => !rules.has(id));
  assert.equal(missingDefs.length, 0,
    `SARIF spec §3.27.3: every referenced ruleId must have a rule definition. Missing: ${JSON.stringify(missingDefs)}`);
});

test('#96 --strict-preconditions exits 1 on warn-level preconditions', () => {
  // secrets has a regex-engine (on_fail: warn) precondition. Without
  // --strict-preconditions, exit 0. With it, exit 1.
  const sub = JSON.stringify({});
  const rDefault = cli(['run', 'secrets', '--evidence', '-'], { input: sub });
  assert.equal(rDefault.status, 0, 'default mode: warn-level precondition exits 0');
  const rStrict = cli(['run', 'secrets', '--evidence', '-', '--strict-preconditions'], { input: sub });
  assert.equal(rStrict.status, 1, '--strict-preconditions: warn-level precondition exits 1');
});

test('#100 ok:false from preflight-halt exits non-zero', () => {
  // Kernel-on-Windows triggers linux-platform halt → ok:false → exit 1.
  // Locks in the exit-code contract: any result.ok === false maps to exit 1.
  // On Linux: ok:true exit 0. On Windows/macOS: ok:false exit 1.
  // The contract: exactly one of those two branches must hold — silent
  // pass when JSON didn't parse at all is the regression worth catching
  // (and pre-strengthening was exactly that silent fall-through).
  const sub = JSON.stringify({});
  const r = cli(['run', 'kernel', '--evidence', '-'], { input: sub });
  const data = tryJson(r.stdout) || tryJson(r.stderr);
  assert.ok(data, `run kernel must emit parseable JSON in either ok:true or ok:false branch. stdout=${JSON.stringify(r.stdout.slice(0,200))} stderr=${JSON.stringify(r.stderr.slice(0,200))}`);
  assert.notEqual(data.ok, undefined,
    'data.ok must be present (true or false) — undefined means the runner emitted a body without the contract field');
  if (data.ok === false) {
    // emit() universal contract (bin/exceptd.js:615) sets exitCode = 1
    // whenever the emitted body has ok:false, unless a caller already
    // chose a different non-zero code. Pin to 1 — notEqual(0) would
    // silently pass if a future regression swapped to exit 2 (which
    // collides with the "unknown verb" code).
    assert.equal(r.status, 1, 'ok:false must exit 1 (universal emit() contract)');
  } else {
    assert.equal(data.ok, true, 'data.ok must be strictly true or false, never another truthy value');
    assert.equal(r.status, 0, 'ok:true must exit 0 (contract: ok:true ↔ exit 0)');
  }
});

test('#100 warn-level preconditions do NOT block (run completes ok:true exit 0)', () => {
  // secrets has on_fail: warn preconditions (regex-engine). With empty
  // evidence and no --strict-preconditions, the run MUST complete ok:true
  // exit 0 — warn-level issues populate preflight_issues but don't fail.
  // Pre-strengthening, this only checked `if (data.ok===true) assert.equal
  // status 0`, which would have silently passed if the runner crashed
  // before emitting JSON (data=null → branch never taken). Hard-assert
  // both contract sides unconditionally.
  const sub = JSON.stringify({});
  const r = cli(['run', 'secrets', '--evidence', '-'], { input: sub });
  const data = tryJson(r.stdout);
  assert.ok(data, 'secrets run must emit parseable JSON to stdout');
  assert.equal(data.ok, true,
    'warn-level preconditions are non-blocking by default — run must complete ok:true');
  assert.equal(r.status, 0,
    'warn-level run with ok:true must exit 0 — flipping to non-zero would re-introduce the very behavior --strict-preconditions was added to opt INTO');
});

test('#100 --strict-preconditions escalates warn-level to exit 1', () => {
  // Pre-stage a submission that GUARANTEES at least one preflight issue:
  // submit precondition_checks.regex-engine=false explicitly. This dodges
  // any autoDetect path that might silently populate the check on hosts
  // where pcre support is present. Without this pre-stage, the original
  // test silently passed on machines where preflight_issues happened to
  // be empty — the staged condition never reproduced, the `if` never
  // fired, the assertion was a no-op (Hard Rule #11 violation).
  const sub = JSON.stringify({ precondition_checks: { 'regex-engine': false } });
  const r = cli(['run', 'secrets', '--evidence', '-', '--strict-preconditions'], { input: sub });
  const data = tryJson(r.stdout) || tryJson(r.stderr);
  assert.ok(data, '--strict-preconditions run must still emit JSON (just to a non-zero exit)');
  assert.ok(Array.isArray(data.preflight_issues),
    'preflight_issues must be present as an array on a --strict-preconditions run');
  assert.ok(data.preflight_issues.length >= 1,
    `with regex-engine:false pre-staged, preflight_issues MUST contain ≥1 entry; got ${data.preflight_issues.length}. If 0, the runner silently dropped the staged precondition check — that's the bug.`);
  assert.equal(r.status, 1,
    '--strict-preconditions must exit exactly 1 when preflight issues are present (NOT 0, NOT 2 — 1 is the warn-escalation code)');
});

test('#104 jurisdiction clocks fire on detected classification (with --ack — E7: operator awareness starts the clock)', () => {
  // E7: pre-fix the engine auto-stamped clock_started_at = now whenever
  // classification was 'detected', even without operator awareness. AGENTS.md
  // Phase 7 binds the clock to operator awareness (typically --ack). This
  // test now passes --ack so the clock legitimately starts.
  const sub = JSON.stringify({
    secrets: {
      observations: { w: { captured: true, value: 'AKIA', indicator: 'aws-access-key-id', result: 'hit' } },
      verdict: { classification: 'detected', blast_radius: 4 }
    }
  });
  const tmpFile = secureTmpFile('ev.json', 'civ-');
  fs.writeFileSync(tmpFile, sub);
  const r = cli(['ci', '--required', 'secrets', '--evidence', tmpFile, '--ack', '--json']);
  fs.unlinkSync(tmpFile);
  const data = tryJson(r.stdout);
  assert.ok(data, 'ci output should be JSON');
  assert.ok(data.summary.jurisdiction_clocks_started >= 1,
    'detected classification with detect_confirmed obligations should fire at least one jurisdiction clock');
  // Pre-strengthening, the count check passed even if the clocks_started
  // counter was a stale integer with no underlying obligations (field-
  // populated-but-content-empty class). Drill into the result the count
  // SHOULD be derived from and verify the EU jurisdiction (GDPR/NIS2) is
  // present — secrets stages multiple EU obligations under detect_confirmed,
  // so absent that, the counter is lying.
  const result = data.results?.[0];
  assert.ok(result, 'ci must surface per-playbook results so the counter can be cross-checked');
  const obligations = result.phases?.govern?.jurisdiction_obligations || [];
  assert.ok(Array.isArray(obligations) && obligations.length > 0,
    'govern.jurisdiction_obligations must be a non-empty array — that is what jurisdiction_clocks_started is counting against');
  const euOblig = obligations.filter(o => o.jurisdiction === 'EU');
  assert.ok(euOblig.length >= 1,
    `secrets stages EU obligations (GDPR Art.33, NIS2 Art.23) under detect_confirmed — at least one must be present; got jurisdictions=${JSON.stringify([...new Set(obligations.map(o => o.jurisdiction))])}`);
});

test('#113 --operator surfaces in run result top-level', () => {
  const r = cli(['run', 'library-author', '--evidence', '-', '--operator', 'robert@example.com', '--session-id', 'oper113-' + Date.now(), '--force-overwrite', '--json'], { input: '{}' });
  const data = tryJson(r.stdout);
  assert.ok(data, 'run output should be JSON');
  assert.equal(data.operator, 'robert@example.com',
    '--operator must surface at result.operator (pre-0.11.9 was attestation-only)');
});

test('#114 --ack surfaces in run result top-level', () => {
  const r = cli(['run', 'library-author', '--evidence', '-', '--ack', '--session-id', 'ack114-' + Date.now(), '--force-overwrite', '--json'], { input: '{}' });
  const data = tryJson(r.stdout);
  assert.ok(data, 'run output should be JSON');
  assert.ok(data.operator_consent && data.operator_consent.explicit === true,
    '--ack must surface at result.operator_consent.explicit');
});

test('#119 result.ack alias for --ack consent state', () => {
  const r = cli(['run', 'library-author', '--evidence', '-', '--ack', '--session-id', 'ack119-' + Date.now(), '--force-overwrite', '--json'], { input: '{}' });
  const data = tryJson(r.stdout);
  assert.equal(data?.ack, true, 'result.ack must be true when --ack is passed');
  assert.equal(data?.operator_consent?.explicit, true, 'operator_consent.explicit also true');
});

test('#119 result.ack is false without --ack', () => {
  const r = cli(['run', 'library-author', '--evidence', '-', '--session-id', 'noack-' + Date.now(), '--force-overwrite', '--json'], { input: '{}' });
  const data = tryJson(r.stdout);
  assert.equal(data?.ack, false, 'result.ack must be false without --ack');
});

test('#123 jurisdiction_notifications entries carry obligation metadata', () => {
  const sub = JSON.stringify({
    observations: { w: { captured: true, value: 'AKIA', indicator: 'aws-access-key-id', result: 'hit' } },
    verdict: { classification: 'detected', blast_radius: 4 }
  });
  const r = cli(['run', 'secrets', '--evidence', '-', '--session-id', 'jur123-' + Date.now(), '--force-overwrite', '--json'], { input: sub });
  const data = tryJson(r.stdout);
  const notifs = data?.phases?.close?.jurisdiction_notifications || [];
  assert.ok(notifs.length > 0, 'must have notifications when classification=detected');
  const enriched = notifs.filter(n => n.jurisdiction && n.regulation);
  assert.ok(enriched.length > 0,
    'at least one notification entry must carry jurisdiction + regulation (enriched from govern.jurisdiction_obligations)');
  for (const n of enriched) {
    assert.equal(typeof n.jurisdiction, 'string', 'jurisdiction must be a string, not null');
    assert.equal(typeof n.regulation, 'string', 'regulation must be a string, not null');
    assert.ok(typeof n.window_hours === 'number', 'window_hours must be a number');
    assert.ok(typeof n.notification_deadline === 'string', 'notification_deadline must be a string (ISO or sentinel)');
    assert.ok(Array.isArray(n.evidence_required), 'evidence_required must be an array');
  }
});

test('#124 --ack propagates into phases.govern.operator_consent', () => {
  const r = cli(['run', 'library-author', '--evidence', '-', '--ack', '--session-id', 'gov124-' + Date.now(), '--force-overwrite', '--json'], { input: '{}' });
  const data = tryJson(r.stdout);
  assert.ok(data?.phases?.govern, 'govern phase must be present');
  assert.ok(data.phases.govern.operator_consent,
    'phases.govern.operator_consent must be populated when --ack passed (consent semantically belongs in govern)');
  assert.equal(data.phases.govern.operator_consent.explicit, true);
});

test('#124 phases.govern.operator_consent is null without --ack', () => {
  const r = cli(['run', 'library-author', '--evidence', '-', '--session-id', 'noackg-' + Date.now(), '--force-overwrite', '--json'], { input: '{}' });
  const data = tryJson(r.stdout);
  assert.equal(data?.phases?.govern?.operator_consent, null,
    'govern.operator_consent must be null (not undefined) when --ack not passed');
});

test('#131 run <skill-name> suggests the right playbook', () => {
  // Operators read the site, see skill names, type `exceptd run <skill>`.
  // Pre-0.11.14: "Playbook not found." Post-0.11.14: error includes a hint
  // pointing at the playbook that loads that skill.
  const r = cli(['run', 'kernel-lpe-triage', '--evidence', '-', '--json'], { input: '{}' });
  assert.equal(r.status, 1, 'unknown playbook must exit 1 (emitError refusal from cmdRun playbook lookup)');
  const err = tryJson(r.stderr.trim());
  assert.ok(err && err.ok === false, 'stderr must carry structured JSON error');
  assert.match(err.error, /SKILL.*not.*PLAYBOOK|skill.*playbook|exceptd skill|exceptd plan/i,
    'error must explain skill≠playbook and suggest the right verb');
  // The "kernel" playbook loads "kernel-lpe-triage" — must be mentioned.
  assert.match(err.error, /kernel\b/, 'must name the playbook that loads this skill');
});

test('#131 run <typo-playbook-id> suggests nearest playbooks', () => {
  const r = cli(['run', 'secret', '--evidence', '-', '--json'], { input: '{}' });
  assert.equal(r.status, 1, 'typo-playbook-id must exit 1 (emitError unknown-playbook with suggestion)');
  const err = tryJson(r.stderr.trim());
  assert.match(err.error, /Did you mean|exceptd plan|secrets/i,
    'partial-match must suggest the canonical id');
});

test('run --upstream-check surfaces upstream_check on result and warns when behind', () => {
  const fix = withFixture('99.99.99', 5);
  try {
    const r = cli(['run', 'library-author', '--evidence', '-', '--upstream-check', '--session-id', 'us-' + Date.now(), '--force-overwrite', '--json'], {
      input: '{}',
      env: { EXCEPTD_REGISTRY_FIXTURE: fix }
    });
    const data = tryJson(r.stdout);
    assert.ok(data?.upstream_check, 'run result must carry upstream_check when --upstream-check is passed');
    assert.equal(data.upstream_check.behind, true);
    assert.equal(data.upstream_check.latest_version, '99.99.99');
    assert.match(r.stderr, /STALE: local v.* < published v99\.99\.99/,
      'stderr must surface a visible STALE warning so operators see the freshness gap before relying on findings');
  } finally { fs.unlinkSync(fix); }
});

test('run without --upstream-check does NOT contact the registry', () => {
  // No fixture configured — if the runner contacted the registry we'd either
  // succeed (network) or fail (timeout). The contract is: opt-in only.
  const r = cli(['run', 'library-author', '--evidence', '-', '--session-id', 'noUp-' + Date.now(), '--force-overwrite', '--json'], { input: '{}' });
  const data = tryJson(r.stdout);
  assert.ok(data, 'run JSON must parse');
  assert.equal(data.upstream_check, undefined,
    'no upstream_check field unless --upstream-check is explicitly passed');
});

test('#104 close emits jurisdiction_notifications alias + clocks count (with --ack — E7 binds clock to operator awareness)', () => {
  const sub = JSON.stringify({
    observations: { w: { captured: true, value: 'AKIA', indicator: 'aws-access-key-id', result: 'hit' } },
    verdict: { classification: 'detected', blast_radius: 4 }
  });
  // E7: pre-fix the clock auto-stamped on classification=detected. Now the
  // operator must acknowledge via --ack for the clock to start.
  const r = cli(['run', 'secrets', '--evidence', '-', '--ack', '--session-id', 'jur104-' + Date.now(), '--force-overwrite', '--json'], { input: sub });
  const data = tryJson(r.stdout);
  assert.ok(Array.isArray(data?.phases?.close?.jurisdiction_notifications),
    'phases.close.jurisdiction_notifications must be present (alias for notification_actions)');
  assert.ok(data.phases.close.jurisdiction_clocks_count >= 1,
    'jurisdiction_clocks_count must be > 0 when classification=detected + --ack with detect_confirmed obligations');
});

test('#E7 jurisdiction clock pending without --ack on detected classification', () => {
  // E7: without --ack, classification=detected MUST NOT auto-start the clock.
  // The pre-fix behavior (auto-stamping Date.now() in computeClockStart for
  // detect_confirmed events) was legally incorrect per AGENTS.md Phase 7 —
  // the clock binds to operator awareness, not engine classification.
  const sub = JSON.stringify({
    observations: { w: { captured: true, value: 'AKIA', indicator: 'aws-access-key-id', result: 'hit' } },
    verdict: { classification: 'detected', blast_radius: 4 }
  });
  const r = cli(['run', 'secrets', '--evidence', '-', '--session-id', 'e7-' + Date.now(), '--force-overwrite', '--json'], { input: sub });
  const data = tryJson(r.stdout);
  const notifs = data?.phases?.close?.notification_actions || [];
  const detectConfirmed = notifs.filter(n => n && n.clock_start_event === 'detect_confirmed');
  assert.ok(detectConfirmed.length >= 1,
    'secrets stages at least one detect_confirmed obligation');
  assert.ok(detectConfirmed.every(n => n.clock_started_at == null),
    'without --ack every detect_confirmed clock must be unstarted');
  assert.ok(detectConfirmed.every(n => n.clock_pending_ack === true),
    'each unstarted detect_confirmed notification must surface clock_pending_ack=true so operators see why');
});
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});


// ---- routed from precondition-source-provenance ----
require("node:test").describe("precondition-source-provenance", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
/**
 * Regression suite for precondition_check_source provenance accuracy.
 *
 * Before the fix, a CLI `run` reported EVERY precondition as "merged" because
 * the CLI copied the submission's precondition_checks into runOpts (the value
 * then appeared in both the submission and runOpts maps). And an
 * engine-auto-detected precondition was mislabeled "submission". Now:
 *   - a submission-supplied precondition → "submission"
 *   - an engine-auto-detected precondition → "auto"
 *   - (engine-level) a value in both submission and runOpts → "merged"
 * Gating is unchanged — preconditions still block correctly.
 *
 * Discipline: exact provenance value assertions + a gating guard.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const { makeSuiteHome, makeCli, tryJson } = require("./_helpers/cli");

const cli = makeCli(makeSuiteHome("exceptd-pcsource-"));

test("a submission-supplied precondition reports provenance 'submission' (not 'merged')", () => {
  const r = cli(["run", "secrets", "--evidence", "-", "--json"], {
    input: JSON.stringify({ precondition_checks: { "repo-context": true }, signal_overrides: { "aws-access-key-id": "hit" } }),
  });
  const j = tryJson(r.stdout);
  assert.ok(j && j.precondition_check_source, "must surface precondition_check_source");
  assert.equal(j.precondition_check_source["repo-context"], "submission",
    "an operator-submitted precondition must be tagged submission, not merged");
});

test("an engine-auto-detected precondition reports provenance 'auto' (not 'submission')", () => {
  const r = cli(["run", "secrets", "--evidence", "-", "--json"], {
    input: JSON.stringify({ signal_overrides: { "aws-access-key-id": "hit" } }),
  });
  const j = tryJson(r.stdout);
  const src = j.precondition_check_source || {};
  // repo-context (cwd readability) is auto-detected by the engine when not submitted.
  assert.ok("repo-context" in src, "the auto-detected precondition must appear");
  assert.equal(src["repo-context"], "auto",
    "an engine-auto-detected precondition must be tagged auto, not submission");
});

test("gating is unchanged: a false halt precondition still blocks the run", () => {
  const r = cli(["run", "kernel", "--evidence", "-", "--json"], {
    input: JSON.stringify({ precondition_checks: { "linux-platform": false } }),
  });
  const j = tryJson(r.stdout);
  assert.equal(j.verdict, "blocked", "a false halt precondition must still block");
  assert.equal(j.blocked_by, "precondition");
});

test("engine-level: a precondition in both the submission and runOpts is still 'merged'", () => {
  // Direct runner call (the programmatic-override path the CLI never produces):
  // the same key in both maps is a genuine merge.
  const runner = require("../lib/playbook-runner");
  const res = runner.run("secrets", "full-repo-secret-scan",
    { precondition_checks: { "repo-context": true }, signal_overrides: {} },
    { precondition_checks: { "repo-context": true }, force_replay: true });
  assert.ok(res, "run must return a result");
  if (res.precondition_check_source) {
    assert.equal(res.precondition_check_source["repo-context"], "merged",
      "submission ∩ runOpts is a genuine merge");
  }
});
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});


// ---- routed from renderer-and-reattest-traversal ----
require("node:test").describe("renderer-and-reattest-traversal", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
/**
 * Regression suite for a cluster found auditing the human-readable output
 * paths and the attestation read verbs:
 *
 *   SECURITY — `reattest` joined an unvalidated session-id into a filesystem
 *     path, so `reattest "../.."` escaped the attestation root to read a forged
 *     attestation and write a signed replay record outside the root. It now
 *     validates the session-id at the same boundary the other read verbs use.
 *
 *   run-multi (`run --all` / `run-all`) had no human renderer and dumped the
 *     full (hundreds-of-KB) JSON even in default mode; it now prints a table.
 *
 *   `attest diff --against` dumped raw JSON while the no-against branch
 *     rendered a summary; both now share one renderer.
 *
 *   run-renderer detail: CVE KEV renders Y/N (not the raw boolean), a
 *     deterministic indicator doesn't print "deterministic/deterministic",
 *     and a `message`-shaped preflight warning isn't shown as "(no detail)".
 *
 * Discipline: exact exit codes; value + type assertions; the security test
 * asserts BOTH the refusal AND that nothing was written outside the root.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { makeSuiteHome, makeCli, tryJson } = require("./_helpers/cli");

const cli = makeCli(makeSuiteHome("exceptd-renderer-"));

// The shared harness sets EXCEPTD_RAW_JSON=1, which forces JSON and bypasses
// the human renderer. Human-mode tests pass HUMAN env to disable it ("" is
// falsy under the `!!process.env.EXCEPTD_RAW_JSON` check).
const HUMAN = { EXCEPTD_RAW_JSON: "" };

const DET2 = JSON.stringify({ signal_overrides: { "aws-secret-access-key": "hit", "github-personal-access-token": "hit" } });

test("run --all renders a per-playbook table in human mode (not a raw JSON dump)", () => {
  const r = cli(["run-all"], { env: HUMAN });
  const out = r.stdout;
  assert.doesNotMatch(out.trimStart().slice(0, 1), /[{[]/, "default human output must not start with JSON");
  assert.match(out, /playbook\s+verdict\s+rwep\s+evidence\s+finding/, "must render the summary table header");
  assert.match(out, /detected=\d+\s+inconclusive=\d+/, "must render the rollup line");
});

test("attest diff --against renders a human summary (not raw JSON)", () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "exceptd-diff-"));
  try {
    const env = { EXCEPTD_HOME: home };
    const a = tryJson(cli(["run", "secrets", "--evidence", "-", "--json"], { input: JSON.stringify({ signal_overrides: { "aws-secret-access-key": "hit" } }), env }).stdout);
    const b = tryJson(cli(["run", "secrets", "--evidence", "-", "--json"], { input: JSON.stringify({ signal_overrides: { "github-personal-access-token": "hit" } }), env }).stdout);
    const r = cli(["attest", "diff", a.session_id, "--against", b.session_id], { env: { ...env, ...HUMAN } });
    assert.doesNotMatch(r.stdout.trimStart().slice(0, 1), /[{[]/, "must not dump JSON in human mode");
    assert.match(r.stdout, /attest diff:/, "must render the diff header");
    assert.match(r.stdout, /artifact diff:/, "must render the artifact diff line");
    assert.match(r.stdout, /sidecar verify:/, "must render the sidecar class");
  } finally {
    fs.rmSync(home, { recursive: true, force: true });
  }
});

test("run CVE line renders KEV=Y/N, and a deterministic indicator is not doubled", () => {
  // ai-api with firing signals produces a matched CVE + deterministic indicators.
  const r = cli(["run", "ai-api", "--evidence", "-"], {
    input: JSON.stringify({ signal_overrides: { "cleartext-api-key-in-dotfile": "hit", "ai-api-beaconing-cadence": "hit", "long-lived-aws-keys": "hit" } }),
    env: HUMAN,
  });
  const out = r.stdout;
  assert.doesNotMatch(out, /KEV=(true|false)/, "KEV must render Y/N, never the raw boolean");
  assert.match(out, /KEV=[YN]/, "KEV must render as Y or N");
  assert.doesNotMatch(out, /deterministic\/deterministic/, "must not double-print deterministic/deterministic");
});

test("run preflight warning surfaces a message-shaped detail (not '(no detail)')", () => {
  const r = cli(["run", "ai-api", "--evidence", "-"], { input: JSON.stringify({ signal_overrides: { "ai-api-beaconing-cadence": "hit" } }), env: HUMAN });
  const out = r.stdout;
  if (/Preflight warnings/.test(out)) {
    // If a preflight warning rendered, it must not be the bare "(no detail)".
    const warnBlock = out.slice(out.indexOf("Preflight warnings"));
    assert.doesNotMatch(warnBlock.split("\n").slice(1, 3).join("\n"), /: \(no detail\)\s*$/m,
      "a message-shaped preflight warning must show its message, not (no detail)");
  }
});

;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});


// ---- routed from resolver-trust-and-flag-hardening ----
require("node:test").describe("resolver-trust-and-flag-hardening", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
/**
 * Resolver-trust + flag-hardening regression suite.
 *
 * Pins three independently-exploitable contracts so they can't silently
 * regress:
 *
 *   1. Resolved-cache integrity (lib/citation-resolve.js). A resolved record is
 *      only trusted when it carries a sha256 `_digest` over its own canonical
 *      bytes AND its embedded `resolved_at` is inside the freshness window.
 *      A poisoned/tampered/stale/future-dated file cannot launder a verdict —
 *      it reads back as a cache miss and the resolver falls through to
 *      offline/unknown. This is the security headline: an operator-writable
 *      cache directory can never turn a rejected/fabricated citation into a
 *      "published" one.
 *
 *   2. Unknown-flag rejection on the cve/rfc resolvers. A swallowed `--josn`
 *      would emit human text into a pipe that asked for JSON and defeat a CI
 *      gate, so an unrecognized flag is a hard exit 1 with an ok:false envelope.
 *
 *   3. Evidence-shape / --max-rwep / --format guards on run + ci. `null`, an
 *      array, or a scalar parse as valid JSON but are not a submission; a
 *      non-numeric or negative cap would degenerate the gate; `--format`
 *      explicitly overrides `--json`.
 *
 * Plus the applyResolution RFC-flip contract (a cited RFC number that resolves
 * to nothing is a bad citation; an obsoleted-but-real RFC is not).
 *
 * Discipline (project anti-coincidence rules): assert EXACT exit codes (never
 * notEqual(0)); pair every field-presence check with a value/type assertion;
 * never weaken a test to make it pass. Every test is deterministic and offline:
 * cache tests inject a per-suite EXCEPTD_RESOLVE_CACHE_DIR and a tiny catalog
 * fixture WITHOUT the test ids (so the resolver reaches the cache path), and
 * pass { noNetwork: true } so no network is touched.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const fs = require('node:fs');
const os = require('node:os');
const crypto = require('node:crypto');

const { makeSuiteHome, makeCli, tryJson } = require('./_helpers/cli');

// --- isolated resolved-cache dir + a tiny catalog fixture that deliberately
//     does NOT contain the ids these tests resolve, so resolveCve falls past
//     the catalog branch into the cache branch. Both env vars are set BEFORE
//     require('../lib/citation-resolve.js') — the catalog path is read +
//     memoized at module-require time; the cache dir is read at call time but
//     is set here too to be safe. --------------------------------------------
const CACHE_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'exceptd-resolver-trust-cache-'));
const FIXTURE_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'exceptd-resolver-trust-fixture-'));
const CVE_FIXTURE = path.join(FIXTURE_DIR, 'cve-catalog.json');

// A catalog hit for the CLI fixture-id test, but NONE of the cache-integrity
// test ids, so those reach the cache path rather than short-circuiting here.
const CVE_FIXTURE_DATA = {
  'CVE-2030-0001': {
    cvss_score: 9.8,
    cisa_kev: true,
    name: 'FixtureVuln',
    status: 'published',
  },
};
fs.writeFileSync(CVE_FIXTURE, JSON.stringify(CVE_FIXTURE_DATA, null, 2));

process.on('exit', () => {
  try { fs.rmSync(CACHE_DIR, { recursive: true, force: true }); } catch { /* non-fatal */ }
  try { fs.rmSync(FIXTURE_DIR, { recursive: true, force: true }); } catch { /* non-fatal */ }
});

process.env.EXCEPTD_CVE_CATALOG = CVE_FIXTURE;
process.env.EXCEPTD_RESOLVE_CACHE_DIR = CACHE_DIR;

const { resolveCve } = require('../lib/citation-resolve.js');
const citationHygiene = require('../lib/collectors/citation-hygiene.js');

// Spawned-CLI harness. Pass the fixture catalog + isolated cache dir as env
// overrides so subprocesses resolve offline against them, not the network.
const SUITE_HOME = makeSuiteHome('exceptd-resolver-trust-');
const baseCli = makeCli(SUITE_HOME);
const RESOLVER_ENV = {
  EXCEPTD_CVE_CATALOG: CVE_FIXTURE,
  EXCEPTD_RESOLVE_CACHE_DIR: CACHE_DIR,
};
function cli(args, opts = {}) {
  return baseCli(args, { ...opts, env: { ...RESOLVER_ENV, ...(opts.env || {}) } });
}

// --- digest helper: replicate lib/citation-resolve.js recordDigest exactly so
//     a test can write a VALID (trusted) cache record. sha256 over the record's
//     canonical JSON: keys sorted, `_digest` excluded. ------------------------
function recordDigest(rec) {
  const canon = {};
  for (const k of Object.keys(rec).sort()) {
    if (k === '_digest') continue;
    canon[k] = rec[k];
  }
  return crypto.createHash('sha256').update(JSON.stringify(canon)).digest('hex');
}
function writeRawCveCache(id, rec) {
  const dir = path.join(CACHE_DIR, 'cve');
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, `${id}.json`), JSON.stringify(rec));
  return path.join(dir, `${id}.json`);
}
function writeDigestedCveCache(id, rec) {
  const signed = { ...rec };
  signed._digest = recordDigest(signed);
  return writeRawCveCache(id, signed);
}

// ===================================================================
// 1. Resolved-cache integrity
// ===================================================================








// ===================================================================
// 2. cve / rfc unknown-flag rejection (spawned CLIs)
// ===================================================================




// ===================================================================
// 3. run evidence-shape guard
// ===================================================================

for (const bad of [
  { label: 'null', input: 'null' },
  { label: 'array', input: '[]' },
  { label: 'string', input: '"astring"' },
  { label: 'number', input: '123' },
]) {
  test(`run CLI: --evidence - with ${bad.label} exits 1 with "evidence must be a JSON object"`, () => {
    const r = cli(['run', 'secrets', '--evidence', '-'], { input: bad.input });
    assert.equal(r.status, 1, `expected exit 1; got ${r.status} (stderr: ${r.stderr.slice(0, 200)})`);
    const body = tryJson(r.stderr.trim());
    assert.ok(body, `stderr should be parseable JSON; got: ${r.stderr.slice(0, 200)}`);
    assert.equal(body.ok, false);
    assert.match(body.error, /evidence must be a JSON object/);
  });
}


// ===================================================================
// 4. applyResolution RFC flip
// ===================================================================



// ===================================================================
// 5. ci --max-rwep validation
// ===================================================================




// ===================================================================
// 6. --format overrides --json (note on stderr, markdown on stdout)
// ===================================================================


// ===================================================================
// 7. help lists the cve / rfc / collect verbs
// ===================================================================

test('run CLI: --evidence - with an empty object {} runs (exit 0, not the shape error)', () => {
  const r = cli(['run', 'secrets', '--evidence', '-', '--json'], { input: '{}' });
  assert.equal(r.status, 0, `expected exit 0; got ${r.status} (stderr: ${r.stderr.slice(0, 200)})`);
  const body = tryJson(r.stdout.trim());
  assert.ok(body, `stdout should be parseable JSON; got: ${r.stdout.slice(0, 200)}`);
  assert.equal(body.ok, true);
});

test('run CLI: --format markdown overrides --json — stdout is markdown, stderr carries the note', () => {
  const r = cli(['run', 'secrets', '--evidence', '-', '--json', '--format', 'markdown'], { input: '{}' });
  assert.equal(r.status, 0, `expected exit 0; got ${r.status} (stderr: ${r.stderr.slice(0, 200)})`);
  assert.equal(r.stdout.trimStart()[0], '#',
    `stdout should be a markdown document (starts with '#'); got: ${r.stdout.slice(0, 80)}`);
  assert.match(r.stderr, /overrides --json/);
});
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});


// ---- routed from ux-next-step-guidance ----
require("node:test").describe("ux-next-step-guidance", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
/**
 * tests/ux-next-step-guidance.test.js
 *
 * Stage-by-stage next-step guidance surfaces. The behavior is
 * operator-facing prose, so regression coverage is grep-shaped — each
 * assertion pins the exact substring an operator searches for when
 * they ask "what do I do now?"
 *
 * Surfaces pinned:
 *   1. ci BLOCKED prints "Next steps (unblock the N halted playbook(s)):"
 *      with one `exceptd lint <playbook> -` per blocked id.
 *   2. ci NO_EVIDENCE prints "Next steps (every playbook ran inconclusive
 *      — no evidence supplied):" with a lint + ci-evidence-dir pair.
 *   3. run prints "evidence: <state> (<evaluated>/<known> indicators
 *      evaluated)" on every success.
 *   4. run prints "Attestation written:" + the verify/diff command pair
 *      after persistence.
 *   5. run non-detect prose says "Remediation path (informational — verdict
 *      =<x>, no action required now):" — NOT "Recommended remediation:".
 *   6. run unknown-playbook error references the live playbook count,
 *      not a hardcoded literal.
 *   7. ci FAIL fires guidance even when no playbook hit detected (delta-
 *      cap path).
 *   8. lint flags nested-shape submissions that supply artifacts but no
 *      signal_overrides — the workflow trapdoor.
 *
 * Per the anti-coincidence rule: assertions check exact substrings.
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
    env: { ...process.env, EXCEPTD_DEPRECATION_SHOWN: "1", ...(opts.env || {}) },
    input: opts.input,
  });
}

function tryJson(s) { try { return JSON.parse(s); } catch { return null; } }

test("run prints 'evidence: <state> (N/M indicators evaluated)' on the verdict line", () => {
  const evidence = JSON.stringify({
    precondition_checks: { "linux-platform": true, "uname-available": true },
    artifacts: { "kernel-release": "5.15.0-69-generic" },
    signal_overrides: { "kver-in-affected-range": "hit" },
  });
  const tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), "run-evidence-"));
  try {
    const r = cli(["run", "kernel", "--evidence", "-",
      "--attestation-root", path.join(tmpHome, "attestations")], { input: evidence });
    assert.equal(r.status, 0, `run kernel must exit 0; stderr: ${r.stderr.slice(0, 200)}`);
    // Match the literal "evidence: " row followed by the N/M counter.
    assert.match(r.stdout, /evidence: (complete|partial|missing|unknown|not-evaluated)\s+\(\d+\/\d+ indicators evaluated\)/,
      "verdict line must surface evidence_completeness + indicators-evaluated counter");
  } finally {
    try { fs.rmSync(tmpHome, { recursive: true, force: true }); } catch {}
  }
});

test("run prints 'Attestation written: <path>' + verify/diff command pair after persistence", () => {
  const evidence = JSON.stringify({
    precondition_checks: { "linux-platform": true, "uname-available": true },
    artifacts: { "kernel-release": "5.15.0-69-generic" },
    signal_overrides: { "kver-in-affected-range": "hit" },
  });
  const tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), "run-attest-"));
  try {
    const r = cli(["run", "kernel", "--evidence", "-",
      "--attestation-root", path.join(tmpHome, "attestations")], { input: evidence });
    assert.equal(r.status, 0, `run kernel must exit 0; stderr: ${r.stderr.slice(0, 200)}`);
    assert.match(r.stdout, /Attestation written: .+attestation\.json/,
      "human renderer must print the absolute attestation_path");
    assert.match(r.stdout, /exceptd attest verify [0-9a-f-]+\s+# tamper check/,
      "human renderer must point at attest verify with the session id");
    assert.match(r.stdout, /exceptd attest diff [0-9a-f-]+\s+# vs\. most-recent prior/,
      "human renderer must point at attest diff with the session id");
  } finally {
    try { fs.rmSync(tmpHome, { recursive: true, force: true }); } catch {}
  }
});

test("run non-detect prose says 'Remediation path (informational — verdict=<x>, no action required now):'", () => {
  // A run with no evidence on `secrets` returns not_detected (the
  // catalog-baseline indicators don't fire against the local cwd).
  const r = cli(["run", "secrets", "--evidence", "-"], { input: "{}" });
  assert.equal(r.status, 0, `run secrets must exit 0; stderr: ${r.stderr.slice(0, 200)}`);
  // Either inconclusive or not_detected — both must use the
  // informational phrasing, NOT "Recommended remediation:".
  if (/classification=(not_detected|inconclusive)/.test(r.stdout)) {
    assert.match(r.stdout, /Remediation path \(informational — verdict=(not_detected|inconclusive), no action required now\):/,
      "non-detect runs must NOT print 'Recommended remediation:' (that string is for detected runs)");
    // And the misleading detected-only phrasing must NOT appear.
    assert.doesNotMatch(r.stdout, /^Recommended remediation:/m,
      "non-detect runs must not print the unconditional detected-only phrasing");
  }
});

test("run unknown-playbook error says 'list the <live count> playbooks', not the stale literal 13", () => {
  const r = cli(["run", "this-playbook-does-not-exist"]);
  assert.equal(r.status, 1);
  const err = tryJson(r.stderr);
  assert.ok(err, `stderr must be JSON; got: ${r.stderr.slice(0, 200)}`);
  // The live count is whatever runner.listPlaybooks() returns; it must
  // NOT be the literal "13" (the value before the v0.13.x expansion).
  assert.doesNotMatch(err.error, /list the 13 playbooks/,
    "playbook-not-found message must not carry the stale hardcoded count");
  assert.match(err.error, /list the \d+ playbooks/,
    "playbook-not-found message must reference a live count");
});
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});


// ---- routed from readme-run-format-consistency ----
require("node:test").describe("readme-run-format-consistency", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
/**
 * tests/readme-run-format-consistency.test.js
 *
 * The `run --format` value list must stay consistent across the three
 * operator-facing surfaces: the README synopsis, the `exceptd help` text, and
 * the runtime's accepted `supported_formats`. A README that omits a value the
 * runtime accepts and `--help` advertises misleads an operator reading the
 * command reference to learn which formats are valid.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');
const README = fs.readFileSync(path.join(ROOT, 'README.md'), 'utf8');
const HELP = fs.readFileSync(path.join(ROOT, 'bin', 'exceptd.js'), 'utf8');
const RUNNER = fs.readFileSync(path.join(ROOT, 'lib', 'playbook-runner.js'), 'utf8');

// Anchors the run --format synopsis line uniquely in both README and --help.
const ANCHOR = 'csaf-2.0 | sarif | openvex';

function pipeTokens(text, anchor) {
  const line = text.split('\n').find(l => l.includes(anchor));
  assert.ok(line, `expected a line containing "${anchor}"`);
  const run = line.slice(line.indexOf('csaf-2.0'));
  return run.replace(/[.\s]+$/, '').split('|').map(s => s.trim()).filter(Boolean);
}

function runtimeFormats(text) {
  const m = text.match(/supported_formats:\s*\[([^\]]*)\]/);
  assert.ok(m, 'expected a supported_formats array literal in lib/playbook-runner.js');
  return m[1].split(',').map(s => s.trim().replace(/^['"]|['"]$/g, '')).filter(Boolean);
}

test('README run --format synopsis advertises json', () => {
  const readme = pipeTokens(README, ANCHOR);
  assert.equal(readme.includes('json'), true,
    `README --format list must include json; got: ${readme.join(' | ')}`);
});

test('README and `exceptd help` advertise the identical run --format value set', () => {
  const readme = pipeTokens(README, ANCHOR);
  const help = pipeTokens(HELP, ANCHOR);
  assert.deepEqual([...readme].sort(), [...help].sort(),
    `README (${readme.join('|')}) and --help (${help.join('|')}) must advertise the same --format values`);
});

test('every README-advertised run --format value is accepted by the runtime', () => {
  const readme = pipeTokens(README, ANCHOR);
  const runtime = runtimeFormats(RUNNER);
  for (const tok of readme) {
    assert.equal(runtime.includes(tok), true,
      `README advertises --format ${tok}, but the runtime supported_formats does not accept it`);
  }
});
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});
