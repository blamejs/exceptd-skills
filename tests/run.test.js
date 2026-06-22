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
      try {
        fs.linkSync(realFile, linkPath);  // hardlink: same inode, in evDir
      } catch (e) {
        if (e.code === 'EPERM' || e.code === 'EXDEV' || e.code === 'EACCES') {
          return;
        }
        throw e;
      }
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


// ---- routed from cycle17-ux-fixes ----
require("node:test").describe("cycle17-ux-fixes", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
/**
 * tests/cycle17-ux-fixes.test.js
 *
 * Cycle 17 fixes (v0.12.37):
 *
 *   S4 — `--evidence -` with empty stdin now emits a stderr nudge.
 *        Pre-fix the empty payload was silently accepted as {} and the
 *        run looked successful. Cycle 15 flagged; cycle 17 verified
 *        still open. The fix preserves the legitimate "posture-only
 *        walk" use case (the run still proceeds with {}) but surfaces
 *        a stderr `[exceptd] note: ...` message so the operator at
 *        least knows.
 *
 *   S13 — unknown verb with Levenshtein-1 typo now suggests the
 *         intended verb. `exceptd discoer` → `discover`,
 *         `exceptd attst` → `attest`. Includes transposition detection
 *         so `disocver` also resolves to `discover`. Unknown verbs
 *         outside edit-distance 1 still get the generic hint.
 *
 *   F1/F2 — operator-misleading skill prose about CVE-2024-3094
 *         (xz-utils). Pre-fix 2 skills said "not in current cve-catalog
 *         — pre-scope incident" while the catalog actually carries the
 *         entry; a 3rd skill quoted RWEP 95 against the catalog's 70
 *         plus drifted ai_discovered and active_exploitation. This
 *         test pins the corrected prose.
 *
 *   F3 — Volt-Typhoon hyphenation drift (cosmetic). Two skills used
 *         `Volt-Typhoon-aligned` / `Volt-Typhoon-style`. All others use
 *         unhyphenated `Volt Typhoon`. Test pins single canonical form.
 *
 * Per the anti-coincidence rule, every assertion checks an EXACT
 * value (string match, deepEqual, or specific count).
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
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
  });
}

function tryJson(s) { try { return JSON.parse(s); } catch { return null; } }

// S4 — empty-stdin nudge ---------------------------------------------------



// S13 — did-you-mean for unknown verbs -------------------------------------




// F1/F2 — CVE-2024-3094 prose corrections ----------------------------------

test('S4: --evidence - with empty stdin emits stderr nudge + still proceeds', () => {
  // posture-only walk on framework playbook (no preconditions block it).
  const r = cli(['run', 'framework', '--evidence', '-'], { input: '' });
  assert.equal(r.status, 0, `posture-only run must succeed; got ${r.status}`);
  assert.match(r.stderr, /--evidence - read 0 bytes from stdin/,
    `stderr must surface the empty-stdin nudge; got: ${r.stderr.slice(0, 200)}`);
  assert.match(r.stderr, /exceptd brief/, 'nudge must point at `exceptd brief` for the expected shape');
});

test('S4: --evidence - with valid JSON does NOT emit the empty-stdin nudge', () => {
  const r = cli(['run', 'framework', '--evidence', '-'], { input: '{}' });
  assert.equal(r.status, 0);
  assert.equal(/read 0 bytes from stdin/.test(r.stderr), false,
    'non-empty stdin must NOT emit the nudge');
});
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});
