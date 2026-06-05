'use strict';

/**
 * Every orchestrator error surface must emit the structured ok:false envelope
 * when a JSON consumer is downstream — including the framework-gap catalog-read
 * failure and the top-level fatal handler, which previously printed plain text.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const ROOT = path.join(__dirname, '..');
const ORCH = path.join(ROOT, 'orchestrator', 'index.js');

const baseEnv = () => ({
  ...process.env,
  EXCEPTD_SUPPRESS_DEPRECATION: '1',
});

// framework-gap's catalog-read catch must honor --json. Drive main() with
// fs.readFileSync forced to throw for the catalog files, so the real catch
// path runs without touching the shipped data/ tree.
test('framework-gap catalog-read failure emits ok:false JSON under --json', () => {
  const script = `
    const fs = require('fs');
    const orig = fs.readFileSync;
    fs.readFileSync = function (p, ...rest) {
      if (typeof p === 'string' && /framework-control-gaps\\.json$|cve-catalog\\.json$/.test(p)) {
        const e = new Error('forced read failure');
        e.code = 'EIO';
        throw e;
      }
      return orig.call(this, p, ...rest);
    };
    process.argv = [process.argv[0], ${JSON.stringify(ORCH)}, 'framework-gap', 'NIST-800-53', 'CVE-2026-31431', '--json'];
    const orch = require(${JSON.stringify(ORCH)});
    orch.main().then(() => { process.exitCode = process.exitCode || 0; });
  `;
  const r = spawnSync(process.execPath, ['-e', script], { encoding: 'utf8', env: baseEnv() });
  assert.equal(r.status, 1, `expected GENERIC_FAILURE exit 1; got ${r.status} stderr=${r.stderr}`);
  // Envelope lands on stdout (where the verb's other --json error paths write).
  const parsed = JSON.parse(r.stdout.trim());
  assert.equal(parsed.ok, false);
  assert.equal(parsed.verb, 'framework-gap');
  assert.equal(typeof parsed.error, 'string');
  assert.match(parsed.error, /cannot read catalog/);
});

// Without --json the same path stays human-readable on stderr.
test('framework-gap catalog-read failure stays plain text without --json', () => {
  const script = `
    const fs = require('fs');
    const orig = fs.readFileSync;
    fs.readFileSync = function (p, ...rest) {
      if (typeof p === 'string' && /framework-control-gaps\\.json$|cve-catalog\\.json$/.test(p)) {
        throw new Error('forced read failure');
      }
      return orig.call(this, p, ...rest);
    };
    process.argv = [process.argv[0], ${JSON.stringify(ORCH)}, 'framework-gap', 'NIST-800-53', 'CVE-2026-31431'];
    require(${JSON.stringify(ORCH)}).main();
  `;
  const r = spawnSync(process.execPath, ['-e', script], { encoding: 'utf8', env: baseEnv() });
  assert.equal(r.status, 1, `expected exit 1; got ${r.status}`);
  assert.match(r.stderr, /\[framework-gap\] cannot read catalog/);
  assert.equal(r.stdout.trim(), '', 'human path must not emit JSON on stdout');
});

// The top-level fatal handler must emit a parseable ok:false envelope on
// stderr, not the legacy plain-text "[orchestrator] Fatal:" line.
test('orchestrator fatal handler emits ok:false JSON envelope on stderr', () => {
  // Patch the scanner so scan() throws an uncaught error that escapes runScan
  // and reaches main().catch(). require.main === module here (direct spawn),
  // so the fatal handler fires.
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'orch-fatal-'));
  const preloadPath = path.join(tmp, 'preload.js');
  const scannerPath = path.join(ROOT, 'orchestrator', 'scanner.js');
  fs.writeFileSync(preloadPath, [
    "'use strict';",
    "const Module = require('module');",
    `const scannerPath = ${JSON.stringify(scannerPath)};`,
    'const orig = Module._load;',
    'Module._load = function (request, parent, isMain) {',
    '  let resolved = request;',
    '  try { resolved = Module._resolveFilename(request, parent, isMain); } catch { /* keep request */ }',
    '  if (resolved === scannerPath) {',
    "    return { scan: () => { throw new Error('synthetic scan failure'); }, scanDomain: () => {}, sanitizeConfig: (x) => x };",
    '  }',
    '  return orig.apply(this, arguments);',
    '};',
    '',
  ].join('\n'));

  try {
    const r = spawnSync(process.execPath, ['--require', preloadPath, ORCH, 'scan', '--json'], {
      encoding: 'utf8',
      env: baseEnv(),
    });
    assert.equal(r.status, 1, `expected exit 1 on fatal; got ${r.status} stderr=${r.stderr}`);
    // The last stderr line is the fatal envelope; parse it.
    const lines = r.stderr.trim().split(/\r?\n/).filter(Boolean);
    const last = lines[lines.length - 1];
    const parsed = JSON.parse(last);
    assert.equal(parsed.ok, false);
    assert.equal(parsed.verb, 'scan');
    assert.equal(typeof parsed.error, 'string');
    assert.match(parsed.error, /synthetic scan failure/);
    // The legacy plain-text marker must be gone.
    assert.ok(!r.stderr.includes('[orchestrator] Fatal:'), 'plain-text fatal marker must not appear');
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});
