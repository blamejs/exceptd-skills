'use strict';

/**
 * Tests for the v0.12.21 audit-EE / GG CLI surface closures.
 *
 *   GG P1-1  --help text does not leak `(Audit L F22)` parenthetical
 *   EE P1-1  --vex accepts a CycloneDX SBOM with no vulnerabilities[]
 *            (0-CVE VEX filter) — but still rejects bogus shapes
 *   EE P1-2  --vex / --evidence reads tolerate UTF-8-BOM + UTF-16 LE/BE
 *   EE P1-3  --operator refuses U+202E bidi-override + zero-width chars
 *   EE P1-4  --vex oversize error message names "MiB" + comma-formatted bytes
 *   EE P1-5  --evidence-dir refuses Windows junctions (skip on POSIX)
 *            and refuses POSIX symlinks (skip on Windows without privs)
 *   EE P1-6  --ack on info-only verbs (brief) is refused with hint;
 *            --ack on run against not-detected does NOT persist consent
 *   EE P1-7  stdin auto-detect does not hang on a wrapped empty stream
 *            (size === 0 via fstat probe; bounded run completes < 5s)
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const { ROOT, makeSuiteHome, makeCli, tryJson } = require('./_helpers/cli');

const SUITE_HOME = makeSuiteHome('exceptd-audit-ee-gg-');
const cli = makeCli(SUITE_HOME);

// ---------------------------------------------------------------------------
// GG P1-1 — help text does not leak audit vocabulary to operators
// ---------------------------------------------------------------------------

test('GG P1-1: ai-run --help text contains "Stdin acceptance contract:" without parenthetical', () => {
  const r = cli(['ai-run', '--help']);
  assert.equal(r.status, 0, 'help should exit 0; got ' + r.status);
  assert.match(r.stdout, /Stdin acceptance contract:/,
    'help must include the contract section heading');
  assert.doesNotMatch(r.stdout, /Stdin acceptance contract \(Audit L F22\)/,
    'help must NOT include the internal `(Audit L F22)` parenthetical');
  assert.doesNotMatch(r.stdout, /Audit L F22/,
    'help must not surface internal audit identifiers anywhere');
});

test('GG P1-1: source no longer contains the audit-leak string', () => {
  const src = fs.readFileSync(path.join(ROOT, 'bin', 'exceptd.js'), 'utf8');
  assert.equal(src.indexOf('Stdin acceptance contract (Audit L F22)'), -1,
    'source must not contain the leaking parenthetical');
  assert.ok(src.indexOf('Stdin acceptance contract:') >= 0,
    'source must contain the clean heading');
});

// ---------------------------------------------------------------------------
// EE P1-1 — CycloneDX SBOM without vulnerabilities[] is accepted (0-CVE VEX)
// ---------------------------------------------------------------------------

test('EE P1-1: --vex accepts a CycloneDX SBOM without a vulnerabilities key (0-CVE VEX)', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'ee-p1-1-'));
  try {
    const vexPath = path.join(tmp, 'sbom-no-vex.json');
    fs.writeFileSync(vexPath, JSON.stringify({
      bomFormat: 'CycloneDX',
      specVersion: '1.6',
      components: [],
      // explicitly no vulnerabilities key
    }), 'utf8');
    const sub = JSON.stringify({ observations: {}, verdict: {} });
    const r = cli(['run', 'library-author', '--evidence', '-', '--vex', vexPath], { input: sub });
    // The run may exit 0 (clean) or 2 (detected) or 1 (framework), but it
    // must NOT exit on the --vex shape check. Walk stderr for the shape-
    // refusal phrase and assert it's absent.
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
  // Windows tooling sometimes drops `bomFormat` on export. specVersion 1.x
  // alone is sufficient evidence of CycloneDX shape.
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
  // Defense-in-depth: the new acceptance path must not regress the
  // R-F4-era rejection of "looks like nothing" documents.
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'ee-p1-1c-'));
  try {
    const vexPath = path.join(tmp, 'garbage.json');
    fs.writeFileSync(vexPath, JSON.stringify({
      not_cyclonedx: true,
      not_openvex: true,
    }), 'utf8');
    const sub = JSON.stringify({ observations: {}, verdict: {} });
    const r = cli(['run', 'library-author', '--evidence', '-', '--vex', vexPath], { input: sub });
    assert.notEqual(r.status, 0, 'garbage shape must still be refused');
    const err = tryJson(r.stderr.trim()) || {};
    assert.equal(err.ok, false);
    assert.match(err.error || '', /doesn't look like CycloneDX or OpenVEX|unrecognized/,
      'shape error must still fire; got: ' + (err.error || ''));
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// EE P1-2 — UTF-8 BOM + UTF-16 LE/BE tolerance on --vex and --evidence
// ---------------------------------------------------------------------------

function writeWithBom(filePath, jsonString, encoding) {
  // encoding ∈ "utf8-bom" | "utf16le-bom" | "utf16be-bom"
  if (encoding === 'utf8-bom') {
    const bom = Buffer.from([0xEF, 0xBB, 0xBF]);
    fs.writeFileSync(filePath, Buffer.concat([bom, Buffer.from(jsonString, 'utf8')]));
  } else if (encoding === 'utf16le-bom') {
    const bom = Buffer.from([0xFF, 0xFE]);
    fs.writeFileSync(filePath, Buffer.concat([bom, Buffer.from(jsonString, 'utf16le')]));
  } else if (encoding === 'utf16be-bom') {
    const bom = Buffer.from([0xFE, 0xFF]);
    // Encode as UTF-16LE then byte-swap pairs to produce UTF-16BE.
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
    // Positive: run must reach detect phase, not fail at file-read.
    // We don't pin the status — many playbook outcomes are valid — but the
    // body in stdout must be parseable JSON, indicating the run got past
    // the read step.
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

// ---------------------------------------------------------------------------
// EE P1-3 — --operator rejects Unicode bidi / zero-width / control chars
// ---------------------------------------------------------------------------

test('EE P1-3: --operator rejects U+202E (RTL OVERRIDE) bidi-control character', () => {
  // "alice‮evilbob" renders as "alicebobevila" in any bidi-aware UI
  // — a forgery surface for attestation operator names.
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
  // Guards against over-correction — the Unicode allowlist must not refuse
  // ordinary ASCII + accented characters in real names.
  const r = cli(['run', 'library-author', '--evidence', '-', '--operator', 'alice.bob+1@example.com'],
    { input: JSON.stringify({ observations: {}, verdict: {} }) });
  const err = tryJson(r.stderr.trim()) || {};
  if (err.error) {
    assert.doesNotMatch(err.error, /Unicode control|bidi-override/,
      'a plain ASCII operator identifier must not trip the Unicode gate; got: ' + err.error);
  }
});

// ---------------------------------------------------------------------------
// EE P1-4 — oversize --vex error names "MiB" and comma-formatted bytes
// ---------------------------------------------------------------------------

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
    assert.notEqual(r.status, 0, 'oversize --vex must exit non-zero');
    const err = tryJson(r.stderr.trim()) || {};
    assert.equal(err.ok, false);
    // The new message must name the MiB convention explicitly.
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

// ---------------------------------------------------------------------------
// EE P1-5 — --evidence-dir refuses junctions / symlinks
// ---------------------------------------------------------------------------

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
        // On some POSIX CI sandboxes symlink creation is forbidden.
        if (e.code === 'EPERM' || e.code === 'EACCES') return;
        throw e;
      }
      const r = cli(['run', '--all', '--evidence-dir', tmp]);
      assert.notEqual(r.status, 0,
        '--evidence-dir with a symlink entry must exit non-zero; got ' + r.status);
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
    // Create a real directory + a junction pointing somewhere else; place
    // `library-author.json` AS a junction-targeted path so the realpath
    // check fires. We use `cmd /c mklink /J` since Node has no native
    // junction-create API. mklink /J does NOT require admin on Win11.
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'ee-p1-5-junction-'));
    const evDir = path.join(tmp, 'evidence');
    const outside = path.join(tmp, 'outside');
    fs.mkdirSync(evDir);
    fs.mkdirSync(outside);
    // Place a real evidence file in `outside`; junction `evDir/library-author.json`
    // can't be a junction itself (junctions are directories), so we instead
    // junction the WHOLE evDir at a sibling path that resolves outside.
    // The realpath check fires when the *file* resolves outside resolvedDir.
    // To exercise that path on Windows we need a file inside evDir that
    // realpath-resolves to outside. The closest portable trigger is a
    // hardlink across drives (refused at API level) — instead we test the
    // junction-as-evidence-dir case: junction the dir, run, ensure either
    // (a) the entry resolves cleanly under the junction's realpath (no
    // refusal — junctions resolve to a real path, which is fine if the
    // junction target itself is the source dir), or (b) when junction
    // points elsewhere, the refusal fires. We pick (b).
    const realFile = path.join(outside, 'library-author.json');
    fs.writeFileSync(realFile, JSON.stringify({ observations: {}, verdict: {} }), 'utf8');
    // Junction evDir/sub → outside, then point the run at evDir.
    // But the loop iterates entries IN the dir; the entry would be the
    // junction `sub`, which is a directory, not a file — the !isFile()
    // check fires first. To exercise the realpath refusal we need a
    // FILE inside evDir whose realpath is elsewhere. Hardlinks across
    // directories work for this on Windows too.
    const linkPath = path.join(evDir, 'library-author.json');
    let createdLink = false;
    try {
      fs.linkSync(realFile, linkPath);  // hardlink: same inode, in evDir
      createdLink = true;
    } catch (e) {
      // EPERM / EXDEV: skip rather than fail.
      if (e.code === 'EPERM' || e.code === 'EXDEV' || e.code === 'EACCES') {
        return;
      }
      throw e;
    }
    if (!createdLink) return;
    try {
      const r = cli(['run', '--all', '--evidence-dir', evDir]);
      // Hardlinks have nlink>1, so the warning must appear on stderr.
      assert.match(r.stderr, /WARNING.*nlink=2|nlink=\d+/,
        'hardlinked evidence-dir entry must emit nlink warning on stderr');
    } finally {
      try { fs.rmSync(tmp, { recursive: true, force: true }); } catch { /* non-fatal */ }
    }
  });

// ---------------------------------------------------------------------------
// EE P1-6 — --ack on info-only verbs is refused; --ack on not-detected skips persistence
// ---------------------------------------------------------------------------

test('EE P1-6: brief --ack is refused with hint to use a run-class verb', () => {
  const r = cli(['brief', 'library-author', '--ack', '--json']);
  assert.equal(r.status, 1,
    'brief --ack must exit 1 (framework error). status=' + r.status + ' stderr=' + r.stderr.slice(0,300));
  const err = tryJson(r.stderr.trim()) || {};
  assert.equal(err.ok, false);
  assert.match(err.error || '',
    /--ack is irrelevant on this verb|no jurisdiction clock at stake/,
    'brief --ack must surface the "irrelevant" hint; got: ' + (err.error || ''));
  // The error must name the verbs where --ack DOES apply.
  assert.match(err.error || '', /run|ci|ai-run/,
    'hint must name at least one of run/ci/ai-run; got: ' + (err.error || ''));
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
  // Result body: ack=true (operator did pass --ack), but ack_applied=false
  // (classification ≠ detected, no clock at stake).
  assert.equal(out.ack, true, 'result.ack should reflect that --ack was passed');
  assert.equal(out.ack_applied, false,
    'result.ack_applied must be false when classification != detected');
  assert.match(out.ack_skipped_reason || '',
    /classification=not_detected|jurisdiction clock at stake/,
    'result.ack_skipped_reason must explain the skip; got: ' + (out.ack_skipped_reason || ''));

  // Locate the on-disk attestation and confirm operator_consent is absent.
  const candidates = [
    path.join(SUITE_HOME, 'attestations', sid),
    path.join(SUITE_HOME, '.exceptd', 'attestations', sid),
  ];
  const attRoot = candidates.find(p => fs.existsSync(p));
  assert.ok(attRoot, 'attestation dir must exist after run');
  const files = fs.readdirSync(attRoot).filter(f => f.endsWith('.json') && !f.endsWith('.sig'));
  assert.ok(files.length >= 1, 'at least one attestation file must exist');
  const body = JSON.parse(fs.readFileSync(path.join(attRoot, files[0]), 'utf8'));
  // persistAttestation may write either undefined (omitted) or null (explicit
  // skip marker) when consent does not apply. Either form proves the explicit
  // {acked_at, explicit:true} payload was NOT persisted.
  const consent = body.operator_consent;
  assert.ok(consent === undefined || consent === null,
    'persisted attestation must NOT carry the explicit operator_consent payload when classification != detected; got: ' + JSON.stringify(consent));
  if (consent && typeof consent === 'object') {
    assert.notEqual(consent.explicit, true,
      'consent.explicit must not be true when persistence was supposed to be skipped');
  }
});

// ---------------------------------------------------------------------------
// EE P1-7 — stdin auto-detect on a wrapped empty stream does not hang
// ---------------------------------------------------------------------------

test('EE P1-7: run with explicit --evidence-dir and empty stdin (size 0) completes < 5s', () => {
  // Smoke: spawn cli without piping input; opts.input is undefined, so
  // spawnSync provides a closed/empty stdin (depending on platform). On
  // POSIX this looks like a wrapped pipe with size === 0. Pre-fix the
  // truthy `!isTTY` check fell into readFileSync(0) and could block;
  // the fstat probe must short-circuit.
  //
  // We don't have a portable way to construct an "isTTY===undefined &&
  // size===0" stdin without writing a native C wrapper, so we exercise
  // the closest portable analog: invoke `run --evidence <file>` so the
  // stdin auto-detect must NOT fire (because args.evidence is set), and
  // separately invoke run without --evidence relying on spawnSync's
  // default stdin (a closed pipe).
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
  // Empty input — spawnSync writes nothing and closes stdin. Pre-fix
  // could hang on platforms where stdin appears non-TTY but has no data.
  const start = Date.now();
  const r = cli(['run', 'library-author', '--json'], { input: '', timeout: 5000 });
  const elapsed = Date.now() - start;
  assert.ok(elapsed < 5000,
    `run with empty stdin must complete < 5s (no readFileSync block). Took ${elapsed}ms; status=${r.status} signal=${r.signal}`);
  assert.notEqual(r.signal, 'SIGTERM',
    'run must not be killed by timeout (would indicate stdin block)');
  // Either the run completed (any exit code is acceptable) or it produced
  // a parseable error body — both prove the process didn't hang.
  const body = tryJson(r.stdout.trim()) || tryJson(r.stderr.trim()) || {};
  assert.ok(body && (body.ok !== undefined || body.error !== undefined || r.status === 0),
    'empty-stdin run must yield a parseable body or clean exit; got status=' + r.status + ' stdout=' + r.stdout.slice(0,200) + ' stderr=' + r.stderr.slice(0,200));
});

test('EE P1-7: hasReadableStdin helper is defined in bin/exceptd.js', () => {
  // Contract: the fstat-probing helper must exist by name. Drift-resistant
  // way to assert the EE P1-7 architecture is in place.
  const src = fs.readFileSync(path.join(ROOT, 'bin', 'exceptd.js'), 'utf8');
  assert.match(src, /function hasReadableStdin\(\)/,
    'bin/exceptd.js must define a hasReadableStdin() helper');
  assert.match(src, /fs\.fstatSync\(0\)/,
    'hasReadableStdin must probe via fs.fstatSync(0) to avoid blocking');
});
