#!/usr/bin/env node
'use strict';

/**
 * exceptd Security — bootstrap ceremony.
 *
 * Three audiences, three behaviors. The script auto-detects which mode is
 * appropriate so a downstream consumer never accidentally invalidates the
 * maintainer's signing key.
 *
 *   1. Downstream consumer (keys/public.pem exists, .keys/private.pem missing,
 *      no --init flag) — VERIFY ONLY. The maintainer already shipped the public
 *      key + signed manifest. Running `npm run bootstrap` here just confirms
 *      the working tree is intact. No keypair is generated; no signatures are
 *      rewritten. This is the safe default.
 *
 *   2. Maintainer re-sign (.keys/private.pem exists) — SIGN + VERIFY. Used
 *      after editing skill content. Re-signs every skill with the existing
 *      private key, then verifies.
 *
 *   3. First-maintainer init (no keys/public.pem, OR --init explicitly passed)
 *      — GENERATE + SIGN + VERIFY. Used once when a maintainer sets up signing
 *      for a brand-new clone. Generates an Ed25519 keypair, signs every skill,
 *      and verifies. The new public key is committed; the private key stays in
 *      .keys/ (gitignored).
 *
 * The private key never leaves the maintainer's machine. The public key in
 * keys/public.pem is the one tracked artifact and is committed by the
 * maintainer after first init.
 *
 * Subprocesses use execFileSync (no shell) with argument arrays — there is no
 * user input on the path, and avoiding the shell removes the injection surface
 * regardless.
 *
 * Usage:
 *   node scripts/bootstrap.js              Auto-detect mode and run.
 *   node scripts/bootstrap.js --init       Force first-maintainer init (generate
 *                                          keypair + sign + verify).
 *   node scripts/bootstrap.js --force      Re-run even if marker exists.
 *   node scripts/bootstrap.js --help       Print this help text.
 *
 * Dependencies: Node 24 stdlib only. package.json has no runtime deps and
 * this script keeps it that way.
 */

const fs = require('node:fs');
const path = require('node:path');
const childProcess = require('node:child_process');

const ROOT = path.join(__dirname, '..');
const PRIVATE_KEY_PATH = path.join(ROOT, '.keys', 'private.pem');
const PUBLIC_KEY_PATH = path.join(ROOT, 'keys', 'public.pem');
const MARKER_PATH = path.join(ROOT, '.bootstrap-complete');
const SIGN_SCRIPT = path.join(ROOT, 'lib', 'sign.js');
const VERIFY_SCRIPT = path.join(ROOT, 'lib', 'verify.js');

const HELP = `
exceptd Security — bootstrap ceremony

Mode is auto-detected from current state:

  Downstream consumer (default):
    Public key present, private key absent → VERIFY ONLY.
    No keypair generated; no signatures rewritten.

  Maintainer re-sign:
    Private key present → SIGN + VERIFY.
    Re-signs every skill in manifest.json with the existing private key.

  First-maintainer init (--init or no keys at all):
    GENERATE + SIGN + VERIFY.
    Generates an Ed25519 keypair, signs every skill, runs the verifier.

Usage:
  node scripts/bootstrap.js              Auto-detect mode and run.
  node scripts/bootstrap.js --init       Force first-maintainer init.
  node scripts/bootstrap.js --force      Re-run even if marker exists.
  node scripts/bootstrap.js --help       Show this message.

Outputs (only in maintainer modes):
  .keys/private.pem        Ed25519 private key (gitignored — never commit).
  keys/public.pem          Ed25519 public key (commit this).
  manifest.json            Updated with per-skill signatures.
  .bootstrap-complete      Local timestamp marker (gitignored).
`;

function parseArgs(argv) {
  const args = { force: false, init: false, help: false };
  for (const a of argv.slice(2)) {
    if (a === '--force') args.force = true;
    else if (a === '--init') args.init = true;
    else if (a === '--help' || a === '-h') args.help = true;
    else {
      console.error(`[bootstrap] Unknown argument: ${a}`);
      console.error('[bootstrap] Run with --help for usage.');
      process.exit(2);
    }
  }
  return args;
}

function detectMode(args) {
  const hasPublic = fs.existsSync(PUBLIC_KEY_PATH);
  const hasPrivate = fs.existsSync(PRIVATE_KEY_PATH);

  if (args.init) return 'init';
  if (hasPrivate) return 'resign';
  if (hasPublic) return 'verify-only';
  return 'init';
}

function run(label, scriptPath, scriptArgs) {
  const pretty = `node ${path.relative(ROOT, scriptPath)} ${scriptArgs.join(' ')}`.trim();
  console.log(`[bootstrap] ${label}: ${pretty}`);
  try {
    // execFileSync: no shell, args passed as a vetted array. The script path
    // and all args here are constants under this repo's control.
    childProcess.execFileSync(process.execPath, [scriptPath, ...scriptArgs], {
      cwd: ROOT,
      stdio: 'inherit'
    });
  } catch (err) {
    console.error(`[bootstrap] FAILED at step "${label}".`);
    process.exit(err.status && Number.isInteger(err.status) ? err.status : 1);
  }
}

function writeMarker() {
  const payload = {
    completed_at: new Date().toISOString(),
    node_version: process.version,
    platform: process.platform
  };
  fs.writeFileSync(MARKER_PATH, JSON.stringify(payload, null, 2) + '\n', 'utf8');
  console.log(`[bootstrap] Wrote ${path.relative(ROOT, MARKER_PATH)}`);
}

function main() {
  const args = parseArgs(process.argv);

  if (args.help) {
    process.stdout.write(HELP);
    return;
  }

  if (fs.existsSync(MARKER_PATH) && !args.force) {
    console.log('[bootstrap] Already complete (.bootstrap-complete present).');
    console.log('[bootstrap] Pass --force to re-run the ceremony.');
    return;
  }

  const mode = detectMode(args);

  if (mode === 'verify-only') {
    // Downstream consumer path. The maintainer already shipped the public
    // key and signed manifest. Running bootstrap here just confirms tree
    // integrity — never generates or signs, which would invalidate the
    // upstream maintainer's signing chain.
    console.log('[bootstrap] Detected downstream-consumer state:');
    console.log('  - keys/public.pem present (shipped by maintainer)');
    console.log('  - .keys/private.pem absent');
    console.log('[bootstrap] Running VERIFY ONLY. No keypair will be generated.');
    console.log('[bootstrap] If you ARE the maintainer setting up a new clone, pass --init.');
    console.log();
    run('verify signatures', VERIFY_SCRIPT, []);
    writeMarker();
    console.log('\n[bootstrap] Verify-only ceremony complete. Tree integrity confirmed.');
    return;
  }

  if (mode === 'resign') {
    // Maintainer re-sign path. Private key already exists; re-sign every
    // skill against the current content and verify.
    console.log('[bootstrap] Detected maintainer re-sign state (private key present).');
    console.log('[bootstrap] Re-signing every skill with the existing private key.');
    console.log();
    run('sign all skills', SIGN_SCRIPT, ['sign-all']);
    run('verify signatures', VERIFY_SCRIPT, []);
    writeMarker();
    console.log('\n[bootstrap] Re-sign ceremony complete.');
    console.log('[bootstrap] If skill content or manifest.json changed, commit the updates:');
    console.log('  git add manifest.json');
    console.log('  git commit -m "resign: skill content updated"');
    return;
  }

  // mode === 'init' — first-maintainer setup.
  console.log('[bootstrap] First-maintainer init mode:');
  console.log('  - generating Ed25519 keypair (one-time)');
  console.log('  - signing every skill listed in manifest.json');
  console.log('  - verifying the signature chain end-to-end');
  console.log();
  run('generate Ed25519 keypair', SIGN_SCRIPT, ['generate-keypair']);
  run('sign all skills', SIGN_SCRIPT, ['sign-all']);
  run('verify signatures', VERIFY_SCRIPT, []);
  writeMarker();

  console.log('\n[bootstrap] First-maintainer init complete. Next steps:');
  console.log('  git add keys/public.pem manifest.json');
  console.log('  git commit -m "bootstrap: add signing public key and signed manifest"');
}

if (require.main === module) {
  main();
}
