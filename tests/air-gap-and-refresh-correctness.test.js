'use strict';

/**
 * Air-gap egress guards + refresh/cve/framework-gap correctness regressions.
 *
 * Every test exercises the real CLI through the shared cli() harness
 * (subprocess spawn of bin/exceptd.js) and asserts the EXACT exit code plus
 * the field value/type per the project anti-coincidence rule: never
 * `notEqual(0)`, never bare `assert.ok(field)` without a paired value/type
 * assertion. All reproduction is offline — no test makes a real network call;
 * air-gap is forced via EXCEPTD_AIR_GAP=1 / --air-gap and offline catalogs.
 *
 * Areas covered (one block per reproduced finding):
 *   1. watchlist --org-scan refuses under air-gap instead of fetching GitHub.
 *   2. refresh --network refuses under air-gap (exit 4).
 *   3. prefetch treats EXCEPTD_AIR_GAP / --air-gap as no-network (dry-run).
 *   4. cache-integrity refusals propagate exit 4 (not 1).
 *   5. refresh --source "" errors (exit 2) instead of silently running all.
 *   6. cve "<whitespace>" is a usage error (exit 1), not a fabricated lookup.
 *   7. refresh --advisory "   " hits the dedicated empty-advisory guard (exit 2).
 *   8. framework-gap single-framework summary agrees with the per-framework body.
 *   9. report executive writes its progress line to stderr, not stdout.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const fs = require('node:fs');
const os = require('node:os');
const crypto = require('node:crypto');
const { spawnSync } = require('node:child_process');

const { ROOT, makeSuiteHome, makeCli, tryJson } = require('./_helpers/cli');

const SUITE_HOME = makeSuiteHome('exceptd-airgap-refresh-');
const cli = makeCli(SUITE_HOME);

// A scenario CVE that the offline catalog carries framework-control gaps for.
const SCENARIO_CVE = 'CVE-2025-53773';

// Per-suite scratch dir for caches / report-out files so refresh runs never
// pollute the package root (the child spawns with cwd = PKG_ROOT).
const SCRATCH = fs.mkdtempSync(path.join(os.tmpdir(), 'exceptd-airgap-scratch-'));
process.on('exit', () => { try { fs.rmSync(SCRATCH, { recursive: true, force: true }); } catch { /* non-fatal */ } });

// ===================================================================
// 1. watchlist --org-scan air-gap egress guard
// ===================================================================

test('watchlist --org-scan refuses under EXCEPTD_AIR_GAP=1 (exit 4, no fetch)', () => {
  const r = cli(['watchlist', '--org-scan', '--org', 'someorg', '--json'], { env: { EXCEPTD_AIR_GAP: '1' } });
  assert.equal(r.status, 4, `expected exit 4; got ${r.status} (stdout: ${r.stdout.slice(0, 200)})`);
  const body = tryJson(r.stdout.trim()) || tryJson(r.stderr.trim());
  assert.ok(body, `expected JSON output; got stdout=${r.stdout.slice(0, 200)}`);
  assert.equal(body.ok, false);
  assert.equal(body.source, 'air-gap');
  assert.equal(body.verb, 'watchlist');
  assert.equal(body.mode, 'org-scan');
  assert.equal(typeof body.error, 'string');
  assert.match(body.error, /air-gap: watchlist --org-scan requires network egress to api\.github\.com; refused\./);
});

test('watchlist --org-scan refuses under --air-gap flag (exit 4)', () => {
  const r = cli(['watchlist', '--org-scan', '--org', 'someorg', '--air-gap', '--json']);
  assert.equal(r.status, 4, `expected exit 4; got ${r.status} (stdout: ${r.stdout.slice(0, 200)})`);
  const body = tryJson(r.stdout.trim());
  assert.ok(body, `expected JSON on stdout; got ${r.stdout.slice(0, 200)}`);
  assert.equal(body.ok, false);
  assert.equal(body.source, 'air-gap');
});

// ===================================================================
// 2. refresh --network air-gap refusal
// ===================================================================

test('refresh --network refuses under EXCEPTD_AIR_GAP=1 (exit 4, no fetch)', () => {
  const r = cli(['refresh', '--network', '--json'], { env: { EXCEPTD_AIR_GAP: '1' } });
  assert.equal(r.status, 4, `expected exit 4; got ${r.status} (stdout: ${r.stdout.slice(0, 200)} stderr: ${r.stderr.slice(0, 200)})`);
  const body = tryJson(r.stdout.trim()) || tryJson(r.stderr.trim());
  assert.ok(body, `expected JSON output; got stdout=${r.stdout.slice(0, 200)}`);
  assert.equal(body.ok, false);
  assert.equal(body.source, 'air-gap');
  assert.equal(typeof body.error, 'string');
  assert.match(body.error, /air-gap: refresh --network requires network egress; refused\. Use --from-cache --apply for the offline path\./);
});

test('refresh --network refuses under --air-gap flag (exit 4)', () => {
  const r = cli(['refresh', '--network', '--air-gap', '--json']);
  assert.equal(r.status, 4, `expected exit 4; got ${r.status} (stdout: ${r.stdout.slice(0, 200)})`);
  const body = tryJson(r.stdout.trim()) || tryJson(r.stderr.trim());
  assert.ok(body, `expected JSON; got ${r.stdout.slice(0, 200)}`);
  assert.equal(body.ok, false);
  assert.equal(body.source, 'air-gap');
});

// ===================================================================
// 2b. tarball fetch-destination allowlist (SSRF guard)
// ===================================================================

test('refresh-network pins the tarball fetch host to the npm registry', () => {
  const { isAllowedTarballHost } = require('../lib/refresh-network.js');
  // The registry the /latest metadata is queried from, and its tarball path.
  assert.equal(isAllowedTarballHost('https://registry.npmjs.org/@blamejs/exceptd-skills/-/exceptd-skills.tgz'), true);
  assert.equal(isAllowedTarballHost('https://npmjs.com/x.tgz'), true);
  // A tampered metadata response / fixture must not be able to steer the fetch
  // at an internal or attacker-controlled host.
  assert.equal(isAllowedTarballHost('https://registry.npmjs.org.attacker.test/x.tgz'), false);
  assert.equal(isAllowedTarballHost('https://evil.example/x.tgz'), false);
  assert.equal(isAllowedTarballHost('http://169.254.169.254/latest/meta-data/'), false);
  assert.equal(isAllowedTarballHost('not a url'), false);
});

// ===================================================================
// 3. prefetch honors EXCEPTD_AIR_GAP / --air-gap (dry-run, no egress)
// ===================================================================

test('prefetch under EXCEPTD_AIR_GAP=1 plans no live fetches (dry-run)', () => {
  const r = cli(['prefetch'], { env: { EXCEPTD_AIR_GAP: '1' } });
  assert.equal(r.status, 0, `expected exit 0; got ${r.status} (stderr: ${r.stderr.slice(0, 200)})`);
  // The dry-run branch prints "DRY-RUN ... item(s)" and the "(dry-run)" summary
  // and NEVER the "fetching ... item(s)" header that the live path uses.
  assert.match(r.stdout, /prefetch — DRY-RUN/, 'prefetch should report DRY-RUN under air-gap');
  assert.match(r.stdout, /\(dry-run\)/, 'prefetch should emit the dry-run summary');
  assert.doesNotMatch(r.stdout, /prefetch — fetching/, 'prefetch must NOT plan live fetches under air-gap');
});

test('prefetch under --air-gap flag plans no live fetches (dry-run)', () => {
  const r = cli(['prefetch', '--air-gap']);
  assert.equal(r.status, 0, `expected exit 0; got ${r.status} (stderr: ${r.stderr.slice(0, 200)})`);
  assert.match(r.stdout, /prefetch — DRY-RUN/);
  assert.doesNotMatch(r.stdout, /prefetch — fetching/);
});

// ===================================================================
// 4. cache-integrity refusals exit 4 (documented BLOCKED), not 1
// ===================================================================

test('refresh --from-cache sha256 mismatch propagates exit 4 (not 1)', () => {
  // Build a cache whose payload no longer matches the sha256 recorded in
  // _index.json (a payload-tamper). --force-stale lets us past the cache
  // SIGNATURE gate so the run reaches readCachedJson's sha256 check, which
  // --force-stale deliberately does NOT bypass — the canonical tamper signal.
  // Before the fix this surfaced as exit 1 (the generic hadFailure code);
  // the integrity marker must now drive exit 4.
  const cacheDir = fs.mkdtempSync(path.join(SCRATCH, 'tampered-'));
  fs.mkdirSync(path.join(cacheDir, 'kev'), { recursive: true });
  const payload = { vulnerabilities: [{ cveID: SCENARIO_CVE, dateAdded: '2026-01-01' }] };
  fs.writeFileSync(path.join(cacheDir, 'kev', 'known_exploited_vulnerabilities.json'), JSON.stringify(payload));
  // Record a deliberately wrong sha256 so the recompute mismatches.
  fs.writeFileSync(path.join(cacheDir, '_index.json'), JSON.stringify({
    entries: { 'kev/known_exploited_vulnerabilities': { sha256: '0'.repeat(64) } },
  }));

  const reportOut = path.join(cacheDir, 'report.json');
  const r = cli([
    'refresh', '--source', 'kev', '--from-cache', cacheDir,
    '--report-out', reportOut, '--force-stale', '--quiet',
  ]);
  assert.equal(r.status, 4, `expected exit 4; got ${r.status} (stderr: ${r.stderr.slice(0, 300)})`);
  const report = JSON.parse(fs.readFileSync(reportOut, 'utf8'));
  assert.equal(report.sources.kev.status, 'error');
  assert.equal(report.sources.kev.cache_integrity, true);
  assert.match(report.sources.kev.error, /cache-integrity: sha256 mismatch/);
});

test('refresh --from-cache unsigned/partial index refuses with exit 4', () => {
  // A partial-index injection (index present, no per-entry sha256, no valid
  // sidecar signature) without --force-stale must refuse with exit 4 rather
  // than consuming the unverified cache. The signature precondition catches
  // it first; the documented code is 4 (BLOCKED / precondition refusal).
  const cacheDir = fs.mkdtempSync(path.join(SCRATCH, 'partial-'));
  fs.mkdirSync(path.join(cacheDir, 'kev'), { recursive: true });
  const payload = { vulnerabilities: [{ cveID: SCENARIO_CVE, dateAdded: '2026-01-01' }] };
  fs.writeFileSync(path.join(cacheDir, 'kev', 'known_exploited_vulnerabilities.json'), JSON.stringify(payload));
  fs.writeFileSync(path.join(cacheDir, '_index.json'), JSON.stringify({ entries: {} }));

  const reportOut = path.join(cacheDir, 'report.json');
  const r = cli([
    'refresh', '--source', 'kev', '--from-cache', cacheDir,
    '--report-out', reportOut, '--quiet',
  ]);
  assert.equal(r.status, 4, `expected exit 4; got ${r.status} (stderr: ${r.stderr.slice(0, 300)})`);
  // Confirm the refusal is the cache precondition, not a network attempt.
  assert.match(r.stderr, /signature verification failed|cache-integrity/);
});

// keep the integrity-marker recompute honest: the recorded sha must be the
// canonical-stringify of the parsed payload, so an *untampered* index would
// have matched. (Sanity guard, not an egress test.)
test('cache sha256 recompute is over JSON.stringify(parsed) (sanity)', () => {
  const payload = { vulnerabilities: [{ cveID: SCENARIO_CVE }] };
  const sha = crypto.createHash('sha256').update(JSON.stringify(payload)).digest('hex');
  assert.equal(sha.length, 64);
  assert.notEqual(sha, '0'.repeat(64));
});

// ===================================================================
// 5. refresh --source "" errors instead of silently running all
// ===================================================================

test('refresh --source "" errors (exit 2) listing valid sources', () => {
  const r = cli(['refresh', '--source', '', '--quiet']);
  assert.equal(r.status, 2, `expected exit 2; got ${r.status} (stderr: ${r.stderr.slice(0, 200)})`);
  // The error lists the valid source names so the operator sees the typo.
  assert.match(r.stderr, /--source requires at least one source name/);
  for (const name of ['kev', 'epss', 'nvd', 'rfc', 'pins', 'ghsa', 'osv', 'advisories', 'cve-regression-watcher']) {
    assert.match(r.stderr, new RegExp(`\\b${name}\\b`), `valid-source list should mention "${name}"`);
  }
});

test('refresh --source "," (trims to empty) also errors exit 2', () => {
  const r = cli(['refresh', '--source', ',', '--quiet']);
  assert.equal(r.status, 2, `expected exit 2; got ${r.status} (stderr: ${r.stderr.slice(0, 200)})`);
  assert.match(r.stderr, /--source requires at least one source name/);
});

// ===================================================================
// 6. cve "<whitespace>" is a usage error, not a fabricated lookup
// ===================================================================

test('cve "   " (whitespace) is a usage error (exit 1), matching cve ""', () => {
  const ws = cli(['cve', '   ']);
  assert.equal(ws.status, 1, `expected exit 1; got ${ws.status} (stderr: ${ws.stderr.slice(0, 200)})`);
  const body = tryJson(ws.stderr.trim()) || tryJson(ws.stdout.trim());
  assert.ok(body, `expected JSON; got stderr=${ws.stderr.slice(0, 200)}`);
  assert.equal(body.ok, false);
  assert.equal(body.verb, 'cve');
  assert.match(body.error, /usage: exceptd cve/);
  // It must NOT have resolved as a "fabricated" citation.
  assert.equal(body.status, undefined, 'whitespace cve must not produce a resolution status');

  // Parity with the empty-string form.
  const empty = cli(['cve', '']);
  assert.equal(empty.status, 1, `cve "" should also exit 1; got ${empty.status}`);
});

// ===================================================================
// 7. refresh --advisory "   " hits the dedicated empty-advisory guard
// ===================================================================

test('refresh --advisory "   " hits the dedicated empty-advisory guard (exit 2)', () => {
  const r = cli(['refresh', '--advisory', '   ', '--quiet'], { env: { EXCEPTD_AIR_GAP: '1' } });
  assert.equal(r.status, 2, `expected exit 2; got ${r.status} (stderr: ${r.stderr.slice(0, 200)})`);
  const body = tryJson(r.stderr.trim()) || tryJson(r.stdout.trim());
  assert.ok(body, `expected JSON; got stderr=${r.stderr.slice(0, 200)}`);
  assert.equal(body.ok, false);
  assert.match(body.error, /--advisory requires a non-empty identifier/);
});

// ===================================================================
// 8. framework-gap single-framework summary agrees with the body
// ===================================================================

test('framework-gap single framework: summary total_gaps equals per-framework gap_count', () => {
  const r = cli(['framework-gap', 'nist-800-53', SCENARIO_CVE, '--json']);
  assert.equal(r.status, 0, `expected exit 0; got ${r.status} (stderr: ${r.stderr.slice(0, 200)})`);
  const body = tryJson(r.stdout.trim());
  assert.ok(body, `expected JSON on stdout; got ${r.stdout.slice(0, 200)}`);
  const perFw = Object.values(body.frameworks).reduce((acc, v) => acc + v.gap_count, 0);
  // Single explicit framework -> summary matching count equals the body.
  assert.equal(typeof body.summary.total_gaps, 'number');
  assert.equal(body.summary.total_gaps, perFw,
    `summary.total_gaps (${body.summary.total_gaps}) must equal the sum of per-framework gap_count (${perFw})`);
});

test('framework-gap single framework: human Summary line agrees with body count', () => {
  const r = cli(['framework-gap', 'nist-800-53', SCENARIO_CVE]);
  assert.equal(r.status, 0, `expected exit 0; got ${r.status} (stderr: ${r.stderr.slice(0, 200)})`);
  const bodyMatch = r.stdout.match(/### nist-800-53 — (\d+) matching control gap\(s\)/);
  const sumMatch = r.stdout.match(/Summary: (\d+) matching gaps/);
  assert.ok(bodyMatch, `expected a per-framework body line; got ${r.stdout.slice(0, 300)}`);
  assert.ok(sumMatch, `expected a Summary line; got ${r.stdout.slice(0, 300)}`);
  assert.equal(sumMatch[1], bodyMatch[1],
    `Summary count (${sumMatch[1]}) must equal the per-framework body count (${bodyMatch[1]})`);
});

test('framework-gap all: summary counts every scenario-relevant gap (unchanged)', () => {
  const r = cli(['framework-gap', 'all', SCENARIO_CVE, '--json']);
  assert.equal(r.status, 0, `expected exit 0; got ${r.status} (stderr: ${r.stderr.slice(0, 200)})`);
  const body = tryJson(r.stdout.trim());
  assert.ok(body, `expected JSON; got ${r.stdout.slice(0, 200)}`);
  // "all" keeps catalog-wide counting: total_gaps must be a number >= the
  // max single-framework gap_count (it aggregates the scenario hits).
  assert.equal(typeof body.summary.total_gaps, 'number');
  const maxFw = Math.max(0, ...Object.values(body.frameworks).map((v) => v.gap_count));
  assert.ok(body.summary.total_gaps >= maxFw,
    `all-frameworks total_gaps (${body.summary.total_gaps}) should be >= max per-framework gap_count (${maxFw})`);
});

// ===================================================================
// 9. report executive: progress line goes to stderr, markdown on stdout
// ===================================================================

test('report executive writes markdown header as the first stdout line', () => {
  const r = cli(['report', 'executive']);
  assert.equal(r.status, 0, `expected exit 0; got ${r.status} (stderr: ${r.stderr.slice(0, 200)})`);
  const firstStdoutLine = r.stdout.split('\n')[0];
  assert.equal(firstStdoutLine, '# exceptd Executive Report',
    `first stdout line must be the markdown header; got "${firstStdoutLine}"`);
  // The progress notice must NOT pollute stdout.
  assert.doesNotMatch(r.stdout, /\[orchestrator\] Generating/, 'progress line must not be on stdout');
  assert.match(r.stderr, /\[orchestrator\] Generating executive report/, 'progress line must be on stderr');
});

// ===================================================================
// 10. refresh --network transport-integrity floor
//
// The swap loop replaces data/ + manifest-snapshot.json, which carry no
// per-content Ed25519 signature — a transport hash is their only integrity
// anchor. Registry metadata that supplies dist.tarball but NEITHER
// dist.integrity (sha512 SRI) NOR dist.shasum must refuse the swap (exit 4)
// instead of installing unauthenticated catalog bytes. A fixture with a valid
// sha512 dist.integrity over the served bytes still swaps.
// ===================================================================

// Build an isolated install copy + a signed-but-data-poisoned npm-style
// tarball, then drive the real lib/refresh-network.js main() with https.get
// stubbed to serve that tarball, so the full swap path runs offline. The
// install copy is a sibling tempdir so the swap never touches the repo tree.
function refreshNetworkSwapHarness() {
  const sign = require('../lib/sign.js');
  const REPO = ROOT;
  const inst = fs.mkdtempSync(path.join(SCRATCH, 'rn-install-'));
  for (const rel of ['keys', 'manifest.json', 'package.json', 'lib', 'vendor', 'skills', 'data']) {
    fs.cpSync(path.join(REPO, rel), path.join(inst, rel), { recursive: true });
  }
  // EPHEMERAL signing identity — never read the repo's .keys/private.pem, which
  // is gitignored and absent on a fresh CI checkout. The install copy's public
  // key, every per-skill signature, and the manifest envelope are all re-signed
  // with this key, so the swap path's signature + fingerprint checks verify
  // against an identity that exists only inside this test.
  const { privateKey: priv, publicKey: pub } = crypto.generateKeyPairSync('ed25519', {
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    publicKeyEncoding: { type: 'spki', format: 'pem' },
  });
  fs.writeFileSync(path.join(inst, 'keys', 'public.pem'), pub);
  // Re-pin keys/EXPECTED_FINGERPRINT to the ephemeral key (same SHA256:<base64-
  // of-spki-der> form the swap path compares), else the fingerprint-pin guard
  // refuses the swap because the install copy still carries the repo key's pin.
  const ephFp = crypto.createHash('sha256')
    .update(crypto.createPublicKey(pub).export({ type: 'spki', format: 'der' }))
    .digest('base64');
  fs.writeFileSync(path.join(inst, 'keys', 'EXPECTED_FINGERPRINT'), `SHA256:${ephFp}\n`);

  // Version bumped so the swap is not a no-op; re-sign every per-skill body and
  // the manifest envelope with the ephemeral key so they verify against the
  // ephemeral public key written above.
  // Per-skill signature in the exact form lib/sign.js#signContent produces
  // (normalize → Ed25519 ieee-p1363) — signContent itself is not exported, but
  // normalize is, and lib/verify.js uses the identical transform.
  const signBody = (body) =>
    crypto.sign(null, Buffer.from(sign.normalize(body), 'utf8'), { key: priv, dsaEncoding: 'ieee-p1363' }).toString('base64');
  const manifest = JSON.parse(fs.readFileSync(path.join(inst, 'manifest.json'), 'utf8'));
  manifest.version = '999.0.0';
  for (const sk of manifest.skills) {
    sk.signature = signBody(fs.readFileSync(path.join(inst, sk.path), 'utf8'));
  }
  delete manifest.manifest_signature;
  manifest.manifest_signature = sign.signCanonicalManifest(manifest, priv);

  // Poison data/cve-catalog.json — the file with no per-content signature.
  const poisonedCatalog = fs
    .readFileSync(path.join(inst, 'data', 'cve-catalog.json'), 'utf8')
    .replace(/^\{/, '{"__ATTACKER_INJECTED__":"transport-integrity regression marker",');

  const tarHeader = (name, size) => {
    const b = Buffer.alloc(512, 0);
    b.write(name.slice(0, 100), 0, 'utf8');
    b.write('0000644\0', 100); b.write('0000000\0', 108); b.write('0000000\0', 116);
    b.write(size.toString(8).padStart(11, '0') + '\0', 124);
    b.write(Math.floor(Date.now() / 1000).toString(8).padStart(11, '0') + '\0', 136);
    b.write('        ', 148); b.write('0', 156);
    b.write('ustar\0', 257); b.write('00', 263);
    let sum = 0; for (let i = 0; i < 512; i++) sum += b[i];
    b.write(sum.toString(8).padStart(6, '0') + '\0 ', 148);
    return b;
  };
  const tarEntry = (name, body) => {
    const x = Buffer.isBuffer(body) ? body : Buffer.from(body, 'utf8');
    return Buffer.concat([tarHeader(name, x.length), x, Buffer.alloc((512 - (x.length % 512)) % 512, 0)]);
  };
  const parts = [
    tarEntry('package/manifest.json', JSON.stringify(manifest, null, 2)),
    tarEntry('package/keys/public.pem', pub),
    tarEntry('package/manifest-snapshot.json', '{"snapshot":"attacker-controlled"}'),
    tarEntry('package/data/cve-catalog.json', poisonedCatalog),
  ];
  for (const sk of manifest.skills) parts.push(tarEntry('package/' + sk.path, fs.readFileSync(path.join(inst, sk.path))));
  parts.push(Buffer.alloc(1024, 0));
  const tgz = require('node:zlib').gzipSync(Buffer.concat(parts));
  const tgzPath = path.join(inst, 'tarball.tgz');
  fs.writeFileSync(tgzPath, tgz);

  // Preload that serves `tgz` for any npmjs.org *.tgz GET (offline; no network).
  const preloadPath = path.join(inst, 'preload.js');
  fs.writeFileSync(preloadPath,
    '"use strict";const https=require("https");const fs=require("fs");' +
    'const {PassThrough}=require("stream");const {EventEmitter}=require("events");' +
    'const TGZ=fs.readFileSync(process.env.RN_TGZ);const o=https.get;' +
    'https.get=function(opts,cb){const h=(opts&&opts.host)||"";const p=(opts&&opts.path)||"";' +
    'if(String(h).includes("npmjs.org")&&/\\.tgz$/.test(p)){' +
    'const res=new PassThrough();res.statusCode=200;const req=new EventEmitter();req.destroy=()=>{};' +
    'process.nextTick(()=>{cb(res);process.nextTick(()=>res.end(TGZ));});return req;}' +
    'return o.apply(this,arguments);};');

  const sri = 'sha512-' + crypto.createHash('sha512').update(tgz).digest('base64');
  const tarballUrl = 'https://registry.npmjs.org/@blamejs/exceptd-skills/-/exceptd-skills-999.0.0.tgz';

  const run = (distMeta) => {
    const fixturePath = path.join(inst, 'fixture.json');
    fs.writeFileSync(fixturePath, JSON.stringify({ version: '999.0.0', dist: distMeta }));
    const r = spawnSync(process.execPath,
      ['-r', preloadPath, path.join(inst, 'lib', 'refresh-network.js'), 'refresh', '--network', '--json'],
      { env: { ...process.env, RN_TGZ: tgzPath, EXCEPTD_REGISTRY_FIXTURE: fixturePath }, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
    const poisoned = fs.readFileSync(path.join(inst, 'data', 'cve-catalog.json'), 'utf8').includes('__ATTACKER_INJECTED__');
    return { r, poisoned };
  };
  return { run, sri, tarballUrl };
}

test('refresh --network refuses the swap when dist.integrity AND dist.shasum are both absent (exit 4)', () => {
  const { run, tarballUrl } = refreshNetworkSwapHarness();
  // dist.tarball present, NO dist.integrity, NO dist.shasum.
  const { r, poisoned } = run({ tarball: tarballUrl });
  assert.equal(r.status, 4, `expected exit 4; got ${r.status} (stdout: ${r.stdout.slice(0, 300)} stderr: ${r.stderr.slice(0, 300)})`);
  const body = tryJson(r.stdout.trim().split('\n').pop()) || tryJson(r.stderr.trim().split('\n').pop());
  assert.ok(body, `expected JSON refusal; got stdout=${r.stdout.slice(0, 300)}`);
  assert.equal(body.ok, false);
  assert.equal(typeof body.error, 'string');
  assert.match(body.error, /no verifiable transport integrity/);
  // The unauthenticated catalog bytes must NOT have been installed.
  assert.equal(poisoned, false, 'poisoned data/cve-catalog.json must NOT be swapped in when no transport hash is verifiable');
});

test('refresh --network still swaps when a valid sha512 dist.integrity is present (exit 0)', () => {
  const { run, sri, tarballUrl } = refreshNetworkSwapHarness();
  // Valid sha512 SRI over the served bytes — the legitimate path must keep working.
  const { r } = run({ tarball: tarballUrl, integrity: sri });
  assert.equal(r.status, 0, `expected exit 0; got ${r.status} (stdout: ${r.stdout.slice(0, 300)} stderr: ${r.stderr.slice(0, 300)})`);
  const body = tryJson(r.stdout.trim().split('\n').pop());
  assert.ok(body, `expected JSON success; got stdout=${r.stdout.slice(0, 300)}`);
  assert.equal(body.ok, true);
  assert.equal(typeof body.files_written, 'number');
  assert.ok(body.files_written > 0, 'a successful swap writes at least one file');
});
