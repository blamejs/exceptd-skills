'use strict';

/**
 * `run --all` lock-contention surfacing.
 *
 * Cycle 6 P1 gap: persistAttestation acquires a per-attestation-file
 * lockfile (`<filename>.lock`). When a sibling process holds the lock and
 * is still alive, persist returns
 *   { ok:false, lock_contention:true, exit_code: EXIT_CODES.LOCK_CONTENTION }
 * and pins process.exitCode = 8. Pre-staging a lockfile pointing at the
 * current test process PID forces the live-PID branch (vs. the stale-PID
 * reclaim or stale-mtime cleanup branches) — that's the only path that
 * yields exit 8 without a real concurrent invocation.
 *
 * The test pins r.status === 8 EXACTLY (per CLAUDE.md anti-coincidence
 * rule: notEqual(0) would mask a regression to exit 1/3/9) and asserts
 * the structured surfacing path: top-level lock_contention or per-result
 * attestation_persist.lock_contention.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
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
    // To trigger the lock-contention path in persistAttestation, three
    // preconditions must hold simultaneously:
    //   1. The attestation file already exists (so 'wx' write throws EEXIST)
    //   2. --force-overwrite is passed (otherwise persist returns
    //      session-id-collision exit 7 instead of entering the lock path)
    //   3. The .lock sibling exists with an alive PID different from this
    //      process (so EEXIST on the lockfile + alive-PID probe blocks
    //      reclaim, forcing the MAX_RETRIES spin to exhaust)
    const sid = 'lock-contention-' + Date.now();
    const sessionDir = path.join(SUITE_HOME, 'attestations', sid);
    fs.mkdirSync(sessionDir, { recursive: true });

    const playbookIds = [
      'kernel', 'mcp', 'crypto', 'ai-api', 'framework', 'sbom', 'runtime',
      'hardening', 'secrets', 'cred-stores', 'containers',
      'library-author', 'crypto-codebase',
    ];
    // Stage prior attestations so --force-overwrite is necessary to proceed.
    // Minimal payload — persistAttestation reads the prior body to chain
    // audit-trail fields; only `evidence_hash` + `captured_at` are required.
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
