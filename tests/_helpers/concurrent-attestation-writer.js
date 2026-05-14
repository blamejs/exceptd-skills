'use strict';

/**
 * Test helper: drive persistAttestation --force-overwrite from a child
 * process so multiple writers race against the same session-id slot.
 *
 * Usage: node concurrent-attestation-writer.js <root> <sessionId> <writerIndex>
 *
 * Emits a single JSON line on stdout with { ok, evidence_hash, prior_evidence_hash, persist_path }.
 */

const path = require('path');
const crypto = require('crypto');

// Reach into bin/exceptd.js. The file's top-level code dispatches on argv
// when invoked directly; we sidestep that by loading the module fresh via
// require and pulling persistAttestation off the exports if exposed, OR by
// invoking the function via a small in-process re-import. Since bin/
// exceptd.js does NOT export persistAttestation, we instead call the CLI's
// own attest verb is not feasible — we replicate persistAttestation's
// contract here at the FS level. To keep this honest, the helper actually
// exercises the public CLI surface via spawnSync against the production
// binary: `exceptd attest persist` is the operator-facing path. If that
// surface isn't available, we degrade to a direct require with module
// stubbing.
//
// Simplest robust approach: use spawnSync on bin/exceptd.js with the
// attest persist subcommand. This guarantees we drive the EXACT code path
// users hit.

const { spawnSync } = require('child_process');

async function main() {
  const [root, sessionId, idxStr] = process.argv.slice(2);
  if (!root || !sessionId || idxStr === undefined) {
    console.error('usage: concurrent-attestation-writer.js <root> <sessionId> <writerIndex>');
    process.exit(2);
  }
  const idx = Number(idxStr);
  // Unique evidence-hash per writer so the final on-disk
  // prior_evidence_hash can be traced back.
  const evidenceHash = `writer-${idx}-${crypto.randomBytes(4).toString('hex')}`;

  // Stagger writers slightly so they don't all hit the lock at the exact
  // same instant — increases interleaving.
  await new Promise((r) => setTimeout(r, Math.random() * 25));

  // We invoke the persistAttestation function directly via require()
  // rather than spawning the CLI, because bin/exceptd.js runs main() on
  // load when invoked as a script. The function is reachable through
  // require if we set up the module exports to expose it; if not, we
  // fall back to driving FS state directly.
  let persistResult;
  try {
    const binMod = require(path.join(__dirname, '..', '..', 'bin', 'exceptd.js'));
    if (binMod && typeof binMod.persistAttestation === 'function') {
      persistResult = binMod.persistAttestation({
        sessionId,
        playbookId: 'synth',
        directiveId: 'default',
        evidenceHash,
        operator: null,
        operatorConsent: null,
        submission: { writer: idx },
        runOpts: { airGap: false, forceStale: false, mode: 'test', attestationRoot: root },
        forceOverwrite: true,
        filename: 'attestation.json',
      });
    } else {
      // Fallback: drive via spawnSync against the CLI. Use the
      // `exceptd attest persist` path if it exists; otherwise fail loudly.
      const r = spawnSync(process.execPath, [
        path.join(__dirname, '..', '..', 'bin', 'exceptd.js'),
        'attest', 'persist',
        '--session-id', sessionId,
        '--playbook', 'synth',
        '--directive', 'default',
        '--evidence-hash', evidenceHash,
        '--force-overwrite',
        '--attestation-root', root,
      ], { encoding: 'utf8' });
      persistResult = { ok: r.status === 0, evidence_hash: evidenceHash, raw: r.stdout || r.stderr };
    }
  } catch (e) {
    persistResult = { ok: false, error: e.message };
  }
  process.stdout.write(JSON.stringify({
    writer_index: idx,
    evidence_hash: evidenceHash,
    ok: !!persistResult.ok,
    prior_session_id: persistResult.prior_session_id || null,
    overwrote_at: persistResult.overwrote_at || null,
    error: persistResult.error || null,
  }) + '\n');
  process.exitCode = persistResult.ok ? 0 : 1;
}

main().catch((err) => {
  process.stdout.write(JSON.stringify({ ok: false, error: err.message }) + '\n');
  process.exitCode = 1;
});
