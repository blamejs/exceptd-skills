'use strict';

/**
 * Wrap test bodies that mutate repo-tracked files with snapshot-then-restore
 * semantics + SIGINT/SIGTERM/exit handlers.
 *
 * History: `tests/build-incremental.test.js` mutated `skills/compliance-theater/skill.md`
 * inside a try/finally. A SIGINT between the mutation and the finally block
 * left a polluted skill on disk, which broke Ed25519 verify on the next run.
 * The historical class — "smoke test mutates state and forgets to restore" —
 * shipped to operators twice across v0.11.x → v0.12.4. This helper closes
 * the class by ensuring restoration also fires on signals + process exit.
 *
 * Usage:
 *   const { withFileSnapshot } = require('./_helpers/snapshot-restore');
 *   await withFileSnapshot([skillPath, manifestPath], async () => {
 *     // ... test that mutates the files ...
 *   });
 *
 * Restoration runs on:
 *   - normal completion (finally block)
 *   - any thrown error inside the callback (finally block)
 *   - SIGINT (Ctrl-C)
 *   - SIGTERM
 *   - process 'exit' event (best-effort sync write)
 */

const fs = require('fs');

function withFileSnapshot(paths, body) {
  const list = Array.isArray(paths) ? paths : [paths];
  const originals = new Map();
  for (const p of list) {
    try {
      originals.set(p, fs.readFileSync(p));
    } catch {
      // File didn't exist pre-test; restore by deleting if it appears.
      originals.set(p, null);
    }
  }
  const restore = () => {
    for (const [p, bytes] of originals.entries()) {
      try {
        if (bytes === null) {
          if (fs.existsSync(p)) fs.unlinkSync(p);
        } else {
          fs.writeFileSync(p, bytes);
        }
      } catch {
        // Best-effort; surface to stderr only because finally blocks should
        // not swallow original errors.
        try { process.stderr.write(`[snapshot-restore] failed to restore ${p}\n`); } catch {}
      }
    }
  };
  const sigHandler = () => { restore(); process.exit(130); };
  const exitHandler = () => { restore(); };
  process.once('SIGINT', sigHandler);
  process.once('SIGTERM', sigHandler);
  process.once('exit', exitHandler);
  const cleanup = () => {
    process.removeListener('SIGINT', sigHandler);
    process.removeListener('SIGTERM', sigHandler);
    process.removeListener('exit', exitHandler);
  };
  const result = (async () => body())();
  return result.then(
    (v) => { try { restore(); } finally { cleanup(); } return v; },
    (e) => { try { restore(); } finally { cleanup(); } throw e; },
  );
}

module.exports = { withFileSnapshot };
