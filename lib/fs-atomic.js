'use strict';

/**
 * Rename with retry for the atomic writes and file moves the CLI makes.
 *
 * On Windows a rename fails with EPERM, EACCES or EBUSY while another process
 * (a sync client, an indexer, a virus scanner or a concurrent reader) holds the
 * source or the target open. renameWithRetry retries those three codes with a
 * linear backoff of 20 ms, 40 ms, 60 ms and so on, and throws the last error
 * after the final attempt. Any other error is thrown at once.
 */

const fs = require('fs');

const TRANSIENT_RENAME_CODES = new Set(['EPERM', 'EACCES', 'EBUSY']);
const DEFAULT_ATTEMPTS = 10;

function sleepSync(ms) {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

/**
 * fs.renameSync(from, to), retried on a transient Windows error.
 * opts.attempts sets the number of tries (default 10); opts.rename replaces
 * fs.renameSync, for tests.
 */
function renameWithRetry(from, to, opts = {}) {
  const attempts = Number.isInteger(opts.attempts) && opts.attempts > 0 ? opts.attempts : DEFAULT_ATTEMPTS;
  const rename = typeof opts.rename === 'function' ? opts.rename : fs.renameSync;
  let lastErr;
  for (let attempt = 0; attempt < attempts; attempt++) {
    try {
      rename(from, to);
      return;
    } catch (e) {
      if (!e || !TRANSIENT_RENAME_CODES.has(e.code)) throw e;
      lastErr = e;
      if (attempt < attempts - 1) sleepSync(20 * (attempt + 1));
    }
  }
  throw lastErr;
}

module.exports = { renameWithRetry, TRANSIENT_RENAME_CODES };
