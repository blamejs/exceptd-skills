'use strict';

/**
 * Test helper for the prefetch _index.json concurrent-write regression.
 *
 * Forked as a child process by tests/prefetch.test.js. Two of these run in
 * parallel against the same tempdir; each writes N entries under its own
 * key prefix into _index.json via lib/prefetch.js's withIndexLock helper.
 * Without the lock the second writer's saveIndex overwrites the first; with
 * the lock, both runs' entries survive in the merged result.
 *
 * Usage: node concurrent-prefetch-index-writer.js <cacheDir> <prefix> <count>
 */

const path = require('path');
const { _internal } = require(path.join(__dirname, '..', '..', 'lib', 'prefetch.js'));
const { withIndexLock } = _internal;

async function main() {
  const [cacheDir, prefix, countStr] = process.argv.slice(2);
  const count = Number(countStr);
  if (!cacheDir || !prefix || !Number.isInteger(count) || count <= 0) {
    console.error('usage: concurrent-prefetch-index-writer.js <cacheDir> <prefix> <count>');
    process.exit(2);
  }
  for (let i = 0; i < count; i++) {
    const key = `test/${prefix}-${i}`;
    await withIndexLock(cacheDir, (current) => {
      current.entries[key] = {
        fetched_at: new Date().toISOString(),
        etag: null,
        last_modified: null,
        url: `https://example.invalid/${prefix}/${i}`,
        sha256: 'deadbeef'.repeat(8),
      };
      return current;
    });
    // Small jitter to maximize interleaving between the two writers.
    await new Promise((r) => setTimeout(r, Math.random() * 5));
  }
  process.exitCode = 0;
}

main().catch((err) => {
  console.error(err && err.stack ? err.stack : err);
  process.exitCode = 1;
});
