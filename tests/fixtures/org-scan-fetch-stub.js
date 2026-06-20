'use strict';

/**
 * Preload stub for tests/watchlist-org-scan-retry.test.js.
 *
 * Injected into the CLI subprocess via `node --require <this>`. It replaces
 * global.fetch with a deterministic GitHub-search responder so the org-scan
 * retry path can be exercised offline. Behaviour is selected by the
 * ORG_SCAN_STUB env var:
 *
 *   transient-recover : the Shai-Hulud pattern query returns 502 twice then
 *                       200 with a match; every other query returns 200/empty.
 *                       Proves a transient failure is retried, not dropped.
 *   transient-exhaust : the Shai-Hulud pattern query always returns 502.
 *                       Proves an exhausted pattern is surfaced as errored.
 *   rate-limit        : the Shai-Hulud pattern query returns 429.
 *                       Proves 429 maps to rate_limited (not retried).
 *
 * The per-pattern attempt count is written to stderr as
 * `ATTEMPTS:<n>` so the parent can assert the retry count.
 */

const FLAKY_Q = encodeURIComponent('Shai-Hulud');
const mode = process.env.ORG_SCAN_STUB || '';
let attempts = 0;

function match(fullName) {
  return {
    ok: true,
    status: 200,
    json: async () => ({
      items: [{
        full_name: fullName,
        html_url: `https://github.com/${fullName}`,
        private: false,
        created_at: '2026-06-01T00:00:00Z',
        updated_at: '2026-06-01T00:00:00Z',
        stargazers_count: 0,
      }],
    }),
  };
}
function empty() { return { ok: true, status: 200, json: async () => ({ items: [] }) }; }
function status(code) { return { ok: false, status: code, json: async () => ({}) }; }

global.fetch = async (url) => {
  const u = String(url);
  if (u.includes(FLAKY_Q)) {
    attempts++;
    process.stderr.write(`ATTEMPTS:${attempts}\n`);
    if (mode === 'transient-recover') return attempts <= 2 ? status(502) : match('attacker/shai-hulud-clone');
    if (mode === 'transient-exhaust') return status(502);
    if (mode === 'rate-limit') return status(429);
  }
  return empty();
};
