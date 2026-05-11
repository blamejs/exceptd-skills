# Vendored from blamejs

Subset of [blamejs](https://github.com/blamejs/blamejs), Apache-2.0, pinned to
upstream commit [`1442f17`](https://github.com/blamejs/blamejs/commit/1442f17758a4bd511c63877561c0ffa759f66a87).

## What's here

| File | Upstream | Why vendored |
|---|---|---|
| `retry.js` | `lib/retry.js` | Battle-tested exponential backoff + crypto jitter + AbortSignal + circuit-breaker. Used by `lib/job-queue.js` and `lib/refresh-external.js` for HTTP retry semantics on KEV/EPSS/NVD/IETF/GitHub fetches. |
| `worker-pool.js` | `lib/worker-pool.js` | Generic worker_threads pool with bounded queue, per-task timeout, worker recycle. Used by `scripts/build-indexes.js --parallel` and any future CPU-bound fan-out work. |
| `LICENSE` | `LICENSE` | Apache-2.0 license text (identical to exceptd's). |
| `_PROVENANCE.json` | — | sha256 of each vendored file + upstream file at pin, plus the strip rules applied. `lib/validate-vendor.js` re-hashes on every predeploy run. |

## Flatten-and-inline strategy

Each vendored file is a single-file leaf:

- No imports of upstream blamejs siblings (`framework-error`, `constants`,
  `validate-opts`, `numeric-bounds`, `lazy-require`, `audit`,
  `observability`, `safe-async`).
- Public surface preserved verbatim where possible. Behavior preserved
  verbatim where preserved. Audit/observability sinks become no-op stubs
  so call-site code from upstream patterns drops in cleanly.
- Error envelope: upstream uses typed `XxxError` classes with stable
  `code` strings. We replace the class with vanilla `Error` carrying the
  same `code` field. Callers that switch on `err.code` keep working;
  callers that did `instanceof WorkerPoolError` must switch to `err.code`.

Every file lists its specific strip rules in its header banner and in
`_PROVENANCE.json`.

## Updating the pin

1. Note the new upstream commit hash.
2. Copy the upstream file into this directory.
3. Re-apply the strip rules in the file header (the diff against the
   raw upstream file is small).
4. Update `_PROVENANCE.json` with the new commit, vendored sha256, and
   upstream sha256 at pin.
5. Run `npm run validate-vendor` — it confirms the recorded hashes
   match the on-disk vendored copies.
6. Bump the project version per the cadence rules. Pin updates are
   patch-level; a structural change to the vendored surface is minor.

## What we DON'T vendor

| Upstream module | Why skipped |
|---|---|
| `lib/queue.js`, `lib/queue-local.js`, `lib/queue-redis.js`, `lib/queue-sqs.js` | DB-backed / cluster-aware / cloud-queue adapters. exceptd is an offline-first static-data CLI corpus with no database. The in-memory `lib/job-queue.js` covers the actual use case. |
| `lib/http-client.js`, `lib/http-client-cache.js`, `lib/http-client-cookie-jar.js`, `lib/http-message-signature.js` | Full production HTTP client. Our needs are bounded to `fetch` + 10s `AbortController` timeout; stdlib is sufficient. |
| `lib/cache.js`, `lib/cache-redis.js`, `lib/cache-status.js`, `lib/cdn-cache-control.js` | HTTP-layer cache with negotiation. The exceptd cache (`.cache/upstream/`) is a simple JSON file-per-entry layout with a flat index, a different problem. |
| `lib/circuit-breaker.js` (standalone) | The `CircuitBreaker` class is already part of `retry.js` and is what we use; the standalone module is for callers that want only the breaker without the retry surface. |
| `lib/audit.js`, `lib/observability.js`, `lib/framework-error.js`, etc. | exceptd has no audit chain, no metrics sink, and no framework-error infrastructure. The relevant call sites in the vendored files have been replaced with no-op stubs or vanilla `Error` objects. |
