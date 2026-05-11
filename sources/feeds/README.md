<!-- NOTE for humans: cached `.json` snapshots in this directory can grow large. If they do, add `sources/feeds/*.json` (with `!sources/feeds/*.example.json` and `!sources/feeds/.gitkeep` exceptions) to `.gitignore`. The example file is the only content intended to be tracked. -->

# sources/feeds

This directory holds **cached snapshots of upstream feeds** consumed by the validators in
`sources/validators/`. It exists so that:

1. CVE validation in a multi-CVE run hits the CISA KEV feed once, not once per CVE.
2. Downstream tooling (reports, currency checks) can inspect what was last fetched,
   when, and from where.
3. Offline / airgapped environments retain a known-good reference snapshot.

## What lives here

| File | Status | Source | Written by |
|---|---|---|---|
| `cve-cache.example.json` | tracked, illustrative | hand-written | humans |
| `cisa-kev-snapshot.json` | gitignore-eligible | `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` | `cve-validator.js` |
| `nvd-recent.json` | gitignore-eligible | `https://services.nvd.nist.gov/rest/json/cves/2.0?...` | `cve-validator.js` |
| `atlas-version.json` | gitignore-eligible | GitHub releases for `mitre-atlas/atlas-data` | `atlas-validator.js` |

The validators currently keep the KEV feed in **process memory** for the duration of a
run (see `cve-validator.js`'s `loadKevCache`). On-disk snapshots are persisted when the
orchestrator is run with `--refresh` (wired in `orchestrator/index.js`'s
`runValidateCves`); offline runs (`--offline`) read from these snapshots instead of
hitting the network.

## Cache rebuild contract

- Every run with `--refresh` overwrites the relevant snapshot atomically.
- A snapshot is considered stale at >24h for KEV, >7d for ATLAS.
- Snapshots must include a `_meta` block with `fetched_at` (ISO 8601), `source_url`, and
  `etag` if returned. The validators that consume snapshots ignore unknown fields, so
  schema growth is backwards-compatible.
- A corrupted snapshot must not crash the validators — they treat parse errors the same
  as a network error (`status: 'unreachable'`).

## Why the example file is tracked

`cve-cache.example.json` documents the cache shape so contributors can write tooling
against it without needing live network. It is clearly marked with `_example: true` so
real validators will never mistake it for a live snapshot.

## AGENTS.md cross-reference

This directory does **not** store direct exploit URLs. Rule #1 ("no stale threat intel")
mandates fresh validation; the cache is the mechanism, not a substitute. Anything older
than the freshness thresholds above must be re-fetched before its contents are quoted
in a skill or report.
