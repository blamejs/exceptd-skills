# Changelog

## 0.9.1 — 2026-05-11

**Patch: test-runner concurrency fix for first npm publish.**

The v0.9.0 release workflow failed at the predeploy `Run tests` gate on the Linux CI runner with a byte-stability assertion on `data/_indexes/section-offsets.json`. Root cause: the Node test runner defaults to running test files in parallel, and three test files (`tests/build-incremental.test.js`, `tests/indexes-v070.test.js`, `tests/refresh-*.test.js`) all manipulate shared filesystem state under `data/_indexes/` + `refresh-report.json` + skill bodies. The `build-incremental` test that temporarily touches `skills/compliance-theater/skill.md` races against the idempotence assertion in `indexes-v070`, producing a different `section-offsets.json` snapshot between the two reads.

Fix: add `--test-concurrency=1` to both `npm test` and the predeploy test gate. Sequential file execution adds ~1.5s locally and eliminates the race entirely. No code or schema changes — only the test runner flag.

Tag rule on the remote prevented rewriting `v0.9.0` (correctly — published tags are immutable by repo policy), so this version becomes the actual first npm publish under `@blamejs/exceptd-skills`. `v0.9.0` on the remote remains as a historical marker for the failed release attempt.

## 0.9.0 — 2026-05-11

**Minor: npm distribution. Package is now `@blamejs/exceptd-skills` on npm with provenance attestation.** Adds a clean `npx` install path for AI consumers and operators, a single-entry-point `exceptd` CLI that dispatches to every internal command, a tag-triggered release workflow with GitHub OIDC-signed provenance, and a new predeploy gate that checks the publish tarball shape on every commit.

### npm publishing

- **Package name**: `@blamejs/exceptd-skills` (was `exceptd-security`, never published)
- **Distribution**: `https://www.npmjs.com/package/@blamejs/exceptd-skills`
- **Provenance**: every release tarball is signed via GitHub OIDC + npm `--provenance`. Consumers can verify with `npm audit signatures`.
- **`publishConfig.access`**: `public` (scoped public packages need this explicit)
- **`files`** whitelist replaces the previous `private: true` block — only `bin/`, `lib/`, `orchestrator/`, `scripts/`, `vendor/`, `agents/`, `data/`, `skills/`, `keys/public.pem`, and top-level docs ship. Tests, `.cache/`, `.keys/`, `refresh-report.json`, dev tooling are excluded.
- **Tarball**: ~860 KB packed / 3 MB unpacked / 136 files.

### `bin/exceptd.js` CLI

Single executable, exposed as `exceptd` after install. Dispatches to every existing script:

```
npx @blamejs/exceptd-skills path                          # absolute install path
npx @blamejs/exceptd-skills prefetch
npx @blamejs/exceptd-skills refresh --from-cache --swarm
npx @blamejs/exceptd-skills build-indexes --changed --parallel
npx @blamejs/exceptd-skills validate-cves --from-cache
npx @blamejs/exceptd-skills currency
npx @blamejs/exceptd-skills skill kernel-lpe-triage
```

The `exceptd path` subcommand is the recommended way for downstream AI consumers to discover where the installed package lives — they point their assistant at `<path>/AGENTS.md` + `<path>/data/_indexes/summary-cards.json` without needing to know the npm install location.

### Release workflow `.github/workflows/release.yml`

- **Trigger**: tag push matching `v*.*.*` (or `workflow_dispatch` for dry-runs)
- **Gates**: verifies tag ↔ package.json version match → `npm install --no-audit --no-fund` (asserts zero deps) → `npm run bootstrap` → `npm run predeploy` (all 13 gates) → `npm pack --dry-run` preview → `npm publish --access public --provenance` → GitHub Release with the CHANGELOG section as the body
- **Permissions**: `contents: write` + `id-token: write` (OIDC for provenance)
- **Secrets**: `NPM_TOKEN` (granular automation token, scoped to `@blamejs/exceptd-skills` only)
- **Dry-run mode**: `workflow_dispatch` with `dry_run: true` skips the `npm publish` and GitHub Release steps but runs everything else

### `validate-package` predeploy gate

New gate (#13 in the predeploy sequence). Runs `npm pack --dry-run --json` and asserts:

- Every required file (README, LICENSE, NOTICE, AGENTS, manifest, sbom, bin, lib leaves, vendor leaves, data/_indexes/_meta, keys/public.pem) is present in the publish tarball
- No forbidden file (`.keys/`, `.cache/`, `tests/`, `refresh-report.json`, `.env*`, `node_modules/`, any non-public `.pem`) is in the publish tarball
- Tarball size is under 5 MB
- `bin/exceptd.js` has a `#!/usr/bin/env node` shebang
- `package.json` invariants: not private, has `bin.exceptd`, has `files[]`, has `publishConfig.access: public` + `provenance: true`

Predeploy gate count: **12 → 13**. All green on this release.

### Other changes

- **README rewrite**: three audience paths (AI consumer / operator / maintainer), npx install instructions, full CLI command reference, pre-computed indexes summary. npm badge added back alongside the release badge.
- **MAINTAINERS.md release runbook**: full one-time setup + per-release procedure + dry-run instructions + rollback options + consumer verification commands.
- **SBOM updates**: package's own `bom-ref` switches from `pkg:project/exceptd-skills@version` to canonical PURL `pkg:npm/@blamejs/exceptd-skills@version`. Adds `externalReferences` linking to the npm package page + GitHub repo.
- **Tests**: 182 → 192 (10 new in `tests/bin-dispatcher.test.js`). Covers help, version, path, alias flags, unknown command, orchestrator passthrough, package.json publish-readiness invariants.
- **package.json updates**: keywords array for npm discoverability (`ai-security`, `compliance`, `cve`, `kev`, `mcp`, `prompt-injection`, `rwep`, `threat-intelligence`, etc.), explicit `author` field, `prepublishOnly` runs `predeploy + validate-package` so an accidental `npm publish` can't skip the gates.

### Operator workflows

The npm distribution doesn't change how the project is used. It just gives a cleaner install path:

```
# Previously: required git clone + npm run bootstrap
git clone https://github.com/blamejs/exceptd-skills && cd exceptd-skills && npm run bootstrap

# Now: one command, no clone, no install
npx @blamejs/exceptd-skills path
npx @blamejs/exceptd-skills prefetch
```

Maintainers still clone + `npm run bootstrap` + `npm run predeploy` for active development.

### Release this version

This release ships the npm publish infrastructure but does NOT itself publish. To publish v0.9.0 to npm, the maintainer must push the `v0.9.0` tag (after this commit lands on `main`) and supply `NPM_TOKEN` in repo secrets. See `MAINTAINERS.md` § "Release runbook" for the full procedure.

## 0.8.0 — 2026-05-11

**Minor: prefetch cache + queue/retry/worker primitives + incremental build + swarm fan-out.** Adds the infrastructure to (a) warm a local cache of every upstream artifact so refresh/validate work without re-paying network cost, (b) run source fetches and builders in parallel, (c) rebuild only what changed since the last build. Also vendors `retry.js` + `worker-pool.js` from blamejs so battle-tested retry/threading semantics aren't reinvented.

### Vendored from blamejs (Apache-2.0)

- `vendor/blamejs/retry.js` — flattened and stripped from `blamejs@1442f17/lib/retry.js`. Provides `withRetry`, `isRetryable`, `backoffDelay`, `CircuitBreaker`. Stripped: observability sink, audit hooks, `numeric-checks` dep, `safeAsync.sleep` (replaced with stdlib AbortSignal-aware sleep). Documented exceptd delta: the sleep timer is NOT `unref`'d (one-shot CLI callers need the event loop kept alive while the backoff completes).
- `vendor/blamejs/worker-pool.js` — flattened and stripped from `blamejs@1442f17/lib/worker-pool.js`. Provides `create(scriptPath, opts) → { run, drain, terminate, stats }` with bounded concurrency, bounded queue depth, per-task timeout, and worker recycle. Stripped: `WorkerPoolError` class (replaced with `Error` carrying a `code` field), `validate-opts` / `numeric-bounds` / `constants` deps, audit sink.
- `vendor/blamejs/_PROVENANCE.json` — pinned commit, vendored sha256 + upstream sha256 at pin, strip rules per file, exceptd-deltas.
- `vendor/blamejs/README.md` + `vendor/blamejs/LICENSE` — re-vendor instructions + Apache-2.0 license text.
- `NOTICE` updated with full attribution paragraph.

### New `lib/` primitives

- **`lib/job-queue.js`** — async queue with per-source concurrency caps, token-bucket rate limiting, priority ordering, and per-source stats. Retry classification + exponential backoff delegated to vendored `retry.js`. Used by the upstream-fetch path of `refresh-external` and (transitively) `prefetch`.
- **`lib/worker-pool.js`** — thin wrapper over vendored `worker-pool` providing a `WorkerPool` class + `runAll(tasks)` helper. Available to any caller wanting CPU fan-out, used today by the `--parallel` test harness pattern.
- **`lib/prefetch.js`** — downloads and caches every upstream artifact this project consumes into `.cache/upstream/` (gitignored). Layout: `_index.json` + `<source>/<id>.json`. Sources: `kev` (CISA), `nvd`, `epss`, `rfc` (IETF Datatracker), `pins` (MITRE GitHub releases). Per-source rate budgets via JobQueue. `--max-age <dur>` to skip fresh entries, `--source <names>` filter, `--force`, `--no-network` (dry-run plan).
- **`lib/validate-vendor.js`** — predeploy gate. Re-hashes every vendored file and compares to `_PROVENANCE.json`; smoke-loads each via `require()`. Silent hand-edits to a vendored copy fail the build.

### refresh-external — cache + swarm + report-out

- **`--from-cache [<dir>]`** — read every source from the prefetch cache instead of upstream. Default path `.cache/upstream`. Combine with `--apply` for fully-offline upserts.
- **`--swarm`** — fan-out source fetches across worker threads (`Promise.all`-based). Best paired with `--from-cache` so the parallel workers don't compete for upstream rate budgets. Report shape is identical to sequential mode.
- **`--report-out <path>`** — redirect the `refresh-report.json` artifact so parallel test suites don't race on the shared file at the repo root.
- Cache helpers per source (`kevDiffFromCache`, `epssDiffFromCache`, `nvdDiffFromCache`, `rfcDiffFromCache`, `pinsDiffFromCache`) — synthesize the same `ValidationResult` shape downstream consumers already understand.

### validate-cves / validate-rfcs — cache-first

- Both now accept **`--from-cache [<dir>]`**. When set, the orchestrator opportunistically reads NVD/KEV/EPSS (CVEs) or Datatracker (RFCs) records from the prefetch cache and falls through to live network on per-entry cache misses. Reports `cache hits` / `live fallbacks` at the end of the run. Logs the cache directory in the mode banner.
- `validateAllCvesPreferCache(catalog, cacheDir)` is the new orchestrator-internal helper; it produces the same shape `validateAllCves` does so existing print-and-fail logic doesn't fork.

### build-indexes — incremental + parallel + selective

- Refactored to a declarative outputs registry. Each output declares its source-file dependencies (`deps`) + any produced-output prerequisites (`dependsOn`, e.g. `token-budget` needs `section-offsets` on disk first).
- **`--only <names>`** — rebuild specific outputs (and their dependency closure).
- **`--changed`** — rebuild only outputs whose declared deps changed since the last `_meta.json` snapshot. CI-safe: identical inputs produce identical outputs. Allowed in CI per project decision.
- **`--parallel`** — run independent outputs concurrently via `Promise.all()`. Same byte-identical output as sequential mode (verified by `tests/build-incremental.test.js`).
- No-op short-circuit when `--changed` finds zero changed sources: `_meta.json` is re-written with the current hashes so the freshness gate stays correct.

### CI workflow updates

- **`.github/workflows/refresh.yml`** — adds a `Warm upstream cache` step before the dry-run that uses `npm run prefetch`. The subsequent refresh runs use `--from-cache .cache/upstream --swarm` for parallel apply against cached data. Eliminates parallel-fetch rate-limit contention.
- **`.github/workflows/ci.yml`** — data-integrity job picks up the new `validate-indexes` and `validate-vendor` gates (previously only enforced via predeploy).

### Predeploy

12 gates now (was 11). New: **Vendor tree integrity** (`validate-vendor`). 12/12 green on this release.

### npm scripts

- `prefetch`, `prefetch:dry`
- `refresh:from-cache`, `refresh:swarm`
- `validate-vendor`

### Tests

- **`tests/job-queue.test.js`** — concurrency cap, priority order, transient-retry via vendored classifier, no retry on 4xx, drain, queue_meta propagation. 7 tests.
- **`tests/worker-pool.test.js`** — single dispatch, parallelism wall-clock check, worker-reported error, scriptPath validation. 5 tests.
- **`tests/prefetch.test.js`** — dry-run produces empty cache, source filter, `SOURCES` shape, `readCached` freshness + `allowStale`, unknown source rejection. 5 tests.
- **`tests/build-incremental.test.js`** — `--only` dependency closure (`token-budget` pulls in `section-offsets`), unknown name rejection, `--changed` no-op when sources unchanged, `--changed` picks up a touched skill body, `--parallel` produces byte-identical output, `OUTPUTS` registry parity. 6 tests.
- **`tests/refresh-swarm.test.js`** — swarm vs. sequential report parity, `--from-cache` reads cache layout, `--from-cache <nonexistent>` exits non-zero. 3 tests.

Total: 182/182 pass (was 156).

### SBOM

`sbom.cdx.json` `components` array now lists the vendored files as proper CycloneDX library components with SHA-256 hashes, source repo, pinned commit, and an `externalReferences` link back to upstream. Metadata properties add `exceptd:vendor:count` and `exceptd:vendor:pin`.

## 0.7.0 — 2026-05-11

**Minor: tier-2/3/4 derived indexes + external-data refresh automation.** Builds on v0.6.0's six-index baseline with eleven more pre-computed indexes for AI-consumer ergonomics, plus a scheduled GitHub Actions job that pulls upstream KEV/EPSS/NVD/RFC data and either upserts catalogs or opens issues for version-pin bumps.

### New indexes (eleven, under `data/_indexes/`)

| File | Purpose |
|---|---|
| `summary-cards.json` | Per-skill 100-word abstract: description, Threat Context excerpt, what it produces, key cross-refs, handoff targets. Saves the `researcher` skill from parsing each routed skill's body to summarize. |
| `section-offsets.json` | Per-skill byte/line offsets of every H2 section. Consumers slice a single section (e.g. "Compliance Theater Check") from disk instead of reading the whole body. Fence-aware — code-block `## Foo` lines are not counted. |
| `chains.json` (extended) | Pre-computed cross-walks now keyed by both CVE-id and CWE-id. CWE chains hydrate skills citing the CWE, plus related CVEs reached through the skill graph. |
| `token-budget.json` | Approximate token cost per skill + per section. Lets AI consumers budget context cost before loading. |
| `recipes.json` | 8 curated multi-skill recipes for common ops use cases: AI red team prep, PCI 4.0 audit defense, federal IR, DORA TLPT scoping, K-12 EdTech privacy review, ransomware tabletop, new-CVE triage, OSS dep triage. |
| `jurisdiction-clocks.json` | Normalized jurisdiction × obligation × hours matrix (breach notification, patch SLA). 29 jurisdictions, derived from `data/global-frameworks.json`. |
| `did-ladders.json` | Canonical defense-in-depth ladders per attack class (prompt injection, kernel LPE, AI-C2, ransomware, supply chain, BOLA, model exfiltration, BEC). Each layer references the source skill + D3FEND id backing it. |
| `theater-fingerprints.json` | Structured records for the 7 compliance-theater patterns: claim, audit evidence, reality, fast detection test, controls implicated, evidence CVE / campaign. Inverted by control id. |
| `currency.json` | Pre-computed skill currency snapshot against `manifest.threat_review_date` (deterministic). Saves the watchlist/scheduler from re-running `orchestrator currency`. |
| `frequency.json` | Citation-count tables per catalog field (CWE / ATLAS / ATT&CK / D3FEND / framework_gap / RFC / DLP). Surfaces load-bearing entries and orphan-adjacent ones. |
| `activity-feed.json` | "What changed when" feed across skills + catalogs, sorted descending. Lightweight RSS. |
| `catalog-summaries.json` | Compact per-catalog summary cards: purpose, schema version, last-updated, TLP, source confidence, entry count. |
| `stale-content.json` | Persisted snapshot of audit-cross-skill stale-content findings (renamed-skill tokens, README badge drift, researcher count claim, stale skill reviews, stale catalog freshness). Deterministic against `manifest.threat_review_date`. |

### Builder restructure

`scripts/build-indexes.js` now orchestrates `scripts/builders/*.js` — one module per index. The main script keeps the v0.6.0 outputs inline and delegates new outputs. All builders are zero-dep Node 24 stdlib.

`_meta.json` now records source SHA-256 hashes for 49 files (manifest + 10 catalogs + 38 skills) and stamps every new index with stats.

### External-data refresh automation

- **`lib/refresh-external.js`** — new orchestrator. Five source modules: KEV (CISA), EPSS (FIRST.org), NVD (CVSS metrics), RFC (IETF Datatracker), and PINS (MITRE ATLAS / ATT&CK / D3FEND / CWE upstream releases). Each module returns a diff list; `--apply` writes upserts back to the local catalog, bumps `last_verified`, then rebuilds indexes. PINS is intentionally **report-only** per AGENTS.md Hard Rule #12 — version-pin bumps require audit, surfaced as a GitHub issue instead of an auto-PR.
- **`sources/validators/version-pin-validator.js`** — checks ATLAS, ATT&CK, D3FEND, and CWE GitHub releases against the local pin.
- **`.github/workflows/refresh.yml`** — daily 06:00 UTC dry-run + apply; weekly 06:30 UTC version-pin slot. On diffs, opens an auto-PR (`data-refresh/auto` branch, labels `data-refresh` + `automation`). On pin drift, opens an issue (labels `version-pin` + `automation` + `minor-update`). Uses `NVD_API_KEY` secret if available.
- **`tests/fixtures/refresh/`** — frozen fixture payloads (kev / epss / nvd / rfc / pins .json) so the test suite exercises the orchestrator deterministically with no network.
- **`tests/refresh-external.test.js`** — 8 tests covering dry-run, `--source` filter, `--help`, fixture-mode determinism, fixture/source-module parity.

### `npm run` additions

- `refresh` / `refresh:dry` — dry-run all sources, write `refresh-report.json`
- `refresh:apply` — apply diffs + rebuild indexes
- `refresh:offline` — fixture-mode run, never touches network

`refresh-report.json` is gitignored — CI uploads it as an artifact.

### Test coverage

- `tests/indexes-v070.test.js` — 16 new tests across the 13 new/extended index files. Covers shape, cross-references to real skills + catalogs, byte-stability across rebuilds (idempotence).
- 156 tests pass (was 132); 11/11 predeploy gates green.

### Internal fixes during this release

- `scripts/builders/section-offsets.js` skips code-fenced `## ` lines so output-template H2s (e.g. inside `### Output Format` code blocks) don't get mistaken for real section boundaries.
- `scripts/builders/summary-cards.js` extractor skips leading H3 / metadata / table-separator lines before grabbing the first prose paragraph for `threat_context_excerpt`.
- `scripts/builders/theater-fingerprints.js` properly skips the `### Pattern N:` header line before scanning for the next H2 boundary (otherwise the section block collapsed to a single char).

## 0.6.0 — 2026-05-11

**Minor: derived-data indexes layer for AI-consumer token efficiency.** Real bottleneck for skill use is token cost (AI consumers loading 1.6 MB of catalogs + skill bodies to answer one cross-reference question), not parse speed (every operation was already sub-5ms). This release adds a pre-computed derived-data layer at `data/_indexes/`.

### New `data/_indexes/` directory

Six derived index files. Never hand-edited; regenerated by `npm run build-indexes` after any source change. A `_meta.json` records SHA-256 of every source file so the new predeploy gate detects staleness automatically.

- **`xref.json`** — inverted index over 161 catalog entries across 7 fields (cwe_refs, d3fend_refs, framework_gaps, atlas_refs, attack_refs, rfc_refs, dlp_refs). Answers "which skills cite CWE-79?" in O(1) instead of a 38-skill linear scan.
- **`trigger-table.json`** — 453 unique trigger strings → list of skills. Replaces the dispatcher's linear scan with a hash lookup.
- **`chains.json`** — 5 pre-computed CVE chains (per CVE: referencing skills + hydrated CWE / ATLAS / D3FEND / framework_gaps entries). Single-file answer to "what does the project know about CVE-2026-31431?".
- **`jurisdiction-map.json`** — 34 jurisdictions → skills mentioning them in body. Built from both jurisdiction codes and regulator-name patterns (GDPR → EU, NCSC → UK, MAS → SG, etc.).
- **`handoff-dag.json`** — 38 nodes, 285 edges. Pre-computed cross-skill mention graph with in-degree / out-degree per node.
- **`_meta.json`** — SHA-256 source hash table for staleness detection; predeploy gate consumes this.

Total index size: ~125 KB across 6 files — **93% reduction** vs loading all skills + catalogs (1.66 MB) for cross-reference queries.

### New tooling

- `scripts/build-indexes.js` — regenerates all 6 indexes from canonical sources. Idempotent. Zero new npm deps.
- `lib/validate-indexes.js` — predeploy gate. Re-hashes every source file and compares to `_meta.json`. Fails the build if indexes are stale (developer must `npm run build-indexes`).
- `scripts/audit-perf.js` — micro-benchmarks hot paths (manifest load, catalog load, skill body read, frontmatter parse, trigger match, xref lookup, multi-hop chain, watchlist aggregator). Confirms baseline numbers + measures index speedups.
- `npm run` scripts added: `build-indexes`, `validate-indexes`, `audit-perf`, `audit-cross-skill`.

### Predeploy gate count

10 → 11 gates. New gate: **Pre-computed indexes freshness**. Sits in `data-integrity` CI job.

### Speed measurements

| Operation | Before | After (index) | Speedup |
|---|---|---|---|
| "Which skills cite CWE-79?" | 0.037 ms | 0.011 ms | 3.4× |
| Full CVE chain reconstruction | 0.569 ms | 0.009 ms | 63× |
| Token cost for cross-ref query | ~450K tokens | ~30K tokens | 93% reduction |

### Verification

- 11/11 predeploy gates green
- 38/38 skills signed
- audit-cross-skill: 0 issues
- audit-perf: all hot paths sub-5ms; indexes 60+× faster than on-the-fly chain reconstruction

## 0.5.5 — 2026-05-11

Pin: cross-skill audit fixes. Added `scripts/audit-cross-skill.js` (comprehensive accuracy checker) and ran it against the v0.5.4 state.

### Bugs found and fixed

| # | Bug | Fix |
|---|---|---|
| 1 | `mcp-agent-trust` skill cited `RFC-8446` in catalog's `skills_referencing` but missing from skill's own `rfc_refs` (asymmetric reference) | Restored `RFC-8446` to skill's frontmatter + manifest entry |
| 2 | README badge `skills-25-` 13 stale | Bumped to `skills-38-` |
| 3 | README badge `jurisdictions-33-` 1 stale | Bumped to `jurisdictions-34-` |
| 4 | `researcher` skill body claimed "36 specialized skills downstream"; actual is 37 | Updated to 37 in both occurrences |

### New tooling

- `scripts/audit-cross-skill.js` — runs 15 cross-skill accuracy checks: manifest path existence, frontmatter ↔ manifest name parity, researcher-dispatch coverage, AGENTS.md Quick-Ref coverage, version triple agreement, snapshot drift, SBOM drift, every-catalog-ref-resolves, RFC reverse-ref symmetry, skill-update-loop affected-skills validity, stale renamed-skill tokens, trigger collisions, README badge drift, researcher count claim. Exit non-zero on any finding.
- Trigger collisions (13 informational) — all intentional fan-out per researcher dispatch policy (promptsteal/promptflux, compliance gap, mas trm, apra cps 234, defense in depth, tlpt, tiber-eu, csaf, blue team, workload identity, nerc cip, falco).

### Verification

- `node scripts/audit-cross-skill.js` → 0 issues
- 10/10 predeploy gates green
- 38/38 skills signed

## 0.5.4 — 2026-05-11

Pin-level rename + terminology cleanup. The `age-gates-minor-safeguarding` skill shipped in 0.5.3 has been renamed to `age-gates-child-safety`. Prose use of "minor" replaced with "child" / "children" / specific cohort terms ("under-13", "under-16", "under-18") throughout the skill body. Direct regulatory citations that use the word (CN Minors Protection Law, DSA Art. 28 wording, AVMSD "minor protection" terminology, Character.ai case reference) preserved verbatim.

### Public-surface change

This is a renamed skill (removed `age-gates-minor-safeguarding` + added `age-gates-child-safety`). The snapshot gate handled the additive rename via `npm run refresh-snapshot`. Downstream consumers pinned to the previous name should update their reference; the published name had only been on `main` for ~one commit.

### Files touched

- Directory rename: `skills/age-gates-minor-safeguarding/` → `skills/age-gates-child-safety/`
- Skill frontmatter: `name`, `description`, `triggers`
- Skill body: prose "minor" → "child" where context allowed (~71 of 86 occurrences); 15 remaining are regulatory citations preserved verbatim
- `manifest.json`: renamed entry + updated path + triggers
- `manifest-snapshot.json`: regenerated
- `AGENTS.md`: Quick Skill Reference row updated
- `skills/researcher/skill.md`: dispatch routing entry added (the rename surfaced that this skill was never wired into researcher dispatch in 0.5.3 — corrected here)
- `CHANGELOG.md`: 0.5.3 entry retroactively updated to use the new name
- SBOM refreshed

### Verification

- 10/10 predeploy gates green
- 38/38 skills signed and lint-passing

## 0.5.3 — 2026-05-11

Pin-level skill additions closing thematic and age-related coverage gaps. Total skills 31 → 38.

### New skills (7)

**Thematic (6)**:
- **`api-security`** — OWASP API Top 10 2023, AI-API specific (rate limits, prompt-shape egress, MCP HTTP transport), GraphQL + gRPC + REST + WebSocket attack surfaces, API gateway posture, BOLA/BFLA/SSRF/Mass Assignment.
- **`cloud-security`** — CSPM/CWPP/CNAPP, CSA CCM v4, AWS/Azure/GCP shared responsibility, cloud workload identity federation (IRSA, Azure Workload Identity, GCP Workload Identity, SPIFFE/SPIRE), eBPF runtime detection (Falco, Tetragon).
- **`container-runtime-security`** — CIS K8s Benchmark v1.10, NSA/CISA Hardening Guide, Pod Security Standards (Privileged/Baseline/Restricted), Kyverno/OPA Gatekeeper admission, Sigstore policy-controller, AI inference workloads (KServe, vLLM, Triton).
- **`mlops-security`** — Training data integrity, model registry signing, deployment pipeline provenance, inference serving hardening, drift detection, feedback loop integrity. MLflow / Kubeflow / Vertex AI / SageMaker / Azure ML / Hugging Face. NIST 800-218 SSDF + SLSA L3 + ISO 42001.
- **`incident-response-playbook`** — NIST 800-61r3 (2025), ISO/IEC 27035-1/-2:2023, ATT&CK-driven detection, PICERL phases, AI-class incident handling (prompt injection breach, model exfiltration, AI-API C2). Cross-jurisdiction notification clocks (DORA 4h, NIS2 24h, GDPR 72h, NYDFS 72h + 24h ransom, CERT-In 6h, LGPD/PIPL/AE).
- **`email-security-anti-phishing`** — SPF/DKIM/DMARC/BIMI/ARC/MTA-STS/TLSRPT email auth, AI-augmented phishing (voice cloning, deepfake video, hyperpersonalized email), Business Email Compromise, secure email gateways, FIDO2/WebAuthn passkey deployment.

**Age-related (1)** — flagged as audit gap during this cycle:
- **`age-gates-child-safety`** — Age verification + child online safety across ~25 jurisdictions: US COPPA + CIPA + California AADC + NY SAFE for Kids + adult-site age-verification state laws (TX/MS/UT/16+ states); EU GDPR Art. 8 + DSA Art. 28 + AVMSD + CSAM Regulation pending; UK Online Safety Act 2023 (Ofcom enforcement July 2025) + Children's Code; AU Online Safety Act + under-16 social media ban; IN DPDPA child provisions; BR LGPD Art. 14; CN Minors Protection Law (regulation name preserved verbatim); SG Online Safety Act; KOSA pending US federal. Age-verification standards (IEEE 2089-2021, OpenID Connect age claims). AI product age policies. CSAM detection (NCMEC).

### Cross-skill integration

- `researcher` dispatch table extended with 7 new routing entries; count bumped to "37 specialized skills downstream + researcher".
- `skill-update-loop`: 7 new skills wired into Triggers 1/3/4/5/9 where appropriate. New **Trigger 12 (Vendor Security Tool Capability Shift)** for CSPM/CWPP/EDR/SEG/MLOps platform vendor-category capability changes.
- 14 new RFC reverse-references in `data/rfc-references.json`.
- `AGENTS.md` Quick Skill Reference table extended with 7 new rows.

### Verification

- 10/10 predeploy gates passing
- 38/38 skills passing lint
- 132/132 tests passing
- SBOM refreshed to reflect 38 skills + 10 catalogs

## 0.5.2 — 2026-05-11

Pin-level skill additions closing the sector and thematic coverage gaps the cross-skill audit flagged. Six new skills written by parallel agents; total skills 25 → 31.

### New skills

- **`webapp-security`** — OWASP Top 10 2025, OWASP ASVS v5, CWE root-cause coverage (CWE-22/79/89/77/78/94/200/269/287/352/434/502/732/862/863/918/1188), AI-generated code weakness drift, server-rendered vs SPA tradeoffs.
- **`ai-risk-management`** — ISO/IEC 23894 risk process, ISO/IEC 42001 management system, NIST AI RMF, EU AI Act high-risk obligations (binding 2026-08-02), AI impact assessments, AI red-team programs, AI incident lifecycle.
- **`sector-healthcare`** — HIPAA + HITRUST + HL7 FHIR security, medical device cyber (FDA 524B + EU MDR), AI-in-healthcare under EU AI Act + FDA AI/ML SaMD, PHI in LLM clinical tools.
- **`sector-financial`** — EU DORA TLPT, PSD2 RTS-SCA, SWIFT CSCF v2026, NYDFS 23 NYCRR 500 Second Amendment, FFIEC CAT, MAS TRM, APRA CPS 234, IL BoI Directive 361, OSFI B-13; threat-led pen testing schemes TIBER-EU + CBEST + iCAST.
- **`sector-federal-government`** — FedRAMP Rev5, CMMC 2.0, EO 14028, NIST 800-171/172 CUI, FISMA, M-22-09 federal Zero Trust, OMB M-24-04 AI risk, CISA BOD/ED; cross-jurisdiction NCSC UK + ENISA EUCC + AU PSPF + IL government cyber methodology.
- **`sector-energy`** — Electric power + oil & gas + water/wastewater + renewable-integration cyber. NERC CIP v6/v7, NIST 800-82r3, TSA Pipeline SD-2021-02C, AWWA, EU NIS2 energy + NCCS-G (cross-border electricity), AU AESCSF + SOCI, ENISA energy sector.

### Cross-skill integration

- `researcher` dispatch table extended with 6 new routing entries; count bumped to "30 specialized skills downstream of the researcher (31st)".
- `skill-update-loop`: 6 new skills wired into Triggers 1/3/4/5/9/10 where appropriate. New **Trigger 11 (Sector regulatory cycle)** for healthcare/financial/federal/energy regulatory updates.
- 12 new RFC reverse-references in `data/rfc-references.json` (RFC-7519 / RFC-8725 / RFC-8446 / RFC-9114 / RFC-9421 / RFC-8032 added skills_referencing entries).
- `AGENTS.md` Quick Skill Reference table extended with 6 new trigger-routing rows.

### Verification

- 10/10 predeploy gates passing
- 31/31 skills passing lint
- 132/132 tests passing
- SBOM refreshed to reflect 31 skills + 10 catalogs

## 0.5.1 — 2026-05-11

Pin-level audit cleanup. Closes the final orphans surfaced by the cross-skill audit.

### Orphan closures via citation backfill

- **10 CWE orphans → 0** through citations in existing skills:
  - CWE-22 / CWE-77 / CWE-352 / CWE-434 / CWE-918 cited in `mcp-agent-trust` (MCP HTTP transport weakness classes) and `attack-surface-pentest` (pen-test scope).
  - CWE-269 / CWE-732 cited in `identity-assurance` (privilege management) and `attack-surface-pentest`.
  - CWE-125 / CWE-362 cited in `kernel-lpe-triage` (memory + concurrency kernel classes) and `fuzz-testing-strategy`.
  - CWE-1188 cited in `policy-exception-gen` and `security-maturity-tiers` (insecure-defaults posture).
- **1 framework_gap orphan → 0**: `ISO-IEC-23894-2023-clause-7` cited in `ai-attack-surface` and `threat-modeling-methodology`.

### Cumulative orphan state across all catalogs

| Catalog | Orphans | Total entries |
|---|---|---|
| `data/atlas-ttps.json` | 0 | (full) |
| `data/cve-catalog.json` | 0 | 5 |
| `data/cwe-catalog.json` | 0 | 34 |
| `data/d3fend-catalog.json` | 0 | 21 |
| `data/rfc-references.json` | 0 | 19 |
| `data/framework-control-gaps.json` | 0 | 49 |

Every entry across every catalog is now referenced by ≥1 skill.

### Verification

- 10/10 predeploy gates green (Ed25519 / tests / catalog / offline-CVE / offline-RFC / snapshot / lint / watchlist / catalog-meta / SBOM-currency)
- 132/132 tests passing
- All 25 skills re-signed; manifest snapshot regenerated additively

## 0.5.0 — 2026-05-11

**Cross-skill cohesion + foundational expansion completion.** Closes the orphan framework gaps the cross-skill audit identified, expands jurisdiction coverage, completes the hand-off DAG between skills.

### Four new skills (21 → 25)

Each closes a previously orphaned framework_gap and ships with the full 7-required-section contract plus the optional 8th Defensive Countermeasure Mapping plus a `## Hand-Off / Related Skills` section.

- **`identity-assurance`** — Closes the `NIST-800-63B-rev4` orphan. NIST 800-63 AAL/IAL/FAL, FIDO2/WebAuthn passkeys, OIDC/SAML/SCIM federation, agent-as-principal identity, short-lived workload tokens, OAuth 2.0 + RFC 9700 BCP. References RFC 7519/8725/6749/9700/8032.
- **`ot-ics-security`** — Closes the `NIST-800-82r3`, `IEC-62443-3-3`, `NERC-CIP-007-6-R4` orphans. NIST 800-82r3, IEC 62443-3-3, NERC CIP, IT/OT convergence, AI-augmented HMI threats, ATT&CK for ICS (T0855, T0883).
- **`coordinated-vuln-disclosure`** — Process skill: ISO 29147 (disclosure) + ISO 30111 (handling), VDP, bug bounty, CSAF 2.0 advisories, security.txt (RFC 9116), EU CRA Art. 11 / NIS2 Art. 12 regulator-mandated disclosure, AI vulnerability classes.
- **`threat-modeling-methodology`** — Methodology skill: STRIDE, PASTA, LINDDUN (privacy), Cyber Kill Chain, Diamond Model, MITRE Unified Kill Chain v3, AI-system threat modeling, agent-based threat modeling.

### Cross-skill graph fixes

- **DAG hand-off backfill**: 5 v0.4.0 skills had IN-DEGREE 0 (no skill mentioned them — including the dispatcher); 4 v0.3.0 skills had OUT-DEGREE 0 (leaf with no hand-off). Both fixed. `researcher` dispatch table now routes to all 24 specialized skills with explicit disambiguation policy for 4 trigger collisions (`promptsteal`/`promptflux` fan-out, `compliance gap`, `defense in depth`, `zero trust`). Four former-leaf skills (`kernel-lpe-triage`, `mcp-agent-trust`, `rag-pipeline-security`, `ai-c2-detection`) gained `## Hand-Off / Related Skills` sections.
- **CWE/D3FEND cross-reference backfill**: 16 of 21 skills carried zero `cwe_refs` and 19 of 21 carried zero `d3fend_refs` in manifest entries pre-v0.5.0. Comprehensive backfill applied — D3FEND orphans dropped from 20/20 to 0/20 (every defensive technique now cited by ≥1 skill).
- **Frontmatter dedup pass** — fixed double-`d3fend_refs` blocks introduced by the bulk sync in 3 skills.

### Jurisdiction expansion (22 → 33)

`data/global-frameworks.json` grew from 22 to 33 entries (v1.2.0 → v1.3.0). New nation-state jurisdictions: NO (Norway), MX (Mexico), AR (Argentina), TR (Turkey), TH (Thailand), PH (Philippines). New US sub-national: US_CALIFORNIA (CCPA + CPRA + CPPA + AI Transparency Act). New EU sub-regulators (split out from monolithic EU block): EU_DE_BSI (Germany IT-Grundschutz + TR-02102 crypto), EU_FR_ANSSI (RGS + PASSI + LPM), EU_ES_AEPD (most active GDPR enforcer + AESIA AI agency), EU_IT_AgID_ACN (Italian Perimetro), EU_ENISA (EUCC/EUCS-Cloud certification schemes).

### Update-loop integration

`skill-update-loop` got 4 new skills wired into Triggers 4, 5, and 9. New **Trigger 10: Threat Modeling Methodology Updates** added for STRIDE/LINDDUN/Unified Kill Chain revisions.

### Governance doc refresh

`README.md`, `CONTEXT.md`, `ARCHITECTURE.md`, `MAINTAINERS.md`, `AGENTS.md` Quick Skill Reference table all updated to reflect 25 skills, 10 data catalogs, 33 jurisdictions.

### Verification

- 25/25 skills passing lint
- 132/132 tests passing
- 7/7 predeploy gates passing
- DAG: 0 skills with in-degree 0, 0 skills with out-degree 0
- Orphans: 0 ATLAS, 0 D3FEND, 0 RFC, 0 CVE, 16/34 CWE (unallocated weakness classes — documented gap), 13/49 framework_gaps reduced via the 4 new skills to 9/49 (remaining 9 are sectoral gaps requiring future sector skills)

## 0.4.0 — 2026-05-11

**Foundational expansion pass.** Catches the gaps a deeper-research audit surfaced: CWE / D3FEND / EPSS / DLP / supply-chain / pen-testing / fuzz / ISO 42001 / additional jurisdictions / vendor advisories.

### New data catalogs
- **`data/cwe-catalog.json`** — 30 CWE entries pinned to CWE v4.17. Covers 19 of CWE Top 25 (2024) plus AI/ML / supply-chain entries (CWE-1395, CWE-1426, CWE-1357, CWE-494, CWE-829). Each entry cross-walks to evidence_cves, capec, framework controls, and skills_referencing.
- **`data/d3fend-catalog.json`** — 21 MITRE D3FEND defensive techniques pinned to D3FEND v1.0.0. Counter-mapped to ATT&CK and ATLAS techniques. Each entry carries `ai_pipeline_applicability` per AGENTS.md hard rule #9.
- **`data/dlp-controls.json`** — 21 DLP control entries spanning channel (LLM-prompt, MCP-tool-arg, clipboard-AI, code-completion, IDE-telemetry), classification (regex, ML, embedding-match, watermark), surface (RAG corpus, embedding store, training data), enforcement (block/redact/coach), and evidence (audit, forensics).

### Catalog augmentation
- **`data/cve-catalog.json`** — Every CVE entry gets `epss_score`, `epss_percentile`, `epss_date`, `epss_source` fields. `_meta.epss_methodology` explicitly documents that scores are estimates derived from public catalog signals (KEV, PoC, AI-discovery, blast radius) pending live FIRST API replacement on the next `validate-cves --live` run.
- **`data/framework-control-gaps.json`** — 26 new entries: ISO/IEC 42001:2023, ISO/IEC 23894, OWASP LLM Top 10 (LLM01/02/06/08), OWASP ASVS v5.0, NIST 800-218 SSDF, NIST 800-82r3, NIST 800-63B rev4, IEC 62443-3-3, FedRAMP Rev5, CMMC 2.0, HIPAA Security Rule, HITRUST CSF v11.4, NERC CIP-007-6, PSD2 RTS-SCA, SWIFT CSCF v2026, SLSA Build L3, VEX/CSAF v2.1, CycloneDX 1.6, SPDX 3.0, OWASP Pen Testing Guide v5, PTES, NIST 800-115, CWE Top 25 meta-control. Catalog grew from 23 to 49 entries.
- **`data/global-frameworks.json`** — 8 new jurisdictions: BR (LGPD), CN (PIPL+DSL+CSL), ZA (POPIA), AE (UAE PDPL), SA (KSA PDPL), NZ (Privacy Act 2020), KR (PIPA), CL (Law 19.628 + 2024 amendments). `IN` block enriched with DPDPA alongside the existing CERT-In entry; `CA` enriched with Quebec Law 25 and PIPEDA. `_notification_summary` rolled up across 21 jurisdictions.
- **`sources/index.json`** — 15 new primary sources registered: EPSS API, OSV.dev (promoted), CSAF 2.0, STIX/TAXII (export target), MISP, VulnCheck KEV, CWE, CAPEC, MITRE ATT&CK (pinned v17 / 2025-06-25), D3FEND, SSVC, SLSA, Sigstore, plus a `vendor_advisories` block listing MSRC, RHSA, USN, Apple, Cisco, Oracle, SUSE, Debian DSA, Google ASB.

### Version pinning (AGENTS.md hard rule #12)
- **MITRE ATT&CK v17** (2025-06-25) now pinned at `manifest.json` top level alongside ATLAS v5.1.0. Manifest snapshot tracks both.
- **CWE v4.17, CAPEC v3.9, D3FEND v1.0.0** pinned in `sources/index.json`.

### Frontmatter spec extension
- New optional skill frontmatter fields: `cwe_refs`, `d3fend_refs`, `dlp_refs`. Each validates against the corresponding catalog. Schema in `lib/schemas/skill-frontmatter.schema.json`. Manifest snapshot now diffs these fields.
- New optional 8th body section: `## Defensive Countermeasure Mapping`. Required for skills shipped on or after 2026-05-11; pre-existing skills are exempt until their next minor version bump.
- `## Analysis Procedure` must now explicitly thread **defense in depth, least privilege, and zero trust** as foundational design dimensions (not optional considerations).

### Five new skills (16 → 21)
- **`attack-surface-pentest`** — Modern attack surface management + pen testing methodology. NIST 800-115, OWASP WSTG v5, PTES, ATT&CK-driven adversary emulation, TIBER-EU. AI-surface (APIs, MCP, RAG, embedding stores) included in scope.
- **`fuzz-testing-strategy`** — Continuous fuzzing as security control. AFL++, libFuzzer, syzkaller, RESTler, garak, AI-augmented fuzz (OSS-Fuzz pipelines, Microsoft AIM). NIST 800-218 SSDF gap.
- **`dlp-gap-analysis`** — DLP gaps for mid-2026: legacy DLP misses LLM prompts, MCP tool args, RAG retrievals, embedding-store exfiltration, code-completion telemetry. Layered defense across SDK logging / proxy inspection / endpoint DLP / egress NTA.
- **`supply-chain-integrity`** — SLSA Build L3+, in-toto attestations, Sigstore signing, SBOM (CycloneDX 1.6 / SPDX 3.0), VEX via CSAF 2.0, AI-generated code provenance, model weights as supply-chain artifacts.
- **`defensive-countermeasure-mapping`** — Meta-skill mapping offensive findings (CVE / TTP / framework gap) to MITRE D3FEND defensive techniques with explicit defense-in-depth layer, least-privilege scope, zero-trust posture, AI-pipeline applicability.

### Linter + snapshot gate updates
- `lib/lint-skills.js` validates `cwe_refs` against `data/cwe-catalog.json`, `d3fend_refs` against `data/d3fend-catalog.json`, `dlp_refs` against `data/dlp-controls.json`.
- `scripts/check-manifest-snapshot.js` and `scripts/refresh-manifest-snapshot.js` include the three new ref fields in the public-surface diff.
- AGENTS.md skill format spec + Quick Skill Reference table updated for the 5 new skills.

### Verification
- 21/21 skills passing lint
- 132/132 tests passing
- 7/7 predeploy gates passing

## 0.3.0 — 2026-05-11

Pre-release: every CI gate green, full skill corpus compliant with the AGENTS.md hard rules.

### Vendor-neutrality refactor
- **Renamed `AGENT.md` → `AGENTS.md`** to align with the cross-vendor convention (OpenAI Codex CLI, Sourcegraph amp, Aider, Continue, Cline, Roo Code, Q Developer all auto-load `AGENTS.md`). `AGENTS.md` is the canonical agent-agnostic source for all internal citations and the **only** project-rules file shipped in the repo.
- **Removed `CLAUDE.md` entirely.** No per-vendor mirror is shipped. The earlier plan to maintain a byte-identical Claude Code mirror was dropped after recognizing that a globally-gitignored filename would never reach downstream consumers anyway. Claude Code users load `AGENTS.md` manually (`@AGENTS.md`) or via a per-machine `~/.claude/CLAUDE.md` they configure themselves.
- **Added `.windsurfrules`** as a pointer stub for Windsurf's auto-load convention.
- **Bulk replaced all internal citations** (~20 files: `.github/workflows/*`, `.github/ISSUE_TEMPLATE/*`, schemas, library code, scripts, skill bodies) so the project no longer privileges one vendor's filename when citing its own rules.
- **`README.md` AI Assistant Configuration table** now lists every major coding assistant — OpenAI Codex CLI, Anthropic Claude Code, Cursor, GitHub Copilot, Windsurf, Sourcegraph amp, Aider, Continue, Cline, Roo Code, Q Developer, Google Gemini CLI, JetBrains AI, Replit Agent — with explicit instructions for how each one picks up `AGENTS.md`.

### Skills (16th added)
- `researcher` — Top-level triage entry-point that classifies raw threat intel inputs (CVE ID, ATLAS TTP, framework control, incident narrative), researches them across every `data/*.json` catalog, applies RWEP scoring, and routes to the right downstream specialized skill with an EU/UK/AU/ISO global-jurisdiction surface. Closes the orchestration gap between operator and the 15 specialist skills.

### Pre-ship gate compliance
- Every CI gate now passes locally and in-workflow: `npm run predeploy` reports 6/6 green (Ed25519 signature verification, cross-OS tests, CVE catalog + zero-day learning loop validation, offline CVE state, manifest snapshot gate, skill lint).
- Lint compliance backfill: 14 skills updated to satisfy the 7-required-section body contract from CLAUDE.md without rewriting any existing content. Added sections preserve mid-2026 grounding, real CVE / ATLAS / framework refs, and RWEP-anchored prioritization throughout.
- Frontmatter completeness: `pqc-first`, `skill-update-loop`, `zeroday-gap-learn` now carry the full required field set (`atlas_refs`, `attack_refs`, `framework_gaps`) per the CLAUDE.md skill spec.

### Data
- `data/framework-control-gaps.json` — added `NIST-800-53-SC-7` (Boundary Protection) entry. Documents how AI-API C2 routes through allowlisted provider domains (api.openai.com, api.anthropic.com, generativelanguage.googleapis.com) and defeats boundary inspection. Maps to `AML.T0096`, `AML.T0017`, `T1071`, `T1102`, `T1568`. Closes the orphaned-reference gap that the lint gate caught in `ai-c2-detection`.

### Verification
- 110/110 tests passing (`npm test`)
- 16/16 skills passing lint (`npm run lint`)
- All 6 predeploy gates green (`npm run predeploy`)

## 0.2.0 — 2026-05-11

### Skills (15th added)
- `security-maturity-tiers` — Four-tier security maturity model with RWEP-indexed priorities and MCP audit integration

### Infrastructure added
- `lib/sign.js` — Ed25519 keypair management and skill signing utility
- `lib/verify.js` — Upgraded from SHA-256 to Ed25519 cryptographic signature verification
- `lib/framework-gap.js` — Framework lag scorer with 7 compliance theater pattern detectors
- `orchestrator/scanner.js` — Domain scanner (kernel, MCP, crypto, AI-API, framework) using shell-injection-safe execFileSync/spawnSync
- `orchestrator/dispatcher.js` — Skill router: finding → skill dispatching, natural language routing
- `orchestrator/pipeline.js` — Multi-agent pipeline coordination with currency scoring
- `orchestrator/event-bus.js` — Event-driven architecture (ExceptdEventBus) for CISA KEV, ATLAS releases, framework amendments
- `orchestrator/scheduler.js` — Weekly currency checks, monthly CVE validation, annual skill audit
- `orchestrator/index.js` — CLI entrypoint (scan, dispatch, currency, report, watch, validate-cves)
- `package.json` — Node.js 24 LTS pinning (>=24.0.0 <25.0.0), npm scripts for all orchestrator commands
- `.gitignore` — Starts with `.*` catch-all; whitelists tracked dotfiles

### Configuration files added
- `AGENT.md` — Agent-agnostic copy of CLAUDE.md (no Claude-specific language)
- `CONTEXT.md` — Universal AI context file: skill system orientation, RWEP explanation, data files, orchestrator usage
- `.cursorrules` — Cursor-specific skill system config with MCP audit paths
- `.github/copilot-instructions.md` — GitHub Copilot skill system configuration

### Data completeness
- `data/atlas-ttps.json` — 9 MITRE ATLAS v5.1.0 TTPs with framework gap analysis and detection guidance
- `data/global-frameworks.json` — 14-jurisdiction GRC registry with patch SLAs and notification windows
- `data/framework-control-gaps.json` — Added 11 entries: NIS2-Art21-patch-management, NIST-800-53-CM-7, ISO-27001-2022-A.8.30, SOC2-CC9-vendor-management, NIST-800-53-SC-28, NIST-800-53-SI-12, NIST-AI-RMF-MEASURE-2.5, ISO-27001-2022-A.8.16, SOC2-CC7-anomaly-detection, CIS-Controls-v8-Control7 (11 total additions)
- `data/zeroday-lessons.json` — Added CVE-2026-43284 and CVE-2026-43500 lessons; now covers all 5 catalog CVEs

### RWEP formula correction
- **Bug fix**: `ai_factor` now applies to `ai_discovered` OR `ai_assisted_weaponization` (was: weaponization only)
- **Bug fix**: `reboot_required` now always adds +5 when patch requires reboot (was: conditional on !live_patch_available)
- **Blast radius scale**: extended from 0-15 to 0-30 to properly capture population-level risk
- **Recalculated RWEP scores** (all formula-consistent):
  - CVE-2026-31431: 90 (was 96 — narrative error)
  - CVE-2026-43284: 38 (was 84 — factors didn't sum to stored score)
  - CVE-2026-43500: 32 (was 81 — same)
  - CVE-2025-53773: 42 (was 91 — CVSS overscored; no KEV, suspected exploitation)
  - CVE-2026-30615: 35 (was 94 — CVSS dramatically overscored; supply-chain prerequisite)
- **Narrative**: Copy Fail (CVSS 7.8 / RWEP 90) vs Windsurf MCP (CVSS 9.8 / RWEP 35) demonstrates RWEP provides correct prioritization in both directions
- Added `live_patch_available`, `live_patch_tools`, `ai_discovered` to CVE_SCHEMA_REQUIRED
- Added `complexity_notes` field to CVE-2026-43500
- CVE-2026-43284 `live_patch_available` corrected to false (kpatch RHEL-only, not population-level available)

### CLAUDE.md additions
- Hard Rule 11: No-MVP ban — half-implemented skill is worse than no skill
- Hard Rule 12: External data version pinning — ATLAS v5.1.0 current pinned version
- Hard Rule 13: Skill integrity verification via Ed25519 (lib/sign.js + lib/verify.js)
- Non-developer contribution section (GitHub Issue → Skill Request template)
- Pre-ship checklist expanded to 14 items
- Quick skill reference table (15 skills)

---

## 0.1.0 — 2026-05-01

### Initial release

**Skills (14 — security-maturity-tiers added in 0.2.0):**
- `kernel-lpe-triage` — Linux kernel LPE assessment (Copy Fail, Dirty Frag)
- `ai-attack-surface` — Comprehensive AI/ML attack surface assessment (ATLAS v5.1.0)
- `mcp-agent-trust` — MCP trust boundary enumeration and hardening
- `framework-gap-analysis` — Framework control → current TTP gap analysis
- `compliance-theater` — Seven-pattern compliance theater detection
- `exploit-scoring` — Real-World Exploit Priority (RWEP) scoring
- `rag-pipeline-security` — RAG pipeline threat model (no framework coverage)
- `ai-c2-detection` — SesameOp/PROMPTFLUX/PROMPTSTEAL detection and response
- `policy-exception-gen` — Defensible exception templates for architectural realities
- `threat-model-currency` — 14-item threat model currency assessment
- `global-grc` — 14-jurisdiction GRC mapping with universal gap declaration
- `zeroday-gap-learn` — Zero-day learning loop (CVE → control gap → framework gap)
- `pqc-first` — Post-quantum cryptography first mentality with version gates and loopback learning
- `skill-update-loop` — Meta-skill for keeping all skills current

**Data files:**
- `data/cve-catalog.json` — CVE-2026-31431, CVE-2026-43284, CVE-2026-43500, CVE-2025-53773, CVE-2026-30615
- `data/atlas-ttps.json` — MITRE ATLAS v5.1.0 TTPs for AI attack classes
- `data/framework-control-gaps.json` — NIST, ISO, SOC 2, PCI, NIS2, CIS documented gaps
- `data/global-frameworks.json` — 14-jurisdiction framework registry
- `data/exploit-availability.json` — PoC status and weaponization tracking
- `data/zeroday-lessons.json` — Learning loop output for 5 documented CVEs

**Infrastructure:**
- `sources/` — Primary source registry, validation protocol, multi-agent research verification
- `agents/` — threat-researcher, source-validator, skill-updater, report-generator definitions
- `reports/templates/` — Executive summary, compliance gap, zero-day response templates
- `lib/scoring.js` — RWEP scoring engine with schema validation
- `lib/ttp-mapper.js` — Control ID → TTP gap mapper
- `lib/framework-gap.js` — Framework lag scorer

**Architecture:**
- Forward watch mechanism in every skill's YAML frontmatter
- Loopback learning encoded in skill-update-loop and pqc-first
- Source validation gate before any data enters the catalog
- Multi-agent coordination protocol (threat-researcher → source-validator → skill-updater → report-generator)
- RWEP scoring (CVSS + KEV + PoC + AI-acceleration + blast radius + live-patch factors)
- Compliance theater detection (7 patterns with specific detection tests)
- 14-jurisdiction global GRC coverage
- PQC version gates: OpenSSL 3.5+, Go 1.23+, Bouncy Castle 1.78+
- Hard algorithm deprecation table with sunset reasoning

**ATLAS version:** 5.1.0 (November 2025)
**Threat review date:** 2026-05-01

---

## Forthcoming in 0.3.0

- `sources/validators/cve-validator.js` — NVD API cross-check script
- `sources/validators/kev-validator.js` — CISA KEV feed cross-check
- `reports/templates/technical-assessment.md`
- `reports/templates/threat-model-update.md`
- `agents/framework-analyst.md` — Framework analyst agent definition
- Integration tests for `lib/scoring.js`
- Ed25519 signatures for all 15 skills (`node lib/sign.js generate-keypair && sign-all`) — requires key ceremony
