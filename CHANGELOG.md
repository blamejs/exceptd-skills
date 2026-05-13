# Changelog

## 0.12.6 — 2026-05-13

**Patch: primary-source IoC audit across the catalog — five CVEs reviewed line-level against published exploit source. AGENTS.md Hard Rule #14 added.**

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
