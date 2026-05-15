# exceptd Security — Development Standards

> **This is the canonical development guide and the only project-rules file shipped in this repo.** It is AI-system-agnostic — internal citations throughout the repo all reference `AGENTS.md` (this file). The project does NOT ship per-vendor mirrors; tool users configure their tool to load `AGENTS.md`. Multiple tools auto-load `AGENTS.md` directly under the cross-vendor convention (OpenAI Codex CLI, Sourcegraph amp, Aider, Continue, Cline, Roo Code, Q Developer). Cursor (`.cursorrules`), GitHub Copilot (`.github/copilot-instructions.md`), and Windsurf (`.windsurfrules`) get small pointer stubs that reference this file. Claude Code / Gemini CLI / JetBrains AI / Replit Agent users should add `AGENTS.md` to their tool's context manually (Claude Code: `@AGENTS.md`, or symlink their own local `~/.claude/CLAUDE.md` to it).

Also read [CONTEXT.md](CONTEXT.md) for a complete orientation to the skill system.

## Hard Rules

1. **No stale threat intel** — Every CVE reference must include: CVSS score, KEV status, PoC availability, AI-discovery flag, active exploitation status, and patch/live-patch availability. No theoretical vulnerabilities without real-world grounding.

2. **Framework lag is a first-class concept** — Every skill must explicitly declare which framework controls are insufficient for the threats it covers. Never imply a framework control is adequate when current TTPs bypass it.

3. **No CVSS-only risk scoring** — CVSS is a severity metric, not a risk metric. Every risk score uses the Real-World Exploit Priority (RWEP) model defined in `lib/scoring.js`. CVSS is reported alongside RWEP for compatibility, never as the sole score.

4. **No orphaned controls** — Every control recommendation maps to a real attacker TTP in `data/atlas-ttps.json` or `data/cve-catalog.json`. Controls without a mapped threat are removed, not kept for completeness.

5. **Global-first, not US-centric** — Every framework gap analysis includes at least EU (NIS2/DORA/EU AI Act), UK (CAF), AU (ISM/Essential 8), and ISO 27001:2022 alongside NIST references. US-only analysis is incomplete.

6. **Zero-day learning is live** — `data/zeroday-lessons.json` is updated whenever a new CVE in scope is added to `data/cve-catalog.json`. The learning loop (zero-day → attack vector → control gap → framework gap → new control requirement) runs completely, not partially.

7. **Skill files are instructions, not descriptions** — Each `skill.md` tells the AI assistant exactly how to perform the analysis: what questions to ask, what data to pull, how to score, what to output. Generic "assess security posture" language is not a skill.

8. **Compliance theater detection is mandatory** — Every skill that touches a compliance framework must include a compliance theater check: a specific question or test that distinguishes paper compliance from actual security.

9. **Ephemeral and AI-pipeline realities are first-class** — Never recommend controls that are architecturally impossible for serverless, container, or AI pipeline environments without providing an explicitly scoped alternative.

10. **No placeholder data** — `data/*.json` files contain real CVE metadata, real ATLAS TTP IDs, real framework control IDs. Placeholder entries (`"tbd"`, `"coming soon"`, empty arrays where data exists) fail the pre-ship check.

11. **No-MVP ban** — A half-implemented skill is worse than no skill. Every shipped skill has: complete frontmatter, all required body sections, real data deps populated, a compliance theater check, and a concrete output format. Partial skills are not merged — they are finished or removed.

12. **External data version pinning** — Every reference to external data (MITRE ATLAS, MITRE ATT&CK, NIST frameworks, CISA KEV, IETF RFCs and Internet-Drafts) must pin to a specific version. When a new version is released: (a) audit for breaking changes (renamed TTPs, tactic-split moves, replaced RFCs, deprecated controls), (b) bump `last_threat_review` in all affected skills, (c) update `_meta` version fields in the relevant `data/*.json` file, (d) update `last_verified` on affected `data/rfc-references.json` entries, (e) never silently inherit version changes. Frameworks lag RFCs; RFCs lag attacker innovation — skills must track lag at every layer.

    **Pinned ATLAS version: v5.4.0 (February 2026), Secure AI v2 layer (May 2026). Audit cadence: monthly** (ATLAS now ships monthly per CTID; the Secure AI v2 layered set and per-technique maturity classification are tracked separately in `data/atlas-ttps.json` via the `secure_ai_v2_layer` and `maturity` fields).

    **Pinned ATT&CK version: v19.0 (April 2026). Audit cadence: semi-annual** (April and October releases). v19 split Defense Evasion (TA0005) into Stealth (TA0005) and Defense Impairment (TA0112) — affected entries in `data/attack-techniques.json` carry `tactic_moved_from` for traceability. v18 introduced Detection Strategies (DSxxxx) as first-class objects; record applicable strategy IDs on entries where canonical strategies exist.

    The IETF RFC / Internet-Draft catalog lives at `data/rfc-references.json`; each entry tracks status, errata count, replaces / replaced-by, and `last_verified`.

13. **Skill integrity verification** — Every skill in `manifest.json` carries an Ed25519 `signature` (base64) and a `signed_at` timestamp covering its `skill.md` content. `lib/verify.js` checks each signature against the public key at `keys/public.pem` before any skill is loaded by the orchestrator. Tampered or unsigned skills are rejected. The private key at `.keys/private.pem` is gitignored and never enters the repo. Run `node lib/verify.js` (or `npm run verify`) before shipping; sign new or changed skills with `npm run bootstrap` for first-run, or `node lib/sign.js sign-all` after content changes.

14. **Primary-source IoC review** — Any CVE entry in `data/cve-catalog.json` whose `poc_available: true` AND whose exploit code is publicly available (published PoC repo, vendor advisory with attached payload, researcher blog with reproducer) must include `iocs` populated from a line-level cross-reference of the published source — not from secondary-source paraphrase. The `iocs` block records which IoC categories were extracted (`payload_artifacts`, `persistence_artifacts`, `credential_paths_scanned`, `c2_indicators`, `host_recon`, `behavioral`, `runtime_syscall`, `kernel_trace`, `livepatch_gap`, `destructive`, `payload_content_patterns`, `supply_chain_entry_vectors`), and each IoC must be traceable to a specific source URL or commit hash. v0.12.6 audit reviewed CVE-2026-45321 (Mini Shai-Hulud), CVE-2026-31431 (Copy Fail / Dirty Pipe / Dirty COW family), CVE-2026-43284 + CVE-2026-43500 (Dirty Frag pair), CVE-2025-53773 (Copilot YOLO mode), and CVE-2026-30615 (Windsurf MCP) against primary sources from Aikido, StepSecurity, Socket, Wiz, Datadog, Sysdig, Trail of Bits, Invariant Labs, Embrace the Red, NVD, MSRC. Catalog updates landed in v0.12.6 changelog. Skipping this audit is equivalent to shipping "untested security advice" — the IoC list IS the operator-facing detection contract.

15. **Test coverage on every diff** — Every feature change (added, removed, or modified) must land with a covering test reference in the same PR. The shapes the gate enforces:

    | Change                                                | Required test reference                                                          |
    | ----------------------------------------------------- | -------------------------------------------------------------------------------- |
    | New / removed CLI verb in `bin/exceptd.js`            | Quoted verb literal in a `tests/*.test.js` file                                  |
    | New / removed CLI flag                                | Flag literal (e.g. `--my-flag`) somewhere under `tests/`                         |
    | New / removed / renamed `module.exports` identifier   | `require('…/<lib>')` plus a reference to the identifier in `tests/`              |
    | New `phases.detect.indicators[].id` in a playbook     | Quoted indicator id literal in `tests/e2e-scenarios/*/expect.json` or `tests/*.test.js` |
    | New / changed `iocs` field on a CVE entry             | CVE id and the word `iocs` in the same test file                                 |

    Mechanical enforcement lives in `scripts/check-test-coverage.js` and runs as the 13th gate of `npm run predeploy` (also the `Diff coverage` job in `ci.yml`). Docs (`*.md`), workflow YAML, and skill body changes are allowlisted — skill bodies are covered by the Ed25519 signature gate (Hard Rule #13), workflows surface a manual-review flag rather than a hard finding. Whitespace-only diffs are ignored.

    The gate is blocking: a covered surface change without a covering test reference fails the predeploy run and the `Diff coverage` CI job. Never bypass with `--no-verify` or `--warn-only` — add the covering test first. This rule is additive to Hard Rule #11 (no-MVP ban): a new playbook indicator or CLI surface that ships without a regression test is the same shape of incomplete-feature ship that #11 forbids, applied to the test layer.

---

## Seven-phase playbook contract

exceptd ships investigation playbooks under `data/playbooks/*.json` (schema: `lib/schemas/playbook.schema.json`; reference playbook: `data/playbooks/kernel.json`). Each playbook defines a **seven-phase** investigation that splits cleanly between exceptd (knowledge + GRC layer) and the host AI assistant (artifact collection + indicator evaluation). The host AI invokes the runner via the `exceptd brief` / `exceptd run` / `exceptd ai-run` verbs or, for in-process callers, `require('@blamejs/exceptd-skills/lib/playbook-runner.js')`. exceptd owns **govern, direct, analyze, validate, close**; the AI owns **look, detect**. Phases run strictly in order — never reorder, never skip.

### The seven phases

1. **govern (exceptd)** — Runner emits jurisdiction obligations (e.g. NIS2 24h, DORA 4h, GDPR 72h), theater fingerprints to test for, framework gap context, and `skill_preload` listing skills the AI must load into its session context before proceeding. The AI loads `skill_preload` and surfaces jurisdiction obligations to the operator **before** doing any investigation work.
2. **direct (exceptd)** — Runner emits `threat_context` (current real CVEs/TTPs with dates from `data/cve-catalog.json`), `rwep_threshold` (live-patch / urgent-patch / scheduled-patch bands), `framework_lag_declaration`, `skill_chain`, and `token_budget`. The AI uses this to plan its collection work — what to look for and why.
3. **look (AI)** — The AI collects typed artifacts per the playbook's `look.artifacts` spec using **native** tools (Bash, Read, Grep, Glob — no shelling back into exceptd for collection). When `_meta.air_gap_mode=true`, the AI honors each artifact's `air_gap_alternative` instead of the default collection method. Every artifact submission is structured as `artifacts: { <id>: { value, captured: true|false, reason?: string } }`. Failed collections are **never** silently dropped — they get `captured: false` with a `reason` string so the runner records the visibility gap.
4. **detect (AI)** — The AI evaluates the collected artifacts against `playbook.detect.indicators`. Pattern-matching (regex against raw artifact content, version range checks, presence/absence tests) happens in the AI — exceptd does not see the raw artifact content. The AI submits `signal_overrides: { <indicator_id>: 'hit' | 'miss' | 'inconclusive' }` plus any other signal values the playbook declares. If the indicator definition includes `false_positive_checks_required`, the AI MUST run those checks before declaring `hit`.
5. **analyze (exceptd)** — Runner joins the AI's signals to `data/cve-catalog.json`, computes RWEP per `lib/scoring.js`, scores blast radius, runs the compliance theater check, builds the `framework_gap_mapping` (EU/UK/AU/ISO/NIST per Hard Rule #5), and fires `escalation_criteria` when thresholds are crossed.
6. **validate (exceptd)** — Runner picks a `remediation_path` from the playbook's options (priority-ordered), returns `validation_tests` the AI must run to confirm the remediation worked, a `residual_risk_statement`, `evidence_requirements`, and a `regression_next_run` cadence.
7. **close (exceptd)** — Runner assembles a CSAF-2.0-shaped `evidence_package` (signed=true by default), drafts a `learning_loop` lesson queued for `data/zeroday-lessons.json`, computes `notification_actions` with ISO-8601 deadlines derived from each obligation's `clock_starts` event, evaluates the `exception_generation` trigger and renders `auditor_ready_language` verbatim when it fires, finalizes the `regression_schedule`, and lists `feeds_into` downstream playbooks.

### What the AI MUST do

- **Never bypass govern.** Always surface jurisdiction obligations to the operator before any investigation activity. This is non-negotiable — DPO / GRC accountability begins at govern, not at close.
- **Never silently drop artifacts.** Collection failures get `captured: false, reason: "<string>"`. The runner uses missing-artifact records to compute visibility gaps and to qualify confidence in the analyze phase.
- **Always run `false_positive_checks_required`** tests when detect returns them. A `hit` without its false-positive checks is reported as `inconclusive`.
- **Always show the operator `auditor_ready_language` verbatim** from `close.exception` when the exception fires. Never paraphrase, summarize, or "clean up" the auditor-ready language — it is signed-off language and changing it invalidates the artifact.
- **Always offer to persist the signed `evidence_package`** to the operator's evidence store. Never discard it silently, never replace it with a chat-window summary.
- **Honor `_meta.mutex`.** If a playbook's `_meta.mutex` lists a currently-running playbook ID, the AI MUST refuse to start the new playbook and tell the operator which one is blocking it.
- **Honor `threat_currency_score`.** Below 70: surface a currency warning to the operator. Below 50: hard-block playbook execution unless the operator passes `--force-stale`.

### What the AI MUST NOT do

- **Do not duplicate exceptd's catalog data** in your own response. CVE metadata, ATLAS TTP IDs, framework control IDs, RFC numbers — always cross-reference live via the runner. Stale duplicates violate Hard Rule #1.
- **Do not skip close.** A finding without a close phase is not durable. Do not claim a finding is "complete" without an `evidence_package` emission. Open findings without close phase are tracked as IR-incomplete.
- **Do not invent** CVE IDs, framework controls, jurisdiction obligations, ATLAS TTPs, or RFC references not present in the playbook output. If the playbook does not return it, it does not exist for this investigation.
- **Do not reorder the phases.** govern → direct → look → detect → analyze → validate → close. No exceptions, no shortcuts, no "we already know what's wrong so skip govern."
- **Do not auto-execute `notification_actions`** or auto-file tickets. The runner produces drafts; the operator reviews and dispatches. AI-initiated regulator notification is out of scope and out of policy.

### Worked example (kernel playbook)

Operator asks: "is this host vulnerable to Copy Fail?" AI invokes `node lib/playbook-runner.js data/playbooks/kernel.json`. **govern** returns NIS2 24h incident notification + DORA 4h major-ICT-incident notification obligations and preloads `kernel-lpe-triage`, `exploit-scoring`, `global-grc`; AI surfaces both deadlines to the operator. **direct** emits threat_context anchored on real 2026 kernel CVEs and rwep_threshold bands 90 (live-patch) / 70 (urgent) / 30 (scheduled). **look** directs the AI to capture `uname -r` and `/etc/os-release`; AI uses Bash to read both and submits `artifacts: { kernel_version: { value: "5.15.0-101-generic", captured: true }, os_release: { value: "Ubuntu 22.04.4 LTS", captured: true } }`. **detect** evaluates the `kver-in-affected-range` indicator; AI confirms 5.15.0 falls in the affected range and submits `signal_overrides: { 'kver-in-affected-range': 'hit' }` after running its false-positive checks; the playbook classifies the host as "detected". **analyze** matches three catalogued CVEs (including CVE-2026-31431, KEV-listed, RWEP 90), computes `blast_radius_score=3`, runs the theater check and returns `verdict=theater` (paper SI-2 compliance does not address sub-hour live-patch reality). **validate** selects remediation path `live-patch-deploy` (priority 1) over `kernel-upgrade` (priority 2), returns validation_tests and a residual_risk_statement. **close** emits a signed CSAF-2.0 evidence_package, draft NIS2 (24h from operator-confirmed detection time) and DORA (4h from same anchor) notification text, and a learning_loop lesson queued for `data/zeroday-lessons.json`. AI shows the operator both notification drafts and asks whether to persist the evidence_package — does not auto-send either.

### CLI invocation

- **CLI verb:** `exceptd run <playbook> --evidence <file>` walks the full seven phases against operator-supplied evidence. `exceptd brief <playbook>` returns Phase 2 threat context for prep; `exceptd ai-run` is the streaming variant for AI agents. `exceptd ci` is the gate-only variant for CI pipelines (exit 8 on lock contention, 6 on tampered attestations).
- **Library entry point:** `require('@blamejs/exceptd-skills/lib/playbook-runner.js')` exposes the same engine for in-process callers — schema reference at `lib/schemas/playbook.schema.json`.

Schema reference: `lib/schemas/playbook.schema.json`. Reference playbook (read this before authoring a new one): `data/playbooks/kernel.json`.

### feeds_into threshold matrix

Each playbook's `_meta.feeds_into[]` declares downstream playbooks the host AI should consider chaining into after this run, and the condition that fires the chain. The condition expressions evaluate at `close()` against `analyze` + `validate` + `agentSignals` context. AI assistants surface the suggested next playbook to the operator but never auto-execute; the operator decides.

The current matrix:

| From | Triggers | To | Why |
|---|---|---|---|
| ai-api | `analyze.compliance_theater_check.verdict == 'theater'` | framework | dotfile-cred-exposure theater pattern |
| ai-api | `analyze.blast_radius_score >= 4` | sbom | broad blast radius → inventory check |
| ai-api | `finding.includes_mcp_server_credential_exposure == true` | mcp | MCP creds leaked → MCP fleet audit |
| containers | `finding.severity >= 'high'` | kernel | container escape → kernel surface |
| containers | `always` | secrets | manifests routinely embed secrets |
| cred-stores | `finding.severity >= 'high'` | secrets | leaked creds in store → repo grep |
| cred-stores | `finding.severity == 'critical'` | runtime | critical exposure → listening-surface audit |
| crypto | `analyze.compliance_theater_check.verdict == 'theater'` | framework | FIPS-claim vs reality |
| crypto | `analyze.blast_radius_score >= 4` | sbom | crypto blast → SBOM-cve match |
| framework | `any compliance_theater_check.verdict == 'theater' AND blast_radius_score >= 4` | sbom | theater + breadth → inventory |
| hardening | `always` | kernel | hardening is corroborator for kernel finding |
| hardening | `finding.severity >= 'high'` | runtime | weak hardening → check actual exposure |
| kernel | `finding.severity == 'critical' OR analyze.blast_radius_score >= 4` | sbom | critical kernel → SBOM cross-ref |
| kernel | `analyze.compliance_theater_check.verdict == 'theater'` | framework | patch-SLA theater |
| mcp | `finding.severity == 'critical' OR analyze.blast_radius_score >= 4` | sbom | broad MCP impact → inventory |
| mcp | `analyze.compliance_theater_check.verdict == 'theater'` | framework | MCP-trust theater |
| mcp | `finding.includes_credential_exposure == true` | ai-api | MCP cred → AI-API cred audit |
| runtime | `always` | kernel | listener finding always informs kernel triage |
| runtime | `always` | hardening | runtime exposure pairs with hardening posture |
| runtime | `finding.severity == 'critical' OR analyze.blast_radius_score >= 3` | cred-stores | critical runtime → check cred stores |
| sbom | `analyze.compliance_theater_check.verdict == 'theater'` | framework | SBOM-signing theater |
| sbom | `any matched_cve.attack_class == 'kernel-lpe'` | kernel | kernel CVE in inventory → kernel playbook |
| sbom | `any matched_cve.attack_class == 'mcp-supply-chain'` | mcp | MCP CVE in inventory → MCP playbook |
| sbom | `any matched_cve.attack_class IN ['ai-c2', 'prompt-injection']` | ai-api | AI CVE → AI-API playbook |
| secrets | `finding.severity >= 'high'` | cred-stores | leaked secret in repo → check store posture |

Cross-cutting playbook `framework` is the natural correlation layer — many playbooks chain into it on a theater verdict. `sbom` is the breadth-of-impact follow-up most playbooks suggest when blast radius crosses 4. `kernel` + `hardening` + `runtime` form a tightly-coupled triangle (any one finding raises questions in the other two). When a playbook lists `always` as a feeds_into condition, the chain runs unconditionally — the AI should always at least offer the next playbook to the operator.

### CLI reference

| Verb | What it does |
|---|---|
| `exceptd brief --all` | Grouped-by-scope summary of all 13 playbooks. `--scope <type>` filters. `--directives` expands directive IDs/titles per playbook. `--flat` for non-grouped. Legacy alias: `exceptd plan` (deprecated, scheduled for removal in v0.13). |
| `exceptd brief <pb>` | Phase 2 threat-context briefing — threat context, RWEP thresholds, skill chain, token budget, jurisdiction obligations. |
| `exceptd run <pb> --evidence <file>` | Phases 5-7 (analyze + validate + close) from agent evidence. Auto-detect cwd when no playbook positional. `--vex <file>` drops CycloneDX/OpenVEX `not_affected` CVEs. `--diff-from-latest` for drift mode. `--force-stale` overrides currency hard-block. |
| `exceptd ai-run <pb>` | Streaming variant of `run` for AI agents; emits phase-by-phase NDJSON. |
| `exceptd run-all` | Multi-playbook batch run. `--scope <type>` filters. |
| `exceptd ci` | Top-level CI gate for a single playbook with exit-code semantics. Preferred over `run --ci`. |
| `exceptd discover` | Repo discovery — scans cwd and surfaces matching playbooks + collection hints. |
| `exceptd ask <pb> <question>` | Read-only Q&A against a playbook's directives, indicators, and threat context. |
| `exceptd attest diff <sid>` | Replay analyze against a stored evidence bundle for drift detection. `--against <other-sid>` compares two sessions. `--playbook <id>` + `--since <ISO>` accepted with `--latest`. Legacy alias: `exceptd reattest` (deprecated, scheduled for removal in v0.13). |
| `exceptd attest verify <sid>` | Verify a persisted attestation's signature + evidence hash. |
| `exceptd attest list` | Inventory `.exceptd/attestations/` — newest first. `--playbook <id>` filters. |
| `exceptd attest show <sid>` | Print the attestation body. |
| `exceptd doctor` | Health checks. `--signatures` verifies Ed25519 chains; `--cves` / `--rfcs` check catalog currency; `--fix` repairs recoverable state. |
| `exceptd lint` | Skill format lint — frontmatter completeness, required body sections, signature presence. |

All verbs support `--help` for per-verb usage. JSON output by default; `--pretty` for indented.

---

## Recurring Drift Rules

**DR-1: Framework-as-truth drift**
Wrong: "SOC 2 CC6.1 covers access control for this threat."
Right: "SOC 2 CC6.1 defines logical access controls for on-prem/cloud IAM. It does not cover prompt injection as an access control bypass vector, which achieves equivalent unauthorized access via the model's context window."

**DR-2: CVSS-as-risk drift**
Wrong: "CVSS 7.8 High — remediate within 30 days."
Right: "CVSS 7.8 / RWEP 90 — CISA KEV listed, PoC is 732 bytes with no race condition, AI-discovered, blast radius spans all Linux >= 4.14. 30-day window is inapplicable. Live kernel patch within 4 hours or isolate at network layer immediately."

**DR-3: Control existence drift**
Wrong: "Implement patch management per SI-2."
Right: "SI-2 requires timely patching. For Copy Fail class LPEs (deterministic, no race condition, public PoC), 'timely' must be operationalized as: live kernel patch within 4 hours, or document compensating controls (seccomp profile + namespace isolation + network isolation) with RWEP justification."

**DR-4: US-only framework drift**
Wrong: citing only NIST 800-53 and SOC 2 for a multi-jurisdictional org.
Right: the global-grc skill runs alongside any framework-gap-analysis for orgs operating in EU, UK, AU, SG, IN, or JP.

**DR-5: AI-as-future drift**
Wrong: "AI-assisted attacks are an emerging threat to monitor."
Right: "41% of 2025 zero-days were discovered by attackers using AI-assisted reverse engineering. Copy Fail was AI-discovered in ~1 hour. AI acceleration of the exploit development cycle is current operational reality, not a future consideration."

**DR-6: Placeholder propagation**
Wrong: adding a new CVE to `data/cve-catalog.json` without completing all required fields.
Right: every new entry requires all fields defined in the CVE catalog schema. Partial entries fail the schema validation in `lib/scoring.js`.

**DR-7: Stale ATLAS / ATT&CK version**
Current pinned ATLAS version: **v5.4.0 (February 2026)** with the **CTID Secure AI v2 layer (May 2026)**. ATLAS audit cadence is **monthly** (CTID now ships monthly). Current pinned ATT&CK version: **v19.0 (April 2026)**, semi-annual cadence (April + October). When either source updates: audit all TTP IDs for changes (including v19's Defense Evasion → Stealth / Defense Impairment split), bump `last_threat_review` in affected skills, update `_meta` version fields in `data/atlas-ttps.json` and `data/attack-techniques.json`. Never silently upgrade.

**DR-8: Missing zero-day learning loop**
Wrong: adding a new entry to `data/cve-catalog.json` without running the learning loop.
Right: every new CVE triggers a corresponding entry in `zeroday-lessons.json` mapping: attack vector → what control should have caught it → which framework covers that control → whether the control is adequate → what new control requirement the zero-day implies.

---

## Skill File Format

Every `skills/*/skill.md` must have this frontmatter:

```yaml
---
name: skill-name
version: "1.0.0"
description: One-line trigger description (used by AI assistant skill matching)
triggers:
  - phrase patterns that invoke this skill
data_deps:
  - cve-catalog.json
  - atlas-ttps.json
atlas_refs:
  - AML.T0xxx
attack_refs:
  - Txxx
framework_gaps:
  - NIST-800-53-SI-2
  - ISO-27001-A.12.6.1
rfc_refs:
  - RFC-8446                 # or DRAFT-IETF-... for Internet-Drafts
cwe_refs:
  - CWE-787                  # root-cause weakness classes per data/cwe-catalog.json
d3fend_refs:
  - D3-EAL                   # MITRE D3FEND defensive techniques per data/d3fend-catalog.json
dlp_refs:
  - DLP-CHAN-LLM-PROMPT      # DLP control IDs per data/dlp-controls.json (only for DLP-relevant skills)
forward_watch:
  - Upcoming standards changes, new TTPs, RFC publications, CWE Top 25 revisions, or D3FEND ontology additions to monitor for skill update
last_threat_review: "YYYY-MM-DD"
---
```

Required body sections (no skill ships without all of these):
- **Threat Context** — what's actually happening in mid-2026 relevant to this domain
- **Framework Lag Declaration** — per-framework statement of what each control misses
- **TTP Mapping** — ATLAS/ATT&CK IDs with gap flags
- **Exploit Availability Matrix** — PoC? KEV? AI-accelerated? Live-patchable?
- **Analysis Procedure** — step-by-step instructions for performing the analysis. Every Analysis Procedure must explicitly thread **defense in depth** (multi-layer control assumption), **least privilege** (per-principal scope), and **zero trust** (verify-not-assume posture). These three are foundational design principles, not optional considerations.
- **Output Format** — exact structure the skill should produce
- **Compliance Theater Check** — specific test distinguishing paper compliance from real posture

Optional 8th section (required for skills shipped on or after 2026-05-11; pre-existing skills are exempt until their next minor version bump):
- **Defensive Countermeasure Mapping** — maps the skill's offensive findings to MITRE D3FEND IDs from `data/d3fend-catalog.json`, with explicit defense-in-depth layer position, least-privilege scope, zero-trust posture, and AI-pipeline applicability per Hard Rule #9.

---

## Adding a New Skill

1. Create `skills/<skill-name>/skill.md` with complete frontmatter — no empty arrays, no placeholder text.
2. Add all CVE references to `data/cve-catalog.json`.
3. Add all ATLAS/ATT&CK TTPs to `data/atlas-ttps.json`.
4. Add all framework control gaps to `data/framework-control-gaps.json`.
5. Register in `manifest.json` with all fields.
6. Sign the new skill: `node lib/sign.js sign-all` (or `npm run bootstrap` on first run) to add the Ed25519 `signature` and `signed_at` fields to `manifest.json`. Then run `node lib/verify.js` to confirm signatures verify.
7. Verify: compliance theater check present? Concrete output format? Exploit availability assessment?
8. Refresh the project SBOM so the `exceptd:skill:count` and `exceptd:catalog:count` properties in `sbom.cdx.json` track the live surface: `npm run refresh-sbom`. The predeploy SBOM-currency gate fails if `sbom.cdx.json` drifts from `manifest.json` skill count or `data/*.json` catalog count.
9. Update CHANGELOG.md.

## Adding a New CVE

1. Add entry to `data/cve-catalog.json` with all required fields (schema in `lib/scoring.js`).
2. Add corresponding entry to `data/zeroday-lessons.json` (attack vector → control gap → framework gap → new control requirement).
3. Update any skill files that reference the affected technology or attack class.
4. Update `data/exploit-availability.json` with `last_verified` date.
5. Bump `last_threat_review` in affected skill frontmatter.
6. Update CHANGELOG.md with the CVE addition and RWEP score.

## Updating Framework Mappings

When a framework publishes an update:
1. Update `data/framework-control-gaps.json` — mark gaps `"status": "closed"` with the update reference if addressed. Do not delete entries.
2. Update `data/global-frameworks.json`.
3. Audit all skills that reference the changed framework controls.
4. Update CHANGELOG.md.

## Updating External Data Versions

When ATLAS, NIST, or another external source releases a new version:
1. Check for breaking changes: renamed TTPs, removed controls, changed IDs.
2. Update `_meta` version fields in affected data files.
3. Audit all skill frontmatter `atlas_refs` and `attack_refs` against the new version.
4. Bump `last_threat_review` in all affected skills.
5. Update CHANGELOG.md with the version change and any ID migrations.
6. Re-sign any skills whose content changed: `node lib/sign.js sign-all`, then `node lib/verify.js` to confirm.

## Contributing Without Writing Code

Domain experts (DPOs, GRC analysts, pentesters, security researchers) can contribute by opening a GitHub Issue using the **Skill Request** template:
- Describe the threat scenario or compliance gap in plain language
- Include one or more CVEs, attack techniques, or framework control IDs
- Note the jurisdictions or industries most affected

Maintainers convert approved requests into skill files. The contributor is credited in CHANGELOG.md and the skill's frontmatter. You do not need to know how to write a `skill.md` to contribute threat intelligence.

---

## Pre-Ship Checklist

- [ ] All new CVEs have complete `data/cve-catalog.json` entries
- [ ] All new CVEs have `data/zeroday-lessons.json` entries
- [ ] All skill `data_deps` resolve to existing files
- [ ] All ATLAS refs are valid v5.4.0 IDs (current pinned version); Secure AI v2 layer flags + maturity present on AI-pipeline entries
- [ ] All ATT&CK refs are valid v19.0 IDs (current pinned version); post-split tactics (Stealth / Defense Impairment) used where applicable
- [ ] All framework control IDs resolve in `data/framework-control-gaps.json`
- [ ] No skill body contains placeholder language (TODO, TBD, coming soon, placeholder)
- [ ] No skill uses CVSS as sole risk metric
- [ ] No skill implies a framework control is adequate without checking the gap analysis
- [ ] No skill ships without all 7 required body sections
- [ ] `manifest.json` updated with new/changed skills
- [ ] Skill signatures verified: `node lib/verify.js` passes
- [ ] CHANGELOG.md updated with what changed, what CVEs were added, what gaps were closed or opened
- [ ] No partial skills — if it can't be completed now, branch it, don't merge it
- [ ] Global coverage: EU + UK + AU + ISO 27001 present in all framework gap analyses

---

## Quick Skill Reference

| Trigger | Skill |
|---------|-------|
| research this cve, triage threat, where do I start, which skill should I use | researcher |
| kernel lpe, copy fail, dirty frag | kernel-lpe-triage |
| ai attack surface, prompt injection | ai-attack-surface |
| mcp security, tool trust | mcp-agent-trust |
| compliance theater | compliance-theater |
| framework gap | framework-gap-analysis |
| rwep, exploit scoring | exploit-scoring |
| global grc, nis2, dora | global-grc |
| pqc, post-quantum | pqc-first |
| security maturity, mvp security | security-maturity-tiers |
| zero day lesson | zeroday-gap-learn |
| update skills | skill-update-loop |
| threat model currency | threat-model-currency |
| rag security | rag-pipeline-security |
| ai c2, sesameop | ai-c2-detection |
| policy exception | policy-exception-gen |
| attack surface, pen test, red team, tiber-eu | attack-surface-pentest |
| fuzz testing, oss-fuzz, syzkaller, libfuzzer, ai-assisted fuzz | fuzz-testing-strategy |
| dlp, data loss prevention, llm dlp, prompt dlp, rag exfil | dlp-gap-analysis |
| supply chain, slsa, sbom, vex, sigstore, in-toto, cyclonedx, spdx | supply-chain-integrity |
| defensive mapping, d3fend, blue team, defense in depth, least privilege, zero trust | defensive-countermeasure-mapping |
| identity assurance, aal, ial, fal, fido2, webauthn, passkey, oidc, saml | identity-assurance |
| ot security, ics security, scada, plc, iec 62443, nist 800-82, nerc cip | ot-ics-security |
| cvd, vdp, bug bounty, iso 29147, iso 30111, csaf, security.txt | coordinated-vuln-disclosure |
| threat model, stride, pasta, linddun, kill chain, diamond model, unified kill chain | threat-modeling-methodology |
| webapp security, owasp top 10, owasp asvs, xss, csrf, sqli, ssrf, path traversal, file upload, command injection, deserialization, broken access control | webapp-security |
| ai risk management, ai governance, iso 23894, iso 42001, nist ai rmf, ai impact assessment, eu ai act high-risk | ai-risk-management |
| healthcare security, hipaa, hitrust, hl7 fhir, phi, medical device, samd, eu mdr, clinical decision support | sector-healthcare |
| financial security, banking, dora, psd2 sca, swift cscf, nydfs, ffiec, mas trm, apra cps 234, tiber-eu, cbest | sector-financial |
| federal cyber, fedramp, cmmc, eo 14028, nist 800-171, cui, fisma, m-22-09 zero trust, omb m-24-04, cisa bod/ed | sector-federal-government |
| energy security, electric grid, nerc cip, tsa pipeline, awwa, nccs-g, aescsf, der security, inverter, smart meter | sector-energy |
| telecom security, 5g core, salt typhoon, volt typhoon, gnb integrity, lawful intercept, calea, fcc cpni, gsma nesas, ss7, diameter, gtp, 3gpp ts 33.501, o-ran, n6 n9 isolation | sector-telecom |
| api security, owasp api top 10, bola, bfla, mass assignment, api gateway, graphql, grpc, websocket, mcp transport | api-security |
| cloud security, cspm, cwpp, cnapp, csa ccm, aws, azure, gcp, workload identity, cloud iam, multi-cloud | cloud-security |
| container security, kubernetes, cis k8s, pod security standards, kyverno, gatekeeper, falco, tetragon, admission policy | container-runtime-security |
| mlops security, model registry, training data integrity, mlflow, kubeflow, vertex ai, sagemaker, hugging face, model signing, drift detection | mlops-security |
| incident response, ir playbook, csirt, picerl, nist 800-61, iso 27035, breach notification, bec incident, ai incident | incident-response-playbook |
| email security, anti-phishing, dmarc, dkim, spf, bimi, arc, mta-sts, bec, vishing, deepfake phishing | email-security-anti-phishing |
| age gate, age verification, coppa, cipa, california aadc, uk children's code, kosa, gdpr article 8, dsa article 28, parental consent, csam, child safety, children's online safety | age-gates-child-safety |
| forward watch, watchlist, upcoming standards, horizon scan | `node orchestrator/index.js watchlist` (add `--by-skill` to invert) |
