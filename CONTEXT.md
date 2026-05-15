# exceptd Security — AI Context

This file gives any AI assistant the context it needs to use this repository effectively. It is AI-system-agnostic and does not assume any particular assistant runtime.

---

## What This Repository Is

exceptd Security ships two interlocking surfaces grounded in mid-2026 threat reality:

1. **Skills** — Markdown instruction files telling an AI assistant how to perform a specific security analysis (what questions to ask, what data to query, how to score risk, what output to produce).
2. **Playbooks** — JSON specifications of attack-class investigations executed by the CLI engine through a seven-phase contract (govern → direct → look → detect → analyze → validate → close).

**The core insight:** Every major compliance framework (NIST 800-53, ISO 27001, SOC 2, PCI-DSS) was written for environments that no longer describe how attacks happen. Both skills and playbooks explicitly map where framework coverage ends and real attacker capability begins.

---

## How Skills Work

Each skill is a Markdown file at `skills/<name>/skill.md` with a YAML frontmatter header and a structured body.

### Frontmatter Fields

```yaml
name: skill-name          # Unique identifier
version: "1.0.0"          # Semantic version
description: "..."        # One-line description for skill matching
triggers:                 # Phrases that invoke this skill
  - kernel lpe
  - privilege escalation
data_deps:                # Data files this skill reads
  - cve-catalog.json
atlas_refs:               # MITRE ATLAS TTP IDs referenced
  - AML.T0051
attack_refs:              # MITRE ATT&CK TTP IDs referenced
  - T1068
framework_gaps:           # Framework controls this skill exposes as insufficient
  - NIST-800-53-SI-2
rfc_refs:                 # IETF RFC / Internet-Draft references
  - RFC-8446
cwe_refs:                 # Root-cause weakness classes
  - CWE-787
d3fend_refs:              # MITRE D3FEND defensive techniques
  - D3-EAL
dlp_refs:                 # DLP control IDs (DLP-relevant skills only)
  - DLP-CHAN-LLM-PROMPT
forward_watch:            # Upcoming changes to monitor for skill updates
  - FIPS 206 finalization
last_threat_review: "2026-05-01"
```

### Skill Body Structure

Required sections (every shipped skill):

1. **Threat Context** — current exploitation reality, not theoretical risk
2. **Framework Lag Declaration** — per-framework gap statements with specific control IDs
3. **TTP Mapping** — ATLAS/ATT&CK IDs with framework coverage gap flags
4. **Exploit Availability Matrix** — PoC status, KEV listing, AI-acceleration factor, live-patchability
5. **Analysis Procedure** — step-by-step instructions, threading defense-in-depth, least privilege, and zero trust as foundational design principles (not optional considerations)
6. **Output Format** — exact structure the analysis should produce
7. **Compliance Theater Check** — specific test distinguishing paper compliance from real posture

Required 8th section for skills shipped on or after 2026-05-11 (pre-existing skills exempt until next minor bump):

8. **Defensive Countermeasure Mapping** — maps offensive findings to MITRE D3FEND IDs with explicit defense-in-depth layer position, least-privilege scope, zero-trust posture, and AI-pipeline applicability.

---

## Playbooks and the Seven-Phase Contract

Playbooks live at `data/playbooks/<id>.json` and are executed by the CLI engine. Each playbook is an attack-class investigation that walks a govern → direct → look → detect → analyze → validate → close loop.

Thirteen playbooks ship today:

| Playbook | Attack class |
|---|---|
| `ai-api` | AI API as covert C2 |
| `containers` | Container escape |
| `cred-stores` | Credential-store abuse |
| `crypto` | PQC exposure / HNDL |
| `crypto-codebase` | Crypto misuse in source |
| `framework` | Compliance theater (pure-analyze; correlates other playbooks' findings) |
| `hardening` | Kernel / OS hardening posture |
| `kernel` | Kernel LPE |
| `library-author` | Upstream library supply-chain posture |
| `mcp` | MCP supply chain |
| `runtime` | Runtime tamper |
| `sbom` | SBOM / dependency supply chain |
| `secrets` | DLP exfiltration |

Phase contract:

| Phase | Purpose | CLI surface |
|---|---|---|
| 1 govern | Operator consent + jurisdiction clocks (NIS2 24h, DORA 4h, GDPR 72h, etc.) | `exceptd brief <playbook> --phase govern` |
| 2 direct | Threat-context briefing + skill chain + RWEP threshold | `exceptd brief <playbook> --phase direct` |
| 3 look | Artifacts and indicators to gather; air-gap alternates | `exceptd brief <playbook> --phase look` |
| 4 detect | AI applies indicators to captured evidence; runs every required false-positive check | walked inline by the assistant |
| 5 analyze | Correlate hits → findings | `exceptd run <playbook> --evidence -` |
| 6 validate | Priority-sorted remediation paths + validation tests + residual-risk statement | (part of `run`) |
| 7 close | CSAF-2.0 bundle + jurisdiction notification drafts + auditor-ready exception language + `feeds_into` chaining | (part of `run`) |

Preconditions encode hard refuse-to-run conditions: `threat_currency_score < 50` hard-blocks unless `--force-stale`; `_meta.mutex` refuses concurrent conflicting playbooks; `--air-gap` substitutes `air_gap_alternative` source paths.

Attestations persist at `.exceptd/attestations/<session_id>/attestation.json` and can be replayed against the stored evidence with `exceptd reattest <session-id>` (drift verdict) or inspected with `exceptd attest verify|show|list|diff`.

---

## Data Files

Skills and playbooks read from `data/`. Authoritative catalog inventory:

| File | Entries | Purpose |
|------|---------|---------|
| `cve-catalog.json` | 10 | CVEs with CVSS, RWEP score, EPSS estimates, CISA KEV flags, PoC and live-patch availability |
| `atlas-ttps.json` | 15 | MITRE ATLAS v5.1.0 (November 2025) techniques with framework gap flags |
| `attack-techniques.json` | 79 | MITRE ATT&CK techniques with framework coverage mappings |
| `framework-control-gaps.json` | 62 | Framework control gap entries: designed-for vs. what each control misses |
| `exploit-availability.json` | 10 | Per-CVE PoC locations, weaponization stage, AI-acceleration factor, live-patch status |
| `global-frameworks.json` | 35 jurisdictions | Patch SLAs and notification windows across global regulatory regimes |
| `zeroday-lessons.json` | 10 | Learning-loop entries: zero-day → attack vector → control gap → framework gap → new control |
| `cwe-catalog.json` | 55 | CWE v4.17 entries (Top 25 2024 plus AI- and supply-chain-relevant weaknesses) |
| `d3fend-catalog.json` | 28 | MITRE D3FEND v1.0.0 defensive techniques for offensive → defensive mapping |
| `rfc-references.json` | 31 | IETF RFC / Internet-Draft references with status, errata count, replaces / replaced-by, `last_verified` dates |
| `dlp-controls.json` | 22 | DLP control entries indexed by channel, classifier, surface, enforcement mode, evidence type |
| `playbooks/` | 13 | Playbook specifications (see above) |
| `_indexes/` | 17 derived files | Pre-computed indexes built by `npm run build-indexes` |

---

## Invoking Skills

To use a skill, match its trigger phrases and follow its Analysis Procedure. Example invocations:

```
kernel-lpe-triage           — Linux kernel LPE exposure
ai-attack-surface           — AI/ML attack surface assessment
framework-gap-analysis      — control ID + threat → gap statement
compliance-theater          — detect audit-passing ≠ real-secure
global-grc NIS2             — map a threat to NIS2 + companion jurisdictions
exploit-scoring CVE-2026-31431  — RWEP score with full factor breakdown
security-maturity-tiers     — MVP / Practical / Overkill roadmap
zeroday-gap-learn CVE-...   — zero-day learning loop on a new CVE
pqc-first                   — post-quantum cryptography readiness
researcher                  — front-door dispatcher for raw threat intel
```

---

## Risk Scoring: RWEP

The repository uses Real-World Exploit Priority (RWEP) scoring, not CVSS alone. CVSS is reported alongside RWEP but never as the sole score.

RWEP formula (0–100):
```
base = cisa_kev(+25) + poc_public(+20) + ai_factor(+15)
     + active_exploitation(+20) + blast_radius(0-30)
     - patch_available(-15) - live_patch(-10) + reboot_required(+5)

ai_factor = ai_discovered OR ai_assisted_weaponization
blast_radius = 0-30 scale (30 = all-Linux or 150M+ installations)
reboot_required = +5 always when patch requires reboot
```

Example: CVE-2026-31431 (Copy Fail) — CVSS 7.8 / **RWEP 90**
- CVSS 7.8 suggests "high, patch within 30 days"
- RWEP 90 means: deterministic root in < 1 second, CISA KEV, 732-byte public PoC, AI-discovered, blast radius = all Linux >= 4.14 — 30 days is exploitation acceptance

The RWEP scoring engine is at `lib/scoring.js`.

---

## Compliance Theater

This repository uses the term "compliance theater" for a specific, measurable condition: an organization that passes an audit of a security control while remaining exposed to the threat that control is supposed to address.

Seven documented patterns:
1. **Patch Management Theater** — meets framework SLA, still exposed to active exploitation
2. **AI Access Control Theater** — service account compliant; prompt injection bypasses it entirely
3. **Vendor Management Theater** — vendor controls pass audit; MCP plugins are out of scope
4. **Malware Protection Theater** — signatures current; AI-generated novel code evades all signatures
5. **Supply Chain Theater** — software supply chain passes review; developer-installed AI plugins excluded
6. **Encryption Theater** — classical encryption compliant; HNDL exposure unaddressed
7. **Detection Theater** — monitoring compliant; AI C2 channels and AI-querying malware not detected

Run `lib/framework-gap.js` → `theaterCheck()` for programmatic detection. The `framework` playbook surfaces these patterns across an entire estate by correlating findings from other playbooks.

---

## Agents vs. Skills vs. Playbooks

Three distinct artifact types:

- **`skills/<name>/skill.md`** — user-invoked, matched by trigger phrases, interactive front door.
- **`data/playbooks/<id>.json`** — engine-executed attack-class investigations, structured seven-phase output.
- **`agents/<name>/`** — pipeline workers (`threat-researcher`, `source-validator`, `skill-updater`, `report-generator`) that run autonomously inside the orchestrator. Not user-invokable.

The `researcher` **skill** (front-door dispatcher) and `threat-researcher` **agent** (background pipeline worker) share a thematic name but are different artifacts with different runtimes. When in doubt, the path tells you which: `skills/researcher/` vs `agents/threat-researcher/`.

---

## AI System Integration Notes

### How to Load Skills

1. Read `manifest.json` for the full skill registry
2. Match user intent against `triggers` arrays
3. Load the matched `skill.md` into context
4. Follow the skill's **Analysis Procedure** step by step
5. Pull data from referenced `data_deps` files as needed
6. Produce output matching the skill's **Output Format**

### How to Walk a Playbook

1. `exceptd brief` (no args) lists available playbooks; `exceptd brief <id>` returns the full Phase 1+2+3 briefing in one document
2. Surface the Phase-1 jurisdiction obligations to the operator and wait for ack (use `exceptd brief <id> --phase govern` for just that slice)
3. `exceptd brief <id> --phase direct` and `--phase look` pull the threat context and indicator set
4. Walk Phase 4 (detect) inline using local tools; run every required false-positive check
5. Pipe evidence to `exceptd run <id> --evidence -` for Phases 5–7 (use `exceptd ci` for the gate-only variant in CI pipelines)
6. Offer to persist the attestation and draft any notification messages

### Context Budget Guidance

- `manifest.json` — load first (small, high-value index)
- `data/cve-catalog.json` — load on demand for CVE-specific analysis
- `data/framework-control-gaps.json` — load for gap analysis and theater detection
- `data/global-frameworks.json` — load for multi-jurisdiction questions
- `data/atlas-ttps.json`, `data/attack-techniques.json` — load for TTP-driven work
- Individual skill files — 15–40 KB each; load on match, not preemptively
- Playbook JSON — load on demand via `exceptd direct/look`; the engine handles phase orchestration

### What This Repo Does Not Contain

- No code that executes automatically in your environment
- No outbound network calls; all data is local and static (the watchlist surface is read-only)
- No credentials or keys
- Skills are instruction text — the AI implements them; playbook execution is governed by the CLI engine

---

## Key Concepts Quick Reference

| Term | Definition |
|------|------------|
| RWEP | Real-World Exploit Priority — risk score beyond CVSS |
| KEV | CISA Known Exploited Vulnerabilities catalog |
| ATLAS | MITRE ATLAS v5.1.0 — AI threat framework |
| MCP | Model Context Protocol — AI tool integration standard |
| HNDL | Harvest-Now-Decrypt-Later — quantum threat to current crypto |
| Framework lag | Gap between what a framework requires and what current TTPs demand |
| Theater | Audit-passing compliance that doesn't close the real attack path |
| RWEP 90+ | Priority 1: live-patch or isolate same-day |
| Seven-phase | govern → direct → look → detect → analyze → validate → close |
| CSAF-2.0 | Common Security Advisory Framework — Phase-7 output bundle format |
| Copy Fail | CVE-2026-31431 — RWEP 90, CISA KEV, 732-byte deterministic root |
| Dirty Frag | CVE-2026-43284/43500 — IPsec subsystem LPE chain |
| SesameOp | AI API as covert C2 channel (ATLAS AML.T0096) |
| PROMPTFLUX | Malware querying LLMs for real-time AV evasion code |
| PROMPTSTEAL | Malware querying LLMs for target intelligence |
