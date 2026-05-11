# exceptd Security — AI Context

This file gives any AI assistant the context it needs to use this skill repository effectively. It is AI-system-agnostic and does not assume any particular assistant runtime.

---

## What This Repository Is

exceptd Security is a library of AI security skills grounded in mid-2026 threat reality. Each skill is a structured instruction file that tells an AI assistant how to perform a specific security analysis — what questions to ask, what data to query, how to score risk, and what output to produce.

**The core insight:** Every major compliance framework (NIST 800-53, ISO 27001, SOC 2, PCI-DSS) was written for environments that no longer describe how attacks happen. These skills explicitly map where framework coverage ends and real attacker capability begins.

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
forward_watch:            # Upcoming changes to watch for skill updates
  - FIPS 206 finalization
last_threat_review:       # Date of last threat currency review
  "2026-05-01"
```

### Skill Body Structure

Every skill has these sections:

1. **Threat Context** — Current exploitation reality, not theoretical risk
2. **Framework Lag Declaration** — Per-framework gap statements with specific control IDs
3. **TTP Mapping** — ATLAS/ATT&CK IDs with framework coverage gap flags
4. **Exploit Availability Matrix** — PoC status, KEV listing, AI-acceleration factor
5. **Analysis Procedure** — Step-by-step instructions for performing the analysis
6. **Output Format** — Exact structure the analysis should produce
7. **Compliance Theater Check** — Specific test distinguishing paper compliance from real posture

---

## Data Files

Skills read from `data/`. These are the authoritative data sources:

| File | Purpose |
|------|---------|
| `cve-catalog.json` | 5 CVEs with CVSS, RWEP score, EPSS estimates, CISA KEV flags, PoC and live-patch availability |
| `atlas-ttps.json` | MITRE ATLAS v5.1.0 (November 2025) techniques and mappings with framework gap flags |
| `framework-control-gaps.json` | 49 framework control gap entries: designed-for vs. what each control misses |
| `exploit-availability.json` | Per-CVE PoC locations, weaponization stage, AI-acceleration factor, live-patch status |
| `global-frameworks.json` | 22+ jurisdictions (expanding to 29+) — framework registry with patch SLAs and notification windows |
| `zeroday-lessons.json` | Learning-loop entries: zero-day → attack vector → control gap → framework gap → new control requirement |
| `cwe-catalog.json` | 30 CWE entries pinned to CWE v4.17 (Top 25 2024 plus AI- and supply-chain-relevant weaknesses) for root-cause classification |
| `d3fend-catalog.json` | 21 MITRE D3FEND defensive techniques pinned to D3FEND v1.0.0; used to map offensive findings to specific defensive countermeasures |
| `rfc-references.json` | 19 IETF RFC / Internet-Draft references with status, errata count, replaces / replaced-by, and `last_verified` dates |
| `dlp-controls.json` | 21 DLP control entries indexed by channel, classifier, surface, enforcement mode, and evidence type for DLP-relevant skills |

---

## Invoking Skills

To use a skill, match its trigger phrases and follow its Analysis Procedure. Example invocations:

```
kernel-lpe-triage           — Assess Linux kernel LPE exposure
ai-attack-surface           — AI/ML attack surface assessment
framework-gap-analysis      — Feed a control ID + threat → get the gap
compliance-theater          — Detect where audit compliance ≠ real security
global-grc NIS2             — Map a threat to NIS2 + companion jurisdictions
exploit-scoring CVE-2026-31431  — RWEP score with full factor breakdown
security-maturity-tiers     — MVP / Practical / Overkill roadmap for any domain
zeroday-gap-learn CVE-...   — Run the zero-day learning loop on a new CVE
pqc-first                   — Post-quantum cryptography readiness assessment
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
2. **AI Access Control Theater** — service account is compliant; prompt injection bypasses it entirely
3. **Vendor Management Theater** — vendor controls pass audit; AI tool plugins (MCP servers) are out of scope
4. **Malware Protection Theater** — signatures are current; AI-generated novel code evades all signatures
5. **Supply Chain Theater** — software supply chain passes review; developer-installed AI plugins are excluded
6. **Encryption Theater** — classical encryption is compliant; HNDL exposure is unaddressed
7. **Detection Theater** — monitoring is compliant; AI C2 channels and AI-querying malware are not detected

Run `lib/framework-gap.js` → `theaterCheck()` to detect these patterns programmatically.

---

## Orchestration Layer

The `orchestrator/` directory provides:
- **Scanner** — discovers kernel versions, MCP configs, crypto posture, framework claims
- **Dispatcher** — routes scanner findings to relevant skills via manifest triggers
- **Pipeline** — coordinates `threat-researcher` → `source-validator` → `skill-updater` → `report-generator`
- **Event bus** — triggers skill updates on CISA KEV additions, ATLAS releases, framework amendments
- **Scheduler** — runs weekly currency checks and annual full audits

Entry point: `node orchestrator/index.js`

### Agents vs. Skills

The four orchestration components above (`threat-researcher`, `source-validator`, `skill-updater`, `report-generator`) are **agent definitions** living under `agents/`. They are pipeline workers that run inside the orchestrator — not user-invokable skills.

Skills live under `skills/<name>/skill.md` and are matched by trigger phrases. The `researcher` **skill** (separate from the `threat-researcher` **agent**) is the user-facing entry-point dispatcher: when an operator drops in raw threat intel without knowing which specialized skill to call, the `researcher` skill cross-joins the data catalogs, produces an RWEP-anchored dispatch report, and routes to the right specialized skill(s).

Naming convention to keep straight:
- `agents/threat-researcher/` — orchestrator pipeline worker (autonomous, background)
- `skills/researcher/skill.md` — user-invoked triage dispatcher (interactive, front door)

They share a thematic name but are different artifacts with different runtimes.

---

## AI System Integration Notes

### How to Load Skills

1. Read `manifest.json` to get the full skill registry
2. Match user intent against `triggers` arrays
3. Load the matched `skill.md` into context
4. Follow the skill's **Analysis Procedure** step by step
5. Pull data from the referenced `data_deps` files as needed
6. Produce output matching the skill's **Output Format**

### Context Budget Guidance

- `manifest.json` — load first, always (small, high-value index)
- `data/cve-catalog.json` — load on demand for any CVE-specific analysis
- `data/framework-control-gaps.json` — load for gap analysis and theater detection
- `data/global-frameworks.json` — load for multi-jurisdiction questions
- `data/atlas-ttps.json` — load for AI attack surface and C2 detection work
- Individual skill files — 15–40KB each; load on match, not preemptively

### What This Repo Does Not Contain

- No code that executes automatically in your environment
- No network calls — all data is local and static
- No credentials or keys
- Skills are instruction text — the AI implements them, not the files themselves

---

## Key Concepts Quick Reference

| Term | Definition |
|------|------------|
| RWEP | Real-World Exploit Priority — risk score beyond CVSS |
| KEV | CISA Known Exploited Vulnerabilities catalog |
| ATLAS | MITRE ATLAS v5.1.0 — AI threat framework |
| MCP | Model Context Protocol — AI tool integration standard |
| HNDL | Harvest-Now-Decrypt-Later — quantum threat to current crypto |
| Framework lag | The gap between what a framework requires and what current TTPs demand |
| Theater | Audit-passing compliance that doesn't close the real attack path |
| RWEP 90+ | Priority 1: live-patch or isolate same-day |
| Copy Fail | CVE-2026-31431 — RWEP 90, CISA KEV, 732-byte deterministic root |
| Dirty Frag | CVE-2026-43284/43500 — IPsec subsystem LPE chain |
| SesameOp | AI API as covert C2 channel (ATLAS AML.T0096) |
| PROMPTFLUX | Malware querying LLMs for real-time AV evasion code |
| PROMPTSTEAL | Malware querying LLMs for target intelligence |
