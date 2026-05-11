<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="public/img/logo/exceptd-logo-dark.svg">
  <img src="public/img/logo/exceptd-logo-primary.svg" alt="exceptd" width="220" />
</picture>

# exceptd Security

**AI security skills grounded in mid-2026 threat reality, not framework documentation from 2020.**

[![release](https://img.shields.io/github/v/release/blamejs/exceptd-skills?include_prereleases&sort=semver&label=release)](https://github.com/blamejs/exceptd-skills/releases)
[![CI](https://img.shields.io/github/actions/workflow/status/blamejs/exceptd-skills/ci.yml?branch=main&label=CI)](https://github.com/blamejs/exceptd-skills/actions/workflows/ci.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/blamejs/exceptd-skills/badge)](https://scorecard.dev/viewer/?uri=github.com/blamejs/exceptd-skills)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)
[![Skills](https://img.shields.io/badge/skills-25-d946ef)](#skill-inventory)
[![ATLAS](https://img.shields.io/badge/MITRE%20ATLAS-v5.1.0-d946ef)](https://atlas.mitre.org)
[![ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-v17-d946ef)](https://attack.mitre.org)
[![Ed25519-signed](https://img.shields.io/badge/skills-Ed25519--signed-2ea043)](AGENTS.md)
[![Jurisdictions](https://img.shields.io/badge/jurisdictions-33-blue)](data/global-frameworks.json)

</div>

---

**Core premise:** Every major security and compliance tool on the market is still operating on stale threat models. NIST 800-53, ISO 27001, SOC 2, and PCI-DSS were written for network-centric, on-prem or early-cloud environments. They have no controls for AI pipeline integrity, MCP/agent tool trust boundaries, LLM prompt injection as an access control failure, page-cache exploitation bypassing filesystem integrity checks, or ephemeral infrastructure where traditional asset inventory is architecturally impossible.

This platform surfaces what is actually happening right now. Every skill explicitly flags where a compliance framework's control is insufficient for current attack patterns. The framework is often the problem, not the org.

## Status

Pre-1.0. Latest release lives on [GitHub Releases](https://github.com/blamejs/exceptd-skills/releases). 25 skills across kernel LPE, AI attack surface, MCP trust, RAG security, AI-API C2 detection, PQC migration, framework gap analysis, compliance theater, exploit scoring, threat-model currency, zero-day learning, global GRC, policy exception generation, security maturity tiers, skill update loop, attack-surface pen testing, fuzz testing, DLP gap analysis, supply-chain integrity, defensive-countermeasure mapping, identity assurance, OT/ICS security, coordinated vulnerability disclosure, and threat-modeling methodology — plus a `researcher` triage dispatcher. 10 data catalogs cover CVE / ATLAS / ATT&CK / CWE / D3FEND / DLP / RFC / framework gaps / global frameworks / zero-day lessons. 33 jurisdictions tracked.

---

## Skill Inventory

### Triage & Dispatch

**[researcher](skills/researcher/skill.md)**
Front-door triage skill for raw threat intel. Takes a CVE ID, ATLAS TTP, vendor advisory, framework control ID, or incident narrative; cross-joins it across `data/cve-catalog.json`, `data/atlas-ttps.json`, `data/framework-control-gaps.json`, `data/zeroday-lessons.json`, `data/exploit-availability.json`, and `data/global-frameworks.json`; produces a one-page RWEP-anchored dispatch report; routes the operator to the right specialized skill(s). Start here when the input is "here's a thing, tell me what to do with it".

### Kernel & Privilege Escalation

**[kernel-lpe-triage](skills/kernel-lpe-triage/skill.md)**
Assess Linux kernel local privilege escalation exposure. Covers Copy Fail (CVE-2026-31431, CISA KEV, 732-byte deterministic root, all Linux since 2017), Dirty Frag (CVE-2026-43284/CVE-2026-43500, page-cache chain via ESP/IPsec and RxRPC). Outputs: exposure score, live-patch vs. reboot remediation path, compensating controls, framework gap declaration.

### AI-Specific Attack Surface

**[ai-attack-surface](skills/ai-attack-surface/skill.md)**
Comprehensive AI/ML attack surface assessment mapped to MITRE ATLAS v5.1.0 with explicit gap flags. Covers prompt injection as enterprise RCE (CVE-2025-53773 CVSS 9.6, 85%+ bypass rate against SOTA defenses), MCP supply chain RCE (CVE-2026-30615, zero user interaction, 150M+ downloads), RAG exfiltration, model poisoning, AI-assisted exploit development (41% of 2025 zero-days), credential theft acceleration (160% increase).

**[mcp-agent-trust](skills/mcp-agent-trust/skill.md)**
Enumerate MCP (Model Context Protocol) trust boundary failures. Covers tool allowlisting gaps, unsigned server manifests, prompt injection via tool responses, supply chain compromise. CVE-2026-30615 (Windsurf, zero-interaction RCE). Generates: tool allowlist policy, server signing requirements, bearer auth config, output sanitization requirements.

**[rag-pipeline-security](skills/rag-pipeline-security/skill.md)**
RAG-specific threat model with no current framework coverage. Embedding manipulation for data exfiltration, vector store poisoning, chunking attacks, retrieval filter bypass, indirect prompt injection via retrieved documents. ATLAS-mapped. Generates: retrieval audit controls, anomaly detection requirements, output monitoring policy.

**[ai-c2-detection](skills/ai-c2-detection/skill.md)**
Detect adversary use of AI APIs as covert command-and-control (SesameOp case study, ATLAS AML.T0096). PROMPTFLUX/PROMPTSTEAL malware families that query LLMs during execution for real-time evasion. Outputs: behavioral baseline model, detection signatures, network monitoring rules, incident response playbook.

### Framework & Compliance

**[framework-gap-analysis](skills/framework-gap-analysis/skill.md)**
Feed a compliance framework control ID and a threat scenario — receive: what the control was designed for, why it is insufficient against current TTPs, which attacker technique exploits the gap, what a real control would require. Built-in gap mappings for NIST 800-53, ISO 27001:2022, SOC 2, PCI-DSS 4.0, NIS2, DORA, CIS v8.

**[compliance-theater](skills/compliance-theater/skill.md)**
Identify where an organization passes an audit but remains exposed. Seven documented compliance theater patterns with specific detection tests. Outputs: theater score per control domain, exposure summary, auditor-facing remediation language, evidence gap list.

**[global-grc](skills/global-grc/skill.md)**
Multi-jurisdiction GRC mapping. Covers EU (GDPR Art. 32, NIS2, DORA, EU AI Act, EU CRA), UK (Cyber Essentials Plus, NCSC CAF), Australia (ISM, ASD Essential 8, APRA CPS 234), Singapore (MAS TRM, CSA CCoP), Japan (METI, NISC), India (CERT-In, SEBI), Canada (OSFI B-10), and global (ISO 27001:2022, CSA CCM v4, CIS Controls v8). Identifies universal gaps that no jurisdiction's framework covers.

**[policy-exception-gen](skills/policy-exception-gen/skill.md)**
Generate defensible policy exceptions for architectural realities frameworks don't accommodate. Templates for: ephemeral/serverless infrastructure (no traditional asset inventory), AI pipelines (continuous opaque model updates), zero trust architecture (no network perimeter), live-system no-reboot patching. Each exception includes compensating controls, risk acceptance language, and auditor-ready justification.

### Risk Intelligence

**[exploit-scoring](skills/exploit-scoring/skill.md)**
Real-World Exploit Priority (RWEP) scoring beyond CVSS. Factors: CISA KEV status (0.25), public PoC (0.20), AI-assisted weaponization (0.15), active exploitation (0.20), patch availability (-0.15), live-patch availability (-0.10), blast radius (0.15). Pre-calculated RWEP scores for all CVEs in `data/cve-catalog.json`. Outputs RWEP alongside CVSS with plain-language priority guidance.

**[threat-model-currency](skills/threat-model-currency/skill.md)**
Score how current an organization's threat model is against 2026 threat reality. Checklist of 14 current threat classes against documented model coverage. Outputs: currency percentage, specific missing threat classes, recommended additions with ATLAS/ATT&CK references, prioritized update roadmap.

**[zeroday-gap-learn](skills/zeroday-gap-learn/skill.md)**
Run the zero-day learning loop: zero-day description → attack vector extraction → control gap identification → framework coverage assessment → new control requirement generation → exposure scoring. Encodes lessons from Copy Fail, Dirty Frag, CVE-2025-53773, CVE-2026-30615, SesameOp. Feeds back into framework-gap-analysis and threat-model-currency.

### Identity, OT, Disclosure & Threat Modeling

**[identity-assurance](skills/identity-assurance/skill.md)**
Identity assurance for mid-2026. NIST 800-63 AAL/IAL/FAL levels, FIDO2/WebAuthn passkey deployment, OIDC/SAML/SCIM federation, agent-as-principal identity for autonomous AI workloads, short-lived workload token issuance, OAuth 2.0 + RFC 9700 (OAuth 2.0 Security BCP) hardening. Outputs: assurance-level gap map, passkey rollout plan, agent identity policy, token-lifetime targets.

**[ot-ics-security](skills/ot-ics-security/skill.md)**
OT / ICS security for mid-2026. NIST 800-82r3, IEC 62443-3-3, NERC CIP, IT/OT convergence risks (flat networks, shared AD, jump-host weaknesses), AI-augmented HMI threats, and ATT&CK for ICS mappings. Outputs: zone/conduit gap map, safety-instrumented-system isolation review, OT-specific patching exception templates.

**[coordinated-vuln-disclosure](skills/coordinated-vuln-disclosure/skill.md)**
Coordinated Vulnerability Disclosure for mid-2026. ISO 29147 (disclosure) + ISO 30111 (handling), VDP and bug bounty design, CSAF 2.0 machine-readable advisories, security.txt (RFC 9116), EU CRA / NIS2 regulator-mandated disclosure timelines, AI-specific vulnerability classes (prompt injection, training data poisoning, model exfiltration). Outputs: VDP policy, advisory template, regulator notification calendar.

**[threat-modeling-methodology](skills/threat-modeling-methodology/skill.md)**
Methodology selection and execution across STRIDE, PASTA, LINDDUN (privacy), Cyber Kill Chain, Diamond Model, MITRE Unified Kill Chain, AI-system threat modeling, and agent-based threat modeling. Outputs: methodology choice with justification, scoped DFD or attack tree, threat-to-control crosswalk against ATLAS / ATT&CK / D3FEND.

---

## Using These Skills

These skills work with any AI assistant: Claude Code, GitHub Copilot (via `.github/copilot-instructions.md`), Cursor (via `.cursorrules`), or any assistant that can read Markdown files.

### Quick Start

```bash
git clone https://github.com/blamejs/exceptd-skills
cd exceptd-skills
npm run bootstrap          # downstream consumers: this runs VERIFY ONLY
npm run predeploy          # optional: run the full local CI gate
```

`npm run bootstrap` auto-detects the right mode:

- **Downstream consumer** (default for fresh clones) — `keys/public.pem` ships in the repo and `.keys/private.pem` doesn't exist on your machine. Bootstrap runs verify-only: it never generates a keypair or rewrites signatures. Confirms the working tree is intact and exits.
- **Maintainer re-sign** — `.keys/private.pem` already exists locally. Bootstrap re-signs every skill against the current content and verifies.
- **First-maintainer init** — no `keys/public.pem` shipped, or the maintainer passes `--init` explicitly. Bootstrap generates an Ed25519 keypair, signs every skill, and verifies.

Maintainers can also use `npm run verify` (verify-only) and `node lib/sign.js sign-all` (sign without verify) directly if needed.

### Invoking a Skill

Type a trigger phrase or skill name in your AI assistant:

```
kernel-lpe-triage
ai-attack-surface
framework-gap-analysis NIST-800-53-SI-2 CVE-2026-31431
compliance-theater
global-grc NIS2
exploit-scoring CVE-2026-31431
zeroday-gap-learn CVE-2026-30615
security-maturity-tiers
pqc-first
```

### AI Assistant Configuration

The canonical agent-agnostic project rules live in `AGENTS.md` — the **only** project-rules file in this repo. The project does not ship per-vendor mirrors; each tool is configured to load `AGENTS.md` directly.

| Assistant | How it picks up the rules |
|-----------|---------------------------|
| OpenAI Codex CLI, Sourcegraph amp, Aider, Continue, Cline, Roo Code, Q Developer, and any tool that follows the cross-vendor `AGENTS.md` convention | Auto-loads `AGENTS.md` from the project root. |
| Cursor | Auto-loads `.cursorrules` (a short stub pointing at `AGENTS.md`). |
| GitHub Copilot | Auto-loads `.github/copilot-instructions.md` (stub pointing at `AGENTS.md`). |
| Windsurf | Auto-loads `.windsurfrules` (stub pointing at `AGENTS.md`). |
| Anthropic Claude Code | Doesn't auto-load `AGENTS.md`. Load it manually with `@AGENTS.md` on the first turn, or add your own per-machine `~/.claude/CLAUDE.md` that references it. The project intentionally does not ship a `CLAUDE.md` mirror. |
| Google Gemini CLI, JetBrains AI, Replit Agent, anything else | Point the tool at `AGENTS.md` via its config, or load `CONTEXT.md` manually for a shorter orientation. |

If your tool has a conventional auto-load filename not listed here and you'd like first-class support, open an issue — we'll add a pointer stub.

### Orchestrator

For programmatic use:

```bash
node orchestrator/index.js scan          # Scan environment
node orchestrator/index.js dispatch      # Route findings to skills
node orchestrator/index.js currency      # Check skill currency
node orchestrator/index.js report        # Generate report
```

### Data Files

All skills pull from `data/`. The files are:

- `cve-catalog.json` — CVE metadata with RWEP scores, CISA KEV status, PoC availability, live-patch info
- `atlas-ttps.json` — MITRE ATLAS v5.1.0 TTPs with gap flags and exploitation examples
- `framework-control-gaps.json` — Per-framework, per-control: what it was designed for vs. what it misses
- `exploit-availability.json` — PoC locations, weaponization status, AI-assist factor
- `global-frameworks.json` — All major global compliance frameworks (22+ jurisdictions, expanding to 29+) with control inventories and lag scores
- `zeroday-lessons.json` — Zero-day → control gap → framework gap → new control requirement mappings
- `cwe-catalog.json` — 30 CWE entries pinned to CWE v4.17 (Top 25 2024 + AI- and supply-chain-relevant additions)
- `d3fend-catalog.json` — 21 MITRE D3FEND defensive technique entries pinned to D3FEND v1.0.0
- `rfc-references.json` — 19 IETF RFC / Internet-Draft references with status, errata count, replaces / replaced-by, `last_verified`
- `dlp-controls.json` — 21 DLP control entries indexed by channel / classifier / surface / enforcement / evidence

---

## Philosophy

**Compliance is not security.** A SOC 2 Type II report confirms that controls existed and operated effectively during the audit period. It says nothing about whether those controls are adequate for current attack patterns. When NIST 800-53 SI-2 says "apply security patches in a timely manner" and Copy Fail is a 732-byte deterministic root with a public PoC and no race condition, "timely" is the wrong frame entirely.

**Framework lag is measured in months.** MITRE ATLAS v5.1.0 (November 2025) is the most current AI threat framework available. It still lags real exploitation by 3-6 months. NIST AI RMF lags by years. ISO 27001:2022 has no AI-specific controls. These skills explicitly flag every place where framework coverage ends and real attacker capability begins.

**AI changed the exploit development timeline.** Copy Fail was discovered by an AI system in approximately one hour. 41% of 2025 zero-days involved AI-assisted reverse engineering on the attacker side. The time between vulnerability introduction and reliable exploitation is compressing faster than patch management processes can adapt. Risk scoring must reflect this.

**Every org has a compliance theater problem.** The question is not whether paper controls map to audit requirements. The question is whether those controls would actually detect or prevent an attack. These skills answer the second question.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Key rules:

- No new CVE reference without a complete `data/cve-catalog.json` entry
- No new framework gap claim without a `data/framework-control-gaps.json` entry
- No skill uses CVSS as the sole risk metric
- Every new zero-day triggers a `data/zeroday-lessons.json` entry

---

## License

Apache 2.0. See [LICENSE](LICENSE).

Community at [exceptd.com](https://exceptd.com).
