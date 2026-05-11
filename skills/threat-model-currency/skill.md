---
name: threat-model-currency
version: "1.0.0"
description: Score how current an org's threat model is against 2026 reality — 14-item checklist, currency percentage, prioritized update roadmap
triggers:
  - threat model currency
  - update threat model
  - threat model review
  - is our threat model current
  - threat model gap
  - threat intelligence gap
data_deps:
  - atlas-ttps.json
  - cve-catalog.json
  - framework-control-gaps.json
atlas_refs: []
attack_refs: []
framework_gaps: []
forward_watch:
  - New AI attack classes as ATLAS v6 publishes
  - Post-quantum adversary capability timeline
  - New CISA KEV entries in kernel/AI/supply chain categories
  - New MCP or agent protocol security disclosures
  - Emerging malware families using AI for evasion
last_threat_review: "2026-05-01"
---

# Threat Model Currency Assessment

## Purpose

Most organizational threat models were last substantially revised 2–4 years ago. They describe the threat landscape of 2021–2022: ransomware, supply chain (SolarWinds-era), cloud misconfiguration, credential phishing using template emails. This is not the 2026 threat landscape.

This skill produces a currency score and a specific update roadmap. Currency is measured against 14 threat classes that define the mid-2026 threat reality. Each unchecked item is a specific gap, not a generic "keep monitoring" recommendation.

---

## The 14 Threat Class Checklist

### Class 1: AI-Discovered Kernel Vulnerabilities

**2026 reality:** AI systems discovered Copy Fail (CVE-2026-31431) in approximately one hour. The vulnerability class — page-cache write primitives enabling deterministic LPE — had existed in every major Linux distribution since 2017. Human researchers did not find it in 9 years.

**Currency check questions:**
- Does the threat model include AI-accelerated vulnerability discovery as a threat actor capability?
- Does the threat model acknowledge that AI-discovered vulnerabilities may be weaponized faster than human-speed patch cycles?
- Does the patch management policy differentiate CISA KEV + public PoC from non-exploited High CVEs?

**If unchecked:** The threat model assumes human-speed exploit development. This assumption fails for Copy Fail class vulnerabilities.

**ATLAS/ATT&CK ref:** T1068 (Exploitation for Privilege Escalation)

---

### Class 2: Deterministic Kernel LPE (No Race Condition)

**2026 reality:** Copy Fail is deterministic. Previous privilege escalation class vulnerabilities (Dirty COW, etc.) had race conditions that introduced unreliability and noise. Copy Fail has none. A 732-byte script reliably escalates to root on every attempt.

**Currency check questions:**
- Does the threat model distinguish deterministic LPEs from probabilistic ones?
- Does the incident response plan treat a confirmed exploitation of a deterministic LPE as an immediate full-system compromise, not a "potential" compromise?

**If unchecked:** IR playbooks may underestimate the reliability and speed of privilege escalation on unpatched systems.

---

### Class 3: IPsec Subsystem Exploitation (Network Control Bypass)

**2026 reality:** Dirty Frag (CVE-2026-43284/43500) exploits the IPsec implementation itself. Network segmentation controls that rely on IPsec cannot be claimed as compensating controls for unpatched systems.

**Currency check questions:**
- Does the threat model include exploitation of cryptographic subsystems as a bypass for network isolation controls?
- Are IPsec-dependent network controls flagged for review when kernel CVEs affecting IPsec are published?

**If unchecked:** Network segmentation controls may be claimed as compensating controls when they are actually part of the attack surface.

---

### Class 4: Prompt Injection as Enterprise RCE

**2026 reality:** CVE-2025-53773 demonstrated prompt injection in a production developer tool (GitHub Copilot) achieving CVSS 9.6 RCE. This is not a research demo. It is a real CVE in a tool used by hundreds of millions of developers. Attack success rates against SOTA defenses exceed 85%.

**Currency check questions:**
- Does the threat model include prompt injection as an RCE vector (not just a chatbot annoyance)?
- Is prompt injection included in application threat models for any system with an LLM component?
- Are AI coding assistants in scope for the threat model?

**If unchecked:** Prompt injection is classified as a "trust and safety" issue, not a security control failure. The CVSS 9.6 data says otherwise.

---

### Class 5: MCP Supply Chain RCE

**2026 reality:** CVE-2026-30615 (Windsurf) demonstrated zero-user-interaction RCE via the MCP tool ecosystem. 150M+ affected. Every major AI coding assistant has the same architectural attack surface.

**Currency check questions:**
- Does the threat model include AI tool supply chain as an attack surface?
- Are MCP servers treated as third-party code with supply chain risk?
- Is developer workstation compromise via AI tool plugins in scope?

**If unchecked:** Supply chain threat model covers npm packages, Docker images, and cloud providers — but not AI tool plugins, which now have an equal or greater attack surface.

---

### Class 6: AI-Assisted Exploit Development (Attacker-Side)

**2026 reality:** 41% of 2025 zero-days involved AI-assisted reverse engineering on the attacker side. AI has compressed the weaponization timeline from weeks to hours for a significant class of vulnerabilities.

**Currency check questions:**
- Does the threat model account for AI-compressed exploit development timelines?
- Do patch SLAs reflect that "critical patch in 30 days" is now an exploitation window, not a safety window?
- Is AI-assisted vulnerability research by threat actors included in the threat actor capability section?

**If unchecked:** Risk assessments assume historical exploit development timelines. These timelines are broken.

---

### Class 7: AI as Covert C2 (SesameOp Pattern)

**2026 reality:** Adversaries are using legitimate AI API endpoints as covert C2 channels (ATLAS AML.T0096). Traffic is indistinguishable from legitimate AI usage. Traditional C2 detection (DGA, beaconing, protocol anomalies) has zero coverage.

**Currency check questions:**
- Does the threat model include AI APIs as potential C2 channels?
- Is AI API behavioral monitoring included in the detection architecture?
- Is there a detection control that would fire for a SesameOp-style C2 pattern?

**If unchecked:** The C2 detection architecture has a complete blind spot for a confirmed, documented threat technique.

---

### Class 8: AI-Generated Malware Evasion (PROMPTFLUX Pattern)

**2026 reality:** PROMPTFLUX queries public LLMs in real-time to generate novel evasion code. Every execution produces a unique sample. Signature-based detection has zero coverage.

**Currency check questions:**
- Does the threat model include AI-generated dynamic malware evasion?
- Does the detection architecture go beyond signature matching for malware detection?
- Is behavioral detection the primary malware detection mechanism?

**If unchecked:** Malware detection architecture is primarily signature-based. For PROMPTFLUX class, signature-based detection is bypassed by design.

---

### Class 9: RAG Data Exfiltration

**2026 reality:** Attackers can manipulate vector embeddings to force RAG retrieval mechanisms to surface and exfiltrate proprietary data. No framework covers this. Organizations deploying RAG for sensitive data have zero control guidance.

**Currency check questions:**
- Does the threat model include RAG pipeline attacks if the organization uses RAG?
- Are vector stores classified as sensitive data assets requiring access controls?
- Is retrieval behavior monitored for anomalous patterns?

**If unchecked:** RAG systems are deployed with the same security model as traditional databases (perimeter + access control), which doesn't account for semantic retrieval attacks.

---

### Class 10: Model Poisoning of Decision Systems

**2026 reality:** Training pipeline targeting has moved to biasing ML models used in decision systems (logistics, classification, fraud detection). The attack is subtle — the model performs normally on most inputs but produces adversary-favorable decisions on specific inputs.

**Currency check questions:**
- Does the threat model include model poisoning for any ML system used in consequential decisions?
- Is model integrity verification (behavioral testing, output monitoring) in place?
- Is the ML training pipeline in scope for supply chain security?

**If unchecked:** ML decision systems are treated as software (covered by standard SDLC security) without accounting for ML-specific attacks on model behavior.

---

### Class 11: AI-Speed Reconnaissance

**2026 reality:** AI-assisted reconnaissance is observed at 36,000 probes per second per campaign. Rate-based detection thresholds set for human-speed reconnaissance (hundreds to low thousands of probes per second) don't fire until significant intelligence has already been gathered.

**Currency check questions:**
- Do network monitoring thresholds account for AI-speed reconnaissance rates?
- Is asset exposure to the internet minimized given the AI-speed enumeration baseline?
- Are external attack surface management tools in place?

**If unchecked:** Reconnaissance detection thresholds allow complete infrastructure mapping before an alert fires.

---

### Class 12: AI-Generated Credential Phishing

**2026 reality:** 82.6% of phishing emails contain AI-generated content. AI-generated phishing is indistinguishable from legitimate emails by grammar/style analysis. Credential theft via AI-assisted phishing increased 160% in 2025.

**Currency check questions:**
- Does the threat model reflect AI-generated phishing as the baseline phishing capability (not an advanced technique)?
- Are phishing detection controls updated for AI-generated content?
- Is MFA phishing-resistant (passkeys/hardware keys)? SMS/TOTP remains vulnerable to real-time AI-assisted phishing.

**If unchecked:** Phishing threat model is built on detection of human-generated templates. 82.6% of actual phishing bypasses these detectors.

---

### Class 13: MITRE ATLAS v5.1.0 Coverage

**2026 reality:** MITRE ATLAS (November 2025, v5.1.0) is the primary AI threat framework. Most SOC detection engineering programs are built on ATT&CK, not ATLAS. AI-specific TTPs have zero detection coverage in ATT&CK-only programs.

**Currency check questions:**
- Is MITRE ATLAS v5.1.0 incorporated into the threat model?
- Are ATLAS TTPs mapped to detection controls?
- What is the current ATLAS version in use? (Current: 5.1.0, November 2025)

**If unchecked:** AI-specific threat techniques are not covered by the detection architecture. The SOC has no alerts for ATLAS TTPs.

---

### Class 14: Post-Quantum Adversary Timeline

**2026 reality:** NIST has standardized ML-KEM (FIPS 203), ML-DSA (FIPS 204), and SLH-DSA (FIPS 205). CISA and NSA have recommended PQC migration timelines. Harvest-now-decrypt-later attacks against encrypted traffic are ongoing. The "decrypt later" timeline is shortening.

**Currency check questions:**
- Does the threat model include quantum adversary capability timelines?
- Is there a PQC migration roadmap?
- Are long-lived sensitive communications (data with > 10-year sensitivity requirement) protected with post-quantum cryptography?

**If unchecked:** Adversaries conducting harvest-now-decrypt-later operations against sensitive traffic are not in the threat model.

---

## Threat Context

Most organizational threat models in circulation today are 2022–2024 vintage. They were written before the operational reality of mid-2026:

- **AI-discovered LPEs.** Copy Fail (CVE-2026-31431) was found by an AI system in roughly one hour in a code path that had been in every major Linux distribution for nine years. A threat model that does not name "AI-assisted vulnerability discovery" as an attacker capability cannot reason about Copy Fail-class exposure.
- **Zero-interaction MCP RCE.** CVE-2026-30615 (Windsurf) demonstrated that a malicious MCP server can drive an AI coding assistant to execute code in the developer's user context without any human action. 150M+ combined downloads of MCP-capable assistants share the same architectural surface. A threat model that lists "third-party software" but not "AI tool plugins" is no longer comprehensive.
- **AI-API C2 (SesameOp).** Adversaries are using legitimate AI API endpoints (ATLAS AML.T0096) as covert command-and-control channels. Traffic is indistinguishable from legitimate usage at the network layer. A threat model whose C2 chapter still lists only DGAs, beaconing, and protocol anomalies has a documented blind spot.
- **AI-accelerated weaponization.** 41% of 2025 zero-days involved AI-assisted reverse engineering on the attacker side. The window between disclosure and reliable exploitation has compressed from weeks to hours for a meaningful class of CVEs.
- **AI-generated phishing as baseline.** 82.6% of phishing in 2025 contained AI-generated content. Threat models that treat AI-generated phishing as an "emerging" or "advanced" capability are scoring below the actual median attacker.

Currency is the gap. The threat-model document is rarely "wrong" — it is usually correct *for 2022*. This skill measures the delta.

---

## Framework Lag Declaration

No major risk-assessment or threat-intelligence framework defines a currency metric or mandates a refresh cadence indexed to current TTPs. The gap is global, not US-specific.

| Framework | Control | What it misses |
|---|---|---|
| NIST | SP 800-30 Rev. 1 (Guide for Conducting Risk Assessments) | Process-only. Requires identifying threats, vulnerabilities, likelihood, impact — defines no metric for the *currency* of the threat catalog used. A 2022 threat model can be SP 800-30-compliant in 2026. |
| NIST | SP 800-39 / SP 800-37 (Risk Management Framework) | Mandates ongoing risk assessment but not threat-model refresh cycles tied to KEV/ATLAS updates. |
| NIST | AI RMF MAP-2.1 | Requires categorising AI-system risks; does not require the categorisation be re-run when new ATLAS TTPs publish. |
| ISO | 27005:2022 (Information security risk management) | Same shape as SP 800-30 — process guidance with no currency requirement. |
| ISO | 27001:2022 A.5.7 (Threat intelligence) | Requires collection and analysis of threat intelligence. Defines no recency requirement, no metric for "current", no test that distinguishes current threat intel from a 2022 PDF on a shelf. |
| EU | NIS2 Art. 21(2)(a) (Risk analysis and information system security policies) | Mandates risk analysis as a measure; is silent on threat-model age or refresh trigger. National competent authorities have not (mid-2026) issued binding guidance on threat-model currency. |
| EU | DORA Art. 6 (ICT risk management framework) | Requires identification of ICT risks "on an ongoing basis"; "ongoing" is undefined and unmetered. |
| EU | EU AI Act Art. 9 (Risk Management System for high-risk AI) | Mandates "continuous iterative" risk management; provides no currency test, no mapping to ATLAS, no required refresh trigger. |
| UK | NCSC CAF Principle A2 (Risk Management) | Principle-based, leaves currency to the assessor. No threat-class checklist, no minimum refresh cadence. |
| AU | ISM-0042 / Essential 8 governance | Requires documented risk assessment; no currency metric. ISM updates monthly but does not require organisations' threat models to track its cadence. |
| Global | COSO ERM / ISO 31000 | Enterprise risk frameworks treat cyber as one risk category; no operational threat-currency requirement. |

The recurring failure across all of the above: every framework treats threat modelling as a process to perform, not a knowledge artefact to keep fresh against external TTP catalogs. The 14-class checklist in this skill is the missing currency metric.

---

## TTP Mapping

The 14-class checklist above *is* the TTP map. Each class is a coverage requirement against the canonical sources of truth: `data/atlas-ttps.json` (MITRE ATLAS v5.1.0) and the ATT&CK techniques referenced in `data/cve-catalog.json`. A current threat model must address — explicitly or by reasoned exclusion — every TTP below.

| Class | Primary TTP | Catalog source | Gap if absent |
|---|---|---|---|
| 1 — AI-discovered kernel LPE | T1068 (Exploitation for Privilege Escalation) | cve-catalog.json: CVE-2026-31431 | Threat model assumes human-speed exploit discovery |
| 2 — Deterministic LPE | T1068 | cve-catalog.json: CVE-2026-31431 | IR plan treats LPE as probabilistic |
| 3 — IPsec subsystem LPE | T1068 | cve-catalog.json: CVE-2026-43284 / CVE-2026-43500 | Network-segmentation claimed as compensating control for the attack surface itself |
| 4 — Prompt injection RCE | AML.T0051 (LLM Prompt Injection), AML.T0054 (Craft Adversarial Data — NLP) | atlas-ttps.json + CVE-2025-53773 | Prompt injection treated as T&S, not security |
| 5 — MCP supply chain RCE | AML.T0010 (ML Supply Chain Compromise), T1190 (Exploit Public-Facing Application) | atlas-ttps.json + CVE-2026-30615 | AI plugin ecosystem out of supply-chain scope |
| 6 — AI-assisted weaponization | AML.T0017 (Develop Capabilities) | atlas-ttps.json | Patch SLAs sized for 2019 attacker speed |
| 7 — AI as covert C2 | AML.T0096 (LLM Integration Abuse — C2) | atlas-ttps.json | C2 detection architecture has total blind spot |
| 8 — AI-generated malware evasion | AML.T0016 (Acquire Public ML Artifacts) | atlas-ttps.json | Detection stack signature-bound; PROMPTFLUX bypasses by design |
| 9 — RAG exfiltration | AML.T0043 (Craft Adversarial Data) | atlas-ttps.json | Vector store treated as database, not as semantic exfil surface |
| 10 — Model poisoning | AML.T0020 (Poison Training Data) | atlas-ttps.json | ML decision systems treated as standard software |
| 11 — AI-speed reconnaissance | T1595 (Active Scanning), T1190 | ATT&CK | Rate-based detection thresholds calibrated for human-speed scans |
| 12 — AI-generated phishing | AML.T0016 (Acquire Public ML Artifacts — misuse), T1566 (Phishing) | atlas-ttps.json + ATT&CK | Detection rules tuned for 2021 phishing |
| 13 — ATLAS coverage | All AML.T* in atlas-ttps.json | atlas-ttps.json `_meta.atlas_version` | SOC detection programs are ATT&CK-only |
| 14 — Post-quantum adversary | T1557 (harvest-now-decrypt-later context) | global-frameworks.json (PQC standards) | Long-lived sensitive traffic captured today, decrypted later |

The truth set: every `AML.T*` key in `data/atlas-ttps.json` (excluding `_meta`) and every `attack_refs` entry across every CVE in `data/cve-catalog.json`. A threat model that does not address each, or document a reasoned exclusion for each, is non-current by construction.

---

## Exploit Availability Matrix

A threat model is "current" only if it accounts for every `data/cve-catalog.json` entry with RWEP >= 50 — with either a deployed mitigation or a documented, accepted residual risk. As of `last_threat_review: 2026-05-01`:

| CVE | Name | CVSS | RWEP | KEV | PoC | AI factor | Live-patchable | Required threat-model treatment |
|---|---|---|---|---|---|---|---|---|
| CVE-2026-31431 | Copy Fail | 7.8 | 90 | Yes (2026-03-15) | Yes — 732-byte deterministic | AI-discovered | Yes (kpatch / canonical-livepatch / kGraft) | Must name as named threat. Patch SLA must reflect KEV + deterministic class — live-patch within hours, not 30 days. |
| CVE-2025-53773 | Copilot prompt-injection RCE | 9.6 | 42 | No | Yes — demonstrated | AI-weaponized | Yes (SaaS vendor patch) | Must include prompt injection as RCE vector if any developer uses Copilot. |
| CVE-2026-30615 | Windsurf MCP zero-interaction RCE | 9.8 | 35 | No | Partial | No | Yes (IDE update) | Must include MCP supply chain if any developer uses any MCP-capable assistant. |
| CVE-2026-43284 | Dirty Frag (ESP/IPsec) | 7.8 | 38 | No | Yes — chain component | No | No | Required if IPsec-based controls are claimed as compensating. |
| CVE-2026-43500 | Dirty Frag (RxRPC) | 7.6 | 32 | No | Yes — chain component | No | No | Required when chained with CVE-2026-43284 in IR scenario planning. |

The hard rule for currency scoring: every CVE in the catalog with RWEP >= 50 (currently CVE-2026-31431) must appear in the threat model under its named threat or its CVE ID. RWEP 40–49 entries should appear if the org uses the affected technology. Sub-40 entries appear by exception.

Run `node lib/scoring.js` to recompute RWEP if `data/cve-catalog.json` has been updated since `last_threat_review`.

---

## Compliance Theater Check

Apply this single test to any "yes, we have a threat model" claim:

> "What was the publish or last-revision date of the version of the threat model that is currently authoritative inside your organisation? Now list every CISA KEV addition since that date that affects any technology in your stack (Linux kernel, AI coding assistants, MCP servers, identity providers, edge appliances). For each, point to the line in the threat model that addresses it, or the dated risk-acceptance memo. If the answer is 'we'll update it at next review' and the next review is more than 30 days out, the threat model is a compliance artefact, not an operational document. The control is documented; it is not operational."

A complementary test for AI surfaces:

> "Open `data/atlas-ttps.json`. Pick any three `AML.T*` IDs at random. For each, show where in your threat model the technique is named or where the equivalent attack is described. If the threat model has zero ATLAS IDs and the org operates any LLM-integrated system, the AI section is theater — the document predates the threat catalog that defines AI threats."

A complementary test for global orgs:

> "Your org is subject to DORA (4h initial incident notification). When did your threat model last refresh its incident-classification taxonomy against DORA's RTS on classification of major ICT-related incidents? If the answer is 'before January 2025', the threat model cannot drive DORA-compliant classification decisions — by definition, the taxonomy predates the regulation."

---

## Scoring

For each class, score:
- **2 points:** Explicitly addressed in threat model with specific controls
- **1 point:** Mentioned in threat model but without specific controls
- **0 points:** Not addressed

**Total: 28 points maximum**

| Score | Currency Rating |
|---|---|
| 25–28 | Current (≥ 89%) |
| 20–24 | Mostly current — 2–3 gaps |
| 14–19 | Partially current — systematic AI/modern threat gaps |
| 7–13 | Significantly stale — 2022 threat model |
| 0–6 | Critically stale — 2019-era threat model |

---

## Analysis Procedure

### Step 1: Obtain the current threat model

Request or locate:
- Most recent threat model document
- Date of last substantive update (not just cosmetic/formatting)
- Which threat actors are in scope
- Which attack classes are documented

### Step 2: Score each of the 14 classes

For each class:
1. Is it explicitly in the threat model? If yes, with specific controls?
2. Score 0/1/2

### Step 3: Identify top gaps

Prioritize unchecked classes by RWEP impact:
1. Classes where a real, exploited CVE (Copy Fail, Windsurf MCP) means current exposure
2. Classes where detection architecture has zero coverage (AI C2, PROMPTFLUX)
3. Classes that affect future risk posture (PQC, AI reconnaissance speed)

### Step 4: Generate update roadmap

For each gap, produce a specific, actionable update:
- What text to add to the threat model
- What ATLAS/ATT&CK TTP to reference
- What control to add or update

---

## Output Format

```
## Threat Model Currency Assessment

**Date:** YYYY-MM-DD
**Threat Model Version:** [document version / last update date]

### Currency Score: [X / 28] = [percentage]%
**Rating:** [Current / Mostly current / Partially current / Significantly stale / Critically stale]

### Class-by-Class Scoring
| # | Threat Class | Score | Finding |
|---|---|---|---|
| 1 | AI-Discovered Kernel Vulnerabilities | 0/1/2 | [specific gap or confirmation] |
| 2 | Deterministic Kernel LPE | 0/1/2 | |
| 3 | IPsec Subsystem Exploitation | 0/1/2 | |
| 4 | Prompt Injection as Enterprise RCE | 0/1/2 | |
| 5 | MCP Supply Chain RCE | 0/1/2 | |
| 6 | AI-Assisted Exploit Development | 0/1/2 | |
| 7 | AI as Covert C2 | 0/1/2 | |
| 8 | AI-Generated Malware Evasion | 0/1/2 | |
| 9 | RAG Data Exfiltration | 0/1/2 | |
| 10 | Model Poisoning | 0/1/2 | |
| 11 | AI-Speed Reconnaissance | 0/1/2 | |
| 12 | AI-Generated Credential Phishing | 0/1/2 | |
| 13 | MITRE ATLAS v5.1.0 Coverage | 0/1/2 | |
| 14 | Post-Quantum Adversary Timeline | 0/1/2 | |

### Priority Update Roadmap
[Ordered by current exposure risk: specific additions for each gap]

### ATLAS Version Check
Current reference: MITRE ATLAS v5.1.0 (November 2025)
Threat model references: [version cited in document]
Gap: [if different]
```
