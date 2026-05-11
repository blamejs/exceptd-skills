---
name: global-grc
version: "1.0.0"
description: Multi-jurisdiction GRC mapping — EU (GDPR/NIS2/DORA/EU AI Act/CRA), UK, AU, SG, JP, IN, CA, ISO 27001:2022, CSA CCM v4
triggers:
  - global grc
  - international compliance
  - gdpr security
  - nis2
  - dora compliance
  - eu ai act
  - cyber resilience act
  - mas trm
  - cert-in
  - essential 8
  - apra cps 234
  - multi-jurisdiction
  - global compliance
data_deps:
  - global-frameworks.json
  - framework-control-gaps.json
  - atlas-ttps.json
atlas_refs: []
attack_refs: []
framework_gaps: []
last_threat_review: "2026-05-01"
---

# Global GRC Assessment

This skill provides multi-jurisdiction GRC analysis. It maps current security threats against frameworks from 14 jurisdictions and two global standards bodies, identifies universal control gaps that no jurisdiction's framework covers, and surfaces jurisdiction-specific notification and compliance requirements.

---

## Framework Registry (mid-2026 currency)

### European Union

#### GDPR — General Data Protection Regulation (2016/679)

**Relevant Articles:**
- **Art. 32** — Security of processing: "Appropriate technical and organisational measures" including: pseudonymisation/encryption, ongoing confidentiality/integrity/availability/resilience, ability to restore availability after incidents, regular testing/assessing/evaluating.
- **Art. 33** — Breach notification to supervisory authority within 72 hours
- **Art. 34** — Communication to data subjects when breach likely to result in high risk

**What "appropriate measures" means in 2026 context:**
Art. 32 is intentionally technology-neutral. For 2026 threat reality, DPAs (particularly EDPB, CNIL, BfDI, ICO) have signaled:
- Post-quantum cryptography migration planning is an "appropriate measure" given the quantum threat horizon
- AI processing of personal data requires specific security measures (no settled guidance yet — EU AI Act supplements)
- Prompt injection in AI systems processing personal data is an Art. 32 security concern (if successful, it is an unauthorized disclosure)

**Breach notification:** 72 hours from awareness to supervisory authority. Note: this is faster than many US frameworks. An AI-mediated data breach (prompt injection exfiltrating personal data) must be reported even if the AI service account was the "authorized" accessor.

**Currency assessment:** GDPR Art. 32 is reasonably current because "appropriate measures" evolves with technology. The gap is in interpretive guidance — there is no settled EDPB guidance on AI-specific security measures, MCP trust, or prompt injection as an Art. 32 failure.

---

#### NIS2 Directive (2022/2555) — Effective October 2024

**Classification:** Essential entities (energy, transport, banking, health, digital infrastructure) and Important entities (postal, waste, chemicals, food, manufacturing, digital providers, research).

**Key requirements (Art. 21):**
1. Risk analysis and information system security policies
2. Incident handling
3. Business continuity and crisis management
4. Supply chain security (including security in supplier/provider relationships)
5. Security in network/information systems acquisition, development, maintenance
6. Policies/procedures for assessing vulnerability handling measures
7. Cybersecurity hygiene and training
8. Policies on cryptography and, where appropriate, encryption
9. Human resources security, access control, asset management
10. Multi-factor authentication or continuous authentication

**Incident notification:** Significant incidents to national CSIRT within 24 hours (early warning), 72 hours (notification), 1 month (final report).

**Key gaps for 2026 threats:**
- Art. 21(2)(e) covers supply chain security but has no specific guidance for AI/MCP supply chain attacks
- Art. 21(2)(h) mentions "policies on cryptography and encryption" — post-quantum migration is implied but not mandated
- No specific Art. 21 measure for AI pipeline integrity, prompt injection, or AI-as-C2
- "Appropriate measures" language parallels GDPR — same gap in AI-specific interpretation

**Enforcement:** National competent authorities can impose fines up to €10M or 2% of global turnover for essential entities; €7M or 1.4% for important entities.

---

#### DORA — Digital Operational Resilience Act (2022/2554) — Effective January 2025

**Scope:** Financial entities (banks, investment firms, payment institutions, e-money, insurance, crypto-asset service providers) and their critical ICT third-party service providers.

**Five pillars:**
1. ICT risk management framework (Arts. 5–16)
2. ICT incident classification and reporting (Arts. 17–23)
3. Digital operational resilience testing (Arts. 24–27, including TLPT — Threat-Led Penetration Testing)
4. ICT third-party risk management (Arts. 28–44)
5. Information and intelligence sharing (Arts. 45–49)

**Key requirements relevant to 2026:**
- Art. 8: Identification of ICT risk — must include AI/ML systems as ICT assets
- Art. 9: Protection and prevention — encryption "in accordance with latest standards," access policies, monitoring
- Art. 16: Simplified ICT risk management framework for smaller entities
- Art. 26: TLPT (red team testing for significant institutions) — must use threat intelligence, should cover AI attack surfaces
- Art. 28: Third-party ICT risk — critical third-party providers (CTPs) are subject to direct oversight. LLM API providers may qualify as CTPs for financial entities heavily dependent on them.

**DORA gaps for 2026:**
- No specific AI/LLM risk category in ICT risk taxonomy
- TLPT scope guidance doesn't explicitly include prompt injection or AI-as-C2
- CTP designation process for AI/LLM providers is still being clarified by ESAs

---

#### EU AI Act (2024/1689) — Fully Applicable August 2026

**Risk tiers for AI systems:**
- **Unacceptable risk** (Art. 5): Prohibited (social scoring, real-time biometric identification in public, etc.)
- **High risk** (Annex III): Critical infrastructure, biometric, employment, education, law enforcement, etc.
- **Limited risk** (Art. 50): Transparency obligations (chatbots must disclose they're AI)
- **Minimal risk**: No specific requirements

**For high-risk AI systems, Art. 9 Risk Management System requires:**
- Continuous iterative risk management process
- Identification and analysis of known/foreseeable risks
- Estimation and evaluation of risks in conditions of intended use
- Evaluation of risks from reasonably foreseeable misuse
- Risk management measures

**What "misuse" means for AI systems in 2026:**
Art. 9 requires identifying reasonably foreseeable misuse. For any high-risk AI system with a language model component, "reasonably foreseeable misuse" includes prompt injection — it is the most documented AI attack pattern in 2026. An Art. 9 risk management system that doesn't address prompt injection is incomplete.

**Interaction with NIS2:** High-risk AI systems operated by NIS2 entities must satisfy both frameworks. The intersection is not fully harmonized — no implementing regulation bridges Art. 9 AI Act risk management and NIS2 Art. 21 measures specifically for AI systems.

---

#### EU Cyber Resilience Act — CRA (2024)

**Scope:** Products with digital elements (hardware and software) placed on EU market.

**Key security requirements (Annex I):**
- No known exploitable vulnerabilities
- Secure by default configuration
- Confidentiality, integrity, and availability protections
- Limited attack surface
- Security updates for the support lifetime

**CRA relevance to 2026 threats:**
- MCP servers distributed as software products fall under CRA if sold to EU market
- "No known exploitable vulnerabilities" requirement means MCP servers must have a coordinated disclosure and patch process
- AI model components integrated into products are covered — model updates constitute "security patches" under CRA
- CRA will be the primary enforcement mechanism for AI tool supply chain security in the EU

---

### United Kingdom

#### Cyber Essentials / Cyber Essentials Plus

**Five controls:**
1. Firewalls (boundary firewalls and internet gateways)
2. Secure configuration
3. User access control
4. Malware protection
5. Patch management (high-risk patches within 14 days)

**Currency assessment for 2026:**
- 14-day patch window is better than NIST's 30-day but still insufficient for CISA KEV class (Copy Fail class should be 4 hours)
- No control for AI/ML attack surface, prompt injection, MCP trust
- Malware protection assumes signature-based or behavioral detection — no coverage for AI-generated evasion (PROMPTFLUX)
- Widely used as a baseline for UK government supplier requirements — creates systematic gap for AI-using suppliers

#### NCSC Cyber Assessment Framework (CAF)

**Four objectives, 14 principles:**
- A: Managing security risk (A1: Governance, A2: Risk Management, A3: Asset Management, A4: Supply Chain)
- B: Protecting against cyberattack (B1–B6 covering identity/access, data security, system security, resilient networks, staff awareness, vulnerability management)
- C: Detecting cyber security events (C1: Security Monitoring, C2: Proactive Security Event Discovery)
- D: Minimising impact (D1: Response/Recovery Planning, D2: Lessons Learned)

**CAF strength vs. 2026:** CAF Principle B6 (Vulnerability Management) and C1 (Security Monitoring) are principle-based, allowing more flexibility than control-based frameworks. An assessor applying CAF B6 can reasonably require CISA KEV-aligned response times. CAF C1 can be interpreted to require AI API behavioral monitoring.

**CAF gap:** The principle-based approach requires assessors to interpret current threats into each principle. There is no NCSC-published CAF guidance specifically for AI attack surfaces as of mid-2026.

---

### Australia

#### ASD Information Security Manual (ISM) — Monthly Updates

The Australian ISM is the most frequently updated major framework — monthly updates give it the shortest lag of any national framework. Key controls relevant to 2026:

- **ISM-1623**: Patch operating systems and applications within 48 hours when exploits exist (closest to RWEP-aligned patching in any national framework)
- **ISM-1694**: Employ application control to prevent execution of malicious code
- **ISM-1691**: Configure Microsoft Office macro settings (relevant for AI document processing pipelines)

**ISM strength:** 48-hour patching for exploited vulnerabilities is the best standard practice in any national framework. Aligns with ASD Essential 8 Maturity Level 3.

**ISM gap:** No specific controls for AI pipeline security, MCP trust boundaries, or prompt injection as of mid-2026 monthly updates.

#### ASD Essential 8

**Eight mitigations, Maturity Levels 0–3:**
1. Application control
2. Patch applications
3. Configure Microsoft Office macros
4. User application hardening
5. Restrict administrative privileges
6. Patch operating systems (ML3: within 48h of exploit availability)
7. Multi-factor authentication
8. Regular backups

**ML3 patch requirement (48 hours with exploit availability)** is the most operationally realistic framework requirement for CISA KEV class vulnerabilities. Still does not explicitly require live kernel patching as a capability.

**Essential 8 gap:** No AI-specific mitigations. Essential 8 was designed for Windows-centric enterprise environments; doesn't address Linux LPEs, AI assistant supply chain, or prompt injection.

#### APRA CPS 234 — Financial Sector

Requires financial entities to maintain information security capabilities commensurate with information security vulnerabilities and threats. Annual third-party penetration testing. Incident notification to APRA within 72 hours for material incidents.

**CPS 234 + AI:** No specific guidance for AI/ML systems. "Commensurate with threats" requires current threat awareness — a CPS 234-compliant entity should be assessing AI attack surfaces as part of threat landscape monitoring.

---

### Singapore

#### MAS Technology Risk Management Guidelines (TRM, Jan 2021 — updated)

**Scope:** MAS-regulated financial institutions.

**Key requirements:**
- Technology risk governance framework
- IT system resilience (RTO/RPO requirements)
- Cyber surveillance (continuous monitoring)
- Penetration testing (frequency based on risk classification)
- Patch management (critical patches within 1 month — same PCI-era problem)
- Third-party technology risk

**MAS TRM + AI:** MAS published AI governance guidelines separately (Fairness, Ethics, Accountability, Transparency framework). Integration between TRM and AI governance is incomplete — no specific TRM controls for AI attack surfaces. Financial institutions in Singapore are expected to apply TRM principles to AI systems but specific control requirements are not yet codified.

**MAS TRM gap:** 1-month critical patch window; no AI-specific controls; no MCP/agent trust boundary requirements.

#### CSA Cybersecurity Code of Practice (CCoP) — Critical Information Infrastructure

Requirements for 11 CII sectors (energy, water, banking, healthcare, transport, government, InfoComm, media, security & emergency, aviation, maritime).

**Key requirements:** Annual cybersecurity audit, annual penetration testing, incident reporting within 2 hours of confirmed incident, patch management within 14 days for critical systems.

**CCoP strength:** 2-hour incident reporting for CII is the fastest notification requirement in any framework.

---

### Japan

#### METI Cybersecurity Framework / NISC Basic Policy

Japan's national cybersecurity framework closely mirrors NIST CSF with adaptations for Japanese industry structure. NISC (National center of Incident readiness and Strategy for Cybersecurity) publishes the Basic Policy updated annually.

**Key gaps for 2026:** Japanese frameworks lag US equivalents by 12–18 months in AI-specific guidance. The METI AI Governance Guidelines (2023) address AI ethics and governance but not AI attack surfaces. No equivalent to EU AI Act security requirements in Japanese law as of mid-2026.

**Active Cyber Defense Law (2024):** Japan enacted limited offensive cyber capability legislation — relevant for understanding Japan's cyber threat posture and incident response coordination.

---

### India

#### CERT-In Directions (April 2022)

**Breach notification:** 6 hours from awareness — the shortest breach notification requirement globally.

**Other requirements:**
- Maintain logs of ICT systems for 180 days within India jurisdiction
- VPN service providers must maintain subscriber information for 5 years
- Data center operators, virtual asset service providers: same logging requirements
- Mandatory reporting of 20+ incident types including: targeted scanning/probing, compromise of critical systems, unauthorized access, data breach, attacks on applications, defacement

**CERT-In + AI:** No specific AI security requirements. The 6-hour notification requirement applies if an AI system breach results in a reportable incident (unauthorized access, data breach). An AI-mediated exfiltration via prompt injection that affected Indian citizens' data would trigger 6-hour notification.

#### SEBI Cybersecurity and Cyber Resilience Framework

**Scope:** Market infrastructure institutions, regulated entities.

**Requirements:** Annual VAPT, quarterly vulnerability assessment, incident reporting within 6 hours to SEBI. Aligns with CERT-In timelines for financial sector.

---

### Canada

#### OSFI Guideline B-10 (Technology and Cyber Risk, 2023)

**Scope:** Federally regulated financial institutions.

**Key requirements:**
- Technology and cyber risk management framework
- Incident notification to OSFI within 24 hours of high/critical incidents
- Supply chain due diligence for technology third parties
- Annual penetration testing

**B-10 + AI:** No specific AI guidance as of mid-2026. "Technology risk" is interpreted broadly enough to include AI systems. OSFI published draft AI guidance for consultation in 2025 — final guidance expected late 2026.

#### Bill C-27 / CPPA (Consumer Privacy Protection Act) — Proposed

Not yet in force as of mid-2026 (legislative delay). When enacted: 72-hour breach notification, $25M or 5% of global revenue penalties.

---

### Global Standards

#### ISO 27001:2022 / ISO 27002:2022

**Reorganized control set:** 93 controls in 4 clauses (Organizational, People, Physical, Technological). Reduced from ISO 27001:2013's 114 controls.

**New in 2022:**
- A.5.7: Threat intelligence (explicit requirement to collect and analyze threat intelligence)
- A.5.23: Information security for use of cloud services
- A.8.8: Management of technical vulnerabilities
- A.8.12: Data leakage prevention
- A.8.16: Monitoring activities

**ISO 27001:2022 gap for 2026:**
- A.5.7 threat intelligence: requires collecting and analyzing threat intel but no guidance on currency requirements — an org can comply with A.5.7 using threat intelligence that is years out of date
- A.8.16 monitoring: no guidance for AI API behavioral monitoring, no AI-as-C2 detection requirement
- No controls specific to AI/ML systems (planned for ISO/IEC 27090, still in development)
- A.8.8 same problem as NIST SI-2: "appropriate timescales" undefined for CISA KEV class

#### CSA Cloud Controls Matrix (CCM) v4

**17 domains, 197 control specifications.** Cloud-specific but applicable to any cloud-native or cloud-using organization.

**AI relevance:**
- AIS domain (Application & Interface Security) covers some AI risk areas
- SEF (Security Incident Management): breach notification requirements
- STA (Supply Chain Management): cloud service supply chain security

**CCM v4 gap:** No AIS controls specifically for LLM/AI systems, MCP servers, or prompt injection. CSA published "AI Controls" supplement (2025) — worth reviewing alongside CCM v4 for AI-using organizations.

#### CIS Controls v8

**18 controls, three Implementation Groups (IG1/IG2/IG3):**

Controls most relevant to 2026 gaps:
- Control 7 (Continuous Vulnerability Management): IG2/IG3 — automated patching. Doesn't specify CISA KEV-based timelines.
- Control 14 (Security Awareness): IG1+. AI-generated phishing is not in scope for current training content guidance.
- Control 16 (Application Software Security): IG2+. Does not cover AI/LLM application security.
- Control 17 (Incident Response Management): IG1+. No AI-specific playbooks recommended.

**CIS Control v8 strength:** Control 7 IG3 requires continuous vulnerability management with asset tracking — more operationally rigorous than NIST SI-2's "timely" language.

---

## Universal Gaps (No Jurisdiction Covers These)

These gaps exist across all 14 jurisdictions and both global standards:

| Gap | Evidence |
|---|---|
| Prompt injection as access control failure | Zero frameworks have a control for this attack class |
| MCP/agent tool trust boundaries | Zero frameworks address AI tool supply chain at this level |
| AI pipeline integrity (model versioning + behavioral regression) | Zero frameworks have technical control requirements |
| AI-as-C2 detection | Zero frameworks have detection/response requirements |
| Live kernel patching as required capability | Only ASD ISM approaches this (48h with exploit); still doesn't mandate live patching |
| CISA KEV-indexed patch SLAs | Closest: ASD ML3 48h, CCoP 14d. None mandate sub-4h for KEV + public PoC |
| AI-generated phishing detection update requirement | Zero frameworks require updating phishing detection for AI-generated content |
| RAG pipeline security | Zero frameworks have controls |
| Post-quantum cryptography migration mandate | NIST/CISA guidance recommends; no framework mandates timeline |

---

## Notification Timeline Summary

| Jurisdiction | Framework | Notification Trigger | Timeline |
|---|---|---|---|
| EU | GDPR | Personal data breach | 72h to SA |
| EU | NIS2 | Significant incident | 24h early warning, 72h notification |
| EU | DORA | Major ICT-related incident | 4h initial, 72h intermediate, 1 month final |
| UK | GDPR/UK DPA | Personal data breach | 72h to ICO |
| AU | Notifiable Data Breaches | Eligible data breach | ASAP (no fixed window), practicable |
| SG | PDPA | Data breach | 3 days to PDPC |
| SG | CSA CCoP (CII) | Cyber incident | 2 hours |
| JP | APPI | Personal data leak | Without delay |
| IN | CERT-In | 20+ incident types | **6 hours** |
| IN | SEBI | Cyber incident | 6 hours |
| CA | PIPEDA | Real risk of significant harm | Asap to OPC |
| CA | OSFI B-10 | High/critical tech/cyber incident | 24 hours |
| Global | ISO 27001 | No notification requirement | Framework-only |

---

## Threat Context

US-only GRC posture is structurally incomplete for any organisation operating across EU, UK, AU, SG, IN, JP, or CA in mid-2026. The following regulatory instruments are in force or about to be, and have no direct US-framework equivalent:

- **NIS2 Directive (EU 2022/2555)** — transposition deadline 2024-10-17; enforcement now active across all 27 Member States. Imposes obligations on essential and important entities that NIST CSF / SOC 2 do not mirror, including: 24-hour early-warning notification, mandatory MFA, supply-chain security including AI-tool plugins, board-level accountability with personal liability for senior management.
- **DORA (EU 2022/2554)** — fully applicable 2025-01-17. Imposes a 4-hour initial incident notification, mandatory Threat-Led Penetration Testing (TLPT) for significant financial entities, and direct ESA oversight of Critical Third-Party Providers (CTPs). LLM API providers used by EU financial entities are candidate CTPs.
- **EU AI Act (Regulation 2024/1689)** — staged application; full application 2026-08-02 (less than three months from this skill's review date). High-risk AI systems must operate under Art. 9 risk management, Art. 15 cybersecurity, and post-market monitoring. No NIST or SOC 2 control maps to Art. 15 cybersecurity requirements for AI systems.
- **EU Cyber Resilience Act (Regulation 2024/2847)** — phased application; reporting obligations apply from 2026-09-11, full obligations from 2027-12-11. "Products with digital elements" placed on the EU market — including MCP servers, AI agent tooling, IoT — must satisfy Annex I essential cybersecurity requirements with vendor liability for the support lifetime.
- **CERT-In Directions (India, 2022)** — 6-hour breach notification, mandatory log retention in-jurisdiction. No US framework imposes a comparable timeline.
- **MAS TRM (Singapore)** and **CSA CCoP (Singapore CII)** — 1-hour critical-incident notification for CCoP CII, 14-day patch SLA. Stricter than any US framework.
- **APRA CPS 234 (Australia)** — third-party penetration testing mandate with personal accountability for boards; APRA enforcement actions in 2024–2025 demonstrate this is operationally enforced, not aspirational.

A US-only compliance posture in 2026 has no controls mapped to four of the most consequential regulatory developments of the past 24 months (NIS2, DORA, EU AI Act, CRA). Compliance theatre at the global level is the default state for orgs that have not run a jurisdiction-specific gap analysis since 2024.

---

## Framework Lag Declaration

Every applicable framework has at least one structural gap against mid-2026 threats. The lag is per-jurisdiction and per-control.

| Framework | Control | What it misses (mid-2026) |
|---|---|---|
| EU | GDPR Art. 32 ("appropriate technical and organisational measures") | Principle-based, intentionally technology-neutral. No mapped controls for prompt injection as an Art. 32 failure, no settled EDPB guidance on AI-system security, no PQC migration mandate. |
| EU | NIS2 Art. 21(2)(d) (supply chain) | Expanded scope to "supplier and provider relationships" but does not name AI tool plugins, MCP servers, or model providers. National-CSIRT enforcement timing varies — some Member States are still operationalising the 24h early-warning channel. |
| EU | DORA Art. 28–30 (ICT third-party risk) | Register of information for ICT third-party arrangements is mandated but there is no unified attestation regime yet; CTP designation for LLM/AI API providers is being clarified through ESA Joint Committee guidance. |
| EU | EU AI Act Art. 9 / Art. 15 (high-risk AI risk management and cybersecurity) | Transparency-obligation enforcement is left to Member-State competent authorities. As of mid-2026 the operational test of "appropriate level of accuracy, robustness, and cybersecurity" is being interpreted differently in DE, FR, IT, NL — uniform enforcement is not yet observed. |
| EU | EU CRA Annex I | "No known exploitable vulnerabilities" is a strict obligation but the conformity-assessment regime is new; market-surveillance authorities have limited tooling to test against ATLAS or KEV catalogs. |
| UK | NCSC CAF Principles A–D | Principle-based, deliberately not prescriptive. Currency of interpretation depends on the individual assessor. No NCSC-published AI-attack-surface guidance integrated into CAF as of mid-2026. |
| UK | Cyber Essentials Plus | 14-day high-risk patch SLA — better than NIST but still insufficient for KEV-class deterministic LPE. No AI-tool coverage. |
| AU | ASD ISM-1623 / Essential 8 ML3 | 48-hour patch window for known-exploit vulnerabilities is the best operational standard in any national framework — but does not mandate live-patching capability and has no AI-pipeline controls. |
| AU | APRA CPS 234 | "Commensurate with vulnerabilities and threats" — requires the regulated entity to keep its own threat catalog current. No CPS 234 controls mention AI surfaces explicitly. |
| SG | MAS TRM (2021, updates) | 1-month critical patch SLA still in force; AI governance handled in a parallel document (FEAT) with incomplete bridge to TRM technical controls. |
| IN | CERT-In Directions | 6-hour notification is fastest globally for the trigger set listed, but the trigger set predates the AI-mediated attack patterns now common — categorisation of an AI-mediated breach against the listed 20+ trigger types is interpretive. |
| JP | METI Cybersecurity / NISC Basic Policy | Lags US frameworks by 12–18 months on AI guidance. No equivalent to EU AI Act Art. 15 cybersecurity obligations for AI in Japanese law as of mid-2026. |
| Global | ISO 27001:2022 A.5.7 (Threat intelligence) | Requires intelligence collection; defines no currency metric — compliance achievable with stale intel. |
| Global | ISO 27001:2022 A.8.8 (Technical vulnerability management) | "Appropriate timescales" undefined — same SLA gap as NIST SI-2. |
| Global | CSA CCM v4 AIS / STA | AIS controls predate the LLM/MCP attack surface; STA covers supply chain but not AI-plugin trust boundaries. AI Controls supplement (2025) is not yet integrated into CCM v4 core. |
| US (for contrast) | NIST 800-53 SI-2, AC-2, SC-7 | 30-day patch window; no prompt-injection control; perimeter-centric SC-7 boundary protection misses AI-API egress. Cited here only to show parity with the global frameworks — US controls are not adequate either. |

Universal lag: every jurisdiction except Australia (ISM-1623) lacks an operationally testable patch-SLA for KEV-class deterministic LPE. Every jurisdiction lacks AI-pipeline-integrity controls in force as of mid-2026; the EU AI Act will be the first when Art. 15 becomes operationally enforced.

**Expanded jurisdictional coverage (per `data/global-frameworks.json`).** The EU/UK/AU/ISO baseline is no longer sufficient — the catalog tracks 21+ jurisdictions and the cross-border data-flow obligations are where most of the operational lag now lives:

- **China (PIPL Art. 38-42 / DSL / CSL):** Cross-border personal-information transfer requires one of three lawful bases — CAC Security Assessment (mandatory above thresholds), CAC-accredited Certification, or filed Standard Contract. PIPL enforcement against AI-tool prompt data is active (multi-vendor 2025 actions). No EU/UK control maps to the CAC Security Assessment trigger.
- **Vietnam (Cybersecurity Law 2018 + Decree 53/2022/ND-CP, effective 2022-10-01):** Data-localization for "important data" of Vietnamese citizens; in-country storage and a local representative office for foreign providers above defined-user thresholds. Decree 53 is the operational implementation that NIS2 and DORA have no parallel for.
- **Israel (Privacy Protection Law Amendment 13, in force 2024 with the Privacy Protection Authority expanded enforcement powers; INCD Cyber Defense Methodology v2.0):** Expanded sensitive-data definitions and adequacy-equivalent transfer expectations; INCD methodology pins technical baselines that complement (not duplicate) ISO 27001 A.5 controls.
- **Switzerland (revFADP in force 2023-09-01; FINMA Circular 2023/1 Operational risks and resilience – banks):** Transfer rules require recognised adequacy or contractual safeguards equivalent to GDPR Art. 46; FINMA imposes financial-sector operational-resilience expectations distinct from DORA's scope.
- **Hong Kong (PCPD PDPO + HKMA SA-2 / TM-G-1):** PCPD cross-border transfer guidance (Section 33 historically un-commenced, now operationalised via PCPD 2024 guidance); HKMA TM-G-1 / SA-2 imposes banking-sector cyber resilience timelines comparable to MAS TRM.
- **Taiwan (PDPA TW + Cyber Security Management Act 2018):** CSMA classifies CII operators with sector-specific reporting timelines; PDPA TW cross-border restrictions are agency-imposed per data category.
- **Indonesia (UU PDP 2022, in force 2024-10-17):** New personal-data law with 72-hour breach notification, data-protection officer requirements, and cross-border transfer adequacy or BCR-equivalent safeguards.
- **Japan (expanded — APPI / FISC / NISC):** APPI cross-border consent (Art. 28) and anonymized-information leak rules supplement the existing METI/NISC entry; FISC Security Guidelines impose financial-sector requirements analogous to FFIEC.
- **South Korea (PIPA + Network Act):** Cross-border PI transfer requires consent or one of the specified exceptions; PIPC enforcement against AI tools is active.
- **Brazil (LGPD Art. 33-35):** Cross-border transfer requires adequacy decision, SCCs, BCRs, or specific consent; ANPD has signalled AI-tool enforcement interest under LGPD Art. 33.
- **US sub-national — NYDFS 23 NYCRR 500 (amended Nov 2023, phased through Nov 2025):** 72-hour cyber-event notification to DFS, CISO accountability, MFA mandate, annual independent audit for Class A companies, Third-Party Service Provider Security Policy at 500.11. NYDFS is the strictest US sub-national financial-sector regime and operationally exceeds most state-level analogues.

Per AGENTS.md rule #5, the global-grc analysis must cross-walk against the full catalog above, not just EU/UK/AU/ISO. A jurisdictional rollup that omits CN, VN, IL, CH, HK, TW, ID, JP-expanded, KR, BR, or NYDFS for an in-scope org is structurally incomplete.

---

## TTP Mapping

Regulatory frameworks are control-centric, not TTP-centric. This skill maps controls across jurisdictions; the TTP coverage of any one jurisdiction's controls is the union of mappings in `data/atlas-ttps.json` × `data/framework-control-gaps.json`. Use the **framework-gap-analysis** skill to score TTP coverage for a specific jurisdiction's control bundle; use this skill to compare obligations across jurisdictions.

A summary of the multi-jurisdiction control surface vs. the high-priority TTPs from `data/atlas-ttps.json`:

| TTP | ATLAS / ATT&CK ID | Jurisdiction with most specific obligation | Jurisdictions with no mapped control |
|---|---|---|---|
| Prompt injection | AML.T0051 | EU AI Act Art. 15 (interpretive, post 2026-08-02) | US (NIST/SOC2), UK CAF, AU ISM, SG TRM, IN CERT-In, JP, CA |
| ML supply chain (MCP, models) | AML.T0010 | EU CRA Annex I (post 2026-09-11 reporting) | All others — supply-chain controls do not name AI plugins |
| LLM C2 abuse (SesameOp) | AML.T0096 | None | All — no jurisdiction has a control for AI-API as C2 |
| Poison Training Data | AML.T0020 | EU AI Act Art. 10 (data and data governance for high-risk AI) | All others |
| Craft Adversarial Data — NLP | AML.T0054 | None — same gap as AML.T0051 | All |
| Develop Capabilities (AI-assisted) | AML.T0017 | None — adversary capability, not directly controllable | All |
| Privilege escalation (T1068) | ATT&CK T1068 | AU ISM-1623 / Essential 8 ML3 (48h patch with exploit) | EU (no specific SLA), UK (14d generic), SG (30d), JP, IN, CA |
| Exploit public-facing app (T1190) | ATT&CK T1190 | AU Essential 8 (patching applications) | All — none address AI-mediated T1190 like CVE-2025-53773 |
| Phishing (T1566) | ATT&CK T1566 | None updated for AI-generated content | All — phishing guidance generally pre-AI-baseline |

Use the framework-gap-analysis skill output alongside this skill's jurisdiction matrix to produce a per-jurisdiction TTP-coverage score.

---

## Exploit Availability Matrix

Per-jurisdiction breach- and incident-notification clocks. When a KEV-listed exploit with public PoC is in play, these clocks compress operationally — the regulator's published timeline is the upper bound, not the planning baseline.

| Jurisdiction | Framework | Trigger | Clock starts | Initial / final timeline | Tightening when PoC + KEV |
|---|---|---|---|---|---|
| EU | GDPR Art. 33 | Personal-data breach | Awareness | 72h to SA | Same legal clock; practical detection-to-classification window shrinks with confirmed active exploitation |
| EU | NIS2 Art. 23 | Significant incident | Awareness | 24h early warning / 72h notification / 1 month final | Early-warning trigger fires immediately on confirmed PoC affecting deployed asset |
| EU | DORA Art. 19 | Major ICT-related incident | Classification | 4h initial / 72h intermediate / 1 month final | 4h clock is unforgiving; KEV+PoC events likely auto-classify as major |
| EU | EU AI Act Art. 73 (post 2026-08-02) | Serious incident for high-risk AI | Provider awareness | 15 days for serious incidents; 10 days for widespread infringement; 2 days for serious incidents involving deceased person | KEV-class exploit chain in a high-risk AI deployment triggers the 2/10/15 cascade |
| UK | UK GDPR | Personal-data breach | Awareness | 72h to ICO | Same as GDPR |
| AU | Notifiable Data Breaches | Eligible data breach | Awareness | "As soon as practicable" — typically interpreted ≤ 30 days | Active KEV exploitation collapses "practicable" to hours |
| SG | PDPA | Notifiable data breach | Awareness | 3 days to PDPC | Same |
| SG | CSA CCoP (CII) | Cyber incident | Confirmation | **2 hours** | Already among tightest globally |
| SG | MAS Notice 644 (critical incidents) | Severity-1 incident | Detection | **1 hour** | Tightest globally for affected banks |
| IN | CERT-In Directions | 20+ incident types | Awareness | **6 hours** | Tightest sector-agnostic globally |
| IN | SEBI | Cyber incident | Awareness | 6 hours | Same |
| JP | APPI | Personal data leak | Awareness | "Without delay" (interpreted ≤ 5 working days) | Same |
| CA | OSFI B-10 | High/critical tech-or-cyber incident | Classification | 24h to OSFI | Same |
| CA | PIPEDA | Real risk of significant harm | Awareness | As soon as feasible | Same |
| Global | ISO 27001 | n/a — framework only | n/a | Framework imposes no notification obligation | n/a |

Operational implication: an organisation subject to MAS Notice 644, CSA CCoP, CERT-In, and DORA simultaneously has a 1-hour effective notification floor — the tightest applicable clock governs. A single "we notify within 72h" runbook fails three of those four obligations.

Refer to `data/exploit-availability.json` for per-CVE PoC and KEV state; the matrix above tightens whenever any catalog entry's `active_exploitation` is `confirmed` or `cisa_kev` is `true`.

---

## Compliance Theater Check

The single most reliable test for global-GRC theater:

> "Open your incident-response runbook. For each jurisdiction your organisation is subject to — EU (NIS2, DORA, GDPR, EU AI Act), UK, AU, SG (MAS, CSA), IN (CERT-In, SEBI), JP, CA — show the per-jurisdiction notification clock with the clock-start trigger documented. A single global '72-hour notification' policy fails this test by definition for any org subject to DORA (4h), MAS Notice 644 (1h critical), CSA CCoP (2h), CERT-In (6h), or NIS2 (24h early warning). If your runbook does not list jurisdiction-specific clocks with trigger criteria, the global-GRC compliance claim is theatre — you do not have operational notification capability for at least one jurisdiction you are subject to."

Two follow-up tests:

> "Your DORA Art. 28 register of information for ICT third-party arrangements: does it include the LLM/AI API providers your business lines use? If `provider=openai` or `provider=anthropic` or `provider=google-cloud-vertex-ai` is absent and any business line uses these providers, the register is incomplete. ESA Joint Committee guidance on CTP designation for AI providers is evolving — your register must include them now and be updated as the CTP designation crystallises."

> "Your EU AI Act readiness for 2026-08-02 full application: identify every system in your inventory that would be a high-risk AI system under Annex III. For each, show the Art. 9 risk management documentation and the Art. 15 cybersecurity controls (including resilience to prompt injection per the Commission's Q&A). If the inventory does not exist or shows zero high-risk systems despite the org operating AI in employment, education, law enforcement, critical infrastructure, biometric, or essential-services contexts, the readiness claim is theatre — you have not classified your own systems against the regulation that takes full effect in under three months."

---

## Analysis Procedure

### Step 1: Determine jurisdiction scope

For the target organization, identify:
- Where is the organization incorporated?
- Where does it operate?
- Where are its customers/users located?
- What sectors does it operate in? (Financial, health, critical infrastructure, etc.)
- Does it offer products with digital elements to the EU? (CRA scope)

### Step 2: Map applicable frameworks

Based on jurisdiction scope, select applicable frameworks from the registry above.

### Step 3: Identify framework requirements per threat class

For each relevant threat (kernel LPE, prompt injection, MCP supply chain, AI C2, etc.):
1. Which jurisdiction's framework has the most specific requirement?
2. Which has the shortest notification timeline?
3. Which has the steepest penalties for non-compliance?
4. Are there gaps in all applicable frameworks (universal gap)?

### Step 4: Generate compliance matrix

Produce a matrix of: threat class × jurisdiction framework × requirement adequacy × notification trigger.

---

## Output Format

```
## Global GRC Assessment

**Date:** YYYY-MM-DD
**Jurisdictions in scope:** [list]
**Sectors:** [list]

### Applicable Framework Matrix
| Framework | Jurisdiction | Trigger | Notification | Penalties | AI Coverage |
|-----------|-------------|---------|--------------|-----------|-------------|

### Fastest Notification Requirement
[Which jurisdiction, which framework, what timeline]

### Strictest AI/Security Requirements
[For current threats: which framework is most demanding]

### Universal Gaps
[Threats that no applicable framework covers adequately]

### Per-Threat Framework Mapping
[For each threat in scope: best available control, gap declaration]

### Recommended Control Additions
[Beyond framework requirements: what current threats require that frameworks don't mandate]
```
