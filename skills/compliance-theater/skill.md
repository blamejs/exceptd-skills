---
name: compliance-theater
version: "1.0.0"
description: Detect where an organization passes an audit but remains exposed — seven documented compliance theater patterns with specific detection tests
triggers:
  - compliance theater
  - paper compliance
  - audit but exposed
  - compliant but vulnerable
  - compliance gap
  - checkbox security
  - audit theater
data_deps:
  - framework-control-gaps.json
  - cve-catalog.json
  - exploit-availability.json
atlas_refs: []
attack_refs: []
framework_gaps:
  - ALL-AI-PIPELINE-INTEGRITY
  - ALL-PROMPT-INJECTION-ACCESS-CONTROL
  - FedRAMP-Rev5-Moderate
  - CMMC-2.0-Level-2
last_threat_review: "2026-05-01"
---

# Compliance Theater Detection

Compliance theater is the condition where an organization passes an audit of a security control while remaining exposed to the threat that control is supposed to address. It is not fraud — the control exists, operates, and generates the required evidence. The problem is the control was designed for a different threat environment.

This skill identifies the specific, testable conditions where audit-passing controls provide no real protection.

---

## Threat Context (mid-2026)

The defining mid-2026 reality is that an organization can pass a clean ISO 27001:2022, SOC 2 Type II, or PCI DSS 4.0 audit while remaining exposed to KEV-listed deterministic LPEs and zero-interaction RCEs. The contrast cases drive every theater pattern below:

- **CVE-2026-31431 (Copy Fail)** — Linux kernel LPE, CISA KEV, AI-discovered in approximately one hour, deterministic 732-byte public PoC, no race condition. An organization with an A.8.8 / SI-2 / PCI 6.3.3 program that meets the framework's "appropriate timescale" language (commonly 30 days for High) is *passing the audit* during the active-exploitation window. This is the canonical Patch Management Theater case. Catalog entry: `data/cve-catalog.json`.
- **CVE-2026-30615 (Windsurf MCP zero-interaction RCE)** — 150M+ affected downloads. An organization's CC9 / SA-12 / A.5.19 vendor management program rated as "operating effectively" by an auditor typically has zero coverage of MCP servers running in developer environments. The vendor-management control passes the audit and provides no control surface for the attack class. Catalog entry: `data/cve-catalog.json`.
- **CVE-2025-53773 (GitHub Copilot prompt-injection RCE)** — CVSS 9.6. An organization's SOC 2 CC6 access control program is rated "passed" while prompt injection executes attacker-chosen actions using the AI service account's authorized identity. The audit evidence (IAM reviews, access logs with no unauthorized events) is correct and complete; it provides zero signal about the intrusion.

In each case, a real-world public exploit produced by current adversary TTPs renders a passing audit non-informative about actual security posture. The seven theater patterns below codify the most common recurrences of this pattern.

---

## Framework Lag Declaration

Compliance theater is the operational shadow of framework lag. Per-framework lag statements that drive the theater patterns in this skill:

| Framework | Control | Lag (what the control language does not cover) |
|---|---|---|
| SOC 2 | CC6 (Logical and Physical Access) | Logical-access language was drafted for human-controlled accounts and machine identities in traditional IAM. It does not cover prompt injection as an access control bypass: the AI service account is authorized, monitored, and within least-privilege scope; the attacker's intent travels through the model's context window and never appears in access logs. See CVE-2025-53773. |
| ISO 27001:2022 | A.8.8 (Management of Technical Vulnerabilities) | "Appropriate timescales" is undefined; auditor practice typically reads as 30 days for High / 90 days for Medium. The language does not operationalize the CISA KEV class. For CVE-2026-31431 these timescales mean active exploitation during the "compliant" remediation window. |
| PCI DSS 4.0 | 6.3.3 (Patches) | The one-month critical-patch window predates AI-assisted exploit development. For any CVE with CISA KEV listing and a public PoC, the one-month window is an exploitation-acceptance window, not a security window. |
| SOC 2 | CC7 (System Operations) | Anomaly detection guidance has no baseline for AI API traffic, AI-as-C2 (SesameOp), or PROMPTFLUX behavioral patterns. The control passes the audit with no AI-relevant detection surface. |
| ISO 27001:2022 | A.5.19 / A.5.20 (Supplier relationships) | Drafted for SaaS and outsourced-service vendors. Does not cover MCP servers as third-party code executing inside the developer environment, nor LLM API providers as data processors for sensitive prompt content. |
| NIST 800-53 | CM-3 (Configuration Change Control) | Drafted for changes the organization controls. LLM model updates by external providers occur without operator notification or consent, on the provider's schedule, and can alter safety-relevant behavior. The change-management control passes the audit and has zero coverage of this change vector. |
| NIST 800-53 | AT-2 (Security Awareness Training) | Drafted against human-template phishing. 82.6% of phishing emails now contain AI-generated content. Grammar/style heuristics are no longer reliable detectors. A < 5% click rate on human-generated simulations says nothing about resistance to AI-generated highly personalized spear-phishing. |
| US FedRAMP | Rev 5 Moderate baseline | Authorization-as-evidence pattern. A current ATO certifies that the CSP's control implementation was assessed against the Rev 5 Moderate baseline at a point in time. It does not certify that the CSP has any control over MCP servers running in tenant developer environments, prompt-injection attack surface in AI features, or AI-API providers used downstream. The Authority To Operate is treated by procurement as a security guarantee — Pattern 6 (Vendor/Third-Party Risk Theater) recurs at the federal-cloud layer. |
| US DoD | CMMC 2.0 Level 2 (110 NIST 800-171 practices) | Certification-as-evidence pattern. A Level 2 certificate attests to assessor-verified implementation of the 110 practices at the time of assessment. It does not cover AI coding-assistant supply chain, MCP server trust on engineering workstations developing CUI-touching software, or model-update change control. The same Pattern 5 (Change Management Theater) and Pattern 6 (Vendor Management Theater) patterns recur with sharper consequences because CMMC gates DoD contract eligibility. |

The pre-analyzed gaps for these controls live in the framework-gap-analysis skill's Built-In Gap Catalog. This skill consumes those gaps and produces a theater detection per gap.

---

## TTP Mapping (MITRE ATLAS v5.1.0 and ATT&CK)

Each theater pattern below maps to one or more attacker TTPs in `data/atlas-ttps.json` and MITRE ATT&CK Enterprise. The mapping is what distinguishes theater from genuine compliance: a control claimed as compensating must map to a TTP it actually disrupts.

| Theater pattern | Primary TTPs | Bypass mechanism |
|---|---|---|
| Patch Management Theater (Pattern 1) | T1068 (Exploitation for Privilege Escalation), T1203 (Exploitation for Client Execution) | Public PoC + KEV + AI-accelerated weaponization compresses the exploitation window inside the SLA |
| Network Segmentation Theater — IPsec (Pattern 2) | T1190 (Exploit Public-Facing Application) targeting the IPsec kernel subsystem | The control's cryptographic mechanism is the attack surface |
| Access Control Theater — AI Agents (Pattern 3) | AML.T0051 (LLM Prompt Injection), AML.T0054 (Craft Adversarial Data — NLP), T1059 (Command and Scripting Interpreter) | Authorized service account executes attacker-chosen actions; no identity boundary is crossed |
| Incident Response Theater — AI Pipeline (Pattern 4) | AML.T0020 (Poison Training Data), AML.T0096 (LLM Integration Abuse as C2), AML.T0010 (ML Supply Chain Compromise) | Detection triggers do not exist, so documented IR procedures have no input |
| Change Management Theater — AI Models (Pattern 5) | AML.T0018 (Backdoor ML Model), AML.T0020 | Externally-managed model updates bypass operator change control entirely |
| Vendor/Third-Party Risk Theater — AI APIs (Pattern 6) | AML.T0010 (ML Supply Chain Compromise) | MCP servers and LLM APIs sit outside the vendor-management scope |
| Security Awareness Theater — AI Phishing (Pattern 7) | T1566 (Phishing), AML.T0016 (Acquire Public ML Artifacts — misuse) | AI-generated content evades grammar/style heuristics and template-matching detectors |

Source-of-truth TTP catalog: `data/atlas-ttps.json` (pinned to MITRE ATLAS v5.1.0, November 2025). Any theater claim in an assessment must cite at least one TTP ID from that catalog or an ATT&CK Enterprise ID — claims without a mapped TTP fail Hard Rule #4 (no orphaned controls).

---

## Exploit Availability Matrix

The theater patterns most acutely under attack today are those backed by high-RWEP entries in `data/cve-catalog.json`. Prioritize remediation of theater flags in this order:

| Theater pattern | Evidence CVE | CVSS | RWEP tier | KEV | Public PoC | AI-accelerated | Live-patchable | Active exploitation |
|---|---|---|---|---|---|---|---|---|
| Patch Management Theater | CVE-2026-31431 (Copy Fail) | High | Critical | Yes | Yes (732 bytes, deterministic) | Yes (AI-discovered) | Yes (kpatch/livepatch) | Confirmed |
| Vendor Management Theater (AI APIs / MCP) | CVE-2026-30615 (Windsurf MCP) | 9.8 | Critical | No | Partial | No | N/A (vendor-side) | Suspected |
| Access Control Theater (AI agents) | CVE-2025-53773 (Copilot prompt injection RCE) | 9.6 | High | No | Yes (demonstrated) | Yes (AI tooling enables) | N/A (vendor-side) | Suspected |
| Network Segmentation Theater (IPsec) | CVE-2026-43284 (Dirty Frag) | High | High | Pending | Partial | No | Limited (subsystem-dependent) | Suspected |
| Incident Response Theater (AI pipeline) | SesameOp campaign + AML.T0096 | N/A | High | N/A | ATLAS-documented | Yes | N/A | Confirmed campaign |
| Change Management Theater (AI models) | Continuous provider updates | N/A | Medium | N/A | N/A | N/A | N/A | Ongoing (uncontrolled) |
| Security Awareness Theater (AI phishing) | AI-generated phishing baseline (82.6%) | N/A | High | N/A | Operational | Yes | N/A | Confirmed (industry-wide) |

The first three rows (Critical / Critical / High RWEP with public PoC or active exploitation) are the most dangerous theater patterns to leave un-remediated. Pull authoritative scoring from `data/exploit-availability.json` and `data/cve-catalog.json` before producing the output.

---

## Theater Pattern Library

### Pattern 1: Patch Management Theater

**The claim:** "We have a patch management program. All Critical/High CVEs are remediated within 30 days."

**The audit evidence:** Patch management policy document, ticketing system showing CVEs opened and closed within SLA, vulnerability scanner reports showing declining open vulnerabilities.

**The reality:** CVE-2026-31431 (Copy Fail) was CISA KEV listed on 2026-03-15 with a public 732-byte exploit script. A 30-day SLA means an organization can be "compliant" while having a public deterministic root exploit unpatched for 30 days. During that window: active exploitation confirmed.

**Why it's theater:** The 30-day SLA was designed for environments where weaponization takes weeks. Copy Fail's weaponization time was ~1 hour (AI-discovered and PoC-ready). The control measures compliance with a time window that no longer reflects exploit development reality.

**Detection test:**
```
1. Pull the last 12 months of patch management records
2. Filter for CISA KEV entries
3. For each CISA KEV entry: calculate time from KEV listing date to verified-patched date
4. If any CISA KEV took > 72 hours to patch (or deploy live patch): THEATER FLAG
5. Supplemental: does the organization have live kernel patching deployed? 
   If no: for any system running a production workload, kernel CVEs require a reboot.
   Ask: when was the last kernel reboot on each production system?
   If > 90 days: THEATER FLAG (likely accumulating unpatched kernel CVEs behind the "compliant" SLA)
```

**What a real control looks like:** Tiered SLA: CISA KEV = 4 hours to live-patch or isolate; public PoC = 24 hours; Critical (no public PoC) = 72 hours; High = 7 days. Live patching capability deployed and verified quarterly.

---

### Pattern 2: Network Segmentation Theater (IPsec Edition)

**The claim:** "We have network segmentation between security zones implemented via IPsec tunnels. SC-8 / PCI DSS Req 1 compliant."

**The audit evidence:** Network diagrams showing zone separation, IPsec configuration documentation, firewall rule reviews.

**The reality:** CVE-2026-43284 (Dirty Frag) exploits the IPsec subsystem. An unpatched host cannot use IPsec as a compensating control for Dirty Frag — the IPsec implementation is the attack surface. Network controls that rely on IPsec are providing no isolation guarantee for Dirty Frag-exposed hosts.

**Why it's theater:** The segmentation control is real. The IPsec configuration is correct. The audit evidence is legitimate. But the control's security guarantee fails specifically for the class of vulnerability that uses IPsec as its attack path.

**Detection test:**
```
1. Identify hosts using IPsec for network segmentation compliance
2. Check kernel version: is CVE-2026-43284 patched?
3. If unpatched: the IPsec control is not providing the isolation it claims
4. Note in risk register: "SC-8/PCI Req 1 IPsec segmentation provides no isolation guarantee 
   for CVE-2026-43284-exposed hosts until kernel patch applied."
5. THEATER FLAG: any compliance report that claims IPsec segmentation as a compensating 
   control without noting CVE-2026-43284 patch status
```

---

### Pattern 3: Access Control Theater (AI Agent Edition)

**The claim:** "Our access control program (CC6 / AC-2) ensures all system access is authenticated, authorized, and logged."

**The audit evidence:** IAM configuration reviews, access logs showing authorized accounts, no unauthorized access events, SOC 2 CC6 pass.

**The reality:** AI agent service accounts operate under CC6-compliant access controls. Prompt injection attacks cause the AI agent to take actions using its service account. The actions are authorized from CC6's perspective. The attacker's identity never appears in access logs. The audit evidence is correct and complete — and provides zero signal about the intrusion.

**Why it's theater:** CC6 was designed for human-controlled accounts. AI agents with tool use capabilities create an authorization model where model judgment is the gating mechanism, not traditional access control. Prompt injection bypasses the model's judgment — and therefore bypasses the access control — without triggering any CC6 monitoring.

**Detection test:**
```
1. Ask: does the organization have AI systems (coding assistants, chatbots, agents) with 
   access to production systems, data, or codebases?
2. Ask: are AI agent API calls logged with: (a) full prompt content, (b) tool calls made, 
   (c) correlation to initiating user identity?
3. If (2) is no: the access control has no visibility into the access pattern that 
   prompt injection exploits. THEATER FLAG.
4. Ask: is there a behavioral baseline for what actions an AI agent should take?
   Is there alerting when the agent takes unusual actions (accessing files outside normal scope, 
   calling tools it doesn't normally use, making external network requests)?
5. If no: THEATER FLAG for access control coverage of AI agents
```

---

### Pattern 4: Incident Response Theater (AI Pipeline Edition)

**The claim:** "We have an incident response program (IR-1 through IR-8 / A.5.24-A.5.28) with documented procedures for detecting, responding to, and recovering from security incidents."

**The audit evidence:** IR policy, incident response playbooks, tabletop exercise records, defined roles and responsibilities.

**The reality:** The incident response program covers: malware infection, data breach, DDoS, ransomware, insider threat. It does not cover: model poisoning detected in production, prompt injection attack via AI assistant, AI-as-C2 channel discovered in network traffic, SesameOp-style exfiltration via AI API.

**Why it's theater:** The IR program passes the audit because it meets the framework's requirements for documented procedures and tested response capabilities. Those capabilities are real for traditional incidents. For AI-specific incidents, the detection mechanisms don't exist (so incidents aren't detected) and the response procedures haven't been written (so response is ad-hoc if detection does occur).

**Detection test:**
```
1. Pull the incident response playbook library
2. Search for: "prompt injection", "model poisoning", "AI agent", "LLM", "MCP server"
3. If none found: THEATER FLAG — IR program has no AI-specific procedures
4. Ask: has the organization conducted a tabletop exercise for an AI-specific incident 
   in the last 12 months?
5. Ask: what is the detection mechanism for model poisoning? 
   (Acceptable answers: model behavioral regression testing, output monitoring, 
    model fingerprinting. 
    Unacceptable: "our ML team would notice" or "our AV would catch it")
6. If detection mechanism doesn't exist: the IR procedures for AI incidents are 
   a procedure without a trigger. THEATER FLAG.
```

---

### Pattern 5: Change Management Theater (AI Model Edition)

**The claim:** "All changes to production systems go through our change management process (CM-3 / A.8.32). Changes are reviewed, approved, and documented."

**The audit evidence:** Change management tickets for infrastructure deployments, software releases, configuration changes.

**The reality:** LLM models used by the organization are updated continuously by their providers (OpenAI, Anthropic, Google, etc.). These updates change model behavior, capabilities, and potentially safety properties. They do not go through the organization's change management process because the organization does not control them. Behavioral regressions introduced in model updates are not detected by change management controls.

**Why it's theater:** The change management control is real and functioning. It controls everything the organization actually controls. But the organization's AI systems depend on externally managed components (the LLMs themselves) that change continuously outside the control perimeter.

**Detection test:**
```
1. List all LLM API dependencies (OpenAI, Anthropic Claude, Google Gemini, Azure OpenAI)
2. For each: does a change management ticket get opened when the provider deploys a model update?
3. If no: THEATER FLAG — model updates are uncontrolled changes to production AI systems
4. Ask: is there a behavioral test suite that runs against AI systems after model updates?
   (Tests that would detect if model behavior changed in security-relevant ways)
5. If no: changes to AI system behavior are undetected even if a ticket existed
6. Ask: does the organization pin model versions where the API supports it?
   (e.g., gpt-4o-2024-11-20 instead of gpt-4o)
7. If no: the organization is accepting continuous uncontrolled behavioral changes
```

---

### Pattern 6: Vendor/Third-Party Risk Theater (AI API Edition)

**The claim:** "We have a vendor management program (CC9 / SA-12 / A.5.19). All third-party vendors with access to our systems or data undergo security review."

**The audit evidence:** Vendor security questionnaires, SOC 2 reports for critical vendors, data processing agreements.

**The reality:** AI/LLM APIs (OpenAI, Anthropic, Google, etc.) receive organization data in prompts. Developer workstations have MCP servers installed from public npm registries. Neither category typically undergoes the same vendor review as, say, a cloud storage provider — they're treated as SaaS tools, not vendors with data access.

**Why it's theater:** The vendor management program is functional for its intended scope. The scope doesn't include: LLM API providers as data processors for prompt content, MCP server packages as third-party code executing in production environments, AI coding assistants as vendors with access to source code.

**Detection test:**
```
1. List LLM API providers used (OpenAI, Anthropic, Google, Azure OpenAI, Cohere, etc.)
2. For each: is there a vendor risk assessment? A DPA? A data classification for what goes in prompts?
3. If no DPA for LLM providers handling sensitive data: GDPR/CCPA risk, potential THEATER FLAG
4. List MCP servers installed on developer workstations
5. For each: did it go through vendor security review?
6. If no: the vendor management program has zero coverage for the attack surface where 
   CVE-2026-30615 class vulnerabilities occur. THEATER FLAG.
```

---

### Pattern 7: Security Awareness Theater (AI Phishing Edition)

**The claim:** "We conduct regular security awareness training and phishing simulations. Our click-rate on simulated phishes is < 5%."

**The audit evidence:** Training completion records, phishing simulation results showing < 5% click rate, awareness program documentation.

**The reality:** 82.6% of phishing emails now contain AI-generated content indistinguishable from legitimate emails by grammar/style checks. Traditional phishing simulation content is crafted by humans using templates. A < 5% click rate on human-generated phishing simulations says nothing about resistance to AI-generated highly personalized spear-phishing.

**Why it's theater:** The training and simulation program is real. The click-rate metric is real. But the threat has shifted to AI-generated content that looks nothing like what the simulations train against. The 5% click rate is measured against last generation's phishing, not current generation.

**Detection test:**
```
1. Pull the last 3 phishing simulation reports
2. Ask: were any simulation emails AI-generated (not template-based)?
3. If no: THEATER FLAG — simulations test resistance to 2021 phishing, not 2026 phishing
4. Ask: what are the primary phishing detection signals in the email security gateway?
   Acceptable: sender reputation, link analysis, behavioral signals, sandboxing
   Theater: grammar checks, template matching, "unusual phrasing" rules
5. Ask: is MFA deployed and phishing-resistant (hardware keys, passkeys)?
   SMS/TOTP-protected accounts remain fully vulnerable to AI-generated real-time phishing
   If SMS/TOTP and "we have MFA" is the answer: THEATER FLAG for credential theft resistance
```

---

## Analysis Procedure

### Step 1: Identify scope

Ask for or determine:
- Which compliance framework(s) the organization is auditing against
- Which theater patterns are most relevant to their environment (AI systems? Cloud-native? Critical infrastructure?)
- Recent audit results (what passed)

### Step 2: Run applicable detection tests

For each relevant theater pattern:
1. Run the detection test
2. Record: THEATER FLAG / CLEAR / NEEDS VERIFICATION
3. Note specific evidence that supports the finding

### Step 3: Score theater level

| Theater Score | Meaning |
|---|---|
| 0 flags | Controls appear adequate for current threat reality |
| 1–2 flags | Targeted gaps — specific controls are theater for specific threats |
| 3–4 flags | Systematic theater — control program has structural gaps |
| 5+ flags | Compliance framework mismatch — the framework is not aligned with current threats |

### Step 4: Generate output

---

## Output Format

```
## Compliance Theater Assessment

**Date:** YYYY-MM-DD
**Framework(s):** [in scope]

### Theater Detection Results

| Pattern | Finding | Key Evidence |
|---------|---------|--------------|
| Patch Management | THEATER / CLEAR | [e.g., "CISA KEV average remediation time: 18 days"] |
| Network Segmentation (IPsec) | THEATER / CLEAR | [e.g., "CVE-2026-43284 unpatched on 12 of 40 hosts using IPsec"] |
| Access Control (AI Agents) | THEATER / CLEAR | [e.g., "No prompt-level logging on Copilot deployments"] |
| Incident Response (AI) | THEATER / CLEAR | [e.g., "Zero AI-specific playbooks in IR library"] |
| Change Management (Models) | THEATER / CLEAR | [e.g., "No model version pinning, no behavioral test suite"] |
| Vendor Management (AI APIs) | THEATER / CLEAR | [e.g., "3 LLM providers, 0 vendor risk assessments"] |
| Security Awareness (AI Phishing) | THEATER / CLEAR | [e.g., "Zero AI-generated simulation emails in last 12 months"] |

### Theater Score: [X/7 flags]

### Auditor-Facing Remediation Language
[Per theater flag: specific evidence gap, what a closed gap looks like, 
what a compensating control declaration requires]

### Priority Remediation Roadmap
[Ordered by RWEP impact: most dangerous theater first]
```

---

## Compliance Theater Check

This skill *is* the compliance theater check. The seven pattern tests above produce theater findings; the universal test below is the single question that drives every one of them.

> **For each control the organization claims as compensating, demand the publicly documented attacker TTP that bypasses it, mapped to a specific MITRE ATLAS or ATT&CK ID resolvable in `data/atlas-ttps.json`.**

Decision rule:

- The org names a documented TTP and the control's mechanism does not disrupt it → the compensating-control claim is theater. Record the theater flag with the TTP ID and the bypass mechanism.
- The org cannot name any TTP → the claim is unsubstantiated; treat as theater pending verification. The most common variant is "we have controls that would handle that" where no one has traced the control to a specific bypass mechanism.
- The org names a TTP and the control verifiably disrupts it (e.g., the bypass requires a precondition the control prevents) → the claim is genuine, not theater. Record as CLEAR with the TTP ID as the disrupted technique.

Applied at the level of the seven theater patterns:

| Pattern | Demand this evidence | Theater signal |
|---|---|---|
| 1 Patch Management | Time from CISA KEV listing to verified-patched for last 12 months of KEV entries | Any KEV entry > 72 hours unmitigated |
| 2 Network Segmentation (IPsec) | CVE-2026-43284 patch status on every host whose segmentation evidence cites IPsec | Any unpatched host in the IPsec compliance scope |
| 3 Access Control (AI agents) | Prompt-level logging + behavioral baseline for AI agent tool use | Absence of prompt-level visibility |
| 4 Incident Response (AI) | IR playbook search results for prompt injection / model poisoning / MCP / AI-as-C2 | Zero matches in playbook library |
| 5 Change Management (AI models) | Model version pinning + behavioral regression test suite + provider changelog review cadence | Any of the three missing |
| 6 Vendor Management (AI APIs) | DPA + risk assessment for every LLM provider; vendor review record for every installed MCP server | Any AI provider or MCP server without vendor-management evidence |
| 7 Security Awareness (AI phishing) | AI-generated content proportion in last 3 phishing simulations + phishing-resistant MFA deployment | Zero AI-generated simulation content or SMS/TOTP-only MFA |

The output is consumed by policy-exception-gen (to convert theater flags into defensible exceptions with real compensating controls), framework-gap-analysis (to escalate any newly discovered theater pattern into a Framework Lag Declaration), and global-grc (to roll up theater findings across EU/UK/AU/ISO jurisdictions per Hard Rule #5).
