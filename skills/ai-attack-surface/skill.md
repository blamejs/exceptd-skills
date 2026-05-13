---
name: ai-attack-surface
version: "1.0.0"
description: Comprehensive AI/ML attack surface assessment mapped to MITRE ATLAS v5.1.0 with explicit framework gap flags
triggers:
  - ai attack surface
  - prompt injection
  - llm security
  - ai security assessment
  - model security
  - ai threat model
  - ai red team
  - promptsteal
  - promptflux
data_deps:
  - cve-catalog.json
  - atlas-ttps.json
  - framework-control-gaps.json
atlas_refs:
  - AML.T0043
  - AML.T0051
  - AML.T0054
  - AML.T0020
  - AML.T0096
  - AML.T0016
  - AML.T0017
  - AML.T0018
attack_refs:
  - T1566
  - T1059
  - T1190
framework_gaps:
  - ALL-AI-PIPELINE-INTEGRITY
  - ALL-PROMPT-INJECTION-ACCESS-CONTROL
  - ISO-27001-2022-A.8.28
  - ISO-IEC-23894-2023-clause-7
  - NIST-800-53-AC-2
  - NIST-800-53-SI-3
  - OWASP-LLM-Top-10-2025-LLM01
  - OWASP-LLM-Top-10-2025-LLM02
  - SOC2-CC6-logical-access
  - EU-AI-Act-Art-15
  - UK-CAF-A1
  - AU-Essential-8-App-Hardening
cwe_refs:
  - CWE-1039
  - CWE-1426
  - CWE-94
d3fend_refs:
  - D3-IOPR
  - D3-NTA
last_threat_review: "2026-05-13"
---

# AI Attack Surface Assessment

## Threat Context (mid-2026)

The AI attack surface is not speculative. It is actively exploited. The following are confirmed, documented threats as of mid-2026.

### 1. Prompt Injection as Enterprise RCE

**CVE-2025-53773** — Hidden prompt injection in GitHub Copilot PR descriptions enabling RCE. CVSS 9.6. The attack embeds adversarial instructions in GitHub PR descriptions. When a developer uses GitHub Copilot to review or summarize the PR, the injected instructions execute in the context of the developer's session, enabling remote code execution.

This is not a chatbot trick. This is enterprise RCE via a developer tool used by hundreds of millions of developers. The attack surface is any system that:
- Feeds external content (user input, web content, documents, PR descriptions, emails, calendar events) into an LLM prompt
- Where that LLM has tools, actions, or code execution capability

**Attack success rates against SOTA defenses:** A 2026 meta-analysis of 78 studies found adaptive prompt injection strategies succeed against state-of-the-art defenses at rates exceeding 85%. No current framework has adequate controls for this.

**ATLAS ref:** AML.T0054 (Craft Adversarial Data — NLP)

### 2. MCP Supply Chain — Architectural RCE

The Model Context Protocol (MCP) introduced an architectural vulnerability affecting every major AI coding assistant: Cursor, VS Code + GitHub Copilot, Windsurf, Claude Code, Gemini CLI.

**CVE-2026-30615** — Windsurf. Zero user interaction required. The vulnerability allows a malicious MCP server (or a compromised legitimate MCP server) to execute arbitrary code in the context of the AI assistant. 150M+ affected downloads.

This is a supply chain attack surface. Every MCP server a user installs is a potential RCE vector. Trust boundaries that exist for npm packages do not exist for MCP servers because most MCP clients do not enforce signed manifests or tool allowlists.

**ATLAS ref:** AML.T0010 (ML Supply Chain Compromise)

### 3. AI-Assisted Exploit Development

41% of 2025 zero-days were discovered by attackers using AI-assisted reverse engineering. Copy Fail (CVE-2026-31431) was discovered by an AI system in approximately one hour.

The implication: the time between a vulnerability's introduction into a codebase and its reliable exploitation has compressed from months or years to hours or days for AI-capable threat actors. Patch management SLAs designed for human-speed exploit development are structurally inadequate.

**ATLAS ref:** AML.T0017 (Develop Capabilities)

### 4. AI Credential Phishing Acceleration

Credential theft driven by AI increased 160% in 2025. 82.6% of phishing emails now contain AI-generated content undetectable by grammar/style checks. Traditional phishing detection heuristics (poor grammar, unusual phrasing, template patterns) are no longer reliable detectors.

**ATLAS ref:** AML.T0018 (Acquire Public ML Artifacts — misuse of generation capability)

### 5. AI as Covert C2 — SesameOp

Adversaries are repurposing legitimate AI agent APIs as covert command-and-control channels (ATLAS AML.T0096). The SesameOp campaign demonstrated this technique:
- C2 commands encoded in prompt fields
- Exfiltrated data returned in completion fields
- Traffic pattern is indistinguishable from legitimate AI API usage
- Evades all traditional C2 detection (DGA, beaconing, protocol anomalies)

### 6. PROMPTFLUX and PROMPTSTEAL Malware Families

Two malware families actively query LLMs during execution:
- **PROMPTFLUX**: Queries public LLMs for evasion guidance in real time — "generate code equivalent to [flagged signature] that doesn't match this detection pattern"
- **PROMPTSTEAL**: Uses LLMs to analyze captured credentials and PII, structure exfiltration, and select targets — treats the LLM as a live intelligence analyst

Traditional AV and EDR detection cannot match this because the malicious behavior is dynamically generated per-execution.

### 7. RAG Data Exfiltration

Attackers manipulating vector embeddings to force retrieval mechanisms to surface and leak proprietary data chunks. Covered separately in rag-pipeline-security skill.

### 8. Model Poisoning

Training pipeline targeting has moved beyond data injection to directly biasing model behavior. Supply chain logistics and classification systems that use ML models for decisions are at risk of subtle model poisoning that influences decisions in the attacker's favor over time.

**ATLAS ref:** AML.T0020 (Poison Training Data)

### 9. AI-Speed Reconnaissance

AI-assisted reconnaissance is observed at 36,000 probes per second per campaign. Traditional rate-based detection (100–1,000 req/s threshold alerts) does not fire at legitimate-looking distributed AI-directed probe rates until significant reconnaissance has already occurred.

---

## Framework Lag Declaration

| Framework | Control | Why It Fails for AI Threats |
|---|---|---|
| NIST 800-53 | AC-2 (Account Management) | Controls account lifecycle for human users and service accounts. Does not address LLM agent identity, tool authorization, or prompt injection as an access control bypass. An attacker who injects a prompt that causes a model to call `delete_file()` bypasses AC-2 entirely — the API call is authorized by the model's service account, not the attacker's. |
| NIST 800-53 | SI-3 (Malicious Code Protection) | Designed for signature-based malware detection. PROMPTFLUX generates unique evasion code per execution by querying an LLM. SI-3 has no control surface for AI-generated dynamic malware. |
| NIST 800-53 | SI-10 (Information Input Validation) | Input validation for web forms and API endpoints. Does not address prompt injection, where the "input" is semantically legitimate text that contains adversarial instructions for the model. |
| ISO 27001:2022 | A.8.28 (Secure coding) | Secure coding practices for software development. No reference to AI/ML system security, prompt injection, or model integrity. |
| ISO 27001:2022 | A.8.30 (Outsourced development) | Third-party development controls. Does not address MCP server trust, unsigned manifests, or supply chain attacks on AI tool ecosystems. |
| SOC 2 | CC6 (Logical and Physical Access) | Access control via IAM, authentication, authorization. Prompt injection is an access control failure that routes around CC6 entirely — the authorized model account takes the action, not the attacker. Audit trails show the model's service account performed the action. |
| SOC 2 | CC7 (System Operations) | Anomaly detection for system operations. No guidance for AI API baseline, AI C2 detection, or PROMPTFLUX behavioral patterns. |
| PCI DSS 4.0 | 6.4.1 | Web application protection (WAF). WAFs operate on HTTP request/response patterns. They have no semantic understanding of prompt injection embedded in JSON `message` fields. |
| MITRE ATT&CK | Enterprise | Does not include prompt injection as a technique. AI-as-C2 (SesameOp) is not in ATT&CK as of mid-2026. ATLAS v5.1.0 covers these but is not part of SOC detection engineering programs that are ATT&CK-mapped. |
| NIST AI RMF | MEASURE 2.5 | Measure AI risks during operation. Provides a framework for thinking about AI risk but no specific controls for prompt injection, MCP supply chain, or AI-as-C2. |

---

## TTP Mapping (MITRE ATLAS v5.1.0)

| ATLAS ID | Technique | Framework Coverage | Gap Description | Exploitation Example |
|---|---|---|---|---|
| AML.T0054 | Craft Adversarial Data — NLP | Missing in all major frameworks | No control covers adversarial text injection into LLM prompts | CVE-2025-53773 (GitHub Copilot RCE) |
| AML.T0010 | ML Supply Chain Compromise | Partial (ISO A.8.30) | A.8.30 covers outsourced development; does not cover MCP server trust, package signing for AI tools | CVE-2026-30615 (Windsurf MCP) |
| AML.T0096 | LLM Integration Abuse (C2) | Missing in all major frameworks | No framework has a control for AI API traffic as C2 channel | SesameOp campaign |
| AML.T0020 | Poison Training Data | Partial (NIST AI RMF) | NIST AI RMF identifies the risk; no specific technical control | Supply chain logistics model poisoning |
| AML.T0043 | Craft Adversarial Data | Partial (SI-10) | SI-10 covers web input validation; not semantic injection in LLM prompts | RAG vector manipulation |
| AML.T0051 | LLM Prompt Injection | Missing in all major frameworks | Zero controls in NIST, ISO, SOC 2, PCI for prompt injection | CVE-2025-53773, indirect injection via retrieved docs |
| AML.T0017 | Develop Capabilities | Partial (awareness only) | No framework requires monitoring for AI-assisted exploit development against the org | Copy Fail AI discovery, 41% of 2025 0-days |
| AML.T0016 | Acquire Public ML Artifacts | Missing (misuse dimension) | Frameworks don't address adversary use of public AI APIs for reconnaissance/attack | PROMPTFLUX, PROMPTSTEAL, phishing generation |
| AML.T0018 | Backdoor ML Model | Partial (NIST AI RMF) | No technical control requirements for model integrity verification | Training pipeline poisoning |

---

## Exploit Availability Matrix

| Vulnerability | CVSS | RWEP | KEV | PoC | AI-Accelerated | Active Exploitation |
|---|---|---|---|---|---|---|
| CVE-2025-53773 (Copilot prompt injection RCE) | 9.6 | 91 | No | Yes — demonstrated | Yes (AI tooling enables) | Suspected |
| CVE-2026-30615 (Windsurf MCP RCE) | 9.8 | 94 | No | Partial | No | Suspected |
| SesameOp (AI C2 technique) | N/A | N/A | N/A | Yes (ATLAS documented) | Yes | Confirmed campaign |
| PROMPTFLUX family | N/A | N/A | N/A | Behavioral signatures | Yes | Active |
| PROMPTSTEAL family | N/A | N/A | N/A | Behavioral signatures | Yes | Active |

---

## Analysis Procedure

### Step 1: Inventory the AI surface

For the target environment, identify:
- Which LLM APIs are in use? (OpenAI, Anthropic, Google, Azure OpenAI, local models)
- Which AI coding assistants are deployed? (GitHub Copilot, Cursor, Windsurf, Claude Code, Gemini CLI)
- Which MCP servers are installed? (list via IDE settings or `~/.cursor/mcp.json`, `~/.vscode/mcp.json`)
- Does any application take user input and include it in an LLM prompt without semantic sanitization?
- Does any application use RAG? (vector store + retrieval)
- Are any AI model APIs accessible from the internet?
- What service accounts do AI agents run under? What permissions do those accounts have?

### Step 2: Assess prompt injection exposure

For each system that feeds external content into LLM prompts:

**Injection surface score:**
- External content in prompts (user input, documents, emails, web content, PR descriptions): +High
- LLM has tool use / function calling capability: +Critical multiplier
- LLM can take actions on behalf of users (file ops, API calls, code execution): +Critical multiplier
- No semantic input sanitization: +High
- No output monitoring: +Medium
- Attack success rate against SOTA defenses: 85%+ (meta-analysis baseline)

**Current defense adequacy:**
- Prompt injection classifiers reduce success rate; do not eliminate it
- System prompt hardening reduces success rate; does not eliminate it
- No defense achieves <15% bypass rate against adaptive adversaries (2026 data)
- Defense-in-depth is the only viable strategy: minimize tool permissions + monitor outputs + rate-limit + log all prompts

### Step 3: Assess MCP trust posture

For each installed MCP server:
- Is the server package signed? Verify manifest signature.
- Is there an explicit tool allowlist? (`allowed_tools` in MCP client config)
- Does the MCP server require authentication? (bearer token or equivalent)
- What permissions does the MCP server's process run with?
- Are MCP server outputs sanitized before returning to the model?

**MCP risk score:**
- Unsigned server + no allowlist + no auth: Critical
- Signed server + allowlist + bearer auth: Low-Medium
- Any MCP server with filesystem or shell access + unsigned: Critical

### Step 4: Assess AI C2 exposure

Check for SesameOp-style C2 indicators:
- Are AI API calls logged with full prompt + response content?
- Is there a behavioral baseline for normal AI API usage per host/user/process?
- Do alert thresholds exist for unusual AI API call patterns?
- Are AI API calls correlated with other host activity (file access, lateral movement)?
- Is high-entropy content in prompt fields flagged?

### Step 5: Assess credential/phishing risk

For organizations with AI-generated phishing threat:
- Have phishing detection systems been updated for AI-generated content? (grammar checks are inadequate)
- Are behavioral signals (link patterns, sender reputation, context anomalies) the primary detection mechanism?
- Is MFA resistant to phishing (hardware key or passkey)? SMS/TOTP are vulnerable to AI-generated real-time phishing.

### Step 6: Generate framework gap report

For each identified risk, declare the framework gap:
- Which control nominally applies?
- Why it is insufficient for this specific AI attack pattern?
- What a real control would require?

---

## Output Format

```
## AI Attack Surface Assessment

**Assessment Date:** YYYY-MM-DD
**Scope:** [systems/applications assessed]

### Surface Inventory
| Component | Type | External Input | Tool Use | Risk Level |
|-----------|------|---------------|----------|------------|
| [name] | [LLM app / MCP server / coding assistant] | [Yes/No] | [Yes/No] | [Critical/High/Medium/Low] |

### Prompt Injection Exposure
[Per component: injection surface score, current defenses, estimated bypass rate, recommended controls]

### MCP Trust Assessment
[Per installed MCP server: signed/unsigned, allowlist status, auth status, risk level]

### AI C2 Indicators
[Logging coverage, baseline status, detection gaps]

### Credential/Phishing Risk
[Detection system currency, MFA phishing resistance]

### ATLAS TTP Coverage Gaps
[Per TTP: covered/partial/missing in deployed security tools]

### Framework Gaps
[Per framework in scope: specific controls that fail for AI threats, with explanation]

### Prioritized Recommendations
[Ordered by RWEP impact: specific, actionable, accounts for real deployment constraints]
```

---

## Compliance Theater Check

> "Your security awareness training includes phishing detection. 82.6% of phishing emails now contain AI-generated content indistinguishable by grammar or style checks. Open your most recent phishing simulation report: what percentage of simulated phishes used AI-generated content? If zero, the simulation is testing resistance to 2021 phishing, not 2026 phishing. If your detection rule set has not been updated to reflect AI-generated content as the baseline, the control is theater for the threat it claims to address."

> "Your access control logs show no unauthorized access events involving your AI systems. Run this check: are your AI agent service account API calls logged with full request/response bodies? Are those logs monitored for behavioral anomalies? If AI API traffic is treated as trusted internal traffic with no behavioral monitoring, an attacker using AI-as-C2 (SesameOp technique) would not appear in your unauthorized access event log at all. Absence of evidence is not evidence of absence when the detection surface doesn't exist."
