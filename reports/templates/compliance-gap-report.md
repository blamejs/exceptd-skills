---
report_type: compliance-gap-report
version: "1.0.0"
---

# Compliance Gap Report

**Date:** [YYYY-MM-DD]  
**Framework(s) in scope:** [NIST 800-53 / ISO 27001 / SOC 2 / PCI DSS / NIS2 / other]  
**Jurisdiction(s):** [list]  
**Assessed by:** exceptd Security — framework-gap-analysis, compliance-theater, global-grc skills  
**Classification:** [Confidential]

---

## Executive Summary

[3–5 sentences: what frameworks were assessed, how many gaps found, what the compliance theater score is, and the top priority remediation item.]

---

## Compliance Theater Score

**[X] / [Y] controls tested are theater (compliant on paper, exposed in practice)**

A compliance theater finding means: an auditor would mark this control as passing, but the control does not protect against the threat it nominally addresses.

| Theater Pattern | Finding | Evidence |
|---|---|---|
| Patch Management | THEATER / CLEAR | [specific evidence, e.g., "CISA KEV avg remediation: 18 days vs. required 4h"] |
| Network Segmentation (IPsec) | THEATER / CLEAR | |
| Access Control (AI Agents) | THEATER / CLEAR | |
| Incident Response (AI) | THEATER / CLEAR | |
| Change Management (Models) | THEATER / CLEAR | |
| Vendor Management (AI APIs) | THEATER / CLEAR | |
| Security Awareness (AI Phishing) | THEATER / CLEAR | |

---

## Framework Gap Analysis

### [Framework Name] — Gap Summary

| Control ID | Control Name | Status | Gap Description | Evidence CVE |
|---|---|---|---|---|
| [e.g., SI-2] | Flaw Remediation | Open | [why the control is insufficient] | [CVE ID] |
| | | | | |

---

## Universal Gaps (No Framework Covers)

The following threats are not adequately covered by any framework in scope as of mid-2026:

| Threat | Frameworks Assessed | Coverage Status |
|---|---|---|
| AI pipeline integrity | [list] | Missing entirely |
| MCP/agent tool trust boundaries | [list] | Missing entirely |
| Prompt injection as access control failure | [list] | Missing entirely |
| AI-as-C2 detection | [list] | Missing entirely |
| Live kernel patching requirement | [list] | Insufficient in all |
| Ephemeral infrastructure asset inventory | [list] | Insufficient in all |

---

## Policy Exceptions Recommended

For architectural realities that cannot meet standard control requirements:

| Control | Architectural Reality | Exception Basis | Compensating Controls |
|---|---|---|---|
| CM-8 / A.5.9 (Asset Inventory) | Ephemeral/serverless infrastructure | IaC as authoritative inventory | [list] |
| CM-3 / A.8.32 (Change Management) | Externally managed LLM updates | Model pinning + behavioral testing | [list] |
| SC-7 / A.8.22 (Network Segmentation) | Zero Trust Architecture | Identity-centric controls per NIST SP 800-207 | [list] |

[Attach policy exception documents from policy-exception-gen skill]

---

## Global Jurisdiction Matrix

[For multi-jurisdiction scope]

| Jurisdiction | Framework | Fastest Notification | Strictest AI Req | Current Gap |
|---|---|---|---|---|
| EU | GDPR + NIS2 | 24h (NIS2) | EU AI Act Art. 9 | [gap] |
| UK | NCSC CAF | 72h (GDPR/UK DPA) | — | [gap] |
| AU | ISM + Essential 8 | ASAP (NDB) | ISM-1623 (48h) | [gap] |
| SG | MAS TRM + CCoP | 2h (CCoP CII) | — | [gap] |
| IN | CERT-In | **6 hours** | — | [gap] |

---

## Remediation Roadmap

| Priority | Gap | Remediation | Owner | Timeline | Compliance Milestone |
|---|---|---|---|---|---|
| 1 | [highest impact gap] | [specific action] | [team] | [date] | [what it closes] |
| 2 | | | | | |

---

## Evidence Index

| Finding | Evidence Type | Location | Date Captured |
|---|---|---|---|
| [finding] | [scan output / config review / interview] | [file/system] | [date] |

---

## Auditor Notes

**For any auditor reviewing this report:**

The gaps identified in this report are not evidence of negligence. They are evidence of framework lag — the documented gap between when control frameworks were written and the threat environment they are operating in. The organization is compliant with the frameworks as written. The frameworks are insufficient for the threats that exist in mid-2026.

Evidence that the organization has identified these gaps, implemented compensating controls where possible, and is working toward a remediation roadmap is itself a positive indicator of a mature security program.

[Specific compensating control documentation attached: see policy exception documents]
