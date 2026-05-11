---
name: zeroday-gap-learn
version: "1.0.0"
description: Run the zero-day learning loop — CVE to attack vector to control gap to framework gap to new control requirement
triggers:
  - zero day lesson
  - zeroday gap
  - what control gap enabled this
  - learn from exploit
  - exploit to control gap
  - what should have caught this
  - 0day learning
data_deps:
  - cve-catalog.json
  - zeroday-lessons.json
  - framework-control-gaps.json
  - atlas-ttps.json
atlas_refs: []
attack_refs: []
framework_gaps: []
forward_watch:
  - New CISA KEV entries
  - New ATLAS TTP additions in each ATLAS release
  - Framework updates that close previously open gaps
  - Vendor advisories for MCP/AI tool supply chain CVEs
last_threat_review: "2026-05-01"
---

# Zero-Day Learning Loop

Every significant zero-day is a test of the control landscape. The question is not only "how do we patch this?" — it is "what control, if it had existed and been implemented, would have prevented or detected this?" The answer tells us what frameworks are missing.

This skill runs the full learning loop: zero-day description → attack vector extraction → control gap identification → framework coverage assessment → new control requirement generation → exposure scoring.

---

## Threat Context (mid-2026)

The zero-day learning cycle has compressed. The frameworks have not.

- **41% of 2025 zero-days were discovered by attackers using AI-assisted reverse engineering** (AGENTS.md DR-5). Copy Fail (CVE-2026-31431) was AI-found in approximately one hour. The historical learning rhythm — researcher disclosure → industry analysis → framework update cycle measured in quarters or years — is incompatible with AI-discovery cadence measured in weeks.
- **The compounding consequence**: when a zero-day is announced, the relevant question is no longer "when will the patch ship?" but "what control, if it had existed, would have stopped this, and how do we add that control to the next thousand systems before the AI-generated variant lands?" Without a running learning loop, every novel TTP becomes a one-off incident response rather than a control-system improvement.
- **AI-acceleration also compresses variant generation.** A single disclosed primitive (Copy Fail's deterministic page-cache CoW; SesameOp's AI-API C2 channel) can be re-applied by AI tooling to adjacent code paths within days. Frameworks that only respond to specific CVE-IDs miss the class-level lesson entirely.
- **Compliance frameworks do not include zero-day learning as a required control category.** The "learn from incidents" language in NIST CSF 2.0 IMPROVE and ISO 27001:2022 A.5.7 is process-only, no required artifact. An org can be fully compliant while patching every CVE and learning nothing.

This skill exists because the gap between AI-accelerated zero-day production and framework-driven control evolution is the dominant mid-2026 risk multiplier.

---

## Framework Lag Declaration

Frameworks do not require a zero-day learning loop as a control. The closest analogs are process controls without learning artifacts.

| Framework | Control | What It Says | Why It Fails as a Learning Loop |
|---|---|---|---|
| NIST CSF 2.0 | IMPROVE function (ID.IM) | "Identify improvements to organizational cybersecurity risk management processes, procedures, and activities." | Process-level guidance only. Does not require: (a) per-zero-day attack-vector extraction, (b) framework-gap mapping, (c) new-control-requirement generation, (d) measurable closure of identified gaps. Compliance is satisfied by having "an improvement process" without showing it produced any specific control. |
| NIST 800-53 Rev 5 | CA-7 (Continuous Monitoring) + IR-4 (Incident Handling — Lessons Learned) | Lessons learned from incidents and continuous monitoring. | Lessons-learned is required after incidents, but not after public zero-days the org wasn't directly hit by. The most valuable learning surface — other people's incidents — is outside the control's scope. |
| ISO 27001:2022 | A.5.7 (Threat intelligence) | Information about information security threats shall be collected and analyzed. | Threat-intel collection is required; learning-loop output (new control requirements, framework-gap artifacts) is not. Process compliance with zero learning output is auditable as "compliant." |
| ISO 27001:2022 | A.5.27 (Learning from information security incidents) | Knowledge gained from incidents shall be used to strengthen controls. | Limited to incidents the org experienced. Does not require learning from industry-wide zero-days that didn't hit the org. |
| SOC 2 | CC4 (Monitoring Activities) | Ongoing/separate evaluations of internal controls. | Evaluation cadence is internal-controls focused, not threat-landscape focused. No requirement to re-evaluate controls against newly-disclosed TTPs. |
| NIS2 Directive | Art. 21 — incident handling and crisis management | Essential/important entities must handle incidents. | Same scope problem: incidents the org experienced, not zero-days landing across the sector. |
| MITRE ATT&CK / ATLAS | TTP catalogs | Reference taxonomies. | Not frameworks of required controls — they describe TTPs, they do not require an org to maintain a learning loop against them. |

Across all of these: **the learning loop is not a required control output, only an implied behavior.** An org can pass every audit while patching CVEs and absorbing zero TTP-level lessons.

---

## TTP Mapping

This skill is meta — it does not pin to a single TTP class. The learning loop iterates over the full corpus declared in this skill's `data_deps`. Frontmatter `atlas_refs` and `attack_refs` are intentionally empty.

| Input Catalog | Role in the Learning Loop |
|---|---|
| `data/cve-catalog.json` | The CVE-level corpus: each entry is a candidate lesson input. New entries trigger a new loop run per AGENTS.md DR-8. |
| `data/atlas-ttps.json` (MITRE ATLAS v5.1.0) | The AI/ML TTP taxonomy. Attack-vector extraction maps the CVE's mechanism to an ATLAS ID (e.g., AML.T0096 for SesameOp AI-as-C2). |
| `data/framework-control-gaps.json` | The control-gap corpus. Framework-coverage assessment writes into this file via new entries or `status` updates. |
| `data/zeroday-lessons.json` | The output corpus. Each completed loop produces one entry here — the durable artifact of the lesson. |

The skill consumes all four and produces a delta against `zeroday-lessons.json` and `framework-control-gaps.json`. Coverage of any one specific TTP is the responsibility of the topic-specific skills (`kernel-lpe-triage`, `ai-attack-surface`, `mcp-agent-trust`, `ai-c2-detection`).

---

## Exploit Availability Matrix

Status of the learning-loop entry for each CVE currently in `data/cve-catalog.json`:

| CVE | KEV | PoC | AI-Discovered / AI-Enabled | RWEP | Lesson-Entry Status in `zeroday-lessons.json` |
|---|---|---|---|---|---|
| CVE-2026-31431 (Copy Fail) | Yes | Yes (732-byte) | Yes (AI-discovered ~1h) | 90 | Complete — pre-run lesson encoded below; new control requirements CISA-KEV-RESPONSE-SLA, LIVE-PATCH-CAPABILITY, KERNEL-EXPLOITATION-DETECTION generated |
| CVE-2026-43284 (Dirty Frag — ESP/IPsec) | No | Yes (chain) | No | 38 | Complete — pre-run lesson encoded; new control requirements CRYPTO-SUBSYSTEM-INTEGRITY, PRE-PATCH-DISCLOSURE-RESPONSE generated |
| CVE-2026-43500 (Dirty Frag — RxRPC) | No | Yes (chain) | No | 32 | Complete — covered jointly with CVE-2026-43284 (chain partner) |
| CVE-2025-53773 (Copilot prompt-injection RCE) | No | Yes (demonstrated) | Yes (AI tooling enables) | 42 | Complete — pre-run lesson encoded; new control requirements AI-TOOL-ACTION-AUTHORIZATION, AI-TOOL-INPUT-SANITIZATION, PROMPT-INJECTION-MONITORING generated |
| CVE-2026-30615 (Windsurf MCP RCE) | No | Partial | No (supply-chain) | 35 | Complete — pre-run lesson encoded; new control requirements MCP-SERVER-SIGNING, MCP-TOOL-ALLOWLIST, MCP-SUPPLY-CHAIN-AUDIT generated |

Per AGENTS.md DR-8: every new entry added to `data/cve-catalog.json` must produce a corresponding entry here and in `data/zeroday-lessons.json` before the catalog change ships. Any CVE in the catalog without a complete lesson entry is a pre-ship-checklist failure.

---

## The Learning Loop

```
Input: zero-day (CVE ID, description, or vulnerability class)
   ↓
Step 1: Attack vector extraction
   — What technical mechanism was used?
   — What privileges were required?
   — What was the exploitation complexity?
   ↓
Step 2: Defense chain analysis
   — What control SHOULD have prevented this exploitation?
   — What control SHOULD have detected this exploitation?
   — Was that control in any major framework?
   — Was it typically implemented?
   ↓
Step 3: Framework coverage assessment
   — For each major framework: does it have a control that covers this?
   — Is the control adequate (specific enough, actionable enough)?
   — Or is the control present but insufficient (too vague, wrong time horizon)?
   ↓
Step 4: Gap classification
   — Missing entirely: no framework has a control for this attack class
   — Insufficient: controls exist but are inadequate for this specific TTP
   — Compliant-but-exposed: org can pass audit of the control and still be vulnerable
   ↓
Step 5: New control requirement generation
   — What specific, testable control would actually address this?
   — What evidence would demonstrate the control is working?
   ↓
Step 6: Exposure scoring
   — How many compliance-passing orgs are still exposed?
   — What is the RWEP for this zero-day?
Output: Lesson entry for data/zeroday-lessons.json
```

---

## Pre-Run Lessons (Encoded from Documented Zero-Days)

### Lesson: CVE-2026-31431 (Copy Fail)

**Attack vector:** Page-cache copy-on-write primitive in the Linux kernel. Unprivileged local user. Deterministic. No race condition. Single-stage. 732 bytes.

**What control should have prevented this:**
- Prevention: No local code execution → no LPE opportunity. But local code execution is baseline in any multi-user system or container environment. Prevention at this layer is not realistic.
- Mitigation before patch: seccomp profile blocking `userfaultfd`, user namespace restrictions, kernel hardening. These reduce attack surface but do not eliminate it.
- Patch: Apply kernel update. Live patching (kpatch/livepatch/kGraft) enables patching without service interruption.

**What control should have detected this:**
- Detection: auditd/eBPF monitoring for exploitation patterns — privilege escalation from unprivileged context, unusual /proc/self/mem writes, userfaultfd usage outside known applications.
- None of these are required by any major framework.

**Framework coverage assessment:**

| Framework | Control | Assessment |
|---|---|---|
| NIST 800-53 SI-2 | Flaw Remediation | Present but insufficient: 30-day SLA is exploitation window for CISA KEV + public PoC |
| ISO 27001 A.8.8 | Technical vulnerability management | Present but insufficient: "appropriate timescales" undefined; no live-patch requirement |
| PCI DSS 6.3.3 | Critical patches within 1 month | Present but insufficient: same problem |
| ASD ISM-1623 | Patch within 48h with exploit | Closest to adequate, but: no live-patch mandate, 48h window still long for 732-byte public exploit |
| Any framework | Detection for LPE exploitation patterns | Missing entirely: no framework requires auditd/eBPF exploitation detection |
| Any framework | Live kernel patching as required capability | Missing entirely |

**New control requirements generated:**

1. **CISA-KEV-RESPONSE-SLA**: For any CVE on the CISA KEV catalog: deploy verified mitigation (patch, live patch, or documented compensating controls) within 4 hours of KEV listing or patch availability, whichever is later.

2. **LIVE-PATCH-CAPABILITY**: For any system that processes production workloads and cannot tolerate unplanned reboots: live kernel patching capability (kpatch, livepatch, kGraft, or equivalent) must be deployed and tested quarterly.

3. **KERNEL-EXPLOITATION-DETECTION**: Deploy auditd or eBPF-based monitoring rules for kernel privilege escalation indicators. Alert within 60 seconds of pattern detection.

**Exposure scoring:**
- RWEP: 90 (current, with patch+live-patch available)
- Organizations compliant with standard patch management controls but still exposed: estimated 80%+ during the first week after KEV listing (based on industry patch deployment lag data)
- Coverage failure: standard controls allow full exploitation window while displaying "compliant" status

---

### Lesson: CVE-2026-43284/43500 (Dirty Frag)

**Attack vector:** Page-cache write primitive chain through ESP/IPsec (CVE-2026-43284) and RxRPC (CVE-2026-43500) subsystems. Chained — requires fingerprinting to select correct gadget. Disclosed before patches existed.

**What control should have prevented/detected this:**
- Critical insight: the exploitation path runs through the IPsec subsystem → controls that rely on IPsec for network isolation are not compensating controls for Dirty Frag exposure

**New control requirements generated:**

1. **CRYPTO-SUBSYSTEM-INTEGRITY**: Network controls claiming compliance via IPsec must include: kernel CVE status for IPsec-related CVEs, and explicit acknowledgment if IPsec-based controls are degraded by an unpatched IPsec CVE.

2. **PRE-PATCH-DISCLOSURE-RESPONSE**: For vulnerabilities disclosed before patches exist: immediately inventory affected systems, isolate high-risk systems at network layer, deploy detection rules, commit to patch timeline.

---

### Lesson: CVE-2025-53773 (GitHub Copilot Prompt Injection RCE)

**Attack vector:** Hidden prompt injection in GitHub Copilot PR descriptions. Developer reviews PR with Copilot → injected instructions execute in developer session → RCE. CVSS 9.6.

**What control should have prevented this:**
- Access control for AI tool actions: the developer's GitHub session was correctly authenticated. The RCE happened because the AI tool executed adversarial instructions with the developer's authorization context.
- There is no framework control for "AI tool authorization scope at the action level."

**New control requirements generated:**

1. **AI-TOOL-ACTION-AUTHORIZATION**: AI coding assistants must have explicitly scoped permissions. Any action taken by an AI tool (file write, terminal command, API call) requires explicit user approval unless within a pre-approved action whitelist. Implied authorization from context is insufficient.

2. **AI-TOOL-INPUT-SANITIZATION**: Content ingested by AI tools from external sources (PR descriptions, code comments, documentation, web pages) must be treated as potentially adversarial. AI tools should apply adversarial instruction classifiers to externally sourced content before including it in model context.

3. **PROMPT-INJECTION-MONITORING**: Log all AI tool actions, including the content of prompts that triggered those actions. Alert on AI actions that deviate from the user's stated intent or that weren't preceded by an explicit user request.

**Framework coverage:** Missing entirely in all major frameworks. CVSS 9.6 with active exploitation demonstrated and no framework control category for this attack class.

---

### Lesson: CVE-2026-30615 (Windsurf MCP Zero-Interaction RCE)

**Attack vector:** Malicious MCP server achieves RCE without user interaction. AI coding assistant autonomously calls malicious tool, code executes. 150M+ affected.

**New control requirements generated:**

1. **MCP-SERVER-SIGNING**: All MCP servers must have verifiable provenance (npm provenance attestation, signed manifest, or equivalent). AI coding assistants must refuse to load unsigned MCP servers.

2. **MCP-TOOL-ALLOWLIST**: AI clients must implement explicit tool allowlists. Default deny — only tools in the allowlist may be called, regardless of what the MCP server exposes.

3. **MCP-SUPPLY-CHAIN-AUDIT**: MCP server installations must go through the organization's third-party software audit process. Automated installation of MCP packages without review is equivalent to installing unaudited dependencies.

**Framework coverage:** Missing entirely. Supply chain security controls (SA-12, A.5.19) don't address MCP servers as a category.

---

### Lesson: SesameOp (ATLAS AML.T0096 — AI as C2)

**Attack vector:** Compromised host encodes C2 commands in LLM API prompt fields. Exfiltrated data returned in completion fields. Traffic indistinguishable from legitimate AI API usage.

**New control requirements generated:**

1. **AI-API-BEHAVIORAL-BASELINE**: All AI API usage from organizational networks must be baselined (which processes, which users, what volumes, what times). Deviations from baseline must trigger alerts.

2. **AI-API-PROCESS-ALLOWLIST**: Maintain an allowlist of processes authorized to make AI API calls. AI API calls from unlisted processes must alert.

3. **AI-API-CORRELATION**: Correlate AI API call events with security-relevant host events (file access, credential access, lateral movement). AI API calls correlated with security events within defined time windows must escalate.

**Framework coverage:** Missing entirely. SI-4 (system monitoring) and A.8.16 (monitoring activities) don't address AI API behavioral baselines.

---

## Analysis Procedure for New Zero-Days

When a user provides a new CVE or vulnerability description:

### Step 1: Extract attack vector

Document:
- What technical capability does the attacker need to execute this?
- What system components are used in the attack path?
- What is the exploitation complexity? (deterministic / race condition / heap spray / etc.)
- Is the exploit AI-assisted or AI-discovered?
- What is the blast radius? (specific config / default config / all major distros)

### Step 2: Defense chain analysis

Ask and answer:
1. **Prevention control:** What configuration, capability, or process would have prevented this exploit from being possible?
2. **Detection control:** What monitoring rule or anomaly detection would have fired during exploitation?
3. **Response trigger:** What evidence would appear in logs or alerts during/after exploitation?

For each: Is this control required by any major framework?

### Step 3: Framework coverage matrix

Run through each applicable framework:
- NIST 800-53 (which control family?)
- ISO 27001:2022 (which Annex A control?)
- SOC 2 (which trust service criterion?)
- PCI DSS 4.0 (which requirement?)
- NIS2 (which Art. 21 measure?)
- CIS Controls v8 (which control?)
- ASD Essential 8 (which mitigation?)
- ISO 27001:2022 (which control?)
- MITRE ATLAS v5.1.0 (which TTP? Is it covered?)

For each: Covered (adequate) / Covered (insufficient) / Missing entirely

### Step 4: Generate new control requirements

Write new control requirements in the format:
```
[CONTROL-ID]: [One-line control name]
Description: [Specific, testable requirement]
Evidence: [What demonstrates compliance]
Framework gap it closes: [Which framework controls are insufficient]
CVE evidence: [Which CVEs demonstrate this gap]
```

### Step 5: Calculate exposure score

Estimate: What percentage of organizations that pass audits of existing controls are still exposed to this vulnerability?

Use: Known patch deployment lag statistics + framework SLA vs. RWEP gap analysis.

### Step 6: Produce lesson entry

Format the output for addition to `data/zeroday-lessons.json`.

---

## Output Format

```
## Zero-Day Learning Loop: [CVE-ID / Vulnerability Name]

**Date:** YYYY-MM-DD
**RWEP:** [score]

### Attack Vector
[Extracted attack vector analysis]

### Defense Chain Analysis
| Layer | Required Control | Framework Coverage |
|---|---|---|
| Prevention | [control] | [Covered/Insufficient/Missing] |
| Detection | [control] | [Covered/Insufficient/Missing] |
| Response | [control] | [Covered/Insufficient/Missing] |

### Framework Coverage Matrix
[Per-framework table]

### Gap Classification
[Missing entirely / Insufficient / Compliant-but-exposed]

### New Control Requirements
[Generated requirements in standard format]

### Exposure Scoring
Estimated % of audit-passing orgs still exposed: [X]%
Reason: [RWEP vs. framework SLA gap analysis]

### Lesson Entry (for data/zeroday-lessons.json)
[Ready-to-add JSON entry]
```

---

## Compliance Theater Check

Run this check against any organization claiming a mature vulnerability-management or threat-intelligence program:

> "Pull the org's vulnerability-management runbook for the most recent five CISA-KEV-listed zero-days. For each: was the CVE patched? Almost certainly yes. Now ask the harder question: for each, where is the artifact that says (a) what attack vector this zero-day used, (b) what control would have caught it pre-patch, (c) which framework control was responsible for that detection/prevention, (d) was that framework control adequate, and (e) what new internal control requirement, if any, was created? If the answer is `we patched it, ticket closed` with no artifact, the program is patching CVEs and learning nothing. The next AI-generated variant of the same primitive will land against the same unchanged control surface. That is compliance theater for the threat-intel function — process compliance (A.5.7) with zero learning-loop output."

> "Open `data/zeroday-lessons.json` (or the org's equivalent). Count the entries. Compare to the count of CVEs the org actually responded to in the same period. If the lesson-entry count is < CVE-response count, the loop is partial. Per AGENTS.md DR-8, partial is failure: every zero-day-in-scope must produce a lesson entry. The gap between CVEs-patched and lessons-learned is the size of the theater. The org's `Improve` function (NIST CSF 2.0) is not running."

> "Ask: in the last 12 months, has a single internal control requirement been created or modified as a result of a public zero-day the org was NOT directly hit by? If no, the org's threat-intelligence control (ISO A.5.7) is consumption-only — collecting feeds, not changing controls. Threat-intel without control-system change is library subscription, not security capability."
