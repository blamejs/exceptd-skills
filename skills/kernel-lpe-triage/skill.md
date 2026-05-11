---
name: kernel-lpe-triage
version: "1.0.0"
description: Assess Linux kernel LPE exposure — Copy Fail, Dirty Frag, live-patch vs. reboot remediation paths, framework gap declarations
triggers:
  - kernel lpe
  - privilege escalation
  - copy fail
  - dirty frag
  - cve-2026-31431
  - cve-2026-43284
  - linux root
  - kernel patch
  - live kernel patch
data_deps:
  - cve-catalog.json
  - exploit-availability.json
atlas_refs: []
attack_refs:
  - T1068
  - T1548.001
framework_gaps:
  - NIST-800-53-SI-2
  - ISO-27001-2022-A.8.8
  - PCI-DSS-4.0-6.3.3
  - NIS2-Art21-patch-management
rfc_refs:
  - RFC-4301
  - RFC-4303
  - RFC-7296
cwe_refs:
  - CWE-416
  - CWE-672
  - CWE-787
d3fend_refs:
  - D3-ASLR
  - D3-EAL
  - D3-PHRA
  - D3-PSEP
last_threat_review: "2026-05-01"
---

# Kernel LPE Triage

## Threat Context (mid-2026)

### Copy Fail — CVE-2026-31431

**Classification:** Local Privilege Escalation | CISA KEV | AI-Discovered  
**CVSS:** 7.8 (High) | **RWEP:** 90/100

An AI system discovered this vulnerability in approximately one hour. It is a page-cache copy-on-write (CoW) primitive in the Linux kernel affecting all major distributions since kernel 4.14 (2017). Every major Linux distribution is affected: RHEL 7–9, Ubuntu 18.04–24.04, Debian 9–12, CentOS, Fedora, Amazon Linux 2/2023, SUSE 12/15, Alpine, and derivatives.

Key characteristics that make this exceptional:
- **Deterministic exploitation** — no race condition, no heap spray, no timing sensitivity
- **Single-stage** — 732-byte script achieves root from unprivileged user in one step
- **No privileges required** — accessible from any unprivileged container or local user
- **No user interaction** — fully automated
- **CISA KEV listed** — active exploitation confirmed in the wild

The attack abuses a write primitive in the copy-on-write path of the page cache. An attacker with any local code execution can reliably escalate to root. In containerized environments without proper namespace isolation, this means container escape.

**What SI-2 says:** "Identify, report, and correct information system flaws; install security-relevant software updates within organizationally defined time periods."  
**Why SI-2 fails here:** The control is operationalized as a patch cycle (typically 30 days for High, 7 days for Critical). Copy Fail has a public PoC, is CISA KEV listed, and takes 732 bytes and zero expertise to exploit. The 30-day window is not a security window — it is an exploitation window.

---

### Dirty Frag — CVE-2026-43284 + CVE-2026-43500

**Classification:** Local Privilege Escalation Chain | Breaks IPsec Mitigations  
**CVSS:** 7.8 (High) | **RWEP:** 38/100

Discovered by Hyunwoo Kim. A two-CVE chain exploiting page-cache write primitives in:
- ESP/IPsec subsystem (CVE-2026-43284)
- RxRPC subsystem (CVE-2026-43500)

Key characteristics:
- **Disclosed before patches existed** — no coordinated disclosure window observed
- **Single command** — root access via one-line invocation
- **Breaks IPsec** — the exploit path runs through the IPsec subsystem, meaning the exploit actively compromises the IPsec subsystem as it runs. Controls that rely on IPsec for network isolation cannot be considered mitigating controls for this vulnerability.
- **Chained primitive** — more sophisticated than Copy Fail; requires kernel version fingerprinting to select the right gadget chain

The IPsec dimension is critical: organizations with network segmentation controls implemented via IPsec tunnels cannot claim those controls mitigate Dirty Frag exposure. The exploitation path breaks those controls.

**What SC-8 (Transmission Confidentiality and Integrity) says:** Implement cryptographic mechanisms to prevent unauthorized disclosure during transmission.  
**Why SC-8 fails here:** Dirty Frag exploits the IPsec implementation itself. SC-8 compliance via IPsec does not mitigate an LPE that runs through the IPsec subsystem.

---

## Framework Lag Declaration

| Framework | Control | Designed For | Fails Because |
|---|---|---|---|
| NIST 800-53 Rev 5 | SI-2 Flaw Remediation | Network-centric patch cycles, 2013–2020 era | "Timely" is undefined for instant-root deterministic LPEs with public PoC. 30-day window = exploitation window. |
| NIST 800-53 Rev 5 | SC-8, SC-28 | Network/storage encryption via standard protocols | Dirty Frag exploits IPsec implementation — SC-8 controls via IPsec are not compensating controls for CVE-2026-43284 |
| ISO 27001:2022 | A.8.8 Management of technical vulnerabilities | Patch management timelines defined by risk classification | No framework for kernel-specific live patching vs. reboot requirement. "Appropriate timescales" undefined for CISA KEV + public PoC. |
| PCI DSS 4.0 | 6.3.3 | Critical patches within 1 month, all others within 3 months | 1-month window for a 732-byte public PoC is operationally indefensible. No guidance for live kernel patching on PCI-scoped systems. |
| NIS2 Directive | Art. 21 (vulnerability handling) | Systematic patch management for essential/important entities | No guidance on live kernel patching as a required capability. "Appropriate measures" undefined for CISA KEV LPEs. |
| CIS Controls v8 | Control 7 (Continuous Vulnerability Management) | Regular vulnerability scanning and patching | IG1/IG2/IG3 all recommend "remediate within one month" for critical — same problem as PCI. No live-patch framework. |
| ASD Essential 8 | Patch Operating Systems (Maturity 1–3) | Maturity 3: "within 48 hours" for critical with public exploit | Closest to adequate. ML3 "48 hours" with public exploit is approaching the right frame. Still no live-patch operationalization. |

**Spec layer vs. implementation layer.** Dirty Frag (CVE-2026-43284, CVE-2026-43500) exploits the Linux kernel's IPsec ESP implementation, not the underlying protocol specifications. The spec layer is defined by RFC 4301 (IPsec architecture), RFC 4303 (ESP datagram format), and RFC 7296 (IKEv2) — see `data/rfc-references.json` for status and errata. NIST 800-53 SC-8 and equivalent transmission-confidentiality controls implicitly cite this RFC family but do not operationalize the gap between *spec compliance* and *kernel-implementation safety*: an IPsec deployment can be fully RFC-conformant and still expose root via the ESP path. Auditors evaluating IPsec controls must ask whether the kernel is patched against CVE-2026-43284/-43500, not just whether the spec is followed.

---

## TTP Mapping (MITRE ATT&CK Enterprise, mid-2026)

Each CVE class in this skill maps to ATT&CK technique IDs declared in frontmatter (`T1068`, `T1548.001`). Gap flags identify which standard controls fail against the specific TTP variant — these are the controls a compliance-passing org will rely on, and which the exploit walks past.

| CVE Class | ATT&CK Technique | Sub-Technique / Variant | Gap Flag (Controls That Fail) |
|---|---|---|---|
| CVE-2026-31431 (Copy Fail) | T1068 — Exploitation for Privilege Escalation | Page-cache CoW write primitive; deterministic, single-stage; no race | NIST 800-53 SI-2 30-day SLA (exploitation window for 732-byte public PoC); ISO 27001:2022 A.8.8 "appropriate timescales" undefined for CISA KEV; PCI DSS 4.0 6.3.3 1-month critical window is indefensible; CIS Controls v8 Control 7 IG3 "within one month" identical failure |
| CVE-2026-31431 (Copy Fail — container escape variant) | T1611 — Escape to Host | Privileged container or shared host namespace + Copy Fail = host root | NIST 800-53 SC-39 (Process Isolation) assumes kernel boundary is intact; Copy Fail breaks it. No framework requires kernel CVE status be tracked as a precondition for container isolation claims. |
| CVE-2026-43284 (Dirty Frag — ESP/IPsec) | T1068 — Exploitation for Privilege Escalation | Chained page-cache write through ESP/IPsec; requires kernel fingerprinting | NIST 800-53 SC-8 (Transmission Confidentiality) when implemented via IPsec — control runs through the vulnerable subsystem and cannot be claimed as compensating; NIS2 Art. 21 "appropriate measures" silent on crypto-subsystem-CVE → control-degradation linkage |
| CVE-2026-43500 (Dirty Frag — RxRPC) | T1068 — Exploitation for Privilege Escalation | Chain component via RxRPC subsystem | ISO 27001:2022 A.8.8 — no requirement to inventory loaded kernel modules against active CVE chains; ASD Essential 8 ML3 48h-with-exploit window still long for chained public PoC |
| Both classes (post-exploit token abuse) | T1548.001 — Abuse Elevation Control Mechanism: Setuid and Setgid | Setuid binary or capability abuse following LPE foothold | NIST 800-53 AC-6 (Least Privilege) assumes UID boundary holds; after T1068 root, AC-6 audit trail shows legitimate root actions — control surface is gone |
| Both classes (detection gap) | T1068 (detection) | auditd/eBPF coverage for `userfaultfd`, `/proc/self/mem` writes, unprivileged-userns-clone | Missing entirely — no framework (NIST, ISO, PCI, NIS2, CIS, Essential 8) requires kernel-LPE exploitation-pattern detection rules. Detection-as-compensating-control claims are unverifiable without these rules. |

Note: ATLAS refs are intentionally empty in frontmatter — these are Linux kernel LPEs, not AI/ML TTPs. Cross-cutting AI-discovery context (Copy Fail was AI-found in ~1h) is captured in the Threat Context section, not via an ATLAS TTP ID.

---

## Exploit Availability Matrix

| CVE | CVSS | RWEP | CISA KEV | PoC Public | AI-Discovered | Active Exploitation | Patch Available | Live Patch | Reboot Required |
|---|---|---|---|---|---|---|---|---|---|
| CVE-2026-31431 (Copy Fail) | 7.8 | 90 | Yes (2026-03-15) | Yes — 732-byte script | Yes | Confirmed | Yes | Yes (kpatch/livepatch/kGraft) | Yes |
| CVE-2026-43284 (Dirty Frag ESP) | 7.8 | 38 | No | Yes | No | Suspected | Yes | No (kpatch RHEL-only) | Yes |
| CVE-2026-43500 (Dirty Frag RxRPC) | 7.6 | 81 | No | Yes (chain component) | No | Suspected | Yes | Partial (kpatch) | Yes if no live patch |

---

## Analysis Procedure

When a user invokes this skill, perform this assessment in order:

### Step 1: Inventory the environment

Ask for or assess:
- Linux distribution and version
- Kernel version (`uname -r`)
- Deployment model: bare metal / VM / container / serverless
- Existing live-patching capability: kpatch (RHEL), livepatch (Ubuntu), kGraft (SUSE), or none
- Whether IPsec is used for any network segmentation or encryption controls
- Current patch management SLA (how many days for Critical/High CVEs)
- Whether systems can tolerate a reboot (and when)

### Step 2: Determine exposure

**Copy Fail (CVE-2026-31431):**
```
Exposed if: kernel >= 4.14 AND kernel < [patched version for distribution]
Patched versions:
  RHEL 8/9:        kernel-4.18.0-553.xx.el8 / kernel-5.14.0-427.xx.el9
  Ubuntu 22.04:    linux-image-5.15.0-xxx (check USN-7xxx)
  Ubuntu 24.04:    linux-image-6.8.0-xxx (check USN-7xxx)
  Debian 12:       6.1.xxx (check DSA-5xxx)
  Amazon Linux 2:  kernel 5.10.xxx (check ALAS-2026-xxx)
  SUSE 15:         kernel 5.14.xxx (check SUSE-SU-2026:xxx)
```

**Dirty Frag (CVE-2026-43284/43500):**
```
Exposed if: IPsec or RxRPC modules loaded AND kernel < patched version
Check: lsmod | grep -E 'esp|xfrm|rxrpc'
Additional exposure: any IPsec-based network control becomes unreliable
```

### Step 3: Score exposure level

| Condition | Exposure Level |
|---|---|
| Kernel unpatched + no live patch + public internet access | Critical |
| Kernel unpatched + no live patch + internal only | High |
| Kernel unpatched + live patch deployed | Medium (verify live patch applied: `kpatch list` or `canonical-livepatch status`) |
| Kernel patched but reboot pending | Medium |
| Kernel patched + rebooted | Low |
| Containerized + privileged mode or host PID namespace | Add one severity level |
| IPsec used for network controls + CVE-2026-43284 unpatched | Add: "IPsec controls not compensating for Dirty Frag" |

### Step 4: Generate remediation path

**If live patching is available and system cannot tolerate reboot:**
1. Deploy live kernel patch immediately (kpatch/livepatch/kGraft)
2. Verify patch applied: `kpatch list` / `canonical-livepatch status`
3. Schedule reboot at next maintenance window to apply full kernel update
4. Document: "Live patch deployed YYYY-MM-DD; full patch pending reboot at [maintenance window]"

**If no live patching available and system cannot tolerate reboot:**
1. Compensating controls (reduce blast radius, do not eliminate exposure):
   - Seccomp profile restricting `userfaultfd`, `TIOCCONS`, and page-cache-adjacent syscalls
   - User namespace restrictions (`sysctl -w kernel.unprivileged_userns_clone=0` where supported)
   - Network-level isolation of affected hosts
   - Enhanced monitoring: eBPF/auditd rules for exploitation patterns (see detection section)
2. Document as open risk with compensating controls and reboot timeline
3. CISA KEV listing requires documented remediation or mitigation with timeline

**If system can tolerate reboot:**
1. Apply kernel update immediately
2. Reboot to load new kernel
3. Verify: `uname -r` shows patched version

**For containerized workloads:**
- The container host kernel determines exposure — container image patching is irrelevant
- Privileged containers with Copy Fail exposed = host root exposure
- Apply host kernel patch or live patch
- Remove `--privileged` and shared host namespaces from containers where possible

### Step 5: Compliance theater check

Run this check for any org claiming patch management compliance:

> "Your patch management control (SI-2 / A.8.8 / PCI 6.3.3) documents a 30-day remediation window for Critical/High CVEs. CVE-2026-31431 (Copy Fail) is CISA KEV listed with a public 732-byte exploit script requiring no privileges. What is the actual time between CISA KEV listing (2026-03-15) and confirmed patch-or-mitigate? If it exceeds 72 hours without live patching as a deployed capability, the patch management control is theater for CISA KEV class vulnerabilities."

### Step 6: Assess IPsec dependency

If the organization uses IPsec for any of the following, flag explicitly:
- Network segmentation between security zones
- Encryption of inter-host traffic
- VPN tunnels for site-to-site connectivity
- Compliance with SC-8 or equivalent

Flag: "Dirty Frag (CVE-2026-43284) exploits the IPsec implementation. Network controls relying on IPsec cannot be claimed as compensating controls for this vulnerability. These controls should be noted in the risk assessment as providing reduced assurance until CVE-2026-43284 is fully patched."

---

## Output Format

Produce this structure:

```
## Kernel LPE Exposure Assessment

**Assessment Date:** YYYY-MM-DD  
**Kernel Version:** x.x.x  
**Distribution:** [name + version]

### Exposure Summary
| CVE | Status | Severity |
|-----|--------|----------|
| CVE-2026-31431 (Copy Fail) | [Exposed / Live-patched / Patched] | [Critical/High/Medium/Low] |
| CVE-2026-43284 (Dirty Frag ESP) | [Exposed / Patched] | [Critical/High/Medium/Low] |
| CVE-2026-43500 (Dirty Frag RxRPC) | [Exposed / Patched] | [Critical/High/Medium/Low] |

### IPsec Control Impact
[If applicable: which network controls are affected by Dirty Frag]

### Remediation Path
[Live patch or full patch instructions for this specific distro/version]

### Compensating Controls (if no-reboot required)
[Specific sysctl settings, seccomp profiles, monitoring rules]

### Framework Gap Declaration
[Per-framework statement of what the org's patch management control covers and where it falls short]

### Compliance Theater Check Result
[Date of CISA KEV listing vs. date of remediation — theater flag if > 72h without live patch capability]

### RWEP Scores
CVE-2026-31431: CVSS 7.8 / RWEP 90 — immediate action required (4h)
CVE-2026-43284: CVSS 7.8 / RWEP 38 — remediate within 7 days; disable RxRPC/IPsec chain if not required
CVE-2026-43500: CVSS 7.6 / RWEP 32 — remediate within 7 days; consider disabling RxRPC module
```

---

## Detection Rules

If patching is delayed, deploy these detection rules:

**auditd — Copy Fail exploitation pattern:**
```
-a always,exit -F arch=b64 -S userfaultfd -k lpe_attempt
-a always,exit -F arch=b64 -S process_vm_writev -k lpe_attempt
-w /proc/self/mem -p w -k lpe_mem_write
```

**sysctl hardening (reduce attack surface, not a full mitigation):**
```
kernel.unprivileged_userns_clone = 0
kernel.perf_event_paranoid = 3
kernel.kptr_restrict = 2
vm.unprivileged_userfaultfd = 0
```

**Monitoring alert:** Any unprivileged process writing to `/proc/[pid]/mem` or invoking `userfaultfd` outside of a known application allowlist should be treated as a potential LPE attempt.

---

## Hand-Off / Related Skills

After producing the kernel LPE triage output, the operator should chain into the following skills. Each entry names a downstream or sibling skill and the specific reason to invoke it from this finding.

- **`exploit-scoring`** — recalculate RWEP when any of the inputs that drive the score change post-triage: a new CISA KEV listing for Dirty Frag, a public PoC for CVE-2026-43500's RxRPC leg, or an AI-discovery flag flip. RWEP, not CVSS, is the prioritisation signal — re-run scoring rather than re-reading the static value in the matrix above.
- **`defensive-countermeasure-mapping`** — map each kernel LPE finding to D3FEND counters (D3-EAL for executable allowlisting at the kernel-module layer, D3-ASLR for address-space layout randomisation hardening, D3-PSEP for process self-modification prevention, D3-PHRA for process hardening / runtime attestation) and produce the defence-in-depth, least-privilege, zero-trust layered remediation plan rather than a single-control patch ticket.
- **`attack-surface-pentest`** — verify that the kernel LPE class is in the organisation's pen-test scope (TIBER-EU / DORA TLPT for EU financial-sector orgs, CBEST for UK financial, or the equivalent red-team programme). Most 2025-vintage pen-test scopes are perimeter / web-app focused and do not exercise local LPE primitives against the patched-kernel claim.
- **`compliance-theater`** — test whether the org's SI-2 / A.8.8 / PCI 6.3.3 patch-management evidence is CVSS-anchored theater for a KEV-listed, AI-discovered, 732-byte deterministic LPE. The 30-day window is the exploitation window; if the org cannot show live-patch-within-4-hours capability or documented compensating controls, the patch-management control is theater for this CVE class.
- **`policy-exception-gen`** — generate a defensible exception for ephemeral container workloads where the 30-day patch window is architecturally impossible (per AGENTS.md rule #9): immutable image fleets, short-lived serverless functions, and Knative-style scale-to-zero workloads cannot accept a runtime patch and must instead document the compensating controls (host-kernel patched, seccomp profile, namespace isolation, unprivileged-userns disabled) as the exception evidence.
