---
report_type: zero-day-response
version: "1.0.0"
---

# Zero-Day Response Report

**Date:** [YYYY-MM-DD]  
**CVE:** [CVE-ID]  
**Common Name:** [e.g., Copy Fail]  
**CVSS:** [score] [severity]  
**RWEP:** [score] / 100  
**Response Required By:** [4h / 24h / 72h — based on RWEP]  
**Incident Commander:** [name]  
**Classification:** [Confidential — Restricted to incident response team]

---

## Situation

**What happened:** [Plain language description of the vulnerability. What does it allow an attacker to do?]

**Who is affected:** [Scope — all Linux systems since 2017? Specific distros? AI coding tools?]

**Current exploitation status:** [CISA KEV confirmed / Suspected / No public evidence]

**PoC availability:** [Public / Private / Not known]

**AI-accelerated risk:** [If AI-discovered or AI-assisted: note the compressed weaponization timeline]

---

## RWEP Factor Breakdown

| Factor | Value | Points |
|---|---|---|
| CISA KEV | [Yes/No] | [+25/0] |
| PoC Public | [Yes/No] | [+20/0] |
| AI-Assisted | [Yes/No] | [+15/0] |
| Active Exploitation | [Confirmed/Suspected/No] | [+20/+10/0] |
| Blast Radius | [description] | [0-15] |
| Patch Available | [Yes/No] | [-15/0] |
| Live Patch Available | [Yes/No] | [-10/0] |
| Reboot Required | [Yes/No] | [+5/0] |
| **RWEP Total** | | **[score]** |

**Required Response Timeline:** [4 hours / 24 hours / 72 hours]

---

## Affected Systems Inventory

| System | Kernel Version | Distro | Exposed | Live Patch Available | Action Required |
|---|---|---|---|---|---|
| [hostname/service] | [version] | [distro] | [Yes/No] | [Yes/No] | [immediate action] |

---

## Response Timeline

### Within [4h / 24h] — Immediate Actions

- [ ] Deploy live kernel patch on exposed systems (if available)
  - RHEL: `kpatch install [patch-name]`
  - Ubuntu: `canonical-livepatch enable` + verify `canonical-livepatch status`
  - SUSE: `kGraft apply [patch-name]`
- [ ] Verify patch applied: `kpatch list` shows the patch active
- [ ] For systems without live patch capability: implement network isolation
- [ ] Deploy detection rules (see below)
- [ ] Notify affected system owners
- [ ] Document: live patch deployed at [timestamp] by [name]

### Within [24h / 72h] — Remediation

- [ ] Schedule maintenance windows for full kernel patch + reboot on live-patched systems
- [ ] Systems that cannot be live-patched: assess isolation vs. emergency reboot
- [ ] Update patch management records
- [ ] Notify CISO with status update

### Maintenance Window — Full Patch

- [ ] Apply full kernel update: [specific package for distro/version]
- [ ] Reboot: verify new kernel is loaded with `uname -r`
- [ ] Verify patch in place: cross-reference `uname -r` against patched version table
- [ ] Close exception if a compensating-controls exception was issued
- [ ] Update `data/exploit-availability.json` with remediation date

---

## Detection Rules — Deploy Now

### auditd rules (Copy Fail class)

```bash
# Add to /etc/audit/rules.d/lpe-detection.rules
-a always,exit -F arch=b64 -S userfaultfd -k lpe_attempt
-a always,exit -F arch=b64 -S process_vm_writev -k lpe_attempt
-w /proc/self/mem -p w -k lpe_mem_write

# Reload: augenrules --load
```

### sysctl hardening (compensating, not a full mitigation)

```bash
sysctl -w vm.unprivileged_userfaultfd=0
sysctl -w kernel.unprivileged_userns_clone=0
# Make permanent: add to /etc/sysctl.d/99-lpe-hardening.conf
```

### Alert on exploitation indicators

```
Alert: Any process executing with UID=0 where parent process was UID!=0 
       AND no su/sudo/pkexec in the execution chain
Severity: Critical
Action: Immediate isolation of affected host
```

---

## Compliance Impact

### Controls Affected

| Control | Framework | Impact | Action |
|---|---|---|---|
| SI-2 (Patch Management) | NIST 800-53 | Theater: 30-day SLA doesn't apply to CISA KEV | Document RWEP-based response in exception record |
| A.8.8 (Vulnerability Management) | ISO 27001:2022 | Same | |
| [control] | [framework] | | |

### Exception Document Required

If a production system cannot be patched within the RWEP-required timeline:
Generate a policy exception using the policy-exception-gen skill with:
- Exception type: "Critical Systems — No-Reboot Kernel Patching"
- CVE ID: [CVE-ID]
- Compensating controls: [list of detection rules and network isolation deployed]
- Reboot timeline: [scheduled maintenance window date]

---

## Communication Plan

| Audience | Message | Channel | By When |
|---|---|---|---|
| Incident Response Team | Technical brief + immediate actions | [channel] | Now |
| System Owners | "Your system [X] is affected. Action required by [time]." | [channel] | [time] |
| CISO | Status: [X] systems exposed, [Y] patched, [Z] pending | [channel] | [time] |
| [If CISA KEV applies — US federal agencies] | CISA BOD compliance response | [official channel] | Per BOD deadline |

---

## Post-Incident Review

After all systems are patched:
1. Run zeroday-gap-learn on [CVE-ID] to extract the control gap lesson
2. Update compliance-theater Pattern 1 if patch management theater was confirmed
3. Document: time from CISA KEV listing to verified remediation (benchmark for future response SLA)
4. If >72h from KEV listing to live-patch: recommend live patching capability investment
