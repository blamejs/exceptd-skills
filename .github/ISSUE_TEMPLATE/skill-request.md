---
name: Skill Request
about: Propose a new skill (for DPOs, GRC analysts, pentesters, incident responders, and security researchers — no code required)
title: "[skill-request] <short title>"
labels: skill-request
assignees: ''
---

You do not need to write a `skill.md` to contribute. Fill out the sections below in
plain language and a maintainer will convert this into a skill file. You will be
credited in `CHANGELOG.md` and the skill's frontmatter.

See `CONTRIBUTING.md` for the full "Contributing Without Writing Code" guide.

## Threat scenario (plain language)

What is the attack? Who is the attacker, who is the target, what does the attacker
gain? Describe the operational reality — what someone defending against this would
actually see.

<!-- e.g. "An attacker poisons a public HuggingFace model that is silently pulled
by a CI build of a customer support agent. The poisoned model exfiltrates the
contents of system prompts via crafted refusal messages." -->

## Evidence

Provide at least one of: CVE IDs, MITRE ATLAS TTP IDs, MITRE ATT&CK technique IDs,
documented public incidents, or framework control IDs that fail to cover this.
No hypotheticals — real-world grounding is required (AGENTS.md hard rule #1).

- **CVE(s):**
- **ATLAS TTP(s) (v5.1.0):**
- **ATT&CK technique(s):**
- **Public incidents / write-ups:**
- **Framework control IDs implicated:**

## Why current frameworks do not cover this

Which framework controls *would* be cited as relevant by an auditor, and why are
they insufficient for *this specific* TTP? Cite the framework version and the
original intent of the control. (AGENTS.md DR-1: framework-as-truth drift.)

<!-- e.g. "SOC 2 CC6.1 governs logical access controls for IAM. It does not
contemplate context-window exfiltration via crafted model outputs, which achieves
equivalent unauthorized disclosure without an IAM event." -->

## Affected jurisdictions and industries

Per AGENTS.md hard rule #5 (global-first, not US-centric), name the jurisdictions
and industries most exposed. Include at least one of EU (NIS2/DORA/EU AI Act), UK
(CAF), AU (ISM/Essential 8), or ISO 27001:2022 alongside any US references.

- **Jurisdictions:**
- **Industries / sectors:**
- **Regulatory regimes most exposed:**

## Compliance theater check (optional but valued)

A concrete test that would distinguish paper compliance from real security against
this threat. "Ask the auditor whether X is covered" is not concrete. "Run command Y
and cross-reference Z" is concrete. (AGENTS.md hard rule #8.)

## Anything else

Links, prior art, related skills already in the repo, dissenting opinions on
severity, etc.
