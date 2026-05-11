# exceptd Security — Development Standards

> **This is the canonical development guide and the only project-rules file shipped in this repo.** It is AI-system-agnostic — internal citations throughout the repo all reference `AGENTS.md` (this file). The project does NOT ship per-vendor mirrors; tool users configure their tool to load `AGENTS.md`. Multiple tools auto-load `AGENTS.md` directly under the cross-vendor convention (OpenAI Codex CLI, Sourcegraph amp, Aider, Continue, Cline, Roo Code, Q Developer). Cursor (`.cursorrules`), GitHub Copilot (`.github/copilot-instructions.md`), and Windsurf (`.windsurfrules`) get small pointer stubs that reference this file. Claude Code / Gemini CLI / JetBrains AI / Replit Agent users should add `AGENTS.md` to their tool's context manually (Claude Code: `@AGENTS.md`, or symlink their own local `~/.claude/CLAUDE.md` to it).

Also read [CONTEXT.md](CONTEXT.md) for a complete orientation to the skill system.

## Hard Rules

1. **No stale threat intel** — Every CVE reference must include: CVSS score, KEV status, PoC availability, AI-discovery flag, active exploitation status, and patch/live-patch availability. No theoretical vulnerabilities without real-world grounding.

2. **Framework lag is a first-class concept** — Every skill must explicitly declare which framework controls are insufficient for the threats it covers. Never imply a framework control is adequate when current TTPs bypass it.

3. **No CVSS-only risk scoring** — CVSS is a severity metric, not a risk metric. Every risk score uses the Real-World Exploit Priority (RWEP) model defined in `lib/scoring.js`. CVSS is reported alongside RWEP for compatibility, never as the sole score.

4. **No orphaned controls** — Every control recommendation maps to a real attacker TTP in `data/atlas-ttps.json` or `data/cve-catalog.json`. Controls without a mapped threat are removed, not kept for completeness.

5. **Global-first, not US-centric** — Every framework gap analysis includes at least EU (NIS2/DORA/EU AI Act), UK (CAF), AU (ISM/Essential 8), and ISO 27001:2022 alongside NIST references. US-only analysis is incomplete.

6. **Zero-day learning is live** — `data/zeroday-lessons.json` is updated whenever a new CVE in scope is added to `data/cve-catalog.json`. The learning loop (zero-day → attack vector → control gap → framework gap → new control requirement) runs completely, not partially.

7. **Skill files are instructions, not descriptions** — Each `skill.md` tells the AI assistant exactly how to perform the analysis: what questions to ask, what data to pull, how to score, what to output. Generic "assess security posture" language is not a skill.

8. **Compliance theater detection is mandatory** — Every skill that touches a compliance framework must include a compliance theater check: a specific question or test that distinguishes paper compliance from actual security.

9. **Ephemeral and AI-pipeline realities are first-class** — Never recommend controls that are architecturally impossible for serverless, container, or AI pipeline environments without providing an explicitly scoped alternative.

10. **No placeholder data** — `data/*.json` files contain real CVE metadata, real ATLAS TTP IDs, real framework control IDs. Placeholder entries (`"tbd"`, `"coming soon"`, empty arrays where data exists) fail the pre-ship check.

11. **No-MVP ban** — A half-implemented skill is worse than no skill. Every shipped skill has: complete frontmatter, all required body sections, real data deps populated, a compliance theater check, and a concrete output format. Partial skills are not merged — they are finished or removed.

12. **External data version pinning** — Every reference to external data (MITRE ATLAS, NIST frameworks, CISA KEV, IETF RFCs and Internet-Drafts) must pin to a specific version. When a new version is released: (a) audit for breaking changes (renamed TTPs, replaced RFCs, deprecated controls), (b) bump `last_threat_review` in all affected skills, (c) update `_meta` version fields in the relevant `data/*.json` file, (d) update `last_verified` on affected `data/rfc-references.json` entries, (e) never silently inherit version changes. Frameworks lag RFCs; RFCs lag attacker innovation — skills must track lag at every layer. Current pinned ATLAS version: v5.1.0 (November 2025). The IETF RFC / Internet-Draft catalog lives at `data/rfc-references.json`; each entry tracks status, errata count, replaces / replaced-by, and `last_verified`.

13. **Skill integrity verification** — Every skill in `manifest.json` carries an Ed25519 `signature` (base64) and a `signed_at` timestamp covering its `skill.md` content. `lib/verify.js` checks each signature against the public key at `keys/public.pem` before any skill is loaded by the orchestrator. Tampered or unsigned skills are rejected. The private key at `.keys/private.pem` is gitignored and never enters the repo. Run `node lib/verify.js` (or `npm run verify`) before shipping; sign new or changed skills with `npm run bootstrap` for first-run, or `node lib/sign.js sign-all` after content changes.

---

## Recurring Drift Rules

**DR-1: Framework-as-truth drift**
Wrong: "SOC 2 CC6.1 covers access control for this threat."
Right: "SOC 2 CC6.1 defines logical access controls for on-prem/cloud IAM. It does not cover prompt injection as an access control bypass vector, which achieves equivalent unauthorized access via the model's context window."

**DR-2: CVSS-as-risk drift**
Wrong: "CVSS 7.8 High — remediate within 30 days."
Right: "CVSS 7.8 / RWEP 90 — CISA KEV listed, PoC is 732 bytes with no race condition, AI-discovered, blast radius spans all Linux >= 4.14. 30-day window is inapplicable. Live kernel patch within 4 hours or isolate at network layer immediately."

**DR-3: Control existence drift**
Wrong: "Implement patch management per SI-2."
Right: "SI-2 requires timely patching. For Copy Fail class LPEs (deterministic, no race condition, public PoC), 'timely' must be operationalized as: live kernel patch within 4 hours, or document compensating controls (seccomp profile + namespace isolation + network isolation) with RWEP justification."

**DR-4: US-only framework drift**
Wrong: citing only NIST 800-53 and SOC 2 for a multi-jurisdictional org.
Right: the global-grc skill runs alongside any framework-gap-analysis for orgs operating in EU, UK, AU, SG, IN, or JP.

**DR-5: AI-as-future drift**
Wrong: "AI-assisted attacks are an emerging threat to monitor."
Right: "41% of 2025 zero-days were discovered by attackers using AI-assisted reverse engineering. Copy Fail was AI-discovered in ~1 hour. AI acceleration of the exploit development cycle is current operational reality, not a future consideration."

**DR-6: Placeholder propagation**
Wrong: adding a new CVE to `data/cve-catalog.json` without completing all required fields.
Right: every new entry requires all fields defined in the CVE catalog schema. Partial entries fail the schema validation in `lib/scoring.js`.

**DR-7: Stale ATLAS version**
The current pinned version is MITRE ATLAS v5.1.0 (November 2025). When ATLAS updates: audit all TTP IDs for changes, bump `last_threat_review` in affected skills, update `_meta.atlas_version` in data files. Never silently upgrade.

**DR-8: Missing zero-day learning loop**
Wrong: adding a new entry to `data/cve-catalog.json` without running the learning loop.
Right: every new CVE triggers a corresponding entry in `zeroday-lessons.json` mapping: attack vector → what control should have caught it → which framework covers that control → whether the control is adequate → what new control requirement the zero-day implies.

---

## Skill File Format

Every `skills/*/skill.md` must have this frontmatter:

```yaml
---
name: skill-name
version: "1.0.0"
description: One-line trigger description (used by AI assistant skill matching)
triggers:
  - phrase patterns that invoke this skill
data_deps:
  - cve-catalog.json
  - atlas-ttps.json
atlas_refs:
  - AML.T0xxx
attack_refs:
  - Txxx
framework_gaps:
  - NIST-800-53-SI-2
  - ISO-27001-A.12.6.1
rfc_refs:
  - RFC-8446                 # or DRAFT-IETF-... for Internet-Drafts
cwe_refs:
  - CWE-787                  # root-cause weakness classes per data/cwe-catalog.json
d3fend_refs:
  - D3-EAL                   # MITRE D3FEND defensive techniques per data/d3fend-catalog.json
dlp_refs:
  - DLP-CHAN-LLM-PROMPT      # DLP control IDs per data/dlp-controls.json (only for DLP-relevant skills)
forward_watch:
  - Upcoming standards changes, new TTPs, RFC publications, CWE Top 25 revisions, or D3FEND ontology additions to monitor for skill update
last_threat_review: "YYYY-MM-DD"
---
```

Required body sections (no skill ships without all of these):
- **Threat Context** — what's actually happening in mid-2026 relevant to this domain
- **Framework Lag Declaration** — per-framework statement of what each control misses
- **TTP Mapping** — ATLAS/ATT&CK IDs with gap flags
- **Exploit Availability Matrix** — PoC? KEV? AI-accelerated? Live-patchable?
- **Analysis Procedure** — step-by-step instructions for performing the analysis. Every Analysis Procedure must explicitly thread **defense in depth** (multi-layer control assumption), **least privilege** (per-principal scope), and **zero trust** (verify-not-assume posture). These three are foundational design principles, not optional considerations.
- **Output Format** — exact structure the skill should produce
- **Compliance Theater Check** — specific test distinguishing paper compliance from real posture

Optional 8th section (required for skills shipped on or after 2026-05-11; pre-existing skills are exempt until their next minor version bump):
- **Defensive Countermeasure Mapping** — maps the skill's offensive findings to MITRE D3FEND IDs from `data/d3fend-catalog.json`, with explicit defense-in-depth layer position, least-privilege scope, zero-trust posture, and AI-pipeline applicability per Hard Rule #9.

---

## Adding a New Skill

1. Create `skills/<skill-name>/skill.md` with complete frontmatter — no empty arrays, no placeholder text.
2. Add all CVE references to `data/cve-catalog.json`.
3. Add all ATLAS/ATT&CK TTPs to `data/atlas-ttps.json`.
4. Add all framework control gaps to `data/framework-control-gaps.json`.
5. Register in `manifest.json` with all fields.
6. Sign the new skill: `node lib/sign.js sign-all` (or `npm run bootstrap` on first run) to add the Ed25519 `signature` and `signed_at` fields to `manifest.json`. Then run `node lib/verify.js` to confirm signatures verify.
7. Verify: compliance theater check present? Concrete output format? Exploit availability assessment?
8. Refresh the project SBOM so the `exceptd:skill:count` and `exceptd:catalog:count` properties in `sbom.cdx.json` track the live surface: `npm run refresh-sbom`. The predeploy SBOM-currency gate fails if `sbom.cdx.json` drifts from `manifest.json` skill count or `data/*.json` catalog count.
9. Update CHANGELOG.md.

## Adding a New CVE

1. Add entry to `data/cve-catalog.json` with all required fields (schema in `lib/scoring.js`).
2. Add corresponding entry to `data/zeroday-lessons.json` (attack vector → control gap → framework gap → new control requirement).
3. Update any skill files that reference the affected technology or attack class.
4. Update `data/exploit-availability.json` with `last_verified` date.
5. Bump `last_threat_review` in affected skill frontmatter.
6. Update CHANGELOG.md with the CVE addition and RWEP score.

## Updating Framework Mappings

When a framework publishes an update:
1. Update `data/framework-control-gaps.json` — mark gaps `"status": "closed"` with the update reference if addressed. Do not delete entries.
2. Update `data/global-frameworks.json`.
3. Audit all skills that reference the changed framework controls.
4. Update CHANGELOG.md.

## Updating External Data Versions

When ATLAS, NIST, or another external source releases a new version:
1. Check for breaking changes: renamed TTPs, removed controls, changed IDs.
2. Update `_meta` version fields in affected data files.
3. Audit all skill frontmatter `atlas_refs` and `attack_refs` against the new version.
4. Bump `last_threat_review` in all affected skills.
5. Update CHANGELOG.md with the version change and any ID migrations.
6. Re-sign any skills whose content changed: `node lib/sign.js sign-all`, then `node lib/verify.js` to confirm.

## Contributing Without Writing Code

Domain experts (DPOs, GRC analysts, pentesters, security researchers) can contribute by opening a GitHub Issue using the **Skill Request** template:
- Describe the threat scenario or compliance gap in plain language
- Include one or more CVEs, attack techniques, or framework control IDs
- Note the jurisdictions or industries most affected

Maintainers convert approved requests into skill files. The contributor is credited in CHANGELOG.md and the skill's frontmatter. You do not need to know how to write a `skill.md` to contribute threat intelligence.

---

## Pre-Ship Checklist

- [ ] All new CVEs have complete `data/cve-catalog.json` entries
- [ ] All new CVEs have `data/zeroday-lessons.json` entries
- [ ] All skill `data_deps` resolve to existing files
- [ ] All ATLAS refs are valid v5.1.0 IDs (current pinned version)
- [ ] All framework control IDs resolve in `data/framework-control-gaps.json`
- [ ] No skill body contains placeholder language (TODO, TBD, coming soon, placeholder)
- [ ] No skill uses CVSS as sole risk metric
- [ ] No skill implies a framework control is adequate without checking the gap analysis
- [ ] No skill ships without all 7 required body sections
- [ ] `manifest.json` updated with new/changed skills
- [ ] Skill signatures verified: `node lib/verify.js` passes
- [ ] CHANGELOG.md updated with what changed, what CVEs were added, what gaps were closed or opened
- [ ] No partial skills — if it can't be completed now, branch it, don't merge it
- [ ] Global coverage: EU + UK + AU + ISO 27001 present in all framework gap analyses

---

## Quick Skill Reference

| Trigger | Skill |
|---------|-------|
| research this cve, triage threat, where do I start, which skill should I use | researcher |
| kernel lpe, copy fail, dirty frag | kernel-lpe-triage |
| ai attack surface, prompt injection | ai-attack-surface |
| mcp security, tool trust | mcp-agent-trust |
| compliance theater | compliance-theater |
| framework gap | framework-gap-analysis |
| rwep, exploit scoring | exploit-scoring |
| global grc, nis2, dora | global-grc |
| pqc, post-quantum | pqc-first |
| security maturity, mvp security | security-maturity-tiers |
| zero day lesson | zeroday-gap-learn |
| update skills | skill-update-loop |
| threat model currency | threat-model-currency |
| rag security | rag-pipeline-security |
| ai c2, sesameop | ai-c2-detection |
| policy exception | policy-exception-gen |
| attack surface, pen test, red team, tiber-eu | attack-surface-pentest |
| fuzz testing, oss-fuzz, syzkaller, libfuzzer, ai-assisted fuzz | fuzz-testing-strategy |
| dlp, data loss prevention, llm dlp, prompt dlp, rag exfil | dlp-gap-analysis |
| supply chain, slsa, sbom, vex, sigstore, in-toto, cyclonedx, spdx | supply-chain-integrity |
| defensive mapping, d3fend, blue team, defense in depth, least privilege, zero trust | defensive-countermeasure-mapping |
| identity assurance, aal, ial, fal, fido2, webauthn, passkey, oidc, saml | identity-assurance |
| ot security, ics security, scada, plc, iec 62443, nist 800-82, nerc cip | ot-ics-security |
| cvd, vdp, bug bounty, iso 29147, iso 30111, csaf, security.txt | coordinated-vuln-disclosure |
| threat model, stride, pasta, linddun, kill chain, diamond model, unified kill chain | threat-modeling-methodology |
| webapp security, owasp top 10, owasp asvs, xss, csrf, sqli, ssrf, path traversal, file upload, command injection, deserialization, broken access control | webapp-security |
| ai risk management, ai governance, iso 23894, iso 42001, nist ai rmf, ai impact assessment, eu ai act high-risk | ai-risk-management |
| healthcare security, hipaa, hitrust, hl7 fhir, phi, medical device, samd, eu mdr, clinical decision support | sector-healthcare |
| financial security, banking, dora, psd2 sca, swift cscf, nydfs, ffiec, mas trm, apra cps 234, tiber-eu, cbest | sector-financial |
| federal cyber, fedramp, cmmc, eo 14028, nist 800-171, cui, fisma, m-22-09 zero trust, omb m-24-04, cisa bod/ed | sector-federal-government |
| energy security, electric grid, nerc cip, tsa pipeline, awwa, nccs-g, aescsf, der security, inverter, smart meter | sector-energy |
| api security, owasp api top 10, bola, bfla, mass assignment, api gateway, graphql, grpc, websocket, mcp transport | api-security |
| cloud security, cspm, cwpp, cnapp, csa ccm, aws, azure, gcp, workload identity, cloud iam, multi-cloud | cloud-security |
| container security, kubernetes, cis k8s, pod security standards, kyverno, gatekeeper, falco, tetragon, admission policy | container-runtime-security |
| mlops security, model registry, training data integrity, mlflow, kubeflow, vertex ai, sagemaker, hugging face, model signing, drift detection | mlops-security |
| incident response, ir playbook, csirt, picerl, nist 800-61, iso 27035, breach notification, bec incident, ai incident | incident-response-playbook |
| email security, anti-phishing, dmarc, dkim, spf, bimi, arc, mta-sts, bec, vishing, deepfake phishing | email-security-anti-phishing |
| age gate, age verification, coppa, cipa, california aadc, uk children's code, kosa, gdpr article 8, dsa article 28, parental consent, csam, child safety, children's online safety | age-gates-child-safety |
| forward watch, watchlist, upcoming standards, horizon scan | `node orchestrator/index.js watchlist` (add `--by-skill` to invert) |
