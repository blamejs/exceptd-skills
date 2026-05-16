# Architecture

## Overview

exceptd Security is a skills repository. Each skill is a `.md` file with YAML frontmatter that instructs an AI assistant how to perform a specific security analysis task with current threat intelligence.

The platform has three layers:

```
skills/          Instruction layer — tells the AI what to analyze, how to score, what to output
data/            Intelligence layer — CVE metadata, ATLAS TTPs, framework gap mappings
lib/             Logic layer — scoring algorithms, TTP mapper, framework gap analyzer
```

---

## Skill File Anatomy

```
skills/
└── <skill-name>/
    └── skill.md          Single file per skill. Frontmatter + body.
```

### Frontmatter

```yaml
---
name: skill-name
version: "1.0.0"
description: One-line description used for skill matching and the manifest index
triggers:
  - exact phrase
  - partial phrase pattern
data_deps:
  - cve-catalog.json          # files in data/ this skill reads
  - atlas-ttps.json
atlas_refs:
  - AML.T0043                 # MITRE ATLAS v5.4.0 TTP IDs
  - AML.T0054
attack_refs:
  - T1068                     # MITRE ATT&CK TTP IDs
framework_gaps:
  - NIST-800-53-SI-2          # control IDs documented as insufficient in this skill
  - ISO-27001-A.12.6.1
last_threat_review: "2026-05-01"
---
```

### Required Body Sections

Every skill body must have these sections in order:

1. **Threat Context (mid-2026)** — What's actually happening. Specific CVEs, observed campaigns, statistics. Not theoretical.
2. **Framework Lag Declaration** — Per-framework table: control ID, what it was designed for, why it fails against current TTPs.
3. **TTP Mapping** — Table: ATLAS/ATT&CK ID, technique name, gap flag (covered/partial/missing), exploitation example.
4. **Exploit Availability Matrix** — Per-CVE: CVSS, RWEP, KEV, PoC, AI-accelerated, patch status, live-patch, reboot required.
5. **Analysis Procedure** — Numbered steps for the AI to follow when performing this analysis.
6. **Output Format** — Exact structure (tables, sections, score formats) the skill should produce.
7. **Compliance Theater Check** — Specific question or test that distinguishes paper compliance from actual security.
8. **Remediation Guidance** — Accounts for: live systems, patching windows, live kernel patching, ephemeral infra, AI pipelines.

---

## Data Layer

### `data/cve-catalog.json`

Schema per entry:

```json
{
  "CVE-YYYY-NNNNN": {
    "name": "Common name if applicable",
    "type": "LPE | RCE | information-disclosure | supply-chain | ...",
    "cvss_score": 7.8,
    "cvss_vector": "CVSS:3.1/...",
    "cisa_kev": true,
    "cisa_kev_date": "YYYY-MM-DD",
    "poc_available": true,
    "poc_description": "Public PoC description — no direct exploit links",
    "ai_discovered": false,
    "ai_assisted_weaponization": false,
    "active_exploitation": true,
    "affected": "Human-readable scope description",
    "affected_versions": ["kernel >= 4.14", "kernel < 6.8.10"],
    "vector": "Attack vector description",
    "complexity": "deterministic | race-condition | heap-spray | ...",
    "patch_available": true,
    "patch_required_reboot": true,
    "live_patch_available": true,
    "live_patch_tools": ["kpatch", "livepatch", "kGraft"],
    "framework_control_gaps": {
      "NIST-800-53-SI-2": "Why this control is insufficient for this CVE",
      "ISO-27001-A.12.6.1": "Why this control is insufficient"
    },
    "atlas_refs": ["AML.T0043"],
    "attack_refs": ["T1068"],
    "rwep_score": 96,
    "rwep_factors": {
      "cisa_kev": 25,
      "poc_available": 20,
      "ai_assisted": 0,
      "active_exploitation": 20,
      "blast_radius": 15,
      "patch_available": -7,
      "live_patch": -5,
      "reboot_required": 5
    },
    "last_updated": "YYYY-MM-DD"
  }
}
```

### `data/atlas-ttps.json`

Schema per entry:

```json
{
  "AML.T0043": {
    "name": "Craft Adversarial Data",
    "tactic": "ML Attack Staging",
    "atlas_version": "5.4.0",
    "description": "...",
    "framework_coverage": {
      "NIST-800-53": {"covered": false, "nearest_control": null, "gap_description": "..."},
      "ISO-27001-2022": {"covered": false, "nearest_control": null, "gap_description": "..."},
      "NIS2": {"covered": false, "gap_description": "..."}
    },
    "exploitation_examples": ["CVE-2025-53773"],
    "detection_methods": ["..."],
    "last_updated": "2026-01-01"
  }
}
```

### `data/framework-control-gaps.json`

Schema per entry:

```json
{
  "NIST-800-53-SI-2": {
    "framework": "NIST 800-53 Rev 5",
    "control_id": "SI-2",
    "control_name": "Flaw Remediation",
    "designed_for": "Network-centric environments with predictable patch cycles (2013 original, 2020 rev5)",
    "misses": [
      "Deterministic LPEs with no race condition — 'timely' is undefined when exploit takes seconds",
      "AI-assisted exploit development compressing weaponization timelines",
      "Live kernel patching as a required compensating control for critical systems"
    ],
    "real_requirement": "...",
    "status": "open",
    "opened_date": "2026-03-15",
    "evidence_cves": ["CVE-2026-31431"]
  }
}
```

### `data/global-frameworks.json`

Maps jurisdiction to framework to current coverage and lag assessment. Currently covers 35 jurisdictions including EU member states, UK, AU, SG, IN, JP, CA, and major sectoral regulators (DORA, NIS2, EU AI Act, EU CRA at the EU layer; APRA CPS 234, MAS TRM, CERT-In, SEBI, OSFI B-10 at the national layer). See schema in file.

### `data/zeroday-lessons.json`

The zero-day learning loop output. Each entry maps: CVE → attack vector → what control should have caught it → which framework covers that control → whether the control is adequate → what new control requirement the zero-day implies.

### `data/exploit-availability.json`

Tracks PoC status, weaponization stage, and AI-assist factor per CVE. Updated when PoC availability changes.

### `data/cwe-catalog.json`

55 CWE entries pinned to **CWE v4.17**. Covers the Top 25 Most Dangerous Software Weaknesses (2024 release) plus AI- and supply-chain-relevant weakness classes (prompt-injection-as-trust-boundary failure, training data integrity, dependency confusion, untrusted artifact ingestion). Each entry records root-cause description, common consequences, mitigation patterns, and the CVEs in `cve-catalog.json` that instantiate the weakness. Skills cite CWE IDs in `cwe_refs` to anchor a finding to a stable weakness taxonomy rather than to a single CVE; the CWE provides the durable root-cause lens that survives across exploit generations.

`_meta.cwe_version` pins the version; on a CWE release, audit IDs for renames or deprecations, bump `last_threat_review` on affected skills, and update `_meta`.

### `data/d3fend-catalog.json`

29 MITRE D3FEND defensive technique entries pinned to **D3FEND v1.0.0**. Each entry records the defensive technique ID (e.g., `D3-EAL` Executable Allowlisting), the tactic / artifact it defends, the offensive ATLAS / ATT&CK TTPs it counters, defense-in-depth layer position, least-privilege scope assumptions, zero-trust posture compatibility, and AI-pipeline applicability per Hard Rule #9. Skills cite D3FEND IDs in `d3fend_refs` to map offensive findings to a defensive countermeasure rather than to abstract control language. The `defensive-countermeasure-mapping` skill is the canonical consumer; any skill shipped on or after 2026-05-11 includes a Defensive Countermeasure Mapping section referencing this catalog.

`_meta.d3fend_version` pins the version; D3FEND ontology additions are tracked in skill `forward_watch` fields.

### `data/rfc-references.json`

31 IETF RFC / Internet-Draft references covering authentication and authorization (OAuth 2.0 Security BCP RFC 9700, JWT BCP, FIDO/WebAuthn-related drafts), cryptography (TLS 1.3 RFC 8446, hybrid PQC drafts), disclosure (security.txt RFC 9116), and adjacent IETF standards skills depend on. Each entry tracks: title, status (Proposed Standard / Best Current Practice / Internet-Draft / Historic), errata count, replaces / replaced-by chains, IESG / IRTF stream, and a `last_verified` date. Skills cite RFC IDs in `rfc_refs`. Per Hard Rule #12, RFC references are version-pinned: when an RFC is obsoleted or a draft is published as an RFC, the catalog entry's `replaced_by` field is updated, `last_verified` is refreshed, and affected skills bump `last_threat_review`. Frameworks lag RFCs; RFCs lag attacker innovation — this catalog makes that middle layer auditable.

### `data/dlp-controls.json`

22 DLP control entries indexed along five axes: **channel** (where data flows — LLM prompt, RAG retrieval, MCP tool response, email, SaaS API, endpoint), **classifier** (how sensitive data is identified — regex, ML, embedding similarity, watermark), **surface** (where enforcement runs — endpoint, network proxy, API gateway, model gateway), **enforcement** mode (block, redact, warn, log-only), and **evidence** type (the audit artifact each control produces). The `dlp-gap-analysis` skill is the canonical consumer; other DLP-relevant skills cite control IDs in `dlp_refs`. Entries explicitly flag classical DLP controls that are architecturally inadequate for LLM/RAG channels (DR-1 framework-as-truth drift applied to DLP).

---

## Logic Layer

### `lib/scoring.js`

RWEP (Real-World Exploit Priority) scoring engine.

- `score(cveId)` — Return RWEP score for a CVE in the catalog
- `scoreCustom(factors)` — Score a custom factor set (for CVEs not yet in catalog)
- `validate()` — Schema validation: check all skill data_deps resolve, all CVE entries are complete, all ATLAS refs are valid v5.4.0 IDs
- `compare(cveId)` — Return CVSS vs. RWEP comparison with explanation of the delta

RWEP factor weights:
```
cisa_kev              +25  (binary)
poc_available         +20  (binary)
ai_assisted_weapon    +15  (binary)
active_exploitation   +20  (binary)
blast_radius          +15  (0–15 scaled)
patch_available       -15  (binary)
live_patch_available  -10  (binary: additional reduction if no reboot required)
reboot_required       +5   (binary penalty: patch exists but requires reboot)
```

### `lib/ttp-mapper.js`

Maps compliance framework control IDs to ATLAS/ATT&CK TTPs and produces gap analysis.

- `map(controlId)` — Return TTPs relevant to a control ID and gap status
- `gapsFor(attackPattern)` — Return framework controls that fail to cover an attack pattern
- `coverage(frameworkId, ttpId)` — Return coverage status for a specific framework/TTP pair

### `lib/framework-gap.js`

Framework lag scoring and gap report generation.

- `lagScore(frameworkId)` — Return a 0–100 lag score for a framework against current threat landscape
- `gapReport(frameworkId, scope)` — Generate gap report for a framework within a scope (e.g., "kernel LPE", "AI attack surface")
- `theaterCheck(controlId, orgControls)` — Run compliance theater detection for a specific control

### `scripts/check-test-coverage.js`

Diff-coverage analyzer. Walks the staged/working-tree diff for the changed-surface shapes Hard Rule #15 enforces (CLI verbs, CLI flags, `module.exports` identifiers, new playbook indicator IDs, CVE `iocs` fields) and asserts that each change has a covering test reference somewhere under `tests/`. Skill bodies, docs, and workflow YAML are allowlisted. Runs as the 13th gate of `npm run predeploy` (and the `Diff coverage` job in `ci.yml`). Direct invocation: `npm run diff-coverage`.

### `scripts/check-sbom-currency.js`

Compares `sbom.cdx.json` against the live `manifest.json` skill count and `data/*.json` catalog counts. Fails the predeploy gate when the SBOM drifts from the shipped surface. Refresh with `npm run refresh-sbom`.

### `scripts/verify-shipped-tarball.js`

Packs the project with `npm pack`, extracts the tarball, and runs Ed25519 signature verification against the extracted bytes — the same path a downstream `npm install` exercises. Predeploy gate guaranteeing the shipped tarball verifies, independent of source-tree verification.

### `tests/_helpers/cli.js`

Shared test harness for spawning the CLI under tempdir-isolated state. Tests that exercise verb dispatch should consume this helper rather than spawning subprocesses ad-hoc — the helper enforces the "no mutation outside the tempdir" contract that prevents CI-vs-local state divergence.

---

## manifest.json

Central skill registry. Each skill entry:

```json
{
  "name": "kernel-lpe-triage",
  "version": "1.0.0",
  "path": "skills/kernel-lpe-triage/skill.md",
  "description": "...",
  "triggers": ["..."],
  "data_deps": ["cve-catalog.json"],
  "last_threat_review": "2026-05-01"
}
```

---

## Skill Composition

Skills can be composed. The framework-gap-analysis skill calls out to threat-model-currency context. The compliance-theater skill uses exploit-scoring output. The zeroday-gap-learn skill feeds back into framework-gap-analysis data.

Composition is explicit: skills declare which other skills they depend on in their frontmatter `skill_deps` field. Circular dependencies are not permitted.

```
zeroday-gap-learn  →  framework-control-gaps.json (writes)
framework-gap-analysis  →  framework-control-gaps.json (reads)
compliance-theater  →  exploit-scoring (depends on RWEP)
threat-model-currency  →  atlas-ttps.json, cve-catalog.json (reads)
global-grc  →  global-frameworks.json, framework-control-gaps.json (reads)
```
