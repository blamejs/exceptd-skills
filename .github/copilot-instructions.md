# exceptd Security — GitHub Copilot Instructions

## Repository Purpose

This repository contains AI security skills: structured analysis instruction files that tell an AI assistant how to perform specific security assessments. The skills are grounded in mid-2026 threat reality and explicitly flag where compliance framework controls are insufficient for current attack patterns.

## Context Files

Load these for full context:
- `CONTEXT.md` — complete orientation to how the skill system works
- `manifest.json` — skill registry with trigger phrases and file locations
- `AGENTS.md` — development standards for all contributions

## Skill System Overview

Each skill is at `skills/<name>/skill.md`. Skills have:
- YAML frontmatter: `name`, `version`, `triggers`, `data_deps`, `atlas_refs`, `framework_gaps`
- Structured body sections: Threat Context, Framework Lag, TTP Mapping, Analysis Procedure, Output Format

To invoke a skill: match the query to `triggers` in `manifest.json`, load the skill file, and execute the Analysis Procedure.

## Data Sources

All threat data lives in `data/`. Do not fabricate CVE or framework data:

| File | Use |
|------|-----|
| `data/cve-catalog.json` | CVE metadata, RWEP scores, KEV status |
| `data/atlas-ttps.json` | MITRE ATLAS v5.1.0 TTPs |
| `data/framework-control-gaps.json` | Per-control gap analysis |
| `data/exploit-availability.json` | PoC status and weaponization stage |
| `data/global-frameworks.json` | 14-jurisdiction framework registry |
| `data/zeroday-lessons.json` | CVE → control gap learning loop output |

## Key Rules for Copilot Suggestions

1. **Risk scoring**: Always use RWEP (Real-World Exploit Priority) from `lib/scoring.js`, not CVSS alone
2. **Framework gaps**: Read from `data/framework-control-gaps.json`; do not assert gap status from training data
3. **Global scope**: Include EU (NIS2/DORA/GDPR), UK (CAF), AU (ISM/Essential 8), ISO 27001 in all framework analysis
4. **Zero-day loop**: Every new CVE added to `data/cve-catalog.json` requires a corresponding `data/zeroday-lessons.json` entry
5. **No placeholder data**: All `data/` entries must have real CVE IDs, ATLAS TTP IDs, control IDs

## Orchestrator

The `orchestrator/` directory coordinates scanning → skill dispatch → report generation:
```
node orchestrator/index.js [scan|dispatch|report|pipeline]
```

## Library Code

```
lib/scoring.js        — RWEP scoring engine, schema validation
lib/ttp-mapper.js     — Control ID → TTP gap mapper
lib/framework-gap.js  — Framework lag scorer, theater detection
```

## What to Avoid

- Suggesting CVE details not in `data/cve-catalog.json` — use the data files
- Implying a framework control is adequate without checking `data/framework-control-gaps.json`
- US-only framework references for multi-jurisdiction analysis
- Generating exploit code or PoC payloads — describe techniques only
- Adding skills without complete frontmatter (all required fields must be present)
