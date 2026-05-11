# Agents

Multi-agent coordination for exceptd Security. Each agent file defines a specialized agent role: what it does, what tools it uses, what it produces, and how it hands off to other agents.

---

## Agent Roster

| Agent | Role | Triggers |
|---|---|---|
| [threat-researcher](threat-researcher.md) | Research and validate new CVEs, threat campaigns, and ATLAS TTPs | New CVE published, ATLAS update, CISA KEV addition |
| [framework-analyst](framework-analyst.md) | Analyze framework updates and gap changes | Framework amendment published |
| [skill-updater](skill-updater.md) | Apply validated intelligence to update skill files | Threat researcher or framework analyst output |
| [source-validator](source-validator.md) | Cross-check data against primary sources | Before any data enters cve-catalog.json or atlas-ttps.json |
| [report-generator](report-generator.md) | Generate structured reports from skill outputs | User invokes a reporting workflow |

---

## Multi-Agent Workflow Overview

```
External trigger (new CVE, ATLAS update, framework change)
          ↓
[threat-researcher] or [framework-analyst]
   — researches the trigger
   — identifies affected skills
   — produces a validated intelligence package
          ↓
[source-validator]
   — cross-checks all claims against primary sources (sources/index.json)
   — flags any unverified claims
   — produces a verification report
          ↓
[skill-updater]
   — applies validated intelligence to skill files
   — updates data files
   — runs the zeroday learning loop if applicable
   — updates manifest.json last_threat_review
          ↓
[report-generator] (optional)
   — generates structured output for the user
```

---

## Parallelization Model

These agents can run in parallel when their inputs are independent:

**Parallel-safe:**
- Multiple threat-researcher instances on different CVEs
- framework-analyst + threat-researcher on unrelated topics
- Multiple source-validator instances on different data items

**Must be sequential:**
- source-validator must complete before skill-updater writes to data files
- skill-updater must complete before report-generator reads skill state

---

## Agent Coordination Protocol

Each agent produces a structured handoff package:

```json
{
  "agent": "threat-researcher",
  "run_id": "2026-05-01-CVE-2026-31431",
  "timestamp": "2026-05-01T12:00:00Z",
  "input": {"cve_id": "CVE-2026-31431"},
  "output": {
    "cve_data": {...},
    "affected_skills": ["kernel-lpe-triage", "exploit-scoring"],
    "proposed_changes": {...}
  },
  "verification_required": true,
  "next_agent": "source-validator"
}
```

The handoff package is the audit trail. Every change to skill files or data files must trace to a handoff package.
