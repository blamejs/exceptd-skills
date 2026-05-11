# Orchestrator

The scanning and orchestration layer that ties all exceptd skills together. It scans an environment, routes findings to relevant skills, coordinates the multi-agent pipeline, and generates structured reports.

## Architecture

```
┌──────────────────────────────────────────────────────┐
│                    orchestrator/                      │
│                                                       │
│   scanner.js    →    dispatcher.js    →   pipeline.js │
│     │                    │                    │       │
│     ↓                    ↓                    ↓       │
│  findings.json   matched skills       agent handoffs  │
│                                                       │
│   event-bus.js  ←  external events (KEV, ATLAS, etc) │
│   scheduler.js  ←  weekly/annual currency checks     │
└──────────────────────────────────────────────────────┘
```

## Components

### scanner.js
Discovers the security posture of the current environment:
- Kernel version and patch status
- MCP server configurations across AI coding assistants
- Cryptographic posture (TLS versions, algorithm inventory)
- Framework compliance claims
- AI API dependencies in use

Outputs: `findings.json` — a structured list of signals, each with a severity and a hint toward which skills apply.

### dispatcher.js
Routes scanner findings to relevant skills. Matches findings against skill `triggers` in `manifest.json`. Returns an ordered list of skills to invoke, sorted by RWEP urgency.

### pipeline.js
Coordinates the multi-agent research → validation → update → report pipeline:
1. **threat-researcher** — investigates new CVEs and TTPs
2. **source-validator** — gates data quality before it enters the catalog
3. **skill-updater** — applies validated findings to skill files and data
4. **report-generator** — produces structured output for the target audience

### event-bus.js
Event-driven trigger system. Fires when:
- CISA KEV catalog adds a new entry
- MITRE ATLAS publishes a new version
- A kernel CVE with RWEP > 80 is added to the catalog
- An AI/MCP platform CVE drops
- A compliance framework publishes an amendment

Each event triggers `skill-update-loop` and marks affected skills for review.

### scheduler.js
Scheduled tasks:
- **Weekly**: currency check on all skills (any `last_threat_review` > 30 days gets flagged)
- **Monthly**: full CVE catalog validation against NVD
- **Annual**: full skill audit — all skills reviewed against current threat landscape

## Usage

```bash
# Scan current environment and produce findings
node orchestrator/index.js scan

# Route findings to relevant skills
node orchestrator/index.js dispatch

# Run a specific skill programmatically
node orchestrator/index.js skill kernel-lpe-triage

# Run the full agent pipeline (threat-researcher → report)
node orchestrator/index.js pipeline

# Check skill currency scores
node orchestrator/index.js currency

# Generate an executive report from current findings
node orchestrator/index.js report --format executive

# Watch for events and trigger updates automatically
node orchestrator/index.js watch
```

## Output Formats

The orchestrator produces output in three formats:

| Format | Audience | File |
|--------|----------|------|
| `executive` | CISO / Board | `reports/templates/executive-summary.md` |
| `technical` | Security Engineers | `reports/templates/technical-assessment.md` |
| `compliance` | Auditors / GRC | `reports/templates/compliance-gap-report.md` |
| `zero-day` | Incident Response | `reports/templates/zero-day-response.md` |

## Agent Handoff Protocol

When `pipeline.js` hands off between agents, it passes a structured JSON package:

```json
{
  "handoff_id": "uuid",
  "from_agent": "threat-researcher",
  "to_agent": "source-validator",
  "timestamp": "2026-05-11T00:00:00Z",
  "payload": {
    "cve_id": "CVE-XXXX-XXXXX",
    "findings": {},
    "confidence": "high|medium|low",
    "primary_sources": [],
    "flags": []
  }
}
```

Source-validator either approves (passes to skill-updater), returns for revision, or rejects with reason.

## Environment Variables

```bash
EXCEPTD_SCAN_TARGETS=./          # Directories to scan for MCP configs
EXCEPTD_REPORT_FORMAT=technical  # Default report format
EXCEPTD_KEV_CHECK_INTERVAL=3600  # KEV polling interval in seconds (default: 1h)
EXCEPTD_DATA_DIR=./data          # Path to data directory
```
