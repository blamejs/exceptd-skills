# Security Policy

## Scope

This security policy covers the exceptd Security skills repository itself — the skill files, data catalogs, and library code. It does not cover downstream applications that use these skills.

## Reporting a Vulnerability

Email: security@exceptd.com

Include:
- Description of the issue
- Steps to reproduce
- Impact assessment
- Whether you believe this is being actively exploited

**Do not file public GitHub issues for security vulnerabilities.**

## Response SLAs

| Severity | First Response | Triage | Fix |
|---|---|---|---|
| Critical (data integrity attack on CVE catalog, RWEP score manipulation) | 24h | 72h | 7d |
| High (skill instruction that produces incorrect remediation for CISA KEV) | 72h | 7d | 14d |
| Medium (incorrect framework gap mapping, wrong control ID) | 7d | 14d | 30d |
| Low (missing data, incomplete entries) | 14d | 30d | next minor |

## Threat Model

### What This Repo Defends

**Data integrity of the CVE catalog and RWEP scores.** Tampered scores could cause security teams to deprioritize genuinely critical vulnerabilities. Every RWEP calculation is reproducible from `data/cve-catalog.json` inputs and the formula in `lib/scoring.js`. Auditors should verify scores independently for high-stakes decisions.

**Accuracy of framework gap declarations.** If a gap is incorrectly declared as "closed" when it remains open, organizations may believe they are protected when they are not. Gap status changes require evidence (framework update reference + control text analysis) not assertions.

**Freshness of exploit availability data.** Stale PoC status (marking an exploit as not-public when it is) causes teams to use incorrect RWEP scores. `data/exploit-availability.json` is versioned and dated. Every entry has a `last_verified` field.

**Skill instruction correctness.** A skill that produces incorrect remediation guidance (e.g., recommending a patch that doesn't exist for a kernel version, citing a wrong ATLAS TTP ID) creates direct harm. Skills are pinned to `last_threat_review` dates and reviewed when referenced CVEs or TTPs change.

### What This Repo Does Not Defend

- Runtime security of applications that use these skills (that's blamejs's scope)
- Upstream framework accuracy (NIST, ISO, MITRE ATLAS) — we track lag, we don't control it
- Physical access to systems this runs on

## Data Integrity

CVE catalog entries and RWEP scores are not authoritative sources — they are analytical summaries for operational use. Always cross-reference:

- CISA KEV: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- NVD: https://nvd.nist.gov/
- MITRE ATLAS: https://atlas.mitre.org/
- MITRE ATT&CK: https://attack.mitre.org/

For critical security decisions, verify CISA KEV status directly. RWEP scores are a prioritization heuristic, not a compliance instrument.

## Supported Versions

Pre-1.0: Latest patch on the most recent minor receives data updates (CVE catalog, framework gap updates, new ATLAS TTPs). All versions receive critical accuracy corrections.

Once 1.0: 18-month data update support after each major version.

## Supply Chain

This repository has no npm runtime dependencies. The library code in `lib/` is self-contained. Skills and data files are plain text/JSON.

When using these skills via an AI assistant, the skills are loaded as instruction text. No code from this repository executes in your environment beyond what your AI assistant chooses to implement.

## Accuracy Disclaimer

Security threat intelligence has a short shelf life. CVE data, PoC availability status, and framework coverage assessments in this repository reflect the state of knowledge at the `last_threat_review` date in each skill's frontmatter. Verify current status with primary sources before making production security decisions.

RWEP scores are analytical tools, not authoritative risk assessments. They are designed to surface prioritization signal beyond CVSS, not to replace professional security judgment.
