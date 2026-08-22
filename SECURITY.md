# Security Policy

## Reporting a vulnerability

Two private channels, either is fine:

- **GitHub** — open a draft advisory from the repository's Security tab
  ([Report a vulnerability](https://github.com/blamejs/exceptd-skills/security/advisories/new)).
  Private vulnerability reporting is enabled, so the report stays between you and
  the maintainers until an advisory is published.
- **Email** — security@exceptd.com

**Do not open a public GitHub issue.** A public issue is the one channel that
tells everyone else before the fix exists.

Include what you have:

- What the issue is
- How to reproduce it
- What an attacker gets
- Whether you believe it is being exploited now

## What to expect

| Severity | First response | Triage | Fix |
|---|---|---|---|
| Critical — data-integrity attack on the CVE catalog, RWEP score manipulation | 24h | 72h | 7d |
| High — a skill that produces incorrect remediation for a CISA KEV entry | 72h | 7d | 14d |
| Medium — an incorrect framework gap mapping or wrong control ID | 7d | 14d | 30d |
| Low — missing data, incomplete entries | 14d | 30d | next minor |

## Supported versions

Pre-1.0, the latest patch on the most recent minor receives data updates: CVE
catalog, framework gap changes, new ATLAS TTPs. Every version receives critical
accuracy corrections.

From 1.0, each major version receives data updates for 18 months.

## Scope

This policy covers the repository itself — the skill files, the data catalogs,
and the library code. It does not cover applications built on top of them.

The repository has no npm runtime dependencies; `lib/` is self-contained and the
skills and catalogs are plain text and JSON. Loaded through an AI assistant, the
skills are instruction text: nothing here executes in your environment unless
your assistant chooses to run it.

Out of scope:

- Runtime security of applications that consume these skills
- Accuracy of the upstream frameworks themselves — NIST, ISO and MITRE lag is
  tracked here, not controlled here
- Physical access to the machine this runs on

## What the repository defends

**The CVE catalog and its RWEP scores.** Tampered scores deprioritize
vulnerabilities that are genuinely critical. Every RWEP score is reproducible
from the inputs in `data/cve-catalog.json` and the formula in `lib/scoring.js`;
recompute it yourself when the decision is a large one.

**Framework gap declarations.** A gap recorded as closed while it remains open
tells an organization it is covered when it is not. Changing a gap's status
requires evidence — a framework update reference and the control text it turns
on — not an assertion.

**Exploit-availability freshness.** An exploit marked not-public when it is
public understates RWEP by a fifth of the scale. `data/exploit-availability.json`
is versioned and every entry carries `last_verified`.

**Skill instruction correctness.** A skill that recommends a patch which does not
exist for a given kernel version, or cites the wrong ATLAS technique, does direct
harm. Skills carry a `last_threat_review` date and are re-reviewed when the CVEs
or techniques they cite change.

## Using the data

Catalog entries and RWEP scores are analytical summaries for operational use, not
authoritative sources. Cross-reference before acting:

- CISA KEV — https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- NVD — https://nvd.nist.gov/
- MITRE ATLAS — https://atlas.mitre.org/
- MITRE ATT&CK — https://attack.mitre.org/

Verify KEV status against CISA directly for critical decisions. RWEP is a
prioritization heuristic, not a compliance instrument.

Threat intelligence has a short shelf life. What this repository asserts reflects
the state of knowledge at each skill's `last_threat_review` date. Check the
primary source before a production decision rests on it.
