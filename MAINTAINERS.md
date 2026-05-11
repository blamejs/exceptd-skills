# Maintainers

Current maintainers of `blamejs/exceptd-skills`.

| Handle        | Areas                                                                 |
|---------------|-----------------------------------------------------------------------|
| @dotCooCoo    | All — threat intel curation, scoring, skill content, tooling, releases |

## Maintainer responsibilities

Per CONTRIBUTING.md:

- Triage incoming issues within 7 days.
- Respond to security reports per the SLA in [SECURITY.md](SECURITY.md):
  - **Critical** (data integrity attack on CVE catalog, RWEP score manipulation): first response 24h, triage 72h, fix 7d.
  - **High** (skill instruction that produces incorrect remediation for CISA KEV): 72h / 7d / 14d.
  - **Medium** (incorrect framework gap mapping, wrong control ID): 7d / 14d / 30d.
  - **Low** (missing data, incomplete entries): 14d / 30d / next minor.
- Review PRs in your domain area within 14 days.
- Sign-off + tag releases; refresh `manifest-snapshot.json` and `last_threat_review` dates on affected skills as part of the release commit.

## High-trust paths

Changes to the following paths require maintainer review per `.github/CODEOWNERS`:

- `/data/` and `/data/*.json` — all intelligence catalogs, including:
  - `/data/cve-catalog.json` — CVE metadata and RWEP scores
  - `/data/atlas-ttps.json` — MITRE ATLAS v5.1.0 TTPs
  - `/data/framework-control-gaps.json` — per-control gap analysis
  - `/data/global-frameworks.json` — multi-jurisdiction framework registry
  - `/data/zeroday-lessons.json` — zero-day learning loop entries
  - `/data/exploit-availability.json` — PoC, KEV, AI-acceleration, live-patch status
  - `/data/cwe-catalog.json` — CWE v4.17 weakness taxonomy
  - `/data/d3fend-catalog.json` — MITRE D3FEND v1.0.0 defensive techniques
  - `/data/rfc-references.json` — IETF RFC / Internet-Draft references
  - `/data/dlp-controls.json` — DLP control catalog
- `/manifest.json` — skill registry + Ed25519 signatures
- `/lib/verify.js`, `/lib/sign.js`, `/lib/scoring.js` — signing and RWEP scoring code
- `/keys/` — signing public key
- `/skills/` — all skill content, including the v0.4.0 additions:
  - `/skills/attack-surface-pentest/`
  - `/skills/fuzz-testing-strategy/`
  - `/skills/dlp-gap-analysis/`
  - `/skills/supply-chain-integrity/`
  - `/skills/defensive-countermeasure-mapping/`
  - and the v0.5.0 additions:
  - `/skills/identity-assurance/`
  - `/skills/ot-ics-security/`
  - `/skills/coordinated-vuln-disclosure/`
  - `/skills/threat-modeling-methodology/`
- `/.github/` — workflows, templates, repo policy

When a security-team GitHub handle is created (e.g. `@blamejs/security`), add it as an additional owner on the lines above so two reviewers are required for high-trust changes.

## Becoming a maintainer

The project is pre-1.0 and currently single-maintainer. The maintainer ladder will open once the skill content stabilizes (target: v1.0). Until then, sustained high-quality contributions through PRs are the path. See CONTRIBUTING.md.

## Stepping down

A maintainer stepping down opens a PR removing themselves from this file and reassigning their CODEOWNERS lines. Notify other maintainers in the PR description with a target handover date.
