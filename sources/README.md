# Sources

The sources directory is the data quality gate for exceptd Security. Every claim in every skill must trace to a primary source. Bad data in produces bad analysis out — this directory makes source integrity a first-class concern.

## The Problem: Data Corruption in Security Intelligence

Security intelligence has several common failure modes:
- **Stale data**: A CVE is marked as "no public PoC" when a PoC went public six months ago
- **Misattribution**: A CVSS score copied from a secondary source that applied the wrong vector
- **Fabricated details**: AI-summarized threat intel that introduced plausible-but-wrong specifics
- **Framework version drift**: A control ID that changed in a framework revision but wasn't updated in skills
- **Dead links**: Source URLs that return 404 — removing the ability to verify

The sources system prevents these failures by:
1. Maintaining a registry of authoritative primary sources per data type
2. Providing validators that check data against primary sources
3. Tracking source verification dates and flagging stale verifications
4. Making multi-agent research verifiable and auditable

---

## Directory Structure

```
sources/
├── README.md                  # This file
├── index.json                 # Source registry — authoritative sources per data type
├── SOURCES.md                 # Guide for adding and verifying sources
├── validators/
│   ├── cve-validator.js       # Cross-check CVE data against NVD API
│   ├── kev-validator.js       # Verify CISA KEV status against official feed
│   ├── atlas-validator.js     # Verify ATLAS TTP IDs against mitre.org
│   └── framework-validator.js # Verify framework control IDs
└── feeds/
    ├── cisa-kev-snapshot.json # Snapshot of CISA KEV at last verification
    ├── atlas-version.json     # Current ATLAS version metadata
    └── nvd-recent.json        # Recent NVD entries (last 30 days)
```

---

## Primary Sources by Data Type

### CVE Data

| Field | Authoritative Source | Update Frequency |
|---|---|---|
| CVSS score + vector | NVD (nvd.nist.gov/vuln/detail/CVE-XXXX) | On NVD analysis |
| CISA KEV status | CISA KEV catalog (cisa.gov/known-exploited-vulnerabilities-catalog) | Real-time feed |
| PoC availability | NVD references + researcher advisories | Monitor CVE references |
| Active exploitation | CISA KEV, threat intelligence, incident reports | Monitor |
| Affected versions | Vendor advisory (Red Hat, Ubuntu, etc.) | On vendor advisory |
| Patch availability | Vendor advisory | On vendor advisory |
| Live patch support | kpatch.com, ubuntu.com/security/livepatch, suse.com/products/live-patching | On vendor announcement |

**Never use as primary source:** Wikipedia, news articles, blog posts, AI-generated summaries, secondary aggregators without NVD cross-reference.

### ATLAS TTPs

| Field | Authoritative Source |
|---|---|
| TTP ID | atlas.mitre.org (canonical IDs may change between versions) |
| TTP name | atlas.mitre.org/techniques/ |
| TTP version | atlas.mitre.org/resources/changelog |

**ATLAS version pinning:** All skills reference a specific ATLAS version. When ATLAS updates, TTP IDs must be re-verified. The `atlas-validator.js` checks all skill `atlas_refs` against the current published ATLAS.

### Framework Controls

| Framework | Authoritative Source |
|---|---|
| NIST 800-53 Rev 5 | csrc.nist.gov/publications/detail/sp/800-53/rev-5/final |
| ISO 27001:2022 | iso.org/standard/27001 (requires purchase for full text) |
| SOC 2 | aicpa.org (TSC 2017) |
| PCI DSS 4.0 | pcisecuritystandards.org/document_library |
| NIS2 | eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32022L2555 |
| DORA | eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32022R2554 |
| EU AI Act | eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32024R1689 |
| EU CRA | Official Journal of EU |
| NCSC CAF | ncsc.gov.uk/collection/cyber-assessment-framework |
| ASD ISM | cyber.gov.au/resources-business-and-government/essential-cyber-security/ism |
| ASD Essential 8 | cyber.gov.au/resources-business-and-government/essential-cyber-security/essential-eight |
| MAS TRM | mas.gov.sg/regulation/guidelines/technology-risk-management-guidelines |
| CIS Controls v8 | cisecurity.org/controls/v8 |
| CSA CCM v4 | cloudsecurityalliance.org/research/cloud-controls-matrix |

### PQC Standards

| Standard | Authoritative Source |
|---|---|
| FIPS 203 (ML-KEM) | csrc.nist.gov/pubs/fips/203/final |
| FIPS 204 (ML-DSA) | csrc.nist.gov/pubs/fips/204/final |
| FIPS 205 (SLH-DSA) | csrc.nist.gov/pubs/fips/205/final |
| FIPS 206 (HQC, pending) | csrc.nist.gov/projects/post-quantum-cryptography |
| OpenSSL 3.5 release notes | github.com/openssl/openssl/blob/master/CHANGES.md |
| CNSA 2.0 | cnss.gov |

---

## Source Verification Requirement

Every entry in `data/cve-catalog.json` must have a `source_verified` field:
```json
{
  "source_verified": "2026-05-01",
  "verification_sources": [
    "https://nvd.nist.gov/vuln/detail/CVE-2026-31431",
    "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
  ]
}
```

A `source_verified` date older than 90 days triggers a reverification requirement in the skill-update-loop.

---

## Multi-Agent Research Protocol

When agents research new threat intelligence, they must:
1. Identify primary sources (from the registry above)
2. Record what was found at each source and when
3. Cross-reference across at least 2 independent sources for critical claims
4. Flag any claim that could only be verified from a single source
5. Record the agent ID and timestamp in the `source_verified` audit trail

See `agents/threat-researcher.md` for the research agent protocol.

---

## Bad Data Prevention

These categories of sources are **rejected** for skill data:

| Source Type | Why Rejected |
|---|---|
| AI-generated summaries without primary source citation | Plausible hallucination risk |
| News articles | Often inaccurate on technical details, not updated when details change |
| Blog posts | No editorial standard, often repost errors from other blogs |
| Wikipedia | Community-edited, not authoritative for CVE details or framework text |
| Secondary aggregators without NVD cross-reference | May lag or misquote NVD |
| Social media / X posts | Not citable, not stable |
| Forum posts | Not authoritative |

The only exception: researcher/discoverer announcements about their own research (e.g., Hyunwoo Kim's Dirty Frag disclosure) may be used as a source alongside NVD, since the researcher is the primary source for their own findings.

---

## Validators

Real validation against primary sources lives in `sources/validators/`. These are
zero-dependency Node 24 modules (stdlib `fetch`, `AbortController`, `fs/promises`
only). Every network call has a 10s timeout and degrades to an `unreachable`
status rather than throwing — the validators are safe to run in airgapped CI.

| Module | Purpose | Upstream |
|---|---|---|
| [`validators/cve-validator.js`](validators/cve-validator.js) | Cross-check one CVE's CVSS score, vector, and KEV status against NVD and the CISA KEV feed. Caches the KEV feed once per process. | NVD `services.nvd.nist.gov` + CISA KEV JSON |
| [`validators/atlas-validator.js`](validators/atlas-validator.js) | Confirm the pinned MITRE ATLAS version (in `manifest.json` and `sources/index.json`) matches the latest upstream release. | GitHub releases for `mitre-atlas/atlas-data`, raw `ATLAS.yaml` fallback |
| [`validators/index.js`](validators/index.js) | Barrel export plus `validateAllCves(catalog)` for catalog-wide aggregation with bounded concurrency. | — |

The orchestrator wires the CVE validator into the CLI:

```
node orchestrator/index.js validate-cves            # live cross-check, non-zero exit on drift
node orchestrator/index.js validate-cves --offline  # local view only, no network
node orchestrator/index.js validate-cves --no-fail  # report drift but always exit 0
```

Feed snapshots are written under `sources/feeds/`; see `sources/feeds/README.md`
for the cache contract and freshness thresholds.
