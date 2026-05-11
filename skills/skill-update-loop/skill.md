---
name: skill-update-loop
version: "1.0.0"
description: Meta-skill for keeping all exceptd skills current — fires on new CVEs, ATLAS updates, framework changes, and forward_watch triggers
triggers:
  - update skills
  - skill review
  - check skill currency
  - forward watch
  - are skills current
  - update threat intel
  - skill maintenance
  - new cve update
  - atlas update
  - framework update
data_deps:
  - cve-catalog.json
  - atlas-ttps.json
  - framework-control-gaps.json
  - global-frameworks.json
  - zeroday-lessons.json
  - exploit-availability.json
  - rfc-references.json
atlas_refs: []
attack_refs: []
framework_gaps: []
forward_watch:
  - MITRE ATLAS version releases (check atlas.mitre.org/resources/changelog)
  - CISA KEV additions (check cisa.gov/known-exploited-vulnerabilities-catalog)
  - NIST PQC standards finalization (check csrc.nist.gov/projects/post-quantum-cryptography)
  - Major kernel CVEs (CNA: kernel.org, distro security advisories)
  - AI/MCP platform CVEs (GitHub Security Advisories, OSV database)
  - Framework publication updates (NIST SP updates, ISO amendments, NIS2 implementing acts)
  - IETF RFC publications and draft status changes (datatracker.ietf.org, rfc-editor.org); run `npm run validate-rfcs` quarterly
last_threat_review: "2026-05-11"
---

# Skill Update Loop

This meta-skill manages the evolution of all other exceptd skills. It is the loopback mechanism that keeps the platform current as threats, tools, standards, and frameworks change.

---

## Why Skills Decay

Security skills have a half-life. The specific decay mechanisms are:

| Decay Type | Example | Detection |
|---|---|---|
| New CVE in covered domain | New kernel LPE in Copy Fail class | CISA KEV + NVD monitoring |
| ATLAS version update | New TTP added, TTP ID changed | atlas.mitre.org changelog |
| Framework amendment | NIST SP revision, ISO amendment | NIST/ISO publication monitors |
| New forward_watch item resolved | HQC becomes FIPS 206 | NIST csrc.nist.gov |
| Algorithm deprecation | NIST deprecates classical algo | NIST SP 800-131A updates |
| New attack class not in any skill | Novel technique documented in research | CVE database, academic preprints |
| Exploit availability change | PoC goes from private to public | Exploit databases, researcher announcements |
| CISA KEV addition | Known CVE gets confirmed exploitation | CISA KEV feed |

---

## Update Triggers and Assigned Skills

### Trigger 1: New CISA KEV Entry

**Monitor:** CISA KEV catalog RSS feed / API

When a new entry is added:
1. Check `data/cve-catalog.json` — is this CVE in the catalog?
   - If no: run zeroday-gap-learn on the new CVE, add to catalog
   - If yes: update `cisa_kev: true` and `cisa_kev_date`
2. Update `data/exploit-availability.json` — CISA KEV implies active exploitation
3. Check which skills reference this CVE or its technology domain
4. Update `last_threat_review` in affected skills
5. Re-run RWEP calculation for the CVE (KEV adds +25 to score)
6. If RWEP changes by more than 10 points: update any skill that displays pre-calculated RWEP for this CVE
7. Check if compliance theater patterns for this CVE need updating

**Affected skills (by default):** kernel-lpe-triage, exploit-scoring, compliance-theater, threat-model-currency, zeroday-gap-learn

---

### Trigger 2: MITRE ATLAS New Version

**Monitor:** https://atlas.mitre.org/resources/changelog

When a new ATLAS version is published:
1. Check all skill `atlas_refs` fields against new TTP IDs
2. Identify: renamed TTPs, removed TTPs, new TTPs relevant to covered domains
3. Update `atlas_refs` in all affected skill frontmatter
4. Update TTP tables in skill bodies where TTP descriptions changed
5. Identify new TTPs that should be added to existing skills or warrant new skills
6. Update AGENTS.md version reference: "The current reference version is MITRE ATLAS vX.X (Month YYYY)"
7. Update threat-model-currency checklist item 13

**Affected skills (by default):** ai-attack-surface, mcp-agent-trust, rag-pipeline-security, ai-c2-detection, zeroday-gap-learn, threat-model-currency

---

### Trigger 3: New Kernel CVE in LPE/Container Escape Class

**Monitor:** kernel.org CVE announcements, RHEL/Ubuntu/Debian security advisories

When a new kernel CVE in the LPE, container escape, or page-cache exploitation class is published:
1. Add to `data/cve-catalog.json` with complete fields (RWEP, CISA KEV status, etc.)
2. Run zeroday-gap-learn to extract control gaps
3. Update kernel-lpe-triage skill if the CVE represents a new technique class
4. Update exploit-scoring pre-calculated table
5. Check compliance-theater Pattern 1 (patch management) — does new CVE change the theater analysis?
6. Check threat-model-currency Classes 1–3

**Affected skills:** kernel-lpe-triage, exploit-scoring, compliance-theater, threat-model-currency, zeroday-gap-learn

---

### Trigger 4: New AI/MCP/Agent Platform CVE

**Monitor:** GitHub Security Advisories, OSV database (osv.dev), MCP-related GitHub repos

When a new CVE affecting AI coding assistants, MCP clients/servers, or LLM tools is published:
1. Add to `data/cve-catalog.json`
2. Run zeroday-gap-learn
3. Update mcp-agent-trust if it's an MCP trust boundary CVE
4. Update ai-attack-surface if it's a prompt injection or AI-specific CVE
5. Update threat-model-currency Classes 4–5
6. Update exploit-scoring

**Affected skills:** mcp-agent-trust, ai-attack-surface, exploit-scoring, threat-model-currency, zeroday-gap-learn, identity-assurance, coordinated-vuln-disclosure

---

### Trigger 5: Framework Amendment or New Publication

**Monitor:** NIST csrc.nist.gov (SP updates), ISO.org (ISO 27001 amendments), ENISA publications, EU Official Journal (NIS2/DORA implementing acts)

When a framework publishes an update:
1. Check `data/framework-control-gaps.json` — does the update close any open gaps?
   - If gap closed: update `status: "closed"`, add amendment reference, preserve history
   - If gap partially addressed: update gap_analysis to reflect partial improvement
   - If update is insufficient: document why in gap_analysis
2. Check `data/global-frameworks.json` for jurisdiction-specific updates
3. Update global-grc skill for the relevant jurisdiction section
4. Update framework-gap-analysis built-in gap catalog if affected
5. Update compliance-theater patterns if the theater pattern changes
6. Bump `last_threat_review` in affected skills

**Affected skills:** framework-gap-analysis, compliance-theater, global-grc, policy-exception-gen (exception templates may need update), ot-ics-security, coordinated-vuln-disclosure, threat-modeling-methodology

---

### Trigger 6: PQC Standards Forward Watch

**Monitor:** NIST csrc.nist.gov/projects/post-quantum-cryptography

When any pqc-first `forward_watch` item resolves:

| Item | Action |
|---|---|
| FIPS 206 (HQC) published | Add HQC to pqc-first algorithm registry; note as backup KEM |
| X25519+ML-KEM TLS RFC published | Update pqc-first TLS section from "draft" to "standard" |
| OpenSSL FIPS 140-3 certified | Update pqc-first version gate commentary |
| CNSA 2.0 deadline passes for a sector | Update pqc-first framework compliance table |
| ENISA PQC mandate published | Update global-grc EU section; update pqc-first framework section |
| CRQC estimate significantly changes | Update pqc-first HNDL threat assessment table |
| New algorithm broken by classical cryptanalysis | Immediate update — deprecate algorithm, update all affected skills |

**If a NIST-standardized PQC algorithm is broken:** This is a Critical update. All skills referencing that algorithm must be updated immediately. The pqc-first algorithm registry must show the algorithm as deprecated with the cryptanalysis reference.

---

### Trigger 7: Exploit Availability Change

**Monitor:** Public exploit databases, researcher announcements, Metasploit module releases

When a CVE's exploit availability changes (e.g., private research PoC becomes public):
1. Update `data/exploit-availability.json` — `poc_available: true`, `last_verified: date`
2. Recalculate RWEP (+20 points for public PoC)
3. Update `data/cve-catalog.json`
4. Update any skill displaying pre-calculated RWEP for this CVE
5. Check if compliance theater analysis changes (a private PoC becoming public changes the theater threshold)

---

### Trigger 8: New Attack Class Not Covered

When a new attack class is documented in research, CVE disclosures, or threat intelligence that isn't covered by any existing skill:
1. Check all 12 skill `forward_watch` sections — was this anticipated?
2. If anticipated: activate the planned update for the relevant skill
3. If unanticipated: evaluate whether to:
   - Add to an existing skill (if it fits a domain already covered)
   - Create a new skill (if it's a genuinely new domain)
4. Run zeroday-gap-learn to extract the control gap
5. Add to threat-model-currency checklist (may expand beyond 14 items)
6. Update AGENTS.md threat context section

---

### Trigger 9: IETF RFC or Internet-Draft Status Change

**Monitor:** IETF Datatracker (https://datatracker.ietf.org), RFC Editor (https://www.rfc-editor.org). Run `npm run validate-rfcs` (which calls `node orchestrator/index.js validate-rfcs --live`) on a quarterly cadence or whenever a tracked RFC/draft is known to have advanced.

Per AGENTS.md hard rule #12 (external data version pinning), RFCs are tracked alongside ATLAS, NIST, CISA KEV. The catalog lives at `data/rfc-references.json`. Drift surfaces:

- A draft advances to Proposed Standard, Internet Standard, or Best Current Practice.
- A new RFC errata is published.
- A document is obsoleted (`replaced_by` populated upstream).
- A draft expires without progress (operator decides whether to drop it or note the stall).

When drift is detected:
1. Update the affected entry in `data/rfc-references.json`: `status`, `replaces`, `replaced_by`, `errata_count`, `last_verified`.
2. If the change is breaking (draft promoted to RFC with a new number; original RFC obsoleted), audit every skill with that entry in `rfc_refs` and update its frontmatter.
3. Bump `last_threat_review` on affected skills.
4. If a draft becomes an RFC, its catalog key changes from `DRAFT-...` to `RFC-NNNN`. Update all `rfc_refs` lists that cite the draft, and refresh `manifest-snapshot.json` (this counts as a public-surface change — a removed reference is breaking per the snapshot gate).
5. If a new RFC newly applies to a domain a skill covers, add its catalog entry and the corresponding `rfc_refs` field.

**Affected skills (by default):** any skill currently carrying `rfc_refs` — at the time of writing: `kernel-lpe-triage`, `mcp-agent-trust`, `ai-c2-detection`, `pqc-first`, `identity-assurance` (RFC 7519 / RFC 8725 / RFC 6749 / RFC 9700 / RFC 8032 for JWT, OAuth, and EdDSA), `coordinated-vuln-disclosure` (RFC 9116 for security.txt). Skills without `rfc_refs` are not affected by this trigger.

**Affected catalogs:** `data/rfc-references.json`, `manifest.json`, `manifest-snapshot.json`.

---

### Trigger 10: Threat Modeling Methodology Updates

**Monitor:** Microsoft STRIDE updates (microsoft.com/en-us/securityengineering/sdl/threatmodeling), Linddun-go updates (linddun.org), Pol's Unified Kill Chain repository (https://www.unifiedkillchain.com/), MITRE D3FEND ontology releases (d3fend.mitre.org).

Threat modeling methodologies evolve. STRIDE has periodic Microsoft revisions; LINDDUN's privacy-extension catalog grows as new privacy-violating AI patterns are documented; the Unified Kill Chain is versioned by Pol et al. and absorbs new phase definitions as adversary behavior shifts; MITRE D3FEND adds defensive-technique IDs and reorganizes its ontology on a published release cadence. A skill that names a methodology without tracking its version is the same drift class as a skill that names ATLAS without pinning v5.1.0.

When a new methodology version drops:
1. Update `threat-modeling-methodology` skill body — refresh the methodology-version table, the DFD templates, and the attack-tree templates in its Output Format section to match the new release.
2. Audit the `threat-model-currency` checklist for new methodology items (new STRIDE category, new LINDDUN privacy threat, new Unified Kill Chain phase, new D3FEND tactic).
3. Bump `last_threat_review` in both affected skills.
4. If a D3FEND ontology release adds or renames technique IDs cited in `defensive-countermeasure-mapping`, audit that skill's `d3fend_refs` and update `data/d3fend-catalog.json`.
5. Cross-jurisdiction: ENISA Threat Landscape methodology guidance and NIST SP 800-154 (Data-Centric Threat Modeling) are parallel anchors — surface any updates from those publishers in the same review window.

**Affected skills (by default):** threat-modeling-methodology, threat-model-currency, researcher.

**Affected catalogs:** `data/d3fend-catalog.json` (when D3FEND-version-driven), `data/atlas-ttps.json` (when methodology-to-TTP mapping shifts).

---

## Skill Currency Scores

Each skill has a currency decay model:

| Staleness | Currency Score |
|---|---|
| `last_threat_review` < 30 days ago | 100% |
| 30–60 days, no unprocessed triggers | 90% |
| 60–90 days | 80% |
| 90–180 days, no unprocessed triggers | 60% |
| 180+ days | 40% |
| Has unprocessed CISA KEV entries | -30% |
| Has unprocessed ATLAS version update | -20% |
| Has unprocessed forward_watch resolutions | -10% per item |

**Minimum acceptable currency:** 70%

A skill below 70% currency should be flagged in the repository README and prioritized for review.

---

## Running the Update Loop

### Scheduled (Weekly)

1. Query CISA KEV feed for new entries
2. Check ATLAS changelog for version updates
3. Scan GitHub Security Advisories for AI/MCP CVEs
4. Check NIST csrc.nist.gov for PQC project updates
5. For each new item: identify affected skills, queue updates

### Event-Driven

Trigger the update loop immediately when:
- A new CISA KEV entry is added (same-day)
- A new ATLAS version is published (within 7 days)
- A NIST FIPS standard is finalized (within 14 days)
- A zero-interaction RCE CVE is published affecting covered platforms (same-day)

### Annual

1. Full currency audit of all skills
2. Verify all data file entries are still accurate
3. Review all `status: "open"` framework gaps for framework update activity
4. Review `forward_watch` items for resolved items
5. Assess whether threat-model-currency checklist needs new items
6. Update `last_threat_review` in AGENTS.md and manifest.json

---

## Analysis Procedure

When a user invokes this skill:

### Step 1: Check for unprocessed triggers

Ask or assess:
- Any new CISA KEV entries since `last_threat_review` date in manifest.json?
- Any new ATLAS version since last review?
- Any resolved `forward_watch` items in any skill?
- Any framework amendments since last review?
- Any new CVEs in kernel/AI/MCP domain?

### Step 2: Calculate currency scores

For each skill, apply the currency decay model.

### Step 3: Prioritize updates

Order by:
1. Unprocessed CISA KEV (highest urgency — active exploitation)
2. Unprocessed ATLAS version (affects TTP mapping accuracy)
3. Resolved forward_watch items (PQC standards especially)
4. Framework amendments
5. Staleness-only decays (no specific trigger)

### Step 4: Generate update tasks

For each required update: specific skill file, specific section, specific change required.

---

## Output Format

```
## Skill Update Loop Report

**Date:** YYYY-MM-DD
**Last Full Review:** [date from manifest.json]

### Unprocessed Triggers
| Trigger Type | Item | Affected Skills | Urgency |
|---|---|---|---|

### Skill Currency Scores
| Skill | Last Review | Currency Score | Status |
|---|---|---|---|

### Prioritized Update Tasks
[Ordered by urgency: specific skill, specific section, specific required change]

### Forward Watch Status
[Per skill's forward_watch items: resolved/pending/newly added]
```

---

## Framework Lag Declaration

This skill is meta — it operates the maintenance loop for every other skill. Its `atlas_refs`, `attack_refs`, and `framework_gaps` arrays are intentionally empty because the skill's subject is the loop, not a specific TTP or control. Frameworks that touch on threat-intelligence currency leave the operational cadence undefined; this is the lag.

| Framework | Control | What It Misses for Skill-Currency Maintenance |
|---|---|---|
| ISO 27001:2022 | A.5.7 (Threat Intelligence) | Requires that threat intelligence be collected, analyzed, and used to take action. Does not operationalize cadence — "appropriate" intel maintenance is left to the entity. An organization subscribed to a feed with no documented re-review trigger on KEV additions or ATLAS bumps is nominally compliant with A.5.7. |
| NIST CSF 2.0 | IDENTIFY — Improvement (ID.IM) | The IM function speaks to improvements derived from lessons learned and threat intelligence. It does not define currency metrics (e.g. "skills must be reviewed within N days of an ATLAS minor-version release") or describe a loopback mechanism between threat intel and the org's defined controls. |
| NIST 800-53 | PM-16 (Threat Awareness Program) | Requires a threat-awareness program with information-sharing. Does not require a programmatic mechanism that maps new threat intelligence to specific control documents and triggers a re-review. |
| NIST 800-53 | RA-3 / RA-7 (Risk Assessment / Risk Response) | Risk assessment is required on a defined cadence, but the cadence is not tied to upstream threat-intel events (new KEV, new ATLAS version, new FIPS publication). The decoupling permits stale risk assessments that pass audit. |
| ISO 22301 | BCM Lifecycle | Business-continuity-management lifecycle has no analog for threat-intel-skill currency. BCM exercises are scheduled; threat-intel skill review is not. |
| NIS2 | Art. 21(2)(a)/(g) | Requires risk-analysis and policies on the effectiveness of cybersecurity risk-management measures, plus basic cyber-hygiene practices. Silent on the cadence of revisiting those analyses against current threat-intel state. |
| DORA | Art. 13 (Learning and Evolving) | Requires ICT-related incident learning and evolution. The evolution mechanism is not tied to external threat-intel events outside the entity's own incident stream. |
| MITRE ATT&CK / ATLAS | Versioning Policy | The frameworks publish changelogs but place no obligation on consumers to track them. The obligation is one-directional — consumers must self-impose the loopback. |

**Net effect:** frameworks treat threat intelligence as a noun ("we have it") rather than a verb ("we re-evaluate our controls against it on a defined cadence"). The skill-update-loop exists to operationalize the verb.

---

## Exploit Availability Matrix

This skill does not have a single exploited target — its "exploit surface" is the set of upstream data sources the loop consumes. Each source must have a documented re-verification cadence, tracked via `last_verified` in `data/exploit-availability.json`.

| Source | What It Provides | Cadence | Pinned Version / Anchor | Tracked In |
|---|---|---|---|---|
| CISA KEV catalog | Confirmed in-the-wild exploitation flag per CVE | Real-time (RSS / JSON API) | cisa.gov/known-exploited-vulnerabilities-catalog | `data/exploit-availability.json` (`cisa_kev`, `cisa_kev_date`) |
| MITRE ATLAS changelog | TTP additions, renames, removals for AI/ML threat domain | Quarterly check; immediate on minor-version release | ATLAS v5.1.0 (November 2025) — pinned in AGENTS.md and `data/atlas-ttps.json._meta.atlas_version` | `_meta.atlas_version` |
| NVD CVE 2.0 API | Authoritative CVE metadata, CVSS vectors, references | Real-time on new CVE in covered domain | services.nvd.nist.gov/rest/json/cves/2.0 | `data/cve-catalog.json` |
| NIST FIPS publication tracker | PQC and crypto-standard finalizations | Per-publication (event-driven) | csrc.nist.gov/publications | pqc-first `forward_watch` + manifest `last_threat_review` |
| MITRE ATT&CK Enterprise | Non-AI TTP additions/renames | Per ATT&CK version release | attack.mitre.org (current pinned: v15) | Skill `attack_refs` fields |
| GitHub Security Advisories / OSV | CVEs for AI assistants, MCP clients/servers, supply-chain JS/Python packages | Real-time on covered repos | osv.dev, github.com/advisories | `data/cve-catalog.json` |
| Framework publisher feeds | NIST SP revisions, ISO amendments, NIS2 implementing acts, EU Official Journal, ENISA, NCSC, ASD | RSS / changelog per publisher | csrc.nist.gov, iso.org, eur-lex.europa.eu | `data/framework-control-gaps.json`, `data/global-frameworks.json` |
| Kernel CNA / distro advisories | Kernel LPE, container-escape, page-cache CVEs | Per advisory | kernel.org, RHEL/Ubuntu/Debian security advisories | `data/cve-catalog.json`, kernel-lpe-triage |
| Exploit databases / Metasploit | PoC public-availability transition | Per release | exploit-db.com, Metasploit module releases | `data/exploit-availability.json` (`poc_available`, `last_verified`) |
| Academic preprints | Cryptanalysis breakthroughs, novel attack classes, CRQC timeline estimates | Continuous; major estimate → immediate trigger | arXiv, IACR ePrint | pqc-first `forward_watch`, `data/zeroday-lessons.json` |

**Each source's `last_verified` date is itself a currency input.** If a source's `last_verified` is older than its cadence window, the loop's own currency degrades and a self-review trigger fires.

---

## Compliance Theater Check

> "Your organization claims a current threat-intelligence capability under [ISO 27001 A.5.7 / NIST CSF ID.IM / NIST 800-53 PM-16]. Ask the team how 'currency' is measured. If the answer is 'we subscribe to [a feed]' or 'we get a daily digest', the capability is theater. A feed subscription with no documented re-review trigger that fires on (a) new CISA KEV additions in covered technologies, (b) new MITRE ATLAS minor-version releases, (c) new FIPS publications in covered crypto, and (d) new framework amendments in applicable jurisdictions, is a noun-grade capability against a verb-grade threat environment."

> "Concrete test: pull the most recent MITRE ATLAS minor-version release date from atlas.mitre.org. Now pull the `last_threat_review` from every skill's frontmatter (or the equivalent currency timestamp in your own threat-intel documents). If any covered-domain document's `last_threat_review` predates the most recent ATLAS minor-version release by more than 30 days with no documented decision to defer, the currency claim fails. The control is being measured by the existence of the subscription rather than the freshness of the derived analysis."

> "Second concrete test: pull the most recent CISA KEV additions in the last 30 days that affect technologies the organization runs. For each, identify the document (skill, runbook, policy) where the new KEV entry should have triggered a re-review. If the re-review either did not occur or occurred without updating the document's stated `last_threat_review`, the loopback is non-functional and the threat-intel program is theater regardless of how many feeds are consumed."
