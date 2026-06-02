<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="public/img/logo/exceptd-logo-dark.svg">
  <img src="public/img/logo/exceptd-logo-primary.svg" alt="exceptd" width="220" />
</picture>

# exceptd Security

**AI security skills grounded in mid-2026 threat reality, not framework documentation from 2020.**

[![release](https://img.shields.io/github/v/release/blamejs/exceptd-skills?include_prereleases&sort=semver&label=release)](https://github.com/blamejs/exceptd-skills/releases)
[![npm](https://img.shields.io/npm/v/@blamejs/exceptd-skills.svg?label=npm)](https://www.npmjs.com/package/@blamejs/exceptd-skills)
[![CI](https://img.shields.io/github/actions/workflow/status/blamejs/exceptd-skills/ci.yml?branch=main&label=CI)](https://github.com/blamejs/exceptd-skills/actions/workflows/ci.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/blamejs/exceptd-skills/badge)](https://scorecard.dev/viewer/?uri=github.com/blamejs/exceptd-skills)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)
[![Skills](https://img.shields.io/badge/skills-44-d946ef)](#skill-inventory)
[![ATLAS](https://img.shields.io/badge/MITRE%20ATLAS-v5.6.0-d946ef)](https://atlas.mitre.org)
[![ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-v19.0-d946ef)](https://attack.mitre.org)
[![Ed25519-signed](https://img.shields.io/badge/skills-Ed25519--signed-2ea043)](AGENTS.md)
[![Jurisdictions](https://img.shields.io/badge/jurisdictions-35-blue)](data/global-frameworks.json)

</div>

---

**Core premise:** Every major security and compliance tool on the market is still operating on stale threat models. NIST 800-53, ISO 27001, SOC 2, and PCI-DSS were written for network-centric, on-prem or early-cloud environments. They have no controls for AI pipeline integrity, MCP/agent tool trust boundaries, LLM prompt injection as an access control failure, page-cache exploitation bypassing filesystem integrity checks, or ephemeral infrastructure where traditional asset inventory is architecturally impossible.

This platform surfaces what is actually happening right now. Every skill explicitly flags where a compliance framework's control is insufficient for current attack patterns. The framework is often the problem, not the org.

## Status

Pre-1.0. Latest release lives on [GitHub Releases](https://github.com/blamejs/exceptd-skills/releases) and on npm as [`@blamejs/exceptd-skills`](https://www.npmjs.com/package/@blamejs/exceptd-skills) with signed npm provenance attestation and Ed25519-signed skill bodies. The package ships 44 skills across kernel LPE, MCP supply chain, AI-as-C2, prompt injection, post-quantum crypto, SBOM integrity, identity-incident response, and 35 other AI/security domains, plus 11 intelligence catalogs (CVE / ATLAS / ATT&CK / CWE / D3FEND / DLP / RFC / framework gaps / global frameworks / zero-day lessons / exploit availability) covering 35 jurisdictions; the CVE catalog holds 439 actively-exploited and high-priority entries, each carrying behavioral indicators, an ATT&CK technique mapping, and a defense-chain zero-day lesson. 26 investigation playbooks (kernel, MCP, AI-API, framework, SBOM, runtime, hardening, secrets, cred-stores, containers, crypto, plus `webhook-callback-abuse`, `cicd-pipeline-compromise`, `identity-sso-compromise`, `llm-tool-use-exfil`, `post-quantum-migration`, `ai-discovered-cve-triage`, `supply-chain-recovery`, `citation-hygiene`, `vc-wallet-trust`, `mail-server-hardening`, and more), a CLI for discovery and investigation built around `discover → brief → run → attest` (each run executes the playbook's seven-phase contract), and a nightly auto-refresh job that pulls KEV / NVD / EPSS / GHSA / OSV / IETF deltas plus 15 primary-source advisory, research-blog, and tech-press feeds (Qualys TRU, Red Hat RHSA, Ubuntu USN, ZDI, kernel.org, oss-security, JFrog, CISA, Microsoft Security Blog, Sysdig, Trail of Bits, Embrace the Red, BleepingComputer security, and The Hacker News) into auto-PRs for editorial review, alongside a silent-regression watcher that flags historical CVEs re-broken without a new identifier.

---

## Skill Inventory

### Triage & Dispatch

**[researcher](skills/researcher/skill.md)**
Front-door triage skill for raw threat intel. Takes a CVE ID, ATLAS TTP, vendor advisory, framework control ID, or incident narrative; cross-joins it across `data/cve-catalog.json`, `data/atlas-ttps.json`, `data/framework-control-gaps.json`, `data/zeroday-lessons.json`, `data/exploit-availability.json`, and `data/global-frameworks.json`; produces a one-page RWEP-anchored dispatch report; routes the operator to the right specialized skill(s). Start here when the input is "here's a thing, tell me what to do with it".

### Kernel & Privilege Escalation

**[kernel-lpe-triage](skills/kernel-lpe-triage/skill.md)**
Assess Linux kernel local privilege escalation exposure. Covers Copy Fail (CVE-2026-31431, CISA KEV, 732-byte deterministic root, all Linux since 2017), Dirty Frag (CVE-2026-43284/CVE-2026-43500, page-cache chain via ESP/IPsec and RxRPC). Outputs: exposure score, live-patch vs. reboot remediation path, compensating controls, framework gap declaration.

### AI-Specific Attack Surface

**[ai-attack-surface](skills/ai-attack-surface/skill.md)**
Comprehensive AI/ML attack surface assessment mapped to MITRE ATLAS v5.6.0 with explicit gap flags. Covers prompt injection as enterprise RCE (CVE-2025-53773 CVSS 7.8, 85%+ bypass rate against SOTA defenses), MCP supply chain RCE (CVE-2026-30615, zero user interaction, 150M+ downloads), RAG exfiltration, model poisoning, AI-assisted exploit development (41% of 2025 zero-days), credential theft acceleration (160% increase).

**[mcp-agent-trust](skills/mcp-agent-trust/skill.md)**
Enumerate MCP (Model Context Protocol) trust boundary failures. Covers tool allowlisting gaps, unsigned server manifests, prompt injection via tool responses, supply chain compromise. CVE-2026-30615 (Windsurf, zero-interaction RCE). Generates: tool allowlist policy, server signing requirements, bearer auth config, output sanitization requirements.

**[rag-pipeline-security](skills/rag-pipeline-security/skill.md)**
RAG-specific threat model with no current framework coverage. Embedding manipulation for data exfiltration, vector store poisoning, chunking attacks, retrieval filter bypass, indirect prompt injection via retrieved documents. ATLAS-mapped. Generates: retrieval audit controls, anomaly detection requirements, output monitoring policy.

**[ai-c2-detection](skills/ai-c2-detection/skill.md)**
Detect adversary use of AI APIs as covert command-and-control (SesameOp case study, ATLAS AML.T0096). PROMPTFLUX/PROMPTSTEAL malware families that query LLMs during execution for real-time evasion. Outputs: behavioral baseline model, detection signatures, network monitoring rules, incident response playbook.

### Framework & Compliance

**[framework-gap-analysis](skills/framework-gap-analysis/skill.md)**
Feed a compliance framework control ID and a threat scenario — receive: what the control was designed for, why it is insufficient against current TTPs, which attacker technique exploits the gap, what a real control would require. Built-in gap mappings for NIST 800-53, ISO 27001:2022, SOC 2, PCI-DSS 4.0, NIS2, DORA, CIS v8.

**[compliance-theater](skills/compliance-theater/skill.md)**
Identify where an organization passes an audit but remains exposed. Seven documented compliance theater patterns with specific detection tests. Outputs: theater score per control domain, exposure summary, auditor-facing remediation language, evidence gap list.

**[global-grc](skills/global-grc/skill.md)**
Multi-jurisdiction GRC mapping. Covers EU (GDPR Art. 32, NIS2, DORA, EU AI Act, EU CRA), UK (Cyber Essentials Plus, NCSC CAF), Australia (ISM, ASD Essential 8, APRA CPS 234), Singapore (MAS TRM, CSA CCoP), Japan (METI, NISC), India (CERT-In, SEBI), Canada (OSFI B-10), and global (ISO 27001:2022, CSA CCM v4, CIS Controls v8). Identifies universal gaps that no jurisdiction's framework covers.

**[policy-exception-gen](skills/policy-exception-gen/skill.md)**
Generate defensible policy exceptions for architectural realities frameworks don't accommodate. Templates for: ephemeral/serverless infrastructure (no traditional asset inventory), AI pipelines (continuous opaque model updates), zero trust architecture (no network perimeter), live-system no-reboot patching. Each exception includes compensating controls, risk acceptance language, and auditor-ready justification.

### Risk Intelligence

**[exploit-scoring](skills/exploit-scoring/skill.md)**
Real-World Exploit Priority (RWEP) scoring beyond CVSS. Factors: CISA KEV status (0.25), public PoC (0.20), AI-assisted weaponization (0.15), active exploitation (0.20), patch availability (-0.15), live-patch availability (-0.10), blast radius (0.15). Pre-calculated RWEP scores for all CVEs in `data/cve-catalog.json`. Outputs RWEP alongside CVSS with plain-language priority guidance.

**[threat-model-currency](skills/threat-model-currency/skill.md)**
Score how current an organization's threat model is against 2026 threat reality. Checklist of 14 current threat classes against documented model coverage. Outputs: currency percentage, specific missing threat classes, recommended additions with ATLAS/ATT&CK references, prioritized update roadmap.

**[zeroday-gap-learn](skills/zeroday-gap-learn/skill.md)**
Run the zero-day learning loop: zero-day description → attack vector extraction → control gap identification → framework coverage assessment → new control requirement generation → exposure scoring. Encodes lessons from Copy Fail, Dirty Frag, CVE-2025-53773, CVE-2026-30615, SesameOp. Feeds back into framework-gap-analysis and threat-model-currency.

### Identity, OT, Disclosure & Threat Modeling

**[identity-assurance](skills/identity-assurance/skill.md)**
Identity assurance for mid-2026. NIST 800-63 AAL/IAL/FAL levels, FIDO2/WebAuthn passkey deployment, OIDC/SAML/SCIM federation, agent-as-principal identity for autonomous AI workloads, short-lived workload token issuance, OAuth 2.0 + RFC 9700 (OAuth 2.0 Security BCP) hardening. Outputs: assurance-level gap map, passkey rollout plan, agent identity policy, token-lifetime targets.

**[ot-ics-security](skills/ot-ics-security/skill.md)**
OT / ICS security for mid-2026. NIST 800-82r3, IEC 62443-3-3, NERC CIP, IT/OT convergence risks (flat networks, shared AD, jump-host weaknesses), AI-augmented HMI threats, and ATT&CK for ICS mappings. Outputs: zone/conduit gap map, safety-instrumented-system isolation review, OT-specific patching exception templates.

**[coordinated-vuln-disclosure](skills/coordinated-vuln-disclosure/skill.md)**
Coordinated Vulnerability Disclosure for mid-2026. ISO 29147 (disclosure) + ISO 30111 (handling), VDP and bug bounty design, CSAF 2.0 machine-readable advisories, security.txt (RFC 9116), EU CRA / NIS2 regulator-mandated disclosure timelines, AI-specific vulnerability classes (prompt injection, training data poisoning, model exfiltration). Outputs: VDP policy, advisory template, regulator notification calendar.

**[threat-modeling-methodology](skills/threat-modeling-methodology/skill.md)**
Methodology selection and execution across STRIDE, PASTA, LINDDUN (privacy), Cyber Kill Chain, Diamond Model, MITRE Unified Kill Chain, AI-system threat modeling, and agent-based threat modeling. Outputs: methodology choice with justification, scoped DFD or attack tree, threat-to-control crosswalk against ATLAS / ATT&CK / D3FEND.

---

## Install

Three audience paths. Pick the one that matches how you'll use this.

### 1. AI consumer (read-only — most users)

You want an AI assistant to load the skills + catalogs against a question of yours. Easiest path:

```bash
npx @blamejs/exceptd-skills path
```

That prints the absolute path of the installed package. Point your AI assistant at:

- `<path>/AGENTS.md` — canonical project rules + ground truth for every skill
- `<path>/data/_indexes/summary-cards.json` — 100-word abstract per skill (~95 KB)
- `<path>/data/_indexes/recipes.json` — curated multi-skill chains for common use cases

No clone, no signing keys, no Node 24 required for assistants that read directly from disk. If your assistant needs a local copy as a regular checkout, use `npx degit blamejs/exceptd-skills my-skills` instead.

### 2. Operator (run commands locally)

You want to refresh CVE/RFC data, run currency checks, or generate reports. Install + invoke via `npx` (no global install needed):

```bash
npx @blamejs/exceptd-skills doctor                                # health check
npx @blamejs/exceptd-skills refresh --apply --swarm               # pull KEV/NVD/EPSS/RFC/GHSA + apply
npx @blamejs/exceptd-skills refresh --advisory CVE-2026-45321     # seed one CVE draft from GHSA
npx @blamejs/exceptd-skills refresh --advisory MAL-2026-3083      # seed via OSV (MAL-/SNYK-/RUSTSEC-/USN-/PYSEC-/GO-/MGASA-/UVI-)
npx @blamejs/exceptd-skills refresh --curate CVE-2026-45321       # surface editorial questions for a draft
npx @blamejs/exceptd-skills refresh --network                     # swap data/ from latest signed npm tarball
```

For frequent use, install globally to skip the `npx` resolution every time:

```bash
npm install -g @blamejs/exceptd-skills
exceptd help
```

First run — verify the signing chain and pin the public-key fingerprint for out-of-band checks:

```bash
exceptd doctor --signatures            # verify Ed25519 chains (44/44 expected)
cat $(exceptd path)/keys/EXPECTED_FINGERPRINT   # pin fingerprint for OOB verify
```

Verify on npm: `npm view @blamejs/exceptd-skills@<version> dist.signatures` shows the SLSA v1 provenance attestation.

Air-gapped operation: run `exceptd refresh --prefetch` on a connected host, copy the resulting `.cache/upstream/` to the airgap, run `exceptd refresh --from-cache <path> --apply` over there. The vendored upstream snapshots replace every network call.

Fresh-disclosure workflow (v0.12.0): the nightly auto-PR job pulls KEV / NVD / EPSS / IETF / **GHSA** (added in v0.12.0) / **OSV** (added in v0.12.10). KEV typically takes days; NVD ~10 days; GHSA fires within hours of disclosure and covers npm + PyPI + Maven + Go + NuGet + …; OSV aggregates the OSSF Malicious Packages dataset (`MAL-*` keys) + Snyk + RustSec + Mageia + Ubuntu USN + Go Vuln DB + PYSEC + UVI on top of GHSA — useful for malicious-package compromises that don't have CVEs yet (`exceptd refresh --advisory MAL-2026-3083`). New IDs land as drafts (`_auto_imported: true`, `_draft: true`) that the catalog validator treats as warnings, not errors — operators get the fresh entry immediately, editorial review (framework gaps, IoCs, ATLAS/ATT&CK refs) follows via `exceptd refresh --curate <ID>`. For "I want this advisory today, not tomorrow": `exceptd refresh --advisory <CVE-or-GHSA-or-MAL-or-SNYK-or-RUSTSEC-ID> --apply`.

Primary-source advisory polling: `exceptd refresh --check-advisories` polls 15 vendor and coordinated-disclosure feeds — 8 advisory/coordinated-disclosure venues (Qualys TRU, Red Hat RHSA, Ubuntu USN, Zero Day Initiative, kernel.org commits, oss-security mailing list, JFrog SecOps, CISA current advisories), 4 vendor security research blogs (Microsoft Security Blog, Sysdig, Trail of Bits, Embrace the Red), and 3 more (BleepingComputer security, The Hacker News, and a researcher activity-feed tracker). Combined coverage publishes CVE IDs at T+0 to T+1 — typically 3–14 days ahead of NVD enrichment. The command is report-only: it returns a structured `diffs[]` listing each newly-seen CVE ID with its source attributions and advisory URLs, but does not mutate the catalog. A complementary silent-regression watcher (`lib/cve-regression-watcher.js`) cross-checks poller diffs for historical-CVE references (year ≤ currentYear − 2) and surfaces candidate silent-regression cases — historical CVEs re-broken by a new proof-of-concept without a new ID being assigned. Operators triage the output and route promising IDs through `exceptd refresh --advisory <CVE-ID> --apply`. Pairs naturally with the daily scheduled remote agent below.

CVE-class alert surfacing: `exceptd watchlist --alerts` matches the live `cve-catalog.json` against five operational patterns (`kernel_lpe_with_poc`, `supply_chain_family`, `ai_discovered_kev`, `active_exploitation_unpatched`, `recent_poc_no_kev_yet`) and returns the matches sorted critical-severity-first, then by RWEP. Use as a fast operational triage on a refreshed catalog without scanning every entry by hand.

GitHub repo-pattern monitoring: `exceptd watchlist --org-scan --org <login>` probes GitHub Search for repositories matching known threat-actor naming patterns ("A Gift From TeamPCP", "Shai-Hulud", "TeamPCP") scoped to one org. Custom patterns via repeatable `--pattern <s>`. Implements the canonical detection for the Shai-Hulud / TeamPCP supply-chain framework class — the attacker uses GitHub itself as the exfil channel. Set `GITHUB_TOKEN` for private-repo coverage and rate-limit headroom; public-repo search works without auth.

AI-assistant config-file audit: `exceptd doctor --ai-config` walks `~/.claude`, `~/.cursor`, `~/.codeium`, `~/.aider`, and `~/.continue`, flagging sensitive files (`settings.json`, `mcp.json`, `*.mcp_config.json`, `api_key*`, `*.token`, `*.credentials`) not at mode 0600 on POSIX. On Windows the mode bits aren't load-bearing; each finding is surfaced with an info-level "manual ACL review" note. Catches the AI-config-credential-exfil class that the Shai-Hulud framework targets. Opt-in — does not run as part of the default no-flag `doctor` pass.

Evidence-collection layer: `exceptd collect <playbook>` invokes a companion script under `lib/collectors/<playbook>.js` that walks cwd, applies the catalogued regex set, stats permissions, and emits the submission JSON in the same shape `exceptd run --evidence -` accepts. 14 of 26 playbooks have collectors today (`ai-api`, `cicd-pipeline-compromise`, `citation-hygiene`, `containers`, `cred-stores`, `crypto`, `crypto-codebase`, `hardening`, `kernel`, `library-author`, `mcp`, `runtime`, `sbom`, `secrets`); the remaining 12 are policy-skipped per AGENTS.md (judgement-shaped incident / governance / pure-analyze playbooks where AI-driven evidence collection is the design). Canonical operator pipe: `exceptd collect <pb> | exceptd run <pb> --evidence -`. `exceptd doctor --collectors` enumerates the layer; `exceptd discover` tags applicable playbooks with `[collector]` when one ships. `cicd-pipeline-compromise` requires `--attest-ownership` on the collect call (the playbook's `operator-owns-ci-fleet` precondition is opt-in to prevent unauthorized CI assessments).

Daily scheduled threat intake: a `routine: exceptd-threat-intake` (claude.ai remote agent) runs daily at 14:00 UTC. Sequence: `npm install` → `refresh --check-advisories` → `watchlist --alerts` → `refresh --apply` → `refresh --advisory <CVE-ID>` for up to 5 new CVE IDs from the primary-source feeds → re-sign + rebuild-indexes if the catalog mutated → commit on `intake/<YYYY-MM-DD>` branch with the full diff in the report. Closes the cadence gap that previously left fresh disclosures dependent on operator-triggered intake. Operator-managed at <https://claude.ai/code/routines>.

Optional env vars for higher rate budgets:

| Variable | Purpose |
|---|---|
| `NVD_API_KEY` | Lifts NVD 2.0 from 5 → 50 requests per 30s window. Free key at <https://nvd.nist.gov/developers/request-an-api-key>. |
| `GITHUB_TOKEN` | Lifts GitHub Releases + GHSA from 60 → 5000 requests per hour. |
| `EXCEPTD_GHSA_FIXTURE` | Path to a JSON fixture matching the api.github.com/advisories shape. For offline tests + air-gap workflows. |
| `EXCEPTD_OSV_FIXTURE` | Path to a JSON fixture matching the OSV schema (https://ossf.github.io/osv-schema/). For offline tests + air-gap workflows against the OSV source (added v0.12.10). |
| `EXCEPTD_REGISTRY_FIXTURE` | Path to a JSON fixture matching the npm registry response. Used by `doctor --registry-check` + `run --upstream-check` + `refresh --network` for offline testing. |

### 3. Maintainer (extend / sign / publish)

You're adding a skill, updating a catalog, or cutting a release. Clone + bootstrap the full toolchain:

```bash
git clone https://github.com/blamejs/exceptd-skills
cd exceptd-skills
npm run bootstrap          # auto-detects: verify-only / re-sign / first-init
npm run predeploy          # full predeploy gate sequence locally
```

`bootstrap` auto-detects the right mode based on which keys exist on disk:

- **Verify-only** (default on a fresh clone): `keys/public.pem` ships in the repo, no `.keys/private.pem` locally. Checks that every skill verifies against the shipped signature, exits.
- **Re-sign**: `.keys/private.pem` exists locally. Re-signs every skill against current content, verifies.
- **First-init**: no `keys/public.pem` shipped or `--init` passed. Generates a new Ed25519 keypair, signs everything.

Direct invocations also available: `npm run verify`, `node lib/sign.js sign-all`.

## CLI command reference

Every command works the same via `npx @blamejs/exceptd-skills`, a global install (`exceptd`), or a local `node bin/exceptd.js`.

### v0.11.0 canonical verbs

```
exceptd                               First-run welcome — two ways to start
                                      (discover / ask) plus common starting
                                      playbooks for code / Linux / service contexts.

exceptd discover                      Scan cwd → recommend playbooks based on
                                      detected files (.git, package.json,
                                      Dockerfile, requirements.txt, etc) + host
                                      platform. Replaces scan + dispatch.
  --scan-only                         Also include legacy host scan findings.
  --json | --pretty                   Machine output (default is human checklist).

exceptd brief [playbook]              Unified info doc — jurisdictions + threat
                                      context + RWEP thresholds + preconditions
                                      + artifacts + indicators. Replaces plan +
                                      govern + direct + look.
  --all                               Every playbook (replaces `plan`).
  --scope <type>                      system | code | service | cross-cutting.
  --directives                        Expand directive metadata per playbook.
  --phase <name>                      Emit only one phase (legacy compat).

exceptd run [playbook]                Phases 4-7. Auto-detects cwd context when
                                      no playbook positional.
  --evidence <file|->                 Submission JSON (flat or nested shape).
  --evidence-dir <dir>                Per-playbook submission files (cron-friendly).
  --scope <type> | --all              Multi-playbook run.
  --vex <file>                        CycloneDX / OpenVEX filter (drop not_affected).
  --format <fmt> ...                  csaf-2.0 | sarif | openvex | markdown | summary.
                                      Repeatable. CSAF is primary; extras go to
                                      close.evidence_package.bundles_by_format.
  --diff-from-latest                  Drift vs prior attestation for same playbook.
  --ci                                Exit-code gate (use `exceptd ci` instead).
  --operator <name>                   Bind attestation to identity.
  --ack                               Explicit jurisdiction-obligation consent.
  --session-id <id>                   Reuse session id (collision refused).
  --force-overwrite                   Override session collision refusal.
  --session-key <hex>                 HMAC sign evidence_package (≥ 16 hex chars).
  --attestation-root <path>           Override ~/.exceptd/attestations/ root.
                                      Alternative: set EXCEPTD_HOME=<dir>
                                      env var (attestations land in
                                      $EXCEPTD_HOME/attestations/). Useful for
                                      multi-tenant shared hosts where each
                                      operator wants a private attestation
                                      root, or for CI runners that should
                                      scope attestations to the job workspace.
  --explain                           Dry-run: preconditions + artifacts +
                                      signal keys + submission skeleton.
  --signal-list                       Lighter than --explain; enumerate signal
                                      keys only.
  --force-stale                       Override threat_currency_score < 50 gate.
  --air-gap                           Honor air_gap_alternative paths.

exceptd ai-run <playbook>             JSONL streaming variant of run. AI emits
                                      evidence events on stdin; runner streams
                                      phase events on stdout. One pipe, no
                                      file handoff. See `exceptd ai-run --help`
                                      for the full stdin event grammar.
  --no-stream                         Single-shot mode (emit one combined JSON).

# Stdin event the host emits (one JSON object per line):
#   {"event":"evidence","payload":{
#     "precondition_checks": {...},  // per-precondition boolean assertions
#     "observations":       {...},   // per-artifact + per-indicator captures
#     "verdict":            {...}    // optional operator-supplied verdict
#   }}
# observations[<key>] carries both artifact captures
# ({ captured: true, value: "..." }) AND indicator overrides
# ({ indicator: "<id>", result: "hit"|"miss" }) — the runner normalises
# both branches from a single map. The alternative nested shape
# ({ artifacts, signal_overrides, signals }) is also accepted, but do not
# mix the two — if `signal_overrides` is present, `observations` and
# `verdict` are ignored.
# Phases emitted on stdout (in order): govern → direct → look →
# await_evidence → detect → analyze → validate → close → done.
# Errors emit {"event":"error","reason":"..."} and exit non-zero.

exceptd collect <playbook>            Walk cwd + invoke the companion collector
                                      under lib/collectors/<playbook>.js. Emits
                                      a submission JSON ready to pipe into
                                      `exceptd run <playbook> --evidence -`.
                                      14/26 playbooks have collectors; the rest
                                      are AI-driven by design (incident /
                                      governance / pure-analyze — see
                                      AGENTS.md).
  --cwd <path>                        Collect against a different repo / host.
  --pretty                            Indented JSON.
  --attest-ownership                  cicd-pipeline-compromise only — opt-in to
                                      the operator-owns-ci-fleet precondition
                                      so the runner doesn't halt at preflight.

# Canonical operator flow on a freshly-cloned repo:
exceptd discover                      # which playbooks apply here?
exceptd collect <pb> | exceptd run <pb> --evidence -   # full pipe to verdict
exceptd doctor --collectors           # list every collector + which are skipped

exceptd attest <subverb> [<sid>]      Auditor-facing operations.
  attest list                         Inventory all sessions across both
                                      ~/.exceptd and cwd-legacy roots.
  attest show <sid>                   Full (unredacted) attestation.
  attest export <sid>                 Redacted bundle for audit submission.
                                      Strips raw artifact values; preserves
                                      evidence_hash + signature + verdict.
                                      --format csaf wraps in CSAF envelope.
  attest verify <sid>                 Ed25519 .sig sidecar verification.
  attest diff <sid>                   Drift replay (= reattest default).
                                      --against <other-sid> compares two
                                      sessions side-by-side with per-artifact
                                      diff (added / removed / changed).
  --playbook <id>                     Filter (list / diff).
  --since <ISO>                       Filter list / diff to entries after date.

exceptd discover / doctor / ci        See above for doctor and ci.

exceptd doctor                        One-shot health check.
  --signatures                        Only Ed25519 skill verification.
  --currency                          Only skill currency report.
  --cves                              Only CVE catalog drift check.
  --rfcs                              Only RFC catalog drift check.
  --ai-config                         Audit AI-assistant config-file permissions
                                      across ~/.claude, ~/.cursor, ~/.codeium,
                                      ~/.aider, ~/.continue. Flags sensitive
                                      files (settings.json, mcp.json,
                                      *.mcp_config.json, api_key*, *.token,
                                      *.credentials) not at mode 0600 on POSIX;
                                      surfaces an info-level "manual ACL review"
                                      note for each sensitive file on Windows.
                                      Opt-in; not part of the default doctor
                                      pass.
  --fix                               Auto-remediate signing gaps: regenerate
                                      the local Ed25519 private key when
                                      keys/public.pem exists but .keys/private.pem
                                      is absent. No-op when the key is present.
  --registry-check                    Probe the npm registry for the latest
                                      published version + days-since-publish.
                                      Off by default; --air-gap suppresses it.
  --collectors                        Enumerate the per-playbook collector layer:
                                      which playbooks ship a collector, which are
                                      policy-skipped, and which are unwired.
  --shipped-tarball                   Run the pack + extract + verify round-trip
                                      against the tarball operators receive, not
                                      just the source tree.
  --exit-codes                        Print the canonical exit-code table as
                                      JSON for CI / scripting consumers.

exceptd ci                            One-shot CI gate. Exit codes: 0 PASS,
                                      1 framework error, 2 detected/escalate
                                      (or rwep ≥ rwep_threshold.escalate),
                                      3 ran-but-no-evidence, 4 blocked
                                      (ok:false), 5 jurisdiction clock started.
  --all | --scope <type>              Pick playbooks; auto-detect if neither.
  --max-rwep <n>                      Cap below playbook default.
  --block-on-jurisdiction-clock       Fail when notification clock fires.
  --evidence / --evidence-dir         Per-playbook submission files.

exceptd ask "<question>"              Plain-English routing to playbook(s).
                                      Returns ranked playbook IDs based on
                                      keyword overlap with each playbook's
                                      domain.name + attack_class + threat_context.
                                      A question in a domain covered by a skill
                                      rather than a playbook (email-auth, child
                                      safety, HIPAA, DLP) surfaces the skill.

exceptd recipes [<id>]                List the curated multi-skill workflows;
                                      `recipes <id>` expands one into its
                                      ordered skill chain.

exceptd lint <pb> <evidence>          Pre-flight check submission shape vs
                                      playbook (preconditions / artifacts /
                                      indicators) without executing phases 4-7.

exceptd cve <CVE-ID>                  Resolve one CVE citation → status
                                      (published / rejected / disputed /
                                      fabricated / nonexistent / unknown) plus
                                      cvss / kev / product. Order: curated
                                      catalog (offline) → resolved cache
                                      (7-day TTL, warmed by a prior lookup) →
                                      one NVD lookup, then cached. Lets a
                                      fan-out of agents share one answer
                                      instead of each researching the same id.
  --air-gap | --no-network            Offline-only (also EXCEPTD_AIR_GAP=1).
                                      Returns unknown + a reason when the id
                                      isn't in catalog/cache.
  --json | --pretty                   Machine output.
                                      Exit 2 when the citation won't stand up
                                      (rejected / fabricated / nonexistent /
                                      withdrawn).

exceptd rfc <number>                  Resolve an RFC number → title + status
                                      from the local index (whole current
                                      series, fully offline).
  --check "<title>"                   Report title_match true/false; exit 2 on
                                      mismatch (e.g. RFC 9404 cited as the
                                      Sieve spec — it's JMAP Blob Management).
  --air-gap                           Offline-only. Not-found numbers are
                                      likely obsoleted/historic or nonexistent;
                                      with network it disambiguates via the
                                      datatracker.
  --json | --pretty                   Machine output.

exceptd refresh                       Refresh upstream catalogs + indexes.
                                      Replaces prefetch + refresh + build-indexes.
  --apply                             Write diffs back + rebuild indexes.
  --from-cache [<dir>]                Read from prefetch cache.
  --prefetch                          Warm the offline cache by fetching every
                                      upstream artifact now (network required).
                                      Run on a connected host, then point
                                      --from-cache at the result on the air-gap.
  --no-network                        Report-only dry-run: list what would be
                                      fetched without touching the network.
  --network                           (v0.11.14) Fetch latest signed catalog
                                      snapshot from npm tarball, verify against
                                      local public.pem, swap data/ in place.
  --advisory <CVE-or-GHSA-ID>         (v0.12.0) Seed a single catalog entry from
                                      GitHub Advisory Database. Writes a draft
                                      flagged _auto_imported. --apply commits it.
  --curate <CVE-ID>                   (v0.12.0) Emit editorial questions + ranked
                                      candidates (ATLAS/ATT&CK/CWE/framework) for
                                      a draft catalog entry.
  --check-advisories                  Poll 15 primary-source advisory feeds
                                      (Qualys TRU, Red Hat RHSA, Ubuntu USN,
                                      ZDI, kernel.org commits, oss-security
                                      mailing list, JFrog SecOps, CISA current
                                      advisories, Microsoft Security Blog,
                                      Sysdig, Trail of Bits, Embrace the Red,
                                      BleepingComputer, The Hacker News,
                                      researcher activity-feed tracker) for
                                      CVE IDs disclosed at T+0 to T+1 —
                                      days ahead of NVD enrichment.
                                      Report-only: emits structured diffs[]
                                      with {cve_id, sources[], advisory_urls[],
                                      disclosed_at, title}; does NOT mutate the
                                      catalog. Route promising IDs through
                                      `refresh --advisory <CVE-ID>` to enrich.
  --indexes-only                      Rebuild data/_indexes/*.json only.

Sources (default = all): kev | epss | nvd | rfc | pins | ghsa | osv.
GHSA covers npm, PyPI, Maven, Go, NuGet, etc.; OSV layers Snyk, RustSec,
Mageia, Ubuntu USN, Go Vuln DB, PYSEC, UVI, plus the OSSF Malicious
Packages dataset (`MAL-*` keys). New IDs land as drafts that the catalog
validator treats as warnings, not errors — editorial review (framework
gaps, IoCs, ATLAS/ATT&CK refs) is still required.

exceptd watchlist                     Default mode: aggregate every skill's
                                      forward_watch entries (upcoming standards,
                                      RFC publications, new TTPs to monitor) in
                                      one shot.
                                      `--by-skill` inverts the grouping.
  --alerts                            Switch to CVE-catalog pattern alerts.
                                      Five patterns ship:
                                        - kernel_lpe_with_poc (high) — kernel
                                          LPE class with public PoC + blast
                                          radius >= 25
                                        - supply_chain_family (high) — MAL-*
                                          entries or `type: malicious-*`
                                        - ai_discovered_kev (high) — AI-
                                          discovered AND CISA KEV-listed
                                        - active_exploitation_unpatched
                                          (critical) — confirmed in-the-wild
                                          + no patch available
                                        - recent_poc_no_kev_yet (medium) —
                                          public PoC verified within 14 days,
                                          not yet KEV-listed
                                      Sorted critical-severity first, then by
                                      RWEP descending. JSON or human output.
  --org-scan --org <login>            Probe GitHub Search for repositories
                                      matching known threat-actor naming
                                      patterns ("A Gift From TeamPCP",
                                      "Shai-Hulud", "TeamPCP") scoped to one
                                      org. Custom patterns via repeatable
                                      `--pattern <s>`. Set GITHUB_TOKEN for
                                      private-repo coverage + higher rate
                                      limit; without it, public-repo search
                                      only.

exceptd watch                         Long-running forward-watch daemon. Blocks
                                      and listens for KEV additions, ATLAS
                                      updates, CVE drops, and framework
                                      amendments, with scheduled currency /
                                      validation checks. Ctrl-C (or SIGTERM /
                                      SIGHUP / SIGBREAK) to stop. For one-shot
                                      aggregation, pattern alerts, or org-scan,
                                      use `exceptd watchlist`.

exceptd skill <name>                  Show context for one skill.
exceptd framework-gap <FW> <ref>      One framework + one CVE/scenario, JSON
                                      or human. (Operates outside the seven-
                                      phase contract for ad-hoc gap analysis.)
exceptd report [executive]            Structured posture report. Bare `report`
                                      emits the full posture; the optional
                                      `executive` argument emits the
                                      executive-summary view.
exceptd path                          Absolute path to the installed package.
exceptd version                       Package version.
exceptd help                          This help.
exceptd <verb> --help                 Most verbs print per-verb usage with flag
                                      descriptions.
```

### Legacy v0.10.x verbs

Five verbs removed in v0.13.0 after deprecation since v0.11.0. Invoking any of these now returns a structured `ok:false` refusal pointing at the replacement; pre-v0.13 scripts must migrate.

| Removed verb | Replacement |
|---|---|
| `plan` | `brief --all` |
| `govern <pb>` | `brief <pb> --phase govern` |
| `direct <pb>` | `brief <pb> --phase direct` |
| `look <pb>` | `brief <pb> --phase look` |
| `ingest` | `run` |

The remaining v0.10.x verbs are still functional, no banner, no removal scheduled. Two shapes:

**Canonical-equivalent aliases** — same output shape as the canonical verb; safe to use interchangeably:

| Alias | Canonical | Output shape |
|---|---|---|
| `verify` | `doctor --signatures` | matches canonical |
| `validate-cves` | `doctor --cves` | matches canonical |
| `validate-rfcs` | `doctor --rfcs` | matches canonical |
| `list-attestations` | `attest list` | matches canonical |
| `reattest <sid>` | `attest diff <sid>` | matches canonical |
| `prefetch` | `refresh --no-network` | matches canonical |
| `build-indexes` | `refresh --indexes-only` | matches canonical |

**Legacy passthrough verbs** — dispatch to the v0.10.x orchestrator script. The output shape is **NOT** identical to the canonical verb — it's the legacy `{timestamp, host, findings}` envelope. Use the canonical verb when you want the v0.11+ structured envelope contract; the passthrough is kept only for scripts that depend on the legacy output:

| Passthrough | Canonical (different output shape) |
|---|---|
| `scan` | `discover --scan-only` |
| `dispatch` | `discover` |
| `currency` | `doctor --currency` |

### Result envelope contract

Every `run` (and every per-playbook result inside a `ci` body) hoists the headline summary fields to the top of the JSON envelope so machine consumers do not have to walk `phases.*` to find them:

| Field | Type | Meaning |
|---|---|---|
| `ok` | boolean | `true` on success, `false` on blocked-at-preflight or persistence failure |
| `playbook_id` | string | Playbook id (present on blocked results too, so a `results[]` iterator can identify the row without joining against `playbooks_run[]` by index) |
| `directive_id` | string | Directive within the playbook |
| `session_id` | string | Run id (used by `attest verify <sid>` / `attest diff <sid>`) |
| `verdict` | string | One of `detected` / `not_detected` / `inconclusive` / `pending` / `skipped` / `blocked` |
| `rwep_score` | number \| null | `phases.analyze.rwep.adjusted`, or `null` on blocked / catalog-baseline-zero runs |
| `top_finding` | string \| null | First matched CVE id, or the indicator classification when no CVE correlated |
| `summary_line` | string | One-line human summary (~240 chars) — `<playbook>: <verdict> (rwep=<n>, <finding>, evidence=<state>)` |
| `evidence_completeness` | string | One of `complete` / `partial` / `missing` / `unknown` / `not-evaluated` |
| `indicators_evaluated` | number \| null | Indicators that produced a verdict |
| `indicators_known` | number \| null | Indicators declared by the playbook |
| `evidence_hash` | string | SHA-256 of the normalized submission |
| `submission_digest` | string | SHA-256 of the structured envelope |
| `attestation_path` | string | Absolute path to the persisted attestation JSON (success path only) |
| `preflight_issues` | array | Preconditions evaluated, with per-precondition `on_fail` + `check` |
| `precondition_check_source` | object | Per-precondition: `submission` / `runOpts` / `merged` |
| `phases` | object | Full per-phase outputs — `govern`, `direct`, `look`, `detect`, `analyze`, `validate`, `close` |

On a blocked result (preflight halt, missing precondition), `ok` is `false` and the envelope additionally carries `blocked_by` / `reason` / `remediation` / `phase: 'preflight'` / `verdict: 'blocked'`. `evidence_completeness` reports `not-evaluated`. In default human output a blocked result renders as a one-line `[blocked]` summary with the reason and a next step; `--json` / `--pretty` return the full envelope.

### Default terminal output vs `--json` / `--pretty`

By default `ci`, `run`, `attest verify`, `attest diff`, and `discover` emit a human-readable digest at the terminal — verdict line, per-playbook table (for `ci`), next-step block keyed on verdict (BLOCKED → `exceptd lint <pb> -`; NO_EVIDENCE → lint + `--evidence-dir`; FAIL → `--format markdown` / `--format csaf-2.0` per detected playbook; CLOCK_STARTED → CSAF advisory), pending jurisdiction obligations grouped by `clock_start_event`, deduped session warnings, framework-gap rollup.

Pass `--json` (compact) or `--pretty` (indented) to reach the structured envelope when automating. Setting `EXCEPTD_RAW_JSON=1` in the environment has the same effect. `--quiet` keeps human output but drops advisory stderr notes (and the deprecation / unsigned-attestation banners) so `run … 2>&1 | jq` stays clean; `--json-stdout-only` goes further and silences all stderr.

## Invoking a skill from your AI assistant

Once your assistant has loaded `AGENTS.md`, type a trigger phrase or skill name:

```
kernel-lpe-triage
ai-attack-surface
framework-gap-analysis NIST-800-53-SI-2 CVE-2026-31431
compliance-theater
global-grc NIS2
exploit-scoring CVE-2026-31431
zeroday-gap-learn CVE-2026-30615
security-maturity-tiers
pqc-first
```

## AI assistant configuration

The canonical agent-agnostic project rules live in `AGENTS.md` — the **only** project-rules file in this repo. The project does not ship per-vendor mirrors; each tool is configured to load `AGENTS.md` directly.

| Assistant | How it picks up the rules |
|-----------|---------------------------|
| OpenAI Codex CLI, Sourcegraph amp, Aider, Continue, Cline, Roo Code, Q Developer, and any tool that follows the cross-vendor `AGENTS.md` convention | Auto-loads `AGENTS.md` from the project root. |
| Cursor | Auto-loads `.cursorrules` (a short stub pointing at `AGENTS.md`). |
| GitHub Copilot | Auto-loads `.github/copilot-instructions.md` (stub pointing at `AGENTS.md`). |
| Windsurf | Auto-loads `.windsurfrules` (stub pointing at `AGENTS.md`). |
| Anthropic Claude Code | Doesn't auto-load `AGENTS.md`. Load it manually with `@AGENTS.md` on the first turn, or add your own per-machine `~/.claude/CLAUDE.md` that references it. The project intentionally does not ship a `CLAUDE.md` mirror. |
| Google Gemini CLI, JetBrains AI, Replit Agent, anything else | Point the tool at `AGENTS.md` via its config, or load `CONTEXT.md` manually for a shorter orientation. |

If your tool has a conventional auto-load filename not listed here and you'd like first-class support, open an issue — we'll add a pointer stub.

## Pre-computed indexes

`data/_indexes/` ships 17 derived files so AI consumers can answer cross-reference questions without scanning every skill + catalog. Highlights:

- **`summary-cards.json`** — 100-word abstract per skill; what to load when planning a multi-skill workflow.
- **`recipes.json`** — 8 curated skill sequences for common use cases (AI red team prep, PCI audit defense, federal IR, DORA TLPT, K-12 EdTech review, ransomware tabletop, new-CVE triage, OSS dep triage).
- **`chains.json`** — pre-hydrated cross-walks per CVE and per CWE: which skills cite this, which framework gaps it surfaces, which D3FEND countermeasures back it.
- **`token-budget.json`** — approximate token cost per skill + per section for context budgeting.
- **`jurisdiction-clocks.json`** — normalized jurisdiction × obligation × hours matrix (breach notification, patch SLA) across 35 jurisdictions.
- **`did-ladders.json`** — canonical defense-in-depth ladders per attack class (prompt injection, kernel LPE, AI-as-C2, ransomware, supply chain, BOLA, model exfiltration, BEC).
- **`theater-fingerprints.json`** — structured records for the 7 compliance theater patterns: claim, audit evidence, reality, fast detection test, controls implicated.
- **`_meta.json`** — sha256 of every source file. The `validate-indexes` predeploy gate fails if any source changed after the last build; `build-indexes --changed` reads this to know what to rebuild.

Regenerate with `exceptd refresh --indexes-only`.

## For skill authors — `agents/`

The `agents/` directory ships markdown role cards documenting authoring conventions for contributors writing new skills or playbooks. The cards are reference material for humans and AI assistants editing the repo; the CLI runtime does not load them. Operators consuming `@blamejs/exceptd-skills` can ignore the directory.

## Data catalogs

All skills pull from `data/`. Cross-validated against canonical upstream sources via `exceptd refresh` / `exceptd doctor --cves` / `exceptd doctor --rfcs`.

To resolve a single citation rather than refresh the whole catalog, `exceptd cve <CVE-ID>` and `exceptd rfc <number>` return a status verdict for one id (catalog → resolved cache → one NVD / datatracker lookup, offline-capable). The lookup caches, so a fan-out of agents shares the answer instead of each independently re-researching the same citation.

- `cve-catalog.json` — CVE metadata with RWEP scores, CISA KEV status, PoC availability, live-patch info
- `atlas-ttps.json` — MITRE ATLAS v5.6.0 TTPs with gap flags and exploitation examples. Each TTP now carries a `cve_refs[]` back-edge — operators reading an ATLAS entry see the catalogued CVEs that cite it without grepping `cve-catalog.json`. The same back-edge is populated on `attack-techniques.json`, and each playbook carries a `_meta.fed_by[]` reverse field naming the upstream playbooks that chain into it.
- `framework-control-gaps.json` — Per-framework, per-control: what it was designed for vs. what it misses
- `exploit-availability.json` — PoC locations, weaponization status, AI-assist factor
- `global-frameworks.json` — All major global compliance frameworks (35 jurisdictions) with control inventories and lag scores
- `zeroday-lessons.json` — Zero-day → control gap → framework gap → new control requirement mappings
- `cwe-catalog.json` — CWE entries pinned to CWE v4.20 (Top 25 + AI- / supply-chain-relevant additions)
- `d3fend-catalog.json` — MITRE D3FEND defensive technique entries pinned to D3FEND v1.3.0
- `rfc-references.json` — IETF RFC / Internet-Draft references with status, errata, replaces / replaced-by, `last_verified`
- `dlp-controls.json` — DLP control entries indexed by channel / classifier / surface / enforcement / evidence

---

## Philosophy

**Compliance is not security.** A SOC 2 Type II report confirms that controls existed and operated effectively during the audit period. It says nothing about whether those controls are adequate for current attack patterns. When NIST 800-53 SI-2 says "apply security patches in a timely manner" and Copy Fail is a 732-byte deterministic root with a public PoC and no race condition, "timely" is the wrong frame entirely.

**Framework lag is measured in months.** MITRE ATLAS v5.6.0 (May 2026) is the most current AI threat framework available. It still lags real exploitation by 3-6 months. NIST AI RMF lags by years. ISO 27001:2022 has no AI-specific controls. These skills explicitly flag every place where framework coverage ends and real attacker capability begins.

**AI changed the exploit development timeline.** Copy Fail was discovered by an AI system in approximately one hour. 41% of 2025 zero-days involved AI-assisted reverse engineering on the attacker side. The time between vulnerability introduction and reliable exploitation is compressing faster than patch management processes can adapt. Risk scoring must reflect this.

**Every org has a compliance theater problem.** The question is not whether paper controls map to audit requirements. The question is whether those controls would actually detect or prevent an attack. These skills answer the second question.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Key rules:

- No new CVE reference without a complete `data/cve-catalog.json` entry
- No new framework gap claim without a `data/framework-control-gaps.json` entry
- No skill uses CVSS as the sole risk metric
- Every new zero-day triggers a `data/zeroday-lessons.json` entry

---

## License

Apache 2.0. See [LICENSE](LICENSE).

Community at [exceptd.com](https://exceptd.com).
