#!/usr/bin/env node
// One-shot backfill of theater_test field for data/framework-control-gaps.json.
// Hard Rule #6: every compliance-framework finding includes a specific test
// that distinguishes paper compliance from actual security.
//
// Per-entry tests are authored against the entry's framework + control_name +
// real_requirement so each one discriminates the named framework's paper
// language from the named real-world threat.

const fs = require('fs');
const path = require('path');

const CATALOG_PATH = path.resolve(__dirname, '..', 'data', 'framework-control-gaps.json');

const PAPER = 'compliance-theater';

// Map of entry-key → theater_test. Hand-authored, grouped by framework family
// so the discriminating test fits the language an auditor for THAT framework
// uses. Where two entries share the same audit pattern (e.g. several NIST
// 800-53 SI-* controls), the tests are similar in shape but worded against
// the specific control text — never literally copy-pasted.
const TESTS = {
  // ---------------------------------------------------------------------
  // Universal / cross-framework AI gaps
  // ---------------------------------------------------------------------
  'ALL-AI-PIPELINE-INTEGRITY': {
    claim: "We monitor our AI providers for security and treat model updates like any other vendor change.",
    test: "Pull the change-control register for the last 4 quarters; filter for entries where the affected asset is an externally hosted LLM, embedding model, or AI provider API. Count how many record (a) the model version pinned at the time, (b) a behavioural regression suite executed against the new version, and (c) the provider changelog reviewed with sign-off. Theater verdict if fewer than 90% of provider-side model updates produced an in-scope change-control entry, or if any sampled entry lacks a regression-suite artifact.",
    evidence_required: ["change-control register CSV export filtered to AI/ML assets", "behavioural regression test results bundle keyed to provider model versions", "provider changelog review log with reviewer identity + timestamp"],
    verdict_when_failed: PAPER
  },
  'ALL-MCP-TOOL-TRUST': {
    claim: "Developer tooling is governed; AI plugins are no different from any other dev dependency.",
    test: "Scan every developer endpoint and CI runner for installed MCP server manifests (.claude/, .cursor/, .vscode/, ~/.codeium/, etc.). For each discovered MCP server, attempt to verify a publisher signature, locate it in an organisational allowlist, and trace its tool-grant prompt history. Theater verdict if any endpoint has an MCP server that is unsigned, absent from the allowlist, or has tool grants that bypassed user prompting.",
    evidence_required: ["endpoint-scan output enumerating MCP server manifests with hashes", "organisational MCP allowlist (or evidence one does not exist)", "tool-grant audit log for one randomly selected developer over 30 days"],
    verdict_when_failed: PAPER
  },
  'ALL-PROMPT-INJECTION-ACCESS-CONTROL': {
    claim: "Our IAM controls cover all actions taken in our environment, including those by AI agents.",
    test: "Review the audit log for the past 30 days of any AI-agent service account. Sample 10 actions taken by the agent; for each, identify whether the action was the result of (a) an end-user request that the agent fulfilled within scope, or (b) content from a third-party data source (web page, document, RAG corpus) that influenced the action. Theater verdict if any sampled action originated from third-party content without per-action user re-authorization, or if the audit log does not preserve the prompt input chain for forensic reconstruction.",
    evidence_required: ["AI agent service account audit log 30d", "prompt input chain (system prompt + user prompt + tool results) for sampled actions", "policy text defining prompt-level scope for each agent role"],
    verdict_when_failed: PAPER
  },

  // ---------------------------------------------------------------------
  // Australian frameworks (Essential 8, ISM)
  // ---------------------------------------------------------------------
  'AU-Essential-8-App-Hardening': {
    claim: "We hardened user applications per Essential Eight Maturity Level 2; browsers and Office are locked down.",
    test: "Take the operator's hardened-application list. Confirm whether it enumerates AI coding assistants (Copilot, Cursor, Claude Code, Windsurf), MCP servers, and AI-tool config files (.claude/settings.json, .cursor/mcp.json, .vscode/settings.json:chat.tools.autoApprove) as in-scope. Pick a developer endpoint at random; verify those config files are integrity-monitored with the same alerting profile as security-sensitive files. Theater verdict if AI assistants are absent from the hardened-application list or if a config-file modification on the sampled endpoint would not generate an integrity alert.",
    evidence_required: ["hardened-application policy document with version date", "FIM/HIDS configuration showing watch list", "test-induced modification on a non-production endpoint to confirm alert fires"],
    verdict_when_failed: PAPER
  },
  'AU-Essential-8-Backup': {
    claim: "Daily backups with off-network retention satisfy Essential Eight Maturity Level 2 Strategy 8.",
    test: "From the latest backup catalogue, confirm presence of fine-tuned model weights, RAG corpora, and AI tool configuration files (.claude/settings.json, MCP server registry). Restore one RAG corpus to an isolated environment; per-document-hash compare to current production. Theater verdict if AI artefacts are absent from the catalogue, or if any document hash diverges from production without a documented authoring event explaining the divergence.",
    evidence_required: ["backup catalogue manifest", "test-restore log for one RAG corpus", "per-document hash diff between restored and production corpus"],
    verdict_when_failed: PAPER
  },
  'AU-Essential-8-MFA': {
    claim: "MFA is enforced on all administrative identities per Essential Eight ML2 with phishing-resistant factors.",
    test: "Sample 10 admin identities; for each, confirm the registered authenticator class is FIDO2/WebAuthn-bound (not SMS, voice, or TOTP). Then enumerate AI-provider service credentials (OpenAI, Anthropic, HuggingFace API tokens) used by the same admin scope; check token age and rotation policy. Theater verdict if any sampled human admin uses SMS/voice, or if any AI-provider credential has no rotation policy or is older than 90 days.",
    evidence_required: ["IdP authenticator export for sampled admins", "AI-provider credential inventory with creation/rotation timestamps", "documented credential rotation policy"],
    verdict_when_failed: PAPER
  },
  'AU-Essential-8-Patch': {
    claim: "We patch operating systems within the Essential Eight ML3 48-hour window for critical exploits.",
    test: "Pull the last 5 CISA KEV listings affecting an OS in scope. For each, measure elapsed time from KEV listing date to deployed-on-fleet-percentage >=95%. For one host that cannot accept a reboot in the window, confirm a live-patching capability is provisioned and was used. Theater verdict if any sampled KEV listing exceeded 48h to 95% fleet coverage, or if any 'cannot reboot' host lacks a live-patching pathway.",
    evidence_required: ["patch-deployment telemetry timestamped against KEV listing dates", "live-patch agent inventory with last-applied-patch evidence", "fleet coverage rollup per CVE"],
    verdict_when_failed: PAPER
  },

  // ---------------------------------------------------------------------
  // CIS Controls
  // ---------------------------------------------------------------------
  'CIS-Controls-v8-Control7': {
    claim: "We meet CIS Control 7 IG3 by remediating critical vulnerabilities within one month.",
    test: "Pull the vulnerability register for the past 12 months. Filter for CVEs that appeared on CISA KEV with public PoC during the period. For each, measure (a) time from KEV listing to verified mitigation, and (b) whether the mitigation was a live patch, configuration change, or isolation. Theater verdict if any KEV+PoC entry exceeded 4h to verified mitigation or if 'monthly cadence' was applied to a KEV-listed CVE.",
    evidence_required: ["vuln-management register CSV export with timestamped state transitions", "KEV listing dates per CVE", "mitigation evidence (patch deployment log, config change ticket, isolation network ACL)"],
    verdict_when_failed: PAPER
  },

  // ---------------------------------------------------------------------
  // CMMC / FedRAMP
  // ---------------------------------------------------------------------
  'CMMC-2.0-Level-2': {
    claim: "We are CMMC Level 2 attested across all 110 NIST 800-171 controls; CUI is protected end-to-end.",
    test: "Walk the 3.4.1 (CM) asset inventory and check for AI assistants and MCP servers with CUI-adjacent access. Then inspect 3.13 system-and-communications protections to confirm AI-API egress is enumerated as a CUI exfiltration channel with monitoring. Theater verdict if AI assistants are absent from the asset inventory, or if AI-API egress at the CUI boundary has no monitoring rule, or if cross-walks to UK DEF STAN / AU DISP for joint programmes are missing.",
    evidence_required: ["3.4.1 asset inventory export filtered to AI/ML and MCP entries", "egress monitoring rule export for AI-API destinations", "cross-walk document for joint programmes (if any)"],
    verdict_when_failed: PAPER
  },
  'FedRAMP-Rev5-Moderate': {
    claim: "All cloud services in our boundary are FedRAMP Moderate authorised; AI services are covered.",
    test: "Enumerate every AI/ML service consumed within the authorisation boundary. For each, locate either (a) a FedRAMP Moderate ATO letter, (b) a documented exception with risk acceptance signed by the AO, or (c) an equivalence path (StateRAMP, FedRAMP Tailored, etc.). Verify the SSP includes shared-responsibility language covering prompt data, output data, training opt-out, and retention. Theater verdict if any AI service is in use without one of (a)-(c), or if the SSP shared-responsibility matrix lacks AI-specific clauses.",
    evidence_required: ["AI service inventory keyed to FedRAMP marketplace IDs", "AO-signed risk acceptance for non-authorised AI services", "SSP excerpts showing AI shared-responsibility language"],
    verdict_when_failed: PAPER
  },

  // ---------------------------------------------------------------------
  // CWE / SBOM standards
  // ---------------------------------------------------------------------
  'CWE-Top-25-2024-meta': {
    claim: "Our SAST/DAST coverage maps to the CWE Top 25; we test for the most dangerous weaknesses.",
    test: "Pull the SAST/DAST rule pack and enumerate which CWE IDs each rule targets. Confirm rules exist for AI-specific CWE classes (CWE-1039 model integrity, CWE-1395 dependency on vulnerable third-party component, prompt-injection class CWEs). Run the rule pack against a known-vulnerable test fixture containing prompt-injection patterns. Theater verdict if AI-relevant CWE IDs are absent from the rule pack, or if the fixture run produces zero findings on the planted prompt-injection.",
    evidence_required: ["SAST/DAST rule-to-CWE mapping export", "test fixture with planted prompt-injection patterns", "scan report against the fixture"],
    verdict_when_failed: PAPER
  },
  'CycloneDX-v1.6-SBOM': {
    claim: "We ship a CycloneDX 1.6 SBOM with every release; supply-chain transparency is satisfied.",
    test: "Pull the SBOM for the most recent release. Confirm presence of an `mlComponent` (or equivalent ML-BOM) section enumerating model + adapters + tokenizer. Check provenance fields (signature, supplier, training data source) for empty values. Confirm MCP servers in the build environment are reflected. Theater verdict if ML components are absent, or if more than 20% of components have an empty provenance field.",
    evidence_required: ["latest CycloneDX 1.6 SBOM JSON", "ML-BOM section specifically", "MCP server manifest from build environment"],
    verdict_when_failed: PAPER
  },
  'SPDX-v3.0-SBOM': {
    claim: "We publish SPDX 3.0 SBOMs and they include AI-BOM coverage per the AI profile.",
    test: "Pull the SPDX 3.0 document for the most recent release. Confirm the `Build` profile and `AI` profile are both declared. Inspect AI-profile sections for populated `useSensitivePersonalInformation`, `safetyRiskAssessment`, `modelDataPreprocessing`, and training-data fields. Cross-walk SPDX AI-BOM identifiers against CycloneDX ML-BOM identifiers to confirm consistency. Theater verdict if the AI profile is declared but key fields are empty, or if SPDX↔CycloneDX cross-walk produces conflicting model identities.",
    evidence_required: ["latest SPDX 3.0 document with profile declarations", "AI-profile field-population coverage report", "SPDX↔CycloneDX cross-walk mapping"],
    verdict_when_failed: PAPER
  },

  // ---------------------------------------------------------------------
  // EU DORA family
  // ---------------------------------------------------------------------
  'DORA-Art28': {
    claim: "Our DORA Art. 28 ICT third-party register covers all critical or important function dependencies.",
    test: "From the Art. 28 register, sample 5 third-party ICT services consumed in CIF (critical or important function) flows. For each, verify presence of build-provenance metadata (SLSA producer identifier, workflow file hash, cache key surface). Check for monthly producer-side cache verification evidence. Theater verdict if any sampled CIF dependency lacks build-provenance metadata, or if cache verification has not run in the last 90 days.",
    evidence_required: ["Art. 28 register export with provenance fields", "monthly cache-verification job logs", "SLSA attestations from sampled producers"],
    verdict_when_failed: PAPER
  },
  'DORA-RTS-Subcontracting': {
    claim: "Our DORA RTS subcontracting register lists every sub-processor for ICT services supporting CIF.",
    test: "Pull the subcontracting register. Confirm enumeration of AI sub-processors per ICT service line: model providers, embedding providers, vector stores, RAG corpus hosts, MCP server providers. Compute foundation-model concentration (% of CIF flows that share a single foundation model). Theater verdict if AI sub-processors are absent from any service line that consumes AI, or if foundation-model concentration is undocumented.",
    evidence_required: ["subcontracting register export with AI sub-processor entries", "foundation-model concentration analysis report", "exit-strategy evidence per critical AI sub-processor"],
    verdict_when_failed: PAPER
  },
  'DORA-ITS-TLPT': {
    claim: "Our most recent threat-led penetration test under DORA Art. 26 covered the full CIF estate.",
    test: "Pull the TLPT scoping template and final report. Confirm AI/MCP assets are enumerated in scope. Verify the threat-intel inputs cite ATLAS TTPs and AI-discovered CVE classes. Confirm the TLPT team includes documented AI/MCP competency. Inspect the report for at least one finding originating from an AI/MCP attack path. Theater verdict if the scoping template excludes AI/MCP assets despite their presence in CIF flows, or if the team lacks documented AI competency.",
    evidence_required: ["TLPT scoping template", "TLPT final report with AI/MCP findings section", "TLPT team CVs covering AI/MCP red-team experience"],
    verdict_when_failed: PAPER
  },
  'DORA-RTS-Incident-Classification': {
    claim: "Our incident-classification process implements the DORA RTS criteria for major ICT incidents.",
    test: "Pull the incident register for the last 12 months. For each major-classified incident, confirm presence of qualitative criteria evaluation. Then ask whether AI-incident classes (model invocations on injected intent, RAG corpus integrity loss, agent actions outside scope) would surface a major classification under the current criteria. Theater verdict if AI-class quantitative measures are absent, or if a synthetic AI-incident scenario evaluated against current criteria fails to trigger major classification when impact warrants it.",
    evidence_required: ["incident register CSV with classification rationale per entry", "RTS criteria mapping document", "synthetic AI-incident classification dry-run record"],
    verdict_when_failed: PAPER
  },
  'DORA-IA-CTPP-Oversight': {
    claim: "We track designated critical third-party providers (CTPPs) per DORA Art. 31-44.",
    test: "Pull the CTPP designation list. Confirm whether frontier-AI providers and MCP/agent-runtime providers consumed by the entity appear or have a documented evaluation against designation criteria. Check Lead Overseer audit deliverables for AI-specific artefacts (model cards, system cards, eval results, training data manifests). Theater verdict if AI providers consumed at scale are absent without an evaluation record, or if Lead Overseer artefacts lack AI-specific content.",
    evidence_required: ["CTPP designation list with evaluation rationale", "Lead Overseer engagement record with deliverable list", "AI-provider concentration analysis"],
    verdict_when_failed: PAPER
  },
  'DORA-Art-19-IdP-4h': {
    claim: "We can meet the DORA Art. 19 4-hour major-ICT-incident notification clock for IdP compromise.",
    test: "Run a tabletop: at T0 a SIEM alert fires for IdP token-signing certificate rotation by an unrecognised principal. Stopwatch the elapsed time from T0 to a draft notification ready for the Competent Authority covering scope, root cause hypothesis, impacted services, and recovery posture. Theater verdict if elapsed time exceeds 4h, or if the playbook does not name the on-call who initiates the clock, or if the tabletop has not been run in the last 12 months.",
    evidence_required: ["tabletop execution log with stopwatch timestamps", "DORA notification draft produced under exercise", "on-call rota covering 24/7 IdP-incident response"],
    verdict_when_failed: PAPER
  },
  'DORA-Art-21-Telecom-ICT': {
    claim: "Our telecom ICT third-party arrangements satisfy DORA Art. 21.",
    test: "Pull the Art. 21 ICT register; filter for telecom-class providers (carriers, MVNOs, SMS gateways, voice carriers). Confirm enumeration of LI-gateway access risk, signaling-protocol exposure (SS7/Diameter/HTTP/2 for 5G), and sub-carrier visibility into CIF flows. Theater verdict if telecom providers appear only as 'connectivity vendors' without carrier-class threat-model entries, or if no concentration analysis exists across telecom providers.",
    evidence_required: ["Art. 21 ICT register telecom subset", "carrier-class threat-model document", "concentration analysis report"],
    verdict_when_failed: PAPER
  },

  // ---------------------------------------------------------------------
  // EU AI Act
  // ---------------------------------------------------------------------
  'EU-AI-Act-Art-15': {
    claim: "Our high-risk AI system meets the EU AI Act Art. 15 'appropriate level of cybersecurity'.",
    test: "Request the cybersecurity test pack. Confirm presence of (a) prompt-injection red-team results bound to OWASP LLM Top 10, (b) RAG-corpus integrity test results, (c) model-extraction-resistance assessment, (d) MCP/plugin trust verification log. Then check incident-reporting bridge to NIS2 + DORA. Theater verdict if any of (a)-(d) are absent or older than 12 months, or if the bridge to NIS2/DORA notification clocks is undocumented.",
    evidence_required: ["adversarial test pack covering OWASP LLM Top 10", "RAG corpus integrity test report", "incident-reporting playbook with NIS2/DORA bridge"],
    verdict_when_failed: PAPER
  },
  'EU-AI-Act-Art-53-GPAI': {
    claim: "We comply with EU AI Act Art. 53 GPAI provider obligations including training-data summary publication.",
    test: "Pull the published training-data summary. Confirm machine-readable corpus-level granularity sufficient for copyright audit (per-corpus identifier + size + collection method + opt-out evidence). Walk downstream-provider documentation; confirm signed bindings to a production model fingerprint. Theater verdict if the summary is prose-only without machine-readable structure, or if downstream docs reference an unsigned/floating model identity.",
    evidence_required: ["machine-readable training-data summary file (YAML/JSON)", "downstream documentation bundle with signed model fingerprint", "per-corpus copyright-policy attestations"],
    verdict_when_failed: PAPER
  },
  'EU-AI-Act-Art-55-Systemic': {
    claim: "Our GPAI model with systemic risk meets the additional Art. 55 obligations.",
    test: "Pull the adversarial-evaluation report. Confirm coverage of OWASP LLM Top 10 + ATLAS TTPs + MCP-trust scenarios. Pull the energy report; confirm kWh-per-million-tokens and training compute under ISO/IEC TR 24028 framing. Cross-walk the incident-reporting clock with DORA Art. 19 timing. Theater verdict if the eval omits any of OWASP/ATLAS/MCP coverage, if energy reporting is qualitative only, or if the incident-clock cross-walk is missing.",
    evidence_required: ["adversarial eval report with method per attack class", "energy reporting per ISO/IEC TR 24028", "incident-clock cross-walk to DORA"],
    verdict_when_failed: PAPER
  },
  'EU-AI-Act-Annex-IX-Conformity': {
    claim: "Our high-risk AI system passed conformity assessment per Annex IX.",
    test: "If internal-control route was used: request the third-party sample audit (e.g. AI-Office annual sampling) outcome. If notified-body route: request the body's scope letter and confirm AI-specific competency. For both, confirm an operational definition of 'substantial modification' covers fine-tuning, RAG changes, and system-prompt changes — and that a recent change was assessed against it. Theater verdict if the sampling/notified-body record is absent, or if substantial-modification gating has never fired despite a known fine-tune or RAG change.",
    evidence_required: ["internal-control attestation + sampling outcome OR notified-body scope letter", "substantial-modification policy document", "change log showing modifications assessed against the policy"],
    verdict_when_failed: PAPER
  },
  'EU-AI-Act-GPAI-CoP': {
    claim: "We follow the GPAI Code of Practice as our presumed-compliance route for Art. 53/55.",
    test: "Confirm signatory status. Pull the AI Office's published enforcement-deference position for code-conformant signatories. For each evidentiary commitment in the Code, locate the artefact (training-data summary, eval report, downstream-distributor list, energy report) and confirm it is current. Theater verdict if signatory but any required Code artefact is missing or older than the Code's refresh cadence.",
    evidence_required: ["Code-of-Practice signatory confirmation", "evidentiary artefact bundle keyed to Code commitments", "AI Office enforcement-deference reference"],
    verdict_when_failed: PAPER
  },

  // ---------------------------------------------------------------------
  // EU CRA
  // ---------------------------------------------------------------------
  'EU-CRA-Art13': {
    claim: "We satisfy EU CRA Art. 13 essential cybersecurity requirements with technical documentation on file.",
    test: "Request the canonical build-pipeline definition for the most recent release. Confirm publication alongside the release artifact (workflow file hash, runner attestation, secrets scope). Pick the release-being-installed at a downstream operator; verify its build pipeline matches the published definition by comparing producer-side hashes. Confirm the incident-notification clock starts from FIRST awareness (not from confirmed exploit). Theater verdict if pipeline definitions are unpublished, hashes diverge, or the clock policy starts later than first awareness.",
    evidence_required: ["published build-pipeline definition with hashes", "downstream-side hash verification log", "incident-notification policy document"],
    verdict_when_failed: PAPER
  },

  // ---------------------------------------------------------------------
  // HIPAA
  // ---------------------------------------------------------------------
  'HIPAA-Security-Rule-164.312(a)(1)': {
    claim: "We meet HIPAA 164.312(a)(1) access controls; PHI is access-controlled with unique user IDs.",
    test: "Inventory AI providers in use; for each consuming PHI, locate a BAA covering prompt retention + training opt-out + breach notification within HIPAA timelines. Inspect prompt-flow telemetry for PHI; confirm DLP minimisation runs pre-egress. Confirm AI agent sessions have controls separate from human user controls. Theater verdict if any AI provider consuming PHI lacks a BAA, if DLP is absent on prompt egress, or if AI agent sessions inherit human controls without separation.",
    evidence_required: ["AI-provider BAA bundle", "DLP rule export for prompt egress", "agent-session control configuration"],
    verdict_when_failed: PAPER
  },
  'HIPAA-Security-Rule-2026-NPRM-164.308': {
    claim: "Our administrative safeguards meet the HIPAA Security Rule including 2026 NPRM updates.",
    test: "Walk the technology-asset register; confirm AI assistants and model-API providers are enumerated as asset categories. Pull the network map; confirm AI-API egress routes are marked with BAA and training-opt-out attestation. Confirm the tabletop catalogue contains at least one AI-specific PHI loss scenario exercised in the past 12 months. Theater verdict if AI assets are absent, network-map AI routes lack attestations, or the tabletop catalogue has no AI scenario.",
    evidence_required: ["technology-asset register with AI categories", "network map with AI-API egress annotations", "tabletop exercise catalogue with execution dates"],
    verdict_when_failed: PAPER
  },
  'HIPAA-Security-Rule-2026-NPRM-164.310': {
    claim: "Our physical safeguards meet HIPAA 164.310 including network-access logging in the 2026 NPRM.",
    test: "Sample developer endpoints with PHI exposure. Confirm AI-API session logging is captured under the network-access-logging mandate (timestamp, user, prompt hash, response hash, destination provider). Confirm media-disposal verification extends to AI training-data opt-out attestation per provider. Theater verdict if AI-API sessions are unlogged, or if any departed user retained AI provider credentials past their termination date.",
    evidence_required: ["AI-API session log sample for sampled endpoints", "training-data opt-out attestation per AI provider", "departed-user credential-revocation evidence"],
    verdict_when_failed: PAPER
  },
  'HIPAA-Security-Rule-2026-NPRM-164.312': {
    claim: "Our technical safeguards meet HIPAA 164.312 including the 2026 NPRM expansions.",
    test: "Pick 5 AI-agent flows that touch PHI. For each, confirm a per-action MFA-equivalent (delegated-authority attestation) is captured. Inspect storage of AI-provider artifacts (conversation history, embeddings, fine-tune sets) for encryption-at-rest. Confirm prompt-injection and RAG-poisoning detection rules exist as anti-malware-equivalents. Theater verdict if per-action attestations are absent, AI artifacts are stored unencrypted, or no prompt-injection/RAG-poisoning detection rules exist.",
    evidence_required: ["delegated-authority attestation samples", "encryption-at-rest configuration for AI artifacts", "prompt-injection / RAG-poisoning detection rule export"],
    verdict_when_failed: PAPER
  },
  'HIPAA-Security-Rule-2026-NPRM-164.314': {
    claim: "Our BAAs satisfy HIPAA 164.314 organisational requirements including 2026 NPRM AI provisions.",
    test: "Pull the AI-provider BAA portfolio. Confirm each contract covers (a) prompt retention policy with explicit duration, (b) training opt-out with attestation evidence, (c) breach-notification timeline aligned with HIPAA, (d) sub-processor disclosure. Theater verdict if any AI provider's BAA is silent on prompt retention, training opt-out, or sub-processors, or if 'training opt-out' is contractual without an evidence path.",
    evidence_required: ["AI-provider BAA portfolio with clause-by-clause checklist", "training-opt-out attestation evidence per provider", "sub-processor disclosure inventories"],
    verdict_when_failed: PAPER
  },

  // ---------------------------------------------------------------------
  // HITRUST
  // ---------------------------------------------------------------------
  'HITRUST-CSF-v11.4-09.l': {
    claim: "We meet HITRUST CSF 09.l outsourced services management for all third-party providers.",
    test: "Pull the third-party register. Filter for AI providers; confirm AI vendors are inventoried separately from general SaaS. Spot-check 5 AI vendors for AI-specific contractual clauses (prompt retention, training opt-out, residency, model version pinning, prompt-breach notification). Search for self-signup AI usage on developer endpoints; confirm a policy prohibits it for in-scope data. Theater verdict if AI is bucketed inside generic SaaS, if any sampled AI vendor lacks AI-specific clauses, or if self-signup AI is in evidence on a developer endpoint that touches in-scope data.",
    evidence_required: ["third-party register with AI subset", "AI-specific contract clause checklist per vendor", "endpoint scan for self-signup AI tools"],
    verdict_when_failed: PAPER
  },

  // ---------------------------------------------------------------------
  // IEC 62443 / NIST 800-82 / NERC CIP — OT / ICS
  // ---------------------------------------------------------------------
  'IEC-62443-3-3': {
    claim: "Our IACS architecture meets IEC 62443-3-3 system security requirements.",
    test: "Inspect the zone-and-conduit diagram. Confirm AI operator assistants and AI-API egress paths from the corporate-to-OT boundary are enumerated as conduits with documented security levels. Sample 3 OT operator workstations; confirm any installed AI assistants are inventoried and that prompt-injection-class threats appear in the threat model. Theater verdict if AI conduits are absent from the zone diagram, or if AI assistants on OT operator workstations are not threat-modelled.",
    evidence_required: ["zone-and-conduit diagram with AI annotations", "OT operator workstation inventory", "threat-model document covering AI conduit threats"],
    verdict_when_failed: PAPER
  },
  'NIST-800-82r3': {
    claim: "Our OT environment is secured per NIST SP 800-82 Rev 3 guidance.",
    test: "Confirm the OT asset inventory enumerates AI operator assistants, AI-API egress at the IT/OT boundary, and any MCP servers running on engineering workstations. Inspect monitoring rules for AI-prompted operator actions. Theater verdict if AI assets are absent from the OT inventory, or if no monitoring rule alerts on AI-initiated control-system commands.",
    evidence_required: ["OT asset inventory with AI subset", "monitoring rule export for AI-prompted operator actions", "engineering workstation MCP-server scan"],
    verdict_when_failed: PAPER
  },
  'NERC-CIP-007-6-R4': {
    claim: "We satisfy NERC CIP-007-6 R4 security event monitoring for our BES Cyber Systems.",
    test: "Pull the R4 monitored-event source list. Confirm AI operator assistants are enumerated with explicit alerting on assistant-initiated operator commands. Confirm AI-API egress at the corporate-to-OT boundary is monitored. Confirm prompt-injection indicators are present as a distinct event class. Theater verdict if AI assistants are not monitored event sources, or if no NIS2 24h/72h alignment is documented for multinational operators.",
    evidence_required: ["R4 event source inventory", "alerting rule export for AI-initiated commands", "NIS2 alignment document where applicable"],
    verdict_when_failed: PAPER
  },

  // ---------------------------------------------------------------------
  // ISO 27001 / ISO 27017 / ISO 23894 / ISO 42001
  // ---------------------------------------------------------------------
  'ISO-27001-2022-A.8.16': {
    claim: "Our monitoring activities under ISO 27001:2022 A.8.16 cover all in-scope systems.",
    test: "From the SIEM event-source inventory, confirm AI-API egress events, MCP server invocations, and AI-agent action audit logs are ingested. Sample one alert from each class in the past 30 days; confirm an analyst reviewed it. Theater verdict if any of those source classes are missing from the SIEM, or if no AI/MCP-related alert has been triaged in the past 90 days despite traffic being present.",
    evidence_required: ["SIEM event-source inventory", "alert triage records for AI/MCP-class alerts", "telemetry volume report by source class"],
    verdict_when_failed: PAPER
  },
  'ISO-27001-2022-A.8.28': {
    claim: "We follow secure coding practices per ISO 27001:2022 A.8.28.",
    test: "Pull the secure-coding standard. Confirm it addresses AI-generated code (Copilot, Claude Code, Cursor diffs) with reviewer-attestation requirements and prompt-injection-class CWE coverage. Check git history for AI-coauthored commits; confirm the pre-merge review record is preserved. Theater verdict if the standard is silent on AI-generated code, or if AI-attributed commits lack a reviewer-attestation trail.",
    evidence_required: ["secure-coding standard document with version date", "git history sample with AI-attribution analysis", "code-review records for AI-attributed diffs"],
    verdict_when_failed: PAPER
  },
  'ISO-27001-2022-A.8.30': {
    claim: "Our outsourced development meets ISO 27001:2022 A.8.30 oversight requirements.",
    test: "Pull the outsourced-dev contract bundle. Confirm clauses naming AI tool usage by the contractor (which AI assistants, which models, which prompt destinations) and reviewer attestation for AI-generated diffs. Sample one delivered build; confirm SBOM enumerates AI-build dependencies. Theater verdict if contracts are silent on contractor AI usage, or if delivered SBOMs omit AI build-environment components.",
    evidence_required: ["outsourced-dev contract clause export", "delivered build SBOM", "contractor AI-usage attestation"],
    verdict_when_failed: PAPER
  },
  'ISO-27001-2022-A.8.8': {
    claim: "We manage technical vulnerabilities per ISO 27001:2022 A.8.8.",
    test: "Pull the vuln-management procedure. Confirm a CISA-KEV-anchored response tier (4h to verified mitigation for KEV+PoC). Pull the past 12 months of KEV-listed CVEs in scope; measure time-to-mitigation. Theater verdict if the procedure has only a generic 'critical = 30 days' SLA, or if any KEV+PoC entry exceeded the documented tier.",
    evidence_required: ["A.8.8 procedure document", "KEV-listed CVE list with mitigation timestamps", "live-patching capability evidence"],
    verdict_when_failed: PAPER
  },
  'ISO-IEC-23894-2023-clause-7': {
    claim: "We perform AI risk assessment per ISO/IEC 23894:2023 clause 7.",
    test: "Pull the most recent AI risk assessment. Confirm coverage of supply-chain risks (model provenance, MCP/plugin trust, training-data integrity), prompt-injection as a current threat, and operational AI-incident scenarios. Confirm the assessment is dated within the framework's review cadence. Theater verdict if supply-chain or prompt-injection risks are absent, or if the assessment has no documented owner who acted on findings.",
    evidence_required: ["AI risk assessment document", "risk-treatment plan with action owner", "review-cadence schedule"],
    verdict_when_failed: PAPER
  },
  'ISO-IEC-42001-2023-clause-6.1.2': {
    claim: "Our AI Management System satisfies ISO/IEC 42001:2023 clause 6.1.2 risk-treatment requirements.",
    test: "Walk the AIMS risk-treatment register. Confirm prompt injection, MCP/agent trust, RAG-poisoning, and model-supply-chain compromise appear as named risks with treatment plans. Confirm owner + due-date + verification path for each. Theater verdict if any of those risk classes are absent, or if treatments have no verification path documented.",
    evidence_required: ["AIMS risk-treatment register export", "risk-treatment plan with verification paths", "AIMS internal audit report"],
    verdict_when_failed: PAPER
  },
  'ISO-27017-Cloud-IAM': {
    claim: "Our cloud-IAM posture is hardened per ISO/IEC 27017:2015 cloud-services controls.",
    test: "Inspect cloud-IAM configuration: managed identities token-bound to instance identity (where supported); IMDSv2 required with hop-limit and short token TTL; bearer-token TTLs ≤1h non-CAE / ≤24h with Continuous Access Evaluation. Spot-check 10 cross-account assume-role chains and confirm subject-claim specificity > 'wildcard'. Theater verdict if IMDSv1 is in use anywhere, if bearer TTLs exceed the ceilings, or if any sampled cross-account chain has wildcard subject claims.",
    evidence_required: ["cloud-IAM configuration export per CSP", "IMDSv2 enforcement audit", "assume-role policy document sample"],
    verdict_when_failed: PAPER
  },

  // ---------------------------------------------------------------------
  // NIS2
  // ---------------------------------------------------------------------
  'NIS2-Art21-incident-handling': {
    claim: "We can meet NIS2 Art. 21 incident handling obligations including the 24h early warning.",
    test: "Run a tabletop with a synthetic significant-incident inject affecting an essential-service flow at T0. Stopwatch elapsed time to a Competent Authority early warning containing initial assessment, severity, and impact. Theater verdict if elapsed exceeds 24h, if no on-call is named to start the clock, or if the playbook has not been exercised in the past 12 months.",
    evidence_required: ["tabletop execution log", "early-warning notification draft", "on-call rota and playbook ownership"],
    verdict_when_failed: PAPER
  },
  'NIS2-Art21-patch-management': {
    claim: "Our patch-management posture meets NIS2 Art. 21(2)(e) for technical and organisational measures.",
    test: "Pull the patch SLA document. Confirm a CISA-KEV-anchored tier (4h to verified mitigation for KEV+PoC). Cross-reference past 12 months of KEV-listed CVEs in scope; measure compliance. Confirm live-patching capability for hosts that cannot reboot in window. Theater verdict if the SLA collapses to 'critical = 30 days' across the board, or if any KEV+PoC entry breached the documented tier.",
    evidence_required: ["patch SLA document", "KEV listing→mitigation telemetry", "live-patching agent inventory"],
    verdict_when_failed: PAPER
  },
  'NIS2-Annex-I-Telecom': {
    claim: "Our NIS2 Annex I telecom obligations are satisfied; signaling and LI-system risks are managed.",
    test: "Confirm gNB firmware hash attestation pipeline runs continuously across the production fleet. Confirm signaling-anomaly baselines exist per PLMN-pair and that anomalies trigger SOC tickets. Confirm LI-gateway activation auditing runs at least quarterly. Theater verdict if any of those streams are absent, or if no signaling anomaly has been triaged in 90 days despite carrier-pair traffic.",
    evidence_required: ["gNB firmware hash attestation telemetry", "signaling-anomaly baseline document and recent alerts", "LI-gateway activation audit log"],
    verdict_when_failed: PAPER
  },
  'NIS2-Art-21-Federated-Identity': {
    claim: "Our identity-provider risk management satisfies NIS2 Art. 21 for federated-identity dependencies.",
    test: "From the supply-chain register, confirm each IdP (Okta, Entra ID, Auth0, Ping, Google Workspace) is listed as an essential-service dependency with concentration analysis. Inspect monitoring rules for token-signing certificate rotation, claim-transformation rule changes, and management-API token activity. Theater verdict if IdPs appear only as 'IT vendor' without dependency-class treatment, or if token-signing rotation events have no alerting rule.",
    evidence_required: ["supply-chain register IdP subset", "IdP control-plane monitoring rule export", "IdP concentration analysis"],
    verdict_when_failed: PAPER
  },

  // ---------------------------------------------------------------------
  // NIST SPs and AI RMF
  // ---------------------------------------------------------------------
  'NIST-800-115': {
    claim: "Our pen-test methodology aligns with NIST SP 800-115 technical guidance.",
    test: "Pull the most recent pen-test report. Confirm coverage of AI/MCP attack surfaces (prompt injection, MCP plugin trust, RAG corpus integrity, AI-API egress). Confirm the testing methodology document references AI-specific test classes and tooling. Theater verdict if AI/MCP testing is absent from the methodology, or if the pen-test report contains no AI-class findings despite AI being in production.",
    evidence_required: ["pen-test methodology document", "most-recent pen-test report with AI/MCP test sections", "tester competency CV/credentials"],
    verdict_when_failed: PAPER
  },
  'NIST-800-218-SSDF': {
    claim: "We follow NIST SSDF practices for secure software development.",
    test: "Pull the SSDF mapping document. Confirm AI-generated code provenance practices (per-block AI authorship attestation, reviewer identity, human approval before merge). Inspect git history; confirm AI-attributed commits have linked review records. Pull build-time SBOM; confirm AI build-tooling is enumerated. Theater verdict if AI authorship is unattributed, AI commits bypass review, or build-time SBOM omits AI tooling.",
    evidence_required: ["SSDF mapping document", "AI-attribution policy + recent merge sample", "build-time SBOM"],
    verdict_when_failed: PAPER
  },
  'NIST-800-53-AC-2': {
    claim: "Our account management satisfies NIST 800-53 AC-2 across all account types.",
    test: "Inventory AI-agent service accounts. For each, confirm an authorization context defines (who initiated each invocation, what actions are in scope, what tools are authorised). Pull AC-2 audit log for one agent over 7 days; confirm prompt-level access decisions are reconstructable. Theater verdict if AI-agent accounts have no per-session authorisation context, or if AC-2 logs collapse to 'service account X did Y' without prompt-input chain.",
    evidence_required: ["AI-agent service account inventory", "authorization-context policy document", "7-day audit log sample with prompt input chain"],
    verdict_when_failed: PAPER
  },
  'NIST-800-53-CM-7': {
    claim: "We enforce least-functionality per NIST 800-53 CM-7 across all configuration items.",
    test: "Sample 5 developer endpoints. Enumerate installed MCP servers + AI plugins; confirm each is on an organisational allowlist with documented business justification. Confirm tool-grant default is deny with explicit per-tool prompts. Theater verdict if any sampled endpoint runs an MCP server absent from the allowlist, or if any tool-grant defaults to allow without prompting.",
    evidence_required: ["endpoint MCP/plugin inventory for sampled hosts", "organisational allowlist with justifications", "tool-grant default-policy export"],
    verdict_when_failed: PAPER
  },
  'NIST-800-53-SA-12': {
    claim: "Our supply chain protection practices meet NIST 800-53 SA-12.",
    test: "Pull the supplier-protection program. Confirm AI providers are enumerated with the same diligence as software suppliers (security questionnaire, SOC 2 review, contractual breach-notification). Confirm model and MCP-server provenance attestation is collected at consumption. Theater verdict if AI providers are exempt from supplier diligence, or if model artefacts are consumed without provenance attestation.",
    evidence_required: ["supplier-protection program document", "AI-provider diligence record sample", "model-provenance attestations at consumption"],
    verdict_when_failed: PAPER
  },
  'NIST-800-53-SC-28': {
    claim: "Information at rest is protected per NIST 800-53 SC-28 with encryption.",
    test: "Inventory AI-provider artefact storage (conversation history, embeddings, fine-tune sets, vector indices). Confirm encryption-at-rest with key management by an in-scope KMS. Spot-check 3 storage locations; confirm key access is logged. Theater verdict if any AI artefact storage is unencrypted, key management is provider-default with no in-scope KMS, or key access is unlogged.",
    evidence_required: ["AI artefact storage inventory", "KMS key-policy export", "key access log sample"],
    verdict_when_failed: PAPER
  },
  'NIST-800-53-SC-7': {
    claim: "Boundary protection is enforced per NIST 800-53 SC-7 for the system boundary.",
    test: "Inspect egress firewall rules for AI-API destinations (api.openai.com, api.anthropic.com, generativelanguage.googleapis.com, etc.). Confirm allowlist with documented business justification per destination. Confirm logging captures prompt hash + identity per egress. Theater verdict if AI destinations are reachable from any source without allowlist enforcement, or if egress logs lack identity binding.",
    evidence_required: ["egress firewall rule export", "AI destination allowlist with justifications", "egress log sample with identity binding"],
    verdict_when_failed: PAPER
  },
  'NIST-800-53-SC-8': {
    claim: "Transmission confidentiality and integrity is protected per NIST 800-53 SC-8.",
    test: "Confirm TLS 1.3 (or PQC-hybrid where deployed) on every AI-API destination, including any internal gateways. Inspect MCP server transport; confirm authentication and integrity (signed JWT or mTLS) on MCP traffic. Theater verdict if any AI-API egress allows TLS<1.2 or unauthenticated MCP transport.",
    evidence_required: ["TLS configuration audit per destination", "MCP transport configuration", "PQC migration roadmap if claimed"],
    verdict_when_failed: PAPER
  },
  'NIST-800-53-SI-10': {
    claim: "We validate information inputs per NIST 800-53 SI-10.",
    test: "Inspect input-validation rules at AI prompt boundaries: system-prompt protection from third-party content, RAG-corpus content sanitisation, tool-output sanitisation before re-injection. Theater verdict if no input validation exists at any of those boundaries, or if SI-10 evidence cites only HTML/SQL escaping without prompt-injection treatment.",
    evidence_required: ["input-validation policy at prompt boundaries", "RAG-corpus sanitisation rule export", "tool-output sanitisation logic"],
    verdict_when_failed: PAPER
  },
  'NIST-800-53-SI-12': {
    claim: "Information handling and retention satisfies NIST 800-53 SI-12.",
    test: "Pull the records-retention schedule. Confirm AI artefacts (prompts, outputs, embeddings, fine-tune sets) appear with explicit retention periods aligned to data-classification. Confirm provider-side retention is documented per AI provider with attestation. Theater verdict if AI artefacts are absent from the retention schedule, or if provider-side retention is undocumented.",
    evidence_required: ["records-retention schedule with AI categories", "provider retention attestation per AI provider", "deletion verification log"],
    verdict_when_failed: PAPER
  },
  'NIST-800-53-SI-2': {
    claim: "Flaw remediation is timely per NIST 800-53 SI-2.",
    test: "Pull the flaw-remediation SLA. Confirm a KEV-anchored tier (≤4h for KEV+PoC). Pull the past 12 months of KEV listings affecting in-scope assets; measure deployment compliance. Confirm live-patching is provisioned for hosts that can't reboot in window. Theater verdict if the SLA does not have a KEV tier or if KEV compliance dropped below 95%.",
    evidence_required: ["SI-2 SLA document", "KEV deployment timeline per CVE", "live-patching agent inventory"],
    verdict_when_failed: PAPER
  },
  'NIST-800-53-SI-3': {
    claim: "Malicious code protection is in place per NIST 800-53 SI-3.",
    test: "Confirm SI-3 controls cover prompt-injection (input-side malicious instructions delivered via third-party content) and RAG-poisoning (corpus-side malicious instructions). Confirm detection rules exist and have triggered at least once on synthetic test inputs. Theater verdict if SI-3 evidence cites only AV signatures without prompt-injection or RAG-poisoning treatment.",
    evidence_required: ["SI-3 control description with AI extensions", "prompt-injection / RAG-poisoning detection rule export", "synthetic-input test results"],
    verdict_when_failed: PAPER
  },
  'NIST-800-63B-rev4': {
    claim: "Our digital-identity authentication satisfies NIST SP 800-63B Rev 4 at the targeted AAL.",
    test: "Sample 10 admin identities; confirm registered authenticator class is FIDO2/WebAuthn-bound (phishing-resistant). Confirm session re-authentication on high-risk actions. Confirm service-account token lifecycles match the AAL claim (no long-lived bearer tokens for AAL3-claimed scopes). Theater verdict if any admin uses SMS/voice/TOTP for an AAL3-claimed scope, or if AAL3-claimed service accounts use static long-lived tokens.",
    evidence_required: ["IdP authenticator export for sampled admins", "session-management policy document", "service-account token lifecycle export"],
    verdict_when_failed: PAPER
  },
  'NIST-AI-RMF-MEASURE-2.5': {
    claim: "We map and measure AI risks per NIST AI RMF MEASURE 2.5 including continuous validity assessment.",
    test: "Pull the AI risk-measurement plan. Confirm coverage of OWASP LLM Top 10 + ATLAS TTPs + MCP-trust scenarios with explicit measurement cadence. Confirm a metric exists for each category (e.g. prompt-injection success rate, RAG-poisoning detection rate). Inspect the metrics dashboard for actual measurement data within the past quarter. Theater verdict if metrics are defined but unpopulated, or if any of the OWASP/ATLAS/MCP categories has no measurement plan.",
    evidence_required: ["AI risk-measurement plan", "metrics dashboard with current quarter data", "ATLAS/OWASP coverage matrix"],
    verdict_when_failed: PAPER
  },

  // ---------------------------------------------------------------------
  // OWASP family
  // ---------------------------------------------------------------------
  'OWASP-ASVS-v5.0-V14': {
    claim: "Our application meets OWASP ASVS v5.0 V14 configuration controls.",
    test: "For any AI-mediated feature, confirm V14-equivalent controls cover prompt-isolation, output-sanitisation, and tool-grant defaults. Confirm SDK pinning and provider-version pinning where supported. Theater verdict if AI-feature configuration management is informal (no pinned versions, no documented prompt-isolation policy).",
    evidence_required: ["AI-feature configuration policy", "SDK + provider version pinning manifest", "prompt-isolation design document"],
    verdict_when_failed: PAPER
  },
  'OWASP-LLM-Top-10-2025-LLM01': {
    claim: "We mitigate prompt injection per OWASP LLM Top 10 LLM01.",
    test: "Inspect SDK-level prompt logging; confirm identity binding per call (which user, which agent, which scope). Confirm AI-provider domains are network-allowlisted with business justification. Confirm anomaly detection runs on prompt shape/volume/timing with alerting. Inspect SOC tooling for ATLAS+ATT&CK dual-mapping on LLM01 findings. Theater verdict if prompt logging is absent, allowlists are wildcard, or LLM01 findings are not dual-mapped.",
    evidence_required: ["SDK prompt-logging configuration", "AI-provider allowlist with justifications", "anomaly detection rule export with recent alerts"],
    verdict_when_failed: PAPER
  },
  'OWASP-LLM-Top-10-2025-LLM02': {
    claim: "We mitigate insecure output handling per OWASP LLM Top 10 LLM02.",
    test: "Inspect every code path that consumes LLM output and routes it to a downstream sink (HTML, SQL, shell, eval, tool dispatch). Confirm sink-specific encoding/escaping or schema validation. Theater verdict if any LLM output reaches a sensitive sink without validation.",
    evidence_required: ["LLM-output sink inventory", "output-validation logic per sink", "test cases proving validation fires on malicious payloads"],
    verdict_when_failed: PAPER
  },
  'OWASP-LLM-Top-10-2025-LLM06': {
    claim: "We mitigate sensitive information disclosure per OWASP LLM Top 10 LLM06.",
    test: "Inspect prompt egress for DLP rules covering PII, credentials, source-code-with-comments, and customer-data identifiers. Run a synthetic prompt containing planted secrets; confirm DLP triggers before egress to the AI provider. Theater verdict if DLP is not on the egress path, or if the synthetic test does not trigger.",
    evidence_required: ["DLP rule export for prompt egress", "synthetic prompt test result", "data classification policy"],
    verdict_when_failed: PAPER
  },
  'OWASP-LLM-Top-10-2025-LLM08': {
    claim: "We mitigate excessive agency per OWASP LLM Top 10 LLM08.",
    test: "Pick an AI agent in production. Enumerate the tools it can call. For each tool, confirm scope-of-action limits (read-only by default, write requires per-action attestation, destructive requires user confirmation). Theater verdict if any agent has wildcard write access or destructive actions without per-call confirmation.",
    evidence_required: ["agent tool inventory with scope limits", "per-action attestation policy", "destructive-action confirmation flow evidence"],
    verdict_when_failed: PAPER
  },
  'OWASP-Pen-Testing-Guide-v5': {
    claim: "Our web app pen-tests follow OWASP WSTG v5 methodology.",
    test: "Pull the most-recent pen-test report. Confirm test cases for AI-mediated features (prompt injection in chatbot widgets, AI-augmented input flows, agent-mediated workflows). Confirm tester used WSTG-aligned methodology with explicit AI-test extensions. Theater verdict if AI-mediated features are excluded from the pen-test scope.",
    evidence_required: ["pen-test methodology document", "pen-test report covering AI-mediated features", "scope-of-engagement document"],
    verdict_when_failed: PAPER
  },

  // ---------------------------------------------------------------------
  // PCI DSS family
  // ---------------------------------------------------------------------
  'PCI-DSS-4.0-6.3.3': {
    claim: "We address security vulnerabilities in custom and bespoke software per PCI DSS 6.3.3.",
    test: "Confirm the SDLC includes prompt-injection-class CWE coverage in code review for AI-mediated features. Inspect change tickets for AI-feature changes; confirm reviewer attestation includes AI-class threat sign-off. Theater verdict if AI-mediated changes bypass the prompt-injection threat-review gate.",
    evidence_required: ["SDLC document with AI-class CWE coverage", "AI-feature change tickets with reviewer attestation", "code review checklist"],
    verdict_when_failed: PAPER
  },
  'PCI-DSS-4.0.1-6.4.3': {
    claim: "We meet PCI DSS 4.0.1 6.4.3 inventory of payment-page scripts.",
    test: "Pull the payment-page script inventory. Confirm completeness against a fresh DOM snapshot of the live payment page. Confirm authorisation attestation per script (who approved, when, why). Confirm SRI hashes are pinned per script. Theater verdict if the inventory diverges from the live DOM, or if any script lacks attestation/SRI pinning.",
    evidence_required: ["payment-page script inventory", "live DOM snapshot per page", "SRI configuration export"],
    verdict_when_failed: PAPER
  },
  'PCI-DSS-4.0.1-11.6.1': {
    claim: "We perform tamper detection on payment pages per PCI DSS 4.0.1 11.6.1.",
    test: "Confirm tamper-detection cadence is sub-hour, not weekly. Confirm baselines distinguish AI-driven dynamic content from injection. Confirm coverage extends to mobile-app SDKs, kiosks, and agent-mediated checkout. Confirm CSP report-uri + Reporting API correlation. Theater verdict if cadence is weekly, baselining cannot tell legitimate dynamic content from injection, or non-browser surfaces are uncovered.",
    evidence_required: ["tamper-detection cadence configuration", "baseline document with AI-aware logic", "CSP report-uri correlation pipeline"],
    verdict_when_failed: PAPER
  },
  'PCI-DSS-4.0.1-12.3.3': {
    claim: "Our cryptographic suite review meets PCI DSS 4.0.1 12.3.3 annual cadence.",
    test: "Pull the cryptographic suite inventory and most-recent annual review. Confirm enumeration of in-use algorithms with deprecation status. Confirm a PQC-readiness assessment exists with migration roadmap for long-lived keys (TLS for >5y data, signing for code/SBOM). Theater verdict if PQC is absent from the review, or if deprecated algorithms remain in use without a documented exception.",
    evidence_required: ["cryptographic suite inventory", "annual review document with date", "PQC migration roadmap"],
    verdict_when_failed: PAPER
  },
  'PCI-DSS-4.0.1-12.10.7': {
    claim: "Our incident response procedures address suspected ransomware per PCI DSS 4.0.1 12.10.7.",
    test: "Pull the IR playbook for ransomware. Confirm pre-rehearsed sanctions-screening (OFAC SDN + EU 2014/833 + UK OFSI + AU DFAT + JP MOF) as a precondition to any payment posture. Confirm decryptor-availability lookup, immutability test on backup recovery path, and exfil-before-encrypt detection. Confirm 24h cyber-insurance carrier notification workflow is rehearsed end-to-end. Theater verdict if any of those is undocumented or not exercised in the past 12 months.",
    evidence_required: ["ransomware IR playbook with sub-procedures", "tabletop exercise log within past 12 months", "carrier-notification workflow record"],
    verdict_when_failed: PAPER
  },

  // ---------------------------------------------------------------------
  // PSD2 / PTES
  // ---------------------------------------------------------------------
  'PSD2-RTS-SCA': {
    claim: "Our payment authentication satisfies PSD2 RTS-SCA strong customer authentication requirements.",
    test: "Inventory payment-initiation flows. For any AI-mediated initiation (agent-initiated transactions, copilot-drafted payments), confirm an explicit delegated-authority attestation per transaction class with scope (amount, counterparty, frequency). Confirm a distinct audit indicator marks AI-mediated transactions. Theater verdict if AI initiations inherit the human-user SCA evidence path without delegated-authority attestation.",
    evidence_required: ["payment-initiation flow inventory", "delegated-authority policy document", "audit log sample with AI-mediated indicator"],
    verdict_when_failed: PAPER
  },
  'PTES-Pre-engagement': {
    claim: "Our pen-test scoping follows PTES pre-engagement methodology.",
    test: "Pull the most-recent PTES scoping document. Confirm AI/MCP assets are enumerated, AI-class attack vectors are in-scope, and the rules-of-engagement permit prompt-injection and MCP-trust testing. Confirm tester competency on AI-class attacks. Theater verdict if AI/MCP is excluded from scope, or if rules-of-engagement prohibit AI-class testing without documented justification.",
    evidence_required: ["PTES scoping document", "rules-of-engagement document", "tester competency CV"],
    verdict_when_failed: PAPER
  },

  // ---------------------------------------------------------------------
  // SLSA
  // ---------------------------------------------------------------------
  'SLSA-v1.0-Build-L3': {
    claim: "Our build pipeline is SLSA Build L3 with non-falsifiable provenance signed by a hardened build platform.",
    test: "Pull the SLSA provenance attestation for the most-recent release. Confirm the build platform is hosted/hardened, the attestation is signed, and the materials cover the full source-of-truth. Then confirm AI-authorship attestation (per-block provenance for AI-generated code with reviewer identity) is present. Confirm any model artefacts shipped have a Model Track equivalent attestation. Theater verdict if attestations exist but AI-authored diffs lack reviewer attestation, or if model artefacts ship at SLSA L0/L1 equivalent without explicit model-track attestation.",
    evidence_required: ["SLSA provenance attestation for latest release", "AI-authorship attestation policy and recent merge sample", "model-track attestation if model artefacts shipped"],
    verdict_when_failed: PAPER
  },

  // ---------------------------------------------------------------------
  // SOC 2
  // ---------------------------------------------------------------------
  'SOC2-CC6-logical-access': {
    claim: "Our SOC 2 CC6 logical and physical access controls cover all in-scope systems.",
    test: "Sample AI-agent invocation flows. Confirm authorisation-context evidence per invocation (scope, tools, data sensitivity). Confirm prompt logging captures sufficient detail for post-incident analysis (input chain, output, tool calls). Confirm anomaly detection alerts on AI-agent actions outside baseline. Theater verdict if AI-agent actions are not separately authorised, prompts are unlogged, or anomaly detection is absent.",
    evidence_required: ["AI-agent authorisation-context policy", "prompt-logging configuration with retention", "anomaly-detection rule export"],
    verdict_when_failed: PAPER
  },
  'SOC2-CC7-anomaly-detection': {
    claim: "Our SOC 2 CC7 system monitoring detects anomalous behaviour.",
    test: "Inspect monitoring rules for AI-class anomalies (prompt injection patterns, RAG-corpus drift, agent action volume spikes, tool-call sequence deviations). Confirm at least one alert per class triggered in the past 90 days; confirm triage records exist. Theater verdict if AI-class anomaly rules are absent, or if no alerts triggered despite AI being in production for 90+ days.",
    evidence_required: ["AI-class anomaly rule export", "alert-triage records past 90 days", "telemetry volume report"],
    verdict_when_failed: PAPER
  },
  'SOC2-CC9-vendor-management': {
    claim: "Our SOC 2 CC9 vendor management covers all third parties with system access.",
    test: "Pull the vendor register. Filter for AI providers; confirm AI-specific contractual clauses (prompt retention, training opt-out, residency, sub-processor disclosure, breach notification). Confirm self-signup AI usage by employees is policy-prohibited and detection is in place. Theater verdict if AI vendors have generic SaaS contracts without AI clauses, or if self-signup is undetected.",
    evidence_required: ["vendor register AI subset", "AI-vendor contract clause checklist", "self-signup detection telemetry"],
    verdict_when_failed: PAPER
  },
  'SOC2-CC6-OAuth-Consent': {
    claim: "Our SOC 2 CC6 covers OAuth consent grants in our SaaS estate.",
    test: "Pull the OAuth consent-grant inventory across the IdP estate. Confirm continuous alerting on high-risk scope grants. Confirm per-grant business-purpose attestation. Confirm unverified-publisher grants are gated. Theater verdict if any of those is missing or if high-risk grants exist without attestation/justification.",
    evidence_required: ["OAuth consent-grant inventory", "alerting rule for high-risk scope grants", "business-purpose attestation samples"],
    verdict_when_failed: PAPER
  },
  'SOC2-CC6-Access-Key-Leak-Public-Repo': {
    claim: "Our SOC 2 CC6 covers credential leakage detection across public repositories.",
    test: "Confirm continuous secret-scanning across public repos and developer-affiliated personal repos. Confirm leaked-credential auto-revocation (≤5 minutes) integrated with the IdP/CSP. Pull the past 12 months of credential leaks; measure time-from-leak-to-revocation. Theater verdict if scanning is not continuous, auto-revocation is absent, or any leak exceeded 5 minutes to revocation.",
    evidence_required: ["secret-scanning configuration", "auto-revocation pipeline architecture", "leak-to-revocation timing per incident"],
    verdict_when_failed: PAPER
  },

  // ---------------------------------------------------------------------
  // SWIFT CSCF
  // ---------------------------------------------------------------------
  'SWIFT-CSCF-v2026-1.1': {
    claim: "Our SWIFT secure zone is segregated and protected per CSCF v2026 1.1.",
    test: "Inspect the secure-zone policy. Confirm explicit prohibition or strict gating of LLM assistants inside the secure zone. Confirm AI-API egress from administrative jump zones is enumerated as a named conduit with monitoring. Confirm AI-generated MT/MX message drafts are flagged as a distinct review class. Cross-walk to DORA Art. 28 register. Theater verdict if LLM assistants are silently permitted, AI-API egress is unmonitored, or no DORA cross-walk exists.",
    evidence_required: ["secure-zone policy document", "AI-API egress monitoring configuration", "DORA Art. 28 cross-walk record"],
    verdict_when_failed: PAPER
  },

  // ---------------------------------------------------------------------
  // UK CAF
  // ---------------------------------------------------------------------
  'UK-CAF-A1': {
    claim: "Our governance satisfies UK CAF A1 with board-level cyber risk accountability.",
    test: "Pull the board governance pack. Confirm an AI-systems-in-use inventory is reviewed at board cadence, an MCP/plugin trust register exists, and accountability for AI security outcomes maps to a named executive in the NIS2/CCRA scope. Theater verdict if AI is absent from board-pack contents, or if AI accountability is unassigned at executive level.",
    evidence_required: ["board governance pack table-of-contents", "AI-systems inventory with board-review cadence", "executive accountability matrix"],
    verdict_when_failed: PAPER
  },
  'UK-CAF-B2': {
    claim: "Our identity and access management satisfies UK CAF B2.",
    test: "Inventory identities including AI-agent service accounts. Confirm authentication strength matches sensitivity (FIDO2 for admin, scope-limited tokens for agents). Confirm continuous verification, not just provisioning-time. Theater verdict if AI-agent accounts use long-lived bearer tokens for admin-equivalent scope, or if verification is provisioning-only.",
    evidence_required: ["identity inventory including AI agents", "authentication-strength policy", "continuous-verification configuration"],
    verdict_when_failed: PAPER
  },
  'UK-CAF-C1': {
    claim: "Our security monitoring satisfies UK CAF C1 across essential service flows.",
    test: "Pull the monitoring coverage matrix. Confirm AI-API egress, MCP server invocations, and AI-agent action telemetry are ingested. Confirm alerting on AI-class anomalies has triaged alerts in the past 90 days. Theater verdict if any AI source class is unmonitored or if no AI-class alert has been triaged despite production AI activity.",
    evidence_required: ["monitoring coverage matrix", "AI-source ingestion configuration", "alert-triage records past 90 days"],
    verdict_when_failed: PAPER
  },
  'UK-CAF-D1': {
    claim: "Our response and recovery planning satisfies UK CAF D1.",
    test: "Pull the incident response plan. Confirm AI-incident scenarios (prompt-injection RCE, RAG-poisoning, agent-action-on-injected-intent, AI-API supply-chain compromise) are exercised in the past 12 months. Confirm the plan integrates with NIS2 24h notification timing. Theater verdict if AI scenarios are absent from the exercise catalogue, or if NIS2 timing is not integrated.",
    evidence_required: ["incident response plan", "exercise catalogue with execution dates", "NIS2 timing integration document"],
    verdict_when_failed: PAPER
  },
  'UK-CAF-B5': {
    claim: "Our resilient telecom networks satisfy UK CAF B5.",
    test: "Confirm gNB firmware hash attestation is continuous, signaling-anomaly baselines exist per PLMN-pair, and LI-gateway access auditing is in place. Confirm sub-carrier visibility risks are documented. Theater verdict if any of those streams are missing or if no signaling anomaly has been triaged in 90 days despite carrier-pair traffic.",
    evidence_required: ["gNB attestation telemetry", "signaling baseline document", "LI-gateway audit log"],
    verdict_when_failed: PAPER
  },
  'UK-CAF-B2-IdP-Tenant': {
    claim: "Our IdP tenant access controls satisfy UK CAF B2.",
    test: "Inspect IdP tenant management; confirm tenant-admin actions require step-up MFA, management-API tokens are scoped + TTL-bounded + source-IP-locked, and token-signing certificate rotation is alert-attested. Theater verdict if any tenant-admin path lacks step-up MFA, or if management-API tokens are unrotated/unscoped/unbounded.",
    evidence_required: ["tenant-admin action flow with MFA evidence", "management-API token inventory with TTL/scope/source-IP", "token-signing rotation alert configuration"],
    verdict_when_failed: PAPER
  },
  'UK-CAF-B2-Cloud-IAM': {
    claim: "Our cloud-IAM posture satisfies UK CAF B2 across CSPs.",
    test: "Pull cloud-IAM configuration: managed-identity binding to instance identity, IMDSv2 required with short token TTL, bearer-token TTL ≤1h non-CAE / ≤24h with CAE, cross-account assume-role with subject-claim specificity. Theater verdict if IMDSv1 is in use, TTLs exceed ceilings, or cross-account claims are wildcard.",
    evidence_required: ["cloud-IAM configuration export per CSP", "IMDSv2 enforcement audit", "cross-account assume-role policy export"],
    verdict_when_failed: PAPER
  },

  // ---------------------------------------------------------------------
  // VEX
  // ---------------------------------------------------------------------
  'VEX-CSAF-v2.1': {
    claim: "We publish VEX statements via OASIS CSAF 2.1 for our products.",
    test: "Pull the published CSAF 2.1 documents. Confirm AI-component identifier scheme presence (model + version + adapters + tokenizer). Confirm at least one VEX statement covers an AI-class vulnerability (jailbreak, prompt injection, embedding inversion). Confirm chaining of base-model VEX statements to derived-model VEX statements where applicable. Theater verdict if AI components are absent from the identifier scheme, or if no AI-class VEX statements exist despite AI components shipping.",
    evidence_required: ["CSAF 2.1 published documents", "AI-component identifier mapping", "VEX chain example for base→derived model"],
    verdict_when_failed: PAPER
  },

  // ---------------------------------------------------------------------
  // FCC / Telecom
  // ---------------------------------------------------------------------
  'FCC-CPNI-4.1': {
    claim: "Our annual CPNI certification satisfies FCC CPNI obligations.",
    test: "Confirm quarterly LI-gateway activation auditing (Salt-Typhoon/PRC threat model). Confirm gNB firmware hash attestation and signaling-anomaly baselines per PLMN-pair. Pull the most recent CPNI certification; confirm those operational artefacts are referenced. Theater verdict if certification is annual-only without LI-gateway/firmware-hash/signaling artefacts.",
    evidence_required: ["LI-gateway audit log", "gNB firmware hash telemetry", "signaling baseline document"],
    verdict_when_failed: PAPER
  },
  'FCC-Cyber-Incident-Notification-2024': {
    claim: "We can meet the FCC 2024 cyber incident notification rule for telecom carriers.",
    test: "Run a tabletop with a synthetic significant-incident inject affecting CPNI. Stopwatch elapsed time to a draft FCC notification. Confirm cross-walk to NIS2 24h / DORA 4h timing for multinational operators. Theater verdict if no on-call is named, the playbook hasn't been exercised in 12 months, or cross-walks are absent.",
    evidence_required: ["tabletop execution log", "FCC notification draft", "cross-jurisdiction timing matrix"],
    verdict_when_failed: PAPER
  },
  'AU-ISM-1556': {
    claim: "Our telecom posture satisfies AU ISM control 1556 for signaling-protocol abuse.",
    test: "Confirm signaling-anomaly baselines per PLMN-pair, gNB firmware hash attestation, and LI-gateway audit. Pull the past 90 days of signaling alerts; confirm triage records. Theater verdict if any of those streams is missing, or if signaling anomalies are unmonitored.",
    evidence_required: ["signaling baseline document with PLMN-pair coverage", "gNB attestation telemetry", "alert-triage records"],
    verdict_when_failed: PAPER
  },
  'GSMA-NESAS-Deployment': {
    claim: "Our telecom equipment is GSMA NESAS-certified across the network.",
    test: "Confirm NESAS product-time certification AND operator-attested-runtime gNB hash AND EMS/OSS NESAS-equivalent scheme. Confirm firmware-update cadence triggers recertification attestation. Theater verdict if certification is product-time-only without runtime-attestation, or if firmware updates bypass recertification.",
    evidence_required: ["NESAS certification per product", "runtime-attestation telemetry", "firmware-update → recertification mapping"],
    verdict_when_failed: PAPER
  },
  '3GPP-TR-33.926': {
    claim: "Our 5G gNB security posture aligns with 3GPP TR 33.926 threat-model assumptions.",
    test: "Inspect deployment posture against TR 33.926 threats. Confirm runtime gNB integrity attestation and that LI-system compromise paths and signaling-protocol-abuse paths are addressed. Theater verdict if attestation is product-time-only or LI/signaling threats are not deployment-checklisted.",
    evidence_required: ["TR 33.926 → deployment-posture mapping", "runtime gNB attestation telemetry", "LI/signaling threat-treatment document"],
    verdict_when_failed: PAPER
  },
  'ITU-T-X.805': {
    claim: "Our network security architecture follows ITU-T X.805 8-dimension framing.",
    test: "Pull the X.805 architecture document. Confirm modern-threat-model annexes covering LI-system compromise, signaling-protocol abuse, and slice-isolation are present. Confirm a deployment-validation checklist exists and was executed in the past year. Theater verdict if annexes are absent or the deployment checklist has never been executed.",
    evidence_required: ["X.805 architecture document with annexes", "deployment-validation checklist execution log", "slice-isolation test results"],
    verdict_when_failed: PAPER
  },

  // ---------------------------------------------------------------------
  // Federated identity / IdP
  // ---------------------------------------------------------------------
  'NIST-800-53-IA-5-Federated': {
    claim: "Our IA-5 authenticator management covers federated identity providers.",
    test: "Inspect IdP control-plane: continuous attestation of token-signing certificate fingerprints, claim-transformation rule baseline with per-modification change-control attestation, management-API-token inventory with TTL + scope + source-IP enforcement. Theater verdict if attestation is snapshot-only (quarterly) rather than continuous, or if management-API tokens lack TTL/scope/source-IP enforcement.",
    evidence_required: ["IdP token-signing fingerprint telemetry", "claim-transformation change log", "management-API token inventory"],
    verdict_when_failed: PAPER
  },
  'ISO-27001-2022-A.5.16-Federated': {
    claim: "Our identity management satisfies ISO 27001:2022 A.5.16 across federated systems.",
    test: "Confirm IdP-tenant lifecycle management: tenant-admin discovery, off-boarding alerts, dormant-tenant alerts, claim-transformation review cadence. Theater verdict if dormant tenants exist with no alerting, or if claim transformations have no review cadence.",
    evidence_required: ["IdP tenant inventory", "off-boarding/dormant alerting configuration", "claim-transformation review cadence document"],
    verdict_when_failed: PAPER
  },
  'AU-ISM-1559-IdP': {
    claim: "Our IdP posture satisfies AU ISM 1559 for identity provider security.",
    test: "Confirm IdP token-signing certificate rotation alerting, claim-transformation change-control, management-API token TTL/scope/source-IP enforcement. Confirm the IdP is treated as critical-infrastructure-tier in the asset inventory. Theater verdict if IdP is in 'IT vendor' tier rather than critical-infrastructure tier.",
    evidence_required: ["IdP control-plane monitoring rule export", "asset-tier classification record", "management-API token inventory"],
    verdict_when_failed: PAPER
  },
  'OFAC-Sanctions-Threat-Actor-Negotiation': {
    claim: "Our sanctions compliance covers any threat-actor negotiation scenario.",
    test: "Pull the IR playbook. Confirm pre-rehearsed sanctions screening (US OFAC SDN + EU 2014/833 + UK OFSI + AU DFAT + JP MOF) as a precondition to any negotiator engagement. Confirm counsel-signed attestation workflow with timestamp. Confirm an annual tabletop with a sanctions-match inject under time-pressure. Theater verdict if screening is not pre-rehearsed or if the tabletop has not been run.",
    evidence_required: ["IR playbook with sanctions sub-procedure", "counsel-signed attestation template", "tabletop execution log"],
    verdict_when_failed: PAPER
  },
  'FedRAMP-IL5-IAM-Federated': {
    claim: "Our FedRAMP IL5 IAM posture covers federated identity for high-impact authorisations.",
    test: "Confirm IdP control-plane controls (token-signing rotation alerting, claim-transformation change-control, management-API TTL/scope/source-IP) at IL5 evidence-quality. Confirm cross-account assume-role with subject-claim specificity > wildcard. Theater verdict if controls exist at SP-quality without IL5 evidence-rigor, or if any cross-account chain has wildcard subject claims.",
    evidence_required: ["IL5-quality IdP control evidence bundle", "cross-account assume-role policy export", "evidence retention per IL5 cadence"],
    verdict_when_failed: PAPER
  },
  'CISA-Snowflake-AA24-IdP-Cloud': {
    claim: "We have remediated against the AA24 Snowflake-class advisory pattern (IdP/cloud credential abuse).",
    test: "For SaaS data platforms (Snowflake, Databricks, BigQuery, Redshift), confirm SSO-required posture (no local user/password fallback), MFA on every login, and network policies restricting access to known IPs. Pull the user inventory; confirm zero local-auth users and zero MFA exemptions. Theater verdict if any local-auth user persists, MFA exemption exists, or network policies are absent.",
    evidence_required: ["data-platform user inventory with auth method", "MFA exemption list", "network policy configuration"],
    verdict_when_failed: PAPER
  },
  'NIST-800-53-AC-2-Cross-Account': {
    claim: "Our cross-account access management satisfies NIST 800-53 AC-2.",
    test: "Sample 10 cross-account assume-role chains. For each, confirm subject-claim specificity (no wildcard principal), session-policy scoping, and external-ID where third-party assume-role. Inspect monitoring rules for assume-role chain depth and unusual chain shapes. Theater verdict if any sampled chain has wildcard subject claims or external-ID is missing in third-party scenarios.",
    evidence_required: ["cross-account assume-role policy sample", "monitoring rule for chain depth", "external-ID enforcement evidence"],
    verdict_when_failed: PAPER
  },
  'AU-ISM-1546-Cloud-Service-Account': {
    claim: "Our cloud service-account posture satisfies AU ISM 1546.",
    test: "Inventory cloud service accounts. Confirm short-lived OIDC tokens (workload identity federation) are used in preference to static keys; for any remaining static keys, confirm rotation policy ≤90 days and source-IP allowlisting. Theater verdict if static keys exist without rotation/IP-allowlisting, or if workload identity federation is available but not adopted.",
    evidence_required: ["cloud service-account inventory by auth method", "rotation policy document", "source-IP allowlist configuration"],
    verdict_when_failed: PAPER
  },
  'AWS-Security-Hub-Coverage-Gap': {
    claim: "Our cloud posture is monitored end-to-end by AWS Security Hub (or equivalent CSP-native posture tool).",
    test: "Pull the past 90 days of Security Hub findings. Cross-reference against IR ticket-tracker. Theater verdict if more than 5 findings closed without remediation evidence (suppression rules only). Then run the project's `cloud-iam-incident` playbook detect-indicator inventory against CloudTrail; theater verdict if Security Hub did not surface indicators that the behavioural inventory does (posture-tool deployment ≠ behavioural coverage).",
    evidence_required: ["Security Hub findings export 90 days", "IR ticket-tracker correlation", "cloud-iam-incident detect-indicator → CloudTrail behavioural-rule mapping"],
    verdict_when_failed: PAPER
  },

  // ---------------------------------------------------------------------
  // Ransomware playbook entries (RANSOMWARE-GAP-*)
  // ---------------------------------------------------------------------
  'OFAC-SDN-Payment-Block': {
    claim: "Our incident response covers OFAC sanctions screening before any ransomware payment.",
    test: "Run a tabletop where the inject is a ransomware demand from an attribution-likely-sanctioned actor. Stopwatch the workflow: attribution-evidence package assembled → cross-jurisdiction lookup (OFAC SDN + EU 2014/833 + UK OFSI + AU DFAT + JP MOF) → counsel-signed attestation → pay/restore decision. Theater verdict if any cross-jurisdiction list is missing, counsel-signed attestation is unrehearsed, or the tabletop has not been exercised in the past 12 months.",
    evidence_required: ["sanctions-screening sub-procedure document", "tabletop execution log with decision artefacts", "counsel-signed attestation template"],
    verdict_when_failed: PAPER
  },
  'Insurance-Carrier-24h-Notification': {
    claim: "We can meet the 24h cyber insurance carrier notification clock with pre-approval workflow rehearsed.",
    test: "Run a tabletop with carrier-notification as an inject. Stopwatch from T0 to (a) loss-notice form submitted via carrier-reachable channel, (b) broker after-hours contact engaged, (c) on-panel IR firm engagement attestation, (d) pre-approval workflow exercised end-to-end. Theater verdict if any sub-step is unrehearsed, the IR firm is off the carrier panel, or the broker after-hours channel is undocumented.",
    evidence_required: ["tabletop execution log with stopwatch timestamps", "carrier panel + retained IR firm attestation", "broker after-hours contact + loss-notice form"],
    verdict_when_failed: PAPER
  },
  'EU-Sanctions-Reg-2014-833-Cyber': {
    claim: "Our incident response includes EU Regulation 2014/833 cyber sanctions screening.",
    test: "Confirm IR playbook integrates EU Reg 2014/833 lookup as a precondition to ransomware payment posture, alongside OFAC + UK + AU + JP. Confirm counsel-signature workflow includes EU jurisdiction-specific counsel where the entity has EU exposure. Theater verdict if EU 2014/833 lookup is absent from the IR playbook, or if EU-jurisdiction counsel is not pre-identified.",
    evidence_required: ["IR playbook with EU 2014/833 sub-procedure", "EU-jurisdiction counsel pre-identification record", "tabletop execution log covering EU sanctions inject"],
    verdict_when_failed: PAPER
  },
  'Immutable-Backup-Recovery': {
    claim: "Our backups are immutable and survive a production-admin-credential adversary.",
    test: "Annual exercise: take a copy of a production-admin credential to a test environment with replica immutable backups. Attempt deletion via every API the production admin can invoke. Theater verdict if any deletion succeeds without a separate immutability-admin credential, or if 'immutable' resolves to versioning/write-protect/governance-retention that admin can override. Also confirm storage-side compliance-lock (S3 Object Lock compliance-retention, Azure immutable blob with legal hold, Veeam Hardened Repository) is in use.",
    evidence_required: ["immutability adversary-test execution log", "storage-side compliance-lock configuration", "admin-separation policy document"],
    verdict_when_failed: PAPER
  },
  'Decryptor-Availability-Pre-Decision': {
    claim: "Our ransomware response checks decryptor availability before any pay/restore decision.",
    test: "Run a tabletop. Inject a ransomware family fingerprint (e.g. LockBit 3.0, BlackCat, Akira). Confirm IR playbook executes a curated decryptor catalogue lookup (No More Ransom + Emsisoft + Kaspersky NoMoreCry + Bitdefender + Avast + law-enforcement releases) and records the result with timestamp before the pay/restore decision. Confirm decryptor known-failure-mode review (e.g. ~35% partial-decryption rate per Coveware) is documented as decision input. Theater verdict if catalogue lookup is absent, failure-mode review is missing, or quarterly catalogue refresh is undocumented.",
    evidence_required: ["IR playbook decryptor sub-procedure", "tabletop execution log", "quarterly catalogue refresh evidence"],
    verdict_when_failed: PAPER
  },
  'PHI-Exfil-Before-Encrypt-Breach-Class': {
    claim: "Our HIPAA incident response treats exfil-before-encrypt as a parallel breach class.",
    test: "Pull the IR playbook. Confirm exfil-before-encrypt detection (24-72h egress profile preceding encryption event) is integrated. Confirm exfil-scope determination is a parallel obligation independent of encryption-recovery status. Confirm HIPAA 164.402 breach risk assessment auto-triggers on exfil event. Confirm GDPR Art.33/34 + state breach laws + UK GDPR + AU NDB parallel-clock matrix is framework-mandated output. Confirm tabletop exercise injected an exfil-before-encrypt scenario in past 12 months. Theater verdict if any of those is absent.",
    evidence_required: ["IR playbook with exfil-before-encrypt sub-procedure", "parallel-clock matrix document", "tabletop execution log within past 12 months"],
    verdict_when_failed: PAPER
  }
};

function backfill() {
  const raw = fs.readFileSync(CATALOG_PATH, 'utf8');
  const data = JSON.parse(raw);
  const keys = Object.keys(data).filter(k => k !== '_meta');

  const missing = [];
  let updated = 0;
  for (const k of keys) {
    if (!TESTS[k]) {
      missing.push(k);
      continue;
    }
    data[k].theater_test = TESTS[k];
    updated++;
  }

  if (missing.length) {
    console.error('Missing theater_test for:', missing.join(', '));
    process.exit(2);
  }

  // Re-emit with stable 2-space indentation matching the file's existing style.
  // Trailing newline preserved.
  const out = JSON.stringify(data, null, 2) + '\n';
  fs.writeFileSync(CATALOG_PATH, out);
  console.log(`Updated ${updated}/${keys.length} entries with theater_test.`);
}

backfill();
