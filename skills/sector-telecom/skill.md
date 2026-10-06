---
name: sector-telecom
version: "1.0.0"
description: Telecom and 5G security for mid-2026 — Salt Typhoon, Volt Typhoon, CALEA / IPA-LI gateway compromise, signaling-protocol abuse (SS7 / Diameter / GTP), 5G N6 / N9 isolation, gNB / DU / CU integrity, OEM-equipment supply-chain compromise, AI-RAN / O-RAN security; FCC CPNI + 7-business-day breach notification, NIS2 Annex I telecom essential entities, UK TSA 2021 + Ofcom, AU SOCI Act (Part 2D replaced TSSR on 2025-04-04), GSMA NESAS, 3GPP TR 33.926 + TS 33.501, ITU-T X.805.
triggers:
  - telecom security
  - 5g core
  - salt typhoon
  - volt typhoon
  - gnb integrity
  - lawful intercept
  - calea
  - fcc cpni
  - 7-business-day notification
  - gsma nesas
  - ss7
  - diameter
  - gtp
  - 3gpp ts 33.501
  - 3gpp tr 33.926
  - o-ran
  - n6 n9 isolation
  - nis2 annex i
  - uk tsa 2021
  - au soci
  - tssr
  - itu-t x.805
data_deps:
  - cve-catalog.json
  - framework-control-gaps.json
atlas_refs:
  - AML.T0010
attack_refs:
  - T1071
  - T1078
  - T1098
  - T1190
  - T1199
  - T1556
framework_gaps:
  - FCC-CPNI-4.1
  - FCC-Cyber-Incident-Notification-2024
  - NIS2-Annex-I-Telecom
  - DORA-Art-21-Telecom-ICT
  - UK-CAF-B5
  - AU-ISM-1173-Telecom-NMS
  - GSMA-NESAS-Deployment
  - 3GPP-TR-33.926
  - ITU-T-X.805
rfc_refs:
  - RFC-9622
cwe_refs:
  - CWE-287
  - CWE-306
  - CWE-918
d3fend_refs:
  - D3-NTA
  - D3-NTPM
  - D3-IOPR
  - D3-NI
forward_watch:
  - "FCC CPNI rule updates (47 CFR 64.2009 / 64.2011 amendments)"
  - "5G AI-RAN security guidance from CISA, ENISA, NCSC, ASD ACSC"
  - "GSMA FS.32 / FS.36 / FS.43 revisions"
  - "Volt Typhoon / Salt Typhoon successor-actor disclosures"
  - "Five Eyes joint advisories on telecom-equipment intrusion"
  - "3GPP TS 33.501 updates (5G security architecture rebaseline)"
  - "O-RAN Alliance WG11 (Security Work Group) security specifications"
last_threat_review: "2026-10-05"
discovery_mode: "standalone"  # operator-reached via `exceptd brief sector-telecom` or `exceptd ask`; not chained into any playbook's direct.skill_chain by design
---

## Threat Context (mid-2026)

**Salt Typhoon (China nation-state; PRC Ministry of State Security nexus).** The campaign, active since at least 2021, was disclosed in an FBI and CISA joint statement (2024-11-13), in the joint guide Enhanced Visibility and Hardening Guidance for Communications Infrastructure from CISA, NSA, FBI, ASD's ACSC, the Canadian Centre for Cyber Security and NCSC-NZ (2024-12-04), and in joint advisory AA25-239A from the Five Eyes agencies and partner agencies in eight more countries (2025-08-27, last revised 2025-09-03). It compromised at least nine US carriers (publicly named: AT&T, Verizon, T-Mobile US, Lumen, Charter, Cox, Windstream, Consolidated, plus undisclosed others) and extended to AU / CA / NZ / UK Tier-1 carriers. Threat actor TTPs map to T1199 (Trusted Relationship) via OEM vendor supply chain, T1098 (Account Manipulation) for persistent admin access on NMS, and T1078 (Valid Accounts) with stolen LI-gateway operator credentials. The campaign's defining feature: targeted access to CALEA-mandated lawful-intercept systems, allowing PRC actors to read US-authorized intercept feeds — including those covering PRC counter-intelligence targets and presidential-campaign communications (2024 election cycle). The intercept-system vector is structurally novel: every carrier serving US-jurisdiction subscribers is legally required to maintain a CALEA-compliant intercept capability, which means every carrier has a high-value, low-monitored attack surface by mandate.

**Volt Typhoon (China; OT-adjacent telecom + ISP critical infrastructure).** CISA AA24-038A (Feb 2024) and follow-ons document prepositioning across US critical infrastructure operators, including telecom-adjacent ISPs and edge equipment. Living-off-the-land TTPs (T1190 + T1556) defeat conventional EDR. Distinct from Salt Typhoon in mission (prepositioning vs intelligence collection) but the equipment-supply-chain access pattern overlaps.

**Lawful-intercept abuse vectors.** LI gateway compromise can defeat CALEA / IPA-LI mandated intercept capability protections and EU NIS2 security measures (NIS2 Art. 43 deleted EECC Art. 40 with effect from 2024-10-18). LIDB poisoning, J-STD-025 / ATIS-1000013 reference-data tampering, and operator-credential theft against the LI-management subsystems are the primary access patterns. The same vectors apply to UK IPA 2016 + TSA 2021, AU SOCI Act 2018 (Part 2D, which replaced the TSSR obligations in the Telecommunications Act 1997 on 2025-04-04), Singapore IMDA TCCSCoP, India CERT-In 6-hour rule, Japan Telecommunications Business Act amended 2023.

**Signaling-protocol attacks.** SS7 (2G/3G legacy), Diameter (4G LTE/IMS), GTP (3G/4G data plane), and 5G core interfaces N1 / N2 / N4 / N6 / N9 — each carries authentication and authorization fragility legacies. SS7-class abuse remains operationally relevant in mid-2026 against carriers maintaining legacy interconnect. 5G core slice-isolation under TS 33.501 is the modern equivalent control surface.

**OEM equipment supply-chain compromise.** Cisco / Juniper / Nokia / Ericsson / Huawei / ZTE equipment vendors are the high-value target. Vendor remote-support inbound tunnels (Cisco TAC, Ericsson ENS, Nokia 1350 OMS) are a recurring intrusion vector. GSMA NESAS (FS.13 / FS.14 / FS.15) is product-time certification — operator-attested deployment posture is the operational gap.

**AI-RAN / O-RAN security.** O-RAN Alliance WG11 (Security Work Group), 3GPP TR 33.926, NIST SP 1800-33 (5G Cybersecurity practice guide, in draft; the Volume A initial public draft was published 2025-03-18). AI-RAN deployments add model-tampering and slice-mismapping risks that 3GPP TR 33.926 does not yet model.

## Framework Lag Declaration

Telecom security mandates lag the current threat reality because the regulatory frame was constructed before the Salt Typhoon-class adversary access pattern surfaced. **NIS2 Annex I** (EU) designates telecom providers as essential entities and requires a 24-hour early warning and a 72-hour incident notification (Art. 23) + supply-chain due diligence (Art. 21(2)(d)), but does not name OEM-equipment firmware integrity attestation, AI-RAN model-tampering controls, or LI-gateway-specific access auditing. **FCC CPNI rules** (47 CFR 64.2009(e) annual certification, 47 CFR 64.2011 CPNI breach notification to the USSS and FBI within seven business days; the amendments published 2024-02-12, which add FCC notification and widen the breach definition, remain delayed until the FCC publishes their effective date) predate the Salt Typhoon LI-system vector and do not require notification on LI-system compromise that does not exfiltrate PII directly. **UK CAF Principle B5** (resilient networks) is outcome-tested but the outcome catalog does not include signaling-anomaly detection, gNB firmware attestation, or slice-isolation tests; lawful-intercept access is covered separately by IPA 2016 + TSA 2021. **AU ISM-1173** (multi-factor authentication for privileged human users) covers human privileged users but does not reach telecom NMS service accounts (the actual privilege-holders) or OEM remote-support tunnels. **DORA Art. 28** (EU, ICT third-party risk) binds the financial entity consuming telecom services but does not align cadences with NIS2 telecom-essential-entity reporting and does not bridge to 5G slice-isolation obligations for finance-dedicated slices. **GSMA NESAS** is product-time, vendor-attested certification with no operator-attested-runtime check, no firmware-update-cadence-tied recertification, and no EMS / OSS / NMS coverage. **3GPP TR 33.926** assumes deterministic equipment behavior — adversary-modified firmware that passes the SCAS suite at submission remains undetected after deployment. **ITU-T X.805** (2003) is reference architecture, not a deployment-validation framework, and predates 5G, O-RAN, AI-RAN, and the modern threat model. **CTID Secure AI v2** (2026-05-06) extends MITRE ATLAS coverage of agentic-AI and large language model threats but is layered guidance, not a mandate.

## TTP Mapping

| Tactic | ATT&CK | ATLAS | Description |
|---|---|---|---|
| Initial Access | T1199 Trusted Relationship | AML.T0010 (AI Supply Chain Compromise) | OEM vendor remote-support tunnel or AI-RAN plugin compromise opens a path into the operator network |
| Initial Access | T1190 Exploit Public-Facing Application | — | Internet-facing OSS / EMS / NMS exposed services (Salt Typhoon access pattern) |
| Persistence | T1098 Account Manipulation | — | Persistent admin role grants on NMS / EMS / OSS after initial compromise |
| Credential Access | T1556 Modify Authentication Process | — | LI-gateway credential pivot — operator account credentials forged or replayed against LI provisioning subsystem |
| Initial Access | T1078 Valid Accounts | — | Stolen LI-gateway operator credentials used directly, no separate exploitation path |
| Command and Control | T1071 Application Layer Protocol | — | Living-off-the-land C2 over telecom internal management protocols (SNMP, NETCONF, Telco-IP-fabric) |
| Collection | T1199 (downstream) | AML.T0010 (downstream) | Pulling subscriber call-detail records, location data, and LI feed contents via compromised access |

ATLAS AML.T0010 (AI Supply Chain Compromise) anchors the AI-RAN attack class: plugin-layer compromise of an O-RAN xApp or rApp can route traffic through an adversary-controlled inference path while the NMS believes the legitimate xApp is still in use.

## Exploit Availability Matrix

| Vector | PoC status | Weaponization | AI-assist factor | Notes |
|---|---|---|---|---|
| LI-gateway operator credential theft | Public (credential-capture TTPs in CISA AA25-239A) | Confirmed in-the-wild | Low | Salt Typhoon TTP; credentials harvested through OEM-vendor supply chain |
| OEM vendor remote-support tunnel | Public (TTP class, no single PoC) | Confirmed in-the-wild | Low | Vendor TAC / ENS tunnels documented as Salt Typhoon vector |
| SS7 / Diameter signaling abuse | Public (signaling-research community) | Commodity | Low | Pre-dates AI-augmented attack landscape |
| GTP-U tunneling attacks | Public | Demonstrated | Low | Operator-side defense via signaling firewalls |
| 5G core N4 abuse (PFCP) | Researcher PoCs | Demonstrated | Low | Defense via N4 isolation per TS 33.501 |
| AI-RAN xApp tampering | No public PoC | Speculative | High (ATLAS AML.T0010 class) | CTID Secure AI v2 forward-watch |
| gNB firmware tampering | Researcher PoCs (vendor-specific) | Demonstrated against vendor pre-prod | Low | GSMA NESAS scope gap |
| Slice mismapping (cross-slice leak) | Researcher PoCs against test cores | Demonstrated | Low | TS 33.501 control surface |

## Analysis Procedure

### Jurisdictional clocks + obligations

Surface the operator's jurisdictional notification clocks immediately on detection:

- **US**: FCC 47 CFR 64.2011 — notify the USSS and FBI through the central reporting facility within seven business days after reasonable determination of a CPNI breach; CALEA / Title III LI-system compromise reporting through DOJ / FBI per separate channel
- **EU**: NIS2 Art. 23 — 24 hours early warning, 72 hours incident notification, final report 1 month after the incident notification (telecom essential entity)
- **EU finance-touching**: DORA Art. 19 — 4 hours major-ICT-incident initial notification for financial-entity-impacting telecom incidents
- **UK**: TSA 2021 + Electronic Communications (Security Measures) Regulations 2022 — Ofcom notification as soon as reasonably practicable of a security compromise that has a significant effect on the operation of the network or service (Communications Act 2003 s.105K); NCSC notification when applicable
- **AU**: SOCI Act 2018 Part 2B: report a cyber security incident to ASD within 12 hours of becoming aware when it has a significant impact on the availability of a critical telecommunications asset, or within 72 hours when it has a relevant impact (Part 2B has applied since 2025-04-04 to critical telecommunications assets owned or operated by a carrier and to relevant carriage service provider assets). The TSSR obligations in Part 14 of the Telecommunications Act 1997 ceased on 2025-04-04 and are now in the SOCI Act and the Security of Critical Infrastructure (Telecommunications Security and Risk Management Program) Rules 2025. Under Part 2D, the responsible entity for a critical telecommunications asset owned or operated by a carrier notifies the Secretary of Home Affairs, using the Cyber and Infrastructure Security Centre (CISC) Change Notification Form, of changes or proposed changes to its networks and services that could have a material effect on its capacity to protect the security of the asset. Notify ACMA where applicable.
- **CA**: Critical Cyber Systems Protection Act (enacted by Bill C-8 as S.C. 2026, c. 9, s. 11, Royal Assent 2026-06-15, not in force as of 2026-09-21) notification once in force
- **JP**: MIC Telecommunications Business Act amended 2023; immediate notification
- **IN**: Telecommunications (Security) Rules 2024 + CERT-In 6-hour rule
- **SG**: IMDA TCCSCoP (2022 v2 + 2024 update) — immediate
- **NZ**: TICSA 2013

Wait for operator acknowledgment of the highest-priority clock before proceeding.

### Threat context briefing

Brief the operator on Salt Typhoon-class TTPs + RWEP-threshold bands. For telecom CVEs with active exploitation: RWEP 90 or above, live patch or isolate within 4 hours; 75 or above, patch or apply compensating controls within 24 hours; 60 or above, patch within 72 hours; 40 or above, patch within 7 days; 20 or above, patch within 30 days; below 20, patch at the next scheduled maintenance.

### Artifacts to capture

Capture the following telecom-specific evidence (use `air_gap_alternative` paths if operator is in disconnected mode):

- **LI provisioning audit log** — full activation/deactivation history for the assessment window (typically last 90 days). Air-gap alternative: operator-supplied CSV export.
- **gNB / DU / CU firmware hashes** — operator-attested hash for every running base station, compared against vendor-published expected hashes. Air-gap alternative: out-of-band hash list verified against PGP-signed vendor bulletin.
- **NMS / EMS / OSS access logs** — last 90 days of admin actions on the network management plane.
- **Signaling-flow statistics** — SS7 SCCP / TCAP / MAP message rates per peer; Diameter ABMF / CCR / CCA rates per Diameter peer; GTP-C / GTP-U bytes per APN.
- **Cross-PLMN signaling exchange patterns** — anomalous PLMN-pair flows that did not previously exchange traffic.
- **eUICC SIM-swap event log** — recent IMSI swaps, MSISDN reassignments.
- **5GC slice-isolation verification output** — last AMF / SMF / UPF reachability test per slice.
- **OEM vendor remote-support tunnel inventory** — open Cisco TAC / Ericsson ENS / Nokia OMS tunnels with last-active timestamp.
- **NESAS deployment posture report** — most recent operator-attested deployment match against the vendor-certified build.

### Detection indicators

Walk every indicator's `false_positive_checks_required` list before submitting a hit:

- **Anomalous LI activation requests** — provisioning events outside the operator's standard workflow (e.g. activation without paired law-enforcement-agency ticket reference, activation from a service-account that never previously performed LI provisioning).
- **gNB firmware hash drift** — running firmware does not match the vendor-published or operator-attested expected hash. FP check: rule out staged update window.
- **NMS access from anomalous source** — admin login from an ASN, region, or device class not previously used for the role. FP check: rule out OEM TAC support session (correlate against open tunnel inventory).
- **Cross-PLMN signaling spikes** — sudden order-of-magnitude increase in signaling exchange with a previously-quiet PLMN-pair. FP check: rule out legitimate roaming-agreement reactivation, peering reconfiguration.
- **Unauthorized LI gateway tunnel** — outbound connection from the LI gateway to an IP outside the LE / DOJ / regulator allowlist. FP check: rule out documented maintenance bastion.
- **OEM firmware downgrade events** — vendor-equipment firmware version regressed below the operator-published minimum. FP check: rule out documented incident-response rollback.

### Correlation

Match captured artifacts against `data/cve-catalog.json` entries with `attack_class: telecom` or matching `attack_refs`. Cross-reference against `data/framework-control-gaps.json` for FCC-CPNI-4.1, FCC-Cyber-Incident-Notification-2024, NIS2-Annex-I-Telecom, DORA-Art-21-Telecom-ICT, UK-CAF-B5, AU-ISM-1173-Telecom-NMS, GSMA-NESAS-Deployment, 3GPP-TR-33.926, ITU-T-X.805. Score blast-radius based on subscriber count + LI-feed-exposure dimension + AI-RAN slice-mismapping potential.

### Priority-sorted remediation

Priority 1 (immediate): isolate compromised NMS account; revoke and re-issue LI-gateway operator credentials; pull running-gNB firmware hash off every base station and compare against operator-attested expected.
Priority 2 (24h): rotate all OEM vendor remote-support credentials; close TAC tunnels not actively in use; signaling-firewall block on cross-PLMN spike sources.
Priority 3 (72h): operator-attested NESAS recertification of every gNB / EMS / OSS; slice-isolation verification across every active 5GC slice; comprehensive review of the last 90 days of NMS admin actions.

### Regulator notifications + evidence preservation

Draft jurisdictional notification messages with regulator-specific evidence templates. Preserve LI-system audit trail for downstream law-enforcement / intelligence-community handoff. Schedule a follow-up re-attestation window at the highest applicable regulator deadline minus 48 hours.

## Output Format

The investigation evidence bundle has this shape:

```json
{
  "session_id": "telecom-<iso>",
  "playbook_id": "sector-telecom",
  "classification": "detected | clean | not_detected | inconclusive",
  "evidence_hash": "sha256:...",
  "telecom_specific_findings": {
    "li_gateway_audit": {
      "anomalous_activations": 0,
      "activations_outside_ticket": 0,
      "outbound_tunnel_to_non_allowlist_ip": 0
    },
    "gnb_attestation_state": {
      "expected_hashes_compared": 0,
      "drifted_basestations": [],
      "downgrade_events": 0
    },
    "signaling_anomaly_count": {
      "ss7_per_peer_z_score_outliers": 0,
      "diameter_per_peer_z_score_outliers": 0,
      "gtp_apn_byte_z_score_outliers": 0,
      "cross_plmn_unexpected_pairs": []
    },
    "nms_admin_access": {
      "logins_from_anomalous_asn": 0,
      "service_account_role_grants_outside_workflow": 0,
      "open_oem_tac_tunnels": []
    },
    "oem_firmware_drift": {
      "vendor_published_min_version_violations": [],
      "operator_attested_mismatch": []
    },
    "slice_isolation": {
      "amf_smf_upf_reachability_misses": [],
      "cross_slice_packet_leakage_detected": false
    }
  },
  "jurisdiction_notifications": [
    { "jurisdiction": "US-FCC", "regulation": "47-CFR-64.2011", "deadline_iso": "...", "clock_anchor": "detect_confirmed" },
    { "jurisdiction": "EU", "regulation": "NIS2-Art-23", "deadline_iso": "...", "clock_anchor": "detect_confirmed" }
  ]
}
```

## Compliance Theater Check

Theater patterns specific to telecom posture:

- **"We have CPNI annual certification."** Annual certification is a process artifact, not a compromise-detection control. The certification covers operational procedures; it does not test LI-gateway compromise detection. Theater test: ask whether the last CPNI certification audit reviewed LI provisioning logs for anomalous activations.
- **"We are GSMA NESAS certified."** NESAS is product-time, vendor-attested certification of the equipment itself — not the deployed posture. Theater test: ask for the most recent operator-attested-runtime gNB firmware hash report compared against the NESAS-certified build hash. Mismatch or absence is theater.
- **"OEM firmware is verified at receipt."** Vendor-supplied hash is the input to the receipt verification; the operator does not independently re-derive the hash from upstream OEM-vendor source. Theater test: ask whether the operator separately verifies OEM firmware against an out-of-band PGP-signed vendor bulletin OR an operator-side reproducible build.
- **"3GPP TR 33.926 tests passed at deployment."** TR 33.926 lists threats and critical assets per network product class, and SCAS testing against specifications such as TS 33.511 (gNB) is product-class testing; it does not detect adversary-modified firmware that passes the test suite at submission. Theater test: ask for the post-deployment hash-attestation report on the running gNB.
- **"ITU-T X.805 framework adopted."** X.805 is reference architecture, not validation. Theater test: ask for a deployment validation checklist mapping X.805's 8 dimensions to specific operational telemetry. Most operators cite the framework but do not validate against it.
- **"We have signaling firewall (SS7 / Diameter / GTP)."** Signaling firewalls are policy-engine dependent on a current threat-actor PLMN catalog. Theater test: ask when the threat-actor PLMN list was last refreshed against GSMA Fraud and Security Group bulletins.
- **"LI-gateway operator credentials use MFA."** Human-MFA on the LI gateway is necessary but not sufficient — service accounts and OEM remote-support tunnels frequently bypass. Theater test: count the LI-gateway admin actions executed in the last 30 days by service-account principals vs human-MFA principals.

## Defensive Countermeasure Mapping

| Threat | D3FEND technique | Operational mapping |
|---|---|---|
| Signaling anomaly | D3-NTA (Network Traffic Analysis) | SS7 / Diameter / GTP per-peer baseline + alert on z-score outliers |
| 5G slice cross-leak | D3-NTPM (Network Traffic Policy Mapping) | Per-slice ACL + AMF/SMF/UPF reachability testing |
| LI-gateway audit-trail integrity | D3-IOPR (I/O Read) | Immutable / append-only LI provisioning log + cross-system reconciliation |
| 5GC slice / N6 / N9 isolation | D3-NI (Network Isolation) | Slice ID + DNN + S-NSSAI policy enforcement; N6 transit egress monitoring |
| OEM firmware tampering | D3-FV (Firmware Verification) | Out-of-band hash verification + operator-attested-runtime checks |

## Hand-Off / Related Skills

- **incident-response-playbook** — parent IR flow; sector-telecom extends the IR contract with telecom-specific evidence and jurisdictional clocks.
- **framework-gap-analysis** — invoke for downstream Hard-Rule-5 gap mapping against catalog framework_gaps.
- **cred-stores** *(playbook chain, not a skill)* — LI-gateway operator credential storage falls under the `cred-stores` playbook for secret-management depth.
- **sector-federal-government** — national-security adjacency on LI-system compromise touches federal investigation scope.
- **mcp-agent-trust** — AI-RAN xApp / rApp compromise (ATLAS AML.T0010 class) crosses into MCP-class agent-tool trust boundaries.
