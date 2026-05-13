---
name: mlops-security
version: "1.0.0"
description: MLOps pipeline security for mid-2026 — training data integrity, model registry signing, deployment pipeline provenance, inference serving hardening, drift detection, feedback loop integrity; covers MLflow / Kubeflow / Vertex AI / SageMaker / Azure ML / Hugging Face
triggers:
  - mlops security
  - ml pipeline security
  - model registry security
  - training data integrity
  - mlflow
  - kubeflow
  - vertex ai
  - sagemaker
  - azure ml
  - hugging face
  - model signing
  - model card
  - data card
  - feature store
  - drift detection
  - model monitoring
data_deps:
  - cve-catalog.json
  - atlas-ttps.json
  - framework-control-gaps.json
  - cwe-catalog.json
  - d3fend-catalog.json
  - rfc-references.json
atlas_refs:
  - AML.T0010
  - AML.T0018
  - AML.T0020
  - AML.T0043
  - AML.T0017
attack_refs:
  - T1195.001
  - T1565
framework_gaps:
  - NIST-800-218-SSDF
  - SLSA-v1.0-Build-L3
  - ISO-IEC-42001-2023-clause-6.1.2
  - NIST-AI-RMF-MEASURE-2.5
  - OWASP-LLM-Top-10-2025-LLM08
  - EU-AI-Act-Art-15
  - UK-CAF-A1
  - AU-Essential-8-App-Hardening
rfc_refs:
  - RFC-8032
cwe_refs:
  - CWE-1426
  - CWE-1395
  - CWE-1357
  - CWE-502
d3fend_refs:
  - D3-EHB
  - D3-EAL
  - D3-IOPR
forward_watch:
  - CycloneDX 1.7 ML-BOM enrichment — training-data lineage fields and model-card embedding stabilize; re-baseline ML-BOM coverage when published
  - SPDX 3.1 AI / Dataset profile maturation — dataset provenance schema firms up; re-audit training-data lineage attestations
  - OpenSSF model-signing emergence to v1.0 — Sigstore-based model-weight signing; track for production adoption and admission-control integration
  - SLSA v1.1 ML profile (draft) — model-provenance extension for training-run attestation chains; track ID and section changes
  - EU AI Act high-risk technical-file implementing acts (2026-2027) — operational requirements for Article 10 / 13 / 15 documentation may pin ML-BOM or model-signing
  - MITRE ATLAS v5.2 — track AML.T0010 sub-technique expansion and any new MLOps-pipeline-specific TTPs
last_threat_review: "2026-05-11"
---

# MLOps Pipeline Security Assessment

## Threat Context (mid-2026)

MLOps replaced ad-hoc ML by 2023 — MLflow, Kubeflow Pipelines, Weights & Biases, Vertex AI Pipelines, SageMaker Pipelines, Azure ML Studio, and Hugging Face Hub are now the operational substrate for most production ML. By mid-2026, adversarial pressure has caught up. The MLOps lifecycle (data ingestion → feature store → training pipeline → experiment tracking → model registry → deployment pipeline → inference serving → monitoring → feedback loop) is now a contiguous supply chain whose every handoff is a documented attack class.

The defining realities for mid-2026:

- **Training-data poisoning is documented operational practice, not academic exercise.** Hugging Face has executed periodic model and dataset takedowns through 2024-2026 for embedded backdoor weights and poisoned training corpora; the Mithril repository takedown in 2024 (embedded backdoor in distributed model weights) is the canonical public reference. Academic demonstrations of small-fraction targeted poisoning (BadNets, TrojanNN, BackdoorBench) show that <1% of training samples can achieve targeted misclassification at >90% attack success — this is the AML.T0020 class made concrete.
- **Model weights are native binary artifacts that execute on load.** PyTorch `.pt` checkpoints in code-executing serialization (Python object-graph serialization) are CWE-502 deserialization vectors; periodic CVEs against PyTorch and TensorFlow demonstrate arbitrary code execution via crafted checkpoints (TorchServe deserialization issues, TensorFlow `SavedModel` deserialization, ONNX shape-inference parsers). GGUF format gaps are still maturing — parsing logic for quantized LLM weights has produced multiple memory-safety findings in 2025-2026. Hash-pinning a malicious blob does not prevent execution; only signature verification against a pinned publishing key (Sigstore keyless or OpenSSF model-signing) plus a non-executing format (safetensors) closes the class. See `supply-chain-integrity` for the artifact-layer treatment; this skill addresses the MLOps-pipeline integration.
- **Deployment-pipeline compromise is a transitive supply chain.** The chain runs AI-codegen IDE (Copilot, Cursor, Claude Code) → notebook (Jupyter, Colab, Databricks) → training-run orchestrator (Kubeflow, Vertex, SageMaker) → model registry (MLflow Registry, SageMaker Model Registry, Vertex Model Registry, Hugging Face Hub) → deployment pipeline (KServe, SageMaker endpoint, Vertex endpoint, Azure ML online endpoint) → inference service. Each step is a handoff where provenance can be lost. AML.T0010 (ML Supply Chain Compromise) sub-techniques AML.T0010.001 (ML framework), AML.T0010.002 (model repository), and AML.T0010.003 (MCP server) are now all realized attack classes.
- **Drift detection often only watches accuracy on labeled holdout sets, missing semantic-drift caused by silent input distribution shift or active adversarial probing.** Most production drift dashboards (Evidently, Arize, Fiddler, WhyLabs) instrument data-quality and accuracy regression but stop short of adversarial-input detection or output anomaly profiling. AML.T0043 (Craft Adversarial Data) is the class missed.
- **Experiment-tracking systems are credential goldmines.** MLflow tracking servers, Weights & Biases workspaces, and Vertex Experiments routinely contain API keys, dataset access tokens, and customer-data sample rows in run artifacts. Public CVEs against MLflow (path-traversal, SSRF, authentication bypass — CVE-2023-43472 class and follow-ons through 2024-2025) demonstrate this is not theoretical. Model registries without RBAC are de-facto unauthenticated.
- **The feedback loop is a poisoning vector.** Production models that retrain on human feedback, click-through data, or LLM-as-judge labels close the loop adversaries already exploit: AML.T0043 (Craft Adversarial Data) → feedback collection → retrain → poisoned model in production. The defense is provenance on every retrain plus statistical detection of feedback distribution shift.

This skill is distinct from `rag-pipeline-security` (which is retrieval-side of the inference path) and `ai-attack-surface` (which is the broader technical attack surface). MLOps-security covers the full ML lifecycle as a supply chain, with explicit defense per layer.

---

## Framework Lag Declaration

| Framework | Control | Why It Fails for MLOps in mid-2026 |
|---|---|---|
| NIST SP 800-218 SSDF | PS / PW / RV practices (verify integrity, configure software securely, respond to vulnerabilities) | SSDF v1.1 (2022) is software-development process language. It does not operationalize ML artifacts: training datasets, model weights, hyperparameter configurations, experiment-run metadata, and feature-store entries are not "software" in SSDF's scope. An organization can claim full SSDF conformance with no model-weight signing, no training-data lineage attestation, and no model-registry provenance. AI-generated code provenance is not addressed. See `data/framework-control-gaps.json` `NIST-800-218-SSDF` entry. |
| SLSA v1.0 | Build L3 (hardened builder, isolated, signed provenance) | SLSA Build L3 applies to software-build pipelines. The ML-specific extension — model provenance, training-data lineage, training-run attestation — is on the SLSA v1.1 draft roadmap, not in v1.0. Even where SLSA L3 is achieved for the training-script repository, the model artifact emerging from the training run is not covered by a v1.0-conformant attestation. See `data/framework-control-gaps.json` `SLSA-v1.0-Build-L3`. |
| ISO/IEC 42001:2023 | Clause 6.1.2 (AI risk assessment) | AI management-system standard. Clause 6.1.2 requires identification of AI risks but is process-focused — no technical floor for training-data integrity controls, model-weight signing, drift-detection cadence, or feedback-loop attestation. An organization can be 42001-certified with none of these in place. See `data/framework-control-gaps.json` `ISO-IEC-42001-2023-clause-6.1.2`. |
| NIST AI RMF | MEASURE 2.5 (Continuous Monitoring) | Recommends operational monitoring but provides no specific technical requirements for MLOps. Drift detection cadence is unspecified; adversarial-input monitoring is unspecified; feedback-loop integrity is unspecified. See `data/framework-control-gaps.json` `NIST-AI-RMF-MEASURE-2.5`. |
| OWASP LLM Top 10 (2025) | LLM08 (Vector and Embedding Weaknesses) | Retrieval-side concern. Does not cover training-pipeline integrity, model-registry RBAC, deployment-pipeline gating, or inference-serving runtime hardening. See `rag-pipeline-security` for retrieval coverage; this gap remains for the rest of the MLOps lifecycle. See `data/framework-control-gaps.json` `OWASP-LLM-Top-10-2025-LLM08`. |
| EU AI Act (Regulation 2024/1689) | Article 10 (data governance), Article 13 (technical documentation), Article 15 (accuracy, robustness, cybersecurity) for high-risk AI | Requires training-data documentation and a technical file for high-risk AI systems. Does not specify ML-BOM format, model-weight signing technology, training-data lineage attestation format, or drift-detection cadence. CycloneDX 1.6 ML-BOM and SPDX 3.0 AI profile are usable implementation vehicles, but neither is mandated. Implementing acts through 2026-2027 may tighten this. |
| UK DSIT AI Cyber Code of Practice (2025) | 13 principles for secure AI development and deployment | Principles-based code published by Department for Science, Innovation and Technology in 2025. Names training-data integrity, model-deployment security, monitoring, and supply chain — but as principles, not testable controls. No technical floor for signing, lineage, or drift cadence. |
| AU Voluntary AI Safety Standard | 10 guardrails (2024) | Voluntary; principles-language similar to UK DSIT. No technical floor; no signing, no lineage attestation, no drift cadence required. |
| JP AI Strategy Council "Society Principles" | Principles for human-centric AI | Higher-level than UK / AU; aspirational rather than operational. METI's AI Operator Guidelines (2024) add some operational guidance but no MLOps-specific technical floor. |
| IL INCD AI Systems Cyber Defense Methodology (2024) | INCD AI methodology | Closest-to-operational national methodology in this list — names supply-chain, training-data, model-integrity, and monitoring as in-scope. Recommends but does not mandate signing or lineage attestation. |
| SG AI Verify Foundation testing framework | Model Card + AI Verify toolkit | Testing-and-documentation framework, not a security control. Useful for transparency; not sufficient for MLOps integrity. |
| IN MeitY pending AI Act | Draft (2025-2026) | Not yet in force as of 2026-05; sector-specific guidance from SEBI / RBI / IRDAI applies in finance. No MLOps-specific technical floor enacted. |
| US NYDFS Part 500 + 2024 AI letter | 23 NYCRR 500 + DFS Industry Letter on AI Cybersecurity Risks (Oct 2024) | Letter classifies AI as a material risk and requires covered entities to address AI-specific vectors including training-data integrity and model-supply-chain risk. Letter is interpretive; underlying Part 500 controls (500.11 third-party, 500.07 access privileges) are the enforceable hooks. No prescriptive MLOps technical floor. |
| US NIST 800-53 Rev 5 | SI-7 (information integrity), SA-12 (supply chain), SI-4 (system monitoring) | Apply nominally to ML artifacts but specify no MLOps-specific evidence. Auditors accept process documents. |
| ISO 27001:2022 | A.5.21 (ICT supply chain), A.8.16 (monitoring), A.8.28 (secure coding) | Process-language across the board. Same lag pattern as for traditional software supply chain. |

**Fundamental gap:** no framework requires cryptographic provenance verification at every MLOps handoff (data → training → registry → deployment → inference) as the integrity control. Frameworks accept process and inventory evidence. The technical standards (CycloneDX 1.6 ML-BOM, SPDX 3.0 AI profile, OpenSSF model-signing, in-toto for ML, SLSA ML extension draft) exist but are unmandated as of mid-2026.

---

## TTP Mapping

Descriptions sourced from `data/atlas-ttps.json` (ATLAS v5.1.0, released 2025-11-01).

| ATLAS / ATT&CK ID | Technique | MLOps Lifecycle Stage | Gap |
|---|---|---|---|
| AML.T0010 | ML Supply Chain Compromise (sub-techniques: GPU Firmware, ML Framework, Model Repository, MCP Server) | Cross-cutting — touches every ingestion point: dependencies in training environment (AML.T0010.001), model pulls from Hugging Face / vendor registries (AML.T0010.002), MCP plugins in dev tooling (AML.T0010.003) | No framework mandates registry-side cryptographic verification of all ingested artifacts; the SLSA-style attestation chain for ML artifacts is draft, not required |
| AML.T0018 | Manipulate AI Model (sub-techniques: Poison Training Data, Trojan Model via direct weight manipulation, Federated Learning Poisoning) | Training pipeline and post-training tampering — adversary modifies weights either through poisoned training data persisted into weights or through direct binary edit of an unsigned checkpoint | No framework requires model-weight signature verification at registry write and at deployment read; CWE-502 deserialization risk on `.pt` / `SavedModel` is unmapped to compliance control |
| AML.T0020 | Poison Training Data (sub-techniques: Inject at Scale, Craft Targeted, RAG Knowledge Base Poisoning) | Data ingestion → feature store → training. Adversary contaminates training corpus to embed targeted misbehavior. Sub-technique AML.T0020.002 is RAG-side (see `rag-pipeline-security`); AML.T0020.000 / 001 are MLOps-side. | No framework requires training-data lineage attestation, source signing, or poisoning-detection scanning at ingestion. EU AI Act Art. 10 requires data-governance documentation but not cryptographic attestation. |
| AML.T0043 | Craft Adversarial Data (White-Box, Black-Box, Physical) | Inference serving and feedback loop — adversary crafts inputs to either cause misclassification at inference time or to poison the feedback corpus when feedback is logged for retraining | No framework requires adversarial-robustness testing for deployed models or adversarial-input detection at the serving layer; AI RMF MEASURE-2.5 recommends but does not require |
| AML.T0017 | Discover ML Model Family / Ontology (Probe, Extract System Prompt, Map Filters) | Model registry exposure — adversary maps deployed model family, extracts metadata, infers training corpus, harvests prompts and guardrails | No framework requires model-registry RBAC at the granularity needed (per-project read scoping, signed registry queries, audit of model-extraction-pattern queries) |
| T1195.001 | Supply Chain Compromise: Software Dependencies and Development Tools | Training pipeline dependency chain — Python wheels, CUDA drivers, ML framework versions, notebook kernels | SCA detects known-vulnerable; XZ-class novel compromise is not detectable without SLSA L3 + reproducible builds for the training environment |
| T1565 | Data Manipulation (Stored, Transmitted, Runtime) | Cross-cuts every MLOps stage — manipulation of stored training data, transmitted features to inference, or runtime model state | SI-7 maps to traditional file/firmware integrity; extending to feature-store payload integrity and embedding-space integrity is not in current control |

Cross-walk to CWE (see `data/cwe-catalog.json`):

| CWE | Why It Maps |
|---|---|
| CWE-1426 (AI/ML — Improper Validation of Generative AI Output) | Output-validation gap on the inference-serving layer; feedback-loop integrity depends on validating model outputs before they enter retrain corpora |
| CWE-1395 (Dependency on Vulnerable AI/ML Components) | Training pipelines pull AI-specific dependencies (PyTorch, TensorFlow, transformers, ML framework plugins) where reachability analysis is rarely applied; pinning helps but is not signature verification |
| CWE-1357 (Reliance on Insufficiently Trustworthy Component) | Continuous re-evaluation of model-publisher trust — the Hugging Face takedown class is exactly the CWE-1357 lag (publisher-position compromise that procurement-time review does not catch) |
| CWE-502 (Deserialization of Untrusted Data) | Model weights in code-executing serialization formats — Python-object `.pt`, executable `SavedModel` payloads, unsafe ONNX parsers, GGUF parsing memory-safety findings — reject and migrate to safetensors |

---

## Exploit Availability Matrix

Sourced from `data/cve-catalog.json`, public incident history, and `data/atlas-ttps.json` real-world-instances as of 2026-05-11. Per AGENTS.md hard rule #1, CVE references include CVSS, KEV, PoC, AI-discovery, exploitation, and patch availability. Technique-class rows are scored as ongoing class risks per AGENTS.md hard rule #3 — RWEP is not assigned because the field is defined for individual CVEs in `data/cve-catalog.json`.

| Incident / Class | CVSS | PoC Public? | CISA KEV? | AI-Accelerated? | Patch / Mitigation | SLSA-Detectable? | ML-BOM-Detectable? |
|---|---|---|---|---|---|---|---|
| Hugging Face poisoned model weights (Mithril 2024 + ongoing takedowns through 2026) — AML.T0018 class | N/A (technique class) | Yes — repository takedowns and reproducible RCE demonstrations via code-executing checkpoints | No (technique class) | Yes — adversarial fine-tuning at scale + LLM-assisted backdoor design | Reject code-executing serialization (Python-object `.pt`, executable `SavedModel`); require safetensors; verify Sigstore / OpenSSF model-signing against pinned publisher identity | Partially — SLSA-style training-run attestation flags missing provenance | Partial — ML-BOM (CycloneDX 1.6) inventories models; does not by itself attest integrity |
| MLflow tracking-server vulnerabilities (CVE-2023-43472 class: path-traversal, SSRF, auth-bypass — ongoing patches through 2025-2026) | 7.5 – 9.8 across the class | Yes — multiple public exploit demonstrations | No KEV at time of writing | Partial — security researchers using AI-assisted source analysis surface follow-on findings | MLflow upstream patches; auth front-end (reverse proxy with auth, network segmentation of tracking servers, RBAC layer) | Yes when SBOM tracks MLflow version | Not applicable (the tracking server is software, not a model artifact) |
| PyTorch / TensorFlow deserialization RCE (CWE-502, recurring) | 7.8 – 9.8 per CVE | Yes — Python-object deserialization RCE is canonical demonstration | No KEV at writing for the model-deserialization specific subset | Yes — automated checkpoint-crafting | Reject code-executing serialization; migrate to safetensors; isolate model-loading services (containerized, seccomp, no outbound network) | Partial — SLSA on training repo flags upstream framework versions | Yes — ML-BOM inventories framework version |
| BadNets / TrojanNN / BackdoorBench academic class demonstrations (AML.T0020 sub-techniques) | N/A (technique class) | Yes — code released for all three | No | Yes — backdoor pattern generation accelerated by adversarial fine-tuning | Mitigation only: training-data lineage attestation, source signing, poisoning-detection scanning (Spectral Signatures, Activation Clustering, STRIP), provenance on every retrain | Partial — training-data lineage is a SLSA ML extension draft requirement | Partial — ML-BOM can inventory datasets; integrity attestation is separate |
| MCP server typosquat in `@modelcontextprotocol/*` namespace (AML.T0010.003, ongoing) | N/A (technique class) | Yes — multiple public incidents 2024-2026 | No | Yes — AI accelerates convincing tool-description authoring | Pin versions, verify npm provenance attestation, enforce publisher allowlist; see `mcp-agent-trust` and `supply-chain-integrity` | Yes — SLSA provenance from known publisher fails on typosquat | Yes — SBOM diff at install flags new packages |
| Feedback-loop poisoning (AML.T0043 → retrain pipeline class risk, ongoing) | N/A (technique class) | Yes — academic demonstrations of LLM-as-judge poisoning, RLHF reward-model poisoning | No | Yes — adversaries use LLMs to generate convincing feedback at scale | Mitigation: feedback-source attestation, statistical detection of feedback distribution shift, holdout retraining where feedback is sampled rather than wholesale incorporated, every retrain provenance-attested with input dataset hash | Yes when retrain pipeline produces in-toto attestation per run | Partial — ML-BOM lists training datasets; lineage to feedback corpus must be explicit |

**Tool maturity for defenders (mid-2026 baseline):**

- **ProtectAI ModelScan** (open source) — static analysis on model artifacts for unsafe deserialization patterns; production-ready for `.pt`, `.h5`, ONNX, GGUF surface checks.
- **Garak** (open source) — LLM red-team probing framework; useful for AML.T0017 and AML.T0043 coverage on deployed LLMs.
- **CleverHans** (open source) — adversarial-input library; production use for AML.T0043 robustness testing.
- **Hugging Face model scanner** — first-party scanning on uploaded artifacts; surface-level deserialization and known-malicious detection.
- **Sigstore cosign + OpenSSF model-signing** — production signing for model weights via OCI registries.
- **Evidently / Arize / Fiddler / WhyLabs** — drift detection; coverage of data-quality drift and accuracy regression; weak on adversarial-input detection and output anomaly profiling without additional configuration.

**Interpretation:** because most MLOps integrity threats are architectural (no single vendor CVE to patch), posture is determined by the presence or absence of cross-pipeline cryptographic provenance. CVE-feed-scoped vulnerability management programs will surface MLflow / framework vulns but will not surface model-weight tampering, training-data poisoning, or feedback-loop poisoning. The class-level findings dominate.

---

## Analysis Procedure

The procedure threads three foundational principles. Each is non-negotiable; any MLOps-security program missing one of them is structurally vulnerable.

### Defense in depth

Layered controls across the MLOps lifecycle — data → training → registry → deployment → inference → monitoring → feedback. One layer is fragile; the depth makes the program robust.

- **Training-data lineage attestation.** Every training dataset has a data card (transparency document) plus a cryptographically signed source attestation. The training run records dataset hash and lineage as in-toto evidence.
- **Training-run integrity.** Training scripts in version control are Sigstore-signed. Training runs execute in isolated environments (per-run ephemeral GPU pods, fresh credentials, no production-write paths). SBOM per training environment captures every dependency.
- **Model artifact signing.** Output model weights signed by cosign keyless against an OIDC-issued Fulcio certificate. Signatures recorded in the Rekor transparency log. Format restricted to non-executing (safetensors); code-executing formats rejected.
- **Model registry RBAC and provenance.** Project-scoped read/write permissions on MLflow Registry / SageMaker Model Registry / Vertex Model Registry / Azure ML registry / Hugging Face Hub private orgs. Every registry write produces an in-toto attestation linking training run → dataset hashes → model artifact hash → committing identity.
- **Deployment pipeline admission gate.** Pre-deployment policy controller (Sigstore policy-controller, Kyverno verify-images extended for model artifacts, custom admission webhook) verifies model artifact signature, attestation chain, and registry-source identity before allowing deployment.
- **Inference serving runtime hardening.** Serving containers run under restricted seccomp / AppArmor profiles. GPU isolation via NVIDIA confidential computing or dedicated nodes. Falco / Tetragon monitoring for anomalous syscalls. See `container-runtime-security` for the runtime-layer handoff.
- **Drift and adversarial monitoring.** Statistical drift (input distribution, feature distribution, output distribution) plus semantic drift (concept drift in input meaning) plus adversarial input detection (OOD detection, prediction confidence anomaly, query-pattern profiling — D3-IOPR).
- **Feedback-loop integrity.** Every retrain run produces in-toto attestation. Feedback sources are attested (signed by collecting service). Statistical detection of feedback distribution shift. Holdout retraining where feedback is sampled and validated rather than wholesale incorporated.

### Least privilege

Scope every privilege as narrowly as the MLOps action requires.

- Training pipelines have minimum data access — read-only on training datasets, no broad ETL roles, no production-data read by default.
- Model registries are scoped per project — write only by the training pipeline of that project; read only by deployment pipelines and approved inference services.
- Serving services load only their own signed models — model-load permission scoped to a single registry path; pull other models requires a separate authorization.
- AI agents using models in tool-use loops have least scope — the agent's service account is scoped to the action set, never inherited from the deploying user.
- Notebook environments (Jupyter, Colab, Databricks, SageMaker Studio) have no production-write paths. Notebook-driven training writes to a staging registry, not production.
- Experiment-tracking systems segregate credentials — no shared service account across projects. MLflow / W&B / Vertex Experiments run on isolated networks with per-project authentication.

### Zero trust

Every artifact is untrusted until cryptographically verified.

- Every model artifact is untrusted until the signature is verified against a pinned publisher identity (Sigstore Fulcio subject) and the Rekor inclusion proof is checked.
- Every training data source is untrusted until lineage attestation is verified — a CSV from S3 is not trusted because S3 is in your account; it is trusted because the upstream system signed the data export.
- Every inference request can re-verify the loaded model's signature — load-time verification is the gate, but the serving service should expose a health-check that re-asserts the model hash for audit.
- Default-deny on unsigned artifacts at deployment admission and at model-load time. A signature file next to a model is decoration; verifying signature + identity + attestation + Rekor is evidence.
- Verify the **build config**: the training-run attestation must show a hardened-builder (SLSA L3-equivalent for training, on the draft ML extension trajectory) — not just that some pipeline produced the model.

### Step-by-step procedure

1. **Data lineage inventory.** For every training dataset, record: sources, consumers, purpose, classification, signing identity at source, lineage chain to derived features in the feature store. Build a sources × consumers × purpose matrix. Flag any dataset without a lineage attestation.

2. **Training data integrity controls.** Datasets are versioned (DVC, lakeFS, Delta Lake) with content-hash addressing. Each dataset has a data card per Google / Hugging Face conventions. Each dataset source emits a signed attestation at export. Ingestion pipelines verify the signed attestation before incorporating the dataset into the training corpus. Poisoning detection (Spectral Signatures, Activation Clustering, STRIP, or equivalent) is applied to suspect or third-party datasets.

3. **Training pipeline hardening.** Training scripts are Sigstore-signed in version control. Training runs execute in isolated ephemeral environments (per-run pods, fresh credentials short-lived via OIDC, no production-write paths). Generate SBOM per training environment (Syft on the container image, cdxgen on the Python environment) capturing every dependency including CUDA driver, ML framework version, transformers / accelerators, and notebook kernels.

4. **Model artifact signing.** Use cosign keyless to sign model weights against an OIDC-issued Fulcio certificate, attach as OCI artifact (referrers API) to the model in the registry. Reject code-executing serialization formats — require safetensors or equivalent type-safe format. Maintain an explicit allowlist of approved model publishers (org-internal MLOps registry, vetted Hugging Face orgs, vendor model registries).

5. **Model registry RBAC and provenance attestation.** Configure RBAC per project on MLflow Registry / SageMaker Model Registry / Vertex Model Registry / Azure ML / Hugging Face private orgs. Every registry write emits an in-toto attestation that links training run → dataset hashes → model artifact hash → committing identity. Verify registry queries can be audited.

6. **Deployment pipeline gate.** Implement admission verification at deployment time. For Kubernetes-based serving (KServe, Seldon, BentoML), use Sigstore policy-controller or Kyverno verify-images extended to model artifacts. For managed endpoints (SageMaker, Vertex, Azure ML), use the platform's signing-verification feature where available, otherwise a custom pre-deployment validator. Default-deny on unsigned artifacts.

7. **Inference runtime hardening.** Inference serving containers run under restricted seccomp / AppArmor / SELinux profiles. GPU isolation via NVIDIA confidential computing or dedicated node pools. Runtime monitoring (Falco, Tetragon) on serving processes. Outbound network egress restricted — no unsolicited outbound from inference services. Hand off the runtime-layer treatment to `container-runtime-security`.

8. **Drift detection (semantic + statistical).** Instrument three layers:
   - **Statistical drift** — input feature distributions, output distributions, accuracy on labeled holdout (Evidently, Arize, Fiddler, WhyLabs).
   - **Semantic drift** — concept drift in input meaning; embedding-distribution shift over time; D3-IOPR-style profiling of input/output payloads.
   - **Cadence** — daily statistical, weekly semantic, alert on threshold breach. Quarterly drift review is not sufficient — that is miss-the-attacker territory.

9. **Adversarial monitoring.** Input distribution profiling for OOD detection, prediction confidence anomaly detection, query-pattern profiling (D3-IOPR) to surface AML.T0017 (model probing) and AML.T0043 (adversarial inputs). For LLM-serving, integrate Garak-class probing into a continuous red-team loop.

10. **Feedback loop integrity.** Every retrain run produces an in-toto attestation. Feedback sources are signed by the collecting service. Statistical detection of feedback distribution shift on a per-source basis. Holdout retraining — feedback is sampled and validated against a labeled baseline before incorporation, not wholesale ingested. Verify that every model in production carries a chain of attestations back to the original training run plus every retrain run since.

---

## Output Format

```
## MLOps Pipeline Security Assessment

**Assessment Date:** YYYY-MM-DD
**Scope:** [MLOps stack(s): MLflow / Kubeflow / Vertex AI / SageMaker / Azure ML / Hugging Face / DIY]
**Models in Scope:** [count, classification, deployment surfaces]
**Frameworks in scope:** [NIST 800-218 SSDF | SLSA v1.0 | ISO/IEC 42001:2023 | NIST AI RMF | OWASP LLM Top 10 | EU AI Act | UK DSIT AI Cyber Code | AU AI Safety Standard | JP Society Principles | IL INCD AI | SG AI Verify | IN MeitY draft | NYDFS Part 500]

### MLOps Stack Inventory
| Stage | Tooling | Hosted / Self-Managed | Auth Model | Notes |
|---|---|---|---|---|
| Data ingestion | | | | |
| Feature store | | | | |
| Training orchestrator | | | | |
| Experiment tracking | | | | |
| Model registry | | | | |
| Deployment pipeline | | | | |
| Inference serving | | | | |
| Monitoring / drift | | | | |
| Feedback collection | | | | |

### Training Data Lineage Map
| Dataset | Source | Classification | Signed at Source? | Data Card? | Consumers | Poisoning Detection Applied? |

### Model Registry Provenance Matrix
| Model | Registry | Training Run Attested? | Dataset Hashes Recorded? | Artifact Signed? | Publisher Identity Pinned? | Format (safetensors / code-executing / ONNX / GGUF) |

### Deployment Pipeline Gate Coverage
| Deployment Path | Admission Verification? | Signature Verified? | Attestation Chain Verified? | Default-Deny on Unsigned? |

### Drift Detection Scorecard
| Model | Statistical Drift Cadence | Semantic Drift Cadence | Adversarial-Input Detection? | Output Anomaly Detection? | Feedback Distribution Monitoring? |

### Model Signing Coverage
| Class | Count Signed / Total | Publisher Identities Pinned | OpenSSF Model-Signing Used? | Cosign + Rekor? |

### AI Artifact SBOM (ML-BOM) Compliance
| Artifact Class | CycloneDX 1.6 ML-BOM Coverage | SPDX 3.0 AI Profile Coverage | Training-Data Lineage Embedded? |

### CVE / Incident Exposure
[MLflow / framework vulns from current `cve-catalog.json`; ongoing class risks per Exploit Availability Matrix]

### Framework Gap Declaration
[Per framework in scope: which control nominally applies; why current implementation does not close the MLOps integrity gap; what real evidence would close it]

### Gap Remediation Roadmap
[Prioritized by blast radius (production model classification × query volume × feedback-loop presence). Each item: specific delta, owner, target date, success criterion (e.g., "All production model weights signed via cosign keyless against pinned org Fulcio identity by YYYY-MM-DD, admission gate enforcing in SageMaker deployment pipeline, verification logged with Rekor inclusion proof").]
```

---

## Compliance Theater Check

Concrete tests that distinguish a paper-compliant MLOps program from one that actually verifies integrity at every handoff. Run all four. Any "we trust X" answer is theater post-Hugging-Face-incidents.

1. **End-to-end provenance chain.** Ask: *"For your last production model deployment, walk me through the chain: data sources → training run → model artifact → registry entry → deployment commit. Paste an attestation or signed artifact at every link."* If any link is missing provenance — if the training run does not record dataset hashes, or the registry entry does not link to the training run attestation, or the deployment commit does not reference a signed artifact — the chain is broken, and the AI Act Article 13 technical-file claims, the 42001 lifecycle claims, and the SSDF integrity claims are theater.

2. **Model artifact signing.** Ask: *"Is your last production model artifact signed? Paste the `cosign verify --certificate-identity=<expected> --certificate-oidc-issuer=<expected>` output, and show the Rekor inclusion proof."* If the answer is "we trust the registry because it's our private MLflow / SageMaker / Vertex / Azure ML" — that is theater post-Hugging-Face-takedowns. The registry is the storage location; signing identifies the publisher. Trusting the storage does not authenticate the contents. A registry compromise (CVE-2023-43472 class on MLflow, IAM misconfiguration on a managed registry) replaces the artifact without signature verification surfacing the change.

3. **Training data poisoning detection.** Ask: *"What is your detection for training-data poisoning? Describe the technique (Spectral Signatures? Activation Clustering? STRIP? data-card review + provenance attestation?) and the cadence."* If the answer is "we trust upstream datasets" or "we use only internal data" — internal data is poisoned through feedback loops (AML.T0043 → retrain → AML.T0020) without explicit feedback-source attestation. Internal-data assumption is the exposure.

4. **Drift detection cadence.** Ask: *"What is the cadence and threshold for drift alerts on production models?"* If quarterly — that is miss-the-attacker territory; an adversary executing a feedback-loop poisoning attack has weeks before the next review. If only on labeled holdout accuracy — semantic drift and adversarial-input distribution shift are invisible. A real program runs statistical drift daily, semantic drift weekly, and has an adversarial-input detector continuously profiling inputs at the serving layer.

A genuinely conformant MLOps program answers all four with concrete artifacts: an end-to-end provenance chain printed for any production model, a cosign verify output with pinned publisher identity, a documented poisoning-detection pipeline with measurable false-positive rate, and a drift-detection dashboard showing daily / weekly / continuous cadence.

---

## Defensive Countermeasure Mapping

D3FEND techniques referenced (see `data/d3fend-catalog.json`). Each is annotated with defense-in-depth layer position, least-privilege scope, zero-trust posture, and AI-pipeline applicability per AGENTS.md hard rule #9.

- **D3-EHB (Executable Hash-based Allowlist)** — Hash-pinned allowlist for model artifacts at load time. Maps to model-weight SHA-256 verification at inference-service load, and to in-toto / SLSA-style attestation enforcement at deployment. Defense-in-depth layer: runtime model-load. Least-privilege scope: serving service has read-only access to a pinned set of model hashes for its project, no read on other models. Zero-trust posture: default-deny on any model hash not in the allowlist. AI-pipeline applicability: persistent registries store the allowlist; ephemeral serving pods pull and verify on each model-load.

- **D3-EAL (Executable Allowlisting)** — Runtime restriction of execution to pre-approved executables, extended in the MLOps context to inference-service binary lineage. Closes the loop on training-run signing: even if a tampered training artifact reaches the serving host, D3-EAL on the serving container blocks unauthorized binary execution emerging from a deserialization-RCE in the model artifact. Defense-in-depth layer: runtime inference-service host. Least-privilege scope: serving container has a minimum binary allowlist for the model-serving framework only — no shell, no debugging utilities, no outbound-network utilities. Zero-trust posture: every binary execution is verified against the allowlist regardless of pathway. AI-pipeline applicability: ephemeral serving pods are reprovisioned with the allowlist baked into the immutable image; persistent training runs use a separate, broader allowlist scoped to training-only operations.

- **D3-IOPR (Input/Output Profiling)** — Profiling of input and output payloads at inference services to detect adversarial inputs (AML.T0043) and model-probing patterns (AML.T0017). Defense-in-depth layer: serving-layer pre- and post-inference. Least-privilege scope: profiling service has read-only access to inference traffic at the serving proxy; no model-load privileges, no registry-write privileges. Zero-trust posture: every inference request is profiled regardless of source authentication — authenticated users execute AML.T0043 attacks too. AI-pipeline applicability: serves both ephemeral inference pods (profiling sidecar) and persistent monitoring services (drift-detection pipeline ingesting profiled telemetry).

Per AGENTS.md hard rule #9, MLOps stacks span three architectural layers each requiring an explicit defense story:

- **Ephemeral training jobs** — per-run pods on Kubeflow / Vertex / SageMaker / Ray. SLSA-style training-run attestation is the integrity anchor; D3-EAL on the training container is the runtime control. Live patching is not applicable — runs are torn down post-training.
- **Persistent model registries** — MLflow Model Registry, SageMaker Model Registry, Vertex Model Registry, Azure ML registry, Hugging Face Hub private orgs. RBAC is the access-layer control; signature attestation on every write is the integrity control. Standard server-hardening + patch-SLA applies.
- **Ephemeral inference serving pods** — KServe, SageMaker endpoints, Vertex endpoints, Azure ML online endpoints, BentoML, Seldon. Pre-load signature verification + D3-EHB allowlist + D3-EAL + D3-IOPR profiling. Live patching is replacement of the immutable image; rolling redeploy is the operational control.

Signing baseline reference: RFC 8032 (Ed25519 / Ed448) is the asymmetric signature algorithm used by Sigstore keyless signing for cosign and is one of the supported algorithms for OpenSSF model-signing. PQC migration to ML-DSA (FIPS 204) / SLH-DSA (FIPS 205) for model-weight signing is on the forward-watch list; track via `pqc-first`.

---

## Hand-Off / Related Skills

After producing the MLOps pipeline security assessment, chain into the following skills. Each entry is specific to a finding class this skill produces.

- **`rag-pipeline-security`** — retrieval-side of the inference path. Where this skill identifies a feedback-loop poisoning risk or a model serving an embedding-similarity retrieval surface, chain into the RAG skill for the vector-store, retrieval-filter, and indirect-prompt-injection treatment.
- **`ai-attack-surface`** — broader AI threat landscape. MLOps integrity findings are one component of the wider AI-application threat model; the AI attack surface skill situates them alongside LLM tool-use, prompt-handling, and agent autonomy threats.
- **`supply-chain-integrity`** — SLSA / Sigstore / in-toto / SBOM foundation. Every signing, attestation, and provenance recommendation in this skill is operationalized through the controls defined there. Model weights are supply-chain artifacts; this skill's MLOps integration sits on top of the supply-chain skill's signing primitives.
- **`container-runtime-security`** — inference serving hardening. Where this skill identifies a serving-layer hardening gap (D3-EAL, D3-EHB at load, seccomp / AppArmor profiles, GPU isolation, Falco / Tetragon monitoring), hand off the runtime treatment to the container-runtime-security skill.
- **`cloud-security`** — cloud MLOps. Where the stack is Vertex AI / SageMaker / Azure ML, cloud-side IAM, KMS key custody for signing keys, VPC service controls / private endpoints for registries, and cloud-native admission policies are the operational substrate. Chain into cloud-security for the cloud-control-plane treatment.
- **`ai-risk-management`** — governance overlay (ISO 42001, ISO 23894, NIST AI RMF). Where this skill identifies a framework gap, the governance overlay translates findings into the management-system documentation, AI impact assessment, and high-risk AI classification work products.
- **`coordinated-vuln-disclosure`** — AI vulnerability intake. Where this skill surfaces a vendor vulnerability (MLflow class, framework class, MCP server class), or where research surfaces a novel poisoning pattern requiring coordinated disclosure, chain into the CVD skill for the ISO 29147 / 30111 / CSAF 2.0 publication workflow.

For ephemeral / serverless MLOps pipelines (per AGENTS.md hard rule #9): training-run lineage attestation in environments where the training pod is torn down before the registry write completes requires that the attestation is emitted from inside the training run and pushed to the registry as a registry-side artifact (OCI referrers API or in-toto bundle attached to the model entry). Live patching of in-flight training runs is architecturally impossible — the scoped alternative is roll-forward (kill the run, re-run from a signed training-script revision) plus post-hoc attestation-chain audit.
