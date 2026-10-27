---
name: decompression-dos
version: "1.0.0"
description: Decompression-bomb, parser-DoS, and ReDoS resistance for mid-2026 — decompression size/ratio caps, Zip Slip path confinement, XML entity-expansion disabling, linear-time regex on untrusted input, parse-depth limits, and length-field allocation bounds against single-input amplification denial of service
triggers:
  - decompression bomb
  - zip bomb
  - zip slip
  - redos
  - regular expression denial of service
  - catastrophic backtracking
  - billion laughs
  - xml entity expansion
  - xxe
  - parser dos
  - resource exhaustion
  - amplification attack
  - nested archive
  - recursion depth
  - length field allocation
  - input amplification
  - brotli
  - node2shell
  - content-encoding br
discovery_mode: standalone
data_deps:
  - cve-catalog.json
  - atlas-ttps.json
  - attack-techniques.json
  - framework-control-gaps.json
  - cwe-catalog.json
  - rfc-references.json
atlas_refs: []
attack_refs:
  - T1499
  - T1499.001
  - T1059
framework_gaps:
  - NIST-800-53-SI-2
  - NIS2-Art21-network-security
  - UK-CAF-B4
  - AU-ISM-1240
cwe_refs:
  - CWE-409
  - CWE-1333
  - CWE-400
  - CWE-776
  - CWE-22
  - CWE-834
  - CWE-770
  - CWE-787
last_threat_review: "2026-10-27"
---

# Decompression-Bomb / Parser-DoS / ReDoS Resistance

## Threat Context (mid-2026)

Amplification denial of service turns a tiny, structurally-valid input into ruinous server work. A 42 KB zip bomb expands to petabytes; a few lines of nested XML entities expand to gigabytes (the billion-laughs attack); a crafted string pins a CPU core for seconds-to-minutes on a backtracking regular expression (ReDoS); a binary parser that reads a declared 2 GB length field allocates a 2 GB buffer from a 10-byte message. A Zip Slip archive entry named `../../x` escapes the extraction directory to overwrite a binary on the execution path. Input-format validation passes all of these because each input is valid — the amplification lives in how it is processed, not in its shape. The defense is a resource bound at the parser, not validation or autoscaling.

A resource bound does not protect against a memory-safety flaw in the decoder itself. CVE-2026-111497 (Node2Shell, CVSS 4.0 9.2, RWEP 55) is an out-of-bounds write in the Google Brotli decoder 1.0.3 through 1.2.0: a crafted stream with an invalid block switch makes the streaming decoder write past an eight-byte internal buffer, which can crash the process, disclose memory or, under narrow conditions, execute code. Node.js bundles the decoder and is fixed in 22.23.4, 24.22.1 and 26.12.1; Node.js 20, 23 and 25 receive no fix. A Node.js process reaches it through `node:zlib` (`brotliDecompress`, `createBrotliDecompress`), through Express 5 and body-parser 2 decoding a request body sent with `Content-Encoding: br`, and through `fetch()` and other HTTP clients, which decode a `Content-Encoding: br` response even when the request advertised only gzip and deflate. A size cap on the decompressed output does not stop the write, because the overflow happens inside the decoder before any output limit applies.

## Framework Lag Declaration

Organizational controls treat "we validate all input" and "the cloud autoscales" as denial-of-service protection. NIST 800-53 SI-10 (information input validation) is satisfied by validating format and does not require bounding decompression ratio, entity expansion, or regex complexity. SC-5 (denial-of-service protection) is framed at the network tier and is not operationalized for single-request, asymmetric application-layer DoS. A clean "we validate input / have a WAF / autoscale" audit is therefore NON-EVIDENCE for amplification-DoS resistance; it confirms format validation and elastic infra, not the decompression caps, entity disabling, regex-complexity bounds, parse-depth limits, and length-field allocation bounds that actually stop a single crafted input from exhausting the instance.

## TTP Mapping

The amplification-DoS failures map to MITRE ATT&CK: **T1499 (Endpoint Denial of Service)** for ReDoS and circuit-style resource exhaustion; **T1499.001 (OS Exhaustion Flood)** for decompression bombs, billion-laughs entity expansion, deep-recursion parsing, and length-field over-allocation that exhaust memory/CPU from a single input; and **T1059 (Command/Execution)** for Zip Slip path traversal that overwrites an executable or config to gain code execution. The weakness classes are CWE-409 (improper handling of highly compressed data), CWE-1333 (inefficient regular expression complexity / ReDoS), CWE-776 (XML entity expansion), CWE-834 (excessive iteration / unbounded recursion), CWE-22 (path traversal — Zip Slip), CWE-400 (uncontrolled resource consumption), and CWE-770 (allocation without limits).

## Exploit Availability Matrix

These are processing-bound gaps exploited by a single small input, so the exploit is the absent bound, not a published CVE. Zip bombs (42.zip), billion-laughs XML, and ReDoS strings are public, well-documented, and trivially reproduced; Zip Slip has public proof-of-concept archives. None require a network position beyond an endpoint that accepts an upload or a string. The real-world priority is set by whether the ingest is internet-facing and whether a single crafted input can exhaust the whole instance (one-shot DoS) or, for Zip Slip, write outside the extraction target — the latter escalating from DoS to arbitrary file write and code execution.

CVE-2026-111497 is the exception to the processing-bound pattern: it is a decoder memory-safety flaw with a published CVE and public proof-of-concept code. The dimasma0305/CVE-2026-111497-POC repository reports probabilistic code execution against Express 5.3.0 on Node.js v24.22.0, other researchers argue code execution is unreachable, and ProjectDiscovery's nuclei template and Assetnote's node2shell-scanner send a 23,068,764-byte Brotli probe that does not execute a command. It is not in the CISA KEV catalog; one vendor, ELLIO, reports a failed in-the-wild attempt on 2026-10-26, so the catalog records exploitation as suspected.

## Analysis Procedure

1. Enumerate every code path that decompresses an archive, parses XML/JSON/CBOR/protobuf/ASN.1/MIME, or applies a regex to attacker-suppliable input. 2. Confirm decompression caps total output size and per-entry ratio, and caps cumulative output + recursion depth for nested archives. 3. Confirm archive extraction normalizes and confines each entry path within the target (Zip Slip). 4. Confirm the XML parser disables DTDs and external/general entities. 5. Confirm regexes on untrusted input are linear-time (RE2) or length-capped with no catastrophic-backtracking patterns. 6. Confirm structured parsers enforce a maximum nesting depth and validate declared length/count fields against remaining input before allocating. 7. For every Brotli decode path (`node:zlib` Brotli calls, request-body parsers that accept `Content-Encoding: br`, and HTTP clients that decode Brotli responses), confirm the decoder is a fixed build: Node.js 22.23.4, 24.22.1 or 26.12.1 or later, checked with `node --version` on the running process or image, since `process.versions.brotli` reports 1.2.0 on vulnerable and fixed Node.js 24 builds; Brotli 1.0.10, 1.1.1 or 1.2.1 or later elsewhere; and a process restarted since the update. Rejecting `Content-Encoding: br` at the proxy covers request bodies only, not Brotli responses the application fetches. Run the `decompression-dos` playbook to execute these as detect indicators with false-positive checks, then score by internet-reachability and one-shot-exhaustion potential.

## Output Format

Report per parser/decompression path, marking each resource bound enforced / missing / inconclusive (visibility gap). For every missing bound, state whether the ingest is internet-facing and whether a single crafted input could exhaust the instance (or, for Zip Slip, write outside the target). Distinguish a bound enforced at a lower layer (streaming runtime, RE2 engine, size-limited proxy) from an absent one, and a path that ingests only trusted fixed-size input from one that ingests attacker input. Provide the prioritized remediation (cap decompression size/ratio/nesting, confine extraction paths, disable XML entities, bound regex complexity, limit parse depth + length-field allocation) and the negative validation tests (zip bomb rejected, Zip Slip rejected, billion-laughs rejected, ReDoS bounded) plus a functional test that legitimate inputs still parse.

## Compliance Theater Check

The recurring theater is "we validate all input, so malformed data is handled," "our WAF blocks malicious uploads," and "the service autoscales, so resource exhaustion is handled." Format validation does not bound amplification; a zip bomb and a ReDoS string are structurally valid and small, so a WAF rarely catches them; autoscaling pays for the amplification without stopping it. The distinguishing test: feed a zip bomb, a billion-laughs XML, and a ReDoS string. If any expands unbounded, pins a CPU, or allocates from a declared length, validation, the WAF, and autoscaling did not bound the amplification, and the assurance is paper.

## Defensive Countermeasure Mapping

Map findings to MITRE D3FEND: decompression size/ratio caps and length-field bounds realize Resource Consumption Limiting and Input-Size Restriction (countering T1499.001); XML entity disabling realizes Document Parser Hardening (countering billion-laughs / XXE); linear-time regex realizes Algorithmic-Complexity Limiting (countering ReDoS / T1499); extraction path confinement realizes Path-Traversal Prevention (countering Zip Slip / T1059); parse-depth limits realize Recursion Bounding. Pair the static bounds with continuous coverage-guided fuzzing (the fuzz-testing-strategy skill) as the regression control for novel amplification inputs. The residual risk after bounding the known classes is an unforeseen pathological input, caught by the fuzzer rather than the caps, accepted at the CISO level.
