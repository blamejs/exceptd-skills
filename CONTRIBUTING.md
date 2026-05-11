# Contributing

## What Needs Contributing

1. **New CVE entries** — When a significant kernel, AI-platform, or supply-chain CVE drops, add it to `data/cve-catalog.json` and run the zero-day learning loop.
2. **Framework gap updates** — When a framework publishes new guidance that closes (or fails to close) a documented gap, update `data/framework-control-gaps.json`.
3. **New skill files** — When an attack class or compliance domain emerges that isn't covered by existing skills.
4. **ATLAS version updates** — When MITRE ATLAS publishes a new version, audit TTP IDs and descriptions across all skills.
5. **Global framework additions** — New jurisdiction-specific frameworks or updates to existing ones in `data/global-frameworks.json`.

## Quality Bar

The quality bar is: a senior security practitioner could use this output to make a real decision. Not a generic checklist — specific, current, actionable.

That means:

- CVE references include real exploit availability data, not "a PoC may exist"
- Framework gaps explain *why* the control fails for *this* specific TTP, not just "this control is insufficient"
- RWEP scores are justified by the factor breakdown, not asserted
- Remediation guidance accounts for real operational constraints: patching windows, live systems, production reboots, ephemeral infrastructure
- Compliance theater checks are concrete: "ask the auditor whether X is covered" is not concrete; "run `uname -r` and cross-reference against the patched kernel version for CVE-2026-31431; if unpatched, the org's patch management control is theater" is concrete

## Adding a CVE

1. Verify: NVD entry exists and has a CVSS score.
2. Check CISA KEV: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
3. Assess PoC availability. Do not include direct exploit links. Include a plain-language description of what exists publicly.
4. Document AI-discovery and AI-assisted-weaponization if relevant.
5. Add to `data/cve-catalog.json` with all required fields. Partial entries fail schema validation.
6. Run the zero-day learning loop: add corresponding entry to `data/zeroday-lessons.json`.
7. Add to `data/exploit-availability.json` with `last_verified` date.
8. Calculate RWEP score using the formula in `lib/scoring.js` and document the factor breakdown.
9. Update any skill files that cover the affected technology class (`last_threat_review` bump).

## Adding a Framework Gap

1. Identify the specific control ID (e.g., `NIST-800-53-SI-2`, `ISO-27001-2022-A.8.8`).
2. Document what the control was actually designed for (cite the framework version and original context).
3. Document which specific CVE or ATLAS TTP exposes the gap. No hypothetical gaps — evidence required.
4. Document what a real control would require to address the gap.
5. Add to `data/framework-control-gaps.json` with `status: "open"` and `opened_date`.
6. Add the control ID to `framework_gaps` in any skill that references it.

When a framework update closes a gap:
- Set `status: "closed"` with the update reference
- Do NOT delete the entry — the history of framework lag is data

## Adding a Skill

1. Create `skills/<skill-name>/skill.md`.
2. Complete all frontmatter fields — no empty arrays for `data_deps`, `atlas_refs`, or `framework_gaps` unless genuinely not applicable (document why in a comment).
3. Complete all required body sections (see ARCHITECTURE.md).
4. Ensure all CVE references are in `data/cve-catalog.json`.
5. Ensure all ATLAS refs are valid v5.1.0 IDs.
6. Ensure all framework control IDs are in `data/framework-control-gaps.json`.
7. Register in `manifest.json`.
8. Add an entry to CHANGELOG.md.

## PR Process

1. **Open an issue first** for non-trivial work — design discussion catches scope problems before code is written. Trivial fixes (typos, doc tweaks, a single field on one CVE) can skip the issue.
2. **Branch off `main`.** Branch name doesn't matter; we squash on merge.
3. **One concern per PR.** A new skill + its CVEs + its framework gap mappings + the manifest registration is one PR. A new skill + an unrelated CVE addition is two.
4. **Fail-loud verification before push** — the same gates CI runs. Skip none of these:

   ```bash
   npm run verify                              # Ed25519 signatures on every skill
   npm test                                    # node:test suite under tests/
   npm run lint                                # skill frontmatter + 7 body sections + cross-refs
   node lib/validate-cve-catalog.js            # CVE schema + zero-day learning coverage
   node orchestrator/index.js validate-cves --offline --no-fail   # local catalog sanity
   node scripts/check-manifest-snapshot.js     # detect breaking surface removals
   ```

   If your change intentionally narrows the public skill surface (removed skill, removed trigger keyword, removed data_dep), refresh the baseline and commit it alongside:
   ```bash
   node scripts/refresh-manifest-snapshot.js
   git add manifest-snapshot.json
   ```

   On Windows or macOS, you can reproduce CI's Linux + Node 24.14.1 environment locally with the Docker harness — useful for catching OS-specific regressions before pushing:
   ```bash
   npm run test:docker          # runs predeploy in a clean Linux container
   npm run test:docker:fresh    # also wipes signing state and re-bootstraps
   ```
   Docker is optional; the native `npm run predeploy` is the primary gate. See [docker/README.md](docker/README.md) for details.

5. **PR description** — for CVE additions: include the NVD URL, CISA KEV status, and your RWEP factor breakdown. For framework gap additions: include the specific control text you're analyzing and why it's insufficient. For new skills: include a worked example showing the skill's output for a real scenario.
6. **Commit message style:** lowercase imperative. First line is a one-sentence summary; body explains *why* and *what tradeoff*. See git log for examples.
7. **The `Lint summary` CI check is required to pass before merge** — it aggregates the skill linter results and posts a sticky comment on the PR.

## What Not To Contribute

- Hypothetical or theoretical vulnerabilities without real-world grounding
- Framework gap claims without specific evidence CVEs or demonstrated exploitation
- RWEP scores without documented factor breakdowns
- Skills that produce generic output ("assess your security posture") rather than specific analysis
- Anything that would make a passing compliance audit look like actual security when it isn't — we expose theater, we don't enable it
- Direct exploit code or PoC payloads — reference existence, describe technique, never ship functional exploits

## Contributing Without Writing Code

Domain experts — DPOs, GRC analysts, pentesters, incident responders, security researchers — can contribute without writing skill files. Open a **Skill Request** GitHub Issue with:

1. **The threat scenario** in plain language: what is the attack, who is affected, what does it do?
2. **Evidence**: one or more CVEs, ATLAS TTP IDs, or documented incidents
3. **The compliance gap**: which framework control should have caught it, and why didn't it?
4. **The jurisdictions or industries** most affected (EU financial sector, AU critical infrastructure, etc.)

Maintainers will convert approved requests into skill files. Contributors are credited in CHANGELOG.md and the skill's frontmatter. You can improve this repository with nothing more than threat intelligence and domain knowledge.

## Code of Conduct

The security community benefits from frank, specific, evidence-based analysis. Disagreements about gap severity or RWEP weighting should be resolved with evidence and citations, not authority or volume. Contributions that improve accuracy are welcome regardless of source.

Personal attacks, harassment, or conduct that discourages evidence-based disagreement are not acceptable.
