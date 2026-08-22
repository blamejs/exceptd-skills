# Contributing

## What needs contributing

1. **New CVE entries** — a significant kernel, AI-platform or supply-chain CVE
   lands in `data/cve-catalog.json` and runs the zero-day learning loop.
2. **Framework gap updates** — when a framework publishes guidance that closes,
   or fails to close, a documented gap in
   `data/framework-control-gaps.json`.
3. **New skills** — an attack class or compliance domain the shipped skills do
   not cover.
4. **Upstream version bumps** — when MITRE publishes a new ATLAS, ATT&CK, CWE or
   D3FEND release, audit the technique IDs and descriptions across every skill.
5. **Global framework additions** — new jurisdictions, or changes to the ones
   already in `data/global-frameworks.json`.

## The quality bar

A senior security practitioner can act on the output. Not a generic checklist —
specific, current, and decidable.

- A CVE reference carries real exploit-availability data. "A PoC may exist" is
  not data.
- A framework gap says why *this* control fails against *this* technique, not
  that the control is insufficient.
- An RWEP score is justified by its factor breakdown, not asserted.
- Remediation guidance survives contact with operations: patch windows, live
  systems, production reboots, infrastructure that no longer exists by morning.
- A compliance-theater check is executable. "Ask the auditor whether X is
  covered" is not. "Run `uname -r`, cross-reference the patched kernel version
  for CVE-2026-31431, and if it is unpatched the patch-management control is
  theater" is.

## Adding a CVE

1. Confirm the NVD entry exists and carries a CVSS score.
2. Check CISA KEV: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
3. Establish whether a public exploit exists. Describe what is public in plain
   language; do not link exploit code.
4. Record AI discovery and AI-assisted weaponization where they apply.
5. Add the entry to `data/cve-catalog.json` with every required field. A partial
   entry fails schema validation.
6. Add the matching entry to `data/zeroday-lessons.json`.
7. Add the exploit status to `data/exploit-availability.json` with a
   `last_verified` date.
8. Compute RWEP with the formula in `lib/scoring.js` and record the factor
   breakdown. The factors must sum to the score.
9. Bump `last_threat_review` on every skill covering the affected technology.

## Adding a framework gap

1. Name the control (`NIST-800-53-SI-2`, `ISO-27001-2022-A.8.8`).
2. Record what the control was designed for, citing the framework version and
   the original context.
3. Name the CVE or technique that exposes the gap. Evidence, not hypothesis.
4. Say what a control that actually closed it would require.
5. Add it to `data/framework-control-gaps.json` with `status: "open"` and an
   `opened_date`.
6. Add the control ID to `framework_gaps` on every skill that cites it.

When an update closes a gap, set `status: "closed"` with the reference. Do not
delete the entry — the record of how long the framework lagged is itself data.

## Adding a skill

1. Create `skills/<skill-name>/skill.md`.
2. Fill in every frontmatter field. `data_deps`, `atlas_refs` and
   `framework_gaps` are empty only when genuinely inapplicable, and then with a
   comment saying why.
3. Write every required body section — [ARCHITECTURE.md](ARCHITECTURE.md) lists
   them.
4. Confirm every CVE you cite is in `data/cve-catalog.json`, every technique ID
   resolves against `data/atlas-ttps.json` or `data/attack-techniques.json`, and
   every control ID against `data/framework-control-gaps.json`.
5. Register the skill in `manifest.json`.
6. Add a CHANGELOG entry.

## Opening a pull request

1. **Open an issue first** for anything non-trivial. Design discussion catches a
   scope problem before the code exists. A typo, a doc tweak or a single field on
   one CVE can skip it.
2. **Branch off `main`.** The name does not matter; merges are squashed.
3. **One concern per PR.** A new skill with its CVEs, its gap mappings and its
   manifest registration is one PR. A new skill plus an unrelated CVE is two.
4. **Run the gates before you push** — the same ones CI runs, none skipped:

   ```bash
   npm run verify                              # Ed25519 signature on every skill
   npm test                                    # the node:test suite
   npm run lint                                # frontmatter, body sections, cross-refs
   npm run diff-coverage                       # every changed verb, flag, export or indicator has a test
   node lib/validate-cve-catalog.js            # CVE schema + zero-day learning coverage
   node scripts/check-manifest-snapshot.js     # breaking-surface detector
   ```

   If the change intentionally narrows the public surface — a removed skill,
   trigger keyword or data dependency — refresh the baseline and commit it in the
   same PR:

   ```bash
   node scripts/refresh-manifest-snapshot.js
   git add manifest-snapshot.json
   ```

   On Windows or macOS, the Docker harness reproduces CI's Linux environment,
   which is where OS-specific regressions surface:

   ```bash
   npm run test:docker          # predeploy in a clean Linux container
   npm run test:docker:fresh    # also wipes signing state and re-bootstraps
   ```

   Docker is optional; `npm run predeploy` on the host is the primary gate. See
   [docker/README.md](docker/README.md).

5. **Say what the reviewer needs.** For a CVE: the NVD URL, the KEV status, and
   your RWEP factor breakdown. For a framework gap: the control text you
   analyzed and why it falls short. For a skill: a worked example of its output
   on a real scenario.
6. **Commit messages** are lowercase imperative — one summary line, then a body
   covering why and what it traded off.
7. **`Lint summary` must pass before merge.** It aggregates the skill linter and
   posts a sticky comment on the PR.

Maintainers cut releases; the runbook is in [MAINTAINERS.md](MAINTAINERS.md).

## What not to contribute

- Theoretical vulnerabilities with no real-world grounding
- Framework gap claims with no evidence CVE and no demonstrated exploitation
- RWEP scores without a factor breakdown
- Skills that emit generic output — "assess your security posture" is not
  analysis
- Anything that makes a passing audit look like security when it is not
- Exploit code or working payloads. Reference that an exploit exists, describe
  the technique, ship neither.

## Contributing without writing skill files

Domain experts — data protection officers, GRC analysts, pentesters, incident
responders, researchers — can contribute the analysis and leave the file format
to maintainers. Open a **Skill Request** issue with:

1. **The scenario**, in plain language: what the attack is, who it reaches, what
   it achieves.
2. **The evidence**: CVEs, technique IDs, or documented incidents.
3. **The compliance gap**: which control should have caught it, and why it did
   not.
4. **Who it lands on**: the jurisdictions or sectors most exposed, such as the
   EU financial sector or Australian critical infrastructure.

Maintainers turn accepted requests into skill files. Contributors are credited in
`CHANGELOG.md` and in the skill's frontmatter.

## Conduct

[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) is the binding policy. One norm specific
to this project sits underneath it: disagreements about gap severity or RWEP
weighting are settled with evidence and citations, not seniority or volume. A
contribution that improves accuracy is welcome wherever it comes from.
