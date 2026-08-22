# Maintainers

Current maintainers of `blamejs/exceptd-skills`.

| Handle        | Areas                                                                 |
|---------------|-----------------------------------------------------------------------|
| @dotCooCoo    | All — threat intel curation, scoring, skill content, tooling, releases |

## Responsibilities

- Triage incoming issues within 7 days.
- Respond to security reports within the SLA in [SECURITY.md](SECURITY.md).
- Review PRs in your area within 14 days.
- Sign off and tag releases, refreshing `manifest-snapshot.json` and the
  `last_threat_review` date on every affected skill in the release commit.

## High-trust paths

`.github/CODEOWNERS` routes review to a maintainer for:

- `/data/` and `/data/*.json` — every intelligence catalog: CVE metadata and RWEP
  scores, ATLAS and ATT&CK techniques, per-control framework gaps, the
  multi-jurisdiction registry, zero-day lessons, exploit availability, the CWE
  and D3FEND taxonomies, RFC references, and the DLP controls. Each catalog pins
  its own upstream version in its `_meta` block; that block is the source of
  truth and is not restated here.
- `/manifest.json` — the skill registry and its Ed25519 signatures
- `/lib/verify.js`, `/lib/sign.js`, `/lib/scoring.js` — signing and scoring
- `/keys/` — the signing public key
- `/skills/` — all skill content, owned wholesale rather than per skill
- `/.github/` — workflows, templates, repository policy

Once a security-team handle exists (`@blamejs/security` or similar), add it
alongside `@dotCooCoo` on those lines so high-trust changes need two reviewers.

## Becoming a maintainer

The project is pre-1.0 and single-maintainer. The ladder opens once the skill
content stabilizes, targeting v1.0; until then the path is sustained
contribution through PRs. See [CONTRIBUTING.md](CONTRIBUTING.md).

## Stepping down

Open a PR removing yourself from this file and reassigning your CODEOWNERS
lines. Name a handover date in the description.

## Release runbook

`main` requires a pull request (PR), a signed commit, linear history, and eight
passing checks, and it enforces those on administrators too. Every release
therefore goes through a branch and a PR — pushing to `main` is rejected.

`scripts/release.js` drives that flow. Each subcommand is one phase, prints what
it did, and exits with a script-safe code, so a phase that fails part-way resumes
rather than repeating itself:

```bash
node scripts/release.js prepare   # bump + sign + indexes + snapshot + sbom + baseline
node scripts/release.js gates     # full suite + the predeploy gates
node scripts/release.js commit    # release branch + signed commit
node scripts/release.js push      # push branch + open PR
node scripts/release.js watch     # CI watch + unresolved review threads
node scripts/release.js merge     # admin squash-merge once CLEAN and threads are clear
node scripts/release.js tag       # guard, then signed tag
node scripts/release.js release   # watch release.yml + verify npm, global install, tarball signatures
node scripts/release.js status    # where the current branch sits in the flow
node scripts/release.js help      # full banner
```

Three things the orchestrator will not do for you:

- **Write the CHANGELOG entry.** `prepare` refuses unless `CHANGELOG.md` already
  carries a `## <next-version>` heading. Release notes are written by hand, terse
  and framed as behavior changes.
- **Choose the bump.** Patch is the default; `--minor` is deliberate and explicit.
- **Clear the review gates.** Unresolved PR review threads and open CodeQL alerts
  both block the merge, and both need a human decision — fix in code, or dismiss
  with a written justification.

`refresh-sbom` runs last inside `prepare`. It digests the shipped tree, so
running it before the indexes and the snapshot are rebuilt records hashes for
files the next two steps rewrite, and the currency gate then fails on ordering
rather than on anything actually wrong.

### One-time publish setup

Complete for the current package owner; recorded for whoever inherits it.

1. Claim the `@blamejs` npm scope (`npm login`, then `npm org create blamejs`).
2. Generate a granular npm automation token scoped to
   `@blamejs/exceptd-skills` (<https://docs.npmjs.com/creating-and-viewing-access-tokens>),
   expiring in 180 days or fewer. Rotate before expiry.
3. Add it to the repository's Actions secrets as `NPM_TOKEN`.
4. Enable 2FA-on-publish (`npm access set 2fa=automation @blamejs/exceptd-skills`).
   The OIDC token and 2FA-automation together are what produce signed provenance.

Publishing runs from `.github/workflows/release.yml` on a tag matching `v*.*.*`.
The `publish` job is bound to the `npm-publish` deployment environment, whose
branch policy accepts only those tags — a `workflow_dispatch` from a branch
reaches the workflow but not the publish step. `npm publish` from a workstation
fails its provenance check by design, because provenance requires the OIDC token
only Actions holds.

### Dry run

Actions → Release → Run workflow, with `tag` set to a real tag and `dry_run` set
to `true`. Predeploy and `npm pack --dry-run` run; publish and the GitHub Release
step are skipped.

### Rolling back

`npm unpublish` is restricted by registry policy to the first 72 hours and to
packages with no dependents, so it is not the path. Instead:

1. Cut a patch release with the issue corrected.
2. If the bad version has to be retracted,
   `npm deprecate '@blamejs/exceptd-skills@<bad-version>' 'reason — use <next-version> instead'`.
   Consumers see a warning; the tarball stays available, so anything pinned to it
   still builds.

### Verifying a published release

```bash
npm install @blamejs/exceptd-skills
npm audit signatures                      # provenance attestation
npx @blamejs/exceptd-skills verify        # Ed25519 skill signatures
node ./node_modules/@blamejs/exceptd-skills/lib/validate-vendor.js   # vendored subset hashes
```
