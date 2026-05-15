# Maintainers

Current maintainers of `blamejs/exceptd-skills`.

| Handle        | Areas                                                                 |
|---------------|-----------------------------------------------------------------------|
| @dotCooCoo    | All — threat intel curation, scoring, skill content, tooling, releases |

## Maintainer responsibilities

Per CONTRIBUTING.md:

- Triage incoming issues within 7 days.
- Respond to security reports per the SLA in [SECURITY.md](SECURITY.md):
  - **Critical** (data integrity attack on CVE catalog, RWEP score manipulation): first response 24h, triage 72h, fix 7d.
  - **High** (skill instruction that produces incorrect remediation for CISA KEV): 72h / 7d / 14d.
  - **Medium** (incorrect framework gap mapping, wrong control ID): 7d / 14d / 30d.
  - **Low** (missing data, incomplete entries): 14d / 30d / next minor.
- Review PRs in your domain area within 14 days.
- Sign-off + tag releases; refresh `manifest-snapshot.json` and `last_threat_review` dates on affected skills as part of the release commit.

## High-trust paths

Changes to the following paths require maintainer review per `.github/CODEOWNERS`:

- `/data/` and `/data/*.json` — all intelligence catalogs, including:
  - `/data/cve-catalog.json` — CVE metadata and RWEP scores
  - `/data/atlas-ttps.json` — MITRE ATLAS v5.1.0 TTPs
  - `/data/framework-control-gaps.json` — per-control gap analysis
  - `/data/global-frameworks.json` — multi-jurisdiction framework registry
  - `/data/zeroday-lessons.json` — zero-day learning loop entries
  - `/data/exploit-availability.json` — PoC, KEV, AI-acceleration, live-patch status
  - `/data/cwe-catalog.json` — CWE v4.17 weakness taxonomy
  - `/data/d3fend-catalog.json` — MITRE D3FEND v1.0.0 defensive techniques
  - `/data/rfc-references.json` — IETF RFC / Internet-Draft references
  - `/data/dlp-controls.json` — DLP control catalog
- `/manifest.json` — skill registry + Ed25519 signatures
- `/lib/verify.js`, `/lib/sign.js`, `/lib/scoring.js` — signing and RWEP scoring code
- `/keys/` — signing public key
- `/skills/` — all skill content. High-trust skill paths:
  - `/skills/attack-surface-pentest/`
  - `/skills/fuzz-testing-strategy/`
  - `/skills/dlp-gap-analysis/`
  - `/skills/supply-chain-integrity/`
  - `/skills/defensive-countermeasure-mapping/`
  - `/skills/identity-assurance/`
  - `/skills/ot-ics-security/`
  - `/skills/coordinated-vuln-disclosure/`
  - `/skills/threat-modeling-methodology/`
- `/.github/` — workflows, templates, repo policy

When a security-team GitHub handle is created (e.g. `@blamejs/security`), add it as an additional owner on the lines above so two reviewers are required for high-trust changes.

## Becoming a maintainer

The project is pre-1.0 and currently single-maintainer. The maintainer ladder will open once the skill content stabilizes (target: v1.0). Until then, sustained high-quality contributions through PRs are the path. See CONTRIBUTING.md.

## Stepping down

A maintainer stepping down opens a PR removing themselves from this file and reassigning their CODEOWNERS lines. Notify other maintainers in the PR description with a target handover date.

## Release runbook (npm publish)

The project publishes `@blamejs/exceptd-skills` to npm with provenance attestation on every tag push that matches `v*.*.*`. The release flow is automated by `.github/workflows/release.yml`.

### One-time setup (already complete for the current package owner)

1. Claim the `@blamejs` npm scope (`npm login` + `npm org create blamejs`).
2. Generate a granular npm automation token scoped to the `@blamejs/exceptd-skills` package: <https://docs.npmjs.com/creating-and-viewing-access-tokens>. Set expiry to ≤180 days; rotate before expiry.
3. Add the token to GitHub repo secrets as `NPM_TOKEN` (Settings → Secrets and variables → Actions → New repository secret).
4. Enable 2FA-on-publish for the package (`npm access set 2fa=automation @blamejs/exceptd-skills`). The OIDC token + 2FA-automation combination is what produces signed provenance.

### Cutting a release

1. Bump `package.json` version + `manifest.json` version to the new semver (e.g. `0.9.0`).
2. Add a `## 0.9.0 — YYYY-MM-DD` section at the top of `CHANGELOG.md`.
3. Re-sign skills + refresh derived artifacts:
   ```
   node lib/sign.js sign-all
   node scripts/refresh-manifest-snapshot.js
   node scripts/refresh-sbom.js
   node scripts/build-indexes.js
   ```
4. Run the full predeploy gate (13 gates as of v0.9.0):
   ```
   npm run predeploy
   ```
5. Commit + push to `main`.
6. Tag the release:
   ```
   git tag -a v0.9.0 -m "v0.9.0"
   git push origin v0.9.0
   ```
7. The `Release` workflow fires automatically. It will:
   - Verify the tag matches `package.json` version
   - Run `npm run bootstrap` (verify-only path)
   - Run `npm run predeploy` (all 13 gates)
   - `npm pack --dry-run --json` and surface the tarball preview
   - `npm publish --access public --provenance` using `NPM_TOKEN` + GitHub OIDC
   - Create a GitHub Release with the CHANGELOG section as the body

### Dry-run a release

Use `workflow_dispatch` with `dry_run: true`:

- Go to Actions → Release → "Run workflow"
- Set `tag` to a real tag (e.g. `v0.9.0`)
- Set `dry_run` to `true`
- The workflow runs predeploy + `npm pack --dry-run` but skips `npm publish` and the GitHub Release step.

### Rolling back a published release

`npm unpublish` is restricted by registry policy (only within 72h, only if no dependents). The reliable rollback path is:

1. Cut a `<version>-fix.1` patch release with the issue corrected.
2. If the bad version must be retracted, `npm deprecate '@blamejs/exceptd-skills@<bad-version>' 'reason — use <next-version> instead'` — published consumers see a warning but the tarball stays available for reproducibility.

### Verifying a published release

A downstream consumer can verify:

```
npm install @blamejs/exceptd-skills
# inspect the provenance attestation
npm audit signatures
# verify Ed25519 skill signatures
npx @blamejs/exceptd-skills verify
# verify vendored blamejs subset hashes
npx @blamejs/exceptd-skills --help    # if installed locally, just `node ./node_modules/@blamejs/exceptd-skills/lib/validate-vendor.js`
```

`npm audit signatures` cross-references the publish provenance attestation against the GitHub OIDC issuer and the workflow run that produced the tarball.
