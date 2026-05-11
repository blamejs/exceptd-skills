# GitHub Repository Settings

The non-file repo configuration that lives in GitHub's UI rather than in
the repo itself. Run these commands once after `gh repo create
blamejs/exceptd-skills`, then re-run them after any maintainer-team
change. All commands assume you are authenticated as a maintainer with
admin rights on the repo.

The settings here match the posture of `blamejs/blamejs`. The same
required-check names, the same branch-protection shape, the same
security features. A repo in the `blamejs` org should look the same
from a downstream perspective.

---

## 1. Repository metadata

```bash
gh repo edit blamejs/exceptd-skills \
  --description "AI security skills grounded in mid-2026 threat reality, not stale framework documentation." \
  --homepage "https://exceptd.com" \
  --visibility public \
  --default-branch main \
  --enable-issues \
  --enable-discussions \
  --enable-wiki=false \
  --enable-projects=false \
  --enable-merge-commit=false \
  --enable-squash-merge=true \
  --enable-rebase-merge=false \
  --delete-branch-on-merge=true \
  --allow-update-branch=true
```

Why these choices:
- **Squash-only merge** matches blamejs. One commit per PR keeps `git log` readable; the PR description carries the why.
- **Delete branch on merge** keeps the branch list bounded.
- **Discussions on** is where non-bug Q&A goes (the `config.yml` for
  issue templates points users there).
- **Wiki off, projects off** — the project's documentation lives in the
  repo (`docs/`, `CONTEXT.md`, `ARCHITECTURE.md`); a separate GitHub
  Wiki would fork the source-of-truth.

---

## 2. Security features

```bash
# Enable secret scanning + push protection. Push protection blocks a
# push that contains a detectable secret, rather than only alerting
# after the secret is already on GitHub.
gh api -X PATCH /repos/blamejs/exceptd-skills \
  --field 'security_and_analysis[secret_scanning][status]=enabled' \
  --field 'security_and_analysis[secret_scanning_push_protection][status]=enabled'

# Enable Dependabot security updates (auto-PRs on vulnerable deps).
# The project is zero-dep by design, so the immediate value is the
# GitHub Actions ecosystem updates configured in .github/dependabot.yml.
gh api -X PATCH /repos/blamejs/exceptd-skills \
  --field 'security_and_analysis[dependabot_security_updates][status]=enabled'

# Enable private vulnerability reporting. Researchers click "Report a
# vulnerability" on the Security tab; the report lands in a private
# advisory thread, not a public issue. Backs SECURITY.md's disclosure
# process.
gh api -X PATCH /repos/blamejs/exceptd-skills \
  --field 'security_and_analysis[private_vulnerability_reporting][status]=enabled'
```

---

## 3. Branch protection on `main`

Required: every push to `main` goes through a PR; every PR passes the CI
gates; signed commits required; force-pushes blocked; one approval
minimum.

```bash
gh api -X PUT /repos/blamejs/exceptd-skills/branches/main/protection \
  --input - <<'JSON'
{
  "required_status_checks": {
    "strict": true,
    "checks": [
      { "context": "Verify skill signatures (Ed25519)" },
      { "context": "Tests (ubuntu-latest)" },
      { "context": "Tests (windows-latest)" },
      { "context": "Tests (macos-latest)" },
      { "context": "Data integrity (catalog + manifest snapshot)" },
      { "context": "Lint skill files" },
      { "context": "Secret scan (gitleaks)" },
      { "context": "Lint summary" },
      { "context": "Scorecard analysis" },
      { "context": "Threshold gate" }
    ]
  },
  "enforce_admins": false,
  "required_pull_request_reviews": {
    "dismiss_stale_reviews": true,
    "require_code_owner_reviews": true,
    "required_approving_review_count": 1,
    "require_last_push_approval": true
  },
  "restrictions": null,
  "required_linear_history": true,
  "allow_force_pushes": false,
  "allow_deletions": false,
  "block_creations": false,
  "required_conversation_resolution": true,
  "lock_branch": false,
  "allow_fork_syncing": true,
  "required_signatures": true
}
JSON
```

Why each setting:
- **`required_status_checks`** — the context names must match the job
  `name:` values in `.github/workflows/ci.yml` and `scorecard.yml`
  exactly. If you rename a job, update this list.
- **`strict: true`** — PRs must be up-to-date with `main` before merge.
  Catches "merged stale" regressions where two PRs each pass CI in
  isolation but conflict semantically.
- **`require_code_owner_reviews`** — CODEOWNERS-listed paths require a
  code-owner approval, not just any approval.
- **`enforce_admins: false`** — admins can bypass in genuine emergencies
  (rollbacks of a broken `main`), but `required_signatures: true` and
  the audit trail still apply. Set this to `true` once the project has
  more than one maintainer.
- **`required_signatures: true`** — every commit on `main` must be
  signed (GPG / SSH / GitHub web-edit). Aligns with the project's
  threat-intel-trust posture: the commit log must be verifiable.
- **`required_linear_history: true`** + **squash-only merge** = no
  merge commits, no rebase commits, just one signed commit per PR.

---

## 4. Tag protection

Protects release tags from being deleted or overwritten.

```bash
gh api -X POST /repos/blamejs/exceptd-skills/tags/protection \
  --field 'pattern=v*'
```

---

## 5. GitHub Actions permissions

```bash
# Restrict the GITHUB_TOKEN's default permissions to read-only.
# Per-job permissions in workflows elevate only where needed.
# This is the org-default in blamejs/blamejs already, so on a fresh
# blamejs-org repo the setting may already be applied — re-running
# is idempotent.
gh api -X PUT /repos/blamejs/exceptd-skills/actions/permissions/workflow \
  --field 'default_workflow_permissions=read' \
  --field 'can_approve_pull_request_reviews=false'

# Restrict which actions can run. The allowlist matches the SHA-pinned
# actions used in our workflows.
gh api -X PUT /repos/blamejs/exceptd-skills/actions/permissions \
  --field 'enabled=true' \
  --field 'allowed_actions=selected'

gh api -X PUT /repos/blamejs/exceptd-skills/actions/permissions/selected-actions \
  --field 'github_owned_allowed=true' \
  --field 'verified_allowed=true' \
  --field 'patterns_allowed[]=ossf/scorecard-action@*' \
  --field 'patterns_allowed[]=hadolint/hadolint-action@*'
```

---

## 6. Topics and discoverability

```bash
gh api -X PUT /repos/blamejs/exceptd-skills/topics \
  --field 'names[]=security' \
  --field 'names[]=ai-security' \
  --field 'names[]=mitre-atlas' \
  --field 'names[]=cve' \
  --field 'names[]=cisa-kev' \
  --field 'names[]=threat-intelligence' \
  --field 'names[]=compliance' \
  --field 'names[]=nist' \
  --field 'names[]=iso-27001' \
  --field 'names[]=nis2' \
  --field 'names[]=claude-code' \
  --field 'names[]=ai-skills'
```

---

## 7. Sponsor button

The `.github/FUNDING.yml` file already configures the Sponsor button
(GitHub Sponsors `@dotCooCoo` + Ko-fi `dotcoocoo`). No CLI action
needed; the button appears once the file is on `main`.

---

## 8. Verification

After applying all of the above, confirm:

```bash
gh repo view blamejs/exceptd-skills --json visibility,defaultBranchRef,hasIssuesEnabled,hasDiscussionsEnabled,securityAndAnalysis
gh api /repos/blamejs/exceptd-skills/branches/main/protection | jq '.required_status_checks.checks, .required_pull_request_reviews, .required_signatures'
gh api /repos/blamejs/exceptd-skills/tags/protection
```

The first push to `main` after this setup should land green if and only
if every required check passes. A red check there is the signal that the
gate is working as intended.

---

## 9. Re-running this document

These settings drift over time as GitHub adds features and the project's
posture matures. The expectation is:

- Re-run sections 1, 2, 5, 6 quarterly to refresh against any new
  GitHub defaults.
- Re-run section 3 whenever a CI job is renamed or a new required
  check is added in `.github/workflows/*.yml`.
- Re-run section 4 whenever the release tag scheme changes.

If the org adopts a "settings as code" tool (Probot Settings, Repository
Settings Configurator, etc.), migrate the above into a tracked
`.github/settings.yml` so the configuration becomes auditable in git
rather than living only as imperative `gh` invocations.
