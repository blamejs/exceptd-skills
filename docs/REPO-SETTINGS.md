# GitHub Repository Settings

The non-file repo configuration that lives in GitHub's UI rather than in
the repo itself. Run these commands once after `gh repo create
blamejs/exceptd-skills`, then re-run them after any maintainer-team
change. All commands assume you are authenticated as a maintainer with
admin rights on the repo.

The settings here match the posture of `blamejs/blamejs`: the same
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
gh api -X PATCH repos/blamejs/exceptd-skills \
  --field 'security_and_analysis[secret_scanning][status]=enabled' \
  --field 'security_and_analysis[secret_scanning_push_protection][status]=enabled'

# Enable Dependabot security updates (auto-PRs on vulnerable deps).
# The project is zero-dep by design, so the immediate value is the
# GitHub Actions ecosystem updates configured in .github/dependabot.yml.
gh api -X PATCH repos/blamejs/exceptd-skills \
  --field 'security_and_analysis[dependabot_security_updates][status]=enabled'

# Enable private vulnerability reporting. Researchers click "Report a
# vulnerability" on the Security tab; the report lands in a private
# advisory thread, not a public issue. Backs SECURITY.md's disclosure
# process.
gh api -X PATCH repos/blamejs/exceptd-skills \
  --field 'security_and_analysis[private_vulnerability_reporting][status]=enabled'
```

---

## 3. Branch protection on `main`

Required: every push to `main` goes through a PR; every PR passes the CI
gates; signed commits required; force-pushes blocked; every conversation
resolved.

The approval count is **0**, not 1. On a single-maintainer project an
approval minimum cannot be satisfied — the only person who could approve
is the author — so requiring one locks `main` against its own maintainer.
The protection that does the work here is the check set plus
`enforce_admins`, which applies to the maintainer too. Raise the count to
1 and re-enable `require_code_owner_reviews` and
`require_last_push_approval` at the point a second maintainer joins;
`dismiss_stale_reviews` is already on so that flip needs no other change.

```bash
gh api -X PUT repos/blamejs/exceptd-skills/branches/main/protection \
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
      { "context": "Lint summary" }
    ]
  },
  "enforce_admins": true,
  "required_pull_request_reviews": {
    "dismiss_stale_reviews": true,
    "require_code_owner_reviews": false,
    "required_approving_review_count": 0,
    "require_last_push_approval": false
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
- **`require_code_owner_reviews: false`** — off while the project has one
  maintainer, for the same reason the approval count is 0. Turn it on
  with the approval count when a second maintainer joins, at which point
  CODEOWNERS-listed paths start requiring a code-owner approval rather
  than any approval.
- **`enforce_admins: true`** — the rules apply to admins as well, so the
  maintainer cannot bypass the check set on their own repository. This is
  what carries the weight given the approval count is 0. An emergency
  rollback means turning it off deliberately and turning it back on,
  which leaves a trail, rather than a standing exemption that does not.
- **`required_signatures: true`** — every commit on `main` must be
  signed (GPG / SSH / GitHub web-edit). Aligns with the project's
  threat-intel-trust posture: the commit log must be verifiable.
- **`required_linear_history: true`** + **squash-only merge** = no
  merge commits, no rebase commits, just one signed commit per PR.

---

## 4. Tag protection

Protects release tags from being deleted or overwritten. A published version
is a fixed point: if a published tag can be moved, every consumer who pinned it
is holding a reference that no longer means what it meant. Bumping the version
is the only way to correct a bad release.

This is a **ruleset**, not the old per-repo tag-protection API — that endpoint
is deprecated and now returns 404, so the command previously documented here
would fail without saying why.

```bash
gh api -X POST repos/blamejs/exceptd-skills/rulesets \
  --input - <<'JSON'
{
  "name": "Protect release tags (v*)",
  "target": "tag",
  "enforcement": "active",
  "conditions": { "ref_name": { "include": ["refs/tags/v*"], "exclude": [] } },
  "rules": [
    { "type": "deletion" },
    { "type": "non_fast_forward" },
    { "type": "update" }
  ],
  "bypass_actors": []
}
JSON
```

`bypass_actors` is empty on purpose: an admin exemption would make the
protection advisory. Verify with
`gh api repos/:owner/:repo/rulesets --jq '.[] | select(.target=="tag")'`.

---

## 5. GitHub Actions permissions

```bash
# Restrict the GITHUB_TOKEN's default permissions to read-only.
# Per-job permissions in workflows elevate only where needed.
# This is the org-default in blamejs/blamejs already, so on a fresh
# blamejs-org repo the setting may already be applied — re-running
# is idempotent.
gh api -X PUT repos/blamejs/exceptd-skills/actions/permissions/workflow \
  --field 'default_workflow_permissions=read' \
  --field 'can_approve_pull_request_reviews=false'

# Restrict which actions can run. The allowlist matches the SHA-pinned
# actions used in our workflows.
gh api -X PUT repos/blamejs/exceptd-skills/actions/permissions \
  --field 'enabled=true' \
  --field 'allowed_actions=selected'

gh api -X PUT repos/blamejs/exceptd-skills/actions/permissions/selected-actions \
  --field 'github_owned_allowed=true' \
  --field 'verified_allowed=false' \
  --field 'patterns_allowed[]=ossf/scorecard-action@*' \
  --field 'patterns_allowed[]=softprops/action-gh-release@*' \
  --field 'patterns_allowed[]=peter-evans/create-pull-request@*'
```

The pattern list is a replace, not an append, so it has to name every
third-party action in use or the next run of the workflow that needs the
missing one fails on a permissions error rather than on anything it did.
`softprops/action-gh-release` publishes the GitHub Release from `release.yml`
and `peter-evans/create-pull-request` opens the nightly data PR from
`refresh.yml`; both are required. `hadolint/hadolint-action` is not in the
allowlist because no workflow uses it.

`verified_allowed=false` keeps the list to actions that were chosen
deliberately. Admitting everything in the Marketplace verified-creator
programme would widen the set to publishers this project has never reviewed,
which is the opposite of what an allowlist is for. `github_owned_allowed`
covers `actions/*` and `github/codeql-action/*`, so those need no pattern.

Check the live list before editing it:

```bash
gh api repos/:owner/:repo/actions/permissions/selected-actions
```

---

## 6. Topics and discoverability

```bash
gh api -X PUT repos/blamejs/exceptd-skills/topics \
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
gh api repos/blamejs/exceptd-skills/branches/main/protection | jq '.required_status_checks.contexts, .required_pull_request_reviews, .required_signatures, .enforce_admins'
gh api repos/blamejs/exceptd-skills/rulesets --jq '.[] | select(.target=="tag")'
gh api repos/blamejs/exceptd-skills/actions/permissions/selected-actions
```

Read the protection back as `.required_status_checks.contexts`. The write
side takes `checks` (context plus an optional app id); the read side returns
`contexts`, so querying the field you sent gets you `null` and an apparently
empty required-check list.

The first push to `main` after this setup should land green if and only
if every required check passes. A red check there is the signal that the
gate is working as intended.

---

## 9. Keeping these settings current

These settings drift over time as GitHub adds features and the project's
posture matures, and the drift is silent: nothing fails until someone
re-applies this file and finds it describes a repository that no longer
exists. Read the live value before editing any section — every one of them
has a matching read command in section 8.

- Re-run sections 1, 2, 5, 6 quarterly to refresh against any new
  GitHub defaults.
- Re-run section 3 whenever a CI job is renamed or a new required
  check is added in `.github/workflows/*.yml`.
- Re-run section 4 whenever the release tag scheme changes.

Two things about the commands themselves. The endpoints are written without
a leading slash — `gh api repos/...`, not `gh api /repos/...` — because a
POSIX-style shell on Windows rewrites a leading-slash argument into a
filesystem path, and `gh` then reports an invalid endpoint under the Git
installation directory. The no-slash form behaves identically everywhere.
And section 5's `patterns_allowed` is a replace rather than an append, so it
has to name every third-party action currently in use; dropping one there
does not fail until the workflow that needs it next runs.

If the org adopts a "settings as code" tool (Probot Settings, Repository
Settings Configurator, etc.), migrate the above into a tracked
`.github/settings.yml` so the configuration becomes auditable in git
rather than living only as imperative `gh` invocations.
