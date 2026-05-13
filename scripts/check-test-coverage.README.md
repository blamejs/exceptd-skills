# Diff-coverage analyzer

`scripts/check-test-coverage.js` compares the changed surface in a diff
against the `tests/` tree and reports any surface change that has no
matching test reference. Zero dependencies, Node 24 stdlib only, runs
identically on Windows + Linux.

## Usage

```bash
# Default: HEAD vs origin/main, human output.
node scripts/check-test-coverage.js

# Staged changes only (pre-commit shape).
node scripts/check-test-coverage.js --staged

# Compare HEAD vs a custom base.
node scripts/check-test-coverage.js --base v0.12.6

# Machine-readable.
node scripts/check-test-coverage.js --json

# Surface findings without failing the gate.
node scripts/check-test-coverage.js --warn-only
```

## What it covers

| Source file                       | Surface extracted                                       |
| --------------------------------- | ------------------------------------------------------- |
| `bin/exceptd.js`                  | CLI verbs (`COMMANDS` map + `PLAYBOOK_VERBS` set), flags |
| `lib/*.js`, `orchestrator/*.js`, `scripts/*.js` | `module.exports = { ... }` identifiers       |
| `data/playbooks/*.json`           | `phases.detect.indicators[].id`, `phases.look.artifacts[].id` |
| `data/cve-catalog.json`           | CVE entries whose `iocs` field added / removed / changed |

For each added / removed / modified surface, the analyzer searches every
`*.js` and `*.json` file under `tests/` for a reference to the surface
identifier (quoted literal for verbs / playbook IDs, raw substring for
flags + CVE IDs, `require()` site plus identifier reference for lib
exports). Missing references become findings.

## Allowlist

Changes in these locations are accepted without a covering test:

- `*.md` outside `data/`, `.gitignore`, `.npmrc`, `.editorconfig`
- `CHANGELOG.md` / `README.md` / `CONTRIBUTING.md` / `SECURITY.md` / `LICENSE` / `NOTICE` / `CODE_OF_CONDUCT.md` / `AGENTS.md` / `CLAUDE.md`
- Whitespace-only diffs (detected via `git diff --ignore-all-space --ignore-blank-lines`)
- Any file under `tests/` (no test-of-tests recursion)
- `skills/<name>/skill.md` (signature gate already covers content integrity)
- `.github/workflows/*.yml` — surfaced as **manual review required** rather than as a finding, because workflow steps don't pattern-match cleanly to test code paths

## Integration: predeploy gate

Append this entry to `GATES` in `scripts/predeploy.js` (placement: after
the existing tarball-verify gate, before the e2e-scenarios gate or at the
end — the gates are independent):

```js
  {
    name: "Diff coverage (no-MVP: feature changes require test coverage)",
    command: process.execPath,
    args: [path.join(ROOT, "scripts", "check-test-coverage.js")],
    ciJobName: "Diff coverage",
  },
```

The gate passes when no findings are produced and fails with the
analyzer's human-readable output when findings exist. Use `--warn-only`
during the rollout window if you want the gate informational before it
becomes blocking.

A matching CI job needs to land in `.github/workflows/ci.yml` so
`tests/predeploy.test.js` (which asserts the local runner mirrors the CI
workflow) stays green:

```yaml
  diff-coverage:
    name: Diff coverage
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }
      - uses: actions/setup-node@v4
        with: { node-version: '24' }
      - run: node scripts/check-test-coverage.js --base origin/main
```

## Integration: pre-commit hook

`scripts/hooks/pre-commit.sh` invokes the analyzer in `--staged` mode.
Not installed by default. Opt in with:

```bash
git config core.hooksPath scripts/hooks
chmod +x scripts/hooks/pre-commit.sh   # Linux only
```

Bypass for a single commit (acceptable when the covering test will land
in a follow-up before push):

```bash
git commit --no-verify
```

## AGENTS.md addition — Hard Rule

Drop-in markdown for the next available Hard Rule number (currently
adding as **Rule #15** if the existing list ends at #14):

```markdown
### Rule #15 — Test coverage on every diff

Every feature change — added, removed, or modified — must land with a
matching test reference in the same PR. The shapes the gate enforces:

| Change                                           | Required test reference                                 |
| ------------------------------------------------ | ------------------------------------------------------- |
| New CLI verb in `bin/exceptd.js`                 | Quoted verb literal in a `tests/*.test.js` file         |
| New CLI flag                                     | Flag literal (e.g. `--my-flag`) somewhere in `tests/`   |
| New / removed `module.exports` identifier        | `require('…/<lib>')` + identifier reference             |
| New `phases.detect.indicators[].id` in a playbook | Quoted ID literal in `tests/e2e-scenarios/*/expect.json` or any `tests/*.test.js` |
| New / changed `iocs` field on a CVE entry        | CVE ID + the word `iocs` in the same test file          |

Mechanical enforcement lives in `scripts/check-test-coverage.js` and runs
as the 15th gate of `npm run predeploy`. Whitespace-only diffs, docs,
workflow YAML, and skill body changes are allowlisted (skill bodies are
covered by the Ed25519 signature gate).

The gate is blocking. `--warn-only` exists for the rollout window only;
once the gate is wired into CI, do not bypass with `--no-verify` or
`--warn-only` — add the covering test first.

This rule is additive to **Hard Rule #11 (No-MVP ban)**: shipping a new
playbook indicator or CLI surface without a regression test is the
same shape of incomplete-feature ship that #11 forbids.
```

## Smoke results against the current repo

Run from repo root:

```bash
node scripts/check-test-coverage.js
```

Expected on a clean working tree at `v0.12.7`: zero changed files, zero
findings, exit 0.
