---
name: Feature request
about: Propose a new orchestrator command, tooling capability, or framework integration
title: ''
labels: enhancement
assignees: ''
---

<!--
For proposing a NEW SKILL (the most common contribution path), use the
"Skill request" template instead — it has the threat-scenario + framework-gap
fields tailored to that flow.

For proposing a NEW CVE for the catalog, use the "CVE addition" template.

This template is for non-skill features: new orchestrator subcommands, new
validators, new report formats, new scoring inputs, etc.

Per AGENTS.md hard rule #11 (no-MVP ban): every feature lands complete, not
"minimum viable with key parts deferred." File the issue first to discuss
scope before opening a PR; it saves a round of rework.
-->

## Problem

<!-- What gap in current capability are you solving? Concrete scenario preferred over abstract. -->

## Proposed surface

<!-- What does the new command / function / output look like? -->

```bash
# Imagined CLI invocation
npm run <new-script>
# or
node orchestrator/index.js <new-subcommand> --flag value
```

```js
// Or imagined library API
const { newFn } = require('./lib/<file>');
const result = newFn(input);
```

## Initial-release scope

What's IN the first shipped version:
-

What's explicitly OUT (and why each "out" is a complete decision, not a deferred bullet):
-

## Failure modes

<!--
- Bad input to a CLI / library entry point → throw with a clear error code so
  the operator sees the typo immediately.
- Network failures in a validator → return `unreachable`, never throw; CI in
  airgapped runners must still pass.
- Drift between local catalog and upstream feed → flag for human review, exit
  non-zero only when `--no-fail` is absent.
-->

- Bad CLI args → throw with code
- Network unreachable → return `unreachable`, never throw
- Drift detected → flag for human review

## Threat-intel implications

<!-- Does this change how RWEP is scored, how CVEs are validated, or how skills are dispatched? -->

- [ ] No change to scoring / dispatch / verification
- [ ] Changes RWEP factor weights (which factor? what's the rationale?)
- [ ] Changes the skill verification path (Ed25519 signing / loading)
- [ ] Adds a new external source (which? what's the rate-limit / offline-mode plan?)
- [ ] Adds new framework coverage (which? remember global-first rule: EU/UK/AU/ISO must accompany NIST)

## Operator-facing surface

- [ ] README quick-start updated
- [ ] AGENTS.md rule or pre-ship checklist updated
- [ ] New `npm run` script added
- [ ] CI workflow updated
- [ ] None — internal-only

## Alternatives considered

<!-- What did you rule out and why. Saves the reviewer asking. -->

## Additional context
