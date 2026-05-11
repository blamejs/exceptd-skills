---
name: Bug report
about: Report a defect in a skill, the orchestrator, the scoring library, or the tooling
title: ''
labels: bug
assignees: ''
---

<!--
Security bug? Don't file here — see SECURITY.md for the private disclosure
process. Public issues are for non-security defects.

Threat-intel correction that itself discloses sensitive detail? Use the
"Threat-intel correction" link on the new-issue chooser, not this template.

Before filing: search existing issues to avoid duplicates.
-->

## What happened

<!-- One or two sentences. What did exceptd-skills do that you didn't expect. -->

## What you expected

## How to reproduce

<!-- Minimal repro. Exact command + flags preferred over prose. -->

```bash
npm run <script>
# or
node orchestrator/index.js <subcommand>
# or
node lib/<file>.js
```

If the bug is in a skill output, paste the prompt or invocation that triggered it.

## Environment

- exceptd-skills version: `v0.X.Y` (or `main <sha>`)
- Node.js version: `node --version`
- OS: `uname -a` or Windows version
- Affected skill (if any): `skills/<name>/skill.md`
- Affected data file (if any): `data/<name>.json`

## Logs / output

<details><summary>Click to expand</summary>

```
paste relevant log lines or error stack traces here
```

</details>

## Threat-intel grounding (when relevant)

<!--
If the bug touches the RWEP score, a CVE entry, an ATLAS TTP mapping, or a
framework gap, cite the source(s) so the maintainer can cross-check without
re-doing the research:
-->

- NVD link (if CVE): https://nvd.nist.gov/vuln/detail/CVE-YYYY-NNNNN
- CISA KEV status (if relevant):
- ATLAS TTP ID (if relevant): AML.TXXXX
- Framework control ID (if relevant):

## What you've already tried

<!-- Helpful for ruling out duplicates / known interactions. -->

## Additional context
