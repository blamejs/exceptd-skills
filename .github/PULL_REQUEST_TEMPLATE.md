<!--
  Pull request template for exceptd Security.
  The checklist below is the literal pre-ship checklist from AGENTS.md.
  Do not delete unchecked items — leave them unchecked so reviewers can see
  what was deliberately skipped and why.
-->

## Summary

<!-- One-paragraph description of what threat intel changed or what gap was
identified. Link any related issues (skill-request, cve-addition, etc.). -->

## Type of change

- [ ] New skill (`skills/<name>/skill.md`)
- [ ] New CVE entry in `data/cve-catalog.json` (+ zero-day learning loop)
- [ ] Framework gap update in `data/framework-control-gaps.json`
- [ ] ATLAS or external-data version bump
- [ ] Skill update / `last_threat_review` bump
- [ ] Library / orchestrator / tooling change
- [ ] Documentation only
- [ ] Other (describe):

## Pre-Ship Checklist

Mirrors the AGENTS.md "Pre-Ship Checklist" exactly. Every item must be
considered. If an item is N/A for this PR, check it and add a one-line
justification.

- [ ] All new CVEs have complete `data/cve-catalog.json` entries
- [ ] All new CVEs have `data/zeroday-lessons.json` entries
- [ ] All skill `data_deps` resolve to existing files
- [ ] All ATLAS refs are valid v5.1.0 IDs (current pinned version)
- [ ] All framework control IDs resolve in `data/framework-control-gaps.json`
- [ ] No skill body contains placeholder language (TODO, TBD, coming soon, placeholder)
- [ ] No skill uses CVSS as sole risk metric
- [ ] No skill implies a framework control is adequate without checking the gap analysis
- [ ] No skill ships without all 7 required body sections
- [ ] `manifest.json` updated with new/changed skills
- [ ] Skill hashes verified: `node lib/verify.js` passes
- [ ] CHANGELOG.md updated with what changed, what CVEs were added, what gaps were closed or opened
- [ ] No partial skills — if it can't be completed now, branch it, don't merge it
- [ ] Global coverage: EU + UK + AU + ISO 27001 present in all framework gap analyses

## Evidence

<!-- For CVE additions: NVD URL, CISA KEV status, RWEP factor breakdown.
     For framework gap additions: the specific control text being analyzed.
     For new skills: a worked example of the skill's output for a real
     scenario. (See CONTRIBUTING.md "PR Process".) -->

## Reviewer notes

<!-- Anything reviewers should look at first, known follow-ups, deferred work,
     etc. -->
