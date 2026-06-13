# Evidence collectors

Companion scripts that turn a playbook's `phases.look.artifacts[]` declarations into an actual evidence submission, so an operator (or a CI workflow) can produce a real verdict without a human-in-loop AI translating prose into filesystem walks every time.

## Interface contract

Each collector lives at `lib/collectors/<playbook-id>.js` and exports:

```js
module.exports = {
  // Playbook id this collector implements. Must match the file name.
  playbook_id: "<playbook-id>",

  // Pure synchronous function. Walks the filesystem, runs child_process
  // commands as needed, returns the submission JSON in the same shape
  // `exceptd run --evidence -` accepts.
  collect({ cwd, env, args }) {
    return {
      precondition_checks: { /* "<precondition-id>": true|false */ },
      artifacts: {
        /* "<artifact-id>": { value: <captured text>, captured: true|false, reason?: "<why captured=false>" } */
      },
      signal_overrides: { /* "<indicator-id>": "hit"|"miss"|"inconclusive" */ },
      collector_meta: {
        // Self-describing metadata so the operator knows WHAT the
        // collector did and which version produced this evidence.
        collector_id: "<playbook-id>",
        collector_version: "<semver-or-date>",
        platform: process.platform,
        captured_at: new Date().toISOString(),
        cwd: cwd,
      },
      // Collector-level errors that did NOT prevent producing a
      // submission (e.g. "couldn't read /proc/version on Windows").
      // Each entry is { artifact_id?, kind, reason }.
      collector_errors: [],
    };
  },
};
```

### Rules

- **Stdlib + child_process only.** No npm dependencies beyond what's already vendored. The point is to ship inside the npm tarball and run anywhere Node runs.
- **No network calls.** Evidence collection is a local snapshot. Refreshing upstream data lives in `exceptd refresh`.
- **Synchronous.** Matches the rest of the bin/lib code shape. Async machinery would force colored functions through the runner.
- **Errors don't throw.** Catch every recoverable error and add an entry to `collector_errors[]` with a human-readable `reason`. The CLI wrapper turns `collector_errors[]` into runtime warnings on the run output.
- **Cwd is the only entry point.** Default `cwd` is `process.cwd()`. The operator can override via `exceptd collect <pb> --cwd <path>`.
- **Walk caps.** Filesystem walks default to depth 6 + the standard exclusion set (`node_modules/`, `.git/objects/`, `dist/`, `build/`, `.venv/`, `__pycache__/`). Override the depth + exclusions via the playbook's `look.artifacts[].source` declaration when it says so.
- **Don't leak secrets.** When an artifact captures file *contents* (e.g. the secret-regex-scan output), redact the matched literal in `value` — keep file path + offset + classifier, drop the actual key material. The point of the audit is finding the leak; persisting the leak in the attestation makes the attestation itself a leak vector.
- **Indicators win over artifacts.** When the collector can determine an indicator verdict deterministically (e.g. a regex match means `aws-access-key-id: hit`), set the `signal_overrides[<indicator>]` rather than relying on the runner to re-evaluate the artifact text. Faster + more honest.

## CLI

```bash
exceptd collect <playbook>                  # walk cwd, emit submission JSON to stdout
exceptd collect <playbook> --cwd <path>     # collect against a different repo / host
exceptd collect <playbook> --pretty         # indented JSON for the dev loop
exceptd collect <playbook> | exceptd run <playbook> --evidence -   # full loop
```

Exit codes:

- `0` — submission emitted successfully (operator should check `collector_errors[]` for partial-evidence warnings)
- `1` — failure: either no collector exists for the playbook id (the AI-evidence path remains) **or** the collector threw an unhandled exception (file a bug). Both go through the shared error path, so both exit `1`; the JSON envelope on stderr distinguishes them — `type: "collector_not_found"` for the missing-collector case, an `"threw an unhandled exception"` message plus a `stack` for the crash case.

Run `exceptd doctor --exit-codes` for the full exit-code map. Code `2` is reserved for the CI escalation gate (`detected` classification), not used by `collect`.

## When to write a collector

See `AGENTS.md § Evidence collection roadmap` for the policy. Summary: code-scope and system-scope playbooks with deterministic detect shapes are good candidates; judgement-shaped playbooks (`framework`, `ransomware`, incident playbooks) stay AI-driven.

## Reference collectors

- [`secrets.js`](secrets.js) — filesystem walk + regex against the catalogued secret patterns + permission-posture stat
- [`kernel.js`](kernel.js) — `uname -s` / `uname -r` for linux-platform + kernel-release detection
- [`sbom.js`](sbom.js) — lockfile presence + ecosystem fingerprint
