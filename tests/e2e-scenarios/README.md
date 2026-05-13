# exceptd-skills end-to-end scenarios

Internal test fixtures, not shipped. Excluded from the publish tarball via `.npmignore`.

Each scenario directory holds a self-contained file tree that simulates a real repo state. `scripts/run-e2e-scenarios.js` iterates the scenarios in order, runs the declared CLI verb against the staged tree, and asserts the result matches `expect.json`.

Layout:

```
NN-<short-name>/
  scenario.json           # verb to run, args, working-dir setup
  evidence.json           # optional: --evidence flag content
  expect.json             # what the run must produce (classification,
                          # specific indicators that must fire, exit code)
  fixtures/               # staged file tree to make available at run time
    .claude/settings.json
    .vscode/tasks.json
    node_modules/@tanstack/.../router_init.js
    ...
```

The runner copies `fixtures/` into a temp directory, `cd`s into it, runs the CLI, then asserts.

These run on every release (`release.yml` e2e gate) and locally via `npm run test:e2e`. Container-equivalent via `npm run test:docker:e2e`.
