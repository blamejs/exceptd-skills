# Docker test harness

A clean-room test environment for the exceptd-skills pre-deploy gates.
**Not a release artifact** — this image exists only so contributors can
reproduce CI's Linux + Node 24.14.1 LTS environment locally before
pushing.

## When to use it

- Your local machine runs a different Node version than CI and you want
  to confirm a gate passes on the pinned version before pushing.
- You're on Windows or macOS and a CI failure looks Linux-specific.
- You changed `scripts/bootstrap.js`, `lib/sign.js`, or `lib/verify.js`
  and want to confirm a fresh clone still reaches a clean signed state.
- You want to test the full `bootstrap → sign → verify → predeploy`
  ceremony without touching your local `.keys/`.

If none of those describe you, just run `npm run predeploy` directly.

## Targets

Two build targets defined in `test.Dockerfile`:

| Target           | What it does                                                                                       | When to run                                                                 |
|------------------|----------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------|
| `predeploy`      | Runs `npm run predeploy` against the repo state as-is.                                              | Day-to-day: "does my change break a gate on Linux/Node 24.14.1?"             |
| `fresh-bootstrap`| Wipes inherited signing state, runs `npm run bootstrap`, then `npm run predeploy`.                  | After touching the signing toolchain or onboarding docs.                    |

## Run

```bash
# Standard pre-push check.
npm run test:docker

# Full ceremony from a fresh state.
npm run test:docker:fresh
```

Equivalent raw docker invocations:

```bash
docker build --target predeploy       -t exceptd-test:predeploy       -f docker/test.Dockerfile .
docker run --rm exceptd-test:predeploy

docker build --target fresh-bootstrap -t exceptd-test:fresh-bootstrap -f docker/test.Dockerfile .
docker run --rm exceptd-test:fresh-bootstrap
```

## What it does NOT cover

- **Windows / macOS-specific regressions.** Tests pass in Linux Docker
  but fail on a Windows GitHub runner. The CI matrix is the only
  authoritative cross-OS gate.
- **Network-required validation.** The validator under
  `sources/validators/cve-validator.js` is invoked in `--offline` mode
  inside the container (per the predeploy gate sequence). Live NVD /
  CISA KEV cross-checks live in the scheduled `atlas-currency.yml`
  workflow, not the local harness.
- **Repository hygiene checks that require git history.** Gitleaks
  full-history scanning is excluded — `.git/` is in `.dockerignore`
  because most contributors don't want their local working tree's
  history copied into a build context. Run gitleaks locally outside
  Docker if you need it, or rely on the CI `secret-scan` job.

## Pinning policy

The base image tag (`node:24.14.1-alpine3.21`) is pinned to match the
`node-version` field in `.github/workflows/ci.yml`. When the workflow
bumps Node, bump this tag in the same commit. The
`tests/docker.test.js` regression test enforces the alignment.
