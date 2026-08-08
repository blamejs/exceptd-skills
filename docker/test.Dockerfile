# syntax=docker/dockerfile:1.7
#
# Test-harness image for exceptd-skills.
#
# This Dockerfile is NOT a release artifact. It exists so contributors
# can reproduce the CI workflow's Linux + Node 24.19.0 LTS environment
# on their own machine before pushing. CI runs the same gates on
# GitHub-hosted ubuntu/windows/macos runners; this image gives a fast
# Linux signal without burning a CI cycle.
#
# Three targets:
#   predeploy        — runs `npm run predeploy` against the repo as
#                      mounted/copied. Mirrors the CI gate sequence.
#                      Skips `verify-signatures` if keys/public.pem is
#                      missing — same behavior as the local runner.
#
#   fresh-bootstrap  — wipes any inherited signing state, then runs the
#                      full ceremony: `npm run bootstrap` (generate
#                      keypair, sign every skill, verify) followed by
#                      `npm run predeploy`. Proves a fresh clone reaches
#                      a clean green state with no manual steps.
#
#   e2e              — runs `npm run test:e2e`, the end-to-end scenario
#                      gate over tests/e2e-scenarios/ (synthetic file
#                      trees with real IoC patterns, asserted against
#                      each scenario's expect.json).
#
# Use via the package.json scripts:
#   npm run test:docker          → predeploy target
#   npm run test:docker:fresh    → fresh-bootstrap target
#
# Why pinned image:
#   node:24.19.0-alpine3.23 — pinned to the same Node version CI uses
#   in `.github/workflows/ci.yml`. A drift here lets a Node-version-
#   sensitive bug pass local Docker and fail CI (or vice versa). The
#   tag is additionally pinned by digest so a registry-side mutation
#   (rare but possible) cannot change the image under us — Scorecard's
#   Pinned-Dependencies check requires this for a contributor-facing
#   reproducer image. When the CI workflow bumps Node, bump this tag
#   AND its digest in the same commit (look up via
#   `docker buildx imagetools inspect node:<new-tag>`).

# ── base ───────────────────────────────────────────────────────────────────
FROM node:24.19.0-alpine3.23@sha256:244cc2b53f46f9e876304391d17682b0ddae9ac33491f4857e25e35a36ba7995 AS base

# Run as a non-root user to match GitHub Actions runner behavior.
# `node` is the upstream image's existing non-root user.
WORKDIR /app

# WORKDIR creates /app owned by root, while the COPY steps below land their
# contents as `node` and the suite runs as `node`. Anything that writes into the
# project directory — the vendor-refresh install path, atomic-write temp files —
# then fails on permissions rather than on what it was testing. Hand the
# directory to the user that runs the suite; a CI runner's checkout is owned by
# the invoking user too, which is the state this image exists to reproduce.
RUN chown node:node /app

# The git binary, so the gates that shell out to it fail on a missing repository
# rather than a missing executable — the two are different conditions and only
# one of them is expected here. .git/ is deliberately not in the build context
# (see .dockerignore), so git has no repository to answer about: the gates that
# ask which files are tracked or ignored skip in this image and report that they
# skipped. That is the accepted cost of not copying a contributor's history into
# a build context, not an oversight to work around by admitting .git.
RUN apk add --no-cache git

# Copy package manifests first so `npm install` is cached when only
# source files change. The repo declares zero runtime/dev deps today,
# but the install layer stays so the cache exists if that changes.
COPY --chown=node:node package.json package-lock.json* ./
RUN npm install --no-audit --no-fund

# Copy the rest of the repo. The .dockerignore already strips .keys/,
# .git/, node_modules, etc. so only the project surface lands here.
COPY --chown=node:node . .

USER node

# ── predeploy ──────────────────────────────────────────────────────────────
# Default target: run the gate sequence against the repo state in the
# build context. If the host has already run `npm run bootstrap` and
# committed keys/public.pem + signed manifest, signature verification
# passes; otherwise the verify gate is skipped (predeploy.js handles
# both cases). Useful for "did my change break a gate?" iteration.
FROM base AS predeploy
CMD ["npm", "run", "predeploy"]

# ── fresh-bootstrap ────────────────────────────────────────────────────────
# Wipe any inherited signing state, then run the full ceremony from
# zero. This is the harshest check: every contributor's first command
# on a fresh clone, executed in a clean OS. If bootstrap fails or
# leaves the repo in a state where predeploy fails, the test fails.
FROM base AS fresh-bootstrap
# Strip any signature blocks the build context inherited from the host.
# After this step the repo looks identical to a fresh `git clone` of
# a state where no maintainer has signed yet.
RUN node -e "const fs=require('fs'); const p='manifest.json'; const m=JSON.parse(fs.readFileSync(p,'utf8')); for (const s of m.skills) { delete s.signature; delete s.signed_at; delete s.sha256; } fs.writeFileSync(p, JSON.stringify(m,null,2)+'\n');" \
 && rm -rf .keys keys .bootstrap-complete
CMD ["sh", "-c", "npm run bootstrap && npm run predeploy"]

# ── e2e ────────────────────────────────────────────────────────────────────
# End-to-end scenario gate. Each scenario under tests/e2e-scenarios/
# stages a synthetic file tree containing the real IoC patterns a
# playbook checks for (CVE-2026-45321 payload files, Claude SessionStart
# hooks, VS Code folder-open tasks, GitHub Actions cache co-residency,
# missing .npmrc cooldown, etc.). The runner copies each fixture into a
# temp dir, runs the CLI verb against it, and asserts the JSON result
# matches expect.json. Failure here means a playbook detection
# regressed even though unit tests pass. Wired into release.yml so a
# bad detection layer can't ship to npm.
FROM base AS e2e
CMD ["npm", "run", "test:e2e"]
