#!/usr/bin/env bash
# scripts/hooks/pre-commit.sh
#
# Diff-coverage gate as a pre-commit hook. NOT installed by default.
# To opt in:
#   git config core.hooksPath scripts/hooks
#
# To bypass once (acceptable when you genuinely have no covering test
# yet and intend to add one before push):
#   git commit --no-verify
#
# Exits non-zero when staged changes add a CLI verb, CLI flag, lib
# export, playbook indicator, or CVE iocs field that has no matching
# reference in tests/. Run `node scripts/check-test-coverage.js --staged`
# manually for the full report.
set -e

ROOT="$(git rev-parse --show-toplevel)"
node "$ROOT/scripts/check-test-coverage.js" --staged
