# 16-containers-root-user

Stages a single `Dockerfile` exercising three container anti-patterns simultaneously: floating `FROM ubuntu:latest` (no digest pin), explicit `USER root`, and a `curl | bash` install step. The `containers` playbook must classify `detected` via `dockerfile-from-latest`, `dockerfile-no-digest-pin`, `dockerfile-runs-as-root`, and `dockerfile-curl-pipe-bash`.

Why this matters: each indicator alone is a finding; their combination is the canonical insecure-container-build pattern. The scenario keeps the multi-indicator container-hardening detection path green.
