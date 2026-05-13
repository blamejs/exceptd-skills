# 10-kernel-copy-fail

Stages a synthetic `/proc/version` for Linux 6.11.4-generic on Ubuntu 24.04 — kernel version falls inside the affected range for CVE-2026-31431 (Copy Fail family, page-cache write primitive). Livepatch list is empty for that CVE, unprivileged userns is on. The `kernel` playbook must classify `detected` via `kver-in-affected-range` + `unpriv-userns-enabled` indicators and surface a CVE-2026-31431 match.

Why this matters: Copy Fail is memory-only, 732-byte single-stage, leaves no disk forensics. The detection layer hinges on version match + livepatch absence + userns primitive. If any of those signal paths regress, this scenario fails.
