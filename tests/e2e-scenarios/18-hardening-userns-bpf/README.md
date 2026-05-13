# 18-hardening-userns-bpf

Stages a `/proc/sys/kernel` snapshot indicating `unprivileged_userns_clone=1` and `unprivileged_bpf_disabled=0` — two primitives required by several catalogued LPE classes (notably the CVE-2026-31431 Copy Fail family). The `hardening` playbook must classify `detected` via `unprivileged-userns-enabled` and `unprivileged-bpf-allowed`.

Why this matters: kernel hardening posture gates exploitability of kernel LPE findings. These two sysctls being permissive is the most common kernel-LPE-gating-flags drift on default-config developer machines.
