# 17-runtime-suid-drift

Stages runtime evidence consistent with two post-foothold persistence primitives present simultaneously: a setuid-root binary at `/usr/local/bin/agent.sh` whose sha256 is not in the distro package database, plus an `/etc/sudoers.d/deploy` granting `NOPASSWD: /usr/bin/*` to a service account. The `runtime` playbook must classify `detected` via `non-baseline-suid` and `sudoers-nopasswd-wildcard`.

Why this matters: setuid drift outside the distro baseline is the canonical privileged-persistence indicator; a NOPASSWD wildcard is effective root for the named user. Both belong to the runtime playbook's post-foothold-imitation chain.

Note: the runtime playbook's `auditd-config-absent` indicator suggested in the audit was not present in the shipped playbook — the existing detection surface here (non-baseline-suid + sudoers-nopasswd-wildcard) is the most credible substitute and covers the same threat class.
