# 12-crypto-codebase-md5-eol

Stages a `src/auth.py` that uses `hashlib.md5` on its production user-session fingerprint path. The `crypto-codebase` playbook must classify `detected` via `weak-hash-import` and `no-ml-kem-implementation`, and surface PQC + hash-deprecation migration paths in the close phase.

Why this matters: MD5 in an authentication identifier is collision-attackable; the `crypto-codebase` playbook is the entry point for the broader PQC-readiness audit and must surface both the deprecated-hash and the missing-PQC-adoption signals in the same run.
