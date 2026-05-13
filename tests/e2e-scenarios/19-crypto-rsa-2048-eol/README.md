# 19-crypto-rsa-2048-eol

Stages a host running OpenSSL 3.4 (pre-ML-KEM availability) with an RSA-2048 host certificate valid for three years and an sshd config that does not negotiate `sntrup761x25519-sha512`. The `crypto` playbook must classify `detected` via `rsa-2048-cert-long-life`, `ml-kem-absent`, `ml-dsa-slh-dsa-absent`, `openssl-pre-3-5`, `sshd-no-pqc-kex`, and `tls-no-hybrid-group`.

Why this matters: long-validity RSA-2048 certs in a pre-PQC stack are the canonical "harvest now, decrypt later" exposure. PQC migration roadmaps are a hard rule (AGENTS.md crypto posture) and this scenario keeps that detection path green.
