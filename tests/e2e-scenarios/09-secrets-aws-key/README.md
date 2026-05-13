# 09-secrets-aws-key

Stages a tracked `src/config.py` containing an AWS Access Key ID (AKIA shape, not the published `AKIAIOSFODNN7EXAMPLE` test key) alongside its 40-character secret half. The `secrets` playbook should classify the run as `detected`, fire the `aws-access-key-id` + `aws-secret-access-key` indicators, and start at least one jurisdiction notification clock (GDPR Article 33 / CCPA breach notice apply once an active credential is in scope).

Why this matters: scraper bots index public repos within minutes of push; a leaked AKIA + secret pair is direct IAM-user impersonation. The detection path must remain green across releases.
