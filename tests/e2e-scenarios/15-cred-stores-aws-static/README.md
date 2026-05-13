# 15-cred-stores-aws-static

Stages a `home/.aws/credentials` INI carrying a `[default]` block with long-lived `aws_access_key_id` + `aws_secret_access_key` and no `sso_session` declaration. The `cred-stores` playbook must classify `detected` via `aws-static-key-present` and surface the AWS-SSO / IAM-Identity-Center migration recommendation.

Why this matters: long-lived AWS root or IAM-user keys on developer workstations are the canonical credential-store anti-pattern; the playbook's whole purpose is moving operators off them. The fixture exercises the static-key detection path independent of the actual `$HOME` location.
