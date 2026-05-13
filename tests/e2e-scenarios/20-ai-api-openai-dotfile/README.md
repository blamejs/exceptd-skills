# 20-ai-api-openai-dotfile

Stages a `.zshrc` exporting a cleartext `OPENAI_API_KEY` (sk-proj-* shape) alongside a `~/.aws/credentials` carrying a long-lived `[default]` static-key block. Concurrent AI-SDK egress to api.openai.com and api.anthropic.com is captured. The `ai-api` playbook must classify `detected` via `cleartext-api-key-in-dotfile` and `long-lived-aws-keys`.

Why this matters: dotfile-resident cleartext AI keys are the dominant exfiltration primitive for AI-C2 (ATLAS AML.T0096 / SesameOp class). Pairing the AI key with long-lived AWS keys on the same workstation is the standard cross-credential harvest path; the playbook's whole reason for existing is to surface this combination.
