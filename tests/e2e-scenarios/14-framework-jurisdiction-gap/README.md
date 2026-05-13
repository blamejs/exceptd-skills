# 14-framework-jurisdiction-gap

Stages an organisation operating in EU (Ireland), UK, and AU whose framework-mapping matrix declares NIST-800-53 only — no NIS2, DORA, EU AI Act, CAF, or Essential 8 bindings — and an unexpired exception register entry covering an active kernel CVE finding with RWEP=82. The `framework` playbook must classify `detected` and fire `jurisdiction-without-framework`, `framework-lag-no-compensating-control`, `exception-missing-expiry-or-owner`, `mapping-without-tempo`, `audit-clean-with-active-finding`, and `ai-use-without-ai-controls`.

Why this matters: compliance-theater detection is a hard rule (AGENTS.md Hard Rule #6) and the EU/UK/AU jurisdictional gap is the single most common framework-monoculture pattern in US-headquartered orgs. This scenario keeps the multi-fingerprint correlation path green.
