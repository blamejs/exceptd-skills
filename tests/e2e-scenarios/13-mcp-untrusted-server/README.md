# 13-mcp-untrusted-server

Stages a `.claude/settings.local.json` that registers an MCP server pulled with `npx -y untrusted-fs-mcp@latest` — no version pin, no integrity hash, no signature verification, no allowlist policy. The `mcp` playbook must classify `detected` via `mcp-version-without-integrity`, `unsigned-mcp-manifest`, and `mcp-allowlist-missing`.

Why this matters: floating tag + no integrity is the canonical MCP supply-chain compromise primitive. An attacker that controls the package can land arbitrary code under the user's AI assistant with file-system + network capabilities.
