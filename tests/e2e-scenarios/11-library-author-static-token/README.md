# 11-library-author-static-token

Stages a `.github/workflows/publish.yml` that publishes to npm using a long-lived `secrets.NPM_TOKEN` rather than OIDC trusted publishing, alongside a `package.json` that lacks `publishConfig.provenance: true`. The `library-author` playbook must classify `detected` and surface the `publish-workflow-uses-static-token`, `publish-workflow-no-id-token-write`, and `package-json-provenance-missing` indicators.

Why this matters: static publish tokens are the dominant exploitation primitive in npm supply-chain compromises; the `library-author` playbook exists specifically to detect this anti-pattern in maintained packages.
