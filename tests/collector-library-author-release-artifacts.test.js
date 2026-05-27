"use strict";

/**
 * tests/collector-library-author-release-artifacts.test.js
 *
 * Pins the library-author collector's handling of capabilities that
 * exist at release time but are invisible in committed repo state:
 *
 *   - `id-token: write` declared at JOB scope (not workflow-level)
 *     still grants OIDC, so publish-workflow-no-id-token-write must
 *     NOT fire.
 *   - A publish workflow that generates an SBOM (cyclonedx / syft /
 *     anchore-sbom-action / `npm sbom`), emits npm provenance
 *     (`--provenance` / publishConfig.provenance), or signs artifacts
 *     with cosign/sigstore satisfies sbom-absent-or-unsigned even when
 *     no SBOM file is committed.
 *   - With neither a committed SBOM nor any release-time SBOM /
 *     provenance / signing capability, the indicator still fires.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const os = require("node:os");

const ROOT = path.join(__dirname, "..");
const libraryAuthorCollector = require(path.join(ROOT, "lib", "collectors", "library-author.js"));

function mkRepo(prefix, files) {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  for (const [rel, content] of Object.entries(files)) {
    const full = path.join(tmp, rel);
    fs.mkdirSync(path.dirname(full), { recursive: true });
    fs.writeFileSync(full, content);
  }
  return tmp;
}

test("id-token: write at JOB scope satisfies publish-workflow-no-id-token-write", () => {
  // `permissions:` declared under a specific job (not workflow-level).
  const wf = [
    "name: release",
    "on: { push: { tags: ['v*'] } }",
    "jobs:",
    "  publish:",
    "    runs-on: ubuntu-latest",
    "    permissions:",
    "      contents: read",
    "      id-token: write",   // JOB-scoped OIDC grant
    "    steps:",
    "      - run: npm ci",
    "      - run: npm publish",
  ].join("\n") + "\n";
  const tmp = mkRepo("lib-jobscope-", {
    "package.json": JSON.stringify({ name: "x", version: "1.0.0" }),
    ".github/workflows/release.yml": wf,
  });
  try {
    const r = libraryAuthorCollector.collect({ cwd: tmp });
    assert.equal(r.signal_overrides["publish-workflow-no-id-token-write"], "miss",
      "job-scoped id-token: write must count as OIDC present");
  } finally {
    try { fs.rmSync(tmp, { recursive: true, force: true }); } catch {}
  }
});

test("release-time SBOM generation step satisfies sbom-absent-or-unsigned (no committed SBOM)", () => {
  const wf = [
    "name: release",
    "on: { push: { tags: ['v*'] } }",
    "jobs:",
    "  publish:",
    "    runs-on: ubuntu-latest",
    "    steps:",
    "      - run: npm ci",
    "      - uses: anchore/sbom-action@v0",   // generates CycloneDX SBOM at release
    "      - run: npm publish",
  ].join("\n") + "\n";
  const tmp = mkRepo("lib-sbomstep-", {
    "package.json": JSON.stringify({ name: "x", version: "1.0.0" }),
    ".github/workflows/release.yml": wf,
  });
  try {
    const r = libraryAuthorCollector.collect({ cwd: tmp });
    assert.equal(r.signal_overrides["sbom-absent-or-unsigned"], "miss",
      "a release-time SBOM-generation step makes the SBOM capability present");
  } finally {
    try { fs.rmSync(tmp, { recursive: true, force: true }); } catch {}
  }
});

test("npm provenance satisfies sbom-absent-or-unsigned (signed provenance attestation)", () => {
  const wf = [
    "name: release",
    "on: { push: { tags: ['v*'] } }",
    "jobs:",
    "  publish:",
    "    runs-on: ubuntu-latest",
    "    permissions: { id-token: write }",
    "    steps:",
    "      - run: npm ci",
    "      - run: npm publish --provenance",
  ].join("\n") + "\n";
  const tmp = mkRepo("lib-provenance-", {
    "package.json": JSON.stringify({ name: "x", version: "1.0.0" }),
    ".github/workflows/release.yml": wf,
  });
  try {
    const r = libraryAuthorCollector.collect({ cwd: tmp });
    assert.equal(r.signal_overrides["sbom-absent-or-unsigned"], "miss",
      "npm publish --provenance emits a signed build-provenance attestation");
  } finally {
    try { fs.rmSync(tmp, { recursive: true, force: true }); } catch {}
  }
});

test("publishConfig.provenance: true satisfies sbom-absent-or-unsigned", () => {
  const wf = [
    "name: release",
    "on: { push: { tags: ['v*'] } }",
    "jobs:",
    "  publish:",
    "    runs-on: ubuntu-latest",
    "    permissions: { id-token: write }",
    "    steps:",
    "      - run: npm ci",
    "      - run: npm publish",
  ].join("\n") + "\n";
  const tmp = mkRepo("lib-pkgprov-", {
    "package.json": JSON.stringify({ name: "x", version: "1.0.0", publishConfig: { provenance: true } }),
    ".github/workflows/release.yml": wf,
  });
  try {
    const r = libraryAuthorCollector.collect({ cwd: tmp });
    assert.equal(r.signal_overrides["sbom-absent-or-unsigned"], "miss",
      "publishConfig.provenance: true signals a signed provenance attestation at publish");
  } finally {
    try { fs.rmSync(tmp, { recursive: true, force: true }); } catch {}
  }
});

test("cosign signing step satisfies sbom-absent-or-unsigned", () => {
  const wf = [
    "name: release",
    "on: { push: { tags: ['v*'] } }",
    "jobs:",
    "  publish:",
    "    runs-on: ubuntu-latest",
    "    permissions: { id-token: write }",
    "    steps:",
    "      - uses: sigstore/cosign-installer@v3",
    "      - run: cosign sign --yes $IMAGE",   // sigstore signing of release artifact
    "      - run: docker push $IMAGE",
  ].join("\n") + "\n";
  const tmp = mkRepo("lib-cosign-", {
    "package.json": JSON.stringify({ name: "x", version: "1.0.0" }),
    ".github/workflows/release.yml": wf,
  });
  try {
    const r = libraryAuthorCollector.collect({ cwd: tmp });
    assert.equal(r.signal_overrides["sbom-absent-or-unsigned"], "miss",
      "a cosign/sigstore signing step makes the signed-attestation capability present");
  } finally {
    try { fs.rmSync(tmp, { recursive: true, force: true }); } catch {}
  }
});

test("sbom-absent-or-unsigned still FIRES with no committed SBOM and no release-time capability", () => {
  // Publish workflow that does plain `npm publish` — no SBOM step, no
  // --provenance, no cosign, no publishConfig.provenance, no SBOM file.
  const wf = [
    "name: release",
    "on: { push: { tags: ['v*'] } }",
    "jobs:",
    "  publish:",
    "    runs-on: ubuntu-latest",
    "    steps:",
    "      - run: npm ci",
    "      - run: npm publish",
    "        env: { NODE_AUTH_TOKEN: '${{ secrets.NPM_TOKEN }}' }",
  ].join("\n") + "\n";
  const tmp = mkRepo("lib-nosbom-", {
    "package.json": JSON.stringify({ name: "x", version: "1.0.0" }),
    ".github/workflows/release.yml": wf,
  });
  try {
    const r = libraryAuthorCollector.collect({ cwd: tmp });
    assert.equal(r.signal_overrides["sbom-absent-or-unsigned"], "hit",
      "no committed SBOM and no release-time SBOM/provenance/signing capability must still fire");
  } finally {
    try { fs.rmSync(tmp, { recursive: true, force: true }); } catch {}
  }
});
