"use strict";

/**
 * lib/upstream-check.js
 *
 * Shared helper used by `doctor --registry-check`, `run --upstream-check`,
 * and `refresh --network`. Queries the npm registry for the package's
 * latest published version + publish timestamp. Operator opts in — never
 * fired automatically on every CLI invocation.
 *
 * Trust model: the registry call is a freshness signal, not a trust
 * anchor. The Ed25519-signed skill catalog shipped in the operator's
 * installed package remains the source of truth. This helper only
 * reports "you're N days behind" — does not auto-update anything.
 *
 * Zero npm deps. Node 24 stdlib only.
 */

const https = require("https");

const REGISTRY_HOST = "registry.npmjs.org";
const PKG_NAME = "@blamejs/exceptd-skills";
const REQUEST_TIMEOUT_MS = 5000;

/**
 * Fetch the latest version + publish time from the npm registry.
 *
 * Returns:
 *   { ok: true,  version: "0.11.14", published_at: ISO_STRING, source: "npm-registry" }
 *   { ok: false, error: "timeout" | "offline" | "parse" | string, source: "offline" }
 *
 * Honors EXCEPTD_REGISTRY_FIXTURE env var for offline testing — value is
 * a path to a JSON file with { version, time: { <ver>: ISO } } shape.
 */
async function fetchLatestPublished({ timeoutMs = REQUEST_TIMEOUT_MS, pkgName = PKG_NAME } = {}) {
  // Air-gap refusal — registry probes are a network operation and must never
  // be issued when the operator has declared an air-gapped environment.
  // Returning a structured refusal (instead of throwing) lets callers degrade
  // gracefully the same way they handle `offline` — the freshness signal is
  // intentionally absent, not in error.
  if (process.env.EXCEPTD_AIR_GAP === "1") {
    return { ok: false, error: "air-gap-blocked", source: "fetchLatestPublished" };
  }

  if (process.env.EXCEPTD_REGISTRY_FIXTURE) {
    try {
      const fs = require("fs");
      const fixture = JSON.parse(fs.readFileSync(process.env.EXCEPTD_REGISTRY_FIXTURE, "utf8"));
      const version = fixture["dist-tags"]?.latest || fixture.version;
      const published = fixture.time?.[version] || fixture.time?.modified;
      return { ok: true, version, published_at: published, source: "fixture" };
    } catch (e) {
      return { ok: false, error: `fixture: ${e.message}`, source: "offline" };
    }
  }

  return new Promise((resolve) => {
    const path = `/${encodeURIComponent(pkgName).replace("%40", "@").replace("%2F", "/")}`;
    const req = https.get({
      host: REGISTRY_HOST,
      path,
      headers: {
        "Accept": "application/vnd.npm.install-v1+json, application/json",
        "User-Agent": "exceptd/upstream-check"
      },
      timeout: timeoutMs,
    }, (res) => {
      if (res.statusCode !== 200) {
        res.resume();
        return resolve({ ok: false, error: `registry returned HTTP ${res.statusCode}`, source: "offline" });
      }
      const chunks = [];
      res.on("data", (c) => chunks.push(c));
      res.on("end", () => {
        try {
          const body = JSON.parse(Buffer.concat(chunks).toString("utf8"));
          const version = body["dist-tags"]?.latest;
          const published = body.time?.[version] || body.time?.modified || null;
          if (!version) {
            return resolve({ ok: false, error: "registry response missing dist-tags.latest", source: "offline" });
          }
          resolve({ ok: true, version, published_at: published, source: "npm-registry" });
        } catch (e) {
          resolve({ ok: false, error: `parse: ${e.message}`, source: "offline" });
        }
      });
    });
    req.on("timeout", () => { req.destroy(new Error("timeout")); });
    req.on("error", (e) => resolve({ ok: false, error: e.message, source: "offline" }));
  });
}

/**
 * Semver compare (returns -1, 0, 1). Accepts canonical N.N.N strings only;
 * pre-release tags are ignored (rare on this package, and operators behind
 * a pre-release would explicitly opt in).
 */
function semverCmp(a, b) {
  const pa = String(a).split(".").map((n) => parseInt(n, 10) || 0);
  const pb = String(b).split(".").map((n) => parseInt(n, 10) || 0);
  for (let i = 0; i < 3; i++) {
    const da = pa[i] || 0, db = pb[i] || 0;
    if (da !== db) return da < db ? -1 : 1;
  }
  return 0;
}

/**
 * Build the operator-facing freshness report. Pure function — takes the
 * registry response and the local version/manifest, returns the report.
 */
function buildFreshnessReport({ localVersion, registry, localManifest }) {
  if (!registry || !registry.ok) {
    return {
      ok: false,
      source: "offline",
      error: registry?.error || "registry unreachable",
      local_version: localVersion,
      hint: "Network unreachable. Skipping upstream-check. This is a freshness signal only; the local catalog remains the source of truth.",
    };
  }
  const cmp = semverCmp(localVersion, registry.version);
  const daysBehind = registry.published_at
    ? Math.max(0, Math.floor((Date.now() - new Date(registry.published_at).getTime()) / (24 * 3600 * 1000)))
    : null;
  // Manifest's last_threat_review (per-skill) — surface the most stale.
  let oldestReview = null;
  if (localManifest && Array.isArray(localManifest.skills)) {
    for (const s of localManifest.skills) {
      if (s.last_threat_review && (!oldestReview || s.last_threat_review < oldestReview)) {
        oldestReview = s.last_threat_review;
      }
    }
  }
  return {
    ok: true,
    source: registry.source,
    local_version: localVersion,
    latest_version: registry.version,
    latest_published_at: registry.published_at,
    days_since_latest_publish: daysBehind,
    behind: cmp < 0,
    same: cmp === 0,
    ahead: cmp > 0,
    oldest_skill_last_threat_review: oldestReview,
    hint: cmp < 0
      ? `Local install is behind. Run \`npm update -g @blamejs/exceptd-skills\` to consume v${registry.version} (published ${registry.published_at}). Or \`exceptd refresh --network\` to pull just the catalog without changing the CLI/lib code.`
      : cmp === 0
      ? `Local install matches the latest published version.`
      : `Local install is AHEAD of the published registry version (development build?).`
  };
}

module.exports = { fetchLatestPublished, semverCmp, buildFreshnessReport };
