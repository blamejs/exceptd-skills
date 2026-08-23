"use strict";

/**
 * Queries the npm registry for the package's latest published version and
 * publish time, for `doctor --registry-check`, `run --upstream-check` and
 * `refresh --network`. The registry call is a freshness signal, not a trust
 * anchor: the Ed25519-signed local catalog stays the source of truth, and this
 * reports how far behind it is without updating anything.
 */

const https = require("https");

const REGISTRY_HOST = "registry.npmjs.org";
const PKG_NAME = "@blamejs/exceptd-skills";
const REQUEST_TIMEOUT_MS = 5000;

/**
 * Returns { ok: true, version, published_at, source: "npm-registry" }, or
 * { ok: false, error, source: "offline" } — never throws, so a caller treats an
 * absent freshness signal as absent rather than as an error.
 * EXCEPTD_REGISTRY_FIXTURE points at a JSON file shaped
 * { version, time: { <ver>: ISO } } for offline runs.
 */
async function fetchLatestPublished({ timeoutMs = REQUEST_TIMEOUT_MS, pkgName = PKG_NAME } = {}) {
  // A network operation: air-gap gets a structured refusal, as `offline` does.
  if (process.env.EXCEPTD_AIR_GAP === "1") {
    return { ok: false, error: "air-gap-blocked", source: "fetchLatestPublished" };
  }

  if (process.env.EXCEPTD_REGISTRY_FIXTURE) {
    try {
      const fs = require("fs");
      const fixture = JSON.parse(fs.readFileSync(process.env.EXCEPTD_REGISTRY_FIXTURE, "utf8"));
      const version = fixture["dist-tags"]?.latest || fixture.version;
      // Same guard as the network branch: ok:true with version undefined leaks
      // into buildFreshnessReport's semver compare and its hint.
      if (!version) {
        return { ok: false, error: "fixture missing dist-tags.latest / version", source: "offline" };
      }
      const published = fixture.time?.[version] || fixture.time?.modified || null;
      return { ok: true, version, published_at: published, source: "fixture" };
    } catch (e) {
      return { ok: false, error: `fixture: ${e.message}`, source: "offline" };
    }
  }

  return new Promise((resolve) => {
    const path = `/${encodeURIComponent(pkgName).replace(/%40/g, "@").replace(/%2F/g, "/")}`;
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
 * Semver compare, returning -1, 0 or 1. Canonical N.N.N only; a pre-release tag
 * is ignored rather than ordered.
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

/** Operator-facing freshness report. Pure — no I/O of its own. */
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
  // An unparseable registry `time` yields NaN from getTime(); it degrades to the
  // explicit null signal-absent branch rather than reaching the report.
  const publishedTs = registry.published_at ? new Date(registry.published_at).getTime() : NaN;
  const daysBehind = Number.isFinite(publishedTs)
    ? Math.max(0, Math.floor((Date.now() - publishedTs) / (24 * 3600 * 1000)))
    : null;
  // last_threat_review is per-skill; the report surfaces the most stale.
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
