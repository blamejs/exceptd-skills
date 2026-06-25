"use strict";
/**
 * sources/validators/version-pin-validator.js
 *
 * Checks pinned upstream catalog versions against their canonical release
 * channels:
 *
 *   - MITRE ATLAS:     GitHub releases (mitre-atlas/atlas-data)
 *   - MITRE ATT&CK:    GitHub releases (mitre-attack/attack-stix-data)
 *
 * MITRE D3FEND and MITRE CWE do NOT publish tagged GitHub releases — D3FEND
 * ships its ontology from d3fend/d3fend-ontology untagged, and CWE distributes
 * XML from cwe.mitre.org. Their pin currency is tracked on the upstream-check
 * path (lib/upstream-check.js) against those canonical mitre.org endpoints, not
 * via the GitHub releases API. They remain enumerated here for completeness but
 * are flagged `github_releases: false`, so the GitHub-release check is skipped
 * for them and they are reported as `tracked_elsewhere` rather than emitting a
 * spurious `unreachable` (a release API call for a repo with no releases always
 * fails). This keeps the live path checking the same two GitHub-release repos
 * the cache path (pinsDiffFromCache) checks.
 *
 * Each check returns:
 *   { pin_name, local_version, latest_version, drift: bool, source_url, error? }
 *
 * Network resilience: 10s AbortController timeout per call. A failure is
 * `{ error: ... }` — never throws. Version-pin drift is REPORT-ONLY: the
 * upgrade requires audit per AGENTS.md Hard Rule #12, so refresh-external
 * surfaces these as separate findings (GitHub issue, not an auto-apply PR).
 *
 * Zero npm deps. Node 24 stdlib only.
 */

const TIMEOUT_MS = 10_000;

const PINS = [
  {
    pin_name: "atlas_version",
    repo: "mitre-atlas/atlas-data",
    local_path_hint: "manifest.json — atlas_version",
    strip_v_prefix: true,
    github_releases: true,
  },
  {
    pin_name: "attack_version",
    repo: "mitre-attack/attack-stix-data",
    local_path_hint: "manifest.json — attack_version",
    strip_v_prefix: true,
    github_releases: true,
  },
  {
    // D3FEND does not tag GitHub releases — currency is tracked via
    // lib/upstream-check.js against the canonical mitre.org endpoint. Listed
    // here for completeness; the GitHub-release check is skipped.
    pin_name: "d3fend_version",
    repo: "d3fend/d3fend-data",
    local_path_hint: "data/d3fend-catalog.json _meta.version",
    strip_v_prefix: true,
    github_releases: false,
    tracked_via: "lib/upstream-check.js (d3fend.mitre.org)",
  },
  {
    // CWE distributes XML from cwe.mitre.org with no tagged GitHub releases —
    // currency is tracked via lib/upstream-check.js. GitHub-release check skipped.
    pin_name: "cwe_version",
    repo: "mitre/cwe",
    local_path_hint: "data/cwe-catalog.json _meta.version",
    strip_v_prefix: true,
    github_releases: false,
    tracked_via: "lib/upstream-check.js (cwe.mitre.org)",
  },
];

async function fetchWithTimeout(url, opts = {}) {
  const ac = new AbortController();
  const t = setTimeout(() => ac.abort(), TIMEOUT_MS);
  try {
    return await fetch(url, { ...opts, signal: ac.signal });
  } finally {
    clearTimeout(t);
  }
}

async function latestGithubRelease(repo) {
  // Use the un-authenticated /releases endpoint and pick the most recent
  // non-draft, non-prerelease entry. Limits: 60 anonymous requests/hour, more
  // than enough for a weekly refresh job.
  const url = `https://api.github.com/repos/${repo}/releases?per_page=5`;
  try {
    const res = await fetchWithTimeout(url, {
      headers: { Accept: "application/vnd.github+json", "User-Agent": "exceptd-security/version-pin-validator" },
    });
    if (!res.ok) {
      return { error: `HTTP ${res.status}`, source_url: url };
    }
    const arr = await res.json();
    if (!Array.isArray(arr)) return { error: "unexpected payload", source_url: url };
    const stable = arr.find((r) => !r.draft && !r.prerelease);
    if (!stable) return { error: "no stable release found", source_url: url };
    return { tag: stable.tag_name, name: stable.name, published_at: stable.published_at, source_url: stable.html_url };
  } catch (err) {
    return { error: err.message || "fetch failed", source_url: url };
  }
}

function normalize(version, stripV) {
  if (version == null) return null;
  let v = String(version).trim();
  if (stripV && v.startsWith("v")) v = v.slice(1);
  return v;
}

/**
 * Resolve the local pinned version for a given pin name.
 * @param {string} pin_name
 * @param {object} ctx - { manifest, cweCatalog, d3fendCatalog }
 */
function resolveLocalVersion(pin_name, ctx) {
  switch (pin_name) {
    case "atlas_version":
      return ctx.manifest.atlas_version;
    case "attack_version":
      return ctx.manifest.attack_version;
    case "cwe_version":
      return ctx.cweCatalog?._meta?.version || ctx.cweCatalog?._meta?.cwe_version || null;
    case "d3fend_version":
      return ctx.d3fendCatalog?._meta?.version || ctx.d3fendCatalog?._meta?.d3fend_version || null;
    default:
      return null;
  }
}

async function checkAllPins(ctx) {
  const out = [];
  for (const pin of PINS) {
    const local = normalize(resolveLocalVersion(pin.pin_name, ctx), pin.strip_v_prefix);
    // Pins whose upstream does not publish GitHub releases (D3FEND, CWE) have
    // no release tag to compare against — calling the releases API would always
    // fail and surface a spurious `unreachable`. Report them as tracked
    // elsewhere (drift:null, no error) so the live path checks exactly the same
    // GitHub-release repos as the cache path.
    if (pin.github_releases === false) {
      out.push({
        pin_name: pin.pin_name,
        local_version: local,
        latest_version: null,
        drift: null,
        tracked_elsewhere: true,
        tracked_via: pin.tracked_via || null,
        local_path_hint: pin.local_path_hint,
      });
      continue;
    }
    const release = await latestGithubRelease(pin.repo);
    if (release.error) {
      out.push({
        pin_name: pin.pin_name,
        local_version: local,
        latest_version: null,
        drift: null,
        unreachable: true,
        error: release.error,
        source_url: release.source_url,
      });
      continue;
    }
    const latest = normalize(release.tag, pin.strip_v_prefix);
    out.push({
      pin_name: pin.pin_name,
      local_version: local,
      latest_version: latest,
      latest_release_name: release.name,
      latest_published_at: release.published_at,
      drift: local != null && latest != null && local !== latest,
      source_url: release.source_url,
      local_path_hint: pin.local_path_hint,
    });
  }
  return out;
}

module.exports = { checkAllPins, PINS };
