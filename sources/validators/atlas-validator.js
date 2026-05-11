'use strict';

/**
 * atlas-validator.js — Confirm pinned MITRE ATLAS version against upstream.
 *
 * Zero npm dependencies. Node 24 stdlib only.
 *
 * MITRE ATLAS does not (as of v5.x) publish a stable machine-readable changelog JSON.
 * The canonical source-of-truth for releases is the public GitHub repo:
 *   https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/dist/ATLAS.yaml
 * which carries an `id: ATLAS` / `version: x.y.z` header. The GitHub releases API
 * also lists tagged versions:
 *   https://api.github.com/repos/mitre-atlas/atlas-data/releases/latest
 *
 * We prefer the releases API (lightweight JSON, no YAML parsing), fall back to the
 * raw YAML version line, and finally report unreachable if both fail. Both are
 * read-only public endpoints; no auth is required.
 *
 * Exported:
 *   validateAtlasVersion(opts?) -> Promise<{
 *     pinned: string|null,
 *     pinned_sources: { manifest: string|null, index: string|null },
 *     latest: string|null,
 *     drift: boolean,
 *     status: 'match'|'drift'|'unreachable'|'unknown',
 *     fetched_from: string|null,
 *     error: string|null
 *   }>
 */

const fs = require('node:fs/promises');
const path = require('node:path');

const REQUEST_TIMEOUT_MS = 10_000;
const USER_AGENT = 'exceptd-security/atlas-validator (+https://exceptd.com)';

const REPO_ROOT = path.resolve(__dirname, '..', '..');
const MANIFEST_PATH = path.join(REPO_ROOT, 'manifest.json');
const SOURCES_INDEX_PATH = path.join(REPO_ROOT, 'sources', 'index.json');

const GH_RELEASE_URL = 'https://api.github.com/repos/mitre-atlas/atlas-data/releases/latest';
const RAW_ATLAS_YAML = 'https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/dist/ATLAS.yaml';

async function timedFetch(url, accept = 'application/json') {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
  try {
    const res = await fetch(url, {
      signal: controller.signal,
      headers: { 'User-Agent': USER_AGENT, Accept: accept },
    });
    if (!res.ok) return { ok: false, error: `HTTP ${res.status}` };
    const body = accept.includes('json') ? await res.json() : await res.text();
    return { ok: true, body };
  } catch (err) {
    const code = err.name === 'AbortError' ? 'timeout' : (err.code || 'network_error');
    return { ok: false, error: `${code}: ${err.message}` };
  } finally {
    clearTimeout(timer);
  }
}

function normalizeVersion(v) {
  if (!v || typeof v !== 'string') return null;
  // Strip leading "v" / "ATLAS-v" prefixes; trim.
  return v.trim().replace(/^ATLAS[-_ ]?/i, '').replace(/^v/i, '');
}

async function readPinnedVersions() {
  const out = { manifest: null, index: null };
  try {
    const manifest = JSON.parse(await fs.readFile(MANIFEST_PATH, 'utf8'));
    out.manifest = normalizeVersion(
      manifest?._meta?.atlas_version || manifest?.atlas_version || null
    );
  } catch { /* leave null */ }
  try {
    const idx = JSON.parse(await fs.readFile(SOURCES_INDEX_PATH, 'utf8'));
    out.index = normalizeVersion(idx?.sources?.atlas?.current_version || null);
  } catch { /* leave null */ }
  return out;
}

async function fetchLatestFromGithubReleases() {
  const res = await timedFetch(GH_RELEASE_URL);
  if (!res.ok) return { ok: false, error: res.error };
  const tag = res.body?.tag_name || res.body?.name || null;
  const version = normalizeVersion(tag);
  if (!version) return { ok: false, error: 'no tag_name in response' };
  return { ok: true, version, source: 'github-releases' };
}

async function fetchLatestFromRawYaml() {
  const res = await timedFetch(RAW_ATLAS_YAML, 'text/yaml');
  if (!res.ok) return { ok: false, error: res.error };
  // Naive YAML scrape: look for a top-level `version:` line within the first 200 lines.
  const text = String(res.body).split(/\r?\n/).slice(0, 200).join('\n');
  const match = text.match(/^version:\s*['"]?([0-9]+(?:\.[0-9]+){1,2})['"]?\s*$/m);
  if (!match) return { ok: false, error: 'version line not found in ATLAS.yaml' };
  return { ok: true, version: normalizeVersion(match[1]), source: 'raw-yaml' };
}

async function validateAtlasVersion(_opts = {}) {
  const pinned_sources = await readPinnedVersions();
  // Canonical pinned value: prefer manifest._meta or top-level, then sources/index.json.
  const pinned = pinned_sources.manifest || pinned_sources.index || null;

  // Cross-check that the two pinned locations agree.
  const pinnedDisagree =
    pinned_sources.manifest &&
    pinned_sources.index &&
    pinned_sources.manifest !== pinned_sources.index;

  // Try GitHub releases first, fall back to raw YAML.
  let upstream = await fetchLatestFromGithubReleases();
  if (!upstream.ok) {
    const fallback = await fetchLatestFromRawYaml();
    if (fallback.ok) upstream = fallback;
  }

  if (!upstream.ok) {
    return {
      pinned,
      pinned_sources,
      latest: null,
      drift: pinnedDisagree === true, // internal drift is still reportable offline
      status: 'unreachable',
      fetched_from: null,
      error: upstream.error,
    };
  }

  const latest = upstream.version;
  if (!pinned) {
    return {
      pinned: null,
      pinned_sources,
      latest,
      drift: true,
      status: 'unknown',
      fetched_from: upstream.source,
      error: 'no pinned ATLAS version found in manifest.json or sources/index.json',
    };
  }

  const drift = pinned !== latest || pinnedDisagree === true;
  return {
    pinned,
    pinned_sources,
    latest,
    drift,
    status: drift ? 'drift' : 'match',
    fetched_from: upstream.source,
    error: null,
  };
}

module.exports = { validateAtlasVersion };
