'use strict';

// ===========================================================================
// atlas-validator — sources/validators/atlas-validator.js
//
// validateAtlasVersion() reads the pinned ATLAS version from the repo
// (manifest.json / sources/index.json) and compares it against the latest
// upstream tag. The upstream lookup tries the GitHub releases API first, then
// falls back to scraping the version line out of the raw ATLAS.yaml. We stub
// global.fetch so every test runs offline and exercises the real decision
// logic: version normalization, the github-vs-yaml fallback, and the
// match / drift / unreachable / unknown status branches.
// ===========================================================================

const test = require('node:test');
const assert = require('node:assert/strict');

const { validateAtlasVersion } = require('../sources/validators/atlas-validator');

// --- fetch stubbing helpers -------------------------------------------------

const GH_HOST = 'api.github.com';
const RAW_HOST = 'raw.githubusercontent.com';

function jsonRes(obj, status = 200) {
  return { ok: status >= 200 && status < 300, status, json: async () => obj, text: async () => JSON.stringify(obj) };
}
function textRes(body, status = 200) {
  return { ok: status >= 200 && status < 300, status, text: async () => body, json: async () => { throw new Error('not json'); } };
}

// routes: { gh: response|Error|null, raw: response|Error|null }
// A null route means "behave as a hard network failure" (throw).
function stubFetch(routes) {
  const orig = global.fetch;
  global.fetch = async (url) => {
    let host = '';
    try { host = new URL(String(url)).hostname; } catch { /* non-URL */ }
    const pick = host === GH_HOST ? routes.gh : host === RAW_HOST ? routes.raw : undefined;
    if (pick === undefined) throw new Error('unexpected fetch in test: ' + url);
    if (pick === null) throw Object.assign(new Error('network down'), { code: 'ENOTFOUND' });
    if (pick instanceof Error) throw pick;
    return pick;
  };
  return () => { global.fetch = orig; };
}

// The repo's real pinned ATLAS value (manifest.json.atlas_version). The
// validator reads this from disk; we assert against it so the pinned-read
// path is genuinely exercised rather than mocked away.
const REPO_PINNED = require('../manifest.json').atlas_version; // e.g. "2026.06"

test('reports match when the upstream github tag equals the repo pin', async () => {
  const restore = stubFetch({ gh: jsonRes({ tag_name: `v${REPO_PINNED}` }), raw: null });
  try {
    const r = await validateAtlasVersion();
    assert.equal(r.pinned, REPO_PINNED, 'pinned should be read from the repo manifest');
    assert.equal(r.latest, REPO_PINNED, 'a "v"-prefixed tag normalizes to the bare version');
    assert.equal(r.status, 'match');
    assert.equal(r.drift, false);
    assert.equal(r.fetched_from, 'github-releases');
    assert.equal(r.error, null);
  } finally {
    restore();
  }
});

test('reports drift when the upstream tag is newer than the pin', async () => {
  const restore = stubFetch({ gh: jsonRes({ tag_name: 'v9999.12' }), raw: null });
  try {
    const r = await validateAtlasVersion();
    assert.equal(r.pinned, REPO_PINNED);
    assert.equal(r.latest, '9999.12');
    assert.equal(r.status, 'drift');
    assert.equal(r.drift, true);
    assert.equal(r.fetched_from, 'github-releases');
  } finally {
    restore();
  }
});

test('strips an "ATLAS-v" prefix from the upstream tag when normalizing', async () => {
  // normalizeVersion strips a leading ATLAS[-_ ]? then a leading v.
  const restore = stubFetch({ gh: jsonRes({ tag_name: 'ATLAS-v5.1.0' }), raw: null });
  try {
    const r = await validateAtlasVersion();
    assert.equal(r.latest, '5.1.0', 'ATLAS-v5.1.0 must normalize to 5.1.0');
  } finally {
    restore();
  }
});

test('falls back to raw ATLAS.yaml when the github releases API fails', async () => {
  const yaml = [
    'id: ATLAS',
    "version: '5.1.0'",
    'matrices:',
    '  - id: ATLAS',
  ].join('\n');
  const restore = stubFetch({ gh: jsonRes({ message: 'Not Found' }, 404), raw: textRes(yaml) });
  try {
    const r = await validateAtlasVersion();
    assert.equal(r.latest, '5.1.0', 'version line is scraped from the YAML');
    assert.equal(r.fetched_from, 'raw-yaml', 'fallback source must be recorded');
    // 5.1.0 vs the repo pin differs, so this is drift, not match.
    assert.equal(r.status, 'drift');
  } finally {
    restore();
  }
});

test('reports unreachable when both github and raw-yaml fail', async () => {
  const restore = stubFetch({ gh: null, raw: null });
  try {
    const r = await validateAtlasVersion();
    assert.equal(r.status, 'unreachable');
    assert.equal(r.latest, null);
    assert.equal(r.fetched_from, null);
    assert.ok(typeof r.error === 'string' && r.error.length > 0, 'an error string must be surfaced');
    // The pinned read still succeeds offline.
    assert.equal(r.pinned, REPO_PINNED);
    // No internal pin disagreement, so drift is false even when unreachable.
    assert.equal(r.drift, false);
  } finally {
    restore();
  }
});

test('treats a github response with no tag_name as a github failure and falls back to yaml', async () => {
  const yaml = "version: '7.2.1'\n";
  // gh returns 200 but with no tag_name/name -> fetchLatestFromGithubReleases !ok -> raw fallback.
  const restore = stubFetch({ gh: jsonRes({ message: 'ok but empty' }), raw: textRes(yaml) });
  try {
    const r = await validateAtlasVersion();
    assert.equal(r.fetched_from, 'raw-yaml');
    assert.equal(r.latest, '7.2.1');
  } finally {
    restore();
  }
});

test('reports unreachable when github has no tag and the yaml has no version line', async () => {
  const yaml = "id: ATLAS\nmatrices: []\n"; // no top-level version: line
  const restore = stubFetch({ gh: jsonRes({}), raw: textRes(yaml) });
  try {
    const r = await validateAtlasVersion();
    assert.equal(r.status, 'unreachable', 'a yaml with no version line is not a successful upstream read');
    assert.equal(r.latest, null);
  } finally {
    restore();
  }
});

test('result envelope always carries the documented fields', async () => {
  const restore = stubFetch({ gh: jsonRes({ tag_name: `v${REPO_PINNED}` }), raw: null });
  try {
    const r = await validateAtlasVersion();
    for (const k of ['pinned', 'pinned_sources', 'latest', 'drift', 'status', 'fetched_from', 'error']) {
      assert.ok(Object.prototype.hasOwnProperty.call(r, k), `result must carry "${k}"`);
    }
    assert.equal(typeof r.pinned_sources, 'object');
    assert.ok(Object.prototype.hasOwnProperty.call(r.pinned_sources, 'manifest'));
    assert.ok(Object.prototype.hasOwnProperty.call(r.pinned_sources, 'index'));
    assert.ok(['match', 'drift', 'unreachable', 'unknown'].includes(r.status));
  } finally {
    restore();
  }
});
