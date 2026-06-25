'use strict';

// ===========================================================================
// version-pin-validator — sources/validators/version-pin-validator.js
//
// checkAllPins(ctx) resolves each locally-pinned upstream catalog version
// (ATLAS / ATT&CK / D3FEND / CWE) from a caller-supplied context object and
// compares it against the latest stable GitHub release tag for that repo.
// Drift is REPORT-ONLY (never throws). We stub global.fetch per-repo so the
// whole comparison runs offline and exercises: the stable-release selection
// (skip draft + prerelease), "v"-prefix stripping, drift vs match, the
// unreachable branch (drift:null), and the ctx-resolution per pin name.
// ===========================================================================

const test = require('node:test');
const assert = require('node:assert/strict');

const { checkAllPins, PINS } = require('../sources/validators/version-pin-validator');

// --- fetch stubbing ---------------------------------------------------------

function releasesRes(arr, status = 200) {
  return { ok: status >= 200 && status < 300, status, json: async () => arr };
}

// routesByRepo: { '<owner/repo>': release-array | {httpError:status} | Error }
function stubFetch(routesByRepo) {
  const orig = global.fetch;
  global.fetch = async (url) => {
    const u = String(url);
    // URL shape: https://api.github.com/repos/<owner>/<repo>/releases?per_page=5
    const m = u.match(/repos\/([^/]+\/[^/]+)\/releases/);
    const repo = m ? m[1] : null;
    const route = repo != null ? routesByRepo[repo] : undefined;
    if (route === undefined) throw new Error('unexpected fetch in test: ' + u);
    if (route instanceof Error) throw route;
    if (route && route.httpError) return releasesRes([], route.httpError);
    return releasesRes(route);
  };
  return () => { global.fetch = orig; };
}

// Build a ctx whose four resolvable pins map to known local versions.
function ctx({ atlas = '2026.05', attack = '19.1', cwe = '4.18', d3fend = '1.5.0' } = {}) {
  return {
    manifest: { atlas_version: atlas, attack_version: attack },
    cweCatalog: cwe == null ? {} : { _meta: { version: cwe } },
    d3fendCatalog: d3fend == null ? {} : { _meta: { version: d3fend } },
  };
}

// A release-array where the first stable entry has the given tag, preceded by
// a draft and a prerelease that MUST be skipped.
function withNoise(tag) {
  return [
    { tag_name: 'v99.99', draft: true, prerelease: false, name: 'draft', html_url: 'u', published_at: 'd' },
    { tag_name: 'v98.98', draft: false, prerelease: true, name: 'rc', html_url: 'u', published_at: 'd' },
    { tag_name: tag, draft: false, prerelease: false, name: 'stable', html_url: 'https://gh/' + tag, published_at: '2026-01-01' },
  ];
}

const REPOS = {
  atlas: 'mitre-atlas/atlas-data',
  attack: 'mitre-attack/attack-stix-data',
  d3fend: 'd3fend/d3fend-data',
  cwe: 'mitre/cwe',
};

// --- PINS table invariants --------------------------------------------------

test('PINS enumerates the four expected catalog pins with the required fields', () => {
  assert.equal(PINS.length, 4);
  const names = PINS.map(p => p.pin_name).sort();
  assert.deepEqual(names, ['atlas_version', 'attack_version', 'cwe_version', 'd3fend_version']);
  for (const p of PINS) {
    assert.equal(typeof p.pin_name, 'string');
    assert.ok(/^[^/]+\/[^/]+$/.test(p.repo), `repo must be owner/repo, got ${p.repo}`);
    assert.equal(typeof p.local_path_hint, 'string');
    assert.equal(p.strip_v_prefix, true);
  }
});

// --- match / drift ----------------------------------------------------------

test('reports no drift when every GitHub-release upstream tag matches the local pin', async () => {
  // Only atlas + attack publish GitHub releases and are fetched; cwe + d3fend
  // are tracked elsewhere and must NOT be fetched (no route provided for them).
  const restore = stubFetch({
    [REPOS.atlas]: withNoise('v2026.05'),
    [REPOS.attack]: withNoise('v19.1'),
  });
  try {
    const out = await checkAllPins(ctx());
    assert.equal(out.length, 4);
    const ghPins = out.filter(r => r.pin_name === 'atlas_version' || r.pin_name === 'attack_version');
    for (const r of ghPins) {
      assert.equal(r.drift, false, `${r.pin_name} should not drift (local ${r.local_version} vs latest ${r.latest_version})`);
      assert.equal(r.unreachable, undefined);
      assert.equal(r.tracked_elsewhere, undefined);
    }
    const atlas = out.find(r => r.pin_name === 'atlas_version');
    assert.equal(atlas.local_version, '2026.05');
    assert.equal(atlas.latest_version, '2026.05', 'the "v" prefix must be stripped from the upstream tag');
  } finally {
    restore();
  }
});

// --- non-GitHub-release pins (CWE, D3FEND): tracked elsewhere, never fetched
// Regression for: PINS listed mitre/cwe + d3fend/d3fend-data, which publish no
// GitHub releases, so the live path fired a doomed releases API call and
// surfaced two spurious `unreachable` errors the cache path never produced.
// They must now be reported as tracked_elsewhere (drift:null, no error, no fetch).

test('CWE and D3FEND pins are tracked elsewhere and never hit the GitHub releases API', async () => {
  let fetched = false;
  // Provide routes ONLY for the two GitHub-release repos. If checkAllPins tried
  // to fetch cwe/d3fend, stubFetch would throw "unexpected fetch in test".
  const restore = stubFetch({
    [REPOS.atlas]: withNoise('v2026.05'),
    [REPOS.attack]: withNoise('v19.1'),
  });
  const origFetch = global.fetch;
  global.fetch = async (url) => { fetched = true; return origFetch(url); };
  try {
    const out = await checkAllPins(ctx({ cwe: '4.18', d3fend: '1.5.0' }));
    const cwe = out.find(r => r.pin_name === 'cwe_version');
    const d3 = out.find(r => r.pin_name === 'd3fend_version');

    // Tracked-elsewhere shape — exact values AND types.
    for (const r of [cwe, d3]) {
      assert.equal(r.tracked_elsewhere, true);
      assert.equal(r.drift, null, 'a non-release-publishing pin must not synthesize a drift signal');
      assert.equal(r.latest_version, null);
      assert.equal(r.unreachable, undefined, 'must NOT be reported as unreachable');
      assert.equal(r.error, undefined, 'must carry no error — it is intentionally not compared here');
      assert.equal(typeof r.tracked_via, 'string');
      assert.match(r.tracked_via, /upstream-check\.js/);
    }
    // Local versions still resolve from their catalogs.
    assert.equal(cwe.local_version, '4.18', 'cwe local comes from cweCatalog._meta.version');
    assert.equal(d3.local_version, '1.5.0', 'd3fend local comes from d3fendCatalog._meta.version');
  } finally {
    global.fetch = origFetch;
    restore();
  }
  assert.equal(fetched, true, 'the GitHub-release pins (atlas/attack) are still fetched');
});

test('reports drift when an upstream tag is newer than the local pin', async () => {
  const restore = stubFetch({
    [REPOS.atlas]: withNoise('v2027.01'),  // newer than 2026.05
    [REPOS.attack]: withNoise('v19.1'),
    [REPOS.d3fend]: withNoise('v1.5.0'),
    [REPOS.cwe]: withNoise('v4.18'),
  });
  try {
    const out = await checkAllPins(ctx());
    const atlas = out.find(r => r.pin_name === 'atlas_version');
    assert.equal(atlas.drift, true);
    assert.equal(atlas.local_version, '2026.05');
    assert.equal(atlas.latest_version, '2027.01');
    assert.equal(atlas.source_url, 'https://gh/v2027.01');
    assert.equal(atlas.latest_release_name, 'stable');
    assert.equal(atlas.latest_published_at, '2026-01-01');
    // The other three still match.
    assert.equal(out.filter(r => r.drift === true).length, 1);
  } finally {
    restore();
  }
});

test('skips draft and prerelease entries when picking the latest stable tag', async () => {
  // Only the third entry is stable; if the validator picked entry[0]/[1] the
  // version would be 99.99/98.98 and drift would be true.
  const restore = stubFetch({
    [REPOS.atlas]: withNoise('v2026.05'),
    [REPOS.attack]: withNoise('v19.1'),
    [REPOS.d3fend]: withNoise('v1.5.0'),
    [REPOS.cwe]: withNoise('v4.18'),
  });
  try {
    const out = await checkAllPins(ctx());
    const attack = out.find(r => r.pin_name === 'attack_version');
    assert.equal(attack.latest_version, '19.1', 'draft/prerelease entries must be ignored');
    assert.equal(attack.drift, false);
  } finally {
    restore();
  }
});

// --- unreachable / error paths ---------------------------------------------

test('an HTTP error on one repo yields unreachable with drift:null, others unaffected', async () => {
  const restore = stubFetch({
    [REPOS.atlas]: { httpError: 403 },               // rate limited
    [REPOS.attack]: withNoise('v19.1'),
    [REPOS.d3fend]: withNoise('v1.5.0'),
    [REPOS.cwe]: withNoise('v4.18'),
  });
  try {
    const out = await checkAllPins(ctx());
    const atlas = out.find(r => r.pin_name === 'atlas_version');
    assert.equal(atlas.unreachable, true);
    assert.equal(atlas.drift, null, 'unreachable must report drift:null, not a boolean');
    assert.equal(atlas.latest_version, null);
    assert.equal(atlas.error, 'HTTP 403');
    assert.ok(typeof atlas.source_url === 'string');
    // The reachable ones still resolve.
    assert.equal(out.find(r => r.pin_name === 'attack_version').drift, false);
  } finally {
    restore();
  }
});

test('a thrown fetch is caught and surfaced as unreachable (never throws)', async () => {
  const restore = stubFetch({
    [REPOS.atlas]: withNoise('v2026.05'),
    [REPOS.attack]: Object.assign(new Error('ECONNRESET'), { code: 'ECONNRESET' }),
    [REPOS.d3fend]: withNoise('v1.5.0'),
    [REPOS.cwe]: withNoise('v4.18'),
  });
  try {
    const out = await checkAllPins(ctx());
    const attack = out.find(r => r.pin_name === 'attack_version');
    assert.equal(attack.unreachable, true);
    assert.equal(attack.drift, null);
    assert.ok(/ECONNRESET/.test(attack.error));
  } finally {
    restore();
  }
});

test('an empty release array (no stable release) is unreachable', async () => {
  const restore = stubFetch({
    [REPOS.atlas]: [],                                // no entries at all
    [REPOS.attack]: withNoise('v19.1'),
    [REPOS.d3fend]: withNoise('v1.5.0'),
    [REPOS.cwe]: withNoise('v4.18'),
  });
  try {
    const out = await checkAllPins(ctx());
    const atlas = out.find(r => r.pin_name === 'atlas_version');
    assert.equal(atlas.unreachable, true);
    assert.equal(atlas.error, 'no stable release found');
  } finally {
    restore();
  }
});

// --- local-version resolution ----------------------------------------------

test('a missing local pin resolves to null and drift is false (cannot compare)', async () => {
  // drift is `local != null && latest != null && local !== latest`. With a null
  // local version the comparison is suppressed -> drift false. Asserted against
  // a GitHub-release pin (atlas), since cwe/d3fend are tracked elsewhere.
  const restore = stubFetch({
    [REPOS.atlas]: withNoise('v2026.05'),
    [REPOS.attack]: withNoise('v19.1'),
  });
  try {
    const out = await checkAllPins(ctx({ atlas: null })); // manifest has no atlas_version
    const atlas = out.find(r => r.pin_name === 'atlas_version');
    assert.equal(atlas.local_version, null);
    assert.equal(atlas.latest_version, '2026.05');
    assert.equal(atlas.drift, false, 'no local version means no drift signal, not a false positive');
  } finally {
    restore();
  }
});

test('cwe and d3fend versions are read from their catalog _meta, atlas/attack from manifest', async () => {
  const restore = stubFetch({
    [REPOS.atlas]: withNoise('v2026.05'),
    [REPOS.attack]: withNoise('v19.1'),
  });
  try {
    const out = await checkAllPins(ctx({ cwe: '4.18', d3fend: '1.5.0' }));
    const cwe = out.find(r => r.pin_name === 'cwe_version');
    const d3 = out.find(r => r.pin_name === 'd3fend_version');
    assert.equal(cwe.local_version, '4.18', 'cwe local comes from cweCatalog._meta.version');
    assert.equal(d3.local_version, '1.5.0', 'd3fend local comes from d3fendCatalog._meta.version');
    // Neither has a GitHub release to compare against — tracked elsewhere, so
    // drift is null (no signal) rather than a synthesized true/false.
    assert.equal(cwe.drift, null);
    assert.equal(d3.drift, null);
  } finally {
    restore();
  }
});
