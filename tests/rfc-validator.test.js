'use strict';

// ===========================================================================
// rfc-validator — sources/validators/rfc-validator.js
//
// validateRfc(id, entry) derives a Datatracker doc name from the catalog key,
// fetches the document, and compares the local std-level against Datatracker's
// std_level code, returning match / drift / missing / unreachable. Bad-shaped
// keys short-circuit to drift BEFORE any network call. We stub global.fetch so
// the network branches run offline and exercise the real comparison logic and
// status mapping; the bad-key paths need no stub at all.
// ===========================================================================

const test = require('node:test');
const assert = require('node:assert/strict');

const { validateRfc, validateAllRfcs } = require('../sources/validators/rfc-validator');

// --- fetch stubbing ---------------------------------------------------------

// Build a Datatracker /doc/document/ list response with a single object.
function datatrackerRes(obj, status = 200) {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: async () => ({ objects: obj === null ? [] : [obj] }),
  };
}

// captured: array the stub pushes each requested URL into (to assert which
// doc name was derived). routeFn(url) -> response | Error.
function stubFetch(routeFn, captured) {
  const orig = global.fetch;
  global.fetch = async (url) => {
    if (captured) captured.push(String(url));
    const r = routeFn(String(url));
    if (r instanceof Error) throw r;
    return r;
  };
  return () => { global.fetch = orig; };
}

// --- bad-key short-circuits (no network) -----------------------------------

test('a non-IETF catalog key shape returns skipped without fetching', async () => {
  // A BCP key is not an IETF RFC/DRAFT this validator can resolve on
  // Datatracker. It short-circuits before any network call and is reported as
  // 'skipped' (out of scope) rather than a permanent false-positive drift.
  let fetched = false;
  const orig = global.fetch;
  global.fetch = async () => { fetched = true; throw new Error('should not fetch'); };
  try {
    const r = await validateRfc('BCP-195', { status: 'Best Current Practice' });
    assert.equal(r.status, 'skipped');
    assert.equal(r.fetched, null);
    assert.deepEqual(r.discrepancies, []);
    assert.equal(fetched, false, 'a non-IETF key must short-circuit before any network call');
  } finally {
    global.fetch = orig;
  }
});

test('a non-IETF catalog key (CSAF/ISO) returns skipped, not drift, without fetching', async () => {
  // Regression: validateRfc used to return status:'drift' with an
  // "unrecognized catalog key shape" discrepancy for every non-IETF reference
  // (CSAF-2.0, ISO-29147, ISO-30111). Datatracker only tracks IETF documents,
  // so these have no upstream to diff against — they must be 'skipped', NOT a
  // permanent false-positive drift.
  for (const key of ['CSAF-2.0', 'ISO-29147', 'ISO-30111']) {
    let fetched = false;
    const orig = global.fetch;
    global.fetch = async () => { fetched = true; throw new Error('should not fetch'); };
    try {
      const r = await validateRfc(key, { status: 'Standard' });
      assert.equal(r.status, 'skipped', `${key} must be skipped, not drift`);
      assert.deepEqual(r.discrepancies, [], 'a skipped non-IETF key must carry no discrepancies');
      assert.equal(r.fetched, null);
      assert.equal(r.id, key);
      assert.equal(fetched, false, 'a non-IETF key must short-circuit before any network call');
    } finally {
      global.fetch = orig;
    }
  }
});

test('an RFC key that cannot derive a doc name returns drift', async () => {
  // "RFC-" with no digits fails rfcNumberFromKey -> docName null.
  let fetched = false;
  const orig = global.fetch;
  global.fetch = async () => { fetched = true; throw new Error('should not fetch'); };
  try {
    const r = await validateRfc('RFC-', { status: 'Proposed Standard' });
    assert.equal(r.status, 'drift');
    assert.equal(r.fetched, null);
    assert.ok(r.discrepancies.some(d => /could not derive Datatracker doc name/.test(d)));
    assert.equal(fetched, false);
  } finally {
    global.fetch = orig;
  }
});

// --- doc-name derivation (asserted via the requested URL) -------------------

test('derives "rfcNNNN" for an RFC key and "draft-..." for a DRAFT key', async () => {
  const seen = [];
  const restore = stubFetch(() => datatrackerRes({ std_level: 'ps' }), seen);
  try {
    await validateRfc('RFC-8446', { status: 'Proposed Standard' });
    await validateRfc('DRAFT-IETF-TLS-ECDHE-MLKEM', { status: 'Experimental' });
    assert.ok(seen[0].includes('name=rfc8446'), `expected rfc8446 in ${seen[0]}`);
    assert.ok(
      seen[1].includes('name=draft-ietf-tls-ecdhe-mlkem'),
      `DRAFT key must lowercase + hyphenate to draft-ietf-tls-ecdhe-mlkem, got ${seen[1]}`
    );
  } finally {
    restore();
  }
});

// --- status comparison ------------------------------------------------------

test('reports match when Datatracker std_level maps to the local status', async () => {
  // 'ps' -> 'Proposed Standard'
  const restore = stubFetch(() => datatrackerRes({ std_level: 'ps' }));
  try {
    const r = await validateRfc('RFC-8446', { status: 'Proposed Standard' });
    assert.equal(r.status, 'match');
    assert.deepEqual(r.discrepancies, []);
    assert.equal(r.id, 'RFC-8446');
    assert.equal(r.fetched.std_level, 'ps', 'the upstream object is returned on the result');
  } finally {
    restore();
  }
});

test('reports drift when the local status disagrees with Datatracker std_level', async () => {
  // upstream 'std' -> 'Internet Standard', local says 'Proposed Standard'.
  const restore = stubFetch(() => datatrackerRes({ std_level: 'std' }));
  try {
    const r = await validateRfc('RFC-2026', { status: 'Proposed Standard' });
    assert.equal(r.status, 'drift');
    assert.equal(r.discrepancies.length, 1);
    assert.ok(/status drift/.test(r.discrepancies[0]));
    assert.ok(/Proposed Standard/.test(r.discrepancies[0]));
    assert.ok(/Internet Standard/.test(r.discrepancies[0]));
  } finally {
    restore();
  }
});

test('does not flag status drift when the std_level code is unknown to the map', async () => {
  // 'xyz' is not in DATATRACKER_TO_LOCAL -> upstreamStatusHuman undefined -> no discrepancy.
  const restore = stubFetch(() => datatrackerRes({ std_level: 'xyz' }));
  try {
    const r = await validateRfc('RFC-1', { status: 'Proposed Standard' });
    assert.equal(r.status, 'match', 'an unmappable upstream code must not synthesize a false drift');
  } finally {
    restore();
  }
});

// --- missing / unreachable --------------------------------------------------

test('reports missing when Datatracker returns an empty object list', async () => {
  const restore = stubFetch(() => datatrackerRes(null)); // objects: []
  try {
    const r = await validateRfc('RFC-99999', { status: 'Proposed Standard' });
    assert.equal(r.status, 'missing');
    assert.equal(r.fetched, null);
  } finally {
    restore();
  }
});

test('reports missing on an HTTP 404', async () => {
  const restore = stubFetch(() => ({ ok: false, status: 404, json: async () => ({}) }));
  try {
    const r = await validateRfc('RFC-404', { status: 'Proposed Standard' });
    assert.equal(r.status, 'missing');
  } finally {
    restore();
  }
});

test('reports unreachable when the fetch throws', async () => {
  const restore = stubFetch(() => new Error('socket hang up'));
  try {
    const r = await validateRfc('RFC-8446', { status: 'Proposed Standard' });
    assert.equal(r.status, 'unreachable');
    assert.equal(r.fetched, null);
    assert.ok(/socket hang up/.test(r.reason));
  } finally {
    restore();
  }
});

test('reports unreachable on a non-404 HTTP error', async () => {
  const restore = stubFetch(() => ({ ok: false, status: 503, json: async () => ({}) }));
  try {
    const r = await validateRfc('RFC-8446', { status: 'Proposed Standard' });
    assert.equal(r.status, 'unreachable');
    assert.ok(/HTTP 503/.test(r.reason));
  } finally {
    restore();
  }
});

// --- validateAllRfcs --------------------------------------------------------

test('validateAllRfcs skips "_"-prefixed meta keys and validates the rest', async () => {
  const restore = stubFetch((url) => {
    // rfc8446 -> match (ps); rfc2026 -> drift (std vs local ps)
    if (url.includes('name=rfc8446')) return datatrackerRes({ std_level: 'ps' });
    if (url.includes('name=rfc2026')) return datatrackerRes({ std_level: 'std' });
    return datatrackerRes(null);
  });
  try {
    const refs = {
      _meta: { generated_at: 'x' },           // must be skipped
      'RFC-8446': { status: 'Proposed Standard' },
      'RFC-2026': { status: 'Proposed Standard' },
    };
    const results = await validateAllRfcs(refs, { concurrency: 2 });
    assert.equal(results.length, 2, '_meta must not be validated');
    const byId = Object.fromEntries(results.map(r => [r.id, r.status]));
    assert.equal(byId['RFC-8446'], 'match');
    assert.equal(byId['RFC-2026'], 'drift');
    assert.ok(!('_meta' in byId));
  } finally {
    restore();
  }
});

test('validateAllRfcs excludes non-IETF keys (CSAF/ISO) and only validates RFC/DRAFT keys', async () => {
  // Regression: these keys used to be validated and reported as permanent
  // drift. They must be filtered out entirely — no result entry, no fetch.
  const requested = [];
  const restore = stubFetch((url) => {
    if (url.includes('name=rfc8446')) return datatrackerRes({ std_level: 'ps' });
    return datatrackerRes(null);
  }, requested);
  try {
    const refs = {
      _meta: { generated_at: 'x' },
      'RFC-8446': { status: 'Proposed Standard' },
      'CSAF-2.0': { status: 'Standard' },
      'ISO-29147': { status: 'Standard' },
      'ISO-30111': { status: 'Standard' },
    };
    const results = await validateAllRfcs(refs, { concurrency: 4 });
    assert.equal(results.length, 1, 'only the RFC key is validated; non-IETF + _meta are excluded');
    assert.equal(results[0].id, 'RFC-8446');
    assert.equal(results[0].status, 'match');
    const ids = results.map(r => r.id);
    assert.ok(!ids.includes('CSAF-2.0'));
    assert.ok(!ids.includes('ISO-29147'));
    assert.ok(!ids.includes('ISO-30111'));
    // No fetch was ever issued for a non-IETF key.
    assert.ok(requested.every(u => u.includes('name=rfc8446')),
      `only rfc8446 should be fetched, saw: ${JSON.stringify(requested)}`);
  } finally {
    restore();
  }
});

test('validateAllRfcs returns an empty array when there are no real refs', async () => {
  let fetched = false;
  const orig = global.fetch;
  global.fetch = async () => { fetched = true; throw new Error('should not fetch'); };
  try {
    const results = await validateAllRfcs({ _meta: {} });
    assert.deepEqual(results, []);
    assert.equal(fetched, false, 'a refs object with only meta keys triggers no fetches');
  } finally {
    global.fetch = orig;
  }
});
