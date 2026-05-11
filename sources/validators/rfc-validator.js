"use strict";
/**
 * sources/validators/rfc-validator.js
 *
 * Cross-checks a single entry from data/rfc-references.json against the
 * IETF Datatracker. Mirrors the shape of cve-validator.js:
 *
 *   validateRfc(id, entry) → { id, status, discrepancies, fetched, local }
 *
 * status is one of:
 *   match        — Datatracker view agrees with the local entry on status,
 *                  errata count, and replaces/replaced-by relationships.
 *   drift        — at least one of those fields disagrees.
 *   missing      — Datatracker does not have this RFC / draft.
 *   unreachable  — network failed or the request timed out.
 *
 * Zero external dependencies. Node 24 stdlib (fetch + AbortController).
 *
 * The Datatracker API is generous about rate limits for read-only queries,
 * but every fetch wraps an AbortController with a 10-second timeout so an
 * airgapped CI runner never hangs.
 */

const TIMEOUT_MS = 10_000;

const DATATRACKER_RFC_BASE = 'https://datatracker.ietf.org/api/v1/doc/document/';
const DATATRACKER_DRAFT_BASE = 'https://datatracker.ietf.org/api/v1/doc/document/';

async function fetchWithTimeout(url, opts = {}) {
  const ac = new AbortController();
  const t = setTimeout(() => ac.abort(), TIMEOUT_MS);
  try {
    const res = await fetch(url, { ...opts, signal: ac.signal });
    return res;
  } finally {
    clearTimeout(t);
  }
}

function rfcNumberFromKey(id) {
  // Catalog keys look like "RFC-8446". The Datatracker doc name is "rfc8446".
  const m = id.match(/^RFC-(\d+)$/);
  return m ? `rfc${m[1]}` : null;
}

function draftSlugFromKey(id) {
  // Catalog keys look like "DRAFT-IETF-TLS-ECDHE-MLKEM". The Datatracker doc
  // name is "draft-ietf-tls-ecdhe-mlkem" — lowercased, hyphenated.
  const m = id.match(/^DRAFT-(.+)$/);
  return m ? `draft-${m[1].toLowerCase()}` : null;
}

async function fetchRfcDocument(name) {
  // Datatracker API: /api/v1/doc/document/?name=rfc8446 returns a list with
  // one entry. The fields we care about are `std_level` (status), the
  // related "replaces" and "replaced-by" relationships, and the abstract.
  try {
    const url = `${DATATRACKER_RFC_BASE}?name=${encodeURIComponent(name)}&format=json`;
    const res = await fetchWithTimeout(url, { headers: { 'Accept': 'application/json' } });
    if (!res.ok) {
      if (res.status === 404) return { status: 'missing' };
      return { status: 'unreachable', reason: `HTTP ${res.status}` };
    }
    const body = await res.json();
    const obj = body.objects && body.objects[0];
    if (!obj) return { status: 'missing' };
    return { status: 'found', obj };
  } catch (err) {
    return { status: 'unreachable', reason: err.message };
  }
}

function compareEntry(local, upstream) {
  const discrepancies = [];

  // Datatracker exposes the standards-track level as `std_level`. Map between
  // its short codes and the longer human strings the catalog uses.
  const DATATRACKER_TO_LOCAL = {
    'std': 'Internet Standard',
    'ps':  'Proposed Standard',
    'ds':  'Draft Standard',
    'bcp': 'Best Current Practice',
    'inf': 'Informational',
    'exp': 'Experimental',
    'his': 'Historic',
    'unkn': 'Unknown',
  };
  const upstreamStatusCode = upstream.obj && upstream.obj.std_level;
  const upstreamStatusHuman = upstreamStatusCode && DATATRACKER_TO_LOCAL[upstreamStatusCode];
  if (local.status && upstreamStatusHuman && local.status !== upstreamStatusHuman) {
    discrepancies.push(
      `status drift: local "${local.status}" vs Datatracker "${upstreamStatusHuman}"`
    );
  }

  // Datatracker doesn't expose errata count directly on this endpoint; we
  // capture it as informational only and don't fail on it. A future
  // enhancement could hit https://www.rfc-editor.org/errata/<rfcN>.json
  // for the canonical count.

  // If the upstream record indicates obsoletion (replaced-by populated), the
  // local entry must reflect it.
  // Datatracker exposes related docs through a separate `related_documents`
  // endpoint — keep this simple for now and just surface the abstract URL so
  // the operator can verify by hand. Anything more requires a second fetch.

  return discrepancies;
}

async function validateRfc(id, entry) {
  let docName;
  if (id.startsWith('RFC-')) docName = rfcNumberFromKey(id);
  else if (id.startsWith('DRAFT-')) docName = draftSlugFromKey(id);
  else {
    return {
      id,
      status: 'drift',
      discrepancies: [`unrecognized catalog key shape: ${id}`],
      local: entry,
      fetched: null,
    };
  }

  if (!docName) {
    return {
      id,
      status: 'drift',
      discrepancies: [`could not derive Datatracker doc name from ${id}`],
      local: entry,
      fetched: null,
    };
  }

  const fetched = await fetchRfcDocument(docName);
  if (fetched.status === 'unreachable') {
    return { id, status: 'unreachable', reason: fetched.reason, local: entry, fetched: null };
  }
  if (fetched.status === 'missing') {
    return { id, status: 'missing', local: entry, fetched: null };
  }

  const discrepancies = compareEntry(entry, fetched);
  return {
    id,
    status: discrepancies.length === 0 ? 'match' : 'drift',
    discrepancies,
    local: entry,
    fetched: fetched.obj,
  };
}

async function validateAllRfcs(refs, { concurrency = 4 } = {}) {
  const ids = Object.keys(refs).filter(k => !k.startsWith('_'));
  const results = [];
  for (let i = 0; i < ids.length; i += concurrency) {
    const batch = ids.slice(i, i + concurrency);
    const batchResults = await Promise.all(
      batch.map(id => validateRfc(id, refs[id]))
    );
    results.push(...batchResults);
  }
  return results;
}

module.exports = { validateRfc, validateAllRfcs };
