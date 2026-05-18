'use strict';

/**
 * tests/source-advisories.test.js
 *
 * v0.13.1 primary-source advisory-feed poller. Closes the post-mortem
 * gap on CVE-2026-46333 (ssh-keysign-pwn) where the existing NVD-based
 * sources lagged disclosure by 3+ days.
 *
 * Tests cover:
 *   - Parser correctness on synthetic RSS / Atom / CSAF-index payloads
 *   - CVE-ID extraction permissiveness
 *   - The SOURCE contract shape (fetchDiff returns {status, diffs, errors, summary})
 *   - Deduplication across feeds when multiple advisories cite the same CVE
 *   - The report-only contract (applyDiff is a no-op + returns a note)
 *   - Fixture-mode integration through the ALL_SOURCES registry
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');
const { ADVISORIES_SOURCE, FEEDS, extractCveIds, parseRssAtom, parseCsafIndex } =
  require(path.join(ROOT, 'lib', 'source-advisories.js'));

// ---------- extractCveIds ----------

test('extractCveIds: pulls a single CVE from a sentence', () => {
  const ids = extractCveIds('Patch for CVE-2026-46333 released');
  assert.deepEqual(ids, ['CVE-2026-46333']);
});

test('extractCveIds: deduplicates within input', () => {
  const ids = extractCveIds('CVE-2024-3094 and CVE-2024-3094 are the same');
  assert.deepEqual(ids, ['CVE-2024-3094']);
});

test('extractCveIds: handles multiple distinct CVEs + uppercases', () => {
  const ids = extractCveIds('cve-2024-3094 plus CVE-2026-46333 plus cve-2023-12345');
  assert.deepEqual(ids.sort(), ['CVE-2023-12345', 'CVE-2024-3094', 'CVE-2026-46333']);
});

test('extractCveIds: rejects malformed IDs', () => {
  // 3-digit and 8-digit year, 3-digit and 8-digit serial — all invalid
  assert.deepEqual(extractCveIds('CVE-202-123 / CVE-99999-12345 / CVE-2024-12'), []);
});

test('extractCveIds: returns empty for non-string input', () => {
  assert.deepEqual(extractCveIds(null), []);
  assert.deepEqual(extractCveIds(undefined), []);
  assert.deepEqual(extractCveIds(123), []);
});

// ---------- parseRssAtom ----------

test('parseRssAtom: extracts RSS <item> blocks', () => {
  const rss = `<?xml version="1.0"?>
<rss><channel>
  <item>
    <title>CVE-2026-46333 patched</title>
    <link>https://example.org/cve-2026-46333</link>
    <pubDate>Wed, 14 May 2026 12:00:00 GMT</pubDate>
    <description>Linux kernel ptrace exit-race</description>
  </item>
  <item>
    <title>CVE-2026-99999 advisory</title>
    <link>https://example.org/cve-2026-99999</link>
    <pubDate>Thu, 15 May 2026 12:00:00 GMT</pubDate>
    <description>another</description>
  </item>
</channel></rss>`;
  const items = parseRssAtom(rss);
  assert.equal(items.length, 2);
  assert.equal(items[0].title, 'CVE-2026-46333 patched');
  assert.match(items[0].link, /example\.org\/cve-2026-46333/);
  assert.match(items[0].published, /14 May 2026/);
});

test('parseRssAtom: extracts Atom <entry> blocks', () => {
  const atom = `<?xml version="1.0"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <entry>
    <title>CVE-2026-12345 disclosed</title>
    <link href="https://example.org/advisory/1" />
    <published>2026-05-14T12:00:00Z</published>
    <summary>An advisory</summary>
  </entry>
</feed>`;
  const items = parseRssAtom(atom);
  assert.equal(items.length, 1);
  assert.equal(items[0].title, 'CVE-2026-12345 disclosed');
  assert.match(items[0].link, /advisory\/1/);
});

test('parseRssAtom: strips CDATA + HTML tags from extracted text', () => {
  const rss = `<rss><channel><item>
    <title><![CDATA[CVE-2026-46333 with <b>bold</b> markup]]></title>
    <description><![CDATA[<p>Description with HTML</p>]]></description>
    <link>https://x</link>
    <pubDate>x</pubDate>
  </item></channel></rss>`;
  const items = parseRssAtom(rss);
  assert.equal(items.length, 1);
  assert.equal(items[0].title, 'CVE-2026-46333 with bold markup');
  assert.equal(items[0].body, 'Description with HTML');
});

test('parseRssAtom: returns empty array for non-XML / empty input', () => {
  assert.deepEqual(parseRssAtom(''), []);
  assert.deepEqual(parseRssAtom(null), []);
  assert.deepEqual(parseRssAtom('garbage text no tags'), []);
});

// ---------- parseCsafIndex ----------

test('parseCsafIndex: parses newline-separated advisory filenames', () => {
  const text = 'rhsa-2026_1234.json\nrhsa-2026_5678.json\n';
  const items = parseCsafIndex(text);
  assert.equal(items.length, 2);
  assert.equal(items[0].title, 'rhsa-2026_1234.json');
});

test('parseCsafIndex: extracts CVE IDs embedded in filenames (case-insensitive)', () => {
  const text = 'cve-2026-46333.json\nrhsa-2026_1234-CVE-2024-3094.json\nadvisory-no-cve.json\n';
  const items = parseCsafIndex(text);
  // Case-insensitive matcher + uppercase-normalize means lowercase cve-* in
  // the filename DOES yield a hit on the canonical CVE-* form.
  assert.deepEqual(items[0].cves_from_filename, ['CVE-2026-46333']);
  assert.deepEqual(items[1].cves_from_filename, ['CVE-2024-3094']);
  assert.deepEqual(items[2].cves_from_filename, []);
});

// ---------- ADVISORIES_SOURCE registry ----------

test('ADVISORIES_SOURCE: name matches registry key + describes report-only contract', () => {
  assert.equal(ADVISORIES_SOURCE.name, 'advisories');
  assert.equal(ADVISORIES_SOURCE.applies_to, 'data/cve-catalog.json');
  assert.match(ADVISORIES_SOURCE.description, /report-only/i);
  assert.match(ADVISORIES_SOURCE.description, /Qualys/i);
  assert.match(ADVISORIES_SOURCE.description, /RHSA/i);
  assert.match(ADVISORIES_SOURCE.description, /USN/i);
  assert.match(ADVISORIES_SOURCE.description, /ZDI/i);
});

test('FEEDS: exactly 4 feeds (Qualys, RHSA, USN, ZDI)', () => {
  assert.equal(FEEDS.length, 4);
  const names = FEEDS.map((f) => f.name).sort();
  assert.deepEqual(names, ['qualys', 'rhsa', 'usn', 'zdi']);
});

test('FEEDS: every feed declares a URL + kind + description', () => {
  for (const f of FEEDS) {
    assert.equal(typeof f.url, 'string');
    assert.match(f.url, /^https:\/\//);
    assert.ok(['rss', 'csaf-index'].includes(f.kind), `feed ${f.name}: kind must be rss or csaf-index`);
    assert.equal(typeof f.description, 'string');
    assert.ok(f.description.length > 0);
  }
});

// ---------- fetchDiff: fixture-mode end-to-end ----------

test('fetchDiff: in fixture mode, surfaces CVE IDs not in catalog', async () => {
  const fixtures = {
    advisories: {
      qualys: `<rss><channel>
        <item><title>CVE-2026-99001 disclosed by Qualys TRU</title><link>https://qualys/1</link><pubDate>2026-05-14</pubDate><description></description></item>
      </channel></rss>`,
      usn: `<rss><channel>
        <item><title>USN-9999-1: CVE-2026-99001 fixed</title><link>https://ubuntu/9999</link><pubDate>2026-05-15</pubDate><description></description></item>
        <item><title>USN-9999-2: CVE-2024-3094 backport</title><link>https://ubuntu/9999-2</link><pubDate>2026-05-15</pubDate><description></description></item>
      </channel></rss>`,
      rhsa: 'rhsa-2026_0001.json\n',
      zdi: '<rss><channel></channel></rss>',
    },
  };
  const ctx = {
    fixtures,
    cveCatalog: { 'CVE-2024-3094': { name: 'already-in-catalog' } },
  };
  const result = await ADVISORIES_SOURCE.fetchDiff(ctx);
  assert.equal(result.status, 'ok');
  // CVE-2026-99001 is new; CVE-2024-3094 is in the catalog so it's filtered out.
  const ids = result.diffs.map((d) => d.id).sort();
  assert.deepEqual(ids, ['CVE-2026-99001']);
  // De-duplication across feeds: the same CVE-2026-99001 appeared in both
  // qualys and usn fixtures; should collapse to one diff with sources[] = [qualys, usn].
  const dup = result.diffs.find((d) => d.id === 'CVE-2026-99001');
  assert.deepEqual(dup.sources.sort(), ['qualys', 'usn']);
  assert.equal(dup.advisory_urls.length, 2, 'both source URLs preserved');
});

test('fetchDiff: returns unreachable status when all feeds fail', async () => {
  const ctx = {
    cacheDir: '/nonexistent/path/that/does/not/exist',
    cveCatalog: {},
  };
  const result = await ADVISORIES_SOURCE.fetchDiff(ctx);
  // All 4 feeds will fail to find their cache files.
  assert.equal(result.status, 'unreachable');
  assert.equal(result.errors, FEEDS.length);
});

// ---------- applyDiff: report-only contract ----------

test('applyDiff: is a no-op (report-only contract)', () => {
  const result = ADVISORIES_SOURCE.applyDiff({}, [{ id: 'CVE-9999-0001' }]);
  assert.equal(result.updated, 0);
  assert.equal(result.added, 0);
  assert.equal(result.drift_updated, 0);
  assert.deepEqual(result.errors, []);
  assert.match(result.note, /report-only/i);
  assert.match(result.note, /refresh --advisory/i,
    'note must point operators at the right enrichment path');
});

// ---------- ALL_SOURCES registry integration ----------

test('ALL_SOURCES includes advisories source under the canonical key', () => {
  const { ALL_SOURCES } = require(path.join(ROOT, 'lib', 'refresh-external.js'));
  assert.ok('advisories' in ALL_SOURCES, 'lib/refresh-external.js must register advisories source');
  assert.equal(ALL_SOURCES.advisories.name, 'advisories');
  assert.equal(typeof ALL_SOURCES.advisories.fetchDiff, 'function');
});
