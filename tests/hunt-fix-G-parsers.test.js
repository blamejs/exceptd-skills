'use strict';

/**
 * tests/hunt-fix-G-parsers.test.js
 *
 * Regression coverage for the G-parsers cluster:
 *   #31 lib/xml-tokenizer.js — unescaped '<' in a leaf field (title/body)
 *        corrupted the field and silently dropped a title-only CVE.
 *   #32 lib/source-advisories.js — the tokenizer loud-error contract was
 *        opt-in and the live RSS/Atom path never opted in, so parse errors
 *        were silently discarded ('0 new CVEs' instead of 'feed unparsable').
 *   #33 lib/xml-tokenizer.js — Atom multi-<link> capture took the LAST href
 *        regardless of rel; advisory_url could point at rel=self/replies.
 *   #34 lib/ttp-mapper.js — coverage() with an empty/short/non-string
 *        frameworkId matched EVERY control via includes('') (and threw on
 *        null/undefined).
 *
 * Each case fails on the pre-fix behavior and passes after the root-cause fix.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');

const T = require(path.join(__dirname, '..', 'lib', 'xml-tokenizer.js'));
const SA = require(path.join(__dirname, '..', 'lib', 'source-advisories.js'));
const mapper = require(path.join(__dirname, '..', 'lib', 'ttp-mapper.js'));

// ---------------------------------------------------------------------------
// Finding #31 — stray unescaped '<' in a leaf field no longer drops the field.
// Three lead chars after '<': space, digit, letter.
// ---------------------------------------------------------------------------

test('#31 space-led stray "<" in title keeps the field non-empty and the CVE recoverable', () => {
  const xml = '<rss><channel><item>'
    + '<title>CVE-2026-33333 affects versions < 5.0</title>'
    + '<link>https://c</link></item></channel></rss>';
  const items = T.parseFeed(xml);
  assert.equal(items.length, 1);
  assert.equal(typeof items[0].title, 'string');
  assert.ok(items[0].title.length > 0, 'title must not be empty');
  assert.match(items[0].title, /CVE-2026-33333/);
  // The literal "< 5.0" survives to display form (stripHtml only removes real
  // <tag> shapes, and "< 5.0" has no closing '>').
  assert.match(items[0].title, /<\s*5\.0/);
});

test('#31 digit-led stray "<5.0" in title keeps the field non-empty and the CVE recoverable', () => {
  const xml = '<rss><channel><item>'
    + '<title>CVE-2026-33333 affects <5.0 versions</title>'
    + '<link>https://c</link></item></channel></rss>';
  const items = T.parseFeed(xml);
  assert.equal(typeof items[0].title, 'string');
  assert.ok(items[0].title.length > 0);
  assert.match(items[0].title, /CVE-2026-33333/);
});

test('#31 letter-led stray "<here>" in title keeps the field non-empty and the CVE recoverable', () => {
  // This is the case the verifier flagged: a letter-led pseudo-tag. It must
  // still be tolerated (stripHtml collapses "<here>" away) without dropping
  // the surrounding CVE text.
  const xml = '<rss><channel><item>'
    + '<title>CVE-2026-33333 <here> bypass</title>'
    + '<link>https://c</link></item></channel></rss>';
  const items = T.parseFeed(xml);
  assert.equal(typeof items[0].title, 'string');
  assert.ok(items[0].title.length > 0);
  assert.match(items[0].title, /CVE-2026-33333/);
  // "<here>" is a tag shape with a closing '>', so stripHtml removes it.
  assert.ok(!/<here>/.test(items[0].title), 'pseudo-tag should collapse via stripHtml');
});

test('#31 a stray "<" inside an otherwise-closed leaf records NO spurious unterminated error', () => {
  const errors = [];
  const xml = '<rss><channel><item>'
    + '<title>CVE-2026-33333 affects versions < 5.0</title>'
    + '<link>https://c</link></item></channel></rss>';
  T.parseFeed(xml, errors);
  assert.deepEqual(errors, [], 'a closed leaf with a stray < must not surface an error');
});

test('#31 extractCveIds recovers the CVE from a title-only item with a stray "<"', () => {
  const xml = '<rss><channel><item>'
    + '<title>CVE-2026-33333 affects versions < 5.0</title>'
    + '<link>https://c</link></item></channel></rss>';
  const items = T.parseFeed(xml);
  const ids = SA.extractCveIds(`${items[0].title} ${items[0].body} ${items[0].link}`);
  assert.deepEqual(ids, ['CVE-2026-33333']);
  assert.ok(Array.isArray(ids));
});

test('#31 GENUINELY truncated leaf (no later close tag) still surfaces a loud unterminated error', () => {
  // The fix only reclassifies the false-positive "stray < inside a closed
  // leaf" case as text — a real truncation must still record errors[].
  const errors = [];
  const items = T.parseFeed('<rss><item><title>unterminated', errors);
  assert.equal(items.length, 0);
  assert.ok(errors.length > 0, 'truncated input must surface errors[]');
  assert.match(errors[0].message, /unterminated/i);
});

test('#31 CDATA title still strips inner HTML and preserves inner text (unchanged)', () => {
  const xml = '<rss><channel><item>'
    + '<title><![CDATA[CVE-2026-99999 <b>bold</b> bypass]]></title>'
    + '<link>https://example.com</link>'
    + '<description><![CDATA[<p>html in body</p>]]></description>'
    + '</item></channel></rss>';
  const items = T.parseFeed(xml);
  assert.equal(items[0].title, 'CVE-2026-99999 bold bypass');
  assert.equal(items[0].body, 'html in body');
});

test('#31 entity-escaped <script> in title decodes then strips (unchanged)', () => {
  const xml = '<rss><channel><item>'
    + '<title>CVE-2026 &amp; the &lt;script&gt; bypass</title>'
    + '<link>https://example.com</link></item></channel></rss>';
  const items = T.parseFeed(xml);
  assert.equal(items[0].title, 'CVE-2026 & the bypass');
});

// ---------------------------------------------------------------------------
// Finding #33 — rel-aware Atom <link> selection (first-alternate-wins).
// ---------------------------------------------------------------------------

test('#33 alternate link wins when rel=self appears BEFORE rel=alternate', () => {
  const xml = '<feed><entry><title>t</title>'
    + '<link rel="self" href="https://feed-self"/>'
    + '<link rel="alternate" href="https://article"/>'
    + '</entry></feed>';
  const items = T.parseFeed(xml);
  assert.equal(items[0].link, 'https://article');
});

test('#33 alternate link wins when rel=alternate appears BEFORE rel=self (no clobber)', () => {
  const xml = '<feed><entry><title>t</title>'
    + '<link rel="alternate" href="https://article"/>'
    + '<link rel="self" href="https://feed-self"/>'
    + '</entry></feed>';
  const items = T.parseFeed(xml);
  assert.equal(items[0].link, 'https://article');
});

test('#33 only self/edit links → non-alternate fills the slot (non-empty fallback)', () => {
  const xml = '<feed><entry><title>t</title>'
    + '<link rel="self" href="https://feed-self"/>'
    + '<link rel="edit" href="https://edit"/>'
    + '</entry></feed>';
  const items = T.parseFeed(xml);
  assert.equal(typeof items[0].link, 'string');
  assert.ok(items[0].link.length > 0);
  // First non-alternate seen fills the empty slot; a later non-alternate must
  // not clobber it.
  assert.equal(items[0].link, 'https://feed-self');
});

test('#33 RSS <link>text</link> is authoritative', () => {
  const xml = '<rss><channel><item><title>t</title>'
    + '<link>https://rss-text</link></item></channel></rss>';
  const items = T.parseFeed(xml);
  assert.equal(items[0].link, 'https://rss-text');
});

test('#33 Atom <link href> with NO rel populates the link (defaults to alternate)', () => {
  const xml = '<feed><entry><title>t</title>'
    + '<link href="https://norel"/></entry></feed>';
  const items = T.parseFeed(xml);
  assert.equal(items[0].link, 'https://norel');
});

// ---------------------------------------------------------------------------
// Finding #32 — parse errors surface on the LIVE checkFeed/fetchDiff path.
// ---------------------------------------------------------------------------

function allFixtures(overrides) {
  const fx = {};
  for (const f of SA.FEEDS) {
    fx[f.name] = f.kind === 'csaf-index' ? 'rhsa-2026_0001.json\n'
      : f.kind === 'gitlab-activity' ? '<feed xmlns="http://www.w3.org/2005/Atom"></feed>'
      : '<rss><channel></channel></rss>';
  }
  return Object.assign(fx, overrides || {});
}

test('#32 a reachable-but-unparsable RSS feed yields status=partial with parse_errors>0', async () => {
  const fixtures = allFixtures({ qualys: '<rss><channel><item><title>unterminated' });
  const r = await SA.ADVISORIES_SOURCE.fetchDiff({ fixtures: { advisories: fixtures }, cveCatalog: {} });
  assert.equal(r.status, 'partial');
  assert.equal(typeof r.parse_errors, 'number');
  assert.ok(r.parse_errors > 0);
  assert.ok(Array.isArray(r._parse_errors) && r._parse_errors.length > 0);
  assert.match(r._parse_errors[0].message, /unterminated/i);
  // The integer `errors` field stays the unreachable count — unchanged.
  assert.equal(r.errors, 0);
  assert.match(r.summary, /returned parse errors/);
});

test('#32 well-formed feeds keep status=ok and parse_errors=0 (no false partial)', async () => {
  const fixtures = allFixtures({
    qualys: '<rss><channel><item><title>CVE-2026-99001 disclosed</title>'
      + '<link>https://q/1</link><pubDate>2026-05-14</pubDate><description></description></item></channel></rss>',
  });
  const r = await SA.ADVISORIES_SOURCE.fetchDiff({ fixtures: { advisories: fixtures }, cveCatalog: {} });
  assert.equal(r.status, 'ok');
  assert.equal(r.parse_errors, 0);
  assert.deepEqual(r._parse_errors, []);
});

test('#32 checkFeed-level partial: parseRssAtom always collects errors (channel cannot be dropped)', () => {
  // The opt-in array still works...
  const errors = [];
  SA.parseRssAtom('<rss><channel><item><title>unterminated', errors);
  assert.ok(errors.length > 0);
  assert.match(errors[0].message, /unterminated/i);
  // ...and parseFeedDetailed returns the channel unconditionally.
  const detailed = T.parseFeedDetailed('<rss><channel><item><title>unterminated');
  assert.ok(Array.isArray(detailed.items));
  assert.ok(Array.isArray(detailed.errors));
  assert.ok(detailed.errors.length > 0);
  assert.match(detailed.errors[0].message, /unterminated/i);
});

// ---------------------------------------------------------------------------
// Finding #34 — coverage() input guard + token-boundary framework match.
// ---------------------------------------------------------------------------

const atlasStub = {
  'AML.TEST': {
    name: 'Test',
    framework_gap: true,
    controls_that_partially_help: ['NIST-800-53-X', 'iso-27001-y'],
    controls_that_dont_help: ['soc2-z'],
    framework_gap_detail: 'detail',
    detection: 'none',
  },
};

test('#34 empty-string frameworkId no longer universal-matches — partially_covered_by is null', () => {
  const r = mapper.coverage('', 'AML.TEST', {}, atlasStub);
  assert.equal(r.partially_covered_by, null);
  assert.equal(r.not_covered_by, null);
  assert.equal(r.found, false);
  assert.equal(r.error, 'frameworkId required');
});

test('#34 a short prefix "IS" must NOT match "NIST-..." via token boundary', () => {
  const r = mapper.coverage('IS', 'AML.TEST', {}, atlasStub);
  assert.equal(r.partially_covered_by, null);
  assert.equal(r.not_covered_by, null);
});

test('#34 null / undefined frameworkId returns found:false WITHOUT throwing', () => {
  const rn = mapper.coverage(null, 'AML.TEST', {}, atlasStub);
  assert.equal(rn.found, false);
  assert.equal(rn.error, 'frameworkId required');
  const ru = mapper.coverage(undefined, 'AML.TEST', {}, atlasStub);
  assert.equal(ru.found, false);
  assert.equal(ru.error, 'frameworkId required');
});

test('#34 hyphen-led "-X" (empty first segment) fails closed, not universal-match', () => {
  const r = mapper.coverage('-X', 'AML.TEST', {}, atlasStub);
  assert.equal(r.found, false);
  assert.equal(r.partially_covered_by, null);
  assert.equal(r.not_covered_by, null);
});

test('#34 legitimate loose framework matching still works (token-boundary, case-insensitive)', () => {
  assert.equal(mapper.coverage('NIST-800-53', 'AML.TEST', {}, atlasStub).partially_covered_by, 'NIST-800-53-X');
  assert.equal(mapper.coverage('ISO-27001-2022', 'AML.TEST', {}, atlasStub).partially_covered_by, 'iso-27001-y');
  assert.equal(mapper.coverage('SOC2-CC6', 'AML.TEST', {}, atlasStub).not_covered_by, 'soc2-z');
});

test('#34 unknown TTP still returns found:false cleanly (guard runs first, no throw)', () => {
  const r = mapper.coverage('NIST-800-53', 'AML.NOPE', {}, atlasStub);
  assert.equal(r.found, false);
  assert.equal(r.ttp_id, 'AML.NOPE');
});
