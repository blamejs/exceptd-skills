"use strict";

/**
 * tests/xml-tokenizer.test.js
 *
 * Pins the real XML tokenizer that replaces the regex-based parser in
 * lib/source-advisories.js. Each failure mode the regex parser silently
 * dropped is now an explicit assertion.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");
const T = require(path.join(__dirname, "..", "lib", "xml-tokenizer.js"));

test("decodeEntities: the five canonical XML entities", () => {
  assert.equal(T.decodeEntities("&lt;a&gt; &amp; &apos; &quot;"), "<a> & ' \"");
});

test("decodeEntities: numeric character references (decimal + hex)", () => {
  assert.equal(T.decodeEntities("&#65; &#x41; &#x2014;"), "A A —");
});

test("decodeEntities: unknown named entities pass through unchanged", () => {
  // HTML-style entity in an RSS body is a recoverable variant we tolerate.
  assert.equal(T.decodeEntities("&nbsp;"), "&nbsp;");
});

test("localName strips namespace prefix", () => {
  assert.equal(T.localName("atom:entry"), "entry");
  assert.equal(T.localName("entry"), "entry");
});

test("parseAttrs handles single + double quoted values, whitespace around =", () => {
  const attrs = T.parseAttrs(`href="https://x" rel='alternate' type = "text/html"`);
  assert.deepEqual(attrs, { href: "https://x", rel: "alternate", type: "text/html" });
});

test("parseAttrs decodes entities inside attribute values", () => {
  const attrs = T.parseAttrs(`href="https://x?a=1&amp;b=2"`);
  assert.equal(attrs.href, "https://x?a=1&b=2");
});

test("parseFeed: extracts RSS <item> elements", () => {
  const xml = `<rss><channel>
    <item>
      <title>Sample RSS item</title>
      <link>https://example.com/a</link>
      <pubDate>Wed, 14 May 2026 12:00:00 GMT</pubDate>
      <description>body text</description>
    </item>
  </channel></rss>`;
  const items = T.parseFeed(xml);
  assert.equal(items.length, 1);
  assert.equal(items[0].title, "Sample RSS item");
  assert.equal(items[0].link, "https://example.com/a");
  assert.equal(items[0].body, "body text");
});

test("parseFeed: extracts Atom <entry> elements with namespace prefix", () => {
  // The regex parser silently failed on namespaced Atom feeds.
  const xml = `<atom:feed xmlns:atom="http://www.w3.org/2005/Atom">
    <atom:entry>
      <atom:title>Atom entry</atom:title>
      <atom:link href="https://example.com/atom" rel="alternate"/>
      <atom:published>2026-05-14T12:00:00Z</atom:published>
      <atom:summary>summary text</atom:summary>
    </atom:entry>
  </atom:feed>`;
  const items = T.parseFeed(xml);
  assert.equal(items.length, 1);
  assert.equal(items[0].title, "Atom entry");
  assert.equal(items[0].link, "https://example.com/atom",
    "self-closing <link href=...>/> must populate the link field via the href attribute");
  assert.equal(items[0].body, "summary text");
});

test("parseFeed: CDATA + HTML-tag stripping matches operator-display convention", () => {
  // Project convention (inherited from the v0.13.x regex parser): title +
  // body fields strip HTML tags whether the markup arrived via decoded
  // entities or verbatim through CDATA. Stripping is necessary so the
  // operator sees plain text in CVE-finding context; HTML formatting in
  // RSS titles is virtually always meant for the feed reader's display.
  const xml = `<rss><channel>
    <item>
      <title><![CDATA[CVE-2026-99999 <b>bold</b> bypass]]></title>
      <link>https://example.com</link>
      <description><![CDATA[<p>html in body</p>]]></description>
    </item>
  </channel></rss>`;
  const items = T.parseFeed(xml);
  assert.equal(items[0].title, "CVE-2026-99999 bold bypass",
    "HTML inside CDATA title must be stripped, inner text preserved");
  assert.equal(items[0].body, "html in body",
    "HTML inside CDATA description must be stripped, inner text preserved");
});

test("parseFeed: multi-line title content is preserved as single line", () => {
  const xml = `<rss><channel>
    <item>
      <title>
        Multi-line
        title with
        whitespace
      </title>
      <link>https://example.com</link>
    </item>
  </channel></rss>`;
  const items = T.parseFeed(xml);
  // The current contract trims leading/trailing whitespace but
  // preserves the internal whitespace as the parser saw it (the
  // streaming text events are concatenated verbatim).
  assert.match(items[0].title, /Multi-line[\s\S]*title with[\s\S]*whitespace/,
    "internal whitespace + newlines should be retained in the trimmed title");
});

test("parseFeed: malformed XML records errors[] instead of throwing", () => {
  const errors = [];
  const items = T.parseFeed("<rss><item><title>unterminated", errors);
  assert.equal(items.length, 0);
  assert.ok(errors.length > 0,
    "malformed XML must surface in errors[] — the regex parser failed silently here");
  assert.match(errors[0].message, /unterminated/i);
});

test("parseFeed: HTML entities decode and inner text survives tag-strip", () => {
  // &amp; → & survives; &lt;script&gt; decodes to <script> which then
  // gets stripped by the title HTML-tag stripper. Surviving text is
  // "CVE-2026 & the  bypass" — the operator's display form.
  const xml = `<rss><channel><item>
    <title>CVE-2026 &amp; the &lt;script&gt; bypass</title>
    <link>https://example.com</link>
  </item></channel></rss>`;
  const items = T.parseFeed(xml);
  assert.equal(items[0].title, "CVE-2026 & the bypass",
    "ampersand entity survives; tag-shaped entities decode then strip");
});

test("parseFeed: empty input returns empty array, not undefined", () => {
  assert.deepEqual(T.parseFeed(""), []);
  assert.deepEqual(T.parseFeed("<empty/>"), []);
});

test("stripHtml: strips HTML tags + collapses whitespace", () => {
  // Public export — pinned so a future regression (e.g. switching to
  // a different tag-stripping strategy that breaks the contract) fires.
  assert.equal(T.stripHtml("<p>hello <b>bold</b>   world</p>"), "hello bold world");
  assert.equal(T.stripHtml("plain text\nwith\nnewlines"), "plain text with newlines");
  assert.equal(T.stripHtml(""), "");
  assert.equal(T.stripHtml(null), "");
});

test("tokenize: streaming handlers fire in document order", () => {
  const events = [];
  T.tokenize("<a><b>text</b></a>", {
    onTagOpen: (n, a, sc) => events.push(["open", n, sc]),
    onTagClose: (n) => events.push(["close", n]),
    onText: (t) => events.push(["text", t])
  });
  assert.deepEqual(events, [
    ["open", "a", false],
    ["open", "b", false],
    ["text", "text"],
    ["close", "b"],
    ["close", "a"]
  ]);
});

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
