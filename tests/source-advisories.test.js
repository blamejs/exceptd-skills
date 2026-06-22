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
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');
const SA = require(path.join(ROOT, 'lib', 'source-advisories.js'));
const { ADVISORIES_SOURCE, FEEDS, extractCveIds, parseRssAtom, parseCsafIndex } = SA;
// The full module under another alias used by the intake-coverage pins below.
const SOURCE = SA;
// The XML tokenizer is the upstream parser source-advisories layers on; the
// extractCveIds + parseFeedDetailed paths below thread input through it.
const T = require(path.join(ROOT, 'lib', 'xml-tokenizer.js'));

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
  assert.match(items[0].link, /^https:\/\/example\.org\/cve-2026-46333$/);
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

test('FEEDS: exactly 15 feeds as of v0.13.17 — advisories + vendor security blogs + tech-press + researcher-handle tracker', () => {
  // v0.13.1 shipped 4 (qualys, rhsa, usn, zdi). v0.13.3 added 4 more
  // covering kernel.org commits (catches CVE-2026-46333-class at T+0),
  // oss-security coordinated disclosure, JFrog supply-chain research,
  // and CISA non-KEV advisories. v0.13.14 added 4 vendor security blogs
  // (microsoft-security-blog, sysdig-blog, trail-of-bits-blog,
  // embrace-the-red) to close the DirtyDecrypt-class intake gap where a
  // silent kernel patch + delayed-research-disclosure on a vendor blog
  // fell through the advisory-only feed set. v0.13.17 added 3 more
  // (bleepingcomputer-security, thehackernews, nightmare-eclipse — a GitLab
  // public-activity feed, migrated from GitHub after the account was removed)
  // to close the researcher-drop class anchored by MiniPlasma /
  // YellowKey / GreenPlasma / UnDefend.
  assert.equal(FEEDS.length, 15);
  const names = FEEDS.map((f) => f.name).sort();
  assert.deepEqual(names, [
    'bleepingcomputer-security',
    'cisa-current',
    'embrace-the-red',
    'jfrog',
    'kernel-org',
    'microsoft-security-blog',
    'nightmare-eclipse-gitlab',
    'oss-security',
    'qualys',
    'rhsa',
    'sysdig-blog',
    'thehackernews',
    'trail-of-bits-blog',
    'usn',
    'zdi',
  ]);
});

test('FEEDS: every feed declares a URL + kind + description', () => {
  for (const f of FEEDS) {
    assert.equal(typeof f.url, 'string');
    assert.match(f.url, /^https:\/\//);
    assert.ok(['rss', 'csaf-index', 'github-events', 'gitlab-activity'].includes(f.kind), `feed ${f.name}: kind must be rss, csaf-index, github-events, or gitlab-activity`);
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
      // v0.13.3: 4 additional feeds — provide empty fixture bodies so the
      // de-dup test still anchors on the qualys + usn pair without
      // unreachable-status contamination from the new feeds.
      'kernel-org': '<feed xmlns="http://www.w3.org/2005/Atom"></feed>',
      'oss-security': '<feed xmlns="http://www.w3.org/2005/Atom"></feed>',
      'jfrog': '<rss><channel></channel></rss>',
      'cisa-current': '<rss><channel></channel></rss>',
      // v0.13.14: 4 more — vendor security blogs. Empty fixtures so the
      // de-dup test still anchors on qualys + usn without contamination
      // from the new vendor-blog feeds.
      'microsoft-security-blog': '<rss><channel></channel></rss>',
      'sysdig-blog': '<rss><channel></channel></rss>',
      'trail-of-bits-blog': '<rss><channel></channel></rss>',
      'embrace-the-red': '<feed xmlns="http://www.w3.org/2005/Atom"></feed>',
      // v0.13.17: 3 more — bleepingcomputer-security + thehackernews
      // (tech-press RSS) and nightmare-eclipse-gitlab (GitLab activity Atom).
      // Empty fixtures keep this dedup-anchor test isolated from the
      // new feeds; tests/intake-nightmare-eclipse-coverage.test.js +
      // tests/intake-handle-tracker.test.js exercise the v0.13.17
      // intake-path end-to-end against the live fixture file.
      'bleepingcomputer-security': '<rss><channel></channel></rss>',
      'thehackernews': '<rss><channel></channel></rss>',
      'nightmare-eclipse-gitlab': '<feed xmlns="http://www.w3.org/2005/Atom"></feed>',
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

// ---------------------------------------------------------------------------
// Finding #31 — extractCveIds recovers a CVE from a stray-"<" title.
// ---------------------------------------------------------------------------

test('#31 extractCveIds recovers the CVE from a title-only item with a stray "<"', () => {
  const xml = '<rss><channel><item>'
    + '<title>CVE-2026-33333 affects versions < 5.0</title>'
    + '<link>https://c</link></item></channel></rss>';
  const items = T.parseFeed(xml);
  const ids = SA.extractCveIds(`${items[0].title} ${items[0].body} ${items[0].link}`);
  assert.deepEqual(ids, ['CVE-2026-33333']);
  assert.ok(Array.isArray(ids));
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
// Vendor-security-blog intake coverage (DirtyDecrypt class).
// ---------------------------------------------------------------------------

const REQUIRED_VENDOR_FEEDS = [
  "microsoft-security-blog",
  "sysdig-blog",
  "trail-of-bits-blog",
  "embrace-the-red",
];

test("source-advisories.FEEDS includes the four vendor-security-blog sources", () => {
  const feedNames = SOURCE.FEEDS.map((f) => f.name);
  for (const required of REQUIRED_VENDOR_FEEDS) {
    assert.ok(feedNames.includes(required),
      `FEEDS must include "${required}" — closes the DirtyDecrypt-class intake gap`);
  }
});

test("every vendor-security-blog feed carries an HTTPS URL with kind=rss", () => {
  for (const required of REQUIRED_VENDOR_FEEDS) {
    const feed = SOURCE.FEEDS.find((f) => f.name === required);
    assert.ok(feed, `feed "${required}" must be defined`);
    assert.equal(feed.kind, "rss", `${required} must be parsed as RSS / Atom`);
    assert.match(feed.url, /^https:\/\//,
      `${required} must use HTTPS for transport integrity (RSS feeds over plaintext are mutable in transit)`);
  }
});

test("fixture-mode has frozen content for every vendor-blog feed (no live-RSS fall-through)", () => {
  const fx = JSON.parse(fs.readFileSync(path.join(ROOT, "tests", "fixtures", "refresh", "advisories.json"), "utf8"));
  for (const required of REQUIRED_VENDOR_FEEDS) {
    assert.ok(typeof fx[required] === "string" && fx[required].length > 0,
      `tests/fixtures/refresh/advisories.json must have a frozen entry for "${required}" — fixture-mode would otherwise fall through to live RSS`);
  }
});

test("DirtyDecrypt CVE-2026-31635 is present in the catalog with rxgk anchor", () => {
  // The operator-side anchor that explains why the intake fix exists.
  const catalog = JSON.parse(fs.readFileSync(path.join(ROOT, "data", "cve-catalog.json"), "utf8"));
  const entry = catalog["CVE-2026-31635"];
  assert.ok(entry, "DirtyDecrypt (CVE-2026-31635) must be in the catalog");
  assert.match(entry.name, /DirtyDecrypt/);
  assert.match(entry.vector, /rxgk_decrypt_skb|page-cache write/i,
    "vector must name the rxgk page-cache write primitive");
  assert.equal(entry.type, "LPE");
  assert.equal(entry.poc_available, true);
  assert.ok(entry.intake_gap_note,
    "entry must carry an intake_gap_note explaining why this was added via manual triage");
  assert.match(entry.intake_gap_note, /v0\.13\.14/,
    "intake_gap_note must reference the release that closed the gap class");
});

test("DirtyDecrypt has a matching zeroday-lessons entry naming the intake-coverage control", () => {
  const lessons = JSON.parse(fs.readFileSync(path.join(ROOT, "data", "zeroday-lessons.json"), "utf8"));
  const entry = lessons["CVE-2026-31635"];
  assert.ok(entry, "DirtyDecrypt lesson must exist");
  const controls = entry.new_control_requirements || [];
  const intakeCtrl = controls.find((c) => c && (c.name || "").includes("VENDOR-BLOG-COVERAGE"));
  assert.ok(intakeCtrl,
    "lesson must reference NEW-CTRL-072 (PRIMARY-SOURCE-INTAKE-VENDOR-BLOG-COVERAGE)");
});

// ---------------------------------------------------------------------------
// Nightmare-Eclipse researcher-handle intake coverage.
// ---------------------------------------------------------------------------

const REQUIRED_V0_13_17_FEEDS = [
  { name: "bleepingcomputer-security", kind: "rss" },
  { name: "thehackernews", kind: "rss" },
  // The handle tracker migrated from GitHub events to the GitLab public
  // activity Atom feed after the researcher's GitHub account was removed.
  { name: "nightmare-eclipse-gitlab", kind: "gitlab-activity" },
];

const NIGHTMARE_ECLIPSE_KEYS = [
  "CVE-2020-17103-REREGRESSION-2026",
  "BUG-2026-NIGHTMARE-ECLIPSE-YELLOWKEY",
  "BUG-2026-NIGHTMARE-ECLIPSE-GREENPLASMA",
  "BUG-2026-NIGHTMARE-ECLIPSE-UNDEFEND",
];

test("source-advisories.FEEDS includes the three v0.13.17 intake sources", () => {
  const feedsByName = new Map(SOURCE.FEEDS.map((f) => [f.name, f]));
  for (const req of REQUIRED_V0_13_17_FEEDS) {
    const feed = feedsByName.get(req.name);
    assert.ok(feed, `FEEDS must include "${req.name}" — closes the Nightmare-Eclipse class intake gap`);
    assert.equal(feed.kind, req.kind, `${req.name} must be parsed as ${req.kind}`);
    assert.match(feed.url, /^https:\/\//, `${req.name} must use HTTPS for transport integrity`);
  }
});

test("fixture-mode has frozen content for every v0.13.17 feed", () => {
  const fx = JSON.parse(fs.readFileSync(path.join(ROOT, "tests", "fixtures", "refresh", "advisories.json"), "utf8"));
  for (const req of REQUIRED_V0_13_17_FEEDS) {
    assert.ok(typeof fx[req.name] === "string" && fx[req.name].length > 0,
      `tests/fixtures/refresh/advisories.json must have a frozen entry for "${req.name}" — fixture-mode would otherwise fall through to live fetch`);
  }
});

test("the four Nightmare-Eclipse catalog entries are present with intake_gap_note", () => {
  const catalog = JSON.parse(fs.readFileSync(path.join(ROOT, "data", "cve-catalog.json"), "utf8"));
  for (const key of NIGHTMARE_ECLIPSE_KEYS) {
    const entry = catalog[key];
    assert.ok(entry, `catalog must contain ${key}`);
    assert.ok(entry.intake_gap_note,
      `${key} must carry an intake_gap_note explaining why the prior intake missed it`);
    assert.match(entry.intake_gap_note, /v0\.13\.17/,
      `${key}.intake_gap_note must reference the release that closed the gap class`);
    assert.match(
      entry.discovery_attribution_note || "",
      /Nightmare-Eclipse|Chaotic Eclipse/i,
      `${key}.discovery_attribution_note must name the researcher handle so NEW-CTRL-073 can anchor`,
    );
  }
});

test("MiniPlasma entry encodes the historical-CVE relationship for NEW-CTRL-074", () => {
  const catalog = JSON.parse(fs.readFileSync(path.join(ROOT, "data", "cve-catalog.json"), "utf8"));
  const mini = catalog["CVE-2020-17103-REREGRESSION-2026"];
  assert.ok(mini, "MiniPlasma anchor entry must exist");
  assert.ok(Array.isArray(mini.aliases), "MiniPlasma must declare its aliases[] for the regression-watcher lookup");
  assert.ok(mini.aliases.includes("CVE-2020-17103"),
    "MiniPlasma.aliases must reference the original CVE-2020-17103 — anchors the regression-watcher cross-check");
});

test("the four zeroday-lessons entries reference NEW-CTRL-073", () => {
  const lessons = JSON.parse(fs.readFileSync(path.join(ROOT, "data", "zeroday-lessons.json"), "utf8"));
  for (const key of NIGHTMARE_ECLIPSE_KEYS) {
    const lesson = lessons[key];
    assert.ok(lesson, `zeroday-lessons must contain ${key}`);
    const ctrls = (lesson.new_control_requirements || []).map((c) => c && c.id).filter(Boolean);
    assert.ok(ctrls.includes("NEW-CTRL-073"),
      `${key} must reference NEW-CTRL-073 (researcher-handle tracker)`);
  }
  // UnDefend additionally introduces NEW-CTRL-075 (AV-AGENT-CURRENCY-CROSS-VERIFICATION).
  const undefend = lessons["BUG-2026-NIGHTMARE-ECLIPSE-UNDEFEND"];
  const ctrls = (undefend.new_control_requirements || []).map((c) => c && c.id).filter(Boolean);
  assert.ok(ctrls.includes("NEW-CTRL-075"),
    "UnDefend must introduce NEW-CTRL-075 (AV-agent currency cross-verification)");
});

test("MiniPlasma anchor entry references NEW-CTRL-074 in its zeroday-lessons gap-closure surface", () => {
  const lessons = JSON.parse(fs.readFileSync(path.join(ROOT, "data", "zeroday-lessons.json"), "utf8"));
  const mini = lessons["CVE-2020-17103-REREGRESSION-2026"];
  assert.ok(mini, "MiniPlasma lesson must exist");
  const ctrls = (mini.new_control_requirements || []).map((c) => c && c.id).filter(Boolean);
  assert.ok(ctrls.includes("NEW-CTRL-074"),
    "MiniPlasma must reference NEW-CTRL-074 (CVE regression-watcher) — the detection method that would have caught the historical-CVE reference at T+0");
});

// ---------------------------------------------------------------------------
// FEEDS registry: the original advisory + primary-source pollers stay present
// and every primary-source-poller URL is HTTPS with a recognized feed kind.
// ---------------------------------------------------------------------------

test('ADVISORIES_SOURCE FEEDS includes the eight advisory + primary-source poller entries (count >= 8)', () => {
  // The original eight feeds (qualys, rhsa, usn, zdi + the kernel-org,
  // oss-security, jfrog, cisa-current primary-source pollers) must stay
  // present; the exact-count assertion lives above where it tracks the
  // live total.
  const { FEEDS } = require(path.join(ROOT, 'lib', 'source-advisories'));
  assert.ok(FEEDS.length >= 8, `expected >= 8 feeds; got ${FEEDS.length}`);
  const names = new Set(FEEDS.map((f) => f.name));
  for (const required of ['cisa-current', 'jfrog', 'kernel-org', 'oss-security', 'qualys', 'rhsa', 'usn', 'zdi']) {
    assert.ok(names.has(required), `original feed "${required}" must still be present`);
  }
});

test('every primary-source-poller feed URL uses HTTPS and matches a feed kind', () => {
  const { FEEDS } = require(path.join(ROOT, 'lib', 'source-advisories'));
  const pollers = ['kernel-org', 'oss-security', 'jfrog', 'cisa-current'];
  for (const name of pollers) {
    const f = FEEDS.find((x) => x.name === name);
    assert.ok(f, `${name}: feed must exist in FEEDS`);
    assert.match(f.url, /^https:\/\//);
    assert.ok(['rss', 'csaf-index'].includes(f.kind),
      `${name}: kind must be rss or csaf-index`);
    assert.ok(typeof f.description === 'string' && f.description.length > 0);
  }
});


// ---- routed from doc-feed-count-currency ----
require("node:test").describe("doc-feed-count-currency", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
/**
 * tests/doc-feed-count-currency.test.js
 *
 * v0.13.15 regression pin. README.md + AGENTS.md include prose claims
 * like "12 primary-source advisory feeds". When new feeds land in
 * lib/source-advisories.js FEEDS, the doc claims must move in lockstep.
 * Parallel to tests/doc-playbook-count-currency.test.js.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const ROOT = path.join(__dirname, "..");
const { FEEDS } = require(path.join(ROOT, "lib", "source-advisories"));

function findFeedCountClaims(filePath) {
  const text = fs.readFileSync(filePath, "utf8");
  const re = /\b(\d{1,3})\s+(?:vendor and coordinated-disclosure|primary-source(?:\s+advisory)?|advisory venues?)\s+feeds?\b/gi;
  const claims = [];
  let m;
  while ((m = re.exec(text)) !== null) {
    const n = Number(m[1]);
    const start = Math.max(0, m.index - 30);
    const end = Math.min(text.length, m.index + 80);
    claims.push({ n, snippet: text.slice(start, end).replace(/\s+/g, " ").trim() });
  }
  return claims;
}

test("README + AGENTS feed-count claims match live FEEDS.length", () => {
  const live = FEEDS.length;
  assert.ok(live >= 12, `expected >= 12 feeds; got ${live}`);
  const docs = ["README.md", "AGENTS.md"];
  const mismatches = [];
  for (const rel of docs) {
    const claims = findFeedCountClaims(path.join(ROOT, rel));
    const hasFullTotal = claims.some((c) => c.n === live);
    if (claims.length > 0 && !hasFullTotal) {
      const summary = claims.map((c) => '"' + c.n + ' ... feeds"').join(", ");
      mismatches.push(rel + ": no claim matches live FEEDS.length=" + live + "; found: " + summary);
    }
  }
  assert.deepEqual(mismatches, [],
    "doc feed-count drift; update doc claims to reference " + live + " primary-source advisory feeds.");
});
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});


// ---- routed from hunt-fix-G-parsers ----
require("node:test").describe("hunt-fix-G-parsers", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
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









// ---------------------------------------------------------------------------
// Finding #33 — rel-aware Atom <link> selection (first-alternate-wins).
// ---------------------------------------------------------------------------






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
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});


// ---- routed from intake-handle-tracker ----
require("node:test").describe("intake-handle-tracker", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
/**
 * tests/intake-handle-tracker.test.js
 *
 * NEW-CTRL-073 invariant: when a researcher handle appears in any
 * catalog entry's discovery_attribution_note or poc_description, the
 * intake pipeline must include a feed that tracks that handle. The
 * handle becomes a known signal source after a single catalog-grade
 * drop and warrants prioritized surfacing of subsequent drops.
 *
 * The first registered handle is Nightmare-Eclipse / Chaotic Eclipse
 * via lib/source-advisories.js#FEEDS[nightmare-eclipse-gitlab] — a GitLab
 * public-activity Atom feed, migrated from GitHub after the account was
 * removed. Future additions follow the same pattern — register an activity
 * feed for the handle (GitHub events JSON or GitLab .atom), add a
 * frozen-fixture entry, the invariant flips back to satisfied.
 *
 * This pin asserts the activity parser round-trips a fixture payload into
 * diff entries carrying researcher_handle + repo_name +
 * triage_class=researcher-handle-drop, which downstream triage logic
 * consumes to surface drops that haven't been assigned a CVE yet.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const ROOT = path.join(__dirname, "..");
const SOURCE = require(path.join(ROOT, "lib", "source-advisories.js"));

const REGISTERED_HANDLES = [
  // Each entry: { name: visible handle string, feed: feed-name in FEEDS,
  // anchor_entry_keys: catalog keys whose discovery_attribution_note must
  // name the handle. }
  {
    name: "Nightmare-Eclipse",
    feed: "nightmare-eclipse-gitlab",
    anchor_entry_keys: [
      "CVE-2020-17103-REREGRESSION-2026",
      "BUG-2026-NIGHTMARE-ECLIPSE-YELLOWKEY",
      "BUG-2026-NIGHTMARE-ECLIPSE-GREENPLASMA",
      "BUG-2026-NIGHTMARE-ECLIPSE-UNDEFEND",
    ],
  },
];

test("every registered handle has an activity feed in FEEDS", () => {
  const feedsByName = new Map(SOURCE.FEEDS.map((f) => [f.name, f]));
  for (const h of REGISTERED_HANDLES) {
    const feed = feedsByName.get(h.feed);
    assert.ok(feed, `FEEDS must include "${h.feed}" — handle "${h.name}" anchored by catalog entries`);
    assert.equal(feed.kind, "gitlab-activity", `${h.feed} must be gitlab-activity (handle tracker)`);
    assert.match(feed.url, /^https:\/\/gitlab\.com\/[^/]+\.atom$/,
      `${h.feed} must point at the GitLab public-activity Atom feed for the handle`);
    assert.equal(feed.researcher_handle, "Nightmare-Eclipse",
      `${h.feed} must declare researcher_handle explicitly`);
  }
});

test("gitlab-activity parser extracts ReleaseEvent + PublicEvent items", () => {
  const fx = JSON.parse(fs.readFileSync(path.join(ROOT, "tests", "fixtures", "refresh", "advisories.json"), "utf8"));
  const handleFeed = SOURCE.FEEDS.find((f) => f.name === "nightmare-eclipse-gitlab");
  assert.ok(handleFeed, "feed nightmare-eclipse-gitlab must exist");
  const items = SOURCE.parseGitLabActivity(fx["nightmare-eclipse-gitlab"], handleFeed);
  assert.ok(items.length >= 3,
    `parser must surface multiple drop events from the fixture; got ${items.length}`);
  const types = new Set(items.map((it) => it.event_type));
  assert.ok(types.has("ReleaseEvent"),
    "parser must surface ReleaseEvent items (a tag push — the canonical handle-drop signal)");
  assert.ok(types.has("PublicEvent"),
    "parser must surface PublicEvent items (a newly created public project)");
  // Every item carries the researcher_handle so downstream consumers can
  // group by handle without re-parsing the feed URL.
  for (const it of items) {
    assert.equal(it.researcher_handle, "Nightmare-Eclipse",
      "every gitlab-activity item must carry researcher_handle from the feed config");
    assert.ok(it.repo_name, "every gitlab-activity item must carry repo_name");
  }
});

test("gitlab-activity handle-drop surfaces in fetchDiff diffs even without a CVE ID", () => {
  // Wire a synthetic fetchDiff call against the fixture; assert that a
  // ReleaseEvent without a CVE-ID in its title still appears in the
  // diffs[] with triage_class=researcher-handle-drop.
  const fx = JSON.parse(fs.readFileSync(path.join(ROOT, "tests", "fixtures", "refresh", "advisories.json"), "utf8"));
  const catalog = JSON.parse(fs.readFileSync(path.join(ROOT, "data", "cve-catalog.json"), "utf8"));
  const ctx = {
    fixtures: { advisories: fx },
    cveCatalog: catalog,
  };
  // Drive fetchDiff and inspect.
  return SOURCE.ADVISORIES_SOURCE.fetchDiff(ctx).then((report) => {
    assert.equal(report.status, "ok", "fetchDiff must report ok in fixture mode");
    const handleDrops = report.diffs.filter((d) => d.triage_class === "researcher-handle-drop");
    assert.ok(handleDrops.length >= 1,
      `at least one researcher-handle-drop diff must be surfaced; got ${handleDrops.length}`);
    const miniPlasmaDrop = handleDrops.find((d) => /MiniPlasma/i.test(d.title || ""));
    assert.ok(miniPlasmaDrop, "MiniPlasma tag push (ReleaseEvent) must appear as a researcher-handle-drop diff");
    assert.equal(miniPlasmaDrop.researcher_handle, "Nightmare-Eclipse",
      "diff must carry researcher_handle so triage can group by handle");
  });
});
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});


// ---- routed from intake-nightmare-eclipse-coverage ----
require("node:test").describe("intake-nightmare-eclipse-coverage", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
/**
 * tests/intake-nightmare-eclipse-coverage.test.js
 *
 * v0.13.17 regression pin for the Nightmare-Eclipse researcher-handle
 * intake gap surfaced by the May 2026 audit.
 *
 * Background. The 12-feed intake (v0.13.14) caught BlueHammer
 * (CVE-2026-33825) through Picus Security's Microsoft-Security-Blog
 * publication, but missed four sibling drops by the same researcher
 * handle:
 *   - MiniPlasma  (re-regression of CVE-2020-17103, May 13)
 *   - YellowKey   (BitLocker TPM-only bypass, May 2026)
 *   - GreenPlasma (Windows LPE, May 2026)
 *   - UnDefend    (Defender update-disruption, April 2026 with Huntress
 *                  in-wild observation)
 *
 * The fix has three components:
 *
 *   (1) Three new feeds in lib/source-advisories.js#FEEDS:
 *       - bleepingcomputer-security (tech-press RSS)
 *       - thehackernews             (tech-press RSS)
 *       - nightmare-eclipse-github  (github-events JSON, the canonical
 *                                    handle tracker for NEW-CTRL-073)
 *
 *   (2) lib/cve-regression-watcher.js — a new detection method that
 *       surfaces poller-diff historical-CVE references as candidate
 *       silent-regression cases (NEW-CTRL-074). The MiniPlasma anchor:
 *       a 2026 PoC drop that references CVE-2020-17103 inline.
 *
 *   (3) Four catalog entries:
 *       CVE-2020-17103-REREGRESSION-2026 + the three BUG-2026-NIGHTMARE-
 *       ECLIPSE-* keys, each with intake_gap_note explaining why the
 *       prior intake missed them.
 *
 * This pin asserts (a) the three new feeds are registered with the
 * expected kind + URL, (b) the fixture has matching frozen content for
 * each (no live-feed fall-through), (c) the four catalog entries are
 * present with their intake_gap_note, and (d) the four zeroday-lessons
 * entries reference NEW-CTRL-073 + (UnDefend) NEW-CTRL-075.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const ROOT = path.join(__dirname, "..");
const SOURCE = require(path.join(ROOT, "lib", "source-advisories.js"));

const REQUIRED_V0_13_17_FEEDS = [
  { name: "bleepingcomputer-security", kind: "rss" },
  { name: "thehackernews", kind: "rss" },
  // The handle tracker migrated from GitHub events to the GitLab public
  // activity Atom feed after the researcher's GitHub account was removed.
  { name: "nightmare-eclipse-gitlab", kind: "gitlab-activity" },
];

const NIGHTMARE_ECLIPSE_KEYS = [
  "CVE-2020-17103-REREGRESSION-2026",
  "BUG-2026-NIGHTMARE-ECLIPSE-YELLOWKEY",
  "BUG-2026-NIGHTMARE-ECLIPSE-GREENPLASMA",
  "BUG-2026-NIGHTMARE-ECLIPSE-UNDEFEND",
];

test("source-advisories.FEEDS includes the three v0.13.17 intake sources", () => {
  const feedsByName = new Map(SOURCE.FEEDS.map((f) => [f.name, f]));
  for (const req of REQUIRED_V0_13_17_FEEDS) {
    const feed = feedsByName.get(req.name);
    assert.ok(feed, `FEEDS must include "${req.name}" — closes the Nightmare-Eclipse class intake gap`);
    assert.equal(feed.kind, req.kind, `${req.name} must be parsed as ${req.kind}`);
    assert.match(feed.url, /^https:\/\//, `${req.name} must use HTTPS for transport integrity`);
  }
});

test("fixture-mode has frozen content for every v0.13.17 feed", () => {
  const fx = JSON.parse(fs.readFileSync(path.join(ROOT, "tests", "fixtures", "refresh", "advisories.json"), "utf8"));
  for (const req of REQUIRED_V0_13_17_FEEDS) {
    assert.ok(typeof fx[req.name] === "string" && fx[req.name].length > 0,
      `tests/fixtures/refresh/advisories.json must have a frozen entry for "${req.name}" — fixture-mode would otherwise fall through to live fetch`);
  }
});

test("the four Nightmare-Eclipse catalog entries are present with intake_gap_note", () => {
  const catalog = JSON.parse(fs.readFileSync(path.join(ROOT, "data", "cve-catalog.json"), "utf8"));
  for (const key of NIGHTMARE_ECLIPSE_KEYS) {
    const entry = catalog[key];
    assert.ok(entry, `catalog must contain ${key}`);
    assert.ok(entry.intake_gap_note,
      `${key} must carry an intake_gap_note explaining why the prior intake missed it`);
    assert.match(entry.intake_gap_note, /v0\.13\.17/,
      `${key}.intake_gap_note must reference the release that closed the gap class`);
    assert.match(
      entry.discovery_attribution_note || "",
      /Nightmare-Eclipse|Chaotic Eclipse/i,
      `${key}.discovery_attribution_note must name the researcher handle so NEW-CTRL-073 can anchor`,
    );
  }
});

test("MiniPlasma entry encodes the historical-CVE relationship for NEW-CTRL-074", () => {
  const catalog = JSON.parse(fs.readFileSync(path.join(ROOT, "data", "cve-catalog.json"), "utf8"));
  const mini = catalog["CVE-2020-17103-REREGRESSION-2026"];
  assert.ok(mini, "MiniPlasma anchor entry must exist");
  assert.ok(Array.isArray(mini.aliases), "MiniPlasma must declare its aliases[] for the regression-watcher lookup");
  assert.ok(mini.aliases.includes("CVE-2020-17103"),
    "MiniPlasma.aliases must reference the original CVE-2020-17103 — anchors the regression-watcher cross-check");
});

test("the four zeroday-lessons entries reference NEW-CTRL-073", () => {
  const lessons = JSON.parse(fs.readFileSync(path.join(ROOT, "data", "zeroday-lessons.json"), "utf8"));
  for (const key of NIGHTMARE_ECLIPSE_KEYS) {
    const lesson = lessons[key];
    assert.ok(lesson, `zeroday-lessons must contain ${key}`);
    const ctrls = (lesson.new_control_requirements || []).map((c) => c && c.id).filter(Boolean);
    assert.ok(ctrls.includes("NEW-CTRL-073"),
      `${key} must reference NEW-CTRL-073 (researcher-handle tracker)`);
  }
  // UnDefend additionally introduces NEW-CTRL-075 (AV-AGENT-CURRENCY-CROSS-VERIFICATION).
  const undefend = lessons["BUG-2026-NIGHTMARE-ECLIPSE-UNDEFEND"];
  const ctrls = (undefend.new_control_requirements || []).map((c) => c && c.id).filter(Boolean);
  assert.ok(ctrls.includes("NEW-CTRL-075"),
    "UnDefend must introduce NEW-CTRL-075 (AV-agent currency cross-verification)");
});

test("MiniPlasma anchor entry references NEW-CTRL-074 in its zeroday-lessons gap-closure surface", () => {
  const lessons = JSON.parse(fs.readFileSync(path.join(ROOT, "data", "zeroday-lessons.json"), "utf8"));
  const mini = lessons["CVE-2020-17103-REREGRESSION-2026"];
  assert.ok(mini, "MiniPlasma lesson must exist");
  const ctrls = (mini.new_control_requirements || []).map((c) => c && c.id).filter(Boolean);
  assert.ok(ctrls.includes("NEW-CTRL-074"),
    "MiniPlasma must reference NEW-CTRL-074 (CVE regression-watcher) — the detection method that would have caught the historical-CVE reference at T+0");
});

;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});


// ---- routed from intake-vendor-blog-coverage ----
require("node:test").describe("intake-vendor-blog-coverage", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
/**
 * tests/intake-vendor-blog-coverage.test.js
 *
 * v0.13.14 regression pin for the DirtyDecrypt-class intake gap.
 *
 * Background: CVE-2026-31635 (DirtyDecrypt) was patched silently in
 * mainline 2026-04-25, then disclosed via a published PoC on 2026-05-17.
 * The 8-feed primary-source intake (Qualys / RHSA / USN / ZDI / kernel.org
 * / oss-security / JFrog / CISA) missed it: the kernel.org Atom feed
 * window had rolled past the fix commit by the time the PoC published,
 * the V12 rediscovery went to maintainers privately rather than to
 * oss-security@openwall, and the BleepingComputer / Microsoft Security
 * Blog publications surfaced on vendor blogs that no feed covered.
 *
 * The fix: lib/source-advisories.js now polls four vendor-security-blog
 * feeds — microsoft-security-blog / sysdig-blog / trail-of-bits-blog /
 * embrace-the-red. These are the canonical signal channel for
 * "kernel-class CVE patched silently, class-of-bug research published
 * weeks later" and for AI-tool / MCP supply-chain disclosures.
 *
 * This pin asserts (a) the four new feeds are registered, (b) the
 * fixture has matching frozen-content entries so fixture-mode never
 * falls through to live RSS for them, and (c) the DirtyDecrypt entry
 * itself is in the catalog as the operator-side anchor.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const ROOT = path.join(__dirname, "..");
const SOURCE = require(path.join(ROOT, "lib", "source-advisories.js"));
const REQUIRED_VENDOR_FEEDS = [
  "microsoft-security-blog",
  "sysdig-blog",
  "trail-of-bits-blog",
  "embrace-the-red",
];

test("source-advisories.FEEDS includes the four vendor-security-blog sources", () => {
  const feedNames = SOURCE.FEEDS.map((f) => f.name);
  for (const required of REQUIRED_VENDOR_FEEDS) {
    assert.ok(feedNames.includes(required),
      `FEEDS must include "${required}" — closes the DirtyDecrypt-class intake gap`);
  }
});

test("every vendor-security-blog feed carries an HTTPS URL with kind=rss", () => {
  for (const required of REQUIRED_VENDOR_FEEDS) {
    const feed = SOURCE.FEEDS.find((f) => f.name === required);
    assert.ok(feed, `feed "${required}" must be defined`);
    assert.equal(feed.kind, "rss", `${required} must be parsed as RSS / Atom`);
    assert.match(feed.url, /^https:\/\//,
      `${required} must use HTTPS for transport integrity (RSS feeds over plaintext are mutable in transit)`);
  }
});

test("fixture-mode has frozen content for every vendor-blog feed (no live-RSS fall-through)", () => {
  const fx = JSON.parse(fs.readFileSync(path.join(ROOT, "tests", "fixtures", "refresh", "advisories.json"), "utf8"));
  for (const required of REQUIRED_VENDOR_FEEDS) {
    assert.ok(typeof fx[required] === "string" && fx[required].length > 0,
      `tests/fixtures/refresh/advisories.json must have a frozen entry for "${required}" — fixture-mode would otherwise fall through to live RSS`);
  }
});
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});
