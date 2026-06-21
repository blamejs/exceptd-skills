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
