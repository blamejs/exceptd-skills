"use strict";

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
 * via lib/source-advisories.js#FEEDS[nightmare-eclipse-github]. Future
 * additions follow the same pattern — register a github-events feed
 * for the handle, add a frozen-fixture entry, the invariant flips
 * back to satisfied.
 *
 * This pin asserts the github-events parser round-trips a fixture
 * payload into diff entries carrying researcher_handle + repo_name +
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
    feed: "nightmare-eclipse-github",
    anchor_entry_keys: [
      "CVE-2020-17103-REREGRESSION-2026",
      "BUG-2026-NIGHTMARE-ECLIPSE-YELLOWKEY",
      "BUG-2026-NIGHTMARE-ECLIPSE-GREENPLASMA",
      "BUG-2026-NIGHTMARE-ECLIPSE-UNDEFEND",
    ],
  },
];

test("every registered handle has a github-events feed in FEEDS", () => {
  const feedsByName = new Map(SOURCE.FEEDS.map((f) => [f.name, f]));
  for (const h of REGISTERED_HANDLES) {
    const feed = feedsByName.get(h.feed);
    assert.ok(feed, `FEEDS must include "${h.feed}" — handle "${h.name}" anchored by catalog entries`);
    assert.equal(feed.kind, "github-events", `${h.feed} must be github-events (handle tracker)`);
    assert.match(feed.url, /api\.github\.com\/users\/[^/]+\/events\/public/,
      `${h.feed} must point at the GitHub events API for the handle`);
  }
});

test("every registered handle is named in the anchor catalog entries", () => {
  const catalog = JSON.parse(fs.readFileSync(path.join(ROOT, "data", "cve-catalog.json"), "utf8"));
  for (const h of REGISTERED_HANDLES) {
    for (const key of h.anchor_entry_keys) {
      const entry = catalog[key];
      assert.ok(entry, `catalog must contain anchor entry ${key} for handle ${h.name}`);
      const blob = `${entry.discovery_attribution_note || ""} ${entry.poc_description || ""}`;
      assert.match(blob, new RegExp(h.name, "i"),
        `${key} must name handle "${h.name}" in discovery_attribution_note or poc_description`);
    }
  }
});

test("github-events parser extracts ReleaseEvent + PublicEvent + PushEvent items", () => {
  const fx = JSON.parse(fs.readFileSync(path.join(ROOT, "tests", "fixtures", "refresh", "advisories.json"), "utf8"));
  const handleFeed = SOURCE.FEEDS.find((f) => f.name === "nightmare-eclipse-github");
  assert.ok(handleFeed, "feed nightmare-eclipse-github must exist");
  const items = SOURCE.parseGitHubEvents(fx["nightmare-eclipse-github"], handleFeed);
  assert.ok(items.length >= 3,
    `parser must surface multiple drop events from the fixture; got ${items.length}`);
  const types = new Set(items.map((it) => it.event_type));
  assert.ok(types.has("ReleaseEvent"),
    "parser must surface ReleaseEvent items (the canonical handle-drop signal)");
  // Every item carries the researcher_handle so downstream consumers can
  // group by handle without re-parsing the feed URL.
  for (const it of items) {
    assert.equal(it.researcher_handle, "Nightmare-Eclipse",
      "every github-events item must carry researcher_handle extracted from the feed URL");
    assert.ok(it.repo_name, "every github-events item must carry repo_name");
  }
});

test("github-events handle-drop surfaces in fetchDiff diffs even without a CVE ID", () => {
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
    const yellowKeyDrop = handleDrops.find((d) => /YellowKey/i.test(d.title || ""));
    assert.ok(yellowKeyDrop, "YellowKey ReleaseEvent must appear as a researcher-handle-drop diff");
    assert.equal(yellowKeyDrop.researcher_handle, "Nightmare-Eclipse",
      "diff must carry researcher_handle so triage can group by handle");
  });
});
