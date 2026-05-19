"use strict";

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
  { name: "nightmare-eclipse-github", kind: "github-events" },
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
