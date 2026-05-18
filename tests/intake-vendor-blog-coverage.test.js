"use strict";

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
