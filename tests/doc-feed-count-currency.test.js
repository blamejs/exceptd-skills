"use strict";

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
