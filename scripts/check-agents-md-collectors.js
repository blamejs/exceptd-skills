#!/usr/bin/env node
"use strict";

/**
 * scripts/check-agents-md-collectors.js
 *
 * Predeploy gate. Verifies that AGENTS.md's "<N> reference collectors
 * ship today" paragraph stays in sync with the actual contents of
 * lib/collectors/. Drift is silent today - AGENTS.md gets bumped by
 * hand each release; a missed bump produces inaccurate count + stale
 * enumeration that downstream AI consumers parse.
 *
 * Checks:
 *   1. The numeric count word in the paragraph (Eleven / Twelve /
 *      Thirteen / ...) matches the actual count of
 *      lib/collectors/*.js modules.
 *   2. Every collector named in the parenthesized list exists at
 *      lib/collectors/<name>.js.
 *   3. Every lib/collectors/<name>.js module appears in the
 *      parenthesized list.
 *
 * Exit codes: 0 ok, 1 drift, 2 parse error.
 */

const fs = require("node:fs");
const path = require("node:path");

const ROOT = path.join(__dirname, "..");
const AGENTS = path.join(ROOT, "AGENTS.md");
const COLLECTOR_DIR = path.join(ROOT, "lib", "collectors");

const WORD_TO_NUMBER = {
  one: 1, two: 2, three: 3, four: 4, five: 5, six: 6, seven: 7,
  eight: 8, nine: 9, ten: 10, eleven: 11, twelve: 12, thirteen: 13,
  fourteen: 14, fifteen: 15, sixteen: 16, seventeen: 17, eighteen: 18,
  nineteen: 19, twenty: 20,
};

function fail(msg) {
  console.error(`[check-agents-md-collectors] FAIL - ${msg}`);
  process.exitCode = 1;
}

function ok(msg) {
  console.log(`[check-agents-md-collectors] ok - ${msg}`);
}

function main() {
  let agents;
  try { agents = fs.readFileSync(AGENTS, "utf8"); }
  catch (e) {
    console.error(`[check-agents-md-collectors] cannot read AGENTS.md: ${e.message}`);
    process.exitCode = 2;
    return;
  }

  let collectorFiles;
  try {
    collectorFiles = fs.readdirSync(COLLECTOR_DIR)
      .filter(f => f.endsWith(".js"))
      // A collector is a module exporting a collect() function. Shared
      // helpers under lib/collectors/ (e.g. scan-excludes.js, the directory-
      // walk exclusion policy) are not collectors and must not inflate the
      // count or be required in the AGENTS.md enumeration.
      .filter(f => {
        try { return typeof require(path.join(COLLECTOR_DIR, f)).collect === "function"; }
        catch { return false; }
      })
      .map(f => `lib/collectors/${f}`)
      .sort();
  } catch (e) {
    console.error(`[check-agents-md-collectors] cannot read ${COLLECTOR_DIR}: ${e.message}`);
    process.exitCode = 2;
    return;
  }
  const onDiskCount = collectorFiles.length;

  const para = agents.match(/(\b[A-Z][a-z]+)\s+reference collectors ship today\s*\(([^)]+)\)/);
  if (!para) {
    fail("could not locate the 'N reference collectors ship today (...)' paragraph in AGENTS.md");
    return;
  }
  const word = para[1].toLowerCase();
  const listed = para[2];
  const claimedCount = WORD_TO_NUMBER[word];
  if (!claimedCount) {
    fail(`unrecognized count word '${para[1]}' - extend WORD_TO_NUMBER in scripts/check-agents-md-collectors.js`);
    return;
  }
  if (claimedCount !== onDiskCount) {
    fail(`claimed count ${para[1]} (${claimedCount}) != on-disk count ${onDiskCount}`);
    return;
  }

  const claimedPaths = [];
  const pathRe = /`lib\/collectors\/([a-z0-9-]+\.js)`/g;
  let m;
  while ((m = pathRe.exec(listed)) !== null) {
    claimedPaths.push(`lib/collectors/${m[1]}`);
  }
  claimedPaths.sort();

  const onDiskSet = new Set(collectorFiles);
  const claimedSet = new Set(claimedPaths);

  const missingFromAgents = collectorFiles.filter(f => !claimedSet.has(f));
  const extraInAgents = claimedPaths.filter(f => !onDiskSet.has(f));

  if (missingFromAgents.length > 0) {
    fail(`on-disk but not in AGENTS.md list: ${missingFromAgents.join(", ")}`);
  }
  if (extraInAgents.length > 0) {
    fail(`in AGENTS.md list but not on disk: ${extraInAgents.join(", ")}`);
  }

  if (process.exitCode !== 1) {
    ok(`${onDiskCount}/${onDiskCount} collectors enumerated correctly in AGENTS.md`);
  }
}

main();
