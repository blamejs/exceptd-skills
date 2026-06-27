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
const REAL_COLLECTOR_DIR = path.join(ROOT, "lib", "collectors");
// EXCEPTD_COLLECTOR_DIR lets the test suite drive the gate against a throwaway
// tempdir (so the require-throw / leaked-fixture behaviours are exercised
// without writing into the real lib/collectors/). It is honored ONLY when the
// explicit test-only switch EXCEPTD_COLLECTOR_DIR_TESTONLY=1 is also set, so a
// stray env var in CI or a developer shell can never point the release gate at
// an alternate directory and let missing/broken real collectors pass.
const COLLECTOR_DIR =
  process.env.EXCEPTD_COLLECTOR_DIR_TESTONLY === "1" && process.env.EXCEPTD_COLLECTOR_DIR
    ? path.resolve(process.env.EXCEPTD_COLLECTOR_DIR)
    : REAL_COLLECTOR_DIR;

// A real shipped collector is named [a-z0-9-]+.js — the AGENTS.md enumeration
// regex (`lib/collectors/([a-z0-9-]+\.js)`) cannot even reference an
// underscore-prefixed file. So a `__`-prefixed file is never a collector:
// it is test scaffolding or a stray artifact. classifyCollectors SKIPS it so a
// leaked fixture cannot poison the count/enumeration/load-error scan; the gate
// separately FORBIDS it (see findReservedFixtures) so a leaked fixture cannot
// silently ship in the wholesale-published lib/ tree either.
function isReservedFixture(f) {
  return f.startsWith("__");
}

// Reserved-prefix .js files present in `dir`. These are test scaffolding and
// must never ship; the gate fails hard if any are found in the directory it
// validates.
function findReservedFixtures(dir) {
  try {
    return fs.readdirSync(dir).filter((f) => f.endsWith(".js") && isReservedFixture(f));
  } catch {
    return [];
  }
}

// Classify every <dir>/*.js into collectors (require succeeds + exports
// collect()), helpers (require succeeds, no collect() — silently excluded),
// and load-errors (require throws — surfaced, never silently dropped).
// Exported so the test suite can drive it against a tempdir.
function classifyCollectors(dir) {
  const jsFiles = fs.readdirSync(dir)
    .filter((f) => f.endsWith(".js") && !isReservedFixture(f))
    .sort();
  const collectorFiles = [];
  const loadErrors = [];
  for (const f of jsFiles) {
    let mod;
    try {
      mod = require(path.join(dir, f));
    } catch (e) {
      loadErrors.push(`lib/collectors/${f}: ${e.message.split("\n")[0]}`);
      continue;
    }
    if (typeof mod.collect === "function") {
      collectorFiles.push(`lib/collectors/${f}`);
    }
  }
  collectorFiles.sort();
  return { collectorFiles, loadErrors };
}

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
  // Leak-guard (P2: forbid leaked reserved fixtures before packing). A
  // `__`-prefixed file in the collectors dir is stray test scaffolding;
  // because lib/ is published wholesale, a leaked one would otherwise ship.
  // Fail hard, naming the file, so the release path deletes it.
  const stray = findReservedFixtures(COLLECTOR_DIR);
  if (stray.length > 0) {
    console.error(
      `[check-agents-md-collectors] reserved-prefix file(s) must not ship from lib/collectors/ ` +
      `- delete the stray test scaffolding: ${stray.join(", ")}`
    );
    process.exitCode = 2;
    return;
  }

  let agents;
  try { agents = fs.readFileSync(AGENTS, "utf8"); }
  catch (e) {
    console.error(`[check-agents-md-collectors] cannot read AGENTS.md: ${e.message}`);
    process.exitCode = 2;
    return;
  }

  // Classify every lib/collectors/*.js into exactly one of three buckets:
  //   - collector:  require() succeeds AND exports a collect() function
  //                 (counted; must appear in the AGENTS.md enumeration).
  //   - helper:     require() succeeds but exports no collect() function
  //                 (e.g. scan-excludes.js, the directory-walk exclusion
  //                 policy) — legitimately excluded from the count.
  //   - load-error: require() THROWS (syntax error, bad top-level require,
  //                 init-time exception). A broken collector must NOT be
  //                 silently dropped: doing so excludes it from BOTH the
  //                 count and the enumeration cross-check, so a file that
  //                 still ships in the tarball passes the gate undetected.
  //                 Surface it as a parse error (exit 2) naming the file.
  let collectorFiles, loadErrors;
  try {
    ({ collectorFiles, loadErrors } = classifyCollectors(COLLECTOR_DIR));
  } catch (e) {
    console.error(`[check-agents-md-collectors] cannot read ${COLLECTOR_DIR}: ${e.message}`);
    process.exitCode = 2;
    return;
  }

  if (loadErrors.length > 0) {
    console.error(
      `[check-agents-md-collectors] cannot load ${loadErrors.length} module(s) in lib/collectors/ ` +
      `- a require-time failure must not be silently excluded from the count + enumeration check:\n  ` +
      loadErrors.join("\n  ")
    );
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

if (require.main === module) {
  main();
}

module.exports = { classifyCollectors };
