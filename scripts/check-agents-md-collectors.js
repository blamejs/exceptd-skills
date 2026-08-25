#!/usr/bin/env node
"use strict";

/**
 * Predeploy gate: AGENTS.md's "<N> reference collectors ship today" paragraph
 * must agree with lib/collectors/ — the count word and the enumeration, both
 * directions. Exit codes: 0 ok, 1 drift, 2 parse error.
 */

const fs = require("node:fs");
const path = require("node:path");

const ROOT = path.join(__dirname, "..");
const AGENTS = path.join(ROOT, "AGENTS.md");
const REAL_COLLECTOR_DIR = path.join(ROOT, "lib", "collectors");
// EXCEPTD_COLLECTOR_DIR is honored ONLY alongside EXCEPTD_COLLECTOR_DIR_TESTONLY=1,
// so a stray env var cannot aim the release gate at another directory.
const COLLECTOR_DIR =
  process.env.EXCEPTD_COLLECTOR_DIR_TESTONLY === "1" && process.env.EXCEPTD_COLLECTOR_DIR
    ? path.resolve(process.env.EXCEPTD_COLLECTOR_DIR)
    : REAL_COLLECTOR_DIR;

// A shipped collector is named [a-z0-9-]+.js, so a `__`-prefixed file is test
// scaffolding: classifyCollectors skips it, findReservedFixtures forbids it in lib/.
function isReservedFixture(f) {
  return f.startsWith("__");
}

// Reserved-prefix .js files present in `dir`; an unreadable dir yields [].
function findReservedFixtures(dir) {
  try {
    return fs.readdirSync(dir).filter((f) => f.endsWith(".js") && isReservedFixture(f));
  } catch {
    return [];
  }
}

// Repo-relative POSIX form of <dir>/<file> for a diagnostic, falling back to the
// literal path when `dir` sits outside the repo (a test-only override dir).
function collectorDisplayPath(dir, file) {
  const abs = path.join(dir, file);
  const rel = path.relative(ROOT, abs).split(path.sep).join("/");
  return rel && !rel.startsWith("..") ? rel : abs.split(path.sep).join("/");
}

// Classify every <dir>/*.js: a collector requires cleanly and exports collect();
// a require that throws becomes a load error rather than a silent omission.
//
// collectorFiles entries keep the literal `lib/collectors/` prefix whatever `dir`
// is: they are compared against the paths AGENTS.md enumerates, which always name
// the shipped location. Only the load-error diagnostic names the real path.
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
      loadErrors.push(`${collectorDisplayPath(dir, f)}: ${e.message.split("\n")[0]}`);
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
  // lib/ is published wholesale, so a stray fixture would ship.
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
      `[check-agents-md-collectors] cannot load ${loadErrors.length} module(s) in ${collectorDisplayPath(COLLECTOR_DIR, "")}/ ` +
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

module.exports = { classifyCollectors, collectorDisplayPath };
