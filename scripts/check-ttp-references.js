#!/usr/bin/env node
"use strict";

/**
 * TTP reference-integrity gate. data/attack-techniques.json and
 * data/atlas-ttps.json are the pinned copies of ATT&CK and ATLAS; every other file
 * naming a technique refers into them, and this proves those references resolve.
 * Resolution runs against the pins, not against MITRE:
 * scripts/check-ttp-upstream.js is the network check on whether the pins
 * themselves are current, and it cannot block a release. This one can.
 *
 * Exit 0 when every reference resolves, 1 when any does not.
 */

const fs = require("node:fs");
const path = require("node:path");

const ROOT = path.resolve(__dirname, "..");

/**
 * ATT&CK ids are TNNNN[.NNN]; ATLAS ids are AML.TNNNN[.NNN]. Without the
 * lookbehind the ATT&CK alternative matches the "T0017" inside "AML.T0017" and
 * reports a phantom bare-ATT&CK reference for every ATLAS id. It covers the
 * hyphen too, since ATLAS ids also appear in filenames.
 */
const TTP_PATTERN = /\bAML\.T\d{4}(?:\.\d{3})?\b|(?<!AML[.-])\bT\d{4}(?:\.\d{3})?\b/g;

/** Files whose ids are definitions, not references. */
const SOURCE_CATALOGS = ["data/attack-techniques.json", "data/atlas-ttps.json"];

const SEARCH_ROOTS = ["data", "playbooks", "skills", "lib", "orchestrator", "bin"];
const SEARCH_EXTS = new Set([".json", ".md", ".js"]);
const SKIP_DIRS = new Set(["node_modules", "_indexes", "vendor", ".git"]);

/**
 * Tokens that match the pattern without referencing a technique. Every entry needs
 * a reason: an unexplained allowlist is how a real stale id gets parked here.
 */
const NOT_REFERENCES = [];

function loadKnownIds() {
  const known = new Set();
  for (const rel of SOURCE_CATALOGS) {
    const catalog = JSON.parse(fs.readFileSync(path.join(ROOT, rel), "utf8"));
    for (const key of Object.keys(catalog)) {
      if (key !== "_meta") known.add(key);
    }
  }
  return known;
}

function* walk(dir) {
  let names;
  try {
    names = fs.readdirSync(dir);
  } catch {
    return;
  }
  for (const name of names) {
    if (SKIP_DIRS.has(name)) continue;
    const full = path.join(dir, name);
    let stat;
    try {
      stat = fs.statSync(full);
    } catch {
      continue;
    }
    if (stat.isDirectory()) {
      yield* walk(full);
    } else if (SEARCH_EXTS.has(path.extname(name))) {
      yield full;
    }
  }
}

function allowed(id, rel) {
  return NOT_REFERENCES.some((e) => e.id === id && e.file === rel);
}

function scan(root = ROOT) {
  const known = loadKnownIds();
  const sources = new Set(SOURCE_CATALOGS);
  const unresolved = new Map();

  for (const dirName of SEARCH_ROOTS) {
    const dir = path.join(root, dirName);
    if (!fs.existsSync(dir)) continue;

    for (const file of walk(dir)) {
      const rel = path.relative(root, file).replace(/\\/g, "/");
      if (sources.has(rel)) continue;

      const text = fs.readFileSync(file, "utf8");
      for (const id of text.match(TTP_PATTERN) || []) {
        if (known.has(id) || allowed(id, rel)) continue;
        if (!unresolved.has(id)) unresolved.set(id, new Set());
        unresolved.get(id).add(rel);
      }
    }
  }

  return { unresolved, knownCount: known.size };
}

function main() {
  const { unresolved, knownCount } = scan();

  if (unresolved.size) {
    console.error("TTP reference integrity: FAIL");
    for (const [id, files] of [...unresolved].sort((a, b) => a[0].localeCompare(b[0]))) {
      console.error(`  ${id} — not defined in the pinned catalogs`);
      for (const f of [...files].sort()) console.error(`      ${f}`);
    }
    console.error(
      `\n${unresolved.size} unresolved ${unresolved.size === 1 ? "reference" : "references"}. ` +
        `Either the id was retired upstream and these files still name it — repoint them at the ` +
        `successor — or it is a technique the pinned catalogs do not carry yet, in which case import it.`
    );
    process.exitCode = 1;
    return;
  }

  console.log(`TTP reference integrity: PASS — every referenced technique resolves against the ${knownCount} pinned ids`);
}

if (require.main === module) main();

module.exports = { scan, TTP_PATTERN, NOT_REFERENCES, loadKnownIds };
