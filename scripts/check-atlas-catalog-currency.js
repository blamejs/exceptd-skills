#!/usr/bin/env node
"use strict";
/**
 * Checks data/atlas-ttps.json against the ATLAS release it claims to be pinned to.
 *
 * Every other check treats the catalog as ground truth: check-ttp-references.js
 * resolves ids used elsewhere in the repo against it, and nothing compares it to
 * MITRE. An id can therefore carry a name MITRE gives to a different technique,
 * or name a sub-technique that does not exist, and every gate stays green.
 *
 * Three things are compared, for the release named in `_meta.atlas_version`:
 *   1. every AML id in the catalog exists upstream
 *   2. every catalog name is the name upstream gives that id
 *   3. every AML sub-technique id named inside a `subtechniques` list exists
 *
 * Divergences recorded in tests/.atlas-divergence-baseline.json are reported and
 * allowed, so known work in progress does not block a release while any NEW
 * divergence does. An entry that has been repaired and is still in the baseline
 * is also an error, so the file shrinks instead of going stale.
 *
 * Two naming conventions are accepted without a baseline entry, because they
 * render the same technique rather than a different one: a sub-technique may be
 * written "Parent: Child" where upstream stores only "Child", and a name may
 * carry a parenthetical qualifier.
 *
 * The release data is fetched over the network and cached under
 * .cache/upstream/atlas/. A tagged release is immutable, so the cache is only
 * ever written once per pin. With no cache and no network the check reports
 * that it could not verify and exits non-zero: not having checked is not the
 * same as having passed.
 *
 * Usage: node scripts/check-atlas-catalog-currency.js [--json]
 */

const fs = require("node:fs");
const path = require("node:path");
const https = require("node:https");

const ROOT = path.resolve(__dirname, "..");
const CATALOG = path.join(ROOT, "data", "atlas-ttps.json");
const BASELINE = path.join(ROOT, "tests", ".atlas-divergence-baseline.json");
const CACHE_DIR = path.join(ROOT, ".cache", "upstream", "atlas");
const JSON_OUT = process.argv.includes("--json");

const AML_ID = /^AML\.(?:TA|T|M|CS)[0-9]+(?:\.[0-9]+)?$/;

function emit(line) {
  if (!JSON_OUT) process.stdout.write(line + "\n");
}

function fetchText(url, redirects = 0) {
  return new Promise((resolve, reject) => {
    if (redirects > 5) return reject(new Error("too many redirects"));
    const req = https.get(url, { headers: { "user-agent": "exceptd-atlas-currency" } }, (res) => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        res.resume();
        return resolve(fetchText(res.headers.location, redirects + 1));
      }
      if (res.statusCode !== 200) {
        res.resume();
        return reject(new Error(`HTTP ${res.statusCode} for ${url}`));
      }
      let body = "";
      res.setEncoding("utf8");
      res.on("data", (c) => { body += c; });
      res.on("end", () => resolve(body));
    });
    req.setTimeout(30000, () => req.destroy(new Error("timed out")));
    req.on("error", reject);
  });
}

async function loadRelease(pin) {
  const cached = path.join(CACHE_DIR, `ATLAS-${pin}.yaml`);
  if (fs.existsSync(cached)) {
    const text = fs.readFileSync(cached, "utf8");
    if (text.includes(`version: '${pin}'`)) return { text, source: "cache" };
  }
  const url = `https://raw.githubusercontent.com/mitre-atlas/atlas-data/v${pin}/dist/v6/ATLAS-${pin}.yaml`;
  const text = await fetchText(url);
  if (!text.includes(`version: '${pin}'`)) {
    throw new Error(`the file at ${url} does not declare version ${pin}`);
  }
  fs.mkdirSync(CACHE_DIR, { recursive: true });
  fs.writeFileSync(cached, text);
  return { text, source: "network" };
}

// Format 6 keys each object by its id, with name as the first child key.
function parseNames(text) {
  const re = /\n {2}(AML\.(?:TA|T|M|CS)[0-9.]+):\n {4}name:\s*(?:"([^"]*)"|'([^']*)'|([^\n]*))/g;
  const out = new Map();
  let m;
  while ((m = re.exec(text)) !== null) {
    const name = (m[2] !== undefined ? m[2] : m[3] !== undefined ? m[3] : (m[4] || "")).trim();
    if (!out.has(m[1])) out.set(m[1], name);
  }
  return out;
}

// "Use Alternate Authentication Material: Web Session Cookie" renders upstream's
// "Web Session Cookie" with its parent; "AI Agent (as Attacker Asset)" qualifies
// upstream's "AI Agent". Neither names a different technique.
function isRenderingOf(ours, theirs) {
  if (!theirs) return false;
  const bare = ours.replace(/\s*\([^)]*\)\s*$/, "").trim();
  if (bare === theirs) return true;
  const i = ours.lastIndexOf(": ");
  return i > 0 && ours.slice(i + 2).trim() === theirs;
}

function readBaseline() {
  if (!fs.existsSync(BASELINE)) return { names: {}, missing_ids: [], missing_subtechniques: [] };
  try {
    const j = JSON.parse(fs.readFileSync(BASELINE, "utf8"));
    return {
      names: j.names || {},
      missing_ids: j.missing_ids || [],
      missing_subtechniques: j.missing_subtechniques || [],
    };
  } catch (e) {
    process.stderr.write(`[check-atlas-catalog-currency] cannot read the baseline: ${e.message}\n`);
    return null;
  }
}

async function main() {
  const catalog = JSON.parse(fs.readFileSync(CATALOG, "utf8"));
  const pin = catalog._meta && catalog._meta.atlas_version;
  if (!pin) {
    process.stderr.write("[check-atlas-catalog-currency] data/atlas-ttps.json has no _meta.atlas_version\n");
    process.exitCode = 1;
    return;
  }

  const baseline = readBaseline();
  if (!baseline) { process.exitCode = 1; return; }

  let release;
  try {
    release = await loadRelease(pin);
  } catch (e) {
    process.stderr.write(
      `[check-atlas-catalog-currency] COULD NOT VERIFY against ATLAS ${pin}: ${e.message}\n` +
      "The catalog was not compared to anything. This is not a pass — re-run with network access, " +
      `or prime the cache at .cache/upstream/atlas/ATLAS-${pin}.yaml.\n`
    );
    process.exitCode = 2;
    return;
  }

  const upstream = parseNames(release.text);
  emit(`[check-atlas-catalog-currency] ATLAS ${pin} (${release.source}): ${upstream.size} objects`);

  const ids = Object.keys(catalog).filter((k) => !k.startsWith("_"));
  const missing = [];
  const misnamed = [];
  const missingSub = [];

  for (const id of ids) {
    if (!AML_ID.test(id)) continue;
    const ours = String(catalog[id].name || "").trim();
    if (!upstream.has(id)) { missing.push({ id, ours }); continue; }
    const theirs = upstream.get(id);
    if (ours !== theirs && !isRenderingOf(ours, theirs)) misnamed.push({ id, ours, theirs });
  }

  for (const id of ids) {
    const subs = catalog[id] && catalog[id].subtechniques;
    if (!Array.isArray(subs)) continue;
    for (const s of subs) {
      const m = String(s).match(/AML\.T[0-9]+\.[0-9]+/);
      if (m && !upstream.has(m[0])) missingSub.push({ id, sub: m[0] });
    }
  }

  // Each allowance covers exactly one finding. A recorded name does not excuse a
  // sub-technique id, and a recorded sub-technique id does not excuse its
  // siblings, so a new bad id under an entry that already diverges still fails.
  const allowedName = new Set(Object.keys(baseline.names));
  const allowedMissing = new Set(baseline.missing_ids);
  const allowedSub = new Set(baseline.missing_subtechniques);

  const newMisnamed = misnamed.filter((x) => !(allowedName.has(x.id) && baseline.names[x.id] === x.ours));
  const newMissing = missing.filter((x) => !allowedMissing.has(x.id));
  const newMissingSub = missingSub.filter((x) => !allowedSub.has(x.sub));

  const acceptedName = misnamed.filter((x) => allowedName.has(x.id) && baseline.names[x.id] === x.ours);
  const acceptedSub = missingSub.filter((x) => allowedSub.has(x.sub));
  const staleNames = [...allowedName].filter((id) => !misnamed.some((x) => x.id === id));
  const staleMissing = [...allowedMissing].filter((id) => !missing.some((x) => x.id === id));
  const staleSubs = [...allowedSub].filter((sub) => !missingSub.some((x) => x.sub === sub));

  emit(`  ids checked: ${ids.length}`);
  emit(`  recorded divergences still present: ${acceptedName.length} name(s), ${acceptedSub.length} sub-technique id(s)`);

  const problems = [];
  for (const x of newMisnamed) problems.push(`${x.id} is named ${JSON.stringify(x.ours)}; ATLAS ${pin} names it ${JSON.stringify(x.theirs)}`);
  for (const x of newMissing) problems.push(`${x.id} (${JSON.stringify(x.ours)}) does not exist in ATLAS ${pin}`);
  for (const x of newMissingSub) problems.push(`${x.id} names sub-technique ${x.sub}, which does not exist in ATLAS ${pin}`);
  for (const id of staleNames) problems.push(`${id} is recorded as a name divergence but now agrees with upstream; remove it from ${path.relative(ROOT, BASELINE)}`);
  for (const id of staleMissing) problems.push(`${id} is recorded as absent upstream but now resolves; remove it from ${path.relative(ROOT, BASELINE)}`);
  for (const sub of staleSubs) problems.push(`${sub} is recorded as absent upstream but is no longer named or now resolves; remove it from ${path.relative(ROOT, BASELINE)}`);

  if (JSON_OUT) {
    process.stdout.write(JSON.stringify({
      ok: problems.length === 0, pin, source: release.source,
      checked: ids.length, problems,
      accepted: { names: acceptedName.length, missing_subtechniques: missingSub.length - newMissingSub.length },
    }, null, 2) + "\n");
  }

  if (problems.length) {
    process.stderr.write(`[check-atlas-catalog-currency] FAIL — ${problems.length} problem(s) against ATLAS ${pin}:\n`);
    for (const p of problems) process.stderr.write(`  - ${p}\n`);
    process.stderr.write(
      "\nEither correct data/atlas-ttps.json to match the pinned release, or, if the divergence is " +
      `deliberate and tracked, record it in ${path.relative(ROOT, BASELINE)} with the issue that will close it.\n`
    );
    process.exitCode = 1;
    return;
  }

  emit(`[check-atlas-catalog-currency] PASS — every id and name agrees with ATLAS ${pin}, or is a recorded divergence`);
}

if (require.main === module) {
  main().catch((e) => {
    process.stderr.write(`[check-atlas-catalog-currency] ${e.stack || e.message}\n`);
    process.exitCode = 2;
  });
}

module.exports = { parseNames, isRenderingOf, main };
