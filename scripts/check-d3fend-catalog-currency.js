#!/usr/bin/env node
"use strict";
/**
 * Checks data/d3fend-catalog.json against the D3FEND release it is pinned to.
 *
 * Three things are compared, for the release named in `_meta.d3fend_version`:
 *   1. every D3- and D3A- style id in the catalog exists in the release
 *   2. every catalog name is a label the release gives that id, compared
 *      without regard to case; an id the release shares between artifacts
 *      accepts any of their labels, and an id written with a trailing dot in
 *      the release matches the catalog id without the dot
 *   3. every root tactic an entry lists (Model, Harden, Detect, Isolate,
 *      Deceive, Evict, Restore) is one the release assigns to that technique;
 *      the release assigns a tactic to a technique through `d3f:enables` on the
 *      technique or on a class it descends from. Entries whose tactic is not a
 *      root tactic (for example "Defensive") are not checked.
 *
 * A name may carry a trailing parenthetical qualifier without being a
 * divergence: "Credential Rotation (Automated)" renders the release's
 * "Credential Rotation".
 *
 * Divergences recorded in tests/.d3fend-divergence-baseline.json are reported
 * and allowed. A new divergence fails. A recorded divergence that no longer
 * occurs also fails, so the file only shrinks.
 *
 * The release is fetched from d3fend.mitre.org and cached under
 * .cache/upstream/d3fend/. A tagged release does not change, so the file is
 * written once per pin. With no cache and no network the check reports that it
 * could not verify and exits 2.
 *
 * Usage: node scripts/check-d3fend-catalog-currency.js [--json]
 */

const fs = require("node:fs");
const path = require("node:path");
const https = require("node:https");

const ROOT = path.resolve(__dirname, "..");
const CATALOG = path.join(ROOT, "data", "d3fend-catalog.json");
const BASELINE = path.join(ROOT, "tests", ".d3fend-divergence-baseline.json");
const CACHE_DIR = path.join(ROOT, ".cache", "upstream", "d3fend");
const JSON_OUT = process.argv.includes("--json");

const D3_ID = /^D3[A-Z]?-[A-Z0-9]+$/;
const PIN_SHAPE = /^[0-9]+\.[0-9]+(?:\.[0-9]+)?$/;

function emit(line) {
  if (!JSON_OUT) process.stdout.write(line + "\n");
}

function fetchText(url, redirects = 0) {
  return new Promise((resolve, reject) => {
    if (redirects > 5) return reject(new Error("too many redirects"));
    const req = https.get(url, { headers: { "user-agent": "exceptd-d3fend-currency" } }, (res) => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        res.resume();
        return resolve(fetchText(new URL(res.headers.location, url).toString(), redirects + 1));
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
    req.setTimeout(60000, () => req.destroy(new Error("timed out")));
    req.on("error", reject);
  });
}

function scalar(v) {
  if (Array.isArray(v)) return scalar(v[0]);
  if (v && typeof v === "object") return scalar(v["@value"]);
  return v == null ? "" : String(v).trim();
}

// Reads the JSON-LD graph into id -> label and id -> set of root tactic labels.
function parseRelease(text) {
  const doc = JSON.parse(text);
  const graph = Array.isArray(doc && doc["@graph"]) ? doc["@graph"] : [];
  const byIri = new Map();
  for (const node of graph) if (node && node["@id"]) byIri.set(node["@id"], node);

  const asList = (v) => (v == null ? [] : Array.isArray(v) ? v : [v]);
  const isTactic = (node) => !!node && asList(node["@type"]).includes("d3f:DefensiveTactic");

  const tacticLabels = new Set();
  for (const node of byIri.values()) if (isTactic(node)) tacticLabels.add(scalar(node["rdfs:label"]));

  // Tactics a class enables directly, then through every named ancestor.
  const direct = (node) => {
    const out = new Set();
    for (const e of asList(node["d3f:enables"])) {
      const target = e && byIri.get(e["@id"]);
      if (isTactic(target)) out.add(scalar(target["rdfs:label"]));
    }
    return out;
  };
  const tacticsOf = (node) => {
    const out = new Set();
    const seen = new Set();
    const walk = (n) => {
      if (!n || seen.has(n["@id"])) return;
      seen.add(n["@id"]);
      for (const t of direct(n)) out.add(t);
      for (const parent of asList(n["rdfs:subClassOf"])) {
        const iri = parent && parent["@id"];
        if (iri && !iri.startsWith("_:")) walk(byIri.get(iri));
      }
    };
    walk(node);
    return out;
  };

  // Several artifacts can carry one id (D3A-LR names Logistic Regression,
  // Linear Regression and Logical Rules), so every label and tactic is kept.
  // An id the ontology writes with a trailing dot (D3A-C4.) is keyed without it.
  const names = new Map();
  const labels = new Map();
  const tactics = new Map();
  for (const node of graph) {
    const raw = scalar(node && node["d3f:d3fend-id"]);
    const id = raw.replace(/\.+$/, "");
    if (!id) continue;
    const label = scalar(node["rdfs:label"]);
    if (!names.has(id)) {
      names.set(id, label);
      labels.set(id, []);
      tactics.set(id, new Set());
    }
    if (!labels.get(id).includes(label)) labels.get(id).push(label);
    for (const t of tacticsOf(node)) tactics.get(id).add(t);
  }
  return { names, labels, tactics, tacticLabels };
}

// A trailing parenthetical qualifier renders the same technique, and names
// compare without regard to case. `theirs` is one label or a list of labels
// that share an id.
function isRenderingOf(ours, theirs) {
  const list = (Array.isArray(theirs) ? theirs : [theirs]).filter(Boolean).map((t) => String(t).toLowerCase());
  if (!list.length) return false;
  const full = String(ours).trim().toLowerCase();
  const bare = full.replace(/\s*\([^)]*\)\s*$/, "").trim();
  return list.includes(full) || list.includes(bare);
}

// The root tactics an entry lists that the release does not assign to it. A
// tactic that is not a root tactic, and an id the release assigns no tactic to,
// are not checked.
function tacticProblems(id, tactic, release) {
  const allowed = release.tactics.get(id);
  if (!allowed || !allowed.size) return [];
  const values = (Array.isArray(tactic) ? tactic : [tactic])
    .map((t) => String(t == null ? "" : t).trim())
    .filter((t) => t && release.tacticLabels.has(t));
  return values.filter((v) => !allowed.has(v)).map((v) => ({ id, ours: v, theirs: [...allowed].sort() }));
}

// Returns every divergence between the catalog and the release, unfiltered.
function findDivergences(catalog, release) {
  const ids = Object.keys(catalog).filter((k) => !k.startsWith("_") && D3_ID.test(k));
  const missing = [];
  const misnamed = [];
  const wrongTactic = [];
  for (const id of ids) {
    const entry = catalog[id] || {};
    const ours = String(entry.name || "").trim();
    if (!release.names.has(id)) { missing.push({ id, ours }); continue; }
    const all = release.labels.get(id) || [release.names.get(id)];
    if (!isRenderingOf(ours, all)) misnamed.push({ id, ours, theirs: all.join(" | ") });
    wrongTactic.push(...tacticProblems(id, entry.tactic, release));
  }
  return { ids, missing, misnamed, wrongTactic };
}

function emptyBaseline() {
  return { names: {}, missing_ids: [], tactics: {} };
}

// Each allowance covers one finding: a recorded name excuses that name on that
// id only, and a recorded tactic excuses that tactic on that id only.
function checkCatalog(catalog, release, baseline, pin, baselineLabel = "the baseline file") {
  const { ids, missing, misnamed, wrongTactic } = findDivergences(catalog, release);
  const b = baseline || emptyBaseline();
  const names = b.names || {};
  const tacticBase = b.tactics || {};
  const allowedMissing = new Set(b.missing_ids || []);

  const nameAllowed = (x) => Object.prototype.hasOwnProperty.call(names, x.id) && names[x.id] === x.ours;
  const tacticAllowed = (x) => Array.isArray(tacticBase[x.id]) && tacticBase[x.id].includes(x.ours);

  const problems = [];
  for (const x of misnamed.filter((m) => !nameAllowed(m))) {
    problems.push(`${x.id} is named ${JSON.stringify(x.ours)}; D3FEND ${pin} names it ${JSON.stringify(x.theirs)}`);
  }
  for (const x of missing.filter((m) => !allowedMissing.has(m.id))) {
    problems.push(`${x.id} (${JSON.stringify(x.ours)}) does not exist in D3FEND ${pin}`);
  }
  for (const x of wrongTactic.filter((t) => !tacticAllowed(t))) {
    problems.push(`${x.id} lists tactic ${JSON.stringify(x.ours)}; D3FEND ${pin} assigns ${x.theirs.map((t) => JSON.stringify(t)).join(", ") || "none"}`);
  }
  for (const id of Object.keys(names)) {
    if (!misnamed.some((x) => x.id === id && x.ours === names[id])) {
      problems.push(`${id} is recorded as a name divergence but now agrees with the release; remove it from ${baselineLabel}`);
    }
  }
  for (const id of allowedMissing) {
    if (!missing.some((x) => x.id === id)) {
      problems.push(`${id} is recorded as absent from the release but now resolves; remove it from ${baselineLabel}`);
    }
  }
  for (const id of Object.keys(tacticBase)) {
    for (const t of tacticBase[id]) {
      if (!wrongTactic.some((x) => x.id === id && x.ours === t)) {
        problems.push(`${id} is recorded as listing tactic ${JSON.stringify(t)} against the release but now agrees; remove it from ${baselineLabel}`);
      }
    }
  }
  return {
    problems,
    checked: ids.length,
    found: { names: misnamed.length, missing_ids: missing.length, tactics: wrongTactic.length },
  };
}

async function loadRelease(pin) {
  if (!PIN_SHAPE.test(pin)) {
    throw new Error(`_meta.d3fend_version ${JSON.stringify(pin)} is not a release number`);
  }
  const cached = path.join(CACHE_DIR, `d3fend-${pin}.json`);
  let cachedText = null;
  try { cachedText = fs.readFileSync(cached, "utf8"); }
  catch (e) { if (e.code !== "ENOENT") throw e; }
  if (cachedText !== null) {
    try { return { release: parseRelease(cachedText), source: "cache" }; }
    catch { /* a truncated cache file is fetched again */ }
  }
  const url = `https://d3fend.mitre.org/ontologies/d3fend/${pin}/d3fend.json`;
  const text = await fetchText(url);
  const release = parseRelease(text);
  if (!release.names.size) throw new Error(`the file at ${url} carries no d3fend-id entries`);
  fs.mkdirSync(CACHE_DIR, { recursive: true });
  fs.writeFileSync(cached, text);
  return { release, source: "network" };
}

function readBaseline() {
  try {
    const j = JSON.parse(fs.readFileSync(BASELINE, "utf8"));
    return { names: j.names || {}, missing_ids: j.missing_ids || [], tactics: j.tactics || {} };
  } catch (e) {
    if (e.code === "ENOENT") return emptyBaseline();
    process.stderr.write(`[check-d3fend-catalog-currency] cannot read the baseline: ${e.message}\n`);
    return null;
  }
}

async function main() {
  const catalog = JSON.parse(fs.readFileSync(CATALOG, "utf8"));
  const pin = catalog._meta && catalog._meta.d3fend_version;
  if (!pin) {
    process.stderr.write("[check-d3fend-catalog-currency] data/d3fend-catalog.json has no _meta.d3fend_version\n");
    process.exitCode = 1;
    return;
  }

  const baseline = readBaseline();
  if (!baseline) { process.exitCode = 1; return; }

  let loaded;
  try {
    loaded = await loadRelease(pin);
  } catch (e) {
    process.stderr.write(
      `[check-d3fend-catalog-currency] COULD NOT VERIFY: ${e.message}\n` +
      "The catalog was not compared to anything. " +
      `Re-run with network access, or place the release file under ${path.relative(ROOT, CACHE_DIR)}.\n`
    );
    process.exitCode = 2;
    return;
  }

  emit(`[check-d3fend-catalog-currency] D3FEND ${pin} (${loaded.source}): ${loaded.release.names.size} ids`);
  const baselineLabel = path.relative(ROOT, BASELINE).split(path.sep).join("/");
  const r = checkCatalog(catalog, loaded.release, baseline, pin, baselineLabel);
  emit(`  ids checked: ${r.checked}`);
  emit(`  divergences found: ${r.found.names} name(s), ${r.found.missing_ids} absent id(s), ${r.found.tactics} tactic(s)`);

  if (JSON_OUT) {
    process.stdout.write(JSON.stringify({
      ok: r.problems.length === 0, pin, source: loaded.source,
      checked: r.checked, problems: r.problems, found: r.found,
    }, null, 2) + "\n");
  }

  if (r.problems.length) {
    process.stderr.write(`[check-d3fend-catalog-currency] FAIL: ${r.problems.length} problem(s) against D3FEND ${pin}:\n`);
    for (const p of r.problems) process.stderr.write(`  - ${p}\n`);
    process.stderr.write(
      `\nCorrect data/d3fend-catalog.json to match the pinned release, or record the divergence in ${baselineLabel}.\n`
    );
    process.exitCode = 1;
    return;
  }

  emit(`[check-d3fend-catalog-currency] PASS: every id, name and tactic agrees with D3FEND ${pin}, or is a recorded divergence`);
}

if (require.main === module) {
  main().catch((e) => {
    process.stderr.write(`[check-d3fend-catalog-currency] ${e.stack || e.message}\n`);
    process.exitCode = 2;
  });
}

module.exports = { parseRelease, isRenderingOf, tacticProblems, findDivergences, checkCatalog };
