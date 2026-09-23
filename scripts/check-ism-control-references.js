#!/usr/bin/env node
"use strict";
/**
 * Checks every Australian ISM control the repository cites against the ISM
 * release pinned in sources/index.json (`au_frameworks.ism.oscal_release`).
 *
 * Two things are compared:
 *   1. every ISM-NNNN token in the shipped data, skills, library and scripts
 *      names a control that exists in the release
 *   2. every framework-control-gaps key of the form AU-ISM-NNNN carries
 *      control_id ISM-NNNN, and its control_name begins with that control's
 *      statement, so the key cannot describe a different control
 *
 * The release is ASD's own OSCAL catalog, fetched from
 * github.com/AustralianCyberSecurityCentre/ism-oscal at the pinned tag and
 * cached under .cache/upstream/ism/. With no cache and no network the check
 * reports that it could not verify and exits 2.
 *
 * Usage: node scripts/check-ism-control-references.js [--json]
 */

const fs = require("node:fs");
const path = require("node:path");
const https = require("node:https");

const ROOT = path.resolve(__dirname, "..");
const SOURCES = path.join(ROOT, "sources", "index.json");
const REGISTRY = path.join(ROOT, "data", "framework-control-gaps.json");
const CACHE_DIR = path.join(ROOT, ".cache", "upstream", "ism");
const JSON_OUT = process.argv.includes("--json");

// Paths scanned for citations, relative to the repository root. CHANGELOG.md
// records past releases and is not scanned.
const SCAN_ROOTS = ["data", "skills", "lib", "scripts", "AGENTS.md", "README.md", "ARCHITECTURE.md"];
const SKIP_DIRS = new Set(["_indexes", "node_modules", "vendor"]);
const SELF = path.relative(ROOT, __filename).split(path.sep).join("/");

const PIN_SHAPE = /^v[0-9]{4}\.[0-9]{2}\.[0-9]+$/;
// "ISM-" must not follow a letter or digit, so AU-ISM-1546 is read as a
// citation and a name such as PRISM-1234 is not.
const TOKEN = /(?<![A-Za-z0-9])ISM-([0-9]{4})\b/g;
const REGISTRY_KEY = /^AU-ISM-([0-9]{4})(?:-|$)/;

function emit(line) {
  if (!JSON_OUT) process.stdout.write(line + "\n");
}

function fetchText(url, redirects = 0) {
  return new Promise((resolve, reject) => {
    if (redirects > 5) return reject(new Error("too many redirects"));
    const req = https.get(url, { headers: { "user-agent": "exceptd-ism-references" } }, (res) => {
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
    req.setTimeout(60000, () => req.destroy(new Error("timed out")));
    req.on("error", reject);
  });
}

async function loadRelease(pin) {
  if (!PIN_SHAPE.test(pin)) throw new Error(`oscal_release ${JSON.stringify(pin)} is not a vYYYY.MM.N tag`);
  const cached = path.join(CACHE_DIR, `ISM_catalog-${pin}.json`);
  let text = null;
  try { text = fs.readFileSync(cached, "utf8"); }
  catch (e) { if (e.code !== "ENOENT") throw e; }
  let source = "cache";
  if (text === null) {
    text = await fetchText(`https://raw.githubusercontent.com/AustralianCyberSecurityCentre/ism-oscal/${pin}/ISM_catalog.json`);
    source = "network";
  }
  const controls = parseControls(text);
  const version = (JSON.parse(text).catalog.metadata || {}).version;
  if (`v${version}` !== pin) throw new Error(`the catalog for ${pin} declares version ${JSON.stringify(version)}`);
  if (source === "network") {
    fs.mkdirSync(CACHE_DIR, { recursive: true });
    fs.writeFileSync(cached, text);
  }
  return { controls, source };
}

// Map of "ISM-NNNN" to the control's statement, from an OSCAL catalog document.
function parseControls(text) {
  const out = new Map();
  (function walk(g) {
    for (const x of g.controls || []) {
      const m = /^ism-([0-9]{4})$/.exec(x.id || "");
      if (m) {
        const st = (x.parts || []).find((p) => p.name === "statement");
        out.set(`ISM-${m[1]}`, ((st && st.prose) || "").replace(/\s+/g, " ").trim());
      }
      walk(x);
    }
    for (const y of g.groups || []) walk(y);
  })(JSON.parse(text).catalog || {});
  return out;
}

// Every ISM-NNNN occurrence in a text, with its 1-based line number.
function findTokens(text) {
  const out = [];
  const lines = text.split("\n");
  lines.forEach((line, i) => {
    let m;
    TOKEN.lastIndex = 0;
    while ((m = TOKEN.exec(line)) !== null) out.push({ id: `ISM-${m[1]}`, line: i + 1 });
  });
  return out;
}

// A registry entry keyed AU-ISM-NNNN must name ISM-NNNN and describe it. The
// control_name may add a scope after the statement, as in
// "... managed (identity provider tenant)".
function registryProblems(key, entry, controls) {
  const m = REGISTRY_KEY.exec(key);
  if (!m) return [];
  const id = `ISM-${m[1]}`;
  const problems = [];
  if (!controls.has(id)) {
    problems.push(`${key}: ${id} does not exist in the pinned release`);
    return problems;
  }
  if (entry.control_id !== id) problems.push(`${key}: control_id is ${JSON.stringify(entry.control_id)}, expected ${id}`);
  const statement = controls.get(id).replace(/\.$/, "");
  const name = String(entry.control_name || "");
  if (!name.startsWith(statement)) {
    problems.push(`${key}: control_name ${JSON.stringify(name)} does not begin with the statement of ${id}: ${JSON.stringify(statement)}`);
  }
  return problems;
}

function scanFiles() {
  const files = [];
  function walk(p) {
    let st;
    try { st = fs.statSync(p); } catch (e) { if (e.code === "ENOENT") return; throw e; }
    if (st.isDirectory()) {
      if (SKIP_DIRS.has(path.basename(p))) return;
      for (const e of fs.readdirSync(p)) walk(path.join(p, e));
    } else if (/\.(json|md|js)$/.test(p)) {
      files.push(p);
    }
  }
  for (const r of SCAN_ROOTS) walk(path.join(ROOT, r));
  return files;
}

async function main() {
  const sources = JSON.parse(fs.readFileSync(SOURCES, "utf8"));
  const ism = ((sources.sources || sources).au_frameworks || {}).ism || {};
  const pin = ism.oscal_release;
  if (!pin) {
    process.stderr.write("[check-ism-control-references] sources/index.json has no au_frameworks.ism.oscal_release\n");
    process.exitCode = 1;
    return;
  }

  let release;
  try {
    release = await loadRelease(pin);
  } catch (e) {
    process.stderr.write(
      `[check-ism-control-references] COULD NOT VERIFY: ${e.message}\n` +
      "No citation was compared to anything, which is not the same as passing. " +
      `Re-run with network access, or place ISM_catalog-${pin}.json under ${path.relative(ROOT, CACHE_DIR)}.\n`
    );
    process.exitCode = 2;
    return;
  }
  emit(`[check-ism-control-references] ISM ${pin} (${release.source}): ${release.controls.size} controls`);

  const problems = [];
  let citations = 0;
  for (const f of scanFiles()) {
    const rel = path.relative(ROOT, f).split(path.sep).join("/");
    if (rel === SELF) continue;
    for (const t of findTokens(fs.readFileSync(f, "utf8"))) {
      citations++;
      if (!release.controls.has(t.id)) problems.push(`${rel}:${t.line}: ${t.id} does not exist in ISM ${pin}`);
    }
  }

  const registry = JSON.parse(fs.readFileSync(REGISTRY, "utf8"));
  let keys = 0;
  for (const [key, entry] of Object.entries(registry)) {
    if (key.startsWith("_") || !REGISTRY_KEY.test(key)) continue;
    keys++;
    problems.push(...registryProblems(key, entry, release.controls));
  }

  emit(`  citations checked: ${citations}   AU-ISM registry keys checked: ${keys}`);

  if (JSON_OUT) {
    process.stdout.write(JSON.stringify({ ok: problems.length === 0, pin, source: release.source, citations, registry_keys: keys, problems }, null, 2) + "\n");
  }
  if (problems.length) {
    process.stderr.write(`[check-ism-control-references] FAIL: ${problems.length} problem(s) against ISM ${pin}:\n`);
    for (const p of problems) process.stderr.write(`  - ${p}\n`);
    process.exitCode = 1;
    return;
  }
  emit(`[check-ism-control-references] PASS: every ISM control cited exists in ${pin}, and every AU-ISM registry key describes the control it names`);
}

if (require.main === module) {
  main().catch((e) => {
    process.stderr.write(`[check-ism-control-references] ${e.stack || e.message}\n`);
    process.exitCode = 2;
  });
}

module.exports = { parseControls, findTokens, registryProblems };
