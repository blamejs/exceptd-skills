#!/usr/bin/env node
"use strict";
/**
 * Checks data/attack-techniques.json against the ATT&CK release it claims to be
 * pinned to.
 *
 * check-ttp-references.js resolves technique ids used elsewhere in the repo
 * against this catalog, and nothing else compares the catalog to MITRE, so an id
 * can carry another technique's name or a tactic MITRE no longer assigns while
 * every other gate passes.
 *
 * scripts/check-ttp-upstream.js, which runs in the refresh workflow, checks that
 * each id exists upstream and is not revoked or deprecated. This gate runs in
 * predeploy and also compares what the catalog says about each id.
 *
 * For the release named in `_meta.attack_version`, read from the Enterprise, ICS
 * and Mobile STIX bundles MITRE publishes at the matching tag of attack-stix-data:
 *   1. every T id in the catalog is an active technique upstream (present, not
 *      revoked, not deprecated)
 *   2. every catalog name is the name upstream gives that id
 *   3. every `stix_id` is the STIX id upstream gives that technique
 *   4. every tactic an entry lists is one upstream assigns to that technique; a
 *      sub-technique with no tactics of its own is checked against its parent's
 *
 * A name may be written as upstream stores it or as attack.mitre.org titles a
 * sub-technique ("Parent: Child"), and a name or tactic may carry a trailing
 * parenthetical qualifier such as "(ICS)".
 *
 * Divergences recorded in tests/.attack-divergence-baseline.json are reported
 * and allowed, and a recorded divergence that now agrees with upstream is an
 * error, so the file only shrinks. Tactics and STIX ids have no baseline.
 *
 * The bundles are fetched over the network and cached under
 * .cache/upstream/attack/. A tagged release is immutable, so the cache is
 * written once per pin. With no cache and no network the check exits 2: the
 * catalog was not compared to anything.
 *
 * Usage: node scripts/check-attack-catalog-currency.js [--json]
 */

const fs = require("node:fs");
const path = require("node:path");
const { assertPinShape, assertAllowedUrl } = require("./check-ttp-upstream.js");

const ROOT = path.resolve(__dirname, "..");
const CATALOG = path.join(ROOT, "data", "attack-techniques.json");
const BASELINE = path.join(ROOT, "tests", ".attack-divergence-baseline.json");
const CACHE_DIR = path.join(ROOT, ".cache", "upstream", "attack");
const JSON_OUT = process.argv.includes("--json");

const DOMAINS = ["enterprise-attack", "ics-attack", "mobile-attack"];
const TECHNIQUE_ID = /^T[0-9]{4}(?:\.[0-9]{3})?$/;
const SOURCE_NAME = /^mitre-(?:ics-|mobile-)?attack$/;

function emit(line) {
  if (!JSON_OUT) process.stdout.write(line + "\n");
}

// Only raw.githubusercontent.com, and no redirects.
async function fetchBuffer(url) {
  const res = await fetch(assertAllowedUrl(url), {
    headers: { "user-agent": "exceptd-attack-currency" },
    redirect: "error",
    signal: AbortSignal.timeout(180000),
  });
  if (!res.ok) throw new Error(`HTTP ${res.status} for ${url}`);
  return Buffer.from(await res.arrayBuffer());
}

// The version a bundle declares in its x-mitre-collection object, or null.
function bundleVersion(bundle) {
  const objects = bundle && Array.isArray(bundle.objects) ? bundle.objects : [];
  const coll = objects.find((o) => o && o.type === "x-mitre-collection");
  return coll && typeof coll.x_mitre_version === "string" ? coll.x_mitre_version : null;
}

async function loadBundle(domain, rawPin) {
  // The pin becomes part of a URL and a cache path.
  const pin = assertPinShape("attack", rawPin);
  const file = `${domain}-${pin}.json`;
  const cached = path.join(CACHE_DIR, file);
  // Read and handle absence, rather than asking whether it exists and then
  // reading: between the two answers the file can change.
  let text = null;
  try { text = fs.readFileSync(cached, "utf8"); }
  catch (e) { if (e.code !== "ENOENT") throw e; }
  if (text !== null) {
    let bundle = null;
    try { bundle = JSON.parse(text); } catch { bundle = null; }
    if (bundle && bundleVersion(bundle) === pin) return { bundle, source: "cache" };
  }
  const url = `https://raw.githubusercontent.com/mitre-attack/attack-stix-data/v${pin}/${domain}/${file}`;
  const body = await fetchBuffer(url);
  const bundle = JSON.parse(body.toString("utf8"));
  if (bundleVersion(bundle) !== pin) {
    throw new Error(`the bundle at ${url} declares version ${JSON.stringify(bundleVersion(bundle))}, not ${pin}`);
  }
  fs.mkdirSync(CACHE_DIR, { recursive: true });
  fs.writeFileSync(cached, body);
  return { bundle, source: "network" };
}

// Technique id -> { name, display, status, stixIds, tactics } across the given
// bundles. `display` is the "Parent: Child" title of a sub-technique, `status`
// is active, revoked or deprecated, and `tactics` holds tactic display names.
function buildIndex(bundles) {
  const index = new Map();
  for (const bundle of bundles) {
    const objects = bundle && Array.isArray(bundle.objects) ? bundle.objects : [];
    const tacticNames = new Map();
    for (const o of objects) {
      if (o && o.type === "x-mitre-tactic" && o.x_mitre_shortname) tacticNames.set(o.x_mitre_shortname, o.name);
    }
    const byId = new Map();
    for (const o of objects) {
      if (!o || o.type !== "attack-pattern") continue;
      const ref = (o.external_references || []).find((r) => r && SOURCE_NAME.test(r.source_name));
      if (!ref || !TECHNIQUE_ID.test(ref.external_id)) continue;
      const status = o.revoked ? "revoked" : o.x_mitre_deprecated ? "deprecated" : "active";
      const prev = byId.get(ref.external_id);
      // An id can appear as a revoked object and as its active replacement; the
      // active one is the record for that id.
      if (prev && prev.status === "active" && status !== "active") continue;
      byId.set(ref.external_id, {
        name: o.name,
        status,
        stixId: o.id,
        tactics: (o.kill_chain_phases || []).map((p) => tacticNames.get(p.phase_name) || p.phase_name),
      });
    }
    for (const [id, t] of byId) {
      const parent = /^(T[0-9]{4})\.[0-9]{3}$/.exec(id);
      const parentName = parent && byId.get(parent[1]) ? byId.get(parent[1]).name : null;
      const display = parentName ? `${parentName}: ${t.name}` : t.name;
      const prev = index.get(id);
      if (!prev) {
        index.set(id, { name: t.name, display, status: t.status, stixIds: new Set([t.stixId]), tactics: new Set(t.tactics) });
      } else {
        // The same technique published in more than one domain.
        prev.stixIds.add(t.stixId);
        for (const x of t.tactics) prev.tactics.add(x);
        if (t.status === "active") prev.status = "active";
      }
    }
  }
  return index;
}

function stripQualifier(s) {
  return String(s == null ? "" : s).replace(/\s*\([^)]*\)\s*$/, "").trim();
}

// Whether a catalog name names the same technique as upstream: the stored name,
// the "Parent: Child" title, either with a trailing parenthetical qualifier.
function isRenderingOf(ours, up) {
  if (!up) return false;
  const name = String(ours == null ? "" : ours).trim();
  return [name, stripQualifier(name)].some((n) => n === up.name || n === up.display);
}

// The tactic values an entry lists that upstream does not assign to it. An entry
// may list fewer tactics than upstream; it may not list a different one.
function tacticProblems(id, tactic, index) {
  const values = (Array.isArray(tactic) ? tactic : [tactic]).map(stripQualifier).filter(Boolean);
  if (!values.length) return [];
  const own = index.get(id);
  const parent = /^(T[0-9]{4})\.[0-9]{3}$/.exec(id);
  const allowed = own && own.tactics.size ? own.tactics : parent && index.get(parent[1]) ? index.get(parent[1]).tactics : null;
  if (!allowed || !allowed.size) return [];
  return values.filter((v) => !allowed.has(v)).map((v) => ({ id, ours: v, theirs: [...allowed].sort() }));
}

function readBaseline() {
  let text;
  try { text = fs.readFileSync(BASELINE, "utf8"); }
  catch (e) {
    if (e.code === "ENOENT") return { names: {}, missing_ids: [] };
    throw e;
  }
  const j = JSON.parse(text);
  return { names: j.names || {}, missing_ids: j.missing_ids || [] };
}

// Every problem the catalog has against the index, given the recorded baseline.
function checkCatalog(catalog, index, baseline, pin) {
  const ids = Object.keys(catalog).filter((k) => !k.startsWith("_"));
  const problems = [];
  const misnamed = [];
  const missing = [];
  for (const id of ids) {
    const e = catalog[id] || {};
    if (!TECHNIQUE_ID.test(id)) { problems.push(`${id} is not an ATT&CK technique id`); continue; }
    const up = index.get(id);
    if (!up) { missing.push(id); continue; }
    if (up.status !== "active") problems.push(`${id} is ${up.status} in ATT&CK ${pin}`);
    if (!isRenderingOf(e.name, up)) misnamed.push({ id, ours: String(e.name || ""), theirs: up.display });
    if (e.stix_id && !up.stixIds.has(e.stix_id)) {
      problems.push(`${id} has stix_id ${e.stix_id}; ATT&CK ${pin} gives it ${[...up.stixIds].join(", ")}`);
    }
    for (const x of tacticProblems(id, e.tactic, index)) {
      problems.push(`${x.id} lists tactic ${JSON.stringify(x.ours)}; ATT&CK ${pin} assigns ${x.theirs.map((t) => JSON.stringify(t)).join(", ")}`);
    }
  }
  const allowedName = baseline.names || {};
  const allowedMissing = new Set(baseline.missing_ids || []);
  for (const x of misnamed) {
    if (allowedName[x.id] === x.ours) continue;
    problems.push(`${x.id} is named ${JSON.stringify(x.ours)}; ATT&CK ${pin} names it ${JSON.stringify(x.theirs)}`);
  }
  for (const id of missing) {
    if (allowedMissing.has(id)) continue;
    problems.push(`${id} (${JSON.stringify(String((catalog[id] || {}).name || ""))}) does not exist in Enterprise, ICS or Mobile ATT&CK ${pin}`);
  }
  const rel = path.relative(ROOT, BASELINE);
  for (const id of Object.keys(allowedName)) {
    if (!misnamed.some((x) => x.id === id && x.ours === allowedName[id])) {
      problems.push(`${id} is recorded as a name divergence but no longer diverges that way; remove it from ${rel}`);
    }
  }
  for (const id of allowedMissing) {
    if (!missing.includes(id)) problems.push(`${id} is recorded as absent upstream but now resolves or left the catalog; remove it from ${rel}`);
  }
  return { checked: ids.length, problems };
}

async function main() {
  const catalog = JSON.parse(fs.readFileSync(CATALOG, "utf8"));
  const pin = catalog._meta && catalog._meta.attack_version;
  if (!pin) {
    process.stderr.write("[check-attack-catalog-currency] data/attack-techniques.json has no _meta.attack_version\n");
    process.exitCode = 1;
    return;
  }

  let baseline;
  try { baseline = readBaseline(); }
  catch (e) {
    process.stderr.write(`[check-attack-catalog-currency] cannot read the baseline: ${e.message}\n`);
    process.exitCode = 1;
    return;
  }

  const bundles = [];
  const sources = [];
  try {
    for (const domain of DOMAINS) {
      const r = await loadBundle(domain, String(pin));
      bundles.push(r.bundle);
      sources.push(`${domain} ${r.source}`);
    }
  } catch (e) {
    process.stderr.write(
      `[check-attack-catalog-currency] COULD NOT VERIFY: ${e.message}\n` +
      "The catalog was not compared to anything, which is not the same as passing. " +
      `Re-run with network access, or place the release bundles under ${path.relative(ROOT, CACHE_DIR)}.\n`
    );
    process.exitCode = 2;
    return;
  }

  const index = buildIndex(bundles);
  emit(`[check-attack-catalog-currency] ATT&CK ${pin} (${sources.join(", ")}): ${index.size} techniques`);
  const { checked, problems } = checkCatalog(catalog, index, baseline, pin);
  emit(`  ids checked: ${checked}`);

  if (JSON_OUT) {
    process.stdout.write(JSON.stringify({ ok: problems.length === 0, pin, sources, checked, problems }, null, 2) + "\n");
  }
  if (problems.length) {
    process.stderr.write(`[check-attack-catalog-currency] FAIL: ${problems.length} problem(s) against ATT&CK ${pin}:\n`);
    for (const p of problems) process.stderr.write(`  - ${p}\n`);
    process.stderr.write(
      "\nEither correct data/attack-techniques.json to match the pinned release, or, if a name or a " +
      `missing id is deliberate and tracked, record it in ${path.relative(ROOT, BASELINE)}.\n`
    );
    process.exitCode = 1;
    return;
  }
  emit(`[check-attack-catalog-currency] PASS: every id, name, STIX id and tactic agrees with ATT&CK ${pin}`);
}

if (require.main === module) {
  main().catch((e) => {
    process.stderr.write(`[check-attack-catalog-currency] ${e.stack || e.message}\n`);
    process.exitCode = 2;
  });
}

module.exports = { bundleVersion, buildIndex, isRenderingOf, tacticProblems, checkCatalog };
