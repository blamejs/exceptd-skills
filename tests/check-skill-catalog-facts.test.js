"use strict";

/**
 * tests/check-skill-catalog-facts.test.js
 *
 * Subject coverage for the scripts/check-skill-catalog-facts.js predeploy gate,
 * which compares the CVE facts a skill states (CVSS, RWEP, KEV status and date,
 * public exploit, AI discovery, active exploitation, vendor patch and live
 * patch) against data/cve-catalog.json.
 *
 *  - PASS contract (live): the shipped skills match the shipped catalog;
 *  - FAIL contract: a disagreeing skill exits 1 and names file, line and CVE;
 *  - table columns: each column kind is compared, by header;
 *  - AI columns: "AI-Discovered" reads ai_discovered, a combined AI column
 *    reads ai_discovered or ai_assisted_weaponization;
 *  - skipped: non-comparable cells, ranges, thresholds, projections, superseded
 *    values, a row that only points to a CVE, a CVE the catalog does not hold.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const ROOT = path.resolve(__dirname, "..");
const SCRIPT = path.join(ROOT, "scripts", "check-skill-catalog-facts.js");
const { check, checkSkill, columnKind, yesNo } = require(SCRIPT);

const CATALOG = {
  "CVE-2099-0001": { cvss_score: 7.8, cvss_vector: "CVSS:3.1/AV:L", rwep_score: 35, cisa_kev: false, cisa_kev_date: null, poc_available: true, ai_discovered: true, ai_assisted_weaponization: false },
  "CVE-2099-0002": { cvss_score: 9.8, cvss_vector: "CVSS:3.1/AV:N", rwep_score: 80, cisa_kev: true, cisa_kev_date: "2099-02-03", poc_available: false, ai_discovered: false, ai_assisted_weaponization: false },
  "CVE-2099-0003": { cvss_score: 7.8, cvss_vector: "CVSS:4.0/AV:L", rwep_score: 30, cisa_kev: false, cisa_kev_date: null, poc_available: true, ai_discovered: false, ai_assisted_weaponization: true },
};

function withSkill(body, fn) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "skill-facts-"));
  try {
    fs.mkdirSync(path.join(dir, "demo"));
    const file = path.join(dir, "demo", "skill.md");
    fs.writeFileSync(file, body);
    return fn(file, dir);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

/**
 * Each row in a table and heading section of its own under `header`, so a CVE on
 * several rows is not read as a per-row table. Row i sits on line 3 + 4i.
 */
const apart = (header, rows) => rows.flatMap((row, i) =>
  [header, "|" + "---|".repeat(header.split("|").length - 2), row].concat(i < rows.length - 1 ? [`## Case ${i + 2}`] : []));

/** Failure lines with the skill path removed: "<line> <CVE>: <disagreement>". */
const failuresFor = (lines) =>
  withSkill(lines.join("\n") + "\n", (file) => checkSkill(file, CATALOG).failures.map((f) => f.replace(/^.*skill\.md:/, "")));

/**
 * How the gate reads one patch cell under `header`, found by checking it against
 * both catalog values: a compared cell fails against exactly one of them, and a
 * cell that is not compared fails against neither.
 */
function patchVerdict(cell, header = "Patch Available") {
  const run = (patch) => withSkill([`| CVE | ${header} |`, "|---|---|", `| CVE-2099-0001 | ${cell} |`].join("\n") + "\n",
    (file) => checkSkill(file, { ...CATALOG, "CVE-2099-0001": { ...CATALOG["CVE-2099-0001"], patch_available: patch } }).failures.length);
  const againstTrue = run(true);
  const againstFalse = run(false);
  if (againstTrue && !againstFalse) return "no patch";
  if (!againstTrue && againstFalse) return "patch";
  if (!againstTrue && !againstFalse) return "not compared";
  return "both";
}

/**
 * Reads `template` with each "_" as one space and as two spaces, and each "~" as
 * no space, one space and two spaces, and expects `expected` every time. Closing
 * any one "_" must give a different reading.
 */
function spacing(template, read, expected) {
  const parts = template.split(/([_~])/);
  const build = (gap) => parts.map((p, i) => (i % 2 ? gap(p, (i - 1) / 2) : p)).join("");
  for (const width of [1, 2]) {
    const text = build(() => " ".repeat(width));
    assert.deepEqual(read(text), expected, JSON.stringify(text));
  }
  const tight = build((sep) => (sep === "~" ? "" : " "));
  assert.deepEqual(read(tight), expected, JSON.stringify(tight));
  parts.forEach((p, i) => {
    if (!(i % 2) || p !== "_") return;
    const closed = build((sep, g) => (g === (i - 1) / 2 || sep === "~" ? "" : " "));
    assert.notDeepEqual(read(closed), expected, JSON.stringify(closed));
  });
}

test("PASS contract (live): the shipped skills match data/cve-catalog.json", () => {
  const r = spawnSync(process.execPath, [SCRIPT], { cwd: ROOT, encoding: "utf8" });
  assert.equal(r.status, 0, r.stderr);
  const m = /^Skill catalog facts: PASS — (\d+) CVE rows and lines across (\d+) skills/.exec(r.stdout);
  assert.ok(m, r.stdout);
  // A floor on what the sweep compares: a selection or parsing change that
  // silently stops reading most rows would otherwise still print PASS.
  assert.ok(Number(m[1]) >= 340, `compared only ${m[1]} rows and lines`);
  assert.ok(Number(m[2]) >= 45, `swept only ${m[2]} skills`);
});

test("PASS contract (live): each compared field is still read from the shipped skills", () => {
  // Inverting one field on every catalog entry turns each comparison of that
  // field into a failure, so the failure count is the number of rows and lines
  // the sweep reads for it. A floor per field catches a parsing change that stops
  // comparing cells while rows are still selected.
  const base = JSON.parse(fs.readFileSync(path.join(ROOT, "data", "cve-catalog.json"), "utf8"));
  const EXPL = { confirmed: "none", none: "confirmed", suspected: "confirmed", unknown: "confirmed", theoretical: "confirmed" };
  const flips = {
    patch_available: [(e) => { e.patch_available = !e.patch_available; }, 25],
    live_patch_available: [(e) => { e.live_patch_available = !e.live_patch_available; }, 35],
    active_exploitation: [(e) => { e.active_exploitation = EXPL[String(e.active_exploitation || "").toLowerCase()] || "confirmed"; }, 28],
    poc_available: [(e) => { e.poc_available = !e.poc_available; }, 55],
    cisa_kev: [(e) => { e.cisa_kev = !e.cisa_kev; }, 60],
    rwep_score: [(e) => { e.rwep_score = (e.rwep_score || 0) + 1; }, 80],
    cvss_score: [(e) => { e.cvss_score = Math.round(((e.cvss_score || 0) + 0.1) * 10) / 10; }, 85],
    ai_discovered: [(e) => { e.ai_discovered = !e.ai_discovered; }, 45],
    // An AI / AI-enabled cell reads either flag, so both are set to the negation of
    // their combined value; flipping each alone leaves an entry with one flag set
    // still reading as AI.
    ai_any: [(e) => { const any = Boolean(e.ai_discovered) || Boolean(e.ai_assisted_weaponization); e.ai_discovered = !any; e.ai_assisted_weaponization = !any; }, 35],
    cisa_kev_date: [(e) => { if (e.cisa_kev_date) e.cisa_kev_date = "1999-01-01"; }, 15],
  };
  for (const [field, [flip, floor]] of Object.entries(flips)) {
    const cat = JSON.parse(JSON.stringify(base));
    for (const [id, e] of Object.entries(cat)) if (/^CVE-/.test(id) && e && typeof e === "object") flip(e);
    const n = check(path.join(ROOT, "skills"), cat).failures.length;
    assert.ok(n >= floor, `${field}: only ${n} comparisons read from the skills (floor ${floor})`);
  }
});

test("FAIL contract: a disagreeing skill exits 1 and names file, line and CVE", () => {
  withSkill("intro\nCVE-2099-0001 scores RWEP 20 today.\n", (_file, dir) => {
    const catFile = path.join(dir, "catalog.json");
    fs.writeFileSync(catFile, JSON.stringify(CATALOG));
    const r = spawnSync(process.execPath, [SCRIPT, dir, catFile], { encoding: "utf8" });
    assert.equal(r.status, 1);
    assert.match(r.stderr, /Skill catalog facts: FAIL/);
    assert.match(r.stderr, /demo\/skill\.md:2 CVE-2099-0001: RWEP 20, catalog 35/);
  });
});

test("check() sweeps every skill directory and counts what it compared", () => {
  withSkill("CVE-2099-0002 is CVSS 9.8 and RWEP 80.\n", (_file, dir) => {
    const r = check(dir, CATALOG);
    assert.deepEqual(r.failures, []);
    assert.equal(r.files, 1);
    assert.equal(r.compared, 1);
  });
});

test("checkSkill() returns the failures and the comparison count for one skill file", () => {
  withSkill("CVE-2099-0001: CVSS 7.8 / RWEP 20.\nCVE-2099-0002 is CVSS 9.8.\n", (file) => {
    const r = checkSkill(file, CATALOG);
    assert.equal(r.compared, 2);
    assert.equal(r.failures.length, 1);
    assert.match(r.failures[0], /skill\.md:1 CVE-2099-0001: RWEP 20, catalog 35$/);
  });
});

test("a list of CVEs with parenthesized values is compared CVE by CVE", () => {
  assert.deepEqual(failuresFor([
    "| Tier | Coverage | Example CVEs |",
    "|---|---|---|",
    "| Overkill | RWEP >= 30 | CVE-2099-0002 (80), CVE-2099-0001 (Demo pair, 38, CVSS 8.8), CVE-2099-0003 (Demo, 30, CVSS 7.8) |",
  ]), [
    "3 CVE-2099-0001: CVSS 8.8, catalog 7.8",
    "3 CVE-2099-0001: RWEP 38, catalog 35",
  ]);
  assert.deepEqual(failuresFor([
    "Chained: CVE-2099-0001 (Demo, RWEP 12) and CVE-2099-0002 (Other, RWEP 80).",
  ]), ["1 CVE-2099-0001: RWEP 12, catalog 35"]);
});

test("a bare number in parentheses is read as RWEP only on a line that mentions RWEP", () => {
  assert.deepEqual(failuresFor(["CVE-2099-0001 (12) and CVE-2099-0002 (80) share a vendor."]), []);
  assert.deepEqual(failuresFor(["By RWEP: CVE-2099-0001 (12), CVE-2099-0002 (80)."]), ["1 CVE-2099-0001: RWEP 12, catalog 35"]);
});

test("parentheses that open with a CVE id carry that CVE's values", () => {
  assert.deepEqual(failuresFor([
    "spanning prompt-injection RCE (CVE-2099-0003, CVSS 7.8 / AV:L) and MCP RCE (CVE-2099-0001, CVSS 8.0 / AV:L).",
  ]), ["1 CVE-2099-0001: CVSS 8.0, catalog 7.8"]);
});

test("a score stated for several CVEs outside per-CVE parentheses fails as unattributable", () => {
  const msg = 'states a score for several CVEs outside per-CVE parentheses; write each as "CVE-X (name, RWEP n, CVSS n.n)"';
  assert.deepEqual(failuresFor([
    "**CVSS:** 8.8 for CVE-2099-0001, 9.8 for CVE-2099-0002 | **RWEP:** 35/100 and 80/100",
    "RWEP 35 applies; hosts mitigated for CVE-2099-0001 / CVE-2099-0002 are covered.",
  ]), [`1 CVE-2099-0001, CVE-2099-0002: ${msg}`, `2 CVE-2099-0001, CVE-2099-0002: ${msg}`]);
  assert.deepEqual(failuresFor([
    "| Chain | CVSS | RWEP |",
    "|---|---|---|",
    "| CVE-2099-0001 / CVE-2099-0002 | 7.8 | 35 |",
    "| CVE-2099-0001 / CVE-2099-0002 | High | varies |",
  ]), [`3 CVE-2099-0001, CVE-2099-0002: ${msg}`]);
});

test("a CVE the catalog does not hold still counts when attributing a line's scores", () => {
  const msg = 'states a score for several CVEs outside per-CVE parentheses; write each as "CVE-X (name, RWEP n, CVSS n.n)"';
  assert.deepEqual(failuresFor(["CVE-2099-0001 (CVSS 7.8, RWEP 35) and CVE-2000-9999 (CVSS 9.8, RWEP 80) are chained."]), []);
  assert.deepEqual(failuresFor(["RWEP 80 applies to the pair CVE-2099-0001 and CVE-2000-9999."]), [`1 CVE-2099-0001, CVE-2000-9999: ${msg}`]);
  assert.deepEqual(failuresFor(["RWEP 80 applies to the pair CVE-2000-9998 and CVE-2000-9999."]), []);
  assert.deepEqual(failuresFor([
    "| Pair | RWEP |",
    "|---|---|",
    "| CVE-2099-0001 / CVE-2000-9999 | 80 |",
  ]), [`3 CVE-2099-0001, CVE-2000-9999: ${msg}`]);
});

test("a multi-CVE line with no score, a threshold, or a superseded value is not unattributable", () => {
  assert.deepEqual(failuresFor([
    "Hosts mitigated for CVE-2099-0001 / CVE-2099-0002 are already covered.",
    "Every CVE with RWEP >= 50, such as CVE-2099-0001 and CVE-2099-0002, must appear.",
    "CVE-2099-0001 and CVE-2099-0002 share a vendor; the initial CVSS 9.1 was withdrawn.",
    "CVE-2099-0001 (Demo, RWEP 35) and CVE-2099-0002 (Other, RWEP 80) are chained.",
  ]), []);
});

test("a factor table under a single-CVE heading is compared with that CVE's rwep_factors", () => {
  const cat = { ...CATALOG, "CVE-2099-0001": { ...CATALOG["CVE-2099-0001"], rwep_factors: { cisa_kev: 0, poc_available: 20, ai_factor: 15, blast_radius: 25 } } };
  const run = (lines) => withSkill(lines.join("\n") + "\n", (file) => checkSkill(file, cat).failures.map((f) => f.replace(/^.*skill\.md:/, "")));
  assert.deepEqual(run([
    "### CVE-2099-0001 — Demo",
    "",
    "| Factor | Value | Points |",
    "|---|---|---|",
    "| CISA KEV | No | 0 |",
    "| PoC Public | Partial | +10 |",
    "| AI-Assisted | No | 0 |",
    "| Blast Radius | wide | +25 |",
    "| **RWEP** | | **20** |",
  ]), [
    "6 CVE-2099-0001: factor table PoC Public 10, catalog rwep_factors.poc_available 20",
    '7 CVE-2099-0001: factor table AI-Assisted value "No", catalog ai_discovered / ai_assisted_weaponization true',
    "7 CVE-2099-0001: factor table AI-Assisted 0, catalog rwep_factors.ai_factor 15",
    "9 CVE-2099-0001: factor table RWEP 20, catalog 35",
  ]);
  assert.deepEqual(run([
    "### CVE-2099-0001 — Demo",
    "| Factor | Value | Points |",
    "|---|---|---|",
    "| **RWEP** | | **35** |",
    "### RWEP Factor Breakdown",
    "| Factor | Value | Points |",
    "|---|---|---|",
    "| **RWEP Total** | | **[score]** |",
    "| PoC Public | Yes/No | +20/0 |",
    "### CVE-2099-0001 and CVE-2099-0002",
    "| Factor | Value | Points |",
    "|---|---|---|",
    "| **RWEP** | | **99** |",
    "### CVE-2099-0001 — Demo",
    "| Factor | Source | Meaning |",
    "|---|---|---|",
    "| RWEP | catalog | 99 |",
  ]), []);
});

test("a disagreement stated once on a single-CVE line is reported once", () => {
  assert.deepEqual(failuresFor(["CVE-2099-0001 (Demo, RWEP 12, CVSS 7.8) is the example."]), ["1 CVE-2099-0001: RWEP 12, catalog 35"]);
});

test("table columns are compared by header", () => {
  assert.deepEqual(failuresFor([
    "| CVE | CVSS | RWEP | CISA KEV | PoC Public | AI-Discovered |",
    "|---|---|---|---|---|---|",
    "| CVE-2099-0001 (demo) | 8.8 | 20 | Yes | No | No |",
    "| CVE-2099-0002 (demo) | 9.8 | 80 | Yes (2099-01-01, due 2099-01-22) | No | No |",
  ]), [
    "3 CVE-2099-0001: CVSS 8.8, catalog 7.8",
    "3 CVE-2099-0001: RWEP 20, catalog 35",
    '3 CVE-2099-0001: KEV "Yes", catalog not listed',
    '3 CVE-2099-0001: public exploit "No", catalog poc_available true',
    '3 CVE-2099-0001: AI-discovered "No", catalog ai_discovered true',
    "4 CVE-2099-0002: KEV date 2099-01-01, catalog 2099-02-03",
  ]);
});

test("a CVE in a later column is compared, and a second CVE in a later cell does not stop it", () => {
  assert.deepEqual(failuresFor([
    "| Pattern | Evidence CVE | RWEP tier |",
    "|---|---|---|",
    "| Patch theater | CVE-2099-0001 (demo) | 20 |",
    "| Chain | CVE-2099-0001 | 20 (chained with CVE-2099-0002) |",
  ]), ["3 CVE-2099-0001: RWEP 20, catalog 35", "4 CVE-2099-0001: RWEP 20, catalog 35"]);
});

test("an exact AI-Discovered column reads ai_discovered; a combined AI column also reads weaponization", () => {
  assert.deepEqual(failuresFor([
    "| CVE | AI-Discovered | AI-accelerated |",
    "|---|---|---|",
    "| CVE-2099-0003 | No (AI-assisted weaponization) | Yes (AI tooling enables) |",
    "| CVE-2099-0001 | Yes | No |",
  ]), ['4 CVE-2099-0001: AI "No", catalog ai_discovered true / ai_assisted_weaponization false']);
});

test("a Partial public-exploit cell is read as a PoC the catalog scores as available", () => {
  assert.deepEqual(failuresFor([
    "| CVE | Public PoC |",
    "|---|---|",
    "| CVE-2099-0001 | Partial — conceptual exploit demonstrated |",
    "| CVE-2099-0002 | Partial |",
  ]), ['4 CVE-2099-0002: public exploit "Partial", catalog poc_available false']);
});

test("a factor row's Yes/No value is compared with the catalog field it scores", () => {
  const cat = { ...CATALOG, "CVE-2099-0002": { ...CATALOG["CVE-2099-0002"], patch_available: true, live_patch_available: false, patch_required_reboot: true, rwep_factors: { cisa_kev: 25, poc_available: 0, live_patch_available: 0, reboot_required: 5 } } };
  const run = (lines) => withSkill(lines.join("\n") + "\n", (file) => checkSkill(file, cat).failures.map((f) => f.replace(/^.*skill\.md:/, "")));
  assert.deepEqual(run([
    "### CVE-2099-0002 — Demo",
    "| Factor | Value | Points |",
    "|---|---|---|",
    "| CISA KEV | No | +25 |",
    "| PoC Public | Partial | 0 |",
    "| Live Patch Available | No (vendor has none) | 0 |",
    "| Reboot Required | Yes | +5 |",
    "| Active Exploitation | Confirmed | +20 |",
  ]), [
    '4 CVE-2099-0002: factor table CISA KEV value "No", catalog cisa_kev true',
    '5 CVE-2099-0002: factor table PoC Public value "Partial", catalog poc_available false',
  ]);
});

test("an AI-Discovered factor row reads discovery alone; AI-Assisted also counts weaponization", () => {
  const cat = { ...CATALOG, "CVE-2099-0003": { ...CATALOG["CVE-2099-0003"], rwep_factors: { ai_factor: 15 } } };
  const run = (lines) => withSkill(lines.join("\n") + "\n", (file) => checkSkill(file, cat).failures.map((f) => f.replace(/^.*skill\.md:/, "")));
  assert.deepEqual(run([
    "### CVE-2099-0003 — Demo",
    "| Factor | Value | Points |",
    "|---|---|---|",
    "| AI-Discovered | No | +15 |",
    "| AI-Assisted | Yes | +15 |",
    "| AI-Discovered | Yes | +15 |",
  ]), ['6 CVE-2099-0003: factor table AI-Discovered value "Yes", catalog ai_discovered false']);
});

test("factor points accept a leading plus, hyphen-minus or Unicode minus, and nothing else", () => {
  const cat = { ...CATALOG, "CVE-2099-0001": { ...CATALOG["CVE-2099-0001"], patch_available: true, rwep_factors: { patch_available: -15, poc_available: 20, blast_radius: 25 } } };
  const run = (lines) => withSkill(lines.join("\n") + "\n", (file) => checkSkill(file, cat).failures.map((f) => f.replace(/^.*skill\.md:/, "")));
  assert.deepEqual(run([
    "### CVE-2099-0001 — Demo",
    "| Factor | Value | Points |",
    "|---|---|---|",
    "| Patch Available | Yes | −15 |",
    "| PoC Public | Yes | +20 |",
    "| Blast Radius | wide | x25 |",
  ]), []);
  assert.deepEqual(run([
    "### CVE-2099-0001 — Demo",
    "| Factor | Value | Points |",
    "|---|---|---|",
    "| Patch Available | Yes | -10 |",
  ]), ["4 CVE-2099-0001: factor table Patch Available -10, catalog rwep_factors.patch_available -15"]);
});

test("Markdown emphasis and code marks in a cell are ignored when comparing it", () => {
  assert.deepEqual(failuresFor([
    "| CVE | RWEP | CVSS | KEV |",
    "|---|---|---|---|",
    "| CVE-2099-0001 | **12** | **6.1** | `Yes` |",
    "| CVE-2099-0002 | **80** | _9.8_ | **Yes** (2099-02-03) |",
  ]), [
    "3 CVE-2099-0001: RWEP 12, catalog 35",
    "3 CVE-2099-0001: CVSS 6.1, catalog 7.8",
    '3 CVE-2099-0001: KEV "Yes", catalog not listed',
  ]);
  const msg = 'states a score for several CVEs outside per-CVE parentheses; write each as "CVE-X (name, RWEP n, CVSS n.n)"';
  assert.deepEqual(failuresFor([
    "| Pair | RWEP |",
    "|---|---|",
    "| CVE-2099-0001 / CVE-2099-0002 | **80** |",
  ]), [`3 CVE-2099-0001, CVE-2099-0002: ${msg}`]);
});

test("bold score labels in prose are compared like plain ones", () => {
  assert.deepEqual(failuresFor([
    "CVE-2099-0001: **RWEP:** 1, **CVSS:** 1.0",
    "CVE-2099-0002 (**RWEP 12**, *CVSS 9.8*) is the example.",
  ]), [
    "1 CVE-2099-0001: RWEP 1, catalog 35",
    "1 CVE-2099-0001: CVSS 1.0, catalog 7.8",
    "2 CVE-2099-0002: RWEP 12, catalog 80",
  ]);
});

test("declarative AI cells are read: AI-discovered, AI-weaponized and Human-discovered", () => {
  assert.deepEqual(failuresFor([
    "| CVE | AI factor | AI-Discovered |",
    "|---|---|---|",
    "| CVE-2099-0001 | AI-assisted discovery | AI-discovered |",
    "| CVE-2099-0003 | AI-weaponized | Human-discovered |",
    "| CVE-2099-0001 | Human-discovered | Human-discovered |",
    "| CVE-2099-0002 | AI-accelerated | AI-weaponized |",
  ]), [
    '5 CVE-2099-0001: AI "Human-discovered", catalog ai_discovered true / ai_assisted_weaponization false',
    '5 CVE-2099-0001: AI-discovered "Human-discovered", catalog ai_discovered true',
    '6 CVE-2099-0002: AI "AI-accelerated", catalog ai_discovered false / ai_assisted_weaponization false',
  ]);
});

test("Active Exploitation, Patch and Live Patch columns are compared with the catalog", () => {
  const cat = {
    ...CATALOG,
    "CVE-2099-0001": { ...CATALOG["CVE-2099-0001"], active_exploitation: "suspected", patch_available: true, live_patch_available: false },
    "CVE-2099-0002": { ...CATALOG["CVE-2099-0002"], active_exploitation: "none", patch_available: false, live_patch_available: true },
  };
  const run = (lines) => withSkill(lines.join("\n") + "\n", (file) => checkSkill(file, cat).failures.map((f) => f.replace(/^.*skill\.md:/, "")));
  assert.deepEqual(run(apart("| CVE | Active Exploitation | Patch / Mitigation Available | Live-Patchable |", [
    "| CVE-2099-0001 | Suspected | Vendor patch | Limited (kpatch RHEL-only) |",
    "| CVE-2099-0002 | None observed | No | Yes (IDE update) |",
    "| CVE-2099-0001 | Confirmed mass exploitation | No | Yes |",
    "| CVE-2099-0002 | Patched in modern fleets | Mitigation + vendor patch | n/a |",
  ])), [
    '11 CVE-2099-0001: active exploitation "Confirmed mass exploitation", catalog suspected',
    '11 CVE-2099-0001: patch "No", catalog patch_available true',
    '11 CVE-2099-0001: live patch "Yes", catalog live_patch_available false',
    '15 CVE-2099-0002: patch "Mitigation + vendor patch", catalog patch_available false',
  ]);
});

test("a live-patch No followed by another negation is compared; a qualifier or a later Yes still leaves it uncompared", () => {
  const cat = {
    ...CATALOG,
    "CVE-2099-0001": { ...CATALOG["CVE-2099-0001"], live_patch_available: true },
    "CVE-2099-0002": { ...CATALOG["CVE-2099-0002"], live_patch_available: false },
  };
  const run = (lines) => withSkill(lines.join("\n") + "\n", (file) => checkSkill(file, cat).failures.map((f) => f.replace(/^.*skill\.md:/, "")));
  assert.deepEqual(run(apart("| CVE | Live Patch |", [
    "| CVE-2099-0001 | No (the fix is an IDE upgrade, not a runtime patch) |",
    "| CVE-2099-0001 | No (live patches cover some distributions' kernels only; no live-patch credit) |",
    "| CVE-2099-0001 | No (none yet; kpatch pending) |",
    "| CVE-2099-0001 | No (not on Ubuntu); Yes (RHEL kpatch) |",
    "| CVE-2099-0002 | Yes (not on Ubuntu) |",
    "| CVE-2099-0002 | Yes (kpatch) |",
  ])), [
    '3 CVE-2099-0001: live patch "No (the fix is an IDE upgrade, not a run", catalog live_patch_available true',
    '7 CVE-2099-0001: live patch "No (live patches cover some distribution", catalog live_patch_available true',
    '23 CVE-2099-0002: live patch "Yes (kpatch)", catalog live_patch_available false',
  ]);
});

test("a section that has the same row CVE on several rows leaves its exploitation, patch and live-patch cells uncompared", () => {
  const cat = { ...CATALOG, "CVE-2099-0001": { ...CATALOG["CVE-2099-0001"], patch_available: true, live_patch_available: true } };
  const run = (lines) => withSkill(lines.join("\n") + "\n", (file) => checkSkill(file, cat).failures.map((f) => f.replace(/^.*skill\.md:/, "")));
  // Each section below answers for one row at a time, and one of its rows
  // disagrees with the catalog. The first table's RWEP cells are still compared
  // on both of its rows.
  assert.deepEqual(run([
    // A per-distribution or per-version table.
    "| CVE | Distribution | Live Patch | RWEP |", "|---|---|---|---|",
    "| CVE-2099-0001 | RHEL 9 | Yes (kpatch) | 35 |", "| CVE-2099-0001 | Ubuntu 24.04 | No | 99 |", "## b",
    "| CVE | Product line | Patch Available |", "|---|---|---|",
    "| CVE-2099-0001 | 2.x | Yes |", "| CVE-2099-0001 | 1.x (EoL) | No |", "## c",
    // A continuation row with a blank first cell.
    "| CVE | Distribution | Live Patch |", "|---|---|---|", "| CVE-2099-0001 | RHEL 9 | No |", "| | Ubuntu 24.04 | Yes |", "## d",
    // A row that cites a second CVE is not compared itself but still counts.
    "| CVE | Live Patch | Notes |", "|---|---|---|",
    "| CVE-2099-0001 | No | RHEL 9 |", "| CVE-2099-0001 | Yes | Ubuntu; chained with CVE-2099-0002 |", "## RHEL 9 and Ubuntu",
    // One table per distribution in one section.
    "| CVE | Live Patch |", "|---|---|", "| CVE-2099-0001 | No |", "",
    "| CVE | Live Patch |", "|---|---|", "| CVE-2099-0001 | Yes |",
  ]), ["4 CVE-2099-0001: RWEP 99, catalog 35"]);
  // A "#" comment inside a fenced code block does not end the section, and a row
  // that leaves blank the cell under a later CVE column continues the row above.
  const liveFalse = (lines) => withSkill(lines.join("\n") + "\n", (file) => checkSkill(file,
    { ...CATALOG, "CVE-2099-0001": { ...CATALOG["CVE-2099-0001"], live_patch_available: false } }).failures);
  assert.deepEqual(liveFalse([
    "## Live patch by distribution",
    "| CVE | Live Patch |", "|---|---|", "| CVE-2099-0001 | Yes (kpatch) |", "",
    "```bash", "# check kpatch on RHEL", "```", "",
    "| CVE | Live Patch |", "|---|---|", "| CVE-2099-0001 | No |", "## d",
    "| Distribution | CVE | Live Patch |", "|---|---|---|", "| RHEL 9 | CVE-2099-0001 | Yes (kpatch) |", "| Ubuntu 24.04 | | No |",
  ]), []);
  // A "~~~" fence and an indented fence hold "#" comments too.
  for (const [open, close] of [["~~~bash", "~~~"], ["  ```bash", "  ```"]]) {
    assert.deepEqual(liveFalse([
      "## Live patch by distribution",
      "| CVE | Live Patch |", "|---|---|", "| CVE-2099-0001 | Yes (kpatch) |", "",
      open, "# check on Ubuntu", close, "",
      "| CVE | Live Patch |", "|---|---|", "| CVE-2099-0001 | No |",
    ]), [], open);
  }
  // A fence closes only on a line of its own character, at least as long as the
  // opening run, with nothing after it. A nested block of the other character or
  // of a shorter run leaves the outer fence open, and so does a line that holds
  // an info string.
  for (const block of [
    ["~~~markdown", "```bash", "```", "# check on Ubuntu", "~~~"],
    ["````markdown", "```bash", "```", "# check on Ubuntu", "````"],
    ["```text", "```bash", "# check on Ubuntu", "```"],
  ]) {
    assert.deepEqual(liveFalse([
      "## Live patch by distribution",
      "| CVE | Live Patch |", "|---|---|", "| CVE-2099-0001 | Yes (kpatch) |", "",
      ...block, "",
      "| CVE | Live Patch |", "|---|---|", "| CVE-2099-0001 | No |",
    ]), [], block[0]);
  }
  // After a fence closes, the next "##" heading ends the section again.
  assert.deepEqual(liveFalse([
    "## Live patch by distribution",
    "| CVE | Live Patch |", "|---|---|", "| CVE-2099-0001 | Yes (kpatch) |", "",
    "```bash", "# check kpatch on RHEL", "```",
    "## Summary",
    "| CVE | Live Patch |", "|---|---|", "| CVE-2099-0001 | No |",
  ]).map((f) => f.replace(/^.*skill\.md:/, "")), ['4 CVE-2099-0001: live patch "Yes (kpatch)", catalog live_patch_available false']);
  // "###" sub-headings stay in their "##" section, so one table per distribution
  // under sub-headings is not compared, whichever value the catalog holds.
  const subheadings = [
    "## Live patch status",
    "### RHEL 9", "| CVE | Live Patch |", "|---|---|", "| CVE-2099-0001 | Yes (kpatch) |", "| CVE-2099-0002 | Yes (kpatch) |",
    "### Ubuntu 24.04", "| CVE | Live Patch |", "|---|---|", "| CVE-2099-0001 | No |", "| CVE-2099-0002 | No |",
  ];
  for (const live of [true, false]) {
    assert.deepEqual(withSkill(subheadings.join("\n") + "\n", (file) => checkSkill(file, { ...CATALOG,
      "CVE-2099-0001": { ...CATALOG["CVE-2099-0001"], live_patch_available: live },
      "CVE-2099-0002": { ...CATALOG["CVE-2099-0002"], live_patch_available: !live } }).failures), [], String(live));
  }
  // A "#" heading ends a section as a "##" heading does, so each one-row section
  // is compared.
  assert.deepEqual(run([
    "# Kernel", "| CVE | Live Patch |", "|---|---|", "| CVE-2099-0001 | No |",
    "# Summary", "| CVE | Live Patch |", "|---|---|", "| CVE-2099-0001 | No |",
  ]), ['4 CVE-2099-0001: live patch "No", catalog live_patch_available true', '8 CVE-2099-0001: live patch "No", catalog live_patch_available true']);
  // A failure dropped in one section does not come back in the next one.
  assert.deepEqual(run([
    "## Live patch by distribution",
    "| CVE | Distribution | Live Patch |", "|---|---|---|", "| CVE-2099-0001 | RHEL 9 | Yes |", "| CVE-2099-0001 | Ubuntu 24.04 | No |",
    "## Summary",
    "| CVE | Live Patch |", "|---|---|", "| CVE-2099-0001 | Yes |",
  ]), []);
  // A row with a blank CVE cell that names a CVE in a later cell is that CVE's
  // row: its RWEP cell is compared with that CVE, and the row does not continue
  // the row above.
  assert.deepEqual(failuresFor([
    "| CVE | Alias | RWEP |", "|---|---|---|", "| CVE-2099-0001 | Copy Fail | 35 |", "| | see also CVE-2099-0002 | 99 |",
  ]), ["4 CVE-2099-0002: RWEP 99, catalog 80"]);
  // A continuation row counts under a heading that names the CVE too.
  assert.deepEqual(run([
    "### CVE-2099-0001 live patch by distribution",
    "| CVE | Distribution | Live Patch | Patch Available |", "|---|---|---|---|",
    "| CVE-2099-0001 | RHEL 9 | No | No |", "| | Ubuntu 24.04 | Yes | Yes |",
  ]), []);
  // Under such a heading, a labeled row with no CVE ends the continuation.
  assert.deepEqual(run([
    "### CVE-2099-0001 live patch",
    "| CVE | Live Patch |", "|---|---|", "| CVE-2099-0001 | No |", "| Vendor note | n/a |", "| | Yes |",
  ]), ['4 CVE-2099-0001: live patch "No", catalog live_patch_available true']);
  // The drop applies to each CVE on its own: a CVE with one row in the section is
  // still compared when another CVE has several.
  assert.deepEqual(run([
    "| CVE | Live Patch |", "|---|---|", "| CVE-2099-0002 | No |", "| CVE-2099-0002 | Yes |", "| CVE-2099-0001 | No |",
  ]), ['5 CVE-2099-0001: live patch "No", catalog live_patch_available true']);
  // A row that only points to another CVE ends the continuation.
  assert.deepEqual(run([
    "| CVE | Live Patch |", "|---|---|", "| CVE-2099-0001 | No |", "| No vendor CVE; see CVE-2099-0002 | Yes |", "| | Yes |",
  ]), ['3 CVE-2099-0001: live patch "No", catalog live_patch_available true']);
  // A blank-first-cell row under a row whose CVE the catalog does not hold
  // continues that row, not the CVE above it.
  assert.deepEqual(run([
    "| CVE | Live Patch |", "|---|---|", "| CVE-2099-0001 | No |", "| CVE-2000-9999 | Yes |", "| | Yes |",
  ]), ['3 CVE-2099-0001: live patch "No", catalog live_patch_available true']);
  // The same holds under a several-CVE row, and a blank first row of a new table
  // continues nothing.
  assert.deepEqual(run([
    "| CVE | Live Patch |", "|---|---|", "| CVE-2099-0001 | No |", "| CVE-2099-0002 / CVE-2099-0003 | Yes |", "| | Yes |", "",
    "| CVE | Live Patch |", "|---|---|", "| | Yes |",
  ]), ['3 CVE-2099-0001: live patch "No", catalog live_patch_available true']);
  assert.deepEqual(run([
    "| CVE | Live Patch |", "|---|---|", "| CVE-2099-0001 | No |", "",
    "| CVE | Live Patch |", "|---|---|", "| | Yes |",
  ]), ['3 CVE-2099-0001: live patch "No", catalog live_patch_available true']);
  // A row that only mentions the CVE, or names it among several, does not count:
  // the first row's cell is compared.
  assert.deepEqual(run([
    "| CVE | Live Patch | Notes |", "|---|---|---|",
    "| CVE-2099-0001 | No | |", "| CVE-2099-0002 | Yes | Chained with CVE-2099-0001 |", "| CVE-2099-0001, CVE-2099-0002 | Yes | |",
  ]), ['3 CVE-2099-0001: live patch "No", catalog live_patch_available true']);
  // The same cell on a CVE's only row is compared, including in a skill's last
  // table when the file has no final newline.
  assert.deepEqual(run(["| CVE | Live Patch |", "|---|---|", "| CVE-2099-0001 | No |"]),
    ['3 CVE-2099-0001: live patch "No", catalog live_patch_available true']);
  assert.deepEqual(withSkill(["| CVE | Live Patch |", "|---|---|", "| CVE-2099-0001 | No |"].join("\n"),
    (file) => checkSkill(file, cat).failures.map((f) => f.replace(/^.*skill\.md:/, ""))),
  ['3 CVE-2099-0001: live patch "No", catalog live_patch_available true']);
});

test("a vendor-patch cell that denies availability reads as no patch", () => {
  const cat = {
    ...CATALOG,
    "CVE-2099-0001": { ...CATALOG["CVE-2099-0001"], patch_available: true },
    "CVE-2099-0002": { ...CATALOG["CVE-2099-0002"], patch_available: false },
  };
  const run = (lines) => withSkill(lines.join("\n") + "\n", (file) => checkSkill(file, cat).failures.map((f) => f.replace(/^.*skill\.md:/, "")));
  assert.deepEqual(run(apart("| CVE | Patch Available |", [
    "| CVE-2099-0001 | Vendor patch unavailable |",
    "| CVE-2099-0001 | Vendor update not yet available |",
    "| CVE-2099-0001 | Vendor fix pending |",
    "| CVE-2099-0002 | Vendor patch + config hardening |",
    "| CVE-2099-0002 | Vendor patches shipped 2099-01-01 |",
  ])), [
    '3 CVE-2099-0001: patch "Vendor patch unavailable", catalog patch_available true',
    '7 CVE-2099-0001: patch "Vendor update not yet available", catalog patch_available true',
    '11 CVE-2099-0001: patch "Vendor fix pending", catalog patch_available true',
    '15 CVE-2099-0002: patch "Vendor patch + config hardening", catalog patch_available false',
    '19 CVE-2099-0002: patch "Vendor patches shipped 2099-01-01", catalog patch_available false',
  ]);
});

test("a vendor-patch cell reads as a patch only when it affirms one", () => {
  const cat = { ...CATALOG, "CVE-2099-0002": { ...CATALOG["CVE-2099-0002"], patch_available: false } };
  const run = (lines) => withSkill(lines.join("\n") + "\n", (file) => checkSkill(file, cat).failures.map((f) => f.replace(/^.*skill\.md:/, "")));
  assert.deepEqual(run(apart("| CVE | Patch Available |", [
    "| CVE-2099-0002 | Vendor patch planned |",
    "| CVE-2099-0002 | Vendor patch in development |",
    "| CVE-2099-0002 | Vendor patch status unknown |",
    "| CVE-2099-0002 | Vendor patch |",
    "| CVE-2099-0002 | Vendor patch + config hardening |",
  ])), [
    '15 CVE-2099-0002: patch "Vendor patch", catalog patch_available false',
    '19 CVE-2099-0002: patch "Vendor patch + config hardening", catalog patch_available false',
  ]);
});

test("patch cells are compared only in the closed PATCH_FORMS wording", () => {
  const verdict = (cell) => patchVerdict(cell);
  const expect = {
    patch: [
      "Vendor patch", "Vendor updates", "Vendor IDE update + manifest signing",
      "Vendor IDE update + manifest signing + MCP server allowlisting", "Vendor patches shipped 2099-01-01",
      "Vendor patch available", "Vendor patch is available", "Vendor fix released", "Vendor patch applied", "Mitigation + vendor patch",
      "Config hardening + vendor update", "Yes (vendor patch).",
      "Yes", "Yes.", "Yes — vendor patch", "Yes (vendor IDE update)",
      "Vendor SaaS patch", "Vendor firmware update", "Vendor security fix",
    ],
    "no patch": [
      "Vendor patch pending", "Vendor patch planned", "Vendor patch not yet released", "Vendor fix unavailable",
      "Vendor patch not yet issued", "No vendor patch",
      "Workaround only; no vendor fix available", "Vendor update not yet available", "Vendor fix pending",
      "No", "None", "No patch", "No fix", "No patches", "No patch available", "No patch is available", "No vendor fix available",
      "Vendor patch is pending",
      "No vendor patch (product EoL)", "No patch available (EoL)", "No vendor patch (end-of-life)", "No (unsupported)",
      "Mitigation only; no vendor patch", "Compensating controls only; no vendor fix", "Mitigations, no vendor update",
    ],
    "not compared": [
      "Vendor patch; signatures public", "Vendor patch available; signatures public",
      "No reliable patch; defence-in-depth only", "No (vendor patch pending)", "EoL; no vendor patch",
      "No vendor patch — mitigation is architectural", "Compensating controls; no vendor fix, product EoL",
      "Yes, if on 2.x", "Yes (not for 1.x)", "Yes, pending release", "Yes, but only for 2.x",
      "Yes (workaround only)", "Yes — mitigation only", "Yes, compensating controls only",
      "Yes (SaaS)", "Yes for in-support products; brownfield is exposed", "Yes (workaround)", "Yes — only a workaround",
      "Yes (config change)", "Yes — disable the feature", "Yes (testing on Alma/CloudLinux)",
      "No workaround — vendor patch only", "No mitigation beyond the vendor patch", "No workaround but a vendor patch is available",
      "No mitigation except the vendor patch", "No interim mitigation (vendor fix available)", "No workaround (vendor patch only)",
      "Vendor patch; in progress", "Vendor patch; ETA 2026-10", "Vendor patch, in progress", "Vendor patch; to follow",
      "Vendor patch; never released", "Vendor patch + hardening until it ships",
      "Pending: mitigation + vendor patch", "Not yet: mitigation + vendor patch", "TBD (mitigation + vendor patch)",
      "Awaiting mitigation + vendor patch", "Planned: config hardening + vendor patch",
      "Vendor patch has not been released", "Vendor patch — none released", "Vendor patch (none; product is EoL)",
      "Vendor patch never shipped", "Vendor patch; not yet released", "Vendor patch, pending",
      "Vendor patch; still unreleased", "Vendor patch, currently unavailable", "Vendor patch; in development",
      "Vendor patch; release planned for Q4", "Vendor patch available soon", "Vendor patch released next quarter",
      "Vendor patch available; live patch expected", "Vendor patch released; distro backports pending",
      "Vendor patch available but distro backports pending", "Vendor patch; remove the admission webhook if not in use",
      "Mitigation + vendor patch; not yet released", "Workaround + vendor fix, pending",
      "Fixed server-side; no vendor update needed", "Upstream fix released; no vendor patch needed (SaaS)",
      "Awaiting vendor patch", "Pending vendor fix", "Vendor declined fix", "Vendor never patches", "Vendor pending patch",
      "Vendor fix (no customer action required)", "Vendor patch (status unknown)", "Vendor patch (no reboot required)",
      "Vendor patch not applicable (SaaS, fixed server-side)", "Mostly no (vendor product patching is reboot-class)",
      "No vendor patch needed", "Vendor patch available; no vendor fix for the EoL 1.x line",
      "Vendor patch pending; not yet released", "Vendor patch pending (released for 2.x)",
      "Vendor patch unavailable (SaaS; fixed server-side)", "Vendor patch, if the vendor ships one",
      "Vendor patch pending; mitigation published", "Vendor patch pending; released for 2.x",
      "No patch needed (fixed server-side)", "No action needed; fixed server-side", "No; fixed server-side",
      "No vendor patch; released for 2.x", "No vendor patch for the architectural class — vendor-side patches close the path",
      "Workaround only; no vendor fix except for the 3.x line", "Mitigation only; no vendor patch unless on 3.x",
      "Mitigation + vendor patch; no vendor patch for 1.x", "Mitigation + vendor patch; no vendor fix for the EoL 1.x line",
      "Upstream fix released; no vendor patch for the EoL 1.x line", "Fixed in 2.4.1; no vendor patch for 1.x",
      "Fixed server-side without a vendor patch", "Workaround only; no vendor fix available (fixed upstream in 2.x)",
      "Workaround only; no vendor fix available for 1.x, fixed in 2.x",
      "No; patched server-side", "No (patched server-side)", "No; resolved server-side", "No; remediated server-side",
      "No; SaaS fix deployed server-side", "No vendor patch; patched upstream in 2.4.1", "Patched upstream; no vendor patch",
      "No vendor patch (SaaS; patched server-side)", "Workaround only; no vendor fix available (patched upstream in 2.x)",
      "No patch for the EoL 1.x line; upgrade to 2.x", "No patch available for 1.x", "No patch for 1.x", "No, except on 3.x",
      "No patch unless on 3.x", "No for 1.x; Yes for 2.x", "No (1.x); Yes (2.x)", "No (1.x EoL; 2.x has a fix)", "No for EoL 1.x",
      "No vendor patch (EoL 1.x)",
      "Mitigation + vendor patch; no vendor patch (EoL line)", "No patch needed", "No vendor patch (for EoL releases)", "No (EoL 1.x)",
      "Upgrade to 2.x (1.x EoL, no vendor patch)", "1.x: no vendor patch", "For 1.x, no vendor patch",
      "Upstream fix in 6.12; no vendor patch", "Hotfix 2.4.1-hf1; no vendor patch",
      "No vendor patch (SaaS; fix deployed server-side)", "Vendor patch unavailable (SaaS; fix deployed server-side)",
      "No vendor patch; the SaaS provider deployed a fix", "No vendor patch (SaaS, server-side fix)",
      "Workaround only; no vendor fix available (server-side fix deployed)",
      "No; hotfix deployed server-side", "No; addressed server-side", "No; corrected server-side",
      "Workaround available; no vendor patch", "Mitigations published; no vendor patch",
    ],
  };
  const wrong = [];
  for (const [want, cells] of Object.entries(expect)) {
    for (const cell of cells) if (verdict(cell) !== want) wrong.push(`${cell}: ${verdict(cell)}, want ${want}`);
  }
  assert.deepEqual(wrong, []);
});

test("No confirmed exploitation and mitigation cells are not misread", () => {
  const cat = {
    ...CATALOG,
    "CVE-2099-0001": { ...CATALOG["CVE-2099-0001"], active_exploitation: "suspected", patch_available: false },
  };
  const run = (lines) => withSkill(lines.join("\n") + "\n", (file) => checkSkill(file, cat).failures.map((f) => f.replace(/^.*skill\.md:/, "")));
  assert.deepEqual(run(apart("| CVE | Active Exploitation | Patch / Mitigation Available |", [
    "| CVE-2099-0001 | No confirmed exploitation | Yes — mitigation available; vendor patch pending |",
    "| CVE-2099-0001 | Suspected | Yes |",
    "| CVE-2099-0001 | Suspected | Yes, vendor patch |",
  ])), ['11 CVE-2099-0001: patch "Yes, vendor patch", catalog patch_available false']);
});

test("exploitation, patch and live-patch cells are compared only on a row that names a single CVE", () => {
  const cat = {
    ...CATALOG,
    "CVE-2099-0001": { ...CATALOG["CVE-2099-0001"], active_exploitation: "none", patch_available: false, live_patch_available: false },
  };
  const run = (lines) => withSkill(lines.join("\n") + "\n", (file) => checkSkill(file, cat).failures.map((f) => f.replace(/^.*skill\.md:/, "")));
  // Every cell disagrees with CVE-2099-0001. On the row that also cites another
  // CVE the RWEP cell is compared, and the Active Exploitation, Patch and Live
  // Patch cells are not.
  assert.deepEqual(run(apart("| CVE | Active Exploitation | Patch Available | Live Patch | RWEP | Notes |", [
    "| CVE-2099-0001 | Confirmed | Yes | Yes | 99 | Standalone flaw |",
    "| CVE-2099-0001 | Confirmed | Yes | Yes | 98 | Chained with CVE-2099-0002 |",
    "| CVE-2099-0001 | Confirmed | Yes | Yes | 97 | CVE-2099-0001 is the upstream id |",
  ])), [
    '3 CVE-2099-0001: active exploitation "Confirmed", catalog none',
    '3 CVE-2099-0001: patch "Yes", catalog patch_available false',
    '3 CVE-2099-0001: live patch "Yes", catalog live_patch_available false',
    "3 CVE-2099-0001: RWEP 99, catalog 35",
    "7 CVE-2099-0001: RWEP 98, catalog 35",
    // A later cell that repeats the row's own CVE keeps the row a single-CVE row.
    '11 CVE-2099-0001: active exploitation "Confirmed", catalog none',
    '11 CVE-2099-0001: patch "Yes", catalog patch_available false',
    '11 CVE-2099-0001: live patch "Yes", catalog live_patch_available false',
    "11 CVE-2099-0001: RWEP 97, catalog 35",
  ]);
  // A Patch / Mitigation column follows the same rule.
  assert.deepEqual(run([
    "| CVE | Patch / Mitigation Available | RWEP | Notes |",
    "|---|---|---|---|",
    "| CVE-2099-0001 | Vendor patch | 98 | Chained with CVE-2099-0002 |",
  ]), ["3 CVE-2099-0001: RWEP 98, catalog 35"]);
  // A row whose first CVE-bearing cell is a related CVE is read against that CVE
  // for its CVSS, RWEP, KEV, public-exploit and AI columns (RWEP 31 against
  // CVE-2099-0003's 30), and its Patch cell, which disagrees with both CVEs, is
  // not compared.
  assert.deepEqual(run([
    "| Related CVE | CVE | Patch Available | RWEP |",
    "|---|---|---|---|",
    "| CVE-2099-0003 | CVE-2099-0001 | Yes | 31 |",
  ]), ["3 CVE-2099-0003: RWEP 31, catalog 30"]);
  // A row whose only CVE is a related case cited in a PoC column has its Patch
  // cell left uncompared: the row describes a technique, not that CVE. Its KEV
  // cell is still compared (Yes against a CVE KEV does not list).
  assert.deepEqual(run([
    "| ATLAS Technique | PoC / Public Demo Available? | CISA KEV? | Patch Available? |",
    "|---|---|---|---|",
    "| AML.T0051 | Yes — CVE-2099-0001 is the sibling case | Yes | Yes |",
  ]), ['3 CVE-2099-0001: KEV "Yes", catalog not listed']);
  // The same row with its CVE under an identifier header is compared, and so is a
  // row whose CVE sits in the first column under a header that names no CVE.
  assert.deepEqual(run([
    "| ATLAS Technique | Evidence CVE | Patch Available? |", "|---|---|---|", "| AML.T0051 | CVE-2099-0001 | Yes |", "## b",
    "| Technique | CVEs | Patch Available |", "|---|---|---|", "| AML.T0051 | CVE-2099-0001 | Yes |", "## c",
    "| Vulnerability | Patch Available |", "|---|---|", "| CVE-2099-0001 | Yes |",
  ]), ['3 CVE-2099-0001: patch "Yes", catalog patch_available false', '7 CVE-2099-0001: patch "Yes", catalog patch_available false',
    '11 CVE-2099-0001: patch "Yes", catalog patch_available false']);
  // Each identifier header form names the row; other CVE headers do not.
  for (const header of ["CVE", "CVEs", "CVE ID", "CVE Class", "Evidence CVE", "Evidence CVEs", "CVE (if any)", "Class / CVE", "CVE?", "**CVE**", "`CVE ID`"]) {
    assert.deepEqual(run([`| Technique | ${header} | Patch Available |`, "|---|---|---|", "| AML.T0051 | CVE-2099-0001 | Yes |"]),
      ['3 CVE-2099-0001: patch "Yes", catalog patch_available false'], header);
  }
  for (const header of ["CVE Number", "CVE IDs", "CVE Reference", "Paired CVE"]) {
    assert.deepEqual(run([`| Technique | ${header} | Patch Available |`, "|---|---|---|", "| AML.T0051 | CVE-2099-0001 | Yes |"]), [], header);
  }
  // A "Related CVE" or "Example CVE" column names a related case, not the row,
  // in any position.
  assert.deepEqual(run([
    "| ATLAS Technique | Related CVE | Patch Available? | Active Exploitation |", "|---|---|---|---|",
    "| AML.T0051 | CVE-2099-0001 | Yes | Confirmed |", "## b",
    "| Example CVE | Technique | Patch Available? |", "|---|---|---|", "| CVE-2099-0001 | AML.T0051 | Yes |", "## c",
    "| Example CVEs | Technique | Patch Available? |", "|---|---|---|", "| CVE-2099-0001 | AML.T0051 | Yes |", "## d",
    "| Related CVEs | Technique | Patch Available? |", "|---|---|---|", "| CVE-2099-0001 | AML.T0051 | Yes |", "## e",
    "| _Example CVE_ | Technique | Patch Available? |", "|---|---|---|", "| CVE-2099-0001 | AML.T0051 | Yes |",
  ]), []);
  // A header whose note or "/" part names a role, or a PoC or notes column in the
  // first position, does not name the row either.
  for (const header of ["CVE (example)", "CVE (related)", "CVE (e.g.)", "CVE (analog)", "CVE / Example", "PoC / CVE"]) {
    assert.deepEqual(run([`| Technique | ${header} | Patch Available |`, "|---|---|---|", "| AML.T0051 | CVE-2099-0001 | Yes |"]), [], header);
  }
  for (const word of ["Related", "Sibling", "Siblings", "Similar", "See also", "See-also", "Example", "Examples", "E.g.", "Analog", "Analogs",
    "Analogue", "Analogues", "PoC", "PoCs", "Demo", "Demos", "Exploit", "Exploits", "Note", "Notes", "Comment", "Comments", "Rationale",
    "Rationales", "Reason", "Reasons", "Description", "Descriptions", "Detail", "Details"]) {
    assert.deepEqual(run([`| ${word} | Technique | Patch Available |`, "|---|---|---|", "| CVE-2099-0001 sibling case | AML.T0051 | Yes |"]), [], word);
    assert.deepEqual(run([`| Technique | CVE (${word.toLowerCase()}) | Patch Available |`, "|---|---|---|", "| AML.T0051 | CVE-2099-0001 | Yes |"]), [], `CVE (${word})`);
  }
  // A first column whose header names some other CVE does not name the row.
  for (const header of ["Paired CVE", "Paired CVEs", "CVE Number"]) {
    assert.deepEqual(run([`| ${header} | Technique | Patch Available |`, "|---|---|---|", "| CVE-2099-0001 | AML.T0051 | Yes |"]), [], header);
  }
  // "Exploited" and "exploitation" are not role words: the column still names the row.
  assert.deepEqual(run(["| Exploited Vulnerability | Patch Available |", "|---|---|", "| CVE-2099-0001 | Yes |"]),
    ['3 CVE-2099-0001: patch "Yes", catalog patch_available false']);
  assert.deepEqual(run(["| Technique | CVE (exploitation confirmed) | Patch Available |", "|---|---|---|", "| AML.T0051 | CVE-2099-0001 | Yes |"]),
    ['3 CVE-2099-0001: patch "Yes", catalog patch_available false']);
});

test("in a Patch / Mitigation column a Yes or a mitigation cell is read only on its vendor-patch statement", () => {
  const expect = {
    patch: ["Vendor patch available", "Mitigation + vendor patch", "Yes — vendor patch", "Yes, vendor patch available"],
    "no patch": ["Mitigation only; no vendor patch", "Workaround only; no vendor fix available", "No", "No (product EoL)"],
    "not compared": [
      "Vendor patch available; mitigation guidance published", "No vendor patch — mitigation is architectural",
      "No — compensating controls only", "Mitigation deployed without a vendor fix",
      "Yes", "Yes (config change)", "Yes — disable the feature",
      "Yes — mitigations available", "Yes — mitigation available; vendor patch pending", "Yes, vendor patch pending",
      "Mitigation only; vendor patch pending", "Workaround published",
      "Vendor patch available plus mitigation guidance",
      "Mitigation + vendor patch; no vendor patch for 1.x", "No for 1.x; vendor patch for 2.x",
      "No — mitigation only", "No — workaround only", "EoL 1.x line: no vendor fix", "Mitigate on 1.x; no vendor patch",
      "Mitigation available; no vendor patch", "Workaround published; no vendor fix",
    ],
  };
  const wrong = [];
  for (const header of ["Patch / Mitigation Available", "Patch / Remediation Available"]) {
    for (const [want, cells] of Object.entries(expect)) {
      for (const cell of cells) if (patchVerdict(cell, header) !== want) wrong.push(`${header}: ${cell}: ${patchVerdict(cell, header)}, want ${want}`);
    }
  }
  assert.deepEqual(wrong, []);
});

test("a mitigation-only cell that says no vendor patch reads as no patch", () => {
  const cells = [
    "Mitigation only; no vendor patch",
    "Mitigations; no vendor patch",
    "Workaround only; no vendor fix available",
    "Compensating controls only; no vendor fix",
    "Workarounds, no vendor update",
  ];
  const rows = apart("| CVE | Patch / Mitigation Available |", cells.map((c) => `| CVE-2099-0001 | ${c} |`));
  const run = (patch) => withSkill(rows.join("\n") + "\n", (file) => checkSkill(file, {
    ...CATALOG, "CVE-2099-0001": { ...CATALOG["CVE-2099-0001"], patch_available: patch },
  }).failures.map((f) => f.replace(/^.*skill\.md:/, "").split(" ")[0]));
  // The text agrees with a catalog that records no patch and differs from one that records a patch.
  assert.deepEqual(run(false), []);
  assert.deepEqual(run(true), ["3", "7", "11", "15", "19"]);
});

test("each alternative of the closed patch, exploitation and live-patch wordings is read", () => {
  const wrong = [];
  const want = (cell, expected, header) => { const got = patchVerdict(cell, header); if (got !== expected) wrong.push(`${header || "Patch Available"}: ${cell}: ${got}, want ${expected}`); };
  for (const q of ["", "IDE ", "SaaS ", "firmware ", "security ", "product ", "OS ", "kernel ", "browser ", "app ", "agent ", "server ", "client ", "cloud ", "library ", "platform "]) {
    for (const noun of ["patch", "patches", "update", "updates", "fix", "fixes"]) want(`Vendor ${q}${noun}`, "patch");
  }
  for (const status of ["available", "released", "shipped", "published", "issued", "applied"]) {
    want(`Vendor patch ${status}`, "patch");
    want(`Vendor patch is ${status}`, "patch");
    want(`Vendor patch ${status} 2099-01-01`, "patch");
    want(`Vendor patch not ${status === "available" ? "" : "yet "}${status}`, status === "applied" ? "not compared" : "no patch");
  }
  for (const denial of ["unavailable", "unreleased", "pending", "planned"]) want(`Vendor fix ${denial}`, "no patch");
  want("Vendor patches are available", "patch");
  want("Vendor patches are pending", "no patch");
  want("No patches are available", "no patch");
  want("Vendor patch.", "patch");
  want("Vendor patch pending.", "no patch");
  want("No vendor patch.", "no patch");
  want("Mitigation only; no vendor patch.", "no patch");
  want("Mitigation + vendor patch.", "patch");
  want("Defense-in-depth + vendor patch", "patch");
  want("Vendor patch + A", "patch");
  for (const sep of [":", ";", " -", " –", " —", ","]) want(`Yes${sep} vendor patch`, "patch");
  for (const cell of ["Vendor patch + hardening; 1.x exposed", "Vendor patch + hardening, 1.x exposed", "Vendor patch + hardening (2.x)",
    "Yes (vendor patch) + hardening"]) want(cell, "not compared");
  for (const noun of ["patch", "patches", "fix", "fixes", "update", "updates", "vendor patch", "vendor update"]) {
    want(`No ${noun}`, "no patch");
    want(`No ${noun} available`, "no patch");
  }
  for (const note of ["(EoL)", "(product EoL)", "(end of life)", "(end-of-life)", "(unsupported)"]) want(`No vendor patch ${note}`, "no patch");
  for (const lead of ["Mitigation", "Mitigations", "Workaround", "Workarounds", "Compensating control", "Compensating controls"]) {
    want(`${lead} only; no vendor patch`, "no patch");
    want(`${lead}, no vendor fix available`, "no patch");
  }
  // Each qualifying word after a "+" item leaves the cell not compared.
  const QUALIFYING_WORDS = ["not", "no", "none", "never", "n/a", "tbd", "tba", "eta", "pending", "planned", "expected", "unavailable",
    "unreleased", "awaiting", "awaited", "outstanding", "delayed", "forthcoming", "upcoming", "coming", "unknown", "soon", "later",
    "next", "progress", "development", "scheduled", "future", "until", "needed", "required", "necessary", "still", "yet", "q1", "q4",
    "if", "unless", "except", "but", "although", "however", "withdrawn", "revoked", "reverted", "pulled", "superseded"];
  for (const word of QUALIFYING_WORDS) want(`Vendor patch + hardening ${word}`, "not compared");
  assert.deepEqual(wrong, []);
  // The same qualifying words after a live-patch Yes or No leave it not compared,
  // except that no, not, none and never after a No restate it and leave it read.
  const NEGATIONS = ["not", "no", "none", "never"];
  for (const live of [true, false]) {
    const rows = apart("| CVE | Live Patch |", QUALIFYING_WORDS.flatMap((w) => [`| CVE-2099-0001 | Yes (kpatch ${w}) |`].concat(NEGATIONS.includes(w) ? [] : [`| CVE-2099-0001 | No (kpatch ${w}) |`])));
    assert.deepEqual(withSkill(rows.join("\n") + "\n", (file) => checkSkill(file, { ...CATALOG, "CVE-2099-0001": { ...CATALOG["CVE-2099-0001"], live_patch_available: live } }).failures), [], String(live));
  }
  for (const w of NEGATIONS) {
    const rows = apart("| CVE | Live Patch |", [`| CVE-2099-0001 | No (kpatch ${w}) |`]);
    assert.equal(withSkill(rows.join("\n") + "\n", (file) => checkSkill(file, { ...CATALOG, "CVE-2099-0001": { ...CATALOG["CVE-2099-0001"], live_patch_available: true } }).failures).length, 1, w);
  }
  // Every none and not-confirmed wording is read.
  const states = ["suspected", "unknown", "none", "theoretical", "confirmed"];
  const fails = (cell) => states.map((state) => withSkill(["| CVE | Active Exploitation |", "|---|---|", `| CVE-2099-0001 | ${cell} |`].join("\n") + "\n",
    (file) => checkSkill(file, { ...CATALOG, "CVE-2099-0001": { ...CATALOG["CVE-2099-0001"], active_exploitation: state } }).failures.length));
  for (const verb of ["observed", "recorded", "reported", "seen", "detected"]) {
    assert.deepEqual(fails(`None ${verb}`), [1, 1, 0, 0, 1], `None ${verb}`);
    assert.deepEqual(fails(`No exploitation ${verb} in the wild`), [1, 1, 0, 0, 1], verb);
  }
  for (const cell of ["No known attacks", "No known attack", "No publicly known exploitation in the wild", "No in-the-wild exploitation known",
    "No exploitation yet confirmed", "No exploitation publicly known"]) {
    assert.deepEqual(fails(cell), [0, 0, 0, 0, 1], cell);
  }
  // "In the wild" is read with spaces or hyphens in every position.
  for (const cell of ["No in the wild exploitation", "None observed in-the-wild"]) {
    assert.deepEqual(fails(cell), [1, 1, 0, 0, 1], cell);
  }
  for (const cell of ["No known in the wild use", "No known exploitation in-the-wild", "No in the wild exploitation known"]) {
    assert.deepEqual(fails(cell), [0, 0, 0, 0, 1], cell);
  }
  for (const cell of ["Confirmed exploitation 2023-2024", "Confirmed exploitation 2023–2024", "Confirmed exploitation 2023 - 2024", "Confirmed."]) {
    assert.deepEqual(fails(cell), [1, 1, 1, 1, 0], cell);
  }
  assert.deepEqual(fails("None observed."), [1, 1, 0, 0, 1], "None observed.");
  assert.deepEqual(fails("No confirmed exploitation."), [0, 0, 0, 0, 1], "No confirmed exploitation.");
});

test("a \"+\" list the patch forms reject fails fast", () => {
  // Eight items take well under a millisecond in the shipped pattern and tens of
  // seconds in one that backtracks exponentially, so a regression trips the bound
  // instead of hanging the suite.
  const started = process.hrtime.bigint();
  patchVerdict("Vendor patch" + " +  item  ".repeat(8) + ";");
  assert.ok(Number(process.hrtime.bigint() - started) / 1e6 < 2000, "an 8-item patch cell took too long");
});

test("an exploitation claim is compared with an unknown or theoretical catalog state too", () => {
  const cat = {
    ...CATALOG,
    "CVE-2099-0001": { ...CATALOG["CVE-2099-0001"], active_exploitation: "unknown" },
    "CVE-2099-0002": { ...CATALOG["CVE-2099-0002"], active_exploitation: "theoretical" },
  };
  const run = (lines) => withSkill(lines.join("\n") + "\n", (file) => checkSkill(file, cat).failures.map((f) => f.replace(/^.*skill\.md:/, "")));
  assert.deepEqual(run(apart("| CVE | Active Exploitation |", [
    "| CVE-2099-0001 | Confirmed |",
    "| CVE-2099-0001 | Unknown |",
    "| CVE-2099-0002 | Theoretical only |",
    "| CVE-2099-0002 | None observed |",
    "| CVE-2099-0002 | Suspected |",
  ])), [
    '3 CVE-2099-0001: active exploitation "Confirmed", catalog unknown',
    '19 CVE-2099-0002: active exploitation "Suspected", catalog theoretical',
  ]);
});

test("a None cell reads as no exploitation only in its plain wording, and agrees with a theoretical entry", () => {
  const states = ["suspected", "unknown", "none", "theoretical", "confirmed"];
  const fails = (cell) => states.map((state) => withSkill(["| CVE | Active Exploitation |", "|---|---|", `| CVE-2099-0001 | ${cell} |`].join("\n") + "\n",
    (file) => checkSkill(file, { ...CATALOG, "CVE-2099-0001": { ...CATALOG["CVE-2099-0001"], active_exploitation: state } }).failures.length));
  for (const cell of ["None", "No", "None observed", "None recorded", "No exploitation observed in the wild", "No in-the-wild exploitation"]) {
    assert.deepEqual(fails(cell), [1, 1, 0, 0, 1], cell);
  }
  assert.deepEqual(fails("Theoretical"), [1, 1, 0, 0, 1], "Theoretical");
  for (const cell of ["Confirmed", "Confirmed mass exploitation", "Confirmed active exploitation", "Confirmed exploitation 2024", "Confirmed exploitation 2023-2024"]) {
    assert.deepEqual(fails(cell), [1, 1, 1, 1, 0], cell);
  }
  for (const cell of [
    "No mass exploitation; targeted attacks observed", "No mass exploitation (targeted attacks)", "No; APT use reported",
    "None at scale; used in targeted intrusions", "No data", "No telemetry", "No reliable data", "None (PoC only)",
    "No ITW exploitation; PoC public", "No confirmed exploitation; targeted attacks observed",
    "No in-the-wild exploitation has been publicly confirmed by any vendor", "No confirmed mass exploitation",
    "No public PoC known", "No known widespread exploitation", "No confirmed exploitation at scale",
    "None known outside targeted attacks", "No known PoC", "No known exploit code",
    "No public PoC (exploitation confirmed by CISA)", "No known public PoC yet exploited in the wild",
  ]) {
    assert.deepEqual(fails(cell), [0, 0, 0, 0, 0], cell);
  }
});

test("'no ... confirmed' and 'none known' differ only from a confirmed entry, in either word order", () => {
  for (const cell of [
    "No confirmed exploitation", "No exploitation confirmed", "None known", "No known in-the-wild use", "No publicly confirmed exploitation",
    "None yet confirmed", "None confirmed", "No known exploitation", "No confirmed in-the-wild attacks",
  ]) {
    const fails = (state) => withSkill(["| CVE | Active Exploitation |", "|---|---|", `| CVE-2099-0001 | ${cell} |`].join("\n") + "\n",
      (file) => checkSkill(file, { ...CATALOG, "CVE-2099-0001": { ...CATALOG["CVE-2099-0001"], active_exploitation: state } }).failures.length);
    assert.deepEqual(["suspected", "unknown", "none", "theoretical", "confirmed"].map(fails), [0, 0, 0, 0, 1], cell);
  }
  // A cell that opens with No or None and continues outside NONE_FORMS and
  // NOT_CONFIRMED_FORMS is not compared, and neither is a state word followed by
  // any text outside STATE_FORMS.
  for (const cell of [
    "No PoC but exploitation confirmed", "None observed, although exploitation is suspected",
    "No public PoC — exploitation confirmed by CISA", "No PoC; exploitation confirmed", "No public PoC; exploited in the wild",
    "None confirmed; suspected", "No, suspected", "No (theoretical only)",
    "Confirmed PoC; no in-the-wild exploitation", "Confirmed exploitable in lab; none observed in the wild",
    "Suspected, attribution unknown", "Theoretical until a PoC is published",
    "Confirmed PoC", "Confirmed (PoC only)", "Confirmed in lab", "Confirmed (lab only)", "Confirmed exploitable",
    "Confirmed vulnerable", "Suspected (supply-chain)",
  ]) {
    const fails = (state) => withSkill(["| CVE | Active Exploitation |", "|---|---|", `| CVE-2099-0001 | ${cell} |`].join("\n") + "\n",
      (file) => checkSkill(file, { ...CATALOG, "CVE-2099-0001": { ...CATALOG["CVE-2099-0001"], active_exploitation: state } }).failures.length);
    assert.deepEqual(["suspected", "unknown", "none", "theoretical", "confirmed"].map(fails), [0, 0, 0, 0, 0], cell);
  }
});

test("each exploitation and live-patch reading differs from a disagreeing catalog value", () => {
  const cat = {
    ...CATALOG,
    "CVE-2099-0001": { ...CATALOG["CVE-2099-0001"], active_exploitation: "confirmed", live_patch_available: true },
    "CVE-2099-0002": { ...CATALOG["CVE-2099-0002"], active_exploitation: "none" },
    "CVE-2099-0003": { ...CATALOG["CVE-2099-0003"], active_exploitation: "suspected" },
  };
  const run = (lines) => withSkill(lines.join("\n") + "\n", (file) => checkSkill(file, cat).failures.map((f) => f.replace(/^.*skill\.md:/, "")));
  assert.deepEqual(run(apart("| CVE | Active Exploitation | Live Patch |", [
    "| CVE-2099-0001 | Theoretical only | No (one distribution) |",
    "| CVE-2099-0002 | Unknown | n/a |",
    "| CVE-2099-0001 | No confirmed exploitation | Yes |",
    "| CVE-2099-0003 | None confirmed | n/a |",
    "| CVE-2099-0001 | None confirmed | n/a |",
  ])), [
    '3 CVE-2099-0001: active exploitation "Theoretical only", catalog confirmed',
    '3 CVE-2099-0001: live patch "No (one distribution)", catalog live_patch_available true',
    '7 CVE-2099-0002: active exploitation "Unknown", catalog none',
    '11 CVE-2099-0001: active exploitation "No confirmed exploitation", catalog confirmed',
    '19 CVE-2099-0001: active exploitation "None confirmed", catalog confirmed',
  ]);
  // A live-patch Yes or No followed by punctuation, a dash or a parenthesis is read.
  const liveRows = ["No — kpatch RHEL-only", "No; reboot window", "No: reboot", "Yes, kpatch", "Yes - kpatch", "Yes – livepatch", "Yes.", "Yes (kpatch)"];
  const liveRun = (live) => withSkill(apart("| CVE | Live Patch |", liveRows.map((c) => `| CVE-2099-0001 | ${c} |`)).join("\n") + "\n",
    (file) => checkSkill(file, { ...CATALOG, "CVE-2099-0001": { ...CATALOG["CVE-2099-0001"], live_patch_available: live } }).failures.map((f) => f.replace(/^.*skill\.md:/, "").split(" ")[0]));
  assert.deepEqual(liveRun(true), ["3", "7", "11"]);
  assert.deepEqual(liveRun(false), ["15", "19", "23", "27", "31"]);
  // A live-patch Yes or No followed by a qualifying word, a hyphen, another word
  // or a second answer is not compared.
  for (const live of [true, false]) {
    assert.deepEqual(withSkill(apart("| CVE | Live Patch |", [
      "| CVE-2099-0001 | Yes (kpatch pending) |",
      "| CVE-2099-0001 | Yes, if on RHEL 9.4 (planned) |", "| CVE-2099-0001 | No, but kpatch is expected |",
      "| CVE-2099-0001 | No-reboot hotpatch on supported builds |", "| CVE-2099-0001 | No reboot (hotpatch) |",
      "| CVE-2099-0001 | No reboot; kpatch |", "| CVE-2099-0001 | No-reboot |", "| CVE-2099-0001 | No-downtime kpatch |",
      "| CVE-2099-0001 | No (Ubuntu); Yes (RHEL kpatch) |", "| CVE-2099-0001 | No (1.x); Yes (2.x) |",
      "| CVE-2099-0001 | Yes (SUSE); No (RHEL, Ubuntu) |",
      "| CVE-2099-0001 | Yes, if on RHEL 9.4 |", "| CVE-2099-0001 | Yes (planned) |",
      "| CVE-2099-0001 | No, but kpatch ships for RHEL |", "| CVE-2099-0001 | No, kpatch expected |",
      "| CVE-2099-0001 | Yes (kpatch Q4) |"]).join("\n") + "\n",
    (file) => checkSkill(file, { ...CATALOG, "CVE-2099-0001": { ...CATALOG["CVE-2099-0001"], live_patch_available: live } }).failures), [], String(live));
  }
  // "Limited" live patching is not compared: the catalog scores some single-vendor
  // live patches as available and others as not.
  for (const live of [true, false]) {
    assert.deepEqual(withSkill(["| CVE | Live Patch |", "|---|---|", "| CVE-2099-0001 | Limited (kpatch RHEL-only) |"].join("\n") + "\n",
      (file) => checkSkill(file, { ...CATALOG, "CVE-2099-0001": { ...CATALOG["CVE-2099-0001"], live_patch_available: live } }).failures), [], String(live));
  }
  // An entry with no active_exploitation value is not compared.
  const bare = { ...CATALOG, "CVE-2099-0001": { ...CATALOG["CVE-2099-0001"] } };
  delete bare["CVE-2099-0001"].active_exploitation;
  assert.deepEqual(withSkill(["| CVE | Active Exploitation |", "|---|---|", "| CVE-2099-0001 | Confirmed |"].join("\n") + "\n",
    (file) => checkSkill(file, bare).failures), []);
});

test("cells that state no comparable value are not compared", () => {
  assert.deepEqual(failuresFor([
    "| CVE | CVSS | RWEP | KEV | Public PoC |",
    "|---|---|---|---|---|",
    "| CVE-2099-0001 | High | varies (historical reference) | No (candidate) | Partial conceptual exploit |",
    "| CVE-2099-0001 | 7.8 | 35 (60 if KEV-listed) | No | Yes (one-liner) |",
  ]), []);
});

test("a row that only points to a CVE, and a CVE the catalog does not hold, are skipped", () => {
  assert.deepEqual(failuresFor([
    "| Channel | CVE? | AI-Accelerated? |",
    "|---|---|---|",
    "| MCP tool args | No vendor CVE; see CVE-2099-0001 class | No |",
    "| Orion | CVE-2000-9999 | Yes |",
  ]), []);
  // A CVE cell that begins with No or N/A, or points to a CVE with "see", does not
  // name the row.
  for (const pointer of ["No CVE (CVE-2099-0002 withdrawn)", "N/A (CVE-2099-0002 rejected)", "Tracked upstream; see CVE-2099-0002"]) {
    assert.deepEqual(failuresFor(["| CVE | RWEP |", "|---|---|", `| ${pointer} | 99 |`]), [], pointer);
  }
  assert.deepEqual(failuresFor(["CVE-2000-9999 has RWEP 99."]), []);
});

test("prose: a stated RWEP or CVSS is compared; ranges, thresholds, projections and superseded values are not", () => {
  assert.deepEqual(failuresFor([
    "CVE-2099-0001: CVSS 7.8 / RWEP 20 — patch within the standard cycle.",
    "every CVE with RWEP >= 50 (for example CVE-2099-0002) must appear; RWEP 40–49 entries should appear.",
    "CVE-2099-0001 reassess if KEV-listed (expected RWEP 55+).",
    "CVE-2099-0002 scores CVSS 9.8; the initial CVSS 7.5 was withdrawn.",
    "CVE-2099-0002 was scored CVSS 7.5, which was corrected later.",
  ]), ["1 CVE-2099-0001: RWEP 20, catalog 35", "5 CVE-2099-0002: CVSS 7.5, catalog 9.8"]);
});

test("a score that ends a sentence is compared; a decimal continuation is not read as a score", () => {
  assert.deepEqual(failuresFor([
    "CVE-2099-0001 carries RWEP 99.",
    "CVE-2099-0001 carries RWEP 35. It stays in the standard band.",
    "CVE-2099-0002 has RWEP 8.5 in an old draft.",
    "| CVE | RWEP |",
    "|---|---|",
    "| CVE-2099-0001 | 99. |",
  ]), ["1 CVE-2099-0001: RWEP 99, catalog 35", "6 CVE-2099-0001: RWEP 99, catalog 35"]);
});

test("prose: a CVSS with a version is compared only against a catalog vector of that version", () => {
  assert.deepEqual(failuresFor(["CVE-2099-0003 is CVSS 3.1 9.8 per NVD."]), []);
  assert.deepEqual(failuresFor(["CVE-2099-0003 is CVSS 4.0 9.8 per the vendor."]), ["1 CVE-2099-0003: CVSS 9.8, catalog 7.8"]);
});

test("prose: KEV statements are compared with the catalog listing", () => {
  assert.deepEqual(failuresFor([
    "CVE-2099-0002 is not KEV-listed.",
    "CVE-2099-0002 (CISA KEV pending) is a worm.",
    "CVE-2099-0002 was KEV-listed 2099-01-01.",
    "CVE-2099-0001 was KEV-listed 2099-01-01.",
    "CVE-2099-0001 is not KEV-listed as of the latest feed.",
  ]), [
    "1 CVE-2099-0002: says not KEV-listed, catalog listed 2099-02-03",
    "2 CVE-2099-0002: says not KEV-listed, catalog listed 2099-02-03",
    "3 CVE-2099-0002: KEV date 2099-01-01, catalog 2099-02-03",
    "4 CVE-2099-0001: says KEV-listed 2099-01-01, catalog not listed",
  ]);
});

test("every spacing, anchor and word boundary in the closed wordings is read as written", () => {
  const strip = (f) => f.replace(/^.*skill\.md:/, "");
  const with1 = (fields) => ({ ...CATALOG, "CVE-2099-0001": { ...CATALOG["CVE-2099-0001"], ...fields } });
  const run = (lines, fields) => withSkill(lines.join("\n") + "\n", (file) => checkSkill(file, with1(fields)).failures.map(strip));
  const states = ["suspected", "unknown", "none", "theoretical", "confirmed"];
  const fails = (cell) => states.map((state) => run(["| CVE | Active Exploitation |", "|---|---|", `| CVE-2099-0001 | ${cell} |`],
    { active_exploitation: state }).length);
  const live = (cell) => [true, false].map((value) => run(["| CVE | Live Patch |", "|---|---|", `| CVE-2099-0001 | ${cell} |`],
    { live_patch_available: value }).length);

  // Headers.
  spacing("Live Patch_Available", columnKind, "live_patch");
  spacing("Patch_Availability", columnKind, "patch");
  spacing("Patches~/~Mitigations_Availability", columnKind, "patch_or_mitigation");
  for (const h of ["Evidence of Active Exploitation", "Live Patch / Mitigation", "Patch / Mitigation Required"]) assert.equal(columnKind(h), null, h);

  // Exploitation cells.
  spacing("No_in-the-wild_exploitation_observed_in-the-wild~.", fails, [1, 1, 0, 0, 1]);
  spacing("None_yet_publicly_confirmed_in-the-wild_attacks_in-the-wild~.", fails, [0, 0, 0, 0, 1]);
  spacing("No_in-the-wild_exploitation_yet_publicly_known~.", fails, [0, 0, 0, 0, 1]);
  spacing("Confirmed_mass_exploitation_2023~-~2024_only~.", fails, [1, 1, 1, 1, 0]);
  spacing("Suspected_active_exploitation", fails, [0, 1, 1, 1, 1]);
  assert.deepEqual(fails("Suspected; no known exploitation"), [0, 0, 0, 0, 0]);

  // Patch cells.
  const verdict = (cell) => patchVerdict(cell);
  spacing("Vendor patch_is_available_2099-01-01~.", verdict, "patch");
  spacing("Vendor patches_are_released", verdict, "patch");
  spacing("Vendor patch~+~config hardening", verdict, "patch");
  spacing("Mitigation +~vendor patch~.", verdict, "patch");
  spacing("Vendor patch_is_unavailable~.", verdict, "no patch");
  spacing("Vendor fixes_are_pending", verdict, "no patch");
  spacing("No_vendor patch_is_available_(product_EoL)~.", verdict, "no patch");
  spacing("None_patches_are_available", verdict, "no patch");
  spacing("Mitigation_only~;~no_vendor patch_available~.", verdict, "no patch");
  const expect = {
    patch: [
      // A qualifying word inside another word does not qualify the cell.
      "Vendor patch + incoming traffic filtering", "Vendor patch + node isolation",
      // A "+" item of two characters, a one-letter lead, and the longest lead.
      "Vendor patch + UI", "X+ vendor patch", `${"x".repeat(41)}+ vendor patch`,
      "Yes(vendor patch)", "Yes ( vendor patch )", "Yes ()", "Yes (vendor patch) .",
    ],
    "not compared": [
      // The phrase must open the cell, and "+ vendor patch" must end it.
      "Legacy vendor patch + hardening", "3 mitigations + vendor patch", "Temporary mitigation only; no vendor patch",
      "Mitigation + vendor patch v2", `${"x".repeat(42)}+ vendor patch`, "Yes, yes (vendor patch)",
      // A "+" item does not start, hold or end with "+", ";", ",", or a parenthesis.
      "Vendor patch + ;a", "Vendor patch + ,a", "Vendor patch + (a", "Vendor patch + )a", "Vendor patch + +a", "Vendor patch + + a",
      "Vendor patch + a ++ b", "Vendor patch + a(b", "Vendor patch + a)b",
      "Vendor patch + a+", "Vendor patch + a;", "Vendor patch + a,", "Vendor patch + a(", "Vendor patch + a)",
    ],
  };
  for (const [want, cells] of Object.entries(expect)) for (const cell of cells) assert.equal(patchVerdict(cell), want, cell);

  // Live-patch cells: a Yes inside a word does not count, and the answer opens the cell.
  assert.deepEqual(live("No (eyes-on review only)"), [1, 0]);
  assert.deepEqual(live("No (fixed in yesterday's build)"), [1, 0]);
  assert.deepEqual(live("Eyes."), [0, 0]);

  // Fences: a longer, trailing-space or indented closing run closes the fence. A
  // line that holds inline code after other text, or that starts with a run of
  // fewer than three backticks or tildes, is not a fence.
  const section = (block) => run([
    "## Live patch by distribution",
    "| CVE | Live Patch |", "|---|---|", "| CVE-2099-0001 | Yes (kpatch) |", "",
    ...block,
    "| CVE | Live Patch |", "|---|---|", "| CVE-2099-0001 | No |",
  ], { live_patch_available: false });
  const split = ['4 CVE-2099-0001: live patch "Yes (kpatch)", catalog live_patch_available false'];
  for (const block of [
    ["```bash", "# x", "````", "## b"], ["```bash", "# x", "```  ", "## b"], ["```bash", "# x", "  ```", "## b"],
    ["Inline ```code``` here", "## b"], ["``inline`` code", "## b"], ["~~struck~~ text", "## b"],
    // A bare run as long as a backtick outer fence closes it, so "# check" ends the section.
    ["```markdown", "```bash", "```", "# check", "```"],
  ]) assert.deepEqual(section(block), split, block.join(" / "));
  // An indented run shorter than the opening one does not close it.
  assert.deepEqual(section(["````markdown", "  ```", "# check", "````"]), []);
  // An opening line whose info string holds U+2028, U+2029 or a lone CR still
  // opens a fence ("\r\r" leaves one CR after the line split).
  for (const opener of ["```bash ", "```bash ", "```bash\r\r"]) {
    assert.deepEqual(section([opener, "# check", "```"]), [], JSON.stringify(opener));
  }

  // Identifier headers.
  const patchFalse = (lines) => run(lines, { patch_available: false });
  const named = ['3 CVE-2099-0001: patch "Yes", catalog patch_available false'];
  for (const header of ["Evidence  CVE", "CVE  ID", "CVE ()", "Class (ATLAS) / CVE (if any)"]) {
    assert.deepEqual(patchFalse([`| Technique | ${header} | Patch Available |`, "|---|---|---|", "| AML.T0051 | CVE-2099-0001 | Yes |"]), named, header);
  }
  for (const header of ["EvidenceCVE", "CVEID"]) {
    assert.deepEqual(patchFalse([`| Technique | ${header} | Patch Available |`, "|---|---|---|", "| AML.T0051 | CVE-2099-0001 | Yes |"]), [], header);
  }
  // A first-column header names the row unless a whole word in it names a CVE or a role.
  for (const header of ["OpenCVE", "CVEfeed", "Footnotes"]) {
    assert.deepEqual(patchFalse([`| ${header} | Technique | Patch Available |`, "|---|---|---|", "| CVE-2099-0001 | AML.T0051 | Yes |"]), named, header);
  }
  // In a table with an identifier column, a first column that only mentions a CVE
  // does not name the row when the identifier cell is blank or n/a. Without that
  // column, the first column names the row.
  const mention = "Prompt injection (analog of CVE-2099-0001)";
  const disagree = { patch_available: false, live_patch_available: false, active_exploitation: "none" };
  for (const idCell of ["", "n/a"]) {
    assert.deepEqual(run(["| Technique | CVE | Patch Available | Live Patch | Active Exploitation |", "|---|---|---|---|---|",
      `| ${mention} | ${idCell} | Yes | Yes | Confirmed |`], disagree), [], JSON.stringify(idCell));
  }
  assert.deepEqual(run(["| Technique | Patch Available |", "|---|---|", `| ${mention} | Yes |`], disagree),
    ['3 CVE-2099-0001: patch "Yes", catalog patch_available false']);

  // A CVE cell is a pointer only when it opens with No or N/A as a word, or holds "see CVE-".
  const rwep = (cell) => failuresFor(["| CVE | RWEP |", "|---|---|", `| ${cell} | 99 |`]);
  for (const cell of ["CVE-2099-0002 (no vendor fix)", "Notable CVE-2099-0002", "Oversee CVE-2099-0002 rollout", "seeCVE-2099-0002"]) {
    assert.deepEqual(rwep(cell), ["3 CVE-2099-0002: RWEP 99, catalog 80"], cell);
  }
  for (const cell of ["See CVE-2099-0002", "see  CVE-2099-0002"]) assert.deepEqual(rwep(cell), [], cell);
  // A failure message quotes the first 40 characters of the cell.
  assert.deepEqual(run(["| CVE | Active Exploitation | Patch Available | Live Patch |", "|---|---|---|---|",
    "| CVE-2099-0001 | Confirmed mass exploitation 2021-2024 only | Vendor firmware updates are available 2099-01-01 | Yes (kpatch, livepatch and kGraft all ship one) |"],
  { active_exploitation: "none", patch_available: false, live_patch_available: false }), [
    '3 CVE-2099-0001: active exploitation "Confirmed mass exploitation 2021-2024 on", catalog none',
    '3 CVE-2099-0001: patch "Vendor firmware updates are available 20", catalog patch_available false',
    '3 CVE-2099-0001: live patch "Yes (kpatch, livepatch and kGraft all sh", catalog live_patch_available false',
  ]);
  // A row with fewer cells than the header leaves the missing columns uncompared.
  assert.deepEqual(failuresFor(["| CVE | Notes | RWEP |", "|---|---|---|", "| CVE-2099-0001 | x |"]), []);
});

test("helpers: column kinds and Yes/No cells", () => {
  assert.equal(columnKind("CVSS"), "cvss");
  assert.equal(columnKind("RWEP tier"), "rwep");
  assert.equal(columnKind("CISA KEV?"), "kev");
  assert.equal(columnKind("PoC Public?"), "poc");
  assert.equal(columnKind("Public PoC"), "poc");
  assert.equal(columnKind("AI-Discovered"), "ai_discovered");
  assert.equal(columnKind("AI-Discovered / AI-Enabled"), "ai_any");
  assert.equal(columnKind("AI factor"), "ai_any");
  assert.equal(columnKind("Active Exploitation"), "active");
  assert.equal(columnKind("Patch / Mitigation Available"), "patch_or_mitigation");
  assert.equal(columnKind("Patch Available?"), "patch");
  assert.equal(columnKind("Live-Patchable"), "live_patch");
  assert.equal(columnKind("Patch / Remediation Available"), "patch_or_mitigation");
  assert.equal(columnKind("Patch Reboot Required?"), null);
  assert.equal(columnKind("Live-patch decisions in scope?"), null);
  assert.equal(columnKind("Patch Tuesday date"), null);
  assert.equal(columnKind("Live Patch"), "live_patch");
  assert.equal(columnKind("Live-patchable"), "live_patch");
  assert.equal(columnKind("Live Patch Available"), "live_patch");
  assert.equal(columnKind("Live Patch Availability"), "live_patch");
  assert.equal(columnKind("Livepatch"), null);
  assert.equal(columnKind("Live Patches"), "live_patch");
  assert.equal(columnKind("Live-Patch"), "live_patch");
  assert.equal(columnKind("Patches"), "patch");
  assert.equal(columnKind("Patch Availability"), "patch");
  assert.equal(columnKind("Patch / Mitigation?"), "patch_or_mitigation");
  assert.equal(columnKind("Patch / Workaround"), "patch_or_mitigation");
  assert.equal(columnKind("Patches / Mitigations"), "patch_or_mitigation");
  assert.equal(columnKind("Patch / Mitigation Availability"), "patch_or_mitigation");
  assert.equal(columnKind("Live Patchable"), "live_patch");
  assert.equal(columnKind("Livepatches"), null);
  // Any other patch, live-patch or exploitation header is not compared.
  for (const h of ["Patch Applied?", "Patch Downtime", "Patch Needed?", "Patch ETA", "Patch Known Issues", "Patch / Live Patch",
    "Live Patch Applied?", "Active Exploitation Actor", "Active Exploitation Since", "Active Exploitation Notes"]) {
    assert.equal(columnKind(h), null, h);
  }
  assert.equal(columnKind("Blast Radius"), null);
  assert.equal(yesNo("Yes — 732-byte script"), true);
  assert.equal(yesNo("No (candidate)"), false);
  assert.equal(yesNo("Partial"), null);
});

test("a row citing a CVE an entry lists in aliases[] is compared with that entry", () => {
  const cat = { ...CATALOG, "BUG-2099-ALIASED": { ...CATALOG["CVE-2099-0002"], aliases: ["CVE-2099-0404"] } };
  const run = (row) => withSkill(["| CVE | CVSS | RWEP |", "|---|---|---|", row].join("\n") + "\n", (file) => checkSkill(file, cat));
  const wrong = run("| CVE-2099-0404 | 9.9 | 99 |");
  assert.equal(wrong.compared, 1, "the aliased row is compared");
  assert.ok(wrong.failures.some((f) => /CVE-2099-0404/.test(f) && /9\.9|CVSS/.test(f)), wrong.failures.join("; "));
  const right = run("| CVE-2099-0404 | 9.8 | 80 |");
  assert.equal(right.compared, 1);
  assert.deepEqual(right.failures, []);
});
