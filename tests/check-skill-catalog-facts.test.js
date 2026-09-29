"use strict";

/**
 * tests/check-skill-catalog-facts.test.js
 *
 * Subject coverage for the scripts/check-skill-catalog-facts.js predeploy gate,
 * which compares the CVE facts a skill states (CVSS, RWEP, KEV status and date,
 * public exploit, AI discovery) against data/cve-catalog.json.
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

/** Failure lines with the skill path removed: "<line> <CVE>: <disagreement>". */
const failuresFor = (lines) =>
  withSkill(lines.join("\n") + "\n", (file) => checkSkill(file, CATALOG).failures.map((f) => f.replace(/^.*skill\.md:/, "")));

test("PASS contract (live): the shipped skills match data/cve-catalog.json", () => {
  const r = spawnSync(process.execPath, [SCRIPT], { cwd: ROOT, encoding: "utf8" });
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stdout, /^Skill catalog facts: PASS — \d+ CVE rows and lines across \d+ skills/);
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
    "| CVE chain | CVSS | RWEP |",
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
    "| CVE pair | RWEP |",
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
    "| CVE pair | RWEP |",
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
  assert.deepEqual(run([
    "| CVE | Active Exploitation | Patch / Mitigation Available | Live-Patchable |",
    "|---|---|---|---|",
    "| CVE-2099-0001 | Suspected | Vendor patch | Limited (kpatch RHEL-only) |",
    "| CVE-2099-0002 | None observed | No | Yes (IDE update) |",
    "| CVE-2099-0001 | Confirmed mass exploitation | No | Yes |",
    "| CVE-2099-0002 | Patched in modern fleets | Mitigation + vendor patch | n/a |",
  ]), [
    '5 CVE-2099-0001: active exploitation "Confirmed mass exploitation", catalog suspected',
    '5 CVE-2099-0001: patch "No", catalog patch_available true',
    '5 CVE-2099-0001: live patch "Yes", catalog live_patch_available false',
  ]);
});

test("a vendor-patch cell that denies availability reads as no patch", () => {
  const cat = {
    ...CATALOG,
    "CVE-2099-0001": { ...CATALOG["CVE-2099-0001"], patch_available: true },
    "CVE-2099-0002": { ...CATALOG["CVE-2099-0002"], patch_available: false },
  };
  const run = (lines) => withSkill(lines.join("\n") + "\n", (file) => checkSkill(file, cat).failures.map((f) => f.replace(/^.*skill\.md:/, "")));
  assert.deepEqual(run([
    "| CVE | Patch Available |",
    "|---|---|",
    "| CVE-2099-0001 | Vendor patch unavailable |",
    "| CVE-2099-0002 | Vendor update not yet available |",
    "| CVE-2099-0002 | Vendor fix pending |",
    "| CVE-2099-0001 | Vendor patch + config hardening |",
    "| CVE-2099-0002 | Vendor patches shipped 2099-01-01 |",
  ]), [
    '3 CVE-2099-0001: patch "Vendor patch unavailable", catalog patch_available true',
    '7 CVE-2099-0002: patch "Vendor patches shipped 2099-01-01", catalog patch_available false',
  ]);
});

test("a vendor-patch cell reads as a patch only when it affirms one", () => {
  const cat = { ...CATALOG, "CVE-2099-0002": { ...CATALOG["CVE-2099-0002"], patch_available: false } };
  const run = (lines) => withSkill(lines.join("\n") + "\n", (file) => checkSkill(file, cat).failures.map((f) => f.replace(/^.*skill\.md:/, "")));
  assert.deepEqual(run([
    "| CVE | Patch Available |",
    "|---|---|",
    "| CVE-2099-0002 | Vendor patch planned |",
    "| CVE-2099-0002 | Vendor patch in development |",
    "| CVE-2099-0002 | Vendor patch status unknown |",
    "| CVE-2099-0002 | Vendor patch |",
    "| CVE-2099-0002 | Vendor patch + config hardening |",
  ]), [
    '6 CVE-2099-0002: patch "Vendor patch", catalog patch_available false',
    '7 CVE-2099-0002: patch "Vendor patch + config hardening", catalog patch_available false',
  ]);
});

test("a column headed CVE outranks a broad subject column", () => {
  assert.deepEqual(failuresFor([
    "| Related Threat | Evidence CVE | RWEP |",
    "|---|---|---|",
    "| Chained with CVE-2099-0002 | CVE-2099-0001 | 99 |",
  ]), ["3 CVE-2099-0001: RWEP 99, catalog 35"]);
});

test("an exploitation claim is compared with an unknown or theoretical catalog state too", () => {
  const cat = {
    ...CATALOG,
    "CVE-2099-0001": { ...CATALOG["CVE-2099-0001"], active_exploitation: "unknown" },
    "CVE-2099-0002": { ...CATALOG["CVE-2099-0002"], active_exploitation: "theoretical" },
  };
  const run = (lines) => withSkill(lines.join("\n") + "\n", (file) => checkSkill(file, cat).failures.map((f) => f.replace(/^.*skill\.md:/, "")));
  assert.deepEqual(run([
    "| CVE | Active Exploitation |",
    "|---|---|",
    "| CVE-2099-0001 | Confirmed |",
    "| CVE-2099-0001 | Unknown |",
    "| CVE-2099-0002 | Theoretical only |",
    "| CVE-2099-0002 | None observed |",
  ]), [
    '3 CVE-2099-0001: active exploitation "Confirmed", catalog unknown',
    '6 CVE-2099-0002: active exploitation "None observed", catalog theoretical',
  ]);
});

test("the row's CVE is taken from its subject column, not from an earlier citation", () => {
  assert.deepEqual(failuresFor([
    "| Notes | Evidence CVE | RWEP |",
    "|---|---|---|",
    "| Related to CVE-2099-0002 | CVE-2099-0001 | 99 |",
  ]), ["3 CVE-2099-0001: RWEP 99, catalog 35"]);
});

test("a CVE mentioned outside the row's subject column is not compared", () => {
  assert.deepEqual(failuresFor([
    "| ATLAS Technique | PoC / Public Demo Available? | CISA KEV? |",
    "|---|---|---|",
    "| AML.T0051 | Yes — CVE-2099-0002 is the sibling case | No |",
    "| Surface / CVE Class | CVSS | CISA KEV |",
  ]), []);
  assert.deepEqual(failuresFor([
    "| Surface / CVE Class | CISA KEV |",
    "|---|---|",
    "| Demo flaw (CVE-2099-0002) | No |",
  ]), ['3 CVE-2099-0002: KEV "No", catalog listed 2099-02-03']);
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
  assert.equal(columnKind("Patch / Mitigation Available"), "patch");
  assert.equal(columnKind("Live-Patchable"), "live_patch");
  assert.equal(columnKind("Blast Radius"), null);
  assert.equal(yesNo("Yes — 732-byte script"), true);
  assert.equal(yesNo("No (candidate)"), false);
  assert.equal(yesNo("Partial"), null);
});
