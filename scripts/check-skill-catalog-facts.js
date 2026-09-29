#!/usr/bin/env node
"use strict";

/**
 * Skill catalog-facts gate. Exit 0 consistent, 1 when a skill states a CVE fact
 * that differs from data/cve-catalog.json.
 *
 * A markdown table row is compared when the first cell that names a CVE names
 * exactly one catalog CVE. Its cells are compared by column header: CVSS, RWEP, a KEV column (Yes/No, and the listing date when the
 * cell gives one), a public-exploit column (Yes/No), and an AI column. An
 * "AI-Discovered" column is compared with ai_discovered; an AI column that also
 * covers acceleration, enablement or weaponization is compared with
 * ai_discovered OR ai_assisted_weaponization. A prose line that names exactly one
 * catalog CVE is compared on "RWEP <n>", "CVSS <n.n>", "KEV-listed <date>" and
 * "not KEV-listed". On any line, the parentheses that follow a CVE id are read
 * as that CVE's values, so a list such as "CVE-A (90), CVE-B (Dirty Frag, 38,
 * CVSS 7.8)" is compared CVE by CVE. A cell or line that states no comparable value is skipped,
 * and so is a CVE the catalog does not hold, a row whose CVE cell only points
 * to one ("No vendor CVE; see CVE-..."), and a value the text marks as superseded.
 */

const fs = require("node:fs");
const path = require("node:path");

const ROOT = path.resolve(__dirname, "..");
const CVE = /CVE-\d{4}-\d{4,}/g;
const DATE = /\d{4}-\d{2}-\d{2}/;

const splitRow = (line) => line.trim().replace(/^\|/, "").replace(/\|$/, "").split("|").map((c) => c.trim());
const isDivider = (cells) => cells.every((c) => /^:?-{2,}:?$/.test(c));
const uniqueCves = (text) => [...new Set(text.match(CVE) || [])];

/** Leading Yes or No of a cell; anything else ("Partial", "varies") is not compared. */
function yesNo(cell) {
  if (/^yes\b/i.test(cell)) return true;
  if (/^no\b/i.test(cell)) return false;
  return null;
}

/**
 * An AI cell's claim: a leading Yes/No, a declarative form the column counts as
 * yes ("AI-discovered", "AI-weaponized"), or "Human-discovered" as no.
 */
function aiValue(cell, yesForm) {
  const v = yesNo(cell);
  if (v !== null) return v;
  if (yesForm.test(cell)) return true;
  if (/^human[- ](?:discovered|found)\b/i.test(cell)) return false;
  return null;
}

/** The CVSS major version a text names ("CVSS 4.0", "CVSS v3.1"), or null. */
function cvssVersion(vector) {
  const m = /^CVSS:(\d)/.exec(vector || "");
  return m ? m[1] : null;
}

function columnKind(header) {
  const h = header.toLowerCase().replace(/[`*?]/g, "").trim();
  if (/^cvss\b/.test(h)) return "cvss";
  if (/^rwep\b/.test(h)) return "rwep";
  if (/\bkev\b/.test(h)) return "kev";
  if (/\bpoc\b|public exploit/.test(h)) return "poc";
  if (/^ai[- ]discovered$/.test(h)) return "ai_discovered";
  if (/^ai\b/.test(h)) return "ai_any";
  return null;
}

/** A cell's text with Markdown emphasis and code marks removed. */
const plain = (cell) => cell.replace(/[*_`]/g, "").trim();

function compareCell(kind, raw, e, say) {
  const cell = plain(raw);
  if (kind === "cvss") {
    const m = /^(\d{1,2}(?:\.\d)?)\b/.exec(cell);
    if (m && Number(m[1]) !== e.cvss_score) say(`CVSS ${m[1]}, catalog ${e.cvss_score}`);
  } else if (kind === "rwep") {
    const m = /^(\d{1,3})(?![\d+–-]|\.\d)/.exec(cell);
    if (m && Number(m[1]) !== e.rwep_score) say(`RWEP ${m[1]}, catalog ${e.rwep_score}`);
  } else if (kind === "kev") {
    const v = yesNo(cell);
    if (v === null) return;
    if (v !== Boolean(e.cisa_kev)) say(`KEV "${cell.slice(0, 40)}", catalog ${e.cisa_kev ? `listed ${e.cisa_kev_date}` : "not listed"}`);
    else if (v) {
      const d = DATE.exec(cell);
      if (d && e.cisa_kev_date && d[0] !== e.cisa_kev_date) say(`KEV date ${d[0]}, catalog ${e.cisa_kev_date}`);
    }
  } else if (kind === "poc") {
    // "Partial" is the catalog's own granular value for a conceptual or chain-only
    // exploit, which it scores as poc_available true.
    const v = /^partial\b/i.test(cell) ? true : yesNo(cell);
    if (v !== null && v !== Boolean(e.poc_available)) say(`public exploit "${cell.slice(0, 40)}", catalog poc_available ${e.poc_available}`);
  } else if (kind === "ai_discovered") {
    const v = aiValue(cell, /^ai[- ](?:discovered|assisted)\b/i);
    if (v !== null && v !== Boolean(e.ai_discovered)) say(`AI-discovered "${cell.slice(0, 40)}", catalog ai_discovered ${e.ai_discovered}`);
  } else if (kind === "ai_any") {
    const v = aiValue(cell, /^ai[- ](?:discovered|assisted|accelerated|enabled|weaponi[sz]ed)\b/i);
    const expected = Boolean(e.ai_discovered) || Boolean(e.ai_assisted_weaponization);
    if (v !== null && v !== expected) say(`AI "${cell.slice(0, 40)}", catalog ai_discovered ${e.ai_discovered} / ai_assisted_weaponization ${e.ai_assisted_weaponization}`);
  }
}

/** A value the text marks as superseded ("the initial CVSS 9.8 was withdrawn"). */
function historical(line, m) {
  const before = line.slice(Math.max(0, m.index - 24), m.index);
  const after = line.slice(m.index + m[0].length, m.index + m[0].length + 24);
  return /\b(?:initial|original|previous(?:ly)?|earlier|former|prior)\s*$/i.test(before) || /^\s*(?:was|were|is)\s+(?:withdrawn|superseded|corrected|replaced)\b/i.test(after);
}

function compareProse(text, e, say) {
  const line = plain(text);
  for (const m of line.matchAll(/RWEP(?: score)?(?:\s*(?:of|is|=|:))?\s*(\d{1,3})(?![\d+–-]|\.\d)/gi)) {
    if (historical(line, m)) continue;
    if (Number(m[1]) !== e.rwep_score) say(`RWEP ${m[1]}, catalog ${e.rwep_score}`);
  }
  for (const m of line.matchAll(/CVSS(?:\s*v?(\d)(?:\.\d)?\b)?(?:\s*(?:score|base score))?(?:\s*(?:of|is|=|:))?\s*(\d{1,2}\.\d)\b/gi)) {
    const version = m[1] || null;
    if (version && version !== cvssVersion(e.cvss_vector)) continue;
    if (historical(line, m)) continue;
    if (Number(m[2]) !== e.cvss_score) say(`CVSS ${m[2]}, catalog ${e.cvss_score}`);
  }
  for (const m of line.matchAll(/\bKEV[- ]listed(?: on)? (\d{4}-\d{2}-\d{2})/g)) {
    if (e.cisa_kev_date && m[1] !== e.cisa_kev_date) say(`KEV date ${m[1]}, catalog ${e.cisa_kev_date}`);
    if (!e.cisa_kev) say(`says KEV-listed ${m[1]}, catalog not listed`);
  }
  if (/\bnot (?:yet )?(?:CISA )?KEV[- ]listed\b|\bnot (?:yet )?(?:on|in) (?:the )?(?:CISA )?KEV\b|\bKEV(?: listing)?:? pending\b|\bpending (?:CISA )?KEV\b/i.test(line) && e.cisa_kev) {
    say(`says not KEV-listed, catalog listed ${e.cisa_kev_date}`);
  }
}

/**
 * Values in the parentheses that follow a CVE id, or that open with one, belong
 * to that CVE: "CVE-X (Copy Fail, RWEP 90, CVSS 7.8)", "CVE-X (Dirty Frag, 38,
 * CVSS 7.8)" or "(CVE-X, CVSS 7.8 / AV:L)". A bare 1-3 digit item is read as
 * RWEP when the line mentions RWEP.
 */
const PER_CVE = /(CVE-\d{4}-\d{4,})\s*\(([^()]*)\)|\((CVE-\d{4}-\d{4,})[,;:]\s*([^()]*)\)/g;

const UNATTRIBUTED = 'states a score for several CVEs outside per-CVE parentheses; write each as "CVE-X (name, RWEP n, CVSS n.n)"';

/** A score statement: "RWEP 53", "CVSS 8.8", "**RWEP:** 53/100". */
const SCORE = /RWEP(?: score)?\*{0,2}(?:\s*(?:of|is|=|:))?\*{0,2}\s*\d{1,3}(?![\d+–-]|\.\d)|CVSS(?:\s*v?\d(?:\.\d)?\b)?(?:\s*(?:score|base score))?\*{0,2}(?:\s*(?:of|is|=|:))?\*{0,2}\s*\d{1,2}\.\d\b|\b\d{1,3}\/100\b/i;

function compareParentheticals(line, catalog, say) {
  const rwepContext = /\bRWEP\b/i.test(line);
  let found = 0;
  for (const raw of line.matchAll(PER_CVE)) {
    const m = raw[1] ? [raw[0], raw[1], raw[2]] : [raw[0], raw[3], raw[4]];
    const e = catalog[m[1]];
    if (!e) continue;
    found++;
    const inner = m[2];
    const tell = (msg) => say(m[1], msg);
    compareProse(inner, e, tell);
    if (rwepContext && !/\bRWEP\b/i.test(inner)) {
      for (const item of inner.split(/[,;]/).map((s) => s.trim())) {
        if (/^\d{1,3}$/.test(item) && Number(item) !== e.rwep_score) tell(`RWEP ${item}, catalog ${e.rwep_score}`);
      }
    }
  }
  return found;
}

/** Factor-table row labels and the rwep_factors key each one scores. */
const FACTOR_KEYS = [
  [/^cisa kev$/, "cisa_kev"],
  [/^poc public$|^public poc$/, "poc_available"],
  [/^ai[- ](?:assisted|discovered|factor)$/, "ai_factor"],
  [/^active exploitation$/, "active_exploitation"],
  [/^blast radius$/, "blast_radius"],
  [/^patch available$/, "patch_available"],
  [/^live patch available$/, "live_patch_available"],
  [/^reboot required$/, "reboot_required"],
];

/**
 * A "Factor | Value | Points" row under a heading that names one catalog CVE:
 * the points must equal that CVE's rwep_factors entry, and the RWEP row must
 * equal its rwep_score.
 */
function compareFactorRow(cells, rawHeader, e, say) {
  const pointsCol = rawHeader.findIndex((h) => /^\s*points\s*$/i.test(h));
  if (pointsCol < 1) return false;
  const label = (cells[0] || "").replace(/\*/g, "").trim().toLowerCase();
  const m = /^\*{0,2}\s*([+\-−]?\d{1,3})\b/.exec(cells[pointsCol] || "");
  if (!m) return false;
  const points = Number(m[1].replace("−", "-"));
  if (/^rwep(?: total)?$/.test(label)) {
    if (points !== e.rwep_score) say(`factor table RWEP ${points}, catalog ${e.rwep_score}`);
    return true;
  }
  const hit = FACTOR_KEYS.find(([re]) => re.test(label));
  if (!hit || !e.rwep_factors || typeof e.rwep_factors[hit[1]] !== "number") return false;
  if (points !== e.rwep_factors[hit[1]]) say(`factor table ${cells[0].replace(/\*/g, "").trim()} ${points}, catalog rwep_factors.${hit[1]} ${e.rwep_factors[hit[1]]}`);
  return true;
}

function checkSkill(file, catalog) {
  const seen = new Set();
  const failures = [];
  const push = (msg) => { if (!seen.has(msg)) { seen.add(msg); failures.push(msg); } };
  let compared = 0;
  let header = null;
  let rawHeader = null;
  let sectionCve = null;
  const lines = fs.readFileSync(file, "utf8").split(/\r?\n/);
  lines.forEach((line, i) => {
    const where = `${path.relative(ROOT, file).replace(/\\/g, "/")}:${i + 1}`;
    if (/^#{1,6}\s/.test(line)) {
      const headingIds = uniqueCves(line);
      sectionCve = headingIds.length === 1 && catalog[headingIds[0]] ? headingIds[0] : null;
    }
    compared += compareParentheticals(line, catalog, (id, msg) => push(`${where} ${id}: ${msg}`));
    if (/^\s*\|/.test(line)) {
      const cells = splitRow(line);
      if (header === null) { rawHeader = cells; header = cells.map(columnKind); return; }
      if (isDivider(cells)) return;
      if (sectionCve && uniqueCves(line).length === 0) {
        if (compareFactorRow(cells, rawHeader, catalog[sectionCve], (msg) => push(`${where} ${sectionCve}: ${msg}`))) compared++;
        return;
      }
      const idCell = cells.find((c) => uniqueCves(c).length > 0) || "";
      if (/^(?:no|n\/a)\b/i.test(idCell) || /\bsee\s+CVE-/i.test(idCell)) return;
      const ids = uniqueCves(idCell);
      if (ids.length > 1) {
        const known = ids.filter((id) => catalog[id]);
        const scored = header.some((kind, k) => (kind === "cvss" || kind === "rwep") && /^\d/.test(plain(cells[k] || "")));
        if (known.length && scored) push(`${where} ${ids.join(", ")}: ${UNATTRIBUTED}`);
        return;
      }
      if (ids.length !== 1 || !catalog[ids[0]]) return;
      const e = catalog[ids[0]];
      compared++;
      header.forEach((kind, k) => {
        if (kind && cells[k] !== undefined) compareCell(kind, cells[k], e, (msg) => push(`${where} ${ids[0]}: ${msg}`));
      });
      return;
    }
    header = null;
    const ids = uniqueCves(line);
    if (ids.length > 1) {
      const rest = plain(line.replace(PER_CVE, " "));
      const m = SCORE.exec(rest);
      if (ids.some((id) => catalog[id]) && m && !historical(rest, m)) push(`${where} ${ids.join(", ")}: ${UNATTRIBUTED}`);
      return;
    }
    if (ids.length !== 1 || !catalog[ids[0]]) return;
    compared++;
    compareProse(line, catalog[ids[0]], (msg) => push(`${where} ${ids[0]}: ${msg}`));
  });
  return { failures, compared };
}

function check(skillsDir, catalog) {
  const failures = [];
  let compared = 0;
  let files = 0;
  for (const name of fs.readdirSync(skillsDir).sort()) {
    const file = path.join(skillsDir, name, "skill.md");
    if (!fs.existsSync(file)) continue;
    files++;
    const r = checkSkill(file, catalog);
    failures.push(...r.failures);
    compared += r.compared;
  }
  return { failures, compared, files };
}

function main() {
  const skillsDir = process.argv[2] || path.join(ROOT, "skills");
  const catalogFile = process.argv[3] || path.join(ROOT, "data", "cve-catalog.json");
  const catalog = JSON.parse(fs.readFileSync(catalogFile, "utf8"));
  const { failures, compared, files } = check(skillsDir, catalog);
  if (failures.length) {
    console.error("Skill catalog facts: FAIL");
    for (const f of failures) console.error(`  ${f}`);
    console.error(`\n${failures.length} skill ${failures.length === 1 ? "statement differs" : "statements differ"} from data/cve-catalog.json. Update the skill text to the catalog value.`);
    process.exitCode = 1;
    return;
  }
  console.log(`Skill catalog facts: PASS — ${compared} CVE rows and lines across ${files} skills match data/cve-catalog.json`);
}

if (require.main === module) main();

module.exports = { check, checkSkill, columnKind, yesNo };
