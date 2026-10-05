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
 * ai_discovered OR ai_assisted_weaponization. The Active Exploitation, Patch and
 * Live Patch columns (the headers columnKind lists) are compared only when no
 * cell in the row names another CVE, the row's CVE is under an identifier
 * header (ID_HEADER_PART, with no ROLE_HEADER word) or, in a table with no
 * identifier column, in the first column under a header that names no CVE and
 * no role, and no other row in the same section
 * (from one "#" or "##" heading outside a fenced code block to the next) has
 * that CVE as its own row CVE (a row that names no CVE and leaves blank the
 * cell under the row above's CVE continues that row): Active Exploitation in the
 * STATE_FORMS,
 * NONE_FORMS or NOT_CONFIRMED_FORMS wording ("No confirmed exploitation"
 * differs only from Confirmed, and None agrees with Theoretical); Patch in one
 * of the PATCH_FORMS wordings, or as a Yes alone or followed by a PATCH_FORMS
 * patch statement (a bare Yes only in a plain Patch column); Live Patch as a Yes
 * or No that ends the cell or is followed by a comma, semicolon, period, colon,
 * dash or parenthesis, with no qualifying word or second answer after it. A
 * prose line that names exactly one
 * catalog CVE is compared on "RWEP <n>", "CVSS <n.n>", "KEV-listed <date>" and
 * "not KEV-listed". On any line, the parentheses that follow a CVE id are read
 * as that CVE's values, so a list such as "CVE-A (90), CVE-B (Dirty Frag, 38,
 * CVSS 7.8)" is compared CVE by CVE. A cell or line that states no comparable value is skipped,
 * and so is a CVE the catalog does not hold, a row whose CVE cell only points
 * to one ("No vendor CVE; see CVE-..."), and a value the text marks as superseded.
 */

const fs = require("node:fs");
const path = require("node:path");
const { cveLookupTargets } = require("../lib/catalog-ids.js");

const ROOT = path.resolve(__dirname, "..");

// The catalog as the checker reads it: each CVE id an entry lists in aliases[]
// also names that entry, so a skill line citing the alias is compared with it.
function withAliases(catalog) {
  const view = Object.assign(Object.create(null), catalog);
  for (const t of cveLookupTargets(catalog)) if (t.alias && !(t.cveId in view)) view[t.cveId] = catalog[t.key];
  return view;
}
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
  // The exploitation, patch and live-patch columns are read only under these
  // headers. Any other header ("Patch Reboot Required?", "Patch Downtime",
  // "Active Exploitation Actor", "Patch / Live Patch") is not compared.
  if (/^active exploitation$/.test(h)) return "active";
  // "Live Patch" or "Live-Patch"; a bare "Livepatch" column names Canonical
  // Livepatch alone in a per-vendor matrix.
  if (/^live[- ]patch(?:able|es)?(?:\s+availab(?:le|ility))?$/.test(h)) return "live_patch";
  if (/^patch(?:es)?(?:\s+availab(?:le|ility))?$/.test(h)) return "patch";
  if (/^patch(?:es)?\s*\/\s*(?:mitigation|remediation|workaround)s?(?:\s+availab(?:le|ility))?$/.test(h)) return "patch_or_mitigation";
  return null;
}

/**
 * The vendor-patch phrase: "Vendor patch", "Vendor updates", "Vendor IDE update".
 * The one qualifier word is a closed list, so a status word in that slot
 * ("Vendor declined fix", "Vendor never patches") never forms the phrase.
 */
const PHRASE = "vendor(?: (?:ide|saas|firmware|security|product|os|kernel|browser|app|agent|server|client|cloud|library|platform))? (?:patch|update|fix)(?:e?s)?";
// A word that can qualify or reverse the statement it follows ("Yes (kpatch
// pending)", "Vendor patch + hardening still pending"). A live-patch cell whose text after
// its leading Yes or No holds one, and a cell in a qualifiable PATCH_FORMS
// wording that holds one, is not compared.
const QUALIFYING = /\b(?:not|no|none|never|n\/a|tbd|tba|eta|pending|planned|expected|unavailable|unreleased|awaiting|awaited|outstanding|delayed|forthcoming|upcoming|coming|unknown|soon|later|next|progress|development|scheduled|future|until|needed|required|necessary|still|yet|q[1-4]|if|unless|except|but|although|however|withdrawn|revoked|reverted|pulled|superseded)\b/i;

/**
 * The patch cells the gate reads, each matched against the whole cell, with the
 * value it reads and whether a qualifying word leaves it not compared. Any other
 * wording is not compared.
 */
const PATCH_FORMS = [
  // "Vendor patch", "Vendor updates available", "Vendor patches shipped 2099-01-01".
  [new RegExp(`^${PHRASE}(?:\\s+(?:is\\s+|are\\s+)?(?:available|released|shipped|published|issued|applied)(?:\\s+\\d{4}-\\d{2}-\\d{2})?)?\\s*\\.?$`, "i"), true, false], // allow:dynamic-regex — built from the static PHRASE literal
  // "Vendor patch + config hardening", "Vendor IDE update + manifest signing".
  // Each "+" item starts and ends on a non-space character and stops at "+", ";",
  // "," or a parenthesis, so the spaces around a "+" can only match `\s*` and a
  // failing match backtracks at most linearly.
  [new RegExp(`^${PHRASE}(?:\\s*\\+\\s*[^+;,()\\s](?:[^+;,()]*[^+;,()\\s])?)+$`, "i"), true, true], // allow:dynamic-regex — static PHRASE
  // "Mitigation + vendor patch".
  [new RegExp(`^[a-z][a-z -]{0,40}\\+\\s*${PHRASE}\\s*\\.?$`, "i"), true, true], // allow:dynamic-regex — static PHRASE
  // "Vendor patch pending", "Vendor fix unavailable", "Vendor update not yet available".
  [new RegExp(`^${PHRASE}\\s+(?:is\\s+|are\\s+)?(?:unavailable|unreleased|pending|planned|not (?:yet )?(?:available|released|shipped|published|issued))\\s*\\.?$`, "i"), false, false], // allow:dynamic-regex — static PHRASE
  // "No", "None", "No patch", "No vendor fix available", "No vendor patch (product EoL)".
  [new RegExp(`^(?:no|none)(?:\\s+(?:${PHRASE}|patch(?:es)?|fix(?:es)?|updates?)(?:\\s+(?:is\\s+|are\\s+)?available)?)?(?:\\s+\\((?:product\\s+)?(?:eol|end[- ]of[- ]life|unsupported)\\))?\\s*\\.?$`, "i"), false, false], // allow:dynamic-regex — static PHRASE
  // "Mitigation only; no vendor patch", "Workaround only, no vendor fix available".
  [new RegExp(`^(?:mitigations?|workarounds?|compensating controls?)(?:\\s+only)?\\s*[;,]\\s*no\\s+${PHRASE}(?:\\s+available)?\\s*\\.?$`, "i"), false, false], // allow:dynamic-regex — static PHRASE
];

/**
 * The value of the first PATCH_FORMS entry that matches the whole cell, or null
 * when no entry matches or when that entry is qualifiable and the cell holds a
 * QUALIFYING word.
 */
function patchForm(cell) {
  for (const [re, value, qualifiable] of PATCH_FORMS) {
    if (re.test(cell)) return qualifiable && QUALIFYING.test(cell) ? null : value;
  }
  return null;
}

/**
 * A leading Yes or No that ends the cell or is followed by a comma, semicolon,
 * period, colon, dash or parenthesis ("Yes (kpatch/livepatch)", "No — kpatch
 * RHEL-only"), or null when another word or a hyphen follows it ("No-reboot
 * hotpatch", "No reboot"), when a qualifying word comes after it ("Yes (kpatch
 * pending)"), or when a later Yes follows it ("No (Ubuntu); Yes (RHEL
 * kpatch)"). After a leading No, the negations no, not, none and never restate
 * it ("No (the fix is an IDE upgrade, not a runtime patch)") and do not count as
 * qualifying words.
 */
function plainAnswer(cell) {
  const m = /^(yes|no)(?=\s*(?:$|[,;.:(—–]|-\s))/i.exec(cell);
  if (!m) return null;
  const isNo = m[1].toLowerCase() === "no";
  const rest = cell.slice(m[0].length);
  const qualifiers = isNo ? rest.replace(/\b(?:not|no|none|never)\b/gi, " ") : rest;
  if (QUALIFYING.test(qualifiers) || /\byes\b/i.test(rest)) return null;
  return !isNo;
}

/**
 * A Patch column cell's claim. A Yes reads as a patch when a PATCH_FORMS patch
 * statement follows it ("Yes, vendor patch"), or when it is the whole cell in a
 * plain Patch column; in a "Patch / Mitigation", "Patch / Remediation" or "Patch
 * / Workaround" column a bare Yes can answer for the mitigation and is not
 * compared. A Yes with any other text after it ("Yes (workaround)", "Yes, if on
 * 2.x") is not compared. Any other cell is read only when the whole cell is one
 * of PATCH_FORMS.
 */
function patchCellValue(cell, kind) {
  if (/^yes\b/i.test(cell)) {
    // "Yes (vendor IDE update)" is read on the text inside the parentheses.
    const wrapped = /^yes\s*\(([^()]*)\)\s*\.?$/i.exec(cell);
    const rest = wrapped ? wrapped[1].trim() : cell.replace(/^yes\b[\s,;:—–-]*/i, "");
    if (/^\.?$/.test(rest)) return kind === "patch" ? true : null;
    return patchForm(rest) === true ? true : null;
  }
  return patchForm(cell);
}

/** The cells that read as no exploitation: "None", "None observed", "No exploitation observed in the wild". */
const NONE_FORMS = /^(?:none|no)(?:\s+(?:in[- ]the[- ]wild\s+)?exploitation)?(?:\s+(?:observed|recorded|reported|seen|detected))?(?:\s+in[- ]the[- ]wild)?\s*\.?$/i;
/** The cells that deny confirmation: "No confirmed exploitation", "No exploitation confirmed", "None known", "No known in-the-wild use". */
const NOT_CONFIRMED_FORMS = /^(?:(?:no|none)\s+(?:yet\s+)?(?:publicly\s+)?(?:confirmed|known)(?:\s+(?:in[- ]the[- ]wild\s+)?(?:exploitation|use|attacks?))?(?:\s+in[- ]the[- ]wild)?|no\s+(?:in[- ]the[- ]wild\s+)?exploitation\s+(?:yet\s+)?(?:publicly\s+)?(?:confirmed|known))\s*\.?$/i;
/** The cells that name a state: "Confirmed", "Confirmed mass exploitation", "Confirmed exploitation 2024", "Theoretical only". */
const STATE_FORMS = /^(confirmed|suspected|unknown|theoretical)(?:\s+(?:mass\s+|active\s+)?exploitation)?(?:\s+\d{4}(?:\s*[-–]\s*\d{4})?)?(?:\s+only)?\s*\.?$/i;

/**
 * Active-exploitation cell, read only when the whole cell is one of STATE_FORMS,
 * NONE_FORMS or NOT_CONFIRMED_FORMS. "No confirmed exploitation" (or "None
 * known") denies confirmation, not exploitation: it is true of every state but
 * confirmed, so it returns "not_confirmed", which differs only from a confirmed
 * entry. Any other wording ("Confirmed PoC", "No confirmed mass exploitation",
 * "Suspected (supply-chain)", "No data") is not compared.
 */
function exploitationValue(cell) {
  if (NOT_CONFIRMED_FORMS.test(cell)) return "not_confirmed";
  if (NONE_FORMS.test(cell)) return "none";
  const m = STATE_FORMS.exec(cell);
  return m ? m[1].toLowerCase() : null;
}

/** A cell's text with Markdown emphasis and code marks removed. */
const plain = (cell) => cell.replace(/[*_`]/g, "").trim();

/** The column kinds compared only on a row that names a single CVE. */
const ROW_CVE_KINDS = new Set(["active", "patch", "patch_or_mitigation", "live_patch"]);
/**
 * One "/" part of an identifier column's header, with parenthetical notes
 * removed: CVE or CVEs, optionally preceded by Evidence and followed by ID or
 * Class ("CVE", "CVE ID", "Evidence CVE", "CVE Class", "CVE (if any)").
 */
const ID_HEADER_PART = /^(?:evidence\s+)?cves?(?:\s+(?:id|class))?$/i;
/** A header word that marks a column as describing or citing a case, not naming the row. */
const ROLE_HEADER = /\b(?:related|siblings?|similar|see[- ]also|examples?|e\.g|analog(?:ue)?s?|pocs?|demos?|exploits?|notes?|comments?|rationales?|reasons?|descriptions?|details?)\b/i;

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
  } else if (kind === "active") {
    const v = exploitationValue(cell);
    const actual = String(e.active_exploitation || "").toLowerCase();
    // The catalog's theoretical state is a public PoC with no exploitation seen,
    // so a None cell agrees with it, and a Theoretical cell with a none entry.
    const quiet = (s) => s === "none" || s === "theoretical";
    const differs = v === "not_confirmed" ? actual === "confirmed" : v !== actual && !(quiet(v) && quiet(actual));
    if (v && actual && differs) say(`active exploitation "${cell.slice(0, 40)}", catalog ${actual}`);
  } else if (kind === "patch" || kind === "patch_or_mitigation") {
    const v = patchCellValue(cell, kind);
    if (v !== null && v !== Boolean(e.patch_available)) say(`patch "${cell.slice(0, 40)}", catalog patch_available ${e.patch_available}`);
  } else if (kind === "live_patch") {
    const v = plainAnswer(cell);
    if (v !== null && v !== Boolean(e.live_patch_available)) say(`live patch "${cell.slice(0, 40)}", catalog live_patch_available ${e.live_patch_available}`);
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
/** Factor rows whose Value cell states a catalog boolean, with how to read it. */
const FACTOR_VALUES = [
  [/^cisa kev$/, (e) => Boolean(e.cisa_kev), "cisa_kev"],
  [/^poc public$|^public poc$/, (e) => Boolean(e.poc_available), "poc_available"],
  [/^ai[- ]discovered$/, (e) => Boolean(e.ai_discovered), "ai_discovered"],
  [/^ai[- ](?:assisted|factor)$/, (e) => Boolean(e.ai_discovered) || Boolean(e.ai_assisted_weaponization), "ai_discovered / ai_assisted_weaponization"],
  [/^patch available$/, (e) => Boolean(e.patch_available), "patch_available"],
  [/^live patch available$/, (e) => Boolean(e.live_patch_available), "live_patch_available"],
  [/^reboot required$/, (e) => Boolean(e.patch_required_reboot), "patch_required_reboot"],
];

function compareFactorRow(cells, rawHeader, e, say) {
  const pointsCol = rawHeader.findIndex((h) => /^\s*points\s*$/i.test(h));
  if (pointsCol < 1) return false;
  const label = (cells[0] || "").replace(/\*/g, "").trim().toLowerCase();
  const valueCol = rawHeader.findIndex((h) => /^\s*value\s*$/i.test(h));
  const valueRule = FACTOR_VALUES.find(([re]) => re.test(label));
  if (valueCol > 0 && valueRule) {
    const cell = plain(cells[valueCol] || "");
    const v = /^partial\b/i.test(cell) && valueRule[2] === "poc_available" ? true : yesNo(cell);
    if (v !== null && v !== valueRule[1](e)) say(`factor table ${cells[0].replace(/\*/g, "").trim()} value "${cell.slice(0, 40)}", catalog ${valueRule[2]} ${valueRule[1](e)}`);
  }
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

function checkSkill(file, rawCatalog) {
  const catalog = withAliases(rawCatalog);
  const seen = new Set();
  const failures = [];
  // Each failure carries the order in which it was found, so failures held back
  // until the section ends are still reported in line order.
  let seq = 0;
  const push = (msg, at = seq++) => { if (!seen.has(msg)) { seen.add(msg); failures.push([at, msg]); } };
  // Exploitation, patch and live-patch failures are held until the section ends
  // (the next "#" or "##" heading, or the end of the file) and kept only for a
  // CVE that is the row CVE of exactly one row in that section. A per-distribution
  // or per-version table ("RHEL 9 | Yes", "Ubuntu 24.04 | No"), one table or one
  // "###" sub-heading per distribution, or a continuation row that leaves the CVE
  // cell blank answers for one row at a time, not for the CVE.
  let held = [];
  let rowCves = new Map();
  let lastRowCve = null;
  let lastRowCol = -1;
  const flush = () => {
    for (const [at, cve, msg] of held) if (rowCves.get(cve) === 1) push(msg, at);
    held = [];
    rowCves = new Map();
    lastRowCve = null;
  };
  // A "#" line inside a fenced code block does not end the section for the
  // exploitation, patch and live-patch row count. A fence closes only on a line
  // of its own character, at least as long as the opening run, with nothing
  // after it. A nested code block that uses the other character or a shorter run
  // leaves the outer fence open; a bare run of the same character at least as
  // long as the outer one closes it.
  let fence = null;
  const countRow = (cve) => rowCves.set(cve, (rowCves.get(cve) || 0) + 1);
  let compared = 0;
  let header = null;
  let rawHeader = null;
  let sectionCve = null;
  const lines = fs.readFileSync(file, "utf8").split(/\r?\n/);
  lines.forEach((line, i) => {
    const where = `${path.relative(ROOT, file).replace(/\\/g, "/")}:${i + 1}`;
    const fenceLine = /^\s*(`{3,}|~{3,})(.*)$/s.exec(line);
    if (fenceLine && !fence) fence = fenceLine[1];
    else if (fenceLine && fenceLine[1][0] === fence[0] && fenceLine[1].length >= fence.length && !fenceLine[2].trim()) fence = null;
    if (/^#{1,6}\s/.test(line)) {
      // A "###" or deeper heading ("### RHEL 9", "### Ubuntu 24.04") stays in its
      // parent section for the row count.
      if (!fence && /^#{1,2}\s/.test(line)) flush();
      const headingIds = uniqueCves(line);
      sectionCve = headingIds.length === 1 && catalog[headingIds[0]] ? headingIds[0] : null;
    }
    compared += compareParentheticals(line, catalog, (id, msg) => push(`${where} ${id}: ${msg}`));
    if (/^\s*\|/.test(line)) {
      const cells = splitRow(line);
      if (header === null) { rawHeader = cells; header = cells.map(columnKind); lastRowCve = null; return; }
      if (isDivider(cells)) return;
      // A row that names no CVE and leaves blank the cell under the row above's
      // CVE continues that row.
      const continues = lastRowCve && !plain(cells[lastRowCol] || "") && uniqueCves(line).length === 0;
      if (sectionCve && uniqueCves(line).length === 0) {
        if (continues) countRow(lastRowCve);
        else lastRowCve = null;
        if (compareFactorRow(cells, rawHeader, catalog[sectionCve], (msg) => push(`${where} ${sectionCve}: ${msg}`))) compared++;
        return;
      }
      const idCol = cells.findIndex((c) => uniqueCves(c).length > 0);
      const idCell = cells[idCol] || "";
      if (/^(?:no|n\/a)\b/i.test(idCell) || /\bsee\s+CVE-/i.test(idCell)) { lastRowCve = null; return; }
      const ids = uniqueCves(idCell);
      if (ids.length > 1) {
        lastRowCve = null;
        const known = ids.filter((id) => catalog[id]);
        const scored = header.some((kind, k) => (kind === "cvss" || kind === "rwep") && /^\d/.test(plain(cells[k] || "")));
        if (known.length && scored) push(`${where} ${ids.join(", ")}: ${UNATTRIBUTED}`);
        return;
      }
      if (continues) { countRow(lastRowCve); return; }
      if (ids.length !== 1 || !catalog[ids[0]]) { lastRowCve = null; return; }
      const e = catalog[ids[0]];
      compared++;
      countRow(ids[0]);
      lastRowCve = ids[0];
      lastRowCol = idCol;
      // The exploitation, patch and live-patch cells are read against the row's
      // CVE only when no cell names another CVE and the CVE sits under an
      // identifier header (ID_HEADER_PART), or, in a table with no identifier
      // column, in the first column under a header that names no CVE and no role
      // (ROLE_HEADER). A row whose CVE is a related
      // case, cited in a PoC, notes, "Related CVE", "CVE (example)" or similar
      // column, does not have them compared with that entry.
      const single = cells.every((c) => uniqueCves(c).every((id) => id === ids[0]));
      const norm = (h) => (h || "").replace(/[?*`_]/g, " ");
      const idHeader = (h) => !ROLE_HEADER.test(h) && h.replace(/\([^)]*\)/g, " ").split("/").some((part) => ID_HEADER_PART.test(part.trim()));
      const first = norm(rawHeader[0]);
      const idColumn = rawHeader.some((h) => idHeader(norm(h)));
      const named = idHeader(norm(rawHeader[idCol])) || (idCol === 0 && !idColumn && !/\bcves?\b/i.test(first) && !ROLE_HEADER.test(first));
      header.forEach((kind, k) => {
        if (!kind || cells[k] === undefined) return;
        if (!ROW_CVE_KINDS.has(kind)) {
          compareCell(kind, cells[k], e, (msg) => push(`${where} ${ids[0]}: ${msg}`));
        } else if (single && named) {
          compareCell(kind, cells[k], e, (msg) => held.push([seq++, ids[0], `${where} ${ids[0]}: ${msg}`]));
        }
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
  flush();
  return { failures: failures.sort((a, b) => a[0] - b[0]).map(([, msg]) => msg), compared };
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
