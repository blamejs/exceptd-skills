"use strict";

/**
 * Companion collector for the `citation-hygiene` playbook: cross-references CVE
 * and RFC citations in the cwd tree against data/cve-catalog.json and
 * data/rfc-references.json. Interface: see lib/collectors/README.md
 */

const fs = require("node:fs");
const path = require("node:path");

const { codeExcludeSet, walkTree, buildEvidenceLocations, lineFromOffset } = require("./scan-excludes");

const COLLECTOR_ID = "citation-hygiene";

// Required lazily so a plain collect() never loads the resolver.
function loadResolver() {
  return require("../citation-resolve.js");
}

const DEFAULT_MAX_DEPTH = 8;
const EXCLUDES = codeExcludeSet();

// Citations live in source comments, and in docs and config prose.
const SCAN_EXTS = new Set([
  ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".mts", ".cts",
  ".py", ".pyi",
  ".go",
  ".rs",
  ".java", ".kt", ".kts", ".scala",
  ".rb",
  ".php",
  ".c", ".h", ".cc", ".cpp", ".hpp", ".cxx",
  ".cs",
  ".swift",
  ".m", ".mm",
  ".md", ".mdx", ".rst", ".txt", ".adoc", ".asciidoc",
  ".yaml", ".yml", ".toml", ".cfg", ".ini",
]);

const MAX_FILE_BYTES = 2 * 1024 * 1024;

// Paths whose citations are illustrative, not real self-citations.
const ILLUSTRATIVE_PATH_SEGMENTS = [
  "/test/", "/tests/", "/spec/", "/specs/", "/__tests__/",
  "/fixtures/", "/fixture/",
  "/.github/issue_template/", "/.github/pull_request_template/",
  "/issue_template/", "/pull_request_template/",
  // These directories hold the patterns themselves; scanning them flags the scanner.
  "/lib/collectors/", "/data/playbooks/", "/lib/schemas/",
];

function isIllustrativePath(rel) {
  const norm = "/" + rel.replace(/\\/g, "/").toLowerCase() + "/";
  for (const seg of ILLUSTRATIVE_PATH_SEGMENTS) {
    if (norm.includes(seg)) return true;
  }
  if (/\.template($|\.)/i.test(rel)) return true;
  if (/(?:^|[\\/])[^\\/]+\.(test|spec)\.[a-z]+$/i.test(rel)) return true;
  return false;
}

function readSafe(full) {
  try {
    // The cap is byte-based: enforced on the buffer, before any UTF-8 decode.
    const raw = fs.readFileSync(full);
    if (raw.length > MAX_FILE_BYTES) return null;
    return raw.toString("utf8");
  } catch { return null; }
}

// Permissive: a letter tail is captured, not skipped, so the canonical-form test
// below can flag it.
const CVE_CITATION_RE = /CVE-(\d{4})-([0-9A-Za-z]+)/g;
const CVE_CANONICAL_RE = /^CVE-\d{4}-\d{4,}$/;

const RFC_CITATION_RE = /RFC[\s-]?(\d{1,5})\b/gi;

// True only when a reject/dispute/withdraw word refers to THIS citation's own
// record — not a CVSS disagreement, a coordination dispute, or another CVE the
// note mentions. `selfId` is the citation's own CVE id.
function recordRejectedOrDisputed(note, selfId) {
  if (!note) return false;
  const self = String(selfId || "").toUpperCase();
  const re = /\b(reject(?:ed|s|ion)?|disputed?|withdrawn)\b/gi;
  // Qualifier nouns that make a "dispute" a disagreement about something other
  // than the record's validity; 'rejected' / 'withdrawn' bypass this.
  const QUALIFIER = /\b(cvss|scoring|score|severity|coordination|disclosure|methodolog\w*|attribution|naming|assignment|priorit\w*)\b/i;
  // A "duplicate of / superseded by / in favour of" construction names the
  // REPLACEMENT cve, so that other id must not suppress the flag.
  const REPLACEMENT_OF = /\b(?:duplicate|dup)\b[\s\w-]*\bof\b|\b(?:supersed\w+|replaced|merged)\b[\s\w-]*\b(?:by|into)\b|\bin\s+favou?r\s+of\b/i;
  // "Reject" is also the ordinary verb for what code does to input, so the record
  // sense must name what was rejected or who rejected it. Bare "entry" and
  // "advisory" stay out: they are ordinary words in mechanism prose, and admitting
  // them reads SMTP message rejection as a rejected CVE record.
  const RECORD_CONTEXT = /\b(CVE record|catalog(?:ue)? entry|record status|identifier|assignment|CVE|MITRE|NVD|CNA)\b/i;
  const otherCve = (s) => (s.match(/CVE-\d{4}-\d{4,}/gi) || []).some((c) => c.toUpperCase() !== self);
  let m;
  while ((m = re.exec(note)) !== null) {
    const word = m[1].toLowerCase();
    const before = note.slice(Math.max(0, m.index - 60), m.index);
    const after = note.slice(re.lastIndex, re.lastIndex + 60);
    // A different cve BEFORE the word is the subject: that record's status.
    if (otherCve(before)) continue;
    // A cve AFTER suppresses too, unless it is a duplicate-of replacement target.
    if (otherCve(after) && !REPLACEMENT_OF.test(after)) continue;
    // A 'dispute' qualified by a non-record noun is about that noun.
    if (word.startsWith("disput")) {
      const lastTokens = before.trim().split(/[\s-]+/).slice(-3).join(" ");
      if (QUALIFIER.test(lastTokens)) continue;
    }
    // A 'reject' with nothing record-shaped around it is the ordinary verb.
    if (word.startsWith("reject") && !RECORD_CONTEXT.test(before + " " + after)) continue;
    return true;
  }
  return false;
}

// Draft-language proximity for the (unflipped) draft-as-RFC heuristic.
const DRAFT_LANGUAGE_RE = /\b(draft-[a-z0-9-]+|internet[- ]draft|work[- ]in[- ]progress|i-d\b)\b/i;

/**
 * Load the shipped CVE catalog and RFC index, resolved relative to this module so
 * the collector works from a source tree or a node_modules install. Returns
 * { cveKeys:Set, cveNotes:Map<id,string>, rfcTitles:Map<number,string>, errors:[] }.
 */
function loadCatalogs() {
  const errors = [];
  const dataDir = path.resolve(__dirname, "..", "..", "data");
  const cveKeys = new Set();
  const cveNotes = new Map();
  const rfcTitles = new Map();

  try {
    const cve = JSON.parse(fs.readFileSync(path.join(dataDir, "cve-catalog.json"), "utf8"));
    for (const [k, v] of Object.entries(cve)) {
      if (k.startsWith("_")) continue;
      cveKeys.add(k);
      if (v && typeof v === "object") {
        // Analyst-note fields carrying rejected / disputed status, concatenated
        // per entry so a citation matches its own notes and never a neighbour's.
        const noteParts = [
          v.cvss_note, v.active_exploitation_notes, v.vector,
          v.discovery_attribution_note, v.ai_discovery_notes,
          v._kev_short_description,
        ].filter((s) => typeof s === "string");
        cveNotes.set(k, noteParts.join(" • "));
      }
    }
  } catch (e) {
    errors.push({ artifact_id: "cve-catalog", kind: "catalog_load_failed", reason: e.message });
  }

  try {
    const rfc = JSON.parse(fs.readFileSync(path.join(dataDir, "rfc-references.json"), "utf8"));
    for (const [k, v] of Object.entries(rfc)) {
      if (k.startsWith("_")) continue;
      if (v && typeof v === "object" && typeof v.number === "number" && typeof v.title === "string") {
        rfcTitles.set(v.number, v.title);
      }
    }
  } catch (e) {
    errors.push({ artifact_id: "rfc-index", kind: "catalog_load_failed", reason: e.message });
  }

  return { cveKeys, cveNotes, rfcTitles, errors };
}

function normalizeTitle(s) {
  return s
    .toLowerCase()
    .replace(/[^a-z0-9\s]/g, " ")
    .replace(/\s+/g, " ")
    .replace(/^the\s+/, "")
    .trim();
}

const TITLE_STOPWORDS = new Set([
  "the", "a", "an", "of", "for", "and", "to", "in", "on", "with",
  "protocol", "version", "extension", "specification", "spec", "rfc",
]);

function titleTokens(s) {
  return new Set(
    normalizeTitle(s).split(" ").filter((t) => t.length >= 3 && !/^\d+$/.test(t) && !TITLE_STOPWORDS.has(t)),
  );
}

function orderedTitleTokens(s) {
  return normalizeTitle(s)
    .split(" ")
    .filter((t) => t.length >= 3 && !/^\d+$/.test(t) && !TITLE_STOPWORDS.has(t));
}

// Lowercase acronym from the title's meaningful words: "Transport Layer Security
// Protocol" gives "tls". Lets a nickname be recognised as the same document.
function titleAcronym(realTitle) {
  return orderedTitleTokens(realTitle).map((w) => w[0]).join("");
}

/**
 * Decide whether an EXPLICITLY STATED title conflicts with the real index title.
 * Only a title introduced immediately after the RFC number counts (see
 * statedTitleAfter): a mechanism citation states no title, and comparing that
 * prose against a formal title reports a mismatch on a correct citation. Only
 * ZERO token overlap is a mismatch — any shared content word is a paraphrase.
 * Returns "mismatch" | "match" | "no-title-claim".
 */
function classifyRfcTitle(statedTitle, realTitle) {
  const adjTokens = titleTokens(statedTitle);
  if (adjTokens.size < 2) return "no-title-claim";
  const realTokens = titleTokens(realTitle);
  if (realTokens.size === 0) return "no-title-claim";
  const acronym = titleAcronym(realTitle);
  if (acronym.length >= 2 && adjTokens.has(acronym)) return "match";
  let overlap = 0;
  for (const t of adjTokens) {
    if (realTokens.has(t)) { overlap++; continue; }
    // Nickname recognition: a stated token containing (or contained by) a real
    // token of length >= 4 is the same document — "IMAP4rev2" carries "imap".
    for (const rt of realTokens) {
      if (rt.length >= 4 && (t.includes(rt) || rt.includes(t))) { overlap++; break; }
    }
  }
  return overlap === 0 ? "mismatch" : "match";
}

// The whole line containing `index`, as adjacent text for the title comparison.
function lineAround(content, index) {
  const start = content.lastIndexOf("\n", index) + 1;
  let end = content.indexOf("\n", index);
  if (end === -1) end = content.length;
  return content.slice(start, end);
}

// Extract a title EXPLICITLY QUOTED immediately after the RFC number on the same
// line — `RFC N "The Title"`, `RFC N: "The Title"`, `RFC N ("The Title")`. Prose,
// section pointers, bare nicknames and `envelope.rfc822` state no title. The
// opening quote must be SEPARATED from the number by whitespace or a `:` / `(`
// introducer: one touching the last digit is the CLOSING quote of a string ending
// with the citation, and the code after it is then captured as a phantom title.
function statedTitleAfter(after) {
  const m = after.match(/^(?:\s*[:(]\s*|\s+)["“]([^"”\n]{3,100})["”]/);
  return m ? m[1].trim() : null;
}

function collect({ cwd = process.cwd() } = {}) {
  const errors = [];
  const startTime = Date.now();
  const root = path.resolve(cwd);

  const { cveKeys, cveNotes, rfcTitles, errors: catErrors } = loadCatalogs();
  for (const e of catErrors) errors.push(e);
  const catalogsLoaded = cveKeys.size > 0 && rfcTitles.size > 0;

  let files;
  try {
    files = walkTree(root, { maxDepth: DEFAULT_MAX_DEPTH, excludes: EXCLUDES });
  } catch (e) {
    errors.push({ kind: "walk_failed", reason: e.message });
    files = [];
  }
  if (files.length > 50000) {
    errors.push({
      kind: "file_count_capped",
      reason: `walked ${files.length} files; capping content scan at 50000.`,
    });
    files = files.slice(0, 50000);
  }

  const scanFiles = files.filter((f) => SCAN_EXTS.has(path.extname(f.name).toLowerCase()));

  // Each entry keeps file and citation text so the artifact summary is auditable.
  const hits = {
    "fabricated-cve-id": [],
    "rejected-or-disputed-cve": [],
    "rfc-number-title-mismatch": [],
  };
  // Needs-verification buckets: surfaced in artifacts, never flipped to a verdict.
  const needsVerify = {
    cve_not_in_catalog: [],
    rfc_not_in_index: [],
    draft_as_rfc_candidates: [],
  };

  let totalCveCitations = 0;
  let totalRfcCitations = 0;

  for (const f of scanFiles) {
    const content = readSafe(f.full);
    if (content == null) {
      errors.push({ artifact_id: "source-files", kind: "read_failed", reason: f.rel });
      continue;
    }
    const illustrative = isIllustrativePath(f.rel);

    for (const m of content.matchAll(CVE_CITATION_RE)) {
      const full = m[0];
      totalCveCitations++;
      // 1-based, so the evidence location carries a SARIF startLine region.
      const cveLine = lineFromOffset(content, m.index);
      const canonical = CVE_CANONICAL_RE.test(full);
      if (!canonical) {
        if (!illustrative) {
          hits["fabricated-cve-id"].push({ file: f.rel, citation: full, line: cveLine });
        }
        continue;
      }
      if (cveKeys.has(full)) {
        const note = cveNotes.get(full) || "";
        if (recordRejectedOrDisputed(note, full) && !illustrative) {
          hits["rejected-or-disputed-cve"].push({ file: f.rel, citation: full, line: cveLine });
        }
      } else if (catalogsLoaded && !illustrative) {
        // Absent from the curated catalog is inconclusive, not a fabrication.
        needsVerify.cve_not_in_catalog.push({ file: f.rel, citation: full });
      }
    }

    for (const m of content.matchAll(RFC_CITATION_RE)) {
      totalRfcCitations++;
      const num = Number(m[1]);
      if (!Number.isFinite(num)) continue;
      const line = lineAround(content, m.index);
      const rfcLineNo = lineFromOffset(content, m.index);
      if (rfcTitles.has(num)) {
        const lineStart = content.lastIndexOf("\n", m.index) + 1;
        const after = line.slice((m.index - lineStart) + m[0].length);
        const stated = statedTitleAfter(after);
        const verdict = stated ? classifyRfcTitle(stated, rfcTitles.get(num)) : "no-title-claim";
        if (verdict === "mismatch" && !illustrative) {
          hits["rfc-number-title-mismatch"].push({
            file: f.rel,
            citation: `RFC ${num}`,
            real_title: rfcTitles.get(num),
            line: rfcLineNo,
          });
        }
      } else if (catalogsLoaded && !illustrative) {
        // Adjacent draft language makes it a draft-as-RFC candidate, still unflipped.
        needsVerify.rfc_not_in_index.push({ file: f.rel, citation: `RFC ${num}` });
        if (DRAFT_LANGUAGE_RE.test(line)) {
          needsVerify.draft_as_rfc_candidates.push({ file: f.rel, citation: `RFC ${num}` });
        }
      }
    }
  }

  // Only deterministically-decidable indicators flip; the rest stay absent so the
  // runner returns inconclusive for them.
  const signal_overrides = {
    "fabricated-cve-id": hits["fabricated-cve-id"].length > 0 ? "hit" : "miss",
    "rfc-number-title-mismatch": hits["rfc-number-title-mismatch"].length > 0 ? "hit" : "miss",
  };
  // Only assert a verdict when the catalog loaded; without it the check cannot run.
  if (cveKeys.size > 0) {
    signal_overrides["rejected-or-disputed-cve"] =
      hits["rejected-or-disputed-cve"].length > 0 ? "hit" : "miss";
  } else {
    signal_overrides["rejected-or-disputed-cve"] = "inconclusive";
  }
  // Citations the offline catalog cannot confirm are inconclusive, not a miss.
  if (needsVerify.cve_not_in_catalog.length > 0) {
    signal_overrides["cve-citation-needs-external-verification"] = "inconclusive";
  }

  // __fp_checks attest the FP checks this collector ran; without the attestation
  // the runner downgrades a real bad citation to inconclusive.
  if (signal_overrides["fabricated-cve-id"] === "hit") {
    // [0] illustrative paths are excluded before the hit; [1] placeholder forms
    //     never match the numeric citation regex.
    signal_overrides["fabricated-cve-id__fp_checks"] = { "0": true, "1": true };
  }
  if (signal_overrides["rejected-or-disputed-cve"] === "hit") {
    // [1] the catalog note marks THIS identifier; [2] it is in the catalog.
    //     [0] inline dispute acknowledgement in prose is left unattested.
    signal_overrides["rejected-or-disputed-cve__fp_checks"] = { "1": true, "2": true };
  }
  if (signal_overrides["rfc-number-title-mismatch"] === "hit") {
    // [0] a paraphrase / nickname does not fire; [1] numbers absent from the
    //     index do not fire; [2] the stated title comes from the same line.
    signal_overrides["rfc-number-title-mismatch__fp_checks"] = { "0": true, "1": true, "2": true };
  }

  const summarize = (list) => {
    if (list.length === 0) return "0 hits";
    const head = list.slice(0, 5).map((h) => {
      let s = `${h.file}: ${h.citation}`;
      if (h.real_title) s += ` (index title: "${h.real_title}")`;
      return s;
    }).join("; ");
    return `${list.length} hit(s): ${head}` + (list.length > 5 ? "; …" : "");
  };

  const artifacts = {
    "cve-citations-in-source": {
      value: `${totalCveCitations} CVE citation(s) found. ` +
        `fabricated: ${summarize(hits["fabricated-cve-id"])}. ` +
        `rejected/disputed: ${summarize(hits["rejected-or-disputed-cve"])}. ` +
        `needs-external-verification (well-formed, absent from catalog): ${summarize(needsVerify.cve_not_in_catalog)}.`,
      captured: true,
    },
    "rfc-citations-in-source": {
      value: `${totalRfcCitations} RFC citation(s) found. ` +
        `title-mismatch: ${summarize(hits["rfc-number-title-mismatch"])}. ` +
        `not-in-index (needs verification): ${summarize(needsVerify.rfc_not_in_index)}. ` +
        `draft-as-rfc candidates: ${summarize(needsVerify.draft_as_rfc_candidates)}.`,
      captured: true,
    },
    "cve-catalog": {
      value: cveKeys.size > 0
        ? `loaded ${cveKeys.size} catalog entries for cross-reference`
        : "catalog unavailable — CVE cross-reference could not run",
      captured: cveKeys.size > 0,
      ...(cveKeys.size === 0 ? { reason: "cve-catalog.json failed to load" } : {}),
    },
    "rfc-index": {
      value: rfcTitles.size > 0
        ? `loaded ${rfcTitles.size} RFC titles for cross-reference`
        : "RFC index unavailable — RFC cross-reference could not run",
      captured: rfcTitles.size > 0,
      ...(rfcTitles.size === 0 ? { reason: "rfc-references.json failed to load" } : {}),
    },
  };

  // Locations for flipped indicators, so SARIF results point at the source line.
  const evidence_locations = {};
  for (const id of Object.keys(hits)) {
    if (signal_overrides[id] === "hit") {
      const locs = buildEvidenceLocations(hits[id]);
      if (locs.length) evidence_locations[id] = locs;
    }
  }

  return {
    precondition_checks: {
      "repo-cites-security-references": totalCveCitations > 0 || totalRfcCitations > 0,
    },
    artifacts,
    signal_overrides,
    ...(Object.keys(evidence_locations).length ? { evidence_locations } : {}),
    // Consumed by applyResolution (--resolve) to resolve and flip these.
    needs_verification: needsVerify,
    collector_meta: {
      collector_id: COLLECTOR_ID,
      collector_version: "2026-05-26",
      platform: process.platform,
      captured_at: new Date().toISOString(),
      cwd: root,
      duration_ms: Date.now() - startTime,
      files_walked: files.length,
      scan_files_scanned: scanFiles.length,
      cve_citations: totalCveCitations,
      rfc_citations: totalRfcCitations,
      catalogs_loaded: catalogsLoaded,
    },
    collector_errors: errors,
  };
}

/**
 * Resolve the citations collect() left as needs-verification, flipping the parked
 * signals from inconclusive to a real verdict. Each uncatalogued CVE goes through
 * the shared resolver (catalog -> cache -> one NVD lookup, cached), so a fan-out
 * resolves each id once. Returns a shallow copy carrying a resolution summary
 * artifact; `submission` itself is not mutated.
 *
 * @param {object} submission  the object returned by collect()
 * @param {object} [opts]      { airGap?: boolean, _resolveCve?, _resolveRfc? }
 * @returns {Promise<object>}
 */
async function applyResolution(submission, opts = {}) {
  if (!submission || typeof submission !== "object") return submission;
  const nv = submission.needs_verification || {};
  const cveList = Array.isArray(nv.cve_not_in_catalog) ? nv.cve_not_in_catalog : [];
  const rfcList = Array.isArray(nv.rfc_not_in_index) ? nv.rfc_not_in_index : [];
  const resolver = (opts._resolveCve && opts._resolveRfc)
    ? { resolveCve: opts._resolveCve, resolveRfc: opts._resolveRfc }
    : loadResolver();
  const airGap = !!opts.airGap;

  const signals = { ...(submission.signal_overrides || {}) };
  const resolved = { cve: [], rfc: [] };
  let cveUnknown = 0;
  let rejectedHit = false;
  let fabricatedHit = false;

  for (const item of cveList) {
    const id = String(item.citation || "").trim();
    const r = await resolver.resolveCve(id, { airGap });
    resolved.cve.push({ citation: id, file: item.file, status: r.status, from: r.from, product: r.product || null });
    if (r.status === "rejected" || r.status === "disputed") rejectedHit = true;
    else if (r.status === "nonexistent" || r.status === "fabricated") fabricatedHit = true;
    else if (r.status === "unknown") cveUnknown++;
    // published -> resolved-clean (no flip)
  }
  if (rejectedHit) signals["rejected-or-disputed-cve"] = "hit";
  if (fabricatedHit) signals["fabricated-cve-id"] = "hit";
  // A miss once every parked CVE is classified; inconclusive while any stay unknown.
  if (cveList.length > 0) {
    signals["cve-citation-needs-external-verification"] = cveUnknown > 0 ? "inconclusive" : "miss";
  }

  let rfcNonexistentHit = false;
  for (const item of rfcList) {
    const cite = String(item.citation || "");
    const num = (cite.match(/(\d+)/) || [])[1];
    const r = await resolver.resolveRfc(num || cite, { airGap });
    resolved.rfc.push({ citation: cite, file: item.file, status: r.status, found: r.found, from: r.from, title: r.title || null });
    // A number resolving to nothing is a bad citation; an obsoleted RFC still resolves.
    if (r.status === "nonexistent") rfcNonexistentHit = true;
  }
  if (rfcNonexistentHit) signals["rfc-number-title-mismatch"] = "hit";

  const out = { ...submission, signal_overrides: signals };
  out.artifacts = { ...(submission.artifacts || {}) };
  const fmt = (arr) => arr.length === 0 ? "0" : arr.map(x => `${x.citation}=${x.status}`).join(", ");
  out.artifacts["citation-resolution"] = {
    value: `Resolved ${resolved.cve.length} uncatalogued CVE citation(s): ${fmt(resolved.cve)}. ` +
      `Resolved ${resolved.rfc.length} not-in-index RFC citation(s): ${fmt(resolved.rfc)}.` +
      (airGap ? " (air-gap: network resolution skipped — catalog/cache only.)" : ""),
    captured: true,
  };
  out.resolution = resolved;
  return out;
}

module.exports = { playbook_id: COLLECTOR_ID, collect, applyResolution, recordRejectedOrDisputed };
