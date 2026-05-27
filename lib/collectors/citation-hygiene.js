"use strict";

/**
 * lib/collectors/citation-hygiene.js
 *
 * Companion collector for the `citation-hygiene` playbook. Walks the cwd
 * tree (source, comments, docstrings, and security documentation) and
 * extracts every CVE and RFC citation, then cross-references each against
 * the shipped CVE catalog (data/cve-catalog.json) and RFC index
 * (data/rfc-references.json).
 *
 * It flips signal_overrides only for verdicts determinable offline from
 * the catalogs:
 *   - fabricated-cve-id: a citation whose tail is not the canonical
 *     all-numeric CVE form (CVE-2024-XXXX, CVE-2024-zlib). Deterministic.
 *   - rejected-or-disputed-cve: a well-formed citation that resolves to a
 *     catalog entry whose analyst notes mark it rejected / disputed.
 *   - rfc-number-title-mismatch: a citation pairing a number with a title
 *     that conflicts with the index title for that number.
 *
 * Indicators that need an out-of-band lookup or human judgement
 * (cve-citation-needs-external-verification, draft-mislabeled-as-rfc) are
 * surfaced in the artifacts text and left UNFLIPPED so the runner returns
 * inconclusive rather than a forced miss — the catalog is curated, not
 * exhaustive, so absence is never a clean clear or a false fabrication.
 *
 * Interface: see lib/collectors/README.md
 */

const fs = require("node:fs");
const path = require("node:path");

const { codeExcludeSet, isLinkedWorktreeDir, buildEvidenceLocations, lineFromOffset } = require("./scan-excludes");

const COLLECTOR_ID = "citation-hygiene";

// Opt-in resolver (`exceptd collect citation-hygiene --resolve`). Lets the
// collector resolve the citations the offline catalog can't confirm — once,
// through the shared cache — instead of parking them as inconclusive for an
// agent to research. Required lazily so a plain collect() never loads it.
function loadResolver() {
  return require("../citation-resolve.js");
}

const DEFAULT_MAX_DEPTH = 8;
const EXCLUDES = codeExcludeSet();

// File extensions whose contents are worth scanning for citations: source,
// markup/docs, config that carries security prose. Citations live in
// comments and docstrings (source) and in docs (md / rst / txt / adoc).
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

// Paths whose citations are illustrative (templates / fixtures / the
// scanner's own pattern catalogue), not real self-citations.
const ILLUSTRATIVE_PATH_SEGMENTS = [
  "/test/", "/tests/", "/spec/", "/specs/", "/__tests__/",
  "/fixtures/", "/fixture/",
  "/.github/issue_template/", "/.github/pull_request_template/",
  "/issue_template/", "/pull_request_template/",
  // The collectors and the playbooks directory literally contain CVE /
  // RFC patterns and example citations; scanning them would flag the
  // scanner itself. The playbook's intent is the consumer's source.
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

function walkTree(root, opts = {}) {
  const maxDepth = opts.maxDepth ?? DEFAULT_MAX_DEPTH;
  const excludes = opts.excludes ?? EXCLUDES;
  const out = [];
  const seen = new Set();

  function walk(dir, depth) {
    if (depth > maxDepth) return;
    let entries;
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); }
    catch { return; }
    for (const entry of entries) {
      if (excludes.has(entry.name)) continue;
      const full = path.join(dir, entry.name);
      let real;
      try { real = fs.realpathSync(full); } catch { continue; }
      if (seen.has(real)) continue;
      seen.add(real);
      if (entry.isDirectory()) {
        // Skip detached git worktrees (agent scratch copies) — descending
        // into them rescans unrelated repo state.
        if (isLinkedWorktreeDir(full)) continue;
        walk(full, depth + 1);
      } else if (entry.isFile()) {
        out.push({ full, rel: path.relative(root, full), name: entry.name });
      }
    }
  }
  walk(root, 0);
  return out;
}

function readSafe(full) {
  try {
    const s = fs.statSync(full);
    if (s.size > MAX_FILE_BYTES) return null;
    return fs.readFileSync(full, "utf8");
  } catch { return null; }
}

// Permissive CVE matcher: 4-digit year, then a tail of digits OR letters
// (so malformed citations like CVE-2024-XXXX / CVE-2024-zlib are captured,
// not silently skipped). The canonical-form test is applied afterwards.
const CVE_CITATION_RE = /CVE-(\d{4})-([0-9A-Za-z]+)/g;
const CVE_CANONICAL_RE = /^CVE-\d{4}-\d{4,}$/;

// RFC citation: `RFC 9404`, `RFC9404`, `RFC-9404`. Capture the number.
const RFC_CITATION_RE = /RFC[\s-]?(\d{1,5})\b/gi;

// Words that mark a catalog note as recording a rejected / disputed status.
const REJECT_DISPUTE_RE = /\b(reject(?:ed|s|ion)?|disputed?|withdrawn)\b/i;

// Draft-language proximity for the (unflipped) draft-as-RFC heuristic.
const DRAFT_LANGUAGE_RE = /\b(draft-[a-z0-9-]+|internet[- ]draft|work[- ]in[- ]progress|i-d\b)\b/i;

/**
 * Load the shipped CVE catalog and RFC index. The catalogs ship in the
 * package tarball under data/; resolve relative to this module so the
 * collector works whether run from the source tree or a node_modules
 * install. Returns { cveKeys:Set, cveNotes:Map<id,string>, rfcTitles:Map<number,string>, errors:[] }.
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
        // Concatenate the analyst-note fields that carry rejected /
        // disputed status. Matching the cited key's OWN notes (not a
        // neighbour's) is enforced by per-entry concatenation.
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

// Normalise a title for comparison: lowercase, drop punctuation, collapse
// whitespace, and strip a leading "the".
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

// Ordered list of meaningful (post-stopword, non-numeric) tokens in a
// title — used both for overlap and for acronym construction.
function orderedTitleTokens(s) {
  return normalizeTitle(s)
    .split(" ")
    .filter((t) => t.length >= 3 && !/^\d+$/.test(t) && !TITLE_STOPWORDS.has(t));
}

// Build the lowercase acronym from the title's meaningful words
// (Transport Layer Security Protocol -> "tls", since protocol/version are
// stopwords). Lets a nickname / abbreviation in the adjacent text be
// recognised as the same document, not a wrong title.
function titleAcronym(realTitle) {
  return orderedTitleTokens(realTitle).map((w) => w[0]).join("");
}

/**
 * Decide whether an adjacent text fragment makes a TITLE CLAIM that
 * conflicts with the real index title. Conservative by design — the cost
 * of a false positive (telling an author their correct citation is wrong)
 * is high, so the bar to flag a mismatch is deliberately strict:
 *   - the cited RFC number must be in the index (checked by the caller),
 *   - the adjacent text must carry at least THREE meaningful tokens — a
 *     bare nickname / abbreviation ("TLS 1.3", "(HTTP)") reduces below
 *     this and is treated as no-title-claim, never a mismatch,
 *   - if the adjacent tokens contain the title's acronym, it is the same
 *     document (TLS for Transport Layer Security); not a mismatch,
 *   - only ZERO overlap between the meaningful adjacent tokens and the
 *     real-title tokens flags a mismatch. Any shared content word means
 *     the author is describing the right document (paraphrase) — demote.
 * Returns "mismatch" | "match" | "no-title-claim".
 */
function classifyRfcTitle(adjacentText, realTitle) {
  const adjTokens = titleTokens(adjacentText);
  // Require a substantive title claim. Fewer than three content tokens is
  // a nickname / abbreviation, not a stated title — stay conservative.
  if (adjTokens.size < 3) return "no-title-claim";
  const realTokens = titleTokens(realTitle);
  if (realTokens.size === 0) return "no-title-claim";
  // Acronym recognition: "tls" in the adjacent text matches "Transport
  // Layer Security". Same document, not a wrong title.
  const acronym = titleAcronym(realTitle);
  if (acronym.length >= 2 && adjTokens.has(acronym)) return "match";
  let overlap = 0;
  for (const t of adjTokens) {
    if (realTokens.has(t)) overlap++;
  }
  // Any shared content word -> the author is describing the right
  // document. Only a stated title with ZERO overlap is a conflicting
  // claim. This trades recall for precision intentionally.
  return overlap === 0 ? "mismatch" : "match";
}

// Pull the text on the same line as the match, used as the "adjacent text"
// for the RFC title comparison.
function lineAround(content, index) {
  const start = content.lastIndexOf("\n", index) + 1;
  let end = content.indexOf("\n", index);
  if (end === -1) end = content.length;
  return content.slice(start, end);
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
    files = walkTree(root);
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

  // Hit collectors. Each entry keeps the file + the citation text so the
  // artifact summary is auditable. CVE / RFC literals are references, not
  // secrets, so they are safe to retain in the value text.
  const hits = {
    "fabricated-cve-id": [],
    "rejected-or-disputed-cve": [],
    "rfc-number-title-mismatch": [],
  };
  // Inconclusive / needs-verification buckets — surfaced in artifacts,
  // never flipped to a deterministic verdict.
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

    // ---- CVE citations ----
    for (const m of content.matchAll(CVE_CITATION_RE)) {
      const full = m[0];
      totalCveCitations++;
      // 1-based line of the citation so the evidence location carries a SARIF
      // startLine region. Does not change any hit/miss verdict.
      const cveLine = lineFromOffset(content, m.index);
      const canonical = CVE_CANONICAL_RE.test(full);
      if (!canonical) {
        // Fabricated / malformed. Illustrative surfaces (templates,
        // fixtures, the format-explaining docs) are demoted.
        if (!illustrative) {
          hits["fabricated-cve-id"].push({ file: f.rel, citation: full, line: cveLine });
        }
        continue;
      }
      // Well-formed. Cross-reference the catalog.
      if (cveKeys.has(full)) {
        const note = cveNotes.get(full) || "";
        if (REJECT_DISPUTE_RE.test(note) && !illustrative) {
          hits["rejected-or-disputed-cve"].push({ file: f.rel, citation: full, line: cveLine });
        }
      } else if (catalogsLoaded && !illustrative) {
        // Absent from the curated catalog: needs an external lookup.
        // NOT a fabrication — inconclusive by design.
        needsVerify.cve_not_in_catalog.push({ file: f.rel, citation: full });
      }
    }

    // ---- RFC citations ----
    for (const m of content.matchAll(RFC_CITATION_RE)) {
      totalRfcCitations++;
      const num = Number(m[1]);
      if (!Number.isFinite(num)) continue;
      const line = lineAround(content, m.index);
      const rfcLineNo = lineFromOffset(content, m.index);
      if (rfcTitles.has(num)) {
        const verdict = classifyRfcTitle(line, rfcTitles.get(num));
        if (verdict === "mismatch" && !illustrative) {
          hits["rfc-number-title-mismatch"].push({
            file: f.rel,
            citation: `RFC ${num}`,
            real_title: rfcTitles.get(num),
            line: rfcLineNo,
          });
        }
      } else if (catalogsLoaded && !illustrative) {
        // Number not in the published index. Needs verification; if draft
        // language is adjacent, record it as a draft-as-RFC candidate
        // (still inconclusive — left unflipped).
        needsVerify.rfc_not_in_index.push({ file: f.rel, citation: `RFC ${num}` });
        if (DRAFT_LANGUAGE_RE.test(line)) {
          needsVerify.draft_as_rfc_candidates.push({ file: f.rel, citation: `RFC ${num}` });
        }
      }
    }
  }

  // signal_overrides: only the deterministically-decidable indicators are
  // flipped. The needs-verification indicators stay absent so the runner
  // returns inconclusive for them.
  const signal_overrides = {
    "fabricated-cve-id": hits["fabricated-cve-id"].length > 0 ? "hit" : "miss",
    "rfc-number-title-mismatch": hits["rfc-number-title-mismatch"].length > 0 ? "hit" : "miss",
  };
  // rejected-or-disputed-cve is high-confidence (not deterministic) — flip
  // on a catalog-backed match, otherwise miss. Only assert a verdict when
  // the catalog actually loaded; without it the check could not run.
  if (cveKeys.size > 0) {
    signal_overrides["rejected-or-disputed-cve"] =
      hits["rejected-or-disputed-cve"].length > 0 ? "hit" : "miss";
  } else {
    signal_overrides["rejected-or-disputed-cve"] = "inconclusive";
  }
  // The needs-verification CVE indicator: hit means "found citations the
  // offline catalog cannot confirm" — itself an inconclusive state, so it
  // maps to inconclusive (not a clean miss) when such citations exist.
  if (needsVerify.cve_not_in_catalog.length > 0) {
    signal_overrides["cve-citation-needs-external-verification"] = "inconclusive";
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

  // Per-indicator file locations for the indicators flipped to "hit",
  // so SARIF results point at the source file that carries the bad
  // citation. The hits record a 1-based `line` (from the match offset),
  // so locations include a startLine region.
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
    // The citations the offline catalog could not confirm. `applyResolution`
    // (opt-in --resolve) consumes this to resolve + flip them; on a plain
    // collect it documents what still needs verification.
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
 * Resolve the citations a plain collect() left as needs-verification, flipping
 * the parked signals from inconclusive to a real verdict. Opt-in: only invoked
 * for `exceptd collect citation-hygiene --resolve`. Each uncatalogued CVE goes
 * through the shared resolver (catalog -> cache -> one NVD lookup, cached), so a
 * fan-out resolves each id once. Honors air-gap (resolver returns unknown).
 *
 * Mutates a shallow copy of the submission's signal_overrides and records a
 * resolution summary artifact. Returns the updated submission.
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
  // The needs-verification signal: a clean miss once every parked CVE was
  // classified, inconclusive while any remain unresolvable (NVD unreachable /
  // air-gap), and absent when there was nothing to verify.
  if (cveList.length > 0) {
    signals["cve-citation-needs-external-verification"] = cveUnknown > 0 ? "inconclusive" : "miss";
  }

  let rfcNonexistentHit = false;
  for (const item of rfcList) {
    const cite = String(item.citation || "");
    const num = (cite.match(/(\d+)/) || [])[1];
    const r = await resolver.resolveRfc(num || cite, { airGap });
    resolved.rfc.push({ citation: cite, file: item.file, status: r.status, found: r.found, from: r.from, title: r.title || null });
    // A cited RFC number that resolves to nothing is a bad citation, same class
    // as a fabricated CVE — surface it instead of discarding the verdict. (An
    // obsoleted/historic RFC that resolves IS a real RFC, so it isn't flagged.)
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

module.exports = { playbook_id: COLLECTOR_ID, collect, applyResolution };
