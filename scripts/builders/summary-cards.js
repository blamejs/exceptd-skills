"use strict";
/**
 * Builds `data/_indexes/summary-cards.json`: a compact per-skill abstract that
 * downstream AI consumers — researcher dispatch in particular — render without
 * loading the full skill body.
 */

const fs = require("fs");
const path = require("path");

// Walk a body and yield real H2 lines (outside fenced code blocks).
function findRealH2Indices(lines) {
  const out = [];
  let inFence = false;
  for (let i = 0; i < lines.length; i++) {
    if (/^```/.test(lines[i])) {
      inFence = !inFence;
      continue;
    }
    if (!inFence && /^## /.test(lines[i])) out.push(i);
  }
  return out;
}

function locateHeader(lines, headerRegex) {
  const h2 = findRealH2Indices(lines);
  for (const idx of h2) {
    if (headerRegex.test(lines[idx])) return idx;
  }
  return -1;
}

function firstParagraphAfterHeader(body, headerRegex) {
  // The first prose paragraph beneath the matching H2, skipping the H3/H4,
  // bold-prefix metadata, rules and table separators that often lead a section.
  const lines = body.split(/\r?\n/);
  const hdrIdx = locateHeader(lines, headerRegex);
  if (hdrIdx < 0) return null;
  const allH2 = findRealH2Indices(lines);
  const nextH2 = allH2.find((i) => i > hdrIdx);
  const sectionEnd = nextH2 != null ? nextH2 : lines.length;

  let i = hdrIdx + 1;
  const isSkippableLeading = (line) => {
    const t = line.trim();
    if (t === "") return true;
    if (t === "---") return true;
    if (/^#{1,6}\s/.test(t)) return true;
    if (/^\|/.test(t)) return true;
    if (/^\*\*[^*]+:\*\*/.test(t)) return true;
    if (/^[-=]{3,}$/.test(t)) return true;
    return false;
  };
  for (; i < sectionEnd; i++) {
    if (!isSkippableLeading(lines[i])) break;
  }
  if (i >= sectionEnd) return null;

  const para = [];
  for (; i < sectionEnd; i++) {
    if (lines[i].trim() === "" && para.length) break;
    para.push(lines[i]);
  }
  const joined = para.join(" ").replace(/\s+/g, " ").trim();
  if (!joined) return null;
  if (joined.length <= 600) return joined;
  const cut = joined.slice(0, 600);
  const lastSpace = cut.lastIndexOf(" ");
  return (lastSpace > 400 ? cut.slice(0, lastSpace) : cut) + " ...";
}

function firstChunkAfterHeader(body, headerRegex, maxChars = 600) {
  const lines = body.split(/\r?\n/);
  const hdrIdx = locateHeader(lines, headerRegex);
  if (hdrIdx < 0) return null;
  const allH2 = findRealH2Indices(lines);
  const nextH2 = allH2.find((i) => i > hdrIdx);
  const sectionEnd = nextH2 != null ? nextH2 : lines.length;

  let i = hdrIdx + 1;
  while (i < sectionEnd && lines[i].trim() === "") i++;
  const chunk = lines.slice(i, sectionEnd);
  const joined = chunk.join("\n").trim();
  if (!joined) return null;
  if (joined.length <= maxChars) return joined;
  return joined.slice(0, maxChars) + " ...";
}

function handoffTargets(body, allSkillNames, selfName) {
  // Only the Hand-Off section counts, and a backtick-quoted skill name is a
  // target. The scan is bounded to [header, next real H2) so a later section is
  // not mis-attributed, and both bounds are fence-aware.
  const lines = body.split(/\r?\n/);
  const h2 = findRealH2Indices(lines);
  const handoffIdx = h2.find((i) => /^## Hand-?Off/.test(lines[i]));
  if (handoffIdx == null) return [];
  const nextH2 = h2.find((i) => i > handoffIdx);
  const sectionEnd = nextH2 != null ? nextH2 : lines.length;
  const slice = lines.slice(handoffIdx, sectionEnd).join("\n");
  const targets = new Set();
  for (const name of allSkillNames) {
    if (name === selfName) continue;
    if (slice.includes("`" + name + "`")) targets.add(name);
  }
  return [...targets].sort();
}

function buildSummaryCards({ root, manifest, skills }) {
  const cards = {};
  const allNames = new Set(skills.map((s) => s.name));

  for (const s of skills) {
    const body = fs.readFileSync(path.join(root, s.path), "utf8");

    const threatCtx = firstParagraphAfterHeader(body, /^## Threat Context/);
    const produces = firstChunkAfterHeader(body, /^## Output Format/, 600);

    cards[s.name] = {
      description: s.description || null,
      threat_context_excerpt: threatCtx,
      produces: produces,
      key_xrefs: {
        cwe_refs: s.cwe_refs || [],
        d3fend_refs: s.d3fend_refs || [],
        framework_gaps: s.framework_gaps || [],
        atlas_refs: s.atlas_refs || [],
        attack_refs: s.attack_refs || [],
        rfc_refs: s.rfc_refs || [],
        dlp_refs: s.dlp_refs || [],
      },
      trigger_count: (s.triggers || []).length,
      atlas_count: (s.atlas_refs || []).length,
      attack_count: (s.attack_refs || []).length,
      framework_gap_count: (s.framework_gaps || []).length,
      cwe_count: (s.cwe_refs || []).length,
      d3fend_count: (s.d3fend_refs || []).length,
      rfc_count: (s.rfc_refs || []).length,
      last_threat_review: s.last_threat_review || null,
      path: s.path,
      handoff_targets: handoffTargets(body, allNames, s.name),
    };
  }

  return {
    _meta: {
      schema_version: "1.0.0",
      note: "Compact per-skill abstract for researcher dispatch and AI consumer planning. See scripts/builders/summary-cards.js.",
    },
    skills: cards,
  };
}

module.exports = { buildSummaryCards };
