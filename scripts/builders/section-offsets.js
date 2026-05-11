"use strict";
/**
 * scripts/builders/section-offsets.js
 *
 * Builds `data/_indexes/section-offsets.json` — for each skill, the byte
 * + line offsets of every H2 section header in the body. AI consumers can
 * slice a single section (e.g. "Compliance Theater Check") from disk
 * without parsing the full skill file.
 *
 * Per-skill shape:
 *   {
 *     path:           "skills/<name>/skill.md",
 *     total_bytes:    n,
 *     total_lines:    n,
 *     frontmatter:    { byte_start, byte_end, line_start, line_end },
 *     sections: [
 *       {
 *         name:            raw H2 text (e.g. "Threat Context (mid-2026)")
 *         normalized_name: collapsed for lookup ("threat-context")
 *         line:            1-based line number of the "## …" header
 *         byte_start:      byte offset of the "## " character
 *         byte_end:        byte offset where the next H2 begins (or EOF)
 *         bytes:           byte_end - byte_start
 *         h3_count:        number of "### " headers contained
 *       },
 *       ...
 *     ]
 *   }
 *
 * The normalized_name strips parenthetical qualifiers and common phrasings
 * so consumers can request a canonical section name without caring about
 * formatting drift.
 */

const fs = require("fs");
const path = require("path");

// Recognized canonical section anchors. Multiple raw H2 phrasings map to one
// normalized name — see grep survey of skills/* for the variant phrasings.
const NORMALIZERS = [
  [/threat\s*context/i,                     "threat-context"],
  [/framework\s*lag\s*declaration/i,        "framework-lag-declaration"],
  [/ttp\s*mapping/i,                        "ttp-mapping"],
  [/exploit\s*availability\s*matrix/i,      "exploit-availability-matrix"],
  [/compliance\s*theater\s*check/i,         "compliance-theater-check"],
  [/analysis\s*procedure/i,                 "analysis-procedure"],
  [/defensive\s*countermeasure\s*mapping/i, "defensive-countermeasure-mapping"],
  [/output\s*format/i,                      "output-format"],
  [/hand-?off/i,                            "hand-off"],
  [/detection\s*rules?/i,                   "detection-rules"],
  [/exposure\s*assessment/i,                "exposure-assessment"],
];

function normalize(headerText) {
  const stripped = headerText.replace(/^##\s+/, "").trim();
  for (const [re, canonical] of NORMALIZERS) {
    if (re.test(stripped)) return canonical;
  }
  // Fall back: slug.
  return stripped
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-|-$/g, "");
}

function buildOne(absPath, relPath) {
  const buf = fs.readFileSync(absPath);
  const totalBytes = buf.length;
  const text = buf.toString("utf8");
  const lines = text.split(/\r?\n/);
  const lineByteOffsets = [];
  let cursor = 0;
  for (const line of lines) {
    lineByteOffsets.push(cursor);
    // +1 for the newline. Counts as one byte for LF; CRLF would skew slightly
    // but the file is written via the project's tooling which is LF-uniform.
    cursor += Buffer.byteLength(line, "utf8") + 1;
  }

  // Frontmatter: lines between the first "---" and the second "---".
  let fmLineStart = -1, fmLineEnd = -1;
  for (let i = 0; i < lines.length; i++) {
    if (lines[i].trim() === "---") {
      if (fmLineStart === -1) fmLineStart = i;
      else if (fmLineEnd === -1) {
        fmLineEnd = i;
        break;
      }
    }
  }
  const frontmatter = fmLineStart >= 0 && fmLineEnd > fmLineStart
    ? {
        line_start: fmLineStart + 1,
        line_end: fmLineEnd + 1,
        byte_start: lineByteOffsets[fmLineStart],
        byte_end: lineByteOffsets[Math.min(fmLineEnd + 1, lineByteOffsets.length - 1)] || totalBytes,
      }
    : null;

  // H2 headers — only those outside fenced code blocks. Skill bodies often
  // contain "## Foo" lines inside ```...``` blocks as output templates; those
  // are not real sections.
  const h2 = [];
  let inFence = false;
  for (let i = 0; i < lines.length; i++) {
    if (/^```/.test(lines[i])) {
      inFence = !inFence;
      continue;
    }
    if (!inFence && /^## /.test(lines[i])) {
      h2.push({ line: i + 1, idx: i, raw: lines[i].trim() });
    }
  }

  const sections = [];
  for (let j = 0; j < h2.length; j++) {
    const cur = h2[j];
    const next = h2[j + 1];
    const startByte = lineByteOffsets[cur.idx];
    const endByte = next ? lineByteOffsets[next.idx] : totalBytes;
    // Count H3 within this section.
    const endIdx = next ? next.idx : lines.length;
    let h3Count = 0;
    for (let k = cur.idx + 1; k < endIdx; k++) {
      if (/^### /.test(lines[k])) h3Count++;
    }
    sections.push({
      name: cur.raw.replace(/^##\s+/, ""),
      normalized_name: normalize(cur.raw),
      line: cur.line,
      byte_start: startByte,
      byte_end: endByte,
      bytes: endByte - startByte,
      h3_count: h3Count,
    });
  }

  return {
    path: relPath,
    total_bytes: totalBytes,
    total_lines: lines.length,
    frontmatter,
    sections,
  };
}

function buildSectionOffsets({ root, skills }) {
  const out = {};
  for (const s of skills) {
    out[s.name] = buildOne(path.join(root, s.path), s.path);
  }
  return {
    _meta: {
      schema_version: "1.0.0",
      note: "Per-skill byte/line offsets of every H2 section. Use byte_start/byte_end to slice a specific section. normalized_name collapses phrasing variants (e.g. 'Threat Context (mid-2026)' → 'threat-context').",
      canonical_section_names: NORMALIZERS.map(([, name]) => name),
    },
    skills: out,
  };
}

module.exports = { buildSectionOffsets };
