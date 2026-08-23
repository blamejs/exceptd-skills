"use strict";
/**
 * Builds `data/_indexes/section-offsets.json`: per skill, the byte and line
 * offsets of every H2 section in the body, so a consumer can slice one section
 * off disk without parsing the whole file. normalized_name collapses
 * parenthetical qualifiers and phrasing variants onto a canonical name.
 */

const fs = require("fs");
const path = require("path");

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
  // Line-start byte offsets are measured off the real terminator bytes: a CRLF
  // terminator is 2 bytes, and assuming a fixed 1-byte newline misaligns every
  // offset in a CRLF body. The split above discards the terminators, so their
  // width can only be recovered from the raw text.
  const lineByteOffsets = [0];
  const eolRe = /\r?\n/g;
  let m;
  while ((m = eolRe.exec(text)) !== null) {
    lineByteOffsets.push(Buffer.byteLength(text.slice(0, m.index + m[0].length), "utf8"));
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

  // H2 headers outside fenced code blocks only — skill bodies carry "## Foo"
  // lines inside ```...``` blocks as output templates, which are not sections.
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
    // Fence-aware like the H2 loop: a section starts and ends on an H2, both
    // outside any fence, so fence state always begins false here.
    const endIdx = next ? next.idx : lines.length;
    let h3Count = 0;
    let h3InFence = false;
    for (let k = cur.idx + 1; k < endIdx; k++) {
      if (/^```/.test(lines[k])) {
        h3InFence = !h3InFence;
        continue;
      }
      if (!h3InFence && /^### /.test(lines[k])) h3Count++;
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

// buildOne is exported for the CRLF byte-offset regression test.
module.exports = { buildSectionOffsets, buildOne };
