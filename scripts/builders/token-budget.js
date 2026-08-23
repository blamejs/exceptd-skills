"use strict";
/**
 * Builds `data/_indexes/token-budget.json`: per-skill token counts from a
 * 1-token ≈ 4-characters density heuristic, with no tokenizer dependency. The
 * result is an upper bound for context-budget planning, never a precise count —
 * the caveat travels with the data in `_meta.tokenizer_note`.
 */

const fs = require("fs");
const path = require("path");

function approxTokens(chars) {
  return Math.round(chars / 4);
}

function buildTokenBudget({ root, skills, sectionOffsets }) {
  const skillBudgets = {};
  let totalChars = 0;
  let totalApprox = 0;

  for (const s of skills) {
    const abs = path.join(root, s.path);
    const buf = fs.readFileSync(abs);
    const text = buf.toString("utf8");
    const chars = text.length;
    const tokens = approxTokens(chars);
    totalChars += chars;
    totalApprox += tokens;

    const sectionMap = {};
    const sectionEntry = sectionOffsets.skills?.[s.name];
    if (sectionEntry && Array.isArray(sectionEntry.sections)) {
      for (const sec of sectionEntry.sections) {
        const sliceText = buf
          .slice(sec.byte_start, sec.byte_end)
          .toString("utf8");
        sectionMap[sec.normalized_name] = {
          bytes: sec.bytes,
          chars: sliceText.length,
          approx_tokens: approxTokens(sliceText.length),
        };
      }
    }

    skillBudgets[s.name] = {
      path: s.path,
      bytes: buf.length,
      chars,
      lines: text.split(/\r?\n/).length,
      approx_tokens: tokens,
      approx_chars_per_token: 4,
      sections: sectionMap,
    };
  }

  return {
    _meta: {
      schema_version: "1.0.0",
      tokenizer_note: "Character-density approximation: 1 token ≈ 4 chars. This is the canonical rule-of-thumb for OpenAI tokenizers on English+technical text. Claude's tokenizer is typically more efficient on prose; treat this as an upper-bound budget for both. Consumers with stricter precision needs should re-tokenize with their own tokenizer.",
      approx_chars_per_token: 4,
      total_chars: totalChars,
      total_approx_tokens: totalApprox,
      skill_count: skills.length,
    },
    skills: skillBudgets,
  };
}

module.exports = { buildTokenBudget };
