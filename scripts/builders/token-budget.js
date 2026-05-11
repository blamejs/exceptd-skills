"use strict";
/**
 * scripts/builders/token-budget.js
 *
 * Builds `data/_indexes/token-budget.json` — per-skill approximate token
 * counts using a character-density heuristic. Zero-dep (no tiktoken). The
 * approximation is documented as such so consumers know to recompute with
 * their own tokenizer if precision matters.
 *
 * Heuristic: 1 token ≈ 4 characters for English prose mixed with technical
 * tokens (matches the well-known OpenAI rule-of-thumb). This is an upper
 * bound for Claude (Anthropic's tokenizer is more efficient on common
 * prose) but is good enough for context-budget planning where consumers
 * just need to know "is this load 5K or 50K tokens".
 *
 * Per-skill shape:
 *   {
 *     path:                 skill file path
 *     bytes:                total file bytes
 *     chars:                total character count
 *     lines:                line count
 *     approx_tokens:        chars / 4 (integer)
 *     approx_chars_per_token: 4
 *     sections: {
 *       <normalized_section_name>: { bytes, approx_tokens }
 *     }
 *   }
 *
 * Plus a totals block:
 *   {
 *     total_chars, total_approx_tokens,
 *     by_recipe: { … } — placeholder consumers can use to estimate bundles
 *   }
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
