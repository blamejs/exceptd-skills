"use strict";
/**
 * scripts/builders/theater-fingerprints.js
 *
 * Builds `data/_indexes/theater-fingerprints.json` — for each Compliance
 * Theater pattern in the `compliance-theater` skill, a structured record:
 *   - the claim (what auditors hear)
 *   - the audit evidence (what passes the audit)
 *   - the reality (why it's theater)
 *   - the detection test (operational steps)
 *   - the controls it spans (NIST 800-53 / ISO 27001 / PCI / SOC 2)
 *   - the evidence CVE / campaign tying the pattern to the real world
 *
 * Extracted from `skills/compliance-theater/skill.md`. The compliance-theater
 * skill is the source-of-truth — this index just structures the pattern
 * library so downstream consumers (audit defense, framework-gap-analysis)
 * can join on control IDs without re-parsing the markdown.
 */

const fs = require("fs");
const path = require("path");

// Stable mapping of each Pattern → the controls it spans. Manually curated
// from the skill's Framework Lag Declaration table — keep this in lockstep
// with skills/compliance-theater/skill.md.
const PATTERN_CONTROL_MAP = {
  1: {
    pattern_name: "Patch Management Theater",
    primary_attack_class: "patch-cycle vs. KEV-listed instant-root exploits",
    controls: [
      { framework: "NIST 800-53", control_id: "SI-2", note: "30-day critical patch SLA designed for slow-weaponization era" },
      { framework: "ISO 27001:2022", control_id: "A.8.8", note: "'Appropriate timescales' undefined; commonly read as 30 days for High" },
      { framework: "PCI DSS 4.0", control_id: "6.3.3", note: "One-month critical-patch window" },
      { framework: "NIS2", control_id: "Art. 21", note: "No specific patching SLA" },
      { framework: "CIS Controls v8", control_id: "Control 7", note: "Continuous vulnerability management; 'within one month' still too long" },
    ],
    evidence: { cve: "CVE-2026-31431", rationale: "Copy Fail: deterministic 732-byte root, CISA KEV, AI-discovered, public PoC" },
    ttps: ["T1068", "T1203"],
    fast_test: "Pull last 12 months of patch records. Any CISA KEV patched > 72 hours after KEV listing = THEATER FLAG.",
  },
  2: {
    pattern_name: "Network Segmentation Theater (IPsec)",
    primary_attack_class: "IPsec subsystem as both control and attack surface",
    controls: [
      { framework: "NIST 800-53", control_id: "SC-8", note: "Transmission confidentiality — IPsec common compensating control" },
      { framework: "NIST 800-53", control_id: "SC-7", note: "Boundary protection — IPsec tunnel as zone separator" },
      { framework: "PCI DSS 4.0", control_id: "Req 1", note: "Network segmentation between trust zones" },
    ],
    evidence: { cve: "CVE-2026-43284", rationale: "Dirty Frag: kernel IPsec subsystem LPE — the control's cryptographic mechanism is the attack surface" },
    ttps: ["T1190"],
    fast_test: "Identify hosts using IPsec for segmentation compliance. If kernel patch for CVE-2026-43284 not applied = THEATER FLAG.",
  },
  3: {
    pattern_name: "Access Control Theater (AI Agent)",
    primary_attack_class: "prompt injection bypasses access control via authorized service account",
    controls: [
      { framework: "SOC 2", control_id: "CC6", note: "Logical access — designed for human-controlled accounts" },
      { framework: "NIST 800-53", control_id: "AC-2", note: "Account management — no concept of AI agent authority delegation" },
      { framework: "NIST 800-53", control_id: "AC-3", note: "Access enforcement — model judgment is the gate, not a recognized control" },
      { framework: "ISO 27001:2022", control_id: "A.5.15", note: "Access control policy" },
    ],
    evidence: { cve: "CVE-2025-53773", rationale: "Copilot prompt-injection RCE: AI service account executes attacker-chosen actions; no identity boundary crossed" },
    ttps: ["AML.T0051", "AML.T0054", "T1059"],
    fast_test: "If AI agents have prod access and (a) prompt content + tool calls aren't logged or (b) no behavioral baseline = THEATER FLAG.",
  },
  4: {
    pattern_name: "Incident Response Theater (AI Pipeline)",
    primary_attack_class: "IR program with no detection input or procedure for AI-class incidents",
    controls: [
      { framework: "SOC 2", control_id: "CC7", note: "System operations / anomaly detection — no baseline for AI-API traffic" },
      { framework: "NIST 800-53", control_id: "IR-4", note: "Incident handling — phases defined but not AI-class triggers" },
      { framework: "ISO 27001:2022", control_id: "A.5.24-A.5.28", note: "IR planning/preparation/reporting/response/learning" },
    ],
    evidence: { campaign: "SesameOp", rationale: "AML.T0096 LLM Integration Abuse as C2 — no detection triggers exist, so IR procedures have no input" },
    ttps: ["AML.T0020", "AML.T0096", "AML.T0010"],
    fast_test: "Search IR playbooks for 'prompt injection', 'model poisoning', 'AI agent', 'LLM', 'MCP server'. Zero matches = THEATER FLAG.",
  },
  5: {
    pattern_name: "Change Management Theater (AI Model)",
    primary_attack_class: "external model updates bypass operator change control",
    controls: [
      { framework: "NIST 800-53", control_id: "CM-3", note: "Configuration change control — drafted for changes the operator controls" },
      { framework: "ISO 27001:2022", control_id: "A.8.32", note: "Change management" },
      { framework: "SOC 2", control_id: "CC8", note: "Change management" },
    ],
    evidence: { campaign: "Continuous provider model updates", rationale: "Vendor-managed model updates bypass operator change control entirely; safety properties can shift silently" },
    ttps: ["AML.T0018", "AML.T0020"],
    fast_test: "List LLM API deps. Does each provider update open a change ticket? Is there a behavioral test suite? Is the model version pinned? Any 'no' = THEATER FLAG.",
  },
  6: {
    pattern_name: "Vendor/Third-Party Risk Theater (AI API + MCP)",
    primary_attack_class: "vendor program scope excludes LLM APIs and MCP servers",
    controls: [
      { framework: "SOC 2", control_id: "CC9", note: "Risk mitigation; vendor management" },
      { framework: "NIST 800-53", control_id: "SA-12", note: "Supply chain protection" },
      { framework: "ISO 27001:2022", control_id: "A.5.19", note: "Supplier relationships — drafted for SaaS-style vendors" },
      { framework: "ISO 27001:2022", control_id: "A.5.20", note: "Information security in supplier agreements" },
      { framework: "US FedRAMP", control_id: "Rev 5 Moderate", note: "Authorization-as-evidence pattern; ATO does not cover tenant-side MCP" },
      { framework: "US DoD CMMC", control_id: "2.0 Level 2", note: "Certification-as-evidence; does not cover AI coding-assistant supply chain" },
    ],
    evidence: { cve: "CVE-2026-30615", rationale: "Windsurf MCP zero-interaction RCE — vendor management program had no coverage of MCP servers as third-party code" },
    ttps: ["AML.T0010"],
    fast_test: "List LLM API providers. Is there a vendor risk assessment + DPA for each? List MCP servers on dev workstations — did each pass vendor review? Either gap = THEATER FLAG.",
  },
  7: {
    pattern_name: "Security Awareness Theater (AI Phishing)",
    primary_attack_class: "phishing simulation tests resistance to template-era phish, not AI-generated content",
    controls: [
      { framework: "NIST 800-53", control_id: "AT-2", note: "Security awareness training — drafted against human-template phishing" },
      { framework: "ISO 27001:2022", control_id: "A.6.3", note: "Information security awareness, education and training" },
      { framework: "PCI DSS 4.0", control_id: "12.6", note: "Security awareness program" },
    ],
    evidence: { campaign: "AI-generated phishing baseline (82.6% of phish contain AI-generated content)", rationale: "Grammar/style heuristics are no longer reliable detectors; <5% click rate on template phish is non-informative" },
    ttps: ["T1566", "AML.T0016"],
    fast_test: "Were any simulation emails AI-generated (not template-based) in the last 3 sims? Is MFA phishing-resistant (hardware keys / passkeys)? Either 'no' = THEATER FLAG.",
  },
};

function extractPatternBodyFromSkill(skillBody, patternNumber) {
  // Find "### Pattern N:" and capture until the next "### Pattern N+1:" OR
  // the next ## H2 after the header line itself. We skip the header's own
  // line before scanning for an H2 boundary — otherwise the `### Pattern N:`
  // line would match the `## ` prefix regex once its leading `#` is sliced.
  const startRe = new RegExp(`^### Pattern ${patternNumber}:`, "m");
  const startMatch = skillBody.match(startRe);
  if (!startMatch) return null;
  const startIdx = startMatch.index;
  const headerEnd = skillBody.indexOf("\n", startIdx);
  const afterHeader = headerEnd >= 0 ? headerEnd + 1 : skillBody.length;
  const tail = skillBody.slice(startIdx);
  const nextPatternRe = new RegExp(`^### Pattern ${patternNumber + 1}:`, "m");
  const nextPatternMatch = tail.match(nextPatternRe);
  const h2Re = /^## /m;
  const afterHeaderSlice = skillBody.slice(afterHeader);
  const h2Match = afterHeaderSlice.match(h2Re);
  const stops = [
    nextPatternMatch ? nextPatternMatch.index : Infinity,
    h2Match ? (afterHeader - startIdx) + h2Match.index : Infinity,
  ];
  const stopAt = Math.min(...stops);
  return tail.slice(0, Number.isFinite(stopAt) ? stopAt : tail.length).trim();
}

function pullField(body, label) {
  // The patterns use a "**Label:** ..." prose convention. Return the line(s)
  // after the label until the next "**" or blank line.
  const re = new RegExp(`\\*\\*${label.replace(/[-/\\^$*+?.()|[\\]{}]/g, "\\$&")}:?\\*\\*\\s*([\\s\\S]*?)(?=\\n\\n|\\n\\*\\*|$)`);
  const m = body.match(re);
  return m ? m[1].trim() : null;
}

function buildTheaterFingerprints({ root }) {
  const skillPath = path.join(root, "skills/compliance-theater/skill.md");
  const body = fs.readFileSync(skillPath, "utf8");

  const out = {};
  for (const [num, meta] of Object.entries(PATTERN_CONTROL_MAP)) {
    const patternBody = extractPatternBodyFromSkill(body, Number(num));
    out[`pattern-${num}`] = {
      pattern_number: Number(num),
      pattern_name: meta.pattern_name,
      primary_attack_class: meta.primary_attack_class,
      claim: pullField(patternBody || "", "The claim"),
      audit_evidence: pullField(patternBody || "", "The audit evidence"),
      reality: pullField(patternBody || "", "The reality"),
      why_its_theater: pullField(patternBody || "", "Why it's theater"),
      fast_test: meta.fast_test,
      controls: meta.controls,
      evidence: meta.evidence,
      ttps: meta.ttps,
      source_skill: "compliance-theater",
      source_section: `### Pattern ${num}: ${meta.pattern_name}`,
    };
  }

  // Inverted index: control_id → pattern(s) it spans, so a consumer can ask
  // "is this control implicated in a theater pattern?" without scanning all
  // seven patterns.
  const byControl = {};
  for (const [pid, p] of Object.entries(out)) {
    for (const c of p.controls) {
      const key = `${c.framework}::${c.control_id}`;
      (byControl[key] = byControl[key] || []).push(pid);
    }
  }

  return {
    _meta: {
      schema_version: "1.0.0",
      source: "skills/compliance-theater/skill.md (7 documented patterns)",
      pattern_count: Object.keys(out).length,
    },
    patterns: out,
    by_control: byControl,
  };
}

module.exports = { buildTheaterFingerprints };
