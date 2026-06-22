'use strict';

/**
 * Skill dispatcher. Routes scanner findings to relevant skills via manifest trigger matching.
 * Returns an ordered dispatch plan sorted by RWEP urgency.
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const MANIFEST_PATH = process.env.EXCEPTD_MANIFEST || path.join(__dirname, '..', 'manifest.json');
const SKILLS_DIR = process.env.EXCEPTD_SKILLS_DIR || path.join(__dirname, '..', 'skills');

/**
 * Deterministic serialization of a finding for dedupe identity. Object keys are
 * recursively sorted so two findings with the same content but different key
 * insertion order produce the same fingerprint. Used to key the per-skill
 * dedupe set on the FULL finding content rather than a single optional field
 * (cve_id), so two genuinely distinct findings that route to the same skill
 * — differing only in e.g. server_name or api_name — each keep a plan entry
 * while true duplicates (identical content) still fold.
 */
function stableStringify(value) {
  if (value === null || typeof value !== 'object') {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return '[' + value.map(stableStringify).join(',') + ']';
  }
  const keys = Object.keys(value).sort();
  return '{' + keys.map(k => JSON.stringify(k) + ':' + stableStringify(value[k])).join(',') + '}';
}

/**
 * Stable dedupe fingerprint for a finding. Prefer the catalogued cve_id when
 * present (compact + already unique per CVE); otherwise hash the full finding
 * content so the key stays bounded while still discriminating every distinct
 * finding family without having to enumerate its fields.
 */
function findingFingerprint(finding) {
  if (finding && finding.cve_id) return finding.cve_id;
  return crypto.createHash('sha1').update(stableStringify(finding)).digest('hex');
}

// --- public API ---

/**
 * Route findings to skills and return a dispatch plan.
 *
 * @param {object[]} findings - From scanner.scan()
 * @returns {{ plan: object[], unmatched: object[], summary: object }}
 */
function dispatch(findings) {
  // Type-check up front. A string argument would iterate character-by-
  // character (since `for...of` on a string yields code points), producing
  // nonsense "findings" with no domain/signal. Refuse loudly rather than
  // silently process garbage; downstream consumers depend on plan entries
  // being shaped by real findings.
  if (!Array.isArray(findings)) {
    throw new TypeError('dispatch: findings must be an array');
  }
  const manifest = loadManifest();
  const plan = [];
  const unmatched = [];
  const seen = new Set();

  for (const finding of findings) {
    const matched = matchFinding(finding, manifest.skills);

    if (matched.length === 0) {
      unmatched.push(finding);
      continue;
    }

    for (const skill of matched) {
      // De-duplicate by (skill, FULL finding identity), NOT by skill alone and
      // NOT by skill + a single optional field. Two distinct findings (two
      // different CVEs, two MCP servers under one config, two AI APIs) that
      // route to the same skill must each produce a plan entry so their
      // per-finding evidence is preserved — keying on skill.name + cve_id alone
      // silently dropped every non-CVE finding after the first that reached a
      // given skill (cve_id was undefined, so the coarse `signal` fallback
      // collapsed them). The fingerprint is the cve_id when present, else a hash
      // of the full finding content, so a genuine duplicate (same skill + same
      // content) still folds while every distinct finding family stays separate
      // without having to enumerate its discriminator fields.
      const dedupeKey = `${skill.name}|${findingFingerprint(finding)}`;
      if (seen.has(dedupeKey)) continue;
      seen.add(dedupeKey);

      // Preserve per-CVE evidence so operators see the actual CVE IDs
      // (not just an aggregate count). Earlier output read "1 CISA
      // KEV CVE with RWEP >= 90" — the entry below now also carries
      // the CVE ID + RWEP score so the print path can render
      // "1 CISA KEV CVE with RWEP >= 90 (CVE-2026-31431 / Copy Fail
      // RWEP 90)".
      const evidence = {};
      if (Array.isArray(finding.items) && finding.items.length > 0) evidence.items = finding.items;
      if (finding.cve_id) evidence.cve_id = finding.cve_id;
      if (finding.rwep_score !== undefined) evidence.rwep_score = finding.rwep_score;

      plan.push({
        skill_name: skill.name,
        skill_path: path.join(SKILLS_DIR, skill.name, 'skill.md'),
        triggered_by: finding.signal,
        finding_domain: finding.domain,
        finding_severity: finding.severity,
        action_required: finding.action_required,
        priority: severityToPriority(finding.severity),
        last_threat_review: skill.last_threat_review || 'unknown',
        // Omit `evidence` entirely when it has no content (no items / cve_id /
        // rwep_score) rather than emitting a bare {} — a field-present-but-empty
        // object reads to a consumer as "evidence was captured" when none was.
        ...(Object.keys(evidence).length > 0 ? { evidence } : {}),
      });
    }
  }

  plan.sort((a, b) => a.priority - b.priority);

  return {
    plan,
    unmatched,
    summary: {
      total_findings: findings.length,
      matched_findings: findings.length - unmatched.length,
      skills_to_invoke: plan.length,
      critical_priority: plan.filter(p => p.priority === 1).length,
      high_priority: plan.filter(p => p.priority === 2).length
    }
  };
}

/**
 * Route a single natural language query to matching skills.
 *
 * @param {string} query - Free text query
 * @returns {object[]} Matched skills from manifest
 */
function routeQuery(query) {
  const manifest = loadManifest();
  if (typeof query !== 'string') return [];
  const q = query.trim().toLowerCase();
  // Reject empty + very short queries. The legacy substring match treats
  // any trigger string as containing the empty string, so a bare empty
  // query matched every skill — useless and misleading for callers.
  // Short queries (1-2 chars) only match when they are an explicit
  // prefix of a trigger; that prevents single letters from matching
  // every trigger that contains them (e.g. "a" would match anything).
  if (q.length === 0) return [];

  return manifest.skills.filter(skill => {
    const triggers = skill.triggers || [];
    if (q.length < 3) {
      // Trigger-prefix match only for short queries.
      return triggers.some(t => t.toLowerCase().startsWith(q));
    }
    return triggers.some(t => q.includes(t.toLowerCase()) || t.toLowerCase().includes(q));
  });
}

/**
 * Get the full dispatch context for a specific skill (data deps, frontmatter).
 *
 * @param {string} skillName
 * @returns {{ skill: object, data_paths: object, skill_content: string|null }}
 */
function getSkillContext(skillName) {
  const manifest = loadManifest();
  const skill = manifest.skills.find(s => s.name === skillName);
  if (!skill) return null;

  const DATA_DIR = path.join(__dirname, '..', 'data');
  const dataPaths = {};
  for (const dep of skill.data_deps || []) {
    const fullPath = path.join(DATA_DIR, dep);
    dataPaths[dep] = { path: fullPath, exists: fs.existsSync(fullPath) };
  }

  const skillPath = path.join(SKILLS_DIR, skillName, 'skill.md');
  let skillContent = null;
  try {
    skillContent = fs.readFileSync(skillPath, 'utf8');
  } catch (_) {}

  return { skill, data_paths: dataPaths, skill_content: skillContent };
}

// --- private helpers ---

function matchFinding(finding, skills) {
  if (finding.skill_hint) {
    const direct = skills.find(s => s.name === finding.skill_hint);
    if (direct) return [direct];
  }

  const domainToSkills = {
    kernel: ['kernel-lpe-triage', 'exploit-scoring', 'compliance-theater'],
    mcp: ['mcp-agent-trust', 'ai-attack-surface', 'security-maturity-tiers'],
    crypto: ['pqc-first', 'framework-gap-analysis'],
    ai_api: ['ai-c2-detection', 'ai-attack-surface', 'threat-model-currency'],
    framework: ['framework-gap-analysis', 'compliance-theater', 'global-grc']
  };

  const candidateNames = domainToSkills[finding.domain] || [];
  return skills.filter(s => candidateNames.includes(s.name));
}

function severityToPriority(severity) {
  const map = { critical: 1, high: 2, medium: 3, low: 4, info: 5 };
  return map[severity] || 5;
}

function loadManifest() {
  return JSON.parse(fs.readFileSync(MANIFEST_PATH, 'utf8'));
}

module.exports = { dispatch, routeQuery, getSkillContext, stableStringify, findingFingerprint };
