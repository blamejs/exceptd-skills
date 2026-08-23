'use strict';

/**
 * Routes scanner findings to skills via manifest trigger matching, returning
 * a dispatch plan ordered by severity priority.
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const MANIFEST_PATH = process.env.EXCEPTD_MANIFEST || path.join(__dirname, '..', 'manifest.json');
const SKILLS_DIR = process.env.EXCEPTD_SKILLS_DIR || path.join(__dirname, '..', 'skills');

/**
 * Serializes a value deterministically: object keys are recursively sorted, so
 * the same content in a different key order produces the same string.
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

function findingFingerprint(finding) {
  if (finding && finding.cve_id) return finding.cve_id;
  return crypto.createHash('sha1').update(stableStringify(finding)).digest('hex');
}

/**
 * Route scanner findings to skills, returning { plan, unmatched, summary }.
 * Throws TypeError on a non-array, or an element that is not a non-null object.
 */
function dispatch(findings) {
  // A string would iterate code point by code point into nonsense findings.
  if (!Array.isArray(findings)) {
    throw new TypeError('dispatch: findings must be an array');
  }
  const manifest = loadManifest();
  const plan = [];
  const unmatched = [];
  const seen = new Set();

  for (const finding of findings) {
    // Refuse here, or matchFinding derefs null with an opaque message.
    if (finding === null || typeof finding !== 'object' || Array.isArray(finding)) {
      throw new TypeError('dispatch: each finding must be a non-null object');
    }
    const matched = matchFinding(finding, manifest.skills);

    if (matched.length === 0) {
      unmatched.push(finding);
      continue;
    }

    for (const skill of matched) {
      // Key on (skill, full finding identity): skill + cve_id alone collapses
      // every non-CVE finding reaching a skill into one entry.
      const dedupeKey = `${skill.name}|${findingFingerprint(finding)}`;
      if (seen.has(dedupeKey)) continue;
      seen.add(dedupeKey);

      // Carries the CVE id and RWEP so the print path can name them, not count them.
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
        // Omitted when empty: a bare {} reads as "evidence was captured".
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
 * Match a free-text query against skill triggers; [] for a non-string query.
 */
function routeQuery(query) {
  const manifest = loadManifest();
  if (typeof query !== 'string') return [];
  const q = query.trim().toLowerCase();
  // An empty query is a substring of every trigger. Queries under 3 chars
  // prefix-match instead, or a single letter matches every trigger holding it.
  if (q.length === 0) return [];

  return manifest.skills.filter(skill => {
    const triggers = skill.triggers || [];
    if (q.length < 3) {
      return triggers.some(t => t.toLowerCase().startsWith(q));
    }
    return triggers.some(t => q.includes(t.toLowerCase()) || t.toLowerCase().includes(q));
  });
}

/**
 * Full dispatch context for one skill — its manifest entry, resolved data-dep
 * paths and skill.md body. null when the manifest carries no such skill.
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
