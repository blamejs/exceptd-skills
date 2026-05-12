'use strict';

/**
 * Skill dispatcher. Routes scanner findings to relevant skills via manifest trigger matching.
 * Returns an ordered dispatch plan sorted by RWEP urgency.
 */

const fs = require('fs');
const path = require('path');

const MANIFEST_PATH = process.env.EXCEPTD_MANIFEST || path.join(__dirname, '..', 'manifest.json');
const SKILLS_DIR = process.env.EXCEPTD_SKILLS_DIR || path.join(__dirname, '..', 'skills');

// --- public API ---

/**
 * Route findings to skills and return a dispatch plan.
 *
 * @param {object[]} findings - From scanner.scan()
 * @returns {{ plan: object[], unmatched: object[], summary: object }}
 */
function dispatch(findings) {
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
      if (seen.has(skill.name)) continue;
      seen.add(skill.name);

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
        evidence,
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
  const q = query.toLowerCase();

  return manifest.skills.filter(skill => {
    const triggers = skill.triggers || [];
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

module.exports = { dispatch, routeQuery, getSkillContext };
