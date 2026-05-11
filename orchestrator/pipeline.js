'use strict';

/**
 * Multi-agent pipeline coordinator.
 * Orchestrates: threat-researcher → source-validator → skill-updater → report-generator
 *
 * This module coordinates agent handoffs using a structured JSON protocol.
 * Each stage produces a handoff package that the next stage consumes.
 * Agents themselves are defined in agents/ and executed by AI assistants — not by this code.
 * This module tracks state, validates handoffs, and routes between stages.
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const AGENTS_DIR = path.join(__dirname, '..', 'agents');
const DATA_DIR = process.env.EXCEPTD_DATA_DIR || path.join(__dirname, '..', 'data');
const REPORTS_DIR = path.join(__dirname, '..', 'reports');

const PIPELINE_STAGES = ['threat-researcher', 'source-validator', 'skill-updater', 'report-generator'];

// --- public API ---

/**
 * Initialize a new pipeline run for a given trigger.
 *
 * @param {'new_cve'|'atlas_update'|'framework_amendment'|'manual'} triggerType
 * @param {object} triggerPayload - CVE ID, ATLAS version, etc.
 * @returns {{ pipeline_id: string, trigger: object, stages: object[], status: string }}
 */
function initPipeline(triggerType, triggerPayload) {
  const pipelineId = crypto.randomUUID();
  const run = {
    pipeline_id: pipelineId,
    trigger: { type: triggerType, payload: triggerPayload, timestamp: new Date().toISOString() },
    stages: PIPELINE_STAGES.map(name => ({
      name,
      status: 'pending',
      agent_path: path.join(AGENTS_DIR, `${name}.md`),
      started_at: null,
      completed_at: null,
      handoff: null,
      errors: []
    })),
    status: 'initialized',
    created_at: new Date().toISOString()
  };

  run.stages[0].status = 'ready';
  return run;
}

/**
 * Build the handoff package for a specific pipeline stage.
 * This is what an AI assistant reads to understand what to do and what to pass forward.
 *
 * @param {object} run - Pipeline run object from initPipeline()
 * @param {number} stageIndex - 0-based stage index
 * @param {object} stageOutput - Output from the current stage
 * @returns {object} Handoff package for the next stage
 */
function buildHandoff(run, stageIndex, stageOutput) {
  const currentStage = run.stages[stageIndex];
  const nextStage = run.stages[stageIndex + 1];

  validateHandoff(currentStage.name, stageOutput);

  const handoff = {
    handoff_id: crypto.randomUUID(),
    pipeline_id: run.pipeline_id,
    from_stage: currentStage.name,
    to_stage: nextStage?.name || 'complete',
    timestamp: new Date().toISOString(),
    trigger: run.trigger,
    payload: stageOutput,
    instructions: nextStage ? getStageInstructions(nextStage.name, stageOutput) : null
  };

  currentStage.handoff = handoff;
  currentStage.status = 'completed';
  currentStage.completed_at = new Date().toISOString();

  if (nextStage) {
    nextStage.status = 'ready';
  } else {
    run.status = 'completed';
  }

  return handoff;
}

/**
 * Check the currency of all skills and return a report.
 * Used by the scheduler for weekly currency checks.
 *
 * @returns {{ currency_report: object[], action_required: boolean }}
 */
function currencyCheck() {
  const manifest = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'manifest.json'), 'utf8'));
  const now = new Date();
  const report = [];

  for (const skill of manifest.skills) {
    const reviewDate = new Date(skill.last_threat_review || '2020-01-01');
    const daysSinceReview = Math.floor((now - reviewDate) / (1000 * 60 * 60 * 24));

    const currencyScore = _currencyScore(daysSinceReview, skill.forward_watch?.length || 0);

    report.push({
      skill: skill.name,
      last_threat_review: skill.last_threat_review,
      days_since_review: daysSinceReview,
      currency_score: currencyScore,
      currency_label: _currencyLabel(currencyScore),
      forward_watch_count: skill.forward_watch?.length || 0,
      action_required: currencyScore < 70
    });
  }

  report.sort((a, b) => a.currency_score - b.currency_score);

  return {
    currency_report: report,
    action_required: report.some(r => r.action_required),
    critical_count: report.filter(r => r.currency_score < 50).length,
    check_timestamp: now.toISOString()
  };
}

/**
 * Get the agent definition for a stage.
 *
 * @param {string} stageName - Agent name
 * @returns {string|null} Agent instruction content
 */
function getAgentDefinition(stageName) {
  const agentPath = path.join(AGENTS_DIR, `${stageName}.md`);
  try {
    return fs.readFileSync(agentPath, 'utf8');
  } catch (_) {
    return null;
  }
}

// --- private helpers ---

function validateHandoff(stageName, output) {
  const required = {
    'threat-researcher': ['cve_id_or_ttp', 'findings', 'primary_sources', 'confidence'],
    'source-validator': ['verdict', 'verified_claims', 'rejected_claims'],
    'skill-updater': ['updated_skills', 'updated_data_files', 'change_summary'],
    'report-generator': ['report_format', 'report_content', 'audience']
  };

  const req = required[stageName] || [];
  const missing = req.filter(k => !(k in output));
  if (missing.length > 0) {
    throw new Error(`Handoff from ${stageName} missing required fields: ${missing.join(', ')}`);
  }
}

function getStageInstructions(stageName, previousOutput) {
  const instructions = {
    'source-validator': `Validate the threat research findings. Check each claimed primary source.
      Verify: CVE exists in NVD, CISA KEV status is accurate, RWEP factor breakdown is justified.
      Return verdict: approved | approved_with_corrections | rejected.
      Input: ${JSON.stringify(previousOutput, null, 2).substring(0, 500)}...`,

    'skill-updater': `Apply validated research to skill files and data catalogs.
      For each approved finding: update data/cve-catalog.json, data/zeroday-lessons.json,
      data/framework-control-gaps.json as appropriate. Bump last_threat_review in affected skills.
      Input: ${JSON.stringify(previousOutput, null, 2).substring(0, 500)}...`,

    'report-generator': `Generate structured reports from the completed pipeline run.
      Produce: executive-summary.md, compliance-gap-report.md as applicable.
      Focus on RWEP scores >= 80 and compliance theater findings.
      Input: ${JSON.stringify(previousOutput, null, 2).substring(0, 500)}...`
  };

  return instructions[stageName] || null;
}

function _currencyScore(daysSinceReview, forwardWatchCount) {
  let score = 100;
  if (daysSinceReview > 180) score -= 30;
  else if (daysSinceReview > 90) score -= 20;
  else if (daysSinceReview > 60) score -= 10;
  else if (daysSinceReview > 30) score -= 5;
  score -= forwardWatchCount * 5;
  return Math.max(0, score);
}

function _currencyLabel(score) {
  if (score >= 90) return 'current';
  if (score >= 70) return 'acceptable';
  if (score >= 50) return 'stale';
  return 'critical_stale';
}

module.exports = { initPipeline, buildHandoff, currencyCheck, getAgentDefinition };
