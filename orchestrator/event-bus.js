'use strict';

/**
 * Event bus for trigger-driven skill updates. This bus is in-process only: the
 * event log is a bounded in-memory FIFO ring buffer and is NOT persisted across
 * restarts, so a deployment needing durable history swaps the emitter for a
 * queue without changing the event schema. The cap keeps a long-running `watch`
 * from growing without bound — 1000 entries, overridden at process start by
 * EXCEPTD_EVENT_LOG_MAX_SIZE (positive integer).
 */

const { EventEmitter } = require('events');

const DEFAULT_EVENT_LOG_MAX_SIZE = 1000;

function _resolveLogMaxSize() {
  const raw = process.env.EXCEPTD_EVENT_LOG_MAX_SIZE;
  if (raw === undefined || raw === null || raw === '') return DEFAULT_EVENT_LOG_MAX_SIZE;
  const n = Number(raw);
  if (!Number.isFinite(n) || !Number.isInteger(n) || n <= 0) return DEFAULT_EVENT_LOG_MAX_SIZE;
  return n;
}

const EVENT_LOG_MAX_SIZE = _resolveLogMaxSize();

const EVENT_TYPES = {
  CISA_KEV_ADDED: 'cisa.kev.added',
  ATLAS_VERSION_RELEASED: 'atlas.version.released',
  KERNEL_CVE_HIGH_RWEP: 'cve.kernel.high_rwep',
  AI_PLATFORM_CVE: 'cve.ai_platform',
  FRAMEWORK_AMENDMENT: 'framework.amendment',
  PQC_STANDARD_UPDATE: 'pqc.standard.update',
  EXPLOIT_STATUS_CHANGE: 'exploit.status.change',
  NEW_ATTACK_CLASS: 'attack_class.new',
  SKILL_CURRENCY_LOW: 'skill.currency.low',
  SKILL_CURRENCY_LOW_AGGREGATE: 'skill.currency.low.aggregate'
};

const EVENT_SKILL_MAP = {
  [EVENT_TYPES.CISA_KEV_ADDED]: ['kernel-lpe-triage', 'exploit-scoring', 'compliance-theater', 'skill-update-loop'],
  [EVENT_TYPES.ATLAS_VERSION_RELEASED]: ['ai-attack-surface', 'mcp-agent-trust', 'rag-pipeline-security', 'ai-c2-detection', 'skill-update-loop'],
  [EVENT_TYPES.KERNEL_CVE_HIGH_RWEP]: ['kernel-lpe-triage', 'exploit-scoring', 'zeroday-gap-learn', 'framework-gap-analysis'],
  [EVENT_TYPES.AI_PLATFORM_CVE]: ['mcp-agent-trust', 'ai-attack-surface', 'zeroday-gap-learn'],
  [EVENT_TYPES.FRAMEWORK_AMENDMENT]: ['framework-gap-analysis', 'compliance-theater', 'global-grc', 'policy-exception-gen'],
  [EVENT_TYPES.PQC_STANDARD_UPDATE]: ['pqc-first', 'framework-gap-analysis'],
  [EVENT_TYPES.EXPLOIT_STATUS_CHANGE]: ['exploit-scoring', 'kernel-lpe-triage', 'compliance-theater'],
  [EVENT_TYPES.NEW_ATTACK_CLASS]: ['threat-model-currency', 'ai-attack-surface', 'skill-update-loop'],
  [EVENT_TYPES.SKILL_CURRENCY_LOW]: ['skill-update-loop'],
  [EVENT_TYPES.SKILL_CURRENCY_LOW_AGGREGATE]: ['skill-update-loop']
};

class ExceptdEventBus extends EventEmitter {
  constructor(opts) {
    super();
    const cap = opts && Number.isInteger(opts.maxLogSize) && opts.maxLogSize > 0
      ? opts.maxLogSize
      : EVENT_LOG_MAX_SIZE;
    this.eventLog = [];
    this.maxLogSize = cap;
  }

  // Overrides EventEmitter.emit: `eventType` is one of EVENT_TYPES, and the
  // return is the constructed event record, not the listener-present boolean.
  emit(eventType, payload) {
    const event = {
      event_id: `evt_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`,
      type: eventType,
      timestamp: new Date().toISOString(),
      payload,
      affected_skills: EVENT_SKILL_MAP[eventType] || []
    };

    this.eventLog.push(event);
    // A loop rather than an `if`: a lowered maxLogSize or a burst that clears
    // the cap in one tick must still leave the buffer at-cap.
    while (this.eventLog.length > this.maxLogSize) {
      this.eventLog.shift();
    }
    super.emit(eventType, event);
    super.emit('*', event);
    return event;
  }

  on(eventType, handler) {
    super.on(eventType, handler);
    return this;
  }

  onAny(handler) {
    return this.on('*', handler);
  }

  offAny(handler) {
    this.removeListener('*', handler);
    return this;
  }

  getSkillEvents(skillName) {
    return this.eventLog.filter(e => e.affected_skills.includes(skillName));
  }

  // Always a fresh array; mutating it does not touch the live log.
  getLog(eventType) {
    if (eventType) return this.eventLog.filter(e => e.type === eventType);
    return [...this.eventLog];
  }

  kevAdded({ cve_id, kev_date, rwep_score }) {
    return this.emit(EVENT_TYPES.CISA_KEV_ADDED, { cve_id, kev_date, rwep_score });
  }

  atlasReleased({ old_version, new_version, release_date }) {
    return this.emit(EVENT_TYPES.ATLAS_VERSION_RELEASED, { old_version, new_version, release_date });
  }

  exploitStatusChanged({ cve_id, old_status, new_status }) {
    return this.emit(EVENT_TYPES.EXPLOIT_STATUS_CHANGE, { cve_id, old_status, new_status });
  }

  skillCurrencyLow({ skill_name, currency_score, days_since_review }) {
    return this.emit(EVENT_TYPES.SKILL_CURRENCY_LOW, { skill_name, currency_score, days_since_review });
  }
}

const bus = new ExceptdEventBus();

module.exports = { bus, EVENT_TYPES, EVENT_SKILL_MAP, ExceptdEventBus, EVENT_LOG_MAX_SIZE, DEFAULT_EVENT_LOG_MAX_SIZE };
