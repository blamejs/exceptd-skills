'use strict';

/**
 * Event bus for trigger-driven skill updates.
 *
 * Events are typed and carry structured payloads. Handlers are registered per
 * event type. This bus is in-process only; the event log is held in a bounded
 * ring buffer in memory and is NOT persisted across process restarts. For
 * production deployments where event history must survive restarts, swap the
 * internal emitter for a durable queue (Redis Streams, SQS, NATS JetStream,
 * etc.) without changing the event schema.
 *
 * Bounded log policy:
 *   - The in-memory log is capped at EVENT_LOG_MAX_SIZE entries to prevent
 *     unbounded memory growth on long-running `watch` processes.
 *   - Default cap is 1000 entries; override at process start via the
 *     EXCEPTD_EVENT_LOG_MAX_SIZE env var (positive integer).
 *   - When the cap is reached, the oldest entry is shifted off on each new
 *     emit (FIFO ring buffer semantics).
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

// Maps event types to the skills they should trigger for review
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

  /**
   * Emit a typed event with structured payload.
   *
   * @param {string} eventType - One of EVENT_TYPES
   * @param {object} payload - Event-specific data
   */
  emit(eventType, payload) {
    const event = {
      event_id: `evt_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`,
      type: eventType,
      timestamp: new Date().toISOString(),
      payload,
      affected_skills: EVENT_SKILL_MAP[eventType] || []
    };

    this.eventLog.push(event);
    // Bounded ring buffer — shift the oldest entry off when over cap. Loop
    // rather than `if` so a runtime mutation of maxLogSize (or a burst that
    // exceeds the cap in a single tick) still leaves the buffer at-cap.
    while (this.eventLog.length > this.maxLogSize) {
      this.eventLog.shift();
    }
    super.emit(eventType, event);
    super.emit('*', event);
    return event;
  }

  /**
   * Register a handler for an event type.
   *
   * @param {string} eventType
   * @param {function} handler - (event) => void
   */
  on(eventType, handler) {
    super.on(eventType, handler);
    return this;
  }

  /**
   * Register a handler for all events.
   *
   * @param {function} handler - (event) => void
   */
  onAny(handler) {
    return this.on('*', handler);
  }

  /**
   * Detach a handler previously registered via onAny().
   *
   * @param {function} handler
   */
  offAny(handler) {
    this.removeListener('*', handler);
    return this;
  }

  /**
   * Get all events that affected a specific skill.
   *
   * @param {string} skillName
   * @returns {object[]}
   */
  getSkillEvents(skillName) {
    return this.eventLog.filter(e => e.affected_skills.includes(skillName));
  }

  /**
   * Get the event log, optionally filtered by type.
   *
   * @param {string} [eventType]
   * @returns {object[]}
   */
  getLog(eventType) {
    if (eventType) return this.eventLog.filter(e => e.type === eventType);
    return [...this.eventLog];
  }

  /**
   * Fire a CISA KEV addition event.
   *
   * @param {{ cve_id: string, kev_date: string, rwep_score: number }} params
   */
  kevAdded({ cve_id, kev_date, rwep_score }) {
    return this.emit(EVENT_TYPES.CISA_KEV_ADDED, { cve_id, kev_date, rwep_score });
  }

  /**
   * Fire an ATLAS version release event.
   *
   * @param {{ old_version: string, new_version: string, release_date: string }} params
   */
  atlasReleased({ old_version, new_version, release_date }) {
    return this.emit(EVENT_TYPES.ATLAS_VERSION_RELEASED, { old_version, new_version, release_date });
  }

  /**
   * Fire an exploit status change event.
   *
   * @param {{ cve_id: string, old_status: string, new_status: string }} params
   */
  exploitStatusChanged({ cve_id, old_status, new_status }) {
    return this.emit(EVENT_TYPES.EXPLOIT_STATUS_CHANGE, { cve_id, old_status, new_status });
  }

  /**
   * Fire a skill currency low event (emitted by scheduler).
   *
   * @param {{ skill_name: string, currency_score: number, days_since_review: number }} params
   */
  skillCurrencyLow({ skill_name, currency_score, days_since_review }) {
    return this.emit(EVENT_TYPES.SKILL_CURRENCY_LOW, { skill_name, currency_score, days_since_review });
  }
}

const bus = new ExceptdEventBus();

module.exports = { bus, EVENT_TYPES, EVENT_SKILL_MAP, ExceptdEventBus, EVENT_LOG_MAX_SIZE, DEFAULT_EVENT_LOG_MAX_SIZE };
