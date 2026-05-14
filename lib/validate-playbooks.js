#!/usr/bin/env node
/*
 * lib/validate-playbooks.js — exceptd playbook validator.
 *
 * Walks every JSON file in data/playbooks/, validates it against
 * lib/schemas/playbook.schema.json (using the same inline JSON-Schema
 * subset validator as lib/validate-cve-catalog.js), and additionally
 * resolves every cross-playbook + cross-catalog reference the playbook
 * shape carries.
 *
 * Cross-references checked:
 *   - _meta.feeds_into[].playbook_id  → other playbook files
 *   - _meta.mutex[]                   → other playbook files
 *   - _meta.skill_chain[]             → manifest.json.skills[]
 *     (legacy alias; the canonical chain lives under
 *      phases.direct.skill_chain[].skill — both are resolved)
 *   - phases.govern.skill_preload[]   → manifest.json.skills[]
 *   - domain.atlas_refs[]             → data/atlas-ttps.json keys
 *   - domain.cve_refs[]               → data/cve-catalog.json keys
 *   - domain.cwe_refs[]               → data/cwe-catalog.json keys
 *   - domain.d3fend_refs[]            → data/d3fend-catalog.json keys
 *   - phases.detect.indicators[].attack_ref → data/attack-techniques.json
 *   - phases.detect.indicators[].atlas_ref  → data/atlas-ttps.json
 *   - phases.detect.indicators[].cve_ref    → data/cve-catalog.json
 *
 * Internal consistency:
 *   - Indicator ids are unique within a playbook.
 *   - rwep_threshold ordering: close <= monitor <= escalate, each in 0..100.
 *   - close.notification_actions[].obligation_ref resolves to a synthesized
 *     "<jurisdiction>/<regulation> <window_hours>h" key from
 *     govern.jurisdiction_obligations[] (the schema does not give
 *     jurisdiction_obligations an explicit `id` field; the shipped playbooks
 *     reference them by this composite string).
 *   - _meta.mutex is symmetric across the whole playbook set: if A lists B,
 *     B must list A. Asymmetry surfaces as a warning in v0.12.16 (and will
 *     flip to error in v0.13.0) — see checkMutexReciprocity().
 *
 * Finding severity:
 *   - error   — structural problems that block the runner (missing required
 *               field, JSON parse error, internal ordering violation,
 *               duplicate indicator id).
 *   - warning — schema-shape drift the runner can still tolerate (enum
 *               vocabulary lag, cross-catalog refs introduced after the
 *               playbook last shipped). v0.12.12 surfaces these to the
 *               operator without failing the gate; v0.13.0 will flip them
 *               to hard errors via predeploy `informational: false`.
 *
 * Exit code: 0 if no errors (warnings allowed), 1 if any errors, 2 on
 *            argv error.
 *
 * Usage:
 *   node lib/validate-playbooks.js          validate every playbook
 *   node lib/validate-playbooks.js --quiet  only print FAIL playbooks + summary
 *   node lib/validate-playbooks.js --strict treat warnings as errors (v0.13.0
 *                                           preview).
 */

'use strict';

const fs = require('node:fs');
const path = require('node:path');
const process = require('node:process');

const REPO_ROOT = path.resolve(__dirname, '..');
const SCHEMA_PATH = path.join(REPO_ROOT, 'lib', 'schemas', 'playbook.schema.json');
const PLAYBOOKS_DIR = path.join(REPO_ROOT, 'data', 'playbooks');
const MANIFEST_PATH = path.join(REPO_ROOT, 'manifest.json');
const ATLAS_PATH = path.join(REPO_ROOT, 'data', 'atlas-ttps.json');
const CVE_PATH = path.join(REPO_ROOT, 'data', 'cve-catalog.json');
const CWE_PATH = path.join(REPO_ROOT, 'data', 'cwe-catalog.json');
const D3FEND_PATH = path.join(REPO_ROOT, 'data', 'd3fend-catalog.json');
const ATTACK_PATH = path.join(REPO_ROOT, 'data', 'attack-techniques.json');

function parseArgs(argv) {
  const opts = { quiet: false, strict: false };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--quiet' || a === '-q') opts.quiet = true;
    else if (a === '--strict') opts.strict = true;
    else if (a === '--help' || a === '-h') {
      console.log(
        'Usage: node lib/validate-playbooks.js [--quiet] [--strict]\n' +
          '\n' +
          '  --quiet   Suppress per-playbook PASS output; show failures only.\n' +
          '  --strict  Treat warnings as errors (v0.13.0 preview).\n',
      );
      process.exit(0);
    } else {
      console.error(`Unknown argument: ${a}`);
      process.exit(2);
    }
  }
  return opts;
}

function readJson(p) {
  return JSON.parse(fs.readFileSync(p, 'utf8'));
}

function readJsonIfExists(p) {
  if (!fs.existsSync(p)) return null;
  return readJson(p);
}

function typeOf(value) {
  if (value === null) return 'null';
  if (Array.isArray(value)) return 'array';
  return typeof value;
}

function typeMatches(value, expected) {
  if (Array.isArray(expected)) return expected.some((t) => typeMatches(value, t));
  const actual = typeOf(value);
  if (expected === 'integer') return actual === 'number' && Number.isInteger(value);
  return actual === expected;
}

/* Inline JSON-Schema subset validator. Returns a flat list of finding objects
 * shaped as { severity, message }. Severity defaults to 'error'; enum
 * mismatches and unknown additional properties under
 * additionalProperties:false are downgraded to 'warning' so vocabulary drift
 * between the schema and shipped playbooks does not hard-fail v0.12.12.
 * v0.13.0 will flip via --strict / predeploy informational:false. */
function validate(value, schema, schemaName, pathStr) {
  const findings = [];
  const here = pathStr || schemaName;
  const err = (message, severity = 'error') => findings.push({ severity, message });

  if (schema.type !== undefined) {
    if (!typeMatches(value, schema.type)) {
      err(`${here}: expected type ${JSON.stringify(schema.type)}, got ${typeOf(value)}`);
      return findings;
    }
  }

  if (schema.enum !== undefined) {
    if (!schema.enum.includes(value)) {
      // Enum drift is downgraded to a warning so vocabulary-evolution does
      // not break patch-class releases.
      err(
        `${here}: value ${JSON.stringify(value)} not in enum ${JSON.stringify(schema.enum)}`,
        'warning',
      );
    }
  }

  const t = typeOf(value);

  if (t === 'string') {
    if (schema.minLength !== undefined && value.length < schema.minLength) {
      err(`${here}: string shorter than minLength ${schema.minLength}`);
    }
    if (schema.pattern !== undefined) {
      const re = new RegExp(schema.pattern);
      if (!re.test(value)) {
        err(`${here}: string ${JSON.stringify(value)} does not match pattern /${schema.pattern}/`);
      }
    }
    if (schema.format === 'uri') {
      try {
        new URL(value);
      } catch {
        err(`${here}: value ${JSON.stringify(value)} is not a valid URI`);
      }
    }
    if (schema.format === 'date') {
      if (!/^\d{4}-\d{2}-\d{2}$/.test(value)) {
        err(`${here}: value ${JSON.stringify(value)} is not an ISO date (YYYY-MM-DD)`);
      }
    }
  }

  if (t === 'number') {
    if (schema.minimum !== undefined && value < schema.minimum) {
      err(`${here}: value ${value} < minimum ${schema.minimum}`);
    }
    if (schema.maximum !== undefined && value > schema.maximum) {
      err(`${here}: value ${value} > maximum ${schema.maximum}`);
    }
  }

  if (t === 'array') {
    if (schema.minItems !== undefined && value.length < schema.minItems) {
      err(`${here}: array shorter than minItems ${schema.minItems}`);
    }
    if (schema.items !== undefined) {
      value.forEach((item, idx) => {
        findings.push(...validate(item, schema.items, schemaName, `${here}[${idx}]`));
      });
    }
  }

  if (t === 'object') {
    if (schema.required) {
      for (const req of schema.required) {
        if (!(req in value)) {
          err(`${here}: missing required field "${req}"`);
        }
      }
    }
    if (schema.minProperties !== undefined && Object.keys(value).length < schema.minProperties) {
      err(`${here}: object has fewer than ${schema.minProperties} properties`);
    }
    const props = schema.properties || {};
    const allowAdditional = schema.additionalProperties !== false;
    const addlSchema =
      typeof schema.additionalProperties === 'object' ? schema.additionalProperties : null;
    for (const [k, v] of Object.entries(value)) {
      if (k in props) {
        findings.push(...validate(v, props[k], schemaName, `${here}.${k}`));
      } else if (addlSchema) {
        findings.push(...validate(v, addlSchema, schemaName, `${here}.${k}`));
      } else if (!allowAdditional) {
        // Drift between schema and shipped data: surface as warning, not
        // an error. v0.13.0 will flip these.
        err(`${here}: unexpected property "${k}"`, 'warning');
      }
    }
  }

  return findings;
}

function loadContext() {
  const manifest = readJson(MANIFEST_PATH);
  const atlas = readJson(ATLAS_PATH);
  const cve = readJson(CVE_PATH);
  const cwe = readJson(CWE_PATH);
  const d3 = readJson(D3FEND_PATH);
  const attack = readJsonIfExists(ATTACK_PATH);

  return {
    skillKeys: new Set(manifest.skills.map((s) => s.name)),
    atlasKeys: new Set(Object.keys(atlas).filter((k) => !k.startsWith('_'))),
    cveKeys: new Set(Object.keys(cve).filter((k) => !k.startsWith('_'))),
    cweKeys: new Set(Object.keys(cwe).filter((k) => !k.startsWith('_'))),
    d3fendKeys: new Set(Object.keys(d3).filter((k) => !k.startsWith('_'))),
    attackKeys: attack
      ? new Set(Object.keys(attack).filter((k) => !k.startsWith('_')))
      : null,
  };
}

function loadPlaybooks() {
  if (!fs.existsSync(PLAYBOOKS_DIR)) return [];
  const out = [];
  for (const f of fs.readdirSync(PLAYBOOKS_DIR)) {
    if (!f.endsWith('.json')) continue;
    const p = path.join(PLAYBOOKS_DIR, f);
    const entry = { file: f, path: p };
    try {
      entry.data = readJson(p);
    } catch (e) {
      entry.parseError = e.message;
    }
    out.push(entry);
  }
  return out;
}

function obligationKey(o) {
  // The schema does not define an explicit `id` field on
  // jurisdiction_obligations entries; the shipped playbooks reference them
  // by the composite "<jurisdiction>/<regulation> <window_hours>h" string.
  return `${o.jurisdiction}/${o.regulation} ${o.window_hours}h`;
}

function checkCrossRefs(playbook, ctx, playbookIds) {
  const findings = [];
  const meta = playbook._meta || {};
  const phases = playbook.phases || {};
  const domain = playbook.domain || {};
  const warn = (message) => findings.push({ severity: 'warning', message });
  const err = (message) => findings.push({ severity: 'error', message });

  for (const fi of meta.feeds_into || []) {
    if (fi && fi.playbook_id && !playbookIds.has(fi.playbook_id)) {
      warn(`_meta.feeds_into: unresolved playbook_id "${fi.playbook_id}"`);
    }
  }
  for (const m of meta.mutex || []) {
    if (m && !playbookIds.has(m)) {
      warn(`_meta.mutex: unresolved playbook_id "${m}"`);
    }
  }
  // Some playbooks may carry a legacy _meta.skill_chain[] (string list); the
  // canonical chain lives at phases.direct.skill_chain[].skill but we still
  // resolve a flat list if present, per the task brief.
  for (const s of meta.skill_chain || []) {
    if (typeof s === 'string' && !ctx.skillKeys.has(s)) {
      warn(`_meta.skill_chain: unresolved skill "${s}"`);
    }
  }

  const govern = phases.govern || {};
  for (const s of govern.skill_preload || []) {
    if (!ctx.skillKeys.has(s)) {
      warn(`phases.govern.skill_preload: unresolved skill "${s}"`);
    }
  }

  const direct = phases.direct || {};
  for (const sc of direct.skill_chain || []) {
    if (sc && sc.skill && !ctx.skillKeys.has(sc.skill)) {
      warn(`phases.direct.skill_chain: unresolved skill "${sc.skill}"`);
    }
  }

  for (const a of domain.atlas_refs || []) {
    if (!ctx.atlasKeys.has(a)) {
      warn(`domain.atlas_refs: unresolved "${a}" (not in data/atlas-ttps.json)`);
    }
  }
  for (const c of domain.cve_refs || []) {
    if (!ctx.cveKeys.has(c)) {
      warn(`domain.cve_refs: unresolved "${c}" (not in data/cve-catalog.json)`);
    }
  }
  for (const w of domain.cwe_refs || []) {
    if (!ctx.cweKeys.has(w)) {
      warn(`domain.cwe_refs: unresolved "${w}" (not in data/cwe-catalog.json)`);
    }
  }
  for (const d of domain.d3fend_refs || []) {
    if (!ctx.d3fendKeys.has(d)) {
      warn(`domain.d3fend_refs: unresolved "${d}" (not in data/d3fend-catalog.json)`);
    }
  }

  // Indicators: id uniqueness, attack_ref / atlas_ref / cve_ref resolution.
  const detect = phases.detect || {};
  const indIds = new Set();
  const indicators = detect.indicators || [];
  for (let i = 0; i < indicators.length; i++) {
    const ind = indicators[i];
    if (!ind || typeof ind !== 'object') continue;
    if (ind.id) {
      if (indIds.has(ind.id)) {
        err(
          `phases.detect.indicators[${i}]: duplicate indicator id "${ind.id}"`,
        );
      }
      indIds.add(ind.id);
    }
    if (ind.attack_ref && ctx.attackKeys && !ctx.attackKeys.has(ind.attack_ref)) {
      warn(
        `phases.detect.indicators[${i}].attack_ref: unresolved "${ind.attack_ref}" (not in data/attack-techniques.json)`,
      );
    }
    if (ind.atlas_ref && !ctx.atlasKeys.has(ind.atlas_ref)) {
      warn(
        `phases.detect.indicators[${i}].atlas_ref: unresolved "${ind.atlas_ref}" (not in data/atlas-ttps.json)`,
      );
    }
    if (ind.cve_ref && !ctx.cveKeys.has(ind.cve_ref)) {
      warn(
        `phases.detect.indicators[${i}].cve_ref: unresolved "${ind.cve_ref}" (not in data/cve-catalog.json)`,
      );
    }
  }

  // rwep_threshold ordering. Hard error — a misordered threshold actively
  // breaks the scoring path.
  const rwep = direct.rwep_threshold || {};
  if (
    typeof rwep.close === 'number' &&
    typeof rwep.monitor === 'number' &&
    typeof rwep.escalate === 'number'
  ) {
    if (!(rwep.close <= rwep.monitor && rwep.monitor <= rwep.escalate)) {
      err(
        `phases.direct.rwep_threshold: ordering violation — expected close <= monitor <= escalate, got close=${rwep.close} monitor=${rwep.monitor} escalate=${rwep.escalate}`,
      );
    }
    for (const [k, v] of [
      ['close', rwep.close],
      ['monitor', rwep.monitor],
      ['escalate', rwep.escalate],
    ]) {
      if (v < 0 || v > 100) {
        err(`phases.direct.rwep_threshold.${k}: ${v} outside 0..100`);
      }
    }
  }

  // notification_actions obligation_ref resolution.
  const obligationKeys = new Set(
    (govern.jurisdiction_obligations || []).map(obligationKey),
  );
  const close = phases.close || {};
  for (const [i, na] of (close.notification_actions || []).entries()) {
    if (!na || typeof na !== 'object') continue;
    if (na.obligation_ref && !obligationKeys.has(na.obligation_ref)) {
      warn(
        `phases.close.notification_actions[${i}].obligation_ref: unresolved "${na.obligation_ref}" — no matching govern.jurisdiction_obligations entry (synthesized as "<jurisdiction>/<regulation> <window_hours>h")`,
      );
    }
  }

  return findings;
}

/* Cross-playbook mutex-reciprocity check.
 *
 * `_meta.mutex` is a symmetric relation: if playbook A lists B, B must list A.
 * Asymmetry is a latent runner bug — the engine's mutex enforcement only
 * blocks concurrent execution from whichever side declared the conflict, so
 * an asymmetric declaration silently degrades to a race condition when the
 * undeclared side is started first.
 *
 * Emits one warning per asymmetric pair (keyed off the side that declares
 * the edge). v0.12.16 keeps this at warning severity per the patch-class
 * cadence; v0.13.0 will flip it to error via --strict / predeploy
 * `informational: false`.
 */
function checkMutexReciprocity(playbooks) {
  const findings = [];
  const mutexMap = new Map();
  for (const pb of playbooks) {
    if (!pb.data || !pb.data._meta || !pb.data._meta.id) continue;
    const id = pb.data._meta.id;
    const mutex = Array.isArray(pb.data._meta.mutex) ? pb.data._meta.mutex : [];
    mutexMap.set(id, new Set(mutex));
  }
  const byPlaybook = new Map(); // playbookId -> array of warning messages
  for (const [id, mset] of mutexMap.entries()) {
    for (const other of mset) {
      const otherSet = mutexMap.get(other);
      if (!otherSet) continue; // unresolved-id warning is already emitted by checkCrossRefs
      if (!otherSet.has(id)) {
        const msg = `_meta.mutex: asymmetric mutex with "${other}" — "${other}" does not list "${id}" in its _meta.mutex. v0.13.0 will flip this to a hard error.`;
        if (!byPlaybook.has(id)) byPlaybook.set(id, []);
        byPlaybook.get(id).push(msg);
      }
    }
  }
  findings.push(byPlaybook);
  return byPlaybook;
}

function main() {
  const opts = parseArgs(process.argv);
  const schema = readJson(SCHEMA_PATH);
  const ctx = loadContext();
  const playbooks = loadPlaybooks();
  const playbookIds = new Set();
  for (const pb of playbooks) {
    if (pb.data && pb.data._meta && pb.data._meta.id) {
      playbookIds.add(pb.data._meta.id);
    }
  }
  const mutexAsymmetries = checkMutexReciprocity(playbooks);

  let errored = 0;
  let warned = 0;
  for (const pb of playbooks) {
    const label = pb.data && pb.data._meta && pb.data._meta.id
      ? pb.data._meta.id
      : pb.file;
    if (pb.parseError) {
      errored++;
      console.log(`FAIL  ${label}`);
      console.log(`        - [error] JSON parse error: ${pb.parseError}`);
      continue;
    }
    const findings = [
      ...validate(pb.data, schema, 'playbook', label),
      ...checkCrossRefs(pb.data, ctx, playbookIds),
    ];
    const reciprocityMsgs =
      (pb.data && pb.data._meta && mutexAsymmetries.get(pb.data._meta.id)) || [];
    for (const m of reciprocityMsgs) findings.push({ severity: 'warning', message: m });
    const effective = opts.strict
      ? findings.map((f) => ({ ...f, severity: 'error' }))
      : findings;
    const errs = effective.filter((f) => f.severity === 'error');
    const warns = effective.filter((f) => f.severity === 'warning');
    if (errs.length === 0 && warns.length === 0) {
      if (!opts.quiet) console.log(`PASS  ${label}`);
      continue;
    }
    if (errs.length === 0) {
      warned++;
      if (!opts.quiet) console.log(`WARN  ${label}`);
      for (const f of warns) console.log(`        - [warn] ${f.message}`);
    } else {
      errored++;
      console.log(`FAIL  ${label}`);
      for (const f of errs) console.log(`        - [error] ${f.message}`);
      for (const f of warns) console.log(`        - [warn]  ${f.message}`);
    }
  }

  const total = playbooks.length;
  const passed = total - errored - warned;
  console.log(
    `\n${passed}/${total} playbooks validated` +
      (warned ? `, ${warned} with warnings` : '') +
      (errored ? `, ${errored} failed` : '') + '.',
  );
  process.exit(errored === 0 ? 0 : 1);
}

module.exports = {
  validate,
  checkCrossRefs,
  checkMutexReciprocity,
  loadContext,
  loadPlaybooks,
  obligationKey,
};

if (require.main === module) {
  main();
}
