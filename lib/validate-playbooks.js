#!/usr/bin/env node
/*
 * lib/validate-playbooks.js — validates every data/playbooks/*.json against
 * lib/schemas/playbook.schema.json and resolves the cross-references it carries.
 * Findings are `error` (blocks the runner) or `warning` (tolerated drift);
 * --strict promotes every warning to an error. Exits 0 clean, 1 on any error,
 * 2 on an argv error.
 */

'use strict';

const fs = require('node:fs');
const path = require('node:path');
const process = require('node:process');
const { safeExit } = require('./exit-codes');
// The SAME parser the runner uses, so a condition the engine cannot parse is
// rejected here instead of silently returning false for every input. Required
// defensively: a stripped test mirror stages this validator without the engine.
let _evalCondition = null;
try { ({ _evalCondition } = require('./playbook-runner')); } catch { /* warned at the gate */ }

// Decompose a condition into leaf atoms the way evalCondition does. Checking each
// leaf independently catches a dead sub-clause: evalCondition short-circuits AND
// via `.every` and OR via `.some`, so a later clause never reports unparsed.
function _splitTopLevel(expr, sep) {
  const parts = []; const needle = ' ' + sep + ' ';
  let depth = 0, buf = '', i = 0, quote = null;
  while (i < expr.length) {
    const ch = expr[i];
    if (quote) { if (ch === '\\' && i + 1 < expr.length) { buf += ch + expr[i + 1]; i += 2; continue; } if (ch === quote) quote = null; buf += ch; i++; continue; }
    if (ch === "'" || ch === '"') { quote = ch; buf += ch; i++; continue; }
    if (ch === '(') { depth++; buf += ch; i++; continue; }
    if (ch === ')') { depth--; buf += ch; i++; continue; }
    if (depth === 0 && expr.startsWith(needle, i)) { parts.push(buf.trim()); buf = ''; i += needle.length; continue; }
    buf += ch; i++;
  }
  parts.push(buf.trim());
  return parts;
}
function _stripWrappingParens(e) {
  e = e.trim();
  while (e.startsWith('(') && e.endsWith(')')) {
    let d = 0, wraps = true;
    for (let i = 0; i < e.length; i++) {
      if (e[i] === '(') d++;
      else if (e[i] === ')') { d--; if (d === 0 && i < e.length - 1) { wraps = false; break; } }
    }
    if (wraps) e = e.slice(1, -1).trim(); else break;
  }
  return e;
}
function atomizeCondition(cond) {
  const atoms = [];
  (function rec(e) {
    e = _stripWrappingParens(e);
    const ors = _splitTopLevel(e, 'OR'); if (ors.length > 1) { ors.forEach(rec); return; }
    const ands = _splitTopLevel(e, 'AND'); if (ands.length > 1) { ands.forEach(rec); return; }
    atoms.push(e);
  })(cond);
  return atoms;
}

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
          '  --strict  Treat warnings as errors (used by the predeploy gate).\n',
      );
      safeExit(0);
      return null;
    } else {
      console.error(`Unknown argument: ${a}`);
      safeExit(2);
      return null;
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

// Strict ISO calendar check: the shape regex alone accepts impossible dates —
// `new Date('2026-02-30T00:00:00Z')` rolls over to March 2 — so the parsed Y-M-D
// must round-trip. Mirrors parseIsoDateStrict in lib/validate-catalog-meta.js.
function isStrictIsoDate(value) {
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(value)) return false;
  const d = new Date(value + 'T00:00:00Z');
  if (Number.isNaN(d.getTime())) return false;
  const [y, m, day] = value.split('-').map(Number);
  return (
    d.getUTCFullYear() === y &&
    d.getUTCMonth() + 1 === m &&
    d.getUTCDate() === day
  );
}

function typeMatches(value, expected) {
  if (Array.isArray(expected)) return expected.some((t) => typeMatches(value, t));
  const actual = typeOf(value);
  if (expected === 'integer') return actual === 'number' && Number.isInteger(value);
  return actual === expected;
}

/* Inline JSON-Schema subset validator. Returns a flat list of
 * { severity, message }: 'error' except enum mismatches and unknown properties
 * under additionalProperties:false, which are 'warning' so vocabulary drift does
 * not hard-fail outside --strict. */
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
      const re = new RegExp(schema.pattern); // allow:dynamic-regex — bundled schema.pattern, not operator input
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
      if (!isStrictIsoDate(value)) {
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
  // Required, not optional: an optional load skips attack_ref validation silently.
  const attack = readJson(ATTACK_PATH);

  // Sourced from the schema so the hard-error checks in checkCrossRefs stay in
  // lockstep with its enum lists.
  let clockStartsEnum = null;
  let frameworksEnum = null;
  try {
    const schema = readJson(SCHEMA_PATH);
    clockStartsEnum =
      schema.properties.phases.properties.govern.properties
        .jurisdiction_obligations.items.properties.clock_starts.enum || null;
    frameworksEnum =
      schema.properties.domain.properties.frameworks_in_scope.items.enum || null;
  } catch (e) {
    throw new Error(`validate-playbooks: cannot read playbook schema ${SCHEMA_PATH} — ${e && e.message}. The closed-vocabulary checks must not silently disable.`);
  }
  // A wrong-shape parse leaves the enums null and disables the checks, so it is
  // fatal too.
  if (!Array.isArray(clockStartsEnum) || !Array.isArray(frameworksEnum)) {
    throw new Error(`validate-playbooks: playbook schema ${SCHEMA_PATH} did not yield the clock_starts / frameworks_in_scope enums (shape changed). Refusing to validate with the closed-vocab checks silently disabled — fix the schema path expressions in loadContext().`);
  }

  return {
    skillKeys: new Set(manifest.skills.map((s) => s.name)),
    atlasKeys: new Set(Object.keys(atlas).filter((k) => !k.startsWith('_'))),
    cveKeys: new Set(Object.keys(cve).filter((k) => !k.startsWith('_'))),
    cweKeys: new Set(Object.keys(cwe).filter((k) => !k.startsWith('_'))),
    d3fendKeys: new Set(Object.keys(d3).filter((k) => !k.startsWith('_'))),
    attackKeys: attack
      ? new Set(Object.keys(attack).filter((k) => !k.startsWith('_')))
      : null,
    clockStartsEnum: clockStartsEnum ? new Set(clockStartsEnum) : null,
    frameworksEnum: frameworksEnum ? new Set(frameworksEnum) : null,
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
  // Obligations carry no `id`; playbooks reference one by this composite string.
  return `${o.jurisdiction}/${o.regulation} ${o.window_hours}h`;
}

function checkCrossRefs(playbook, ctx, playbookIds) {
  const findings = [];
  // validate() already emits the type error; returning empty keeps main()
  // reporting the FAIL instead of dying on `playbook._meta`.
  if (!playbook || typeof playbook !== 'object' || Array.isArray(playbook)) {
    return findings;
  }
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
  // _meta.skill_chain[] aliases the canonical phases.direct.skill_chain[].skill.
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
  // Hard Rule #4: domain-level TTPs resolve against the ATT&CK catalog.
  for (const a of domain.attack_refs || []) {
    if (ctx.attackKeys && !ctx.attackKeys.has(a)) {
      warn(`domain.attack_refs: unresolved "${a}" (not in data/attack-techniques.json)`);
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

  // A dangling indicator_id wires an FP test to nothing the runner can apply.
  for (const [i, fp] of (detect.false_positive_profile || []).entries()) {
    if (!fp || typeof fp !== 'object') continue;
    if (fp.indicator_id && !indIds.has(fp.indicator_id)) {
      warn(
        `phases.detect.false_positive_profile[${i}].indicator_id: unresolved "${fp.indicator_id}" — no matching phases.detect.indicators[].id`,
      );
    }
  }

  // A dangling for_signals never matches: selected_remediation falls back to
  // priority 1 without the finding-specific link.
  const validatePhase = phases.validate || {};
  for (const [i, rp] of (validatePhase.remediation_paths || []).entries()) {
    if (!rp || typeof rp !== 'object' || !Array.isArray(rp.for_signals)) continue;
    for (const sig of rp.for_signals) {
      if (!indIds.has(sig)) {
        warn(
          `phases.validate.remediation_paths[${i}] (${rp.id || 'unknown'}).for_signals: unresolved "${sig}" — no matching phases.detect.indicators[].id`,
        );
      }
    }
  }

  // Helpers, so the same checks run against a directive's phase_overrides copy.
  checkRwepThreshold(direct.rwep_threshold, 'phases.direct.rwep_threshold');

  checkClockStarts(govern.jurisdiction_obligations, 'phases.govern.jurisdiction_obligations');

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

  // The escalation context resolves the flat keys plus `analyze` and `finding`;
  // feeds_into also resolves `validate`. A dotted path rooted at any other phase
  // name never resolves. Bare identifiers are agent-signal names, not checked.
  const conditionPathRoots = (cond) => {
    if (typeof cond !== 'string') return [];
    const stripped = cond.replace(/'[^']*'|"[^"]*"|\/[^/\n]*\//g, ' ');
    const roots = [];
    const re = /(?<![.\w])([A-Za-z_][A-Za-z0-9_]*)(?:\.[A-Za-z_][A-Za-z0-9_]*)+/g;
    let m;
    while ((m = re.exec(stripped)) !== null) roots.push(m[1]);
    return roots;
  };
  const PHASE_NAME_ROOTS = new Set(['govern', 'direct', 'look', 'detect', 'analyze', 'validate', 'close']);
  const ESCALATION_OK_ROOTS = new Set(['analyze', 'finding']);
  const FEEDS_OK_ROOTS = new Set(['analyze', 'validate', 'finding']);
  for (const [i, ec] of (((phases.analyze || {}).escalation_criteria) || []).entries()) {
    if (!ec || typeof ec !== 'object') continue;
    for (const root of conditionPathRoots(ec.condition)) {
      if (PHASE_NAME_ROOTS.has(root) && !ESCALATION_OK_ROOTS.has(root)) {
        err(
          `phases.analyze.escalation_criteria[${i}].condition: path root "${root}." is not resolvable in the escalation context (phase-result roots available there: analyze, finding) — the condition would never fire`,
        );
      }
    }
  }
  for (const [i, f] of (meta.feeds_into || []).entries()) {
    if (!f || typeof f !== 'object') continue;
    for (const root of conditionPathRoots(f.condition)) {
      if (PHASE_NAME_ROOTS.has(root) && !FEEDS_OK_ROOTS.has(root)) {
        err(
          `_meta.feeds_into[${i}].condition: path root "${root}." is not resolvable in the feeds_into context (phase-result roots available there: analyze, validate, finding) — the condition would never fire`,
        );
      }
    }
  }

  // Parseability gate over the three places the runner threads a condition through
  // evalCondition: analyze escalation_criteria, _meta.feeds_into, and validate
  // remediation_paths preconditions. Only condition_unparsed gates: a parse failure
  // is input-independent, where condition_path_unresolved and
  // condition_type_mismatch are runtime diagnostics that false-positive here.
  if (!_evalCondition) {
    warn(
      'escalation/feeds_into/precondition parse-gate skipped: lib/playbook-runner.js (the condition evaluator) was not resolvable from this validator location, so condition parseability was not checked',
    );
  }
  const conditionParses = (cond) => {
    if (typeof cond !== 'string' || !cond.trim()) return true;
    if (!_evalCondition) return true; // engine unavailable — warned above, never a silent error-skip
    for (const atom of atomizeCondition(cond)) {
      const runErrors = [];
      try { _evalCondition(atom, { _runErrors: runErrors }, { _runErrors: runErrors }); }
      catch { continue; } // an evaluator throw is a separate concern, not "unparseable"
      if (runErrors.some((e) => e && e.kind === 'condition_unparsed')) return false;
    }
    return true;
  };
  for (const [i, ec] of (((phases.analyze || {}).escalation_criteria) || []).entries()) {
    if (ec && typeof ec === 'object' && !conditionParses(ec.condition)) {
      err(
        `phases.analyze.escalation_criteria[${i}].condition: not parseable by the runner's evalCondition (${JSON.stringify(String(ec.condition).slice(0, 80))}) — it returns false for every input, so action "${ec.action || '?'}" never fires. Rewrite into the mini-language (<indicator-id> == true [AND/OR …], engine roots rwep/blast_radius_score/matched_cve/finding.*, membership IN [...], quantifier any/all, matches '…').`,
      );
    }
  }
  for (const [i, f] of (meta.feeds_into || []).entries()) {
    if (f && typeof f === 'object' && !conditionParses(f.condition)) {
      err(
        `_meta.feeds_into[${i}].condition: not parseable by the runner's evalCondition (${JSON.stringify(String(f.condition).slice(0, 80))}) — the chain to "${f.playbook_id || '?'}" never fires. Rewrite into the mini-language.`,
      );
    }
  }
  for (const [i, rp] of (validatePhase.remediation_paths || []).entries()) {
    if (!rp || typeof rp !== 'object' || !Array.isArray(rp.preconditions)) continue;
    for (const [j, pc] of rp.preconditions.entries()) {
      if (!conditionParses(pc)) {
        err(
          `phases.validate.remediation_paths[${i}] (${rp.id || 'unknown'}).preconditions[${j}]: not parseable by the runner's evalCondition (${JSON.stringify(String(pc).slice(0, 80))}) — it is never satisfiable, so the path can only be selected as the priority fallback. Rewrite into the mini-language (bare token → "<token> == true", prose gate → an operator-signalable "<snake_token> == true").`,
        );
      }
    }
  }

  // Under _meta.air_gap_mode the runner refuses the network, so a network-sourced
  // artifact needs a non-empty air_gap_alternative. The schema states this as an
  // allOf/if/then block the inline validator does not implement.
  if (meta.air_gap_mode === true) {
    const look = phases.look || {};
    // `api/v\d` is deliberately not a token — it false-positives on local
    // code-scan artifacts that merely reference an API path. The same `source`
    // pattern lives in lib/schemas/playbook.schema.json and must be broadened
    // in lockstep with this one.
    const netSourceRe = /(https?:\/\/|\bgh (?:api|release)\b|\bcurl\b|\bwget\b|\bfetch\b|\b(?:GET|POST|PUT|PATCH|DELETE)\s+\/|\bGraph\b|\b(?:Okta|Entra ID|Microsoft Graph)\b)/i;
    for (const [i, art] of (look.artifacts || []).entries()) {
      if (!art || typeof art !== 'object') continue;
      if (typeof art.source === 'string' && netSourceRe.test(art.source)) {
        const alt = art.air_gap_alternative;
        if (typeof alt !== 'string' || alt.trim().length === 0) {
          err(
            `phases.look.artifacts[${i}]: _meta.air_gap_mode is true and source "${art.source}" makes a network call, but no non-empty air_gap_alternative is set — the artifact cannot be collected offline`,
          );
        }
      }
    }
  }

  // TTP-mapping floor (Hard Rule #4): every playbook maps to at least one
  // technique. The cross-cutting correlation layer has no first-party TTPs.
  const atlasCount = (domain.atlas_refs || []).length;
  const attackCount = (domain.attack_refs || []).length;
  if (atlasCount === 0 && attackCount === 0 && meta.scope !== 'cross-cutting') {
    err(
      'domain: no TTP mapping — at least one of domain.atlas_refs or domain.attack_refs must be non-empty (cross-cutting correlation playbooks are exempt)',
    );
  }

  // frameworks_in_scope drives gap-analysis routing, so a value outside the
  // schema's closed enum errors rather than warns.
  if (ctx.frameworksEnum) {
    for (const [i, f] of (domain.frameworks_in_scope || []).entries()) {
      if (typeof f === 'string' && !ctx.frameworksEnum.has(f)) {
        err(
          `domain.frameworks_in_scope[${i}]: invalid value ${JSON.stringify(f)} — not in closed vocabulary`,
        );
      }
    }
  }

  // Directives reach the runner live — phase_overrides deep-merged into the base
  // phase — so they face the same cross-reference and override checks.
  for (const [i, d] of (playbook.directives || []).entries()) {
    if (!d || typeof d !== 'object') continue;
    const label = d.id ? `directives[${i}] (${d.id})` : `directives[${i}]`;

    const at = d.applies_to;
    if (at && typeof at === 'object') {
      if (at.cve && !ctx.cveKeys.has(at.cve)) {
        warn(`${label}.applies_to.cve: unresolved "${at.cve}" (not in data/cve-catalog.json)`);
      }
      if (at.atlas_ttp && !ctx.atlasKeys.has(at.atlas_ttp)) {
        warn(`${label}.applies_to.atlas_ttp: unresolved "${at.atlas_ttp}" (not in data/atlas-ttps.json)`);
      }
      if (at.attack_technique && ctx.attackKeys && !ctx.attackKeys.has(at.attack_technique)) {
        warn(`${label}.applies_to.attack_technique: unresolved "${at.attack_technique}" (not in data/attack-techniques.json)`);
      }
    }

    // The runner merges these into the base phase, so an override-supplied
    // clock_starts or rwep_threshold must clear the same gates.
    const ov = d.phase_overrides;
    if (ov && typeof ov === 'object') {
      if (ov.govern && typeof ov.govern === 'object') {
        checkClockStarts(
          ov.govern.jurisdiction_obligations,
          `${label}.phase_overrides.govern.jurisdiction_obligations`,
        );
      }
      if (ov.direct && typeof ov.direct === 'object') {
        checkRwepThreshold(
          ov.direct.rwep_threshold,
          `${label}.phase_overrides.direct.rwep_threshold`,
        );
      }
      // Resolved against the effective set the runner sees after the merge: the
      // override's own obligations when it supplies them, else the base phase's.
      if (ov.close && typeof ov.close === 'object' && Array.isArray(ov.close.notification_actions)) {
        const overrideObligations =
          (ov.govern && Array.isArray(ov.govern.jurisdiction_obligations))
            ? ov.govern.jurisdiction_obligations
            : (govern.jurisdiction_obligations || []);
        const effectiveKeys = new Set(overrideObligations.map(obligationKey));
        for (const [j, na] of ov.close.notification_actions.entries()) {
          if (!na || typeof na !== 'object') continue;
          if (na.obligation_ref && !effectiveKeys.has(na.obligation_ref)) {
            warn(
              `${label}.phase_overrides.close.notification_actions[${j}].obligation_ref: unresolved "${na.obligation_ref}" — no matching jurisdiction_obligations entry (synthesized as "<jurisdiction>/<regulation> <window_hours>h")`,
            );
          }
        }
      }
    }
  }

  return findings;

  // Hoisted for the calls above; they close over `findings`, `ctx` and `err`.

  // close <= monitor <= escalate, each in 0..100. `pathPrefix` keeps the message
  // accurate for both the base phase and a directive override.
  function checkRwepThreshold(rwepObj, pathPrefix) {
    const rwep = rwepObj || {};
    // Per-key and independent: an override is a partial fragment, so gating the
    // range check on all three keys present lets `{escalate: 150}` through.
    for (const k of ['close', 'monitor', 'escalate']) {
      const v = rwep[k];
      if (typeof v === 'number' && (v < 0 || v > 100)) {
        err(`${pathPrefix}.${k}: ${v} outside 0..100`);
      }
    }
    // Ordering needs the full triple: a partial override inherits its missing edges.
    if (
      typeof rwep.close === 'number' &&
      typeof rwep.monitor === 'number' &&
      typeof rwep.escalate === 'number'
    ) {
      if (!(rwep.close <= rwep.monitor && rwep.monitor <= rwep.escalate)) {
        err(
          `${pathPrefix}: ordering violation — expected close <= monitor <= escalate, got close=${rwep.close} monitor=${rwep.monitor} escalate=${rwep.escalate}`,
        );
      }
    }
  }

  // clock_starts decides when a notification deadline begins counting; an
  // out-of-vocabulary value never starts the clock.
  function checkClockStarts(obligations, pathPrefix) {
    if (!ctx.clockStartsEnum || !Array.isArray(obligations)) return;
    for (const [i, o] of obligations.entries()) {
      if (!o || typeof o !== 'object') continue;
      if (o.clock_starts !== undefined && !ctx.clockStartsEnum.has(o.clock_starts)) {
        err(
          `${pathPrefix}[${i}].clock_starts: invalid value ${JSON.stringify(o.clock_starts)} — not in closed vocabulary ${JSON.stringify([...ctx.clockStartsEnum])}`,
        );
      }
    }
  }
}

/* `_meta.mutex` is symmetric: if playbook A lists B, B must list A. The engine
 * blocks concurrency only from the side that declared the conflict, so an
 * asymmetric declaration degrades to a race. Returns one warning per asymmetric
 * pair, keyed by the declaring playbook. */
function checkMutexReciprocity(playbooks) {
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
        const msg = `_meta.mutex: asymmetric mutex with "${other}" — "${other}" does not list "${id}" in its _meta.mutex. Promoted to a hard error under --strict.`;
        if (!byPlaybook.has(id)) byPlaybook.set(id, []);
        byPlaybook.get(id).push(msg);
      }
    }
  }
  return byPlaybook;
}

function main() {
  const opts = parseArgs(process.argv);
  if (opts === null) return; // parseArgs handled --help / bad-arg and set the exit code
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
  safeExit(errored === 0 ? 0 : 1);
  return;
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
