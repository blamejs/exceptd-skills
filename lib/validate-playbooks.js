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
 *   - domain.attack_refs[]            → data/attack-techniques.json keys
 *   - domain.cve_refs[]               → data/cve-catalog.json keys
 *   - domain.cwe_refs[]               → data/cwe-catalog.json keys
 *   - domain.d3fend_refs[]            → data/d3fend-catalog.json keys
 *   - phases.detect.indicators[].attack_ref → data/attack-techniques.json
 *   - phases.detect.indicators[].atlas_ref  → data/atlas-ttps.json
 *   - phases.detect.indicators[].cve_ref    → data/cve-catalog.json
 *   - phases.detect.false_positive_profile[].indicator_id
 *                                     → phases.detect.indicators[].id
 *   - directives[].applies_to.cve     → data/cve-catalog.json keys
 *   - directives[].applies_to.atlas_ttp → data/atlas-ttps.json keys
 *   - directives[].applies_to.attack_technique → data/attack-techniques.json
 *   - directives[].phase_overrides.govern.jurisdiction_obligations[].clock_starts
 *                                     → closed clock_starts vocabulary
 *   - directives[].phase_overrides.direct.rwep_threshold → ordering + range
 *   - directives[].phase_overrides.close.notification_actions[].obligation_ref
 *                                     → effective jurisdiction_obligations
 *
 * Internal consistency:
 *   - Indicator ids are unique within a playbook.
 *   - Every playbook maps to at least one TTP via domain.atlas_refs or
 *     domain.attack_refs (the cross-cutting correlation layer is exempt).
 *   - When _meta.air_gap_mode is true, network-sourced look.artifacts carry
 *     a non-empty air_gap_alternative (error if missing).
 *   - Closed controlled vocabularies (jurisdiction_obligations[].clock_starts,
 *     domain.frameworks_in_scope[]) are enforced at error severity, unlike the
 *     evolving-drift enums (artifact/indicator `type`) which stay warnings.
 *   - rwep_threshold ordering: close <= monitor <= escalate, each in 0..100.
 *   - close.notification_actions[].obligation_ref resolves to a synthesized
 *     "<jurisdiction>/<regulation> <window_hours>h" key from
 *     govern.jurisdiction_obligations[] (the schema does not give
 *     jurisdiction_obligations an explicit `id` field; the shipped playbooks
 *     reference them by this composite string).
 *   - _meta.mutex is symmetric across the whole playbook set: if A lists B,
 *     B must list A. Asymmetry surfaces as a warning by default (promoted to
 *     an error under --strict) — see checkMutexReciprocity().
 *
 * Finding severity:
 *   - error   — structural problems that block the runner (missing required
 *               field, JSON parse error, internal ordering violation,
 *               duplicate indicator id).
 *   - warning — schema-shape drift the runner can still tolerate (enum
 *               vocabulary lag, cross-catalog refs introduced after the
 *               playbook last shipped). Surfaced to the operator without
 *               failing the gate by default; promoted to hard errors under
 *               --strict (predeploy `informational: false`).
 *
 * Exit code: 0 if no errors (warnings allowed), 1 if any errors, 2 on
 *            argv error.
 *
 * Usage:
 *   node lib/validate-playbooks.js          validate every playbook
 *   node lib/validate-playbooks.js --quiet  only print FAIL playbooks + summary
 *   node lib/validate-playbooks.js --strict treat warnings as errors (used by
 *                                           the predeploy gate).
 */

'use strict';

const fs = require('node:fs');
const path = require('node:path');
const process = require('node:process');
const { safeExit } = require('./exit-codes');

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
 * between the schema and shipped playbooks does not hard-fail by default.
 * Promoted to errors under --strict / predeploy informational:false. */
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
        // an error. Promoted to an error under --strict.
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
  // Required, like the other ref catalogs (cwe / d3fend). It is committed and
  // always present; loading it optionally let attack_ref validation skip
  // silently when it was absent — the asymmetry that allowed an unresolvable
  // attack_ref to ship. Its absence must fail loud.
  const attack = readJson(ATTACK_PATH);

  // Closed controlled-vocabulary enums sourced from the schema so the
  // hard-error enum checks in checkCrossRefs stay in lockstep with the
  // schema's own enum lists. A typo'd clock_starts must hard-fail the
  // predeploy gate (it changes when a notification clock starts ticking),
  // so unlike evolving-drift enums (artifact/indicator `type`) these are
  // promoted to error severity rather than left as generic-validator
  // warnings.
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
    // The playbook schema is a committed, required file. Swallowing a read error
    // here silently disabled the clock_starts / frameworks_in_scope closed-vocab
    // checks, so a typo in those fields could ship. Fail loud instead.
    throw new Error(`validate-playbooks: cannot read playbook schema ${SCHEMA_PATH} — ${e && e.message}. The closed-vocabulary checks must not silently disable.`);
  }
  // A successful parse with the wrong shape (enum path moved/renamed) would also
  // leave the enums null and disable the checks. Treat that as fatal too.
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
  // Hard Rule #4 ("no orphaned controls"): domain.attack_refs must resolve to
  // the ATT&CK technique catalog, mirroring the atlas_refs block above and the
  // detect.indicators[].attack_ref check below. Without this, every TTP listed
  // at the domain level bypassed catalog cross-referencing.
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

  // false_positive_profile[].indicator_id must reference a real indicator id.
  // A dangling reference means an FP-distinguishing test is wired to nothing,
  // so the runner can never apply it. Warning severity (vocabulary-style
  // drift, not a structural break).
  for (const [i, fp] of (detect.false_positive_profile || []).entries()) {
    if (!fp || typeof fp !== 'object') continue;
    if (fp.indicator_id && !indIds.has(fp.indicator_id)) {
      warn(
        `phases.detect.false_positive_profile[${i}].indicator_id: unresolved "${fp.indicator_id}" — no matching phases.detect.indicators[].id`,
      );
    }
  }

  // validate.remediation_paths[].for_signals[] must reference real indicator
  // ids. A dangling ref silently never matches, so selected_remediation falls
  // back to priority-1 without surfacing the intended finding-specific link —
  // exactly the kind of "looks wired, does nothing" drift this gate exists to
  // catch. Warning severity (promoted to a hard error under --strict, matching
  // the false_positive_profile precedent above).
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

  // rwep_threshold ordering. Hard error — a misordered threshold actively
  // breaks the scoring path. Factored into a helper so the same check runs
  // against the playbook-level direct phase AND any directive-level
  // phase_overrides.direct copy the runner deep-merges at run time.
  checkRwepThreshold(direct.rwep_threshold, 'phases.direct.rwep_threshold');

  // clock_starts closed-vocab against the base govern phase. Factored into a
  // helper for the same reason — an override-supplied jurisdiction_obligations
  // copy must pass the same closed-vocabulary gate.
  checkClockStarts(govern.jurisdiction_obligations, 'phases.govern.jurisdiction_obligations');

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

  // Escalation / feeds_into condition path-root resolvability. The
  // analyze-phase escalation context resolves the flat keys (rwep,
  // blast_radius_score, theater_verdict, agent signals) plus the `analyze`
  // and `finding` roots; close()'s feeds_into context additionally resolves
  // `validate` and `theater_score`. A dotted path rooted at any OTHER phase
  // name can never resolve at evaluation time — the condition would
  // silently never fire — so it is rejected here. Bare (un-dotted)
  // identifiers are agent-signal names, an open vocabulary, and are not
  // checked.
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

  // Air-gap completeness. When _meta.air_gap_mode is true the runner refuses
  // to touch the network, so every artifact whose source is a network call
  // (https://, http://, gh api, gh release, curl, wget, fetch) MUST carry a
  // non-empty air_gap_alternative or the run is silently incomplete. The
  // schema encodes this as an allOf/if/then block, but the inline validator
  // does not implement conditional keywords, so it is enforced imperatively
  // here at error severity.
  if (meta.air_gap_mode === true) {
    const look = phases.look || {};
    // Case-insensitive + word-bounded so `HTTPS://`, `Curl`, and `fetch(` (no
    // trailing space) still flag a network source — otherwise an artifact could
    // ship under air_gap_mode with no offline alternative and run incomplete.
    const netSourceRe = /(https?:\/\/|\bgh (?:api|release)\b|\bcurl\b|\bwget\b|\bfetch\b)/i;
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

  // TTP-mapping floor (Hard Rule #4): every playbook must map to at least one
  // adversary technique via domain.atlas_refs OR domain.attack_refs. The sole
  // exemption is the cross-cutting correlation layer (_meta.scope ===
  // "cross-cutting"), which has no first-party TTPs — it correlates findings
  // produced by the other playbooks. Error severity for everything else.
  const atlasCount = (domain.atlas_refs || []).length;
  const attackCount = (domain.attack_refs || []).length;
  if (atlasCount === 0 && attackCount === 0 && meta.scope !== 'cross-cutting') {
    err(
      'domain: no TTP mapping — at least one of domain.atlas_refs or domain.attack_refs must be non-empty (cross-cutting correlation playbooks are exempt)',
    );
  }

  // frameworks_in_scope closed vocabulary. A value outside the schema's closed
  // enum is an error, not a warning, so a typo cannot ship — frameworks_in_scope
  // drives gap-analysis routing.
  if (ctx.frameworksEnum) {
    for (const [i, f] of (domain.frameworks_in_scope || []).entries()) {
      if (typeof f === 'string' && !ctx.frameworksEnum.has(f)) {
        err(
          `domain.frameworks_in_scope[${i}]: invalid value ${JSON.stringify(f)} — not in closed vocabulary`,
        );
      }
    }
  }

  // Directive-level coverage. A directive's applies_to fields and its
  // phase_overrides both reach the runner live (the runner selects directives
  // by id, deep-merges phase_overrides into the base phase, and surfaces
  // applies_to in the discovery API) but neither was cross-referenced or
  // re-validated — so a stale CVE/TTP reference or a tampered override
  // (bogus clock_starts, out-of-range rwep_threshold) shipped past this gate
  // even though the identical content is a hard error at playbook level.
  for (const [i, d] of (playbook.directives || []).entries()) {
    if (!d || typeof d !== 'object') continue;
    const label = d.id ? `directives[${i}] (${d.id})` : `directives[${i}]`;

    // applies_to.{cve,atlas_ttp,attack_technique} resolution, mirroring the
    // domain-ref checks at warning severity (promoted to error under --strict).
    const at = d.applies_to;
    if (at && typeof at === 'object') {
      if (at.cve && !ctx.cveKeys.has(at.cve)) {
        warn(`${label}.applies_to.cve: unresolved "${at.cve}" (not in data/cve-catalog.json)`);
      }
      if (at.atlas_ttp && !ctx.atlasKeys.has(at.atlas_ttp)) {
        warn(`${label}.applies_to.atlas_ttp: unresolved "${at.atlas_ttp}" (not in data/atlas-ttps.json)`);
      }
      // Guard the attack catalog the same way domain.attack_refs does:
      // attack-techniques.json is loaded via readJsonIfExists and may be null.
      if (at.attack_technique && ctx.attackKeys && !ctx.attackKeys.has(at.attack_technique)) {
        warn(`${label}.applies_to.attack_technique: unresolved "${at.attack_technique}" (not in data/attack-techniques.json)`);
      }
    }

    // phase_overrides re-validation. The runner merges these into the base
    // phase before govern()/close() consume them, so an override-supplied
    // clock_starts or rwep_threshold must pass the same gates as the base
    // phase or the regulatory clock / scoring path breaks at run time.
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
      // An override-supplied notification obligation_ref must resolve against
      // the EFFECTIVE obligation set the runner sees after the merge: the
      // base govern obligations, plus any the override adds. Warning severity,
      // matching the base-phase obligation_ref precedent.
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

  // ---- local helpers (hoisted; close over `findings`/`ctx`/`err`) ----

  // rwep_threshold ordering + range. close <= monitor <= escalate, each in
  // 0..100. Error severity — a misordered or out-of-range threshold actively
  // breaks the scoring path. `pathPrefix` keeps the message accurate whether
  // the source is the base phase or a directive override.
  function checkRwepThreshold(rwepObj, pathPrefix) {
    const rwep = rwepObj || {};
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
      for (const [k, v] of [
        ['close', rwep.close],
        ['monitor', rwep.monitor],
        ['escalate', rwep.escalate],
      ]) {
        if (v < 0 || v > 100) {
          err(`${pathPrefix}.${k}: ${v} outside 0..100`);
        }
      }
    }
  }

  // clock_starts closed-vocabulary check over a jurisdiction_obligations list.
  // Error severity — clock_starts decides when a notification deadline starts
  // counting; an out-of-vocabulary value silently never starts the clock.
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

/* Cross-playbook mutex-reciprocity check.
 *
 * `_meta.mutex` is a symmetric relation: if playbook A lists B, B must list A.
 * Asymmetry is a latent runner bug — the engine's mutex enforcement only
 * blocks concurrent execution from whichever side declared the conflict, so
 * an asymmetric declaration silently degrades to a race condition when the
 * undeclared side is started first.
 *
 * Emits one warning per asymmetric pair (keyed off the side that declares
 * the edge). Kept at warning severity by default per the patch-class
 * cadence; promoted to an error under --strict / predeploy
 * `informational: false`.
 */
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
