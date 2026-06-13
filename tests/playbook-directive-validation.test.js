'use strict';
/**
 * tests/playbook-directive-validation.test.js
 *
 * Locks two directive-level validation gaps that previously let bad content
 * ship past the predeploy gate, even though the identical content is a hard
 * error at playbook level:
 *
 *   A. directives[].applies_to.{cve,atlas_ttp,attack_technique} are now
 *      cross-referenced to their catalogs (warning; error under --strict).
 *   B. directives[].phase_overrides re-validates its govern.clock_starts and
 *      direct.rwep_threshold copies — the runner deep-merges these into the
 *      base phase at run time, so a bogus override must be rejected pre-ship.
 *
 * Pattern: load the live context, deep-clone a shipped playbook, mutate
 * exactly one directive field, and assert the exact severity + message.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const { spawnSync } = require('node:child_process');

const ROOT = path.join(__dirname, '..');
const VALIDATOR = path.join(ROOT, 'lib', 'validate-playbooks.js');
const { checkCrossRefs, loadContext, loadPlaybooks } = require(VALIDATOR);

function ctxAndIds() {
  const ctx = loadContext();
  const playbooks = loadPlaybooks();
  const ids = new Set(playbooks.filter((p) => p.data).map((p) => p.data._meta.id));
  return { ctx, ids };
}

function goodKernel() {
  return JSON.parse(
    fs.readFileSync(path.join(ROOT, 'data', 'playbooks', 'kernel.json'), 'utf8'),
  );
}

function severities(findings, sev) {
  return findings.filter((f) => f.severity === sev);
}

// ---------- control ----------

test('shipped kernel directives produce zero directive-coverage findings', () => {
  const { ctx, ids } = ctxAndIds();
  const findings = checkCrossRefs(goodKernel(), ctx, ids).filter((f) =>
    /directives\[/.test(f.message),
  );
  assert.deepEqual(
    findings,
    [],
    'unmutated shipped directives must produce no directive-coverage findings; got:\n' +
      findings.map((f) => `  [${f.severity}] ${f.message}`).join('\n'),
  );
});

// ---------- A. applies_to cross-reference ----------

test('directive applies_to.cve unresolved → warning naming the directive path', () => {
  const { ctx, ids } = ctxAndIds();
  const pb = goodKernel();
  pb.directives[0].applies_to = { cve: 'CVE-0000-00000' };
  const findings = checkCrossRefs(pb, ctx, ids);
  const matched = findings.filter((f) =>
    /directives\[0\].*applies_to\.cve: unresolved "CVE-0000-00000"/.test(f.message),
  );
  assert.equal(matched.length, 1, 'exactly one applies_to.cve finding');
  assert.equal(matched[0].severity, 'warning');

  // Good form: a resolvable cve is silent.
  const good = goodKernel();
  good.directives[0].applies_to = { cve: 'CVE-2024-3094' };
  const clean = checkCrossRefs(good, ctx, ids).filter((f) =>
    /applies_to\.cve/.test(f.message),
  );
  assert.deepEqual(clean, [], 'resolvable applies_to.cve must be silent');
});

test('directive applies_to.atlas_ttp unresolved → warning', () => {
  const { ctx, ids } = ctxAndIds();
  const pb = goodKernel();
  pb.directives[0].applies_to = { atlas_ttp: 'AML.T9999' };
  const findings = checkCrossRefs(pb, ctx, ids);
  const matched = findings.filter((f) =>
    /directives\[0\].*applies_to\.atlas_ttp: unresolved "AML\.T9999"/.test(f.message),
  );
  assert.equal(matched.length, 1);
  assert.equal(matched[0].severity, 'warning');
});

test('directive applies_to.attack_technique unresolved → warning', () => {
  const { ctx, ids } = ctxAndIds();
  const pb = goodKernel();
  pb.directives[0].applies_to = { attack_technique: 'T9999999' };
  const findings = checkCrossRefs(pb, ctx, ids);
  const matched = findings.filter((f) =>
    /directives\[0\].*applies_to\.attack_technique: unresolved "T9999999"/.test(f.message),
  );
  assert.equal(matched.length, 1);
  assert.equal(matched[0].severity, 'warning');
});

test('directive applies_to.attack_technique with a null attack catalog → no finding', () => {
  // Mirror domain.attack_refs: when the ATT&CK catalog is absent (null), the
  // check must not fire (it cannot resolve anything).
  const { ctx, ids } = ctxAndIds();
  ctx.attackKeys = null;
  const pb = goodKernel();
  pb.directives[0].applies_to = { attack_technique: 'T9999999' };
  const findings = checkCrossRefs(pb, ctx, ids).filter((f) =>
    /applies_to\.attack_technique/.test(f.message),
  );
  assert.deepEqual(findings, [], 'null attack catalog must suppress the attack_technique check');
});

// ---------- B. phase_overrides re-validation ----------

test('phase_overrides.govern bogus clock_starts → error naming the override path', () => {
  const { ctx, ids } = ctxAndIds();
  const pb = goodKernel();
  pb.directives[0].phase_overrides = {
    govern: {
      jurisdiction_obligations: [
        { jurisdiction: 'EU', regulation: 'NIS2', window_hours: 24, clock_starts: 'TOTALLY_BOGUS' },
      ],
    },
  };
  const findings = checkCrossRefs(pb, ctx, ids);
  const matched = findings.filter((f) =>
    /directives\[0\].*phase_overrides\.govern\.jurisdiction_obligations\[0\]\.clock_starts: invalid value "TOTALLY_BOGUS"/.test(
      f.message,
    ),
  );
  assert.equal(matched.length, 1, 'exactly one override clock_starts error');
  assert.equal(matched[0].severity, 'error', 'override clock_starts is an error, like the base phase');
});

test('phase_overrides.direct rwep_threshold ordering violation → error naming the override path', () => {
  const { ctx, ids } = ctxAndIds();
  const pb = goodKernel();
  pb.directives[0].phase_overrides = {
    direct: { rwep_threshold: { close: 90, monitor: 50, escalate: 10 } },
  };
  const findings = checkCrossRefs(pb, ctx, ids);
  const matched = findings.filter((f) =>
    /directives\[0\].*phase_overrides\.direct\.rwep_threshold: ordering violation/.test(f.message),
  );
  assert.equal(matched.length, 1, 'exactly one override rwep ordering error');
  assert.equal(matched[0].severity, 'error');
});

test('phase_overrides.direct rwep_threshold out-of-range → error naming the override path', () => {
  const { ctx, ids } = ctxAndIds();
  const pb = goodKernel();
  pb.directives[0].phase_overrides = {
    direct: { rwep_threshold: { close: 10, monitor: 50, escalate: 999 } },
  };
  const findings = checkCrossRefs(pb, ctx, ids);
  const matched = findings.filter((f) =>
    /directives\[0\].*phase_overrides\.direct\.rwep_threshold\.escalate: 999 outside 0\.\.100/.test(
      f.message,
    ),
  );
  assert.equal(matched.length, 1);
  assert.equal(matched[0].severity, 'error');
});

test('a VALID phase_overrides still passes (no false positive)', () => {
  const { ctx, ids } = ctxAndIds();
  const pb = goodKernel();
  pb.directives[0].phase_overrides = {
    govern: {
      jurisdiction_obligations: [
        { jurisdiction: 'EU', regulation: 'NIS2', window_hours: 24, clock_starts: 'detect_confirmed' },
      ],
    },
    direct: { rwep_threshold: { close: 25, monitor: 45, escalate: 75 } },
  };
  const findings = checkCrossRefs(pb, ctx, ids).filter((f) =>
    /phase_overrides/.test(f.message),
  );
  assert.deepEqual(findings, [], 'a valid override must produce no override findings');
  assert.equal(severities(findings, 'error').length, 0);
});

// ---------- end-to-end: predeploy --strict fails on a tampered override ----------

function stageMirror(tmp) {
  // Mirror just enough of the tree for the validator to load context + the
  // single synthetic playbook. lib/, data catalogs, manifest, schema.
  fs.mkdirSync(path.join(tmp, 'lib', 'schemas'), { recursive: true });
  fs.mkdirSync(path.join(tmp, 'data', 'playbooks'), { recursive: true });
  const copy = (rel) => fs.copyFileSync(path.join(ROOT, rel), path.join(tmp, rel));
  copy('lib/validate-playbooks.js');
  copy('lib/exit-codes.js');
  copy('lib/schemas/playbook.schema.json');
  copy('manifest.json');
  for (const f of ['atlas-ttps.json', 'cve-catalog.json', 'cwe-catalog.json', 'd3fend-catalog.json', 'attack-techniques.json']) {
    fs.copyFileSync(path.join(ROOT, 'data', f), path.join(tmp, 'data', f));
  }
}

test('--strict fails the predeploy gate on a tampered directive override', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'playbook-directive-override-'));
  try {
    stageMirror(tmp);
    const pb = goodKernel();
    pb.directives[0].phase_overrides = {
      govern: {
        jurisdiction_obligations: [
          { jurisdiction: 'EU', regulation: 'NIS2', window_hours: 24, clock_starts: 'TOTALLY_BOGUS' },
        ],
      },
    };
    fs.writeFileSync(
      path.join(tmp, 'data', 'playbooks', 'synthetic.json'),
      JSON.stringify(pb, null, 2),
    );
    const r = spawnSync(process.execPath, [path.join(tmp, 'lib', 'validate-playbooks.js'), '--strict'], {
      cwd: tmp,
      encoding: 'utf8',
    });
    assert.equal(r.status, 1, `expected exit 1 for the tampered override; got ${r.status}\n${r.stdout}\n${r.stderr}`);
    assert.match(r.stdout, /phase_overrides\.govern\.jurisdiction_obligations\[0\]\.clock_starts/);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});
