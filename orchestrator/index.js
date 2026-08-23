#!/usr/bin/env node
'use strict';

/**
 * exceptd orchestrator — CLI entry point. printHelp() below is the
 * authoritative verb and flag list.
 */

const fsMod = require('fs');
const osMod = require('os');
const pathMod = require('path');

const { scan } = require('./scanner');
const { dispatch, routeQuery, getSkillContext } = require('./dispatcher');
const { currencyCheck, initPipeline } = require('./pipeline');
const { bus, EVENT_TYPES } = require('./event-bus');
const { start: startScheduler, stop: stopScheduler, runCurrencyNow } = require('./scheduler');
const { EXIT_CODES, safeExit } = require('../lib/exit-codes');
const { withRetry } = require('../vendor/blamejs/retry.js');

const cmd = process.argv[2];
const args = process.argv.slice(3);

/**
 * Returns `{ flags: Set<string>, options: Map<string,string>, positionals:
 * string[] }`. A flag named in `optionFlags` consumes the following token (or an
 * `=value`) into `options`; every other `--flag` is a boolean in `flags`.
 */
function parseFlags(argv, optionFlags) {
  const optSet = new Set(optionFlags || []);
  const flags = new Set();
  const options = new Map();
  const positionals = [];
  for (let i = 0; i < argv.length; i++) {
    const tok = argv[i];
    if (typeof tok !== 'string') continue;
    if (tok.startsWith('--')) {
      const eq = tok.indexOf('=');
      if (eq !== -1) {
        const key = tok.slice(0, eq);
        const val = tok.slice(eq + 1);
        if (optSet.has(key)) options.set(key, val);
        else flags.add(tok);
      } else if (optSet.has(tok)) {
        const next = argv[i + 1];
        if (next !== undefined && !next.startsWith('--')) {
          options.set(tok, next);
          i++;
        } else {
          options.set(tok, '');
        }
      } else {
        flags.add(tok);
      }
    } else {
      positionals.push(tok);
    }
  }
  return { flags, options, positionals };
}

async function main() {
  switch (cmd) {
    case 'scan':
      await runScan();
      break;
    case 'dispatch':
      await runDispatch();
      break;
    case 'skill':
      runSkillContext(args);
      break;
    case 'pipeline': {
      // Reachable only through a direct orchestrator invocation. The guarded
      // parse turns malformed findings into an ok:false envelope.
      let findings = {};
      if (args[1]) {
        try {
          findings = JSON.parse(args[1]);
        } catch (err) {
          process.stdout.write(JSON.stringify({
            ok: false,
            verb: 'pipeline',
            error: `pipeline: findings argument is not valid JSON: ${err.message}`,
          }) + '\n');
          safeExit(EXIT_CODES.GENERIC_FAILURE);
          break;
        }
      }
      runPipeline(args[0] || 'manual', findings);
      break;
    }
    case 'currency':
      runCurrency();
      break;
    case 'report':
      // The first non-flag positional, so `report --json` does not read "--json"
      // as the format.
      await runReport(args.find((a) => typeof a === 'string' && !a.startsWith('--')) || 'technical');
      break;
    case 'watch':
      await runWatch();
      break;
    case 'validate-cves':
      await runValidateCves(args);
      break;
    case 'validate-rfcs':
      await runValidateRfcs(args);
      break;
    case 'watchlist':
      runWatchlist(args);
      break;
    case 'framework-gap':
    case 'framework-gap-analysis':
      runFrameworkGap(args);
      break;
    case 'help':
    default:
      printHelp();
  }
}

function runFrameworkGap(rawArgs) {
  const fs = require('fs');
  const path = require('path');
  const { gapReport, theaterCheck } = require('../lib/framework-gap');

  // Air-gap flags are accepted and ignored: this path reads local catalogs only.
  if (rejectUnknownFlags('framework-gap', rawArgs, ['--json', '--air-gap', '--offline', '--no-network'])) return;
  const args = rawArgs.filter(a => !a.startsWith('--'));
  const flags = new Set(rawArgs.filter(a => a.startsWith('--')));
  const jsonOut = flags.has('--json');

  if (args.length < 2) {
    const usage = `Usage: exceptd framework-gap <FRAMEWORK_ID|all> <SCENARIO|CVE-ID> [--json]
Examples:
  exceptd framework-gap NIST-800-53 CVE-2026-31431
  exceptd framework-gap PCI-DSS-4.0 "prompt injection"
  exceptd framework-gap all CVE-2025-53773 --json`;
    // A JSON consumer needs the ok:false envelope, not usage text on stderr.
    if (jsonOut) {
      process.stdout.write(JSON.stringify({
        ok: false,
        verb: 'framework-gap',
        error: 'framework-gap requires <FRAMEWORK_ID|all> and <SCENARIO|CVE-ID>',
        usage,
      }) + '\n');
    } else {
      console.error(usage);
    }
    // A usage error is GENERIC_FAILURE, never DETECTED_ESCALATE — exit 2 tells a
    // CI gate the verb ran and found something.
    safeExit(EXIT_CODES.GENERIC_FAILURE);
    return;
  }

  const root = path.join(__dirname, '..');
  let controlGaps, cveCatalog, lessons;
  try {
    controlGaps = JSON.parse(fs.readFileSync(path.join(root, 'data', 'framework-control-gaps.json'), 'utf8'));
    cveCatalog = JSON.parse(fs.readFileSync(path.join(root, 'data', 'cve-catalog.json'), 'utf8'));
    lessons = JSON.parse(fs.readFileSync(path.join(root, 'data', 'zeroday-lessons.json'), 'utf8'));
  } catch (err) {
    const msg = `framework-gap: cannot read catalog: ${err.message}`;
    if (jsonOut) {
      process.stdout.write(JSON.stringify({ ok: false, verb: 'framework-gap', error: msg }) + '\n');
    } else {
      console.error(`[framework-gap] cannot read catalog: ${err.message}`);
    }
    safeExit(EXIT_CODES.GENERIC_FAILURE);
    return;
  }

  const knownFrameworks = [...new Set(Object.values(controlGaps).flatMap(g =>
    Array.isArray(g.framework) ? g.framework : [g.framework]
  ).filter(f => f && f !== 'ALL'))];

  const requested = args[0].toLowerCase() === 'all'
    ? knownFrameworks
    : [args[0]];

  // An unknown framework reports zero matching gaps — indistinguishable from a
  // real "no gaps" result, so a typo could read as proof of coverage. Matching is
  // as gapReport does it, so the short forms still resolve.
  if (args[0].toLowerCase() !== 'all') {
    const normalize = (s) => String(s).toLowerCase().replace(/[\s_-]/g, '');
    const idNorm = normalize(args[0]);
    const matchesFramework = Object.entries(controlGaps).some(([key, g]) => {
      const fws = Array.isArray(g.framework) ? g.framework : [g.framework];
      if (fws.some(f => f && normalize(f).includes(idNorm))) return true;
      if (normalize(key).startsWith(idNorm)) return true;
      return false;
    });
    if (!matchesFramework) {
      const sorted = knownFrameworks.slice().sort();
      const msg = `[framework-gap] unknown framework "${args[0]}". No catalog control gaps reference it. Known frameworks: ${sorted.join(', ')}. Use "all" to analyze every framework.`;
      if (jsonOut) console.log(JSON.stringify({ ok: false, verb: 'framework-gap', error: msg, known_frameworks: sorted }, null, 2));
      else console.error(msg);
      safeExit(EXIT_CODES.GENERIC_FAILURE);
      return;
    }
  }
  const scenario = args[1];

  const allFrameworks = args[0].toLowerCase() === 'all';
  const report = gapReport(requested, scenario, controlGaps, cveCatalog, { allFrameworks, lessons });
  const theater = theaterCheck(controlGaps, cveCatalog);

  if (jsonOut) {
    console.log(JSON.stringify({ ...report, theater_findings: theater.findings, theater_score: theater.theater_score }, null, 2));
    return;
  }

  console.log(`\nFramework gap analysis — ${new Date().toISOString().slice(0, 10)}`);
  console.log(`Scenario: ${scenario}`);
  console.log(`Frameworks: ${requested.join(', ')}\n`);

  for (const [fwId, result] of Object.entries(report.frameworks)) {
    const flag = result.theater_exposure ? '⚠ THEATER RISK' : '✓ no scoped gaps';
    console.log(`### ${fwId} — ${result.gap_count} matching control gap(s) — ${flag}`);
    for (const g of result.gaps) {
      console.log(`  - ${g.id} (${g.control}) — status: ${g.status}`);
      if (g.real_requirement) console.log(`    real-requirement: ${g.real_requirement.slice(0, 160)}${g.real_requirement.length > 160 ? '…' : ''}`);
    }
    console.log();
  }

  if (report.universal_gaps.length > 0) {
    console.log(`### Universal gaps (no jurisdiction covers these) — ${report.universal_gaps.length}`);
    for (const g of report.universal_gaps) {
      const req = g.real_requirement || '';
      console.log(`  - ${g.id || g.name}: ${req.length > 140 ? req.slice(0, 140) + '…' : req}`);
    }
    console.log();
  }

  if (report.new_control_requirements.length > 0) {
    console.log(`### New controls this CVE requires (no framework carries them) — ${report.new_control_requirements.length}`);
    for (const c of report.new_control_requirements) {
      const req = c.requirement || '';
      console.log(`  - ${c.id} ${c.name}: ${req.length > 140 ? req.slice(0, 140) + '…' : req}`);
      if (c.closes.length) console.log(`    closes: ${c.closes.join(', ')}`);
    }
    console.log();
  }

  if (report.theater_risks.length > 0) {
    console.log(`### Theater risk controls (compliant but exposed) — ${report.theater_risks.length}`);
    for (const t of report.theater_risks) {
      console.log(`  - ${t.control} → ${t.pattern} (framework: ${t.framework})`);
    }
    console.log();
  }

  console.log(`Summary: ${report.summary.total_gaps} matching gaps, ${report.summary.universal_gaps} universal, ${report.summary.new_control_requirements} new controls required, ${report.summary.theater_risk_controls} theater-risk controls`);
}

async function runScan() {
  // scan's TLS-reachability probe is its one network touch; --air-gap (or
  // EXCEPTD_AIR_GAP=1) suppresses it in scanner.js, so the flags are honored there.
  if (rejectUnknownFlags('scan', args, ['--json', '--air-gap', '--offline', '--no-network'])) return;
  const { flags } = parseFlags(process.argv.slice(2), []);
  const jsonOut = flags.has('--json');
  if (!jsonOut) console.log('[orchestrator] Scanning environment...\n');
  const result = await scan();
  if (jsonOut) {
    // ok:true so one consumer branches on the same envelope as the error paths.
    process.stdout.write(JSON.stringify({ ok: true, ...result }) + '\n');
    return result;
  }

  console.log('Host:', JSON.stringify(result.host, null, 2));
  console.log('\nFindings by domain:');
  for (const [domain, count] of Object.entries(result.summary.by_domain)) {
    console.log(`  ${domain}: ${count}`);
  }

  console.log('\nBy severity:');
  for (const [severity, count] of Object.entries(result.summary.by_severity)) {
    if (count > 0) console.log(`  ${severity}: ${count}`);
  }

  console.log('\nRecommended skills:');
  for (const skill of result.summary.recommended_skills) {
    console.log(`  - ${skill}`);
  }

  if (result.summary.action_required) {
    console.log('\n⚠ Action required — critical or high severity findings present.');
  }

  console.log(`\nTotal findings: ${result.summary.total_findings}`);
  console.log('Timestamp:', result.timestamp);
  return result;
}

async function runDispatch() {
  // dispatch runs scan(), whose TLS probe is suppressed under air-gap.
  if (rejectUnknownFlags('dispatch', args, ['--json', '--air-gap', '--offline', '--no-network'])) return;
  const jsonOut = process.argv.includes('--json');
  if (!jsonOut) console.log('[orchestrator] Scanning then dispatching...\n');
  const scanResult = await scan();
  const plan = dispatch(scanResult.findings);

  if (jsonOut) {
    process.stdout.write(JSON.stringify({ ok: true, scan: scanResult, dispatch: plan }) + '\n');
    return plan;
  }

  console.log(`Dispatch plan — ${plan.plan.length} skills to invoke:\n`);

  for (const item of plan.plan) {
    const urgency = item.priority <= 1 ? 'CRITICAL' : item.priority === 2 ? 'HIGH' : 'MEDIUM';
    console.log(`[${urgency}] ${item.skill_name}`);
    console.log(`  Triggered by: ${item.triggered_by} (${item.finding_domain})`);
    console.log(`  Action: ${item.action_required}`);
    if (item.evidence && Array.isArray(item.evidence.items) && item.evidence.items.length > 0) {
      console.log(`  Evidence:`);
      for (const ev of item.evidence.items) {
        const parts = [ev.id, ev.name && `"${ev.name}"`, ev.rwep != null && `RWEP ${ev.rwep}`].filter(Boolean);
        console.log(`    - ${parts.join(' · ')}`);
      }
    } else if (item.evidence && item.evidence.cve_id) {
      console.log(`  Evidence: ${item.evidence.cve_id}${item.evidence.rwep_score != null ? ` · RWEP ${item.evidence.rwep_score}` : ''}`);
    }
    console.log(`  Path: ${item.skill_path}`);
    console.log();
  }

  if (plan.unmatched.length > 0) {
    console.log(`Unmatched findings (${plan.unmatched.length}):`);
    for (const f of plan.unmatched) console.log(`  - ${f.signal} (${f.domain})`);
  }

  return plan;
}

function runSkillContext(rawArgs) {
  // --flags are filtered out before the first positional is read as the skill
  // name, or `skill --json` reports "Skill not found: --json".
  const argList = Array.isArray(rawArgs) ? rawArgs : (rawArgs == null ? [] : [rawArgs]);
  // Air-gap flags are accepted and ignored; skill context is read from local files.
  if (rejectUnknownFlags('skill', argList, ['--json', '--air-gap', '--offline', '--no-network'])) return;
  const jsonOut = argList.includes('--json');
  const positionals = argList.filter(a => typeof a === 'string' && !a.startsWith('--'));
  const skillName = positionals[0];

  if (!skillName) {
    // Skill IDs are not the playbook names `brief --all` lists, so listing them
    // from the signed manifest keeps `exceptd skill` self-documenting.
    let skills = [];
    try {
      skills = (require('../manifest.json').skills || [])
        .map(s => ({ id: s.name, description: s.description || '' }))
        .sort((a, b) => a.id.localeCompare(b.id));
    } catch { /* fall back to the bare usage line below */ }
    if (jsonOut) {
      process.stdout.write(JSON.stringify({
        ok: false,
        verb: 'skill',
        error: 'usage: exceptd skill <skill-name>',
        hint: `Pass one of the ${skills.length} skill IDs listed in "skills".`,
        skills,
      }) + '\n');
    } else {
      console.error('Usage: exceptd skill <skill-name>');
      if (skills.length) {
        console.error(`\nAvailable skills (${skills.length}):`);
        for (const s of skills) {
          console.error(`  ${s.id.padEnd(36)} ${s.description.slice(0, 64)}`);
        }
      } else {
        console.error('       (manifest unreadable — see skills/ for available skill IDs)');
      }
    }
    safeExit(EXIT_CODES.GENERIC_FAILURE);
    return;
  }

  const context = getSkillContext(skillName);
  if (!context) {
    // ok:false bodies land on stdout beside successful results, so one consumer
    // parses the envelope without splitting across two streams.
    process.stdout.write(JSON.stringify({ ok: false, verb: "skill", error: `Skill not found: ${skillName}`, hint: "Run `exceptd skill` with no arguments to list all available skill IDs." }) + "\n");
    safeExit(EXIT_CODES.GENERIC_FAILURE);
    return;
  }

  console.log(`Skill: ${context.skill.name} v${context.skill.version}`);
  console.log(`Description: ${context.skill.description}`);
  console.log(`\nTriggers: ${context.skill.triggers?.join(', ')}`);
  console.log(`\nData dependencies:`);
  for (const [dep, info] of Object.entries(context.data_paths)) {
    console.log(`  ${dep}: ${info.exists ? 'OK' : 'MISSING'}`);
  }

  if (context.skill_content) {
    const lines = context.skill_content.split('\n').length;
    console.log(`\nSkill file: ${lines} lines`);
  }
}

function runPipeline(triggerType, payload) {
  const run = initPipeline(triggerType, payload);
  console.log(`Pipeline initialized: ${run.pipeline_id}`);
  console.log(`Trigger: ${run.trigger.type}`);
  console.log('\nStages:');
  for (const stage of run.stages) {
    console.log(`  ${stage.name}: ${stage.status}`);
    console.log(`  Agent: ${stage.agent_path}`);
  }
  console.log('\nTo run each stage, load the agent definition and follow its instructions:');
  console.log('  exceptd skill skill-update-loop');
  return run;
}

function runCurrency() {
  // Local-only verb; the air-gap flags are accepted and ignored.
  if (rejectUnknownFlags('currency', args, ['--json', '--air-gap', '--offline', '--no-network'])) return;
  const jsonOut = process.argv.includes('--json');
  const result = runCurrencyNow();
  const { currency_report, action_required, critical_count } = currencyCheck();

  if (jsonOut) {
    process.stdout.write(JSON.stringify({ ok: true, currency_report, action_required, critical_count, generated_at: new Date().toISOString() }) + '\n');
    return;
  }

  console.log(`\nSkill currency check — ${new Date().toISOString()}\n`);
  console.log('Score | Days | Skill');
  console.log('------|------|-----');
  for (const s of currency_report) {
    const flag = s.currency_score < 50 ? '⚠' : s.currency_score < 70 ? '!' : ' ';
    console.log(`${flag} ${String(s.currency_score).padStart(3)}% | ${String(s.days_since_review).padStart(4)}d | ${s.skill}`);
  }

  console.log(`\n${currency_report.length} skills checked.`);
  if (action_required) {
    console.log(`⚠ ${critical_count} skills require immediate update (currency < 50%)`);
  } else {
    console.log('All skills within acceptable currency range.');
  }
}

async function runReport(format) {
  // The air-gap flags are honored downstream by scan()'s TLS probe.
  if (rejectUnknownFlags('report', args, ['--json', '--air-gap', '--offline', '--no-network'])) return;
  const VALID_REPORT_FORMATS = ['executive', 'technical', 'compliance', 'csaf'];
  if (!VALID_REPORT_FORMATS.includes(format)) {
    // GENERIC_FAILURE, not DETECTED_ESCALATE — exit 2 is how a CI consumer reads
    // "the verb ran and found something".
    const { suggestFlag } = require('../lib/flag-suggest');
    const dym = suggestFlag(String(format), VALID_REPORT_FORMATS);
    const hint = dym ? ` Did you mean "${dym}"?` : '';
    process.stdout.write(JSON.stringify({
      ok: false,
      verb: 'report',
      error: `report: format "${format}" not in accepted set ${JSON.stringify(VALID_REPORT_FORMATS)}.${hint}`,
      provided: format,
      accepted_formats: VALID_REPORT_FORMATS,
      did_you_mean: dym ? [dym] : [],
    }) + '\n');
    safeExit(EXIT_CODES.GENERIC_FAILURE);
    return;
  }

  // `report csaf` emits a CSAF 2.0 envelope for VEX downstreams.
  if (format === 'csaf') {
    const scanResult = await scan();
    const plan = dispatch(scanResult.findings);
    const { currency_report } = currencyCheck();
    const ver = (function(){try{return require('../package.json').version;}catch{return 'unknown';}})();
    const csaf = {
      document: {
        category: 'csaf_security_advisory',
        csaf_version: '2.0',
        publisher: { category: 'vendor', name: 'exceptd', namespace: 'https://exceptd.com' },
        title: `exceptd assessment report — ${scanResult.summary.total_findings} finding(s) across ${plan.plan.length} skill(s)`,
        tracking: {
          id: `exceptd-report-${Date.now()}`,
          status: 'final',
          version: ver,
          initial_release_date: new Date().toISOString(),
          revision_history: [{ number: '1', date: new Date().toISOString(), summary: 'Initial report emission' }],
        },
      },
      // CSAF vulnerabilities[] is CVE-scoped by spec, so a signal detection
      // without a catalogued CVE is preserved in exceptd_extension, not dropped.
      vulnerabilities: scanResult.findings
        .filter(f => f.cve_id)
        .map(f => {
          const vuln = {
            cve: f.cve_id,
            // The CSAF schema requires non-empty strings, so never emit null here.
            notes: [{ category: 'description', text: f.action_required || f.signal || 'Vulnerability detected' }],
            threats: f.severity === 'critical'
              ? [{ category: 'exploit_status', details: f.action_required || f.signal || 'Critical vulnerability detected' }]
              : [],
          };
          // The real catalog CVSS, never a hardcoded base_score of 0 — that reads
          // as "no impact". A cvss_v3 block carries vectorString (CSAF §3.2.1.5),
          // so emit only when both are known rather than fabricate one.
          if (typeof f.cvss_score === 'number' && Number.isFinite(f.cvss_score) &&
              typeof f.cvss_vector === 'string' && f.cvss_vector) {
            vuln.scores = [{ products: [], cvss_v3: { baseScore: f.cvss_score, vectorString: f.cvss_vector } }];
          }
          return vuln;
        }),
      exceptd_extension: {
        scan_summary: scanResult.summary,
        dispatch_plan: plan,
        skill_currency: currency_report,
        host: scanResult.host,
      },
    };
    process.stdout.write(JSON.stringify(csaf, null, 2) + '\n');
    return;
  }

  // stderr, so `report executive > out.md` opens with the report header.
  console.error(`[orchestrator] Generating ${format} report...\n`);
  const scanResult = await scan();
  const plan = dispatch(scanResult.findings);
  const { currency_report } = currencyCheck();

  // The help advertises --json for every format, not only csaf.
  if (args.includes('--json')) {
    process.stdout.write(JSON.stringify({
      ok: true,
      verb: 'report',
      format,
      generated_at: new Date().toISOString(),
      summary: scanResult.summary,
      priority_actions: plan.plan
        .filter((p) => p.priority <= 2)
        .map((p) => ({ severity: p.finding_severity, skill: p.skill_name, action_required: p.action_required })),
      skill_currency: currency_report,
      host: scanResult.host,
    }, null, 2) + '\n');
    return;
  }

  // The header self-describes the flavor, so a piped report carries its provenance.
  const flavorTitle = {
    executive: 'Executive Report',
    technical: 'Technical Report',
    compliance: 'Compliance Report',
  }[format] || 'Report';
  console.log(`# exceptd ${flavorTitle}`);
  console.log(`<!-- exceptd-report:flavor=${format} version=${(function(){try{return require('../package.json').version;}catch{return 'unknown';}})()} -->`);
  console.log(`Generated: ${new Date().toISOString()}\n`);

  console.log('## Executive Summary');
  console.log(`- Total scan findings: ${scanResult.summary.total_findings}`);
  console.log(`- Critical findings: ${scanResult.summary.by_severity.critical}`);
  console.log(`- High findings: ${scanResult.summary.by_severity.high}`);
  console.log(`- Skills triggered: ${plan.plan.length}`);
  console.log(`- Action required: ${scanResult.summary.action_required}\n`);

  console.log('## Priority Actions');
  for (const item of plan.plan.filter(p => p.priority <= 2)) {
    console.log(`- [${item.finding_severity.toUpperCase()}] Run ${item.skill_name}: ${item.action_required}`);
  }

  console.log('\n## Skill Currency');
  const critical = currency_report.filter(s => s.currency_score < 50);
  const stale = currency_report.filter(s => s.currency_score >= 50 && s.currency_score < 70);
  if (critical.length === 0 && stale.length === 0) {
    console.log('All skills current (>= 70% currency, reviewed within the last 60 days).');
  } else {
    if (critical.length > 0) {
      console.log(`Critical-stale (< 50% currency, > 90 days since review) — ${critical.length}:`);
      for (const s of critical) console.log(`  - ${s.skill}: ${s.currency_score}% (${s.days_since_review}d old)`);
    }
    if (stale.length > 0) {
      console.log(`Stale (50-69% currency, 30-90 days since review) — ${stale.length}:`);
      for (const s of stale) console.log(`  - ${s.skill}: ${s.currency_score}% (${s.days_since_review}d old)`);
    }
  }
}

/**
 * A writable directory for the watch lockfile: the operator's home, falling
 * back to the OS tempdir when home is absent or non-writable.
 */
function _resolveWatchLockDir() {
  const home = process.env.EXCEPTD_HOME || pathMod.join(osMod.homedir(), '.exceptd');
  try {
    fsMod.mkdirSync(home, { recursive: true });
    const probe = pathMod.join(home, `.write-probe-${process.pid}`);
    fsMod.writeFileSync(probe, '');
    fsMod.unlinkSync(probe);
    return home;
  } catch {
    const fallback = pathMod.join(osMod.tmpdir(), 'exceptd');
    try { fsMod.mkdirSync(fallback, { recursive: true }); } catch { /* tmp always exists */ }
    return fallback;
  }
}

/**
 * Returns `{ path, release }`, or throws code 'EWATCHLOCKED' when a live watcher
 * holds the lock. Stale means the recorded PID is dead or the mtime is older than
 * 60s; the PID check covers Windows, where the graceful release never ran.
 */
function _acquireWatchLock() {
  const dir = _resolveWatchLockDir();
  const lockPath = pathMod.join(dir, 'watch.lock');
  const STALE_MS = 60_000;

  function tryCreate() {
    // The predictable lock-file name IS the mutex, so the safety is the exclusive
    // create plus the owner-only mode, not an unguessable name.
    const fd = fsMod.openSync(lockPath, 'wx', 0o600);
    fsMod.writeSync(fd, JSON.stringify({ pid: process.pid, started_at: new Date().toISOString() }));
    fsMod.closeSync(fd);
  }

  function _pidAlive(pid) {
    if (!Number.isInteger(pid) || pid <= 0) return false;
    try {
      // Signal 0 is the "is it alive" probe; ESRCH means dead, EPERM alive.
      process.kill(pid, 0);
      return true;
    } catch (e) {
      return e.code === 'EPERM';
    }
  }

  try {
    tryCreate();
  } catch (err) {
    if (err.code !== 'EEXIST') throw err;
    let stale = false;
    let recordedPid = null;
    try {
      const raw = fsMod.readFileSync(lockPath, 'utf8');
      try { recordedPid = JSON.parse(raw).pid; } catch { /* malformed file = stale */ stale = true; }
      const st = fsMod.statSync(lockPath);
      const ageStale = (Date.now() - st.mtimeMs) > STALE_MS;
      const pidStale = recordedPid != null && !_pidAlive(recordedPid);
      stale = stale || ageStale || pidStale;
    } catch {
      stale = true;
    }
    if (!stale) {
      const e = new Error(
        `another exceptd watch process (pid ${recordedPid}) appears to hold ${lockPath}; remove the file if you're sure no watcher is running`
      );
      e.code = 'EWATCHLOCKED';
      throw e;
    }
    // Stale — unlink and re-create with O_EXCL. Losing that race is contention,
    // so it is re-tagged EWATCHLOCKED to reach the EX_TEMPFAIL "retry later" exit.
    try { fsMod.unlinkSync(lockPath); } catch { /* concurrent reclaim, fine */ }
    try {
      tryCreate();
    } catch (recreateErr) {
      if (recreateErr.code === 'EEXIST') {
        const e = new Error(
          `another exceptd watch process reclaimed ${lockPath} concurrently; retry`
        );
        e.code = 'EWATCHLOCKED';
        throw e;
      }
      throw recreateErr;
    }
  }

  return {
    path: lockPath,
    release() {
      try { fsMod.unlinkSync(lockPath); } catch { /* idempotent */ }
    }
  };
}

async function runWatch() {
  // Reject unknown flags before acquiring the lock or starting the scheduler.
  // --log-file is the value-taking option; watch does no egress of its own.
  if (rejectUnknownFlags('watch', args, ['--log-file', '--json', '--air-gap', '--offline', '--no-network'])) return;
  const { flags, options } = parseFlags(args, ['--log-file']);
  const logFilePath = options.get('--log-file');
  let logStream = null;
  // Intercepting process.stdout.write tees the scheduler and event bus too.
  if (logFilePath) {
    try {
      fsMod.mkdirSync(pathMod.dirname(pathMod.resolve(logFilePath)), { recursive: true });
      logStream = fsMod.createWriteStream(pathMod.resolve(logFilePath), { flags: 'a' });
    } catch (err) {
      // A filesystem error opening the log target is a generic failure, not a
      // detected finding — exit 2 would misroute a CI gate.
      console.error(`[orchestrator] --log-file ${logFilePath}: ${err.message}`);
      safeExit(EXIT_CODES.GENERIC_FAILURE);
      return;
    }
    const origWrite = process.stdout.write.bind(process.stdout);
    process.stdout.write = function teeWrite(chunk, enc, cb) {
      try { logStream.write(chunk, enc); } catch { /* best-effort */ }
      return origWrite(chunk, enc, cb);
    };
  }
  // Parsed for symmetry with the other verbs, unused here.
  void flags;

  // The cross-process lock stops two watchers double-emitting events and
  // double-firing the scheduler bootstrap. Every shutdown path releases it.
  let lock;
  try {
    lock = _acquireWatchLock();
  } catch (err) {
    console.error(`[orchestrator] cannot start watch: ${err.message}`);
    // sysexits EX_TEMPFAIL, read from the canonical table so this path and the
    // `doctor --exit-codes` dump agree.
    const watchLocked = EXIT_CODES.WATCH_LOCK_CONTENTION || 75;
    process.exitCode = err.code === 'EWATCHLOCKED' ? watchLocked : 1;
    return;
  }

  console.log('[orchestrator] Starting event watcher...');
  console.log(`[orchestrator] Lockfile: ${lock.path}`);
  console.log('Listening for: CISA KEV additions, ATLAS updates, CVE drops, framework amendments.\n');

  // Held so shutdown can detach it — a leaked '*' listener accumulates across
  // start/stop cycles.
  const anyListener = (event) => {
    console.log(`[event] ${event.type} — ${event.timestamp}`);
    if (event.affected_skills.length > 0) {
      console.log(`  Affected skills: ${event.affected_skills.join(', ')}`);
    }
    if (event.payload && event.payload.cve_id) {
      console.log(`  CVE: ${event.payload.cve_id}`);
    }
  };
  bus.onAny(anyListener);

  startScheduler();

  let shuttingDown = false;
  const shutdown = (signal) => {
    if (shuttingDown) return;
    shuttingDown = true;
    console.log(`\n[orchestrator] Stopping watcher (${signal}).`);
    try { bus.offAny(anyListener); } catch { /* best-effort */ }
    try { stopScheduler(); } catch { /* best-effort */ }
    try { lock.release(); } catch { /* best-effort */ }
    if (logStream) {
      try { logStream.end(); } catch { /* best-effort */ }
    }
    // process.exitCode, not process.exit() — the loop drains so the goodbye line
    // flushes and the log stream finishes.
    process.exitCode = 0;
  };

  // SIGHUP does not exist on Windows and registering it throws on some Node
  // versions, so the platform gate picks SIGBREAK instead.
  process.on('SIGINT', () => shutdown('SIGINT'));
  process.on('SIGTERM', () => shutdown('SIGTERM'));
  if (process.platform !== 'win32') {
    try { process.on('SIGHUP', () => shutdown('SIGHUP')); } catch { /* unsupported */ }
  } else {
    try { process.on('SIGBREAK', () => shutdown('SIGBREAK')); } catch { /* unsupported */ }
  }

  console.log('Press Ctrl+C to stop. (SIGTERM / SIGHUP / SIGBREAK also honored.)\n');
}

// An unknown flag must be rejected BEFORE any network work: a swallowed
// `--ofline` falls through to the live path and fetches the whole NVD catalog.
const VALIDATE_CVES_KNOWN_FLAGS = Object.freeze([
  '--offline', '--no-fail', '--from-cache', '--concurrency', '--since', '--air-gap',
]);
// `--live` is the explicit opt-in to the default network path; `--air-gap`
// forces the offline view.
const VALIDATE_RFCS_KNOWN_FLAGS = Object.freeze([
  '--offline', '--no-fail', '--from-cache', '--since', '--live', '--air-gap',
]);

// True when a rejection was emitted and the caller must return. Matching is on
// the base flag — the text before any `=` — so `--since=2026-01-01` is accepted.
function rejectUnknownFlags(verb, rawArgs, knownFlags) {
  const known = new Set(knownFlags);
  const unknown = rawArgs
    .filter(a => typeof a === 'string' && a.startsWith('--'))
    .map(a => { const eq = a.indexOf('='); return eq === -1 ? a : a.slice(0, eq); })
    .filter(base => !known.has(base));
  if (unknown.length === 0) return false;
  const uniq = [...new Set(unknown)];
  process.stdout.write(JSON.stringify({
    ok: false,
    verb,
    error: `${verb}: unknown flag(s): ${uniq.join(', ')}`,
    unknown_flags: uniq,
    known_flags: knownFlags,
  }) + '\n');
  safeExit(EXIT_CODES.GENERIC_FAILURE);
  return true;
}

async function runValidateCves(rawArgs = []) {
  const fs = require('fs');
  const path = require('path');

  if (rejectUnknownFlags('validate-cves', rawArgs, VALIDATE_CVES_KNOWN_FLAGS)) return;

  const flags = new Set(rawArgs.filter(a => a.startsWith('--')));
  const offline = flags.has('--offline') || flags.has('--air-gap');
  const noFail = flags.has('--no-fail');
  // --from-cache takes an optional path; the layout is fixed by lib/prefetch.js.
  let cacheDir = null;
  // --concurrency bounds in-flight upstream calls during live validation.
  let concurrency = 4;
  for (let i = 0; i < rawArgs.length; i++) {
    const a = rawArgs[i];
    if (a === '--from-cache') {
      const next = rawArgs[i + 1];
      cacheDir = next && !next.startsWith('--') ? next : '.cache/upstream';
      if (next && !next.startsWith('--')) i++;
    } else if (a.startsWith('--from-cache=')) {
      cacheDir = a.slice('--from-cache='.length);
    } else if (a === '--concurrency') {
      const next = rawArgs[i + 1];
      if (next !== undefined) { const n = Number(next); if (Number.isFinite(n) && n >= 1) concurrency = Math.floor(n); i++; }
    } else if (a.startsWith('--concurrency=')) {
      const n = Number(a.slice('--concurrency='.length));
      if (Number.isFinite(n) && n >= 1) concurrency = Math.floor(n);
    }
  }
  if (cacheDir) cacheDir = path.resolve(cacheDir);

  const catalogPath = path.join(__dirname, '..', 'data', 'cve-catalog.json');
  let catalog;
  try {
    catalog = JSON.parse(fs.readFileSync(catalogPath, 'utf8'));
  } catch (err) {
    console.error(`[validate-cves] cannot read ${catalogPath}: ${err.message}`);
    safeExit(EXIT_CODES.GENERIC_FAILURE);
    return;
  }

  // --since scopes to CVEs whose last_updated (or cisa_kev_date) is on or after it.
  let sinceDate = null;
  for (let i = 0; i < rawArgs.length; i++) {
    if (rawArgs[i] === '--since' && rawArgs[i + 1]) sinceDate = rawArgs[i + 1];
    else if (rawArgs[i].startsWith('--since=')) sinceDate = rawArgs[i].slice('--since='.length);
  }

  let cveIds = Object.keys(catalog).filter(k => /^CVE-\d{4}-\d{4,7}$/.test(k));
  if (sinceDate) {
    const since = sinceDate.length === 10 ? `${sinceDate}T00:00:00Z` : sinceDate;
    const before = cveIds.length;
    cveIds = cveIds.filter(id => {
      const e = catalog[id];
      const stamp = e.last_updated || e.cisa_kev_date || e.first_seen;
      if (!stamp) return false;
      return stamp >= since;
    });
    console.log(`[validate-cves] --since ${sinceDate} filtered ${before} → ${cveIds.length} CVE(s).`);
  }

  console.log(`\nCVE Validation — ${new Date().toISOString()}`);
  const modeStr = offline
    ? 'offline (local view only)'
    : (cacheDir ? `live with cache (${path.relative(path.join(__dirname, '..'), cacheDir)})` : 'live (NVD + CISA KEV)');
  // CVE-* IDs validated against NVD, not the whole catalog: MAL-* entries live in
  // the same file but carry no CVE ID by design.
  const allKeys = Object.keys(catalog).filter((k) => !k.startsWith('_'));
  const nonCveCount = allKeys.length - cveIds.length;
  const totalNote = nonCveCount > 0
    ? ` (catalog has ${nonCveCount} additional non-CVE entries excluded from NVD validation; see \`exceptd doctor\` for the combined catalog total)`
    : '';
  console.log(`${cveIds.length} CVE IDs queued for NVD validation${totalNote}. Mode: ${modeStr}${sinceDate ? ` · since=${sinceDate}` : ''}`);
  console.log(`Fail-on-drift: ${noFail ? 'disabled' : 'enabled'}\n`);

  const header = 'CVE                | Local RWEP | Local CVSS | NVD CVSS         | KEV Local | KEV NVD | EPSS Local      | EPSS Live       | EPSS Drift | Status';
  const rule   = '-------------------|------------|------------|------------------|-----------|---------|-----------------|-----------------|------------|----------';
  console.log(header);
  console.log(rule);

  function fmt(v, n) {
    const s = (v === null || v === undefined) ? '-' : String(v);
    return s.length >= n ? s.slice(0, n) : s + ' '.repeat(n - s.length);
  }

  function fmtEpss(score, pct) {
    if (score === null || score === undefined) return '-';
    const s = Number(score).toFixed(4);
    const p = (pct === null || pct === undefined) ? '?' : Number(pct).toFixed(2);
    return `${s}/${p}`;
  }

  if (offline) {
    for (const id of cveIds) {
      const e = catalog[id];
      console.log(
        fmt(id, 18) + ' | ' +
        fmt(e.rwep_score, 10) + ' | ' +
        fmt(e.cvss_score, 10) + ' | ' +
        fmt('(offline)', 16) + ' | ' +
        fmt(e.cisa_kev, 9) + ' | ' +
        fmt('(offline)', 7) + ' | ' +
        fmt(fmtEpss(e.epss_score, e.epss_percentile), 15) + ' | ' +
        fmt('(offline)', 15) + ' | ' +
        fmt('(offline)', 10) + ' | ' +
        'local-only'
      );
    }
    console.log(`\n[validate-cves] offline mode — no network calls made. ${cveIds.length} entries listed from local catalog.`);
    safeExit(EXIT_CODES.SUCCESS);
    return;
  }

  // sources/validators is absent from some installs, hence the guarded require
  // and the offline fallback.
  let validateAllCves;
  try {
    ({ validateAllCves } = require('../sources/validators'));
  } catch (e) {
    if (e.code === 'MODULE_NOT_FOUND') {
      console.warn('[validate-cves] validator module unavailable (MODULE_NOT_FOUND); falling back to offline mode.');
      console.log(`\n[validate-cves] offline mode (forced by missing validators) — ${cveIds.length} entries listed from local catalog.`);
      safeExit(EXIT_CODES.SUCCESS);
      return;
    }
    throw e;
  }
  let report;
  if (cacheDir && fs.existsSync(cacheDir)) {
    report = await validateAllCvesPreferCache(catalog, cacheDir);
  } else {
    report = await validateAllCves(catalog, { concurrency });
  }

  const byId = new Map(report.results.map(r => [r.cve_id, r]));
  let driftFound = 0;
  let unreachable = 0;

  for (const id of cveIds) {
    const e = catalog[id];
    const r = byId.get(id);
    const status = r?.status || 'unknown';
    if (status === 'drift') driftFound++;
    if (status === 'unreachable') unreachable++;

    const nvdScore = r?.fetched?.cvss_score ?? null;
    const kevNvd = r?.fetched?.in_kev;
    const kevNvdStr = (kevNvd === null || kevNvd === undefined) ? '?' : String(kevNvd);

    const cvssMismatch = r?.discrepancies?.some(d => d.field === 'cvss_score');
    const kevMismatch  = r?.discrepancies?.some(d => d.field === 'cisa_kev');

    const liveEpss = r?.fetched?.epss || null;
    const epssReachable = r?.fetched?.sources?.epss?.reachable === true;
    const epssMismatchScore = r?.discrepancies?.some(d => d.field === 'epss_score');
    const epssMismatchPct = r?.discrepancies?.some(d => d.field === 'epss_percentile');
    const localEpssCell = fmtEpss(e.epss_score, e.epss_percentile);
    const liveEpssCell = liveEpss
      ? fmtEpss(liveEpss.score, liveEpss.percentile)
      : (epssReachable ? 'not-found' : 'unreachable');
    let driftCell = '-';
    if (r?.drift) {
      const dScore = (liveEpss?.score !== null && e.epss_score !== null && e.epss_score !== undefined)
        ? (liveEpss.score - e.epss_score)
        : null;
      const dPct = (liveEpss?.percentile !== null && e.epss_percentile !== null && e.epss_percentile !== undefined)
        ? (liveEpss.percentile - e.epss_percentile)
        : null;
      const parts = [];
      if (dScore !== null) parts.push(`Δs=${(dScore >= 0 ? '+' : '') + dScore.toFixed(3)}`);
      if (dPct !== null) parts.push(`Δp=${(dPct >= 0 ? '+' : '') + dPct.toFixed(3)}`);
      driftCell = parts.join(' ') + ' DRIFT';
    } else if (epssMismatchScore || epssMismatchPct) {
      driftCell = 'DRIFT';
    }

    console.log(
      fmt(id, 18) + ' | ' +
      fmt(e.rwep_score, 10) + ' | ' +
      fmt(e.cvss_score, 10) + ' | ' +
      fmt(nvdScore === null ? '-' : `${nvdScore}${cvssMismatch ? ' DRIFT' : ''}`, 16) + ' | ' +
      fmt(e.cisa_kev, 9) + ' | ' +
      fmt(`${kevNvdStr}${kevMismatch ? ' DRIFT' : ''}`, 7) + ' | ' +
      fmt(localEpssCell, 15) + ' | ' +
      fmt(liveEpssCell, 15) + ' | ' +
      fmt(driftCell, 10) + ' | ' +
      status
    );

    if (r?.discrepancies?.length) {
      for (const d of r.discrepancies) {
        console.log(`                     -> drift on ${d.field}: local=${JSON.stringify(d.local)} fetched=${JSON.stringify(d.fetched)} (${d.severity})`);
      }
    }
  }

  console.log(`\nSummary: match=${report.by_status.match || 0}  drift=${report.by_status.drift || 0}  unreachable=${report.by_status.unreachable || 0}  missing=${report.by_status.missing || 0}  (total=${report.total})`);
  if (unreachable > 0) {
    console.log(`Note: ${unreachable} CVE(s) unreachable — airgapped or upstream down. Re-run when network is available.`);
  }
  if (driftFound > 0) {
    console.log(`\n[validate-cves] DRIFT DETECTED on ${driftFound} CVE(s). Update data/cve-catalog.json and bump source_verified.`);
    if (!noFail) { safeExit(EXIT_CODES.GENERIC_FAILURE); return; }
  } else {
    console.log('[validate-cves] No drift detected against reachable sources.');
  }
}

/**
 * Confirms every entry in data/rfc-references.json is current against the IETF
 * Datatracker. Drift is a status change, new errata since `last_verified`, a
 * replaced-by relationship, or obsoletion; a network error returns `unreachable`
 * for that entry and never fails the run.
 */
async function runValidateRfcs(rawArgs = []) {
  const fs = require('fs');
  const path = require('path');

  if (rejectUnknownFlags('validate-rfcs', rawArgs, VALIDATE_RFCS_KNOWN_FLAGS)) return;

  const flags = new Set(rawArgs.filter(a => a.startsWith('--')));
  const offline = flags.has('--offline') || flags.has('--air-gap');
  const noFail = flags.has('--no-fail');
  let cacheDir = null;
  for (let i = 0; i < rawArgs.length; i++) {
    const a = rawArgs[i];
    if (a === '--from-cache') {
      const next = rawArgs[i + 1];
      cacheDir = next && !next.startsWith('--') ? next : '.cache/upstream';
      if (next && !next.startsWith('--')) i++;
    } else if (a.startsWith('--from-cache=')) {
      cacheDir = a.slice('--from-cache='.length);
    }
  }
  if (cacheDir) cacheDir = path.resolve(cacheDir);

  const refsPath = path.join(__dirname, '..', 'data', 'rfc-references.json');
  let refs;
  try {
    refs = JSON.parse(fs.readFileSync(refsPath, 'utf8'));
  } catch (err) {
    console.error(`[validate-rfcs] cannot read ${refsPath}: ${err.message}`);
    safeExit(EXIT_CODES.GENERIC_FAILURE);
    return;
  }

  // --since <ISO|YYYY-MM-DD>: scope-limit (parity with validate-cves).
  let sinceDate = null;
  for (let i = 0; i < rawArgs.length; i++) {
    if (rawArgs[i] === '--since' && rawArgs[i + 1]) sinceDate = rawArgs[i + 1];
    else if (rawArgs[i].startsWith('--since=')) sinceDate = rawArgs[i].slice('--since='.length);
  }
  let ids = Object.keys(refs).filter(k => !k.startsWith('_'));
  if (sinceDate) {
    const since = sinceDate.length === 10 ? `${sinceDate}T00:00:00Z` : sinceDate;
    const before = ids.length;
    ids = ids.filter(id => {
      const e = refs[id];
      const stamp = e.last_verified || e.published || e.last_updated;
      return stamp && stamp >= since;
    });
    console.log(`[validate-rfcs] --since ${sinceDate} filtered ${before} → ${ids.length} entry(ies).`);
  }

  console.log(`\nRFC Validation — ${new Date().toISOString()}`);
  const modeStr = offline
    ? 'offline (local view only)'
    : (cacheDir ? `live with cache (${path.relative(path.join(__dirname, '..'), cacheDir)})` : 'live (IETF Datatracker)');
  console.log(`${ids.length} RFC / draft entries in catalog. Mode: ${modeStr}${sinceDate ? ` · since=${sinceDate}` : ''}`);
  console.log(`Fail-on-drift: ${noFail ? 'disabled' : 'enabled'}\n`);

  const header = 'ID                              | Status               | Errata | Last verified | Live status';
  const rule   = '--------------------------------|----------------------|--------|---------------|---------------------';
  console.log(header);
  console.log(rule);

  function fmt(v, n) {
    const s = (v === null || v === undefined) ? '-' : String(v);
    return s.length >= n ? s.slice(0, n) : s + ' '.repeat(n - s.length);
  }

  // Lazy-loaded so an install without sources/validators still gets the offline view.
  let validator = null;
  if (!offline) {
    try {
      validator = require('../sources/validators/rfc-validator.js');
    } catch (err) {
      console.log(`[validate-rfcs] note: validator module unavailable (${err.code || err.message}); falling back to offline mode.\n`);
    }
  }

  let driftFound = 0;
  let unreachable = 0;

  // Cache-first: drift is computed the way validateRfc would, and a miss falls
  // through to the validator.
  const STATUS_MAP = {
    std: 'Internet Standard', ps: 'Proposed Standard', ds: 'Draft Standard',
    bcp: 'Best Current Practice', inf: 'Informational', exp: 'Experimental',
    his: 'Historic', unkn: 'Unknown',
  };
  function rfcDocNameFor(id) {
    if (id.startsWith('RFC-')) return `rfc${id.slice(4)}`;
    if (id.startsWith('DRAFT-')) return `draft-${id.slice(6).toLowerCase()}`;
    return null;
  }
  function readCachedRfc(docName) {
    if (!cacheDir || !docName) return null;
    const safe = docName.replace(/[^A-Za-z0-9._-]/g, '_');
    const p = path.join(cacheDir, 'rfc', `${safe}.json`);
    if (!fs.existsSync(p)) return null;
    try { return JSON.parse(fs.readFileSync(p, 'utf8')); }
    catch { return null; }
  }
  let cacheHits = 0;
  let liveFallbacks = 0;

  for (const id of ids) {
    const entry = refs[id];
    let liveStatus = offline || !validator ? 'skipped (offline)' : '?';
    if (!offline) {
      const cached = readCachedRfc(rfcDocNameFor(id));
      if (cached) {
        cacheHits++;
        const obj = cached.objects?.[0];
        if (!obj) {
          liveStatus = 'NOT FOUND upstream (cache)';
          driftFound++;
        } else {
          const upStatus = STATUS_MAP[obj.std_level] || null;
          if (upStatus && entry.status && upStatus !== entry.status) {
            liveStatus = `DRIFT: status local "${entry.status}" vs Datatracker "${upStatus}" (cache)`;
            driftFound++;
          } else {
            liveStatus = 'match (cache)';
          }
        }
      } else if (validator) {
        liveFallbacks++;
        try {
          const result = await validator.validateRfc(id, entry);
          if (result.status === 'unreachable') {
            liveStatus = 'unreachable';
            unreachable++;
          } else if (result.status === 'match') {
            liveStatus = 'match';
          } else if (result.status === 'drift') {
            liveStatus = 'DRIFT: ' + (result.discrepancies || []).join('; ');
            driftFound++;
          } else if (result.status === 'missing') {
            liveStatus = 'NOT FOUND upstream';
            driftFound++;
          }
        } catch (err) {
          liveStatus = `error: ${err.message}`;
          unreachable++;
        }
      }
    }
    console.log(
      `${fmt(id, 32)}| ${fmt(entry.status, 20)} | ${fmt(entry.errata_count, 6)} | ${fmt(entry.last_verified, 13)} | ${liveStatus}`
    );
  }
  if (cacheDir) {
    console.log(`\n[validate-rfcs] cache hits: ${cacheHits}; live fallbacks: ${liveFallbacks}`);
  }

  console.log();
  if (driftFound > 0) {
    console.log(`[validate-rfcs] DRIFT DETECTED on ${driftFound} entry(ies). Update data/rfc-references.json and bump last_verified.`);
    if (!noFail) { safeExit(EXIT_CODES.GENERIC_FAILURE); return; }
  } else if (unreachable > 0) {
    console.log(`[validate-rfcs] ${unreachable} entry(ies) unreachable. Network/IETF Datatracker is intermittent — re-run later.`);
  } else if (!offline && validator) {
    console.log('[validate-rfcs] No drift detected against reachable upstream sources.');
  } else {
    console.log('[validate-rfcs] Offline view only. Re-run with --live (or omit --offline) to check against the IETF Datatracker.');
  }
}

/**
 * Aggregates the `forward_watch` frontmatter across every manifest skill into
 * one deduplicated, sorted list, carrying the skills that listed each item and
 * the most recent `last_threat_review` among them. --by-skill inverts the view.
 */
// Every flag any watchlist mode accepts; the guard runs once at the top of
// runWatchlist, whichever sub-mode a typo would have reached.
const WATCHLIST_KNOWN_FLAGS = Object.freeze([
  '--json', '--by-skill', '--alerts', '--org-scan',
  '--org', '--pattern', '--output-format', '--air-gap',
]);

function runWatchlist(rawArgs = []) {
  const fs = require('fs');
  const path = require('path');
  const { parseFrontmatter, extractFrontmatterBlock } = require('../lib/lint-skills.js');

  if (rejectUnknownFlags('watchlist', rawArgs, WATCHLIST_KNOWN_FLAGS)) return;

  const byskill = rawArgs.includes('--by-skill');
  const alertsMode = rawArgs.includes('--alerts');
  const orgScanMode = rawArgs.includes('--org-scan');
  const manifestPath = path.join(__dirname, '..', 'manifest.json');
  const repoRoot = path.join(__dirname, '..');

  // The modes are mutually exclusive; the first matching flag wins.
  if (alertsMode) {
    return runWatchlistAlerts(rawArgs);
  }

  if (orgScanMode) {
    return runWatchlistOrgScan(rawArgs);
  }

  let manifest;
  try {
    manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
  } catch (err) {
    console.error(`[watchlist] cannot read ${manifestPath}: ${err.message}`);
    safeExit(EXIT_CODES.GENERIC_FAILURE);
    return;
  }

  // Deprecated skills are excluded; the field is optional, absent means active.
  const skills = (Array.isArray(manifest.skills) ? manifest.skills : [])
    .filter(s => s && s.status !== 'deprecated');
  // item -> { skills: [{name, last_threat_review}] }
  const itemToSkills = new Map();
  // skill name -> { items: [...], last_threat_review }
  const skillToItems = new Map();
  let parseErrors = 0;

  for (const entry of skills) {
    const skillPath = path.join(repoRoot, entry.path);
    if (!fs.existsSync(skillPath)) {
      parseErrors++;
      continue;
    }
    const content = fs.readFileSync(skillPath, 'utf8');
    const { frontmatter: fmRaw } = extractFrontmatterBlock(content);
    if (!fmRaw) {
      parseErrors++;
      continue;
    }
    let fm;
    try {
      fm = parseFrontmatter(fmRaw);
    } catch {
      parseErrors++;
      continue;
    }
    const items = Array.isArray(fm.forward_watch) ? fm.forward_watch : [];
    const reviewDate = typeof fm.last_threat_review === 'string' ? fm.last_threat_review : null;
    skillToItems.set(entry.name, { items, last_threat_review: reviewDate });
    for (const itemRaw of items) {
      if (typeof itemRaw !== 'string' || !itemRaw.trim()) continue;
      const item = itemRaw.trim();
      if (!itemToSkills.has(item)) itemToSkills.set(item, []);
      itemToSkills.get(item).push({ skill: entry.name, last_threat_review: reviewDate });
    }
  }

  const jsonOut = rawArgs.includes('--json');
  if (jsonOut) {
    // Top-level ok:true so every verb's JSON body shares one contract.
    const out = {
      ok: true,
      generated_at: new Date().toISOString(),
      skills_scanned: skills.length,
      parse_errors: parseErrors,
      mode: byskill ? 'by-skill' : 'by-item',
    };
    if (byskill) {
      out.by_skill = Object.fromEntries([...skillToItems.entries()]
        .sort(([a], [b]) => a.localeCompare(b))
        .map(([k, v]) => [k, v]));
    } else {
      out.by_item = Object.fromEntries([...itemToSkills.entries()]
        .sort(([a], [b]) => a.localeCompare(b)));
    }
    process.stdout.write(JSON.stringify(out) + '\n');
    return;
  }

  console.log(`\nForward-Watch Aggregator — ${new Date().toISOString()}`);
  console.log(`Skills scanned: ${skills.length}  parse errors: ${parseErrors}`);

  if (byskill) {
    console.log(`Mode: by-skill\n`);
    const names = [...skillToItems.keys()].sort();
    for (const name of names) {
      const info = skillToItems.get(name);
      console.log(`### ${name}  (last_threat_review: ${info.last_threat_review || '-'})`);
      if (info.items.length === 0) {
        console.log('  (no forward_watch entries)');
      } else {
        for (const item of info.items) console.log(`  - ${item}`);
      }
      console.log();
    }
    console.log(`Total unique watch items across all skills: ${itemToSkills.size}`);
    return;
  }

  console.log(`Mode: aggregated (unique items across all skills)\n`);
  const sortedItems = [...itemToSkills.keys()].sort((a, b) => a.localeCompare(b));
  for (const item of sortedItems) {
    const listers = itemToSkills.get(item);
    const dates = listers.map(l => l.last_threat_review).filter(Boolean).sort();
    const mostRecent = dates.length ? dates[dates.length - 1] : '-';
    const skillNames = listers.map(l => l.skill).join(', ');
    console.log(`- ${item}`);
    console.log(`    skills (${listers.length}): ${skillNames}`);
    console.log(`    most-recent last_threat_review among listers: ${mostRecent}`);
  }

  console.log(`\nTotal unique watch items: ${itemToSkills.size}  (across ${skills.length} skills)`);
  console.log(`Run with --by-skill to invert the view.`);
}

/**
 * Surfaces CVE catalog entries matching high-priority pattern rules. Every entry
 * is evaluated against every pattern and several may fire on one entry, so the
 * report carries the list rather than a single label.
 */
function runWatchlistAlerts(rawArgs = []) {
  const fs = require('fs');
  const path = require('path');
  const jsonOut = rawArgs.includes('--json');
  const cvePath = path.join(__dirname, '..', 'data', 'cve-catalog.json');
  let catalog;
  try {
    catalog = JSON.parse(fs.readFileSync(cvePath, 'utf8'));
  } catch (err) {
    console.error(`[watchlist --alerts] cannot read ${cvePath}: ${err.message}`);
    safeExit(EXIT_CODES.GENERIC_FAILURE);
    return;
  }

  // A pattern is a predicate over one entry plus a label and severity. Kept
  // narrow — a false-positive flood defeats the alert.
  const today = new Date();
  function daysSince(iso) {
    if (typeof iso !== 'string') return Infinity;
    const t = Date.parse(iso + 'T00:00:00Z');
    if (Number.isNaN(t)) return Infinity;
    return Math.floor((today - t) / (24 * 60 * 60 * 1000));
  }
  const PATTERNS = [
    {
      id: 'kernel_lpe_with_poc',
      severity: 'high',
      description: 'Linux kernel LPE class with public PoC. The CVE-2026-46333 (ssh-keysign-pwn) / CVE-2026-46300 (Fragnesia) / CVE-2026-31431 (Copy Fail) shape.',
      match: (e) =>
        e && typeof e.vector === 'string' &&
        /kernel|linux|ptrace|pidfd/i.test(`${e.name || ''} ${e.vector}`) &&
        e.poc_available === true &&
        (e.rwep_factors?.blast_radius || 0) >= 25,
    },
    {
      id: 'supply_chain_family',
      severity: 'high',
      description: 'Malicious package or framework family (npm / PyPI registry-pivot). The MAL- entries + Shai-Hulud class.',
      match: (e, id) =>
        id.startsWith('MAL-') ||
        (typeof e?.type === 'string' && /malicious|supply.chain|registry-pivot/i.test(e.type)),
    },
    {
      id: 'ai_discovered_kev',
      severity: 'high',
      description: 'AI-discovered CVE that also appears on CISA KEV — the operational-reality intersection Hard Rule #7 calls out.',
      match: (e) => e?.ai_discovered === true && e?.cisa_kev === true,
    },
    {
      id: 'active_exploitation_unpatched',
      severity: 'critical',
      description: 'Confirmed in-the-wild exploitation AND no patch available. Defensive-posture-only window.',
      match: (e) => e?.active_exploitation === 'confirmed' && e?.patch_available !== true,
    },
    {
      id: 'recent_poc_no_kev_yet',
      severity: 'medium',
      description: 'CVE with public PoC verified within the last 14 days but not yet on KEV. The "exploitation expected; KEV catch-up pending" window.',
      match: (e) =>
        e?.poc_available === true &&
        e?.cisa_kev !== true &&
        daysSince(e?.source_verified) <= 14,
      fresh_only: true,
    },
  ];

  const alerts = [];
  let scanned = 0;
  for (const [id, entry] of Object.entries(catalog)) {
    if (id === '_meta') continue;
    if (!entry || typeof entry !== 'object') continue;
    scanned++;
    const matched = [];
    for (const p of PATTERNS) {
      try {
        if (p.match(entry, id)) matched.push({ id: p.id, severity: p.severity });
      } catch { /* defensive: pattern matcher must not throw on malformed entries */ }
    }
    if (matched.length === 0) continue;
    alerts.push({
      cve_id: id,
      name: entry.name || null,
      rwep_score: entry.rwep_score ?? null,
      cisa_kev: entry.cisa_kev ?? null,
      poc_available: entry.poc_available ?? null,
      active_exploitation: entry.active_exploitation ?? null,
      patch_available: entry.patch_available ?? null,
      source_verified: entry.source_verified || null,
      patterns: matched,
      links: Array.isArray(entry.verification_sources) ? entry.verification_sources.slice(0, 3) : [],
    });
  }

  // Severity band first, then highest RWEP, then CVE id for a stable order.
  const severityWeight = { critical: 0, high: 1, medium: 2, low: 3 };
  alerts.sort((a, b) => {
    const sa = Math.min(...a.patterns.map((p) => severityWeight[p.severity] ?? 9));
    const sb = Math.min(...b.patterns.map((p) => severityWeight[p.severity] ?? 9));
    if (sa !== sb) return sa - sb;
    const ra = a.rwep_score ?? -1;
    const rb = b.rwep_score ?? -1;
    if (ra !== rb) return rb - ra;
    return a.cve_id.localeCompare(b.cve_id);
  });

  if (jsonOut) {
    process.stdout.write(JSON.stringify({
      ok: true,
      verb: 'watchlist',
      mode: 'alerts',
      generated_at: today.toISOString(),
      patterns_evaluated: PATTERNS.length,
      entries_scanned: scanned,
      alert_count: alerts.length,
      alerts,
    }) + '\n');
    return;
  }

  console.log(`\nCVE-class Alerts — ${today.toISOString()}`);
  console.log(`Entries scanned: ${scanned}  patterns evaluated: ${PATTERNS.length}  alerts: ${alerts.length}\n`);
  if (alerts.length === 0) {
    console.log('No alert-pattern matches in current catalog.');
    return;
  }
  for (const a of alerts) {
    const labels = a.patterns.map((p) => `[${p.severity}] ${p.id}`).join(', ');
    console.log(`${a.cve_id}  RWEP=${a.rwep_score ?? '?'}  KEV=${a.cisa_kev ? 'Y' : 'N'}  PoC=${a.poc_available ? 'Y' : 'N'}  patch=${a.patch_available ? 'Y' : 'N'}  active=${a.active_exploitation ?? '?'}`);
    console.log(`  ${a.name || '(no name)'}`);
    console.log(`  patterns: ${labels}`);
    if (a.links.length > 0) console.log(`  ${a.links[0]}`);
    console.log('');
  }
  console.log('Run with --json to consume programmatically.');
}

/**
 * Cache-first variant of validateAllCves: builds a ValidationResult matching the
 * shape sources/validators/cve-validator.js produces, so a downstream consumer
 * needs no second code path. A missing cache entry falls through to the live
 * validator, so a partial cache still yields a complete report.
 */
async function validateAllCvesPreferCache(catalog, cacheDir) {
  const fs = require('fs');
  const path = require('path');
  const crypto = require('crypto');
  const { validateCve } = require('../sources/validators');

  // Cap on any single cache file: a malformed prefetch payload would otherwise
  // OOM the validator on JSON.parse. Well above the few-MB full KEV feed.
  const CACHE_FILE_MAX_BYTES = 50 * 1024 * 1024;

  // Every prefetch payload records a per-entry sha256, so recomputing on read
  // catches a rewrite. It is taken over JSON.stringify(payload) unindented,
  // which is why the re-stringify below matches.
  let cacheIndex = null;
  try {
    cacheIndex = JSON.parse(fs.readFileSync(path.join(cacheDir, '_index.json'), 'utf8'));
  } catch { cacheIndex = null; }

  // False on any tamper signal — no index, no sha256 entry, or a mismatch. The
  // caller then validates that CVE live, so forged cache cannot mask drift.
  function cacheEntryVerified(source, id, parsed) {
    const meta = cacheIndex && cacheIndex.entries && cacheIndex.entries[`${source}/${id}`];
    if (!meta || typeof meta.sha256 !== 'string') {
      console.error(`[validate-cves] cache integrity: no recorded sha256 for ${source}/${id}; ignoring cache entry and validating live.`);
      return false;
    }
    const actual = crypto.createHash('sha256').update(JSON.stringify(parsed)).digest('hex');
    if (actual !== meta.sha256) {
      console.error(`[validate-cves] cache integrity: sha256 mismatch for ${source}/${id} (expected ${meta.sha256.slice(0, 16)}..., got ${actual.slice(0, 16)}...); ignoring tampered cache entry and validating live.`);
      return false;
    }
    return true;
  }

  function readCached(source, id) {
    const safe = id.replace(/[^A-Za-z0-9._-]/g, '_');
    const p = path.join(cacheDir, source, `${safe}.json`);
    let fd;
    // Open once and fstat the descriptor — no existsSync→statSync→read TOCTOU.
    try { fd = fs.openSync(p, 'r'); }
    catch { return null; } // absent / unreadable (matches the old existsSync:false skip)
    try {
      const st = fs.fstatSync(fd);
      if (st.size > CACHE_FILE_MAX_BYTES) {
        console.error(`[validate-cves] cache file ${p} exceeds ${CACHE_FILE_MAX_BYTES} byte cap (${st.size}); refusing to read.`);
        return null;
      }
      // readFileSync(fd) loops to EOF — a single readSync can come back short on
      // a network fd, NUL-filling the tail and truncating the JSON.
      const parsed = JSON.parse(fs.readFileSync(fd, 'utf8'));
      if (!cacheEntryVerified(source, id, parsed)) return null;
      return parsed;
    }
    catch { return null; }
    finally { if (fd !== undefined) { try { fs.closeSync(fd); } catch { /* non-fatal */ } } }
  }

  function extractNvd(payload) {
    const vuln = payload?.vulnerabilities?.[0]?.cve;
    if (!vuln) return { found: false };
    const m = vuln.metrics || {};
    const ordered = [...(m.cvssMetricV31 || []), ...(m.cvssMetricV30 || []), ...(m.cvssMetricV2 || [])];
    const primary = ordered.find((x) => x.type === 'Primary') || ordered[0];
    return {
      found: true,
      score: typeof primary?.cvssData?.baseScore === 'number' ? primary.cvssData.baseScore : null,
      vector: primary?.cvssData?.vectorString || null,
    };
  }

  function extractEpss(payload, id) {
    const data = Array.isArray(payload?.data) ? payload.data : [];
    const row = data.find((r) => r?.cve === id) || data[0];
    if (!row) return null;
    return {
      score: row.epss != null ? Number(row.epss) : null,
      percentile: row.percentile != null ? Number(row.percentile) : null,
      date: typeof row.date === 'string' ? row.date : null,
    };
  }

  const kevFeed = readCached('kev', 'known_exploited_vulnerabilities');
  const kevMap = new Map();
  if (kevFeed) {
    for (const v of kevFeed.vulnerabilities || []) {
      if (v && v.cveID) kevMap.set(v.cveID, v);
    }
  }

  const ids = Object.keys(catalog).filter((k) => /^CVE-\d{4}-\d{4,7}$/.test(k));
  const results = [];
  const by_status = { match: 0, drift: 0, unreachable: 0, missing: 0 };
  let cacheHits = 0;
  let liveFallbacks = 0;

  for (const id of ids) {
    const local = catalog[id];
    const nvdPayload = readCached('nvd', id);
    const epssPayload = readCached('epss', id);

    if (!nvdPayload && !kevFeed && !epssPayload) {
      liveFallbacks++;
      try {
        const r = await validateCve(id, local);
        results.push(r);
        by_status[r.status] = (by_status[r.status] || 0) + 1;
      } catch (err) {
        results.push({ cve_id: id, status: 'unreachable', discrepancies: [], fetched: { sources: { nvd: null, kev: null, epss: null } }, local, error: err.message });
        by_status.unreachable++;
      }
      continue;
    }

    cacheHits++;
    const discrepancies = [];
    const fetched = {
      cvss_score: null, cvss_vector: null,
      in_kev: null, kev_date: null,
      epss: null,
      sources: { nvd: null, kev: null, epss: null },
    };

    if (nvdPayload) {
      const n = extractNvd(nvdPayload);
      if (n.found) {
        fetched.cvss_score = n.score;
        fetched.cvss_vector = n.vector;
        fetched.sources.nvd = { reachable: true, found: true, fromCache: true };
        if (n.score != null && local.cvss_score != null && Math.abs(n.score - local.cvss_score) > 0.05) {
          discrepancies.push({ field: 'cvss_score', local: local.cvss_score, fetched: n.score, severity: 'high' });
        }
        if (n.vector && local.cvss_vector && n.vector !== local.cvss_vector) {
          discrepancies.push({ field: 'cvss_vector', local: local.cvss_vector, fetched: n.vector, severity: 'medium' });
        }
      } else {
        fetched.sources.nvd = { reachable: true, found: false, fromCache: true };
      }
    } else {
      fetched.sources.nvd = { reachable: false, error: 'cache miss' };
    }

    if (kevFeed) {
      const hit = kevMap.get(id);
      fetched.in_kev = !!hit;
      fetched.kev_date = hit?.dateAdded || null;
      fetched.sources.kev = { reachable: true, total_entries: kevMap.size, fromCache: true };
      if (typeof local.cisa_kev === 'boolean' && local.cisa_kev !== fetched.in_kev) {
        discrepancies.push({ field: 'cisa_kev', local: local.cisa_kev, fetched: fetched.in_kev, severity: 'high' });
      }
      if (local.cisa_kev_date && fetched.kev_date && local.cisa_kev_date !== fetched.kev_date) {
        discrepancies.push({ field: 'cisa_kev_date', local: local.cisa_kev_date, fetched: fetched.kev_date, severity: 'low' });
      }
    } else {
      fetched.sources.kev = { reachable: false, error: 'cache miss' };
    }

    if (epssPayload) {
      const e = extractEpss(epssPayload, id);
      if (e) {
        fetched.epss = e;
        fetched.sources.epss = { reachable: true, found: true, date: e.date, fromCache: true };
        if (e.score != null && local.epss_score != null && Math.abs(e.score - local.epss_score) > 0.05) {
          discrepancies.push({ field: 'epss_score', local: local.epss_score, fetched: e.score, severity: 'medium' });
        }
        if (e.percentile != null && local.epss_percentile != null && Math.abs(e.percentile - local.epss_percentile) > 0.05) {
          discrepancies.push({ field: 'epss_percentile', local: local.epss_percentile, fetched: e.percentile, severity: 'medium' });
        }
      } else {
        fetched.sources.epss = { reachable: true, found: false, fromCache: true };
      }
    } else {
      fetched.sources.epss = { reachable: false, error: 'cache miss' };
    }

    const status = discrepancies.length === 0 ? 'match' : 'drift';
    results.push({ cve_id: id, status, discrepancies, fetched, local });
    by_status[status] = (by_status[status] || 0) + 1;
  }

  return {
    generated_at: new Date().toISOString(),
    total: ids.length,
    by_status,
    drift_count: by_status.drift,
    cache_hits: cacheHits,
    live_fallbacks: liveFallbacks,
    results,
  };
}

function printHelp() {
  console.log(`
exceptd Security Orchestrator

Commands:
  scan              Scan environment (kernel, MCP, crypto, AI APIs, framework gaps)
  dispatch          Scan then route findings to relevant skills
  skill <name>      Show context for a specific skill by name
  pipeline [type]   Initialize a pipeline run (type: new_cve|atlas_update|manual)
  currency          Check skill currency scores
  report [format]   Generate report (format: executive|technical|compliance)
  watch             Start event watcher (long-running)
  validate-cves     Cross-check the CVE catalog against NVD + CISA KEV + EPSS
                    Flags: --offline | --no-fail | --from-cache [<dir>]
                    --from-cache prefers cached upstream snapshots written by
                    \`npm run prefetch\` (default .cache/upstream); cache misses
                    fall back to live network per CVE.
  validate-rfcs     Cross-check the RFC catalog against IETF Datatracker
                    Flags: --offline | --no-fail | --from-cache [<dir>]
  watchlist         Aggregate forward_watch entries across all skills (--by-skill to invert)
  help              Show this help

Environment variables:
  EXCEPTD_DATA_DIR     Path to data directory (default: ../data)
  EXCEPTD_MANIFEST     Path to manifest.json (default: ../manifest.json)
  EXCEPTD_SCAN_TARGETS Directories to scan for MCP configs

Examples:
  exceptd scan
  exceptd skill kernel-lpe-triage
  exceptd currency
  exceptd report executive
  exceptd watch
`);
}

/**
 * GitHub repo-pattern monitoring per NEW-CTRL-052: the Shai-Hulud worm uses
 * GitHub itself as the exfil channel, so an operator scans their own org
 * (--org <login>, or GITHUB_ORG) for the threat-actor naming patterns.
 * GITHUB_TOKEN lifts the rate limit and adds private-repo coverage.
 */
async function runWatchlistOrgScan(rawArgs = []) {
  const jsonOut = rawArgs.includes('--json');
  // --output-format takes json | markdown | human; --json resolves to json.
  let outputFormat = jsonOut ? 'json' : 'human';
  for (let i = 0; i < rawArgs.length; i++) {
    if (rawArgs[i] === '--output-format' && rawArgs[i + 1]) outputFormat = rawArgs[i + 1];
    if (rawArgs[i].startsWith('--output-format=')) outputFormat = rawArgs[i].slice('--output-format='.length);
  }
  const VALID_FORMATS = ['json', 'markdown', 'human'];
  if (!VALID_FORMATS.includes(outputFormat)) {
    process.stdout.write(JSON.stringify({
      ok: false,
      verb: 'watchlist',
      mode: 'org-scan',
      error: `watchlist --org-scan: --output-format "${outputFormat}" not in accepted set ${JSON.stringify(VALID_FORMATS)}.`,
      accepted: VALID_FORMATS,
      provided: outputFormat,
    }) + '\n');
    safeExit(EXIT_CODES.GENERIC_FAILURE);
    return;
  }
  let org = null;
  for (let i = 0; i < rawArgs.length; i++) {
    if (rawArgs[i] === '--org' && rawArgs[i + 1]) { org = rawArgs[i + 1]; break; }
    if (rawArgs[i].startsWith('--org=')) { org = rawArgs[i].slice('--org='.length); break; }
  }
  if (!org) org = process.env.GITHUB_ORG || null;
  if (!org) {
    process.stdout.write(JSON.stringify({
      ok: false,
      verb: 'watchlist',
      mode: 'org-scan',
      error: 'watchlist --org-scan requires --org <login> (or GITHUB_ORG env var). Example: exceptd watchlist --org-scan --org blamejs',
    }) + '\n');
    safeExit(EXIT_CODES.GENERIC_FAILURE);
    return;
  }
  // Every pattern query reaches api.github.com with no offline substitute, so
  // air-gap refuses before any fetch. Same refusal shape as source-ghsa.
  if (process.env.EXCEPTD_AIR_GAP === '1' || rawArgs.includes('--air-gap')) {
    process.stdout.write(JSON.stringify({
      ok: false,
      source: 'air-gap',
      verb: 'watchlist',
      mode: 'org-scan',
      error: 'air-gap: watchlist --org-scan requires network egress to api.github.com; refused.',
    }) + '\n');
    safeExit(EXIT_CODES.BLOCKED);
    return;
  }
  // --pattern is repeatable; the defaults come from MAL-2026-SHAI-HULUD-OSS.
  const customPatterns = [];
  for (let i = 0; i < rawArgs.length; i++) {
    if (rawArgs[i] === '--pattern' && rawArgs[i + 1]) customPatterns.push(rawArgs[i + 1]);
    if (rawArgs[i].startsWith('--pattern=')) customPatterns.push(rawArgs[i].slice('--pattern='.length));
  }
  const DEFAULT_PATTERNS = [
    { id: 'shai-hulud-classic', q: 'Shai-Hulud', severity: 'critical', source: 'MAL-2026-SHAI-HULUD-OSS (pre-source-release naming)' },
    { id: 'teampcp-gift', q: 'A Gift From TeamPCP', severity: 'critical', source: 'MAL-2026-SHAI-HULUD-OSS (post-2026-05-12 release naming)' },
    { id: 'teampcp-bare', q: 'TeamPCP', severity: 'high', source: 'MAL-2026-SHAI-HULUD-OSS threat actor reference' },
  ];
  const patterns = [
    ...DEFAULT_PATTERNS,
    ...customPatterns.map((q, i) => ({ id: `custom-${i + 1}`, q, severity: 'medium', source: 'operator --pattern' })),
  ];

  // Both GitHub search endpoints return items[] with name, html_url, owner, created_at.
  const token = process.env.GITHUB_TOKEN || '';
  const matches = [];
  let rateLimited = false;
  let unauth = !token;
  if (typeof fetch !== 'function') {
    process.stdout.write(JSON.stringify({
      ok: false,
      verb: 'watchlist',
      mode: 'org-scan',
      error: 'fetch() not available — Node 18+ required.',
    }) + '\n');
    safeExit(EXIT_CODES.GENERIC_FAILURE);
    return;
  }
  // Patterns whose query exhausted its retries, surfaced in the envelope: a flaky
  // 5xx silently yielding "no matches" for a threat-actor pattern is the false
  // negative NEW-CTRL-052 defends against.
  const erroredPatterns = [];
  // A 5xx, timeout or reset retries with backoff and jitter; a permanent 4xx does
  // not, and 403/429 short-circuit to the rateLimited flag.
  const retryable = (err) => {
    // 403/429 are the documented rate-limit signal — surface at once rather than
    // burn the retry budget; the operator re-runs with GITHUB_TOKEN set.
    if (err && err._rateLimit) return false;
    if (err && typeof err.statusCode === 'number') return err.statusCode >= 500;
    if (err && (err.name === 'AbortError' || err.name === 'TimeoutError')) return true;
    const code = err && (err.code || (err.cause && err.cause.code));
    return !!code && /^(ECONNRESET|ECONNREFUSED|ECONNABORTED|ETIMEDOUT|EPIPE|EAGAIN|ENOTFOUND|ENETUNREACH|UND_ERR)/.test(String(code));
  };
  for (const p of patterns) {
    const url = `https://api.github.com/search/repositories?q=${encodeURIComponent(p.q + ' org:' + org)}&per_page=100`;
    const headers = { 'User-Agent': 'exceptd-watchlist-org-scan/0.13.3 (+https://exceptd.com)', 'Accept': 'application/vnd.github+json' };
    if (token) headers.Authorization = `Bearer ${token}`;
    // Each attempt gets a fresh abort timer.
    const attempt = async () => {
      const ac = new AbortController();
      const timer = setTimeout(() => ac.abort(), 10000);
      try {
        const r = await fetch(url, { headers, signal: ac.signal });
        if (r.status === 403 || r.status === 429) {
          const e = new Error(`HTTP ${r.status}`);
          e.statusCode = r.status;
          e._rateLimit = true; // surfaced as rateLimited, never retried
          throw e;
        }
        if (!r.ok) { const e = new Error(`HTTP ${r.status}`); e.statusCode = r.status; throw e; }
        return await r.json();
      } finally {
        clearTimeout(timer);
      }
    };
    try {
      const body = await withRetry(attempt, { maxAttempts: 3, baseDelayMs: 100, maxDelayMs: 2000, jitterFactor: 0.5, isRetryable: retryable });
      for (const item of body.items || []) {
        matches.push({
          pattern_id: p.id,
          severity: p.severity,
          source: p.source,
          repo: item.full_name,
          url: item.html_url,
          private: item.private,
          created_at: item.created_at,
          updated_at: item.updated_at,
          stars: item.stargazers_count || 0,
        });
      }
    } catch (err) {
      // A non-rate-limit failure that exhausted its retries marks the pattern
      // errored, so a dropped query is distinguishable from a clean no-match.
      if (err && err._rateLimit) {
        rateLimited = true;
      } else {
        erroredPatterns.push({ pattern_id: p.id, error: (err && err.message) || String(err) });
      }
    }
  }
  const generated_at = new Date().toISOString();
  if (outputFormat === 'json') {
    process.stdout.write(JSON.stringify({
      // A rate-limited or errored pattern means a zero match-count is not "clean".
      ok: !rateLimited && erroredPatterns.length === 0,
      verb: 'watchlist',
      mode: 'org-scan',
      generated_at,
      org,
      patterns_evaluated: patterns.length,
      match_count: matches.length,
      matches,
      rate_limited: rateLimited,
      errored_patterns: erroredPatterns,
      unauthenticated: unauth,
      control_reference: 'NEW-CTRL-052 (MAL-2026-SHAI-HULUD-OSS lesson)',
    }) + '\n');
    return;
  }
  if (outputFormat === 'markdown') {
    // Paste-friendly for a PR, issue or advisory body. Carries the unauthenticated
    // and rate-limit caveats, so the receiver knows how far to trust the result.
    const lines = [];
    lines.push(`## GitHub Org-Scan: ${org}`);
    lines.push('');
    lines.push(`Generated at \`${generated_at}\`. ${patterns.length} threat-actor naming patterns evaluated. ${matches.length} match(es) found.`);
    lines.push('');
    if (unauth) {
      lines.push('> **Note:** scan ran unauthenticated. Private-repo coverage is incomplete; rate-limit reduces query throughput. Set `GITHUB_TOKEN` env var for full coverage.');
      lines.push('');
    }
    if (rateLimited) {
      lines.push('> **Warning:** GitHub rate limit hit on at least one pattern query. Some matches may be missing. Re-run with `GITHUB_TOKEN` set to lift the limit.');
      lines.push('');
    }
    if (erroredPatterns.length > 0) {
      lines.push(`> **Warning:** ${erroredPatterns.length} pattern quer${erroredPatterns.length === 1 ? 'y' : 'ies'} failed after retries (${erroredPatterns.map((e) => e.pattern_id).join(', ')}). A zero match-count for ${erroredPatterns.length === 1 ? 'that pattern' : 'those patterns'} is NOT a clean result — re-run to confirm.`);
      lines.push('');
    }
    if (matches.length === 0) {
      lines.push('_No repositories matching threat-actor patterns found._');
    } else {
      lines.push('| Severity | Repo | Visibility | Created | Pattern | URL |');
      lines.push('|---|---|---|---|---|---|');
      for (const m of matches) {
        const vis = m.private ? '🔒 private' : '🌐 public';
        const created = (m.created_at || '').slice(0, 10);
        lines.push(`| **${m.severity}** | \`${m.repo}\` | ${vis} | ${created} | ${m.pattern_id} | [link](${m.url}) |`);
      }
    }
    lines.push('');
    lines.push(`Control reference: NEW-CTRL-052 (MAL-2026-SHAI-HULUD-OSS lesson — \`exceptd watchlist --org-scan\`).`);
    process.stdout.write(lines.join('\n') + '\n');
    return;
  }
  // human (default)
  console.log(`\nGitHub Org-Scan — ${generated_at}`);
  console.log(`Org: ${org}  patterns: ${patterns.length}  matches: ${matches.length}`);
  if (unauth) console.log('(unauthenticated — set GITHUB_TOKEN for private-repo coverage + higher rate limit)');
  if (rateLimited) console.log('WARNING: GitHub rate limit hit on at least one query. Re-run with GITHUB_TOKEN set.');
  if (erroredPatterns.length > 0) {
    console.log(`WARNING: ${erroredPatterns.length} pattern quer${erroredPatterns.length === 1 ? 'y' : 'ies'} failed after retries (${erroredPatterns.map((e) => e.pattern_id).join(', ')}). A zero match-count for those is NOT a clean result — re-run to confirm.`);
  }
  if (matches.length === 0) {
    console.log('No threat-actor-pattern repos found.');
    return;
  }
  for (const m of matches) {
    console.log(`[${m.severity}] ${m.repo}  ${m.private ? '(private)' : ''} created ${m.created_at}`);
    console.log(`    pattern: ${m.pattern_id} (${m.source})`);
    console.log(`    ${m.url}`);
  }
}

// Gated on require.main so `require('./orchestrator')` does not trigger a CLI
// dispatch inside the importing process.
if (require.main === module) {
  main().catch(err => {
    // The same ok:false envelope on the fatal path, so a JSON consumer can parse it.
    console.error(JSON.stringify({ ok: false, verb: cmd, error: String((err && err.message) || err) }));
    process.exitCode = 1;
  });
}

module.exports = {
  // Verb runners stay internal — reach them through the CLI surface.
  main,
  parseFlags,
};
