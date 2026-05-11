#!/usr/bin/env node
'use strict';

/**
 * exceptd orchestrator — CLI entry point.
 *
 * Commands:
 *   scan              Scan current environment and produce findings
 *   dispatch          Route findings to relevant skills
 *   skill <name>      Show context for a specific skill
 *   pipeline          Initialize and describe a pipeline run
 *   currency          Check skill currency scores
 *   report            Print dispatch plan as a report
 *   watch             Start event bus watcher (long-running)
 *   validate-cves     Remind to validate CVE entries against NVD
 *   help              Show this help
 */

const { scan } = require('./scanner');
const { dispatch, routeQuery, getSkillContext } = require('./dispatcher');
const { currencyCheck, initPipeline } = require('./pipeline');
const { bus, EVENT_TYPES } = require('./event-bus');
const { start: startScheduler, stop: stopScheduler, runCurrencyNow } = require('./scheduler');

const cmd = process.argv[2];
const args = process.argv.slice(3);

async function main() {
  switch (cmd) {
    case 'scan':
      await runScan();
      break;
    case 'dispatch':
      await runDispatch();
      break;
    case 'skill':
      runSkillContext(args[0]);
      break;
    case 'pipeline':
      runPipeline(args[0] || 'manual', args[1] ? JSON.parse(args[1]) : {});
      break;
    case 'currency':
      runCurrency();
      break;
    case 'report':
      await runReport(args[0] || 'technical');
      break;
    case 'watch':
      runWatch();
      break;
    case 'validate-cves':
      await runValidateCves(args);
      break;
    case 'validate-rfcs':
      await runValidateRfcs(args);
      break;
    case 'help':
    default:
      printHelp();
  }
}

// --- command implementations ---

async function runScan() {
  console.log('[orchestrator] Scanning environment...\n');
  const result = await scan();

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
  console.log('[orchestrator] Scanning then dispatching...\n');
  const scanResult = await scan();
  const plan = dispatch(scanResult.findings);

  console.log(`Dispatch plan — ${plan.plan.length} skills to invoke:\n`);

  for (const item of plan.plan) {
    const urgency = item.priority <= 1 ? 'CRITICAL' : item.priority === 2 ? 'HIGH' : 'MEDIUM';
    console.log(`[${urgency}] ${item.skill_name}`);
    console.log(`  Triggered by: ${item.triggered_by} (${item.finding_domain})`);
    console.log(`  Action: ${item.action_required}`);
    console.log(`  Path: ${item.skill_path}`);
    console.log();
  }

  if (plan.unmatched.length > 0) {
    console.log(`Unmatched findings (${plan.unmatched.length}):`);
    for (const f of plan.unmatched) console.log(`  - ${f.signal} (${f.domain})`);
  }

  return plan;
}

function runSkillContext(skillName) {
  if (!skillName) {
    console.error('Usage: node orchestrator/index.js skill <skill-name>');
    process.exit(1);
  }

  const context = getSkillContext(skillName);
  if (!context) {
    console.error(`Skill not found: ${skillName}`);
    process.exit(1);
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
  console.log('  node orchestrator/index.js skill skill-update-loop');
  return run;
}

function runCurrency() {
  const result = runCurrencyNow();
  const { currency_report, action_required, critical_count } = currencyCheck();

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
  console.log(`[orchestrator] Generating ${format} report...\n`);
  const scanResult = await scan();
  const plan = dispatch(scanResult.findings);
  const { currency_report } = currencyCheck();

  console.log('# exceptd Security Assessment Report');
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
  const stale = currency_report.filter(s => s.currency_score < 70);
  if (stale.length > 0) {
    console.log(`${stale.length} skills need review:`);
    for (const s of stale) console.log(`  - ${s.skill}: ${s.currency_score}% (${s.days_since_review}d old)`);
  } else {
    console.log('All skills current.');
  }
}

function runWatch() {
  console.log('[orchestrator] Starting event watcher...');
  console.log('Listening for: CISA KEV additions, ATLAS updates, CVE drops, framework amendments.\n');

  bus.onAny(event => {
    console.log(`[event] ${event.type} — ${event.timestamp}`);
    if (event.affected_skills.length > 0) {
      console.log(`  Affected skills: ${event.affected_skills.join(', ')}`);
    }
    if (event.payload.cve_id) {
      console.log(`  CVE: ${event.payload.cve_id}`);
    }
  });

  startScheduler();

  process.on('SIGINT', () => {
    console.log('\n[orchestrator] Stopping watcher.');
    stopScheduler();
    process.exit(0);
  });

  console.log('Press Ctrl+C to stop.\n');
}

async function runValidateCves(rawArgs = []) {
  const fs = require('fs');
  const path = require('path');

  const flags = new Set(rawArgs.filter(a => a.startsWith('--')));
  const offline = flags.has('--offline');
  const noFail = flags.has('--no-fail');

  const catalogPath = path.join(__dirname, '..', 'data', 'cve-catalog.json');
  let catalog;
  try {
    catalog = JSON.parse(fs.readFileSync(catalogPath, 'utf8'));
  } catch (err) {
    console.error(`[validate-cves] cannot read ${catalogPath}: ${err.message}`);
    process.exit(2);
  }

  const cveIds = Object.keys(catalog).filter(k => /^CVE-\d{4}-\d{4,7}$/.test(k));

  console.log(`\nCVE Validation — ${new Date().toISOString()}`);
  console.log(`${cveIds.length} CVEs in catalog. Mode: ${offline ? 'offline (local view only)' : 'live (NVD + CISA KEV)'}`);
  console.log(`Fail-on-drift: ${noFail ? 'disabled' : 'enabled'}\n`);

  // --- Header (fixed-width; works with the existing currency command's style)
  const header = 'CVE                | Local RWEP | Local CVSS | NVD CVSS         | KEV Local | KEV NVD | Status';
  const rule   = '-------------------|------------|------------|------------------|-----------|---------|----------';
  console.log(header);
  console.log(rule);

  function fmt(v, n) {
    const s = (v === null || v === undefined) ? '-' : String(v);
    return s.length >= n ? s.slice(0, n) : s + ' '.repeat(n - s.length);
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
        'local-only'
      );
    }
    console.log(`\n[validate-cves] offline mode — no network calls made. ${cveIds.length} entries listed from local catalog.`);
    process.exit(0);
    return;
  }

  // Live path.
  const { validateAllCves } = require('../sources/validators');
  const report = await validateAllCves(catalog, { concurrency: 4 });

  // Index results by cve_id (validateAllCves preserves insertion order, but be explicit).
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

    console.log(
      fmt(id, 18) + ' | ' +
      fmt(e.rwep_score, 10) + ' | ' +
      fmt(e.cvss_score, 10) + ' | ' +
      fmt(nvdScore === null ? '-' : `${nvdScore}${cvssMismatch ? ' DRIFT' : ''}`, 16) + ' | ' +
      fmt(e.cisa_kev, 9) + ' | ' +
      fmt(`${kevNvdStr}${kevMismatch ? ' DRIFT' : ''}`, 7) + ' | ' +
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
    if (!noFail) process.exit(1);
  } else {
    console.log('[validate-cves] No drift detected against reachable sources.');
  }
}

/**
 * validate-rfcs — companion to validate-cves for the IETF RFC / Internet-Draft
 * catalog. Confirms that every entry in data/rfc-references.json is current
 * against the IETF Datatracker.
 *
 * Modes:
 *   --offline   Print the local view only; do not fetch. Useful for airgapped
 *               CI runs and for fast iteration on the catalog file itself.
 *   --live      Fetch the IETF Datatracker for each RFC / draft (default if
 *               neither flag passed).
 *   --no-fail   Report drift but exit zero. Useful when you want a quarterly
 *               drift report without blocking CI.
 *
 * Per AGENTS.md hard rule #12 (external data version pinning), drift surfaces
 * are: status change (Draft → Standards Track → Internet Standard), new
 * errata since `last_verified`, replaced-by relationships, and obsoletion.
 * A local entry with no upstream is flagged. Network errors return
 * `unreachable` for that entry — they never fail the run.
 */
async function runValidateRfcs(rawArgs = []) {
  const fs = require('fs');
  const path = require('path');

  const flags = new Set(rawArgs.filter(a => a.startsWith('--')));
  const offline = flags.has('--offline');
  const noFail = flags.has('--no-fail');

  const refsPath = path.join(__dirname, '..', 'data', 'rfc-references.json');
  let refs;
  try {
    refs = JSON.parse(fs.readFileSync(refsPath, 'utf8'));
  } catch (err) {
    console.error(`[validate-rfcs] cannot read ${refsPath}: ${err.message}`);
    process.exit(2);
  }

  const ids = Object.keys(refs).filter(k => !k.startsWith('_'));

  console.log(`\nRFC Validation — ${new Date().toISOString()}`);
  console.log(`${ids.length} RFC / draft entries in catalog. Mode: ${offline ? 'offline (local view only)' : 'live (IETF Datatracker)'}`);
  console.log(`Fail-on-drift: ${noFail ? 'disabled' : 'enabled'}\n`);

  const header = 'ID                              | Status               | Errata | Last verified | Live status';
  const rule   = '--------------------------------|----------------------|--------|---------------|---------------------';
  console.log(header);
  console.log(rule);

  function fmt(v, n) {
    const s = (v === null || v === undefined) ? '-' : String(v);
    return s.length >= n ? s.slice(0, n) : s + ' '.repeat(n - s.length);
  }

  // Lazy-load the validator so an environment without `sources/validators`
  // installed still gets the offline view.
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

  for (const id of ids) {
    const entry = refs[id];
    let liveStatus = offline || !validator ? 'skipped (offline)' : '?';
    if (validator) {
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
    console.log(
      `${fmt(id, 32)}| ${fmt(entry.status, 20)} | ${fmt(entry.errata_count, 6)} | ${fmt(entry.last_verified, 13)} | ${liveStatus}`
    );
  }

  console.log();
  if (driftFound > 0) {
    console.log(`[validate-rfcs] DRIFT DETECTED on ${driftFound} entry(ies). Update data/rfc-references.json and bump last_verified.`);
    if (!noFail) process.exit(1);
  } else if (unreachable > 0) {
    console.log(`[validate-rfcs] ${unreachable} entry(ies) unreachable. Network/IETF Datatracker is intermittent — re-run later.`);
  } else if (!offline && validator) {
    console.log('[validate-rfcs] No drift detected against reachable upstream sources.');
  } else {
    console.log('[validate-rfcs] Offline view only. Re-run with --live (or omit --offline) to check against the IETF Datatracker.');
  }
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
  validate-cves     Cross-check the CVE catalog against NVD + CISA KEV (--offline | --no-fail)
  validate-rfcs     Cross-check the RFC catalog against IETF Datatracker  (--offline | --no-fail)
  help              Show this help

Environment variables:
  EXCEPTD_DATA_DIR     Path to data directory (default: ../data)
  EXCEPTD_MANIFEST     Path to manifest.json (default: ../manifest.json)
  EXCEPTD_SCAN_TARGETS Directories to scan for MCP configs

Examples:
  node orchestrator/index.js scan
  node orchestrator/index.js skill kernel-lpe-triage
  node orchestrator/index.js currency
  node orchestrator/index.js report executive
  node orchestrator/index.js watch
`);
}

main().catch(err => {
  console.error('[orchestrator] Fatal:', err.message);
  process.exit(1);
});
