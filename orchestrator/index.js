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
 *   validate-rfcs     Cross-check the RFC catalog against IETF Datatracker
 *   watchlist         Aggregate forward_watch entries across all skills
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
    case 'watchlist':
      runWatchlist(args);
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
  // --from-cache: prefer cached upstream snapshots before falling back to live
  // network. Accepts an optional path; defaults to .cache/upstream when bare.
  // The cache layout is fixed by lib/prefetch.js — same one refresh-external
  // reads from.
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
  const modeStr = offline
    ? 'offline (local view only)'
    : (cacheDir ? `live with cache (${path.relative(path.join(__dirname, '..'), cacheDir)})` : 'live (NVD + CISA KEV)');
  console.log(`${cveIds.length} CVEs in catalog. Mode: ${modeStr}`);
  console.log(`Fail-on-drift: ${noFail ? 'disabled' : 'enabled'}\n`);

  // --- Header (fixed-width; works with the existing currency command's style)
  const header = 'CVE                | Local RWEP | Local CVSS | NVD CVSS         | KEV Local | KEV NVD | EPSS Local      | EPSS Live       | EPSS Drift | Status';
  const rule   = '-------------------|------------|------------|------------------|-----------|---------|-----------------|-----------------|------------|----------';
  console.log(header);
  console.log(rule);

  function fmt(v, n) {
    const s = (v === null || v === undefined) ? '-' : String(v);
    return s.length >= n ? s.slice(0, n) : s + ' '.repeat(n - s.length);
  }

  // Format an EPSS pair as "score / percentile" with 4-decimal score, 2-decimal pct.
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
    process.exit(0);
    return;
  }

  // Live path — opportunistically use the prefetch cache when --from-cache
  // is set. Cache-resolved CVEs short-circuit the network fetch; missing
  // entries fall through to the live validator. Both paths produce the
  // same ValidationResult shape.
  const { validateAllCves } = require('../sources/validators');
  let report;
  if (cacheDir && fs.existsSync(cacheDir)) {
    report = await validateAllCvesPreferCache(catalog, cacheDir);
  } else {
    report = await validateAllCves(catalog, { concurrency: 4 });
  }

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

    // EPSS Local / Live / Drift block
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
    process.exit(2);
  }

  const ids = Object.keys(refs).filter(k => !k.startsWith('_'));

  console.log(`\nRFC Validation — ${new Date().toISOString()}`);
  const modeStr = offline
    ? 'offline (local view only)'
    : (cacheDir ? `live with cache (${path.relative(path.join(__dirname, '..'), cacheDir)})` : 'live (IETF Datatracker)');
  console.log(`${ids.length} RFC / draft entries in catalog. Mode: ${modeStr}`);
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

  // Cache-first helpers — read the prefetch payload for an RFC/draft and
  // compute drift the same way validateRfc would. Cache misses fall through
  // to the live validator.
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
    if (!noFail) process.exit(1);
  } else if (unreachable > 0) {
    console.log(`[validate-rfcs] ${unreachable} entry(ies) unreachable. Network/IETF Datatracker is intermittent — re-run later.`);
  } else if (!offline && validator) {
    console.log('[validate-rfcs] No drift detected against reachable upstream sources.');
  } else {
    console.log('[validate-rfcs] Offline view only. Re-run with --live (or omit --offline) to check against the IETF Datatracker.');
  }
}

/**
 * watchlist — aggregate `forward_watch` entries across every skill in
 * manifest.json into a single deduplicated, sorted list, with the skills
 * that listed each item and the most recent `last_threat_review` date among
 * them. Supports `--by-skill` to invert the view (per-skill watch items).
 *
 * Per AGENTS.md, `forward_watch` is the optional frontmatter field every
 * skill uses to flag upcoming standards changes, new TTPs, or RFC drops
 * that should trigger a skill update. This command surfaces the union so
 * maintainers can see the full horizon at a glance.
 */
function runWatchlist(rawArgs = []) {
  const fs = require('fs');
  const path = require('path');
  const { parseFrontmatter, extractFrontmatterBlock } = require('../lib/lint-skills.js');

  const byskill = rawArgs.includes('--by-skill');
  const manifestPath = path.join(__dirname, '..', 'manifest.json');
  const repoRoot = path.join(__dirname, '..');

  let manifest;
  try {
    manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
  } catch (err) {
    console.error(`[watchlist] cannot read ${manifestPath}: ${err.message}`);
    process.exit(2);
  }

  const skills = Array.isArray(manifest.skills) ? manifest.skills : [];
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
 * Cache-first variant of validateAllCves. For each catalog CVE, reads the
 * NVD + EPSS payload from the prefetch cache (cacheDir/nvd/<id>.json +
 * cacheDir/epss/<id>.json) and the KEV feed from cacheDir/kev/. Builds a
 * ValidationResult matching the shape sources/validators/cve-validator.js
 * produces so downstream consumers don't have to fork their logic.
 *
 * Missing cache entries fall through to the live validator for that CVE,
 * so partial caches still produce a complete report.
 */
async function validateAllCvesPreferCache(catalog, cacheDir) {
  const fs = require('fs');
  const path = require('path');
  const { validateCve } = require('../sources/validators');

  function readCached(source, id) {
    const safe = id.replace(/[^A-Za-z0-9._-]/g, '_');
    const p = path.join(cacheDir, source, `${safe}.json`);
    if (!fs.existsSync(p)) return null;
    try { return JSON.parse(fs.readFileSync(p, 'utf8')); }
    catch { return null; }
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
      // No cache for this CVE on any source — fall through to live.
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
