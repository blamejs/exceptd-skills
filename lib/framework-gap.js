'use strict';

/**
 * Framework gap analysis and lag scoring library.
 * Operates on data/framework-control-gaps.json and data/global-frameworks.json.
 */

const THEATER_PATTERNS = {
  patch_management: {
    name: 'Patch Management Theater',
    description: 'Organization meets framework patch SLA but remains exposed to active exploitation.',
    detection_test: (control, cveData) => {
      if (!control.real_requirement) return false;
      const hasExploitedCVE = control.evidence_cves?.some(id => {
        const cve = cveData[id];
        return cve && (cve.cisa_kev || cve.active_exploitation === 'confirmed');
      });
      return hasExploitedCVE && control.status === 'open';
    }
  },
  access_control_ai: {
    name: 'AI Access Control Theater',
    description: 'Service account authorization is compliant; prompt injection bypasses it entirely.',
    detection_test: (control) => {
      return control.control_id === 'AC-2' && control.status === 'open' &&
        control.misses?.some(m => m.toLowerCase().includes('prompt injection'));
    }
  },
  vendor_management_ai: {
    name: 'Vendor Management Theater',
    description: 'Vendor management controls pass audit but do not reach AI tool plugins (MCP servers).',
    detection_test: (control) => {
      return (control.control_id === 'SA-12' || control.control_id === 'CC9') &&
        control.status === 'open' &&
        control.misses?.some(m => m.toLowerCase().includes('mcp'));
    }
  },
  malware_protection_ai: {
    name: 'Malware Protection Theater',
    description: 'Signature-based malware protection is compliant; AI-generated novel code evades all signatures.',
    detection_test: (control) => {
      return control.control_id === 'SI-3' && control.status === 'open' &&
        control.misses?.some(m => m.toLowerCase().includes('promptflux') || m.toLowerCase().includes('ai-generated'));
    }
  },
  supply_chain_ai: {
    name: 'Supply Chain Theater',
    description: 'Software supply chain controls pass audit; developer-installed AI plugins are outside scope.',
    detection_test: (control) => {
      return control.status === 'open' &&
        control.misses?.some(m => m.toLowerCase().includes('mcp server') && m.toLowerCase().includes('supply chain'));
    }
  },
  encryption_pqc: {
    name: 'Encryption Theater',
    description: 'Encryption controls are compliant with classical algorithms; HNDL exposure is unaddressed.',
    detection_test: (control) => {
      return control.status === 'open' &&
        control.misses?.some(m => m.toLowerCase().includes('quantum') || m.toLowerCase().includes('pqc'));
    }
  },
  detection_ai: {
    name: 'Detection Theater',
    description: 'Security monitoring is compliant; AI C2 (SesameOp) and AI-querying malware are not detected.',
    detection_test: (control) => {
      return control.status === 'open' &&
        control.misses?.some(m => m.toLowerCase().includes('ai api') || m.toLowerCase().includes('c2'));
    }
  }
};

const LAG_WEIGHTS = {
  patch_sla_days_vs_optimal: 0.30,
  universal_gaps_count: 0.25,
  ai_framework_coverage: 0.20,
  pqc_requirement: 0.10,
  notification_sla_hours: 0.15
};

const OPTIMAL = {
  patch_sla_days: 2,
  notification_sla_hours: 4,
  universal_gaps: 0
};

/**
 * How far a framework lags current threat reality, 0 (no lag) to 100 (complete
 * theater), as { score, label, breakdown }. The catalogs arrive parsed.
 */
function lagScore(frameworkId, controlGaps, globalFrameworks) {
  const frameworkData = _findFrameworkData(frameworkId, globalFrameworks);

  // global-frameworks is keyed by short id (EU_AI_ACT) while
  // framework-control-gaps stores display strings ("EU Artificial Intelligence
  // Act (2024/1689)"), so the display name resolves first and matching uses the
  // SAME normalized scheme as gapReport(). `g.framework` is a string or an array.
  const normalize = (s) => String(s).toLowerCase().replace(/[\s_-]/g, '');
  const idNorm = normalize(frameworkId);
  const nameNorm = frameworkData?.full_name ? normalize(frameworkData.full_name) : null;
  // catalog_aliases in data/global-frameworks.json bridges a framework's
  // full_name and the labels the control-gap catalog uses: ASD_ISM is also
  // "au-ism" / "ACSC ISM" there, which neither nameNorm nor idNorm matches.
  const aliasNorms = Array.isArray(frameworkData?.catalog_aliases)
    ? frameworkData.catalog_aliases.map((a) => normalize(a)).filter(Boolean)
    : [];
  const gaps = Object.entries(controlGaps).filter(([key, g]) => {
    if (key.startsWith('_')) return false;
    if (g.status !== 'open' || !g.framework) return false;
    const fwList = Array.isArray(g.framework) ? g.framework : [g.framework];
    for (const fw of fwList) {
      const fwNorm = normalize(fw);
      if (nameNorm && fwNorm.includes(nameNorm)) return true;   // display-name match
      if (fwNorm.includes(idNorm)) return true;                 // short-key substring
      if (aliasNorms.some((a) => a && (fwNorm.includes(a) || a.includes(fwNorm)))) return true; // catalog-label alias
    }
    if (normalize(key).startsWith(idNorm)) return true;         // gap-key prefix
    return false;
  });
  // A framework that resolves yet matches zero catalog gaps is almost always a
  // label missing from catalog_aliases, not a gap-free framework.
  const resolvedButZeroGaps = Boolean(frameworkData && gaps.length === 0);

  const universalGaps = Object.values(controlGaps).filter(g =>
    g.framework === 'ALL' && g.status === 'open'
  );

  const patchSlaScore = _scorePatchSla(frameworkData?.patch_sla);
  const notifSlaScore = _scoreNotifSla(frameworkData?.notification_sla);
  const aiCoverageScore = _scoreAiCoverage(frameworkData?.ai_coverage);
  const pqcScore = frameworkData?.pqc_coverage === 'None' ? 100 : 30;
  const universalGapScore = Math.min(100, universalGaps.length * 20);

  const weighted =
    patchSlaScore * LAG_WEIGHTS.patch_sla_days_vs_optimal +
    universalGapScore * LAG_WEIGHTS.universal_gaps_count +
    aiCoverageScore * LAG_WEIGHTS.ai_framework_coverage +
    pqcScore * LAG_WEIGHTS.pqc_requirement +
    notifSlaScore * LAG_WEIGHTS.notification_sla_hours;

  const score = Math.round(Math.min(100, weighted));

  return {
    score,
    label: _lagLabel(score),
    breakdown: {
      patch_sla: { raw_days: frameworkData?.patch_sla ?? null, score: patchSlaScore },
      notification_sla: { raw_hours: frameworkData?.notification_sla ?? null, score: notifSlaScore },
      ai_coverage: { coverage: frameworkData?.ai_coverage ?? 'unknown', score: aiCoverageScore },
      pqc_coverage: { coverage: frameworkData?.pqc_coverage ?? 'unknown', score: pqcScore },
      universal_gaps: { count: universalGaps.length, score: universalGapScore },
      framework_specific_gaps: gaps.length,
      framework_resolved_but_zero_gaps: resolvedButZeroGaps
    }
  };
}

/**
 * Gap report for one or more frameworks against a threat scenario — a CVE id or
 * free text. Omitting `opts.lessons` (parsed zeroday-lessons.json) yields a
 * report with no new-control section rather than an error. Returns
 * { frameworks, universal_gaps, new_control_requirements, theater_risks, summary }.
 *
 * `cveCatalog` is positional surface this function does not read — the scenario
 * matches against `controlGaps` alone. It holds the fourth slot so `opts` stays
 * fifth, and mirrors theaterCheck(), which does read its catalog. Dropping the
 * parameter would silently bind every caller's `opts` argument to it instead.
 */
function gapReport(frameworkIds, threatScenario, controlGaps, cveCatalog = {}, opts = {}) {
  const scenario = threatScenario.toLowerCase();

  const relevantGaps = Object.entries(controlGaps).filter(([, gap]) => {
    const misses = gap.misses?.join(' ').toLowerCase() ?? '';
    const real = gap.real_requirement?.toLowerCase() ?? '';
    return (
      misses.includes(scenario) ||
      real.includes(scenario) ||
      gap.evidence_cves?.some(id => id.toLowerCase() === scenario)
    );
  });

  const universalGaps = Object.values(controlGaps).filter(g =>
    g.framework === 'ALL' && g.status === 'open'
  );

  const frameworkResults = {};
  for (const id of frameworkIds) {
    // A filter id matches three ways: exactly against gap.framework, as a
    // normalized substring of it ("nist-800-53" → "NIST SP 800-53 Rev 5"), or as
    // a normalized prefix of the gap KEY ("NIST-800-53-SI-2").
    const normalize = (s) => String(s).toLowerCase().replace(/[\s_-]/g, '');
    const idNorm = normalize(id);
    const frameworkGaps = relevantGaps.filter(([key, g]) => {
      if (!g.framework) return false;
      if (g.framework === id) return true;
      if (normalize(g.framework).includes(idNorm)) return true;
      if (normalize(key).startsWith(idNorm)) return true;
      return false;
    });
    frameworkResults[id] = {
      gap_count: frameworkGaps.length,
      gaps: frameworkGaps.map(([key, g]) => ({
        id: key,
        control: g.control_name,
        real_requirement: g.real_requirement,
        status: g.status
      })),
      theater_exposure: frameworkGaps.some(([, g]) => g.status === 'open')
    };
  }

  // With an explicit filter only the gaps that survived it belong in the report;
  // with `all`, every scenario-relevant gap does. theater_risks and the matching
  // count both derive from this, so body, theater list and footer agree.
  let scopedGaps;
  if (opts.allFrameworks) {
    scopedGaps = relevantGaps;
  } else {
    const seen = new Set();
    for (const id of frameworkIds) {
      for (const g of frameworkResults[id]?.gaps ?? []) seen.add(g.id);
    }
    scopedGaps = relevantGaps.filter(([key]) => seen.has(key));
  }

  // Theater-risk is open AND EITHER `theater_test` OR `theater_pattern` — most
  // entries have only the structured test, and filtering on `theater_pattern`
  // alone puts the badge and the summary footer at odds.
  const theaterRisks = scopedGaps
    .filter(([, g]) => g.status === 'open' && (g.theater_test || g.theater_pattern))
    .map(([key, g]) => ({
      control: key,
      pattern: g.theater_pattern || (g.theater_test && g.theater_test.claim) || null,
      framework: g.framework,
      theater_test_present: !!g.theater_test,
    }));

  // The summary counts what the operator sees, so the footer cannot overcount.
  const matchingGapCount = scopedGaps.length;

  // Controls the zero-day lesson for this CVE says no framework carries yet —
  // the other half of what `frameworks[].gaps` answers. Keyed by CVE, so a
  // free-text scenario legitimately resolves to none.
  const lessons = (opts && opts.lessons) || {};
  const lessonEntry = Object.entries(lessons)
    .find(([id]) => id.toLowerCase() === scenario);
  const newControls = (lessonEntry && Array.isArray(lessonEntry[1].new_control_requirements))
    ? lessonEntry[1].new_control_requirements
      // A record the renderer cannot print is dropped rather than emitted as
      // "- undefined undefined:". EVERY interpolated field is checked — guarding
      // `id` alone still lets `{ id: 'NEW-X' }` through as "NEW-X undefined:".
      .filter(c =>
        c && typeof c === 'object' &&
        typeof c.id === 'string' && c.id.trim() !== '' &&
        typeof c.name === 'string' && c.name.trim() !== '' &&
        typeof c.description === 'string' && c.description.trim() !== ''
      )
      .map(c => ({
        id: c.id,
        name: c.name,
        requirement: c.description,
        evidence: c.evidence,
        // The framework controls this closes; without them it is free-floating advice.
        closes: Array.isArray(c.gap_closes) ? c.gap_closes : [],
      }))
    : [];

  return {
    threat_scenario: threatScenario,
    frameworks: frameworkResults,
    universal_gaps: universalGaps.map(g => ({
      id: g.control_id,
      name: g.control_name,
      real_requirement: g.real_requirement
    })),
    new_control_requirements: newControls,
    theater_risks: theaterRisks,
    summary: {
      total_gaps: matchingGapCount,
      universal_gaps: universalGaps.length,
      new_control_requirements: newControls.length,
      theater_risk_controls: theaterRisks.length
    }
  };
}

/**
 * Runs every THEATER_PATTERNS check against a control inventory, returning
 * { findings, theater_score, theater_label, compliant_but_exposed, recommendation }.
 */
function theaterCheck(controlGaps, cveCatalog = {}) {
  const findings = [];

  for (const [patternId, pattern] of Object.entries(THEATER_PATTERNS)) {
    const matchingControls = Object.values(controlGaps).filter(control =>
      pattern.detection_test(control, cveCatalog)
    );

    if (matchingControls.length > 0) {
      findings.push({
        pattern_id: patternId,
        pattern_name: pattern.name,
        description: pattern.description,
        affected_controls: matchingControls.map(c => c.control_id || c.control_name),
        severity: _theaterSeverity(patternId)
      });
    }
  }

  const theaterScore = Math.min(100, findings.length * 15);

  return {
    findings,
    theater_score: theaterScore,
    theater_label: _theaterLabel(theaterScore),
    compliant_but_exposed: findings.length > 0,
    recommendation: findings.length > 0
      ? 'Compliance audit would pass. Real-world exposure exists. Address highest-severity theater patterns first.'
      : 'No theater patterns detected in scanned controls.'
  };
}

/** Every framework in globalFrameworks with its lag score, sorted descending. */
function compareFrameworks(controlGaps, globalFrameworks) {
  const results = [];
  const frameworkIds = _extractFrameworkIds(globalFrameworks);

  for (const id of frameworkIds) {
    const lag = lagScore(id, controlGaps, globalFrameworks);
    results.push({ framework: id, ...lag });
  }

  return results.sort((a, b) => b.score - a.score);
}

function _findFrameworkData(frameworkId, globalFrameworks) {
  for (const jurisdiction of Object.values(globalFrameworks)) {
    if (!jurisdiction.frameworks) continue;
    for (const [key, fw] of Object.entries(jurisdiction.frameworks)) {
      if (key === frameworkId || fw.full_name?.includes(frameworkId)) return fw;
    }
  }
  return null;
}

function _scorePatchSla(sla_hours) {
  if (sla_hours === null || sla_hours === undefined) return 60;
  const days = sla_hours / 24;
  if (days <= 2) return 10;
  if (days <= 7) return 30;
  if (days <= 14) return 55;
  if (days <= 30) return 80;
  return 95;
}

function _scoreNotifSla(sla_hours) {
  if (sla_hours === null || sla_hours === undefined) return 50;
  if (sla_hours <= 4) return 10;
  if (sla_hours <= 24) return 30;
  if (sla_hours <= 72) return 60;
  return 80;
}

function _scoreAiCoverage(coverage) {
  if (!coverage || coverage === 'None') return 100;
  if (coverage.toLowerCase().includes('no ai-specific')) return 80;
  if (coverage.toLowerCase().includes('partial')) return 50;
  return 20;
}

function _lagLabel(score) {
  if (score >= 80) return 'critical_lag';
  if (score >= 60) return 'significant_lag';
  if (score >= 40) return 'moderate_lag';
  if (score >= 20) return 'minor_lag';
  return 'current';
}

function _theaterSeverity(patternId) {
  const high = ['access_control_ai', 'malware_protection_ai', 'vendor_management_ai'];
  const critical = ['patch_management'];
  if (critical.includes(patternId)) return 'critical';
  if (high.includes(patternId)) return 'high';
  return 'medium';
}

function _theaterLabel(score) {
  if (score >= 75) return 'systemic_theater';
  if (score >= 45) return 'significant_theater';
  if (score >= 15) return 'partial_theater';
  return 'minimal_theater';
}

function _extractFrameworkIds(globalFrameworks) {
  const ids = [];
  for (const jurisdiction of Object.values(globalFrameworks)) {
    if (!jurisdiction.frameworks) continue;
    ids.push(...Object.keys(jurisdiction.frameworks));
  }
  return ids;
}

module.exports = { lagScore, gapReport, theaterCheck, compareFrameworks };
