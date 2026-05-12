'use strict';

/**
 * Environment scanner. Discovers security posture signals from the current host.
 * Produces structured findings that dispatcher.js routes to relevant skills.
 *
 * Designed to be run by a human operator or an AI assistant — not a background daemon.
 * All discovery is read-only. No writes, no network calls beyond local probes.
 */

const fs = require('fs');
const path = require('path');
const os = require('os');
const { execFileSync, spawnSync } = require('child_process');

const DATA_DIR = process.env.EXCEPTD_DATA_DIR || path.join(__dirname, '..', 'data');

// --- public API ---

/**
 * Run all scanners and return consolidated findings.
 * @returns {{ timestamp: string, host: object, findings: object[], summary: object }}
 */
async function scan() {
  const timestamp = new Date().toISOString();
  const findings = [];

  const host = hostInfo();
  findings.push(...kernelScan());
  findings.push(...mcpScan());
  findings.push(...cryptoScan());
  findings.push(...aiApiScan());
  findings.push(...frameworkScan());

  const summary = summarize(findings);
  return { timestamp, host, findings, summary };
}

/**
 * Run a targeted scan for a specific domain.
 * @param {'kernel'|'mcp'|'crypto'|'ai_api'|'framework'} domain
 */
async function scanDomain(domain) {
  const scanners = { kernel: kernelScan, mcp: mcpScan, crypto: cryptoScan, ai_api: aiApiScan, framework: frameworkScan };
  const fn = scanners[domain];
  if (!fn) throw new Error(`Unknown scan domain: ${domain}. Valid: ${Object.keys(scanners).join(', ')}`);
  return fn();
}

// --- domain scanners ---

function kernelScan() {
  const findings = [];
  if (os.platform() !== 'linux') return findings;

  const kernel = safeExecFile('uname', ['-r']) || 'unknown';
  const catalog = loadJson('cve-catalog.json');

  for (const [cveId, cve] of Object.entries(catalog)) {
    if (cve.type !== 'LPE' && cve.type !== 'kernel') continue;
    findings.push({
      domain: 'kernel',
      signal: 'kernel_version_detected',
      value: kernel,
      cve_id: cveId,
      rwep_score: cve.rwep_score,
      cisa_kev: cve.cisa_kev,
      action_required: 'Cross-reference kernel version against patched version for this CVE',
      skill_hint: 'kernel-lpe-triage',
      severity: cve.rwep_score >= 90 ? 'critical' : cve.rwep_score >= 70 ? 'high' : 'medium'
    });
  }

  return findings;
}

function mcpScan() {
  const findings = [];
  const homeDir = os.homedir();
  const platform = os.platform();

  const mcpLocations = [
    { tool: 'claude-code', paths: [path.join(homeDir, '.claude', 'settings.json')] },
    { tool: 'cursor', paths: [path.join(homeDir, '.cursor', 'mcp.json')] },
    { tool: 'vscode', paths: [
      path.join(homeDir, '.vscode', 'settings.json'),
      ...(platform === 'darwin' ? [path.join(homeDir, 'Library', 'Application Support', 'Code', 'User', 'settings.json')] : []),
      ...(platform === 'win32' ? [path.join(homeDir, 'AppData', 'Roaming', 'Code', 'User', 'settings.json')] : []),
      ...(platform === 'linux' ? [path.join(homeDir, '.config', 'Code', 'User', 'settings.json')] : [])
    ]},
    { tool: 'windsurf', paths: [path.join(homeDir, '.windsurf', 'mcp.json')] },
    { tool: 'gemini-cli', paths: [path.join(homeDir, '.gemini', 'settings.json')] }
  ];

  for (const { tool, paths } of mcpLocations) {
    for (const p of paths) {
      if (!fs.existsSync(p)) continue;
      try {
        const raw = fs.readFileSync(p, 'utf8');
        const config = JSON.parse(raw);
        const mcpServers = config.mcpServers || config.mcp?.servers || {};
        const serverList = Object.keys(mcpServers);
        if (serverList.length === 0) continue;

        for (const serverName of serverList) {
          const server = mcpServers[serverName];
          const isSigned = server.signature !== undefined;
          const serverJson = JSON.stringify(server);
          const hasPinnedVersion = /[@#]\d+\.\d+\.\d+/.test(serverJson);

          findings.push({
            domain: 'mcp',
            signal: 'mcp_server_detected',
            tool,
            config_path: p,
            server_name: serverName,
            server_config: sanitizeConfig(server),
            signed: isSigned,
            version_pinned: hasPinnedVersion,
            severity: !isSigned ? 'high' : !hasPinnedVersion ? 'medium' : 'low',
            skill_hint: 'mcp-agent-trust',
            action_required: !isSigned
              ? 'Unsigned MCP server — verify provenance immediately'
              : !hasPinnedVersion
              ? 'MCP server version not pinned — pin to a specific version'
              : 'MCP server detected — include in security review'
          });
        }
      } catch (_) {
        findings.push({
          domain: 'mcp',
          signal: 'mcp_config_parse_error',
          tool,
          config_path: p,
          severity: 'low',
          action_required: 'MCP config file exists but could not be parsed'
        });
      }
    }
  }

  return findings;
}

function cryptoScan() {
  const findings = [];

  const opensslRaw = safeExecFile('openssl', ['version']);
  if (opensslRaw) {
    const match = opensslRaw.match(/OpenSSL (\d+\.\d+\.\d+)/);
    const version = match ? match[1] : 'unknown';
    const [major, minor] = version.split('.').map(Number);
    const isPqcReady = major > 3 || (major === 3 && minor >= 5);

    // Probe the full NIST PQC suite + stateful hash signatures.
    // Reports per-algo via boolean flags so downstream callers can
    // decide which gaps matter for their threat model (ML-KEM for
    // HNDL exposure, LMS/XMSS for firmware signing, etc.).
    const pqc = probePqcAlgorithms();
    const pqcDetail = [
      `ML-KEM=${pqc.ml_kem ? 'avail' : 'missing'}`,    // FIPS 203
      `ML-DSA=${pqc.ml_dsa ? 'avail' : 'missing'}`,    // FIPS 204
      `SLH-DSA=${pqc.slh_dsa ? 'avail' : 'missing'}`,  // FIPS 205
      `FN-DSA=${pqc.fn_dsa ? 'avail' : 'missing'}`,    // FIPS 206 draft (Falcon)
      `HQC=${pqc.hqc ? 'avail' : 'missing'}`,          // alternate KEM (March 2025)
      `LMS=${pqc.lms ? 'avail' : 'missing'}`,          // RFC 8554 (firmware)
      `XMSS=${pqc.xmss ? 'avail' : 'missing'}`,        // RFC 8391
    ].join(' ');

    findings.push({
      domain: 'crypto',
      signal: 'openssl_version',
      value: version,
      pqc_ready: isPqcReady,
      pqc_algorithms: pqc,
      severity: isPqcReady && pqc.ml_kem ? 'info' : (isPqcReady ? 'medium' : 'high'),
      skill_hint: 'pqc-first',
      action_required: isPqcReady
        ? (pqc.ml_kem
          ? `OpenSSL ${version} — PQC-capable. Probed: ${pqcDetail}.`
          : `OpenSSL ${version} — claims PQC support but probe found no ML-KEM. Check provider config; may need OQS-Provider or Node 24 crypto.kemEncapsulate. Probed: ${pqcDetail}.`)
        : `OpenSSL ${version} — below 3.5. Upgrade required for PQC support (ML-KEM, ML-DSA, SLH-DSA, FN-DSA, HQC, LMS, XMSS).`
    });
  }

  const tlsProbe = probeTls();
  if (tlsProbe) {
    findings.push({
      domain: 'crypto',
      signal: 'tls_probe',
      value: tlsProbe,
      severity: tlsProbe.includes('TLSv1.3') ? 'info' : 'high',
      skill_hint: 'pqc-first',
      action_required: tlsProbe.includes('TLSv1.3')
        ? 'TLS 1.3 detected — verify X25519+ML-KEM-768 hybrid for HNDL-exposed connections'
        : 'TLS below 1.3 — upgrade to TLS 1.3 minimum'
    });
  }

  return findings;
}

function aiApiScan() {
  const findings = [];

  const aiApiIndicators = [
    { name: 'openai', envVars: ['OPENAI_API_KEY'] },
    { name: 'anthropic', envVars: ['ANTHROPIC_API_KEY'] },
    { name: 'google-ai', envVars: ['GOOGLE_AI_API_KEY', 'GEMINI_API_KEY'] },
    { name: 'azure-openai', envVars: ['AZURE_OPENAI_API_KEY'] },
    { name: 'cohere', envVars: ['COHERE_API_KEY'] },
    { name: 'mistral', envVars: ['MISTRAL_API_KEY'] },
    { name: 'groq', envVars: ['GROQ_API_KEY'] },
    { name: 'together-ai', envVars: ['TOGETHER_API_KEY'] }
  ];

  for (const api of aiApiIndicators) {
    const detected = api.envVars.some(v => process.env[v]);
    if (!detected) continue;

    findings.push({
      domain: 'ai_api',
      signal: 'ai_api_dependency_detected',
      api_name: api.name,
      severity: 'info',
      skill_hint: 'ai-c2-detection',
      action_required: `${api.name} AI API detected — verify process-level monitoring and query anomaly alerting`
    });
  }

  const apiCount = findings.filter(f => f.signal === 'ai_api_dependency_detected').length;
  if (apiCount > 0) {
    findings.push({
      domain: 'ai_api',
      signal: 'ai_api_c2_risk_summary',
      count: apiCount,
      severity: 'medium',
      skill_hint: 'ai-c2-detection',
      action_required: `${apiCount} AI API(s) detected. Run ai-c2-detection skill to assess SesameOp/PROMPTFLUX exposure.`
    });
  }

  return findings;
}

function frameworkScan() {
  const findings = [];
  const gaps = loadJson('framework-control-gaps.json');
  const openGaps = Object.entries(gaps).filter(([, g]) => g.status === 'open');

  if (openGaps.length > 0) {
    findings.push({
      domain: 'framework',
      signal: 'open_framework_gaps',
      count: openGaps.length,
      universal_gaps: openGaps.filter(([, g]) => g.framework === 'ALL').length,
      severity: 'high',
      skill_hint: 'framework-gap-analysis',
      action_required: `${openGaps.length} open control gaps — run framework-gap-analysis for your compliance scope`
    });
  }

  const kev = loadJson('cve-catalog.json');
  const kevHigh = Object.entries(kev).filter(([, c]) => c.cisa_kev && c.rwep_score >= 90);
  if (kevHigh.length > 0) {
    findings.push({
      domain: 'framework',
      signal: 'cisa_kev_high_rwep',
      items: kevHigh.map(([id, c]) => ({ id, rwep: c.rwep_score, name: c.name })),
      severity: 'critical',
      skill_hint: 'compliance-theater',
      action_required: `${kevHigh.length} CISA KEV CVEs with RWEP >= 90. Standard 30-day patch SLAs are theater for these.`
    });
  }

  return findings;
}

// --- helpers ---

function hostInfo() {
  return {
    platform: os.platform(),
    arch: os.arch(),
    release: os.release(),
    hostname: os.hostname(),
    scan_user: os.userInfo().username
  };
}

function summarize(findings) {
  const byDomain = {};
  const bySeverity = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) {
    byDomain[f.domain] = (byDomain[f.domain] || 0) + 1;
    if (bySeverity[f.severity] !== undefined) bySeverity[f.severity]++;
  }
  const skills = [...new Set(findings.map(f => f.skill_hint).filter(Boolean))];
  return {
    total_findings: findings.length,
    by_domain: byDomain,
    by_severity: bySeverity,
    recommended_skills: skills,
    action_required: bySeverity.critical > 0 || bySeverity.high > 0
  };
}

function safeExecFile(cmd, args) {
  try {
    return execFileSync(cmd, args, { timeout: 5000, stdio: ['pipe', 'pipe', 'pipe'] })
      .toString().trim();
  } catch (_) {
    return null;
  }
}

/**
 * Probe runtime for PQC algorithm availability across the full
 * emerging-standards landscape. Returns boolean flags per algorithm
 * + a `provider_hint` indicating which surface confirmed each one.
 *
 *   --- NIST PQC finalized (FIPS 203/204/205, 2024) ---
 *   ml_kem      ML-KEM (Kyber) — FIPS 203, key encapsulation
 *   ml_dsa      ML-DSA (Dilithium) — FIPS 204, signatures
 *   slh_dsa     SLH-DSA (SPHINCS+) — FIPS 205, stateless hash sigs
 *
 *   --- NIST PQC draft / alternate (2025+) ---
 *   fn_dsa      FN-DSA (Falcon) — FIPS 206 draft, compact lattice sigs
 *   hqc         HQC — alternate KEM selected March 2025
 *
 *   --- NIST PQC Round-4 alternates (still relevant in niche / archival) ---
 *   frodo       FrodoKEM — conservative lattice KEM
 *   ntru        NTRU / NTRU-Prime / sNTRU — original lattice KEM family
 *   mceliece    Classic McEliece — code-based, long-term archival use
 *   bike        BIKE — code-based KEM, OQS-Provider exposed
 *
 *   --- NIST additional signature on-ramp (2023+ Round 2) ---
 *   hawk        HAWK — NTRU-based lattice signatures
 *   mayo        MAYO — multivariate
 *   sqisign     SQIsign — isogeny-based, small signatures
 *   cross       CROSS — code-based
 *   uov         UOV / SNOVA — Unbalanced Oil & Vinegar multivariate
 *   sdith       SDitH — code-based (Syndrome Decoding in the Head)
 *   mirath      MIRATH — code-based (rank metric)
 *   faest       FAEST — symmetric-key/AES-based signatures
 *   perk        PERK — code-based (Permuted Kernel Problem)
 *
 *   --- Stateful hash signatures (RFC 8391 / 8554) ---
 *   lms         LMS — Leighton-Micali Signatures (firmware)
 *   xmss        XMSS — eXtended Merkle Signature Scheme
 *   hss         HSS — Hierarchical Signature System
 *
 *   --- IETF hybrid / composite sigs (emerging RFC drafts) ---
 *   composite_sig   Composite Signatures (e.g. RSA+ML-DSA, ECDSA+ML-DSA)
 *   composite_kem   Composite KEMs (e.g. X25519+ML-KEM)
 */
function probePqcAlgorithms() {
  const result = {
    // NIST finalized
    ml_kem: false, ml_dsa: false, slh_dsa: false,
    // NIST draft / alternate
    fn_dsa: false, hqc: false,
    // NIST Round-4 / niche
    frodo: false, ntru: false, mceliece: false, bike: false,
    // NIST signature on-ramp (Round 2)
    hawk: false, mayo: false, sqisign: false, cross: false,
    uov: false, sdith: false, mirath: false, faest: false, perk: false,
    // Stateful hash sigs
    lms: false, xmss: false, hss: false,
    // IETF composite / hybrid
    composite_sig: false, composite_kem: false,
    provider_hint: {},
  };
  const crypto = require('crypto');

  // Pattern table — values are regexes matching common spellings
  // emitted by Node / OpenSSL / OQS-Provider / Bouncy Castle. Tested
  // against algorithm-list output specifically (no English-prose
  // false positives expected; the lists contain only algo names).
  const PATTERNS = {
    // NIST finalized
    ml_kem:        /\b(ml-?kem|kyber)\b/i,
    ml_dsa:        /\b(ml-?dsa|dilithium)\b/i,
    slh_dsa:       /\b(slh-?dsa|sphincs(?:\+|plus)?)\b/i,
    // NIST draft / alternate
    fn_dsa:        /\b(fn-?dsa|falcon-?\d{3,4})\b/i,
    hqc:           /\bhqc(-?\d+)?\b/i,
    // NIST Round-4 / niche
    frodo:         /\bfrodo(-?\d+)?(kem)?\b/i,
    ntru:          /\b(s?ntru(-?prime)?(-?\d+)?|hrss\d*|hps\d+)\b/i,
    mceliece:      /\b(classic-?)?mceliece(-?\d+)?\b/i,
    bike:          /\bbike(-?l?\d+)?\b/i,
    // NIST signature on-ramp (Round 2, 2024+)
    hawk:          /\bhawk(-?\d+)?\b/i,
    mayo:          /\bmayo(-?\d+)?\b/i,
    sqisign:       /\bsqi-?sign(?:hd)?\b/i,
    cross:         /\bcross-?(rsdp|rsdpg)?-?(small|fast|balanced)?-?[lns]?\d*\b/i,
    uov:           /\b(uov|snova)(-?\d+)?\b/i,
    sdith:         /\bsd-?i?t?h(-?gf\d+)?(-?cat\d+)?\b/i,
    mirath:        /\bmirath(-?\d+)?\b/i,
    faest:         /\bfaest(-em)?(-?\d+)?\b/i,
    perk:          /\bperk-?[ls]?-?\d*\b/i,
    // Stateful hash signatures
    lms:           /\blms(?!-sha)\b/i,
    xmss:          /\bxmss(\^?mt)?\b/i,
    hss:           /\bhss(?!-sha)\b/i,
    // Composite / hybrid (IETF drafts)
    composite_sig: /\bcomposite-?(sig|signature)\b|\bhybrid-?sig\b|\b(rsa|ecdsa|eddsa)-?(\+|with)-?(ml-?dsa|dilithium|slh-?dsa|sphincs|falcon|fn-?dsa)\b/i,
    composite_kem: /\bcomposite-?kem\b|\b(x25519|x448|secp\d+)-?(\+|with)-?(ml-?kem|kyber)\b|\bml-?kem-?(\+|with)-?(x25519|x448)\b/i,
  };

  function record(algo, source) {
    if (!result[algo]) {
      result[algo] = true;
      result.provider_hint[algo] = source;
    }
  }

  // Channel 1 — Node's crypto APIs (no shellouts). Node 24+ exposes
  // crypto.kemEncapsulate as an experimental ML-KEM gateway; its
  // presence is itself an ML-KEM availability signal.
  try {
    if (typeof crypto.kemEncapsulate === 'function') {
      record('ml_kem', 'node:crypto.kemEncapsulate');
    }
    const allNames = [
      ...(crypto.getCurves ? crypto.getCurves() : []),
      ...(crypto.getHashes ? crypto.getHashes() : []),
      ...(crypto.getCiphers ? crypto.getCiphers() : []),
    ];
    for (const name of allNames) {
      for (const [algo, re] of Object.entries(PATTERNS)) {
        if (re.test(name)) record(algo, `node:${name}`);
      }
    }
  } catch (_) { /* probe failure → fall through to openssl */ }

  // Channel 2 — `openssl list` enumerations. KEMs and signature
  // algorithms split across two list commands; OQS-Provider exposes
  // the on-ramp / niche algos when installed.
  const kemList = safeExecFile('openssl', ['list', '-kem-algorithms']);
  if (kemList) {
    const kemAlgos = ['ml_kem', 'hqc', 'frodo', 'ntru', 'mceliece', 'bike', 'composite_kem'];
    for (const algo of kemAlgos) {
      if (PATTERNS[algo].test(kemList)) record(algo, 'openssl:list -kem-algorithms');
    }
  }
  const sigList = safeExecFile('openssl', ['list', '-signature-algorithms']);
  if (sigList) {
    const sigAlgos = [
      'ml_dsa', 'slh_dsa', 'fn_dsa',
      'hawk', 'mayo', 'sqisign', 'cross', 'uov', 'sdith', 'mirath', 'faest', 'perk',
      'lms', 'xmss', 'hss',
      'composite_sig',
    ];
    for (const algo of sigAlgos) {
      if (PATTERNS[algo].test(sigList)) record(algo, 'openssl:list -signature-algorithms');
    }
  }

  return result;
}

function probeTls() {
  const result = spawnSync('openssl', ['s_client', '-connect', 'google.com:443', '-brief'], {
    input: '',
    timeout: 5000,
    stdio: ['pipe', 'pipe', 'pipe']
  });
  if (result.error || result.status !== 0) return null;
  const output = (result.stdout || '').toString() + (result.stderr || '').toString();
  const match = output.match(/Protocol\s*:\s*(TLSv\d+\.\d+)/);
  return match ? match[1] : null;
}

function sanitizeConfig(obj) {
  const safe = { ...obj };
  for (const key of Object.keys(safe)) {
    if (/token|key|secret|password|credential/i.test(key)) safe[key] = '[REDACTED]';
  }
  return safe;
}

function loadJson(filename) {
  try {
    return JSON.parse(fs.readFileSync(path.join(DATA_DIR, filename), 'utf8'));
  } catch (_) {
    return {};
  }
}

module.exports = { scan, scanDomain };
