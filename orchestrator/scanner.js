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

    findings.push({
      domain: 'crypto',
      signal: 'openssl_version',
      value: version,
      pqc_ready: isPqcReady,
      severity: isPqcReady ? 'info' : 'high',
      skill_hint: 'pqc-first',
      action_required: isPqcReady
        ? `OpenSSL ${version} — PQC-capable. Verify ML-KEM/ML-DSA algorithm availability.`
        : `OpenSSL ${version} — below 3.5. Upgrade required for PQC support (ML-KEM, ML-DSA, SLH-DSA).`
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
