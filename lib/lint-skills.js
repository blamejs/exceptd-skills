#!/usr/bin/env node
/*
 * lib/lint-skills.js — exceptd skill pre-ship linter.
 *
 * Enforces AGENTS.md rules that are otherwise informal:
 *   Rule #10 — No placeholder data. Skill bodies and frontmatter must not
 *              contain TODO / TBD / coming soon / placeholder / fixme / XXX
 *              / to be determined.
 *   Rule #11 — No-MVP ban. Every skill ships with complete frontmatter,
 *              all 7 required body sections, all data deps existing, and
 *              all referenced TTPs / framework controls resolving.
 *
 * For every skill registered in manifest.json this linter checks:
 *   - skill.md exists at the manifest path
 *   - frontmatter contains every required field per AGENTS.md spec
 *   - frontmatter values conform to lib/schemas/skill-frontmatter.schema.json
 *     (the subset relevant for this codebase — no external validator dep)
 *   - body contains all 7 required H2/H3 sections (case-insensitive):
 *     Threat Context, Framework Lag Declaration, TTP Mapping,
 *     Exploit Availability Matrix, Analysis Procedure, Output Format,
 *     Compliance Theater Check
 *   - body and frontmatter free of placeholder language
 *   - every data_deps filename resolves to data/<filename>
 *   - every atlas_refs ID exists as a top-level key in data/atlas-ttps.json
 *   - every framework_gaps ID exists as a top-level key in
 *     data/framework-control-gaps.json
 *
 * Usage:
 *   node lib/lint-skills.js              lint every skill
 *   node lib/lint-skills.js --skill foo  lint only the named skill
 *   node lib/lint-skills.js --quiet      only print failures and final summary
 *
 * Exit code: 0 if every linted skill passes, 1 otherwise.
 *
 * No external dependencies. Node 24 stdlib only.
 */

'use strict';

const fs = require('node:fs');
const path = require('node:path');
const process = require('node:process');

const REPO_ROOT = path.resolve(__dirname, '..');
const MANIFEST_PATH = path.join(REPO_ROOT, 'manifest.json');
const DATA_DIR = path.join(REPO_ROOT, 'data');
const ATLAS_PATH = path.join(DATA_DIR, 'atlas-ttps.json');
const FRAMEWORK_GAPS_PATH = path.join(DATA_DIR, 'framework-control-gaps.json');
const RFC_REFS_PATH = path.join(DATA_DIR, 'rfc-references.json');
const CWE_REFS_PATH = path.join(DATA_DIR, 'cwe-catalog.json');
const D3FEND_REFS_PATH = path.join(DATA_DIR, 'd3fend-catalog.json');
const DLP_REFS_PATH = path.join(DATA_DIR, 'dlp-controls.json');

const REQUIRED_FRONTMATTER_FIELDS = [
  'name',
  'version',
  'description',
  'triggers',
  'data_deps',
  'atlas_refs',
  'attack_refs',
  'framework_gaps',
  'last_threat_review',
];

const OPTIONAL_FRONTMATTER_FIELDS = ['forward_watch', 'rfc_refs', 'cwe_refs', 'd3fend_refs', 'dlp_refs'];

const ALL_KNOWN_FIELDS = new Set([
  ...REQUIRED_FRONTMATTER_FIELDS,
  ...OPTIONAL_FRONTMATTER_FIELDS,
]);

const REQUIRED_SECTIONS = [
  'Threat Context',
  'Framework Lag Declaration',
  'TTP Mapping',
  'Exploit Availability Matrix',
  'Analysis Procedure',
  'Output Format',
  'Compliance Theater Check',
];

const PLACEHOLDER_PATTERNS = [
  /\bTODO\b/i,
  /\bTBD\b/i,
  /\bcoming soon\b/i,
  /\bplaceholder\b/i,
  /\bto be determined\b/i,
  /\bFIXME\b/i,
  /\bXXX\b/,
];

const ATLAS_ID_RE = /^AML\.T\d{4}(\.\d{3})?$/;
const ATTACK_ID_RE = /^T\d{4}(\.\d{3})?$/;
const SEMVER_RE = /^\d+\.\d+\.\d+$/;
const ISO_DATE_RE = /^\d{4}-\d{2}-\d{2}$/;
const KEBAB_RE = /^[a-z0-9][a-z0-9-]*[a-z0-9]$/;
const JSON_FILENAME_RE = /^[A-Za-z0-9._-]+\.json$/;

function parseArgs(argv) {
  const opts = { skill: null, quiet: false };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--skill') {
      opts.skill = argv[++i] || null;
    } else if (a.startsWith('--skill=')) {
      opts.skill = a.slice('--skill='.length);
    } else if (a === '--quiet' || a === '-q') {
      opts.quiet = true;
    } else if (a === '--help' || a === '-h') {
      printHelp();
      process.exit(0);
    } else {
      console.error(`Unknown argument: ${a}`);
      printHelp();
      process.exit(2);
    }
  }
  return opts;
}

function printHelp() {
  console.log(
    'Usage: node lib/lint-skills.js [--skill <name>] [--quiet]\n' +
      '\n' +
      '  --skill <name>  Lint only the named skill from manifest.json.\n' +
      '  --quiet         Suppress per-skill PASS output; show failures only.\n' +
      '  --help          Show this message.\n',
  );
}

function readJson(p) {
  return JSON.parse(fs.readFileSync(p, 'utf8'));
}

/*
 * Minimal YAML frontmatter parser. Supports the subset actually used in this
 * repo:
 *   key: "quoted string"
 *   key: bare-string
 *   key: []                          (empty list)
 *   key:
 *     - item one
 *     - "item two"
 * Anything outside this shape produces a parse error so we don't silently
 * accept malformed frontmatter.
 */
function parseFrontmatter(text) {
  const lines = text.split(/\r?\n/);
  const result = {};
  let i = 0;
  while (i < lines.length) {
    const raw = lines[i];
    if (raw.trim() === '' || raw.trimStart().startsWith('#')) {
      i++;
      continue;
    }
    if (!/^\S/.test(raw)) {
      throw new Error(
        `Unexpected indented line at frontmatter top level (line ${i + 1}): ${raw}`,
      );
    }
    const m = raw.match(/^([A-Za-z_][A-Za-z0-9_]*):\s*(.*)$/);
    if (!m) {
      throw new Error(`Could not parse frontmatter line ${i + 1}: ${raw}`);
    }
    const key = m[1];
    const rest = m[2];
    if (rest === '' || rest === undefined) {
      const items = [];
      i++;
      while (i < lines.length && /^\s+-\s+/.test(lines[i])) {
        const itemMatch = lines[i].match(/^\s+-\s+(.*)$/);
        items.push(unquote(itemMatch[1].trim()));
        i++;
      }
      result[key] = items;
      continue;
    }
    if (rest.trim() === '[]') {
      result[key] = [];
      i++;
      continue;
    }
    result[key] = unquote(rest.trim());
    i++;
  }
  return result;
}

function unquote(s) {
  if (s.length >= 2) {
    const first = s[0];
    const last = s[s.length - 1];
    if ((first === '"' && last === '"') || (first === "'" && last === "'")) {
      return s.slice(1, -1);
    }
  }
  return s;
}

function extractFrontmatterBlock(content) {
  if (!content.startsWith('---')) {
    return { frontmatter: null, body: content, frontmatterRaw: '' };
  }
  const rest = content.slice(3);
  const endIdx = rest.indexOf('\n---');
  if (endIdx === -1) {
    return { frontmatter: null, body: content, frontmatterRaw: '' };
  }
  const raw = rest.slice(0, endIdx);
  const afterClose = rest.slice(endIdx + '\n---'.length);
  const bodyStart = afterClose.replace(/^\r?\n/, '');
  return { frontmatter: raw.replace(/^\r?\n/, ''), body: bodyStart, frontmatterRaw: raw };
}

/* Validate frontmatter object against the codified schema rules. */
function validateFrontmatter(fm, skillName) {
  const errors = [];

  for (const key of Object.keys(fm)) {
    if (!ALL_KNOWN_FIELDS.has(key)) {
      errors.push(`frontmatter: unknown field "${key}"`);
    }
  }
  for (const field of REQUIRED_FRONTMATTER_FIELDS) {
    if (!(field in fm)) {
      errors.push(`frontmatter: missing required field "${field}"`);
    }
  }

  if (typeof fm.name === 'string') {
    if (!KEBAB_RE.test(fm.name)) {
      errors.push(`frontmatter.name "${fm.name}" is not lowercase kebab-case`);
    }
    if (skillName && fm.name !== skillName) {
      errors.push(
        `frontmatter.name "${fm.name}" does not match manifest skill name "${skillName}"`,
      );
    }
  }

  if (typeof fm.version === 'string') {
    if (!SEMVER_RE.test(fm.version)) {
      errors.push(`frontmatter.version "${fm.version}" is not semver (x.y.z)`);
    }
  }

  if (typeof fm.description === 'string') {
    if (fm.description.length < 10) {
      errors.push('frontmatter.description is shorter than 10 characters');
    }
  } else if ('description' in fm) {
    errors.push('frontmatter.description must be a string');
  }

  if ('triggers' in fm) {
    if (!Array.isArray(fm.triggers) || fm.triggers.length === 0) {
      errors.push('frontmatter.triggers must be a non-empty list');
    } else {
      for (const t of fm.triggers) {
        if (typeof t !== 'string' || t.length === 0) {
          errors.push(`frontmatter.triggers contains a non-string or empty entry: ${JSON.stringify(t)}`);
        }
      }
    }
  }

  if ('data_deps' in fm) {
    if (!Array.isArray(fm.data_deps)) {
      errors.push('frontmatter.data_deps must be a list');
    } else {
      for (const d of fm.data_deps) {
        if (typeof d !== 'string' || !JSON_FILENAME_RE.test(d)) {
          errors.push(`frontmatter.data_deps entry is not a *.json filename: ${JSON.stringify(d)}`);
        }
      }
    }
  }

  if ('atlas_refs' in fm) {
    if (!Array.isArray(fm.atlas_refs)) {
      errors.push('frontmatter.atlas_refs must be a list');
    } else {
      for (const a of fm.atlas_refs) {
        if (typeof a !== 'string' || !ATLAS_ID_RE.test(a)) {
          errors.push(`frontmatter.atlas_refs entry is not a valid ATLAS ID: ${JSON.stringify(a)}`);
        }
      }
    }
  }

  if ('attack_refs' in fm) {
    if (!Array.isArray(fm.attack_refs)) {
      errors.push('frontmatter.attack_refs must be a list');
    } else {
      for (const a of fm.attack_refs) {
        if (typeof a !== 'string' || !ATTACK_ID_RE.test(a)) {
          errors.push(`frontmatter.attack_refs entry is not a valid ATT&CK ID: ${JSON.stringify(a)}`);
        }
      }
    }
  }

  if ('framework_gaps' in fm) {
    if (!Array.isArray(fm.framework_gaps)) {
      errors.push('frontmatter.framework_gaps must be a list');
    } else {
      for (const f of fm.framework_gaps) {
        if (typeof f !== 'string' || f.length === 0) {
          errors.push(`frontmatter.framework_gaps entry is empty or non-string: ${JSON.stringify(f)}`);
        }
      }
    }
  }

  if ('forward_watch' in fm) {
    if (!Array.isArray(fm.forward_watch)) {
      errors.push('frontmatter.forward_watch must be a list');
    }
  }

  if ('last_threat_review' in fm) {
    if (typeof fm.last_threat_review !== 'string' || !ISO_DATE_RE.test(fm.last_threat_review)) {
      errors.push(
        `frontmatter.last_threat_review "${fm.last_threat_review}" is not an ISO date (YYYY-MM-DD)`,
      );
    }
  }

  return errors;
}

function findMissingSections(body) {
  const lower = body.toLowerCase();
  const missing = [];
  for (const section of REQUIRED_SECTIONS) {
    if (!lower.includes(section.toLowerCase())) {
      missing.push(section);
    }
  }
  return missing;
}

function findPlaceholders(text) {
  const hits = [];
  const lines = text.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    for (const re of PLACEHOLDER_PATTERNS) {
      if (re.test(lines[i])) {
        hits.push({ line: i + 1, text: lines[i].trim(), pattern: re.source });
        break;
      }
    }
  }
  return hits;
}

function lintSkill(entry, ctx) {
  const skillErrors = [];
  const skillPath = path.join(REPO_ROOT, entry.path);

  if (!fs.existsSync(skillPath)) {
    return { name: entry.name, errors: [`skill file not found at ${entry.path}`] };
  }

  const content = fs.readFileSync(skillPath, 'utf8');
  const { frontmatter: fmRaw, body } = extractFrontmatterBlock(content);
  if (fmRaw === null) {
    skillErrors.push('skill.md does not start with a `---` YAML frontmatter block');
    return { name: entry.name, errors: skillErrors };
  }

  let fm;
  try {
    fm = parseFrontmatter(fmRaw);
  } catch (err) {
    skillErrors.push(`frontmatter parse error: ${err.message}`);
    return { name: entry.name, errors: skillErrors };
  }

  skillErrors.push(...validateFrontmatter(fm, entry.name));

  if (Array.isArray(fm.data_deps)) {
    for (const dep of fm.data_deps) {
      const depPath = path.join(DATA_DIR, dep);
      if (!fs.existsSync(depPath)) {
        skillErrors.push(`data_deps: file not found at data/${dep}`);
      }
    }
  }

  if (Array.isArray(fm.atlas_refs)) {
    for (const ref of fm.atlas_refs) {
      if (!ctx.atlasKeys.has(ref)) {
        skillErrors.push(`atlas_refs: "${ref}" not present in data/atlas-ttps.json`);
      }
    }
  }

  if (Array.isArray(fm.framework_gaps)) {
    for (const ref of fm.framework_gaps) {
      if (!ctx.frameworkKeys.has(ref)) {
        skillErrors.push(
          `framework_gaps: "${ref}" not present in data/framework-control-gaps.json`,
        );
      }
    }
  }

  if (Array.isArray(fm.rfc_refs)) {
    for (const ref of fm.rfc_refs) {
      if (!ctx.rfcKeys.has(ref)) {
        skillErrors.push(
          `rfc_refs: "${ref}" not present in data/rfc-references.json`,
        );
      }
    }
  }

  if (Array.isArray(fm.cwe_refs)) {
    for (const ref of fm.cwe_refs) {
      if (!ctx.cweKeys.has(ref)) {
        skillErrors.push(
          `cwe_refs: "${ref}" not present in data/cwe-catalog.json`,
        );
      }
    }
  }

  if (Array.isArray(fm.d3fend_refs)) {
    for (const ref of fm.d3fend_refs) {
      if (!ctx.d3fendKeys.has(ref)) {
        skillErrors.push(
          `d3fend_refs: "${ref}" not present in data/d3fend-catalog.json`,
        );
      }
    }
  }

  if (Array.isArray(fm.dlp_refs)) {
    for (const ref of fm.dlp_refs) {
      if (!ctx.dlpKeys.has(ref)) {
        skillErrors.push(
          `dlp_refs: "${ref}" not present in data/dlp-controls.json`,
        );
      }
    }
  }

  const missingSections = findMissingSections(body);
  for (const s of missingSections) {
    skillErrors.push(`body: missing required section "${s}"`);
  }

  const placeholders = findPlaceholders(content);
  for (const p of placeholders) {
    skillErrors.push(`placeholder language at line ${p.line} (pattern /${p.pattern}/): ${p.text}`);
  }

  return { name: entry.name, errors: skillErrors };
}

function loadContext() {
  const atlas = readJson(ATLAS_PATH);
  const frameworks = readJson(FRAMEWORK_GAPS_PATH);
  const atlasKeys = new Set(Object.keys(atlas).filter((k) => !k.startsWith('_')));
  const frameworkKeys = new Set(Object.keys(frameworks).filter((k) => !k.startsWith('_')));
  // Optional catalogs — load if present, otherwise treat as empty.
  function loadKeys(p) {
    const s = new Set();
    if (fs.existsSync(p)) {
      const j = readJson(p);
      for (const k of Object.keys(j)) if (!k.startsWith('_')) s.add(k);
    }
    return s;
  }
  return {
    atlasKeys,
    frameworkKeys,
    rfcKeys: loadKeys(RFC_REFS_PATH),
    cweKeys: loadKeys(CWE_REFS_PATH),
    d3fendKeys: loadKeys(D3FEND_REFS_PATH),
    dlpKeys: loadKeys(DLP_REFS_PATH),
  };
}

function main() {
  const opts = parseArgs(process.argv);
  const manifest = readJson(MANIFEST_PATH);

  let skills = manifest.skills;
  if (opts.skill) {
    skills = skills.filter((s) => s.name === opts.skill);
    if (skills.length === 0) {
      console.error(`No skill named "${opts.skill}" in manifest.json`);
      process.exit(2);
    }
  }

  const ctx = loadContext();

  const results = skills.map((entry) => lintSkill(entry, ctx));

  let failed = 0;
  for (const r of results) {
    if (r.errors.length === 0) {
      if (!opts.quiet) {
        console.log(`PASS  ${r.name}`);
      }
    } else {
      failed++;
      console.log(`FAIL  ${r.name}`);
      for (const e of r.errors) {
        console.log(`        - ${e}`);
      }
    }
  }

  const total = results.length;
  const passed = total - failed;
  console.log(`\n${passed}/${total} skills passed${failed ? `, ${failed} failed` : ''}.`);
  process.exit(failed === 0 ? 0 : 1);
}

// Export the minimal frontmatter parser for downstream consumers
// (e.g., orchestrator `watchlist` command) so they don't reinvent it.
module.exports = {
  parseFrontmatter,
  extractFrontmatterBlock,
  unquote,
};

if (require.main === module) {
  main();
}
