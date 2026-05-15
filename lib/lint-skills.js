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
const SKILLS_DIR = path.join(REPO_ROOT, 'skills');
const DATA_DIR = path.join(REPO_ROOT, 'data');
const ATLAS_PATH = path.join(DATA_DIR, 'atlas-ttps.json');
const FRAMEWORK_GAPS_PATH = path.join(DATA_DIR, 'framework-control-gaps.json');
const RFC_REFS_PATH = path.join(DATA_DIR, 'rfc-references.json');
const CWE_REFS_PATH = path.join(DATA_DIR, 'cwe-catalog.json');
const D3FEND_REFS_PATH = path.join(DATA_DIR, 'd3fend-catalog.json');
const DLP_REFS_PATH = path.join(DATA_DIR, 'dlp-controls.json');
const ATTACK_REFS_PATH = path.join(DATA_DIR, 'attack-techniques.json');

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

// L3 — Defensive Countermeasure Mapping became a required section for skills
// reviewed on or after this cutoff (documented in AGENTS.md). Pre-cutoff
// skills remain exempt to preserve patch-class compatibility; v0.13.0 may
// broaden the cutoff.
const COUNTERMEASURE_SECTION = 'Defensive Countermeasure Mapping';
const COUNTERMEASURE_CUTOFF = '2026-05-11';

// L1 — Minimum number of words of body text between a section heading and the
// next heading (or EOF) for the section to count as populated. Header-only
// sections surface as WARNINGS in v0.12.12; v0.13.0 will tighten to failure.
const MIN_SECTION_BODY_WORDS = 20;

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
  // Track every top-level key we've already assigned. YAML's last-wins
  // semantics would let a tampered skill set name twice
  // ("name: real-skill\nname: evil-skill") and silently take the second
  // value — a skill-identity spoofing primitive. Refuse duplicates
  // outright; an honest skill never has them.
  const seenKeys = new Set();
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
    if (seenKeys.has(key)) {
      throw new Error(
        `Duplicate frontmatter key "${key}" at line ${i + 1} — refusing last-wins semantics`,
      );
    }
    seenKeys.add(key);
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

/* L1 — Heading-anchored section detection.
 *
 * Returns { missing, headerOnly }:
 *   - missing[]    — sections with no `^## <Section Name>` heading anywhere
 *                    in the body (case-insensitive). Hard failure.
 *   - headerOnly[] — sections whose heading exists but whose body between
 *                    that heading and the next heading is shorter than
 *                    MIN_SECTION_BODY_WORDS words. Warning in v0.12.12;
 *                    v0.13.0 will tighten. */
function findMissingSections(body, requiredSections) {
  const sections = requiredSections || REQUIRED_SECTIONS;
  const lines = body.split(/\r?\n/);
  // Index every heading line (any depth) so we know where each section ends.
  const headings = [];
  for (let i = 0; i < lines.length; i++) {
    const m = lines[i].match(/^(#{1,6})\s+(.+?)\s*$/);
    if (m) {
      headings.push({ line: i, depth: m[1].length, title: m[2].trim() });
    }
  }
  // Heading match is case-insensitive and tolerates trailing context
  // qualifiers (e.g. "## Threat Context (mid-2026)" or
  // "## TTP Mapping (MITRE ATT&CK Enterprise, mid-2026)"). The required
  // section name must appear as a leading token followed by end-of-string
  // or a non-alphanumeric character (paren, dash, colon).
  const findHeading = (title) => {
    const t = title.toLowerCase();
    return headings.find((h) => {
      const lower = h.title.toLowerCase();
      if (lower === t) return true;
      if (lower.startsWith(t)) {
        const next = lower[t.length];
        if (next === undefined) return true;
        if (!/[a-z0-9]/.test(next)) return true;
      }
      return false;
    });
  };

  const missing = [];
  const headerOnly = [];
  for (const section of sections) {
    const h = findHeading(section);
    if (!h) {
      missing.push(section);
      continue;
    }
    // Find the next heading at the same or shallower depth, or EOF.
    const idx = headings.indexOf(h);
    let endLine = lines.length;
    for (let j = idx + 1; j < headings.length; j++) {
      if (headings[j].depth <= h.depth) {
        endLine = headings[j].line;
        break;
      }
    }
    const bodyText = lines.slice(h.line + 1, endLine).join(' ').trim();
    const wordCount = bodyText ? bodyText.split(/\s+/).length : 0;
    if (wordCount < MIN_SECTION_BODY_WORDS) {
      headerOnly.push({ section, wordCount });
    }
  }
  return { missing, headerOnly };
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
  const skillWarnings = [];
  const skillPath = path.join(REPO_ROOT, entry.path);

  if (!fs.existsSync(skillPath)) {
    return { name: entry.name, errors: [`skill file not found at ${entry.path}`], warnings: [] };
  }

  const content = fs.readFileSync(skillPath, 'utf8');
  const { frontmatter: fmRaw, body } = extractFrontmatterBlock(content);
  if (fmRaw === null) {
    skillErrors.push('skill.md does not start with a `---` YAML frontmatter block');
    return { name: entry.name, errors: skillErrors, warnings: skillWarnings };
  }

  let fm;
  try {
    fm = parseFrontmatter(fmRaw);
  } catch (err) {
    skillErrors.push(`frontmatter parse error: ${err.message}`);
    return { name: entry.name, errors: skillErrors, warnings: skillWarnings };
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

  // L2 — attack_refs cross-catalog resolution. Surface as WARNINGS in
  // v0.12.12 to preserve patch-class compatibility; v0.13.0 will flip to
  // hard failures. If data/attack-techniques.json is missing entirely the
  // ctx.attackKeys set is null — skip the check (the gate degrades to its
  // pre-v0.12.12 behavior).
  if (Array.isArray(fm.attack_refs) && ctx.attackKeys) {
    for (const ref of fm.attack_refs) {
      if (!ctx.attackKeys.has(ref)) {
        skillWarnings.push(
          `attack_refs: "${ref}" not present in data/attack-techniques.json (will hard-fail in v0.13.0)`,
        );
      }
    }
  }

  // L3 — Defensive Countermeasure Mapping is required for skills reviewed
  // on or after COUNTERMEASURE_CUTOFF. Pre-cutoff skills are exempt. The
  // section's absence on a post-cutoff skill is a WARNING in v0.12.12 so
  // existing skills can add the section gradually; v0.13.0 will flip to
  // a hard failure.
  const { missing, headerOnly } = findMissingSections(body, REQUIRED_SECTIONS);
  for (const s of missing) {
    skillErrors.push(`body: missing required section "${s}"`);
  }
  for (const ho of headerOnly) {
    // L1 — Header-only sections are WARNINGS in v0.12.12; v0.13.0 will
    // tighten to failure.
    skillWarnings.push(
      `body: section "${ho.section}" has only ${ho.wordCount} words of body text (need >= ${MIN_SECTION_BODY_WORDS}); will hard-fail in v0.13.0`,
    );
  }
  if (
    typeof fm.last_threat_review === 'string' &&
    ISO_DATE_RE.test(fm.last_threat_review) &&
    fm.last_threat_review >= COUNTERMEASURE_CUTOFF
  ) {
    const cmResult = findMissingSections(body, [COUNTERMEASURE_SECTION]);
    if (cmResult.missing.length > 0) {
      skillWarnings.push(
        `body: missing required section "${COUNTERMEASURE_SECTION}" (required for skills with last_threat_review >= ${COUNTERMEASURE_CUTOFF}; will hard-fail in v0.13.0)`,
      );
    } else {
      for (const ho of cmResult.headerOnly) {
        skillWarnings.push(
          `body: section "${ho.section}" has only ${ho.wordCount} words of body text (need >= ${MIN_SECTION_BODY_WORDS}); will hard-fail in v0.13.0`,
        );
      }
    }
  }

  const placeholders = findPlaceholders(content);
  for (const p of placeholders) {
    skillErrors.push(`placeholder language at line ${p.line} (pattern /${p.pattern}/): ${p.text}`);
  }

  return { name: entry.name, errors: skillErrors, warnings: skillWarnings };
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
  // L2 — attack-techniques.json may not exist in older trees. When absent,
  // ctx.attackKeys is null and the L2 check is skipped.
  let attackKeys = null;
  if (fs.existsSync(ATTACK_REFS_PATH)) {
    attackKeys = new Set();
    const j = readJson(ATTACK_REFS_PATH);
    for (const k of Object.keys(j)) if (!k.startsWith('_')) attackKeys.add(k);
  }
  return {
    atlasKeys,
    frameworkKeys,
    rfcKeys: loadKeys(RFC_REFS_PATH),
    cweKeys: loadKeys(CWE_REFS_PATH),
    d3fendKeys: loadKeys(D3FEND_REFS_PATH),
    dlpKeys: loadKeys(DLP_REFS_PATH),
    attackKeys,
  };
}

/*
 * S6 — orphan skill.md detector.
 *
 * Walk every subdirectory of skills/ and assert each skill.md file is
 * referenced by exactly one manifest entry. Catches the v0.12.8
 * stash-restore class: a directory left behind on disk that nobody
 * signs because nobody listed it in the manifest, then the next
 * `npm pack` ships an unsigned skill (or worse, conflicts with a
 * future manifest entry of the same name).
 *
 * @param {Array<{path: string}>} manifestSkills
 * @returns {string[]} list of orphan filesystem paths (relative)
 */
function findOrphanSkillFiles(manifestSkills) {
  if (!fs.existsSync(SKILLS_DIR)) return [];
  // F19 — manifest paths are stored as forward-slash strings by contract
  // (lib/verify.js validateSkillPath() rejects backslashes). The previous
  // path.sep split was a no-op on Linux and incorrect on Windows when
  // mixed separators arrived through other ingest paths; the cleaner
  // contract is to normalise the comparison key directly.
  const referenced = new Set(
    manifestSkills.map((s) => String(s.path).replace(/\\/g, '/')),
  );
  const orphans = [];
  for (const entry of fs.readdirSync(SKILLS_DIR, { withFileTypes: true })) {
    if (!entry.isDirectory()) continue;
    const candidate = path.join(SKILLS_DIR, entry.name, 'skill.md');
    if (fs.existsSync(candidate)) {
      const rel = `skills/${entry.name}/skill.md`;
      if (!referenced.has(rel)) orphans.push(rel);
    }
  }
  return orphans;
}

// Substrings that indicate an artifact `source` makes a network call. Used
// by lintPlaybookAirGap() to flag artifacts that lack an air_gap_alternative.
// Conservative-by-design — false positives are surfaced as `warn` (not
// `error`) and a playbook author who has reviewed the source can suppress
// by adding an air_gap_alternative even when the source itself is offline.
const PLAYBOOK_NET_PATTERNS = [
  'https://', 'http://', 'gh api', 'gh release', 'curl ', 'wget ', 'fetch ',
];

const PLAYBOOK_DIR = path.join(DATA_DIR, 'playbooks');

/**
 * Air-gap completeness lint for shipped playbooks. Walks every
 * data/playbooks/*.json file, examines phases.look.artifacts[], and warns
 * when an artifact's `source` contains a network-call substring without a
 * sibling `air_gap_alternative`. The playbook schema's hard `if/then`
 * conditional (added v0.12.24) catches this for playbooks marked
 * `_meta.air_gap_mode: true`; this lint surfaces the gap for every
 * playbook, on the principle that a non-air-gap playbook may still be
 * invoked under `exceptd --air-gap` and operators deserve the warning.
 *
 * Returns an array of `{ playbook, artifact_id, source }` warning records.
 */
function lintPlaybookAirGap() {
  const warnings = [];
  if (!fs.existsSync(PLAYBOOK_DIR)) return warnings;
  const files = fs.readdirSync(PLAYBOOK_DIR).filter(f => f.endsWith('.json') && !f.startsWith('_'));
  for (const f of files) {
    let playbook;
    try {
      playbook = readJson(path.join(PLAYBOOK_DIR, f));
    } catch {
      continue; // schema validator catches parse errors separately
    }
    const arts = playbook && playbook.phases && playbook.phases.look && playbook.phases.look.artifacts;
    if (!Array.isArray(arts)) continue;
    for (const a of arts) {
      if (!a || typeof a !== 'object') continue;
      const src = a.source;
      if (typeof src !== 'string') continue;
      const isNet = PLAYBOOK_NET_PATTERNS.some(p => src.includes(p));
      if (isNet && !a.air_gap_alternative) {
        warnings.push({
          playbook: playbook._meta && playbook._meta.id ? playbook._meta.id : f.replace(/\.json$/, ''),
          artifact_id: a.id || '<unknown>',
          source: src,
        });
      }
    }
  }
  return warnings;
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
  let warned = 0;
  for (const r of results) {
    const warns = r.warnings || [];
    if (r.errors.length === 0 && warns.length === 0) {
      if (!opts.quiet) {
        console.log(`PASS  ${r.name}`);
      }
    } else if (r.errors.length === 0) {
      warned++;
      if (!opts.quiet) console.log(`WARN  ${r.name}`);
      for (const w of warns) console.log(`        - [warn] ${w}`);
    } else {
      failed++;
      console.log(`FAIL  ${r.name}`);
      for (const e of r.errors) {
        console.log(`        - ${e}`);
      }
      for (const w of warns) {
        console.log(`        - [warn] ${w}`);
      }
    }
  }

  // S6 — orphan check runs only on a full lint pass (no --skill filter).
  // A targeted single-skill lint is for diagnosing one entry; running
  // the orphan walk there would surface unrelated findings.
  let orphans = [];
  let airGapWarnings = [];
  if (!opts.skill) {
    orphans = findOrphanSkillFiles(manifest.skills);
    for (const o of orphans) {
      console.log(`FAIL  <orphan>`);
      console.log(`        - skill.md exists on disk but not in manifest: ${o}`);
      console.log(`          fix: re-run \`node lib/sign.js sign-all\` after adding it to manifest.json, OR delete the orphan directory`);
    }
    // P4 — air-gap completeness lint over data/playbooks/*.json.
    airGapWarnings = lintPlaybookAirGap();
    for (const w of airGapWarnings) {
      console.log(`WARN  playbook:${w.playbook}`);
      console.log(`        - [warn] artifact "${w.artifact_id}" source contains a network call but has no air_gap_alternative`);
      console.log(`                 source: ${w.source}`);
      console.log(`                 fix: add an air_gap_alternative source (offline file path / packaged dataset / pre-staged artifact)`);
    }
  }

  const total = results.length;
  const passed = total - failed - warned;
  const orphanSummary = orphans.length ? `, ${orphans.length} orphan skill.md file(s)` : '';
  const warnSummary = warned ? `, ${warned} with warnings` : '';
  const airGapSummary = airGapWarnings && airGapWarnings.length
    ? `, ${airGapWarnings.length} playbook artifact(s) missing air_gap_alternative`
    : '';
  console.log(
    `\n${passed}/${total} skills passed${warnSummary}${failed ? `, ${failed} failed` : ''}${orphanSummary}${airGapSummary}.`,
  );
  process.exit(failed === 0 && orphans.length === 0 ? 0 : 1);
}

// Export the minimal frontmatter parser for downstream consumers
// (e.g., orchestrator `watchlist` command) so they don't reinvent it.
module.exports = {
  parseFrontmatter,
  extractFrontmatterBlock,
  unquote,
  findOrphanSkillFiles,
  findMissingSections,
  lintPlaybookAirGap,
  PLAYBOOK_NET_PATTERNS,
  REQUIRED_SECTIONS,
  COUNTERMEASURE_SECTION,
  COUNTERMEASURE_CUTOFF,
  MIN_SECTION_BODY_WORDS,
};

if (require.main === module) {
  main();
}
