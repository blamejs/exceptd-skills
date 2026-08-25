#!/usr/bin/env node
/*
 * Pre-ship linter for the skills registered in manifest.json. Exit 0 when every
 * linted skill passes, 1 otherwise.
 */

'use strict';

const fs = require('node:fs');
const path = require('node:path');
const process = require('node:process');
const { safeExit } = require('./exit-codes');

const REPO_ROOT = path.resolve(__dirname, '..');
const MANIFEST_PATH = path.join(REPO_ROOT, 'manifest.json');
const FRONTMATTER_SCHEMA_PATH = path.join(__dirname, 'schemas', 'skill-frontmatter.schema.json');
const FRONTMATTER_SCHEMA = JSON.parse(fs.readFileSync(FRONTMATTER_SCHEMA_PATH, 'utf8'));
const SKILLS_DIR = path.join(REPO_ROOT, 'skills');
const DATA_DIR = path.join(REPO_ROOT, 'data');
const ATLAS_PATH = path.join(DATA_DIR, 'atlas-ttps.json');
const FRAMEWORK_GAPS_PATH = path.join(DATA_DIR, 'framework-control-gaps.json');
const RFC_REFS_PATH = path.join(DATA_DIR, 'rfc-references.json');
const CWE_REFS_PATH = path.join(DATA_DIR, 'cwe-catalog.json');
const D3FEND_REFS_PATH = path.join(DATA_DIR, 'd3fend-catalog.json');
const DLP_REFS_PATH = path.join(DATA_DIR, 'dlp-controls.json');
const ATTACK_REFS_PATH = path.join(DATA_DIR, 'attack-techniques.json');
const CVE_CATALOG_PATH = path.join(DATA_DIR, 'cve-catalog.json');

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

// `discovery_mode` records how operators reach the skill: omitted means a
// playbook's direct.skill_chain references it; `standalone` means it is reached
// through `exceptd brief <name>` or `ask` routing, so no chain is deliberate.
const OPTIONAL_FRONTMATTER_FIELDS = ['forward_watch', 'rfc_refs', 'cwe_refs', 'd3fend_refs', 'dlp_refs', 'discovery_mode'];

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

// Required only for skills whose last_threat_review is on or after the cutoff.
const COUNTERMEASURE_SECTION = 'Defensive Countermeasure Mapping';
const COUNTERMEASURE_CUTOFF = '2026-05-11';

// Words of body text between a section heading and the next (or EOF) for the
// section to count as populated. Below it is a warning, an error under --strict.
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

/*
 * ISO_DATE_RE proves only the shape, and Date.parse silently rolls a
 * non-calendar date over (2026-02-30 → 2026-03-02), measuring the staleness
 * gate against a day that never existed.
 */
function isStrictIsoCalendarDate(s) {
  if (typeof s !== 'string' || !ISO_DATE_RE.test(s)) return false;
  const [y, m, d] = s.split('-').map((n) => parseInt(n, 10));
  if (m < 1 || m > 12 || d < 1 || d > 31) return false;
  const dt = new Date(Date.UTC(y, m - 1, d));
  return (
    dt.getUTCFullYear() === y &&
    dt.getUTCMonth() + 1 === m &&
    dt.getUTCDate() === d
  );
}
const KEBAB_RE = /^[a-z0-9][a-z0-9-]*[a-z0-9]$/;
const JSON_FILENAME_RE = /^[A-Za-z0-9._-]+\.json$/;

// `helpExitCode` is null unless the run is over before linting starts: 0 after
// --help, 2 after an unknown argument. parseArgs never terminates the process —
// it returns the code and the caller must honour it and stop.
//
// The invariant this keeps: every exit in this file goes through safeExit(), so
// no path here can write to stdout and then terminate synchronously. That is the
// `process-exit-after-stdout-write` shape, and it is a convention held file-wide
// rather than a repair of an observed truncation: Node writes pipe stdout
// synchronously on Windows and Linux (asynchronously on macOS), and the help
// block is a few hundred bytes, so process.exit() did not in fact truncate it
// here. Holding the invariant means a future help block that grows, or a run on
// a platform with async pipe writes, cannot reintroduce the class.
function parseArgs(argv) {
  const opts = { skill: null, quiet: false, strict: false, helpExitCode: null };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--skill') {
      opts.skill = argv[++i] || null;
    } else if (a.startsWith('--skill=')) {
      opts.skill = a.slice('--skill='.length);
    } else if (a === '--quiet' || a === '-q') {
      opts.quiet = true;
    } else if (a === '--strict') {
      // The predeploy gate runs --strict, so a warned regression cannot scroll past.
      opts.strict = true;
    } else if (a === '--help' || a === '-h') {
      printHelp();
      opts.helpExitCode = 0;
      return opts;
    } else {
      console.error(`Unknown argument: ${a}`);
      printHelp();
      opts.helpExitCode = 2;
      return opts;
    }
  }
  return opts;
}

function printHelp() {
  console.log(
    'Usage: node lib/lint-skills.js [--skill <name>] [--quiet]\n' +
      '\n' +
      '  --skill <name>  Lint only the named skill from manifest.json.\n' +
      '  --strict        Promote warnings to release-blocking failures.\n' +
      '  --quiet         Suppress per-skill PASS output; show failures only.\n' +
      '  --help          Show this message.\n',
  );
}

function readJson(p) {
  return JSON.parse(fs.readFileSync(p, 'utf8'));
}

/*
 * Minimal YAML frontmatter parser: quoted or bare scalars, `[]`, and indented
 * `- ` item lists. Anything outside that shape throws.
 */
function parseFrontmatter(text) {
  // A dangling `\r` survives on the final frontmatter line (the close marker took
  // the `\n`), and `.` does not match `\r`, so the per-line regex would fail.
  const lines = text.split(/\r?\n/).map((l) => l.replace(/\r$/, ''));
  const result = {};
  // YAML's last-wins semantics would let "name: real\nname: evil" take the
  // second value — a skill-identity spoof — so a duplicate key is refused.
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
    // A quoted scalar trailed by an inline comment (`"standalone"  # why`). Only
    // when the tail is whitespace + `#`, so a `#` inside a value is not a comment.
    if (first === '"' || first === "'") {
      const close = s.indexOf(first, 1);
      if (close > 0) {
        const tail = s.slice(close + 1);
        if (/^\s+#/.test(tail)) {
          return s.slice(1, close);
        }
      }
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

// Fields with a dedicated regex and error wording above; the schema-driven pass
// skips them so a field is never reported twice.
const SCHEMA_PATTERN_HANDLED_ELSEWHERE = new Set(['atlas_refs', 'attack_refs', 'data_deps']);

/* Enforce the enum and array-item pattern constraints declared in
 * lib/schemas/skill-frontmatter.schema.json. */
function schemaConstraintErrors(fm, schema) {
  const errors = [];
  const props = (schema && schema.properties) || {};
  for (const [field, spec] of Object.entries(props)) {
    if (!(field in fm)) continue;
    const value = fm[field];

    // Type first, membership only on a string: guarding on `typeof value ===
    // 'string'` would let `discovery_mode: [standalone]` through unvalidated.
    if (Array.isArray(spec.enum)) {
      if (typeof value !== 'string') {
        errors.push(
          `frontmatter.${field} must be a string (one of ${JSON.stringify(spec.enum)}), got ${Array.isArray(value) ? 'array' : typeof value}`,
        );
      } else if (!spec.enum.includes(value)) {
        errors.push(
          `frontmatter.${field} "${value}" is not one of ${JSON.stringify(spec.enum)}`,
        );
      }
    }

    if (
      spec.type === 'array' &&
      spec.items &&
      typeof spec.items.pattern === 'string' &&
      !SCHEMA_PATTERN_HANDLED_ELSEWHERE.has(field) &&
      Array.isArray(value)
    ) {
      const itemRe = new RegExp(spec.items.pattern); // allow:dynamic-regex — bundled schema.pattern, not operator input
      for (const item of value) {
        if (typeof item !== 'string' || !itemRe.test(item)) {
          errors.push(
            `frontmatter.${field} entry ${JSON.stringify(item)} does not match the schema pattern /${spec.items.pattern}/`,
          );
        }
      }
    }
  }
  return errors;
}

/* Returns { errors, warnings } — the review-staleness soft cap warns without
 * failing, so callers must read both arrays. */
function validateFrontmatter(fm, skillName) {
  const errors = [];
  const warnings = [];

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
    if (!isStrictIsoCalendarDate(fm.last_threat_review)) {
      errors.push(
        `frontmatter.last_threat_review "${fm.last_threat_review}" is not a valid ISO date (YYYY-MM-DD). A structurally ISO but non-calendar value (e.g. 2026-13-99 or a rollover like 2026-02-30) is rejected so a malformed date cannot slip past the staleness gate.`,
      );
    } else {
      const days = Math.floor((Date.now() - Date.parse(fm.last_threat_review + 'T00:00:00Z')) / (24 * 60 * 60 * 1000));
      if (days > 365) {
        errors.push(
          `frontmatter.last_threat_review "${fm.last_threat_review}" is ${days} days old — Hard Rule #8 staleness gate (hard fail at >365 days). Refresh the threat review against current intel and bump the date.`,
        );
      } else if (days > 180) {
        warnings.push(
          `frontmatter.last_threat_review "${fm.last_threat_review}" is ${days} days old — Hard Rule #8 staleness warning (warn at >180 days, hard fail at >365). Schedule a review.`,
        );
      }
    }
  }

  errors.push(...schemaConstraintErrors(fm, FRONTMATTER_SCHEMA));

  return { errors, warnings };
}

/* Returns { missing, headerOnly }: sections with no heading in the body, and
 * sections whose heading exists but whose text runs shorter than
 * MIN_SECTION_BODY_WORDS. */
function findMissingSections(body, requiredSections) {
  const sections = requiredSections || REQUIRED_SECTIONS;
  const lines = body.split(/\r?\n/);
  // Headings inside a fenced block are documentation: counting them lets a skill
  // whose sections appear only inside a fence pass the gate vacuously.
  const headings = [];
  let inFence = false;
  for (let i = 0; i < lines.length; i++) {
    if (/^\s*(?:```|~~~)/.test(lines[i])) { inFence = !inFence; continue; }
    if (inFence) continue;
    const m = lines[i].match(/^(#{1,6})\s+(.+?)\s*$/);
    if (m) {
      headings.push({ line: i, depth: m[1].length, title: m[2].trim() });
    }
  }
  // Case-insensitive, and tolerant of a trailing qualifier ("## Threat Context
  // (mid-2026)"): the name must lead, then end-of-string or a non-alphanumeric.
  const findHeading = (title) => {
    const t = title.toLowerCase();
    return headings.find((h) => {
      // Required sections are H1/H2: a nested H3 "### Compliance Theater Check
      // Result" must not satisfy the standalone "## Compliance Theater Check".
      if (h.depth > 2) return false;
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

  const fmResult = validateFrontmatter(fm, entry.name);
  skillErrors.push(...fmResult.errors);
  skillWarnings.push(...fmResult.warnings);

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

  // Unresolved attack_refs warn, and fail under --strict. ctx.attackKeys is
  // null when data/attack-techniques.json is absent, and the check is skipped.
  if (Array.isArray(fm.attack_refs) && ctx.attackKeys) {
    for (const ref of fm.attack_refs) {
      if (!ctx.attackKeys.has(ref)) {
        skillWarnings.push(
          `attack_refs: "${ref}" not present in data/attack-techniques.json (an error under --strict)`,
        );
      }
    }
  }

  // Hard Rule #1 at the prose layer: every CVE-* / MAL-* cited in a skill body
  // must resolve in data/cve-catalog.json. A `_draft: true` entry warns rather
  // than failing — operators promote drafts on their own cadence.
  if (ctx.cveCatalog && body && typeof body === 'string') {
    const cveRefRe = /\b(CVE-\d{4}-\d{4,7}|MAL-\d{4}-[A-Z0-9-]+)\b/g;
    const seen = new Set();
    let m;
    while ((m = cveRefRe.exec(body)) !== null) {
      const id = m[1];
      if (seen.has(id)) continue;
      seen.add(id);
      const entry = ctx.cveCatalog[id];
      if (!entry) {
        skillErrors.push(
          `body cites "${id}" but no such entry in data/cve-catalog.json (Hard Rule #1 — no stale threat intel)`,
        );
      } else if (entry._draft === true) {
        skillWarnings.push(
          `body cites "${id}" which is _draft:true in data/cve-catalog.json — promote to verified before next release or remove from body (Hard Rule #1)`,
        );
      }
    }
  }

  const { missing, headerOnly } = findMissingSections(body, REQUIRED_SECTIONS);
  for (const s of missing) {
    skillErrors.push(`body: missing required section "${s}"`);
  }
  for (const ho of headerOnly) {
    skillWarnings.push(
      `body: section "${ho.section}" has only ${ho.wordCount} words of body text (need >= ${MIN_SECTION_BODY_WORDS}); an error under --strict`,
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
        `body: missing required section "${COUNTERMEASURE_SECTION}" (required for skills with last_threat_review >= ${COUNTERMEASURE_CUTOFF}; an error under --strict)`,
      );
    } else {
      for (const ho of cmResult.headerOnly) {
        skillWarnings.push(
          `body: section "${ho.section}" has only ${ho.wordCount} words of body text (need >= ${MIN_SECTION_BODY_WORDS}); an error under --strict`,
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
  function loadKeys(p) {
    const s = new Set();
    if (fs.existsSync(p)) {
      const j = readJson(p);
      for (const k of Object.keys(j)) if (!k.startsWith('_')) s.add(k);
    }
    return s;
  }
  // Null when data/attack-techniques.json is absent; the attack_refs check skips.
  let attackKeys = null;
  if (fs.existsSync(ATTACK_REFS_PATH)) {
    attackKeys = new Set();
    const j = readJson(ATTACK_REFS_PATH);
    for (const k of Object.keys(j)) if (!k.startsWith('_')) attackKeys.add(k);
  }
  // Loaded whole rather than as a key set, so the body scan can tell a missing
  // CVE from a `_draft: true` one.
  const cveCatalog = fs.existsSync(CVE_CATALOG_PATH) ? readJson(CVE_CATALOG_PATH) : {};

  return {
    atlasKeys,
    frameworkKeys,
    rfcKeys: loadKeys(RFC_REFS_PATH),
    cweKeys: loadKeys(CWE_REFS_PATH),
    d3fendKeys: loadKeys(D3FEND_REFS_PATH),
    dlpKeys: loadKeys(DLP_REFS_PATH),
    attackKeys,
    cveCatalog,
  };
}

/*
 * Every skill.md under skills/ must be referenced by a manifest entry: a
 * directory nobody listed is signed by nobody. Returns repo-relative paths.
 */
function findOrphanSkillFiles(manifestSkills) {
  if (!fs.existsSync(SKILLS_DIR)) return [];
  // Manifest paths are forward-slash by contract (lib/verify.js validateSkillPath
  // rejects backslashes), so normalise rather than splitting on path.sep.
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

// Manifest cover arrays that must resolve to a real catalog entry, paired with
// the loadContext() key set. These manifest-only refs feed build-indexes'
// reverse-ref surface and refresh-reverse-refs; the frontmatter pass never sees them.
const MANIFEST_COVER_RESOLUTION = [
  { field: 'atlas_refs', ctxKey: 'atlasKeys', catalog: 'data/atlas-ttps.json' },
  { field: 'attack_refs', ctxKey: 'attackKeys', catalog: 'data/attack-techniques.json' },
  { field: 'framework_gaps', ctxKey: 'frameworkKeys', catalog: 'data/framework-control-gaps.json' },
  { field: 'rfc_refs', ctxKey: 'rfcKeys', catalog: 'data/rfc-references.json' },
  { field: 'cwe_refs', ctxKey: 'cweKeys', catalog: 'data/cwe-catalog.json' },
  { field: 'd3fend_refs', ctxKey: 'd3fendKeys', catalog: 'data/d3fend-catalog.json' },
  { field: 'dlp_refs', ctxKey: 'dlpKeys', catalog: 'data/dlp-controls.json' },
];

/*
 * Assert every ref in each manifest entry's cover arrays resolves in the
 * matching catalog. A null ctx key set — an absent optional catalog — skips
 * that field.
 */
function findUnresolvedManifestCoverRefs(manifestSkills, ctx) {
  const errors = [];
  for (const entry of manifestSkills) {
    const name = entry.name || entry.id || '<unknown>';
    for (const { field, ctxKey, catalog } of MANIFEST_COVER_RESOLUTION) {
      const keySet = ctx[ctxKey];
      if (!keySet) continue; // catalog absent — degrade gracefully
      const refs = Array.isArray(entry[field]) ? entry[field] : [];
      for (const ref of refs) {
        if (!keySet.has(ref)) {
          errors.push(`${name}.${field}: "${ref}" not present in ${catalog}`);
        }
      }
    }
  }
  return errors;
}

// Substrings that mark an artifact `source` as a network call. Deliberately
// broad: a hit only warns, and an air_gap_alternative silences it.
const PLAYBOOK_NET_PATTERNS = [
  'https://', 'http://', 'gh api', 'gh release', 'curl ', 'wget ', 'fetch ',
];

const PLAYBOOK_DIR = path.join(DATA_DIR, 'playbooks');

/**
 * Warn on any data/playbooks/*.json look artifact whose `source` makes a network
 * call without a sibling `air_gap_alternative`. The schema enforces that only for
 * `_meta.air_gap_mode: true`, but any playbook can run under `--air-gap`. Returns
 * `{ playbook, artifact_id, source }` records.
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
  if (opts.helpExitCode !== null) {
    safeExit(opts.helpExitCode);
    return;
  }
  const manifest = readJson(MANIFEST_PATH);

  let skills = manifest.skills;
  if (opts.skill) {
    skills = skills.filter((s) => s.name === opts.skill);
    if (skills.length === 0) {
      console.error(`No skill named "${opts.skill}" in manifest.json`);
      safeExit(2);
      return;
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

  // These passes run only on a full lint; a --skill run would show unrelated noise.
  let orphans = [];
  let manifestRefErrors = [];
  let airGapWarnings = [];
  if (!opts.skill) {
    orphans = findOrphanSkillFiles(manifest.skills);
    for (const o of orphans) {
      console.log(`FAIL  <orphan>`);
      console.log(`        - skill.md exists on disk but not in manifest: ${o}`);
      console.log(`          fix: re-run sign-all (\`node $(exceptd path)/lib/sign.js sign-all\` from a contributor checkout) after adding it to manifest.json, OR delete the orphan directory`);
    }
    // Hard Rule #4, no orphaned controls: an unresolved control ref is
    // unconditionally wrong, so this fails rather than warning under --strict.
    manifestRefErrors = findUnresolvedManifestCoverRefs(manifest.skills, ctx);
    for (const e of manifestRefErrors) {
      console.log(`FAIL  <manifest-cover-ref>`);
      console.log(`        - ${e}`);
      console.log(`          fix: correct the typo'd/stale ref in manifest.json (or add the entry to the catalog), then re-run sign-all + refresh-reverse-refs + build-indexes`);
    }
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
  const manifestRefSummary = manifestRefErrors.length
    ? `, ${manifestRefErrors.length} unresolved manifest cover ref(s)`
    : '';
  const warnSummary = warned ? `, ${warned} with warnings` : '';
  const airGapSummary = airGapWarnings && airGapWarnings.length
    ? `, ${airGapWarnings.length} playbook artifact(s) missing air_gap_alternative`
    : '';
  console.log(
    `\n${passed}/${total} skills passed${warnSummary}${failed ? `, ${failed} failed` : ''}${orphanSummary}${manifestRefSummary}${airGapSummary}.`,
  );
  const strictFail = opts.strict && (warned > 0 || (airGapWarnings && airGapWarnings.length > 0));
  if (strictFail) {
    console.log(`[lint-skills] --strict: ${warned + (airGapWarnings ? airGapWarnings.length : 0)} warning(s) treated as failures.`);
  }
  safeExit(failed === 0 && orphans.length === 0 && manifestRefErrors.length === 0 && !strictFail ? 0 : 1);
  return;
}

// The frontmatter parser is exported so `watchlist` does not grow a second one.
module.exports = {
  parseArgs,
  parseFrontmatter,
  extractFrontmatterBlock,
  unquote,
  findOrphanSkillFiles,
  findUnresolvedManifestCoverRefs,
  loadContext,
  MANIFEST_COVER_RESOLUTION,
  findMissingSections,
  lintPlaybookAirGap,
  PLAYBOOK_NET_PATTERNS,
  REQUIRED_SECTIONS,
  COUNTERMEASURE_SECTION,
  COUNTERMEASURE_CUTOFF,
  MIN_SECTION_BODY_WORDS,
  validateFrontmatter,
  schemaConstraintErrors,
  isStrictIsoCalendarDate,
  FRONTMATTER_SCHEMA,
};

if (require.main === module) {
  main();
}
