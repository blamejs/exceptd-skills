"use strict";


// ---- routed from j-readme-image-paths ----
require("node:test").describe("j-readme-image-paths", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
/**
 * tests/j-readme-image-paths.test.js
 *
 * README.md ships in the npm tarball and renders on the npm package page, but
 * public/ is not in package.json files[], so any image referenced by a
 * tarball-relative public/ path is a broken image once installed. This pins
 * every README <img>/srcset reference to an absolute (http) URL so the package
 * page render always resolves.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');
const README = fs.readFileSync(path.join(ROOT, 'README.md'), 'utf8');
const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'));

function imageRefs() {
  const refs = [];
  const re = /(?:src|srcset)\s*=\s*"([^"]+)"/g;
  let m;
  while ((m = re.exec(README)) !== null) refs.push(m[1]);
  return refs;
}

test('public/ is not in the npm files[] allowlist (assumption this gate guards)', () => {
  assert.ok(Array.isArray(pkg.files));
  assert.ok(
    !pkg.files.includes('public/') && !pkg.files.includes('public'),
    'public/ is now shipped — if so this image-path gate can be relaxed'
  );
});

test('README image references do not use tarball-excluded public/ relative paths', () => {
  const offenders = imageRefs().filter((r) => /(^|\/)public\//.test(r) && !/^https?:\/\//.test(r));
  assert.deepEqual(
    offenders,
    [],
    `README image refs point at tarball-excluded public/ paths: ${offenders.join(', ')}`
  );
});

test('README logo images resolve to absolute http URLs', () => {
  const logoRefs = imageRefs().filter((r) => /logo/.test(r));
  assert.ok(logoRefs.length >= 1, 'expected at least one logo image reference');
  for (const r of logoRefs) {
    assert.match(r, /^https?:\/\//, `logo image ref is not an absolute URL: ${r}`);
  }
});
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});


// ---- routed from repo-docs ----
require("node:test").describe("repo-docs", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
/**
 * tests/repo-docs.test.js
 *
 * Reads README.md and AGENTS.md and pins that operator-facing docs surface
 * the user-visible CLI features and the control inventory:
 *   - README documents watchlist --alerts / --org-scan (+ GITHUB_TOKEN),
 *     doctor --ai-config, refresh --check-advisories, and names the four
 *     incident-response playbooks.
 *   - AGENTS.md documents NEW-CTRL-048 through NEW-CTRL-055 and the daily
 *     exceptd-threat-intake routine + its schedule.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');

// ---------- README surfaces the CLI features ----------

test('C: README documents watchlist --alerts', () => {
  const readme = fs.readFileSync(path.join(ROOT, 'README.md'), 'utf8');
  assert.match(readme, /watchlist.*--alerts/i, 'README must mention watchlist --alerts');
});

test('C: README documents watchlist --org-scan + GITHUB_TOKEN', () => {
  const readme = fs.readFileSync(path.join(ROOT, 'README.md'), 'utf8');
  assert.match(readme, /--org-scan/, 'README must mention --org-scan');
  assert.match(readme, /GITHUB_TOKEN/, 'README must mention the GITHUB_TOKEN env var for org-scan');
});

test('C: README documents doctor --ai-config', () => {
  const readme = fs.readFileSync(path.join(ROOT, 'README.md'), 'utf8');
  assert.match(readme, /--ai-config/, 'README must mention doctor --ai-config');
  assert.match(readme, /~\/\.claude|~\/\.cursor|~\/\.codeium/,
    'README must name the AI-assistant dirs the audit walks');
});

test('C: README documents refresh --check-advisories', () => {
  const readme = fs.readFileSync(path.join(ROOT, 'README.md'), 'utf8');
  assert.match(readme, /--check-advisories/, 'README must mention refresh --check-advisories');
});

test('C: README names the four incident-response playbooks', () => {
  // The live playbook-count pin lives in tests/doc-playbook-count-currency.test.js
  // (which tracks the catalog total and fires on drift). This test pins that
  // the four incident-response playbooks are mentioned by name in the README
  // synopsis, since they anchor that surface.
  const readme = fs.readFileSync(path.join(ROOT, 'README.md'), 'utf8');
  for (const id of ['webhook-callback-abuse', 'cicd-pipeline-compromise', 'identity-sso-compromise', 'llm-tool-use-exfil']) {
    assert.match(readme, new RegExp(id), `README must name ${id}`);
  }
});

// ---------- AGENTS.md surfaces the control inventory + routine ----------

test('C: AGENTS.md documents NEW-CTRL-048 through NEW-CTRL-055', () => {
  const agents = fs.readFileSync(path.join(ROOT, 'AGENTS.md'), 'utf8');
  for (const id of ['NEW-CTRL-048', 'NEW-CTRL-049', 'NEW-CTRL-050', 'NEW-CTRL-051', 'NEW-CTRL-052', 'NEW-CTRL-053', 'NEW-CTRL-054', 'NEW-CTRL-055']) {
    assert.match(agents, new RegExp(id), `AGENTS.md must document ${id}`);
  }
});

test('C: AGENTS.md documents the daily exceptd-threat-intake routine', () => {
  const agents = fs.readFileSync(path.join(ROOT, 'AGENTS.md'), 'utf8');
  assert.match(agents, /exceptd-threat-intake/);
  assert.match(agents, /14:00\s+UTC|07:00\s+(PDT|PST)/i,
    'AGENTS.md must document the routine schedule');
});
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});


// ---- routed from docs-catalog-counts-pinned ----
require("node:test").describe("docs-catalog-counts-pinned", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
/**
 * tests/docs-catalog-counts-pinned.test.js
 *
 * Cycle 14 docs-accuracy fix (v0.12.34): operator-facing README.md +
 * ARCHITECTURE.md were pinning ATLAS v5.1.0 / ATT&CK v17 / 38 skills /
 * 28 D3FEND entries — nine releases after cycle 9 corrected the manifest
 * pin (v5.6.0 / v19.0). The CHANGELOG advertised v5.6.0 but the README's
 * badge still said v5.1.0; operators reading "which catalog version does
 * this skill set track" saw a 6-month-stale answer.
 *
 * This test asserts that EVERY version mention in the docs aligns with the
 * CURRENT `_meta` pins — not just absence of a specific obsolete string.
 * codex P2 (v0.12.34 follow-up): a banned-string approach catches the
 * historical drift but lets future drift through silently. When ATLAS
 * advances beyond 5.4.0, a doc mention that remains on 5.4.0 must also
 * fail this gate.
 *
 * Per the anti-coincidence rule, every assertion checks an EXACT
 * value or asserts the empty-set property "no mismatching pin found."
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');
const README = fs.readFileSync(path.join(ROOT, 'README.md'), 'utf8');
const ARCH = fs.readFileSync(path.join(ROOT, 'ARCHITECTURE.md'), 'utf8');
const manifest = JSON.parse(fs.readFileSync(path.join(ROOT, 'manifest.json'), 'utf8'));
const atlas = JSON.parse(fs.readFileSync(path.join(ROOT, 'data', 'atlas-ttps.json'), 'utf8'));
const attack = JSON.parse(fs.readFileSync(path.join(ROOT, 'data', 'attack-techniques.json'), 'utf8'));
const d3fend = JSON.parse(fs.readFileSync(path.join(ROOT, 'data', 'd3fend-catalog.json'), 'utf8'));
const cve = JSON.parse(fs.readFileSync(path.join(ROOT, 'data', 'cve-catalog.json'), 'utf8'));
const globalFrameworks = JSON.parse(fs.readFileSync(path.join(ROOT, 'data', 'global-frameworks.json'), 'utf8'));
const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'));

function entryCount(catalog) {
  return Object.keys(catalog).filter((k) => k !== '_meta').length;
}

// Canonical jurisdiction count: every non-metadata top-level entry in the
// registry (GLOBAL, the International / Multi-Jurisdiction standards scope, is
// a counted entry). Only `_`-prefixed keys are metadata. This is the single
// source the operator-facing surfaces below must agree with.
function jurisdictionCount() {
  return Object.keys(globalFrameworks).filter((k) => !k.startsWith('_')).length;
}

// Generic mismatch scan. Pull every version-shaped token next to the named
// context and assert it equals the live pin. If future ATLAS bumps to
// 5.5.0 and a doc still says 5.4.0, this fails — codex P2 review asked
// for this generalized behavior over the prior banned-string approach.
function findMismatches(doc, contextRe, livePin) {
  const mismatches = [];
  let m;
  const re = new RegExp(contextRe.source, contextRe.flags.includes('g') ? contextRe.flags : contextRe.flags + 'g');
  while ((m = re.exec(doc)) !== null) {
    const found = m[1];
    if (found !== livePin) {
      const start = Math.max(0, m.index - 30);
      const end = Math.min(doc.length, m.index + m[0].length + 30);
      mismatches.push({ found, expected: livePin, context: doc.slice(start, end).replace(/\s+/g, ' ').trim() });
    }
  }
  return mismatches;
}







// Cycle 15 P2 F6 (v0.12.35): the v0.12.34 docs-pin test only covered
// README + ARCHITECTURE. Cycle 15 audit found 25+ skill bodies + several
// scripts/ + data/_indexes/ files still citing "MITRE ATLAS v5.1.0".
// This second test extends the gate across the wider operator-facing
// surface so the same drift class can't slip past again.
//
// Strategy: scan every operator-facing markdown / JS file under skills/,
// scripts/builders/, and data/_indexes/ for the literal pattern
// "MITRE ATLAS v<version>" and assert the version always equals the
// live atlas-ttps._meta.atlas_version pin. The README + ARCHITECTURE
// tests above cover those two specific files; this test covers the
// rest.
const SKILL_DIR = path.join(ROOT, 'skills');
const INDEX_DIR = path.join(ROOT, 'data', '_indexes');
const BUILDER_DIR = path.join(ROOT, 'scripts');

function walkFiles(rootDir, predicate) {
  const out = [];
  if (!fs.existsSync(rootDir)) return out;
  for (const entry of fs.readdirSync(rootDir, { withFileTypes: true })) {
    const full = path.join(rootDir, entry.name);
    if (entry.isDirectory()) out.push(...walkFiles(full, predicate));
    else if (entry.isFile() && predicate(full)) out.push(full);
  }
  return out;
}

test('README — every skill-count mention equals live manifest.skills.length', () => {
  const live = manifest.skills.length;
  const badgeMatch = README.match(/badge\/skills-(\d+)-/);
  assert.ok(badgeMatch, 'README must declare a skill-count badge');
  assert.equal(Number(badgeMatch[1]), live,
    `README badge skill count = ${badgeMatch[1]}; live manifest has ${live} skills`);

  const proseMatch = README.match(/(\d+) skills across kernel LPE/);
  assert.ok(proseMatch, 'README intro must declare "<N> skills across kernel LPE"');
  assert.equal(Number(proseMatch[1]), live,
    `README intro skill count = ${proseMatch[1]}; live manifest has ${live} skills`);
});
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});


// ---- routed from v0_13_4-fixes ----
require("node:test").describe("v0_13_4-fixes", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
/**
 * tests/v0_13_4-fixes.test.js
 *
 * Pin tests for the v0.13.4 patch.
 *
 * Coverage:
 *   A — _meta.fed_by is now schema-accepted (drives the 20 cosmetic
 *       validate-playbooks warnings to 0).
 *   C — README + AGENTS surface the v0.13.x operator-facing features.
 *   E — 2 stuck-draft CVEs (MAL-2026-ANTHROPIC-MCP-STDIO + CVE-2026-GTIG-AI-2FA)
 *       are deleted from the catalog and from any cross-referencing data file.
 *   (B and D pin coverage is in their dedicated test files; this file
 *    covers the items that don't have a natural dedicated home.)
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const ROOT = path.join(__dirname, '..');

// ---------- A. fed_by schema acceptance ----------



// ---------- C. README + AGENTS surface v0.13.x features ----------








// ---------- E. 2 stuck-draft CVEs deleted ----------

test('C: README updated playbook count + 4 v0.13.0 playbook names', () => {
  // v0.13.10: the count pin moved to tests/doc-playbook-count-currency.test.js
  // (which tracks the live catalog total and fires on drift). This test
  // still pins that the 4 playbooks added in v0.13.0 are mentioned by name
  // in the README synopsis, since they anchor the v0.13.0 surface.
  const readme = fs.readFileSync(path.join(ROOT, 'README.md'), 'utf8');
  for (const id of ['webhook-callback-abuse', 'cicd-pipeline-compromise', 'identity-sso-compromise', 'llm-tool-use-exfil']) {
    assert.match(readme, new RegExp(id), `README must name ${id}`);
  }
});

test('C: AGENTS.md documents NEW-CTRL-048 through NEW-CTRL-055', () => {
  const agents = fs.readFileSync(path.join(ROOT, 'AGENTS.md'), 'utf8');
  for (const id of ['NEW-CTRL-048', 'NEW-CTRL-049', 'NEW-CTRL-050', 'NEW-CTRL-051', 'NEW-CTRL-052', 'NEW-CTRL-053', 'NEW-CTRL-054', 'NEW-CTRL-055']) {
    assert.match(agents, new RegExp(id), `AGENTS.md must document ${id}`);
  }
});

test('C: AGENTS.md documents the daily exceptd-threat-intake routine', () => {
  const agents = fs.readFileSync(path.join(ROOT, 'AGENTS.md'), 'utf8');
  assert.match(agents, /exceptd-threat-intake/);
  assert.match(agents, /14:00\s+UTC|07:00\s+(PDT|PST)/i,
    'AGENTS.md must document the routine schedule');
});
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});
