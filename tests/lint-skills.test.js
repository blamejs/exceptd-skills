'use strict';

/**
 * tests/lint-skills.test.js
 *
 * Source-shape tests for lib/lint-skills.js.
 *
 * Covers the Hard Rule #1 body-scan: skill bodies that cite a CVE must
 * match the catalog, missing-from-catalog references are a hard error
 * (skillErrors), and draft references stay a warning (skillWarnings). Also
 * pins that validateFrontmatter accepts the discovery_mode optional field.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');

// ---------- lint Hard Rule #1 body-scan ----------

test('B: lint-skills.js source carries the body-scan implementation', () => {
  const src = fs.readFileSync(path.join(ROOT, 'lib', 'lint-skills.js'), 'utf8');
  assert.match(src, /Hard Rule #1/, 'body-scan must explicitly cite Hard Rule #1');
  assert.match(src, /body cites/, 'body-scan must emit "body cites" text');
  assert.match(src, /ctx\.cveCatalog/, 'body-scan must consume ctx.cveCatalog');
  assert.match(src, /_draft\s*===\s*true/, 'body-scan must distinguish draft entries');
  // missing-from-catalog is a hard error.
  assert.match(src, /if \(!entry\) \{[\s\S]*?skillErrors\.push/,
    'missing-from-catalog must push to skillErrors');
});

test('B: validateFrontmatter accepts discovery_mode field (no "unknown field" error)', () => {
  const src = fs.readFileSync(path.join(ROOT, 'lib', 'lint-skills.js'), 'utf8');
  assert.match(src, /discovery_mode/, 'OPTIONAL_FRONTMATTER_FIELDS must include discovery_mode');
});

test('B: lint-skills body-scan flipped from warning to hard error', () => {
  const src = fs.readFileSync(path.join(ROOT, 'lib', 'lint-skills.js'), 'utf8');
  // The body-scan block: missing-from-catalog must push to skillErrors,
  // not skillWarnings. Match the canonical body-scan paragraph and
  // assert it now uses skillErrors.push for the "no such entry" case.
  const m = src.match(/no stale threat intel[\s\S]{0,400}body cites[\s\S]{0,800}/);
  assert.ok(m, 'body-scan block not found');
  // Find the missing-from-catalog branch (the `if (!entry)` arm).
  assert.match(src, /if \(!entry\) \{[\s\S]*?skillErrors\.push/,
    'missing-from-catalog must push to skillErrors (not skillWarnings)');
  // Draft case stays as warning.
  assert.match(src, /entry\._draft === true[\s\S]*?skillWarnings\.push/,
    'draft case still surfaces as warning');
});


// ---- routed from lint-skills-crlf-frontmatter ----
require("node:test").describe("lint-skills-crlf-frontmatter", () => {
const __t = require("node:test"); const __env = Object.assign({}, process.env);
__t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __env)) delete process.env[k]; Object.assign(process.env, __env);
  const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
/**
 * Regression: a CRLF skill.md must parse cleanly. A dangling `\r` survived on
 * the final frontmatter line (split(/\r?\n/) consumes interior CRLFs but the
 * close marker consumed the `\n`, not the `\r`); since `.` does not match `\r`,
 * the per-line regex failed with a misleading "Could not parse frontmatter
 * line N" instead of accepting valid CRLF content.
 */

const test = require('node:test');
const assert = require('node:assert/strict');

const lint = require('../lib/lint-skills.js');

test('parseFrontmatter tolerates CRLF line endings (no misleading line-N crash)', () => {
  const crlf = '---\r\nname: t\r\nversion: 1.0.0\r\n---\r\nbody text';
  const block = lint.extractFrontmatterBlock(crlf);
  const fm = lint.parseFrontmatter(block.frontmatter);
  assert.equal(fm.name, 't');
  // The value must not carry a trailing CR.
  assert.equal(fm.version, '1.0.0');
});

test('parseFrontmatter still parses the equivalent LF content identically', () => {
  const lf = '---\nname: t\nversion: 1.0.0\n---\nbody text';
  const fm = lint.parseFrontmatter(lint.extractFrontmatterBlock(lf).frontmatter);
  assert.equal(fm.name, 't');
  assert.equal(fm.version, '1.0.0');
});
});
