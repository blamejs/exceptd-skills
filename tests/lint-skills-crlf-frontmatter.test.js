'use strict';

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
