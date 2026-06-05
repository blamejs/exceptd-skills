'use strict';

/**
 * tests/j-frontmatter-schema-enforced.test.js
 *
 * The skill linter must drive enum and ref-pattern validation from the
 * published lib/schemas/skill-frontmatter.schema.json so the shipped schema is
 * the source of truth, not a decorative artifact. These tests confirm:
 *   - the schema file is loaded by the linter,
 *   - discovery_mode's enum is enforced,
 *   - the cwe/d3fend/dlp/rfc ref-array patterns are enforced,
 *   - a quoted frontmatter scalar followed by an inline comment is normalized
 *     so the enum check sees the bare value (the parser gap that previously
 *     let discovery_mode pass unchecked).
 */

const test = require('node:test');
const assert = require('node:assert/strict');

const {
  schemaConstraintErrors,
  validateFrontmatter,
  FRONTMATTER_SCHEMA,
  unquote,
} = require('../lib/lint-skills.js');

test('linter loads the published frontmatter schema with discovery_mode enum', () => {
  assert.equal(typeof FRONTMATTER_SCHEMA, 'object');
  const dm = FRONTMATTER_SCHEMA.properties && FRONTMATTER_SCHEMA.properties.discovery_mode;
  assert.ok(dm, 'schema is missing discovery_mode');
  assert.deepEqual(dm.enum, ['standalone']);
});

test('schemaConstraintErrors rejects a discovery_mode outside the enum', () => {
  const errors = schemaConstraintErrors({ discovery_mode: 'chained' }, FRONTMATTER_SCHEMA);
  assert.equal(errors.length, 1);
  assert.match(errors[0], /frontmatter\.discovery_mode "chained" is not one of/);
});

test('schemaConstraintErrors accepts the only legal discovery_mode value', () => {
  assert.deepEqual(
    schemaConstraintErrors({ discovery_mode: 'standalone' }, FRONTMATTER_SCHEMA),
    []
  );
});

test('schemaConstraintErrors enforces ref-array item patterns from the schema', () => {
  const fm = {
    cwe_refs: ['CWE-79', 'cwe-79'], // second is wrong case
    d3fend_refs: ['D3-EAL', 'D3-eal'], // second has lowercase
    dlp_refs: ['DLP-EMAIL', 'dlp-email'], // second lowercase
    rfc_refs: ['RFC-8446', 'RFC8446'], // second missing the hyphen
  };
  const errors = schemaConstraintErrors(fm, FRONTMATTER_SCHEMA);
  assert.ok(errors.some((e) => /cwe_refs entry "cwe-79"/.test(e)));
  assert.ok(errors.some((e) => /d3fend_refs entry "D3-eal"/.test(e)));
  assert.ok(errors.some((e) => /dlp_refs entry "dlp-email"/.test(e)));
  assert.ok(errors.some((e) => /rfc_refs entry "RFC8446"/.test(e)));
  // Exactly one error per malformed entry; the four valid entries produce none.
  assert.equal(errors.length, 4);
});

test('schemaConstraintErrors does not double-report atlas_refs/attack_refs/data_deps', () => {
  // These three carry their own dedicated regex checks elsewhere in the linter;
  // the schema-driven pass must skip them so a bad entry is reported once.
  const fm = {
    atlas_refs: ['not-an-id'],
    attack_refs: ['nope'],
    data_deps: ['not-json'],
  };
  assert.deepEqual(schemaConstraintErrors(fm, FRONTMATTER_SCHEMA), []);
});

test('validateFrontmatter surfaces the discovery_mode enum violation', () => {
  const fm = {
    name: 'sample-skill',
    version: '1.0.0',
    description: 'a sufficiently long description',
    triggers: ['do the thing'],
    data_deps: [],
    atlas_refs: [],
    attack_refs: [],
    framework_gaps: [],
    last_threat_review: new Date().toISOString().slice(0, 10),
    discovery_mode: 'chained',
  };
  const { errors } = validateFrontmatter(fm, 'sample-skill');
  assert.ok(
    errors.some((e) => /frontmatter\.discovery_mode "chained" is not one of/.test(e)),
    `expected discovery_mode enum error; got ${JSON.stringify(errors)}`
  );
});

test('unquote normalizes a quoted scalar followed by an inline comment', () => {
  assert.equal(unquote('"standalone"  # why this skill is standalone'), 'standalone');
  assert.equal(unquote("'standalone' # single-quoted"), 'standalone');
  // A plain quoted scalar still unquotes.
  assert.equal(unquote('"standalone"'), 'standalone');
  // A hash inside the quotes is preserved (not treated as a comment).
  assert.equal(unquote('"a # b"'), 'a # b');
  // A bare value with a hash is left intact (no quotes to anchor a comment).
  assert.equal(unquote('bare # value'), 'bare # value');
});
