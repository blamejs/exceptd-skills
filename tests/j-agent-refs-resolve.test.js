'use strict';

/**
 * tests/j-agent-refs-resolve.test.js
 *
 * The shipped agent docs coordinate by naming sibling agents. A doc that names
 * an agent with no agents/<name>.md points operators at a coordination partner
 * the package does not contain. This pins agents/source-validator.md to the
 * actual roster so it cannot reference a non-existent agent.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const AGENTS_DIR = path.join(__dirname, '..', 'agents');

function existingAgentNames() {
  return new Set(
    fs
      .readdirSync(AGENTS_DIR)
      .filter((f) => f.endsWith('.md') && f !== 'README.md')
      .map((f) => f.replace(/\.md$/, ''))
  );
}

// Agent names follow the kebab-case <role>-<role> shape used by every file in
// agents/. Match those tokens in prose so a dangling reference is caught.
function referencedAgentTokens(text) {
  const known = [
    'threat-researcher',
    'source-validator',
    'skill-updater',
    'report-generator',
    'framework-analyst',
  ];
  return known.filter((name) => new RegExp('\\b' + name + '\\b').test(text));
}

test('agents/source-validator.md references only agents that exist', () => {
  const roster = existingAgentNames();
  const text = fs.readFileSync(path.join(AGENTS_DIR, 'source-validator.md'), 'utf8');
  const referenced = referencedAgentTokens(text);
  const dangling = referenced.filter((name) => !roster.has(name));
  assert.deepEqual(
    dangling,
    [],
    `source-validator.md references agents with no agents/<name>.md: ${dangling.join(', ')}`
  );
});
