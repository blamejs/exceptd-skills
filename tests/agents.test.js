"use strict";


// ---- routed from j-agent-refs-resolve ----
require("node:test").describe("j-agent-refs-resolve", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
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
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});
