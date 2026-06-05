'use strict';

/**
 * sanitizeConfig must scrub credentials from scanner findings at any nesting
 * depth before they reach stdout. MCP server configs place real secrets inside
 * `env` and `headers` sub-objects, so a top-level-only sweep leaks them.
 */

const test = require('node:test');
const assert = require('node:assert/strict');

const { sanitizeConfig } = require('../orchestrator/scanner');

test('sanitizeConfig redacts secret-named keys nested inside env and headers', () => {
  const out = sanitizeConfig({
    command: 'npx',
    args: ['-y', 'some-mcp-server'],
    env: {
      OPENAI_API_KEY: 'sk-proj-LEAKEDsecret0001',
      AUTH_TOKEN: 'bearer-LEAKEDsecret0002',
      PATH: '/usr/bin',
    },
    headers: {
      Authorization: 'Bearer LEAKEDsecret0003headervalue',
      Accept: 'application/json',
    },
  });

  // Secret-named keys redacted regardless of depth.
  assert.equal(out.env.OPENAI_API_KEY, '[REDACTED]');
  assert.equal(out.env.AUTH_TOKEN, '[REDACTED]');
  assert.equal(out.headers.Authorization, '[REDACTED]');

  // Benign values preserved so the finding stays useful.
  assert.equal(out.command, 'npx');
  assert.deepEqual(out.args, ['-y', 'some-mcp-server']);
  assert.equal(out.env.PATH, '/usr/bin');
  assert.equal(out.headers.Accept, 'application/json');

  // No secret substring survives anywhere in the serialized output.
  const serialized = JSON.stringify(out);
  for (const leak of ['sk-proj-LEAKED', 'bearer-LEAKED', 'LEAKEDsecret0003']) {
    assert.ok(!serialized.includes(leak), `leaked credential survived redaction: ${leak}`);
  }
});

test('sanitizeConfig redacts top-level secret keys (existing behavior preserved)', () => {
  const out = sanitizeConfig({ apiKey: 'top-secret-value', password: 'hunter2', name: 'demo' });
  assert.equal(out.apiKey, '[REDACTED]');
  assert.equal(out.password, '[REDACTED]');
  assert.equal(out.name, 'demo');
});

test('sanitizeConfig redacts credential-shaped values under benign key names', () => {
  // A secret can appear positionally (e.g. args: ['--token', 'sk-...']) where
  // the surrounding key name gives no hint.
  const out = sanitizeConfig({
    args: ['--header', 'Bearer abcdEFGH1234567890token'],
    nested: { positional: 'sk-proj-anotherLeakedKey99' },
  });
  const serialized = JSON.stringify(out);
  assert.ok(!serialized.includes('Bearer abcdEFGH'), 'bearer value must be redacted by shape');
  assert.ok(!serialized.includes('sk-proj-anotherLeaked'), 'sk- value must be redacted by shape');
});

test('sanitizeConfig redacts secrets inside arrays of objects', () => {
  const out = sanitizeConfig({
    servers: [
      { name: 'a', env: { API_KEY: 'sk-deepArrayLeak001' } },
      { name: 'b', secret: 'do-not-emit' },
    ],
  });
  assert.equal(out.servers[0].env.API_KEY, '[REDACTED]');
  assert.equal(out.servers[1].secret, '[REDACTED]');
  assert.equal(out.servers[0].name, 'a');
  assert.equal(out.servers[1].name, 'b');
  const serialized = JSON.stringify(out);
  assert.ok(!serialized.includes('sk-deepArrayLeak'), 'array-nested key must be redacted');
  assert.ok(!serialized.includes('do-not-emit'), 'array-nested secret value must be redacted');
});

test('sanitizeConfig tolerates cycles without throwing', () => {
  const a = { token: 'sk-cycleLeak0001', child: {} };
  a.child.parent = a;
  const out = sanitizeConfig(a);
  assert.equal(out.token, '[REDACTED]');
  assert.equal(out.child.parent, '[CIRCULAR]');
});

test('sanitizeConfig passes non-object inputs through unchanged when benign', () => {
  assert.equal(sanitizeConfig('plain-string'), 'plain-string');
  assert.equal(sanitizeConfig(42), 42);
  assert.equal(sanitizeConfig(null), null);
});
