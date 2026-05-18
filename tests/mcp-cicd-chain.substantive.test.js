'use strict';

/**
 * tests/mcp-cicd-chain.substantive.test.js
 *
 * v0.13.5 — Pins the new mcp-server-invoked-from-ci-pipeline indicator
 * and the mcp → cicd-pipeline-compromise feeds_into arc. The arc is
 * what escalates an MCP tool-poisoning finding from local-dev close-out
 * to supply-chain handling when the MCP server runs inside a CI runner.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const fs = require('node:fs');

const ROOT = path.join(__dirname, '..');
const MCP = JSON.parse(fs.readFileSync(
  path.join(ROOT, 'data', 'playbooks', 'mcp.json'),
  'utf8',
));

test('mcp-server-invoked-from-ci-pipeline indicator is present + deterministic', () => {
  const indicators = (MCP.phases.detect.indicators || []);
  const ind = indicators.find((x) => x.id === 'mcp-server-invoked-from-ci-pipeline');
  assert.ok(ind, 'missing mcp-server-invoked-from-ci-pipeline indicator');
  assert.equal(ind.deterministic, true);
  // Must key on at least one of the runner-emitted env vars.
  assert.match(
    ind.value,
    /GITHUB_ACTIONS|GITLAB_CI|BUILDKITE|JENKINS_URL|CIRCLECI|RUNNER_OS/,
    'indicator must key on a runner-emitted env var',
  );
});

test('mcp feeds_into cicd-pipeline-compromise', () => {
  const feeds = (MCP._meta.feeds_into || []).map((f) => f.playbook_id);
  assert.ok(feeds.includes('cicd-pipeline-compromise'),
    'mcp.feeds_into must include cicd-pipeline-compromise');
});

test('cicd-pipeline-compromise.fed_by includes mcp', () => {
  const cicd = JSON.parse(fs.readFileSync(
    path.join(ROOT, 'data', 'playbooks', 'cicd-pipeline-compromise.json'),
    'utf8',
  ));
  const fedBy = cicd._meta.fed_by || [];
  assert.ok(fedBy.includes('mcp'),
    'cicd-pipeline-compromise._meta.fed_by must include mcp (bidirectional chain)');
});

test('playbook schema indicator.type enum includes env_var (CI-runner-context indicator class)', () => {
  // v0.13.8 regression pin. The `mcp-server-invoked-from-ci-pipeline`
  // indicator is `type: "env_var"`. Prior schema enum rejected the value
  // as a validate-playbooks warning. The schema now lists `env_var` plus
  // two near-neighbour types (`config_value`, `registry_key`) that
  // future indicators are likely to need. If any of these are dropped, an
  // operator-visible IoC class regresses to silent failure.
  const schema = JSON.parse(fs.readFileSync(
    path.join(ROOT, 'lib', 'schemas', 'playbook.schema.json'),
    'utf8',
  ));
  // Walk to the indicator.type enum.
  const phases = schema.properties && schema.properties.phases;
  const detect = phases && phases.properties && phases.properties.detect;
  const indicators = detect && detect.properties && detect.properties.indicators;
  const itemProps = indicators && indicators.items && indicators.items.properties;
  const typeEnum = itemProps && itemProps.type && itemProps.type.enum;
  assert.ok(Array.isArray(typeEnum), 'schema indicator.type.enum must be an array');
  for (const required of ['env_var', 'config_value', 'registry_key']) {
    assert.ok(typeEnum.includes(required),
      `indicator.type.enum must include "${required}" (required by current IoC classes)`);
  }
});
