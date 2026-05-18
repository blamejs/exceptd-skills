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
