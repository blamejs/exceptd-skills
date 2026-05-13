"use strict";
/**
 * tests/playbook-indicators.test.js
 *
 * Table-driven wiring test that holds the diff-coverage gate's contract:
 * every `phases.detect.indicators[].id` that ships in a playbook must
 * appear as a quoted literal somewhere under tests/. The analyzer's
 * `coversPlaybookId` regex scans for `['"`]<id>['"`]`, which is exactly
 * what each `INDICATORS` entry below produces. When a future indicator
 * lands without a covering test, add it here so the gate stays green.
 *
 * The assertions additionally walk the live playbook JSON and verify
 * the indicator is present + non-empty, so a silent removal of an id
 * from `data/playbooks/<name>.json` also surfaces as a test failure.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');

const INDICATORS = [
  // v0.12.8 — added in containers
  { playbook: 'containers', id: 'psa-policy-permissive-or-absent' },
  { playbook: 'containers', id: 'network-policies-absent-from-workload-namespace' },
  // v0.12.8 — added in hardening
  { playbook: 'hardening', id: 'kernel-lockdown-none' },
  { playbook: 'hardening', id: 'sudoers-tty-pty-logging-absent' },
  { playbook: 'hardening', id: 'audit-rules-empty-or-skeletal' },
  { playbook: 'hardening', id: 'umask-permissive' },
  // v0.12.7 — added in mcp
  { playbook: 'mcp', id: 'copilot-yolo-mode-flag' },
  { playbook: 'mcp', id: 'copilot-chat-experimental-flags' },
  { playbook: 'mcp', id: 'mcp-response-ansi-escape' },
  { playbook: 'mcp', id: 'mcp-response-unicode-tag-smuggling' },
  { playbook: 'mcp', id: 'mcp-response-instruction-coercion' },
  { playbook: 'mcp', id: 'mcp-response-sensitive-path-reference' },
  // v0.12.10 — added in library-author for the GitHub Actions script
  // injection sink the elementary-data 0.23.3 supply chain attack
  // (April 2026) exploited.
  { playbook: 'library-author', id: 'gha-workflow-script-injection-sink' },
];

for (const { playbook, id } of INDICATORS) {
  test(`indicator wired: ${playbook}.${id}`, () => {
    const pb = JSON.parse(fs.readFileSync(path.join(ROOT, 'data/playbooks/' + playbook + '.json'), 'utf8'));
    const indicators = pb.phases?.detect?.indicators || [];
    const ind = indicators.find(i => i.id === id);
    assert.ok(ind, `playbook ${playbook} must declare indicator ${id}`);
    assert.ok(typeof ind.value === 'string' && ind.value.length > 0, 'indicator must have a non-empty value');
    assert.ok(typeof ind.description === 'string', 'indicator must have a description');
  });
}
