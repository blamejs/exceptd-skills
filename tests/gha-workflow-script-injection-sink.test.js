"use strict";
/**
 * tests/gha-workflow-script-injection-sink.test.js
 *
 * End-to-end fixture test for the GitHub Actions script-injection sink
 * indicator in data/playbooks/library-author.json. The regex is pulled
 * out of the indicator's `value` field at test time so the test stays
 * coupled to what operators actually run.
 *
 * v0.12.10 shipped a regex anchored on `run:\s*\|` (block-scalar pipe)
 * that missed single-line `run: <command>` shapes. v0.12.11 widens the
 * regex to `run:[\s\S]*?...` to admit both forms. Fixture #8 is the
 * exact shape that escaped the v0.12.10 regex; it must fire here.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');
const PB_PATH = path.join(ROOT, 'data/playbooks/library-author.json');
const playbook = JSON.parse(fs.readFileSync(PB_PATH, 'utf8'));

const indicator = playbook.phases.detect.indicators.find(
  (i) => i.id === 'gha-workflow-script-injection-sink'
);

test('gha-workflow-script-injection-sink: indicator is present in playbook', () => {
  assert.ok(indicator, 'indicator must exist in library-author playbook');
  assert.equal(indicator.id, 'gha-workflow-script-injection-sink');
  assert.ok(typeof indicator.value === 'string' && indicator.value.length > 0);
});

// Pull the regex out of the indicator value. The value contains multiple
// backtick-fenced spans (`run: |`, `run: <command>`, and the actual regex);
// the regex is the one whose body starts with `run:[`.
const regexMatch = indicator.value.match(/`(run:\[[^`]+)`/);
assert.ok(regexMatch, 'indicator value must embed the literal regex inside backticks, starting with `run:[`');
const SINK_RE = new RegExp(regexMatch[1]);

test('gha-workflow-script-injection-sink: extracted regex is non-trivial', () => {
  assert.ok(SINK_RE instanceof RegExp);
  // Sanity: must mention github.event somewhere
  assert.match(regexMatch[1], /github\\\.\(event/);
});

const FIXTURES = [
  {
    name: '1. block-scalar elementary-data exact sink',
    yaml: [
      'on:',
      '  issue_comment:',
      '    types: [created]',
      'jobs:',
      '  x:',
      '    runs-on: ubuntu-latest',
      '    steps:',
      '      - run: |',
      '          echo "${{ github.event.comment.body }}"',
      '',
    ].join('\n'),
    fires: true,
  },
  {
    name: '2. env-capture safety pattern (block scalar)',
    yaml: [
      'on: { issue_comment: { types: [created] } }',
      'jobs:',
      '  x:',
      '    runs-on: ubuntu-latest',
      '    steps:',
      '      - env:',
      '          COMMENT_BODY: ${{ github.event.comment.body }}',
      '        run: |',
      '          echo "$COMMENT_BODY"',
      '',
    ].join('\n'),
    fires: false,
  },
  {
    name: '3. sandboxed pull_request with title interpolation (fires at regex; FP demoted downstream)',
    yaml: [
      'on:',
      '  pull_request:',
      '    branches: [main]',
      'permissions:',
      '  contents: read',
      'jobs:',
      '  x:',
      '    runs-on: ubuntu-latest',
      '    steps:',
      '      - run: |',
      '          echo "PR title: ${{ github.event.pull_request.title }}"',
      '',
    ].join('\n'),
    fires: true,
  },
  {
    name: '4. pull_request_target with github.head_ref interpolation',
    yaml: [
      'on:',
      '  pull_request_target:',
      'jobs:',
      '  x:',
      '    runs-on: ubuntu-latest',
      '    steps:',
      '      - run: |',
      '          git checkout ${{ github.head_ref }}',
      '',
    ].join('\n'),
    fires: true,
  },
  {
    name: '5. discussion trigger with discussion.body interpolation',
    yaml: [
      'on:',
      '  discussion:',
      '    types: [created]',
      'jobs:',
      '  x:',
      '    runs-on: ubuntu-latest',
      '    steps:',
      '      - run: |',
      '          echo "${{ github.event.discussion.body }}"',
      '',
    ].join('\n'),
    fires: true,
  },
  {
    name: '6. push trigger with head_commit.message interpolation',
    yaml: [
      'on: push',
      'jobs:',
      '  x:',
      '    runs-on: ubuntu-latest',
      '    steps:',
      '      - run: |',
      '          echo "commit: ${{ github.event.head_commit.message }}"',
      '',
    ].join('\n'),
    fires: true,
  },
  {
    name: '7. env-capture safety pattern (single-line)',
    yaml: [
      'on: { issue_comment: { types: [created] } }',
      'jobs:',
      '  x:',
      '    runs-on: ubuntu-latest',
      '    steps:',
      '      - env:',
      '          COMMENT_BODY: ${{ github.event.comment.body }}',
      '        run: echo "$COMMENT_BODY"',
      '',
    ].join('\n'),
    fires: false,
  },
  {
    name: '8. single-line run: with github.event interpolation (v0.12.11 gap)',
    yaml: [
      'on:',
      '  issue_comment:',
      '    types: [created]',
      'jobs:',
      '  x:',
      '    runs-on: ubuntu-latest',
      '    steps:',
      '      - run: echo "${{ github.event.comment.body }}"',
      '',
    ].join('\n'),
    fires: true,
  },
];

for (const f of FIXTURES) {
  test(`gha-workflow-script-injection-sink: ${f.name}`, () => {
    const hit = SINK_RE.test(f.yaml);
    assert.equal(
      hit,
      f.fires,
      `expected ${f.fires ? 'FIRES' : 'no-fire'} for fixture "${f.name}"`
    );
  });
}
