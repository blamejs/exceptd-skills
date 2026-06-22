"use strict";


// ---- routed from playbook-supply-chain-recovery.substantive ----
require("node:test").describe("playbook-supply-chain-recovery.substantive", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
/**
 * tests/playbook-supply-chain-recovery.substantive.test.js
 *
 * Pins the canonical indicator + artifact ids for the
 * supply-chain-recovery playbook. Diff-coverage refuses merges that
 * rename or drop these ids without an updated test; the NEW-CTRL-050 /
 * 051 / 052 control surface and the cred-stores / idp-incident-response /
 * sbom / mcp / framework feeds_into arcs depend on them.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const fs = require('node:fs');

const ROOT = path.join(__dirname, '..');
const PLAYBOOK = JSON.parse(fs.readFileSync(
  path.join(ROOT, 'data', 'playbooks', 'supply-chain-recovery.json'),
  'utf8',
));

const EXPECTED_INDICATORS = [
  'compromised-install-on-host',
  'ai-assistant-config-mutated',
  'credential-store-touched-during-window',
  'outbound-exfil-during-window',
  'operator-published-package-republish',
  'ir-plan-missing-supply-chain-recovery',
  'long-lived-token-in-compromised-ci-log',
  'no-provenance-revocation-filed',
];

const EXPECTED_ARTIFACTS = [
  'compromised-package-inventory',
  'install-history-per-host',
  'maintainer-credential-inventory',
  'outbound-publish-surface',
  'lateral-exfil-network-evidence',
  'ai-assistant-config-snapshot',
  'downstream-consumer-list',
  'provenance-revocation-state',
  'incident-response-plan',
];

function ids(arr) { return new Set((arr || []).map((x) => x.id).filter(Boolean)); }

test('supply-chain-recovery: playbook id + attack class', () => {
  assert.equal(PLAYBOOK._meta.id, 'supply-chain-recovery');
  assert.equal(PLAYBOOK.domain.attack_class, 'supply-chain');
});

test('supply-chain-recovery: every documented indicator id is present', () => {
  const present = ids(PLAYBOOK.phases.detect.indicators);
  for (const id of EXPECTED_INDICATORS) {
    assert.ok(present.has(id), `missing indicator id: ${id}`);
  }
});

test('supply-chain-recovery: every documented artifact id is present', () => {
  const present = ids(PLAYBOOK.phases.look.artifacts);
  for (const id of EXPECTED_ARTIFACTS) {
    assert.ok(present.has(id), `missing artifact id: ${id}`);
  }
});

test('supply-chain-recovery: feeds_into chain reaches cred-stores + sbom + mcp + framework', () => {
  const feeds = (PLAYBOOK._meta.feeds_into || []).map((f) => f.playbook_id);
  for (const target of ['cred-stores', 'sbom', 'mcp', 'framework']) {
    assert.ok(feeds.includes(target), `missing feeds_into target: ${target}`);
  }
});
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});
