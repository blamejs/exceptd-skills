"use strict";


// ---- routed from hard-rule-forcing-functions ----
require("node:test").describe("hard-rule-forcing-functions", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
/**
 * tests/hard-rule-forcing-functions.test.js
 *
 * Cycle 16 audit fix (v0.12.36): closes 3 gaps in AGENTS.md Hard Rule
 * forcing-function coverage. Without these tests the rules were
 * policy-only — a future PR could violate them and the CI gate would
 * stay green.
 *
 *   Rule #3 (no CVSS-only risk scoring): every non-draft CVE in
 *     data/cve-catalog.json must declare rwep_score + rwep_factors.
 *
 *   Rule #5 (global-first, not US-centric): the framework-control-gaps
 *     catalog must carry entries for EU + UK + AU + INTL alongside US.
 *
 *   Rule #8 (Pinned ATLAS version): manifest.json's atlas_version field
 *     must equal data/atlas-ttps.json._meta.atlas_version exactly, and
 *     same for attack_version. Pre-cycle-9 these drifted silently.
 *
 *   Cross-format CVE consistency: CSAF + OpenVEX + SARIF emitters must
 *     agree on the catalogued-CVE set per playbook run.
 *
 * Per the anti-coincidence rule, every assertion checks an EXACT
 * value (deep-equality or specific count).
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');
const manifest = JSON.parse(fs.readFileSync(path.join(ROOT, 'manifest.json'), 'utf8'));
const cve = JSON.parse(fs.readFileSync(path.join(ROOT, 'data', 'cve-catalog.json'), 'utf8'));
const gaps = JSON.parse(fs.readFileSync(path.join(ROOT, 'data', 'framework-control-gaps.json'), 'utf8'));
const atlas = JSON.parse(fs.readFileSync(path.join(ROOT, 'data', 'atlas-ttps.json'), 'utf8'));
const attack = JSON.parse(fs.readFileSync(path.join(ROOT, 'data', 'attack-techniques.json'), 'utf8'));


function frameworkRegion(frameworkText) {
  if (!frameworkText) return 'OTHER';
  if (/NIST|FedRAMP|CMMC|HIPAA|HITRUST|PCI|SOC|CIS Controls|OFAC|SEC|NYDFS|CIRCIA/i.test(frameworkText)) return 'US';
  if (/NIS2|DORA|GDPR|^EU |EU-|ENISA|CRA |AI Act|EU 2014\/833/i.test(frameworkText)) return 'EU';
  if (/\b(?:UK|CAF|Ofcom|NCSC|OFSI|UK-GDPR)\b/i.test(frameworkText)) return 'UK';
  if (/\b(?:AU|ACSC|ISM|Essential 8|APRA|eSafety|AU NDB)\b/i.test(frameworkText)) return 'AU';
  if (/\b(?:ISO|IEC \d|3GPP|GSMA|ITU|FCC|TSA|OWASP|SLSA|CycloneDX|SPDX)\b/i.test(frameworkText)) return 'INTL';
  return 'OTHER';
}

test('Hard Rule #8 — manifest.atlas_version matches data/atlas-ttps.json._meta.atlas_version exactly', () => {
  const manifestPin = manifest.atlas_version;
  const catalogPin = atlas._meta.atlas_version;
  assert.equal(typeof manifestPin, 'string', 'manifest.atlas_version must be set');
  assert.equal(typeof catalogPin, 'string', 'atlas-ttps._meta.atlas_version must be set');
  assert.equal(manifestPin, catalogPin,
    `Rule #8 violation: manifest pins ATLAS v${manifestPin} but catalog meta is v${catalogPin}. Pre-cycle-9 silent-drift class re-introduced.`);
});
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});
