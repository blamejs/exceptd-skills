"use strict";


// ---- routed from doc-playbook-count-currency ----
require("node:test").describe("doc-playbook-count-currency", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
/**
 * tests/doc-playbook-count-currency.test.js
 *
 * v0.13.10 regression pin. README.md + AGENTS.md include prose like
 * "23 investigation playbooks" or "Grouped-by-scope summary of all 23
 * playbooks". When new playbooks land, the count must move in lockstep
 * with data/playbooks/*.json -- otherwise operators reading the README
 * believe the surface is smaller than it actually is.
 *
 * The pin: every prose number-of-playbooks claim in README.md /
 * AGENTS.md must match the live count of data/playbooks/*.json files.
 * If a future release adds a playbook without bumping the count in
 * docs, this test fires.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');

function livePlaybookCount() {
  return fs.readdirSync(path.join(ROOT, 'data', 'playbooks'))
    .filter((f) => f.endsWith('.json'))
    .length;
}

function findClaims(filePath) {
  const text = fs.readFileSync(filePath, 'utf8');
  // Match "<N> playbook(s)" and "<N> investigation playbook(s)" patterns.
  const re = /\b(\d{1,3})\s+(?:investigation\s+)?playbooks?\b/gi;
  const claims = [];
  let m;
  while ((m = re.exec(text)) !== null) {
    const n = Number(m[1]);
    const start = Math.max(0, m.index - 40);
    const end = Math.min(text.length, m.index + 60);
    claims.push({ n, snippet: text.slice(start, end).replace(/\s+/g, ' ').trim() });
  }
  return claims;
}

test('README + AGENTS playbook-count claims match live catalog count', () => {
  const live = livePlaybookCount();
  assert.ok(live >= 23, `expected live count >= 23; got ${live}`);

  const docs = ['README.md', 'AGENTS.md'];
  const mismatches = [];
  for (const rel of docs) {
    const claims = findClaims(path.join(ROOT, rel));
    for (const c of claims) {
      // Numbers 1-14 are almost certainly grammatical ("five-phase",
      // "two of the playbooks", etc.) -- only assert against the high
      // range that genuinely talks about the catalog total.
      if (c.n < 15) continue;
      if (c.n !== live) {
        mismatches.push(`${rel}: claim "${c.n} playbooks" disagrees with live count ${live} (context: ...${c.snippet}...)`);
      }
    }
  }
  assert.deepEqual(mismatches, [],
    `doc playbook-count drift:\n  - ${mismatches.join('\n  - ')}\n` +
    `Update the claim to "${live} playbooks" in the named file(s).`);
});
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});


// ---- routed from catalog-data-integrity ----
require("node:test").describe("catalog-data-integrity", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
/**
 * Regression suite for a catalog data-integrity / curation pass:
 *
 *   - The AI supply-chain families (ShadowMQ, Triton auth-bypass) carry ATLAS
 *     mappings — they were unmapped while sibling family entries carried
 *     AML.T0049 (Hard Rule #7 coherence).
 *   - The active_exploitation "theoretical" status is an explicit entry in the
 *     RWEP scoring ladder (not an incidental `?? 0` fall-through).
 *   - The jurisdiction count is consistent across the stale-content and
 *     catalog-summaries builders and the README badge (all count GLOBAL → 35).
 *   - framework-control-gaps _meta.entry_count matches the actual entry count
 *     (a gate now enforces this).
 *   - Shipped playbook threat_currency_score stays within the documented band.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");

const ROOT = path.join(__dirname, "..");
const cve = require(path.join(ROOT, "data", "cve-catalog.json"));
const atlas = require(path.join(ROOT, "data", "atlas-ttps.json"));
const gaps = require(path.join(ROOT, "data", "framework-control-gaps.json"));
const gf = require(path.join(ROOT, "data", "global-frameworks.json"));
const scoring = require(path.join(ROOT, "lib", "scoring.js"));

test("shipped playbooks' threat_currency_score stays within the documented 92-96 band", () => {
  const fs = require("fs");
  const dir = path.join(ROOT, "data", "playbooks");
  for (const f of fs.readdirSync(dir)) {
    if (!f.endsWith(".json")) continue;
    const pb = JSON.parse(fs.readFileSync(path.join(dir, f), "utf8"));
    const score = pb._meta && pb._meta.threat_currency_score;
    assert.ok(score >= 92 && score <= 96, `${f}: threat_currency_score ${score} must be in 92-96`);
  }
});
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});
