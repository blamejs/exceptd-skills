"use strict";


// ---- routed from standards-version-canonical ----
require("node:test").describe("standards-version-canonical", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
/**
 * tests/standards-version-canonical.test.js
 *
 * D3FEND and CWE join ATLAS and ATT&CK as pinned external standards whose
 * single source of truth lives in the catalog `_meta`:
 *   - data/d3fend-catalog.json._meta.d3fend_version
 *   - data/cwe-catalog.json._meta.cwe_version
 *
 * Every operator-facing mention of a D3FEND or CWE version — docs, skill
 * bodies, the catalog-summary builder, and its derived index — must equal the
 * pinned value. Before this guard existed the pins drifted badly: the catalog
 * stayed on D3FEND v1.0.0 / CWE 4.16 for over a year while the real releases
 * reached v1.3.0 / 4.20, and the docs even disagreed with the catalog (README
 * said CWE v4.17 while _meta said 4.16; one skill still cited D3FEND v0.10).
 *
 * Exact-match (not stale-only): these are point-in-time pins with no
 * forward-watch convention, so any deviation — older or newer — is drift.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');
const D3FEND = JSON.parse(fs.readFileSync(path.join(ROOT, 'data', 'd3fend-catalog.json'), 'utf8'))._meta.d3fend_version;
const CWE = JSON.parse(fs.readFileSync(path.join(ROOT, 'data', 'cwe-catalog.json'), 'utf8'))._meta.cwe_version;

const DOC_FILES = [
  'README.md',
  'ARCHITECTURE.md',
  'CONTEXT.md',
  'AGENTS.md',
  '.cursorrules',
  'scripts/builders/catalog-summaries.js',
  'data/_indexes/catalog-summaries.json',
];

function skillBodies() {
  const dir = path.join(ROOT, 'skills');
  if (!fs.existsSync(dir)) return [];
  return fs.readdirSync(dir)
    .map((n) => path.join('skills', n, 'skill.md'))
    .filter((rel) => fs.existsSync(path.join(ROOT, rel)));
}

// "D3FEND v1.3.0" / "D3FEND 1.3.0" — version must follow the framework name.
const D3FEND_RE = /D3FEND\s+v?(\d+\.\d+(?:\.\d+)?)/g;
// "CWE v4.20" / "CWE 4.20" — the `4.` prefix avoids matching "CWE-79" IDs.
const CWE_RE = /CWE\s+v?(4\.\d+)/g;

function scan(rel, re, canonical) {
  const abs = path.join(ROOT, rel);
  if (!fs.existsSync(abs)) return [];
  const text = fs.readFileSync(abs, 'utf8');
  const drift = [];
  for (const m of text.matchAll(re)) {
    if (m[1] !== canonical) {
      const lineNo = text.slice(0, m.index).split('\n').length;
      drift.push(`${rel}:${lineNo} — found ${m[1]}, canonical is ${canonical}`);
    }
  }
  return drift;
}

test('every CWE version mention equals the catalog pin', () => {
  const drift = [];
  for (const rel of [...DOC_FILES, ...skillBodies()]) drift.push(...scan(rel, CWE_RE, CWE));
  assert.equal(drift.length, 0,
    `CWE version drift (canonical v${CWE}):\n  ${drift.join('\n  ')}`);
});
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});
