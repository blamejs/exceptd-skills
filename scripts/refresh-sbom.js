#!/usr/bin/env node
/*
 * scripts/refresh-sbom.js — regenerate sbom.cdx.json.
 *
 * The exceptd repository is zero-runtime-dependency by design (see
 * package.json `dependencies: {}`). The SBOM therefore documents the
 * project as an application component with an empty `components` array
 * and pulls live surface counts from manifest.json + data/*.json so the
 * artifact never silently drifts when the surface changes.
 *
 * Generated fields:
 *   - bomFormat / specVersion        CycloneDX 1.6
 *   - serialNumber                   urn:uuid v4 derived from a stable
 *                                    hash of (project name + version +
 *                                    timestamp) so reruns produce a new
 *                                    UUID per refresh.
 *   - metadata.timestamp             ISO 8601 of generation
 *   - metadata.tools                 this script itself, version pulled
 *                                    from package.json at refresh time
 *   - metadata.component             application entry for exceptd-skills,
 *                                    including a hashes[] bundle digest
 *                                    that operators can recompute from
 *                                    the per-file component list (see
 *                                    `bundleDigest` below for the exact
 *                                    canonical-input rule)
 *   - metadata.properties            catalog count, skill count, dataflow
 *                                    inputs, and the per-skill Ed25519
 *                                    integrity claim (lib/sign.js)
 *   - components                     vendored libraries + a `type: file`
 *                                    component per shipped file in the
 *                                    package.json `files` allowlist, each
 *                                    carrying its SHA-256 hash. Lets
 *                                    CycloneDX-aware vuln scanners verify
 *                                    individual files against the bundle
 *                                    without re-deriving the canonical
 *                                    list themselves.
 *   - dependencies                   [] — nothing to depend on
 *
 * Run:   node scripts/refresh-sbom.js
 *        npm run refresh-sbom
 *
 * No external dependencies. Node 24 stdlib only.
 */

'use strict';

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const process = require('node:process');

const REPO_ROOT = path.resolve(__dirname, '..');
const PACKAGE_PATH = path.join(REPO_ROOT, 'package.json');
const MANIFEST_PATH = path.join(REPO_ROOT, 'manifest.json');
const DATA_DIR = path.join(REPO_ROOT, 'data');
const SBOM_PATH = path.join(REPO_ROOT, 'sbom.cdx.json');

function readJson(p) {
  return JSON.parse(fs.readFileSync(p, 'utf8'));
}

function countDataCatalogs(dir) {
  return fs
    .readdirSync(dir)
    .filter((f) => f.endsWith('.json'))
    .sort();
}

/* RFC 4122 v4 UUID derived deterministically from a seed string so a
 * given (project, version, timestamp) triple maps to a stable UUID
 * across observers. Uses crypto.randomUUID() fallback if no seed. */
function uuidV4FromSeed(seed) {
  const hash = crypto.createHash('sha256').update(seed).digest();
  const b = Buffer.from(hash.subarray(0, 16));
  b[6] = (b[6] & 0x0f) | 0x40; // version 4
  b[8] = (b[8] & 0x3f) | 0x80; // RFC 4122 variant
  const hex = b.toString('hex');
  return (
    hex.slice(0, 8) +
    '-' +
    hex.slice(8, 12) +
    '-' +
    hex.slice(12, 16) +
    '-' +
    hex.slice(16, 20) +
    '-' +
    hex.slice(20, 32)
  );
}

function loadVendorProvenance() {
  const p = path.join(REPO_ROOT, 'vendor', 'blamejs', '_PROVENANCE.json');
  if (!fs.existsSync(p)) return null;
  try {
    return readJson(p);
  } catch {
    return null;
  }
}

/* Recursively expand a `package.json.files` allowlist entry into the
 * concrete file list that npm pack would ship. The allowlist accepts
 * either a file path or a directory path (with trailing slash convention
 * inside this repo); directories expand to every regular file beneath
 * them. Returned paths are POSIX-style relative to REPO_ROOT so the
 * SHA-256 input is stable across operating systems.
 *
 * Mirrors npm's pack-time inclusion rules at the level of fidelity this
 * SBOM needs (a deeper match — .npmignore, package-lock fields, npm-CLI
 * defaults — is intentionally out of scope: any divergence here surfaces
 * as a SHA mismatch on the predeploy verify-shipped-tarball gate, which
 * is the authoritative consumer-side check).
 */
function walkFiles(absDir) {
  const out = [];
  const entries = fs.readdirSync(absDir, { withFileTypes: true });
  for (const entry of entries.sort((a, b) => a.name.localeCompare(b.name))) {
    const abs = path.join(absDir, entry.name);
    if (entry.isDirectory()) {
      out.push(...walkFiles(abs));
    } else if (entry.isFile()) {
      out.push(abs);
    }
  }
  return out;
}

/* Files that cannot have a stable SHA inside the SBOM they belong to.
 * `sbom.cdx.json` is the obvious self-reference: hashing it would always
 * be stale the moment the SBOM gets written back. The bundle digest in
 * metadata.component.hashes[] covers everything ELSE that ships and is
 * the operator's verification anchor for the bundle as a whole. */
const SELF_EXCLUDED = new Set(['sbom.cdx.json']);

/* Path prefixes whose contents are derivable / cache-class artifacts.
 * `data/_indexes/` is the pre-computed index cache that ships in the
 * tarball but is regenerated by `npm run build-indexes`. The test suite
 * deliberately mutates these files (build-incremental.test.js,
 * indexes-v070.test.js), so per-file SHA verification would race against
 * any test run that touches the cache between refresh-sbom and the
 * verification gate. The bundle digest at metadata.component.hashes[] is
 * computed from a SBOM-generation-time snapshot of all OTHER files; the
 * cache is excluded from the per-file inventory entirely. Predeploy's
 * `Pre-computed indexes freshness` gate is the authoritative consumer-
 * side check for the cache. */
const DERIVABLE_PREFIXES = ['data/_indexes/'];

function isDerivable(rel) {
  return DERIVABLE_PREFIXES.some((p) => rel === p.replace(/\/$/, '') || rel.startsWith(p));
}

function expandAllowlist(allowlist) {
  const abs = [];
  for (const entry of allowlist) {
    const full = path.join(REPO_ROOT, entry);
    if (!fs.existsSync(full)) continue; // tolerate a stale entry; predeploy gate flags
    const stat = fs.statSync(full);
    if (stat.isDirectory()) {
      abs.push(...walkFiles(full));
    } else if (stat.isFile()) {
      abs.push(full);
    }
  }
  // dedupe + sort by relative POSIX path for deterministic output;
  // strip self-referential entries (see SELF_EXCLUDED) and derivable cache
  // entries (see DERIVABLE_PREFIXES).
  const rel = Array.from(new Set(abs.map((a) => toPosixRel(a))))
    .filter((r) => !SELF_EXCLUDED.has(r))
    .filter((r) => !isDerivable(r))
    .sort();
  return rel;
}

function toPosixRel(absPath) {
  return path
    .relative(REPO_ROOT, absPath)
    .split(path.sep)
    .join('/');
}

function sha256File(absPath) {
  return crypto
    .createHash('sha256')
    .update(fs.readFileSync(absPath))
    .digest('hex');
}

function fileComponents(allowlist) {
  const rels = expandAllowlist(allowlist);
  const out = [];
  for (const rel of rels) {
    const abs = path.join(REPO_ROOT, rel);
    out.push({
      'bom-ref': `file:${rel}`,
      type: 'file',
      name: rel,
      hashes: [{ alg: 'SHA-256', content: sha256File(abs) }],
    });
  }
  return out;
}

/* Bundle digest = SHA-256 over a deterministic newline-delimited
 * "<sha256>\t<relpath>\n" stream of every shipped file, sorted by
 * relpath. The same input shape an operator would assemble from the
 * components[] list (`type: file` entries) lets them recompute and
 * compare without trusting the SBOM's stored value blindly.
 */
function bundleDigest(fileComps) {
  const sorted = [...fileComps].sort((a, b) =>
    a.name < b.name ? -1 : a.name > b.name ? 1 : 0,
  );
  const hash = crypto.createHash('sha256');
  for (const c of sorted) {
    hash.update(c.hashes[0].content);
    hash.update('\t');
    hash.update(c.name);
    hash.update('\n');
  }
  return hash.digest('hex');
}

function vendorComponents(prov) {
  if (!prov || !prov.files) return [];
  const out = [];
  for (const [name, info] of Object.entries(prov.files)) {
    out.push({
      'bom-ref': `vendor:blamejs:${name}`,
      type: 'library',
      name: `blamejs/${name}`,
      version: prov.pinned_commit ? prov.pinned_commit.slice(0, 12) : 'unknown',
      description: `Vendored from blamejs/lib/${name} (flattened + stripped). See vendor/blamejs/README.md.`,
      licenses: [{ license: { id: prov.license || 'Apache-2.0' } }],
      hashes: [{ alg: 'SHA-256', content: info.vendored_sha256 }],
      externalReferences: [
        { type: 'vcs', url: prov.source_repo || 'https://github.com/blamejs/blamejs' },
        { type: 'distribution', url: `${prov.source_repo || 'https://github.com/blamejs/blamejs'}/blob/${prov.pinned_commit}/${info.upstream_path}` },
      ],
      properties: [
        { name: 'exceptd:vendor:upstream_sha256_at_pin', value: info.upstream_sha256_at_pin || '' },
        { name: 'exceptd:vendor:strip_summary', value: (info.stripped || []).join('; ') },
      ],
    });
  }
  return out;
}

function buildSbom() {
  const pkg = readJson(PACKAGE_PATH);
  const manifest = readJson(MANIFEST_PATH);
  const catalogs = countDataCatalogs(DATA_DIR);
  const timestamp = new Date().toISOString();
  const skillCount = Array.isArray(manifest.skills) ? manifest.skills.length : 0;
  const catalogCount = catalogs.length;
  const vendorProv = loadVendorProvenance();
  const vendoredComponents = vendorComponents(vendorProv);
  const fileComps = fileComponents(Array.isArray(pkg.files) ? pkg.files : []);
  const bundleSha = bundleDigest(fileComps);

  // Sort the union of vendor + file components by bom-ref for
  // deterministic regeneration.
  const allComponents = [...vendoredComponents, ...fileComps].sort((a, b) =>
    a['bom-ref'] < b['bom-ref'] ? -1 : a['bom-ref'] > b['bom-ref'] ? 1 : 0,
  );

  const serialNumber =
    'urn:uuid:' +
    uuidV4FromSeed(`${pkg.name}@${pkg.version}@${timestamp}`);

  const dataflowInput = catalogs
    .map((c) => `data/${c}`)
    .join(',');

  const sbom = {
    bomFormat: 'CycloneDX',
    specVersion: '1.6',
    serialNumber: serialNumber,
    version: 1,
    metadata: {
      timestamp: timestamp,
      tools: [
        {
          vendor: 'blamejs',
          name: 'scripts/refresh-sbom.js',
          version: pkg.version,
        },
      ],
      component: {
        // Switch from project: scheme to pkg:npm scheme post-v0.9.0 — the
        // package is now published on npm with provenance attestation, so
        // the CycloneDX bom-ref should reflect the canonical PURL.
        'bom-ref': `pkg:npm/${pkg.name}@${pkg.version}`,
        type: 'application',
        name: pkg.name,
        version: pkg.version,
        description: pkg.description,
        licenses: [{ license: { id: 'Apache-2.0' } }],
        purl: `pkg:npm/${pkg.name.replace('@', '%40')}@${pkg.version}`,
        // Bundle digest over every shipped file (see bundleDigest above
        // for the canonical-input rule). Operators can recompute this
        // from the per-file components[] list and compare without
        // re-deriving package.json.files themselves.
        hashes: [{ alg: 'SHA-256', content: bundleSha }],
        externalReferences: [
          { type: 'distribution', url: `https://www.npmjs.com/package/${pkg.name}/v/${pkg.version}` },
          { type: 'vcs', url: (pkg.repository && pkg.repository.url) || 'https://github.com/blamejs/exceptd-skills' },
        ],
      },
      properties: [
        {
          name: 'cyclonedx:dataflow:input',
          value: dataflowInput,
        },
        {
          name: 'exceptd:catalog:count',
          value: String(catalogCount),
        },
        {
          name: 'exceptd:skill:count',
          value: String(skillCount),
        },
        {
          name: 'exceptd:integrity:method',
          value: 'Ed25519 per-skill (lib/sign.js)',
        },
        {
          name: 'exceptd:runtime:dependency:count',
          value: String(Object.keys(pkg.dependencies || {}).length),
        },
        {
          name: 'exceptd:devDependency:count',
          value: String(Object.keys(pkg.devDependencies || {}).length),
        },
        {
          name: 'exceptd:vendor:count',
          value: String(vendoredComponents.length),
        },
        {
          name: 'exceptd:vendor:pin',
          value: vendorProv?.pinned_commit
            ? `${vendorProv.source_repo}@${vendorProv.pinned_commit}`
            : 'none',
        },
      ],
    },
    components: allComponents,
    dependencies: [],
  };

  return sbom;
}

function main() {
  const sbom = buildSbom();
  const json = JSON.stringify(sbom, null, 2) + '\n';
  fs.writeFileSync(SBOM_PATH, json, 'utf8');
  const lines = json.split(/\r?\n/).length;
  process.stdout.write(
    `wrote sbom.cdx.json — CycloneDX 1.6, ${lines} lines, ` +
      `${sbom.metadata.properties.length} metadata.properties, ` +
      `${sbom.components.length} components, serial ${sbom.serialNumber}\n`,
  );
}

if (require.main === module) {
  main();
}

module.exports = { buildSbom };
