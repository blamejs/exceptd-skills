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
 *   - metadata.tools                 hand-written generator
 *   - metadata.component             application entry for exceptd-skills
 *   - metadata.properties            catalog count, skill count, dataflow
 *                                    inputs, and the per-skill Ed25519
 *                                    integrity claim (lib/sign.js)
 *   - components                     [] — zero npm runtime deps
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
          name: 'hand-written',
          version: '0.1.0',
          description:
            'SBOM generated from package.json + manual review (scripts/refresh-sbom.js).',
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
    components: vendoredComponents,
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
