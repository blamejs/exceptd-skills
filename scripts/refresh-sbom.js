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

function buildSbom() {
  const pkg = readJson(PACKAGE_PATH);
  const manifest = readJson(MANIFEST_PATH);
  const catalogs = countDataCatalogs(DATA_DIR);
  const timestamp = new Date().toISOString();
  const skillCount = Array.isArray(manifest.skills) ? manifest.skills.length : 0;
  const catalogCount = catalogs.length;

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
        'bom-ref': `pkg:project/${pkg.name}@${pkg.version}`,
        type: 'application',
        name: 'exceptd-skills',
        version: pkg.version,
        description: pkg.description,
        licenses: [{ license: { id: 'Apache-2.0' } }],
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
      ],
    },
    components: [],
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
