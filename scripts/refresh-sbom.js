#!/usr/bin/env node
/*
 * Regenerates sbom.cdx.json, a CycloneDX 1.6 bundle. Every generated field is
 * deterministic — identical content reproduces an identical SBOM, which is what
 * makes the currency gate's regenerate-and-compare mean anything.
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

function listDataCatalogs(dir) {
  return fs
    .readdirSync(dir)
    .filter((f) => f.endsWith('.json'))
    .sort();
}

/* RFC 4122 v4 UUID derived from a seed, so one seed maps to one UUID. */
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

/* Every regular file beneath absDir, in name order for a stable inventory. */
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

/* No stable SHA inside the SBOM that contains it: the hash is stale on write. */
const SELF_EXCLUDED = new Set(['sbom.cdx.json']);

/* Derivable cache artifacts, kept out of the per-file inventory: the test suite
 * mutates data/_indexes/, so a pinned per-file hash would race any run that
 * touches the cache. Predeploy's index-freshness gate covers them instead. */
const DERIVABLE_PREFIXES = ['data/_indexes/'];

/* Files npm ships whatever the `files` allowlist says, unioned in so they are
 * hashed too. The list is hand-maintained, which is only safe because
 * lib/validate-package.js compares the real `npm pack` output against this SBOM
 * — a shipped file missing here fails a gate. */
const ALWAYS_SHIPPED = ['package.json', 'sources/README.md'];

function isDerivable(rel) {
  return DERIVABLE_PREFIXES.some((p) => rel === p.replace(/\/$/, '') || rel.startsWith(p));
}

function expandAllowlist(allowlist) {
  const abs = [];
  for (const entry of [...allowlist, ...ALWAYS_SHIPPED]) {
    const full = path.join(REPO_ROOT, entry);
    if (!fs.existsSync(full)) continue; // tolerate a stale entry; predeploy gate flags
    const stat = fs.statSync(full);
    if (stat.isDirectory()) {
      abs.push(...walkFiles(full));
    } else if (stat.isFile()) {
      abs.push(full);
    }
  }
  // Deduped and sorted by POSIX-relative path, so the SHA-256 input is the same
  // on every operating system. npm's pack rules are matched only as far as this
  // SBOM needs; verify-shipped-tarball is the authoritative check.
  const rel = Array.from(new Set(abs.map((a) => toPosixRel(a))))
    .filter((r) => !SELF_EXCLUDED.has(r))
    .filter((r) => !isDerivable(r))
    .sort();
  return rel;
}

/* metadata.timestamp — the release date this version's CHANGELOG heading
 * declares, as an ISO-8601 instant. It must be deterministic for the currency
 * gate's regenerate-and-compare, and true because consumers age-check on it, so
 * a missing heading throws rather than synthesizing a value.
 * scripts/check-changelog-extract.js enforces the heading format. */
function releaseTimestamp(version) {
  const changelogPath = path.join(REPO_ROOT, 'CHANGELOG.md');
  const text = fs.readFileSync(changelogPath, 'utf8');
  const escaped = version.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const m = text.match(new RegExp('^## ' + escaped + ' [—-] (\\d{4}-\\d{2}-\\d{2})\\s*$', 'm'));
  if (!m) {
    throw new Error(
      `refresh-sbom: CHANGELOG.md has no dated heading for ${version}. ` +
      `Add "## ${version} — YYYY-MM-DD" before regenerating — metadata.timestamp ` +
      `is the release date, and there is no honest value to fall back to.`,
    );
  }
  return `${m[1]}T00:00:00.000Z`;
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

// SHA3-512 sits alongside SHA-256 on every file component: a different
// construction to fall back on. check-sbom-currency.js verifies both, so
// dropping the SHA3-512 entry reads as a missing-hash error, not acceptance.
function sha3_512File(absPath) {
  return crypto
    .createHash('sha3-512')
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
      hashes: [
        { alg: 'SHA-256', content: sha256File(abs) },
        { alg: 'SHA3-512', content: sha3_512File(abs) },
      ],
    });
  }
  return out;
}

/* SHA-256 over a "<sha256>\t<relpath>\n" stream of every shipped file, sorted by
 * relpath — the same input an operator assembles from the `type: file` entries
 * in components[], so the stored digest can be recomputed rather than trusted. */
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
  const catalogs = listDataCatalogs(DATA_DIR);
  const skillCount = Array.isArray(manifest.skills) ? manifest.skills.length : 0;
  const catalogCount = catalogs.length;
  const vendorProv = loadVendorProvenance();
  const vendoredComponents = vendorComponents(vendorProv);
  const fileComps = fileComponents(Array.isArray(pkg.files) ? pkg.files : []);
  const bundleSha = bundleDigest(fileComps);

  // Sorted by bom-ref so regeneration is byte-identical.
  const allComponents = [...vendoredComponents, ...fileComps].sort((a, b) =>
    a['bom-ref'] < b['bom-ref'] ? -1 : a['bom-ref'] > b['bom-ref'] ? 1 : 0,
  );

  // Seeded from the bundle content, not the clock: a no-op refresh is a no-op.
  const seed = `${pkg.name}@${pkg.version}@${bundleSha}`;
  const serialNumber = 'urn:uuid:' + uuidV4FromSeed(seed);
  const timestamp = releaseTimestamp(pkg.version);

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
        'bom-ref': `pkg:npm/${pkg.name}@${pkg.version}`,
        type: 'application',
        name: pkg.name,
        version: pkg.version,
        description: pkg.description,
        licenses: [{ license: { id: 'Apache-2.0' } }],
        purl: `pkg:npm/${pkg.name.replace(/@/g, '%40')}@${pkg.version}`,
        // Recomputable from components[]; bundleDigest above states the input rule.
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
        // An operator verifying the bundle holds the SBOM, not this script: these
        // two properties say the inventory is partial by design, and what covers it.
        {
          name: 'exceptd:integrity:uncovered:prefix',
          value: DERIVABLE_PREFIXES.join(','),
        },
        {
          name: 'exceptd:integrity:uncovered:rationale',
          value:
            'Regenerated by `npm run build-indexes` and mutated by the test suite, so a ' +
            'pinned per-file hash would race any run between generation and verification. ' +
            'Covered instead by the pre-computed-index freshness gate in `npm run predeploy`.',
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

module.exports = {
  buildSbom,
  expandAllowlist,
  bundleDigest,
  releaseTimestamp,
  ALWAYS_SHIPPED,
  DERIVABLE_PREFIXES,
};
