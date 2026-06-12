'use strict';

/**
 * scripts/sync-package-description.js
 *
 * Regenerate the count-bearing tokens embedded in package.json.description from
 * the live catalogs + manifest, so the description stays in sync when an
 * auto-refresh changes an entry count. refresh-sbom copies the description into
 * sbom.cdx.json, and check-sbom-currency validates every token against the live
 * counts — without this sync, the first refresh that changes a count would fail
 * the SBOM description-token gate on the auto-PR.
 *
 * Targeted, format-preserving: replaces only the integer in each known
 * "<N> <label>" token (skills / catalogs / jurisdictions / per-catalog entry
 * counts). Reuses check-sbom-currency's token table so the two can't drift.
 *
 * Run before refresh-sbom in the refresh apply path (and idempotent locally).
 */

const fs = require('fs');
const path = require('path');

const { DESCRIPTION_ENTRY_TOKENS, catalogEntryCount } = require('./check-sbom-currency');

function syncPackageDescription(root = path.join(__dirname, '..')) {
  const pkgPath = path.join(root, 'package.json');
  const dataDir = path.join(root, 'data');
  const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
  const manifest = JSON.parse(fs.readFileSync(path.join(root, 'manifest.json'), 'utf8'));

  const before = pkg.description || '';
  let desc = before;

  const liveSkills = Array.isArray(manifest.skills) ? manifest.skills.length : 0;
  const liveCatalogs = fs.readdirSync(dataDir).filter((f) => f.endsWith('.json')).length;
  let liveJurisdictions = null;
  try {
    const gf = JSON.parse(fs.readFileSync(path.join(dataDir, 'global-frameworks.json'), 'utf8'));
    liveJurisdictions = Object.keys(gf).filter((k) => !k.startsWith('_')).length;
  } catch { /* leave null — skip the jurisdiction token */ }

  // Replace only the integer in "<N> <label>"; `labelRe` is the same (already
  // regex-escaped) pattern check-sbom-currency matches, and $2 preserves the
  // matched label text verbatim.
  const sub = (n, labelRe) => {
    if (n == null) return;
    desc = desc.replace(new RegExp('(\\d+)(\\s+' + labelRe + '\\b)'), String(n) + '$2');
  };

  sub(liveSkills, 'skills');
  sub(liveCatalogs, 'catalogs?');
  sub(liveJurisdictions, 'jurisdictions?');
  for (const { file, label } of DESCRIPTION_ENTRY_TOKENS) {
    sub(catalogEntryCount(dataDir, file), label);
  }

  const changed = desc !== before;
  if (changed) {
    pkg.description = desc;
    fs.writeFileSync(pkgPath, JSON.stringify(pkg, null, 2) + '\n');
  }
  return { changed, description: desc };
}

if (require.main === module) {
  const r = syncPackageDescription();
  process.stdout.write(
    r.changed
      ? `package.json description synced from live counts:\n  ${r.description}\n`
      : 'package.json description already in sync with live counts.\n'
  );
}

module.exports = { syncPackageDescription };
