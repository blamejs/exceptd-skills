#!/usr/bin/env node
"use strict";

/**
 * scripts/check-ttp-upstream.js — validates every shipped TTP id against the
 * pinned upstream release.
 *
 * Why this exists. The catalogs in data/attack-techniques.json and
 * data/atlas-ttps.json are curated mirrors of MITRE releases, and nothing
 * checked that the ids in them are ids MITRE actually publishes. The ATLAS
 * 2026.07 / ATT&CK 19.2 pin bump found eleven that were not: five ATT&CK
 * techniques revoked upstream — already revoked in 19.1, the version pinned at
 * the time, so they had been shipping revoked for a full release cycle — and
 * six that appear in no upstream domain at any version. Every one of them was
 * reachable by a skill telling an operator to map a finding to it, which is
 * exactly what Hard Rule #4 (no orphaned controls — every control maps to a
 * real TTP) exists to prevent.
 *
 * This is a NETWORK check, so it runs in the refresh workflow beside the pin
 * checker rather than in predeploy, which is offline. Report-only: it prints
 * findings and exits non-zero, leaving the decision to a maintainer, because a
 * revocation needs a judgement call about the successor rather than an
 * automatic rewrite.
 *
 *   node scripts/check-ttp-upstream.js            validate against the pins
 *   node scripts/check-ttp-upstream.js --json     machine-readable output
 *
 * Exit: 0 clean, 1 findings, 2 upstream unreachable (never a silent pass —
 * an unreachable upstream must not read as "all ids valid").
 */

const fs = require("node:fs");
const path = require("node:path");

const ROOT = path.resolve(__dirname, "..");
const UA = "exceptd-ttp-validator (+https://exceptd.com)";
const ATTACK_DOMAINS = ["enterprise-attack", "ics-attack", "mobile-attack"];

function readJson(p) {
  return JSON.parse(fs.readFileSync(path.join(ROOT, p), "utf8"));
}

/**
 * A pinned version read out of a catalog is file data, and it is about to be
 * interpolated into an upstream URL. Constrain it to the exact shape each
 * project publishes before it can reach a request, so a malformed or tampered
 * `_meta` cannot steer the fetch — and so a typo'd pin fails here with a clear
 * message instead of as a puzzling 404 later.
 *
 *   ATT&CK  semver-ish major.minor           19.2
 *   ATLAS   CalVer YYYY.MM with optional .N  2026.07, 2025.11.2
 */
const VERSION_SHAPES = {
  attack: /^\d{1,3}\.\d{1,3}$/,
  atlas: /^\d{4}\.\d{2}(\.\d{1,2})?$/,
};

function assertPinShape(kind, value) {
  if (typeof value !== "string" || !VERSION_SHAPES[kind].test(value)) {
    throw new Error(
      `${kind} pin ${JSON.stringify(value)} does not match ${VERSION_SHAPES[kind]} — ` +
        `refusing to build an upstream URL from it`
    );
  }
  return value;
}

async function fetchJson(url) {
  const res = await fetch(url, { headers: { "user-agent": UA } });
  if (!res.ok) throw new Error(`${res.status} ${url}`);
  return JSON.parse(await res.text());
}

async function fetchText(url) {
  const res = await fetch(url, { headers: { "user-agent": UA } });
  if (!res.ok) throw new Error(`${res.status} ${url}`);
  return res.text();
}

/** Every ATT&CK technique id in the pinned release, with its revocation state. */
async function liveAttack(rawVersion) {
  const version = encodeURIComponent(assertPinShape("attack", rawVersion));
  const out = new Map();
  for (const dom of ATTACK_DOMAINS) {
    const j = await fetchJson(
      `https://raw.githubusercontent.com/mitre-attack/attack-stix-data/v${version}/${dom}/${dom}.json`
    );
    const byId = new Map(j.objects.map((o) => [o.id, o]));
    for (const o of j.objects) {
      if (o.type !== "attack-pattern") continue;
      const ext = (o.external_references || []).find(
        (r) => r.source_name && r.source_name.includes("attack")
      );
      if (!ext || !ext.external_id) continue;
      let supersededBy = null;
      if (o.revoked) {
        const rel = j.objects.find(
          (r) => r.type === "relationship" && r.relationship_type === "revoked-by" && r.source_ref === o.id
        );
        const tgt = rel && byId.get(rel.target_ref);
        const te = tgt && (tgt.external_references || []).find(
          (r) => r.source_name && r.source_name.includes("attack")
        );
        supersededBy = te ? te.external_id : null;
      }
      out.set(ext.external_id, {
        revoked: !!o.revoked,
        deprecated: !!o.x_mitre_deprecated,
        supersededBy,
        name: o.name,
      });
    }
  }
  return out;
}

/** Every ATLAS id in the pinned content release. */
async function liveAtlas(rawVersion) {
  const version = encodeURIComponent(assertPinShape("atlas", rawVersion));
  const yaml = await fetchText(
    `https://raw.githubusercontent.com/mitre-atlas/atlas-data/v${version}/dist/v6/ATLAS-${version}.yaml`
  );
  // The dist bundle is a mapping keyed by id, each block repeating `id:`.
  return new Set(
    (yaml.match(/^\s*id:\s*(AML\.[A-Za-z]+[0-9.]*)\s*$/gm) || []).map((l) =>
      l.replace(/.*id:\s*/, "").trim()
    )
  );
}

async function main() {
  const asJson = process.argv.includes("--json");
  const attackCat = readJson("data/attack-techniques.json");
  const atlasCat = readJson("data/atlas-ttps.json");
  const attackVersion = attackCat._meta.attack_version;
  const atlasVersion = atlasCat._meta.atlas_version;

  let attack;
  let atlas;
  try {
    [attack, atlas] = await Promise.all([liveAttack(attackVersion), liveAtlas(atlasVersion)]);
  } catch (err) {
    process.stderr.write(
      `[check-ttp-upstream] UNREACHABLE — could not fetch upstream (${err.message}). ` +
        `Not treating this as a pass: an unreachable upstream proves nothing about the shipped ids.\n`
    );
    process.exitCode = 2;
    return;
  }

  if (attack.size === 0 || atlas.size === 0) {
    process.stderr.write("[check-ttp-upstream] UNREACHABLE — upstream returned an empty id set.\n");
    process.exitCode = 2;
    return;
  }

  const findings = [];
  for (const id of Object.keys(attackCat)) {
    if (id === "_meta") continue;
    const live = attack.get(id);
    if (!live) {
      findings.push({ catalog: "attack", id, issue: "absent-upstream", detail: `not published in ATT&CK v${attackVersion} in any domain` });
    } else if (live.revoked) {
      findings.push({ catalog: "attack", id, issue: "revoked", detail: `revoked upstream${live.supersededBy ? ` — superseded by ${live.supersededBy}` : ""}` });
    } else if (live.deprecated) {
      findings.push({ catalog: "attack", id, issue: "deprecated", detail: "deprecated upstream" });
    }
  }
  for (const id of Object.keys(atlasCat)) {
    if (id === "_meta") continue;
    if (!atlas.has(id)) {
      findings.push({ catalog: "atlas", id, issue: "absent-upstream", detail: `not published in ATLAS v${atlasVersion}` });
    }
  }

  if (asJson) {
    process.stdout.write(JSON.stringify({ attackVersion, atlasVersion, findings }, null, 2) + "\n");
  } else {
    process.stdout.write(
      `[check-ttp-upstream] ATT&CK v${attackVersion} (${attack.size} live ids) · ATLAS v${atlasVersion} (${atlas.size} live ids)\n`
    );
    if (findings.length === 0) {
      process.stdout.write("[check-ttp-upstream] ok — every shipped TTP id exists upstream and is neither revoked nor deprecated.\n");
    } else {
      for (const f of findings) {
        process.stdout.write(`  ✗ ${f.catalog} ${f.id}: ${f.detail}\n`);
      }
      process.stdout.write(
        `[check-ttp-upstream] ${findings.length} finding(s). A revocation needs a maintainer decision on the ` +
          `successor — remap the id and carry its cve_refs across rather than deleting the entry.\n`
      );
    }
  }
  process.exitCode = findings.length ? 1 : 0;
}

if (require.main === module) main().catch((err) => {
  process.stderr.write(`[check-ttp-upstream] ERROR ${err && err.stack ? err.stack : err}\n`);
  process.exitCode = 2;
});

module.exports = { VERSION_SHAPES, assertPinShape };
