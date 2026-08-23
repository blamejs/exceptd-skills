"use strict";
/**
 * Canonical resolver for the MITRE ATT&CK / ATLAS version pins. The `_meta`
 * blocks of data/atlas-ttps.json and data/attack-techniques.json are the source
 * of truth and every consumer reads them through here, so a pin bump is a data
 * edit. tests/atlas-version-canonical.test.js and its ATT&CK counterpart
 * compare each operator-facing mention against what this module returns.
 */

const fs = require("fs");
const path = require("path");

const ROOT = path.join(__dirname, "..");

let _cached = null;

function loadPins() {
  if (_cached) return _cached;
  const atlas = JSON.parse(fs.readFileSync(path.join(ROOT, "data", "atlas-ttps.json"), "utf8"));
  const attack = JSON.parse(fs.readFileSync(path.join(ROOT, "data", "attack-techniques.json"), "utf8"));
  const meta = JSON.parse(fs.readFileSync(path.join(ROOT, "manifest.json"), "utf8"));
  _cached = {
    atlas_version: (atlas._meta && atlas._meta.atlas_version) || null,
    atlas_release_date: (atlas._meta && atlas._meta.atlas_release_date) || null,
    attack_version: (attack._meta && attack._meta.attack_version) || null,
    attack_version_date: (attack._meta && attack._meta.attack_version_date) || null,
    manifest_atlas_version: meta.atlas_version || null,
    manifest_attack_version: meta.attack_version || null
  };
  return _cached;
}

function clearCache() { _cached = null; }
function getAtlasVersion() { return loadPins().atlas_version; }
function getAtlasReleaseDate() { return loadPins().atlas_release_date; }
function getAttackVersion() { return loadPins().attack_version; }
function getAttackVersionDate() { return loadPins().attack_version_date; }
function getAllPins() { return { ...loadPins() }; }

module.exports = {
  getAtlasVersion, getAtlasReleaseDate,
  getAttackVersion, getAttackVersionDate,
  getAllPins, clearCache
};
