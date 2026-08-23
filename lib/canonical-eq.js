"use strict";
/**
 * Canonical-form deep equality for catalog diff detection.
 *
 * Arrays compare element-by-element in order — [1,2] !== [2,1], since position
 * in iocs / attack_refs / cwe_refs carries meaning. Objects compare by key set
 * and per-key value, so key order is irrelevant. NaN equals NaN, which makes
 * the comparator total. A pair already under comparison compares equal, so a
 * cycle leaves the verdict to the non-cyclic structure around it.
 */

function canonicalEqual(a, b, seen = new WeakMap()) {
  if (a === b) return true;
  if (typeof a === "number" && typeof b === "number" && Number.isNaN(a) && Number.isNaN(b)) return true;
  if (a === null || b === null) return a === b;
  if (typeof a !== "object" || typeof b !== "object") return false;

  const aSeen = seen.get(a);
  if (aSeen && aSeen.has(b)) return true;
  if (!aSeen) seen.set(a, new WeakSet([b]));
  else aSeen.add(b);

  const aIsArr = Array.isArray(a);
  const bIsArr = Array.isArray(b);
  if (aIsArr !== bIsArr) return false;

  if (aIsArr) {
    if (a.length !== b.length) return false;
    for (let i = 0; i < a.length; i++) {
      if (!canonicalEqual(a[i], b[i], seen)) return false;
    }
    return true;
  }

  const aKeys = Object.keys(a).sort();
  const bKeys = Object.keys(b).sort();
  if (aKeys.length !== bKeys.length) return false;
  for (let i = 0; i < aKeys.length; i++) {
    if (aKeys[i] !== bKeys[i]) return false;
  }
  for (const k of aKeys) {
    if (!canonicalEqual(a[k], b[k], seen)) return false;
  }
  return true;
}

// Sorted-key recursive JSON — stable bytes for hash digests and diffing.
function canonicalStringify(v) {
  if (v === null || typeof v !== "object") return JSON.stringify(v);
  if (Array.isArray(v)) return "[" + v.map(canonicalStringify).join(",") + "]";
  const keys = Object.keys(v).sort();
  return "{" + keys.map((k) => JSON.stringify(k) + ":" + canonicalStringify(v[k])).join(",") + "}";
}

module.exports = { canonicalEqual, canonicalStringify };
