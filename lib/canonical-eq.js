"use strict";
/**
 * lib/canonical-eq.js
 *
 * Canonical-form deep equality for catalog diff detection. The diff-
 * coverage gate previously compared `JSON.stringify(before.iocs)` vs
 * `JSON.stringify(after.iocs)` which is non-canonical: key order,
 * trailing whitespace, and numeric format differences all register as
 * "different" when the operator made no semantic change.
 *
 * Pre-v0.13.20 history: the symptom was patched twice with skip rules
 * (v0.13.17 _auto_imported skip; v0.13.19 _iocs_stub skip). v0.13.20
 * fixes the root cause — canonical recursive equality with sorted-key
 * object comparison and array-position-sensitive element comparison.
 *
 * Contract:
 *   - Primitives (string / number / boolean / null / undefined) compare
 *     by strict equality (===).
 *   - Arrays compare element-by-element in order. [1,2] !== [2,1].
 *     This matches operator intent — array order in IoCs / attack_refs
 *     / cwe_refs is meaningful (most-relevant-first convention).
 *   - Objects compare by key-set equality + per-key recursive equality.
 *     Key order does NOT matter; { a:1, b:2 } === { b:2, a:1 }.
 *   - Cycle protection: WeakSet of visited pairs prevents infinite
 *     recursion on self-referential structures. Cycles compare unequal
 *     across mismatched topologies; equal across identical topologies.
 *   - NaN: NaN === NaN under this comparator (deviates from Object.is
 *     to make the comparator total — useful for catalog data which
 *     never legitimately contains NaN but might pick one up from a
 *     buggy upstream).
 *
 * Helpers:
 *   - canonicalEqual(a, b): full recursive equality.
 *   - canonicalStringify(v): sorted-key JSON for hashing / display.
 *     Produces stable output suitable for SHA-256 etc.
 */

function canonicalEqual(a, b, seen = new WeakMap()) {
  if (a === b) return true;
  // NaN === NaN under this comparator.
  if (typeof a === "number" && typeof b === "number" && Number.isNaN(a) && Number.isNaN(b)) return true;
  if (a === null || b === null) return a === b;
  if (typeof a !== "object" || typeof b !== "object") return false;

  // Cycle detection — if we've already compared this exact pair, treat
  // as equal (assumes the rest of the structure decides). For sibling-
  // cycle differences this means the comparator says "equal at the
  // cycle point" and lets non-cyclic differences elsewhere decide.
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

  // Plain objects — compare key sets + per-key recursive equality.
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

// Sorted-key recursive JSON. Stable output for hash digests, diff
// comparison, and human-readable display.
function canonicalStringify(v) {
  if (v === null || typeof v !== "object") return JSON.stringify(v);
  if (Array.isArray(v)) return "[" + v.map(canonicalStringify).join(",") + "]";
  const keys = Object.keys(v).sort();
  return "{" + keys.map((k) => JSON.stringify(k) + ":" + canonicalStringify(v[k])).join(",") + "}";
}

module.exports = { canonicalEqual, canonicalStringify };
