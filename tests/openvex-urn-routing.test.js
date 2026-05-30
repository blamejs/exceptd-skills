'use strict';

/**
 * OpenVEX vulnerability identifiers route to the correct URN namespace.
 *
 * Cycle 6 P1 gap: lib/playbook-runner.js vulnIdToUrn() (line ~1797) maps:
 *   CVE-*      → urn:cve:*
 *   GHSA-*     → urn:ghsa:*
 *   RUSTSEC-*  → urn:rustsec:*
 *   MAL-*      → urn:malicious-package:*
 *   <other>    → urn:exceptd:advisory:* (private namespace, RFC 8141)
 *
 * The OpenVEX 0.2.0 spec mandates that `vulnerability.@id` is an IRI; a
 * naive `urn:cve:GHSA-xxx` would falsely claim GHSA-* is part of the CVE
 * registry, misrouting downstream consumers' lookups. This test pins each
 * advisory prefix to its required namespace AND asserts non-CVE ids never
 * leak into the cve namespace.
 *
 * Tests vulnIdToUrn directly rather than spinning a full OpenVEX bundle —
 * the function is the canonical routing primitive, and a unit test pins
 * the boundary without depending on the full close-phase bundle build.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');

const { ROOT } = require('./_helpers/cli');
const runner = require(path.join(ROOT, 'lib', 'playbook-runner.js'));

// The function is internal to the runner module, exported under the `_`-prefix
// convention the module uses for test-only helpers. Pin its presence so this
// non-CVE-leak boundary can never go dark again (it previously skipped
// permanently because the export was missing).
const vulnIdToUrn = runner._vulnIdToUrn;
assert.equal(typeof vulnIdToUrn, 'function', 'runner must export _vulnIdToUrn');

test('vulnIdToUrn routes each advisory prefix to its registered URN namespace',
  () => {
    const cases = [
      { id: 'GHSA-1111-2222-3333', expectedPrefix: 'urn:ghsa:' },
      { id: 'RUSTSEC-2024-0001',   expectedPrefix: 'urn:rustsec:' },
      { id: 'MAL-2026-3083',       expectedPrefix: 'urn:malicious-package:' },
      { id: 'CVE-2026-46300',      expectedPrefix: 'urn:cve:' },
    ];
    for (const c of cases) {
      const urn = vulnIdToUrn(c.id);
      assert.equal(typeof urn, 'string', `vulnIdToUrn(${c.id}) must return a string`);
      assert.ok(urn.startsWith(c.expectedPrefix),
        `vulnIdToUrn(${c.id}) must start with ${c.expectedPrefix}; got ${urn}`);
    }

    // Cross-check: non-CVE ids MUST NOT be routed into the cve namespace.
    // A regression that collapsed every advisory to urn:cve:* would silently
    // pass single-prefix assertions; this assertion catches that class.
    const nonCveCases = ['GHSA-1111-2222-3333', 'RUSTSEC-2024-0001', 'MAL-2026-3083'];
    for (const id of nonCveCases) {
      const urn = vulnIdToUrn(id);
      assert.ok(!urn.startsWith('urn:cve:'),
        `non-CVE id ${id} must NEVER route into urn:cve: (would misclaim CVE-registry membership); got ${urn}`);
    }
  });

test('vulnIdToUrn falls back to private namespace for unknown prefixes',
  () => {
    const urn = vulnIdToUrn('UNKNOWN-2026-0001');
    assert.equal(typeof urn, 'string');
    assert.ok(urn.startsWith('urn:exceptd:advisory:'),
      `unknown prefix must route to private urn:exceptd:advisory: namespace; got ${urn}`);
  });
