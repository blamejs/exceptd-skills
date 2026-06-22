'use strict';

/**
 * Subject coverage for lib/flag-suggest.js — the per-verb flag allowlist
 * (flagsFor) and the typo-suggestion resolver (suggestFlag).
 */

const test = require('node:test');
const assert = require('node:assert/strict');

test.describe("cli-surface-drift", () => {
  const { flagsFor, suggestFlag } = require("../lib/flag-suggest.js");

  test("flagsFor('run') includes --directive/--explain/--signal-list and typos resolve", () => {
    const flags = flagsFor("run");
    for (const f of ["directive", "explain", "signal-list"]) {
      assert.ok(flags.includes(f), `run must accept --${f}`);
    }
    assert.equal(suggestFlag("explan", flags), "explain", "a --explain typo must resolve");
    assert.equal(suggestFlag("directiv", flags), "directive", "a --directive typo must resolve");
  });
});
