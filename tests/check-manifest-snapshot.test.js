"use strict";
/**
 * Unit tests for the manifest snapshot gate's diff logic. The gate is
 * the only CI line of defense against silently narrowing the public
 * skill surface (removed skill, removed trigger keyword, removed data
 * dep). If this test set drifts, contributors can land surface-
 * narrowing changes without triggering the breaking-change branch.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");

const { captureSurface, diff } = require(
  path.join(__dirname, "..", "scripts", "check-manifest-snapshot.js")
);

function skill(overrides = {}) {
  return {
    name: "test-skill",
    version: "1.0.0",
    triggers: ["trigger-a", "trigger-b"],
    data_deps: ["cve-catalog.json"],
    atlas_refs: ["AML.T0001"],
    attack_refs: ["T1000"],
    framework_gaps: ["NIST-800-53-AC-1"],
    ...overrides,
  };
}

function manifest(skills, opts = {}) {
  return {
    name: "exceptd-security",
    version: "0.1.0",
    atlas_version: opts.atlas_version || "5.1.0",
    skills,
  };
}

test("captureSurface produces sorted, normalized output", () => {
  const m = manifest([
    skill({ name: "beta", triggers: ["z", "a"] }),
    skill({ name: "alpha", triggers: ["c", "b"] }),
  ]);
  const surface = captureSurface(m);

  assert.equal(surface.skill_count, 2);
  assert.equal(surface.atlas_version, "5.1.0");
  assert.deepEqual(
    surface.skills.map((s) => s.name),
    ["alpha", "beta"],
    "skills sorted by name"
  );
  assert.deepEqual(surface.skills[0].triggers, ["b", "c"], "triggers sorted");
  assert.deepEqual(surface.skills[1].triggers, ["a", "z"], "triggers sorted");
});

test("captureSurface excludes signature/signed_at/sha256 fields", () => {
  const m = manifest([
    skill({
      name: "alpha",
      signature: "BASE64=",
      signed_at: "2026-01-01T00:00:00Z",
      sha256: "abc",
    }),
  ]);
  const surface = captureSurface(m);
  const s = surface.skills[0];
  assert.ok(!("signature" in s), "signature not part of public surface");
  assert.ok(!("signed_at" in s), "signed_at not part of public surface");
  assert.ok(!("sha256" in s), "sha256 not part of public surface");
});

test("diff: identical surfaces produce no breaking and no additive entries", () => {
  const a = captureSurface(manifest([skill()]));
  const b = captureSurface(manifest([skill()]));
  const result = diff(a, b);
  assert.equal(result.breaking.length, 0);
  assert.equal(result.additive.length, 0);
});

test("diff: removed skill is breaking", () => {
  const baseline = captureSurface(
    manifest([skill({ name: "alpha" }), skill({ name: "beta" })])
  );
  const current = captureSurface(manifest([skill({ name: "alpha" })]));
  const result = diff(baseline, current);
  assert.equal(result.breaking.length, 1);
  assert.match(result.breaking[0], /removed skill: beta/);
});

test("diff: added skill is additive only", () => {
  const baseline = captureSurface(manifest([skill({ name: "alpha" })]));
  const current = captureSurface(
    manifest([skill({ name: "alpha" }), skill({ name: "beta" })])
  );
  const result = diff(baseline, current);
  assert.equal(result.breaking.length, 0);
  assert.equal(result.additive.length, 1);
  assert.match(result.additive[0], /added skill: beta/);
});

test("diff: removed trigger keyword is breaking", () => {
  const baseline = captureSurface(
    manifest([skill({ triggers: ["foo", "bar"] })])
  );
  const current = captureSurface(manifest([skill({ triggers: ["foo"] })]));
  const result = diff(baseline, current);
  assert.equal(result.breaking.length, 1);
  assert.match(result.breaking[0], /removed trigger keywords: bar/);
});

test("diff: added trigger keyword is additive only", () => {
  const baseline = captureSurface(manifest([skill({ triggers: ["foo"] })]));
  const current = captureSurface(
    manifest([skill({ triggers: ["foo", "bar"] })])
  );
  const result = diff(baseline, current);
  assert.equal(result.breaking.length, 0);
  assert.match(result.additive[0], /added trigger keywords: bar/);
});

test("diff: removed data_dep is breaking", () => {
  const baseline = captureSurface(
    manifest([skill({ data_deps: ["cve-catalog.json", "atlas-ttps.json"] })])
  );
  const current = captureSurface(
    manifest([skill({ data_deps: ["cve-catalog.json"] })])
  );
  const result = diff(baseline, current);
  assert.match(result.breaking[0], /removed data deps: atlas-ttps\.json/);
});

test("diff: version downgrade is breaking", () => {
  const baseline = captureSurface(manifest([skill({ version: "1.2.0" })]));
  const current = captureSurface(manifest([skill({ version: "1.1.0" })]));
  const result = diff(baseline, current);
  assert.match(result.breaking[0], /version downgraded 1\.2\.0 -> 1\.1\.0/);
});

test("diff: version bump is additive only", () => {
  const baseline = captureSurface(manifest([skill({ version: "1.0.0" })]));
  const current = captureSurface(manifest([skill({ version: "1.1.0" })]));
  const result = diff(baseline, current);
  assert.equal(result.breaking.length, 0);
  assert.match(result.additive[0], /version bumped 1\.0\.0 -> 1\.1\.0/);
});

test("diff: ATLAS version change is breaking per CLAUDE.md rule #12", () => {
  const baseline = captureSurface(manifest([skill()], { atlas_version: "5.1.0" }));
  const current = captureSurface(manifest([skill()], { atlas_version: "5.2.0" }));
  const result = diff(baseline, current);
  assert.ok(
    result.breaking.some((b) => /atlas_version changed 5\.1\.0 -> 5\.2\.0/.test(b)),
    "ATLAS version change must surface as breaking"
  );
});

test("diff: removed ATLAS/ATT&CK/framework refs are breaking", () => {
  const baseline = captureSurface(
    manifest([
      skill({
        atlas_refs: ["AML.T0001", "AML.T0002"],
        attack_refs: ["T1000", "T1001"],
        framework_gaps: ["NIST-800-53-AC-1", "ISO-27001-2022-A.8.1"],
      }),
    ])
  );
  const current = captureSurface(
    manifest([
      skill({
        atlas_refs: ["AML.T0001"],
        attack_refs: ["T1000"],
        framework_gaps: ["NIST-800-53-AC-1"],
      }),
    ])
  );
  const result = diff(baseline, current);
  assert.ok(result.breaking.some((b) => /removed atlas_refs: AML\.T0002/.test(b)));
  assert.ok(result.breaking.some((b) => /removed attack_refs: T1001/.test(b)));
  assert.ok(
    result.breaking.some((b) =>
      /removed framework_gaps: ISO-27001-2022-A\.8\.1/.test(b)
    )
  );
});
