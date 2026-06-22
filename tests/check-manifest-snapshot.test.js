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

test("diff: ATLAS version change is breaking per AGENTS.md Hard Rule #12", () => {
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


// ---- routed from check-manifest-snapshot-sidecar ----
require("node:test").describe("check-manifest-snapshot-sidecar", () => {
const __t = require("node:test"); const __env = Object.assign({}, process.env);
__t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __env)) delete process.env[k]; Object.assign(process.env, __env);
  const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
/**
 * Regression for the manifest-snapshot integrity sidecar.
 *
 * The sha256 sidecar (manifest-snapshot.sha256) is the only thing that
 * catches a hand-edit of manifest-snapshot.json that bypassed
 * refresh-manifest-snapshot.js — e.g. a lockstep edit of manifest.json +
 * the baseline to hide a removed skill/trigger from the surface diff.
 * Deleting the sidecar must NOT downgrade that hard failure to a silent
 * warn-and-continue: the snapshot and its sidecar ship as a pair
 * (package.json `files`) and refresh always writes both, so a present
 * snapshot WITHOUT its sidecar is the integrity-evasion shape, not a
 * benign legacy state.
 *
 * Asserts EXACT outcomes (ok boolean + subprocess exit code), not just
 * "non-zero" — a coincidence-passing test is worse than none.
 *
 * Shadow-tree pattern: copy snapshot + sidecar + script into a tempdir,
 * mutate, run the exported function and the real CLI subprocess.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const crypto = require('node:crypto');
const { spawnSync } = require('node:child_process');

const ROOT = path.join(__dirname, '..');
const SCRIPT = path.join(ROOT, 'scripts', 'check-manifest-snapshot.js');
const { checkSnapshotIntegrity } = require(SCRIPT);

const SNAPSHOT = path.join(ROOT, 'manifest-snapshot.json');

// Build a minimal shadow tree containing only what the integrity check
// needs: <tmp>/manifest-snapshot.json (+ optional sidecar). The exported
// checkSnapshotIntegrity(root) reads relative to the passed root, so we
// never touch the real working tree.
function shadow({ withSidecar }) {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'snap-sidecar-'));
  const snapBytes = fs.readFileSync(SNAPSHOT);
  fs.writeFileSync(path.join(tmp, 'manifest-snapshot.json'), snapBytes);
  if (withSidecar) {
    const sha = crypto.createHash('sha256').update(snapBytes).digest('hex');
    fs.writeFileSync(
      path.join(tmp, 'manifest-snapshot.sha256'),
      sha + '  manifest-snapshot.json\n'
    );
  }
  return tmp;
}

test('checkSnapshotIntegrity: snapshot present + matching sidecar => ok', () => {
  const tmp = shadow({ withSidecar: true });
  try {
    const r = checkSnapshotIntegrity(tmp);
    assert.equal(r.ok, true, 'matching snapshot+sidecar must pass');
    assert.equal(r.error, null);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test('checkSnapshotIntegrity: snapshot present + sidecar ABSENT => FAIL (not skip)', () => {
  const tmp = shadow({ withSidecar: false });
  try {
    const r = checkSnapshotIntegrity(tmp);
    assert.equal(r.ok, false, 'a missing sidecar next to a present snapshot must fail');
    assert.match(
      r.error,
      /manifest-snapshot\.sha256 missing/,
      `error must name the missing sidecar; got ${JSON.stringify(r.error)}`
    );
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test('checkSnapshotIntegrity: snapshot present + tampered sidecar => FAIL', () => {
  const tmp = shadow({ withSidecar: true });
  try {
    // Corrupt the recorded hash so it no longer matches the snapshot bytes.
    fs.writeFileSync(
      path.join(tmp, 'manifest-snapshot.sha256'),
      'deadbeef'.repeat(8) + '  manifest-snapshot.json\n'
    );
    const r = checkSnapshotIntegrity(tmp);
    assert.equal(r.ok, false, 'a hash mismatch must fail');
    assert.match(r.error, /integrity check FAILED/);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test('checkSnapshotIntegrity: no snapshot at all => ok (baseline-read handles it)', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'snap-none-'));
  try {
    const r = checkSnapshotIntegrity(tmp);
    assert.equal(r.ok, true, 'no snapshot => integrity check has nothing to anchor; ok');
    assert.equal(r.error, null);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

// End-to-end through the real CLI: the surface-narrowing bypass must not
// pass with the sidecar deleted. Build a full shadow (script + snapshot,
// no sidecar) and assert the process exits 1 — the EXACT blocking code.
test('CLI: snapshot present + sidecar absent exits 1 (surface-narrowing bypass blocked)', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'snap-cli-'));
  try {
    fs.mkdirSync(path.join(tmp, 'scripts'), { recursive: true });
    fs.copyFileSync(SCRIPT, path.join(tmp, 'scripts', 'check-manifest-snapshot.js'));
    // manifest.json + snapshot kept in lockstep so the surface diff is
    // clean; only the sidecar is missing. Pre-fix this printed
    // "surface unchanged" and exited 0.
    fs.copyFileSync(path.join(ROOT, 'manifest.json'), path.join(tmp, 'manifest.json'));
    fs.copyFileSync(SNAPSHOT, path.join(tmp, 'manifest-snapshot.json'));
    // deliberately NOT copying manifest-snapshot.sha256

    const r = spawnSync(process.execPath, [path.join(tmp, 'scripts', 'check-manifest-snapshot.js')], {
      encoding: 'utf8',
    });
    assert.equal(r.status, 1, `expected exit 1; got ${r.status}\nstdout=${r.stdout}\nstderr=${r.stderr}`);
    assert.match(
      r.stderr,
      /manifest-snapshot\.sha256 missing/,
      'must explain the missing sidecar on stderr'
    );
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});
});
