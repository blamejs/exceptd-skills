'use strict';

/**
 * tests/zeroday-lessons.test.js
 *
 * Data-coherence pins for data/zeroday-lessons.json: the node-ipc
 * maintainer-domain-expiry lesson with its headline novel control
 * NEW-CTRL-047, and the absence of orphan entries for the deleted draft
 * CVEs.
 *
 * Per the anti-coincidence rule, every assertion checks an EXACT value —
 * never `assert.ok` on a field-presence check alone. Field-presence
 * assertions are paired with content-shape assertions.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');
const lessons = JSON.parse(
  fs.readFileSync(path.join(ROOT, 'data', 'zeroday-lessons.json'), 'utf8'),
);

const ENTRY_ID = 'MAL-2026-NODE-IPC-STEALER';

test(`${ENTRY_ID} zeroday-lessons entry exists with headline NEW-CTRL-047`, () => {
  const lesson = lessons[ENTRY_ID];
  assert.ok(lesson, `${ENTRY_ID} must be present in zeroday-lessons.json`);

  // Top-level shape mirrors CVE-2026-31431 / MAL-2026-TANSTACK-MINI.
  assert.equal(typeof lesson.name, 'string');
  assert.equal(lesson.name.length >= 1, true);
  assert.equal(typeof lesson.lesson_date, 'string');
  assert.equal(typeof lesson.attack_vector, 'object');
  assert.equal(lesson.attack_vector !== null, true);
  assert.equal(typeof lesson.defense_chain, 'object');
  assert.equal(typeof lesson.framework_coverage, 'object');
  assert.equal(Array.isArray(lesson.new_control_requirements), true);
  assert.equal(typeof lesson.compliance_exposure_score, 'object');
  assert.equal(lesson.ai_discovered_zeroday, false);
  assert.equal(lesson.ai_assist_factor, 'low');

  // Headline novel control: NEW-CTRL-047 PACKAGE-MAINTAINER-DOMAIN-
  // EXPIRY-MONITORING — exact id + name pin so a re-numbering or rename
  // surfaces here rather than silently in framework-gap output.
  const headline = lesson.new_control_requirements.find(
    (c) => c.id === 'NEW-CTRL-047',
  );
  assert.ok(
    headline,
    `${ENTRY_ID} lesson must declare NEW-CTRL-047 as a new_control_requirement`,
  );
  assert.equal(headline.name, 'PACKAGE-MAINTAINER-DOMAIN-EXPIRY-MONITORING');
  assert.equal(typeof headline.description, 'string');
  assert.equal(
    headline.description.length >= 50,
    true,
    'NEW-CTRL-047 description must be a substantive paragraph (>= 50 chars)',
  );
  assert.equal(typeof headline.evidence, 'string');
  assert.equal(Array.isArray(headline.gap_closes), true);
  assert.equal(
    headline.gap_closes.length >= 1,
    true,
    'NEW-CTRL-047 must close at least 1 framework gap',
  );

  // Secondary controls (NEW-CTRL-048 NPM-MAINTAINER-MFA-ENFORCEMENT,
  // NEW-CTRL-049 LOCKFILE-INTEGRITY-VERIFIED-AT-CI-BOOT) also pinned by
  // exact id+name so the control surface is recoverable from this test
  // alone.
  const mfa = lesson.new_control_requirements.find((c) => c.id === 'NEW-CTRL-048');
  assert.ok(mfa, 'NEW-CTRL-048 NPM-MAINTAINER-MFA-ENFORCEMENT must be present');
  assert.equal(mfa.name, 'NPM-MAINTAINER-MFA-ENFORCEMENT');
  const lockfile = lesson.new_control_requirements.find((c) => c.id === 'NEW-CTRL-049');
  assert.ok(lockfile, 'NEW-CTRL-049 LOCKFILE-INTEGRITY-VERIFIED-AT-CI-BOOT must be present');
  assert.equal(lockfile.name, 'LOCKFILE-INTEGRITY-VERIFIED-AT-CI-BOOT');
});

test('zeroday-lessons.json carries no orphan entries for the deleted CVEs', () => {
  const l = JSON.parse(fs.readFileSync(path.join(ROOT, 'data', 'zeroday-lessons.json'), 'utf8'));
  assert.ok(!('MAL-2026-ANTHROPIC-MCP-STDIO' in l));
  assert.ok(!('CVE-2026-GTIG-AI-2FA' in l));
});


// ---- routed from v0_13_4-fixes ----
require("node:test").describe("v0_13_4-fixes", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
/**
 * tests/v0_13_4-fixes.test.js
 *
 * Pin tests for the v0.13.4 patch.
 *
 * Coverage:
 *   A — _meta.fed_by is now schema-accepted (drives the 20 cosmetic
 *       validate-playbooks warnings to 0).
 *   C — README + AGENTS surface the v0.13.x operator-facing features.
 *   E — 2 stuck-draft CVEs (MAL-2026-ANTHROPIC-MCP-STDIO + CVE-2026-GTIG-AI-2FA)
 *       are deleted from the catalog and from any cross-referencing data file.
 *   (B and D pin coverage is in their dedicated test files; this file
 *    covers the items that don't have a natural dedicated home.)
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const ROOT = path.join(__dirname, '..');

// ---------- A. fed_by schema acceptance ----------



// ---------- C. README + AGENTS surface v0.13.x features ----------








// ---------- E. 2 stuck-draft CVEs deleted ----------

test('E: zeroday-lessons.json carries no orphan entries for the deleted CVEs', () => {
  const l = JSON.parse(fs.readFileSync(path.join(ROOT, 'data', 'zeroday-lessons.json'), 'utf8'));
  assert.ok(!('MAL-2026-ANTHROPIC-MCP-STDIO' in l));
  assert.ok(!('CVE-2026-GTIG-AI-2FA' in l));
});
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});

require("node:test").describe("new_control_requirements entries are well-formed", () => {
  const test = require("node:test");
  const assert = require("node:assert/strict");
  const path = require("node:path");
  const fs = require("node:fs");

  const ROOT = path.join(__dirname, "..");
  const LESSONS = JSON.parse(fs.readFileSync(path.join(ROOT, "data/zeroday-lessons.json"), "utf8"));
  const GAPS = JSON.parse(fs.readFileSync(path.join(ROOT, "data/framework-control-gaps.json"), "utf8"));

  const allControls = () => {
    const out = [];
    for (const [cve, lesson] of Object.entries(LESSONS)) {
      if (cve === "_meta") continue;
      for (const c of lesson.new_control_requirements || []) out.push([cve, c]);
    }
    return out;
  };

  test("every control is an object carrying an id, not a bare string", () => {
    // Three entries held a bare string here. Nothing noticed until the field
    // started being rendered, at which point operators got
    // "- undefined undefined:" in the framework-gap report. A malformed record
    // is invisible right up until it is displayed, so assert the shape.
    const malformed = allControls()
      .filter(([, c]) => !c || typeof c !== "object" || typeof c.id !== "string" || !c.id)
      .map(([cve, c]) => `${cve}: ${JSON.stringify(c).slice(0, 80)}`);
    assert.deepEqual(malformed, [], `malformed new_control_requirements entries:\n  ${malformed.join("\n  ")}`);
  });

  test("the shape check is looking at a real, substantial surface", () => {
    // Anti-coincidence: if the walk returned nothing the assertion above would
    // pass vacuously and stop protecting anything.
    const controls = allControls();
    assert.ok(controls.length > 250, `expected a substantial control surface, walked ${controls.length}`);
    assert.ok(controls.every(([, c]) => c && typeof c === "object"));
  });

  test("every control carries a description, evidence and at least one gap_closes", () => {
    const thin = allControls()
      .filter(([, c]) =>
        typeof c.description !== "string" || c.description.trim().length === 0 ||
        typeof c.evidence !== "string" || c.evidence.trim().length === 0 ||
        !Array.isArray(c.gap_closes) || c.gap_closes.length === 0)
      .map(([cve, c]) => `${cve}/${c.id}`);
    assert.deepEqual(thin, [], `controls missing description, evidence or gap_closes:\n  ${thin.join("\n  ")}`);
  });

  test("gap_closes on the repaired KEV entries resolve to real registry keys", () => {
    // Scoped to the entries repaired alongside this test rather than the whole
    // corpus: gap_closes elsewhere legitimately names real framework controls
    // (NIST-800-53-CM-6, DORA-Article-9) that this catalog has no entry for, so
    // a corpus-wide referential assertion would fail on correct data.
    const keys = new Set(Object.keys(GAPS).filter((k) => k !== "_meta"));
    for (const cve of ["CVE-2026-11645", "CVE-2026-20245", "CVE-2026-7473"]) {
      const controls = LESSONS[cve].new_control_requirements;
      assert.ok(Array.isArray(controls) && controls.length >= 1, `${cve} must carry a control`);
      for (const c of controls) {
        assert.equal(c.id, "NEW-CTRL-001");
        assert.equal(c.name, "CISA-KEV-RESPONSE-SLA");
        for (const g of c.gap_closes) {
          assert.ok(keys.has(g), `${cve}/${c.id} gap_closes "${g}" is not a framework-control-gaps key`);
        }
      }
    }
  });
});

require("node:test").describe("control ids honor the stable NEW-CTRL contract", () => {
  const test = require("node:test");
  const assert = require("node:assert/strict");
  const path = require("node:path");
  const fs = require("node:fs");

  const LESSONS = JSON.parse(
    fs.readFileSync(path.join(__dirname, "..", "data/zeroday-lessons.json"), "utf8")
  );

  const controls = () => {
    const out = [];
    for (const [cve, lesson] of Object.entries(LESSONS)) {
      if (cve === "_meta") continue;
      for (const c of lesson.new_control_requirements || []) out.push([cve, c]);
    }
    return out;
  };

  test("every control id is NEW-CTRL-NNN", () => {
    // AGENTS.md states these ids are stable and citable from skill bodies,
    // operator reports and framework-gap analyses. Descriptive strings used as
    // ids cannot be cited that way, and 13 control classes had drifted into
    // them before this was pinned.
    const bad = controls()
      .filter(([, c]) => !/^NEW-CTRL-\d{3}$/.test(String(c.id)))
      .map(([cve, c]) => `${cve}/${c.id}`);
    assert.deepEqual(bad, [], `control ids must match NEW-CTRL-NNN:\n  ${bad.join("\n  ")}`);
  });

  test("an id always means the same control", () => {
    // Seven ids had been assigned to two different controls each, so citing
    // one was ambiguous: NEW-CTRL-009 meant KERNEL-MODULE-INVENTORY-AND-DISABLE
    // in some lessons and REGISTRY-COOLDOWN-POLICY in others. A stable id that
    // resolves to two controls is worse than no id.
    const names = new Map();
    for (const [, c] of controls()) {
      if (!names.has(c.id)) names.set(c.id, new Set());
      names.get(c.id).add(c.name);
    }
    const split = [...names.entries()]
      .filter(([, s]) => s.size > 1)
      .map(([id, s]) => `${id} -> ${[...s].join(" | ")}`);
    assert.deepEqual(split, [], `each control id must map to exactly one name:\n  ${split.join("\n  ")}`);
  });

  test("the id checks are walking a real surface", () => {
    // Anti-coincidence: an empty walk satisfies both assertions above.
    const all = controls();
    assert.ok(all.length > 800, `expected a substantial control surface, walked ${all.length}`);
    assert.ok(new Set(all.map(([, c]) => c.id)).size > 100, "expected many distinct control ids");
  });
});

require("node:test").describe("AGENTS.md control table matches the catalog", () => {
  const test = require("node:test");
  const assert = require("node:assert/strict");
  const path = require("node:path");
  const fs = require("node:fs");

  const ROOT = path.join(__dirname, "..");
  const LESSONS = JSON.parse(fs.readFileSync(path.join(ROOT, "data/zeroday-lessons.json"), "utf8"));
  const AGENTS = fs.readFileSync(path.join(ROOT, "AGENTS.md"), "utf8");

  // id -> name, from the catalog (the ids are unique by the test above)
  const catalog = new Map();
  for (const [cve, lesson] of Object.entries(LESSONS)) {
    if (cve === "_meta") continue;
    for (const c of lesson.new_control_requirements || []) catalog.set(c.id, c.name);
  }

  // Rows look like: | `NEW-CTRL-048` | NAME | surfacing | gaps |
  const rows = [...AGENTS.matchAll(/^\|\s*`(NEW-CTRL-\d{3})`\s*\|\s*([^|]+?)\s*\|/gm)]
    .map((m) => ({ id: m[1], name: m[2] }));

  test("the table is actually being parsed", () => {
    // Anti-coincidence: a regex that matched nothing would make the checks
    // below vacuous, and the table's format is the thing most likely to move.
    assert.ok(rows.length >= 8, `expected to parse several control rows, got ${rows.length}`);
  });

  test("every id documented in AGENTS.md exists in the catalog", () => {
    const missing = rows.filter((r) => !catalog.has(r.id)).map((r) => r.id);
    assert.deepEqual(missing, [], `AGENTS.md documents ids absent from zeroday-lessons.json: ${missing.join(", ")}`);
  });

  test("each documented id carries the catalog's name for it", () => {
    // The table had been carrying two slash-joined names under one id, which is
    // how a citation contract erodes: the doc says NEW-CTRL-048 is two controls
    // and an operator citing it means either.
    const wrong = rows
      .filter((r) => catalog.get(r.id) !== r.name)
      .map((r) => `${r.id}: table "${r.name}" vs catalog "${catalog.get(r.id)}"`);
    assert.deepEqual(wrong, [], `AGENTS.md control names disagree with the catalog:\n  ${wrong.join("\n  ")}`);
  });
});
