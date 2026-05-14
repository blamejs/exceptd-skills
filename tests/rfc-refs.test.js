"use strict";
/**
 * RFC catalog + rfc_refs wiring regression tests.
 *
 * AGENTS.md hard rule #12 includes IETF RFCs and Internet-Drafts in the
 * external-data version-pinning requirement. The catalog at
 * data/rfc-references.json is the single source of truth; skills cite into
 * it via the `rfc_refs` frontmatter field; the orchestrator's
 * `validate-rfcs` command cross-checks against the IETF Datatracker; the
 * sources/validators/rfc-validator.js module is the airgapped-tolerant
 * fetcher.
 *
 * This test exercises:
 *   - the catalog file exists with the required _meta + entry shape
 *   - every rfc_refs in manifest.json resolves in the catalog (i.e. the
 *     linter's rfc_refs check is itself covered)
 *   - the catalog key shape matches the validator's parsing rules
 *   - predeploy + CI both call validate-rfcs --offline
 *   - sources/validators/index.js re-exports validateRfc + validateAllRfcs
 *   - npm run validate-rfcs is wired
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const ROOT = path.join(__dirname, "..");
const RFC_CATALOG = path.join(ROOT, "data", "rfc-references.json");
const MANIFEST = path.join(ROOT, "manifest.json");

test("data/rfc-references.json exists and has the _meta + entry shape", () => {
  assert.ok(fs.existsSync(RFC_CATALOG), "rfc-references.json must exist");
  const catalog = JSON.parse(fs.readFileSync(RFC_CATALOG, "utf8"));
  assert.ok(catalog._meta, "catalog has _meta");
  assert.ok(catalog._meta.schema_version, "_meta.schema_version present");
  assert.ok(catalog._meta.last_updated, "_meta.last_updated present");
  assert.equal(catalog._meta.skill_refs_field, "rfc_refs", "documents the skill field name");

  const ids = Object.keys(catalog).filter((k) => !k.startsWith("_"));
  assert.ok(ids.length > 0, "catalog has at least one entry");

  for (const id of ids) {
    // v0.12.8: catalog also carries non-RFC standards that the CVD + IR skills
    // legitimately cite (ISO 29147 / 30111 vulnerability handling, OASIS
    // CSAF-2.0 advisory format). Schema name stays `rfc-references.json` for
    // back-compat, but the key shape recognises the broader standards set.
    assert.match(
      id,
      /^(RFC-\d+|DRAFT-[A-Z0-9-]+|ISO-\d+|CSAF-\d+\.\d+)$/,
      `catalog key shape must match validator expectation: ${id}`
    );
    const e = catalog[id];
    assert.ok(typeof e.title === "string" && e.title.length > 0, `${id} has title`);
    assert.ok(typeof e.status === "string" && e.status.length > 0, `${id} has status`);
    assert.ok(typeof e.relevance === "string" && e.relevance.length > 10, `${id} explains relevance`);
    assert.ok(Array.isArray(e.skills_referencing), `${id} declares which skills reference it`);
    assert.match(e.last_verified, /^\d{4}-\d{2}-\d{2}$/, `${id} has ISO last_verified`);
  }
});

test("every rfc_refs entry in manifest.json resolves to a catalog key", () => {
  const manifest = JSON.parse(fs.readFileSync(MANIFEST, "utf8"));
  const catalog = JSON.parse(fs.readFileSync(RFC_CATALOG, "utf8"));
  const catalogKeys = new Set(
    Object.keys(catalog).filter((k) => !k.startsWith("_"))
  );

  let totalRefs = 0;
  for (const skill of manifest.skills) {
    if (!skill.rfc_refs) continue;
    for (const ref of skill.rfc_refs) {
      totalRefs++;
      assert.ok(
        catalogKeys.has(ref),
        `manifest entry for ${skill.name} cites rfc_ref "${ref}" but the catalog has no such key`
      );
    }
  }
  assert.ok(totalRefs > 0, "at least one skill should cite rfc_refs");
});

test("catalog reverse-reference (skills_referencing) matches manifest forward-reference (rfc_refs)", () => {
  // If skill X says it references RFC Y, the catalog entry for Y should
  // list X in skills_referencing. Otherwise either the skill's manifest
  // entry is stale or the catalog's reverse-index is stale.
  const manifest = JSON.parse(fs.readFileSync(MANIFEST, "utf8"));
  const catalog = JSON.parse(fs.readFileSync(RFC_CATALOG, "utf8"));

  // Build the forward index: rfc_id -> [skill names].
  const forward = {};
  for (const skill of manifest.skills) {
    if (!skill.rfc_refs) continue;
    for (const ref of skill.rfc_refs) {
      (forward[ref] ||= []).push(skill.name);
    }
  }

  for (const [rfcId, skillNames] of Object.entries(forward)) {
    const entry = catalog[rfcId];
    if (!entry) continue; // covered by prior test
    const reverseSet = new Set(entry.skills_referencing || []);
    for (const name of skillNames) {
      assert.ok(
        reverseSet.has(name),
        `${rfcId}.skills_referencing must include "${name}" — the skill cites this RFC in its manifest entry`
      );
    }
  }
});

test("orchestrator/index.js wires the validate-rfcs subcommand", () => {
  const src = fs.readFileSync(path.join(ROOT, "orchestrator", "index.js"), "utf8");
  assert.match(src, /case 'validate-rfcs':/, "case-clause for validate-rfcs");
  assert.match(src, /async function runValidateRfcs/, "runValidateRfcs function defined");
  // The function must accept --offline and --no-fail like its CVE sibling.
  assert.match(src, /flags\.has\('--offline'\)/);
  assert.match(src, /flags\.has\('--no-fail'\)/);
});

test("sources/validators/index.js re-exports validateRfc and validateAllRfcs", () => {
  const src = fs.readFileSync(path.join(ROOT, "sources", "validators", "index.js"), "utf8");
  assert.match(src, /validateRfc/, "barrel re-exports validateRfc");
  assert.match(src, /validateAllRfcs/, "barrel re-exports validateAllRfcs");
});

test("sources/validators/rfc-validator.js is airgapped-tolerant", () => {
  // Defensive structural check — the validator MUST wrap fetch in
  // AbortController so an unreachable Datatracker never hangs CI, and it
  // MUST return `unreachable` (not throw) on network failure.
  const src = fs.readFileSync(
    path.join(ROOT, "sources", "validators", "rfc-validator.js"),
    "utf8"
  );
  assert.match(src, /AbortController/, "uses AbortController for timeout");
  assert.match(src, /unreachable/, "surfaces unreachable as a status value");
  assert.match(src, /TIMEOUT_MS/, "has a documented timeout constant");
});

test("predeploy gate sequence no longer carries no-op validate-rfcs gate (Audit G F13)", () => {
  // The previous `Validate offline RFC catalog state` gate ran
  // `orchestrator validate-rfcs --offline --no-fail`; the `--no-fail`
  // forced it to always exit 0, so the gate never blocked a release on
  // a real RFC-catalog problem. Removed in v0.12.14 (Audit G F13) to
  // stop inflating the gate count with no marginal value. The deeper
  // RFC-reference resolution lives in lib/lint-skills.js's rfc_refs
  // walk (per-skill) and lib/validate-cve-catalog.js's V2 cross-ref
  // expansion (per-CVE).
  const { GATES } = require(path.join(ROOT, "scripts", "predeploy.js"));
  const names = GATES.map((g) => g.name);
  assert.equal(
    names.includes("Validate offline RFC catalog state"),
    false,
    "Audit G F13: validate-rfcs gate was removed in v0.12.14 (no-op due to --no-fail)"
  );
});

test("CI workflow runs validate-rfcs in the data-integrity job", () => {
  const yaml = fs.readFileSync(
    path.join(ROOT, ".github", "workflows", "ci.yml"),
    "utf8"
  );
  assert.match(
    yaml,
    /validate-rfcs --offline --no-fail/,
    "ci.yml must call validate-rfcs in the data-integrity job"
  );
});

test("package.json declares the validate-rfcs script", () => {
  const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, "package.json"), "utf8"));
  assert.ok(pkg.scripts["validate-rfcs"], "validate-rfcs script required");
  assert.match(pkg.scripts["validate-rfcs"], /validate-rfcs/);
});

test("sources/index.json registers IETF Datatracker and RFC Editor as primary sources", () => {
  const src = JSON.parse(
    fs.readFileSync(path.join(ROOT, "sources", "index.json"), "utf8")
  );
  assert.ok(src.sources.ietf_datatracker, "ietf_datatracker source registered");
  assert.ok(src.sources.rfc_editor, "rfc_editor source registered");
  assert.match(
    src.sources.ietf_datatracker.validator,
    /rfc-validator\.js/,
    "Datatracker source points at the validator module"
  );
});

test("skill-update-loop forward_watch includes the IETF RFC trigger", () => {
  const body = fs.readFileSync(
    path.join(ROOT, "skills", "skill-update-loop", "skill.md"),
    "utf8"
  );
  assert.match(
    body,
    /IETF RFC publications and draft status changes/,
    "skill-update-loop must monitor IETF RFC drift"
  );
  assert.match(
    body,
    /Trigger 9: IETF RFC or Internet-Draft Status Change/,
    "skill-update-loop must define a numbered trigger for RFC drift"
  );
});
