"use strict";
/**
 * Regression for the ATT&CK catalog currency gate
 * (scripts/check-attack-catalog-currency.js), against a synthetic STIX bundle so
 * no network is needed. Pins reading ids, names, STIX ids, status and tactics out
 * of a bundle, the name renderings that count as the same technique, and each
 * problem class checkCatalog reports.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");

const { bundleVersion, buildIndex, isRenderingOf, tacticProblems, checkCatalog } =
  require(path.resolve(__dirname, "..", "scripts", "check-attack-catalog-currency.js"));

function technique(id, name, stixId, phases, extra = {}) {
  return {
    type: "attack-pattern",
    id: stixId,
    name,
    kill_chain_phases: phases.map((p) => ({ kill_chain_name: "mitre-attack", phase_name: p })),
    external_references: [{ source_name: "mitre-attack", external_id: id }],
    ...extra,
  };
}

const ENTERPRISE = {
  type: "bundle",
  objects: [
    { type: "x-mitre-collection", name: "Enterprise ATT&CK", x_mitre_version: "19.2" },
    { type: "x-mitre-tactic", x_mitre_shortname: "stealth", name: "Stealth" },
    { type: "x-mitre-tactic", x_mitre_shortname: "execution", name: "Execution" },
    { type: "x-mitre-tactic", x_mitre_shortname: "initial-access", name: "Initial Access" },
    technique("T1195", "Supply Chain Compromise", "attack-pattern--p1", ["initial-access"]),
    technique("T1195.002", "Compromise Software Supply Chain", "attack-pattern--s2", ["initial-access"], { x_mitre_is_subtechnique: true }),
    technique("T1574", "Hijack Execution Flow", "attack-pattern--p2", ["stealth", "execution"]),
    technique("T1574.012", "COR_PROFILER", "attack-pattern--s12", [], { x_mitre_is_subtechnique: true }),
    technique("T1000", "Old Technique", "attack-pattern--old", ["execution"], { revoked: true }),
    technique("T1001", "Deprecated Technique", "attack-pattern--dep", ["execution"], { x_mitre_deprecated: true }),
  ],
};

const ICS = {
  type: "bundle",
  objects: [
    { type: "x-mitre-collection", name: "ICS ATT&CK", x_mitre_version: "19.2" },
    { type: "x-mitre-tactic", x_mitre_shortname: "execution-ics", name: "Execution" },
    {
      ...technique("T0853", "Scripting", "attack-pattern--ics1", ["execution-ics"]),
      external_references: [{ source_name: "mitre-ics-attack", external_id: "T0853" }],
    },
  ],
};

const index = buildIndex([ENTERPRISE, ICS]);

test("bundleVersion reads the x-mitre-collection version", () => {
  assert.equal(bundleVersion(ENTERPRISE), "19.2");
  assert.equal(bundleVersion({ objects: [] }), null);
  assert.equal(bundleVersion(null), null);
});

test("buildIndex reads names, display titles, STIX ids, status and tactics", () => {
  const sub = index.get("T1195.002");
  assert.equal(sub.name, "Compromise Software Supply Chain");
  assert.equal(sub.display, "Supply Chain Compromise: Compromise Software Supply Chain");
  assert.ok(sub.stixIds.has("attack-pattern--s2"));
  assert.equal(sub.status, "active");
  assert.deepEqual([...index.get("T1574").tactics].sort(), ["Execution", "Stealth"]);
  assert.equal(index.get("T1000").status, "revoked");
  assert.equal(index.get("T1001").status, "deprecated");
  assert.equal(index.get("T0853").name, "Scripting", "ICS references are read");
  assert.deepEqual([...index.get("T0853").tactics], ["Execution"]);
  assert.equal(index.size, 7);
});

test("isRenderingOf accepts the stored name, the Parent: Child title and a qualifier", () => {
  const sub = index.get("T1195.002");
  assert.equal(isRenderingOf("Compromise Software Supply Chain", sub), true);
  assert.equal(isRenderingOf("Supply Chain Compromise: Compromise Software Supply Chain", sub), true);
  assert.equal(isRenderingOf("Scripting (ICS)", index.get("T0853")), true);
  assert.equal(isRenderingOf("Supply Chain Compromise: Software Supply Chain", sub), false);
  assert.equal(isRenderingOf("Supply Chain Compromise", sub), false, "the parent's name is a different technique");
  assert.equal(isRenderingOf("anything", undefined), false);
});

test("tacticProblems flags a tactic upstream does not assign, using the parent's when the sub-technique has none", () => {
  assert.deepEqual(tacticProblems("T1574.012", ["Stealth", "Execution"], index), []);
  const bad = tacticProblems("T1574.012", ["Persistence", "Stealth", "Defense Evasion"], index);
  assert.deepEqual(bad.map((x) => x.ours), ["Persistence", "Defense Evasion"]);
  assert.deepEqual(bad[0].theirs, ["Execution", "Stealth"]);
  assert.deepEqual(tacticProblems("T0853", "Execution (ICS)", index), [], "a qualifier is accepted");
  assert.deepEqual(tacticProblems("T1195.002", [], index), [], "an entry may list no tactic");
});

function entry(name, stix_id, tactic) {
  return { name, stix_id, tactic };
}

test("checkCatalog passes a catalog that agrees with the release", () => {
  const catalog = {
    _meta: { attack_version: "19.2" },
    "T1195.002": entry("Supply Chain Compromise: Compromise Software Supply Chain", "attack-pattern--s2", "Initial Access"),
    "T1574.012": entry("Hijack Execution Flow: COR_PROFILER", "attack-pattern--s12", ["Stealth", "Execution"]),
    T0853: entry("Scripting", "attack-pattern--ics1", "Execution (ICS)"),
  };
  assert.deepEqual(checkCatalog(catalog, index, { names: {}, missing_ids: [] }, "19.2"), { checked: 3, problems: [] });
});

test("checkCatalog reports each problem class", () => {
  const catalog = {
    "T1195.002": entry("Supply Chain Compromise: Software Supply Chain", "attack-pattern--s2", "Initial Access"),
    "T1574.012": entry("COR_PROFILER", "attack-pattern--wrong", ["Persistence"]),
    T1000: entry("Old Technique", "attack-pattern--old", "Execution"),
    T1999: entry("Invented", null, "Execution"),
    "AML.T0001": entry("Not ATT&CK", null, null),
  };
  const { checked, problems } = checkCatalog(catalog, index, { names: {}, missing_ids: [] }, "19.2");
  assert.equal(checked, 5);
  const has = (re) => assert.ok(problems.some((p) => re.test(p)), `${re} in ${JSON.stringify(problems)}`);
  has(/^T1195\.002 is named "Supply Chain Compromise: Software Supply Chain"; ATT&CK 19\.2 names it "Supply Chain Compromise: Compromise Software Supply Chain"$/);
  has(/^T1574\.012 has stix_id attack-pattern--wrong; ATT&CK 19\.2 gives it attack-pattern--s12$/);
  has(/^T1574\.012 lists tactic "Persistence"; ATT&CK 19\.2 assigns "Execution", "Stealth"$/);
  has(/^T1000 is revoked in ATT&CK 19\.2$/);
  has(/^T1999 \("Invented"\) does not exist in Enterprise, ICS or Mobile ATT&CK 19\.2$/);
  has(/^AML\.T0001 is not an ATT&CK technique id$/);
  assert.equal(problems.length, 6);
});

test("checkCatalog allows a recorded divergence and fails a stale one", () => {
  const catalog = {
    "T1195.002": entry("Supply Chain Compromise: Software Supply Chain", "attack-pattern--s2", "Initial Access"),
    T1999: entry("Invented", null, null),
  };
  const allowed = { names: { "T1195.002": "Supply Chain Compromise: Software Supply Chain" }, missing_ids: ["T1999"] };
  assert.deepEqual(checkCatalog(catalog, index, allowed, "19.2").problems, []);

  const repaired = {
    "T1195.002": entry("Compromise Software Supply Chain", "attack-pattern--s2", "Initial Access"),
  };
  const { problems } = checkCatalog(repaired, index, allowed, "19.2");
  assert.equal(problems.length, 2);
  assert.ok(problems.some((p) => /^T1195\.002 is recorded as a name divergence but no longer diverges that way/.test(p)));
  assert.ok(problems.some((p) => /^T1999 is recorded as absent upstream but now resolves or left the catalog/.test(p)));
});
