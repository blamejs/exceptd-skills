"use strict";
/**
 * tests/validate-playbooks.test.js
 *
 * Tests for lib/validate-playbooks.js (introduced in v0.12.12).
 *
 * Coverage:
 *   - Every shipped playbook in data/playbooks/ validates without errors
 *     (warnings are tolerated in v0.12.12; v0.13.0 will tighten).
 *   - The validator detects duplicate indicator ids.
 *   - The validator detects dangling _meta.feeds_into playbook_id refs.
 *   - The validator detects rwep_threshold ordering violations.
 *   - The CLI's exit code is 0 when only warnings fire, 1 when an error
 *     fires.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const os = require("node:os");
const { spawnSync } = require("node:child_process");

const ROOT = path.join(__dirname, "..");
const VALIDATOR = path.join(ROOT, "lib", "validate-playbooks.js");

const {
  validate,
  checkCrossRefs,
  loadContext,
  loadPlaybooks,
  obligationKey,
} = require(VALIDATOR);

const SCHEMA = JSON.parse(
  fs.readFileSync(path.join(ROOT, "lib", "schemas", "playbook.schema.json"), "utf8"),
);

function runValidator(args = [], cwd = ROOT) {
  return spawnSync(process.execPath, [VALIDATOR, ...args], {
    cwd,
    encoding: "utf8",
  });
}

test("every shipped playbook validates without errors", () => {
  const ctx = loadContext();
  const playbooks = loadPlaybooks();
  const playbookIds = new Set(
    playbooks.filter((p) => p.data).map((p) => p.data._meta.id),
  );

  // privacy-consent-ops (privacy / consent / sanctions operational integrity)
  // brings the canonical set to 33.
  assert.equal(
    playbooks.length,
    33,
    `expected 33 shipped playbooks, found ${playbooks.length}`,
  );

  for (const pb of playbooks) {
    assert.ok(pb.data, `${pb.file} should parse as JSON`);
    const findings = [
      ...validate(pb.data, SCHEMA, "playbook", pb.data._meta.id),
      ...checkCrossRefs(pb.data, ctx, playbookIds),
    ];
    const errors = findings.filter((f) => f.severity === "error");
    assert.deepEqual(
      errors,
      [],
      `playbook ${pb.data._meta.id} should have zero error-severity findings; got:\n` +
        errors.map((e) => `  - ${e.message}`).join("\n"),
    );
  }
});

test("validator emits exit code 0 against the shipped corpus", () => {
  const r = runValidator(["--quiet"]);
  assert.equal(
    r.status,
    0,
    `validator should exit 0; got ${r.status}\nstdout:\n${r.stdout}\nstderr:\n${r.stderr}`,
  );
});

test("validator detects duplicate indicator ids (hard error)", () => {
  // Build a tempdir tree the validator's __dirname anchor can read:
  // <tmp>/lib/validate-playbooks.js
  // <tmp>/lib/schemas/playbook.schema.json
  // <tmp>/data/playbooks/synthetic.json (+ catalogs)
  // <tmp>/manifest.json
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "validate-playbooks-dup-"));
  try {
    stageMirror(tmp);
    const goodPb = readGoodPlaybook();
    // Inject a duplicate id on the second indicator.
    if (goodPb.phases.detect.indicators.length < 2) {
      // Most shipped playbooks have many; assert the precondition.
      throw new Error("kernel.json should have >= 2 indicators");
    }
    const dupId = goodPb.phases.detect.indicators[0].id;
    goodPb.phases.detect.indicators[1].id = dupId;
    fs.writeFileSync(
      path.join(tmp, "data", "playbooks", "synthetic.json"),
      JSON.stringify(goodPb, null, 2),
    );

    // Remove other playbooks so we only see findings from synthetic.json.
    for (const f of fs.readdirSync(path.join(tmp, "data", "playbooks"))) {
      if (f !== "synthetic.json") {
        fs.unlinkSync(path.join(tmp, "data", "playbooks", f));
      }
    }

    const r = spawnSync(process.execPath, [path.join(tmp, "lib", "validate-playbooks.js")], {
      cwd: tmp,
      encoding: "utf8",
    });
    assert.equal(r.status, 1, `expected exit 1 for dup-indicator; got ${r.status}\n${r.stdout}\n${r.stderr}`);
    assert.match(
      r.stdout,
      /duplicate indicator id/,
      "stdout should mention the duplicate-id finding",
    );
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("validator detects dangling _meta.feeds_into playbook_id (warning, not error)", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "validate-playbooks-feed-"));
  try {
    stageMirror(tmp);
    const goodPb = readGoodPlaybook();
    goodPb._meta.feeds_into = [
      { playbook_id: "definitely-not-a-real-playbook", condition: "always" },
    ];
    fs.writeFileSync(
      path.join(tmp, "data", "playbooks", "synthetic.json"),
      JSON.stringify(goodPb, null, 2),
    );
    for (const f of fs.readdirSync(path.join(tmp, "data", "playbooks"))) {
      if (f !== "synthetic.json") {
        fs.unlinkSync(path.join(tmp, "data", "playbooks", f));
      }
    }

    const r = spawnSync(process.execPath, [path.join(tmp, "lib", "validate-playbooks.js")], {
      cwd: tmp,
      encoding: "utf8",
    });
    // Warning-only — exit 0 in v0.12.12.
    assert.equal(r.status, 0, `expected exit 0 (warning only); got ${r.status}\n${r.stdout}\n${r.stderr}`);
    assert.match(
      r.stdout,
      /unresolved playbook_id "definitely-not-a-real-playbook"/,
      "stdout should mention the dangling feeds_into",
    );
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("validator detects rwep_threshold ordering violation (hard error)", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "validate-playbooks-rwep-"));
  try {
    stageMirror(tmp);
    const goodPb = readGoodPlaybook();
    goodPb.phases.direct.rwep_threshold = { close: 90, monitor: 50, escalate: 10 };
    fs.writeFileSync(
      path.join(tmp, "data", "playbooks", "synthetic.json"),
      JSON.stringify(goodPb, null, 2),
    );
    for (const f of fs.readdirSync(path.join(tmp, "data", "playbooks"))) {
      if (f !== "synthetic.json") {
        fs.unlinkSync(path.join(tmp, "data", "playbooks", f));
      }
    }
    const r = spawnSync(process.execPath, [path.join(tmp, "lib", "validate-playbooks.js")], {
      cwd: tmp,
      encoding: "utf8",
    });
    assert.equal(r.status, 1, `expected exit 1 for rwep ordering; got ${r.status}`);
    assert.match(r.stdout, /rwep_threshold.*ordering violation/i);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("--strict promotes warnings to errors against a warning-laden playbook", () => {
  // The validator's real --strict path (main()) re-maps every finding's
  // severity to 'error'. The shipped corpus is clean, so to exercise the
  // promotion we stage a tempdir the validator WILL read and seed it with a
  // single synthetic playbook carrying exactly one warning-class finding: an
  // out-of-enum indicator `type`. (Indicator/artifact `type` are the
  // evolving-drift enums the generic validator keeps at WARNING; closed
  // vocabularies like clock_starts are ERROR and would fail without --strict
  // too, so they cannot demonstrate the promotion.)
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "validate-playbooks-strict-"));
  try {
    stageMirror(tmp);
    const pb = readGoodPlaybook();
    // Out-of-enum indicator type: WARNING by default, ERROR under --strict.
    pb.phases.detect.indicators[0].type = "definitely_not_a_valid_indicator_type";
    fs.writeFileSync(
      path.join(tmp, "data", "playbooks", "synthetic.json"),
      JSON.stringify(pb, null, 2),
    );
    for (const f of fs.readdirSync(path.join(tmp, "data", "playbooks"))) {
      if (f !== "synthetic.json") {
        fs.unlinkSync(path.join(tmp, "data", "playbooks", f));
      }
    }
    const validatorPath = path.join(tmp, "lib", "validate-playbooks.js");

    // Without --strict: the enum-drift finding is a warning, so exit 0.
    const lenient = spawnSync(process.execPath, [validatorPath, "--quiet"], {
      cwd: tmp,
      encoding: "utf8",
    });
    assert.equal(
      lenient.status,
      0,
      `non-strict run should exit 0 (warning only); got ${lenient.status}\n${lenient.stdout}\n${lenient.stderr}`,
    );

    // With --strict: the same finding is promoted to an error, so exit 1.
    const strict = spawnSync(process.execPath, [validatorPath, "--strict"], {
      cwd: tmp,
      encoding: "utf8",
    });
    assert.equal(
      strict.status,
      1,
      `--strict run should exit 1 (warning promoted to error); got ${strict.status}\n${strict.stdout}\n${strict.stderr}`,
    );
    assert.match(
      strict.stdout,
      /definitely_not_a_valid_indicator_type/,
      "strict stdout should surface the promoted enum-drift finding",
    );
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

// ---------- enforcement-gap regression tests ----------
//
// Each test below covers a previously-unenforced cross-reference or schema
// constraint. Pattern: load the live context, deep-clone a known-good
// playbook, mutate exactly one thing, and assert (a) the bad form fires the
// new check at the exact severity with the exact message, and (b) the good
// form is silent for that check.

function ctxAndIds() {
  const ctx = loadContext();
  const playbooks = loadPlaybooks();
  const ids = new Set(playbooks.filter((p) => p.data).map((p) => p.data._meta.id));
  return { ctx, ids };
}

function goodKernel() {
  return JSON.parse(
    fs.readFileSync(path.join(ROOT, "data", "playbooks", "kernel.json"), "utf8"),
  );
}

function severities(findings, sev) {
  return findings.filter((f) => f.severity === sev);
}

test("good playbook produces zero checkCrossRefs findings (control)", () => {
  const { ctx, ids } = ctxAndIds();
  const findings = checkCrossRefs(goodKernel(), ctx, ids);
  assert.deepEqual(
    findings,
    [],
    "an unmutated shipped playbook must produce no cross-ref findings; got:\n" +
      findings.map((f) => `  [${f.severity}] ${f.message}`).join("\n"),
  );
});

test("finding 1: domain.attack_refs unresolved ref → warning", () => {
  const { ctx, ids } = ctxAndIds();
  const pb = goodKernel();
  pb.domain.attack_refs = [...(pb.domain.attack_refs || []), "T9999"];
  const findings = checkCrossRefs(pb, ctx, ids);
  const matched = findings.filter((f) =>
    /domain\.attack_refs: unresolved "T9999"/.test(f.message),
  );
  assert.equal(matched.length, 1, "exactly one attack_refs finding expected");
  assert.equal(matched[0].severity, "warning", "attack_refs drift is a warning");
  assert.equal(
    severities(findings, "error").length,
    0,
    "no errors expected for an attack_refs warning",
  );

  // Good form: a resolvable attack_ref produces no finding.
  const good = goodKernel();
  const clean = checkCrossRefs(good, ctx, ids).filter((f) =>
    /domain\.attack_refs/.test(f.message),
  );
  assert.deepEqual(clean, [], "resolvable attack_refs must be silent");
});

test("finding 2: air_gap_mode network artifact without air_gap_alternative → error", () => {
  const { ctx, ids } = ctxAndIds();
  const pb = goodKernel();
  pb._meta.air_gap_mode = true;
  pb.phases.look.artifacts.push({
    id: "net-artifact",
    type: "api_response",
    source: "curl https://example.com/feed",
    description: "network-sourced artifact with no offline fallback",
    required: true,
  });
  const findings = checkCrossRefs(pb, ctx, ids);
  const matched = findings.filter((f) =>
    /air_gap_mode is true and source .* makes a network call/.test(f.message),
  );
  assert.equal(matched.length, 1, "exactly one air-gap error expected");
  assert.equal(matched[0].severity, "error", "missing offline fallback is an error");

  // Good form: same artifact WITH a non-empty air_gap_alternative is silent.
  const good = goodKernel();
  good._meta.air_gap_mode = true;
  good.phases.look.artifacts.push({
    id: "net-artifact",
    type: "api_response",
    source: "curl https://example.com/feed",
    description: "network-sourced artifact with offline fallback",
    required: true,
    air_gap_alternative: "read cached feed from /var/lib/exceptd/feed.json",
  });
  const clean = checkCrossRefs(good, ctx, ids).filter((f) =>
    /air_gap_mode/.test(f.message),
  );
  assert.deepEqual(clean, [], "network artifact with offline fallback must be silent");

  // Sanity: when air_gap_mode is false the same network artifact is not flagged.
  const off = goodKernel();
  off._meta.air_gap_mode = false;
  off.phases.look.artifacts.push({
    id: "net-artifact",
    type: "api_response",
    source: "curl https://example.com/feed",
    description: "network-sourced artifact, air-gap off",
    required: true,
  });
  const offFindings = checkCrossRefs(off, ctx, ids).filter((f) =>
    /air_gap_mode/.test(f.message),
  );
  assert.deepEqual(offFindings, [], "air-gap check must not fire when air_gap_mode is false");
});

test("finding 3a: empty look.artifacts → schema minItems error", () => {
  const pb = goodKernel();
  pb.phases.look.artifacts = [];
  const findings = validate(pb, SCHEMA, "playbook", "synthetic");
  const matched = findings.filter((f) =>
    /phases\.look\.artifacts: array shorter than minItems 1/.test(f.message),
  );
  assert.equal(matched.length, 1, "exactly one look.artifacts minItems error");
  assert.equal(matched[0].severity, "error");
});

test("finding 3b: empty detect.indicators → schema minItems error", () => {
  const pb = goodKernel();
  pb.phases.detect.indicators = [];
  const findings = validate(pb, SCHEMA, "playbook", "synthetic");
  const matched = findings.filter((f) =>
    /phases\.detect\.indicators: array shorter than minItems 1/.test(f.message),
  );
  assert.equal(matched.length, 1, "exactly one detect.indicators minItems error");
  assert.equal(matched[0].severity, "error");
});

test("finding 3c: no TTP mapping (atlas+attack both empty) → error, unless cross-cutting", () => {
  const { ctx, ids } = ctxAndIds();
  const pb = goodKernel();
  pb.domain.atlas_refs = [];
  pb.domain.attack_refs = [];
  const findings = checkCrossRefs(pb, ctx, ids);
  const matched = findings.filter((f) => /domain: no TTP mapping/.test(f.message));
  assert.equal(matched.length, 1, "exactly one no-TTP error expected");
  assert.equal(matched[0].severity, "error");

  // Exemption: a cross-cutting correlation playbook with no TTPs is allowed.
  const xc = goodKernel();
  xc.domain.atlas_refs = [];
  xc.domain.attack_refs = [];
  xc._meta.scope = "cross-cutting";
  const xcFindings = checkCrossRefs(xc, ctx, ids).filter((f) =>
    /domain: no TTP mapping/.test(f.message),
  );
  assert.deepEqual(xcFindings, [], "cross-cutting playbooks are exempt from the TTP floor");
});

test("finding 4: dangling false_positive_profile.indicator_id → warning", () => {
  const { ctx, ids } = ctxAndIds();
  const pb = goodKernel();
  pb.phases.detect.false_positive_profile.push({
    indicator_id: "ind-does-not-exist",
    benign_pattern: "benign",
    distinguishing_test: "test",
  });
  const findings = checkCrossRefs(pb, ctx, ids);
  const matched = findings.filter((f) =>
    /false_positive_profile\[\d+\]\.indicator_id: unresolved "ind-does-not-exist"/.test(
      f.message,
    ),
  );
  assert.equal(matched.length, 1, "exactly one dangling fp_profile finding");
  assert.equal(matched[0].severity, "warning");
  assert.equal(
    severities(findings, "error").length,
    0,
    "dangling fp_profile ref is a warning, not an error",
  );

  // Good form: a fp_profile pointing at a real indicator id is silent.
  const good = goodKernel();
  good.phases.detect.false_positive_profile.push({
    indicator_id: good.phases.detect.indicators[0].id,
    benign_pattern: "benign",
    distinguishing_test: "test",
  });
  const clean = checkCrossRefs(good, ctx, ids).filter((f) =>
    /false_positive_profile.*indicator_id/.test(f.message),
  );
  assert.deepEqual(clean, [], "fp_profile referencing a real indicator must be silent");
});

test("finding 5a: invalid clock_starts → error (not warning)", () => {
  const { ctx, ids } = ctxAndIds();
  const pb = goodKernel();
  // Ensure there is at least one obligation to mutate.
  assert.ok(
    pb.phases.govern.jurisdiction_obligations.length >= 1,
    "kernel.json should have >= 1 jurisdiction_obligation",
  );
  pb.phases.govern.jurisdiction_obligations[0].clock_starts = "detect_confirmd"; // typo
  const findings = checkCrossRefs(pb, ctx, ids);
  const matched = findings.filter((f) =>
    /clock_starts: invalid value "detect_confirmd"/.test(f.message),
  );
  assert.equal(matched.length, 1, "exactly one clock_starts error from checkCrossRefs");
  assert.equal(
    matched[0].severity,
    "error",
    "a typo'd clock_starts must be an error so it cannot ship",
  );

  // The full validator run (schema + crossRefs) must also surface an error,
  // so the predeploy gate exits non-zero even without --strict.
  const all = [...validate(pb, SCHEMA, "playbook", "synthetic"), ...findings];
  assert.ok(
    severities(all, "error").some((f) => /clock_starts/.test(f.message)),
    "clock_starts typo must produce an error-severity finding overall",
  );
});

test("finding 5b: invalid frameworks_in_scope → error (not warning)", () => {
  const { ctx, ids } = ctxAndIds();
  const pb = goodKernel();
  pb.domain.frameworks_in_scope = [...pb.domain.frameworks_in_scope, "not-a-framework"];
  const findings = checkCrossRefs(pb, ctx, ids);
  const matched = findings.filter((f) =>
    /frameworks_in_scope\[\d+\]: invalid value "not-a-framework"/.test(f.message),
  );
  assert.equal(matched.length, 1, "exactly one frameworks_in_scope error");
  assert.equal(matched[0].severity, "error");
});

test("finding 6: d3fend_ref not matching ^D3-[A-Z]+$ → schema pattern error", () => {
  const pb = goodKernel();
  pb.domain.d3fend_refs = [...(pb.domain.d3fend_refs || []), "d3-lowercase"];
  const findings = validate(pb, SCHEMA, "playbook", "synthetic");
  const matched = findings.filter(
    (f) =>
      /domain\.d3fend_refs\[\d+\]/.test(f.message) &&
      /does not match pattern/.test(f.message),
  );
  assert.equal(matched.length, 1, "exactly one d3fend pattern error");
  assert.equal(matched[0].severity, "error");

  // Good form: an uppercase D3-XXX key matches.
  const good = goodKernel();
  good.domain.d3fend_refs = [...(good.domain.d3fend_refs || []), "D3-CA"];
  const clean = validate(good, SCHEMA, "playbook", "synthetic").filter((f) =>
    /domain\.d3fend_refs.*pattern/.test(f.message),
  );
  assert.deepEqual(clean, [], "an uppercase D3- key must match the pattern");
});

test("obligationKey synthesizes the composite jurisdiction key", () => {
  assert.equal(
    obligationKey({
      jurisdiction: "EU",
      regulation: "NIS2 Art.23",
      window_hours: 24,
    }),
    "EU/NIS2 Art.23 24h",
  );
});

// ---------- helpers ----------

function stageMirror(tmp) {
  // Copy the minimum set of files the validator + schema need to function
  // from the live repo into the tempdir. Keeps tests hermetic.
  fs.mkdirSync(path.join(tmp, "lib", "schemas"), { recursive: true });
  fs.mkdirSync(path.join(tmp, "data", "playbooks"), { recursive: true });

  fs.copyFileSync(
    path.join(ROOT, "lib", "validate-playbooks.js"),
    path.join(tmp, "lib", "validate-playbooks.js"),
  );
  // validate-playbooks.js requires lib/exit-codes.js (safeExit); stage it too
  // or the mirrored script crashes on require with empty stdout.
  fs.copyFileSync(
    path.join(ROOT, "lib", "exit-codes.js"),
    path.join(tmp, "lib", "exit-codes.js"),
  );
  fs.copyFileSync(
    path.join(ROOT, "lib", "schemas", "playbook.schema.json"),
    path.join(tmp, "lib", "schemas", "playbook.schema.json"),
  );
  for (const f of ["atlas-ttps.json", "cve-catalog.json", "cwe-catalog.json", "d3fend-catalog.json", "attack-techniques.json"]) {
    const src = path.join(ROOT, "data", f);
    if (fs.existsSync(src)) {
      fs.copyFileSync(src, path.join(tmp, "data", f));
    }
  }
  fs.copyFileSync(
    path.join(ROOT, "manifest.json"),
    path.join(tmp, "manifest.json"),
  );
  for (const f of fs.readdirSync(path.join(ROOT, "data", "playbooks"))) {
    fs.copyFileSync(
      path.join(ROOT, "data", "playbooks", f),
      path.join(tmp, "data", "playbooks", f),
    );
  }
}

function readGoodPlaybook() {
  return JSON.parse(
    fs.readFileSync(path.join(ROOT, "data", "playbooks", "kernel.json"), "utf8"),
  );
}

function crossRefFindings(pb) {
  const ctx = loadContext();
  const playbookIds = new Set(
    loadPlaybooks().filter((p) => p.data).map((p) => p.data._meta.id),
  );
  return checkCrossRefs(pb, ctx, playbookIds);
}

test("escalation condition rooted at an unavailable phase result is an error", () => {
  const pb = goodKernel();
  pb.phases.analyze.escalation_criteria = [
    { condition: "validate.tests_passed == true", action: "raise_severity" },
  ];
  const matched = crossRefFindings(pb).filter((f) =>
    /escalation_criteria\[0\]\.condition: path root "validate\." is not resolvable/.test(f.message),
  );
  assert.equal(matched.length, 1, "exactly one unresolvable-root error for the escalation condition");
  assert.equal(matched[0].severity, "error");
});

test("feeds_into condition rooted at an unavailable phase result is an error", () => {
  const pb = goodKernel();
  pb._meta.feeds_into = [
    { playbook_id: "sbom", condition: "detect.classification == 'detected'" },
  ];
  const matched = crossRefFindings(pb).filter((f) =>
    /feeds_into\[0\]\.condition: path root "detect\." is not resolvable/.test(f.message),
  );
  assert.equal(matched.length, 1, "exactly one unresolvable-root error for the feeds_into condition");
  assert.equal(matched[0].severity, "error");
});

test("escalation/feeds_into conditions rooted at resolvable phase results pass", () => {
  const pb = goodKernel();
  pb.phases.analyze.escalation_criteria = [
    { condition: "analyze.compliance_theater_check.verdict == 'theater'", action: "notify_legal" },
    { condition: "finding.severity == 'critical'", action: "raise_severity" },
  ];
  pb._meta.feeds_into = [
    { playbook_id: "sbom", condition: "validate.residual_risk == 'high'" },
  ];
  assert.equal(
    crossRefFindings(pb).filter((f) => /is not resolvable in the (escalation|feeds_into) context/.test(f.message)).length,
    0,
    "analyze/finding roots in escalations and analyze/validate/finding roots in feeds_into are resolvable",
  );
});

// ---------- null-playbook guard + air-gap network-source detector ----------
//
// CLI-level cases use a copied-into-tempdir mini-repo (validator + exit-codes
// + schemas + the data it reads) so the real on-disk catalogs are never
// mutated.

function mkTmp(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

function writeJson(p, obj) {
  fs.mkdirSync(path.dirname(p), { recursive: true });
  // String content for the literal-null case is passed through verbatim.
  fs.writeFileSync(p, typeof obj === "string" ? obj : JSON.stringify(obj));
}

function copyInto(dst, relPath) {
  const target = path.join(dst, relPath);
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.copyFileSync(path.join(ROOT, relPath), target);
}

function runNode(scriptPath, args) {
  return spawnSync(process.execPath, [scriptPath, ...args], { encoding: "utf8" });
}

// ===========================================================================
// #20 — checkCrossRefs null-playbook guard
// ===========================================================================

test("#20 checkCrossRefs does not throw on a null playbook and returns []", () => {
  const ctx = loadContext();
  const ids = new Set(loadPlaybooks().filter((p) => p.data).map((p) => p.data._meta.id));
  assert.doesNotThrow(() => checkCrossRefs(null, ctx, ids));
  assert.deepEqual(checkCrossRefs(null, ctx, ids), []);
  // Array / primitive playbooks are also no-ops.
  assert.deepEqual(checkCrossRefs([], ctx, ids), []);
  assert.deepEqual(checkCrossRefs("nope", ctx, ids), []);
});

test("#20 CLI: a literal-null playbook file FAILs with the type error and does not crash", () => {
  const tmp = mkTmp("hfd20-cli-");
  try {
    copyInto(tmp, path.join("lib", "validate-playbooks.js"));
    copyInto(tmp, path.join("lib", "exit-codes.js"));
    copyInto(tmp, path.join("lib", "schemas", "playbook.schema.json"));
    copyInto(tmp, "manifest.json");
    for (const f of ["atlas-ttps.json", "cve-catalog.json", "cwe-catalog.json", "d3fend-catalog.json", "attack-techniques.json"]) {
      copyInto(tmp, path.join("data", f));
    }
    // The crashing input: a playbook file whose JSON content is literally null.
    writeJson(path.join(tmp, "data", "playbooks", "synthetic.json"), "null");

    const r = runNode(path.join(tmp, "lib", "validate-playbooks.js"), []);
    assert.equal(r.status, 1);
    assert.match(r.stdout, /expected type "object", got null/);
    assert.doesNotMatch(r.stdout, /TypeError|Cannot read properties of null/);
    assert.doesNotMatch(r.stderr, /TypeError|Cannot read properties of null/);
    // The summary line printed (process did not abort before the tail).
    assert.match(r.stdout, /playbooks validated/);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

// ===========================================================================
// #21 — air-gap network-source detector flags API-verb-phrased sources
// ===========================================================================

function minimalAirGapPlaybook(source, withAlt) {
  // Smallest playbook shape that exercises the air-gap completeness check in
  // checkCrossRefs. It needs a TTP mapping (atlas_refs) to avoid the unrelated
  // TTP-floor error muddying the assertion; we use the live atlas key set.
  const atlasKey = "__will_be_filled__";
  const art = { source };
  if (withAlt) art.air_gap_alternative = "Local file already staged in cwd; read it directly.";
  return {
    _meta: { id: "synthetic-airgap", air_gap_mode: true, scope: "cross-cutting" },
    domain: {},
    phases: { look: { artifacts: [art] } },
    __atlasKey: atlasKey,
  };
}

function airGapFindings(source, withAlt) {
  const ctx = loadContext();
  const ids = new Set(["synthetic-airgap"]);
  const pb = minimalAirGapPlaybook(source, withAlt);
  delete pb.__atlasKey;
  return checkCrossRefs(pb, ctx, ids).filter((f) => /air_gap_mode is true and source/.test(f.message));
}

test("#21 an API-verb-phrased source under air_gap_mode with no alternative is flagged at error severity", () => {
  const findings = airGapFindings("Entra ID: GET /directoryRoles via Graph", false);
  assert.equal(findings.length, 1, `expected exactly one air-gap finding, got: ${JSON.stringify(findings)}`);
  assert.equal(findings[0].severity, "error");
  assert.match(findings[0].message, /air_gap_mode is true and source .* makes a network call/);
});

test("#21 the same API-verb source WITH an air_gap_alternative is silent", () => {
  const findings = airGapFindings("Entra ID: GET /directoryRoles via Graph", true);
  assert.deepEqual(findings, []);
});

test("#21 a purely-local source under air_gap_mode is silent (no over-firing)", () => {
  assert.deepEqual(airGapFindings("~/.ssh/config", false), []);
  assert.deepEqual(airGapFindings("Walk cwd for *.env files", false), []);
  // "api/v\\d" deliberately NOT a token: a local artifact referencing an API
  // path must not be misclassified as a network call.
  assert.deepEqual(airGapFindings("Code-scan: grep for /api/v2 callback handlers", false), []);
});

test("#21 the full shipped corpus still produces zero air-gap findings under the broadened regex", () => {
  const ctx = loadContext();
  const playbooks = loadPlaybooks();
  const ids = new Set(playbooks.filter((p) => p.data).map((p) => p.data._meta.id));
  const airGapHits = [];
  for (const pb of playbooks) {
    if (!pb.data) continue;
    const hits = checkCrossRefs(pb.data, ctx, ids).filter((f) =>
      /air_gap_mode is true and source/.test(f.message),
    );
    for (const h of hits) airGapHits.push(`${pb.file}: ${h.message}`);
  }
  assert.deepEqual(airGapHits, [], `broadened regex must not over-fire on the shipped corpus:\n${airGapHits.join("\n")}`);
});

// ===========================================================================
// _meta.fed_by schema acceptance — the field is declared, so the validator
// emits no "unexpected property fed_by" warning.
// ===========================================================================

test('A: playbook.schema.json declares _meta.fed_by as an array of strings', () => {
  const src = fs.readFileSync(path.join(ROOT, 'lib', 'schemas', 'playbook.schema.json'), 'utf8');
  // Schema must accept the field — the "unexpected property fed_by"
  // cosmetic warnings on the playbooks should be gone.
  const schema = JSON.parse(src);
  const meta = schema.properties._meta;
  assert.ok(meta, 'schema must declare _meta');
  assert.ok(meta.properties.fed_by, '_meta.fed_by must be declared');
  assert.equal(meta.properties.fed_by.type, 'array');
  assert.equal(meta.properties.fed_by.items.type, 'string');
});

test('A: validate-playbooks no longer emits any "unexpected property fed_by" warnings', () => {
  const r = spawnSync(process.execPath, [path.join(ROOT, 'lib', 'validate-playbooks.js')], {
    encoding: 'utf8', cwd: ROOT,
  });
  // Acceptable: passes or warns on unrelated fields. Must NOT contain
  // any "fed_by" warning.
  assert.ok(!/unexpected property "fed_by"/i.test(r.stdout + r.stderr),
    `validate-playbooks must not warn on fed_by anymore; got:\n${r.stdout.slice(0, 800)}`);
});


// ---- routed from exports-surface ----
;(() => {
// Exports-surface coverage for the v0.12.12 additive helpers / constants.
// The diff-coverage gate (Hard Rule #15) requires every new lib export to
// have a corresponding test reference. These tests assert the shape and
// basic semantics of each export so a future rename, type-change, or
// silent removal is caught.

const test = require('node:test');
const assert = require('node:assert/strict');

const lintSkills = require('../lib/lint-skills');
const validateCveCatalog = require('../lib/validate-cve-catalog');
const prefetch = require('../lib/prefetch');
const scheduler = require('../orchestrator/scheduler');
const crossRefApi = require('../lib/cross-ref-api');
const sourceGhsa = require('../lib/source-ghsa');
const sourceOsv = require('../lib/source-osv');

test('lib/lint-skills exports REQUIRED_SECTIONS as a non-empty array of strings', () => {
  assert.ok(Array.isArray(lintSkills.REQUIRED_SECTIONS));
  assert.ok(lintSkills.REQUIRED_SECTIONS.length >= 1);
  for (const s of lintSkills.REQUIRED_SECTIONS) assert.equal(typeof s, 'string');
});

test('lib/lint-skills exports COUNTERMEASURE_SECTION as a string section name', () => {
  assert.equal(typeof lintSkills.COUNTERMEASURE_SECTION, 'string');
  assert.ok(lintSkills.COUNTERMEASURE_SECTION.length > 0);
});

test('lib/lint-skills exports COUNTERMEASURE_CUTOFF as an ISO-date string', () => {
  assert.equal(typeof lintSkills.COUNTERMEASURE_CUTOFF, 'string');
  assert.match(lintSkills.COUNTERMEASURE_CUTOFF, /^\d{4}-\d{2}-\d{2}$/);
});

test('lib/lint-skills exports MIN_SECTION_BODY_WORDS as a positive integer', () => {
  assert.equal(typeof lintSkills.MIN_SECTION_BODY_WORDS, 'number');
  assert.ok(Number.isInteger(lintSkills.MIN_SECTION_BODY_WORDS));
  assert.ok(lintSkills.MIN_SECTION_BODY_WORDS > 0);
});

test('lib/validate-cve-catalog exports looksLikePublicExploitSource as a function', () => {
  assert.equal(typeof validateCveCatalog.looksLikePublicExploitSource, 'function');
  // Smoke: a known public-exploit URL pattern matches; a non-exploit URL doesn't.
  assert.equal(validateCveCatalog.looksLikePublicExploitSource('https://github.com/some/exploit-poc'), true);
  assert.equal(validateCveCatalog.looksLikePublicExploitSource('https://example.com/about'), false);
});

test('lib/validate-cve-catalog exports isUsableDate as a function returning {ok, reason?}', () => {
  assert.equal(typeof validateCveCatalog.isUsableDate, 'function');
  assert.equal(validateCveCatalog.isUsableDate('2026-05-13').ok, true);
  assert.equal(validateCveCatalog.isUsableDate('1899-01-01').ok, false);
  assert.equal(validateCveCatalog.isUsableDate('2200-01-01').ok, false);
  assert.equal(validateCveCatalog.isUsableDate('not-a-date').ok, false);
  assert.equal(validateCveCatalog.isUsableDate(null).ok, false);
});

test('lib/validate-cve-catalog exports additionalChecks as a callable function', () => {
  assert.equal(typeof validateCveCatalog.additionalChecks, 'function');
  // Smoke-call the helper — exact return shape is internal; assert it doesn't throw.
  validateCveCatalog.additionalChecks('CVE-1999-0001', { name: 'x' }, { _meta: {} });
});

test('lib/validate-cve-catalog exports PUBLIC_EXPLOIT_URL_PATTERNS as an iterable of patterns', () => {
  assert.ok(Array.isArray(validateCveCatalog.PUBLIC_EXPLOIT_URL_PATTERNS));
  assert.ok(validateCveCatalog.PUBLIC_EXPLOIT_URL_PATTERNS.length >= 1);
});

test('lib/validate-cve-catalog exports STRICT_CVSS_PATTERN as a RegExp matching canonical versions', () => {
  assert.ok(validateCveCatalog.STRICT_CVSS_PATTERN instanceof RegExp);
  assert.ok(validateCveCatalog.STRICT_CVSS_PATTERN.test('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'));
  assert.equal(validateCveCatalog.STRICT_CVSS_PATTERN.test('CVSS:99.9/AV:N'), false);
});

test('lib/prefetch exports writeFileAtomic as a function writing files atomically', () => {
  const fs = require('fs');
  const os = require('os');
  const path = require('path');
  assert.equal(typeof prefetch._internal.writeFileAtomic, 'function');
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'pf-export-'));
  try {
    const dest = path.join(tmp, 'sample.txt');
    prefetch._internal.writeFileAtomic(dest, 'hello atomic');
    assert.equal(fs.readFileSync(dest, 'utf8'), 'hello atomic');
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test('orchestrator/scheduler exports TICK_MS as a positive integer not exceeding INT32 max', () => {
  assert.equal(typeof scheduler.TICK_MS, 'number');
  assert.ok(Number.isInteger(scheduler.TICK_MS));
  assert.ok(scheduler.TICK_MS > 0);
  assert.ok(scheduler.TICK_MS <= scheduler.SAFE_MAX_MS);
});

// v0.12.14 surface additions.

test('lib/cross-ref-api exports getLoadErrors as a function returning an array', () => {
  assert.equal(typeof crossRefApi.getLoadErrors, 'function');
  const errs = crossRefApi.getLoadErrors();
  assert.ok(Array.isArray(errs),
    'getLoadErrors must return an array (empty when no catalog/index parse errors)');
});

test('lib/source-ghsa exports FIELD_DROPPED_WATCH as a frozen array of field names', () => {
  assert.ok(Array.isArray(sourceGhsa.FIELD_DROPPED_WATCH));
  assert.ok(sourceGhsa.FIELD_DROPPED_WATCH.length >= 1);
  for (const f of sourceGhsa.FIELD_DROPPED_WATCH) assert.equal(typeof f, 'string');
  // Frozen so downstream consumers can't accidentally mutate the shared
  // watch list and silently change refresh-source behaviour.
  assert.ok(Object.isFrozen(sourceGhsa.FIELD_DROPPED_WATCH));
});

test('lib/source-osv exports FIELD_DROPPED_WATCH as a frozen array of field names', () => {
  assert.ok(Array.isArray(sourceOsv.FIELD_DROPPED_WATCH));
  assert.ok(sourceOsv.FIELD_DROPPED_WATCH.length >= 1);
  for (const f of sourceOsv.FIELD_DROPPED_WATCH) assert.equal(typeof f, 'string');
  assert.ok(Object.isFrozen(sourceOsv.FIELD_DROPPED_WATCH));
});

// v0.12.14 verify.js fingerprint-pin surface.

const verifyMod = require('../lib/verify');

test('lib/verify exports publicKeyFingerprint + checkExpectedFingerprint + EXPECTED_FINGERPRINT_PATH', () => {
  assert.equal(typeof verifyMod.publicKeyFingerprint, 'function');
  assert.equal(typeof verifyMod.checkExpectedFingerprint, 'function');
  assert.equal(typeof verifyMod.EXPECTED_FINGERPRINT_PATH, 'string');
  assert.ok(verifyMod.EXPECTED_FINGERPRINT_PATH.endsWith('EXPECTED_FINGERPRINT'));
});

// v0.12.14 orchestrator/event-bus.js + scheduler.js + pipeline.js additions.

const eventBus = require('../orchestrator/event-bus');
const pipelineMod = require('../orchestrator/pipeline');

test('orchestrator/event-bus exports DEFAULT_EVENT_LOG_MAX_SIZE as a positive integer', () => {
  assert.equal(typeof eventBus.DEFAULT_EVENT_LOG_MAX_SIZE, 'number');
  assert.ok(Number.isInteger(eventBus.DEFAULT_EVENT_LOG_MAX_SIZE));
  assert.ok(eventBus.DEFAULT_EVENT_LOG_MAX_SIZE > 0);
});

test('orchestrator/scheduler exports _lastFiredStorePath + _markFired internals', () => {
  assert.equal(typeof scheduler._lastFiredStorePath, 'function');
  assert.equal(typeof scheduler._markFired, 'function');
});

test('orchestrator/pipeline exports MANIFEST_CACHE_TTL_MS + _resetManifestCache', () => {
  assert.equal(typeof pipelineMod.MANIFEST_CACHE_TTL_MS, 'number');
  assert.ok(pipelineMod.MANIFEST_CACHE_TTL_MS > 0);
  assert.equal(typeof pipelineMod._resetManifestCache, 'function');
  // Smoke: resetManifestCache must not throw on a fresh process.
  pipelineMod._resetManifestCache();
});

// v0.12.14 scripts/validate-vendor-online.js exports.

const validateVendorOnline = require('../scripts/validate-vendor-online');

// v0.12.16 surface additions.

test('lib/validate-playbooks exports checkMutexReciprocity as a function', () => {
  const validatePlaybooks = require('../lib/validate-playbooks');
  assert.equal(typeof validatePlaybooks.checkMutexReciprocity, 'function');
  // Returns a Map keyed by playbook id; values are arrays of warning
  // messages for asymmetric mutex declarations.
  const empty = validatePlaybooks.checkMutexReciprocity([]);
  assert.ok(empty instanceof Map);
  // Reciprocal: a↔b — no asymmetric edges.
  const reciprocal = validatePlaybooks.checkMutexReciprocity([
    { data: { _meta: { id: 'a', mutex: ['b'] } } },
    { data: { _meta: { id: 'b', mutex: ['a'] } } },
  ]);
  assert.ok(reciprocal instanceof Map);
  // Asymmetric: a declares mutex with b but b doesn't reciprocate.
  const asym = validatePlaybooks.checkMutexReciprocity([
    { data: { _meta: { id: 'a', mutex: ['b'] } } },
    { data: { _meta: { id: 'b', mutex: [] } } },
  ]);
  assert.ok(asym instanceof Map);
  // At least one finding registered (against either 'a' or 'b').
  const totalFindings = [...asym.values()].reduce((n, v) => n + (Array.isArray(v) ? v.length : 0), 0);
  assert.ok(totalFindings >= 1, 'asymmetric mutex should produce at least one finding');
});

test('bin/exceptd registers --force-replay flag for cmdReattest', () => {
  // The flag was added in v0.12.16 audit L F10 — operator override to
  // proceed with reattest replay even when the prior attestation .sig
  // sidecar fails to verify. Confirm the flag is in the bool-args list.
  const fs = require('fs');
  const src = fs.readFileSync(require('path').join(__dirname, '..', 'bin', 'exceptd.js'), 'utf8');
  assert.match(src, /"force-replay"/, '--force-replay must be registered as a parseArgs bool flag');
});

test('scripts/validate-vendor-online exports rawUrlForPin + fetchBuffer', () => {
  assert.equal(typeof validateVendorOnline.rawUrlForPin, 'function');
  assert.equal(typeof validateVendorOnline.fetchBuffer, 'function');
  // Smoke: rawUrlForPin produces a github raw URL string for a known shape.
  const url = validateVendorOnline.rawUrlForPin(
    'https://github.com/blamejs/blamejs.git', '1442f17758a4', 'lib/x.js'
  );
  assert.ok(typeof url === 'string' && url.includes('1442f17758a4'));
});
})();
