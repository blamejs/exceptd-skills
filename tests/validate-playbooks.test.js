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

  // self-update-integrity (consumer-side update-channel integrity) brings the
  // canonical set to 29.
  assert.equal(
    playbooks.length,
    29,
    `expected 29 shipped playbooks, found ${playbooks.length}`,
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
