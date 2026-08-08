"use strict";


// ---- routed from gitattributes-hash-coverage ----
require("node:test").describe("gitattributes-hash-coverage", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
/**
 * .gitattributes LF-coverage guard for byte-hashed shipped files.
 *
 * Every shipped file is hashed byte-for-byte by the integrity chain:
 * scripts/refresh-sbom.js records a per-file SHA-256 (+ SHA3-512) into
 * sbom.cdx.json, scripts/check-sbom-currency.js re-hashes the live bytes
 * and fails on drift, lib/validate-vendor.js does the same for vendored
 * files via vendor/blamejs/_PROVENANCE.json, and lib/validate-indexes.js
 * hashes the index inputs. None of those sites normalize line endings —
 * they hash the raw on-disk bytes.
 *
 * That only stays cross-platform-stable because .gitattributes pins every
 * shipped text extension to `eol=lf`. A shipped text file with NO eol rule
 * is checked out as CRLF on a Windows clone with core.autocrlf=true; that
 * checkout records a CRLF hash, while Linux CI re-hashes the LF blob and
 * reports drift. This guard fails the build the moment a shipped text file
 * type lacks an LF pin, so a new hashed surface can never ship un-normalized.
 *
 * Coverage is resolved through git's own attribute engine (`git check-attr
 * eol`), not a re-implementation of .gitattributes glob matching, so the
 * test asserts the EFFECTIVE rule the way every clone resolves it. Binary
 * files (text: unset) are exempt — line-ending normalization does not apply.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { execFileSync } = require("node:child_process");

const ROOT = path.join(__dirname, "..");

// Mirrors scripts/refresh-sbom.js: the shipped surface is package.json
// `files[]` expanded to concrete regular files, minus the SBOM self-
// reference and the derivable index cache (those are excluded from the
// per-file hash inventory there too).
const SELF_EXCLUDED = new Set(["sbom.cdx.json"]);
const DERIVABLE_PREFIXES = ["data/_indexes/"];

function isDerivable(rel) {
  return DERIVABLE_PREFIXES.some(
    (p) => rel === p.replace(/\/$/, "") || rel.startsWith(p)
  );
}

function toPosixRel(absPath) {
  return path.relative(ROOT, absPath).split(path.sep).join("/");
}

function walkFiles(absDir) {
  const out = [];
  for (const entry of fs.readdirSync(absDir, { withFileTypes: true })) {
    const abs = path.join(absDir, entry.name);
    if (entry.isDirectory()) out.push(...walkFiles(abs));
    else if (entry.isFile()) out.push(abs);
  }
  return out;
}

function shippedHashedFiles() {
  const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, "package.json"), "utf8"));
  const abs = [];
  for (const entry of pkg.files || []) {
    const full = path.join(ROOT, entry);
    if (!fs.existsSync(full)) continue;
    const stat = fs.statSync(full);
    if (stat.isDirectory()) abs.push(...walkFiles(full));
    else if (stat.isFile()) abs.push(full);
  }
  return Array.from(new Set(abs.map(toPosixRel)))
    .filter((r) => !SELF_EXCLUDED.has(r))
    .filter((r) => !isDerivable(r))
    .sort();
}

// Resolve `text` + `eol` attributes for a batch of paths through git's
// own attribute engine. Returns Map<relPath, { text, eol }>.
function resolveAttrs(relPaths) {
  const out = execFileSync("git", ["check-attr", "--stdin", "text", "eol"], {
    cwd: ROOT,
    input: relPaths.join("\n"),
    encoding: "utf8",
  });
  const attrs = new Map();
  for (const line of out.split("\n")) {
    // Format: "<path>: <attr>: <value>"
    const m = line.match(/^(.*): (text|eol): (.*)$/);
    if (!m) continue;
    const [, file, attr, value] = m;
    if (!attrs.has(file)) attrs.set(file, {});
    attrs.get(file)[attr] = value;
  }
  return attrs;
}

test("every byte-hashed shipped file is covered by an eol=lf .gitattributes rule", () => {
  const files = shippedHashedFiles();
  // Anti-coincidence: the surface must be non-trivial, otherwise an empty
  // walk would make the assertion vacuously pass.
  assert.ok(
    files.length > 100,
    `expected a substantial shipped-file surface, walked only ${files.length}`
  );

  const attrs = resolveAttrs(files);
  const uncovered = [];
  for (const rel of files) {
    const a = attrs.get(rel) || {};
    // Binary files declare `text: unset` (.gitattributes `binary` macro) —
    // no line-ending normalization applies, so they need no eol rule.
    if (a.text === "unset") continue;
    // Any other shipped file is hashed by-byte and MUST resolve to eol=lf.
    if (a.eol !== "lf") {
      uncovered.push(`${rel} (text=${a.text}, eol=${a.eol})`);
    }
  }

  assert.deepEqual(
    uncovered,
    [],
    "shipped byte-hashed files lack an `eol=lf` rule in .gitattributes — a Windows checkout " +
      "would record CRLF hashes that drift against Linux CI's LF blob. Add an LF pin for each:\n  " +
      uncovered.join("\n  ")
  );
});

test("git check-attr resolves a known-covered file to eol=lf (guard self-check)", () => {
  // Proves the resolution mechanism actually reports `lf` rather than the
  // assertion passing because every value parsed as undefined.
  const attrs = resolveAttrs(["manifest.json"]);
  assert.equal(attrs.get("manifest.json").eol, "lf");
});
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});

require("node:test").describe("sbom metadata honesty", () => {
  const test = require("node:test");
  const assert = require("node:assert/strict");
  const fs = require("node:fs");
  const path = require("node:path");
  const {
    releaseTimestamp,
    ALWAYS_SHIPPED,
    DERIVABLE_PREFIXES,
  } = require("../scripts/refresh-sbom.js");

  const ROOT = path.join(__dirname, "..");
  const readJson = (rel) => JSON.parse(fs.readFileSync(path.join(ROOT, rel), "utf8"));

  test("metadata.timestamp is the CHANGELOG release date, not a synthesized future one", () => {
    const pkg = readJson("package.json");
    const changelog = fs.readFileSync(path.join(ROOT, "CHANGELOG.md"), "utf8");
    // Read the date off the heading by hand rather than rebuilding the
    // generator's pattern here — a second copy of the regex would drift, and
    // this test would then be pinning its own expectation instead of the code's.
    const heading = changelog
      .split("\n")
      .find((l) => l.startsWith(`## ${pkg.version} `));
    assert.ok(heading, `CHANGELOG.md needs a heading for ${pkg.version}`);
    const date = heading.trim().split(/\s+/).pop();
    assert.match(date, /^\d{4}-\d{2}-\d{2}$/, `heading must end in an ISO date: ${heading}`);

    const sbom = readJson("sbom.cdx.json");
    assert.equal(sbom.metadata.timestamp, `${date}T00:00:00.000Z`);
    assert.equal(releaseTimestamp(pkg.version), sbom.metadata.timestamp);
  });

  test("the shipped timestamp is a plausible date, not centuries out", () => {
    // The bug this pins was not a crash: the field parsed fine and read
    // 2147-11-20, because a uint32 of seconds was added to a 2026 anchor. An
    // ISO-8601 check alone accepted it, so assert the VALUE is sane. The upper
    // bound is loose on purpose — it only has to reject a century of drift.
    const sbom = readJson("sbom.cdx.json");
    const t = Date.parse(sbom.metadata.timestamp);
    assert.ok(Number.isFinite(t), "metadata.timestamp must parse");
    assert.ok(t >= Date.UTC(2024, 0, 1), `timestamp ${sbom.metadata.timestamp} predates the project`);
    assert.ok(t <= Date.UTC(2100, 0, 1), `timestamp ${sbom.metadata.timestamp} is implausibly far in the future`);
  });

  test("releaseTimestamp refuses a version with no dated CHANGELOG heading", () => {
    // Refusing matters more than the message: the previous code's willingness
    // to synthesize a value when it had none is what shipped the 2147 date.
    assert.throws(() => releaseTimestamp("no-such-version"), /no dated heading/);
  });

  test("package.json and sources/README.md are hashed even though `files` never names them", () => {
    const pkg = readJson("package.json");
    for (const rel of ALWAYS_SHIPPED) {
      assert.ok(
        !(pkg.files || []).includes(rel),
        `${rel} is in package.json files[] — it no longer needs an ALWAYS_SHIPPED entry`
      );
    }
    const sbom = readJson("sbom.cdx.json");
    const hashed = new Map(
      (sbom.components || [])
        .filter((c) => String(c["bom-ref"] || "").startsWith("file:"))
        .map((c) => [c.name, c])
    );
    for (const rel of ALWAYS_SHIPPED) {
      const comp = hashed.get(rel);
      assert.ok(comp, `${rel} ships in every tarball but has no file: component`);
      // Presence is not coverage: assert the component carries a real digest.
      const sha = (comp.hashes || []).find((h) => h.alg === "SHA-256");
      assert.ok(sha && /^[a-f0-9]{64}$/.test(sha.content), `${rel} component has no SHA-256`);
    }
  });

  test("the SBOM states which shipped paths it does not hash", () => {
    // The rationale used to live only in the generator's source, so an operator
    // holding the SBOM could not tell a partial inventory from a complete one.
    const sbom = readJson("sbom.cdx.json");
    const props = new Map((sbom.metadata.properties || []).map((p) => [p.name, p.value]));
    assert.equal(props.get("exceptd:integrity:uncovered:prefix"), DERIVABLE_PREFIXES.join(","));
    const why = props.get("exceptd:integrity:uncovered:rationale");
    assert.ok(typeof why === "string" && why.length > 40, "the exclusion must carry a stated reason");
    assert.match(why, /predeploy/, "the reason must name the check that covers the gap instead");
  });
});
