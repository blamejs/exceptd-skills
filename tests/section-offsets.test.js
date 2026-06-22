"use strict";

/**
 * tests/section-offsets.test.js
 *
 * scripts/builders/section-offsets.js — byte offsets for the H2 sections of a
 * skill markdown file must be EOL-aware: on a CRLF body the byte_start of each
 * section must point at the real "## " byte (the pre-fix `+ 1` line accumulator
 * undercounts by one byte per preceding line on CRLF). A pure-LF body must be
 * unchanged.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const SECTION = require(path.join(__dirname, "..", "scripts", "builders", "section-offsets.js"));

function tmpDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "huntJ-"));
}

test("#47 section-offsets byte_start points at the real '## ' byte on a CRLF body", () => {
  const body = [
    "---",
    "name: t",
    "---",
    "",
    "## SectionOne",
    "alpha",
    "",
    "## SectionTwo",
    "beta",
  ].join("\r\n") + "\r\n";

  const dir = tmpDir();
  const abs = path.join(dir, "skill.md");
  fs.writeFileSync(abs, body); // exact CRLF bytes (writeFileSync doesn't reflow)
  const buf = fs.readFileSync(abs);

  const out = SECTION.buildOne(abs, "skills/t/skill.md");
  assert.equal(out.sections.length, 2, "two H2 sections");

  const s1 = out.sections.find((s) => s.name === "SectionOne");
  const s2 = out.sections.find((s) => s.name === "SectionTwo");
  assert.ok(s1 && s2, "both sections present");

  // The byte_start must equal the TRUE byte index of the header in the raw
  // buffer. The pre-fix `+ 1` accumulator undercounts by 1 byte per preceding
  // line on CRLF, so byte_start would be wrong.
  assert.equal(s1.byte_start, buf.indexOf("## SectionOne"),
    "SectionOne byte_start equals the raw-buffer index of '## SectionOne'");
  assert.equal(s2.byte_start, buf.indexOf("## SectionTwo"),
    "SectionTwo byte_start equals the raw-buffer index of '## SectionTwo'");

  // And byte_end of section one is the start of section two.
  assert.equal(s1.byte_end, s2.byte_start,
    "SectionOne byte_end is exactly where SectionTwo begins");

  // The raw slice at [byte_start, byte_end) round-trips to the header text.
  const slice = buf.slice(s2.byte_start, s2.byte_end).toString("utf8");
  assert.match(slice, /^## SectionTwo/, "the byte slice starts at the H2 header");

  fs.rmSync(dir, { recursive: true, force: true });
});

test("#47 section-offsets offsets are unchanged on a pure-LF body (no regression)", () => {
  const body = [
    "---", "name: t", "---", "", "## Alpha", "x", "", "## Beta", "y",
  ].join("\n") + "\n";
  const dir = tmpDir();
  const abs = path.join(dir, "skill.md");
  fs.writeFileSync(abs, body);
  const buf = fs.readFileSync(abs);
  const out = SECTION.buildOne(abs, "skills/t/skill.md");
  const a = out.sections.find((s) => s.name === "Alpha");
  const b = out.sections.find((s) => s.name === "Beta");
  assert.equal(a.byte_start, buf.indexOf("## Alpha"));
  assert.equal(b.byte_start, buf.indexOf("## Beta"));
  fs.rmSync(dir, { recursive: true, force: true });
});


// ---- routed from builders-docs ----
require("node:test").describe("builders-docs", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
/**
 * Coverage for the derived-index builders and the operator-facing report
 * surfaces they feed.
 *
 * - section-offsets: h3_count must skip "### " lines that live inside fenced
 *   code blocks, the same way the H2 section detector does. Output templates
 *   embedded in ```...``` are not real sub-sections.
 * - cwe-chains: the emitted chain must carry every dimension the module's
 *   own docstring promises, including dlp_refs.
 * - token-budget: the output shape must match the documented contract —
 *   corpus totals live under _meta, with no top-level by_recipe block.
 * - zero-day-response template: the blast-radius point range must match the
 *   live RWEP weight ceiling so a filled-in report does not undercount.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');
const { buildSectionOffsets } = require(path.join(ROOT, 'scripts', 'builders', 'section-offsets.js'));
const { buildCweChains } = require(path.join(ROOT, 'scripts', 'builders', 'cwe-chains.js'));
const { buildTokenBudget } = require(path.join(ROOT, 'scripts', 'builders', 'token-budget.js'));

test('section-offsets: h3_count ignores "### " headers inside fenced code blocks', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'exceptd-secoff-'));
  try {
    const rel = path.join('skills', 'fixture', 'skill.md');
    const abs = path.join(dir, rel);
    fs.mkdirSync(path.dirname(abs), { recursive: true });
    // One real H3, then a fenced output template carrying two fake H3 lines.
    const body = [
      '---',
      'name: fixture',
      '---',
      '',
      '## Output Format',
      '',
      '### Real Subsection',
      '',
      'Some prose.',
      '',
      '```markdown',
      '### Template Heading One',
      '### Template Heading Two',
      '```',
      '',
    ].join('\n');
    fs.writeFileSync(abs, body);

    const result = buildSectionOffsets({ root: dir, skills: [{ name: 'fixture', path: rel }] });
    const sections = result.skills.fixture.sections;
    const outputFmt = sections.find((s) => s.name === 'Output Format');
    assert.ok(outputFmt, 'Output Format section must be present');
    // Only the real "### Real Subsection" counts; the two fenced ones do not.
    assert.equal(outputFmt.h3_count, 1, 'fenced ### lines must not inflate h3_count');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});


// ---- routed from hunt-fix-J-refresh-upstream ----
require("node:test").describe("hunt-fix-J-refresh-upstream", () => {
const __t = require("node:test"); const __preEnv = Object.assign({}, process.env); const __preCwd = process.cwd();
/**
 * tests/hunt-fix-J-refresh-upstream.test.js
 *
 * Regression coverage for cluster J-refresh-upstream:
 *   #43 — fetchUrl rejects on 4xx/5xx; refreshRfc throws (and does NOT stamp
 *         _meta) when a fetch parses to zero RFC entries (error/empty body).
 *   #44 — fetchUrl caps redirect depth (loop rejects within the cap instead of
 *         hanging) and resolves a relative Location against the current URL.
 *   #45 — writeCatalog is atomic (temp+rename); a no-op refresh leaves the
 *         catalog byte-identical (no spurious _meta-only diff).
 *   #46 — cmdRelease selects the release.yml run by tag ref (headBranch==tag),
 *         not the unconditional newest run.
 *   #47 — section-offsets byte offsets are EOL-aware: on a CRLF body the
 *         byte_start of each section points at the real "## " byte.
 *   extra — build-indexes writeJson uses a crypto.randomBytes suffix on the
 *         temp filename.
 *
 * In-process where possible (injected fetchUrl / load / write deps + isolated
 * tempdirs); a local http server exercises the network-touching fetchUrl.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const http = require("node:http");

const MOD = require(path.join(__dirname, "..", "scripts", "refresh-upstream-catalogs.js"));
const SECTION = require(path.join(__dirname, "..", "scripts", "builders", "section-offsets.js"));

const RELEASE_SRC = fs.readFileSync(
  path.join(__dirname, "..", "scripts", "release.js"), "utf8");
const BUILD_INDEXES_SRC = fs.readFileSync(
  path.join(__dirname, "..", "scripts", "build-indexes.js"), "utf8");

// A minimal valid <rfc-entry> block the real parser accepts.
function rfcIndexXml(num, title) {
  return `<?xml version="1.0"?>
<rfc-index>
<rfc-entry>
<doc-id>RFC${String(num).padStart(4, "0")}</doc-id>
<title>${title}</title>
<current-status>PROPOSED STANDARD</current-status>
<date><month>May</month><year>2026</year></date>
</rfc-entry>
</rfc-index>`;
}

function tmpDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "huntJ-"));
}

// ---------------------------------------------------------------------------
// #44 — fetchUrl redirect cap + relative-Location resolution + drain.
// ---------------------------------------------------------------------------

// fetchUrl is https-only; to exercise its redirect/error logic against a local
// server we re-implement nothing — we assert the load-bearing properties are in
// the shipped source AND prove the *behavioral* contract with an http harness
// that reuses the same Location-resolution + depth-cap shape.



// ---------------------------------------------------------------------------
// #43 — refreshRfc refuses to stamp/write on a zero-entry (error/empty) body.
// ---------------------------------------------------------------------------


// ---------------------------------------------------------------------------
// #45 — atomic writeCatalog + no-op determinism (no spurious _meta-only diff).
// ---------------------------------------------------------------------------




// ---------------------------------------------------------------------------
// #46 — cmdRelease selects the release.yml run by tag ref, not newest-by-id.
// ---------------------------------------------------------------------------


// ---------------------------------------------------------------------------
// #47 — section-offsets byte offsets are EOL-aware (correct on a CRLF body).
// ---------------------------------------------------------------------------



// ---------------------------------------------------------------------------
// extra — build-indexes writeJson temp filename uses a crypto.randomBytes hex.
// ---------------------------------------------------------------------------

test("#47 section-offsets byte_start points at the real '## ' byte on a CRLF body", () => {
  const body = [
    "---",
    "name: t",
    "---",
    "",
    "## SectionOne",
    "alpha",
    "",
    "## SectionTwo",
    "beta",
  ].join("\r\n") + "\r\n";

  const dir = tmpDir();
  const abs = path.join(dir, "skill.md");
  fs.writeFileSync(abs, body); // exact CRLF bytes (writeFileSync doesn't reflow)
  const buf = fs.readFileSync(abs);

  const out = SECTION.buildOne(abs, "skills/t/skill.md");
  assert.equal(out.sections.length, 2, "two H2 sections");

  const s1 = out.sections.find((s) => s.name === "SectionOne");
  const s2 = out.sections.find((s) => s.name === "SectionTwo");
  assert.ok(s1 && s2, "both sections present");

  // The byte_start must equal the TRUE byte index of the header in the raw
  // buffer. The pre-fix `+ 1` accumulator undercounts by 1 byte per preceding
  // line on CRLF, so byte_start would be wrong.
  assert.equal(s1.byte_start, buf.indexOf("## SectionOne"),
    "SectionOne byte_start equals the raw-buffer index of '## SectionOne'");
  assert.equal(s2.byte_start, buf.indexOf("## SectionTwo"),
    "SectionTwo byte_start equals the raw-buffer index of '## SectionTwo'");

  // And byte_end of section one is the start of section two.
  assert.equal(s1.byte_end, s2.byte_start,
    "SectionOne byte_end is exactly where SectionTwo begins");

  // The raw slice at [byte_start, byte_end) round-trips to the header text.
  const slice = buf.slice(s2.byte_start, s2.byte_end).toString("utf8");
  assert.match(slice, /^## SectionTwo/, "the byte slice starts at the H2 header");

  fs.rmSync(dir, { recursive: true, force: true });
});

test("#47 section-offsets offsets are unchanged on a pure-LF body (no regression)", () => {
  const body = [
    "---", "name: t", "---", "", "## Alpha", "x", "", "## Beta", "y",
  ].join("\n") + "\n";
  const dir = tmpDir();
  const abs = path.join(dir, "skill.md");
  fs.writeFileSync(abs, body);
  const buf = fs.readFileSync(abs);
  const out = SECTION.buildOne(abs, "skills/t/skill.md");
  const a = out.sections.find((s) => s.name === "Alpha");
  const b = out.sections.find((s) => s.name === "Beta");
  assert.equal(a.byte_start, buf.indexOf("## Alpha"));
  assert.equal(b.byte_start, buf.indexOf("## Beta"));
  fs.rmSync(dir, { recursive: true, force: true });
});
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});
