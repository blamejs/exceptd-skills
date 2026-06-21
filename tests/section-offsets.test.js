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
