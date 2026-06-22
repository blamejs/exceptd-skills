"use strict";


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

test("#46 cmdRelease selects the release.yml run by tag ref (headBranch==tag), not unconditional newest", () => {
  // Source-level guard, matching tests/release-script.test.js style.
  // The run-list query must request headBranch and filter by the tag — it must
  // NOT be the old unconditional ".[0].databaseId" newest-run selection.
  assert.match(RELEASE_SRC, /headBranch/,
    "cmdRelease must request headBranch to identify the tag-triggered run");
  assert.match(RELEASE_SRC, /select\(\.headBranch\s*==\s*"' \+ tag \+ '"\)/,
    "cmdRelease must filter the release.yml runs by headBranch==tag");
  assert.match(RELEASE_SRC, /--event=push/,
    "cmdRelease must scope to push-triggered runs (excludes workflow_dispatch)");

  // The unconditional newest-run selection (the pre-fix bug) must be gone from
  // cmdRelease's release.yml lookup.
  const relIdx = RELEASE_SRC.indexOf("function cmdRelease(");
  const nextFnIdx = RELEASE_SRC.indexOf("function cmdAll(", relIdx);
  const cmdReleaseBody = RELEASE_SRC.slice(relIdx, nextFnIdx);
  assert.ok(/release\.yml/.test(cmdReleaseBody), "cmdRelease references release.yml");
  assert.doesNotMatch(cmdReleaseBody, /--jq",\s*"\.\[0\]\.databaseId"/,
    "cmdRelease must not select release.yml's newest run unconditionally (.[0].databaseId)");
});
;{ const __postEnv = Object.assign({}, process.env); try { process.chdir(__preCwd); } catch (e) {}
  for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv);
  __t.before(() => { for (const k of Object.keys(__postEnv)) if (__postEnv[k] !== __preEnv[k]) process.env[k] = __postEnv[k]; });
  __t.after(() => { for (const k of Object.keys(process.env)) if (!(k in __preEnv)) delete process.env[k]; Object.assign(process.env, __preEnv); try { process.chdir(__preCwd); } catch (e) {}
    const __ROOT = require("path").resolve(__dirname, ".."); for (const k of Object.keys(require.cache)) { if (k.startsWith(__ROOT) && !k.includes("node_modules")) delete require.cache[k]; } });
}
});
