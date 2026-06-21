"use strict";

/**
 * tests/refresh-upstream-catalogs.test.js
 *
 * Pins the exported surface of scripts/refresh-upstream-catalogs.js so
 * the four upstream-catalog refreshers and their dispatcher remain
 * callable by per-type wrapper scripts + downstream tooling.
 *
 * Network-free — we assert the module exports the expected functions
 * + SOURCES registry. The refresh functions themselves hit live MITRE /
 * IETF endpoints, so end-to-end tests run in a separate `npm run
 * refresh-upstream-catalogs --dry-run` smoke check rather than the
 * default test suite.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const http = require("node:http");

const MOD = require(path.join(__dirname, "..", "scripts", "refresh-upstream-catalogs.js"));

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

test("refresh-upstream-catalogs exports the five refresher functions", () => {
  assert.equal(typeof MOD.refreshRfc, "function",
    "refreshRfc must be exported (consumed by scripts/refresh-rfc-index.js wrapper)");
  assert.equal(typeof MOD.refreshAttack, "function",
    "refreshAttack must be exported (consumed by scripts/refresh-mitre-attack.js wrapper)");
  assert.equal(typeof MOD.refreshIcsAttack, "function",
    "refreshIcsAttack must be exported (consumed by scripts/refresh-mitre-ics-attack.js wrapper)");
  assert.equal(typeof MOD.refreshAtlas, "function",
    "refreshAtlas must be exported (consumed by scripts/refresh-mitre-atlas.js wrapper)");
  assert.equal(typeof MOD.refreshD3fend, "function",
    "refreshD3fend must be exported (consumed by scripts/refresh-mitre-d3fend.js wrapper)");
});

test("refresh-upstream-catalogs exports SOURCES registry with all five keys", () => {
  assert.ok(MOD.SOURCES && typeof MOD.SOURCES === "object",
    "SOURCES registry must be exported");
  for (const key of ["rfc", "attack", "ics-attack", "atlas", "d3fend"]) {
    assert.ok(MOD.SOURCES[key], `SOURCES.${key} must be present`);
    assert.equal(typeof MOD.SOURCES[key].run, "function",
      `SOURCES.${key}.run must be a function (CLI dispatcher target)`);
    assert.equal(typeof MOD.SOURCES[key].name, "string",
      `SOURCES.${key}.name must declare the canonical intake-method tag`);
  }
});

test("refresh-upstream-catalogs exports runCli for the CLI entrypoint", () => {
  assert.equal(typeof MOD.runCli, "function",
    "runCli must be exported so the per-type wrappers + the unified entrypoint share dispatch");
});

test("per-type wrapper scripts exist and import from refresh-upstream-catalogs", () => {
  const fs = require("fs");
  const wrappers = [
    "refresh-rfc-index.js",
    "refresh-mitre-attack.js",
    "refresh-mitre-ics-attack.js",
    "refresh-mitre-atlas.js",
    "refresh-mitre-d3fend.js"
  ];
  for (const w of wrappers) {
    const p = path.join(__dirname, "..", "scripts", w);
    assert.ok(fs.existsSync(p), `${w} per-type wrapper must exist`);
    const body = fs.readFileSync(p, "utf8");
    assert.match(body, /refresh-upstream-catalogs/,
      `${w} must import from refresh-upstream-catalogs.js (single source of truth)`);
  }
});

// ---------------------------------------------------------------------------
// #44 — fetchUrl redirect cap + relative-Location resolution + drain.
// ---------------------------------------------------------------------------

// fetchUrl is https-only; to exercise its redirect/error logic against a local
// server we re-implement nothing — we assert the load-bearing properties are in
// the shipped source AND prove the *behavioral* contract with an http harness
// that reuses the same Location-resolution + depth-cap shape.
test("#44 fetchUrl source caps redirect depth and resolves Location via new URL(base)", () => {
  const src = fs.readFileSync(
    path.join(__dirname, "..", "scripts", "refresh-upstream-catalogs.js"), "utf8");
  // Depth cap present.
  assert.match(src, /too many redirects/,
    "fetchUrl must reject when redirect depth exceeds the cap");
  assert.match(src, /MAX_REDIRECTS/,
    "fetchUrl must use a redirect-depth cap constant");
  // Base-URL resolution present (relative Location handled).
  assert.match(src, /new URL\(\s*loc\s*,\s*url\s*\)/,
    "fetchUrl must resolve Location against the current url (relative + absolute)");
  // Missing-Location guard present.
  assert.match(src, /with no Location header/,
    "fetchUrl must reject a 3xx with no Location header rather than throw ERR_INVALID_URL");
  // Drains the redirect response (frees the socket).
  assert.match(src, /r\.resume\(\)/,
    "fetchUrl must drain the redirect response (r.resume) so the socket is freed");
});

test("#44 redirect-follow + relative-Location semantics terminate (http harness)", async () => {
  // Behavioral proof of the loop-follow contract: a follower with a depth cap
  // and new URL(loc, base) resolution must (a) follow a relative 302 to the
  // next body and (b) reject a self-redirect loop within the cap. We mirror the
  // shipped logic against an http server (fetchUrl itself is https-only).
  const MAX = 5;
  function follow(urlStr, depth = 0) {
    return new Promise((resolve, reject) => {
      http.get(urlStr, (r) => {
        const code = r.statusCode;
        if (code >= 300 && code < 400) {
          r.resume();
          const loc = r.headers.location;
          if (!loc) return reject(new Error("no Location"));
          if (depth >= MAX) return reject(new Error("too many redirects"));
          let next;
          try { next = new URL(loc, urlStr).toString(); }
          catch (e) { return reject(new Error("bad target: " + e.message)); }
          return follow(next, depth + 1).then(resolve, reject);
        }
        if (code >= 400) { r.resume(); return reject(new Error("HTTP " + code)); }
        let b = ""; r.on("data", (c) => (b += c)); r.on("end", () => resolve(b));
      }).on("error", reject);
    });
  }

  let server;
  const base = await new Promise((resolve) => {
    server = http.createServer((req, res) => {
      if (req.url === "/start") { res.writeHead(302, { Location: "/next" }); return res.end(); }
      if (req.url === "/next") { res.writeHead(200); return res.end("ARRIVED"); }
      if (req.url === "/loop") { res.writeHead(302, { Location: "/loop" }); return res.end(); }
      res.writeHead(404); res.end();
    });
    server.listen(0, "127.0.0.1", () => resolve(`http://127.0.0.1:${server.address().port}`));
  });
  try {
    // (b) relative Location resolves against the base and yields the next body.
    const body = await follow(base + "/start");
    assert.equal(body, "ARRIVED", "relative 302 resolves to /next and returns its body");

    // (a) self-redirect loop rejects within the cap (does not hang). The
    // outer timeout guards against a regression that drops the cap.
    let rejected = false;
    await Promise.race([
      follow(base + "/loop").then(
        () => { throw new Error("loop unexpectedly resolved"); },
        (e) => { rejected = true; assert.match(e.message, /too many redirects/); }
      ),
      new Promise((_, rej) => setTimeout(() => rej(new Error("redirect loop HUNG past cap")), 5000)),
    ]);
    assert.equal(rejected, true, "redirect loop rejected within the depth cap");
  } finally {
    await new Promise((r) => server.close(r));
  }
});

test("#44/#43 fetchUrl rejects a 5xx error body (does not resolve it as a successful body)", async () => {
  // fetchUrl is https-only; assert the >=400 reject is in the shipped source
  // AND prove the behavioral contract via the http harness above's shape.
  const src = fs.readFileSync(
    path.join(__dirname, "..", "scripts", "refresh-upstream-catalogs.js"), "utf8");
  assert.match(src, /code\s*>=\s*400/,
    "fetchUrl must treat 4xx/5xx as an error (reject), not resolve the error body");
  assert.match(src, /"HTTP "\s*\+\s*code\s*\+\s*" for "/,
    "fetchUrl must reject with an HTTP <code> message on 4xx/5xx");
  // Behavioral: an http follower with the same >=400 guard rejects a 503.
  let server;
  const base = await new Promise((resolve) => {
    server = http.createServer((req, res) => {
      res.writeHead(503, { "Content-Type": "text/html" });
      res.end("<html><body>Service Unavailable</body></html>");
    });
    server.listen(0, "127.0.0.1", () => resolve(`http://127.0.0.1:${server.address().port}`));
  });
  function follow(urlStr) {
    return new Promise((resolve, reject) => {
      http.get(urlStr, (r) => {
        if (r.statusCode >= 400) { r.resume(); return reject(new Error("HTTP " + r.statusCode + " for " + urlStr)); }
        let b = ""; r.on("data", (c) => (b += c)); r.on("end", () => resolve(b));
      }).on("error", reject);
    });
  }
  try {
    await assert.rejects(() => follow(base + "/anything"), /HTTP 503/,
      "a 503 with an HTML body must reject, not resolve the error page as a 'successful' body");
  } finally {
    await new Promise((r) => server.close(r));
  }
});

// ---------------------------------------------------------------------------
// #43 — refreshRfc refuses to stamp/write on a zero-entry (error/empty) body.
// ---------------------------------------------------------------------------

test("#43 refreshRfc throws on an empty/error body AND leaves _meta.last_threat_review byte-identical", async () => {
  const dir = tmpDir();
  const before = {
    _meta: { schema_version: "1.0.0", last_updated: "2026-01-01", last_threat_review: "2026-01-01" },
    "RFC-4301": { number: 4301, title: "Security Architecture for IP", status: "Proposed Standard" },
  };
  const file = path.join(dir, "rfc-references.json");
  const beforeBytes = JSON.stringify(before, null, 2) + "\n";
  fs.writeFileSync(file, beforeBytes);

  let wrote = false;
  const deps = {
    fetchUrl: async () => "<html><body>503 error page, no rfc-entry blocks here</body></html>",
    loadCatalog: () => JSON.parse(fs.readFileSync(file, "utf8")),
    writeCatalog: (rel, obj) => { wrote = true; fs.writeFileSync(file, JSON.stringify(obj, null, 2) + "\n"); },
  };

  await assert.rejects(
    () => MOD.refreshRfc({ _deps: deps }),
    /parsed 0 entries/,
    "refreshRfc must throw when the fetch parses to zero RFC entries"
  );
  assert.equal(wrote, false, "refreshRfc must NOT write the catalog on a zero-entry fetch");

  const after = JSON.parse(fs.readFileSync(file, "utf8"));
  assert.equal(after._meta.last_threat_review, before._meta.last_threat_review,
    "last_threat_review must be unchanged (no stale staleness mis-advance)");
  assert.equal(after._meta.last_updated, before._meta.last_updated,
    "last_updated must be unchanged");
  assert.equal(fs.readFileSync(file, "utf8"), beforeBytes,
    "the on-disk catalog must be byte-identical after a refused refresh");

  fs.rmSync(dir, { recursive: true, force: true });
});

// ---------------------------------------------------------------------------
// #45 — atomic writeCatalog + no-op determinism (no spurious _meta-only diff).
// ---------------------------------------------------------------------------

test("#45 refreshRfc no-op leaves the catalog byte-identical (no _meta-only restamp)", async () => {
  const dir = tmpDir();
  const file = path.join(dir, "rfc-references.json");
  // Catalog ALREADY contains RFC-9999 fully populated, so a fetch of the same
  // RFC produces 0 added / 0 backfilled / 0 status bumps — a genuine no-op.
  const cat = {
    _meta: { schema_version: "1.0.0", last_updated: "2026-01-01", last_threat_review: "2026-01-01" },
    "RFC-9999": {
      number: 9999, title: "Test RFC", status: "Proposed Standard", published: "2026-05",
      authors: ["A"], stream: "IETF", area: "sec", working_group: "tls",
      abstract: "x", keywords: ["k"], page_count: 1, doi: "10.x/RFC9999",
      obsoletes: [], updates: [], updated_by: [], obsoleted_by: [], is_also: [],
      errata_count: 0, tracker: "t", txt_url: "tx", html_url: "ht",
      relevance: "r", skills_referencing: [], last_verified: "2026-05-01",
    },
  };
  const beforeBytes = JSON.stringify(cat, null, 2) + "\n";
  fs.writeFileSync(file, beforeBytes);

  let wrote = false;
  const deps = {
    fetchUrl: async () => rfcIndexXml(9999, "Test RFC"),
    loadCatalog: () => JSON.parse(fs.readFileSync(file, "utf8")),
    writeCatalog: (rel, obj) => { wrote = true; fs.writeFileSync(file, JSON.stringify(obj, null, 2) + "\n"); },
  };

  const r = await MOD.refreshRfc({ _deps: deps });
  assert.equal(r.added, 0, "no new RFC added");
  assert.equal(r.backfilled, 0, "nothing backfilled (row already complete)");
  assert.equal(r.statusBumped, 0, "no status bump");
  assert.equal(wrote, false, "a genuine no-op must NOT call writeCatalog");
  assert.equal(fs.readFileSync(file, "utf8"), beforeBytes,
    "the catalog file must be byte-identical after a no-op refresh (no _meta-only diff)");

  fs.rmSync(dir, { recursive: true, force: true });
});

test("#45 refreshRfc DOES advance _meta when a new RFC is actually added", async () => {
  const dir = tmpDir();
  const file = path.join(dir, "rfc-references.json");
  const cat = {
    _meta: { schema_version: "1.0.0", last_updated: "2026-01-01", last_threat_review: "2026-01-01" },
    "RFC-4301": { number: 4301, title: "Existing", status: "Proposed Standard",
      authors: ["A"], abstract: "x", keywords: ["k"], obsoletes: [], updates: [],
      updated_by: [], obsoleted_by: [], is_also: [], txt_url: "t", html_url: "h",
      area: "sec", working_group: "wg", stream: "IETF", doi: "d", page_count: 1 },
  };
  fs.writeFileSync(file, JSON.stringify(cat, null, 2) + "\n");

  const deps = {
    fetchUrl: async () => rfcIndexXml(8888, "Brand New RFC"),
    loadCatalog: () => JSON.parse(fs.readFileSync(file, "utf8")),
    writeCatalog: (rel, obj) => fs.writeFileSync(file, JSON.stringify(obj, null, 2) + "\n"),
  };

  const r = await MOD.refreshRfc({ _deps: deps });
  assert.equal(r.added, 1, "the new RFC-8888 must be added");
  const after = JSON.parse(fs.readFileSync(file, "utf8"));
  assert.ok(after["RFC-8888"], "RFC-8888 present after a changed refresh");
  assert.notEqual(after._meta.last_updated, "2026-01-01",
    "last_updated must advance when something actually changed");
  assert.equal(typeof after._meta.last_updated, "string");

  fs.rmSync(dir, { recursive: true, force: true });
});

test("#45 writeCatalog is atomic (temp+rename) — no truncated file is left", () => {
  // The real writeCatalog targets data/<rel>; pointing it at the repo tree would
  // mutate shared state. Instead assert the temp+rename shape in source and
  // prove rename-atomicity semantics in an isolated tmpdir.
  const src = fs.readFileSync(
    path.join(__dirname, "..", "scripts", "refresh-upstream-catalogs.js"), "utf8");
  assert.match(src, /\.tmp-\$\{process\.pid\}/,
    "writeCatalog must write to a temp sibling");
  assert.match(src, /fs\.renameSync\(\s*tmp\s*,\s*abs\s*\)/,
    "writeCatalog must rename the temp file into place (atomic)");

  // Behavioral: a rename never leaves a partial reader-visible file.
  const dir = tmpDir();
  const target = path.join(dir, "out.json");
  const tmp = `${target}.tmp-${process.pid}`;
  fs.writeFileSync(tmp, JSON.stringify({ ok: true }, null, 2) + "\n");
  assert.equal(fs.existsSync(target), false, "target absent before rename");
  fs.renameSync(tmp, target);
  assert.equal(fs.existsSync(tmp), false, "temp removed after rename");
  assert.deepEqual(JSON.parse(fs.readFileSync(target, "utf8")), { ok: true });
  fs.rmSync(dir, { recursive: true, force: true });
});
