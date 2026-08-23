#!/usr/bin/env node
"use strict";
/**
 * Network-touching companion to lib/validate-vendor.js: for every file in
 * vendor/blamejs/_PROVENANCE.json, fetch the upstream blob at the pinned commit
 * and compare its hash against the recorded `upstream_sha256_at_pin`.
 *
 * lib/validate-vendor.js is self-attesting — a hand-edited _PROVENANCE.json
 * passes it. This reaches upstream, so it stays out of the offline-by-design
 * `npm run predeploy`. Exit 0 on match, 1 on a mismatch, 2 on a runtime error.
 */

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const https = require("https");

const ROOT = path.join(__dirname, "..");
const PROV_PATH = path.join(ROOT, "vendor", "blamejs", "_PROVENANCE.json");

function parseArgs(argv) {
  const out = { timeoutMs: 15000, json: false };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--timeout") out.timeoutMs = Number(argv[++i]) || out.timeoutMs;
    else if (a === "--json") out.json = true;
    else if (a === "--help" || a === "-h") {
      process.stdout.write(
        "Usage: node scripts/validate-vendor-online.js [--timeout <ms>] [--json]\n"
      );
      process.exit(0); // allow:process-exit-after-stdout-write — local vendor-check script; the usage line above is human-read on a TTY, not a piped --json result channel
    } else {
      process.stderr.write(`Unknown argument: ${a}\n`);
      process.exit(2); // allow:process-exit-after-stdout-write — local vendor-check script; the error note goes to stderr on a TTY, not a piped --json result channel
    }
  }
  return out;
}

function rawUrlForPin(sourceRepo, commit, upstreamPath) {
  // https://github.com/owner/repo → raw.githubusercontent.com/owner/repo.
  const m = (sourceRepo || "").match(
    /^https?:\/\/github\.com\/([^/]+)\/([^/]+?)(?:\.git)?\/?$/
  );
  if (!m) return null;
  // The URL is built from the same bindings that get validated below, so no
  // unguarded value out of _PROVENANCE.json reaches the fetch.
  const cleanOwner = m[1];
  const cleanRepo = m[2];
  const cleanCommit = String(commit || "");
  const cleanPath = String(upstreamPath || "").replace(/^\/+/, "");
  if (!/^[A-Za-z0-9._-]+$/.test(cleanOwner) || !/^[A-Za-z0-9._-]+$/.test(cleanRepo)) return null;
  if (!/^[0-9a-fA-F]{7,64}$/.test(cleanCommit)) return null;
  if (!/^[A-Za-z0-9._/-]+$/.test(cleanPath) || cleanPath.includes("..")) return null;
  return `https://raw.githubusercontent.com/${cleanOwner}/${cleanRepo}/${cleanCommit}/${cleanPath}`;
}

const MAX_REDIRECTS = 5;

// Redirects re-enter fetchBuffer with a server-supplied Location, so the host is
// checked on every hop, not just the initial URL: that is what stops a redirect
// or a tampered source_repo steering the fetch at an internal address.
const ALLOWED_FETCH_HOST = /(?:^|\.)githubusercontent\.com$|^github\.com$/;

function assertAllowedHost(url) {
  let host;
  try { host = new URL(url).hostname.toLowerCase(); }
  catch { throw new Error(`unparseable fetch URL: ${url}`); }
  if (!ALLOWED_FETCH_HOST.test(host)) {
    throw new Error(`refusing to fetch from non-allowlisted host: ${host}`);
  }
}

function fetchBuffer(url, timeoutMs, redirectsLeft = MAX_REDIRECTS) {
  return new Promise((resolve, reject) => {
    try { assertAllowedHost(url); } catch (e) { return reject(e); }
    const req = https.get(url, (res) => {
      // Hops are counted: a self-referential 3xx Location would recurse forever.
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        res.resume();
        if (redirectsLeft <= 0) {
          return reject(new Error(`exceeded ${MAX_REDIRECTS} redirects fetching ${url}`));
        }
        return resolve(fetchBuffer(res.headers.location, timeoutMs, redirectsLeft - 1));
      }
      if (res.statusCode !== 200) {
        res.resume();
        return reject(new Error(`HTTP ${res.statusCode} for ${url}`));
      }
      const chunks = [];
      res.on("data", (c) => chunks.push(c));
      res.on("end", () => resolve(Buffer.concat(chunks)));
      res.on("error", reject);
    });
    req.on("error", reject);
    req.setTimeout(timeoutMs, () => {
      req.destroy(new Error(`timeout after ${timeoutMs}ms fetching ${url}`));
    });
  });
}

async function main() {
  const opts = parseArgs(process.argv);
  if (!fs.existsSync(PROV_PATH)) {
    process.stderr.write(`vendor/blamejs/_PROVENANCE.json missing\n`);
    process.exitCode = 2;
    return;
  }
  const prov = JSON.parse(fs.readFileSync(PROV_PATH, "utf8"));
  const sourceRepo = prov.source_repo;
  const pinnedCommit = prov.pinned_commit;
  if (!sourceRepo || !pinnedCommit) {
    process.stderr.write(`_PROVENANCE.json missing source_repo or pinned_commit\n`);
    process.exitCode = 2;
    return;
  }

  const findings = [];
  for (const [name, info] of Object.entries(prov.files || {})) {
    const url = rawUrlForPin(sourceRepo, pinnedCommit, info.upstream_path);
    if (!url) {
      findings.push({ name, ok: false, reason: `cannot compute raw URL for ${sourceRepo}` });
      continue;
    }
    try {
      const buf = await fetchBuffer(url, opts.timeoutMs);
      const sha = crypto.createHash("sha256").update(buf).digest("hex");
      if (info.upstream_sha256_at_pin && sha !== info.upstream_sha256_at_pin) {
        findings.push({
          name,
          ok: false,
          reason:
            `upstream sha mismatch: recorded ${String(info.upstream_sha256_at_pin).slice(0, 12)}…, ` +
            `live ${sha.slice(0, 12)}…`,
          url,
        });
      } else {
        findings.push({ name, ok: true, sha, url });
      }
    } catch (e) {
      findings.push({ name, ok: false, reason: `fetch failed: ${e.message}`, url });
    }
  }

  const failed = findings.filter((f) => !f.ok);
  if (opts.json) {
    process.stdout.write(JSON.stringify({ ok: failed.length === 0, findings }, null, 2) + "\n");
  } else {
    for (const f of findings) {
      if (f.ok) process.stdout.write(`PASS  ${f.name}  ${f.sha.slice(0, 12)}…\n`);
      else process.stdout.write(`FAIL  ${f.name}  ${f.reason}\n`);
    }
    process.stdout.write(
      `\n${findings.length - failed.length}/${findings.length} vendored files match upstream pin.\n`
    );
  }
  process.exitCode = failed.length === 0 ? 0 : 1;
}

if (require.main === module) {
  main().catch((e) => {
    process.stderr.write(`runtime error: ${e.message}\n`);
    process.exitCode = 2;
  });
}

module.exports = { rawUrlForPin, fetchBuffer };
