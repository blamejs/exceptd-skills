#!/usr/bin/env node
"use strict";
/**
 * scripts/validate-vendor-online.js
 *
 * Optional, network-touching companion to lib/validate-vendor.js. For every
 * file recorded in vendor/blamejs/_PROVENANCE.json, fetches the upstream
 * blob from github.com/<source_repo>/blob/<pinned_commit>/<upstream_path>
 * (via the raw.githubusercontent.com mirror), hashes it, and compares the
 * result against the `upstream_sha256_at_pin` recorded in _PROVENANCE.json.
 *
 * This catches the class where _PROVENANCE.json was hand-edited to
 * advertise a `upstream_sha256_at_pin` that does not actually match what
 * upstream had at that commit. lib/validate-vendor.js only checks that the
 * local vendored file matches its own recorded hash — that's self-attesting.
 * This script extends the check to upstream, closing the gap.
 *
 * Not part of `npm run predeploy` by default — the predeploy gate sequence
 * must remain network-independent (offline gates only). Run manually:
 *
 *   node scripts/validate-vendor-online.js
 *   node scripts/validate-vendor-online.js --timeout 30000
 *   node scripts/validate-vendor-online.js --json
 *
 * Exit codes:
 *   0  every vendored file's upstream_sha256_at_pin matched upstream
 *   1  at least one mismatch
 *   2  runtime / network error
 *
 * Zero npm deps. Node 24 stdlib only.
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
      process.exit(0);
    } else {
      process.stderr.write(`Unknown argument: ${a}\n`);
      process.exit(2);
    }
  }
  return out;
}

function rawUrlForPin(sourceRepo, commit, upstreamPath) {
  // Translate https://github.com/owner/repo → raw.githubusercontent.com/owner/repo
  // sourceRepo may end in .git; strip it. Tolerate trailing slash.
  const m = (sourceRepo || "").match(
    /^https?:\/\/github\.com\/([^/]+)\/([^/]+?)(?:\.git)?\/?$/
  );
  if (!m) return null;
  const [, owner, repo] = m;
  const cleanPath = String(upstreamPath || "").replace(/^\/+/, "");
  return `https://raw.githubusercontent.com/${owner}/${repo}/${commit}/${cleanPath}`;
}

const MAX_REDIRECTS = 5;

function fetchBuffer(url, timeoutMs, redirectsLeft = MAX_REDIRECTS) {
  return new Promise((resolve, reject) => {
    const req = https.get(url, (res) => {
      // v0.12.14 (codex P2): cap redirect hops. A redirect loop (or a
      // hostile / mis-configured upstream that keeps returning 3xx with
      // Location pointing back to itself) used to recurse until stack
      // overflow or hang. Now: count hops, fail clean on exhaustion.
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
