"use strict";
/**
 * Predeploy gate. Confirms `data/_indexes/*.json` is current against the
 * canonical sources by re-hashing each against the SHA-256 table in
 * data/_indexes/_meta.json. Exit 0 when current, 1 when stale.
 */

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const ROOT = path.join(__dirname, "..");
const ABS = (p) => path.join(ROOT, p);
const IDX_DIR = ABS("data/_indexes");
const META = path.join(IDX_DIR, "_meta.json");

function sha256(buf) {
  return crypto.createHash("sha256").update(buf).digest("hex");
}

/**
 * Confirm every derived index OUTPUT exists, is a real file, and parses as JSON.
 * Returns human-readable issue strings (empty = all good).
 */
function verifyOutputs(idxDir, outputs) {
  const issues = [];
  // O_NOFOLLOW plus a single descriptor: the open atomically refuses a symlinked
  // index path (ELOOP) and every read rides the same fd, so there is no
  // existsSync->lstat->readFileSync TOCTOU. Where unavailable the flag is 0.
  const O_NOFOLLOW = fs.constants.O_NOFOLLOW || 0;
  for (const file of outputs) {
    const abs = path.join(idxDir, file);
    let fd;
    try {
      fd = fs.openSync(abs, fs.constants.O_RDONLY | O_NOFOLLOW);
    } catch (e) {
      if (e.code === "ELOOP") {
        issues.push(`derived index file is a symbolic link: data/_indexes/${file}`);
      } else if (e.code === "ENOENT") {
        issues.push(`derived index file missing: data/_indexes/${file} — run npm run build-indexes`);
      } else {
        issues.push(`derived index file unreadable: data/_indexes/${file} (${e.message})`);
      }
      continue;
    }
    try {
      // readFileSync(fd) loops read() to EOF — a single readSync can return fewer
      // than st.size bytes on a network fd, NUL-filling the tail.
      JSON.parse(fs.readFileSync(fd, "utf8"));
    } catch (e) {
      issues.push(`derived index file does not parse: data/_indexes/${file} (${e.message})`);
    } finally {
      fs.closeSync(fd);
    }
  }
  return issues;
}

/**
 * Compare a live source set against the recorded source_hashes table. Fail-closed:
 * a vanished source and a non-string recorded hash are both REPORTED, never thrown.
 *
 * @param {Set<string>|string[]} liveSources  source paths discovered live
 * @param {Record<string,string>} recorded    the _meta.json source_hashes table
 * @param {(p:string)=>string} absFn          resolves a source path to absolute
 * @returns {{ drift: string[], missing: string[] }}
 */
function checkSourceHashes(liveSources, recorded, absFn) {
  const drift = [];
  const missing = [];
  const recordedKeys = new Set(Object.keys(recorded || {}));
  for (const p of liveSources) {
    if (!recordedKeys.has(p)) {
      missing.push(`new source not in index: ${p}`);
      continue;
    }
    const abs = absFn(p);
    // Open through a single O_NOFOLLOW descriptor and hash the bytes from THAT
    // descriptor: no path stat-then-read, so no check-then-use window. The fstat
    // type check refuses a dir / junction / fifo on every platform.
    let live;
    {
      let fd;
      try { fd = fs.openSync(abs, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0)); }
      catch (e) {
        if (e.code === 'ENOENT') missing.push(`source file disappeared between discovery and hashing: ${p}`);
        else if (e.code === 'ELOOP') missing.push(`source ${p} is a symbolic link — refusing to follow`);
        else missing.push(`source ${p} could not be opened: ${e.code || e.message}`);
        continue;
      }
      try {
        if (!fs.fstatSync(fd).isFile()) {
          missing.push(`source ${p} is not a regular file (symlink / dir / fifo) — refusing`);
          continue;
        }
        live = sha256(fs.readFileSync(fd));
      } catch (e) {
        missing.push(`source ${p} could not be read: ${e.code || e.message}`);
        continue;
      } finally { fs.closeSync(fd); }
    }
    const recordedHash = recorded[p];
    if (typeof recordedHash !== 'string') {
      drift.push(`hash drift: ${p} (recorded entry is not a string: ${JSON.stringify(recordedHash)}, live ${live.slice(0, 12)}…)`);
    } else if (live !== recordedHash) {
      drift.push(`hash drift: ${p} (recorded ${recordedHash.slice(0, 12)}…, live ${live.slice(0, 12)}…)`);
    }
  }
  for (const p of recordedKeys) {
    if (!(liveSources instanceof Set ? liveSources.has(p) : liveSources.includes(p))) {
      missing.push(`stale source in index (file removed): ${p}`);
    }
  }
  return { drift, missing };
}

function main() {
  if (!fs.existsSync(META)) {
    console.error("[validate-indexes] data/_indexes/_meta.json missing — run `npm run build-indexes`.");
    // `process.exitCode` + return, never process.exit(): a piped stderr write
    // can be truncated by the exit. Same for every other exit path below.
    process.exitCode = 1;
    return;
  }

  const meta = JSON.parse(fs.readFileSync(META, "utf8"));
  const recorded = meta.source_hashes || {};

  // An empty source_hashes table is a hard fail, not a "0 sources" pass: the
  // comparison loop never runs, so an empty table would advertise them current.
  if (Object.keys(recorded).length === 0) {
    console.error(
      "[validate-indexes] data/_indexes/_meta.json source_hashes is empty — " +
      "this means build-indexes did not populate the index. " +
      "Regenerate with: npm run build-indexes"
    );
    process.exitCode = 1;
    return;
  }

  const manifest = JSON.parse(fs.readFileSync(ABS("manifest.json"), "utf8"));
  const liveSources = new Set();
  liveSources.add("manifest.json");
  // This set mirrors liveSourceSet() in scripts/build-indexes.js, which hashes
  // README.md for the stale-content index; out of sync, README reads as removed.
  if (fs.existsSync(ABS("README.md"))) liveSources.add("README.md");
  // lstat, not stat: a symlinked .json under data/ would be hashed through its
  // target, letting a checkout swap the data origin without tripping the gate.
  for (const f of fs.readdirSync(ABS("data"))) {
    if (!f.endsWith(".json")) continue;
    const abs = ABS("data/" + f);
    const st = fs.lstatSync(abs);
    if (st.isSymbolicLink()) {
      console.error(
        `[validate-indexes] data/${f} is a symbolic link — refusing to follow. ` +
        `Replace with the real file or remove the entry.`
      );
      process.exitCode = 1;
      return;
    }
    liveSources.add("data/" + f);
  }
  for (const s of manifest.skills) liveSources.add(s.path);

  const { drift, missing } = checkSourceHashes(liveSources, recorded, ABS);

  // Source-hash drift alone does not catch a deleted or corrupted OUTPUT.
  // _meta.outputs is the canonical list build-indexes records; an absent list is
  // itself staleness, folded into the STALE report so hash drift still surfaces.
  const outputs = Array.isArray(meta.outputs) ? meta.outputs : null;
  if (!outputs || outputs.length === 0) {
    missing.push(
      "data/_indexes/_meta.json has no `outputs` list — rebuild with " +
      "`npm run build-indexes` so derived-index integrity can be confirmed"
    );
  } else {
    for (const issue of verifyOutputs(IDX_DIR, outputs)) missing.push(issue);
  }

  const issues = [...drift, ...missing];
  if (issues.length === 0) {
    console.log(`[validate-indexes] indexes current — ${Object.keys(recorded).length} sources hashed at ${meta.generated_at}.`);
    return;
  }

  console.error("[validate-indexes] indexes STALE:");
  for (const i of issues) console.error("  • " + i);
  console.error("[validate-indexes] regenerate with: npm run build-indexes");
  process.exitCode = 1;
}

if (require.main === module) main();

module.exports = { main, verifyOutputs, checkSourceHashes };
