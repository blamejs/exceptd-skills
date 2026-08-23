#!/usr/bin/env node
"use strict";

/**
 * `exceptd rfc <number>` — resolves an RFC number to its title and status:
 * local index, then resolved cache, then one datatracker lookup to separate
 * obsoleted from nonexistent.
 */

const { resolveRfc } = require("./citation-resolve.js");

// Stopwords don't disambiguate one RFC title from another.
const TITLE_STOPWORDS = new Set(["the", "a", "an", "of", "for", "to", "in", "on", "and", "or"]);

function normTitle(s) {
  return String(s).toLowerCase().replace(/[^a-z0-9]+/g, " ").trim();
}

/**
 * Whole-word, phrase-aware comparison of a claimed RFC title against the
 * authoritative index title. Called only when both exist.
 */
function titleMatches(claimed, indexTitle) {
  const claimTokens = normTitle(claimed).split(" ").filter(Boolean);
  const titleTokens = normTitle(indexTitle).split(" ").filter(Boolean);
  if (claimTokens.length === 0 || titleTokens.length === 0) return false;

  const titleSet = new Set(titleTokens);
  for (const t of claimTokens) {
    if (!titleSet.has(t)) return false;
  }

  const runStarts = [];
  for (let i = 0; i + claimTokens.length <= titleTokens.length; i++) {
    let hit = true;
    for (let j = 0; j < claimTokens.length; j++) {
      if (titleTokens[i + j] !== claimTokens[j]) { hit = false; break; }
    }
    if (hit) runStarts.push(i);
  }

  if (runStarts.length > 0) {
    // A single-token claim that survived the whole-word check is unambiguous on
    // its own — "tls" is not a token inside "dtls".
    if (claimTokens.length === 1) return true;
    // A multi-token run counts only where some occurrence begins the title or
    // is preceded by a stopword. Preceded by a content qualifier ("datagram"
    // before "transport layer security") it is the tail of a different title.
    for (const start of runStarts) {
      if (start === 0) return true;
      const prev = titleTokens[start - 1];
      if (TITLE_STOPWORDS.has(prev)) return true;
    }
    return false;
  }

  // No contiguous run, all tokens present out of order: accept only when the
  // claim covers a strong majority of the title's tokens. DISTINCT claim tokens
  // are counted, or a repeated-token claim inflates the ratio past the floor.
  const distinct = new Set(claimTokens);
  const present = [...distinct].filter((t) => titleSet.has(t)).length;
  const ratio = present / titleTokens.length;
  return ratio >= 0.8;
}

async function main() {
  const argv = process.argv.slice(2);
  const flags = new Set(argv.filter((a) => a.startsWith("--")));
  // Unknown flags are rejected, as in the in-process verbs. `--check` consumes
  // the following token, which is a positional and so isn't checked here.
  const KNOWN = new Set(["--json", "--pretty", "--air-gap", "--no-network", "--check", "--help", "-h"]);
  const unknown = [...flags].filter((f) => !KNOWN.has(f));
  if (unknown.length > 0) {
    process.stderr.write(JSON.stringify({
      ok: false, verb: "rfc", error: `rfc: unknown flag(s): ${unknown.join(", ")}`,
      unknown_flags: unknown, known_flags: ["--json", "--pretty", "--air-gap", "--no-network", "--check"],
    }) + "\n");
    process.exitCode = 1;
    return;
  }
  // The `--check` value token is excluded from the positional pool by INDEX, so
  // `rfc --check "Some Title" 9404` reads id=9404, not id="Some Title".
  const checkIdx = argv.indexOf("--check");
  const checkValueIdx = (checkIdx !== -1 && argv[checkIdx + 1] && !argv[checkIdx + 1].startsWith("--")) ? checkIdx + 1 : -1;
  const positionals = argv.filter((a, i) => !a.startsWith("--") && i !== checkValueIdx);
  const id = positionals[0];
  const pretty = flags.has("--pretty");
  const json = flags.has("--json") || pretty;

  // Exactly the excluded value token; a trailing `--check` with no value is null.
  let claimedTitle = null;
  if (checkValueIdx !== -1) claimedTitle = argv[checkValueIdx];

  if (!id) {
    process.stderr.write(
      JSON.stringify({ ok: false, verb: "rfc", error: "usage: exceptd rfc <number> [--check \"<claimed title>\"] [--json|--pretty] [--air-gap|--no-network]" }) + "\n"
    );
    process.exitCode = 1;
    return;
  }

  const r = await resolveRfc(id, { airGap: flags.has("--air-gap"), noNetwork: flags.has("--no-network") });

  let titleMatch = null;
  if (claimedTitle && r.title) {
    titleMatch = titleMatches(claimedTitle, r.title);
  }
  // `ok` derives from the same condition as the exit code below.
  const fails = r.status === "nonexistent" || titleMatch === false;
  const body = { verb: "rfc", ...r, ...(claimedTitle ? { claimed_title: claimedTitle, title_match: titleMatch } : {}), ok: !fails };

  if (json) {
    process.stdout.write(JSON.stringify(body, null, pretty ? 2 : 0) + "\n");
  } else {
    let line;
    if (r.found && r.title) {
      line = `RFC ${r.number}: ${r.title}`;
      if (r.rfc_status) line += `  (${r.rfc_status})`;
      if (r.obsoleted_by) line += `\n  obsoleted by: ${r.obsoleted_by}`;
      if (claimedTitle) line += `\n  claimed "${claimedTitle}" -> ${titleMatch ? "MATCH" : "MISMATCH"}`;
    } else {
      line = `RFC ${r.number ?? r.id}: ${String(r.status).toUpperCase()}`;
      if (r.note) line += `\n  ${r.note}`;
      if (r.reason) line += `\n  ${r.reason}`;
    }
    line += `  (${r.from})`;
    process.stdout.write(line + "\n");
  }
  // A mismatched or nonexistent citation is a non-zero exit for gates.
  if (fails) process.exitCode = 2;
}

// Under require it would read process.argv and write stdout; keep it testable.
if (require.main === module) {
  main().catch((err) => {
    // Any unexpected throw becomes the {ok:false,error} envelope, not a raw
    // stack; `process.exitCode`, not `process.exit()`, so stderr drains.
    process.stderr.write(JSON.stringify({ ok: false, verb: "rfc", error: String((err && err.message) || err) }) + "\n");
    process.exitCode = 1;
  });
}

module.exports = { titleMatches, normTitle, main };
