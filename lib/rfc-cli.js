#!/usr/bin/env node
"use strict";

/**
 * lib/rfc-cli.js — `exceptd rfc <number>` resolver.
 *
 * Local index (whole current RFC series, offline) -> resolved cache -> one
 * datatracker lookup to disambiguate obsoleted-vs-nonexistent. Resolves an RFC
 * number to its title + status so an agent can confirm a citation (e.g. "is
 * RFC 9404 the Sieve spec?") without the datatracker. Optional --check
 * "<claimed title>" reports whether the claimed title matches.
 */

const { resolveRfc } = require("./citation-resolve.js");

// Stopwords that don't disambiguate one RFC title from another. A claimed title
// run preceded by one of these in the index title is still a clean match; a run
// preceded by a CONTENT word (e.g. "datagram" before "transport layer security")
// is the tail of a more-specific title and must NOT be accepted as a match.
const TITLE_STOPWORDS = new Set(["the", "a", "an", "of", "for", "to", "in", "on", "and", "or"]);

function normTitle(s) {
  return String(s).toLowerCase().replace(/[^a-z0-9]+/g, " ").trim();
}

/**
 * Decide whether a claimed RFC title matches the authoritative index title.
 *
 * Replaces the old lenient bidirectional substring test (`a.includes(b) ||
 * b.includes(a)`), which let "TLS" match the DTLS title (substring of "dtls")
 * and let "Transport Layer Security" match the DTLS title (tail-of-phrase).
 * The comparison is now whole-word and phrase-aware:
 *
 *   1. Every claimed token must appear as a WHOLE word in the index title
 *      (so "tls" never matches inside "dtls").
 *   2. The claimed token sequence must appear as a CONTIGUOUS run in the index
 *      title, OR the claim must cover enough of the index title (containment
 *      ratio floor) to be unambiguous.
 *   3. A contiguous run that is immediately preceded by a distinguishing
 *      CONTENT word in the index title is rejected — it is the tail of a
 *      more-specific title (the "datagram transport layer security" trap).
 *
 * Returns true / false. Only called when both a claim and an index title exist.
 */
function titleMatches(claimed, indexTitle) {
  const claimTokens = normTitle(claimed).split(" ").filter(Boolean);
  const titleTokens = normTitle(indexTitle).split(" ").filter(Boolean);
  if (claimTokens.length === 0 || titleTokens.length === 0) return false;

  // (1) Whole-word containment: every claimed token must be a standalone token
  //     in the index title. Kills the tls-inside-dtls substring false positive.
  const titleSet = new Set(titleTokens);
  for (const t of claimTokens) {
    if (!titleSet.has(t)) return false;
  }

  // Find every contiguous run of the claim inside the index title.
  const runStarts = [];
  for (let i = 0; i + claimTokens.length <= titleTokens.length; i++) {
    let hit = true;
    for (let j = 0; j < claimTokens.length; j++) {
      if (titleTokens[i + j] !== claimTokens[j]) { hit = false; break; }
    }
    if (hit) runStarts.push(i);
  }

  if (runStarts.length > 0) {
    // A single-token claim that is a whole word in the title is unambiguous on
    // its own — the whole-word check above already excluded the substring trap
    // (e.g. "tls" is NOT a token inside "dtls"), so "TLS" correctly matches the
    // 8446 title (standalone "tls" token) but not the 9147 DTLS title.
    if (claimTokens.length === 1) return true;
    // (3) For a MULTI-token run, accept only if at least one occurrence is NOT
    //     preceded by a distinguishing content word — i.e. it begins the title
    //     or is preceded only by a stopword. A run preceded solely by a content
    //     qualifier (e.g. "datagram" before "transport layer security") is the
    //     tail of a more-specific title and must not be accepted as a match.
    for (const start of runStarts) {
      if (start === 0) return true;
      const prev = titleTokens[start - 1];
      if (TITLE_STOPWORDS.has(prev)) return true;
    }
    return false;
  }

  // No contiguous run, but all tokens present out of order. Accept only when the
  // claim covers a strong majority of the index title's tokens (containment
  // ratio floor) — a few scattered tokens against a long title is ambiguous,
  // not a match.
  const ratio = claimTokens.length / titleTokens.length;
  return ratio >= 0.8;
}

async function main() {
  const argv = process.argv.slice(2);
  const flags = new Set(argv.filter((a) => a.startsWith("--")));
  // Reject unknown flags (same contract as the in-process verbs). `--check`
  // consumes the following token as its value; that value is a positional, not
  // a flag, so it isn't checked here.
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
  // --check "<claimed title>" consumes the FOLLOWING token as its value. Exclude
  // that value token by INDEX from the positional pool before selecting id, so
  // the RFC number resolves correctly regardless of flag order
  // (`rfc --check "Some Title" 9404` reads id=9404, not id="Some Title").
  const checkIdx = argv.indexOf("--check");
  const checkValueIdx = (checkIdx !== -1 && argv[checkIdx + 1] && !argv[checkIdx + 1].startsWith("--")) ? checkIdx + 1 : -1;
  const positionals = argv.filter((a, i) => !a.startsWith("--") && i !== checkValueIdx);
  const id = positionals[0];
  const pretty = flags.has("--pretty");
  const json = flags.has("--json") || pretty;

  // The claimed title is exactly the excluded value token (kept in lockstep with
  // checkValueIdx so the two never diverge); a trailing `--check` with no value
  // leaves it null.
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
  // Derive `ok` from the resolved status + title-check the same way the exit
  // code is derived below — a non-zero exit (status nonexistent OR an explicit
  // title mismatch) must carry ok:false, not the inverted ok:true the envelope
  // previously hardcoded.
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

// Only run the CLI when invoked directly (`exceptd rfc ...`). When required by a
// test the IIFE must not fire — it would read process.argv and write to stdout —
// so the pure title-match helper can be exercised in-process.
if (require.main === module) {
  main().catch((err) => {
    // A corrupt/unreadable RFC index (or any unexpected throw inside the async
    // body) becomes a rejected promise. Emit the documented {ok:false,error}
    // envelope rather than crashing with a raw stack trace, and signal failure
    // via exitCode so the event loop drains stderr before exit.
    process.stderr.write(JSON.stringify({ ok: false, verb: "rfc", error: String((err && err.message) || err) }) + "\n");
    process.exitCode = 1;
  });
}

module.exports = { titleMatches, normTitle, main };
