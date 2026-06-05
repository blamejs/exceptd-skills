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

(async () => {
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
  const positionals = argv.filter((a) => !a.startsWith("--"));
  const id = positionals[0];
  const pretty = flags.has("--pretty");
  const json = flags.has("--json") || pretty;

  // --check "<claimed title>" : the next non-flag token after the number.
  let claimedTitle = null;
  const checkIdx = argv.indexOf("--check");
  if (checkIdx !== -1 && argv[checkIdx + 1] && !argv[checkIdx + 1].startsWith("--")) {
    claimedTitle = argv[checkIdx + 1];
  }

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
    const norm = (s) => s.toLowerCase().replace(/[^a-z0-9]+/g, " ").trim();
    const a = norm(claimedTitle), b = norm(r.title);
    titleMatch = a.length > 0 && (b.includes(a) || a.includes(b));
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
})();
