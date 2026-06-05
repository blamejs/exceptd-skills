#!/usr/bin/env node
"use strict";
/**
 * release.js — orchestrate the exceptd release flow as a sequence of
 * idempotent subcommands. Each subcommand performs ONE phase, prints what
 * it did, and exits with a code that's safe to script against in a terminal
 * or CI runner. It codifies the flow that CONTRIBUTING.md / the repo's
 * release notes describe step by step, so a release can't skip the
 * load-bearing ordering (CHANGELOG entry first, gates before tag, CI green
 * before tag push, GUARD before tag).
 *
 * Usage:
 *   node scripts/release.js prepare [--minor]   # bump + sign + indexes + snapshot + sbom + baseline
 *   node scripts/release.js gates               # npm test + 20-gate predeploy
 *   node scripts/release.js commit              # release branch + signed commit
 *   node scripts/release.js push                # push branch + open PR
 *   node scripts/release.js watch               # CI watch + flag unresolved review threads
 *   node scripts/release.js merge               # admin squash-merge if CLEAN + zero unresolved
 *   node scripts/release.js tag                 # GUARD + signed tag + push tag + verify
 *   node scripts/release.js release             # watch release.yml + npm/global/tarball verify
 *   node scripts/release.js all [--minor]       # all eight in sequence
 *   node scripts/release.js status              # what phase the current branch is in
 *   node scripts/release.js help                # this banner
 *
 * Pre-conditions the script enforces rather than assumes:
 *   - prepare runs only on a clean `main`, and refuses unless CHANGELOG.md
 *     already carries a `## <next-version>` heading (the operator writes the
 *     behavior-framed notes by hand; they don't auto-generate from a diff).
 *   - The three-version invariant (package.json == manifest.json ==
 *     CHANGELOG top heading) is established by prepare and re-checked by tag.
 *   - tag refuses unless local HEAD == origin/main and the version matches
 *     and no such tag exists (the GUARD that prevents tag-on-stale-HEAD).
 *
 * Patch is the default bump. --minor requires the explicit flag AND is a
 * deliberate choice — the project default is patch-only.
 *
 * The judgment-requiring parts stay manual: writing the CHANGELOG entry,
 * reviewing/fixing CI-surfaced review-thread findings (watch flags them and
 * stops), and choosing patch vs minor.
 */

var fs = require("node:fs");
var path = require("node:path");
var childProcess = require("node:child_process");

var ROOT = path.resolve(__dirname, "..");
var REPO = "blamejs/exceptd-skills";
var PKG_NAME = "@blamejs/exceptd-skills";

// Known-flaky CI jobs that warrant an auto-rerun rather than a hard fail:
// the macOS playbook-runner job and the offline-CLI F1 check both flake on
// fresh runners. watch reruns them up to twice before surfacing a failure.
var RERUN_LIMIT = 2;

// ---- Helpers -------------------------------------------------------------

// Windows resolves `npm` / `npx` as `.cmd` shims, which child_process can
// only invoke through a shell. `git`, `gh`, `node` are native exes that
// spawn directly — keeping shell off avoids the implicit arg-quoting risk.
function _needsShell(cmd) {
  if (process.platform !== "win32") return false;
  return cmd === "npm" || cmd === "npx";
}

// spawnSync with shell:true AND an args array concatenates the args without
// escaping (Node DEP0190 — a real injection surface). When a shell is needed
// (npm/npx on Windows) we instead pass the whole invocation as one command
// string with no args array, which is the correct shell-invocation form. The
// only commands routed through the shell here are npm with static token args
// (verb names + flags, no spaces), so the single-string join is unambiguous.
function _spawn(cmd, args, opts) {
  opts = opts || {};
  var useShell = _needsShell(cmd);
  var spawnCmd = cmd;
  var spawnArgs = args || [];
  if (useShell) {
    spawnCmd = [cmd].concat(args || []).join(" ");
    spawnArgs = [];
  }
  return childProcess.spawnSync(spawnCmd, spawnArgs, {
    cwd: opts.cwd || ROOT,
    stdio: opts.stdio || "inherit",
    env: Object.assign({}, process.env, opts.env || {}),
    shell: useShell,
  });
}

function _run(cmd, args, opts) {
  opts = opts || {};
  var rv = _spawn(cmd, args, { cwd: opts.cwd, stdio: opts.stdio || "inherit", env: opts.env });
  if (rv.status !== 0 && !opts.allowFail) {
    throw new Error("release: " + cmd + " " + (args || []).join(" ") +
      " failed with status " + rv.status);
  }
  return rv;
}

function _capture(cmd, args, opts) {
  opts = opts || {};
  var rv = _spawn(cmd, args, { cwd: opts.cwd, stdio: ["ignore", "pipe", "pipe"], env: opts.env });
  return {
    status: rv.status,
    stdout: (rv.stdout || "").toString().trim(),
    stderr: (rv.stderr || "").toString().trim(),
  };
}

function _section(title) { console.log("\n=== " + title + " ==="); }
function _ok(msg) { console.log("ok: " + msg); }

function _readJsonVersion(file) {
  return JSON.parse(fs.readFileSync(path.join(ROOT, file), "utf8")).version;
}

// Rewrite only the top-level "version" line so formatting/key-order of the
// rest of the file is untouched (a full JSON.stringify would reflow
// manifest.json's hand-maintained shape).
function _writeJsonVersion(file, next) {
  var p = path.join(ROOT, file);
  var content = fs.readFileSync(p, "utf8");
  var updated = content.replace(/"version":\s*"[^"]+"/, '"version": "' + next + '"');
  if (updated === content) {
    throw new Error("release: failed to rewrite " + file + " version line");
  }
  fs.writeFileSync(p, updated);
}

function _bump(version, kind) {
  var parts = version.split(".").map(Number);
  if (parts.length !== 3 || parts.some(isNaN)) {
    throw new Error("release: unparseable current version '" + version + "'");
  }
  if (kind === "minor") return parts[0] + "." + (parts[1] + 1) + ".0";
  return parts[0] + "." + parts[1] + "." + (parts[2] + 1);
}

// Topmost `## X.Y.Z` heading in CHANGELOG.md.
function _changelogTopVersion() {
  var lines = fs.readFileSync(path.join(ROOT, "CHANGELOG.md"), "utf8").split(/\r?\n/);
  for (var i = 0; i < lines.length; i++) {
    var m = lines[i].match(/^##\s+(\d+\.\d+\.\d+)\b/);
    if (m) return m[1];
  }
  return null;
}

// Extract the body of a CHANGELOG section (between its `## X.Y.Z` heading
// and the next `## ` heading) — used to compose the commit + PR body.
function _changelogSection(version) {
  var lines = fs.readFileSync(path.join(ROOT, "CHANGELOG.md"), "utf8").split(/\r?\n/);
  var out = [];
  var inSection = false;
  for (var i = 0; i < lines.length; i++) {
    if (/^##\s+/.test(lines[i])) {
      if (inSection) break;
      var m = lines[i].match(/^##\s+(\d+\.\d+\.\d+)\b/);
      if (m && m[1] === version) { inSection = true; continue; }
    } else if (inSection) {
      out.push(lines[i]);
    }
  }
  return out.join("\n").trim();
}

// Derive a concise "vX.Y.Z: <subject>" commit/PR title from a CHANGELOG
// section. exceptd's entries lead with a prose paragraph (no dedicated
// headline field), so take the first SENTENCE and cap the length rather than
// dump the whole paragraph as the subject. The operator can always amend.
function _releaseSubject(version, section) {
  var firstLine = (section.split(/\r?\n/).find(function (l) { return l.trim(); }) || "").trim();
  var firstSentence = firstLine.split(/(?<=[.!?])\s/)[0] || firstLine;
  var subject = "v" + version + ": " + firstSentence.replace(/[.!?]$/, "");
  if (subject.length > 72) subject = subject.slice(0, 69).replace(/\s+\S*$/, "") + "…";
  return subject;
}

function _gitClean() { return _capture("git", ["status", "--porcelain"]).stdout === ""; }
function _gitBranch() { return _capture("git", ["rev-parse", "--abbrev-ref", "HEAD"]).stdout; }
function _gitOnMain() { return _gitBranch() === "main"; }
function _gitOnRelease() { return /^release-v\d+\.\d+\.\d+$/.test(_gitBranch()); }
function _releaseBranchFor(version) { return "release-v" + version; }

// Verify HEAD's commit signature two independent ways: `git verify-commit`
// (the canonical boolean GitHub's required_signatures ruleset checks) and a
// human-readable `%G? %GS` line. main is under required_signatures, so an
// unsigned commit can't be pushed — fail loudly here rather than at push.
function _verifyCommitSignature(label) {
  var verify = _capture("git", ["verify-commit", "HEAD"]);
  if (verify.status !== 0) {
    var hint = "release: " + label + " commit signature is not Good — check SSH " +
      "signing setup (commit.gpgsign=true + gpg.format=ssh + the public key " +
      "registered as a GitHub signing key).";
    if (verify.stderr) hint += "\n" + verify.stderr;
    throw new Error(hint);
  }
  var sig = _capture("git", ["log", "-1", "--pretty=%h %G? %GS"]);
  console.log("signature: " + (sig.stdout || "(empty — verify-commit reports Good)"));
  _ok(label + " commit signature verified");
}

function _openPrNumber(branch) {
  return _capture("gh", ["pr", "list", "--head", branch, "--state", "open",
    "--json", "number", "--jq", ".[0].number"]).stdout;
}

// Unresolved review threads on the PR. Codex (chatgpt-codex-connector) posts
// review threads with P-badge findings; an unresolved thread is a hard
// branch-protection merge block (conversation-resolution required).
function _unresolvedThreads(prNum) {
  var q = 'query { repository(owner:"blamejs",name:"exceptd-skills") { pullRequest(number:' +
    prNum + ') { reviewThreads(first:50) { nodes { isResolved comments(first:1) ' +
    '{ nodes { author{login} body } } } } } } }';
  var rv = _capture("gh", ["api", "graphql", "-f", "query=" + q,
    "--jq", ".data.repository.pullRequest.reviewThreads.nodes | map(select(.isResolved==false))"]);
  try { return JSON.parse(rv.stdout || "[]"); } catch (_e) { return []; }
}

// ---- Subcommands ---------------------------------------------------------

function cmdPrepare(opts) {
  _section("prepare");
  if (!_gitOnMain()) throw new Error("release: prepare must run on main (on " + _gitBranch() + ")");
  // The documented flow is: write the `## <next>` CHANGELOG entry by hand,
  // THEN run prepare. That edit makes the tree dirty, so requiring a fully
  // clean tree here would make the first phase unusable as documented. Allow
  // a CHANGELOG.md-only dirty tree; refuse if anything else is uncommitted
  // (prepare is about to bump versions + regenerate artifacts — it must start
  // from an otherwise-clean main so the release commit captures only the
  // intended change set).
  var dirty = _capture("git", ["status", "--porcelain"]).stdout
    .split(/\r?\n/)
    .filter(function (l) { return l.trim() && !/\bCHANGELOG\.md$/.test(l); });
  if (dirty.length) {
    throw new Error("release: prepare requires a clean working tree (CHANGELOG.md may be pre-edited). Also uncommitted:\n  " +
      dirty.join("\n  "));
  }

  var current = _readJsonVersion("package.json");
  var next = _bump(current, opts.minor ? "minor" : "patch");
  console.log("current: " + current + "   next: " + next + " (" + (opts.minor ? "minor" : "patch") + ")");

  // The CHANGELOG entry is written by hand (behavior-framed, no internal
  // narrative). Refuse if it isn't there — the three-version invariant the
  // bootstrap-mode test enforces would otherwise fail at gates time.
  var top = _changelogTopVersion();
  if (top !== next) {
    console.error("");
    console.error("release: CHANGELOG.md top heading is '## " + top + "', expected '## " + next + "'.");
    console.error("Write the " + next + " entry first (terse, behavior-change framed, no internal");
    console.error("narrative), then re-run prepare. Example heading:");
    console.error("");
    console.error("  ## " + next + " — <YYYY-MM-DD>");
    console.error("");
    process.exit(2);
  }

  // The `## <next>` heading exists; confirm the section extracts cleanly and
  // passes the operator-facing lint (the release workflow publishes it verbatim
  // as the GitHub Release body). Fail fast here rather than at the gates phase.
  _run("node", ["scripts/check-changelog-extract.js", next]);

  _writeJsonVersion("package.json", next);
  _writeJsonVersion("manifest.json", next);
  _ok("bumped package.json + manifest.json → " + next);

  _section("regen artifacts");
  // Order matters: sign first (re-signs the manifest), then the snapshot/
  // index/SBOM derivations. refresh-sbom runs LAST because it hashes the
  // shipped tree (incl. README) — regenerating it before a later source edit
  // strands the hashes (the recurring "refresh-sbom last" lesson).
  _run("node", ["lib/sign.js", "sign-all"]);
  _run("npm", ["run", "build-indexes"]);
  _run("npm", ["run", "refresh-snapshot"]);
  _run("npm", ["run", "refresh-sbom"]);
  _ok("signed + indexes + snapshot + sbom regenerated");

  _section("test-count baseline");
  // Growth is fine (the gate only fails on shrinkage), but refreshing keeps
  // the canonical-count guard meaningful when a release adds test files.
  _run("node", ["scripts/check-test-count.js", "--update-baseline"]);

  _section("codebase-patterns currency (advisory)");
  // Flag when the upstream pattern catalog (the sibling blamejs codebase-
  // patterns test) has grown a class exceptd hasn't triaged yet — the same
  // forcing function the actions/vendor currency checks give those surfaces.
  // Advisory: never blocks; skips cleanly when the sibling repo is absent.
  _run("node", ["scripts/check-codebase-patterns-currency.js"], { allowFail: true });

  console.log("\nnext: node scripts/release.js gates");
}

function cmdGates() {
  _section("gates");
  // predeploy runs the full suite + every publish gate (signatures, catalog
  // schema, snapshot, lint, sbom currency, indexes, tarball verify, diff
  // coverage, ...). It is the authoritative pre-publish check.
  _run("npm", ["run", "predeploy"]);
  _ok("predeploy gates passed");
  console.log("\nnext: node scripts/release.js commit");
}

function cmdCommit() {
  _section("commit");
  var next = _readJsonVersion("package.json");
  var branch = _releaseBranchFor(next);
  var current = _gitBranch();

  // Resumable: a prior commit that failed after `checkout -b` leaves the
  // branch in place — switch to it instead of refusing.
  if (current === branch) {
    _ok("already on " + branch + " (resume mode)");
  } else if (current === "main") {
    var exists = _capture("git", ["rev-parse", "--verify", "--quiet", branch]).status === 0;
    if (exists) {
      _run("git", ["checkout", branch]);
      _ok("checked out existing " + branch + " (resume mode)");
    } else {
      _run("git", ["checkout", "-b", branch]);
      _ok("created " + branch);
    }
  } else {
    throw new Error("release: commit must run on main or " + branch + " (on " + current + ")");
  }

  // If HEAD already carries this release's commit, don't double-commit —
  // just verify the signature.
  var headSubject = _capture("git", ["log", "-1", "--pretty=%s"]).stdout;
  if (headSubject.indexOf("v" + next + ":") === 0) {
    _ok("HEAD already carries a v" + next + " commit (resume mode)");
    _verifyCommitSignature("existing");
    console.log("\nnext: node scripts/release.js push");
    return;
  }

  // Compose the commit body from the CHANGELOG section — the operator can
  // amend, but the default mirrors the shipped notes.
  var section = _changelogSection(next);
  var subject = _releaseSubject(next, section);
  var bodyPath = path.join(ROOT, ".scratch");
  try { fs.mkdirSync(bodyPath, { recursive: true }); } catch (_e) { /* ignore */ }
  var msgFile = path.join(bodyPath, "release-commit-msg.txt");
  fs.writeFileSync(msgFile, subject + "\n\n" + section + "\n");

  _run("git", ["add", "-A"]);
  _run("git", ["commit", "-F", msgFile]);
  _ok("signed commit: " + subject);
  _verifyCommitSignature("new");
  console.log("\nnext: node scripts/release.js push");
}

function cmdPush() {
  _section("push");
  if (!_gitOnRelease()) throw new Error("release: push must run on a release-vX.Y.Z branch");
  var next = _readJsonVersion("package.json");
  var branch = _releaseBranchFor(next);

  _run("git", ["push", "-u", "origin", branch]);
  _ok("pushed " + branch);

  if (_openPrNumber(branch)) {
    _ok("PR already open for " + branch + " (resume mode)");
  } else {
    var section = _changelogSection(next);
    var title = _releaseSubject(next, section);
    _run("gh", ["pr", "create", "--base", "main", "--head", branch,
      "--title", title, "--body", section]);
    _ok("PR opened");
  }
  console.log("\nnext: node scripts/release.js watch");
}

function cmdWatch() {
  _section("watch");
  var branch = _releaseBranchFor(_readJsonVersion("package.json"));
  var prNum = _openPrNumber(branch);
  if (!prNum) throw new Error("release: no open PR for " + branch);
  console.log("PR #" + prNum);

  // gh pr checks --watch blocks until checks settle. allowFail so a flaky
  // run doesn't throw before we get to inspect + rerun it.
  _run("gh", ["pr", "checks", prNum, "--watch"], { allowFail: true });

  // Gate on check CONCLUSIONS, not only review threads. A red required check
  // leaves the PR BLOCKED at merge, so surfacing failures here (the whole
  // point of the watch phase) beats advancing to "next: merge" and letting
  // cmdMerge reject it. Bucket is gh's normalized verdict: pass / fail /
  // pending / skipping / cancel.
  var checksRaw = _capture("gh", ["pr", "checks", prNum, "--json", "name,bucket,link"]).stdout;
  var checks = [];
  try { checks = JSON.parse(checksRaw || "[]"); } catch (_e) { checks = []; }
  var failed = checks.filter(function (c) { return c.bucket === "fail" || c.bucket === "cancel"; });
  if (failed.length > 0) {
    console.log("\nfailed checks (" + failed.length + "):");
    failed.forEach(function (c) { console.log("  ✗ " + c.name + "  " + (c.link || "")); });
    console.log("\nFix in code, push, then re-run: node scripts/release.js watch");
    process.exit(3);
  }

  var unresolved = _unresolvedThreads(prNum);
  if (unresolved.length > 0) {
    console.log("\nunresolved review threads (" + unresolved.length + "):");
    unresolved.forEach(function (t) {
      var c = t.comments && t.comments.nodes && t.comments.nodes[0];
      if (c) console.log("  - by " + c.author.login + ": " + c.body.split("\n")[0]);
    });
    console.log("\nFix in code, push, resolve the thread, then re-run: node scripts/release.js watch");
    process.exit(3);
  }
  _ok("zero unresolved review threads");
  console.log("\nnext: node scripts/release.js merge");
}

function cmdMerge() {
  _section("merge");
  var next = _readJsonVersion("package.json");
  var branch = _releaseBranchFor(next);
  var prNum = _openPrNumber(branch);
  if (!prNum) throw new Error("release: no open PR for " + branch);

  var state = JSON.parse(_capture("gh", ["pr", "view", prNum,
    "--json", "mergeStateStatus,mergeable"]).stdout || "{}");
  if (state.mergeStateStatus !== "CLEAN" || state.mergeable !== "MERGEABLE") {
    throw new Error("release: PR #" + prNum + " not mergeable (state=" +
      state.mergeStateStatus + " mergeable=" + state.mergeable + ")");
  }
  // Re-check threads right before merge — a reviewer (or Codex) can open one
  // between watch and merge.
  var unresolved = _unresolvedThreads(prNum);
  if (unresolved.length > 0) {
    throw new Error("release: refusing to merge PR #" + prNum + " — " +
      unresolved.length + " unresolved review thread(s); run watch again");
  }
  // Solo-maintainer protection requires 0 approvals; --admin satisfies the
  // remaining required checks gate without a second reviewer.
  _run("gh", ["pr", "merge", prNum, "--squash", "--admin", "--delete-branch"]);
  _ok("PR #" + prNum + " squash-merged");

  _run("git", ["checkout", "main"]);
  _run("git", ["pull", "origin", "main"]);
  console.log("\nnext: node scripts/release.js tag");
}

function cmdTag() {
  _section("tag");
  if (!_gitOnMain()) throw new Error("release: tag must run on main (post-merge)");
  var next = _readJsonVersion("package.json");
  var tag = "v" + next;

  // GUARD against tag-on-stale-HEAD: a transient git index lock can leave
  // local HEAD behind origin/main after a merge, so a tag would land on the
  // wrong commit and the release workflow's version-match gate would reject
  // it (burning a version slot, since the v* ruleset blocks tag rewrites).
  try { fs.rmSync(path.join(ROOT, ".git", "index.lock"), { force: true }); } catch (_e) { /* ignore */ }
  _run("git", ["fetch", "origin", "main"]);
  var local = _capture("git", ["rev-parse", "HEAD"]).stdout;
  var origin = _capture("git", ["rev-parse", "origin/main"]).stdout;
  if (local !== origin) {
    throw new Error("release: GUARD failed — local HEAD (" + local.slice(0, 12) +
      ") != origin/main (" + origin.slice(0, 12) + "). Sync before tagging.");
  }
  // Three-version invariant must hold at tag time.
  var manifest = _readJsonVersion("manifest.json");
  var changelog = _changelogTopVersion();
  if (manifest !== next || changelog !== next) {
    throw new Error("release: GUARD failed — version skew (package=" + next +
      " manifest=" + manifest + " changelog=" + changelog + ")");
  }
  if (_capture("git", ["tag", "-l", tag]).stdout === tag) {
    throw new Error("release: tag " + tag + " already exists locally");
  }
  if (_capture("git", ["ls-remote", "--tags", "origin", tag]).stdout) {
    throw new Error("release: tag " + tag + " already exists on origin");
  }
  _ok("GUARD passed (HEAD==origin/main, 3-version match, no existing tag)");

  // `-s` forces a signed tag regardless of whether tag.gpgsign is set in
  // config; `-a` would silently produce an UNSIGNED annotated tag when the
  // config is absent, and main's tag ruleset / the release provenance both
  // expect a signature. Verify BEFORE pushing so an unsigned tag never
  // reaches origin (the v* ruleset blocks tag rewrites, so a bad push would
  // burn the version slot).
  _run("git", ["tag", "-s", tag, "-m", tag]);
  var verify = _capture("git", ["tag", "-v", tag]);
  if (verify.stderr.indexOf("Good") === -1 && verify.stdout.indexOf("Good") === -1) {
    _run("git", ["tag", "-d", tag], { allowFail: true });
    throw new Error("release: tag " + tag + " is not a Good signature — refusing to push.\n" +
      "Check SSH tag signing (tag.gpgsign=true + gpg.format=ssh + the public key registered as a GitHub signing key).\n" +
      (verify.stderr || verify.stdout));
  }
  _ok("tag signature: Good (verified before push)");
  _run("git", ["push", "origin", tag]);
  _ok("tagged + pushed " + tag);
  console.log("\nnext: node scripts/release.js release");
}

function cmdRelease() {
  _section("release");
  var next = _readJsonVersion("package.json");

  _section("release workflow");
  var runId = _capture("gh", ["run", "list", "--workflow=release.yml", "--limit", "1",
    "--json", "databaseId", "--jq", ".[0].databaseId"]).stdout;
  if (runId) {
    _run("gh", ["run", "watch", runId, "--exit-status"], { allowFail: true });
    var concl = _capture("gh", ["run", "view", runId, "--json", "conclusion", "--jq", ".conclusion"]).stdout;
    // A non-success conclusion is a hard failure: the publish either failed or
    // is unconfirmable, and either way the release is not done. Warning-and-
    // continuing let a stalled publish read as a clean release.
    if (concl !== "success") {
      throw new Error("release: release.yml conclusion=" + (concl || "(unknown)") +
        " — the publish workflow did not finish successfully; re-check release.yml before treating the release as done");
    }
    _ok("release.yml: success");
  } else {
    throw new Error("release: no release.yml run found for the tag — the publish workflow has not started; " +
      "confirm the tag was pushed and the workflow fired before treating the release as done");
  }

  _section("verify npm");
  var npmVersion = _capture("npm", ["view", PKG_NAME, "version"]).stdout;
  console.log("npm " + PKG_NAME + ": " + (npmVersion || "(unable to query)") + "   (expected " + next + ")");
  // Require a POSITIVE confirmation: the queried npm version must equal `next`.
  // The hard failure is asserted at the end of the phase (after the tarball
  // verify). An empty stdout (registry/auth/network failure) is treated as a
  // mismatch — an unconfirmable publish is a failure, not a success.
  if (npmVersion === next) _ok("npm matches " + next);

  _section("fresh-tarball signature verify");
  // Verify against the EXACT bytes a downstream consumer installs — the
  // source-tree verify is necessary-but-insufficient (the v0.11.x signature
  // regression was invisible until a fresh install). Packs, extracts, and
  // runs lib/verify.js against the extracted tree. This is the load-bearing
  // post-publish check: a broken artifact/signature here means the release
  // is broken, so it is a HARD gate — _run (no allowFail) throws on failure
  // and the phase exits non-zero rather than reporting a clean release.
  var wrapper = path.join(ROOT, "scripts", "verify-shipped-tarball.js");
  if (fs.existsSync(wrapper)) {
    _run("node", [wrapper]);
    _ok("shipped-tarball signature verified");
  } else {
    throw new Error("release: scripts/verify-shipped-tarball.js missing — cannot verify the shipped artifact");
  }

  // Require a positive npm confirmation after the workflow finished. A version
  // that is empty (query failed) OR != next is not mere propagation lag — fail
  // so a stalled/failed/unconfirmable publish can't read as a completed
  // release. (A genuinely in-flight publish is caught by the workflow-
  // conclusion check above; by the time we query npm post-watch the version
  // should be live.) The message reports the value actually queried.
  if (npmVersion !== next) {
    throw new Error("release: npm shows " + (npmVersion || "(unable to query)") + " but expected " + next +
      " — publish did not complete or could not be confirmed; re-check release.yml before treating the release as done");
  }

  console.log("\nThe landing site auto-injects the version from jsDelivr @latest — no manual deploy.");
  console.log("Release complete: npm shows " + npmVersion + " and the shipped tarball verifies.");
}

function cmdAll(opts) {
  cmdPrepare(opts);
  cmdGates();
  cmdCommit();
  cmdPush();
  cmdWatch();
  cmdMerge();
  cmdTag();
  cmdRelease();
}

function cmdStatus() {
  _section("status");
  console.log("branch:           " + _gitBranch());
  console.log("clean:            " + _gitClean());
  console.log("package version:  " + _readJsonVersion("package.json"));
  console.log("manifest version: " + _readJsonVersion("manifest.json"));
  console.log("changelog top:    " + _changelogTopVersion());
  var pr = _openPrNumber(_releaseBranchFor(_readJsonVersion("package.json")));
  console.log("open PR:          " + (pr || "(none)"));
}

function cmdHelp() {
  console.log("release.js — orchestrated exceptd release flow");
  console.log("");
  console.log("Usage:");
  console.log("  node scripts/release.js prepare [--minor]   # bump + sign + indexes + snapshot + sbom + baseline");
  console.log("  node scripts/release.js gates               # npm test + 20-gate predeploy");
  console.log("  node scripts/release.js commit              # release branch + signed commit");
  console.log("  node scripts/release.js push                # push branch + open PR");
  console.log("  node scripts/release.js watch               # CI watch + flag unresolved review threads");
  console.log("  node scripts/release.js merge               # admin squash-merge if CLEAN");
  console.log("  node scripts/release.js tag                 # GUARD + signed tag + push tag");
  console.log("  node scripts/release.js release             # watch release.yml + npm/tarball verify");
  console.log("  node scripts/release.js all [--minor]       # all eight in sequence");
  console.log("  node scripts/release.js status              # current branch + version state");
  console.log("  node scripts/release.js help                # this banner");
  console.log("");
  console.log("Patch is the default. --minor is a deliberate, explicit choice.");
}

// ---- Dispatch ------------------------------------------------------------

var sub = process.argv[2] || "help";
var opts = { minor: process.argv.slice(3).indexOf("--minor") !== -1 };

try {
  switch (sub) {
    case "prepare": cmdPrepare(opts); break;
    case "gates":   cmdGates();       break;
    case "commit":  cmdCommit();      break;
    case "push":    cmdPush();        break;
    case "watch":   cmdWatch();       break;
    case "merge":   cmdMerge();       break;
    case "tag":     cmdTag();         break;
    case "release": cmdRelease();     break;
    case "all":     cmdAll(opts);     break;
    case "status":  cmdStatus();      break;
    case "help":
    case "--help":
    case "-h":      cmdHelp();        break;
    default:
      console.error("release: unknown subcommand '" + sub + "'");
      cmdHelp();
      process.exitCode = 1;
  }
} catch (e) {
  console.error("\nrelease: FAIL — " + (e.message || e));
  process.exitCode = 1;
}
