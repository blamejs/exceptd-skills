#!/usr/bin/env node
"use strict";
/**
 * Orchestrates the release as idempotent per-phase subcommands, each enforcing
 * its own preconditions so the load-bearing ordering cannot be skipped. `help`
 * lists them.
 */

var fs = require("node:fs");
var path = require("node:path");
var childProcess = require("node:child_process");

var ROOT = path.resolve(__dirname, "..");
var REPO = "blamejs/exceptd-skills";
var PKG_NAME = "@blamejs/exceptd-skills";

var RERUN_LIMIT = 2;

// Windows resolves `npm` / `npx` as `.cmd` shims, which child_process can only
// invoke through a shell; `git`, `gh` and `node` are native exes that spawn directly.
function _needsShell(cmd) {
  if (process.platform !== "win32") return false;
  return cmd === "npm" || cmd === "npx";
}

// spawnSync with shell:true AND an args array concatenates the args without
// escaping (Node DEP0190 — an injection surface), so the shell path passes the
// whole invocation as one command string. Only npm with static token args goes there.
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

// Rewrites only the "version" line: a full JSON.stringify would reflow
// manifest.json's hand-maintained key order and formatting.
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

function _changelogTopVersion() {
  var lines = fs.readFileSync(path.join(ROOT, "CHANGELOG.md"), "utf8").split(/\r?\n/);
  for (var i = 0; i < lines.length; i++) {
    var m = lines[i].match(/^##\s+(\d+\.\d+\.\d+)\b/);
    if (m) return m[1];
  }
  return null;
}

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

// "vX.Y.Z: <subject>" for the commit and PR title. CHANGELOG entries carry no
// headline field, so the subject is the first sentence, length-capped.
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

// `git verify-commit` is the boolean GitHub's required_signatures ruleset checks;
// main is under that ruleset, so fail here rather than at push.
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

// Conversation resolution is branch-protection-required, so an unresolved
// thread is a hard merge block.
function _unresolvedThreads(prNum) {
  var q = 'query { repository(owner:"blamejs",name:"exceptd-skills") { pullRequest(number:' +
    prNum + ') { reviewThreads(first:50) { nodes { isResolved comments(first:1) ' +
    '{ nodes { author{login} body } } } } } } }';
  var rv = _capture("gh", ["api", "graphql", "-f", "query=" + q,
    "--jq", ".data.repository.pullRequest.reviewThreads.nodes | map(select(.isResolved==false))"]);
  try { return JSON.parse(rv.stdout || "[]"); } catch (_e) { return []; }
}

// Open CodeQL alerts. Returns the alert array, or null when the query cannot run
// at all, so a transient API failure fails OPEN rather than blocking a release.
// The union of two refs is required: refs/pull/<N>/merge misses an alert already
// sitting on main, and the default-branch query misses one this PR introduces.
// tool_name=CodeQL excludes Scorecard's accepted-out-of-scope policy alerts.
function _codeqlAlertsForRef(ref) {
  var args = ["api", "repos/:owner/:repo/code-scanning/alerts", "-X", "GET",
    "-f", "state=open", "-f", "tool_name=CodeQL", "-f", "per_page=100"];
  if (ref) args.push("-f", "ref=" + ref);
  var rv = _capture("gh", args);
  if (rv.status !== 0) return null;
  try {
    var arr = JSON.parse(rv.stdout || "[]");
    return Array.isArray(arr) ? arr : null;
  } catch (_e) { return null; }
}

function _openCodeqlAlerts(prNum) {
  var onDefault = _codeqlAlertsForRef(null);
  var onPr = _codeqlAlertsForRef("refs/pull/" + prNum + "/merge");
  // A failed lookup must never read as "no alerts".
  if (onDefault === null || onPr === null) return null;

  var byNumber = new Map();
  onDefault.forEach(function (a) { byNumber.set(a.number, { alert: a, scope: "default branch" }); });
  onPr.forEach(function (a) {
    if (byNumber.has(a.number)) byNumber.get(a.number).scope = "default branch + this PR";
    else byNumber.set(a.number, { alert: a, scope: "introduced by this PR" });
  });
  return [...byNumber.values()];
}

// Shared by `prepare` and `regen` so the two cannot drift.
function _regenArtifacts() {
  _section("regen artifacts");
  // sign-all first, since it rewrites the manifest; refresh-sbom LAST, since it
  // hashes the shipped tree (README included) and any later edit strands the hashes.
  _run("node", ["lib/sign.js", "sign-all"]);
  _run("npm", ["run", "build-indexes"]);
  _run("npm", ["run", "refresh-snapshot"]);
  _run("npm", ["run", "refresh-sbom"]);
  _ok("signed + indexes + snapshot + sbom regenerated");
}

// Re-derives artifacts after editing an already-prepared release branch: no
// bump, no CHANGELOG requirement, and a dirty tree is the point.
function cmdRegen() {
  _section("regen");
  // A release branch is positively required rather than main merely rejected: a
  // feature branch or detached HEAD would build artifacts out of the wrong tree.
  if (!_gitOnRelease()) {
    throw new Error("release: regen must run on a release-vX.Y.Z branch (on " + _gitBranch() + "). " +
      "On main the regeneration belongs to `prepare`.");
  }
  var dirty = _capture("git", ["status", "--porcelain"]).stdout.split(/\r?\n/).filter(function (l) { return l.trim(); });
  if (!dirty.length) console.log("working tree is clean — regenerating anyway (artifacts may be stale from an earlier commit)");
  else {
    console.log("regenerating against " + dirty.length + " uncommitted path(s):");
    dirty.forEach(function (l) { console.log("  " + l.trim()); });
  }
  _regenArtifacts();
  console.log("\nnext: node scripts/release.js gates");
}

function cmdPrepare(opts) {
  _section("prepare");
  if (!_gitOnMain()) throw new Error("release: prepare must run on main (on " + _gitBranch() + ")");
  // The `## <next>` CHANGELOG entry is written by hand before prepare runs, so a
  // CHANGELOG.md-only dirty tree is allowed and anything else is refused.
  // `--with-content` widens that to a release which SHIPS uncommitted work, and
  // prints what it carries so an unintended file is visible rather than released.
  var dirty = _capture("git", ["status", "--porcelain"]).stdout
    .split(/\r?\n/)
    .filter(function (l) { return l.trim() && !/\bCHANGELOG\.md$/.test(l); });
  if (dirty.length && !opts.withContent) {
    throw new Error("release: prepare requires a clean working tree (CHANGELOG.md may be pre-edited). Also uncommitted:\n  " +
      dirty.join("\n  ") +
      "\n\nIf this release intentionally ships those changes, re-run with --with-content.");
  }
  if (dirty.length) {
    console.log("carrying " + dirty.length + " uncommitted path(s) into this release (--with-content):");
    dirty.forEach(function (l) { console.log("  " + l.trim()); });
  }

  var current = _readJsonVersion("package.json");
  var next = _bump(current, opts.minor ? "minor" : "patch");
  console.log("current: " + current + "   next: " + next + " (" + (opts.minor ? "minor" : "patch") + ")");

  // Without the entry, tests/bootstrap-mode's three-version invariant fails at gates.
  var top = _changelogTopVersion();
  if (top !== next) {
    // Throw, never process.exit: the exit can truncate a piped stdout write, and
    // `release all` must abort here. The dispatcher maps it to exit 1.
    throw new Error(
      "CHANGELOG.md top heading is '## " + top + "', expected '## " + next + "'. " +
      "Write the " + next + " entry first (terse, behavior-change framed, no internal " +
      "narrative), then re-run prepare. Example heading:  ## " + next + " — <YYYY-MM-DD>");
  }

  // The release workflow publishes this section verbatim as the GitHub Release body.
  _run("node", ["scripts/check-changelog-extract.js", next]);

  _writeJsonVersion("package.json", next);
  _writeJsonVersion("manifest.json", next);
  _ok("bumped package.json + manifest.json → " + next);

  _regenArtifacts();

  _section("test-count baseline");
  // Check BEFORE refreshing: `--update-baseline` writes whatever it observes, so
  // refreshing first rebaselines a shrunken suite downward and the shrinkage gate
  // in `gates` then compares the new count against itself.
  _run("node", ["scripts/check-test-count.js"]);
  _run("node", ["scripts/check-test-count.js", "--update-baseline"]);

  _section("codebase-patterns currency (advisory)");
  // Flags a pattern class the sibling blamejs catalog grew; never blocks.
  _run("node", ["scripts/check-codebase-patterns-currency.js"], { allowFail: true });

  console.log("\nnext: node scripts/release.js gates");
}

function cmdGates() {
  _section("gates");
  _run("npm", ["run", "predeploy"]);
  _ok("predeploy gates passed");
  console.log("\nnext: node scripts/release.js commit");
}

function cmdCommit() {
  _section("commit");
  var next = _readJsonVersion("package.json");
  var branch = _releaseBranchFor(next);
  var current = _gitBranch();

  // Resumable: a failed commit leaves the branch in place, so switch to it.
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

  // HEAD already carrying this release's commit means verify, not re-commit.
  var headSubject = _capture("git", ["log", "-1", "--pretty=%s"]).stdout;
  if (headSubject.indexOf("v" + next + ":") === 0) {
    _ok("HEAD already carries a v" + next + " commit (resume mode)");
    _verifyCommitSignature("existing");
    console.log("\nnext: node scripts/release.js push");
    return;
  }

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

  // Blocks until the checks settle; allowFail so failures are inspected below.
  _run("gh", ["pr", "checks", prNum, "--watch"], { allowFail: true });

  // Gate on check CONCLUSIONS, not only review threads. Bucket is gh's normalized
  // verdict — pass / fail / pending / skipping / cancel.
  var checksRaw = _capture("gh", ["pr", "checks", prNum, "--json", "name,bucket,link"]).stdout;
  var checks = [];
  try { checks = JSON.parse(checksRaw || "[]"); } catch (_e) { checks = []; }
  // An empty or still-pending check set is NOT a pass: `gh pr checks --watch`
  // returns immediately while the workflows are still being scheduled.
  if (checks.length === 0) {
    console.log("\nno checks have registered on this PR yet — they are probably still scheduling.");
    console.log("Wait a moment, then re-run: node scripts/release.js watch");
    process.exit(3); // allow:process-exit-after-stdout-write — maintainer-run release orchestrator; the guidance line above is human-read on a TTY, not a piped result channel
  }
  var pending = checks.filter(function (c) { return c.bucket === "pending"; });
  if (pending.length > 0) {
    console.log("\nchecks still running (" + pending.length + " of " + checks.length + "):");
    pending.forEach(function (c) { console.log("  · " + c.name); });
    console.log("\nRe-run when they settle: node scripts/release.js watch");
    process.exit(3); // allow:process-exit-after-stdout-write — maintainer-run release orchestrator; the guidance line above is human-read on a TTY, not a piped result channel
  }

  var failed = checks.filter(function (c) { return c.bucket === "fail" || c.bucket === "cancel"; });
  if (failed.length > 0) {
    console.log("\nfailed checks (" + failed.length + "):");
    failed.forEach(function (c) { console.log("  ✗ " + c.name + "  " + (c.link || "")); });
    console.log("\nFix in code, push, then re-run: node scripts/release.js watch");
    process.exit(3); // allow:process-exit-after-stdout-write — maintainer-run release orchestrator; the guidance line above is human-read on a TTY, not a piped result channel
  }

  // An open CodeQL alert blocks the release like an unresolved review thread.
  var codeqlAlerts = _openCodeqlAlerts(prNum);
  if (codeqlAlerts === null) {
    console.log("\nnote: could not query CodeQL alerts (code scanning unavailable / API error) — " +
      "verify manually per the pre-flight checklist before merge.");
  } else if (codeqlAlerts.length > 0) {
    console.log("\nopen CodeQL alerts (" + codeqlAlerts.length + "):");
    codeqlAlerts.forEach(function (e) {
      var a = e.alert;
      var loc = (a.most_recent_instance && a.most_recent_instance.location) || {};
      var sev = (a.rule && (a.rule.security_severity_level || a.rule.severity)) || "?";
      console.log("  ⚠ " + (a.rule && a.rule.id) + " [" + sev + "]  " +
        (loc.path ? loc.path + ":" + loc.start_line : "") + "  " +
        "(" + e.scope + ")  " + (a.html_url || ""));
    });
    console.log("\nThe union of the default branch and this PR's merge ref: an alert already on main " +
      "blocks the release as surely as one this PR introduces.");
    console.log("\nFix real findings in code (push, let CodeQL re-scan) OR dismiss by-design FPs with a " +
      "written reason, then re-run: node scripts/release.js watch");
    process.exit(3); // allow:process-exit-after-stdout-write — maintainer-run release orchestrator; the guidance line above is human-read on a TTY, not a piped result channel
  } else {
    _ok("zero open CodeQL alerts");
  }

  var unresolved = _unresolvedThreads(prNum);
  if (unresolved.length > 0) {
    console.log("\nunresolved review threads (" + unresolved.length + "):");
    unresolved.forEach(function (t) {
      var c = t.comments && t.comments.nodes && t.comments.nodes[0];
      if (c) console.log("  - by " + c.author.login + ": " + c.body.split("\n")[0]);
    });
    console.log("\nFix in code, push, resolve the thread, then re-run: node scripts/release.js watch");
    process.exit(3); // allow:process-exit-after-stdout-write — maintainer-run release orchestrator; the guidance line above is human-read on a TTY, not a piped result channel
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
  // A reviewer can open a thread between watch and merge.
  var unresolved = _unresolvedThreads(prNum);
  if (unresolved.length > 0) {
    throw new Error("release: refusing to merge PR #" + prNum + " — " +
      unresolved.length + " unresolved review thread(s); run watch again");
  }
  // Solo-maintainer protection requires 0 approvals; --admin covers required checks.
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

  // GUARD against tag-on-stale-HEAD: a tag on the wrong commit burns a version
  // slot, since the v* ruleset blocks tag rewrites.
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

  // `-s` forces a signed tag whatever tag.gpgsign is set to; `-a` silently
  // produces an UNSIGNED annotated tag when the config is absent. Verify before
  // pushing — an unsigned tag on origin burns the version slot.
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
  // Selects the release.yml run created by THIS tag push: gh reports the tag ref
  // as headBranch for tag-triggered runs, and event=="push" excludes
  // workflow_dispatch. The bounded retries cover GitHub registering the run.
  var tag = "v" + next;
  var runId = "";
  for (var _i = 0; _i < 30 && !runId; _i++) {
    runId = _capture("gh", ["run", "list", "--workflow=release.yml",
      "--event=push", "--json", "databaseId,headBranch,event",
      "--jq", '[.[] | select(.headBranch=="' + tag + '")] | sort_by(.databaseId) | last | .databaseId']).stdout;
    if (!runId && _i < 29) {
      _spawn(process.execPath, ["-e", "setTimeout(function(){},2000)"], { stdio: "ignore" });
    }
  }
  if (runId) {
    _run("gh", ["run", "watch", runId, "--exit-status"], { allowFail: true });
    // "The workflow failed" and "the lookup failed" are different answers: an
    // empty stdout is the second, not a verdict. Retry for a terminal state.
    var concl = "";
    var lookupOk = false;
    for (var _c = 0; _c < 5; _c++) {
      var rv = _capture("gh", ["run", "view", runId, "--json", "status,conclusion",
        "--jq", ".status + \"|\" + (.conclusion // \"\")"]);
      if (rv.status === 0 && rv.stdout) {
        var parts = rv.stdout.split("|");
        // Only a completed run WITH a non-empty conclusion counts: an in-progress
        // run reports an empty one, as does a completed one before it settles.
        if (parts[0] === "completed" && parts[1]) { concl = parts[1]; lookupOk = true; break; }
      }
      if (_c < 4) _spawn(process.execPath, ["-e", "setTimeout(function(){},3000)"], { stdio: "ignore" });
    }
    if (!lookupOk) {
      throw new Error("release: could not read a terminal conclusion for release.yml run " + runId +
        " after 5 attempts — the run may still be in progress, or the API call failed. This is an " +
        "UNANSWERED question, not a failed publish: re-run this phase, and check the run directly " +
        "with `gh run view " + runId + " --json status,conclusion,jobs` before treating the release as done.");
    }
    if (concl !== "success") {
      throw new Error("release: release.yml conclusion=" + concl +
        " — the publish workflow did not finish successfully; re-check release.yml before treating the release as done");
    }
    _ok("release.yml: success");
  } else {
    throw new Error("release: no release.yml run found for " + tag + " — the publish workflow has not started; " +
      "confirm the tag was pushed and the workflow fired before treating the release as done");
  }

  _section("verify npm");
  var npmVersion = _capture("npm", ["view", PKG_NAME, "version"]).stdout;
  console.log("npm " + PKG_NAME + ": " + (npmVersion || "(unable to query)") + "   (expected " + next + ")");
  // Positive confirmation only: an empty stdout is a mismatch, not a pass. The
  // hard failure is asserted at the end of the phase, after the tarball verify.
  if (npmVersion === next) _ok("npm matches " + next);

  _section("fresh-tarball signature verify");
  // Verifies the EXACT bytes a downstream consumer installs. A source-tree verify
  // is necessary but not sufficient — a signature can diverge at pack time. HARD
  // gate: _run throws rather than let the phase call the release clean.
  var wrapper = path.join(ROOT, "scripts", "verify-shipped-tarball.js");
  if (fs.existsSync(wrapper)) {
    _run("node", [wrapper]);
    _ok("shipped-tarball signature verified");
  } else {
    throw new Error("release: scripts/verify-shipped-tarball.js missing — cannot verify the shipped artifact");
  }

  // The workflow has finished by now, so an empty or mismatched version is not
  // propagation lag — it must not read as a completed release.
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
  console.log("  node scripts/release.js prepare [--minor] [--with-content]");
  console.log("                                              # bump + sign + indexes + snapshot + sbom + baseline");
  console.log("                                              # --with-content: release ships uncommitted work");
  console.log("  node scripts/release.js regen               # re-derive artifacts after editing a release branch");
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

var sub = process.argv[2] || "help";
var opts = {
  minor: process.argv.slice(3).indexOf("--minor") !== -1,
  withContent: process.argv.slice(3).indexOf("--with-content") !== -1,
};

try {
  switch (sub) {
    case "prepare": cmdPrepare(opts); break;
    case "regen":   cmdRegen();       break;
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
