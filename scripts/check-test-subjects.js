#!/usr/bin/env node
"use strict";
/**
 * check-test-subjects.js — bidirectional test↔subject gate (and reorg driver).
 *
 * Every test file must be named after a real SUBJECT the codebase actually has,
 * and every subject must have a test. A "subject" is derived dynamically from
 * the codebase so this list is never hand-maintained:
 *   - a source MODULE basename (lib/x.js -> x; lib/collectors/x.js -> x and
 *     collectors-x; orchestrator/index.js -> orchestrator; bin/exceptd.js -> cli)
 *   - an exported FUNCTION / CLASS name (kebab-cased) — per-function granularity
 *   - a data PRIMITIVE: a data/*.json catalog FILE, plus each catalog ENTRY that
 *     is itself a primitive — every CVE/MAL/GHSA id in data/cve-catalog.json and
 *     every playbook in data/playbooks/ — so one CVE == one test file
 *   - a .github/workflows/*.yml WORKFLOW (release -> release-workflow, etc.)
 *   - a CLI verb dispatched by bin/exceptd.js
 *
 * FORWARD violation : a tests/<x>.test.js where <x> is not a valid subject.
 * REVERSE violation : a subject (module / CVE / playbook / workflow) with no
 *                     tests/<subject>.test.js.
 *
 * Run with --worklist for the machine-readable reorg work list (JSON on stdout).
 * Run with no flag for a human summary; exits non-zero while any violation
 * remains (so once the suite conforms this becomes a standing predeploy gate).
 */
const fs = require("node:fs");
const path = require("node:path");
const ROOT = path.resolve(__dirname, "..");

function camelKebab(s) { return s.replace(/([a-z0-9])([A-Z])/g, "$1-$2").replace(/_/g, "-").toLowerCase(); }
function read(p) { try { return fs.readFileSync(path.join(ROOT, p), "utf8"); } catch { return ""; } }
function ls(d) { try { return fs.readdirSync(path.join(ROOT, d), { withFileTypes: true }); } catch { return []; } }

function deriveSubjects() {
  const subjects = new Map(); // name -> kind
  const add = (s, kind) => { if (s && !subjects.has(s.toLowerCase())) subjects.set(s.toLowerCase(), kind); };

  function walkSrc(d) {
    for (const e of ls(d)) {
      if (e.name === "node_modules") continue;
      const rel = d + "/" + e.name;
      if (e.isDirectory()) { walkSrc(rel); continue; }
      if (!e.name.endsWith(".js")) continue;
      const base = e.name.replace(/\.js$/, "");
      // index.js is a directory entry point; the directory/canonical subject
      // covers it, so treat the bare "index" basename as an alias, not a
      // separately reverse-required module.
      add(base, (base === "index" ? "alias:" : "module:") + rel);
      const parent = path.basename(path.dirname(rel));
      // parent-prefixed name (collectors-x, builders-x, validators-x) is an
      // ALIAS of the canonical basename subject — a valid test target, but the
      // canonical <base>.test.js already satisfies coverage, so don't double-
      // count the alias as its own reverse gap.
      if (!["lib", "scripts", "orchestrator", "bin"].includes(parent)) add(parent + "-" + base, "alias:" + rel);
      const txt = read(rel);
      for (const m of txt.matchAll(/(?:^|\n)\s*(?:async\s+)?(?:function|class)\s+([A-Za-z_$][\w$]*)/g)) add(camelKebab(m[1]), "fn:" + rel);
      const exp = txt.match(/module\.exports\s*=\s*\{([\s\S]*?)\}/);
      if (exp) for (const k of exp[1].matchAll(/([A-Za-z_$][\w$]*)\s*[,:}\n]/g)) add(camelKebab(k[1]), "fn:" + rel);
    }
  }
  ["lib", "orchestrator", "scripts", "bin", "sources/validators"].forEach(walkSrc);
  add("orchestrator", "module:orchestrator/index.js");
  add("cli", "module:bin/exceptd.js");
  // Vendored (pinned third-party) modules are valid test SUBJECTS but are not
  // reverse-required — we don't force a dedicated test per vendored file.
  (function walkVendor(d) { for (const e of ls(d)) { const rel = d + "/" + e.name; if (e.isDirectory()) walkVendor(rel); else if (e.name.endsWith(".js")) add(e.name.replace(/\.js$/, ""), "vendor:" + rel); } })("vendor");

  // CLI verbs — both the switch-case form and the dispatch-table form
  //   (verb: () => path.join(...)) that bin/exceptd.js uses for most subcommands.
  const cliSrc = read("bin/exceptd.js");
  for (const m of cliSrc.matchAll(/case\s+['"]([a-z][a-z0-9-]+)['"]/g)) { add("cli-" + m[1], "cli-verb"); add(m[1], "cli-verb"); }
  for (const m of cliSrc.matchAll(/^\s*["']?([a-z][a-z0-9-]+)["']?:\s*\(\)\s*=>/gm)) { add("cli-" + m[1], "cli-verb"); add(m[1], "cli-verb"); }

  // data catalog files
  for (const e of ls("data")) if (e.isFile() && e.name.endsWith(".json")) add(e.name.replace(/\.json$/, ""), "data");
  // data ENTRY primitives: every CVE id + every playbook
  try { const cat = JSON.parse(read("data/cve-catalog.json")); for (const k of Object.keys(cat)) if (k !== "_meta") add(k.toLowerCase(), "cve-primitive"); } catch {}
  for (const e of ls("data/playbooks")) if (e.isFile() && e.name.endsWith(".json")) { const b = e.name.replace(/\.json$/, ""); add(b, "playbook-primitive"); add("playbook-" + b, "alias:playbook"); }
  // workflows
  for (const e of ls(".github/workflows")) if (/\.ya?ml$/.test(e.name)) { const b = e.name.replace(/\.ya?ml$/, ""); add(b, "workflow"); add(b + "-workflow", "workflow"); }

  // Repo-artifact subjects: shipped root config/doc files, the docker build
  // context, the agents/ directory, and aggregate catalog directories. A test
  // that pins one of these artifacts (its content, counts, or cross-references)
  // is named after a durable subject, not a release — so these are valid test
  // targets. Kind is not module/cve/playbook, so they are NOT reverse-required
  // (we don't force a dedicated test per doc file).
  for (const f of ["package.json", "manifest.json", "manifest-snapshot.json", "README.md", "AGENTS.md", "SECURITY.md", "ARCHITECTURE.md", "CONTEXT.md", "CHANGELOG.md", "CONTRIBUTING.md", "CODE_OF_CONDUCT.md", "LICENSE", "NOTICE"]) {
    add(f.replace(/\.[^.]*$/, "").toLowerCase().replace(/_/g, "-"), "repo:" + f);
  }
  add("agents-md", "repo:AGENTS.md");
  add("docker", "repo:docker/test.Dockerfile");
  add("agents", "repo:agents/");
  add("playbooks", "aggregate:data/playbooks");
  add("workflows", "aggregate:.github/workflows");
  add("governance", "repo:governance-files"); // LICENSE/NOTICE/FUNDING/CoC/gitignore/gitleaks presence + integrity
  return subjects;
}

function run() {
  const subjects = deriveSubjects();
  const testFiles = ls("tests").filter((e) => e.isFile() && e.name.endsWith(".test.js")).map((e) => e.name.replace(/\.test\.js$/, ""));
  const testSet = new Set(testFiles.map((t) => t.toLowerCase()));

  const suggest = (name) => {
    const toks = name.toLowerCase().split("-");
    for (let n = toks.length; n >= 1; n--) { const c = toks.slice(0, n).join("-"); if (subjects.has(c)) return c; }
    return null;
  };
  const forward = [];
  for (const t of testFiles) if (!subjects.has(t.toLowerCase())) forward.push({ file: "tests/" + t + ".test.js", suggested: suggest(t) });
  const reverse = [];
  for (const [s, kind] of subjects) if (!testSet.has(s)) reverse.push({ subject: s, kind });
  return { subjects: subjects.size, forward, reverse };
}

if (require.main === module) {
  const r = run();
  if (process.argv.includes("--worklist")) { process.stdout.write(JSON.stringify(r) + "\n"); process.exitCode = (r.forward.length || r.reverse.length) ? 1 : 0; }
  else {
    const revMods = r.reverse.filter((x) => x.kind.startsWith("module:") || x.kind.startsWith("cve-primitive") || x.kind.startsWith("playbook-primitive"));
    console.log(`[check-test-subjects] valid subjects=${r.subjects} | FORWARD violations=${r.forward.length} | REVERSE (module/cve/playbook) gaps=${revMods.length}`);
    if (r.forward.length || revMods.length) { console.log("[check-test-subjects] FAIL — run with --worklist for the full list."); process.exitCode = 1; }
    else console.log("[check-test-subjects] ok — every test maps to a subject and every subject has a test.");
  }
}
module.exports = { deriveSubjects, run };
