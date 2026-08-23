#!/usr/bin/env node
"use strict";
/**
 * Bidirectional test↔subject gate. Every tests/<x>.test.js must name a real
 * subject and every subject must have a test. Subjects are derived from the
 * codebase, not a hand-maintained list.
 *
 * A FORWARD violation is a test file naming no subject; a REVERSE violation is
 * a subject with no test. --worklist writes the machine-readable list to
 * stdout; either violation exits non-zero.
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
      // A bare "index" is an alias, not a reverse-required module.
      add(base, (base === "index" ? "alias:" : "module:") + rel);
      const parent = path.basename(path.dirname(rel));
      // A parent-prefixed name (collectors-x) is an alias of the canonical
      // basename: a valid test target, never its own reverse gap.
      if (!["lib", "scripts", "orchestrator", "bin"].includes(parent)) add(parent + "-" + base, "alias:" + rel);
      const txt = read(rel);
      for (const m of txt.matchAll(/(?:^|\n)\s*(?:async\s+)?(?:function|class)\s+([A-Za-z_$][\w$]*)/g)) add(camelKebab(m[1]), "fn:" + rel);
      // Brace-balanced scan, not a non-greedy /\{([\s\S]*?)\}/ — that stops at
      // the first nested `}` and drops every export after it.
      const expAt = txt.search(/module\.exports\s*=\s*\{/);
      if (expAt >= 0) {
        const open = txt.indexOf("{", expAt);
        let depth = 0, end = -1;
        for (let k = open; k < txt.length; k++) { const ch = txt[k]; if (ch === "{") depth++; else if (ch === "}" && --depth === 0) { end = k; break; } }
        if (end > open) for (const m of txt.slice(open + 1, end).matchAll(/([A-Za-z_$][\w$]*)\s*[,:}\n]/g)) add(camelKebab(m[1]), "fn:" + rel);
      }
    }
  }
  ["lib", "orchestrator", "scripts", "bin", "sources/validators"].forEach(walkSrc);
  add("orchestrator", "module:orchestrator/index.js");
  add("cli", "module:bin/exceptd.js");
  // Vendored modules are valid test subjects but not reverse-required.
  (function walkVendor(d) { for (const e of ls(d)) { const rel = d + "/" + e.name; if (e.isDirectory()) walkVendor(rel); else if (e.name.endsWith(".js")) add(e.name.replace(/\.js$/, ""), "vendor:" + rel); } })("vendor");

  // Both dispatch forms bin/exceptd.js uses: switch-case and the `verb: () =>` table.
  const cliSrc = read("bin/exceptd.js");
  for (const m of cliSrc.matchAll(/case\s+['"]([a-z][a-z0-9-]+)['"]/g)) { add("cli-" + m[1], "cli-verb"); add(m[1], "cli-verb"); }
  for (const m of cliSrc.matchAll(/^\s*["']?([a-z][a-z0-9-]+)["']?:\s*\(\)\s*=>/gm)) { add("cli-" + m[1], "cli-verb"); add(m[1], "cli-verb"); }

  for (const e of ls("data")) if (e.isFile() && e.name.endsWith(".json")) add(e.name.replace(/\.json$/, ""), "data");
  // A zero-subject derivation throws rather than passing reverse coverage empty.
  let cveDerived = 0;
  try { const cat = JSON.parse(read("data/cve-catalog.json")); for (const k of Object.keys(cat)) if (k !== "_meta") { add(k.toLowerCase(), "cve-primitive"); cveDerived++; } }
  catch (e) { throw new Error("check-test-subjects: cannot read/parse data/cve-catalog.json — refusing to derive subjects (reverse coverage would falsely pass with no CVE coverage): " + e.message); }
  if (cveDerived === 0) throw new Error("check-test-subjects: data/cve-catalog.json yielded zero CVE entries — refusing to let reverse coverage pass with no CVE coverage.");
  // Same floor for playbooks.
  let pbDerived = 0;
  for (const e of ls("data/playbooks")) if (e.isFile() && e.name.endsWith(".json")) { const b = e.name.replace(/\.json$/, ""); add(b, "playbook-primitive"); add("playbook-" + b, "alias:playbook"); pbDerived++; }
  if (pbDerived === 0) throw new Error("check-test-subjects: data/playbooks/ yielded zero playbooks — refusing to let reverse coverage pass with no playbook coverage.");
  for (const e of ls(".github/workflows")) if (/\.ya?ml$/.test(e.name)) { const b = e.name.replace(/\.ya?ml$/, ""); add(b, "workflow"); add(b + "-workflow", "workflow"); }

  // Repo artifacts — valid test targets, but their kind is not
  // module/cve/playbook, so none of them is reverse-required.
  for (const f of ["package.json", "manifest.json", "manifest-snapshot.json", "README.md", "AGENTS.md", "SECURITY.md", "ARCHITECTURE.md", "CONTEXT.md", "CHANGELOG.md", "CONTRIBUTING.md", "CODE_OF_CONDUCT.md", "LICENSE", "NOTICE"]) {
    add(f.replace(/\.[^.]*$/, "").toLowerCase().replace(/_/g, "-"), "repo:" + f);
  }
  add("agents-md", "repo:AGENTS.md");
  add("docker", "repo:docker/test.Dockerfile");
  add("agents", "repo:agents/");
  add("playbooks", "aggregate:data/playbooks");
  add("workflows", "aggregate:.github/workflows");
  add("governance", "repo:governance-files"); // LICENSE/NOTICE/FUNDING/CoC/gitignore/gitleaks presence + integrity
  // Module floor: ls() returns [] on a read failure, so an unreadable source
  // tree would otherwise pass the gate with no module coverage.
  let moduleCount = 0;
  for (const kind of subjects.values()) if (typeof kind === "string" && kind.startsWith("module:")) moduleCount++;
  if (moduleCount === 0) throw new Error("check-test-subjects: zero source-module subjects derived (lib/orchestrator/scripts/bin unreadable?) — refusing to let reverse coverage pass with no module coverage.");
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
  // Only module, cve and playbook subjects must have a test; the rest are valid
  // targets, not requirements. Both output paths take their exit code from this.
  const reverseRequired = reverse.filter((x) => x.kind.startsWith("module:") || x.kind.startsWith("cve-primitive") || x.kind.startsWith("playbook-primitive"));
  return { subjects: subjects.size, forward, reverse, reverseRequired };
}

if (require.main === module) {
  const r = run();
  const revMods = r.reverseRequired;
  if (process.argv.includes("--worklist")) { process.stdout.write(JSON.stringify(r) + "\n"); process.exitCode = (r.forward.length || revMods.length) ? 1 : 0; }
  else {
    console.log(`[check-test-subjects] valid subjects=${r.subjects} | FORWARD violations=${r.forward.length} | REVERSE (module/cve/playbook) gaps=${revMods.length}`);
    if (r.forward.length || revMods.length) { console.log("[check-test-subjects] FAIL — run with --worklist for the full list."); process.exitCode = 1; }
    else console.log("[check-test-subjects] ok — every test maps to a subject and every subject has a test.");
  }
}
module.exports = { deriveSubjects, run };
