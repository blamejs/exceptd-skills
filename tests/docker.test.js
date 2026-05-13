"use strict";
/**
 * Docker test harness regression tests.
 *
 * The harness lives in docker/test.Dockerfile and only exists to give
 * contributors a local Linux+Node-24.14.1 reproduction of CI. The most
 * common failure mode is silent drift: CI bumps Node but the Dockerfile
 * keeps an old tag, so "passes locally" stops meaning "passes on CI".
 * These tests fail fast on that drift.
 *
 * Docker itself is NOT invoked here. We parse the Dockerfile as text
 * and assert structural facts. A live `docker build` only happens via
 * `npm run test:docker`, which contributors run on demand.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const ROOT = path.join(__dirname, "..");
const DOCKERFILE = path.join(ROOT, "docker", "test.Dockerfile");
const DOCKERIGNORE = path.join(ROOT, ".dockerignore");
const DOCKER_README = path.join(ROOT, "docker", "README.md");
const CI_WORKFLOW = path.join(ROOT, ".github", "workflows", "ci.yml");
const PACKAGE_JSON = path.join(ROOT, "package.json");

function read(p) {
  return fs.readFileSync(p, "utf8");
}

test("docker/test.Dockerfile exists and is non-empty", () => {
  assert.ok(fs.existsSync(DOCKERFILE), "docker/test.Dockerfile is required");
  assert.ok(fs.statSync(DOCKERFILE).size > 0, "docker/test.Dockerfile not empty");
});

test("docker/README.md exists and is non-empty", () => {
  assert.ok(fs.existsSync(DOCKER_README));
  assert.ok(fs.statSync(DOCKER_README).size > 0);
});

test(".dockerignore exists and excludes the private signing key", () => {
  assert.ok(fs.existsSync(DOCKERIGNORE));
  const ign = read(DOCKERIGNORE);
  assert.match(
    ign,
    /^\.keys\/\s*$/m,
    ".dockerignore must exclude .keys/ — private signing key never enters image layers"
  );
  assert.match(
    ign,
    /^\*\.pem\s*$/m,
    ".dockerignore must exclude *.pem"
  );
  // The public key is the documented exception — same shape as
  // .gitignore so the image can ship verification material if needed.
  assert.match(
    ign,
    /^!keys\/public\.pem\s*$/m,
    ".dockerignore must allow keys/public.pem"
  );
});

test(".dockerignore excludes local bootstrap marker and node_modules", () => {
  const ign = read(DOCKERIGNORE);
  assert.match(ign, /^\.bootstrap-complete\s*$/m);
  assert.match(ign, /^node_modules\/\s*$/m);
});

test("Dockerfile pins a SPECIFIC Node version (not :latest, not :24)", () => {
  const df = read(DOCKERFILE);
  // Require an exact major.minor.patch tag. Reject :latest and bare
  // :24 / :24-alpine forms — both can silently advance and break the
  // CI/local-parity guarantee.
  // Only the external base-image FROM lines need a version pin. Internal
  // multi-stage FROMs (e.g. `FROM base AS predeploy`) reference a stage
  // and don't carry a tag.
  const baseImageFroms = df
    .split(/\r?\n/)
    .filter((l) => /^FROM\s+node:/i.test(l));

  assert.ok(
    baseImageFroms.length > 0,
    "Dockerfile must reference at least one external node: image"
  );

  for (const line of baseImageFroms) {
    assert.match(
      line,
      /node:\d+\.\d+\.\d+(?:-[a-z0-9.]+)*(?:@sha256:[a-f0-9]{64})?\s+AS\s+\S+/i,
      `external FROM must pin Node by exact major.minor.patch (optional @sha256: digest pin allowed): ${line}`
    );
    assert.doesNotMatch(
      line,
      /node:latest/i,
      `FROM must not use :latest: ${line}`
    );
  }
});

test("Dockerfile Node version matches the CI workflow Node version", () => {
  // The contract: bump both in the same commit. This test asserts the
  // invariant. A mismatch means a contributor's "passes locally on
  // Docker" no longer matches what CI will see.
  const df = read(DOCKERFILE);
  const ci = read(CI_WORKFLOW);

  const dfMatch = df.match(/node:(\d+\.\d+\.\d+)(?:-[a-z0-9.]+)*(?:@sha256:[a-f0-9]{64})?\s+AS/i);
  assert.ok(dfMatch, "Dockerfile FROM must have a parseable node:X.Y.Z tag");
  const dockerNode = dfMatch[1];

  const ciMatch = ci.match(/node-version:\s*'(\d+\.\d+\.\d+)'/);
  assert.ok(
    ciMatch,
    "ci.yml must declare an exact node-version: '24.14.1'-style version"
  );
  const ciNode = ciMatch[1];

  assert.equal(
    dockerNode,
    ciNode,
    `Dockerfile pins Node ${dockerNode} but ci.yml pins ${ciNode}. ` +
      `Bump both in the same commit so local Docker matches CI.`
  );
});

test("Dockerfile defines both predeploy and fresh-bootstrap targets", () => {
  const df = read(DOCKERFILE);
  // Multi-stage build with explicit AS labels. Each must appear at
  // least once as a stage target.
  assert.match(
    df,
    /^FROM\s+\S+\s+AS\s+base\s*$/im,
    "Dockerfile must define a `base` stage"
  );
  assert.match(
    df,
    /^FROM\s+base\s+AS\s+predeploy\s*$/im,
    "Dockerfile must define a `predeploy` stage built FROM base"
  );
  assert.match(
    df,
    /^FROM\s+base\s+AS\s+fresh-bootstrap\s*$/im,
    "Dockerfile must define a `fresh-bootstrap` stage built FROM base"
  );
});

test("Dockerfile runs as non-root user", () => {
  // Security posture: the test harness should never run as root. The
  // upstream node image ships a `node` user; we use it. A regression
  // here is small in test context but the pattern matters for the
  // image-as-template case.
  const df = read(DOCKERFILE);
  assert.match(
    df,
    /^USER\s+node\s*$/m,
    "Dockerfile must drop to the `node` non-root user"
  );
});

test("predeploy target CMD invokes `npm run predeploy`", () => {
  const df = read(DOCKERFILE);
  // The predeploy stage's CMD must be the gate-runner script. Anything
  // else means a contributor running `npm run test:docker` is not
  // actually testing what CI tests.
  const predeployStage = df.match(
    /FROM\s+base\s+AS\s+predeploy[\s\S]*?(?=\nFROM\s|$(?![\s\S]))/i
  );
  assert.ok(predeployStage, "predeploy stage must be locatable");
  assert.match(
    predeployStage[0],
    /CMD\s*\[\s*"npm"\s*,\s*"run"\s*,\s*"predeploy"\s*\]/,
    "predeploy stage CMD must be `npm run predeploy`"
  );
});

test("fresh-bootstrap target wipes inherited signing state before running", () => {
  const df = read(DOCKERFILE);
  const freshStage = df.match(
    /FROM\s+base\s+AS\s+fresh-bootstrap[\s\S]*$/i
  );
  assert.ok(freshStage, "fresh-bootstrap stage must be locatable");
  // Must strip .keys/ and the bootstrap-complete marker, AND must
  // strip per-skill signature/signed_at from manifest.json so the
  // bootstrap step actually does work. Without the manifest strip,
  // sign-all would no-op against an already-signed manifest.
  assert.match(
    freshStage[0],
    /rm\s+-rf[^\n]*\.keys/,
    "fresh-bootstrap must rm -rf .keys"
  );
  assert.match(
    freshStage[0],
    /rm\s+-rf[^\n]*\.bootstrap-complete/,
    "fresh-bootstrap must rm the bootstrap marker"
  );
  assert.match(
    freshStage[0],
    /delete s\.signature/,
    "fresh-bootstrap must strip inherited signatures from manifest.json"
  );
  // Then runs bootstrap + predeploy in sequence.
  assert.match(
    freshStage[0],
    /npm\s+run\s+bootstrap[^\n]*&&\s*npm\s+run\s+predeploy/,
    "fresh-bootstrap must chain `npm run bootstrap && npm run predeploy`"
  );
});

test("package.json declares test:docker and test:docker:fresh aliases", () => {
  const pkg = JSON.parse(read(PACKAGE_JSON));
  assert.ok(pkg.scripts["test:docker"], "test:docker script required");
  assert.ok(
    pkg.scripts["test:docker:fresh"],
    "test:docker:fresh script required"
  );
  // Sanity: each invocation builds the right target.
  assert.match(
    pkg.scripts["test:docker"],
    /--target\s+predeploy/,
    "test:docker must build the predeploy target"
  );
  assert.match(
    pkg.scripts["test:docker:fresh"],
    /--target\s+fresh-bootstrap/,
    "test:docker:fresh must build the fresh-bootstrap target"
  );
});
