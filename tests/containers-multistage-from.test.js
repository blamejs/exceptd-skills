"use strict";

/**
 * Regression test for the containers collector's multi-stage FROM handling.
 *
 * Surfaced by dogfooding the `containers` playbook against the repo's own
 * docker/test.Dockerfile: a `FROM base AS predeploy` line references a
 * previously-declared build STAGE (FROM <image> AS base), not a registry
 * image — but the collector flagged it as dockerfile-from-latest /
 * dockerfile-no-digest-pin. That false-fires on any normal multi-stage
 * Dockerfile. Build-stage references must be exempt; real registry images
 * (unpinned / :latest) must still fire.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const collector = require("../lib/collectors/containers.js");

function withDockerfile(name, content, fn) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "ctr-ms-"));
  try {
    fs.writeFileSync(path.join(dir, name), content);
    return fn(collector.collect({ cwd: dir }));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

const DIGEST = "a".repeat(64);

test("a digest-pinned multi-stage Dockerfile (FROM <stage>) produces no from-latest / no-digest-pin hit", () => {
  const df = `FROM node:24-alpine3.23@sha256:${DIGEST} AS base\nRUN npm ci\nFROM base AS build\nRUN npm run build\nFROM base AS final\nUSER node\nCMD ["node","x.js"]\n`;
  withDockerfile("Dockerfile", df, (r) => {
    assert.notEqual(r.signal_overrides["dockerfile-from-latest"], "hit", "build-stage FROM must not trip from-latest");
    assert.notEqual(r.signal_overrides["dockerfile-no-digest-pin"], "hit", "build-stage FROM must not trip no-digest-pin");
    const ev = JSON.stringify(r.artifacts || {}) + JSON.stringify(r.evidence_locations || {});
    assert.doesNotMatch(ev, /FROM base/, "a FROM <stage> line must not appear in hit evidence");
  });
});

test("a real unpinned / :latest registry base STILL fires", () => {
  const df = `FROM ubuntu:latest\nRUN echo hi\n`;
  withDockerfile("Dockerfile", df, (r) => {
    assert.equal(r.signal_overrides["dockerfile-from-latest"], "hit", "FROM ubuntu:latest must still fire from-latest");
    assert.equal(r.signal_overrides["dockerfile-no-digest-pin"], "hit", "an undigested image must still fire no-digest-pin");
  });
});

test("a tagged-but-undigested registry base fires no-digest-pin but not from-latest", () => {
  const df = `FROM node:20-alpine3.23 AS base\nRUN npm ci\nUSER node\n`;
  withDockerfile("Dockerfile", df, (r) => {
    assert.equal(r.signal_overrides["dockerfile-no-digest-pin"], "hit", "an undigested registry image must fire no-digest-pin");
    assert.notEqual(r.signal_overrides["dockerfile-from-latest"], "hit", "an explicit non-latest tag must not fire from-latest");
  });
});

// ---------------------------------------------------------------------------
// ARG-interpolated FROM references. A base pinned through an ARG default is a
// legitimate pinning pattern; an unresolvable interpolation can't be proven
// to float on :latest. Both shapes false-fired before ARG resolution.
// ---------------------------------------------------------------------------

test("a digest pinned through an ARG default (FROM ${BASE}) produces no hit", () => {
  const df = `ARG BASE=node:24-alpine3.23@sha256:${DIGEST}\nFROM \${BASE}\nUSER node\n`;
  withDockerfile("Dockerfile", df, (r) => {
    assert.notEqual(r.signal_overrides["dockerfile-no-digest-pin"], "hit", "a digest carried via ARG default must not trip no-digest-pin");
    assert.notEqual(r.signal_overrides["dockerfile-from-latest"], "hit", "a digest carried via ARG default must not trip from-latest");
  });
});

test("a digest in the ARG-interpolated tag (FROM node:${V}) produces no hit", () => {
  const df = `ARG NODE_VERSION=24-alpine3.23@sha256:${DIGEST}\nFROM node:\${NODE_VERSION}\nUSER node\n`;
  withDockerfile("Dockerfile", df, (r) => {
    assert.notEqual(r.signal_overrides["dockerfile-no-digest-pin"], "hit", "a resolved digest must not trip no-digest-pin");
    assert.notEqual(r.signal_overrides["dockerfile-from-latest"], "hit", "a resolved non-latest tag must not trip from-latest");
  });
});

test("an ARG default with a plain tag (no digest) still fires no-digest-pin, not from-latest", () => {
  const df = `ARG NODE_VERSION=24-alpine3.23\nFROM node:\${NODE_VERSION}\nUSER node\n`;
  withDockerfile("Dockerfile", df, (r) => {
    assert.equal(r.signal_overrides["dockerfile-no-digest-pin"], "hit", "a resolved-but-undigested tag must still fire no-digest-pin");
    assert.notEqual(r.signal_overrides["dockerfile-from-latest"], "hit", "a resolved non-latest tag must not fire from-latest");
  });
});

test("an unresolvable interpolation (FROM ${IMG}, no ARG default) suppresses both signals", () => {
  const df = `FROM \${IMG}\nUSER node\n`;
  withDockerfile("Dockerfile", df, (r) => {
    assert.notEqual(r.signal_overrides["dockerfile-from-latest"], "hit", "an unknown interpolated ref can't be proven to be :latest");
    assert.notEqual(r.signal_overrides["dockerfile-no-digest-pin"], "hit", "an unknown interpolated ref may carry a build-arg digest");
  });
});
