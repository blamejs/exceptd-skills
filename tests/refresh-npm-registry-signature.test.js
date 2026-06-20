'use strict';

/**
 * RC-3: the `refresh --network` swap path authenticates the npm registry's
 * ECDSA signature over `<pkg>@<version>:<integrity>` against pinned registry
 * keys before trusting the metadata response — a forged metadata response
 * (man-in-the-middle on the registry) cannot reproduce this signature.
 *
 * verifyNpmRegistrySignature is a pure classifier; these pin its status
 * outcomes so the live swap path's branch (refuse on invalid/unknown-keyid,
 * warn-and-continue on absent/unverifiable) can't silently invert. The `valid`
 * outcome needs a real registry private key and is exercised end-to-end by the
 * registry, not reproducible offline.
 */

const test = require('node:test');
const assert = require('node:assert/strict');

const { verifyNpmRegistrySignature, NPM_REGISTRY_KEYS } = require('../lib/refresh-network.js');

const PINNED_KEYID = Object.keys(NPM_REGISTRY_KEYS)[0];
const INTEGRITY = 'sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==';

test('at least one npm registry key is pinned in-tree', () => {
  assert.ok(Object.keys(NPM_REGISTRY_KEYS).length >= 1, 'NPM_REGISTRY_KEYS must pin the registry signing key(s)');
  assert.match(PINNED_KEYID, /^SHA256:/, 'a pinned keyid is the registry SHA256 fingerprint form');
});

test('absent: no dist.signatures[] entries → status absent (transport hashes still gate)', () => {
  assert.equal(verifyNpmRegistrySignature('pkg', '1.0.0', INTEGRITY, []).status, 'absent');
  assert.equal(verifyNpmRegistrySignature('pkg', '1.0.0', INTEGRITY, null).status, 'absent');
  assert.equal(verifyNpmRegistrySignature('pkg', '1.0.0', INTEGRITY, undefined).status, 'absent');
});

test('unverifiable: missing integrity → no canonical message to verify over', () => {
  const sigs = [{ keyid: PINNED_KEYID, sig: 'AAAA' }];
  assert.equal(verifyNpmRegistrySignature('pkg', '1.0.0', '', sigs).status, 'unverifiable');
  assert.equal(verifyNpmRegistrySignature('pkg', '1.0.0', null, sigs).status, 'unverifiable');
});

test('unknown-keyid: a signature keyid that is not pinned → forged-metadata signal (refused upstream)', () => {
  const r = verifyNpmRegistrySignature('pkg', '1.0.0', INTEGRITY, [
    { keyid: 'SHA256:not-a-pinned-registry-key', sig: 'AAAA' },
  ]);
  assert.equal(r.status, 'unknown-keyid');
  assert.equal(r.keyid, 'SHA256:not-a-pinned-registry-key');
});

test('invalid: a pinned keyid whose signature does not verify → tampering (refused upstream)', () => {
  // A syntactically-valid base64 signature that is not a real registry
  // signature over the message must NOT verify against the pinned key.
  const r = verifyNpmRegistrySignature('pkg', '1.0.0', INTEGRITY, [
    { keyid: PINNED_KEYID, sig: Buffer.from('not a real signature over this message').toString('base64') },
  ]);
  assert.equal(r.status, 'invalid');
});

test('malformed entries are skipped, not crashed on', () => {
  // Entries missing keyid/sig are ignored; with no usable entry the result is
  // the no-entry-verified "invalid" (a present-but-unusable signatures array).
  const r = verifyNpmRegistrySignature('pkg', '1.0.0', INTEGRITY, [
    null,
    { keyid: 123 },
    { sig: 'AAAA' },
  ]);
  assert.equal(r.status, 'invalid');
});
