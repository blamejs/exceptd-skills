'use strict';

/**
 * A fake https.get for the response-cap tests of lib/upstream-check.js and
 * scripts/validate-vendor-online.js. Its response streams a body of a chosen
 * size, so no request leaves the process.
 */

const https = require('node:https');
const { EventEmitter } = require('node:events');
const { Readable } = require('node:stream');

const CAP = 16 * 1024 * 1024;
const CHUNK = 1024 * 1024;
// The fake body is twice the cap. The stream reads a chunk or two ahead of the
// consumer, so a capped reader stops within a few chunks of the cap, far short
// of the whole body an uncapped reader takes.
const OVERSIZE = 2 * CAP;
const STOP_WITHIN = CAP + 4 * CHUNK;

// A fake https.get whose response streams `body` (a Buffer) or `size` filler
// bytes in CHUNK pieces. `stats.sent` records how many bytes it produced.
function fakeGet({ body, size }, stats) {
  return (_opts, cb) => {
    const req = new EventEmitter();
    let sent = 0;
    let stopped = false;
    const total = body ? body.length : size;
    const res = new Readable({
      read() {
        if (stopped) return;
        if (sent >= total) { this.push(null); return; }
        const n = Math.min(CHUNK, total - sent);
        const piece = body ? body.subarray(sent, sent + n) : Buffer.alloc(n, 0x20);
        sent += n;
        stats.sent = sent;
        this.push(piece);
      },
    });
    res.statusCode = 200;
    res.headers = {};
    req.destroy = (err) => {
      stopped = true;
      res.destroy();
      setImmediate(() => req.emit('error', err));
    };
    req.setTimeout = () => req;
    setImmediate(() => cb(res));
    return req;
  };
}

// Runs fn with https.get replaced by `fake` and the air-gap and registry-fixture
// variables unset, restoring all three afterwards.
function withFakeGet(fake, fn) {
  const orig = https.get;
  const env = { gap: process.env.EXCEPTD_AIR_GAP, fix: process.env.EXCEPTD_REGISTRY_FIXTURE };
  https.get = fake;
  delete process.env.EXCEPTD_AIR_GAP;
  delete process.env.EXCEPTD_REGISTRY_FIXTURE;
  return Promise.resolve().then(fn).finally(() => {
    https.get = orig;
    if (env.gap !== undefined) process.env.EXCEPTD_AIR_GAP = env.gap;
    if (env.fix !== undefined) process.env.EXCEPTD_REGISTRY_FIXTURE = env.fix;
  });
}

module.exports = { CAP, CHUNK, OVERSIZE, STOP_WITHIN, fakeGet, withFakeGet };
