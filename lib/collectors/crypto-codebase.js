"use strict";

/**
 * lib/collectors/crypto-codebase.js
 *
 * Companion collector for the `crypto-codebase` playbook. Walks the
 * cwd tree, grepping source files for hash / cipher / KEX / signature
 * / KDF / RNG / TLS / PQC / FIPS call sites. Flips signal_overrides
 * only for indicators whose verdict can be determined deterministically
 * from the codebase scan; behavioral indicators that require operator
 * judgement (e.g. crypto-agility abstraction shape) are left unflipped
 * so the runner returns inconclusive rather than a forced miss.
 *
 * Interface: see lib/collectors/README.md
 */

const fs = require("node:fs");
const path = require("node:path");
const { codeExcludeSet, walkTree, buildEvidenceLocations, lineFromOffset } = require("./scan-excludes");

const COLLECTOR_ID = "crypto-codebase";

const DEFAULT_MAX_DEPTH = 6;
// Shared code-scope exclusions: dependency caches, build output, VCS +
// agent/editor scratch (including `.claude/`). No crypto-codebase-specific
// extras — the shared defaults already cover every directory this scan
// should never descend into.
const DEFAULT_EXCLUDES = codeExcludeSet();

const SOURCE_EXTS = new Set([
  ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".mts", ".cts",
  ".py", ".pyi",
  ".go",
  ".rs",
  ".java", ".kt", ".kts", ".scala",
  ".rb",
  ".php",
  ".c", ".h", ".cc", ".cpp", ".hpp", ".cxx",
  ".cs",
  ".swift",
  ".m", ".mm",
]);

// The exact marker set the crypto-codebase playbook's `repo-has-source-tree`
// gate evaluates (data/playbooks/crypto-codebase.json: exists_any([...])).
// The collector attests the gate by mirroring this predicate against the
// scanned cwd — NOT by counting SOURCE_EXTS files — so a valid package repo
// whose only marker is a manifest or an empty src/ dir (no extension-matched
// source yet) still attests true, matching what the gate would compute.
const SOURCE_TREE_MARKERS = [
  "package.json", "pyproject.toml", "go.mod", "Cargo.toml",
  "pom.xml", "build.gradle", "src", "lib", "crates",
];

const TEST_PATH_SEGMENTS = [
  "/test/", "/tests/", "/spec/", "/specs/", "/__tests__/",
  "/fixtures/", "/fixture/", "/examples/", "/example/",
  "/docs/", "/doc/", "/sample/", "/samples/", "/demo/", "/demos/",
  "/benchmarks/", "/benchmark/", "/bench/",
  // Files whose purpose is grepping for these patterns — their source
  // literally contains the patterns, so production-scope scans would
  // match the scanner itself. The crypto-codebase playbook's intent
  // is the consumer's source, not the scanner's regex catalogue.
  "/lib/collectors/", "/scripts/check-version-tags",
];

const MAX_FILE_BYTES = 1024 * 1024;

function isTestPath(rel) {
  const norm = "/" + rel.replace(/\\/g, "/").toLowerCase() + "/";
  for (const seg of TEST_PATH_SEGMENTS) {
    if (norm.includes(seg)) return true;
  }
  // `foo.test.js`, `bar.spec.py` (dot-separated)
  if (/\.(test|spec)\.[a-z]+$/i.test(rel)) return true;
  // `foo_test.go` (Go convention), `_test.py` (some Python projects)
  if (/(?:^|[\\/])[^\\/]+_test\.[a-z]+$/i.test(rel)) return true;
  return false;
}

function readSafe(full) {
  try {
    // Read raw bytes, enforce the 1 MB cap on the buffer length, then decode.
    // Replaces a statSync-before-read on the hot path with a single read; the
    // cap is byte-based, so Buffer.length is the correct measure and an
    // oversized file is rejected before any UTF-8 decode.
    const raw = fs.readFileSync(full);
    if (raw.length > MAX_FILE_BYTES) return null;
    return raw.toString("utf8");
  } catch { return null; }
}

const WEAK_HASH_RE = /(?:crypto\.createHash\(\s*['"](?:md5|sha1|sha-1)['"]|hashlib\.(?:md5|sha1)\s*\(|MessageDigest\.getInstance\(\s*['"](?:MD5|SHA-1|SHA1)['"]|crypto\/(?:md5|sha1)\b|Digest::(?:MD5|SHA1)\b)/i;
// Token vocabulary signaling a SECURITY-CRITICAL use of the hash
// primitive (not content-fingerprinting / cache-key / build-id usage,
// where MD5 / SHA-1 are legitimate by design).
//
// "integrity" was previously in this set but matched non-security
// integrity contexts (Hugo's content-integrity fingerprinting, sphinx
// docs build-ids, etag generators) — too broad. Drop it; the
// remaining vocabulary still catches crypto-security uses.
const WEAK_HASH_VAR_FLOW_RE = /(hmac|sign|signature|token|jwt|verify|password|hash[-_]?(?:credential|secret|password|key|auth))/i;
// Strong, unambiguous security-context tokens. When ANY of these
// appear in the file content, the hit fires regardless of the
// filename — a file named `hashing.go` that genuinely uses MD5 on
// a `password` / `token` / `jwt` is a real positive, no matter
// what the filename suggests.
const STRONG_SECURITY_VAR_RE = /\b(token|password|jwt|secret|credential|api[-_]?key|access[-_]?key|private[-_]?key)\b/i;
// Filename-path demotion candidates: paths that suggest
// content-addressable / fingerprint / etag / cache-key concerns.
// Demotion fires only when STRONG_SECURITY_VAR_RE did NOT match —
// the filename is a tiebreaker, never an override.
const NON_SECURITY_HASH_FILE_RE = /(?:^|[\\/])(?:integrity|hashing|fingerprint|content[-_]?hash|cache[-_]?key|etag|build[-_]?id)\.(?:go|py|rs|java|js|ts|rb|php|cs|swift|m|cpp|cc|c|h|hpp)$/i;

const WEAK_CIPHER_ECB_RE = /(?:aes-\d+-ecb|AES\/ECB\/|Cipher\.getInstance\(\s*['"]AES['"]\s*\))/i;
const WEAK_CIPHER_DES_RE = /(?:des-cbc|des-ede3|\bDES\/|\bDESede\/|["']3des["']|["']des["']|\bDES_(?:set|encrypt|decrypt|cbc))/i;
const WEAK_CIPHER_RC4_RE = /(?:["']rc4["']|\barc4\b|\bARCFOUR\b)/i;

const RSA_1024_RE = /(?:modulusLength\s*:\s*1024|key_size\s*=\s*1024|["']rsa["']\s*,\s*1024|RSA(?:KeyPair)?Generator[^]{0,80}?1024|Generate\w+Key\([^)]*1024)/;

const MATH_RANDOM_GLOBAL_RE = /\b(?:Math\.random\(|random\.random\(|random\.randint\(|random\.choice\(|mt_rand\(|srand\(|rand\(\s*\))/g;
const SECURITY_VAR_RE = /\b(?:token|secret|key|salt|nonce|iv|seed|state|jwt|jti|csrf|session)\w*\s*[:=]/i;

const PBKDF2_BLOCK_GLOBAL_RE = /\b(?:pbkdf2(?:Sync)?|hashlib\.pbkdf2_hmac)\s*\([^)]{0,400}/g;

const BCRYPT_BLOCK_GLOBAL_RE = /\b(?:bcrypt\.(?:hash|hashSync|gen_salt|genSalt|genSaltSync)|BCrypt::Password\.create)\s*\([^)]{0,200}/g;
// Captures either named-arg form (`cost: 12` / `rounds=12`) or the
// positional-arg trailing-integer form. Match against the block
// captured by BCRYPT_BLOCK_GLOBAL_RE — which truncates at the first
// `)`, so the trailing-int branch must match `, <digits>` followed
// by either end-of-block or whitespace, not a closing paren.
const BCRYPT_COST_RE = /(?:cost|rounds)\s*[:=]\s*(\d+)|,\s*(\d+)\s*$/;

// `hardcoded-key-material` is a SECRET-leak signal, so it must match only an
// actual embedded private key — a full PEM block: a `BEGIN ... PRIVATE KEY`
// header, a base64 body, and a matching `END` marker.
//
//   - Public keys and certificates are published by design (BIMI trust
//     anchors, release-signing public keys, autoupdate pubkeys), so the
//     header is `PRIVATE KEY` only.
//   - Requiring the base64 body + `END` marker distinguishes a real pasted
//     key from a bare marker used as a *detection pattern* (a redaction
//     library's `/-----BEGIN OPENSSH PRIVATE KEY-----/` regex literal) or a
//     documentation placeholder (`privateKeyPem: "-----BEGIN PRIVATE KEY-----
//     ..."`), neither of which carries a body or an `END`.
//
// The body class is base64 + whitespace only; `-` is excluded so the run
// halts at the first `-` of `-----END` — no backtracking, ReDoS-safe. The
// `-----END` requirement is the primary discriminator (detectors and
// placeholders have no closing marker); the {20,4000} bound additionally
// rejects the ~1-char run a bare marker leaves before the next punctuation.
const PEM_PRIVATE_RE = /-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----[A-Za-z0-9+/=\s]{20,4000}-----END/;

const TLS_OLD_PROTO_RE = /(?:secureProtocol\s*:\s*['"](?:TLSv1_method|TLSv1_1_method|SSLv23_method|SSLv3_method)['"]|minVersion\s*:\s*['"]TLSv1(?:\.0|\.1)?['"]|ssl_version\s*=\s*ssl\.PROTOCOL_TLSv1(?:_1)?|MinTlsVersion::TLSv1\b)/i;

const FIPS_ACTIVATION_RE = /(?:OSSL_PROVIDER_load\([^)]*\bfips\b|crypto\.setFips\s*\(\s*true|Provider::load[^,]*,\s*["']fips["']|set_fips_mode\s*\()/i;
const FIPS_CLAIM_RE = /\bfips(?:[- _]?(?:validated|compliance|compliant|140-?[23]|mode))\b/i;

const ML_KEM_IMPL_RE = /(?:ml[-_]?kem|kyber|noble-post-quantum|liboqs|oqsprovider|EVP_KEM_|OQS_KEM_|pqcrypto::|aws-lc-rs::pqc|circl\/kem\/kyber)/i;
const PQC_CLAIM_RE = /\b(?:pqc(?:[- _]?ready)?|post[- _]?quantum)\b/i;

const CLASSICAL_SIG_RE = /\b(?:ECDSA|secp(?:256k1|256r1|384r1|521r1)|Ed25519|Ed448|RSA-?PSS|RSA-?PKCS1)\b/i;
const PQC_SIG_IMPL_RE = /\b(?:ml[-_]?dsa|dilithium|slh[-_]?dsa|sphincs)\b/i;
const HYBRID_ROADMAP_RE = /\b(?:hybrid[- _](?:signature|pqc)|(?:pqc|post[- _]?quantum)[- _](?:migration|roadmap|timeline))\b/i;

const VENDORED_PQC_NAMES_RE = /(?:kyber|dilithium|sphincs|ml[-_]?kem|ml[-_]?dsa|slh[-_]?dsa|falcon)/i;

function scanWeakHash(content, rel) {
  if (!WEAK_HASH_RE.test(content)) return false;
  // Strong security tokens fire the indicator regardless of the
  // filename — a file named `integrity.go` that genuinely uses
  // md5 on a password is a real positive.
  if (STRONG_SECURITY_VAR_RE.test(content)) return true;
  // Otherwise the var-flow regex needs to match (hash / hmac /
  // sign / signature / verify / ...). If neither STRONG nor
  // WEAK_HASH_VAR_FLOW fired, this isn't a security-context use.
  if (!WEAK_HASH_VAR_FLOW_RE.test(content)) return false;
  // Var-flow matched a soft / ambiguous keyword. Use the filename
  // as a tiebreaker: paths like `integrity.go` / `hashing.go` /
  // `fingerprint.py` indicate content-addressable use, demote.
  if (rel && NON_SECURITY_HASH_FILE_RE.test(rel)) return false;
  return true;
}

function scanMathRandom(content) {
  const matches = [];
  for (const m of content.matchAll(MATH_RANDOM_GLOBAL_RE)) {
    const start = Math.max(0, m.index - 200);
    const end = Math.min(content.length, m.index + 200);
    const window = content.slice(start, end);
    if (SECURITY_VAR_RE.test(window)) {
      matches.push({ offset: m.index, snippet: m[0] });
    }
  }
  return matches;
}

function scanPbkdf2(content) {
  const hits = [];
  for (const m of content.matchAll(PBKDF2_BLOCK_GLOBAL_RE)) {
    const block = m[0];
    let threshold = 210000;
    if (/sha[-_]?256/i.test(block)) threshold = 600000;
    else if (/sha1\b/i.test(block) || /sha-1\b/i.test(block)) threshold = 1300000;
    // Take the max 4+ digit literal as the iteration count. Don't
    // pre-filter common key-bit-size values (256/384/512/1024) — a
    // call like `pbkdf2Sync(pw, salt, 1024, 32, 'sha256')` IS under-
    // iterated at 1024 and must hit. The max() picks iteration over
    // keylen in the typical positional shape (iter, keylen, algo).
    const nums = [];
    for (const nm of block.matchAll(/\b(\d{4,8})\b/g)) {
      nums.push(Number(nm[1]));
    }
    if (nums.length === 0) continue;
    const iter = Math.max(...nums);
    if (iter < threshold) {
      hits.push({ offset: m.index, threshold, iter });
    }
  }
  return hits;
}

function scanBcrypt(content) {
  const hits = [];
  for (const m of content.matchAll(BCRYPT_BLOCK_GLOBAL_RE)) {
    const block = m[0];
    const cm = block.match(BCRYPT_COST_RE);
    if (!cm) continue;
    const cost = Number(cm[1] || cm[2]);
    if (!Number.isFinite(cost) || cost === 0) continue;
    if (cost < 12) hits.push({ offset: m.index, cost });
  }
  return hits;
}

function isVendored(rel) {
  const norm = "/" + rel.replace(/\\/g, "/").toLowerCase() + "/";
  return /\/(?:vendor|third_party|3rdparty|external|deps)\//.test(norm);
}

function collect({ cwd = process.cwd(), env = process.env, args = {} } = {}) {
  const errors = [];
  const startTime = Date.now();
  const root = path.resolve(cwd);

  let files;
  try {
    files = walkTree(root, { maxDepth: DEFAULT_MAX_DEPTH, excludes: DEFAULT_EXCLUDES });
  } catch (e) {
    errors.push({ kind: "walk_failed", reason: e.message });
    files = [];
  }
  if (files.length > 50000) {
    errors.push({
      kind: "file_count_capped",
      reason: `walked ${files.length} files; capping content scan at 50000.`,
    });
    files = files.slice(0, 50000);
  }

  const sourceFiles = files.filter(f => SOURCE_EXTS.has(path.extname(f.name).toLowerCase()));

  const hits = {
    "weak-hash-import": [],
    "weak-cipher-mode": [],
    "rsa-1024-anywhere": [],
    "math-random-in-security-path": [],
    "pbkdf2-under-iterated": [],
    "bcrypt-cost-low": [],
    "hardcoded-key-material": [],
    "tls-old-protocol": [],
  };

  let sawClassicalSig = false;
  let sawPqcSigImpl = false;
  let sawHybridRoadmap = false;
  let sawPqcClaim = false;
  let sawMlKemImpl = false;
  let sawFipsClaim = false;
  let sawFipsActivation = false;

  for (const f of sourceFiles) {
    const content = readSafe(f.full);
    if (content == null) {
      errors.push({ artifact_id: "source-files", kind: "read_failed", reason: f.rel });
      continue;
    }
    const isTest = isTestPath(f.rel);

    if (!isTest) {
      if (scanWeakHash(content, f.rel)) {
        hits["weak-hash-import"].push({ file: f.rel });
      }
      if (WEAK_CIPHER_ECB_RE.test(content) || WEAK_CIPHER_DES_RE.test(content) || WEAK_CIPHER_RC4_RE.test(content)) {
        hits["weak-cipher-mode"].push({ file: f.rel });
      }
      if (RSA_1024_RE.test(content)) {
        hits["rsa-1024-anywhere"].push({ file: f.rel });
      }
      // Attach a 1-based `line` (from the match offset) so the evidence
      // location carries a SARIF startLine region rather than pointing at
      // the file. Does not change hit/miss — the same matches still fire.
      const mrHits = scanMathRandom(content);
      for (const h of mrHits) hits["math-random-in-security-path"].push({ file: f.rel, offset: h.offset, line: lineFromOffset(content, h.offset) });

      const pHits = scanPbkdf2(content);
      for (const h of pHits) hits["pbkdf2-under-iterated"].push({ file: f.rel, offset: h.offset, line: lineFromOffset(content, h.offset), iter: h.iter, threshold: h.threshold });

      const bHits = scanBcrypt(content);
      for (const h of bHits) hits["bcrypt-cost-low"].push({ file: f.rel, offset: h.offset, line: lineFromOffset(content, h.offset), cost: h.cost });

      if (PEM_PRIVATE_RE.test(content)) {
        hits["hardcoded-key-material"].push({ file: f.rel });
      }
      if (TLS_OLD_PROTO_RE.test(content)) {
        hits["tls-old-protocol"].push({ file: f.rel });
      }
    }

    // Cross-file evidence for the conditional indicators (ecdsa-
    // without-pqc-roadmap, no-ml-kem-implementation, fips-claim-
    // without-runtime-activation). Production-context only — a
    // PQC / FIPS reference inside `tests/` / `fixtures/` / `examples/`
    // doesn't count as evidence the library SHIPS that capability.
    if (!isTest) {
      if (CLASSICAL_SIG_RE.test(content)) sawClassicalSig = true;
      if (PQC_SIG_IMPL_RE.test(content)) sawPqcSigImpl = true;
      if (ML_KEM_IMPL_RE.test(content)) sawMlKemImpl = true;
      if (FIPS_ACTIVATION_RE.test(content)) sawFipsActivation = true;
    }
  }

  const docFiles = files.filter(f =>
    /^README(\.md|\.rst|\.txt)?$/i.test(f.name) ||
    /^SECURITY\.md$/i.test(f.name) ||
    /^package\.json$/i.test(f.name) ||
    /^Cargo\.toml$/i.test(f.name) ||
    /^pyproject\.toml$/i.test(f.name)
  );
  for (const f of docFiles) {
    const content = readSafe(f.full);
    if (content == null) continue;
    if (PQC_CLAIM_RE.test(content)) sawPqcClaim = true;
    if (HYBRID_ROADMAP_RE.test(content)) sawHybridRoadmap = true;
    if (FIPS_CLAIM_RE.test(content)) sawFipsClaim = true;
  }

  const vendoredPqcFiles = files.filter(f => isVendored(f.rel) && VENDORED_PQC_NAMES_RE.test(f.rel));
  let vendoredPqcNoProvenance = "miss";
  if (vendoredPqcFiles.length > 0) {
    // `MANIFEST.json` / `vendor/MANIFEST.json` is the common provenance
    // record for a vendored dependency tree (records upstream version,
    // source URL, license, copied-at commit). This walk only runs for
    // files already classified as vendored, so a MANIFEST.json found while
    // climbing the vendor tree is a genuine provenance marker, not a stray
    // app/package manifest at the repo root.
    const provenanceMarkers = new Set(["_PROVENANCE.json", "UPSTREAM", "ORIGIN", ".upstream-commit", "PROVENANCE.md", "MANIFEST.json"]);
    // Walk from the file's directory up to the repo root, checking
    // each ancestor for a provenance marker. The marker can live at
    // the immediate sibling (`vendor/kyber/_PROVENANCE.json`), at
    // the vendor root (`vendor/_PROVENANCE.json`), or anywhere in
    // between for deeply-nested vendor trees. Stop at the repo root
    // (cwd) so we don't escape into the parent filesystem.
    let anyMissing = false;
    for (const f of vendoredPqcFiles) {
      let dir = path.dirname(f.full);
      let found = false;
      while (true) {
        let entries;
        try { entries = fs.readdirSync(dir); } catch { break; }
        if (entries.some(e => provenanceMarkers.has(e))) { found = true; break; }
        if (path.resolve(dir) === root) break;
        const parent = path.dirname(dir);
        if (parent === dir) break;
        // Guard against escaping the repo root via symlinks.
        if (path.relative(root, parent).startsWith("..")) break;
        dir = parent;
      }
      if (!found) { anyMissing = true; break; }
    }
    vendoredPqcNoProvenance = anyMissing ? "hit" : "miss";
  }

  let ecdsaWithoutRoadmap;
  if (sawClassicalSig) {
    ecdsaWithoutRoadmap = (!sawPqcSigImpl && !sawHybridRoadmap) ? "hit" : "miss";
  }

  let noMlKemImpl;
  if (sawPqcClaim) {
    noMlKemImpl = sawMlKemImpl ? "miss" : "hit";
  }

  let fipsTheater;
  if (sawFipsClaim) {
    fipsTheater = sawFipsActivation ? "miss" : "hit";
  }

  const signal_overrides = {};
  for (const id of Object.keys(hits)) {
    signal_overrides[id] = hits[id].length > 0 ? "hit" : "miss";
  }
  signal_overrides["vendored-pqc-no-provenance"] = vendoredPqcNoProvenance;
  if (ecdsaWithoutRoadmap !== undefined) signal_overrides["ecdsa-without-pqc-roadmap"] = ecdsaWithoutRoadmap;
  if (noMlKemImpl !== undefined) signal_overrides["no-ml-kem-implementation"] = noMlKemImpl;
  if (fipsTheater !== undefined) signal_overrides["fips-claim-without-runtime-activation"] = fipsTheater;

  const summarize = (id) => {
    const list = hits[id];
    if (list.length === 0) return "0 hits";
    const head = list.slice(0, 5).map(h => h.file + (h.iter ? ` (iter=${h.iter}<${h.threshold})` : "") + (h.cost ? ` (cost=${h.cost})` : "")).join("; ");
    return `${list.length} hit(s): ${head}` + (list.length > 5 ? "; …" : "");
  };

  const artifacts = {
    "package-manifests": {
      value: docFiles.filter(f => /(package\.json|Cargo\.toml|pyproject\.toml)/i.test(f.name)).map(f => f.rel).join(", ") || "no manifest found at root",
      captured: true,
    },
    "hash-primitive-call-sites": {
      value: summarize("weak-hash-import"),
      captured: true,
    },
    "cipher-and-kex-call-sites": {
      value: summarize("weak-cipher-mode"),
      captured: true,
    },
    "signature-call-sites": {
      value: sawClassicalSig
        ? `classical signature use observed; pqc_sig_impl=${sawPqcSigImpl}; hybrid_roadmap=${sawHybridRoadmap}`
        : "no signature call sites detected",
      captured: true,
    },
    "kdf-call-sites": {
      value: `pbkdf2 under-iterated: ${summarize("pbkdf2-under-iterated")}; bcrypt low: ${summarize("bcrypt-cost-low")}`,
      captured: true,
    },
    "rng-call-sites": {
      value: summarize("math-random-in-security-path"),
      captured: true,
    },
    "hardcoded-key-material": {
      value: summarize("hardcoded-key-material"),
      captured: true,
    },
    "tls-config-construction": {
      value: summarize("tls-old-protocol"),
      captured: true,
    },
    "pqc-adoption-signals": {
      value: `pqc_claim=${sawPqcClaim}; ml_kem_impl=${sawMlKemImpl}; pqc_sig_impl=${sawPqcSigImpl}; hybrid_roadmap=${sawHybridRoadmap}`,
      captured: true,
    },
    "fips-provider-activation": {
      value: `fips_claim=${sawFipsClaim}; fips_activation_in_source=${sawFipsActivation}`,
      captured: true,
    },
    "vendored-crypto-tree": {
      value: vendoredPqcFiles.length
        ? vendoredPqcFiles.slice(0, 5).map(f => f.rel).join("; ") + (vendoredPqcFiles.length > 5 ? "; …" : "")
        : "no vendored PQC primitives detected",
      captured: true,
    },
  };

  // Per-indicator file locations for the call-site indicators flipped to
  // "hit". The cross-file derived indicators (ecdsa-without-pqc-roadmap,
  // no-ml-kem-implementation, fips-claim-without-runtime-activation,
  // vendored-pqc-no-provenance) describe a whole-repo state rather than a
  // single offending file, so they carry no file-level location. The
  // offset-bearing call-site scans (math-random / pbkdf2 / bcrypt) now record
  // a 1-based `line`, so their locations include a startLine region; the
  // remaining whole-file scans (weak-hash / weak-cipher / rsa-1024 /
  // hardcoded-key / tls) stay file-level (no startLine).
  const evidence_locations = {};
  for (const id of Object.keys(hits)) {
    if (signal_overrides[id] === "hit") {
      const locs = buildEvidenceLocations(hits[id]);
      if (locs.length) evidence_locations[id] = locs;
    }
  }

  return {
    precondition_checks: {
      // Auto-attest the crypto-codebase playbook's own `repo-has-source-tree`
      // gate by mirroring the gate's own exists_any(SOURCE_TREE_MARKERS)
      // predicate against the scanned cwd. The runner's autoDetectPreconditions
      // probes the run process's cwd (not the collected --cwd) and has no
      // exists_any() branch, so a repo with a recognizable source tree would
      // otherwise surface a spurious precondition_unverified warning. Keying to
      // the gate's exact id + predicate mirrors the sbom / library-author
      // collectors; `repo-context` is not a precondition this playbook
      // references.
      "repo-has-source-tree": SOURCE_TREE_MARKERS.some((m) => fs.existsSync(path.join(cwd, m))),
    },
    artifacts,
    signal_overrides,
    ...(Object.keys(evidence_locations).length ? { evidence_locations } : {}),
    collector_meta: {
      collector_id: COLLECTOR_ID,
      collector_version: "2026-05-31",
      platform: process.platform,
      captured_at: new Date().toISOString(),
      cwd: root,
      duration_ms: Date.now() - startTime,
      files_walked: files.length,
      source_files_scanned: sourceFiles.length,
    },
    collector_errors: errors,
  };
}

module.exports = { playbook_id: COLLECTOR_ID, collect };
