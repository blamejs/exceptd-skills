"use strict";

/**
 * Companion collector for the `crypto-codebase` playbook: greps the cwd source
 * tree for hash / cipher / KEX / signature / KDF / RNG / TLS / PQC / FIPS call
 * sites. Interface: see lib/collectors/README.md
 */

const fs = require("node:fs");
const path = require("node:path");
const { codeExcludeSet, walkTree, buildEvidenceLocations, lineFromOffset } = require("./scan-excludes");

const COLLECTOR_ID = "crypto-codebase";

const DEFAULT_MAX_DEPTH = 6;
// Shared code-scope exclusions; no collector-specific extras needed.
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

// The exact marker set the playbook's `repo-has-source-tree` gate evaluates
// (data/playbooks/crypto-codebase.json: exists_any([...])). Mirrored here, NOT
// counted from SOURCE_EXTS files, so an empty src/ attests what the gate computes.
const SOURCE_TREE_MARKERS = [
  "package.json", "pyproject.toml", "go.mod", "Cargo.toml",
  "pom.xml", "build.gradle", "src", "lib", "crates",
];

const TEST_PATH_SEGMENTS = [
  "/test/", "/tests/", "/spec/", "/specs/", "/__tests__/",
  "/fixtures/", "/fixture/", "/examples/", "/example/",
  "/docs/", "/doc/", "/sample/", "/samples/", "/demo/", "/demos/",
  "/benchmarks/", "/benchmark/", "/bench/",
  // These files contain the scan patterns; scanning them matches the scanner.
  "/lib/collectors/", "/scripts/check-version-tags",
];

const MAX_FILE_BYTES = 1024 * 1024;

function isTestPath(rel) {
  const norm = "/" + rel.replace(/\\/g, "/").toLowerCase() + "/";
  for (const seg of TEST_PATH_SEGMENTS) {
    if (norm.includes(seg)) return true;
  }
  if (/\.(test|spec)\.[a-z]+$/i.test(rel)) return true;
  // Go's `foo_test.go` convention.
  if (/(?:^|[\\/])[^\\/]+_test\.[a-z]+$/i.test(rel)) return true;
  return false;
}

function readSafe(full) {
  try {
    // The cap is byte-based: enforced on the buffer, before any UTF-8 decode.
    const raw = fs.readFileSync(full);
    if (raw.length > MAX_FILE_BYTES) return null;
    return raw.toString("utf8");
  } catch { return null; }
}

const WEAK_HASH_RE = /(?:crypto\.createHash\(\s*['"](?:md5|sha1|sha-1)['"]|hashlib\.(?:md5|sha1)\s*\(|MessageDigest\.getInstance\(\s*['"](?:MD5|SHA-1|SHA1)['"]|crypto\/(?:md5|sha1)\b|Digest::(?:MD5|SHA1)\b)/i;
// Token vocabulary signalling a SECURITY-CRITICAL use of the hash primitive, as
// opposed to fingerprinting / cache-key / build-id use where MD5 and SHA-1 are
// legitimate. "integrity" stays out: it also matches fingerprinting and etags.
const WEAK_HASH_VAR_FLOW_RE = /(hmac|sign|signature|token|jwt|verify|password|hash[-_]?(?:credential|secret|password|key|auth))/i;
// Unambiguous security-context tokens: any of these fires the hit regardless of
// the filename — `hashing.go` running MD5 over a `password` is a real positive.
const STRONG_SECURITY_VAR_RE = /\b(token|password|jwt|secret|credential|api[-_]?key|access[-_]?key|private[-_]?key)\b/i;
// Paths suggesting fingerprint / etag / cache-key concerns. Demotion fires only
// when STRONG_SECURITY_VAR_RE did NOT match: the filename is a tiebreaker only.
const NON_SECURITY_HASH_FILE_RE = /(?:^|[\\/])(?:integrity|hashing|fingerprint|content[-_]?hash|cache[-_]?key|etag|build[-_]?id)\.(?:go|py|rs|java|js|ts|rb|php|cs|swift|m|cpp|cc|c|h|hpp)$/i;

const WEAK_CIPHER_ECB_RE = /(?:aes-\d+-ecb|AES\/ECB\/|Cipher\.getInstance\(\s*['"]AES['"]\s*\))/i;
const WEAK_CIPHER_DES_RE = /(?:des-cbc|des-ede3|\bDES\/|\bDESede\/|["']3des["']|["']des["']|\bDES_(?:set|encrypt|decrypt|cbc))/i;
const WEAK_CIPHER_RC4_RE = /(?:["']rc4["']|\barc4\b|\bARCFOUR\b)/i;

const RSA_1024_RE = /(?:modulusLength\s*:\s*1024|key_size\s*=\s*1024|["']rsa["']\s*,\s*1024|RSA(?:KeyPair)?Generator[^]{0,80}?1024|Generate\w+Key\([^)]*1024)/;

const MATH_RANDOM_GLOBAL_RE = /\b(?:Math\.random\(|random\.random\(|random\.randint\(|random\.choice\(|mt_rand\(|srand\(|rand\(\s*\))/g;
const SECURITY_VAR_RE = /\b(?:token|secret|key|salt|nonce|iv|seed|state|jwt|jti|csrf|session)\w*\s*[:=]/i;

const PBKDF2_BLOCK_GLOBAL_RE = /\b(?:pbkdf2(?:Sync)?|hashlib\.pbkdf2_hmac)\s*\([^)]{0,400}/g;

const BCRYPT_BLOCK_GLOBAL_RE = /\b(?:bcrypt\.(?:hash|hashSync|gen_salt|genSalt|genSaltSync)|BCrypt::Password\.create)\s*\([^)]{0,200}/g;
// Named-arg form (`cost: 12` / `rounds=12`) or the positional trailing integer.
// The captured block truncates at the first `)`, so the trailing-int branch ends
// at end-of-block, not at a paren.
const BCRYPT_COST_RE = /(?:cost|rounds)\s*[:=]\s*(\d+)|,\s*(\d+)\s*$/;

// `hardcoded-key-material` matches only a full PEM block: a `BEGIN ... PRIVATE
// KEY` header, a base64 body, and a matching `END`. Public keys and certificates
// are published by design, so the header is PRIVATE KEY only; requiring the body
// and the `END` separates a pasted key from a bare marker in a detection pattern
// or a placeholder. The body class excludes `-`, so the run halts at the first
// `-` of `-----END`, with no backtracking.
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
  if (STRONG_SECURITY_VAR_RE.test(content)) return true;
  if (!WEAK_HASH_VAR_FLOW_RE.test(content)) return false;
  // Only a soft keyword matched, so the filename is the tiebreaker.
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
    // The max 4+ digit literal is the iteration count. Common key-bit sizes are
    // deliberately not pre-filtered — `pbkdf2Sync(pw, salt, 1024, 32, 'sha256')`
    // IS under-iterated — and max() picks iteration over keylen in (iter, keylen).
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
      // The 1-based `line` gives the evidence location a SARIF startLine region.
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

    // Cross-file evidence for the conditional indicators, production context only:
    // a PQC / FIPS reference in tests is not evidence the library SHIPS it.
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
    // MANIFEST.json is a common provenance record for a vendored tree. The walk
    // runs only over already-vendored files, so a hit is a marker, not the root
    // app manifest.
    const provenanceMarkers = new Set(["_PROVENANCE.json", "UPSTREAM", "ORIGIN", ".upstream-commit", "PROVENANCE.md", "MANIFEST.json"]);
    // Walk from the file's directory up to the repo root: the marker may sit
    // beside the file, at the vendor root, or between. Stopping at the root
    // keeps the search inside the repo.
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

  // __fp_checks attest what the collector actually checked: every surviving hit is
  // in a non-test source file and, for weak-hash, flows into a security sink. The
  // unattested entries are judgements it does not make, and stay inconclusive.
  if (signal_overrides["weak-hash-import"] === "hit") {
    // [0] not under test, plus non-security-file demotion; [2] the hash flows to
    //     an authn/integrity sink. [1] legacy-protocol shim is operator judgement.
    signal_overrides["weak-hash-import__fp_checks"] = { "0": true, "2": true };
  }
  if (signal_overrides["weak-cipher-mode"] === "hit") {
    // [0] not under a test / KAT-vector path; [2] the construction is in a
    //     production source file. [1] legacy-protocol-parser scope is operator.
    signal_overrides["weak-cipher-mode__fp_checks"] = { "0": true, "2": true };
  }
  if (signal_overrides["tls-old-protocol"] === "hit") {
    // [0] the hit is production code, not a test asserting the library REJECTS the
    //     legacy protocol. [1] feature-flag default and [2] later override are not.
    signal_overrides["tls-old-protocol__fp_checks"] = { "0": true };
  }

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

  // File locations for the call-site indicators flipped to "hit". The cross-file
  // derived indicators describe a whole-repo state, so they carry no location; the
  // offset-bearing scans record a line, the whole-file scans stay file-level.
  const evidence_locations = {};
  for (const id of Object.keys(hits)) {
    if (signal_overrides[id] === "hit") {
      const locs = buildEvidenceLocations(hits[id]);
      if (locs.length) evidence_locations[id] = locs;
    }
  }

  return {
    precondition_checks: {
      // Mirrors the playbook's own exists_any(SOURCE_TREE_MARKERS) predicate
      // against the scanned cwd. The runner's autoDetectPreconditions probes the
      // run process's cwd and has no exists_any branch, so without this a real
      // source tree surfaces a spurious precondition_unverified warning.
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
