"use strict";
/**
 * Catalog gap detection. Each detector is a pure function over the loaded
 * catalogs plus options, returning an array of findings; DETECTOR_CLASSES below
 * names the full set.
 */

// Placeholder / curation-pending sentinels, applied to every text-heavy field.
const PLACEHOLDER_SENTINELS = [
  /pending operator curation/i,
  /refer to vendor advisory for IOC list/i,
  /bulk-imported KEV entry, IOCs not extracted/i,
  /\bTBD\b/,
  /\bTKTK\b/,
  /\bcoming soon\b/i,
  /^\s*\[\s*\]\s*$/,
  /\bplaceholder\b/i
];

function hasPlaceholderLanguage(str) {
  if (typeof str !== "string" || str.length === 0) return false;
  for (const re of PLACEHOLDER_SENTINELS) {
    if (re.test(str)) return true;
  }
  return false;
}

// Curation-pipeline wording in shipped prose: text that cites the input bundle a
// curator worked from ("Packet: ...", "the packet names ...") or quotes a catalog
// field name as its source. Each pattern is a construction a network packet cannot
// form, so "packet data", "the packet socket (AF_PACKET)" and "Packet Storm" do not match.
const PIPELINE_WORDING = [
  /(?:^|[.;:!?,]['"’”)\]]*\s+|\(\s*)(?:the )?packet:/i,
  /\b(?:per(?: the)?|(?:in|from|follows) the|this|own) packet:/i,
  /\bpacket:\s*(?:cisa[_ ]kev|active_exploitation|patch_available|live_patch|cwe_refs|cvss|vector|attack_vector|rwep|affected(?:_versions)?|poc_available)\b/i,
  /\bPacket fields?\s*(?::|for\s+(?:CVE-|this\b))/,
  /\bPacket vector\b/,
  /\bpacket(?:'s)? (?:attack_vector|live_patch_notes|cisa_kev|affected_versions|poc_description|patch_available|active_exploitation_notes|vendor_update_paths|cwe_refs|rwep_\w+)\b/i,
  /\b[Tt]he packet (?:(?:also|actually|itself) )?(?:records|names|registers|supplies|lists|says|states|reports|marks|confirms|describes|notes)\b/,
  // Verbs a curator used for the input bundle, each with the object that makes
  // it curation wording rather than a statement about a network packet.
  /\b[Tt]he packet (?:ties (?:this|the) (?:[\w/.-]+ ){0,4}(?:use-after-free|injection|overflow|flaw|defect|sink|weakness|bypass|CWE-\d+|affected|remediation|vulnerability)(?![\w-])|documents\b|locates the (?:flaw|defect|bug)|pairs that with|pairs an? (?:public (?:PoC|exploit)|pre-auth|(?:\d{4}(?:-\d{2}-\d{2})? )?(?:CVE|KEV))|attributes the (?:residual|exposure|flaw|defect)\b|establishes the (?:flaw|defect)|qualifies the (?:flaw|defect)|scores it (?:RWEP|CVSS)|dates the (?:vendor|fix|KEV)|conditions the (?:bypass|flaw|exploit|crash|trigger)\b|cites\b|pins this to|characterizes (?:the caller|the [\w -]{1,40}? as)|classifies this as|classes this CVE|labels this a|calls the (?:[\w-]+ ){0,3}(?:flaw|defect)|places (?:this|the (?:flaw|defect|bug|bypass|trigger|CVE)|execution)(?![\w-])|recording confirmed|naming a chain|chains that with|enumerates fixes|defines it:|has it wired|noting no live|measures:)/,
  /\b(?:per|according to) the packet\b/i,
  /\bthe remediation the packet supports\b/i,
  // A label that opens a text or sentence: "Packet records ...", "Packet attack
  // vector: ...", "Packet NIST-800-53-SI-2 gap: ...", "Packet CVE-2025-0282 ...".
  /(?:^|[.;!?]\s+)Packet (?:records (?:CWE-|CVE-|CVSS|an? CISA|cisa_|patch_|poc_|live_|active_|an? [\w -]{0,30}?(?:flaw|zero-day|write|read|overflow|injection|bypass|vulnerability|use-after-free)(?![\w-]))|names the affected|gives (?:patch|live|poc|cisa)_|gap (?:NIST|NIS2|AU-|UK-CAF|ISO-27001|DORA|EU-)|attack (?:vector|path)(?: as recorded)?:|affected(?::| field\b|\/)|name(?::| and vector\b)|description:|citing gaps\b|for CVE-|entry ['"‘“]|CVE-\d{4}-\d+|(?:NIST|NIS2|AU-|UK-CAF|ISO-27001|DORA|EU-|PCI-DSS|HIPAA|SOC2|CMMC|FedRAMP)[\w.-]* gap\b)/i,
  /\bthe packet makes [\w -]{1,40}? the (?:precondition|condition|clock)\b/i,
  /\bthe packet for CVE-\d/i,
  /\bCWE-\d+ in the packet\b/,
  /\bCorroborating packet fields\b/i,
  /\bthis packet (?:allows only|is one of the few|carries both halves)\b/i,
  /\bpacket's (?:[\w-]+ )?note (?:records|says|states)\b/i,
  /\bpacket's (?:structured record says|range runs from \d+\.\d+\.\d+|history supports|point is that|opening fact|update requires a reboot|access condition includes|second path is simply|mass exploitation|actual exploitation path)\b/i,
  /\bpacket vector (?:states|records|says)\b/,
  // "in the packet" is curation wording only when no part of a network packet
  // (header, capture, payload ...) follows it.
  /\bcited in the packet\b(?![\s-]*(?:headers?|captures?|payloads?|body|trailer|data|stream|buffer|fields?|options?|structure))/i,
  /\b(?:exploit|PoC|proof of concept|proof-of-concept) recorded in the packet\b(?![\s-]*(?:headers?|captures?|payloads?|body|trailer|data|stream|buffer|fields?|options?|structure))/i,
  /\b(?:NVD|KEV|CISA|short) description(?: of CVE-\d{4}-\d+)? (?:carried )?in the packet\b(?![\s-]*(?:headers?|captures?|payloads?|body|trailer|data|stream|buffer|fields?|options?|structure))/i,
  /\bfollows? the packet rather than\b/i,
  /\b(?:a|the) claim the packet makes\b/i,
  /\bwhat this packet establishes\b/i,
  /\bthis packet makes it an? (?:authentication|enforcement|remediation|patch|priority|containment)[\w -]{0,30}?(?:point|item)\b/i,
  /\bThis packet carries (?:two|three|several) facts\b/,
  /\b(?:two|three|several) packet details\b/i,
  /\bthe packet is (?:explicit|specific|silent|clear) (?:that|about)\b/i,
  /\bwhat the packet does (?:not )?(?:establish|supply|say)\b/i,
  /\bfact the packet does supply\b/i,
  /\bthe packet has an? (?:(?:pre-authenticated|unauthenticated|authenticated|remote|local|low-privileged|privileged|adjacent),? ){0,4}attacker(?![\w-])/i,
  /\bthe packet has the (?:flaw|defect)\b/i,
  /\bthe packet requires (?:a user to open\b|a reboot after\b|the fixed build\b)/i,
  /\b(?:reboot|restart) the packet requires\b/i,
  /\bthe packet identifies (?:the (?:affected|vulnerable) (?:product|component|version)|the (?:product|flaw|defect) as)\b/i,
  /\bthe packet identifies [\w.-]+\.exe\b/i,
  /\bwhich the packet identifies as\b/i,
  /\bthe packet sets (?:ai_|poc_|cisa_|patch_|live_|active_)/i,
  // A possessive followed by a curation noun, a catalog field identifier or a
  // framework key. Words a network packet can also own (path, delivery, length,
  // boundary) appear only with the verbs a curator used with them.
  /\bpacket's (?:path (?:ends in (?:OS |arbitrary |remote )?(?:command|code)|hands an? (?:unauthenticated|remote|local|attacker)|(?:needs|requires) no (?:credentials?|authentication|user|account|code)|starts from an? (?:local|remote|unauthenticated)|goes from unauthenticated|requires to reach)\b|delivery (?:path|step) is (?:mail|a victim|a target)\b|request (?:arrives|is) unauthenticated\b|only (?:other )?(?:stated|remediation)\b|(?:[\w-]+ ){0,2}access requirement\b|(?!flow|congestion)[\w-]*(?:protection|management|security|remediation|boundary|patch|hardening|monitoring|control)[\w-]* gap\b|trigger is an? (?:app|user|local)\b|end state is (?:an? attacker|arbitrary|remote (?:code|command)|code execution|command execution)\b)/i,
  /\bpacket's\s+(?:own|vector|stated|attack(?:\s+(?:vector|path))?|exploitation|remediation|live[- ]?patch|livepatch|chain|fix(?:ed)?|attacker|outcome|affected|flaw(?:-remediation)?|precondition|primitive|rwep|exploit|kev|gaps?|description|cit(?:ing|ed)|confirmed|defect|cwe\b|escalation|caf|recorded|requiredaction|product|essential(?:-eight)?|framing|cvss|reachability|timeline|chained|campaign|exposure|actor|interim|named|attribution|title|targeting|coverage|end-of-life|guidance|observed|recommended|threat|public-exploit|vendor|requirement|mitigation|documented|implant|lure|post-exploitation|patch-management|references?|notes?|framework|facts|advisory|versions?(?!\s+(?:field|number|byte|bits?)\b)|summary|deadline|(?:nist-800-53|uk-caf|au-essential-8|au-ism|iso-27001|nis2|dora|eu-ai-act|cwe-)[\w.-]*|(?:active_exploitation(?:_notes)?|affected_versions|ai_discovered|ai_discovery_\w+|attack_vector|cisa_kev\w*|cvss_\w+|cwe_refs|discovery_attribution_note|epss_\w+|framework_control_gaps|known_ransomware_use|live_patch_\w+|patch_available|patch_required_reboot|poc_available|poc_description|rwep_\w+|vendor_advisories|vendor_update_paths|verification_sources))\b/i,
];

function hasPipelineWording(str) {
  if (typeof str !== "string" || str.length === 0) return false;
  return PIPELINE_WORDING.some((re) => re.test(str));
}

// Every string under a value, with its dotted path.
function _strings(value, pathSoFar, out) {
  if (typeof value === "string") out.push([pathSoFar, value]);
  else if (Array.isArray(value)) value.forEach((v, i) => _strings(v, `${pathSoFar}[${i}]`, out));
  else if (value && typeof value === "object") {
    for (const k of Object.keys(value)) _strings(value[k], pathSoFar ? `${pathSoFar}.${k}` : k, out);
  }
  return out;
}

// One finding per curated catalog or lesson text that carries pipeline wording.
// Drafts are skipped unless opts.includeDrafts is set, as it is for a batch about
// to be written, where every submitted object is checked.
function pipelineWordingFindings(loaded, opts = {}) {
  const out = [];
  for (const catalog of ["cve-catalog", "zeroday-lessons"]) {
    const cat = loaded[catalog];
    if (!cat) continue;
    for (const id of Object.keys(cat)) {
      if (id === "_meta") continue;
      const e = cat[id];
      if (!e || (e._auto_imported === true && !opts.includeDrafts)) continue;
      for (const [field, s] of _strings(e, "", [])) {
        if (hasPipelineWording(s)) {
          out.push({ class: "pipeline-wording", catalog, id, field,
            reason: "text cites the curation input or a catalog field name instead of stating the fact and its source" });
        }
      }
    }
  }
  return out;
}

// Wording that states when CISA listed the flaw. Due dates ("KEV due date",
// "due 2026-06-28") are a different date and do not match.
const KEV_LISTING_DATE = [
  /\bKEV[- ]listed (?:(?:it|(?:this|the) (?:CVE|flaw|vulnerability|bug|defect|issue)|CVE-\d{4}-\d+) )?(?:on )?(\d{4}-\d{2}-\d{2})/gi,
  /\bKEV listing (?:on |date |of )?\(?(\d{4}-\d{2}-\d{2})/gi,
  /(\d{4}-\d{2}-\d{2}) KEV listing\b/gi,
  /\blisted (?:(?:it|(?:this|the) (?:CVE|flaw|vulnerability|bug|defect|issue)|CVE-\d{4}-\d+) )?(?:in|on|by) (?:CISA(?:'s)? |its )?(?:the )?(?:KEV|Known Exploited Vulnerabilities)(?: catalog)? (?:on )?(\d{4}-\d{2}-\d{2})/gi,
  /\bKEV clock (?:that )?(?:opened|opens|started|starts|running from) (?:on )?(\d{4}-\d{2}-\d{2})/gi,
  /\b(?:added|listed) (?:to|in) (?:CISA(?:'s)? |the )?KEV(?: catalog)? (?:on )?(\d{4}-\d{2}-\d{2})/gi,
  /\b(?:entered|joined|appeared in) (?:CISA(?:'s)? |the )?(?:KEV|Known Exploited Vulnerabilities)(?: catalog)? on (\d{4}-\d{2}-\d{2})/gi,
  /\badded (?:[\w-]+ ){0,3}to (?:its|the|CISA's) (?:KEV|Known Exploited Vulnerabilities)(?: catalog)? on (\d{4}-\d{2}-\d{2})/gi,
  /\bKEV (?:dateAdded|date) (\d{4}-\d{2}-\d{2})/gi,
];

// Words that point a listing date back at the entry's own flaw. "the flaw" and
// "the CVE" count, so a sibling's date is exempt only when the text names the
// sibling without them ("CVE-2011-0611, a sibling, was KEV-listed ..."). A bare
// pronoun ("it was") does not count, since its antecedent can be the sibling.
const SELF_REFERENCE = /\b(?:this|the same|the) (?:flaw|CVE|vulnerability|bug|defect|entry|issue)\b/i;

// Whether the date at `at` in `s` belongs to another CVE: the nearest CVE id
// before it in the same sentence is not `id`, and nothing between that id and
// the date refers back to this entry ("Unlike CVE-X, this flaw was ...").
function _dateBelongsToOtherCve(s, at, id) {
  // A sentence ends at . ; ? ! (with any closing quote or bracket) before
  // whitespace, or at a line break.
  let start = 0;
  for (const b of s.slice(0, at).matchAll(/[.;?!]['"’”)\]]*\s+|\n/g)) start = b.index + b[0].length;
  const before = s.slice(start, at);
  const ids = [...before.matchAll(/CVE-\d{4}-\d+/g)];
  if (!ids.length) return false;
  const last = ids[ids.length - 1];
  if (last[0] === id) return false;
  return !SELF_REFERENCE.test(before.slice(last.index + last[0].length));
}

// One finding per catalog or lesson text that states a KEV listing date other
// than the entry's cisa_kev_date. Such a text usually describes a different CVE.
// A date that another CVE named earlier in the same sentence owns is skipped.
// `entries` supplies cisa_kev_date for lessons whose entry is not in
// loaded["cve-catalog"], as for a batch about to be written.
function kevListingDateFindings(loaded, opts = {}) {
  const out = [];
  const cve = { ...(loaded["cve-catalog"] || {}), ...(opts.entries || {}) };
  for (const catalog of ["cve-catalog", "zeroday-lessons"]) {
    const cat = loaded[catalog];
    if (!cat) continue;
    for (const id of Object.keys(cat)) {
      if (id === "_meta") continue;
      const listed = cve[id] && cve[id].cisa_kev_date;
      if (typeof listed !== "string" || !listed) continue;
      for (const [field, s] of _strings(cat[id], "", [])) {
        // Two patterns can match the same stated date; it is one finding.
        const seen = new Set();
        for (const re of KEV_LISTING_DATE) {
          for (const m of s.matchAll(re)) {
            if (m[1] === listed) continue;
            // The date's own position, so a CVE id inside the match ("added
            // CVE-2011-0611 to its ... catalog on ...") precedes it.
            const at = m.index + m[0].indexOf(m[1]);
            if (seen.has(at)) continue;
            seen.add(at);
            if (_dateBelongsToOtherCve(s, at, id)) continue;
            out.push({ class: "logical-consistency", catalog, id, field,
              rule: "stated_kev_listing_date_matches_entry",
              reason: `text states a KEV listing date of ${m[1]}, but the entry's cisa_kev_date is ${listed}` });
          }
        }
      }
    }
  }
  return out;
}

// Fields present but weak; what counts as weak is per catalog and field.
function contentQualityFindings(loaded) {
  const out = [];
  const cve = loaded["cve-catalog"];
  if (!cve) return out;

  for (const id of Object.keys(cve)) {
    if (id === "_meta") continue;
    const e = cve[id];
    if (!e) continue;

    // A short or placeholder vector means the exploitation primitive is undescribed.
    if (typeof e.vector === "string" && e.vector.length > 0 && e.vector.length < 50) {
      out.push({ class: "content-quality", catalog: "cve-catalog", id,
        field: "vector", reason: `vector is ${e.vector.length} chars (< 50 threshold) — likely a stub` });
    }
    if (typeof e.vector === "string" && hasPlaceholderLanguage(e.vector)) {
      out.push({ class: "content-quality", catalog: "cve-catalog", id,
        field: "vector", reason: "vector contains placeholder-language sentinel" });
    }

    // poc_available:true with placeholder text claims a PoC without saying where.
    if (e.poc_available === true && hasPlaceholderLanguage(e.poc_description)) {
      out.push({ class: "content-quality", catalog: "cve-catalog", id,
        field: "poc_description", reason: "poc_available:true but description carries placeholder sentinel" });
    }

    // A KEV listing implies CISA linked advisory metadata, so empty is a curation gap.
    if (e.cisa_kev === true && (!Array.isArray(e.vendor_advisories) || e.vendor_advisories.length === 0)) {
      out.push({ class: "content-quality", catalog: "cve-catalog", id,
        field: "vendor_advisories", reason: "cisa_kev:true but vendor_advisories is empty" });
    }

    if (typeof e.name === "string" && typeof e.description === "string"
        && e.name === e.description && e.name.length > 0) {
      out.push({ class: "content-quality", catalog: "cve-catalog", id,
        field: "description", reason: "description is just the name repeated" });
    }
  }
  return out;
}

// Time-based decay: stale entries become an operator re-verify work queue.
function daysSince(iso, now) {
  if (typeof iso !== "string" || !/^\d{4}-\d{2}-\d{2}/.test(iso)) return null;
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return null;
  return Math.floor((now.getTime() - t) / (1000 * 60 * 60 * 24));
}

function temporalStalenessFindings(loaded, opts = {}) {
  const now = opts.now || new Date();
  const STALE_VERIFIED_DAYS = opts.stale_verified_days || 180;
  const STALE_UPDATED_DAYS = opts.stale_updated_days || 365;
  const STALE_EPSS_DAYS = opts.stale_epss_days || 90;
  const out = [];
  const cve = loaded["cve-catalog"];
  if (!cve) return out;

  for (const id of Object.keys(cve)) {
    if (id === "_meta") continue;
    const e = cve[id];
    if (!e) continue;

    const sinceVerified = daysSince(e.source_verified || e.last_verified, now);
    if (sinceVerified !== null && sinceVerified > STALE_VERIFIED_DAYS) {
      out.push({ class: "temporal-staleness", catalog: "cve-catalog", id,
        field: "source_verified", reason: `source_verified is ${sinceVerified}d old (threshold ${STALE_VERIFIED_DAYS}d)` });
    }
    const sinceUpdated = daysSince(e.last_updated, now);
    if (sinceUpdated !== null && sinceUpdated > STALE_UPDATED_DAYS) {
      out.push({ class: "temporal-staleness", catalog: "cve-catalog", id,
        field: "last_updated", reason: `last_updated is ${sinceUpdated}d old (threshold ${STALE_UPDATED_DAYS}d)` });
    }

    // A passed CISA KEV due-date is NOT temporal staleness: it is a fixed
    // external remediation deadline, and every historical entry's passes by
    // calendar while saying nothing about catalog currency.

    // EPSS has its own currency clock; FIRST recalculates daily.
    if (typeof e.epss_score === "number" && typeof e.epss_date === "string") {
      const sinceEpss = daysSince(e.epss_date, now);
      if (sinceEpss !== null && sinceEpss > STALE_EPSS_DAYS) {
        out.push({ class: "temporal-staleness", catalog: "cve-catalog", id,
          field: "epss_date", reason: `epss_date is ${sinceEpss}d old (threshold ${STALE_EPSS_DAYS}d); refresh via 'exceptd refresh --source epss'` });
      }
    }
  }
  return out;
}

// Multi-field rules: combinations that pass schema validation yet contradict.
function logicalConsistencyFindings(loaded) {
  const out = [];
  const cve = loaded["cve-catalog"];
  if (!cve) return out;

  for (const id of Object.keys(cve)) {
    if (id === "_meta") continue;
    const e = cve[id];
    if (!e) continue;

    // CISA's JSON carries dateAdded on every listing, so null means intake lost it.
    if (e.cisa_kev === true && (e.cisa_kev_date == null || e.cisa_kev_date === "")) {
      out.push({ class: "logical-consistency", catalog: "cve-catalog", id,
        rule: "cisa_kev_date_present_when_kev_true",
        reason: "cisa_kev:true requires cisa_kev_date (CISA's dateAdded)" });
    }

    // The RWEP deduction only holds when the tools list names a real live-patch path.
    if (e.live_patch_available === true
        && (!Array.isArray(e.live_patch_tools) || e.live_patch_tools.length === 0)) {
      out.push({ class: "logical-consistency", catalog: "cve-catalog", id,
        rule: "live_patch_tools_required_when_available",
        reason: "live_patch_available:true but live_patch_tools is empty — RWEP factor would mis-fire" });
    }

    // The schema validator catches discovery_source==unknown, not a too-short note.
    if (e.ai_discovered === true) {
      const note = e.ai_discovery_notes || e.discovery_attribution_note || "";
      if (typeof note !== "string" || note.length < 30) {
        out.push({ class: "logical-consistency", catalog: "cve-catalog", id,
          rule: "ai_discovery_attribution_text_required",
          reason: "ai_discovered:true but attribution text is missing or too short to name the AI tool" });
      }
    }

    if (e.active_exploitation === "confirmed"
        && (!Array.isArray(e.verification_sources) || e.verification_sources.length < 2)) {
      out.push({ class: "logical-consistency", catalog: "cve-catalog", id,
        rule: "confirmed_exploitation_needs_sources",
        reason: `active_exploitation:"confirmed" requires >= 2 verification_sources; have ${(e.verification_sources || []).length}` });
    }

    if (typeof e.rwep_score === "number"
        && (!e.rwep_factors || Object.keys(e.rwep_factors).length === 0)) {
      out.push({ class: "logical-consistency", catalog: "cve-catalog", id,
        rule: "rwep_factors_required_when_score_set",
        reason: "rwep_score declared but rwep_factors is empty — score is unjustified" });
    }
  }
  out.push(...kevListingDateFindings(loaded));
  return out;
}

// The dangling-ref class verifies the forward direction; this one verifies the
// back-reference: the target entry lists the CVE that cited it.
function crossRefCompletenessFindings(loaded) {
  const out = [];
  const cve = loaded["cve-catalog"];
  const cwe = loaded["cwe-catalog"];
  const att = loaded["attack-techniques"];
  const fwc = loaded["framework-control-gaps"];

  // Build forward-ref maps: target-id → set of CVE-IDs that cite it.
  const cveByCwe = new Map();
  const cveByAttack = new Map();
  const cveByFwc = new Map();

  for (const cid of Object.keys(cve || {})) {
    if (cid === "_meta") continue;
    const e = cve[cid];
    if (!e) continue;
    // Drafts excluded — an auto-imported entry has no curated refs yet.
    if (e._auto_imported) continue;
    for (const c of (e.cwe_refs || [])) {
      if (!cveByCwe.has(c)) cveByCwe.set(c, new Set());
      cveByCwe.get(c).add(cid);
    }
    for (const a of (e.attack_refs || [])) {
      if (!cveByAttack.has(a)) cveByAttack.set(a, new Set());
      cveByAttack.get(a).add(cid);
    }
    for (const k of Object.keys(e.framework_control_gaps || {})) {
      if (!cveByFwc.has(k)) cveByFwc.set(k, new Set());
      cveByFwc.get(k).add(cid);
    }
  }

  // CWE: every CVE-citation must be in the CWE entry's evidence_cves.
  for (const [cweId, citingSet] of cveByCwe.entries()) {
    const entry = cwe && cwe[cweId];
    if (!entry) continue; // dangling-ref class handles this
    const evidence = new Set(Array.isArray(entry.evidence_cves) ? entry.evidence_cves : []);
    const missing = [];
    for (const cid of citingSet) if (!evidence.has(cid)) missing.push(cid);
    if (missing.length > 0) {
      out.push({ class: "cross-ref-completeness", source: "cve-catalog", target: "cwe-catalog",
        target_id: cweId, reason: `CWE entry's evidence_cves missing ${missing.length} CVE(s) that cite it: ${missing.slice(0, 3).join(", ")}` });
    }
  }

  // Same back-ref check for ATT&CK and framework-control-gaps.
  for (const [attId, citingSet] of cveByAttack.entries()) {
    const entry = att && att[attId];
    if (!entry) continue;
    const evidence = new Set(Array.isArray(entry.cve_refs) ? entry.cve_refs : []);
    const missing = [];
    for (const cid of citingSet) if (!evidence.has(cid)) missing.push(cid);
    if (missing.length > 0) {
      out.push({ class: "cross-ref-completeness", source: "cve-catalog", target: "attack-techniques",
        target_id: attId, reason: `ATT&CK entry's cve_refs missing ${missing.length} CVE(s) that cite it: ${missing.slice(0, 3).join(", ")}` });
    }
  }
  for (const [fwId, citingSet] of cveByFwc.entries()) {
    const entry = fwc && fwc[fwId];
    if (!entry) continue;
    const evidence = new Set(Array.isArray(entry.evidence_cves) ? entry.evidence_cves : []);
    const missing = [];
    for (const cid of citingSet) if (!evidence.has(cid)) missing.push(cid);
    if (missing.length > 0) {
      out.push({ class: "cross-ref-completeness", source: "cve-catalog", target: "framework-control-gaps",
        target_id: fwId, reason: `framework-gap entry's evidence_cves missing ${missing.length} CVE(s) that cite it: ${missing.slice(0, 3).join(", ")}` });
    }
  }
  return out;
}

// Fields the schema requires today that were optional on older entries.
const REQUIRED_SINCE = {
  "cve-catalog": [
    { field: "ai_discovered", since: "0.12.36", check: (v) => typeof v === "boolean" },
    { field: "ai_assisted_weaponization", since: "0.12.36", check: (v) => typeof v === "boolean" },
    { field: "rwep_factors", since: "0.12.36", check: (v) => v && Object.keys(v).length > 0 }
  ]
};

function schemaEvolutionFindings(loaded) {
  const out = [];
  for (const catalogKey of Object.keys(REQUIRED_SINCE)) {
    const cat = loaded[catalogKey];
    if (!cat) continue;
    for (const id of Object.keys(cat)) {
      if (id === "_meta") continue;
      const e = cat[id];
      if (!e) continue;
      for (const r of REQUIRED_SINCE[catalogKey]) {
        if (!r.check(e[r.field])) {
          out.push({ class: "schema-evolution", catalog: catalogKey, id,
            field: r.field, since: r.since,
            reason: `${r.field} required since v${r.since}; missing on this entry` });
        }
      }
    }
  }
  return out;
}

// Past the SLA, an entry's un-curated state is itself the finding.
function operatorActionSlaFindings(loaded, opts = {}) {
  const now = opts.now || new Date();
  const AUTO_IMPORT_SLA_DAYS = opts.auto_import_sla_days || 60;
  const DRAFT_SLA_DAYS = opts.draft_sla_days || 90;
  const out = [];
  const cve = loaded["cve-catalog"];
  if (!cve) return out;

  for (const id of Object.keys(cve)) {
    if (id === "_meta") continue;
    const e = cve[id];
    if (!e) continue;
    if (e._auto_imported === true) {
      const age = daysSince(e.last_updated, now);
      if (age !== null && age > AUTO_IMPORT_SLA_DAYS) {
        out.push({ class: "operator-action-sla", catalog: "cve-catalog", id,
          reason: `_auto_imported entry is ${age}d old (SLA ${AUTO_IMPORT_SLA_DAYS}d); operator-curation pending` });
      }
    }
    if (e._draft === true) {
      const age = daysSince(e.last_updated, now);
      if (age !== null && age > DRAFT_SLA_DAYS) {
        out.push({ class: "operator-action-sla", catalog: "cve-catalog", id,
          reason: `_draft entry is ${age}d old (SLA ${DRAFT_SLA_DAYS}d); promote-or-quarantine SLA breached` });
      }
    }
  }
  return out;
}

// Entries nothing references — dead weight to repurpose or remove.

// Any id token in a skill body or playbook JSON counts as a reference, and the
// full text is scanned rather than the structured fields, because skill bodies
// cite ids in prose. The D3FEND alternative must cover D3-, D3A- and D3F-: a
// narrower `D3-[A-Z]+` misses a D3A- citation and mis-flags its entry as orphan.
const REFERENCE_TOKEN_RE = /\b(?:CWE-\d+|T\d{4}(?:\.\d{3})?|AML\.T\d{4}(?:\.\d{3})?|D3[AF]?-[A-Z0-9]+(?:-[A-Z0-9]+)*|RFC-\d+)\b/g;

function buildExternalRefs(rootPath) {
  // Returns { skillRefs, playbookRefs } as Sets of id strings; a missing
  // skills/ or playbooks/ tree yields an empty set rather than throwing.
  if (!rootPath) {
    const path = require("path");
    rootPath = path.join(__dirname, "..");
  }
  const path = require("path");
  const fs = require("fs");
  const skillRefs = new Set();
  const playbookRefs = new Set();
  const skillsDir = path.join(rootPath, "skills");
  if (fs.existsSync(skillsDir)) {
    for (const skillName of fs.readdirSync(skillsDir)) {
      const skillPath = path.join(skillsDir, skillName, "skill.md");
      if (!fs.existsSync(skillPath)) continue;
      const text = fs.readFileSync(skillPath, "utf8");
      const matches = text.match(REFERENCE_TOKEN_RE);
      if (matches) for (const m of matches) skillRefs.add(m);
    }
  }
  const playbooksDir = path.join(rootPath, "data", "playbooks");
  if (fs.existsSync(playbooksDir)) {
    for (const pbName of fs.readdirSync(playbooksDir)) {
      if (!pbName.endsWith(".json")) continue;
      const text = fs.readFileSync(path.join(playbooksDir, pbName), "utf8");
      const matches = text.match(REFERENCE_TOKEN_RE);
      if (matches) for (const m of matches) playbookRefs.add(m);
    }
  }
  return { skillRefs, playbookRefs };
}

function unusedOrphanFindings(loaded, opts = {}) {
  const out = [];
  // Auto-populate the reference sets when the caller supplies neither; a caller
  // wanting genuinely empty sets passes _autoLoadRefs:false.
  let skillRefs = opts.skillRefs;
  let playbookRefs = opts.playbookRefs;
  if (!skillRefs && !playbookRefs && opts._autoLoadRefs !== false) {
    const refs = buildExternalRefs(opts._rootPath);
    skillRefs = refs.skillRefs;
    playbookRefs = refs.playbookRefs;
  }
  skillRefs = skillRefs || new Set();
  playbookRefs = playbookRefs || new Set();
  const cve = loaded["cve-catalog"];
  const cveRefIds = new Set();
  for (const id of Object.keys(cve || {})) {
    if (id === "_meta") continue;
    const e = cve[id];
    if (!e) continue;
    for (const r of (e.cwe_refs || [])) cveRefIds.add(r);
    for (const r of (e.attack_refs || [])) cveRefIds.add(r);
    for (const r of (e.atlas_refs || [])) cveRefIds.add(r);
    for (const k of Object.keys(e.framework_control_gaps || {})) cveRefIds.add(k);
  }
  const isReferenced = (id) => skillRefs.has(id) || playbookRefs.has(id) || cveRefIds.has(id);

  for (const catKey of ["cwe-catalog", "attack-techniques", "atlas-ttps", "d3fend-catalog", "framework-control-gaps"]) {
    const cat = loaded[catKey];
    if (!cat) continue;
    for (const id of Object.keys(cat)) {
      if (id === "_meta") continue;
      const e = cat[id];
      if (!e) continue;
      if (e._auto_imported !== true) continue; // only flag auto-imported orphans
      if (e.forward_looking === true) continue; // legitimate forward-looking
      if (isReferenced(id)) continue;
      out.push({ class: "unused-orphan", catalog: catKey, id,
        reason: "auto-imported entry with zero references from skills / playbooks / CVE entries — consider quarantine or curation" });
    }
  }
  return out;
}

function runAllDetectors(loaded, opts = {}) {
  // Build the external reference sets once and thread them through, so a composed
  // run does not re-scan per detector or measure against different sets.
  const orphanOpts = { ...opts };
  if (!orphanOpts.skillRefs && !orphanOpts.playbookRefs && opts._autoLoadRefs !== false) {
    const refs = buildExternalRefs(opts._rootPath);
    orphanOpts.skillRefs = refs.skillRefs;
    orphanOpts.playbookRefs = refs.playbookRefs;
  }
  return [
    ...contentQualityFindings(loaded),
    ...temporalStalenessFindings(loaded, opts),
    ...logicalConsistencyFindings(loaded),
    ...crossRefCompletenessFindings(loaded),
    ...schemaEvolutionFindings(loaded),
    ...operatorActionSlaFindings(loaded, opts),
    ...unusedOrphanFindings(loaded, orphanOpts),
    ...pipelineWordingFindings(loaded)
  ];
}

// Every class runAllDetectors can emit. The budget gate asserts class-set equality
// against this list, so a detector added without a budget entry fails closed.
const DETECTOR_CLASSES = [
  "content-quality",
  "temporal-staleness",
  "logical-consistency",
  "cross-ref-completeness",
  "schema-evolution",
  "operator-action-sla",
  "unused-orphan",
  "pipeline-wording"
];

module.exports = {
  hasPlaceholderLanguage,
  hasPipelineWording,
  pipelineWordingFindings,
  PIPELINE_WORDING,
  kevListingDateFindings,
  KEV_LISTING_DATE,
  daysSince,
  contentQualityFindings,
  temporalStalenessFindings,
  logicalConsistencyFindings,
  crossRefCompletenessFindings,
  schemaEvolutionFindings,
  operatorActionSlaFindings,
  unusedOrphanFindings,
  runAllDetectors,
  buildExternalRefs,
  DETECTOR_CLASSES,
  REQUIRED_SINCE,
  PLACEHOLDER_SENTINELS,
  REFERENCE_TOKEN_RE
};
