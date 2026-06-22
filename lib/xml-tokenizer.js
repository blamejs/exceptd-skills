"use strict";
/**
 * lib/xml-tokenizer.js
 *
 * Minimal but proper XML/RSS/Atom tokenizer. Replaces the regex-based
 * parser in lib/source-advisories.js. The regex approach silently
 * failed on:
 *   - XML namespaces (`<atom:entry>` vs `<entry>`)
 *   - Nested CDATA
 *   - Self-closing `<link href="..."/>` vs container `<link>...</link>`
 *   - HTML-escaped entities inside titles
 *   - Multi-line title content
 *
 * Failures returned `[]` silently — operators never saw the parser was
 * broken on a given feed. This module fails loudly via tokenizer
 * errors so a parser regression is visible in the refresh report.
 *
 * Design constraints:
 *   - Zero runtime dependencies (the project ships with no deps).
 *   - Streaming-friendly via a callback API (does not buffer the whole
 *     DOM — relevant for the 15 MB IETF RFC index).
 *   - Namespace-aware via element-localname matching (the local-name
 *     of `<atom:entry>` is `entry`).
 *   - CDATA-correct: `<![CDATA[...]]>` content is passed through verbatim
 *     including unescaped `<` and `&`.
 *   - Entity-correct: the five named XML entities (lt, gt, amp, apos,
 *     quot) plus numeric character references (`&#NNN;`, `&#xHH;`)
 *     are decoded. Other named entities pass through unchanged (HTML
 *     entities in RSS bodies are a recoverable variant we tolerate).
 *
 * Not designed for: DTD parsing, XInclude, XSLT, or any external-entity
 * resolution. Feeds that need those features are outside the scope of
 * a security-tooling intake pipeline.
 *
 * API:
 *   const { parseFeed } = require("./xml-tokenizer");
 *   const items = parseFeed(xmlString);  // returns [{title, link, published, body}, ...]
 *
 * For lower-level use, the underlying tokenizer is exported too:
 *   const { tokenize } = require("./xml-tokenizer");
 *   tokenize(xml, { onTagOpen, onTagClose, onText, onCData });
 */

// Decode the five canonical XML entities + numeric character references.
// Unknown named entities pass through unchanged (we're tolerant of
// HTML-style entities that legitimately appear in RSS body text).
function decodeEntities(s) {
  if (typeof s !== "string") return s;
  return s.replace(/&(#x[0-9a-fA-F]+|#[0-9]+|[a-zA-Z]+);/g, (m, ref) => {
    if (ref[0] === "#") {
      const codepoint = ref[1] === "x" || ref[1] === "X"
        ? parseInt(ref.slice(2), 16)
        : parseInt(ref.slice(1), 10);
      if (!Number.isFinite(codepoint)) return m;
      try { return String.fromCodePoint(codepoint); } catch { return m; }
    }
    switch (ref) {
      case "lt": return "<";
      case "gt": return ">";
      case "amp": return "&";
      case "apos": return "'";
      case "quot": return '"';
      default: return m;  // unknown named entity — leave untouched
    }
  });
}

// Strip the optional `prefix:` from a namespaced element/attribute name.
function localName(qname) {
  const idx = qname.indexOf(":");
  return idx === -1 ? qname : qname.slice(idx + 1);
}

function parseAttrs(rawAttrs) {
  const out = {};
  if (!rawAttrs) return out;
  // Walk character-by-character so quoted values can contain `=` and
  // whitespace without confusing a regex.
  let i = 0;
  const len = rawAttrs.length;
  while (i < len) {
    while (i < len && /\s/.test(rawAttrs[i])) i++;
    if (i >= len) break;
    const nameStart = i;
    while (i < len && rawAttrs[i] !== "=" && !/\s/.test(rawAttrs[i])) i++;
    const name = rawAttrs.slice(nameStart, i);
    if (!name) break;
    while (i < len && /\s/.test(rawAttrs[i])) i++;
    if (rawAttrs[i] !== "=") {
      // Attribute with no value — uncommon in XML but tolerate.
      out[localName(name)] = "";
      continue;
    }
    i++; // skip '='
    while (i < len && /\s/.test(rawAttrs[i])) i++;
    const quote = rawAttrs[i];
    if (quote !== '"' && quote !== "'") {
      // Unquoted value — read until whitespace or end.
      const valStart = i;
      while (i < len && !/\s/.test(rawAttrs[i])) i++;
      out[localName(name)] = decodeEntities(rawAttrs.slice(valStart, i));
      continue;
    }
    i++; // skip opening quote
    const valStart = i;
    while (i < len && rawAttrs[i] !== quote) i++;
    out[localName(name)] = decodeEntities(rawAttrs.slice(valStart, i));
    i++; // skip closing quote
  }
  return out;
}

/**
 * Emit the character-data of a raw-text leaf element span `[start, end)`.
 *
 * CDATA sections inside the span are emitted verbatim (onCData if present,
 * else onText) exactly like the main loop's CDATA fast-path; all other bytes
 * — including a stray unescaped '<' or inline HTML — are entity-decoded and
 * emitted via onText. Keeping the CDATA contract here means a `<![CDATA[...]]>`
 * title still surfaces only its inner text, not the literal markers.
 */
function emitRawText(xml, start, end, H) {
  let p = start;
  while (p < end) {
    const c = xml.indexOf("<![CDATA[", p);
    if (c === -1 || c >= end) {
      const chunk = xml.slice(p, end);
      if (chunk.length && H.onText) H.onText(decodeEntities(chunk));
      return;
    }
    if (c > p) {
      const chunk = xml.slice(p, c);
      if (chunk.length && H.onText) H.onText(decodeEntities(chunk));
    }
    const cend = xml.indexOf("]]>", c + 9);
    // findRawTextEnd already guaranteed a terminated CDATA before the close
    // tag, so cend is within range; guard anyway.
    const inner = cend === -1 || cend > end ? xml.slice(c + 9, end) : xml.slice(c + 9, cend);
    if (H.onCData) H.onCData(inner);
    else if (H.onText) H.onText(inner);
    p = cend === -1 || cend > end ? end : cend + 3;
  }
}

/**
 * Locate the matching close tag of a raw-text leaf element.
 *
 * Scans `xml` from `start` (the byte after the leaf open tag's `>`) for the
 * first close tag `</...name>` whose local-name (namespace prefix stripped)
 * equals `name`. CDATA sections are skipped verbatim so a `</title>` that
 * legitimately appears inside `<![CDATA[ ... ]]>` is treated as literal text,
 * not as the element's terminator.
 *
 * Returns { contentEnd, next } on success — `contentEnd` is the index of the
 * close tag's leading `<`, `next` is the index just past its `>`. Returns null
 * when no matching close tag exists before EOF (genuinely truncated input).
 */
function findRawTextEnd(xml, start, name) {
  const len = xml.length;
  let j = start;
  while (j < len) {
    const lt = xml.indexOf("<", j);
    if (lt === -1) return null;
    // Step over a CDATA section so its contents (which may contain "</name>"
    // literally) cannot satisfy the close-tag match.
    if (xml.startsWith("<![CDATA[", lt)) {
      const cend = xml.indexOf("]]>", lt + 9);
      if (cend === -1) return null; // unterminated CDATA → truncated
      j = cend + 3;
      continue;
    }
    if (xml[lt + 1] === "/") {
      const gt = xml.indexOf(">", lt + 2);
      if (gt === -1) return null;
      const closeName = localName(xml.slice(lt + 2, gt).trim());
      if (closeName === name) {
        return { contentEnd: lt, next: gt + 1 };
      }
      j = gt + 1;
      continue;
    }
    // Any other '<' (stray literal '<', or an inner open tag like <b>) is part
    // of the leaf's character data — advance past it without classifying.
    j = lt + 1;
  }
  return null;
}

/**
 * Streaming tokenizer. Calls handlers in document order. Returns no
 * value — accumulation is the caller's responsibility.
 *
 * Handlers (all optional):
 *   onTagOpen(name, attrs, selfClosing)
 *   onTagClose(name)
 *   onText(text)         decoded
 *   onCData(text)        verbatim, not decoded
 *   onComment(text)
 *   onPI(name, content)  processing instructions (<?xml-stylesheet?>)
 *   onError(message, position)
 *
 * Options (second-position fields on the handlers object):
 *   rawTextElements   Set<string> of leaf-element local-names whose content
 *                     is #PCDATA — once such an element opens, every byte up
 *                     to the matching `</name>` close tag is treated as
 *                     character data (entities decoded, then onText), exactly
 *                     like the CDATA fast-path. This makes leaf fields tolerant
 *                     of stray unescaped '<' (e.g. "affects versions < 5.0"),
 *                     which real RSS/Atom routinely emits, instead of letting a
 *                     recoverable lexical glitch silently drop the whole field.
 *                     Structural parsing stays strict for container elements.
 */
function tokenize(xml, handlers) {
  const H = handlers || {};
  if (typeof xml !== "string") {
    if (H.onError) H.onError("input must be a string", 0);
    return;
  }
  const rawTextElements = H.rawTextElements instanceof Set ? H.rawTextElements : null;
  const len = xml.length;
  let i = 0;
  // Open-tag stack — surfaces EOF-with-unclosed-elements as an error
  // instead of silently dropping the residual content. This is the
  // observability gap the v0.13.17 regex parser had: a malformed feed
  // (truncated mid-element) returned `[]` with no signal that the
  // parser had given up.
  const openStack = [];
  while (i < len) {
    const next = xml.indexOf("<", i);
    if (next === -1) {
      // Trailing text — flush.
      const tail = xml.slice(i);
      if (tail.length && H.onText) H.onText(decodeEntities(tail));
      if (openStack.length && H.onError) {
        H.onError("unterminated element at EOF: " + openStack[openStack.length - 1], len);
      }
      return;
    }
    if (next > i) {
      const text = xml.slice(i, next);
      if (text.length && H.onText) H.onText(decodeEntities(text));
    }
    // Now at `<` — classify the construct.
    if (xml.startsWith("<!--", next)) {
      const end = xml.indexOf("-->", next + 4);
      if (end === -1) {
        if (H.onError) H.onError("unterminated comment", next);
        return;
      }
      if (H.onComment) H.onComment(xml.slice(next + 4, end));
      i = end + 3;
      continue;
    }
    if (xml.startsWith("<![CDATA[", next)) {
      const end = xml.indexOf("]]>", next + 9);
      if (end === -1) {
        if (H.onError) H.onError("unterminated CDATA section", next);
        return;
      }
      // CDATA content is verbatim — entities NOT decoded.
      if (H.onCData) H.onCData(xml.slice(next + 9, end));
      else if (H.onText) H.onText(xml.slice(next + 9, end));
      i = end + 3;
      continue;
    }
    if (xml.startsWith("<?", next)) {
      const end = xml.indexOf("?>", next + 2);
      if (end === -1) {
        if (H.onError) H.onError("unterminated processing instruction", next);
        return;
      }
      if (H.onPI) {
        const piBody = xml.slice(next + 2, end).trim();
        const spaceAt = piBody.indexOf(" ");
        const name = spaceAt === -1 ? piBody : piBody.slice(0, spaceAt);
        const content = spaceAt === -1 ? "" : piBody.slice(spaceAt + 1);
        H.onPI(name, content);
      }
      i = end + 2;
      continue;
    }
    if (xml.startsWith("<!", next)) {
      // DOCTYPE or other declaration — skip to next `>` at depth zero.
      let depth = 1;
      let j = next + 2;
      while (j < len && depth > 0) {
        if (xml[j] === "<") depth++;
        else if (xml[j] === ">") depth--;
        if (depth > 0) j++;
      }
      if (depth !== 0) {
        if (H.onError) H.onError("unterminated declaration", next);
        return;
      }
      i = j + 1;
      continue;
    }
    // Element tag — open / close / self-closing.
    const close = xml.indexOf(">", next);
    if (close === -1) {
      if (H.onError) H.onError("unterminated element tag", next);
      return;
    }
    let inner = xml.slice(next + 1, close);
    let isClose = false;
    let selfClose = false;
    if (inner.startsWith("/")) { isClose = true; inner = inner.slice(1); }
    if (inner.endsWith("/")) { selfClose = true; inner = inner.slice(0, -1); }
    inner = inner.trim();
    // Split name and attrs at the first whitespace.
    const wsAt = inner.search(/\s/);
    const rawName = wsAt === -1 ? inner : inner.slice(0, wsAt);
    const rawAttrs = wsAt === -1 ? "" : inner.slice(wsAt + 1);
    const name = localName(rawName);
    if (isClose) {
      if (openStack.length && openStack[openStack.length - 1] === name) openStack.pop();
      if (H.onTagClose) H.onTagClose(name);
    } else {
      const attrs = parseAttrs(rawAttrs);
      if (H.onTagOpen) H.onTagOpen(name, attrs, selfClose);
      if (selfClose) {
        if (H.onTagClose) H.onTagClose(name);
      } else if (rawTextElements && rawTextElements.has(name)) {
        // Raw-text leaf element (title/summary/description/...). Its content
        // is #PCDATA: scan to the matching `</name>` and treat the whole span
        // as character data — only the matching close tag terminates it. Any
        // inner '<...>' (a stray unescaped '<', or inline HTML like <b>) is
        // preserved as text and normalized later by stripHtml(), instead of
        // being misclassified as markup and silently dropping the field.
        const span = findRawTextEnd(xml, close + 1, name);
        if (span === null) {
          // Genuinely truncated: the leaf never closes before EOF. Surface
          // the loud-error contract just like the structural path would, then
          // flush the residual as text and stop.
          if (H.onError) H.onError("unterminated element at EOF: " + name, len);
          const tail = xml.slice(close + 1);
          if (tail.length && H.onText) H.onText(decodeEntities(tail));
          return;
        }
        emitRawText(xml, close + 1, span.contentEnd, H);
        if (H.onTagClose) H.onTagClose(name);
        i = span.next;
        continue;
      } else {
        openStack.push(name);
      }
    }
    i = close + 1;
  }
  if (openStack.length && H.onError) {
    H.onError("unterminated element at EOF: " + openStack[openStack.length - 1], len);
  }
}

// Leaf-element local-names whose content is character-data (#PCDATA). When
// one of these opens, the tokenizer runs in raw-text mode until the matching
// close tag, so a stray unescaped '<' inside the field (e.g. "affects
// versions < 5.0") is preserved as text instead of being misclassified as
// markup and silently dropping the whole field.
const LEAF_FIELDS = new Set([
  "title", "link", "pubDate", "published", "updated",
  "description", "content", "summary",
]);

// rel-rank for Atom <link> sibling selection. RFC 4287: a <link> with no rel
// defaults to rel="alternate", the canonical article URL. A non-alternate rel
// (self / replies / edit / enclosure) should never clobber an alternate.
function relRank(rel) {
  if (rel == null || rel === "" || String(rel).toLowerCase() === "alternate") return 2;
  return 1;
}

/**
 * Parse an RSS / Atom feed, always collecting parse errors.
 *
 * Returns { items, errors } where errors is an array of
 * { message, position } records. This is the channel a caller cannot forget
 * to opt into — parseFeed() below is a thin back-compat wrapper.
 *
 *   items: [{ title, link, published, body }, ...]
 */
function parseFeedDetailed(xml) {
  const items = [];
  const errors = [];
  // Stack of "in-progress item" contexts. RSS uses <item>; Atom uses
  // <entry>; both nest title / link / pubDate / published / updated /
  // description / content / summary.
  const ITEM_LOCALS = new Set(["item", "entry"]);
  const FIELD_MAP = {
    title: "title",
    link: "link",
    pubDate: "published",
    published: "published",
    updated: "published",
    description: "body",
    content: "body",
    summary: "body"
  };
  let current = null;       // active item context
  let activeField = null;   // active field local-name
  let buffer = "";          // accumulator for current field text
  let linkRank = 0;         // rel-rank of the best <link> captured so far

  tokenize(xml, {
    rawTextElements: LEAF_FIELDS,
    onTagOpen(name, attrs, selfClosing) {
      if (ITEM_LOCALS.has(name)) {
        current = { title: "", link: "", published: "", body: "" };
        linkRank = 0;
        return;
      }
      if (!current) return;
      if (FIELD_MAP[name]) {
        activeField = FIELD_MAP[name];
        buffer = "";
        // Atom <link href="..."/> — rel-aware selection. Only let an
        // alternate / rel-absent link upgrade the captured value, and never
        // let a non-alternate rel (self/replies/edit) clobber an alternate
        // already in hand. First-alternate-wins, independent of document
        // order.
        if (name === "link" && attrs && attrs.href) {
          const r = relRank(attrs.rel);
          if (r > linkRank) {
            current.link = attrs.href;
            linkRank = r;
          }
          // The link value has been resolved from the attribute — there is
          // no element-text close to wait for.
          if (selfClosing) activeField = null;
        }
      }
    },
    onTagClose(name) {
      if (ITEM_LOCALS.has(name)) {
        if (current) items.push(current);
        current = null;
        activeField = null;
        buffer = "";
        linkRank = 0;
        return;
      }
      if (!current) return;
      if (FIELD_MAP[name] && activeField === FIELD_MAP[name]) {
        const value = buffer.trim();
        // RSS <link>...</link> — element text is authoritative (rank 2),
        // unconditional. An empty element-text link falls back to whatever
        // attribute capture onTagOpen already recorded.
        if (name === "link") {
          if (value) {
            current.link = value;
            linkRank = 2;
          }
        } else if (activeField === "body" || activeField === "title") {
          // Strip HTML tags from title + description / content / summary.
          // Many feeds embed inline HTML (<b>, <em>, <a>) in titles for
          // emphasis; the operational consumer wants plain text. CDATA
          // content reaches here verbatim, so this also strips HTML
          // that was wrapped in CDATA to dodge entity-encoding. A stray
          // unescaped '<' that survived raw-text mode collapses here too.
          current[activeField] = stripHtml(value);
        } else {
          current[activeField] = value;
        }
        activeField = null;
        buffer = "";
      }
    },
    onText(text) {
      if (activeField) buffer += text;
    },
    onCData(text) {
      if (activeField) buffer += text;
    },
    onError(msg, pos) {
      errors.push({ message: msg, position: pos });
    }
  });

  return { items, errors };
}

/**
 * Parse an RSS / Atom feed into a flat array of items. Returns:
 *   [{ title, link, published, body }, ...]
 *
 * Empty array on parse failure. Errors are ALWAYS collected internally; the
 * optional `errors` array is filled for callers that pass one (back-compat).
 * Prefer parseFeedDetailed(xml) for new callers — it returns the errors
 * channel unconditionally so it cannot be silently dropped.
 */
function parseFeed(xml, errors = null) {
  const { items, errors: collected } = parseFeedDetailed(xml);
  if (Array.isArray(errors)) {
    for (const e of collected) errors.push(e);
  }
  return items;
}

function stripHtml(s) {
  if (typeof s !== "string") return "";
  // First strip tags, then collapse runs of whitespace including
  // newlines. Entity decoding has already happened by this point.
  return s.replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim();
}

module.exports = { tokenize, parseFeed, parseFeedDetailed, decodeEntities, localName, parseAttrs, stripHtml };
