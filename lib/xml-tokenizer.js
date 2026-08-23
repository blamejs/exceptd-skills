"use strict";
/**
 * Minimal XML/RSS/Atom tokenizer with no runtime dependencies.
 *
 *   parseFeed(xmlString) → [{title, link, published, body}, ...]
 *   tokenize(xml, { onTagOpen, onTagClose, onText, onCData })
 *
 * Streams through callbacks rather than a buffered DOM, which matters for the
 * 15 MB IETF RFC index. Elements match on local-name, so `<atom:entry>` and
 * `<entry>` are the same element. No DTD parsing, XInclude, XSLT, or
 * external-entity resolution.
 */

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

function localName(qname) {
  const idx = qname.indexOf(":");
  return idx === -1 ? qname : qname.slice(idx + 1);
}

function parseAttrs(rawAttrs) {
  const out = {};
  if (!rawAttrs) return out;
  // Character-by-character, so a quoted value may contain `=` and whitespace.
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
 * Emits the character data of a raw-text leaf element span `[start, end)`. CDATA
 * inside the span goes out verbatim (onCData, else onText); every other byte —
 * a stray unescaped '<' or inline HTML included — is entity-decoded via onText.
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
    // findRawTextEnd guarantees a terminated CDATA here; guarded anyway.
    const inner = cend === -1 || cend > end ? xml.slice(c + 9, end) : xml.slice(c + 9, cend);
    if (H.onCData) H.onCData(inner);
    else if (H.onText) H.onText(inner);
    p = cend === -1 || cend > end ? end : cend + 3;
  }
}

/**
 * Finds the close tag of a raw-text leaf element, scanning from `start` (the byte
 * after the open tag's `>`) for the first `</...name>` whose local-name is `name`.
 * CDATA is skipped, so a `</title>` inside `<![CDATA[ ... ]]>` is literal text.
 * Returns `{ contentEnd, next }` — the index of the close tag's `<`, and the index
 * just past its `>` — or null when no close tag exists before EOF.
 */
function findRawTextEnd(xml, start, name) {
  const len = xml.length;
  let j = start;
  while (j < len) {
    const lt = xml.indexOf("<", j);
    if (lt === -1) return null;
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
    // Any other '<' is part of the leaf's character data — advance past it.
    j = lt + 1;
  }
  return null;
}

/**
 * Streaming tokenizer. Calls handlers in document order. Returns no value —
 * accumulation is the caller's responsibility.
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
 * `rawTextElements`, a Set of local-names on the same object, marks leaf elements
 * whose content is #PCDATA: every byte up to the matching `</name>` is character
 * data, so a stray unescaped '<' does not drop the field. Containers stay strict.
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
  // The open-tag stack turns unclosed-at-EOF into an error, not dropped content.
  const openStack = [];
  while (i < len) {
    const next = xml.indexOf("<", i);
    if (next === -1) {
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
        // A raw-text leaf: only the matching `</name>` terminates it. Inner
        // '<...>' stays text for stripHtml(), rather than being classified as markup.
        const span = findRawTextEnd(xml, close + 1, name);
        if (span === null) {
          // Never closes before EOF: report as the structural path does, flush, stop.
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

// The leaf elements parsed in raw-text mode — see tokenize()'s rawTextElements.
const LEAF_FIELDS = new Set([
  "title", "link", "pubDate", "published", "updated",
  "description", "content", "summary",
]);

// rel-rank for Atom <link> sibling selection. RFC 4287: a <link> with no rel
// defaults to rel="alternate", so a non-alternate must never clobber one.
function relRank(rel) {
  if (rel == null || rel === "" || String(rel).toLowerCase() === "alternate") return 2;
  return 1;
}

/**
 * Parses an RSS / Atom feed into `{ items, errors }`, where items are
 * `{ title, link, published, body }` and errors are `{ message, position }`.
 * The errors channel cannot be opted out of, so prefer this over parseFeed().
 */
function parseFeedDetailed(xml) {
  const items = [];
  const errors = [];
  // RSS uses <item>, Atom uses <entry>; both nest the same leaf fields.
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
  let linkRel = null;       // rel of the link element currently open (for its element-text close)

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
        // Remembered so the close below ranks the link as this path does.
        if (name === "link") linkRel = attrs ? attrs.rel : null;
        // Only an alternate or rel-absent link upgrades the captured value,
        // whatever the document order.
        if (name === "link" && attrs && attrs.href) {
          const r = relRank(attrs.rel);
          if (r > linkRank) {
            current.link = attrs.href;
            linkRank = r;
          }
          // Resolved from the attribute — no element-text close to wait for.
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
        // Element text goes through the same rel gate as the attribute path; RSS
        // links carry no rel, so relRank(undefined) is 2 and they keep the top rank.
        if (name === "link") {
          const r = relRank(linkRel);
          if (value && r > linkRank) {
            current.link = value;
            linkRank = r;
          }
          linkRel = null;
        } else if (activeField === "body" || activeField === "title") {
          // Feeds embed inline HTML in titles and bodies. CDATA reaches here
          // verbatim, so HTML wrapped in CDATA to dodge encoding is stripped too.
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
 * Parses an RSS / Atom feed into `[{ title, link, published, body }, ...]`, or an
 * empty array on parse failure. Errors are copied into the optional `errors` array
 * when a caller passes one and dropped otherwise: prefer parseFeedDetailed().
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
  // Single-pass, because a backtracking /<[^>]+>/g is O(n^2) on feed text with many
  // '<' and no '>' — a ReDoS-class DoS, since parseFeed() runs on network-fetched
  // bodies. A stray '<' with no closing '>' and an empty '<>' survive as text.
  let out = "";
  let i = 0;
  while (i < s.length) {
    const lt = s.indexOf("<", i);
    if (lt === -1) { out += s.slice(i); break; }
    out += s.slice(i, lt);
    const gt = s.indexOf(">", lt + 1);
    if (gt === -1) { out += s.slice(lt); break; }       // stray '<' -> literal
    if (gt === lt + 1) { out += "<>"; i = gt + 1; continue; } // empty '<>' is not a tag
    out += " ";                                          // a real tag -> space
    i = gt + 1;
  }
  return out.replace(/\s+/g, " ").trim();
}

module.exports = { tokenize, parseFeed, parseFeedDetailed, decodeEntities, localName, parseAttrs, stripHtml };
