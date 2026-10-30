"use strict";
// bm25: lexical code search over overlapping line chunks, zero dependencies.
// grep finds a string; this finds the part of the codebase a question is about ("where do we
// retry failed uploads") by ranking ~60-line chunks with Okapi BM25. Identifiers are split into
// their words (retryUpload -> retry, upload, retryupload) so prose questions match code, and a
// chunk is returned as a path + line range, so the caller reads fresh lines from disk.
//
// Pure: chunkText / buildIndex / search take strings and plain objects; the caller walks the
// filesystem and stores the index (plain JSON).

const VERSION = 3; // 3: words are stemmed (an older index is rebuilt, not misread)
const CHUNK_LINES = 60, CHUNK_STEP = 50; // 10 lines of overlap so a function cut at a boundary is whole in one chunk

// English and code filler that matches everything and ranks nothing.
const STOP = new Set(("the a an and or of to in on for is are was be it this that with as at by from we our you your " +
  "how where what when which why who does do did can should would could will not no yes into out up if else then " +
  "var let const return function true false null undefined new self def end use used using get set").split(" "));

// Light suffix stemming so prose meets code: "uploads" / "uploaded" / "uploading" -> "upload",
// "retried" / "retries" -> "retry". Applied the same way to the index and the query, so a stem only
// has to be consistent, not a real word. Short words and -ss/-us/-is endings are left alone.
function stem(w) {
  if (w.length <= 4 || /\d/.test(w)) return w;
  if (/ie[sd]$/.test(w)) return w.slice(0, -3) + "y";
  if (/ing$/.test(w) && w.length > 5) return w.slice(0, -3);
  if (/ed$/.test(w) && w.length > 5) return w.slice(0, -2);
  if (/sses$/.test(w)) return w.slice(0, -2);
  if (/s$/.test(w) && !/(ss|us|is)$/.test(w)) return w.slice(0, -1);
  return w;
}

// "retryUpload_v2" -> ["retryupload_v2", "retry", "upload", "v2"]; words under 2 chars and stop words
// dropped; single words are stemmed, a whole multi-part identifier is kept as written.
function tokenize(text) {
  const out = [];
  const s = String(text || "");
  const re = /[A-Za-z_$][\w$]*|\d{2,}/g;
  let m;
  while ((m = re.exec(s))) {
    const w = m[0];
    const lw = w.toLowerCase();
    const parts = w.replace(/([a-z0-9])([A-Z])/g, "$1 $2").replace(/([A-Z]+)([A-Z][a-z])/g, "$1 $2").split(/[\s_$]+/).map((p) => p.toLowerCase()).filter(Boolean);
    if (lw.length >= 2 && !STOP.has(lw)) out.push(parts.length > 1 ? lw : stem(lw));
    if (parts.length > 1) for (const p of parts) if (p.length >= 2 && !STOP.has(p)) out.push(stem(p));
  }
  return out;
}

// Split one file into overlapping line windows: [{ start, end, text }] with 1-based inclusive lines.
function chunkText(content, opts) {
  const size = (opts && opts.lines) || CHUNK_LINES, step = (opts && opts.step) || CHUNK_STEP;
  const lines = String(content || "").split("\n");
  if (lines.length && lines[lines.length - 1] === "") lines.pop();
  const out = [];
  for (let i = 0; i < lines.length; i += step) {
    const end = Math.min(lines.length, i + size);
    out.push({ start: i + 1, end, text: lines.slice(i, end).join("\n") });
    if (end >= lines.length) break;
  }
  return out;
}

// Share of a chunk's non-space characters that sit inside string literals. Payload lists,
// wordlists and embedded datasets score 0.8-1.0; real code sits around 0.1-0.35. Data chunks match
// almost any question by sheer vocabulary, so the index leaves them out.
function stringShare(text) {
  const lits = String(text).match(/(["'`])(?:\\.|(?!\1)[^\\\n])*\1/g) || [];
  let n = 0; for (const l of lits) n += l.replace(/\s/g, "").length;
  return n / Math.max(1, String(text).replace(/\s/g, "").length);
}

// files: [{ path, content }]. The path's own words count as part of every chunk in it (a question
// about "billing" should find billing/invoice.js even if the word is rare inside it).
function buildIndex(files, opts) {
  const docs = [], df = Object.create(null);
  let total = 0;
  for (const f of files || []) {
    if (!f || typeof f.path !== "string" || typeof f.content !== "string") continue;
    const pathToks = tokenize(f.path.replace(/\.[a-z0-9]+$/i, "").replace(/[\/.-]/g, " "));
    for (const c of chunkText(f.content, opts)) {
      if (!/\.(md|txt|rst)$/i.test(f.path) && stringShare(c.text) > ((opts && opts.maxStringShare) || 0.6)) continue;
      const tf = Object.create(null);
      let len = 0;
      for (const t of tokenize(c.text).concat(pathToks)) { tf[t] = (tf[t] || 0) + 1; len++; }
      if (!len) continue;
      for (const t in tf) df[t] = (df[t] || 0) + 1;
      docs.push({ path: f.path, start: c.start, end: c.end, len, tf });
      total += len;
    }
  }
  return { version: VERSION, N: docs.length, avgdl: docs.length ? total / docs.length : 0, df, docs };
}

// Okapi BM25 (k1 1.2, b 0.75). Returns the top k chunks, best first, at most `perFile` from one
// file (default 2) so a single huge file can't fill the list. [{ path, start, end, score, terms }].
function search(index, query, opts) {
  opts = opts || {};
  const k = opts.k || 5, perFile = opts.perFile || 2, k1 = 1.2, b = 0.75;
  if (!index || index.version !== VERSION || !index.N) return [];
  // own-property reads only: a stored index is parsed JSON, so "constructor" would hit Object.prototype
  const has = (o, t) => Object.prototype.hasOwnProperty.call(o, t);
  const qTerms = [...new Set(tokenize(query))].filter((t) => has(index.df, t));
  if (!qTerms.length) return [];
  const idf = Object.create(null);
  for (const t of qTerms) idf[t] = Math.log(1 + (index.N - index.df[t] + 0.5) / (index.df[t] + 0.5));
  const scored = [];
  for (const d of index.docs) {
    let s = 0, matched = 0;
    for (const t of qTerms) {
      const f = has(d.tf, t) ? d.tf[t] : 0;
      if (!f) continue;
      matched++;
      s += idf[t] * (f * (k1 + 1)) / (f + k1 * (1 - b + b * d.len / index.avgdl));
    }
    if (s > 0) scored.push({ path: d.path, start: d.start, end: d.end, score: s, terms: matched });
  }
  scored.sort((x, y) => y.score - x.score || x.path.localeCompare(y.path) || x.start - y.start);
  const out = [], per = new Map();
  for (const r of scored) {
    const n = per.get(r.path) || 0;
    if (n >= perFile) continue;
    // an overlapping window of a chunk already taken adds little; skip it
    if (out.some((o) => o.path === r.path && r.start <= o.end && o.start <= r.end)) continue;
    per.set(r.path, n + 1); out.push(r);
    if (out.length >= k) break;
  }
  return out;
}

module.exports = { stem, tokenize, chunkText, stringShare, buildIndex, search, VERSION, STOP };
