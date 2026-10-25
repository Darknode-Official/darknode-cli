"use strict";
// ================= edit: reliable code edits (multi-edit · flexible match · patch) =================
// Nexus's local agent edited files with a single literal find/replace. That is safe but brittle:
// weak models miscount whitespace, want several edits at once, or emit a unified diff. This module
// makes edits land without becoming unsafe:
//   - applyEdits(content, edits)        atomic multi-edit (all-or-nothing), literal, uniqueness-checked
//   - locateFlexible(content, find)     whitespace-flexible line match, ONLY when it is unambiguous
//   - applyEditsFlexible(content, edits) exact first, then a single-match flexible fallback
//   - parsePatch(patch) / applyPatch    apply a unified diff by ANCHORING on context (drift-proof)
// Everything is pure (string in, string out) and covered by test/run.js. The guiding rule matches
// the rest of Nexus: never guess. A find that is missing, or that matches two places, is an ERROR,
// never a silent edit.

// ---- literal, atomic multi-edit --------------------------------------------------------------
// edits: [{ find, replace, replaceAll? }]. Applied in order against the evolving content. Fails
// (touching nothing) if any find is absent, or matches >1 place without replaceAll.
const isTrue = (v) => v === true || v === 1 || (typeof v === "string" && /^(true|1|yes)$/i.test(v.trim()));
const normEdits = (edits) => Array.isArray(edits) ? edits.map((e) => Object.assign({}, e || {}, { replaceAll: isTrue((e || {}).replaceAll) })) : edits;
function applyEdits(content, edits) {
  if (typeof content !== "string") return { ok: false, error: "content must be a string" };
  if (!Array.isArray(edits) || !edits.length) return { ok: false, error: "no edits given" };
  edits = normEdits(edits);
  let out = content; const applied = [];
  for (let i = 0; i < edits.length; i++) {
    const e = edits[i] || {};
    const find = e.find, repl = e.replace == null ? "" : e.replace;
    if (typeof find !== "string" || !find.length) return { ok: false, error: "edit " + (i + 1) + ": empty find", applied: [] };
    if (find === repl) return { ok: false, error: "edit " + (i + 1) + ": find and replace are identical", applied: [] };
    const occ = out.split(find).length - 1;
    if (occ === 0) return { ok: false, error: "edit " + (i + 1) + ": find text not present — check exact whitespace/indentation", applied: [] };
    if (occ > 1 && !e.replaceAll) return { ok: false, error: "edit " + (i + 1) + ": find matches " + occ + " places — add context to make it unique, or set replaceAll", applied: [] };
    out = e.replaceAll ? out.split(find).join(repl) : out.replace(find, () => repl);
    applied.push({ find: find.slice(0, 40), count: e.replaceAll ? occ : 1 });
  }
  return { ok: true, content: out, applied };
}

const normWs = (l) => l.replace(/\s+/g, " ").trim();
// Leading whitespace of the first non-empty line, and a re-indent that shifts every non-empty line
// by `delta` columns (adding spaces, or stripping leading whitespace). Used so a flexible/patch
// replacement that omitted indentation lands at the indentation of the block it replaced.
const leadWs = (s) => { const first = String(s).split("\n").find((l) => l.trim() !== "") || ""; return (first.match(/^\s*/) || [""])[0]; };
const reindentBlock = (text, delta) => { if (!delta) return text; return String(text).split("\n").map((l) => { if (l.trim() === "") return l; if (delta > 0) return " ".repeat(delta) + l; let k = 0; while (k < -delta && k < l.length && /\s/.test(l[k])) k++; return l.slice(k); }).join("\n"); };

// Locate `find` in `content` ignoring per-line indentation and internal whitespace runs, matching
// on whole lines. Returns { count, start, end } (char offsets of the matched line block) when the
// block occurs exactly once; count:0 or count>1 otherwise. Never returns a location when ambiguous.
// Re-indent a replacement onto a TAB-indented block: each line keeps its indent
// relative to the find's base, with space runs converted to tabs (unit = the
// smallest relative space indent), so a Makefile/Go/tabbed file never gains
// spaces or mixed indentation.
function reindentTabs(text, findBase, target) {
  const ls = String(text).split("\n");
  const rels = ls.map((l) => { const lead = (l.match(/^[ \t]*/) || [""])[0]; return lead.startsWith(findBase) ? lead.slice(findBase.length) : lead; });
  const spaceLens = rels.map((r) => (r.match(/^ +/) || [""])[0].length).filter((n) => n > 0);
  const unit = spaceLens.length ? Math.min.apply(null, spaceLens) : 4;
  return ls.map((l, i) => { if (l.trim() === "") return l; const r = rels[i].replace(/ +/g, (m) => "\t".repeat(Math.max(1, Math.round(m.length / unit)))); return target + r + l.replace(/^[ \t]*/, ""); }).join("\n");
}

function locateFlexible(content, find) {
  const cLines = content.split("\n");
  let fLines = String(find).split("\n");
  while (fLines.length && fLines[fLines.length - 1].trim() === "") fLines.pop();
  while (fLines.length && fLines[0].trim() === "") fLines.shift();
  if (!fLines.length) return { count: 0 };
  const fNorm = fLines.map(normWs);
  const hits = [];
  for (let i = 0; i + fNorm.length <= cLines.length; i++) {
    let ok = true;
    for (let j = 0; j < fNorm.length; j++) if (normWs(cLines[i + j]) !== fNorm[j]) { ok = false; break; }
    if (ok) hits.push(i);
  }
  if (hits.length !== 1) return { count: hits.length };
  // char offsets of the matched block (join with the same \n the split used)
  const startLine = hits[0], endLine = hits[0] + fNorm.length;
  const start = cLines.slice(0, startLine).reduce((n, l) => n + l.length + 1, 0);
  const end = start + cLines.slice(startLine, endLine).join("\n").length;
  return { count: 1, start, end, startLine, indent: (cLines[startLine].match(/^\s*/) || [""])[0] };
}

// Exact multi-edit first; for any edit whose literal find is absent, fall back to a SINGLE-match
// flexible locate and replace that block verbatim (re-indented to the matched block when the
// replacement carries no indentation of its own). Reports the mode of each applied edit.
// ---- failure hints: a bare "not found" makes a model retry blindly ----------------------
// Line numbers of exact occurrences (for "matches N places").
function whereLines(content, find, max) {
  const out = []; let i = -1;
  while ((i = content.indexOf(find, i + 1)) >= 0 && out.length < (max || 5)) out.push(content.slice(0, i).split("\n").length);
  return out;
}
// Character-bigram Dice similarity (0..1) — cheap and robust to small typos.
function dice(a, b) {
  if (a === b) return 1; if (a.length < 2 || b.length < 2) return 0;
  const m = new Map(); for (let i = 0; i < a.length - 1; i++) { const g = a.slice(i, i + 2); m.set(g, (m.get(g) || 0) + 1); }
  let hit = 0; for (let i = 0; i < b.length - 1; i++) { const g = b.slice(i, i + 2), c = m.get(g); if (c) { hit++; m.set(g, c - 1); } }
  return (2 * hit) / (a.length + b.length - 2);
}
const SMART = /[\u2018\u2019\u201c\u201d\u2013\u2014\u00a0]/;
// Why a find was not found, and the closest line in the file.
function missHint(content, find, repl) {
  const hints = [];
  // "already applied" only when the replacement is distinctive: a whole line of the file, or
  // long enough not to occur by chance (replacing with "x" must not match `const x`).
  const rt = repl ? repl.trim() : "";
  const distinct = rt.length >= 4 && (rt.includes("\n") ? content.includes(rt) : content.split("\n").some((l) => l.trim() === rt) || (rt.length >= 12 && content.includes(rt)));
  if (distinct && !content.includes(find)) hints.push("the replacement text is already in the file — this edit looks already applied; re-read before editing again");
  if (SMART.test(find) && !SMART.test(content)) hints.push("find has curly quotes/dashes/nbsp but the file uses plain ASCII ones");
  const first = find.split("\n").map((l) => l.trim()).filter((l) => l.length > 3)[0];
  if (first) {
    const lines = content.split("\n"); let best = 0, at = -1;
    for (let i = 0; i < lines.length; i++) { const t = lines[i].trim(); if (!t || Math.abs(t.length - first.length) > Math.max(20, first.length)) continue; const sc = dice(first.slice(0, 200), t.slice(0, 200)); if (sc > best) { best = sc; at = i; } }
    if (at >= 0 && best >= 0.6) hints.push("closest line " + (at + 1) + ": " + lines[at].trim().slice(0, 160));
  }
  return hints.length ? " — " + hints.join("; ") : "";
}

function applyEditsFlexible(content, edits) {
  const exact = applyEdits(content, edits);
  if (exact.ok) return { ok: true, content: exact.content, applied: exact.applied.map((a) => Object.assign({ mode: "exact" }, a)) };
  if (typeof content !== "string" || !Array.isArray(edits) || !edits.length) return exact;
  edits = normEdits(edits);
  // A CRLF file edited with LF-only text (inlined context is LF-normalised) used to
  // end up with mixed endings: work in LF, restore CRLF at the end.
  const crlf = (content.match(/\r\n/g) || []).length * 2 > (content.match(/\n/g) || []).length;
  let out = crlf ? content.replace(/\r\n/g, "\n") : content; const applied = [];
  for (let i = 0; i < edits.length; i++) {
    const e = edits[i] || {};
    let find = e.find, repl = e.replace == null ? "" : String(e.replace);
    if (typeof find !== "string" || !find.length) return { ok: false, error: "edit " + (i + 1) + ": empty find", applied: [] };
    if (crlf) { find = find.replace(/\r\n/g, "\n"); repl = repl.replace(/\r\n/g, "\n"); }
    const occ = out.split(find).length - 1;
    if (occ === 1 || (occ > 1 && e.replaceAll)) { out = e.replaceAll ? out.split(find).join(repl) : out.replace(find, () => repl); applied.push({ mode: "exact", count: occ }); continue; }
    if (occ > 1) return { ok: false, error: "edit " + (i + 1) + ": matches " + occ + " places (lines " + whereLines(out, find).join(", ") + (occ > 5 ? ", …" : "") + ") — add surrounding lines to make it unique, or set replace_all", applied: [] };
    const loc = locateFlexible(out, find);
    if (loc.count === 0) return { ok: false, error: "edit " + (i + 1) + ": find text not present (even ignoring whitespace)" + missHint(out, find, repl), applied: [] };
    if (loc.count > 1) return { ok: false, error: "edit " + (i + 1) + ": whitespace-flexible match is ambiguous (" + loc.count + " places) — add context", applied: [] };
    const delta = loc.indent.length - leadWs(find).length;
    const placed = loc.indent.includes("\t") ? reindentTabs(repl, leadWs(find), loc.indent) : reindentBlock(repl, delta);
    out = out.slice(0, loc.start) + placed + out.slice(loc.end);
    applied.push({ mode: "flexible", count: 1 });
  }
  if (crlf) out = out.replace(/\n/g, "\r\n");
  return { ok: true, content: out, applied };
}

// ---- unified-diff patching -------------------------------------------------------------------
// Split a unified diff into per-file patches. Understands `diff --git`, `--- a/x`/`+++ b/x`
// headers and @@ hunks. Returns [{ file, hunks:[{ before:[lines], after:[lines] }] }].
function parsePatch(patch) {
  const lines = String(patch).replace(/\r/g, "").split("\n");
  const filesOut = []; let cur = null, hunk = null;
  const closeHunk = () => { if (hunk && cur) cur.hunks.push(hunk); hunk = null; };
  const closeFile = () => { closeHunk(); if (cur && cur.hunks.length) filesOut.push(cur); cur = null; };
  for (const raw of lines) {
    if (/^diff --git /.test(raw)) { closeFile(); cur = { file: null, hunks: [] }; continue; }
    let m;
    if ((m = /^\+\+\+ (?:b\/)?(.+?)\s*$/.exec(raw))) { if (!cur) cur = { file: null, hunks: [] }; if (m[1] !== "/dev/null") cur.file = m[1]; continue; }
    if (/^--- /.test(raw)) { if (!cur) cur = { file: null, hunks: [] }; const mm = /^--- (?:a\/)?(.+?)\s*$/.exec(raw); if (mm && mm[1] !== "/dev/null" && !cur.file) cur.file = mm[1]; continue; }
    if (/^@@/.test(raw)) { closeHunk(); if (!cur) cur = { file: null, hunks: [] }; hunk = { before: [], after: [] }; continue; }
    if (!hunk) continue;
    const tag = raw[0], body = raw.slice(1);
    if (tag === " ") { hunk.before.push(body); hunk.after.push(body); }
    else if (tag === "-") { hunk.before.push(body); }
    else if (tag === "+") { hunk.after.push(body); }
    else if (raw === "\\ No newline at end of file") { /* ignore */ }
    // any other line ends the hunk implicitly
    else { closeHunk(); }
  }
  closeFile();
  return filesOut;
}

// Apply one file's hunks to its content by ANCHORING each hunk's `before` block via exact then
// flexible locate — so mismatched @@ line numbers don't matter. All-or-nothing per file.
function applyHunks(content, hunks) {
  if (typeof content !== "string") return { ok: false, error: "content must be a string" };
  // Hunk before/after blocks are LF-only (parsePatch strips \r). If the file uses
  // CRLF, match and splice on an LF copy, then restore CRLF at the end — otherwise
  // the exact anchor never matches a CRLF file and the flexible path splices LF
  // text in, leaving the patched region with mixed line endings.
  const crlf = content.includes("\r\n");
  let out = crlf ? content.replace(/\r\n/g, "\n") : content;
  for (let h = 0; h < hunks.length; h++) {
    const before = hunks[h].before.join("\n"), after = hunks[h].after.join("\n");
    if (before === after) continue;
    if (!before.length) { // pure insertion with no context: only safe for a brand-new/empty file
      if (out.length) return { ok: false, error: "hunk " + (h + 1) + ": no context to anchor an insertion" };
      out = after; continue;
    }
    const occ = out.split(before).length - 1;
    if (occ === 1) { out = out.replace(before, () => after); continue; }
    if (occ > 1) return { ok: false, error: "hunk " + (h + 1) + ": context matches " + occ + " places (lines " + whereLines(out, before).join(", ") + ") — patch is ambiguous; include more context lines" };
    const loc = locateFlexible(out, before);
    if (loc.count === 1) { const delta = loc.indent.length - leadWs(before).length; out = out.slice(0, loc.start) + reindentBlock(after, delta) + out.slice(loc.end); continue; }
    return { ok: false, error: "hunk " + (h + 1) + ": context not found in file" + (loc.count > 1 ? " (ambiguous)" : missHint(out, before, after)) };
  }
  if (crlf) out = out.replace(/\n/g, "\r\n");
  return { ok: true, content: out };
}

// Convenience: apply a single-file unified diff string to content.
function applyPatch(content, patch) {
  const files = parsePatch(patch);
  if (!files.length) return { ok: false, error: "no hunks parsed from the patch" };
  if (files.length > 1) return { ok: false, error: "patch touches " + files.length + " files — apply per file with parsePatch/applyHunks" };
  return applyHunks(content, files[0].hunks);
}

// After an edit, show the model the changed lines as they now read (numbered, one
// line of context each side) so it can confirm the result without re-reading the
// whole file. Large changes are summarized. Returns { lines: "4" | "4-9", now } or null.
function changedRegion(before, after, maxLines) {
  maxLines = maxLines || 12;
  if (typeof before !== "string" || typeof after !== "string" || before === after) return null;
  const A = before.split("\n"), B = after.split("\n");
  let top = 0; while (top < A.length && top < B.length && A[top] === B[top]) top++;
  let ea = A.length - 1, eb = B.length - 1; while (ea >= top && eb >= top && A[ea] === B[eb]) { ea--; eb--; }
  if (eb < top) return { lines: String(top + 1), now: "(lines removed — " + (ea - top + 1) + " deleted at line " + (top + 1) + ")" };
  const from = Math.max(0, top - 1), to = Math.min(B.length - 1, eb + 1);
  const fmt = (i) => String(i + 1).padStart(5) + "  " + (B[i].length > 200 ? B[i].slice(0, 200) + "…" : B[i]);
  let out;
  if (to - from + 1 <= maxLines) { out = []; for (let i = from; i <= to; i++) out.push(fmt(i)); }
  else { const h = Math.floor(maxLines / 2); out = []; for (let i = from; i < from + h; i++) out.push(fmt(i)); out.push("  …  (" + (to - from + 1 - 2 * h) + " more changed lines)"); for (let i = to - h + 1; i <= to; i++) out.push(fmt(i)); }
  return { lines: top === eb ? String(top + 1) : (top + 1) + "-" + (eb + 1), now: out.join("\n") };
}

module.exports = { changedRegion, applyEdits, applyEditsFlexible, locateFlexible, parsePatch, applyHunks, applyPatch, normWs, missHint, whereLines, dice };
