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
function applyEdits(content, edits) {
  if (typeof content !== "string") return { ok: false, error: "content must be a string" };
  if (!Array.isArray(edits) || !edits.length) return { ok: false, error: "no edits given" };
  let out = content; const applied = [];
  for (let i = 0; i < edits.length; i++) {
    const e = edits[i] || {};
    const find = e.find, repl = e.replace == null ? "" : e.replace;
    if (typeof find !== "string" || !find.length) return { ok: false, error: "edit " + (i + 1) + ": empty find", applied: [] };
    if (find === repl) return { ok: false, error: "edit " + (i + 1) + ": find and replace are identical", applied: [] };
    const occ = out.split(find).length - 1;
    if (occ === 0) return { ok: false, error: "edit " + (i + 1) + ": find text not present — check exact whitespace/indentation", applied: [] };
    if (occ > 1 && !e.replaceAll) return { ok: false, error: "edit " + (i + 1) + ": find matches " + occ + " places — add context to make it unique, or set replaceAll", applied: [] };
    out = e.replaceAll ? out.split(find).join(repl) : out.replace(find, repl);
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
function applyEditsFlexible(content, edits) {
  const exact = applyEdits(content, edits);
  if (exact.ok) return { ok: true, content: exact.content, applied: exact.applied.map((a) => Object.assign({ mode: "exact" }, a)) };
  if (typeof content !== "string" || !Array.isArray(edits) || !edits.length) return exact;
  let out = content; const applied = [];
  for (let i = 0; i < edits.length; i++) {
    const e = edits[i] || {};
    const find = e.find, repl = e.replace == null ? "" : e.replace;
    if (typeof find !== "string" || !find.length) return { ok: false, error: "edit " + (i + 1) + ": empty find", applied: [] };
    const occ = out.split(find).length - 1;
    if (occ === 1 || (occ > 1 && e.replaceAll)) { out = e.replaceAll ? out.split(find).join(repl) : out.replace(find, repl); applied.push({ mode: "exact", count: occ }); continue; }
    if (occ > 1) return { ok: false, error: "edit " + (i + 1) + ": matches " + occ + " places — add context or replaceAll", applied: [] };
    const loc = locateFlexible(out, find);
    if (loc.count === 0) return { ok: false, error: "edit " + (i + 1) + ": find text not present (even ignoring whitespace)", applied: [] };
    if (loc.count > 1) return { ok: false, error: "edit " + (i + 1) + ": whitespace-flexible match is ambiguous (" + loc.count + " places) — add context", applied: [] };
    const delta = loc.indent.length - leadWs(find).length;
    out = out.slice(0, loc.start) + reindentBlock(repl, delta) + out.slice(loc.end);
    applied.push({ mode: "flexible", count: 1 });
  }
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
  let out = content;
  for (let h = 0; h < hunks.length; h++) {
    const before = hunks[h].before.join("\n"), after = hunks[h].after.join("\n");
    if (before === after) continue;
    if (!before.length) { // pure insertion with no context: only safe for a brand-new/empty file
      if (out.length) return { ok: false, error: "hunk " + (h + 1) + ": no context to anchor an insertion" };
      out = after; continue;
    }
    const occ = out.split(before).length - 1;
    if (occ === 1) { out = out.replace(before, after); continue; }
    if (occ > 1) return { ok: false, error: "hunk " + (h + 1) + ": context matches " + occ + " places — patch is ambiguous" };
    const loc = locateFlexible(out, before);
    if (loc.count === 1) { const delta = loc.indent.length - leadWs(before).length; out = out.slice(0, loc.start) + reindentBlock(after, delta) + out.slice(loc.end); continue; }
    return { ok: false, error: "hunk " + (h + 1) + ": context not found in file" + (loc.count > 1 ? " (ambiguous)" : "") };
  }
  return { ok: true, content: out };
}

// Convenience: apply a single-file unified diff string to content.
function applyPatch(content, patch) {
  const files = parsePatch(patch);
  if (!files.length) return { ok: false, error: "no hunks parsed from the patch" };
  if (files.length > 1) return { ok: false, error: "patch touches " + files.length + " files — apply per file with parsePatch/applyHunks" };
  return applyHunks(content, files[0].hunks);
}

module.exports = { applyEdits, applyEditsFlexible, locateFlexible, parsePatch, applyHunks, applyPatch, normWs };
