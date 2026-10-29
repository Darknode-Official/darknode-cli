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
    if (occ > 1 && !e.replaceAll) return { ok: false, error: "edit " + (i + 1) + ": find matches " + occ + " places (lines " + whereLines(out, e.find).join(", ") + (occ > 5 ? ", …" : "") + ") — add context to make it unique, or set replaceAll", applied: [] };
    out = e.replaceAll ? out.split(find).join(repl) : out.replace(find, () => repl);
    applied.push({ find: find.slice(0, 40), count: e.replaceAll ? occ : 1 });
  }
  return { ok: true, content: out, applied };
}

const normWs = (l) => l.replace(/\s+/g, " ").trim();
// Leading whitespace of the first non-empty line, and a re-indent that shifts every non-empty line
// by `delta` columns (adding spaces, or stripping leading whitespace). Used so a flexible/patch
// replacement that omitted indentation lands at the indentation of the block it replaced.
const leadWs = (s) => { const first = String(s).split("\n").find((l) => l.trim() !== "") || ""; return (first.match(/^[ \t]*/) || [""])[0]; };
const reindentBlock = (text, delta) => { if (!delta) return text; return String(text).split("\n").map((l) => { if (l.trim() === "") return l; if (delta > 0) return " ".repeat(delta) + l; let k = 0; while (k < -delta && k < l.length && /[ \t]/.test(l[k])) k++; return l.slice(k); }).join("\n"); };

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

// The indent step of a space-indented block (smallest step between its line indents), or 0
// when it has no space-indented lines to tell from.
function spaceUnit(block) {
  const leads = String(block).split("\n").filter((l) => l.trim()).map((l) => (l.match(/^ */) || [""])[0].length);
  if (!leads.some((n) => n > 0)) return 0;
  const base = Math.min.apply(null, leads), steps = leads.map((n) => n - base).filter((n) => n > 0);
  return steps.length ? Math.min.apply(null, steps) : base;
}

// A space-indented block edited with tab-indented text: leading tabs in the find and the
// replacement become the block's space step, so the result is not mixed indentation.
function untab(old, find, repl) {
  const unit = spaceUnit(old);
  if (!unit || /^\t/m.test(old)) return [find, repl];
  const tabs = (v) => v.replace(/^\t+/gm, (m) => " ".repeat(unit * m.length));
  return [tabs(find), tabs(repl)];
}
// The replacement re-indented onto the block locateFlexible matched.
const placeAt = (loc, find, repl) => loc.indent.includes("\t") ? reindentTabs(repl, leadWs(find), loc.indent) : reindentBlock(repl, loc.indent.length - leadWs(find).length);

function locateFlexible(content, find, all) {
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
  // char offsets of a matched block (join with the same \n the split used)
  const span = (startLine) => {
    // a byte-order mark on line 1 is not part of the match (normWs drops it as whitespace)
    const bom = startLine === 0 && cLines[0].charCodeAt(0) === 0xfeff ? 1 : 0;
    const start = cLines.slice(0, startLine).reduce((n, l) => n + l.length + 1, 0) + bom;
    const end = start - bom + cLines.slice(startLine, startLine + fNorm.length).join("\n").length;
    return { count: 1, start, end, startLine, indent: (cLines[startLine].slice(bom).match(/^[ \t]*/) || [""])[0] };
  };
  // every match, for replace_all; overlapping matches would make it ambiguous, so they refuse
  if (all && hits.length > 1) return hits.every((h, i) => !i || h >= hits[i - 1] + fNorm.length) ? { count: hits.length, all: hits.map(span) } : { count: hits.length, lines: hits.slice(0, 5).map((h) => h + 1) };
  if (hits.length !== 1) return { count: hits.length, lines: hits.slice(0, 5).map((h) => h + 1) };
  return span(hits[0]);
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

// locateFlexible matches whole lines and ignores blank lines at the edges of the find, so
// drop the same number of edge blank lines from the replacement - otherwise a find of
// "\n  return s\n\n" replaced with "\n  return t\n" writes stray blank lines around it.
function trimLikeFind(find, repl) {
  const f = String(find).split("\n"), r = String(repl).split("\n");
  let lead = 0, trail = 0;
  while (lead < f.length && f[lead].trim() === "") lead++;
  while (trail < f.length - lead && f[f.length - 1 - trail].trim() === "") trail++;
  for (let k = 0; k < lead && r.length > 1 && r[0].trim() === ""; k++) r.shift();
  for (let k = 0; k < trail && r.length > 1 && r[r.length - 1].trim() === ""; k++) r.pop();
  return r.join("\n");
}

// A find the model copied with decoration the file does not have: line-number prefixes
// from search output ("12:  code", consecutive numbers on every line) or curly quotes and
// dashes in a file that has none. Returns { find, repl, why } with the decoration removed
// (from the replacement too, when it carries the same decoration), or null.
const LINE_NO = /^\s*(\d+)(?::|\t|\u2192|\|) ?/;
const SMART_MAP = { "\u2018": "'", "\u2019": "'", "\u201c": '"', "\u201d": '"', "\u2013": "-", "\u2014": "-", "\u00a0": " " };
function undecorate(content, find, repl) {
  const fl = String(find).split("\n"), body = fl.filter((l) => l.trim() !== "");
  const nums = body.map((l) => (l.match(LINE_NO) || [])[1]);
  if (body.length && nums.every(Boolean) && nums.every((n, k) => k === 0 || +n === +nums[k - 1] + 1) && !LINE_NO.test(content.split("\n").find((l) => l.trim()) || "")) {
    const strip = (t) => String(t).split("\n").map((l) => l.replace(LINE_NO, "")).join("\n");
    const rl = String(repl).split("\n").filter((l) => l.trim() !== "");
    return { find: strip(find), repl: rl.length && rl.every((l) => LINE_NO.test(l)) ? strip(repl) : repl, why: "line numbers" };
  }
  if (SMART.test(find) && !SMART.test(content)) {
    const plain = (t) => String(t).replace(/[\u2018\u2019\u201c\u201d\u2013\u2014\u00a0]/g, (c) => SMART_MAP[c]);
    return { find: plain(find), repl: plain(repl), why: "curly quotes" };
  }
  return null;
}

function applyEditsFlexible(content, edits) {
  // A CRLF file edited with LF-only text (inlined context is LF-normalised) used to
  // end up with mixed endings: work in LF, restore CRLF at the end.
  const crlf = typeof content === "string" && (content.match(/\r\n/g) || []).length * 2 > (content.match(/\n/g) || []).length;
  // the exact pass splices raw: a one-line find on a CRLF file matched, and a multi-line
  // replace went in with bare LF — give the replacement the file's CRLF first
  const toCrlf = (v) => v == null ? v : String(v).replace(/\r?\n/g, "\r\n");
  const exact = applyEdits(content, crlf && Array.isArray(edits) ? edits.map((e) => Object.assign({}, e || {}, { replace: toCrlf((e || {}).replace) })) : edits);
  if (exact.ok) return { ok: true, content: exact.content, applied: exact.applied.map((a) => Object.assign({ mode: "exact" }, a)) };
  if (typeof content !== "string" || !Array.isArray(edits) || !edits.length) return exact;
  edits = normEdits(edits);
  let out = crlf ? content.replace(/\r\n/g, "\n") : content; const applied = [];
  for (let i = 0; i < edits.length; i++) {
    const e = edits[i] || {};
    let find = e.find, repl = e.replace == null ? "" : String(e.replace);
    if (typeof find !== "string" || !find.length) return { ok: false, error: "edit " + (i + 1) + ": empty find", applied: [] };
    // work in LF either way: a CRLF find/replace on an LF file would splice \r\n in
    find = find.replace(/\r\n/g, "\n"); repl = repl.replace(/\r\n/g, "\n");
    const occ = out.split(find).length - 1;
    if (occ === 1 || (occ > 1 && e.replaceAll)) { out = e.replaceAll ? out.split(find).join(repl) : out.replace(find, () => repl); applied.push({ mode: "exact", count: occ }); continue; }
    if (occ > 1) return { ok: false, error: "edit " + (i + 1) + ": matches " + occ + " places (lines " + whereLines(out, find).join(", ") + (occ > 5 ? ", …" : "") + ") — add surrounding lines to make it unique, or set replace_all", applied: [] };
    let loc = locateFlexible(out, find, e.replaceAll);
    if (loc.all) { // replace_all over loose matches: last to first, so earlier offsets stay valid
      for (const m of loc.all.slice().reverse()) { const [f2, r2] = untab(out.slice(m.start, m.end), find, repl); out = out.slice(0, m.start) + placeAt(m, f2, trimLikeFind(f2, r2)) + out.slice(m.end); }
      applied.push({ mode: "flexible", count: loc.count }); continue;
    }
    if (loc.count === 0) {
      // decoration the model copied along (line-number prefixes, curly quotes): retry once without it
      const alt = undecorate(out, find, repl);
      const altLoc = alt && (out.split(alt.find).length - 1 === 1 ? null : locateFlexible(out, alt.find));
      if (alt && !altLoc) { out = out.replace(alt.find, () => alt.repl); applied.push({ mode: "flexible", count: 1, fixed: alt.why }); continue; }
      if (alt && altLoc.count === 1) { find = alt.find; repl = alt.repl; loc = altLoc; }
      else return { ok: false, error: "edit " + (i + 1) + ": find text not present (even ignoring whitespace)" + missHint(out, find, repl), applied: [] };
    }
    if (loc.count > 1) return { ok: false, error: "edit " + (i + 1) + ": whitespace-flexible match is ambiguous (" + loc.count + " places, lines " + loc.lines.join(", ") + (loc.count > 5 ? ", …" : "") + ") — add surrounding lines to make it unique", applied: [] };
    // a space-indented block edited with tab-indented text: tabs become the block's space unit
    [find, repl] = untab(out.slice(loc.start, loc.end), find, repl);
    out = out.slice(0, loc.start) + placeAt(loc, find, trimLikeFind(find, repl)) + out.slice(loc.end);
    applied.push({ mode: "flexible", count: 1 });
  }
  if (crlf) out = out.replace(/\n/g, "\r\n");
  return { ok: true, content: out, applied };
}

// ---- unified-diff patching -------------------------------------------------------------------
// Split a patch into per-file patches. Understands unified diffs (`diff --git`, `--- a/x` /
// `+++ b/x` headers and @@ hunks) and the "*** Begin Patch" envelope OpenAI/Codex-trained
// models write (*** Update File / *** Add File / *** Delete File, *** Move to). Returns
// [{ file, op?, to?, hunks:[{ before:[lines], after:[lines], anchor? }] }]: op is "add",
// "delete" or "move" when the patch says so; anchor is the text after @@ (the enclosing
// function or class), used to pick between identical context blocks.
// git's C-style quoting: \" \\ \t \n and octal bytes for non-ASCII (caf\303\251 = café)
const CESC = { a: 7, b: 8, t: 9, n: 10, v: 11, f: 12, r: 13, '"': 34, "\\": 92 };
function cUnquote(q) {
  const bytes = [];
  for (let i = 1; i < q.length - 1; i++) {
    if (q[i] !== "\\") { bytes.push(...Buffer.from(q[i])); continue; }
    const o = /^[0-7]{3}/.exec(q.slice(i + 1));
    if (o) { bytes.push(parseInt(o[0], 8)); i += 3; } else { const e = q[++i]; bytes.push(CESC[e] != null ? CESC[e] : e.charCodeAt(0)); }
  }
  return Buffer.from(bytes).toString("utf8");
}
// a ---/+++ header path: GNU diff -u puts a tab and a timestamp after it, git quotes
// paths with spaces or special characters, and git adds the a/ or b/ prefix
function hdrPath(s, pre) {
  s = s.replace(/\t.*$/, "").trim();
  if (/^".*"$/.test(s)) s = cUnquote(s);
  return s.startsWith(pre + "/") ? s.slice(2) : s;
}

function parsePatch(patch) {
  const lines = String(patch).replace(/\r/g, "").split("\n");
  if (lines.some((l) => /^\*\*\* (Begin Patch|Update File:|Add File:|Delete File:)/.test(l))) return parseEnvelope(lines);
  const filesOut = []; let cur = null, hunk = null;
  const closeHunk = () => { if (hunk && cur) cur.hunks.push(hunk); hunk = null; };
  const closeFile = () => { closeHunk(); if (cur && (cur.hunks.length || cur.op === "delete")) filesOut.push(cur); cur = null; };
  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i];
    if (/^diff --git /.test(raw)) { closeFile(); cur = { file: null, hunks: [] }; continue; }
    let m;
    if (!hunk && (m = /^\+\+\+ (.+?)\s*$/.exec(raw))) { if (!cur) cur = { file: null, hunks: [] }; const f = hdrPath(m[1], "b"); if (f !== "/dev/null") cur.file = f; else cur.op = "delete"; continue; }
    if (!hunk && /^--- /.test(raw)) { if (!cur) cur = { file: null, hunks: [] }; const mm = /^--- (.+?)\s*$/.exec(raw); const f = mm && hdrPath(mm[1], "a"); if (f === "/dev/null") cur.op = "add"; else if (f && !cur.file) cur.file = f; continue; }
    if (/^@@/.test(raw)) { closeHunk(); if (!cur) cur = { file: null, hunks: [] }; hunk = newHunk(raw); continue; }
    if (!hunk) continue;
    if (/^(--- |\+\+\+ )/.test(raw) && /^(\+\+\+ |@@)/.test(lines[i + 1] || "")) { closeFile(); i--; continue; } // next file's headers (no diff --git line)
    if (!hunkLine(hunk, raw, lines[i + 1])) closeHunk(); // any other line ends the hunk implicitly
  }
  closeFile();
  return filesOut;
}

function newHunk(header) {
  const anchor = String(header).replace(/^@@(?:\s*-\d+(?:,\d+)?\s+\+\d+(?:,\d+)?\s*@@)?/, "").trim();
  const h = anchor ? { before: [], after: [], anchor } : { before: [], after: [] };
  const n = /^@@\s*-(\d+)/.exec(header); if (n && +n[1] > 0) h.at = +n[1]; // old-file start line
  return h;
}

// One body line of a hunk; false when the line is not part of it. An empty line is a
// blank context line whose leading space was stripped (editors and models do this), but
// only when more hunk lines follow - trailing blank lines after a patch are not context.
function hunkLine(hunk, raw, next) {
  const tag = raw[0], body = raw.slice(1);
  if (tag === " ") { hunk.before.push(body); hunk.after.push(body); }
  else if (tag === "-") hunk.before.push(body);
  else if (tag === "+") { hunk.after.push(body); hunk.added = true; }
  // the marker is about the line above it: after - the old file ends without a newline,
  // after + the new one does, after a context line both do
  else if (raw === "\\ No newline at end of file") { if (hunk.last !== "+") hunk.oldNoEol = true; if (hunk.last !== "-") hunk.noEol = true; }
  else if (raw === "*** End of File") { /* ignore */ }
  else if (raw === "" && next != null && /^[ +\-]/.test(next) && !/^(--- |\+\+\+ )/.test(next)) { hunk.before.push(""); hunk.after.push(""); }
  else return false;
  if (/^[ +\-]$/.test(tag)) hunk.last = tag;
  return true;
}

// The "*** Begin Patch" envelope. Update File sections hold @@ chunks (the @@ line may be
// bare or carry an anchor); Add File holds the new file as + lines; Delete File has no body.
function parseEnvelope(lines) {
  const filesOut = []; let cur = null, hunk = null;
  const closeHunk = () => { if (hunk && cur && (hunk.before.length || hunk.after.length)) cur.hunks.push(hunk); hunk = null; };
  const closeFile = () => { closeHunk(); if (cur) filesOut.push(cur); cur = null; };
  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i]; let m;
    if (/^\*\*\* (Begin|End) Patch\s*$/.test(raw)) { closeFile(); continue; }
    if ((m = /^\*\*\* Update File:\s*(.+?)\s*$/.exec(raw))) { closeFile(); cur = { file: m[1], hunks: [] }; continue; }
    if ((m = /^\*\*\* Add File:\s*(.+?)\s*$/.exec(raw))) { closeFile(); cur = { file: m[1], op: "add", hunks: [] }; hunk = { before: [], after: [] }; continue; }
    if ((m = /^\*\*\* Delete File:\s*(.+?)\s*$/.exec(raw))) { closeFile(); filesOut.push({ file: m[1], op: "delete", hunks: [] }); continue; }
    if ((m = /^\*\*\* Move to:\s*(.+?)\s*$/.exec(raw))) { if (cur) { cur.op = "move"; cur.to = m[1]; } continue; }
    if (!cur) continue;
    if (/^@@/.test(raw)) { closeHunk(); hunk = newHunk(raw); continue; }
    if (!hunk) hunk = { before: [], after: [] }; // a chunk may start without an @@ line
    if (!hunkLine(hunk, raw, lines[i + 1]) && raw.trim()) closeHunk();
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
  // Line numbers settle a tie between identical blocks only when every hunk has one and they
  // run in file order (as diff and git write them); then hunk h's block starts at its stated
  // line plus the lines earlier hunks added or removed. Drifted numbers match no block and
  // the hunk is refused as before, never guessed.
  const numbered = hunks.every((x, i) => x.at && (!i || x.at > hunks[i - 1].at));
  const lineCount = (s) => s.split("\n").length, origLines = lineCount(out);
  let eolHunk = null;
  for (let h = 0; h < hunks.length; h++) {
    // decide on the LINE arrays: one blank line ([""]) and no lines ([]) both join to ""
    const B = hunks[h].before, A = hunks[h].after, before = B.join("\n"), after = A.join("\n");
    if (!!hunks[h].oldNoEol !== !!hunks[h].noEol) eolHunk = { h, after, noEol: !!hunks[h].noEol, lines: A.length }; // the hunk adds or removes the final newline
    if (before === after && B.length === A.length) { if (eolHunk && eolHunk.h === h && !lineHits(out, before).some((x) => out.slice(x + before.length).replace(/^\n/, "") === "")) return { ok: false, error: "hunk " + (h + 1) + ": context not found at the end of the file" }; continue; }
    if (!B.length) { // pure insertion with no context: only safe for a brand-new/empty file
      if (out.length) return { ok: false, error: "hunk " + (h + 1) + ": no context to anchor an insertion" };
      out = after + (hunks[h].noEol ? "" : "\n"); continue;
    }
    // hunk lines are whole lines: "-a = 1;" must not match inside "let data = 1;"
    const hits = lineHits(out, before), occ = hits.length;
    // A hunk that removes every line of its block (diff -U0 deletion) takes the block's line
    // break with it, or a blank line is left where the lines were.
    const cut = (start, end, text) => {
      if (!A.length) { if (out[end] === "\n") end++; else if (start > 0 && out[start - 1] === "\n") start--; }
      out = out.slice(0, start) + text + out.slice(end);
    };
    const splice = (at) => cut(at, at + before.length, after);
    if (occ === 1) { splice(hits[0]); continue; }
    // several identical blocks: the @@ anchor (enclosing function/class) picks the first one after it
    const from = occ > 1 && hunks[h].anchor ? anchorLine(out, hunks[h].anchor) : -1;
    const at = from >= 0 ? hits.find((x) => x >= from) : undefined;
    if (at != null) { splice(at); continue; }
    const byLine = occ > 1 && numbered ? lineOffset(out, hunks[h].at + lineCount(out) - origLines) : -1;
    if (byLine >= 0 && hits.includes(byLine)) { splice(byLine); continue; }
    if (occ > 1) return { ok: false, error: "hunk " + (h + 1) + ": context matches " + occ + " places (lines " + hits.slice(0, 5).map((x) => lineCount(out.slice(0, x))).join(", ") + ") — patch is ambiguous; include more context lines" };
    const loc = locateFlexible(out, before);
    if (loc.count === 1) { const [b, a] = untab(out.slice(loc.start, loc.end), before, after); cut(loc.start, loc.end, a.length ? placeAt(loc, b, a) : ""); continue; }
    return { ok: false, error: "hunk " + (h + 1) + ": context not found in file" + (loc.count > 1 ? " (ambiguous)" : missHint(out, before, after)) };
  }
  // a hunk that removes the last lines (and so leaves none of its own) hands the final newline to the line now last
  if (eolHunk && !eolHunk.lines && out) out = out.replace(/\n?$/, eolHunk.noEol ? "" : "\n");
  if (eolHunk && eolHunk.lines) {
    const at = (b) => b.endsWith(eolHunk.after) && (b.length === eolHunk.after.length || b[b.length - eolHunk.after.length - 1] === "\n");
    // after ending in a blank line ("x\n") is already spliced without its final newline
    const body = at(out) ? out : out.endsWith("\n") ? out.slice(0, -1) : out;
    if (body.endsWith(eolHunk.after) && (body.length === eolHunk.after.length || body[body.length - eolHunk.after.length - 1] === "\n")) out = body + (eolHunk.noEol ? "" : "\n");
  }
  if (crlf) out = out.replace(/\n/g, "\r\n");
  return { ok: true, content: out };
}

// Offsets where `block` occurs as whole lines (starts a line, ends at a newline or EOF).
// The empty block is one blank line: a line start followed by its newline.
function lineHits(content, block) {
  const hits = []; let i = -1;
  if (block === "") { for (let p = 0; p < content.length; p++) if (content[p] === "\n" && (p === 0 || content[p - 1] === "\n")) hits.push(p); return hits; }
  while ((i = content.indexOf(block, i + 1)) >= 0) {
    const end = i + block.length;
    if ((i === 0 || content[i - 1] === "\n") && (end === content.length || content[end] === "\n")) hits.push(i);
  }
  return hits;
}

// Offset of 1-based `line`, or -1 past the end.
function lineOffset(content, line) {
  let off = 0;
  for (let l = 1; l < line; l++) { off = content.indexOf("\n", off) + 1; if (!off) return -1; }
  return off;
}

// Offset of the one line that contains `anchor`, or -1 when the anchor line is missing
// or not unique (then the anchor can't decide anything).
function anchorLine(content, anchor) {
  const lines = content.split("\n"); let at = -1, off = 0;
  for (let i = 0; i < lines.length; i++) {
    if (lines[i].includes(anchor)) { if (at >= 0) return -1; at = off; }
    off += lines[i].length + 1;
  }
  return at;
}

// Convenience: apply a single-file patch string to content.
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

// readEditable(fp, label) -> { text } | { error }. The text of a file for an in-place edit. A file whose
// bytes are not UTF-8 (Latin-1 / Windows-1252 legacy source) is refused: decoding it to a string turned
// every non-ASCII byte into U+FFFD, and writing the edit back corrupted lines nobody asked to change.
function readEditable(fp, label) {
  let buf;
  try { buf = require("fs").readFileSync(fp); } catch (e) { return { error: "cannot read " + (label || fp) + (e && e.code === "EISDIR" ? " (it is a directory)" : "") }; }
  const text = buf.toString("utf8");
  if (text.includes("\uFFFD") && !Buffer.from(text, "utf8").equals(buf)) return { error: (label || fp) + " is not UTF-8 text (likely Latin-1 or Windows-1252); editing it as UTF-8 would corrupt its other non-ASCII characters, so nothing was changed. Convert it first (e.g. iconv -f latin1 -t utf-8) or edit it with a byte-safe command." };
  return { text };
}

module.exports = { readEditable, changedRegion, applyEdits, applyEditsFlexible, locateFlexible, parsePatch, applyHunks, applyPatch, normWs, missHint, whereLines, dice };
