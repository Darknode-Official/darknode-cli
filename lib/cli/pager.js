"use strict";
// In-TUI pager (NTUI-069): read a whole tool output (or answer) that the
// transcript only previews. Pure state + reducer + view so it is testable from
// strings; the TUI only routes keys in and paints the rows it returns.
//
//   createPager(text, title)               -> state
//   pagerKey(state, key, height) -> "close" | "copy" | null   (mutates state; "copy" = the host copies st.lines)
//   scrollBy(state, n, height)
//   pagerView(state, width, height, C)     -> string[]  exactly `height` rows
//
// Keys (less-style): j/k ↑↓ line · space/f/PgDn, b/PgUp page · d/u half page ·
// g/Home top · G/End bottom · / search (smart case) · n/N next/prev match ·
// y copy everything · q/Esc close.
const { ansiWrap, strWidth, sanitizeTerm, stripAnsi } = require("./tui-format");

const MAX_LINES = 200000;
const MAX_LINE = 65536; // a single minified/binary line is cut, not wrapped into thousands of rows

function createPager(text, title, opts) {
  let lines = sanitizeTerm(stripAnsi(String(text == null ? "" : text)), true).replace(/\t/g, "  ").split("\n");
  while (lines.length > 1 && !lines[lines.length - 1].trim()) lines.pop();
  let note = "";
  if (lines.length > MAX_LINES) { note = "first " + MAX_LINES.toLocaleString("en-US") + " of " + lines.length.toLocaleString("en-US") + " lines"; lines = lines.slice(0, MAX_LINES); }
  lines = lines.map((l) => (l.length > MAX_LINE ? l.slice(0, MAX_LINE) + " …" : l));
  const o = opts || {};
  // opts.query opens with a search applied; opts.at "last" lands on the newest match (or the end), "first" on the first
  return { title: String(title || "output"), lines, note, width: 0, rows: [], top: o.at === "last" ? Infinity : 0, query: String(o.query || ""), typing: false, input: "", hits: [], hi: -1, msg: "", jump: o.query ? (o.at === "last" ? -1 : 1) : 0 };
}

// Wrap once per width. rows[i] = { t: text, n: source line index, first: bool }
function layout(st, width) {
  const gut = String(st.lines.length).length + 1;
  const w = Math.max(4, width - gut);
  if (st.width === width) return gut;
  const anchor = st.rows[st.top] ? st.rows[st.top].n : 0; // keep the same source line on top across a resize
  st.rows = [];
  for (let n = 0; n < st.lines.length; n++) {
    const parts = st.lines[n].length ? ansiWrap(st.lines[n], w) : [""];
    parts.forEach((t, k) => st.rows.push({ t, n, first: k === 0 }));
  }
  st.width = width;
  if (st.top !== Infinity) st.top = Math.max(0, st.rows.findIndex((r) => r.n === anchor)); // Infinity = "open at the end", resolved by pagerView
  if (st.query) st.hits = findHits(st, st.query);
  return gut;
}

const maxTop = (st, h) => Math.max(0, st.rows.length - h);
const clampTop = (st, h) => { st.top = Math.min(Math.max(0, st.top), maxTop(st, h)); };
function scrollBy(st, n, h) { st.top += n; clampTop(st, h); }

const smartRe = (q) => new RegExp(q.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), /[A-Z]/.test(q) ? "g" : "gi");
function findHits(st, q) {
  const re = smartRe(q), out = [];
  for (let i = 0; i < st.rows.length; i++) { re.lastIndex = 0; if (re.test(st.rows[i].t)) out.push(i); }
  return out;
}
function jumpHit(st, dir, h) {
  if (!st.hits.length) { st.msg = st.query ? "no match for \"" + st.query + "\"" : ""; return; }
  let i;
  if (dir > 0) { i = st.hits.findIndex((r) => r > (st.hi >= 0 ? st.hits[st.hi] : st.top - 1)); if (i < 0) { i = 0; st.msg = "search wrapped to the top"; } }
  else { i = -1; for (let k = st.hits.length - 1; k >= 0; k--) if (st.hits[k] < (st.hi >= 0 ? st.hits[st.hi] : st.top)) { i = k; break; } if (i < 0) { i = st.hits.length - 1; st.msg = "search wrapped to the bottom"; } }
  st.hi = i;
  const r = st.hits[i];
  if (r < st.top || r >= st.top + h) st.top = r - Math.floor(h / 3);
  clampTop(st, h);
}

function pagerKey(st, key, height) {
  const h = Math.max(1, height);
  st.msg = "";
  if (st.typing) {
    if (key === "\r" || key === "\n") {
      st.typing = false; st.query = st.input; st.hi = -1;
      st.hits = st.query ? findHits(st, st.query) : [];
      if (st.query) jumpHit(st, 1, h);
      return null;
    }
    if (key === "\x1b" || key === "\x03") { st.typing = false; st.input = ""; return null; }
    if (key === "\x7f" || key === "\b") { st.input = [...st.input].slice(0, -1).join(""); return null; }
    if (key === "\x15") { st.input = ""; return null; }
    const typed = key.replace(/\x1b\[20[01]~/g, "").replace(/[\r\n\t]+/g, " ");
    if (typed && !/[\x00-\x1f\x7f]/.test(typed)) st.input += typed;
    return null;
  }
  switch (key) {
    case "q": case "Q": case "\x1b": case "\x03": return "close";
    case "y": case "Y": return "copy";
    case "j": case "\x1b[B": case "\x1bOB": case "\r": case "\n": scrollBy(st, 1, h); break;
    case "k": case "\x1b[A": case "\x1bOA": scrollBy(st, -1, h); break;
    case " ": case "f": case "\x1b[6~": case "\x06": scrollBy(st, h - 1, h); break;
    case "b": case "\x1b[5~": case "\x02": scrollBy(st, -(h - 1), h); break;
    case "d": case "\x04": scrollBy(st, Math.ceil(h / 2), h); break;
    case "u": case "\x15": scrollBy(st, -Math.ceil(h / 2), h); break;
    case "g": case "<": case "\x1b[H": case "\x1b[1~": case "\x1bOH": st.top = 0; break;
    case "G": case ">": case "\x1b[F": case "\x1b[4~": case "\x1bOF": st.top = maxTop(st, h); break;
    case "/": st.typing = true; st.input = ""; break;
    case "n": jumpHit(st, 1, h); break;
    case "N": jumpHit(st, -1, h); break;
    default: break;
  }
  return null;
}

// Highlight query matches in one plain row (inverse for all, bold+inverse for the current hit).
function mark(t, q, cur, C) {
  if (!q) return t;
  const re = smartRe(q); let out = "", last = 0, m;
  while ((m = re.exec(t))) { if (!m[0]) { re.lastIndex++; continue; } out += t.slice(last, m.index) + (cur ? C.cur : C.hit)(m[0]); last = m.index + m[0].length; }
  return out + t.slice(last);
}

function pagerView(st, width, height, C) {
  C = Object.assign({ border: (s) => s, gray: (s) => s, bold: (s) => s, hit: (s) => "[" + s + "]", cur: (s) => "{" + s + "}", yellow: (s) => s }, C || {});
  const W = Math.max(20, width | 0), H = Math.max(3, height | 0);
  const bodyH = H - 2, inner = W - 4; // "│ " + text + " │"
  const gut = layout(st, inner);
  if (st.top === Infinity) st.top = maxTop(st, bodyH);
  if (st.jump) { // first paint of a pager opened with a query: go to the first / newest match
    const d = st.jump; st.jump = 0; st.hi = -1;
    if (!st.hits.length) st.msg = "no match for \"" + st.query + "\"";
    else { if (d < 0) { st.hi = st.hits.length - 1; const r = st.hits[st.hi]; st.top = r - Math.floor(bodyH / 3); } else jumpHit(st, 1, bodyH); st.msg = st.hits.length + " match" + (st.hits.length === 1 ? "" : "es") + (d < 0 && st.hits.length > 1 ? " · newest shown, N for older" : "") + (d > 0 && st.hits.length > 1 ? " · n for the next" : ""); }
  }
  clampTop(st, bodyH);
  const total = st.rows.length;
  const pos = total <= bodyH ? "all" : st.top >= maxTop(st, bodyH) ? "end" : Math.floor((st.top / maxTop(st, bodyH)) * 100) + "%";
  const lineInfo = st.lines.length.toLocaleString("en-US") + " line" + (st.lines.length === 1 ? "" : "s") + " · " + pos;
  const fit = (s, n) => { s = String(s); if (strWidth(s) <= n) return s; let o = ""; for (const ch of s) { if (strWidth(o + ch) > n - 1) break; o += ch; } return o + "…"; };
  const title = " " + fit(st.title, Math.max(4, W - strWidth(lineInfo) - 12)) + " ";
  const topFill = Math.max(1, W - 2 - strWidth(title) - strWidth(lineInfo) - 3);
  const rows = [C.border("╭─") + C.bold(title) + C.border("─".repeat(topFill)) + " " + C.gray(lineInfo) + " " + C.border("╮")];
  const curRow = st.hi >= 0 ? st.hits[st.hi] : -1;
  for (let i = 0; i < bodyH; i++) {
    const r = st.rows[st.top + i];
    let cell = "";
    if (r) {
      const num = r.first ? String(r.n + 1).padStart(gut - 1) + " " : " ".repeat(gut);
      cell = C.gray(num) + mark(r.t, st.query, st.top + i === curRow, C);
    }
    rows.push(C.border("│") + " " + cell + " ".repeat(Math.max(0, inner - strWidth(cell))) + " " + C.border("│"));
  }
  let ft, paint;
  if (st.typing) { ft = "/" + st.input + "█  enter search · esc cancel"; paint = C.yellow; }
  else if (st.msg) { ft = st.msg; paint = C.yellow; }
  else { ft = (st.query && st.hits.length ? (st.hi + 1) + "/" + st.hits.length + " \"" + st.query + "\" · n/N · " : "") + "j/k ↑↓ · space/b page · g/G top/end · / search · y copy · q close" + (st.note ? " · " + st.note : ""); paint = C.gray; }
  ft = fit(ft, W - 6); // fit the plain text, then colour it (never cut inside an escape)
  rows.push(C.border("╰─ ") + paint(ft) + " " + C.border("─".repeat(Math.max(1, W - 5 - strWidth(ft))) + "╯"));
  return rows;
}

module.exports = { createPager, pagerKey, pagerView, scrollBy };
