"use strict";
// The line range a model asked for, whatever it called the arguments. Models
// mix offset/limit, start/end, start_line/end_line, line_start/line_end,
// from/to and lines:"120-180"; an unrecognized spelling used to be ignored, so
// the model got line 1 again, re-asked, and tripped the loop guard.
// Returns { off, lim } — 1-based first line, line count (lim null = to the end).

const num = (v) => { const n = parseInt(v, 10); return Number.isFinite(n) ? n : null; };
const first = (a, keys) => { for (const k of keys) { const n = num(a[k]); if (n != null) return n; } return null; };

function lineRange(a) {
  a = a || {};
  let off = first(a, ["offset", "start", "start_line", "startLine", "line_start", "from", "line"]);
  let end = first(a, ["end", "end_line", "endLine", "line_end", "to"]);
  let lim = first(a, ["limit", "count", "max_lines", "lines_count"]);
  if (off == null && end == null && typeof a.lines === "string") {
    const m = a.lines.match(/^\s*(\d+)\s*(?:-|:|\.\.|to)\s*(\d+)?\s*$/);
    if (m) { off = +m[1]; if (m[2]) end = +m[2]; }
  }
  off = Math.max(1, off || 1);
  if (lim != null && lim > 0) return { off, lim };
  if (end != null) return { off, lim: Math.max(1, end - off + 1) };
  return { off, lim: null };
}

module.exports = { lineRange };
