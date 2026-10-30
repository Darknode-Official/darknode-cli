"use strict";
// The line range a model asked for, whatever it called the arguments. Models
// mix offset/limit, start/end, start_line/end_line, line_start/line_end,
// from/to and lines:"120-180"; an unrecognized spelling used to be ignored, so
// the model got line 1 again, re-asked, and tripped the loop guard.
// Returns { off, lim } — 1-based first line, line count (lim null = to the end).

// a number is truncated, not re-parsed from its string form: parseInt(1e21) read "1e+21" as 1, parseInt(5e-7) as 5
const num = (v) => { const n = typeof v === "number" ? Math.trunc(v) : parseInt(v, 10); return Number.isFinite(n) ? n : null; };
const first = (a, keys) => { for (const k of keys) { const n = num(a[k]); if (n != null) return n; } return null; };

function lineRange(a) {
  a = a || {};
  let off = first(a, ["offset", "start", "start_line", "startLine", "line_start", "from", "line"]);
  let end = first(a, ["end", "end_line", "endLine", "line_end", "to"]);
  let lim = first(a, ["limit", "count", "max_lines", "lines_count"]);
  if (off == null && end == null && Array.isArray(a.lines) && num(a.lines[0]) != null) { off = num(a.lines[0]); end = num(a.lines[1]); } // lines:[120, 180]
  if (off == null && end == null && typeof a.lines === "string") {
    // "120-180", "120:", "L120-L180" (GitHub links), "120,180", "120–180" (en dash), or one line "120"
    const m = a.lines.match(/^\s*L?(\d+)\s*(?:(?:-|\u2013|\u2014|:|,|\.\.|to)\s*(?:L?(\d+))?)?\s*$/i);
    if (m) { off = +m[1]; if (m[2]) end = +m[2]; }
  }
  off = Math.max(1, off || 1);
  if (lim != null && lim > 0) return { off, lim };
  if (end != null) return { off, lim: Math.max(1, end - off + 1) };
  return { off, lim: null };
}

module.exports = { lineRange };
