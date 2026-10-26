"use strict";
// Live output of a running command (NTUI-068): what the agent's shell is doing
// right now, shown under the running tool card instead of a bare "Running…".
// Pure and string-in/string-out so it is testable without a process.
//
//   createTail(maxBytes)  -> state            (default 256 KiB kept per command)
//   pushTail(state, chunk)                    raw stdout/stderr text, any split
//   tailLines(state, n)   -> string[]         last n non-blank lines, sanitized
//   tailText(state)       -> string           everything kept, for /pager
//   lineCount(state)      -> number           lines seen, including dropped ones
//
// Output is untrusted: ANSI and every other control sequence is removed, and a
// carriage-return progress bar ("12%\r40%\r") collapses to its last state.
const { sanitizeTerm, stripAnsi } = require("./tui-format");

const MAX_LINE = 2000; // a line with no newline (minified output, a spinner) stops growing here

function createTail(maxBytes) {
  return { lines: [], partial: "", bytes: 0, max: Math.max(1024, maxBytes || 256 * 1024), dropped: 0, droppedBytes: 0 };
}

function clean(raw) {
  let s = stripAnsi(raw).replace(/\r+$/, "");
  const cr = s.lastIndexOf("\r");
  if (cr >= 0) s = s.slice(cr + 1);
  s = sanitizeTerm(s, false);
  return s.length > MAX_LINE ? s.slice(0, MAX_LINE) + " …" : s;
}

function keep(t, line) {
  t.lines.push(line); t.bytes += line.length + 1;
  while (t.bytes > t.max && t.lines.length > 1) { const d = t.lines.shift(); t.bytes -= d.length + 1; t.dropped++; t.droppedBytes += d.length + 1; }
}

function pushTail(t, chunk) {
  if (chunk == null) return;
  const parts = (t.partial + String(chunk)).split("\n");
  t.partial = parts.pop();
  for (const p of parts) keep(t, clean(p));
  // a carriage-return progress bar never sends \n: keep only its latest frame
  if (t.partial.length > MAX_LINE * 2) { const cr = t.partial.lastIndexOf("\r"); t.partial = cr > 0 ? t.partial.slice(cr) : t.partial.slice(-MAX_LINE); }
}

function tailLines(t, n) {
  const out = [], cur = t.partial ? clean(t.partial) : "";
  if (cur.trim()) out.push(cur);
  for (let i = t.lines.length - 1; i >= 0 && out.length < n; i--) if (t.lines[i].trim()) out.push(t.lines[i]);
  return out.slice(0, n).reverse();
}

function tailText(t) {
  const body = t.lines.concat(t.partial ? [clean(t.partial)] : []).join("\n");
  return (t.dropped ? "[" + t.dropped.toLocaleString("en-US") + " earlier line" + (t.dropped === 1 ? "" : "s") + " (" + Math.round(t.droppedBytes / 1024) + " KiB) dropped — only the last " + Math.round(t.max / 1024) + " KiB are kept while it runs]\n" : "") + body;
}

const lineCount = (t) => t.dropped + t.lines.length + (t.partial ? 1 : 0);

module.exports = { createTail, pushTail, tailLines, tailText, lineCount };
