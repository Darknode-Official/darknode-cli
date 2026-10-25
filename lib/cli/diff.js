"use strict";
// Terminal rendering helpers — the two trickiest pure algorithms in the CLI, so
// they get their own tested module:
//  frameDiff: line-level reconciler — during streaming only the rows that changed
//             are rewritten, so a growing reply emits ~2 line updates, not a full redraw.
//  wordHi:    word-level intra-line diff — highlight exactly which words changed
//             between two lines (GitHub-style), instead of a flat red/green pair.
const DEFAULT_COLOR = process.stdout.isTTY && !process.env.NO_COLOR;

function frameDiff(prev, next, ESC) {
  // First paint (no baseline): draw the whole screen from home, clear below.
  if (!prev) {
    let s = ESC + "[H";
    for (let i = 0; i < next.length; i++) s += next[i] + ESC + "[K" + (i < next.length - 1 ? "\r\n" : "");
    return s + ESC + "[J";
  }
  // Otherwise touch only the rows that actually changed, even when the frame
  // grew or shrank (its height changes constantly while a reply streams in).
  // Repositioning per row with absolute [row;1H never scrolls, so a taller
  // frame no longer triggers a full-screen repaint — the top cause of flicker.
  let s = "";
  const common = Math.min(prev.length, next.length);
  for (let i = 0; i < common; i++) if (next[i] !== prev[i]) s += ESC + "[" + (i + 1) + ";1H" + next[i] + ESC + "[K";
  for (let i = common; i < next.length; i++) s += ESC + "[" + (i + 1) + ";1H" + next[i] + ESC + "[K"; // new rows at the bottom
  if (next.length < prev.length) s += ESC + "[" + (next.length + 1) + ";1H" + ESC + "[J"; // frame shrank: wipe the stale rows below it
  return s;
}
function diffTokens(s) { return String(s).match(/\s+|[A-Za-z0-9_]+|[^\sA-Za-z0-9_]/g) || []; }
// Token-level LCS between two lines: { at, bt, af, bf } where af/bf[k] is true when token k
// carried over unchanged. null when either side exceeds `max` tokens (keeps the n*m table small).
function wordFlags(a, b, max) {
  const at = diffTokens(a), bt = diffTokens(b), n = at.length, m = bt.length;
  if (n > (max || 400) || m > (max || 400)) return null;
  const dp = []; for (let i = 0; i <= n; i++) dp.push(new Array(m + 1).fill(0));
  for (let i = n - 1; i >= 0; i--) for (let j = m - 1; j >= 0; j--) dp[i][j] = at[i] === bt[j] ? dp[i + 1][j + 1] + 1 : Math.max(dp[i + 1][j], dp[i][j + 1]);
  const af = new Array(n).fill(true), bf = new Array(m).fill(true); // true = carried over (common)
  let i = 0, j = 0;
  while (i < n && j < m) { if (at[i] === bt[j]) { i++; j++; } else if (dp[i + 1][j] >= dp[i][j + 1]) { af[i++] = false; } else { bf[j++] = false; } }
  while (i < n) af[i++] = false; while (j < m) bf[j++] = false;
  return { at, bt, af, bf };
}
function wordHi(a, b, useColor) {
  if (useColor === undefined) useColor = DEFAULT_COLOR;
  if (!useColor) return [a, b];
  // Bound the O(n*m) LCS: a single very long changed line (minified JS, a long
  // JSON blob) would otherwise build a multi-million-cell table and freeze the
  // whole TUI synchronously inside render(). Past the cap, skip word-level
  // highlighting and show the lines plainly — the diff is still correct.
  const wf = wordFlags(a, b, 600);
  if (!wf) return [a, b];
  const { at, bt, af, bf } = wf;
  const build = (toks, flags, common, changed) => { let s = ""; for (let k = 0; k < toks.length; k++) s += "\x1b[0m" + (flags[k] ? common : changed) + toks[k]; return s + "\x1b[0m"; };
  return [build(at, af, "\x1b[2;31m", "\x1b[1;4;31m"), build(bt, bf, "\x1b[2;32m", "\x1b[1;4;32m")]; // dim=carried, bold+underline=changed
}
module.exports = { frameDiff, diffTokens, wordFlags, wordHi };
