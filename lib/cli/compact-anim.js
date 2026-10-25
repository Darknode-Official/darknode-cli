"use strict";
// ============================================================================
// compact-anim — the Nexus "condenser": a PURE renderer for the live
// compaction status. Instead of a single spinner line, the conversation is
// drawn as a bar that is squeezed inward from both ends toward a bright core,
// over and over, while a counter shows the context being folded down.
//
//   ⧉ Condensing conversation   12s · ↓ 1.2k tokens · esc to interrupt
//     ·······▸━━━━━◆━━━━━◂·······   48.2k tokens → folding
//
// Pure + deterministic: the frame is a function of (now - start), colors are
// injected, so tests can assert exact frames.
// ============================================================================

const IDENT = (s) => s;
function theme(c) {
  c = c || {};
  return { cyan: c.cyan || IDENT, gray: c.gray || IDENT, bold: c.bold || IDENT, dim: c.dim || IDENT, mag: c.mag || IDENT };
}

const CYCLE_MS = 1600; // one full squeeze, ends → core

function fmtK(n) { n = Math.max(0, n | 0); return n >= 1000 ? (n / 1000).toFixed(n >= 100000 ? 0 : 1) + "k" : String(n); }
function fmtSec(s) { s = Math.max(0, s | 0); return s < 60 ? s + "s" : Math.floor(s / 60) + "m" + String(s % 60).padStart(2, "0") + "s"; }

// The squeeze bar for a given elapsed time: `w` cells (odd widths center
// cleanly). The two jaws close from the edges toward the middle over CYCLE_MS;
// cells outside the jaws are dim dots, the jaws are ▸/◂, the squeezed span is a
// heavy rule, and the center is a ◆ core. Returns { plain, colored }.
function squeezeBar(elapsedMs, w, t) {
  t = t || theme();
  w = Math.max(7, w | 0);
  const mid = (w - 1) / 2;
  const phase = ((Math.max(0, elapsedMs) % CYCLE_MS) / CYCLE_MS); // 0 → 1
  const reach = Math.floor(phase * Math.floor(mid));               // how far the jaws have closed
  let plain = "", colored = "";
  for (let i = 0; i < w; i++) {
    const d = Math.abs(i - mid);
    const left = i < mid;
    let ch, paint;
    if (d < 0.6) { ch = "◆"; paint = (s) => t.bold(t.mag(s)); }               // the core
    else if (i === reach && left) { ch = "▸"; paint = t.cyan; }               // left jaw
    else if (i === w - 1 - reach && !left) { ch = "◂"; paint = t.cyan; }      // right jaw
    else if ((left && i > reach) || (!left && i < w - 1 - reach)) { ch = "━"; paint = (s) => t.cyan(s); } // squeezed span
    else { ch = "·"; paint = t.dim; }                                         // already folded away
    plain += ch; colored += paint(ch);
  }
  return { plain, colored };
}

// compactRows(o) -> string[]  (two rows: title + squeeze bar).
//   o: { now, start, tok, before, width, colors }
function compactRows(o) {
  o = o || {};
  const t = theme(o.colors);
  const now = o.now || Date.now();
  const el = Math.max(0, now - (o.start || now));
  const C = Math.max(24, (o.width | 0) || 80);
  const glyph = ["⧉", "⧈", "⧉", "▣"][Math.floor(el / 200) % 4];
  const meta = fmtSec(Math.round(el / 1000)) + (o.tok ? " · ↓ " + fmtK(o.tok) + " tokens" : "") + " · esc to interrupt";
  const title = t.mag(glyph) + " " + t.bold(t.cyan("Condensing conversation")) + t.gray("   " + meta);
  const tail = o.before ? "   " + fmtK(o.before) + " tokens → folding" : "   folding";
  const barW = Math.max(7, Math.min(31, C - 4 - tail.length) | 1);   // keep it odd so the core centers
  const bar = squeezeBar(el, barW, t);
  return [title, "  " + bar.colored + t.gray(tail)];
}

// doneRow(o) -> string  (the marker left in the transcript once compaction is
// done: the squeeze's final, fully-closed frame "▸◆◂" + what was folded).
//   o: { before, auto, hasSummary, expanded, colors }
function doneRow(o) {
  o = o || {};
  const t = theme(o.colors);
  const what = o.before ? (o.auto ? "auto-condensed " : "condensed ") + fmtK(o.before) + " tokens of conversation" : (o.auto ? "auto-condensed the conversation" : "conversation condensed");
  return t.cyan("▸") + t.bold(t.mag("◆")) + t.cyan("◂") + " " + t.gray(what) + (o.hasSummary ? t.gray(" · ctrl+o " + (o.expanded ? "hides" : "shows") + " the summary") : "");
}

module.exports = { compactRows, squeezeBar, doneRow, CYCLE_MS };
