"use strict";
// ============================================================================
// ledger — PURE helpers for the per-session cost ledger (`/turns`) and the
// lossless cost advisor (`/cheaper`). The host records one plain entry per
// finished turn; everything here is a function of that array (+ the current
// settings), so it is fully snapshot-testable. No I/O, no module state.
//
// A turn entry: { t, inTok, outTok, cost, dt, model, engine, label, paid,
//                 cacheRead }  — all already known to the host at turn end.
// ============================================================================

const { sanitizeTerm, stripAnsi, strWidth, fitWidth } = require("./tui-format");
const IDENT = (s) => s;
function theme(c) {
  c = c || {};
  return { cyan: c.cyan || IDENT, gray: c.gray || IDENT, bold: c.bold || IDENT, dim: c.dim || IDENT, green: c.green || IDENT, yellow: c.yellow || IDENT, mag: c.mag || IDENT };
}

function fmtK(n) { n = Math.max(0, Math.round(n || 0)); return n >= 1000 ? (n / 1000).toFixed(n >= 100000 ? 0 : 1) + "k" : String(n); }
function money(n) { n = Number(n) || 0; return "$" + (n < 1 ? n.toFixed(4) : n.toFixed(2)); }
function fmtDur(s) { s = Math.max(0, Math.round(s || 0)); return s < 60 ? s + "s" : Math.floor(s / 60) + "m" + String(s % 60).padStart(2, "0") + "s"; }
// labels are prompt text: drop escapes (an OSC in one would retitle the terminal) and cut by cells, not UTF-16 units
function fit(s, w) { s = stripAnsi(sanitizeTerm(String(s == null ? "" : s))).replace(/\s+/g, " ").trim(); return fitWidth(s, Math.max(0, w)); }

// Roll the whole session up: totals + the index of the costliest paid turn +
// how many prompts were sent more than once (candidates for the free cache).
function summarizeTurns(turns) {
  turns = Array.isArray(turns) ? turns : [];
  const sum = { turns: turns.length, inTok: 0, outTok: 0, cacheRead: 0, cost: 0, dt: 0, paidTurns: 0, topCostIdx: -1, dupPrompts: 0, dupTurns: 0 };
  let topCost = -1;
  const seen = Object.create(null), dupKeys = Object.create(null);
  turns.forEach((t, i) => {
    sum.inTok += t.inTok || 0; sum.outTok += t.outTok || 0; sum.cacheRead += t.cacheRead || 0;
    sum.cost += Number(t.cost) || 0; sum.dt += t.dt || 0; if (t.paid) sum.paidTurns++;
    if ((t.cost || 0) > topCost) { topCost = t.cost || 0; sum.topCostIdx = i; }
    const key = (t.label || "").trim().toLowerCase();
    if (key) { if (seen[key]) { sum.dupTurns++; if (!dupKeys[key]) { dupKeys[key] = 1; sum.dupPrompts++; } } else seen[key] = 1; }
  });
  if (topCost <= 0) sum.topCostIdx = -1; // no paid cost to highlight
  return sum;
}

// renderTurns(turns, opt) -> string[]  (the `/turns` ledger card).
//   opt: { colors, width, max }   max = how many recent turns to list.
function renderTurns(turns, opt) {
  turns = Array.isArray(turns) ? turns : [];
  opt = opt || {};
  const t = theme(opt.colors);
  const C = Math.max(40, (opt.width | 0) || 80);
  const max = Math.max(1, (opt.max | 0) || 12);
  if (!turns.length) return [t.gray("no turns yet this session — the ledger fills in as you work")];
  const s = summarizeTurns(turns);
  const out = [];
  out.push(t.bold("session ledger") + t.gray("  " + s.turns + " turn" + (s.turns === 1 ? "" : "s") + " · ↑" + fmtK(s.inTok) + " ↓" + fmtK(s.outTok) + (s.cacheRead ? " · cache ↓" + fmtK(s.cacheRead) : "") + (s.cost ? " · " + money(s.cost) : " · free") + " · " + fmtDur(s.dt)));
  const start = Math.max(0, turns.length - max);
  const idxW = String(turns.length).length;
  // the money column is right-aligned to the widest value shown
  const shown = turns.slice(start);
  const costW = Math.max(5, ...shown.map((x) => money(x.cost || 0).length));
  shown.forEach((x, j) => {
    const i = start + j;
    const n = String(i + 1).padStart(idxW);
    const top = i === s.topCostIdx && (x.cost || 0) > 0;
    const costStr = (x.paid ? money(x.cost || 0) : "free").padStart(costW);
    const tail = " ↑" + fmtK(x.inTok) + " ↓" + fmtK(x.outTok) + "  " + costStr + "  " + fmtDur(x.dt);
    const room = C - 2 - idxW - 2 - tail.length - (top ? 2 : 0);
    const label = fit(x.label || "(turn)", Math.max(6, room - 1)); // -1: the gap before the tail is at least one space
    const line = (top ? t.yellow("▲ ") : "") + t.gray(n + ". ") + label + t.gray(" ".repeat(Math.max(1, room - strWidth(label))) + tail);
    out.push("  " + line);
  });
  if (start > 0) out.push(t.dim("  … " + start + " earlier turn" + (start === 1 ? "" : "s") + " above"));
  if (s.topCostIdx >= 0 && turns[s.topCostIdx] && (turns[s.topCostIdx].cost || 0) > 0) out.push(t.gray("  ▲ priciest: turn " + (s.topCostIdx + 1) + " at " + money(turns[s.topCostIdx].cost) + " — ") + t.dim("/cheaper for ways to spend less"));
  return out;
}

// costAdvice(turns, settings) -> [{ tag, text }]  (lossless suggestions only —
// never anything that trades output quality for cost; the one quality tradeoff,
// effort, is flagged as such, not recommended blindly). settings:
//   { cacheOn, effort, engine, paid, autoCompact, ctxPct }
function costAdvice(turns, settings) {
  turns = Array.isArray(turns) ? turns : [];
  settings = settings || {};
  const s = summarizeTurns(turns);
  const tips = [];
  if (!settings.paid) { tips.push({ tag: "free", text: "this engine is local (Ollama) — turns are already free, nothing to save." }); return tips; }
  if (!settings.cacheOn) tips.push({ tag: "cache", text: "exact-repeat cache is OFF — `/cache on` serves an identical read-only turn for free (lossless)." });
  if (s.dupTurns > 0) tips.push({ tag: "dups", text: s.dupTurns + " turn" + (s.dupTurns === 1 ? "" : "s") + " repeated an earlier prompt verbatim" + (settings.cacheOn ? " — the exact-repeat cache already served those free." : " — turn `/cache on` and repeats cost nothing.") });
  if (settings.engine === "claude") tips.push({ tag: "prompt-cache", text: "on the claude engine prompt-caching is automatic — keep a session going (don't `/new`) so the big unchanged context is billed at the cheap cache-read rate." });
  if (settings.effort === "high" || settings.effort === "max" || settings.effort === "xhigh" || settings.effort === "ultracode") tips.push({ tag: "effort", text: "effort is " + settings.effort + " — it buys deeper reasoning but spends far more output tokens; drop to `/effort medium` for routine work (this is a quality tradeoff, your call — not auto-applied)." });
  if ((settings.ctxPct || 0) >= 50 && !settings.autoCompact) tips.push({ tag: "context", text: "context is " + Math.round(settings.ctxPct) + "% full — every turn re-bills the whole thing; `/compact` now folds it down (lossless summary) so later turns are cheaper." });
  if (s.topCostIdx >= 0 && turns[s.topCostIdx] && (turns[s.topCostIdx].cost || 0) > Math.max(0.01, (s.cost / Math.max(1, s.paidTurns)) * 3)) tips.push({ tag: "outlier", text: "turn " + (s.topCostIdx + 1) + " (" + money(turns[s.topCostIdx].cost) + ") cost well above your average — large pastes or wide file reads drive input tokens; trim what you paste in." });
  // "prompt-cache" is informational (always true on claude), so it doesn't count
  // as something to fix — reassure when nothing actionable turned up.
  if (!tips.some((t) => t.tag !== "prompt-cache")) tips.push({ tag: "ok", text: "nothing obvious to cut — cache is on and effort/context look reasonable. /turns shows where the tokens went." });
  return tips;
}

function renderAdvice(turns, settings, colors) {
  const t = theme(colors);
  const tips = costAdvice(turns, settings);
  const out = [t.bold("cost advisor") + t.gray("  — lossless ways to spend less (quality unchanged unless noted)")];
  for (const tip of tips) out.push("  " + t.green("•") + " " + t.gray(tip.text));
  return out;
}

module.exports = { summarizeTurns, renderTurns, costAdvice, renderAdvice, fmtK, money, fmtDur };
