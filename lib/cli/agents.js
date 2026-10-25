"use strict";
const { strWidth: W, cutIdx } = require("./tui-format");
// ============================================================================
// agents — a PURE renderer + key reducer for the Agents panel: the live list of
// sub-agents (spawned via /agents, the spawn_agents tool, or a Claude-engine
// Task) that sits under the prompt bar, Claude-Code style. Each agent shows its
// task, a status glyph and elapsed time; a running agent can be opened to read
// its output or stopped from the list, and finished agents stay listed with a
// done / failed / stopped badge until cleared.
//
// Everything here is pure + snapshot-testable: no DOM, no I/O, no timers, no
// module-scope state. The host (darknode.js) owns the registry array and the
// focus/selection state, feeds raw key sequences through `panelKey`, and paints
// the rows from `panelRows` (the compact list) and `viewRows` (the full-screen
// transcript of one agent). `now` is injected so elapsed time is deterministic
// in tests, and colors are injected so tests see plain text.
// ============================================================================

const IDENT = (s) => s;
function theme(c) {
  c = c || {};
  return { cyan: c.cyan || IDENT, gray: c.gray || IDENT, bold: c.bold || IDENT, dim: c.dim || IDENT, green: c.green || IDENT, red: c.red || IDENT, yellow: c.yellow || IDENT, mag: c.mag || IDENT };
}

// Human elapsed time: "5s", "1m23s", "2h04m". Clamped to >= 0.
function fmtDur(ms) {
  let s = Math.floor(Math.max(0, ms | 0) / 1000);
  if (s < 60) return s + "s";
  const m = Math.floor(s / 60); s = s % 60;
  if (m < 60) return m + "m" + (s < 10 ? "0" : "") + s + "s";
  const h = Math.floor(m / 60), mm = m % 60;
  return h + "h" + (mm < 10 ? "0" : "") + mm + "m";
}

// How long an agent has been (or was) running, given the current clock.
function elapsed(a, now) { return ((a && a.end) || now || 0) - ((a && a.start) || 0); }

// Status → { glyph, badge, paint }. run is a half-filled dot (yellow), ok a
// solid dot (green), fail a cross (red), stopped a square (dim).
function statusOf(a, t) {
  const s = a && a.status;
  if (s === "ok") return { glyph: t.green("●"), badge: "done", paint: t.green };
  if (s === "fail") return { glyph: t.red("✗"), badge: "failed", paint: t.red };
  if (s === "stopped") return { glyph: t.dim("■"), badge: "stopped", paint: t.dim };
  return { glyph: t.yellow("◐"), badge: "running", paint: t.yellow };
}

// Truncate a plain string to w columns with a trailing ellipsis (no ANSI in).
function fit(s, w) { s = String(s == null ? "" : s).replace(/\s+/g, " ").trim(); if (w < 0) w = 0; if (W(s) <= w) return s; if (w <= 1) return w ? s.slice(0, cutIdx(s, 1)) : ""; return s.slice(0, cutIdx(s, w - 1)) + "…"; }

// Plain word-wrap for the transcript body (no ANSI inside — colored by caller).
function wrapPlain(s, w) {
  if (w < 1) w = 1;
  const out = [];
  for (const para of String(s == null ? "" : s).replace(/\r/g, "").split("\n")) {
    const words = para.replace(/\t/g, "  ").split(" ");
    let line = "";
    const hard = (word) => { let r = word; while (W(r) > w) { const k = cutIdx(r, w); out.push(r.slice(0, k)); r = r.slice(k); } return r; };
    for (const word of words) {
      if (!line.length) line = W(word) <= w ? word : hard(word);
      else if (W(line) + 1 + W(word) <= w) line += " " + word;
      else { out.push(line); line = W(word) <= w ? word : hard(word); }
    }
    out.push(line);
  }
  return out.length ? out : [""];
}

// The window of agent rows to show when the list is taller than `max`: a stable
// region that follows the selection (or pins to the most-recent when unfocused).
function windowStart(n, sel, max) {
  if (n <= max) return 0;
  if (sel < 0) return n - max;                       // unfocused: show the newest
  return Math.max(0, Math.min(sel - (max >> 1), n - max));
}

// Running agents animate: a quarter-moon spinner and a 5-cell activity meter
// whose lit pair bounces end to end. Both are pure functions of `now`.
const SPIN = ["◐", "◓", "◑", "◒"];
function spinGlyph(now) { return SPIN[Math.floor((now | 0) / 120) % SPIN.length]; }
function meter(now, w) {
  w = w || 5;
  const last = w - 2, span = last * 2, k = Math.floor((now | 0) / 140) % span, pos = k <= last ? k : span - k; // pair start bounces 0..w-2
  let s = ""; for (let i = 0; i < w; i++) s += (i === pos || i === pos + 1) ? "▰" : "▱";
  return s;
}

// panelRows(agents, opt) -> string[]  (the lanes under the prompt bar).
//   opt: { now, sel, width, colors, max }
//   sel  = focused row index when the panel has keyboard focus, else -1 (idle).
// Layout — a tree of lanes with leader dots aligning a right-hand status column:
//   ⟡ agents ── 1 running · 2 done                         ↓ to select
//    ├─ ◐ write the docs ·························· ▰▰▱▱▱    12s
//   ▶├─ ● add unit tests ·························· done   1m03s
//    └─ ✗ fix the lint errors ····················· failed   50s
// Returns [] when there are no agents (the panel takes no space).
function panelRows(agents, opt) {
  agents = Array.isArray(agents) ? agents : [];
  if (!agents.length) return [];
  opt = opt || {};
  const t = theme(opt.colors);
  const now = opt.now || Date.now();
  const C = Math.max(30, (opt.width | 0) || 80);
  const rawSel = opt.sel == null ? -1 : (opt.sel | 0);
  const focus = rawSel >= 0;                          // sel < 0 is the idle (unfocused) sentinel
  const sel = focus ? clampSel(rawSel, agents.length) : -1;
  const max = Math.max(1, (opt.max | 0) || 5);
  const running = agents.filter((a) => a && a.status === "run").length;
  const done = agents.length - running;
  const out = [];
  const sum = [];
  if (running) sum.push(running + " running");
  if (done) sum.push(done + " done");
  const headPlain = "⟡ agents ── " + sum.join(" · ");
  // the longest hint that fits beside the header (never cut mid-word)
  const hints = focus ? ["enter open · s stop · x clear · esc back", "enter open · s stop · esc back", "↵ open · s stop · esc", "esc back"] : ["↓ to select"];
  const hint = hints.find((h) => headPlain.length + 3 + h.length <= C - 1) || "";
  const gap = Math.max(2, C - 1 - headPlain.length - hint.length);
  out.push(" " + t.mag("⟡") + " " + t.bold("agents") + t.gray(" ── ") + (running ? t.yellow(sum[0]) + (sum[1] ? t.gray(" · " + sum[1]) : "") : t.gray(sum.join(" · "))) + " ".repeat(gap) + t.gray(hint));
  const start = windowStart(agents.length, sel, max);
  const shown = agents.slice(start, start + max);
  const more = agents.length - shown.length;
  shown.forEach((a, j) => {
    const gi = start + j;
    const on = focus && gi === sel;
    const last = j === shown.length - 1 && !more;
    const st = statusOf(a, t);
    const el = fmtDur(elapsed(a, now));
    const isRun = a.status === "run";
    const glyph = isRun ? t.yellow(spinGlyph(now)) : st.glyph;
    const midPlain = isRun ? meter(now) : st.badge;
    const midPad = " ".repeat(Math.max(0, 7 - midPlain.length));             // fixed 7-col status column ("stopped")
    const right = " " + midPad + midPlain + " " + el.padStart(6);
    const lead = (on ? "▶" : " ") + (last ? "└─ " : "├─ ") + "x ";      // cursor + branch + glyph + space
    const room = C - 1 - lead.length - right.length - 1;                  // keep 1 col slack
    const task = fit(a.task, Math.max(4, room - 3));
    const dots = Math.max(1, room - W(task) - 1);
    const cur = on ? t.cyan("▶") : " ";
    const branch = t.gray(last ? "└─ " : "├─ ");
    const label = on ? t.bold(t.cyan(task)) : (isRun ? task : t.gray(task));
    const midC = isRun ? t.cyan(midPlain) : st.paint(midPlain);
    out.push(" " + cur + branch + glyph + " " + label + " " + t.dim("·".repeat(dots)) + " " + midPad + midC + " " + t.gray(el.padStart(6)));
  });
  if (more) out.push("  " + t.gray("└─ ") + t.dim("+" + more + " more"));
  return out;
}

// viewRows(agent, C, R, scroll, colors) -> string[]  (full-screen transcript of
// one agent; replaces the composer, mirroring the /btw overlay geometry). The
// body is the agent's output so far, scrollable; a running agent shows its
// partial output (or a "running…" note) and a live elapsed clock.
function viewRows(agent, C, R, scroll, colors, now) {
  const t = theme(colors);
  const w = Math.max(12, (C | 0) - 6);
  const avail = Math.max(8, (R | 0) - 4);
  const a = agent || { task: "", status: "run", start: 0 };
  const st = statusOf(a, t);
  const isRun = a.status === "run";
  const clock = now || Date.now();
  const rail = t.mag("┃");
  const head = [];
  const glyph = isRun ? t.yellow(spinGlyph(clock)) : st.glyph;
  head.push(" " + t.mag("⟡") + " " + t.bold("agent") + t.gray(" ── ") + glyph + " " + st.paint(st.badge) + t.gray("  ·  " + fmtDur(elapsed(a, clock)) + (a.native === false ? "  ·  " + (a.engine || "engine") : "")) + (isRun ? "  " + t.cyan(meter(clock)) : ""));
  for (const ql of wrapPlain(String(a.task || ""), w)) head.push(" " + rail + " " + t.bold(t.cyan(ql)));
  head.push(" " + rail);
  const bodyMax = Math.max(2, avail - head.length - 2);
  const resultText = String(a.result == null ? "" : a.result);
  const body = resultText ? wrapPlain(resultText, w) : [t.gray(isRun ? "running…" : "(no output)")];
  let sc = scroll | 0;
  const maxSc = Math.max(0, body.length - bodyMax);
  if (sc > maxSc) sc = maxSc;
  if (sc < 0) sc = 0;
  const vis = body.slice(sc, sc + bodyMax);
  const rows = head.concat(vis.map((l) => " " + rail + " " + l));
  const pos = body.length > bodyMax ? "  " + Math.min(body.length, sc + bodyMax) + "/" + body.length + " lines  ·" : "";
  rows.push(" " + t.mag("┗━") + t.gray(pos + "  esc close · ↑↓ scroll · [ ] prev/next · " + (isRun ? "s stop · " : "") + "c copy"));
  return rows;
}

// viewBar(agent, i, n, C, colors, now) -> the 3-row bar shown under an agent's
// full-screen conversation: who it is, how it's doing, and the keys.
function viewBar(agent, i, n, C, colors, now) {
  const t = theme(colors);
  const a = agent || { task: "", status: "run", start: 0 };
  const st = statusOf(a, t);
  const isRun = a.status === "run";
  const clock = now || Date.now();
  C = Math.max(30, C | 0);
  const glyph = isRun ? t.yellow(spinGlyph(clock)) : st.glyph;
  const lead = "⟡ agent " + (i + 1) + "/" + n + " ── ";
  const stat = st.badge + " · " + fmtDur(elapsed(a, clock)) + (a.native === false ? " · " + (a.engine || "engine") : "");
  const room = C - 2 - W(lead) - 2 - W(stat) - 3;
  const head = " " + t.mag("⟡") + " " + t.bold("agent " + (i + 1) + "/" + n) + t.gray(" ── ") + glyph + " " + st.paint(st.badge) + t.gray(stat.slice(st.badge.length)) + (room > 6 ? t.gray("  ·  ") + t.bold(t.cyan(fit(a.task, room))) : "");
  const keys = ["esc back", "↑↓ scroll", n > 1 ? "←→ prev/next agent" : "", isRun ? "s stop" : "", "ctrl+y copy result"].filter(Boolean);
  let hint = ""; for (const k of keys) if (W(hint + " · " + k) <= C - 3) hint += (hint ? " · " : "") + k;
  return [" " + t.mag("━".repeat(Math.max(1, C - 2))), head, " " + t.gray(hint)];
}

function clampSel(sel, n) { sel = sel | 0; if (n <= 0) return 0; if (sel < 0) return 0; if (sel > n - 1) return n - 1; return sel; }

// panelKey(state, key, n) -> a patch describing what a keypress did while the
// Agents panel has focus:
//   { sel }         navigation (host stores it back)
//   { open: i }     open agent i's transcript
//   { stop: i }     stop / cancel agent i
//   { clear }       clear the finished agents from the list
//   { leave }       release focus back to the composer
// `state` = { sel }; `n` = agent count. Pure reducer over a raw key sequence.
function panelKey(state, key, n) {
  n = n | 0;
  const sel = clampSel(state && state.sel, n);
  if (n <= 0) return { leave: true };
  if (key === "\x1b" || key === "\x03") return { leave: true };          // esc / ctrl+c → back to composer
  if (key === "\x1b[A" || key === "[A" || key === "\x1bOA") {            // up (off the top row → leave)
    if (sel <= 0) return { leave: true };
    return { sel: sel - 1 };
  }
  if (key === "\x1b[B" || key === "[B" || key === "\x1bOB") return { sel: Math.min(n - 1, sel + 1) }; // down
  if (key === "\r" || key === "\n" || key === "\x1b[C" || key === "\x1bOC") return { open: sel };     // enter / → open
  if (key === "s" || key === "S" || key === "\x7f" || key === "\b") return { stop: sel };             // s / backspace stop
  if (key === "x" || key === "X") return { clear: true };                                             // clear finished agents
  if (/^[1-9]$/.test(key)) { const i = +key - 1; return i < n ? { open: i } : { sel }; }              // digit opens
  return { sel };                                                        // unrelated key: keep focus
}

module.exports = { spinGlyph, meter, panelRows, viewRows, viewBar, panelKey, fmtDur, elapsed, statusOf, wrapPlain, fit, windowStart };
