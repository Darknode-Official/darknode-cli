"use strict";
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
function fit(s, w) { s = String(s == null ? "" : s).replace(/\s+/g, " ").trim(); if (w < 0) w = 0; if (s.length <= w) return s; if (w <= 1) return s.slice(0, w); return s.slice(0, w - 1) + "…"; }

// Plain word-wrap for the transcript body (no ANSI inside — colored by caller).
function wrapPlain(s, w) {
  if (w < 1) w = 1;
  const out = [];
  for (const para of String(s == null ? "" : s).replace(/\r/g, "").split("\n")) {
    const words = para.replace(/\t/g, "  ").split(" ");
    let line = "";
    const hard = (word) => { let r = word; while (r.length > w) { out.push(r.slice(0, w)); r = r.slice(w); } return r; };
    for (const word of words) {
      if (!line.length) line = word.length <= w ? word : hard(word);
      else if (line.length + 1 + word.length <= w) line += " " + word;
      else { out.push(line); line = word.length <= w ? word : hard(word); }
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

// panelRows(agents, opt) -> string[]  (compact list under the prompt bar).
//   opt: { now, sel, width, colors, max }
//   sel  = focused row index when the panel has keyboard focus, else -1 (idle).
// Returns [] when there are no agents (the panel takes no space). Rows are not
// padded — the host's frame diff clears to end-of-line, same as the slash menu.
function panelRows(agents, opt) {
  agents = Array.isArray(agents) ? agents : [];
  if (!agents.length) return [];
  opt = opt || {};
  const t = theme(opt.colors);
  const now = opt.now || Date.now();
  const C = Math.max(20, (opt.width | 0) || 80);
  const rawSel = opt.sel == null ? -1 : (opt.sel | 0);
  const focus = rawSel >= 0;                          // sel < 0 is the idle (unfocused) sentinel
  const sel = focus ? clampSel(rawSel, agents.length) : -1;
  const max = Math.max(1, (opt.max | 0) || 5);
  const running = agents.filter((a) => a && a.status === "run").length;
  const done = agents.length - running;
  const out = [];
  // header: "agents  2 running · 1 done" + a right-side nav hint.
  const sum = [];
  if (running) sum.push(running + " running");
  if (done) sum.push(done + " done");
  const hint = focus ? "↑↓ move · enter open · s stop · x clear · esc back" : "↓ to select";
  out.push("  " + t.dim("agents") + t.gray("  " + sum.join(" · ")) + t.gray("    " + hint));
  const start = windowStart(agents.length, sel, max);
  const shown = agents.slice(start, start + max);
  shown.forEach((a, j) => {
    const gi = start + j;
    const on = focus && gi === sel;
    const st = statusOf(a, t);
    const el = fmtDur(elapsed(a, now));
    const cur = on ? t.cyan("❯ ") : "  ";
    const taskW = Math.max(6, C - 2 - 2 - 2 - 2 - el.length - 1); // indent + cursor + glyph+sp + gap + elapsed
    const task = fit(a.task, taskW);
    const label = on ? t.bold(task) : (a.status === "run" ? task : t.gray(task));
    out.push("  " + cur + st.glyph + " " + label + "  " + t.gray(el));
  });
  if (agents.length > shown.length) out.push("  " + t.dim("   +" + (agents.length - shown.length) + " more"));
  return out;
}

// viewRows(agent, C, R, scroll, colors) -> string[]  (full-screen transcript of
// one agent; replaces the composer, mirroring the /btw overlay geometry). The
// body is the agent's output so far, scrollable; a running agent shows its
// partial output (or a "running…" note) and a live elapsed clock.
function viewRows(agent, C, R, scroll, colors, now) {
  const t = theme(colors);
  const w = Math.max(12, (C | 0) - 4);
  const avail = Math.max(8, (R | 0) - 4);
  const a = agent || { task: "", status: "run", start: 0 };
  const st = statusOf(a, t);
  const head = [];
  head.push(" " + t.bold("Agent") + t.gray("  — sub-agent output") + (a.native === false ? t.gray("  · " + (a.engine || "engine")) : ""));
  for (const ql of wrapPlain("❯ " + String(a.task || ""), w)) head.push(" " + t.cyan(ql));
  head.push(" " + st.paint(st.badge) + t.gray("  ·  " + fmtDur(elapsed(a, now || Date.now()))));
  head.push("");
  const bodyMax = Math.max(2, avail - head.length - 3);
  const resultText = String(a.result == null ? "" : a.result);
  const body = resultText ? wrapPlain(resultText, w) : [t.gray(a.status === "run" ? "running…" : "(no output)")];
  let sc = scroll | 0;
  const maxSc = Math.max(0, body.length - bodyMax);
  if (sc > maxSc) sc = maxSc;
  if (sc < 0) sc = 0;
  const vis = body.slice(sc, sc + bodyMax);
  const rows = head.concat(vis.map((l) => "  " + l));
  if (body.length > bodyMax) rows.push(" " + t.gray("   … " + Math.min(body.length, sc + bodyMax) + "/" + body.length + " lines"));
  rows.push("");
  rows.push(" " + t.gray("esc close · ↑↓ scroll · " + (a.status === "run" ? "s stop · " : "") + "c copy"));
  return rows;
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

module.exports = { panelRows, viewRows, panelKey, fmtDur, elapsed, statusOf, wrapPlain, fit, windowStart };
