"use strict";
const { strWidth: W, cutIdx } = require("./tui-format");
// ============================================================================
// ask — a PURE renderer + key reducer for the "the model asks YOU a question"
// panel. When the agent raises the `ask_user` tool, the TUI pauses and shows a
// rounded, bordered box (the Claude-Code selection look): the question with an
// accent dot, a numbered option list with a "❯" cursor, a "Type a different
// answer" row that drops into a free-text field, and an explicit Submit row —
// so you confirm by selecting Submit, not by trusting a bare Enter. Multi-select
// shows ◉/○ checkboxes and Submit returns the whole set.
//
// Everything here is pure + snapshot-testable: no DOM, no I/O, no module-scope
// state. The host (darknode.js) owns the terminal, holds the `pendingAsk` state
// and the resolve promise, feeds raw key sequences through `askKey`, and paints
// the rows from `renderAsk`. Colors are injected so tests see plain text.
// ============================================================================

const IDENT = (s) => s;
function theme(c) {
  c = c || {};
  return { cyan: c.cyan || IDENT, gray: c.gray || IDENT, bold: c.bold || IDENT, dim: c.dim || IDENT, green: c.green || IDENT };
}

// Normalize options into [{label, hint}]. Accepts ["a","b"] or [{label,hint}].
function normOptions(options) {
  return (Array.isArray(options) ? options : []).map((o) => {
    if (o && typeof o === "object") return { label: String(o.label != null ? o.label : o.value != null ? o.value : ""), hint: o.hint != null ? String(o.hint) : "" };
    return { label: String(o == null ? "" : o), hint: "" };
  }).filter((o) => o.label.length).slice(0, 9); // at most 9 so a single digit picks any
}

function clampSel(sel, n) { sel = sel | 0; if (sel < 0) return 0; if (sel > n - 1) return Math.max(0, n - 1); return sel; }

// Normalize the multi-select picked set into a sorted array of valid indices.
function normPicked(picked, n) {
  const seen = Object.create(null), out = [];
  for (const i of (Array.isArray(picked) ? picked : [])) { const k = i | 0; if (k >= 0 && k < n && !seen[k]) { seen[k] = 1; out.push(k); } }
  return out.sort((a, b) => a - b);
}

// Does this question allow a free-text "type a different answer" row?  On by
// default for option prompts; the model can suppress it with allowType:false.
function typeAllowed(ask) { return !!(ask && !ask.input && ask.allowType !== false); }

// The navigable rows for an option prompt, in focus order:
//   one row per option, then (optionally) the Type row, then the Submit row.
// Returned as tagged entries so the renderer and reducer agree on the geometry.
function rowModel(ask) {
  const opts = normOptions(ask && ask.options);
  const rows = opts.map((_, i) => ({ kind: "opt", i }));
  if (typeAllowed(ask)) rows.push({ kind: "type" });
  rows.push({ kind: "submit" });
  return { opts, rows };
}

// Plain word-wrap for the question text (no ANSI inside — colored by the caller).
function wrapPlain(s, w) {
  s = String(s || "").replace(/\s+/g, " ").trim();
  if (w < 1) w = 1;
  if (!s) return [""];
  const out = []; let line = "";
  const hard = (word) => { let r = word; while (W(r) > w) { const k = cutIdx(r, w); out.push(r.slice(0, k)); r = r.slice(k); } return r; };
  for (const word of s.split(" ")) {
    if (!line.length) line = W(word) <= w ? word : hard(word);
    else if (W(line) + 1 + W(word) <= w) line += " " + word;
    else { out.push(line); line = W(word) <= w ? word : hard(word); }
  }
  if (line.length) out.push(line);
  return out.length ? out : [""];
}

// Truncate a plain string to w columns with a trailing ellipsis.
function fit(s, w) { s = String(s == null ? "" : s); if (w < 0) w = 0; if (W(s) <= w) return s; if (w <= 1) return w ? s.slice(0, cutIdx(s, 1)) : ""; return s.slice(0, cutIdx(s, w - 1)) + "…"; }

// renderAsk(ask, width, colors) -> string[] (each row ready to paint).
// The Nexus question card — a tab-headed card on a left rail, not a box:
//
//   ┏━ ◆ nexus asks ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//   ┃ Which database should the API use?
//   ┃
//   ┃ ▸ [1] PostgreSQL
//   ┃   [2] SQLite  zero-config
//   ┃   [3] MySQL
//   ┃   [✎] write my own answer
//   ┃
//   ┃   [ Submit ]
//   ┗━ ↑↓ move · 1-3 pick · enter select · esc skip
//
// The focused row gets a ▸ pointer and an accent; multi-select shows ■/□
// checkboxes and the Submit button counts the picks. Rows are measured with
// their PLAIN text (injected colors add no columns) and never exceed `width`.
function renderAsk(ask, width, colors) {
  const C = Math.max(28, (width | 0) || 80);
  const t = theme(colors);
  const mag = (colors && colors.mag) || t.cyan;
  const innerW = C - 4;                    // " ┃ " + content
  const out = [];
  const rail = mag("┃");
  const line = (colored) => out.push(" " + rail + " " + colored);
  const blank = () => out.push(" " + rail);
  const multi = !!(ask && ask.multi);
  const label = ask && ask.input && !ask.typed ? "your answer" : multi ? "pick any" : "nexus asks";
  const tab = " ◆ " + label + " ";
  out.push(" " + mag("┏━") + t.bold(mag(tab)) + mag("━".repeat(Math.max(2, C - 3 - tab.length))));
  for (const ln of wrapPlain(ask && ask.question, Math.max(1, innerW))) line(t.bold(ln));
  blank();

  if (ask && ask.input) {
    // ---- free-text field (a pure input prompt, or "write my own answer" expanded) ----
    const text = String(ask.text || "");
    const avail = Math.max(1, innerW - 3);
    const tail = (n) => { const g = [...text]; let v = 0, i = g.length; while (i > 0 && v + W(g[i - 1]) <= n) v += W(g[--i]); return g.slice(i).join(""); }; // last n cells, wide-char safe
    const shown = W(text) > avail ? "…" + tail(avail - 1) : text;
    const ph = ask.placeholder ? String(ask.placeholder) : "type your answer";
    if (shown) line(t.cyan("› ") + shown + t.cyan("█"));
    else line(t.cyan("› ") + t.dim(fit(ph, avail)) + t.cyan("█"));
    out.push(" " + mag("┗━") + " " + t.gray(fit("enter submit · esc " + (ask.typed ? "back" : "skip"), C - 4)));
    return out;
  }

  const { opts, rows } = rowModel(ask);
  const sel = clampSel(ask && ask.sel, rows.length);
  const picked = multi ? normPicked(ask && ask.picked, opts.length) : [];
  rows.forEach((row, r) => {
    const on = r === sel;
    const cur = on ? t.cyan("▸ ") : "  ";
    if (row.kind === "opt") {
      const o = opts[row.i];
      const key = "[" + (row.i + 1) + "] ";
      const isP = picked.indexOf(row.i) >= 0;
      const box = multi ? (isP ? "■ " : "□ ") : "";
      const boxC = multi ? (isP ? t.green("■ ") : t.gray("□ ")) : "";
      const hintRoom = o.hint ? o.hint.length + 2 : 0;
      const lab = fit(o.label, Math.max(4, innerW - 2 - key.length - box.length - hintRoom));
      const hint = o.hint ? "  " + t.dim(fit(o.hint, Math.max(0, innerW - 2 - key.length - box.length - lab.length - 2))) : "";
      line(cur + (on ? t.cyan(key) : t.gray(key)) + boxC + (on ? t.bold(t.cyan(lab)) : lab) + hint);
    } else if (row.kind === "type") {
          line(cur + (on ? t.cyan("[✎] ") + t.bold(t.cyan("write my own answer")) : t.gray("[✎] write my own answer")));
    } else { // submit — a button, separated from the choices
      blank();
      const tag = "[ Submit" + (multi && picked.length ? " · " + picked.length + " selected" : "") + " ]";
      line(cur + (on ? t.bold(t.green(tag)) : t.gray(tag)));
    }
  });
  const legend = multi
    ? "↑↓ move · space/1-" + Math.max(1, opts.length) + " toggle · enter select · esc skip"
    : "↑↓ move · 1-" + Math.max(1, opts.length) + " pick · enter select · esc skip";
  out.push(" " + mag("┗━") + " " + t.gray(fit(legend, C - 4)));
  return out;
}

// askKey(ask, key) -> a patch describing what the keypress did:
//   { cancelled }            esc / ctrl+c — the user skipped
//   { typing }               the user chose the "type a different answer" row
//   { sel, pick, picked }    a navigation / toggle (host stores these back)
//   { done, value, index }   single-select confirmed (value is the option)
//   { done, indices, values, picked }  multi-select confirmed
//   { done, value, typed }   a free-text answer submitted
// Pure reducer over a raw terminal key sequence.
function askKey(ask, key) {
  // ---- free-text input mode (pure input prompt, or expanded "type" row) ----
  if (ask && ask.input) {
    const text = String(ask.text || "");
    const typed = !!(ask && ask.typed);
    if (key === "\x1b" || key === "\x03") return { text, done: false, cancelled: true };
    if (key === "\r" || key === "\n") return { text, done: true, value: text, typed };
    if (key === "\x7f" || key === "\b") return { text: Array.from(text).slice(0, -1).join(""), done: false };
    if (key === "\x15") return { text: "", done: false };                 // Ctrl+U clears the field
    // Fast typing (keys batched while a frame paints) and pastes arrive as ONE
    // multi-char chunk — taking only single chars silently dropped them. Apply the
    // chunk key by key; newlines inside it are pasted text, not Enter.
    if (key[0] === "\x1b" && !/^\x1b\[200~/.test(key)) return { text, done: false }; // arrows/escape sequences: ignore
    let t = text;
    for (const ch of key.replace(/\x1b\[20[01]~/g, "")) {
      if (ch === "\x7f" || ch === "\b") t = Array.from(t).slice(0, -1).join("");
      else if (ch === "\x15") t = "";
      else if (ch === "\r" || ch === "\n" || ch === "\t") { if (t && !t.endsWith(" ")) t += " "; }
      else if (ch.codePointAt(0) >= 0x20 && ch !== "\x7f") t += ch;
    }
    return { text: t, done: false };
  }
  const { opts, rows } = rowModel(ask);
  const n = opts.length;
  const R = rows.length;
  const sel = clampSel(ask && ask.sel, R);
  const multi = !!(ask && ask.multi);
  const curPicked = () => normPicked(ask && ask.picked, n);
  // The option index to submit in single mode: the last option the cursor sat
  // on (tracked as `pick`), falling back to the focused option or the first.
  const pickOf = () => { const here = rows[sel]; if (here && here.kind === "opt") return here.i; const p = (ask && ask.pick) | 0; return p >= 0 && p < n ? p : 0; };

  if (key === "\x1b" || key === "\x03") return multi ? { sel, picked: curPicked(), done: false, cancelled: true } : { sel, done: false, cancelled: true };
  if (R === 0) return { sel, done: false };

  const move = (d) => { const s2 = (sel + d + R) % R; const here = rows[s2]; const patch = { sel: s2, done: false }; if (here && here.kind === "opt") patch.pick = here.i; if (multi) patch.picked = curPicked(); return patch; };
  if (key === "\x1b[A" || key === "[A" || key === "\x1bOA") return move(-1);
  if (key === "\x1b[B" || key === "[B" || key === "\x1bOB") return move(1);

  // A digit always targets an option directly (single: pick+submit; multi: toggle).
  if (/^[1-9]$/.test(key)) {
    const i = +key - 1;
    if (i >= n) return multi ? { sel, picked: curPicked(), done: false } : { sel, done: false };
    if (multi) { const cur = curPicked(); const at = cur.indexOf(i); if (at >= 0) cur.splice(at, 1); else cur.push(i); return { sel, pick: i, picked: normPicked(cur, n), done: false }; }
    return { done: true, value: opts[i], index: i };
  }

  const here = rows[sel];
  if (multi && key === " ") { if (here && here.kind === "opt") { const cur = curPicked(); const at = cur.indexOf(here.i); if (at >= 0) cur.splice(at, 1); else cur.push(here.i); return { sel, pick: here.i, picked: normPicked(cur, n), done: false }; } return { sel, picked: curPicked(), done: false }; }

  if (key === "\r" || key === "\n") {
    if (here && here.kind === "type") return { typing: true };
    if (here && here.kind === "submit") {
      if (multi) { const idx = curPicked(); return { done: true, indices: idx, values: idx.map((i) => opts[i]), picked: idx }; }
      const p = pickOf(); return { done: true, value: opts[p], index: p };
    }
    // on an option row
    if (here && here.kind === "opt") {
      if (multi) { const cur = curPicked(); const at = cur.indexOf(here.i); if (at >= 0) cur.splice(at, 1); else cur.push(here.i); return { sel, pick: here.i, picked: normPicked(cur, n), done: false }; }
      return { done: true, value: opts[here.i], index: here.i };
    }
    return { sel, done: false };
  }
  return multi ? { sel, picked: curPicked(), done: false } : { sel, done: false };
}

module.exports = { renderAsk, askKey, normOptions, normPicked, wrapPlain, rowModel, typeAllowed };
