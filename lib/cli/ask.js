"use strict";
// ============================================================================
// ask — a PURE renderer + key reducer for the "the model asks YOU a question"
// panel. When the agent raises the `ask_user` tool, the TUI pauses and shows a
// multiple-choice prompt in the same open-rule frame the composer uses (a thin
// horizontal rule above and below, no side walls), with a numbered option list
// and an arrow/number selector — the Claude-Code "pick one" look.
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

// Plain word-wrap for the question text (no ANSI inside — colored by the caller).
function wrapPlain(s, w) {
  s = String(s || "").replace(/\s+/g, " ").trim();
  if (w < 1) w = 1;
  if (!s) return [""];
  const out = []; let line = "";
  const hard = (word) => { let r = word; while (r.length > w) { out.push(r.slice(0, w)); r = r.slice(w); } return r; };
  for (const word of s.split(" ")) {
    if (!line.length) line = word.length <= w ? word : hard(word);
    else if (line.length + 1 + word.length <= w) line += " " + word;
    else { out.push(line); line = word.length <= w ? word : hard(word); }
  }
  if (line.length) out.push(line);
  return out.length ? out : [""];
}

// renderAsk(ask, width, colors) -> string[] (each row ready to paint; the first
// gutter space matches the composer's " " + content convention).
function renderAsk(ask, width, colors) {
  const C = Math.max(24, (width | 0) || 80);
  const t = theme(colors);
  const inner = C - 2;                     // content width after the 1-col gutter
  const rows = [];
  const rule = " " + t.gray("─".repeat(Math.max(0, inner)));
  rows.push(rule);
  // Question — an accent dot on the first line, bold text, wrapped.
  const q = wrapPlain(ask && ask.question, Math.max(1, inner - 2));
  q.forEach((ln, i) => rows.push(" " + (i === 0 ? t.cyan("● ") : "  ") + t.bold(ln)));
  rows.push(" ");
  if (ask && ask.input) {
    // ---- free-text input: a single editable field with a block caret. ----
    const text = String(ask.text || "");
    const avail = Math.max(1, inner - 4);
    const shown = text.length > avail ? "…" + text.slice(-(avail - 1)) : text;
    rows.push(" " + t.cyan(" › ") + (shown ? shown : t.dim(ask.placeholder ? String(ask.placeholder) : "type your answer")) + t.cyan("█"));
    rows.push(" ");
    rows.push(" " + t.gray("type your answer · enter submit · esc skip"));
    rows.push(rule);
    return rows;
  }
  const opts = normOptions(ask && ask.options);
  const sel = clampSel(ask && ask.sel, opts.length);
  const multi = !!(ask && ask.multi);
  const picked = multi ? normPicked(ask && ask.picked, opts.length) : [];
  // Options — numbered; the current row gets a "›" marker and cyan/bold label.
  // In multi-select mode each row also carries a [x]/[ ] checkbox.
  opts.forEach((o, i) => {
    const on = i === sel;
    const num = (i + 1) + ".";
    const box = multi ? (picked.indexOf(i) >= 0 ? t.green("[x] ") : t.gray("[ ] ")) : "";
    const head = on ? t.cyan(" › ") : "   ";
    const body = on ? t.bold(t.cyan(num + " " + o.label)) : t.gray(num + " ") + o.label;
    rows.push(head + box + body + (o.hint ? "  " + t.dim(o.hint) : ""));
  });
  rows.push(" ");
  const hint = multi
    ? "space toggle · enter confirm · esc skip · " + picked.length + " picked"
    : "up/down move · 1-" + Math.max(1, opts.length) + " pick · enter confirm · esc skip";
  rows.push(" " + t.gray(hint));
  rows.push(rule);
  return rows;
}

// askKey(ask, key) -> {sel, done, cancelled?, value?, index?}
// Pure reducer over a raw terminal key sequence. Up/Down (and their bare-CSI
// forms) move with wraparound; a digit 1-9 picks that option immediately; Enter
// confirms the current selection; Esc / Ctrl+C cancel (the model is told the
// user skipped). Any other key is a no-op.
function askKey(ask, key) {
  // ---- free-text input mode ----
  if (ask && ask.input) {
    const text = String(ask.text || "");
    if (key === "\x1b" || key === "\x03") return { text, done: false, cancelled: true };
    if (key === "\r" || key === "\n") return { text, done: true, value: text };
    if (key === "\x7f" || key === "\b") return { text: text.slice(0, -1), done: false };
    if (key === "\x15") return { text: "", done: false };                 // Ctrl+U clears the field
    if (key.length === 1 && key.charCodeAt(0) >= 0x20 && key.charCodeAt(0) !== 0x7f) return { text: text + key, done: false };
    return { text, done: false };
  }
  const opts = normOptions(ask && ask.options);
  const n = opts.length;
  const sel = clampSel(ask && ask.sel, n);
  const multi = !!(ask && ask.multi);
  if (key === "\x1b" || key === "\x03") return multi ? { sel, picked: normPicked(ask && ask.picked, n), done: false, cancelled: true } : { sel, done: false, cancelled: true };
  if (n === 0) return { sel, done: false };
  if (key === "\x1b[A" || key === "[A" || key === "\x1bOA") return multi ? { sel: (sel - 1 + n) % n, picked: normPicked(ask && ask.picked, n), done: false } : { sel: (sel - 1 + n) % n, done: false };
  if (key === "\x1b[B" || key === "[B" || key === "\x1bOB") return multi ? { sel: (sel + 1) % n, picked: normPicked(ask && ask.picked, n), done: false } : { sel: (sel + 1) % n, done: false };
  if (multi) {
    // Space or a digit TOGGLES membership; Enter confirms the whole set.
    const toggle = (i) => { const cur = normPicked(ask && ask.picked, n); const at = cur.indexOf(i); if (at >= 0) cur.splice(at, 1); else cur.push(i); return normPicked(cur, n); };
    if (key === " ") return { sel, picked: toggle(sel), done: false };
    if (/^[1-9]$/.test(key)) { const i = +key - 1; return i < n ? { sel: i, picked: toggle(i), done: false } : { sel, picked: normPicked(ask && ask.picked, n), done: false }; }
    if (key === "\r" || key === "\n") { const idx = normPicked(ask && ask.picked, n); return { sel, picked: idx, done: true, indices: idx, values: idx.map((i) => opts[i]) }; }
    return { sel, picked: normPicked(ask && ask.picked, n), done: false };
  }
  if (key === "\r" || key === "\n") return { sel, done: true, value: opts[sel], index: sel };
  if (/^[1-9]$/.test(key)) { const i = +key - 1; return i < n ? { sel: i, done: true, value: opts[i], index: i } : { sel, done: false }; }
  return { sel, done: false };
}

module.exports = { renderAsk, askKey, normOptions, normPicked, wrapPlain };
