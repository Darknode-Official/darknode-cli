"use strict";
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
  const hard = (word) => { let r = word; while (r.length > w) { out.push(r.slice(0, w)); r = r.slice(w); } return r; };
  for (const word of s.split(" ")) {
    if (!line.length) line = word.length <= w ? word : hard(word);
    else if (line.length + 1 + word.length <= w) line += " " + word;
    else { out.push(line); line = word.length <= w ? word : hard(word); }
  }
  if (line.length) out.push(line);
  return out.length ? out : [""];
}

// Truncate a plain string to w columns with a trailing ellipsis.
function fit(s, w) { s = String(s == null ? "" : s); if (w < 0) w = 0; if (s.length <= w) return s; if (w <= 1) return s.slice(0, w); return s.slice(0, w - 1) + "…"; }

// renderAsk(ask, width, colors) -> string[] (each row ready to paint). The box
// is drawn full width with rounded corners and side walls; the key legend sits
// dimmed beneath it. Rows are padded to `width` visible columns using PLAIN
// text length (injected colors add no columns), so right walls stay aligned.
function renderAsk(ask, width, colors) {
  const C = Math.max(28, (width | 0) || 80);
  const t = theme(colors);
  const innerW = C - 4;                    // content width inside "│ " … " │"
  const out = [];
  const top = t.gray("╭" + "─".repeat(C - 2) + "╮");
  const bot = t.gray("╰" + "─".repeat(C - 2) + "╯");
  // A content row: measure with the PLAIN string, paint with the colored one.
  const line = (plain, colored) => { const pad = Math.max(0, innerW - plain.length); out.push(t.gray("│ ") + (colored == null ? plain : colored) + " ".repeat(pad) + t.gray(" │")); };
  const blank = () => line("", "");
  out.push(top);
  // Question — accent dot on the first wrapped line, bold throughout.
  const q = wrapPlain(ask && ask.question, Math.max(1, innerW - 2));
  q.forEach((ln, i) => line((i === 0 ? "● " : "  ") + ln, (i === 0 ? t.cyan("● ") : "  ") + t.bold(ln)));
  blank();

  if (ask && ask.input) {
    // ---- free-text field (either a pure input prompt, or the "type a different
    // answer" row expanded into an editable line). A block caret marks the end. ----
    const text = String(ask.text || "");
    const avail = Math.max(1, innerW - 3);
    const shown = text.length > avail ? "…" + text.slice(-(avail - 1)) : text;
    const ph = ask.placeholder ? String(ask.placeholder) : "type your answer";
    if (shown) line("› " + shown, t.cyan("› ") + shown + t.cyan("█"));
    else line("› " + ph, t.cyan("› ") + t.dim(ph) + t.cyan("█"));
    out.push(bot);
    out.push(" " + t.gray(fit("enter submit  ·  esc " + (ask.typed ? "cancel" : "skip"), C - 2)));
    return out;
  }

  const { opts, rows } = rowModel(ask);
  const sel = clampSel(ask && ask.sel, rows.length);
  const multi = !!(ask && ask.multi);
  const picked = multi ? normPicked(ask && ask.picked, opts.length) : [];
  rows.forEach((row, r) => {
    const on = r === sel;
    const cur = on ? "❯ " : "  ";
    const curC = on ? t.cyan("❯ ") : "  ";
    if (row.kind === "opt") {
      const o = opts[row.i];
      const num = (row.i + 1) + ".";
      const box = multi ? (picked.indexOf(row.i) >= 0 ? "◉ " : "○ ") : "";
      const boxC = multi ? (picked.indexOf(row.i) >= 0 ? t.green("◉ ") : t.gray("○ ")) : "";
      const label = fit(o.label, Math.max(4, innerW - 2 - box.length - num.length - 1 - (o.hint ? o.hint.length + 2 : 0)));
      const hintP = o.hint ? "  " + o.hint : "";
      const plain = cur + box + num + " " + label + hintP;
      const colored = curC + boxC + (on ? t.bold(t.cyan(num + " " + label)) : t.gray(num + " ") + label) + (o.hint ? "  " + t.dim(o.hint) : "");
      line(plain, colored);
    } else if (row.kind === "type") {
      const plain = cur + "✎ Type a different answer";
      const colored = curC + (on ? t.bold(t.cyan("✎ Type a different answer")) : t.gray("✎ Type a different answer"));
      line(plain, colored);
    } else { // submit
      const tag = multi ? "Submit" + (picked.length ? " (" + picked.length + " selected)" : "") : "Submit";
      const plain = cur + tag;
      const colored = curC + (on ? t.bold(t.cyan(tag)) : t.gray(tag));
      line(plain, colored);
    }
  });
  out.push(bot);
  const legend = multi
    ? "↑↓ move  ·  space toggle  ·  1-" + Math.max(1, opts.length) + " toggle  ·  enter select  ·  esc skip"
    : "↑↓ move  ·  1-" + Math.max(1, opts.length) + " pick  ·  enter select  ·  esc skip";
  out.push(" " + t.gray(fit(legend, C - 2)));
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
    if (key === "\x7f" || key === "\b") return { text: text.slice(0, -1), done: false };
    if (key === "\x15") return { text: "", done: false };                 // Ctrl+U clears the field
    if (key.length === 1 && key.charCodeAt(0) >= 0x20 && key.charCodeAt(0) !== 0x7f) return { text: text + key, done: false };
    return { text, done: false };
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
