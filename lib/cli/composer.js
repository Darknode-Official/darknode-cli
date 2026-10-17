"use strict";
// ============================================================================
// The composer — a PURE line-editing state machine for the Nexus TUI input box.
//
// Adapted from the user's own sibling repo nexus/src/ui/composer.js (the
// ComposerModel there), extended with the editing conventions a terminal line
// editor is expected to have: readline/emacs-style word movement, kill-ring
// yank, an undo snapshot stack, draft-preserving history with multiline cursor
// movement, reverse-i-search, and bracketed-paste collapse/expand.
//
// Everything here is pure + snapshot-testable. The live key loop lives in the
// host (darknode.js); it owns the terminal and the slash/arg menus, syncs its
// `input`/`curPos` into a ComposerModel, calls `feed(model, seq, env)` for the
// editing keys, and reads back the mutated buffer. `feed` returns an effect the
// host acts on (submit / interrupt / exit / newline / help / editor / redraw…).
//
// No leaked or proprietary source: built from standard readline/emacs terminal
// conventions and the user's own composer.js.
// ============================================================================

const fs = require("fs");
const os = require("os");
const path = require("path");
const crypto = require("crypto");

const HISTORY_CAP = 1000;
const PASTE_LINES = 10;    // collapse a paste longer than this many lines…
const PASTE_CHARS = 1000;  // …or this many characters
const UNDO_CAP = 200;
const DOUBLE_MS = 600;     // Esc Esc window
const CTRLC_MS = 2000;     // "ctrl+c again to exit" window

// ---------------------------------------------------------------------------
// Editing model — pure state. The host maps raw keys to these methods (or lets
// feed() do it). text may contain "\n"; cursor is an index into text.
// ---------------------------------------------------------------------------
class ComposerModel {
  constructor(opts = {}) {
    this.text = opts.text || "";
    this.cursor = this.text.length;
    this.history = (opts.history || []).slice();
    this.histIndex = this.history.length; // == length means "the live draft"
    this.draft = "";
    this.kill = "";            // kill-ring (one slot), fed by Ctrl+K/U/W
    this.undoStack = [];       // snapshots {text,cursor} for Ctrl+_
    this.pastes = [];          // real text of collapsed large pastes
    this.searchMode = false;
    this.searchQuery = "";
    this.searchIndex = -1;     // position in history being matched
    this.searchSaved = null;   // {text,cursor} to restore on cancel
    // transient key-timing state (Ctrl+C / Esc-Esc machines live in feed)
    this._lastCtrlC = -Infinity; // so the very first Ctrl+C/Esc is never read as a repeat
    this._lastEsc = -Infinity;
  }

  // ---- snapshots / undo ----
  snapshot() {
    this.undoStack.push({ text: this.text, cursor: this.cursor });
    if (this.undoStack.length > UNDO_CAP) this.undoStack.shift();
  }
  undo() {
    const s = this.undoStack.pop();
    if (!s) return false;
    this.text = s.text; this.cursor = Math.min(s.cursor, s.text.length);
    return true;
  }

  // ---- basic edits (each records an undo snapshot) ----
  insert(str) {
    this.snapshot();
    this.text = this.text.slice(0, this.cursor) + str + this.text.slice(this.cursor);
    this.cursor += str.length;
  }
  newline() { this.insert("\n"); }
  backspace() {
    if (this.cursor <= 0) return;
    // a collapsed-paste / image placeholder deletes as one unit
    const before = this.text.slice(0, this.cursor);
    const ph = before.match(/\[(?:Pasted text #\d+ \+\d+ lines|Image#\d+)\]$/);
    let del = ph ? ph[0].length : 1;
    if (!ph && this.cursor >= 2) { const cc = this.text.charCodeAt(this.cursor - 1); if (cc >= 0xDC00 && cc <= 0xDFFF) del = 2; }
    this.snapshot();
    this.text = this.text.slice(0, this.cursor - del) + this.text.slice(this.cursor);
    this.cursor -= del;
  }
  deleteForward() {
    if (this.cursor >= this.text.length) return;
    let del = 1; const cc = this.text.charCodeAt(this.cursor); if (cc >= 0xD800 && cc <= 0xDBFF) del = 2;
    this.snapshot();
    this.text = this.text.slice(0, this.cursor) + this.text.slice(this.cursor + del);
  }

  // ---- cursor movement (char, word, line) ----
  left() { if (this.cursor > 0) { this.cursor--; const cc = this.text.charCodeAt(this.cursor); if (cc >= 0xDC00 && cc <= 0xDFFF && this.cursor > 0) this.cursor--; } }
  right() { if (this.cursor < this.text.length) { const cc = this.text.charCodeAt(this.cursor); this.cursor += (cc >= 0xD800 && cc <= 0xDBFF) ? 2 : 1; if (this.cursor > this.text.length) this.cursor = this.text.length; } }
  home() { const nl = this.text.lastIndexOf("\n", this.cursor - 1); this.cursor = nl + 1; }            // start of current line
  end() { const nl = this.text.indexOf("\n", this.cursor); this.cursor = nl === -1 ? this.text.length : nl; } // end of current line
  wordLeft() { let i = this.cursor; while (i > 0 && /\s/.test(this.text[i - 1])) i--; while (i > 0 && !/\s/.test(this.text[i - 1])) i--; this.cursor = i; }
  wordRight() { let i = this.cursor; while (i < this.text.length && /\s/.test(this.text[i])) i++; while (i < this.text.length && !/\s/.test(this.text[i])) i++; this.cursor = i; }

  // ---- kill-ring ----
  deleteWordLeft() { const end = this.cursor; this.wordLeft(); if (this.cursor === end) return; this.kill = this.text.slice(this.cursor, end); this.snapshot(); this.text = this.text.slice(0, this.cursor) + this.text.slice(end); }
  killToEnd() { const eol = this.text.indexOf("\n", this.cursor); const stop = eol === -1 ? this.text.length : eol; if (stop === this.cursor) return; this.kill = this.text.slice(this.cursor, stop); this.snapshot(); this.text = this.text.slice(0, this.cursor) + this.text.slice(stop); }
  killToStart() { const bol = this.text.lastIndexOf("\n", this.cursor - 1) + 1; if (bol === this.cursor) return; this.kill = this.text.slice(bol, this.cursor); this.snapshot(); this.text = this.text.slice(0, bol) + this.text.slice(this.cursor); this.cursor = bol; }
  killWordBack() { const end = this.cursor; if (end === 0) return; const before = this.text.slice(0, end); const wm = before.match(/(?:\S+\s*|\s+)$/); const del = wm ? wm[0].length : 1; this.kill = this.text.slice(end - del, end); this.snapshot(); this.text = this.text.slice(0, end - del) + this.text.slice(end); this.cursor = end - del; }
  yank() { if (this.kill) this.insert(this.kill); }

  // ---- multiline-aware vertical movement ----
  // Returns true if the cursor moved WITHIN the buffer; false when already on
  // the top/bottom line (the host then steps through history instead).
  lineInfo() {
    const bol = this.text.lastIndexOf("\n", this.cursor - 1) + 1;
    const eol = this.text.indexOf("\n", this.cursor);
    return { bol, eol: eol === -1 ? this.text.length : eol, col: this.cursor - bol, isFirst: bol === 0, isLast: eol === -1 };
  }
  moveUp() {
    const li = this.lineInfo();
    if (li.isFirst) return false;
    const prevEol = li.bol - 1;
    const prevBol = this.text.lastIndexOf("\n", prevEol - 1) + 1;
    this.cursor = prevBol + Math.min(li.col, prevEol - prevBol);
    return true;
  }
  moveDown() {
    const li = this.lineInfo();
    if (li.isLast) return false;
    const nextBol = li.eol + 1;
    const nextEol = this.text.indexOf("\n", nextBol);
    const stop = nextEol === -1 ? this.text.length : nextEol;
    this.cursor = nextBol + Math.min(li.col, stop - nextBol);
    return true;
  }

  // ---- draft-preserving history (the regression this module fixes) ----
  historyPrev() {
    if (!this.history.length) return;
    if (this.histIndex === this.history.length) this.draft = this.text; // save the live draft on first Up
    if (this.histIndex > 0) this.histIndex--;
    this.text = this.history[this.histIndex] || "";
    this.cursor = this.text.length;
  }
  historyNext() {
    if (this.histIndex >= this.history.length) return;
    this.histIndex++;
    this.text = this.histIndex === this.history.length ? this.draft : (this.history[this.histIndex] || "");
    this.cursor = this.text.length;
  }

  // ---- reverse-i-search ----
  startSearch() {
    if (this.searchMode) { this.searchOlder(); return; }
    this.searchMode = true; this.searchQuery = ""; this.searchIndex = this.history.length;
    this.searchSaved = { text: this.text, cursor: this.cursor };
  }
  _searchFrom(startIdx) {
    for (let i = startIdx; i >= 0; i--) {
      if (this.history[i] != null && this.history[i].includes(this.searchQuery)) { this.searchIndex = i; this.text = this.history[i]; this.cursor = this.text.length; return true; }
    }
    return false;
  }
  updateSearch(q) { this.searchQuery = q; this._searchFrom(this.history.length - 1); }
  searchOlder() { if (!this.searchMode) return; this._searchFrom(this.searchIndex - 1); }    // Ctrl+R again = older match
  searchBackspace() { if (this.searchQuery) { this.searchQuery = this.searchQuery.slice(0, -1); this._searchFrom(this.history.length - 1); } }
  searchType(ch) { this.searchQuery += ch; this._searchFrom(this.history.length - 1); }
  acceptSearch() { this.searchMode = false; this.searchQuery = ""; this.searchSaved = null; this.histIndex = this.history.length; this.cursor = this.text.length; }
  cancelSearch() { if (this.searchSaved) { this.text = this.searchSaved.text; this.cursor = this.searchSaved.cursor; } this.searchMode = false; this.searchQuery = ""; this.searchSaved = null; }

  // ---- bracketed paste: newlines kept; a large paste collapses to a marker ----
  paste(str) {
    const nlines = str.split("\n").length;
    if (str.length > PASTE_CHARS || nlines > PASTE_LINES) {
      this.pastes.push(str);
      this.insert("[Pasted text #" + this.pastes.length + " +" + nlines + " lines]");
      return { collapsed: true, lines: nlines, chars: str.length, n: this.pastes.length };
    }
    this.insert(str);
    return { collapsed: false };
  }
  // Expand collapsed-paste markers back to their real text (called on submit).
  expand(text) {
    const self = this;
    return (text == null ? this.text : text).replace(/\[Pasted text #(\d+) \+\d+ lines\]/g, (m, n) => {
      const real = self.pastes[(+n) - 1];
      return real == null ? m : real;
    });
  }

  clear() { this.snapshot(); this.text = ""; this.cursor = 0; this.histIndex = this.history.length; this.draft = ""; }

  // Finalize a submission: push onto history (dropping a consecutive dupe),
  // reset the buffer, and return the EXPANDED text to send.
  submit() {
    const value = this.expand(this.text);
    const v = value.trim();
    if (v && this.history[this.history.length - 1] !== value) this.history.push(value);
    if (this.history.length > HISTORY_CAP) this.history = this.history.slice(-HISTORY_CAP);
    this.text = ""; this.cursor = 0; this.histIndex = this.history.length; this.draft = ""; this.pastes = []; this.undoStack = [];
    return value;
  }
}

// ---------------------------------------------------------------------------
// keymap — classify a raw stdin chunk into a canonical editing action name.
// Pure and exhaustive for the EDITING path (the host handles menus, mouse,
// bracketed-paste framing and the busy-turn buffer before calling this). This
// is the single source of truth for "which key does what", so it is the thing
// tests assert against.
// ---------------------------------------------------------------------------
function keymap(seq) {
  switch (seq) {
    case "\x1b\r": case "\x1b\n": return "newline";          // Alt+Enter
    case "\n": return "newline";                              // Ctrl+J (lone LF, not paste)
    case "\x1b[27;2;13~": case "\x1b[13;2u": return "newline"; // Shift+Enter (modifyOtherKeys / CSI-u)
    case "\r": return "enter";
    case "\x7f": case "\b": return "backspace";
    case "\x1b\x7f": case "\x1b\b": return "delete-word-back"; // Alt+Backspace
    case "\x17": return "kill-word-back";                     // Ctrl+W
    case "\x15": return "kill-to-start";                      // Ctrl+U
    case "\x0b": return "kill-to-end";                        // Ctrl+K
    case "\x19": return "yank";                               // Ctrl+Y
    case "\x01": return "home";                               // Ctrl+A
    case "\x05": return "end";                                // Ctrl+E
    case "\x1f": case "\x1b_": return "undo";                 // Ctrl+_
    case "\x12": return "search";                             // Ctrl+R
    case "\x0c": return "redraw";                             // Ctrl+L
    case "\x07": return "editor";                             // Ctrl+G
    case "\x03": return "ctrl-c";
    case "\x04": return "ctrl-d";
    case "\x1b": return "esc";                                // LONE esc only (host guarantees)
    case "\x1b[1;5D": case "\x1bb": case "\x1bB": return "word-left";  // Ctrl+Left / Alt+B
    case "\x1b[1;5C": case "\x1bf": case "\x1bF": return "word-right"; // Ctrl+Right / Alt+F
    case "\x1b[A": case "[A": return "up";
    case "\x1b[B": case "[B": return "down";
    case "\x1b[C": case "[C": return "right";
    case "\x1b[D": case "[D": return "left";
    case "\x1b[3~": case "[3~": return "delete-forward";
    case "\x1b[H": case "\x1b[1~": case "\x1bOH": case "[H": return "home-key";
    case "\x1b[F": case "\x1b[4~": case "\x1bOF": case "[F": return "end-key";
    default: return null; // printable / unknown → inserted by the host
  }
}

// ---------------------------------------------------------------------------
// feed — apply one raw key chunk to the model and return an effect for the
// host. env: { busy, empty }. now: injectable clock (tests). Effects:
//   {type:"submit", text}         user pressed Enter on a non-backslash line
//   {type:"newline"}              a newline was inserted
//   {type:"interrupt"}            Esc / Ctrl+C while a turn runs
//   {type:"exit"}                 quit (Ctrl+D empty, or 2nd Ctrl+C)
//   {type:"exit-confirm"}         1st Ctrl+C on empty idle buffer (host prompts)
//   {type:"help"}                 '?' on an empty buffer
//   {type:"editor"}               Ctrl+G external editor
//   {type:"redraw"}               Ctrl+L full repaint
//   {type:"home-scroll"/"end-scroll"}  Home/End on empty buffer (host scrolls)
//   {type:"history-up"/"history-down"} vertical move fell off the buffer edge
//   {type:"render"}               buffer changed; just repaint
//   {type:"none"}                 nothing happened / not handled here
// ---------------------------------------------------------------------------
function feed(model, seq, env, now) {
  env = env || {}; now = now || Date.now();

  // ---- reverse-i-search owns the keyboard while active ----
  if (model.searchMode) {
    if (seq === "\x12") { model.searchOlder(); return { type: "render" }; }
    if (seq === "\r" || seq === "\n") { model.acceptSearch(); return { type: "render" }; }
    if (seq === "\x1b" || seq === "\x07" || seq === "\x03") { model.cancelSearch(); return { type: "render" }; }
    if (seq === "\x7f" || seq === "\b") { model.searchBackspace(); return { type: "render" }; }
    if (seq.length === 1 && seq >= " ") { model.searchType(seq); return { type: "render" }; }
    // any other control key: accept the match, then let the key fall through
    model.acceptSearch();
  }

  const action = keymap(seq);

  // While a turn runs, the model does not edit: only a LONE Esc or Ctrl+C
  // interrupts (every other escape sequence — arrows, etc. — is ignored here;
  // the host buffers/queues real typing). This is the Esc-vs-sequence guard.
  if (env.busy) {
    if (action === "ctrl-c" || action === "esc") { model._lastCtrlC = -Infinity; model._lastEsc = -Infinity; return { type: "interrupt" }; }
    return { type: "none" };
  }

  // ---- Ctrl+C state machine ----
  if (action === "ctrl-c") {
    if (env.busy) { model._lastCtrlC = 0; return { type: "interrupt" }; }
    if (model.text.length) { model.clear(); model._lastCtrlC = 0; return { type: "render" }; }
    if (now - model._lastCtrlC < CTRLC_MS) return { type: "exit" };
    model._lastCtrlC = now; return { type: "exit-confirm" };
  }
  model._lastCtrlC = 0; // any other key resets the "again to exit" window

  // ---- Esc (lone) ----
  if (action === "esc") {
    if (env.busy) return { type: "interrupt" };
    if (now - model._lastEsc < DOUBLE_MS) { // Esc Esc on idle = clear (buffer saved to history first)
      model._lastEsc = 0;
      if (model.text.trim()) model.history.push(model.text);
      model.clear();
      return { type: "render" };
    }
    model._lastEsc = now; return { type: "none" };
  }
  model._lastEsc = 0;

  // ---- Ctrl+D ----
  if (action === "ctrl-d") {
    if (!model.text.length) return { type: "exit" };
    model.deleteForward(); return { type: "render" };
  }

  switch (action) {
    case "newline": model.newline(); return { type: "newline" };
    case "enter":
      if (model.text.endsWith("\\")) { model.snapshot(); model.text = model.text.slice(0, -1) + "\n"; model.cursor = model.text.length; return { type: "newline" }; }
      return { type: "submit", text: model.expand(model.text) };
    case "backspace": model.backspace(); return { type: "render" };
    case "delete-forward": model.deleteForward(); return { type: "render" };
    case "delete-word-back": model.deleteWordLeft(); return { type: "render" };
    case "kill-word-back": model.killWordBack(); return { type: "render" };
    case "kill-to-start": model.killToStart(); return { type: "render" };
    case "kill-to-end": model.killToEnd(); return { type: "render" };
    case "yank": model.yank(); return { type: "render" };
    case "home": model.home(); return { type: "render" };
    case "end": model.end(); return { type: "render" };
    case "left": model.left(); return { type: "render" };
    case "right": model.right(); return { type: "render" };
    case "word-left": model.wordLeft(); return { type: "render" };
    case "word-right": model.wordRight(); return { type: "render" };
    case "undo": return model.undo() ? { type: "render" } : { type: "none" };
    case "search": model.startSearch(); return { type: "render" };
    case "redraw": return { type: "redraw" };
    case "editor": return { type: "editor" };
    case "up": return model.moveUp() ? { type: "render" } : { type: "history-up" };
    case "down": return model.moveDown() ? { type: "render" } : { type: "history-down" };
    case "home-key": if (!model.text.length) return { type: "home-scroll" }; model.home(); return { type: "render" };
    case "end-key": if (!model.text.length) return { type: "end-scroll" }; model.end(); return { type: "render" };
    default: break;
  }

  // ---- printable ----
  if (seq.length && seq >= " " && seq.charCodeAt(0) !== 27) {
    if (seq === "?" && !model.text.length) return { type: "help" }; // '?' on empty = keys help
    model.insert(seq); return { type: "render" };
  }
  return { type: "none" };
}

// ---------------------------------------------------------------------------
// Persistent history, scoped per project (mirrors nexus/src/ui/composer.js:
// ~/.nexus/history/<sha1(cwd)>.jsonl). Best-effort; never throws.
// ---------------------------------------------------------------------------
function historyPath(projectDir, home) {
  const h = home || os.homedir();
  const hash = crypto.createHash("sha1").update(path.resolve(projectDir || ".")).digest("hex").slice(0, 16);
  return path.join(h, ".nexus", "history", hash + ".jsonl");
}
function loadHistory(projectDir, limit, home) {
  limit = limit || HISTORY_CAP;
  try {
    const p = historyPath(projectDir, home);
    if (!fs.existsSync(p)) return [];
    const out = fs.readFileSync(p, "utf8").trim().split("\n").filter(Boolean).map((l) => {
      try { return JSON.parse(l).text; } catch (_) { return l; }
    }).filter((x) => x != null);
    // drop consecutive duplicates, then cap
    const dedup = [];
    for (const x of out) if (dedup[dedup.length - 1] !== x) dedup.push(x);
    return dedup.slice(-limit);
  } catch (_) { return []; }
}
function appendHistory(entry, projectDir, home) {
  try {
    if (!entry || !String(entry).trim()) return;
    const p = historyPath(projectDir, home);
    fs.mkdirSync(path.dirname(p), { recursive: true });
    // skip a write that would duplicate the last line
    try { const prev = loadHistory(projectDir, 1, home); if (prev[0] === entry) return; } catch (_) {}
    fs.appendFileSync(p, JSON.stringify({ text: entry, ts: Date.now() }) + "\n");
  } catch (_) { /* best-effort */ }
}

module.exports = {
  ComposerModel, keymap, feed,
  historyPath, loadHistory, appendHistory,
  HISTORY_CAP, PASTE_LINES, PASTE_CHARS, DOUBLE_MS, CTRLC_MS,
};
