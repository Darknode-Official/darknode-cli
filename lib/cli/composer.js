"use strict";

// Grapheme (user-visible character) boundaries, so the caret and Backspace treat
// 👍🏽, 🇫🇷, e+◌́ and ZWJ emoji as ONE character. Segments a small window around
// the caret (cheap on long drafts); falls back to surrogate pairs without Intl.
const _seg = (typeof Intl !== "undefined" && Intl.Segmenter) ? new Intl.Segmenter(undefined, { granularity: "grapheme" }) : null;
function prevGrapheme(t, i) {
  if (i <= 0) return 0;
  if (!_seg) { const cc = t.charCodeAt(i - 1); return (cc >= 0xDC00 && cc <= 0xDFFF && i >= 2) ? i - 2 : i - 1; }
  const from = Math.max(0, i - 64); let last = from;
  for (const g of _seg.segment(t.slice(from, i))) last = from + g.index;
  return last;
}
function nextGrapheme(t, i) {
  if (i >= t.length) return t.length;
  if (!_seg) { const cc = t.charCodeAt(i); return Math.min(t.length, i + ((cc >= 0xD800 && cc <= 0xDBFF) ? 2 : 1)); }
  for (const g of _seg.segment(t.slice(i, i + 64))) return i + g.segment.length;
  return t.length;
}
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
const { redactCommandSecrets } = require("../governance/security"); // redact token-shaped + inline-command credentials before on-disk history

const HISTORY_CAP = 1000;
const PASTE_LINES = 10;    // collapse a paste longer than this many lines…
const PASTE_CHARS = 1000;  // …or this many characters
const UNDO_CAP = 200;
const DOUBLE_MS = 600;     // Esc Esc window
const CTRLC_MS = 2000;     // "ctrl+c again to exit" window

// Bidirectional-override and zero-width/invisible code points. These are NOT
// stripped (they can be legitimate in RTL or multilingual text); their presence
// is surfaced as a paste warning because they are the Trojan Source (CVE-2021-42574)
// and hidden-character smuggling vectors.
const BIDI_RE = /[‪-‮⁦-⁩‎‏]/;
const ZEROWIDTH_RE = /[​-‍⁠﻿]/;
// C0 controls except TAB (\x09) and LF (\x0A), plus DEL (\x7F) and C1 (\x80-\x9F).
// CR is handled separately (normalized to LF) so it is not in this class.
const CTRL_RE = /[\x00-\x08\x0B\x0C\x0E-\x1F\x7F\x80-\x9F]/g;

// Pure: neutralize hostile control bytes in pasted / recalled / imported text
// before it reaches the terminal buffer. CR/CRLF normalize to LF; TAB and LF are
// preserved; every other C0/C1 control and DEL is removed. An embedded escape
// sequence can otherwise rewrite terminal state or spoof the displayed prompt.
function sanitizeControls(str) {
  return String(str == null ? "" : str).replace(/\r\n?/g, "\n").replace(CTRL_RE, "");
}

// Pure: inspect a raw paste and report what is risky about it, without mutating
// anything. Drives the one-line paste preflight notice the host shows.
function inspectPaste(str) {
  const s = String(str == null ? "" : str);
  const bytes = Buffer.byteLength(s, "utf8");
  const lines = s.split(/\r\n?|\n/).length;
  const controls = (s.match(CTRL_RE) || []).length;
  const hasBidi = BIDI_RE.test(s);
  const hasZeroWidth = ZEROWIDTH_RE.test(s);
  let nonText = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c === 9 || c === 10 || c === 13) continue;
    if (c < 32 || c === 127 || (c >= 128 && c <= 159)) nonText++;
  }
  const binaryRatio = s.length ? nonText / s.length : 0;
  const reasons = [];
  if (controls) reasons.push(controls + " control byte" + (controls > 1 ? "s" : "") + " removed");
  if (hasBidi) reasons.push("bidirectional-override characters (possible Trojan Source)");
  if (hasZeroWidth) reasons.push("zero-width / invisible characters");
  if (binaryRatio > 0.3) reasons.push("looks binary (" + Math.round(binaryRatio * 100) + "% non-text)");
  return { bytes, lines, controls, hasBidi, hasZeroWidth, binaryRatio, reasons, flagged: reasons.length > 0 };
}

// Common shell commands / builtins, compiled in (no runtime lookup). Used to
// recognise a multi-line paste that looks like a command block.
const SHELL_CMDS = new Set([
  "sh", "bash", "zsh", "ksh", "fish", "dash", "eval", "exec", "source", ".", "export", "set", "env",
  "sudo", "su", "doas", "curl", "wget", "fetch", "nc", "ncat", "socat", "ssh", "scp", "sftp", "rsync",
  "rm", "mv", "cp", "ln", "mkdir", "rmdir", "touch", "chmod", "chown", "chgrp", "dd", "mkfs", "mount", "umount",
  "cat", "echo", "printf", "tee", "sed", "awk", "grep", "cut", "sort", "head", "tail", "xargs", "find",
  "git", "svn", "hg", "docker", "podman", "kubectl", "helm", "terraform", "ansible", "vagrant",
  "apt", "apt-get", "yum", "dnf", "pacman", "apk", "brew", "snap", "pip", "pip3", "pipx", "npm", "npx",
  "node", "python", "python3", "ruby", "perl", "php", "go", "cargo", "rustc", "java", "javac", "make", "cmake",
  "systemctl", "service", "journalctl", "kill", "killall", "pkill", "nohup", "crontab", "at",
  "tar", "zip", "unzip", "gzip", "gunzip", "openssl", "gpg", "base64", "nmap", "hydra", "msfconsole", "iptables",
]);

// Pure: classify a paste as shell-command-like, returning the rule ids that
// fired. Deterministic, no AI. A multi-line paste that pipes/chains commands or
// has >=2 lines starting with a known command is "shellLike".
function classifyPaste(text) {
  const s = String(text == null ? "" : text);
  const lines = s.split("\n").map((l) => l.trim()).filter(Boolean);
  const multiLine = lines.length >= 2;
  const ruleIds = [];
  if (/(&&|\|\||;|\|)/.test(s)) ruleIds.push("shell-operator");
  let cmdLines = 0;
  for (const l of lines) {
    let tok = l.replace(/^\.\//, "").split(/\s+/)[0];              // leading ./ runs a script
    if (tok === "sudo" || tok === "doas") tok = l.split(/\s+/)[1] || tok; // look past sudo
    if (tok && SHELL_CMDS.has(tok)) cmdLines++;
  }
  if (cmdLines >= 2) ruleIds.push("command-token-lines");
  return { shellLike: multiLine && ruleIds.length > 0, ruleIds };
}

const MAX_SUBMIT_BYTES = 1048576;        // 1 MiB cap on a single submission (safety)
const DROPPED_TTL_MS = 24 * 3600 * 1000; // dropped-tail temp files expire after 24h

// Longest prefix of `str` whose UTF-8 length is <= n bytes, never splitting a
// multi-byte character.
function sliceBytesSafe(str, n) {
  const buf = Buffer.from(String(str == null ? "" : str), "utf8");
  if (buf.length <= n) return String(str == null ? "" : str);
  let end = Math.max(0, n);
  while (end > 0 && (buf[end] & 0xC0) === 0x80) end--; // back off a continuation byte
  return buf.slice(0, end).toString("utf8");
}

// Persist a dropped paste tail to an owner-only (0600) temp file; return its
// path, or "" on failure. tmpRoot is injectable for tests.
function saveDroppedTail(tail, opts) {
  opts = opts || {};
  try {
    const dir = fs.mkdtempSync(path.join(opts.tmpRoot || os.tmpdir(), "nexus-paste-"));
    const p = path.join(dir, "remainder.txt");
    fs.writeFileSync(p, String(tail == null ? "" : tail), { mode: 0o600 });
    try { fs.chmodSync(p, 0o600); } catch (_) {}
    return p;
  } catch (_) { return ""; }
}

// Remove dropped-tail temp dirs older than the TTL (injected clock). Startup chore.
function cleanupDroppedTails(opts, now) {
  opts = opts || {}; now = now || Date.now();
  try {
    const root = opts.tmpRoot || os.tmpdir();
    for (const name of fs.readdirSync(root)) {
      if (!/^nexus-paste-/.test(name)) continue;
      const full = path.join(root, name);
      try { if (now - fs.statSync(full).mtimeMs > DROPPED_TTL_MS) fs.rmSync(full, { recursive: true, force: true }); } catch (_) {}
    }
  } catch (_) {}
}

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
    this.maxBytes = opts.maxBytes || MAX_SUBMIT_BYTES; // per-submission byte cap (safety)
    this.pasteConfirm = opts.pasteConfirm || "auto";   // auto | always | never
    this._confirmArmed = false;                        // a shell-looking submit is held for a 2nd Enter
    // Optional vim modal editing (/vim). Starts in INSERT so typing is normal;
    // Esc enters NORMAL. _vimOp holds a pending operator (d/c); _vimReplace is r.
    this.vim = !!opts.vim;
    this.vimMode = "insert";
    this._vimOp = "";
    this._vimReplace = false;
  }

  // ---- snapshots / undo ----
  snapshot() {
    this.undoStack.push({ text: this.text, cursor: this.cursor });
    if (this.undoStack.length > UNDO_CAP) this.undoStack.shift();
    this._confirmArmed = false; // any edit disarms a held shell-paste confirm
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
    if (!ph) del = this.cursor - prevGrapheme(this.text, this.cursor); // a whole emoji / accented letter, not half of it
    this.snapshot();
    this.text = this.text.slice(0, this.cursor - del) + this.text.slice(this.cursor);
    this.cursor -= del;
  }
  deleteForward() {
    if (this.cursor >= this.text.length) return;
    // a collapsed-paste / image placeholder deletes as one unit (mirror of backspace)
    const after = this.text.slice(this.cursor);
    const ph = after.match(/^\[(?:Pasted text #\d+ \+\d+ lines|Image#\d+)\]/);
    let del = ph ? ph[0].length : 1;
    if (!ph) del = nextGrapheme(this.text, this.cursor) - this.cursor;
    this.snapshot();
    this.text = this.text.slice(0, this.cursor) + this.text.slice(this.cursor + del);
  }

  // ---- cursor movement (char, word, line) ----
  left() { this.cursor = prevGrapheme(this.text, this.cursor); }   // one user-visible character (👍🏽, é, 🇫🇷 …)
  right() { this.cursor = nextGrapheme(this.text, this.cursor); }
  home() { const nl = this.text.lastIndexOf("\n", this.cursor - 1); this.cursor = nl + 1; }            // start of current line
  end() { const nl = this.text.indexOf("\n", this.cursor); this.cursor = nl === -1 ? this.text.length : nl; } // end of current line
  wordLeft() { let i = this.cursor; while (i > 0 && /\s/.test(this.text[i - 1])) i--; while (i > 0 && !/\s/.test(this.text[i - 1])) i--; this.cursor = i; }
  wordRight() { let i = this.cursor; while (i < this.text.length && /\s/.test(this.text[i])) i++; while (i < this.text.length && !/\s/.test(this.text[i])) i++; this.cursor = i; }
  endWord() { let i = this.cursor; if (i < this.text.length) i++; while (i < this.text.length && /\s/.test(this.text[i])) i++; while (i < this.text.length && !/\s/.test(this.text[i])) i++; this.cursor = i; } // just past the end of the current/next word (vim `e`, operator-friendly)

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
  // Control bytes are neutralized before anything is inserted or stored, and a
  // preflight report of the ORIGINAL paste is returned for the host to surface.
  paste(str) {
    const report = inspectPaste(str);
    let clean = sanitizeControls(str);
    // Size cap: never let one paste push the buffer past maxBytes. Keep the head,
    // report the dropped tail so the host can save it transparently (no silent loss).
    const room = this.maxBytes - Buffer.byteLength(this.text, "utf8");
    if (Buffer.byteLength(clean, "utf8") > room) {
      const head = room > 0 ? sliceBytesSafe(clean, room) : "";
      const tail = clean.slice(head.length);
      report.truncated = true;
      report.droppedBytes = Buffer.byteLength(tail, "utf8");
      report.droppedTail = tail;
      report.reasons.push("capped at " + this.maxBytes + " bytes; " + report.droppedBytes + " dropped");
      report.flagged = true;
      clean = head;
    }
    const nlines = clean.split("\n").length;
    if (clean.length > PASTE_CHARS || nlines > PASTE_LINES) {
      this.pastes.push(clean);
      this.insert("[Pasted text #" + this.pastes.length + " +" + nlines + " lines]");
      return { collapsed: true, lines: nlines, chars: clean.length, n: this.pastes.length, report };
    }
    this.insert(clean);
    return { collapsed: false, report };
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
    this.text = ""; this.cursor = 0; this.histIndex = this.history.length; this.draft = ""; this.pastes = []; this.undoStack = []; this._confirmArmed = false;
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
    case "\x1f": case "\x1b_": case "\x1a": return "undo";    // Ctrl+_ / Ctrl+Z
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
// vim NORMAL-mode dispatch (opt-in via /vim). Pure: mutates the model and
// returns an effect, or null when the key is not a vim key and feed() should
// handle it (Ctrl+C/D/L/G). A practical subset: motions h l j k 0 ^ $ w b e G,
// edits x D C s r p P u, operators d/c with a motion (dw, cw, d$, dd, cc…), and
// mode switches i a I A o O. Enter submits; any other printable is swallowed so
// stray keys never land in the buffer.
// ---------------------------------------------------------------------------
function vimWordStart(m) { let i = m.cursor; while (i < m.text.length && !/\s/.test(m.text[i])) i++; while (i < m.text.length && /\s/.test(m.text[i])) i++; return i; } // vim `w`: start of the next word (skips trailing whitespace)
function vimOperate(m, op, seq) {
  if ((op === "d" && seq === "d") || (op === "c" && seq === "c")) { // line-wise dd / cc
    const bol = m.text.lastIndexOf("\n", m.cursor - 1) + 1;
    const eol = m.text.indexOf("\n", m.cursor);
    m.snapshot();
    if (op === "d") {
      if (eol === -1) { m.kill = m.text.slice(bol); m.text = m.text.slice(0, bol > 0 ? bol - 1 : 0); m.cursor = Math.min(m.cursor, m.text.length); }
      else { m.kill = m.text.slice(bol, eol + 1); m.text = m.text.slice(0, bol) + m.text.slice(eol + 1); m.cursor = bol; }
    } else { const stop = eol === -1 ? m.text.length : eol; m.kill = m.text.slice(bol, stop); m.text = m.text.slice(0, bol) + m.text.slice(stop); m.cursor = bol; m.vimMode = "insert"; }
    return { type: "render" };
  }
  // vim's famous special case: `dw` deletes the trailing whitespace (to the next
  // word start) but `cw` acts like `ce` (to the end of the word, no trailing ws).
  let target;
  const start = m.cursor;
  if (seq === "w") { target = op === "c" ? (m.endWord(), m.cursor) : vimWordStart(m); }
  else { const mv = { b: "wordLeft", e: "endWord", $: "end", "0": "home", h: "left", l: "right" }[seq]; if (!mv) return { type: "none" }; m[mv](); target = m.cursor; }
  m.cursor = start;
  const lo = Math.min(start, target), hi = Math.max(start, target);
  if (hi > lo) { m.snapshot(); m.kill = m.text.slice(lo, hi); m.text = m.text.slice(0, lo) + m.text.slice(hi); m.cursor = lo; }
  if (op === "c") m.vimMode = "insert";
  return { type: "render" };
}
function vimNormal(m, seq) {
  if (seq === "\x03" || seq === "\x04" || seq === "\x0c" || seq === "\x07") return null; // let feed handle ctrl-c/d/l/g
  if (m._vimReplace) { m._vimReplace = false; if (seq.length === 1 && seq >= " " && m.cursor < m.text.length && m.text[m.cursor] !== "\n") { m.snapshot(); m.text = m.text.slice(0, m.cursor) + seq + m.text.slice(m.cursor + 1); } return { type: "render" }; }
  if (m._vimOp) { const op = m._vimOp; m._vimOp = ""; return vimOperate(m, op, seq); }
  switch (seq) {
    case "\r": case "\n": m._confirmArmed = false; return { type: "submit", text: m.expand(m.text) };
    case "h": m.left(); return { type: "render" };
    case "l": m.right(); return { type: "render" };
    case "j": m.moveDown(); return { type: "render" };
    case "k": m.moveUp(); return { type: "render" };
    case "0": case "^": m.home(); return { type: "render" };
    case "$": m.end(); if (m.cursor > 0 && m.text[m.cursor - 1] !== "\n") m.left(); return { type: "render" }; // vim: on the last char, not past it (so `$x` deletes it)
    case "w": m.cursor = vimWordStart(m); return { type: "render" };
    case "b": m.wordLeft(); return { type: "render" };
    case "e": m.endWord(); return { type: "render" };
    case "G": m.cursor = m.text.length; return { type: "render" };
    case "x": if (m.cursor < m.text.length && m.text[m.cursor] !== "\n") { m.snapshot(); m.kill = m.text[m.cursor]; m.text = m.text.slice(0, m.cursor) + m.text.slice(m.cursor + 1); } return { type: "render" };
    case "D": m.killToEnd(); return { type: "render" };
    case "C": m.killToEnd(); m.vimMode = "insert"; return { type: "render" };
    case "s": if (m.cursor < m.text.length && m.text[m.cursor] !== "\n") { m.snapshot(); m.kill = m.text[m.cursor]; m.text = m.text.slice(0, m.cursor) + m.text.slice(m.cursor + 1); } m.vimMode = "insert"; return { type: "render" };
    case "p": if (m.kill) { const at = Math.min(m.text.length, m.cursor + 1); m.snapshot(); m.text = m.text.slice(0, at) + m.kill + m.text.slice(at); m.cursor = at + Math.max(0, m.kill.length - 1); } return { type: "render" };
    case "P": if (m.kill) { m.snapshot(); m.text = m.text.slice(0, m.cursor) + m.kill + m.text.slice(m.cursor); m.cursor += Math.max(0, m.kill.length - 1); } return { type: "render" };
    case "u": return m.undo() ? { type: "render" } : { type: "none" };
    case "i": m.vimMode = "insert"; return { type: "render" };
    case "a": m.right(); m.vimMode = "insert"; return { type: "render" };
    case "I": m.home(); m.vimMode = "insert"; return { type: "render" };
    case "A": m.end(); m.vimMode = "insert"; return { type: "render" };
    case "o": m.end(); m.snapshot(); m.insert("\n"); m.vimMode = "insert"; return { type: "render" };
    case "O": { m.home(); m.snapshot(); const bol = m.cursor; m.text = m.text.slice(0, bol) + "\n" + m.text.slice(bol); m.cursor = bol; m.vimMode = "insert"; return { type: "render" }; }
    case "r": m._vimReplace = true; return { type: "none" };
    case "d": m._vimOp = "d"; return { type: "none" };
    case "c": m._vimOp = "c"; return { type: "none" };
    default: break;
  }
  const a = keymap(seq);
  if (a === "left") { m.left(); return { type: "render" }; }
  if (a === "right") { m.right(); return { type: "render" }; }
  if (a === "up") { m.moveUp(); return { type: "render" }; }
  if (a === "down") { m.moveDown(); return { type: "render" }; }
  if (a === "backspace") { m.left(); return { type: "render" }; } // vim: backspace moves left in normal mode
  if (seq.length === 1 && seq >= " ") return { type: "none" };    // swallow unknown printable
  return { type: "none" };
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

  // ---- vim modal editing (opt-in via /vim) ----
  if (model.vim) {
    if (model.vimMode === "insert") {
      if (action === "esc") { model.vimMode = "normal"; model._vimOp = ""; model._vimReplace = false; if (model.cursor > 0 && model.text[model.cursor - 1] !== "\n") model.left(); return { type: "render" }; }
      // every other key edits normally (fall through to the insert handling below)
    } else if (seq.length > 1 && !/[\x00-\x1f\x7f]/.test(seq)) { // keys that arrived coalesced in one chunk (fast typing, a busy event loop): run them one at a time
      const ks = [...seq]; let eff = { type: "none" };
      for (let k = 0; k < ks.length; k++) { if (model.vimMode === "insert") { model.insert(ks.slice(k).join("")); return { type: "render" }; } const r = vimNormal(model, ks[k]); if (r && r.type !== "none") eff = r; }
      return eff;
    } else {
      const ve = vimNormal(model, seq);
      if (ve) { if (ve.type === "submit") { model._lastCtrlC = 0; model._lastEsc = 0; } return ve; } // null → ctrl-c/d/l/g fall through
    }
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
      if (model.text.trim()) model.history.push(model.expand(model.text));
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
    case "enter": {
      if (model.text.endsWith("\\")) { model.snapshot(); model.text = model.text.slice(0, -1) + "\n"; model.cursor = model.text.length; return { type: "newline" }; }
      // Safe-submit speed bump: a shell-looking multi-line buffer (or pasteConfirm
      // 'always') is held for a second Enter so a command block is not sent unseen.
      const body = model.text;
      const needConfirm = !!body.trim() && !model._confirmArmed && (
        model.pasteConfirm === "always" ||
        (model.pasteConfirm !== "never" && classifyPaste(body).shellLike)
      );
      if (needConfirm) { model._confirmArmed = true; return { type: "confirm-submit", ruleIds: classifyPaste(body).ruleIds, text: model.expand(body) }; }
      model._confirmArmed = false;
      return { type: "submit", text: model.expand(body) };
    }
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
  // Guard against control bytes masquerading as text: `seq >= " "` is a string
  // compare that passes DEL (0x7f) and other C0/C1 controls, so an unhandled
  // backspace/report byte would otherwise be INSERTED into the buffer. Require a
  // real printable leading char (space or above, and not DEL).
  if (seq.length && seq.charCodeAt(0) >= 0x20 && seq.charCodeAt(0) !== 0x7f) {
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
    const lines = fs.readFileSync(p, "utf8").trim().split("\n").filter(Boolean);
    const out = lines.map((l) => {
      try { return JSON.parse(l).text; } catch (_) { return l; }
    }).filter((x) => x != null).map((x) => sanitizeControls(x)); // neutralize controls in recalled text
    // drop consecutive duplicates, then cap
    const dedup = [];
    for (const x of out) if (dedup[dedup.length - 1] !== x) dedup.push(x);
    const capped = dedup.slice(-limit);
    // Compact an oversized file (> 2x cap lines) back to the cap on a full load,
    // so the history never grows without bound. Only on a full read, never on the
    // single-line dedup probe appendHistory makes.
    if (limit >= HISTORY_CAP && lines.length > HISTORY_CAP * 2) {
      try {
        const keep = dedup.slice(-HISTORY_CAP).map((t) => JSON.stringify({ text: t })).join("\n") + "\n";
        const tmp = p + ".tmp-" + process.pid;
        fs.writeFileSync(tmp, keep, { mode: 0o600 });
        fs.renameSync(tmp, p);
      } catch (_) {}
    }
    return capped;
  } catch (_) { return []; }
}
function appendHistory(entry, projectDir, home) {
  try {
    if (!entry || !String(entry).trim()) return;
    // Harden the on-disk copy: strip control bytes, and mask any high-confidence
    // credential so a mistaken paste does not become a durable local leak. The
    // host keeps the real text in its in-memory history array for this session.
    let text = sanitizeControls(entry);
    // Mask token-shaped secrets AND inline command credentials (-pPASS, -u user:pass,
    // --token=…, Authorization headers, URL userinfo) so a pasted command does not
    // become a durable local leak. redactCommandSecrets runs maskSecrets internally.
    text = redactCommandSecrets(text);
    const p = historyPath(projectDir, home);
    fs.mkdirSync(path.dirname(p), { recursive: true, mode: 0o700 }); // owner-only dir
    // skip a write that would duplicate the last line
    try { const prev = loadHistory(projectDir, 1, home); if (prev[0] === text) return; } catch (_) {}
    fs.appendFileSync(p, JSON.stringify({ text, ts: Date.now() }) + "\n", { mode: 0o600 });
    try { fs.chmodSync(p, 0o600); } catch (_) {} // tighten a file that predates 0600 creation
  } catch (_) { /* best-effort */ }
}

module.exports = { prevGrapheme, nextGrapheme,
  ComposerModel, keymap, feed,
  historyPath, loadHistory, appendHistory,
  sanitizeControls, inspectPaste, classifyPaste, sliceBytesSafe, saveDroppedTail, cleanupDroppedTails,
  HISTORY_CAP, PASTE_LINES, PASTE_CHARS, DOUBLE_MS, CTRLC_MS, MAX_SUBMIT_BYTES,
};
