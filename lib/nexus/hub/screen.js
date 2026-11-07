"use strict";
// ============================================================================
// hub/screen — a small terminal screen model for background sessions.
//
// A background session's program (Nexus, Claude Code, Codex, a shell) draws with
// cursor moves and erases, so the raw output is not readable text. This model
// applies the common VT/xterm sequences to a cols x rows grid, so the hub can:
//   - show what a session looks like right now (`nexus peek`, the sessions tool),
//   - spot an agent waiting on a question (hub/status.js reads the bottom lines),
//   - repaint a client that attaches mid-session (alt screen + modes + text).
// It is not a full emulator: colors and attributes are dropped, every character is
// one cell wide. Pure, no I/O.
// ============================================================================

const SCROLLBACK = 400; // main-screen lines kept above the visible area

class Screen {
  constructor(cols, rows) {
    this.cols = Math.max(10, cols | 0 || 80);
    this.rows = Math.max(3, rows | 0 || 24);
    this.title = "";
    this.cursorHidden = false;
    this.modes = new Set(); // private modes currently set (?2004 bracketed paste, ?1000 mouse...)
    this._st = 0; this._buf = ""; // parser state: 0 text, 1 ESC, 2 CSI, 3 OSC, 4 ESC-in-OSC, 5 charset (ESC ( x)
    this._main = this._blank(); this._alt = null; this.scrollback = [];
    this.x = 0; this.y = 0; this._wrap = false; this._saved = { x: 0, y: 0 };
    this.top = 0; this.bot = this.rows - 1;
  }
  get alt() { return !!this._alt; }
  get lines() { return this._alt || this._main; }
  _blank() { const a = []; for (let i = 0; i < this.rows; i++) a.push(this._row()); return a; }
  _row() { return new Array(this.cols).fill(" "); }

  resize(cols, rows) {
    cols = Math.max(10, cols | 0); rows = Math.max(3, rows | 0);
    if (cols === this.cols && rows === this.rows) return;
    // Drop rows from the top only as far as needed to keep the cursor on screen (the
    // dropped main-screen rows go to scrollback); keep the rest from the top down.
    const fit = (grid, cut) => {
      let g = grid.map((r) => (r.length >= cols ? r.slice(0, cols) : r.concat(new Array(cols - r.length).fill(" "))));
      if (cut > 0 && grid === this._main) this.scrollback.push(...g.slice(0, cut).map((r) => r.join("").replace(/\s+$/, "")));
      g = g.slice(cut, cut + rows);
      while (g.length < rows) g.push(new Array(cols).fill(" "));
      return g;
    };
    const shift = Math.max(0, this.y - (rows - 1));
    this.cols = cols; this.rows = rows;
    this._main = fit(this._main, this._alt ? 0 : shift); if (this._alt) this._alt = fit(this._alt, shift);
    this._trimBack();
    this.y = Math.min(rows - 1, this.y - shift); this.x = Math.min(cols - 1, this.x);
    this.top = 0; this.bot = rows - 1; this._wrap = false;
  }
  _trimBack() { if (this.scrollback.length > SCROLLBACK) this.scrollback.splice(0, this.scrollback.length - SCROLLBACK); }

  // ---- output ----
  write(s) {
    s = String(s || "");
    for (let i = 0; i < s.length; i++) {
      const ch = s[i], c = s.charCodeAt(i);
      if (this._st === 0) {
        if (c === 0x1b) { this._st = 1; continue; }
        if (c < 0x20 || c === 0x7f) { this._ctl(c); continue; }
        // a surrogate pair is one character on screen
        if (c >= 0xd800 && c <= 0xdbff && i + 1 < s.length) { this._put(ch + s[++i]); continue; }
        this._put(ch);
      } else if (this._st === 1) {
        this._st = 0;
        if (ch === "[") { this._st = 2; this._buf = ""; }
        else if (ch === "]") { this._st = 3; this._buf = ""; }
        else if (ch === "(" || ch === ")" || ch === "*" || ch === "+" || ch === "#") this._st = 5;
        else if (ch === "7") this._saved = { x: this.x, y: this.y };
        else if (ch === "8") { this.x = this._saved.x; this.y = this._saved.y; this._wrap = false; }
        else if (ch === "D") this._lf();
        else if (ch === "E") { this.x = 0; this._lf(); }
        else if (ch === "M") this._ri();
        else if (ch === "c") this._reset();
        // anything else (=, >, \, P/X/^/_ strings are rare in agent TUIs) is ignored
      } else if (this._st === 2) {
        if (c >= 0x40 && c <= 0x7e) { this._csi(this._buf, ch); this._st = 0; }
        else if (this._buf.length < 64) this._buf += ch;
        else this._st = 0; // runaway sequence: drop it
      } else if (this._st === 3) {
        if (c === 0x07) { this._osc(this._buf); this._st = 0; }
        else if (c === 0x1b) this._st = 4;
        else if (this._buf.length < 512) this._buf += ch;
      } else if (this._st === 4) { this._osc(this._buf); this._st = ch === "\\" ? 0 : 1; if (this._st === 1) i--; }
      else if (this._st === 5) this._st = 0;
    }
  }
  _ctl(c) {
    if (c === 0x0a || c === 0x0b || c === 0x0c) this._lf();
    else if (c === 0x0d) { this.x = 0; this._wrap = false; }
    else if (c === 0x08) { if (this.x > 0) this.x--; this._wrap = false; }
    else if (c === 0x09) { this.x = Math.min(this.cols - 1, (Math.floor(this.x / 8) + 1) * 8); }
  }
  _put(ch) {
    if (this._wrap) { this.x = 0; this._lf(); this._wrap = false; }
    this.lines[this.y][this.x] = ch;
    if (this.x >= this.cols - 1) this._wrap = true; else this.x++;
  }
  _lf() {
    this._wrap = false;
    if (this.y === this.bot) this._scrollUp(1);
    else if (this.y < this.rows - 1) this.y++;
  }
  _ri() { if (this.y === this.top) this._scrollDown(1); else if (this.y > 0) this.y--; }
  _scrollUp(n) {
    const L = this.lines;
    for (let k = 0; k < n; k++) {
      const gone = L.splice(this.top, 1)[0];
      if (!this._alt && this.top === 0) { this.scrollback.push(gone.join("").replace(/\s+$/, "")); }
      L.splice(this.bot, 0, this._row());
    }
    this._trimBack();
  }
  _scrollDown(n) { const L = this.lines; for (let k = 0; k < n; k++) { L.splice(this.bot, 1); L.splice(this.top, 0, this._row()); } }
  _reset() { this._main = this._blank(); this._alt = null; this.x = this.y = 0; this.top = 0; this.bot = this.rows - 1; this.modes.clear(); this.cursorHidden = false; this._wrap = false; }

  _osc(body) {
    const m = /^(0|2);([\s\S]*)$/.exec(body);
    if (m) this.title = m[2].replace(/[\x00-\x1f]/g, "").slice(0, 200);
  }
  _csi(params, f) {
    const priv = params[0] === "?";
    const p = (priv ? params.slice(1) : params).replace(/[<=>!]/g, "").split(";").map((v) => (v === "" ? NaN : parseInt(v, 10)));
    const n = (i, d) => (Number.isFinite(p[i]) && p[i] > 0 ? p[i] : d);
    const R = this.rows, C = this.cols;
    this._wrap = f === "m" ? this._wrap : false;
    switch (f) {
      case "A": this.y = Math.max(this.y < this.top ? 0 : this.top, this.y - n(0, 1)); break;
      case "B": case "e": this.y = Math.min(this.y > this.bot ? R - 1 : this.bot, this.y + n(0, 1)); break;
      case "C": case "a": this.x = Math.min(C - 1, this.x + n(0, 1)); break;
      case "D": this.x = Math.max(0, this.x - n(0, 1)); break;
      case "E": this.x = 0; this.y = Math.min(R - 1, this.y + n(0, 1)); break;
      case "F": this.x = 0; this.y = Math.max(0, this.y - n(0, 1)); break;
      case "G": case "`": this.x = Math.min(C - 1, n(0, 1) - 1); break;
      case "d": this.y = Math.min(R - 1, n(0, 1) - 1); break;
      case "H": case "f": this.y = Math.min(R - 1, n(0, 1) - 1); this.x = Math.min(C - 1, n(1, 1) - 1); break;
      case "J": {
        const m = Number.isFinite(p[0]) ? p[0] : 0, L = this.lines;
        if (m === 0) { this._eraseRow(this.y, this.x, C); for (let r = this.y + 1; r < R; r++) L[r] = this._row(); }
        else if (m === 1) { for (let r = 0; r < this.y; r++) L[r] = this._row(); this._eraseRow(this.y, 0, this.x + 1); }
        else if (m === 2) { for (let r = 0; r < R; r++) L[r] = this._row(); }
        else if (m === 3) this.scrollback = [];
        break;
      }
      case "K": {
        const m = Number.isFinite(p[0]) ? p[0] : 0;
        if (m === 0) this._eraseRow(this.y, this.x, C); else if (m === 1) this._eraseRow(this.y, 0, this.x + 1); else this._eraseRow(this.y, 0, C);
        break;
      }
      case "X": this._eraseRow(this.y, this.x, Math.min(C, this.x + n(0, 1))); break;
      case "P": { const row = this.lines[this.y], k = Math.min(n(0, 1), C - this.x); row.splice(this.x, k); while (row.length < C) row.push(" "); break; }
      case "@": { const row = this.lines[this.y], k = Math.min(n(0, 1), C - this.x); row.splice(this.x, 0, ...new Array(k).fill(" ")); row.length = C; break; }
      case "L": if (this.y >= this.top && this.y <= this.bot) { const L = this.lines; for (let k = 0; k < n(0, 1); k++) { L.splice(this.bot, 1); L.splice(this.y, 0, this._row()); } } break;
      case "M": if (this.y >= this.top && this.y <= this.bot) { const L = this.lines; for (let k = 0; k < n(0, 1); k++) { L.splice(this.y, 1); L.splice(this.bot, 0, this._row()); } } break;
      case "S": this._scrollUp(n(0, 1)); break;
      case "T": if (!priv) this._scrollDown(n(0, 1)); break;
      case "r": { const t = n(0, 1) - 1, b = n(1, R) - 1; if (t < b && b < R) { this.top = t; this.bot = b; } else { this.top = 0; this.bot = R - 1; } this.x = 0; this.y = 0; break; }
      case "s": if (!priv) this._saved = { x: this.x, y: this.y }; break;
      case "u": if (!priv) { this.x = this._saved.x; this.y = this._saved.y; } break;
      case "h": case "l": if (priv) for (const v of p) if (Number.isFinite(v)) this._mode(v, f === "h"); break;
      default: break; // m (colors), n (reports), q, t, c ... carry no text
    }
  }
  _eraseRow(r, a, b) { const row = this.lines[r]; for (let i = Math.max(0, a); i < Math.min(this.cols, b); i++) row[i] = " "; }
  _mode(v, on) {
    if (v === 1049 || v === 1047 || v === 47) {
      if (on && !this._alt) { if (v === 1049) this._saved = { x: this.x, y: this.y }; this._alt = this._blank(); }
      else if (!on && this._alt) { this._alt = null; if (v === 1049) { this.x = this._saved.x; this.y = this._saved.y; } }
      this.top = 0; this.bot = this.rows - 1;
      return;
    }
    if (v === 25) { this.cursorHidden = !on; return; }
    if (on) this.modes.add(v); else this.modes.delete(v);
  }

  // ---- reading ----
  // Visible screen as text, right-trimmed, trailing blank lines dropped.
  text() { const out = this.lines.map((r) => r.join("").replace(/\s+$/, "")); while (out.length && !out[out.length - 1]) out.pop(); return out.join("\n"); }
  // The last `n` non-empty-tail lines, including scrollback on the main screen.
  tail(n) {
    const vis = this.lines.map((r) => r.join("").replace(/\s+$/, ""));
    const all = (this._alt ? [] : this.scrollback).concat(vis);
    while (all.length && !all[all.length - 1]) all.pop();
    return all.slice(-Math.max(1, n | 0 || 40)).join("\n");
  }
  // Bytes that rebuild this screen on a fresh terminal: the alt screen, the modes that
  // change input (bracketed paste, mouse), the text, then the cursor.
  repaint() {
    let s = "\x1b[0m" + (this._alt ? "\x1b[?1049h" : "") + "\x1b[H\x1b[2J";
    for (const m of [1, 1000, 1002, 1003, 1006, 2004]) if (this.modes.has(m)) s += "\x1b[?" + m + "h";
    const L = this.lines;
    for (let r = 0; r < this.rows; r++) { const t = L[r].join("").replace(/\s+$/, ""); if (t) s += "\x1b[" + (r + 1) + ";1H" + t; }
    s += "\x1b[" + (this.y + 1) + ";" + (this.x + 1) + "H" + (this.cursorHidden ? "\x1b[?25l" : "");
    return s;
  }
}

// The bytes that put a client terminal back to normal after a detach.
const RESET_CLIENT = "\x1b[0m\x1b[?1000l\x1b[?1002l\x1b[?1003l\x1b[?1006l\x1b[?2004l\x1b[?1l\x1b[?25h\x1b[?1049l";

module.exports = { Screen, RESET_CLIENT };
