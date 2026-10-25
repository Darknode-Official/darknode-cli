"use strict";
// ============================================================================
// tokcount — PURE helpers for `/tokens`: price files BEFORE you @-attach them,
// so you can see what a paste or a whole directory will cost per turn. The host
// walks the filesystem and hands in plain { path, chars, binary, skipped }
// entries; everything here is deterministic + snapshot-testable.
//
// Token counts are an ESTIMATE (≈ chars / 4, the usual English/code average) —
// labelled "≈" everywhere so it never pretends to be an exact tokenizer count.
// ============================================================================

const IDENT = (s) => s;
function theme(c) {
  c = c || {};
  return { cyan: c.cyan || IDENT, gray: c.gray || IDENT, bold: c.bold || IDENT, dim: c.dim || IDENT, green: c.green || IDENT, yellow: c.yellow || IDENT };
}

function estimateTokens(chars) { return Math.ceil(Math.max(0, chars | 0) / 4); }
function fmtK(n) { n = Math.max(0, Math.round(n || 0)); return n >= 1000 ? (n / 1000).toFixed(n >= 100000 ? 0 : 1) + "k" : String(n); }
function money(n) { n = n || 0; return "$" + (n < 1 ? n.toFixed(4) : n.toFixed(2)); }
function fit(s, w) { s = String(s == null ? "" : s); if (w < 0) w = 0; if (s.length <= w) return s; if (w <= 1) return s.slice(0, w); return "…" + s.slice(-(w - 1)); } // keep the file-name end

// Directories never worth attaching — skipped by the host walker.
const SKIP_DIRS = new Set([".git", "node_modules", ".nexus", "dist", "build", ".next", "coverage", "__pycache__", ".venv", "venv", "target", ".cache"]);

// A buffer looks binary when its first 8KB holds a NUL byte (same rule git uses).
function looksBinary(buf) { if (!buf) return false; const n = Math.min(buf.length, 8192); for (let i = 0; i < n; i++) if (buf[i] === 0) return true; return false; }

// summarize(entries, price) -> totals.  price: { in, cr } USD per million tokens
// (cr = cache-read rate, or null when the model has no prompt caching).
function summarize(entries, price) {
  entries = Array.isArray(entries) ? entries : [];
  const text = entries.filter((e) => !e.binary && !e.skipped);
  const tokens = text.reduce((a, e) => a + estimateTokens(e.chars), 0);
  const p = price || {};
  return {
    files: text.length,
    binary: entries.filter((e) => e.binary).length,
    skipped: entries.filter((e) => e.skipped).length,
    tokens,
    firstSend: p.in != null ? (tokens / 1e6) * p.in : null,      // the first turn that carries it
    cachedResend: p.cr != null ? (tokens / 1e6) * p.cr : null,   // each later turn, when it hits the prompt cache
  };
}

// renderTokens(entries, opt) -> string[].  opt: { price, paid, model, colors, width, max }
function renderTokens(entries, opt) {
  opt = opt || {};
  const t = theme(opt.colors);
  const C = Math.max(40, (opt.width | 0) || 80);
  const max = Math.max(1, (opt.max | 0) || 10);
  entries = Array.isArray(entries) ? entries : [];
  if (!entries.length) return [t.gray("nothing matched — /tokens <file|dir> [more…] prices what you'd attach with @")];
  const s = summarize(entries, opt.price);
  const out = [];
  out.push(t.bold("token estimate") + t.gray("  ≈" + fmtK(s.tokens) + " tokens across " + s.files + " file" + (s.files === 1 ? "" : "s") + (s.binary ? " · " + s.binary + " binary skipped" : "") + (s.skipped ? " · " + s.skipped + " skipped" : "")));
  // the heaviest files first — that's where the cost is
  const ranked = entries.filter((e) => !e.binary && !e.skipped).sort((a, b) => b.chars - a.chars);
  const shown = ranked.slice(0, max);
  const numW = Math.max(4, ...shown.map((e) => ("≈" + fmtK(estimateTokens(e.chars))).length));
  for (const e of shown) {
    const n = ("≈" + fmtK(estimateTokens(e.chars))).padStart(numW);
    const pct = s.tokens ? Math.round((estimateTokens(e.chars) / s.tokens) * 100) : 0;
    const tail = "  " + n + "  " + String(pct).padStart(3) + "%";
    out.push("  " + fit(e.path, C - 4 - tail.length).padEnd(Math.max(0, C - 4 - tail.length)) + t.gray(tail));
  }
  if (ranked.length > shown.length) out.push(t.dim("  … " + (ranked.length - shown.length) + " smaller file" + (ranked.length - shown.length === 1 ? "" : "s")));
  if (!opt.paid) out.push(t.green("  local engine — attaching this is free"));
  else if (s.firstSend != null) {
    out.push(t.gray("  at " + (opt.model || "this model") + ": ") + t.bold(money(s.firstSend)) + t.gray(" first turn") + (s.cachedResend != null ? t.gray(" · ") + t.bold(money(s.cachedResend)) + t.gray("/turn while cached") : ""));
  }
  if (s.tokens > 50000) out.push(t.yellow("  large — consider @-attaching just the files you need, or /pin only the key ones"));
  return out;
}

module.exports = { estimateTokens, looksBinary, summarize, renderTokens, SKIP_DIRS };
