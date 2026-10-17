"use strict";
// Pure, dependency-free formatting helpers for the Nexus terminal UI.
// Everything here is deterministic and side-effect free so it can be unit
// tested (test/run.js) and reused by both the full-screen TUI and the plain
// REPL. Color is applied by the caller via a `paint` map of functions, so the
// same layout code produces either ANSI-colored or NO_COLOR / non-TTY output.

const ANSI_RE = /\x1b\[[0-9;]*m/g;

// strip SGR color escapes
const stripAnsi = (s) => String(s).replace(ANSI_RE, "");
// visible width (ANSI-aware); good enough for the mono box-drawing UI
const visLen = (s) => stripAnsi(s).length;

// Truncate `s` to at most `max` visible columns, keeping ANSI codes intact and
// appending `ell` when it had to cut. Returns "" for max<=0. Non-TTY safe: if
// the input carries no color, the output carries none either.
function fitWidth(s, max, ell = "…") {
  s = String(s);
  if (max <= 0) return "";
  if (visLen(s) <= max) return s;
  const lim = Math.max(0, max - ell.length);
  let out = "", v = 0, hadColor = false, stop = false;
  for (const part of s.split(/(\x1b\[[0-9;]*m)/)) {
    if (stop) break;
    if (/^\x1b/.test(part)) { out += part; hadColor = true; continue; }
    for (const ch of part) { if (v >= lim) { stop = true; break; } out += ch; v++; }
  }
  out += ell;
  return out + (hadColor ? "\x1b[0m" : "");
}

// Pad `s` on the right to `width` visible columns (ANSI-aware). Never truncates.
function padRight(s, width) {
  const gap = width - visLen(s);
  return gap > 0 ? s + " ".repeat(gap) : s;
}

// Abbreviate a filesystem path to fit `max` columns: collapse the home dir to
// "~", and if still too long keep the most informative tail (cut on a slash
// where possible) behind an ellipsis.
function shortenPath(p, max, home) {
  let s = String(p || "");
  if (home && (s === home || s.startsWith(home + "/"))) s = "~" + s.slice(home.length);
  if (max <= 0 || s.length <= max) return s;
  if (max <= 1) return s.slice(-max);
  const tail = s.slice(-(max - 1));
  const slash = tail.indexOf("/");
  return "…" + (slash > 0 ? tail.slice(slash) : tail);
}

// Build the compact, calm Nexus boot/header block as an array of lines.
// opts: { version, engine, engineLabel, model, cwd, branch, home, cols, paint }
// `paint` maps roles -> (s)=>string; omit for plain text (NO_COLOR / non-TTY).
// The layout fits 80 cols, degrades cleanly to ~40, and never emits escapes
// when paint is absent.
function bootHeader(opts) {
  opts = opts || {};
  const cols = Math.max(24, opts.cols || 80);
  const inner = Math.min(cols - 2, 72);
  const P = opts.paint || {};
  const id = (s) => s;
  const brand = P.brand || id, accent = P.accent || id, muted = P.muted || id,
        faint = P.faint || id, rule = P.rule || id, value = P.value || id;

  const version = opts.version ? "v" + String(opts.version).replace(/^v/, "") : "";
  const engine = opts.engine || "";
  const engLabel = opts.engineLabel && opts.engineLabel !== engine ? engine + "  ·  " + opts.engineLabel : engine;
  const lines = [""];

  // wordmark line — single tidy row, tagline dropped on narrow terminals
  let head = brand("NEXUS");
  if (inner >= 58) head += "  " + faint("·  multi-engine coding agent  ·");
  if (version) head += "  " + accent(version);
  lines.push("  " + fitWidth(head, inner));
  lines.push("  " + rule("─".repeat(inner)));

  // key / value rows — only the ones that carry information
  const row = (k, v) => lines.push("  " + muted(padRight(k, 8)) + fitWidth(value(v), inner - 8));
  if (engine) row("engine", engLabel);
  if (opts.model && opts.model !== engine) row("model", opts.model);
  if (opts.cwd) row("dir", shortenPath(opts.cwd, inner - 8, opts.home));
  if (opts.branch) row("branch", opts.branch);

  // hint line — the three things worth knowing up front
  const hints = inner >= 52
    ? faint("/help") + " commands   " + faint("/model") + " switch   " + faint("Esc") + " interrupt"
    : faint("/help") + " · " + faint("/model") + " · " + faint("Esc");
  lines.push("  " + fitWidth(hints, inner));
  lines.push("");
  return lines;
}

// Map a model ID (or an unresolved alias) to a readable display name with its
// version, e.g. claude-opus-5-5 -> "Opus 5.5", claude-3-5-sonnet-* -> "Sonnet
// 3.5", fable-5-1 -> "Fable 5.1". A bare alias ("opus") title-cases with no
// version (the caller resolves the real ID from the engine's init event first).
// Non-claude models (gpt-4o, qwen2.5-coder, gemini-2.5-pro) pass through as-is.
function modelLabel(id) {
  const s = String(id == null ? "" : id).trim();
  if (!s) return "";
  const low = s.toLowerCase();
  const cap = (w) => w.charAt(0).toUpperCase() + w.slice(1);
  const FAM = "opus|sonnet|haiku";
  let m = low.match(new RegExp("(" + FAM + ")-(\\d+)-(\\d+)"));          // family-first: claude-opus-5-5
  if (m) return cap(m[1]) + " " + m[2] + "." + m[3];
  m = low.match(new RegExp("(\\d+)-(\\d+)-(" + FAM + ")"));             // version-first: claude-3-5-sonnet
  if (m) return cap(m[3]) + " " + m[1] + "." + m[2];
  m = low.match(/fable-(\d+)-(\d+)/);
  if (m) return "Fable " + m[1] + "." + m[2];
  if (/^(claude-)?(opus|sonnet|haiku|fable)$/.test(low)) return cap(low.replace(/^claude-/, "")); // bare alias
  const fm = low.match(new RegExp("\\b(" + FAM + "|fable)\\b"));
  if (fm) { const ver = low.match(/(\d+)[-.](\d+)/); return cap(fm[1]) + (ver ? " " + ver[1] + "." + ver[2] : ""); }
  const ENG = { claude: "Claude", ollama: "Ollama", codex: "Codex", gemini: "Gemini", opencode: "OpenCode", aider: "Aider" };
  if (ENG[low]) return ENG[low];
  return s.replace(/^models\//, "");
}

// Effort → a short status segment. "" (the model default) returns "" so the
// caller can omit it rather than invent a level.
function effortLabel(effort) { const e = String(effort || "").trim(); return e ? e + " effort" : ""; }

module.exports = { stripAnsi, visLen, fitWidth, padRight, shortenPath, bootHeader, modelLabel, effortLabel };
