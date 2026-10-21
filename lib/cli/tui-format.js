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
    // count the same unit visLen uses (UTF-16 code units) so a surrogate-pair
    // char can't overshoot the column budget; stop before exceeding `lim`.
    for (const ch of part) { const w = ch.length; if (v + w > lim) { stop = true; break; } out += ch; v += w; }
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
  if (max <= 0) return "";
  if (s.length <= max) return s;
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
  // null-proto: a model id of "constructor"/"toString" must not resolve to an inherited native
  // function that then renders as "function Object() { [native code] }" in the header.
  const ENG = Object.assign(Object.create(null), { claude: "Claude", ollama: "Ollama", codex: "Codex", gemini: "Gemini", opencode: "OpenCode", aider: "Aider" });
  if (ENG[low]) return ENG[low];
  return s.replace(/^models\//, "");
}

// Effort → a short status segment. "" (the model default) returns "" so the
// caller can omit it rather than invent a level.
function effortLabel(effort) { const e = String(effort || "").trim(); return e ? e + " effort" : ""; }

// Welcome card shown at the top of a fresh session: a rounded box with the
// product name + version, the active model/engine, the working directory and
// branch, and one line of starter hints. opts: { version, model, engineLabel,
// cwd, branch, home, cols, paint }. paint roles: brand, border, muted, faint.
// Plain (no escapes) when paint is omitted; fits 40-120 cols.
function welcomeCard(opts) {
  opts = opts || {};
  const cols = Math.max(30, opts.cols || 80);
  const W = Math.min(cols - 2, 62);              // outer width incl. borders
  const inner = W - 4;                           // text width between "│ " and " │"
  const P = opts.paint || {};
  const id = (s) => s;
  const brand = P.brand || id, border = P.border || id, muted = P.muted || id, faint = P.faint || id;
  const version = opts.version ? "v" + String(opts.version).replace(/^v/, "") : "";
  const row = (s) => border("│") + " " + padRight(fitWidth(s, inner), inner) + " " + border("│");
  const lines = [""];
  lines.push(border("╭" + "─".repeat(W - 2) + "╮"));
  const title = brand("Nexus");
  const gap = inner - visLen(title) - version.length;
  lines.push(row(gap >= 2 ? title + " ".repeat(gap) + faint(version) : title));
  lines.push(row(""));
  const who = [opts.model, opts.engineLabel].filter(Boolean).join(muted("  ·  "));
  if (who) lines.push(row("  " + who));
  const where = opts.cwd ? shortenPath(opts.cwd, inner - 2 - (opts.branch ? opts.branch.length + 5 : 0), opts.home) : "";
  if (where) lines.push(row("  " + muted(where) + (opts.branch ? muted("  ·  " + opts.branch) : "")));
  if (opts.status) lines.push(row("  " + faint(opts.status)));
  lines.push(row(""));
  lines.push(row("  " + (inner >= 50
    ? faint("/help") + muted(" commands   ") + faint("/model") + muted(" switch model   ") + faint("?") + muted(" shortcuts")
    : faint("/help") + muted("  ·  ") + faint("?") + muted(" shortcuts"))));
  lines.push(border("╰" + "─".repeat(W - 2) + "╯"));
  lines.push("");
  return lines;
}

// One footer row: `left` hint text and `right` status text, right-aligned to
// `cols`. When both don't fit, the left side is shortened first, then dropped;
// the right side is clipped last. Returns the row (ANSI preserved).
function footerLine(left, right, cols) {
  const W = Math.max(10, cols || 80) - 2;
  left = left || ""; right = right || "";
  const rl = visLen(right);
  if (rl >= W) return " " + fitWidth(right, W);
  const room = W - rl - 2;                       // keep two spaces between the sides
  const l = room >= 8 ? fitWidth(left, room) : "";
  return " " + l + " ".repeat(Math.max(2, W - visLen(l) - rl)) + right;
}

// Lay out grouped help as aligned rows: a heading per section, then one row
// per [name, description] with the descriptions in a single column and long
// descriptions wrapped under that column (never under the name).
// sections: [{ title, rows: [[name, desc], ...] }]; paint roles: heading, name, desc.
function helpLines(sections, cols, paint) {
  const P = paint || {};
  const id = (s) => s;
  const heading = P.heading || id, nameC = P.name || id, descC = P.desc || id;
  const W = Math.max(30, cols || 80) - 4;
  let nw = 0;
  for (const s of sections) for (const r of s.rows) nw = Math.max(nw, String(r[0]).length);
  nw = Math.min(nw + 2, Math.max(12, Math.floor(W * 0.4)));
  const dw = Math.max(10, W - 2 - nw);
  const out = [];
  sections.forEach((s, si) => {
    if (si) out.push("");
    out.push(heading(s.title));
    for (const [n, d] of s.rows) {
      const words = String(d || "").split(/\s+/).filter(Boolean);
      const wrapped = []; let cur = "";
      for (const w of words) { if (cur && cur.length + 1 + w.length > dw) { wrapped.push(cur); cur = w; } else cur = cur ? cur + " " + w : w; }
      if (cur || !wrapped.length) wrapped.push(cur);
      const nm = String(n);
      const first = nm.length > nw - 2 ? fitWidth(nm, nw - 2) : nm;
      out.push("  " + nameC(padRight(first, nw)) + descC(wrapped[0]));
      for (let i = 1; i < wrapped.length; i++) out.push("  " + " ".repeat(nw) + descC(wrapped[i]));
    }
  });
  return out;
}

// Turn a raw engine/network error into one calm, actionable line. Coding sessions
// die on cryptic "fetch failed" / "ECONNREFUSED" strings; this says what to DO.
// Pure and string-only so it's unit-tested and reused anywhere a model call fails.
function explainEngineError(message, opts) {
  opts = opts || {};
  const m = String(message || "").toLowerCase();
  const eng = String(opts.engine || "").toLowerCase();
  const model = opts.model || "the model";
  const isLocal = eng === "ollama" || /ollama|localhost|127\.0\.0\.1|:11434/.test(m);
  if (/econnrefused|connection refused|fetch failed|failed to fetch|enotfound|getaddrinfo|socket hang up|econnreset|network error|dns/.test(m)) {
    return isLocal
      ? "can't reach the local AI server — is Ollama running? start it with `ollama serve`, or run `nexus setup` to install it."
      : "can't reach the AI provider — check your connection, then retry. /engine switches backend.";
  }
  if (/abort|timed? ?out|etimedout|deadline/.test(m)) return "the request timed out — retry, or pick a lighter model with /model (or /engine to switch).";
  if (/429|rate.?limit|too many requests|overloaded|capacity|503|service unavailable/.test(m)) return "the provider is rate-limiting or overloaded — wait a few seconds and retry, or /engine to switch backend.";
  if (/401|403|unauthor|invalid.*(api|key|token)|authentication|forbidden|no api key|missing.*key/.test(m)) return "authentication failed — your API key looks missing or invalid. Re-run /login, or set the key for this engine.";
  if (/not found|no such model|unknown model|does not exist|model.*not|404/.test(m)) return "model '" + model + "' isn't available — see /models" + (isLocal ? ", or pull it: `ollama pull " + model + "`." : ".");
  if (/out of memory|\boom\b|insufficient memory|not enough memory|cannot allocate/.test(m)) return "the model ran out of memory — try a smaller model with /model, or free up RAM.";
  if (/quota|billing|payment|insufficient.*(fund|credit|balance)|exceeded your current quota/.test(m)) return "the provider rejected the request for billing/quota reasons — check your account, or /engine to switch.";
  return "model error: " + (message || "unknown") + "  (retry, or /engine to switch backend)";
}

module.exports = { stripAnsi, visLen, fitWidth, padRight, shortenPath, bootHeader, welcomeCard, footerLine, helpLines, modelLabel, effortLabel, explainEngineError };
