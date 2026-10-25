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

// ANSI-aware word wrap. Splits `text` on newlines and wraps each paragraph to
// `width` *visible* columns — SGR color escapes have zero width and are never
// cut in half. When a wrapped span leaves a color open, the line is closed with
// a reset and the next line re-opens that color, so no color bleeds between rows
// and a continued span stays colored. Prefers to break on a space (unless the
// paragraph is inside a ``` code fence); hard-breaks only when there is none,
// and keeps surrogate pairs intact. Mirrors the plain-text wrapper it replaces.
// Neutralise terminal control in untrusted text (model replies, tool output,
// agent logs): keep SGR colour escapes, drop every other escape sequence (cursor
// moves, screen clears, OSC title/clipboard/hyperlink, DCS) and C0/C1 control
// bytes, which would otherwise move the cursor or rewrite the screen mid-frame.
// keepNl keeps \n and \t for callers that split lines themselves.
const TERM_CTL_RE = /\x1b(\[[0-9;]*m)|\x1b\[[0-?]*[ -\/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)?|\x1b[PX^_][^\x1b]*(?:\x1b\\)?|\x1b[\s\S]?|[\x00-\x08\x0b-\x1f\x7f-\x9f]|(\t|\n)/g;
function sanitizeTerm(s, keepNl) {
  return String(s).replace(TERM_CTL_RE, (m, sgr, nl) => sgr ? m : nl ? (keepNl ? nl : nl === "\t" ? "  " : " ") : "");
}

function ansiWrap(text, width) {
  width = Math.max(1, width | 0);
  const out = [];
  let inCode = false;
  const sgrActive = (active, esc) => {
    for (const p of esc.match(/\x1b\[[0-9;]*m/g) || []) active = (p === "\x1b[0m" || p === "\x1b[m") ? "" : active + p;
    return active;
  };
  // Expand tabs to spaces up front: a literal \t renders as a jump to the next
  // 8-col tab stop but measures as width 1, so one in the output would overflow
  // the right border and shove the scrollbar out of line. Two spaces matches the
  // convention used elsewhere in the renderer.
  for (const para of sanitizeTerm(text, true).replace(/\t/g, "  ").split("\n")) {
    if (/^```/.test(para.trim())) inCode = !inCode;
    if (!para.length) { out.push(""); continue; }
    // Tokenize into visible glyphs, each carrying the escapes that precede it.
    const cells = []; let pre = "";
    const re = /\x1b\[[0-9;]*m|[\s\S]/g; let m;
    while ((m = re.exec(para))) {
      let t = m[0];
      if (t[0] === "\x1b") { pre += t; continue; }
      if (t.length === 1) { const cc = t.charCodeAt(0); if (cc >= 0xD800 && cc <= 0xDBFF) { const nx = re.exec(para); if (nx) t += nx[0]; } }
      cells.push({ pre, ch: t, sp: t === " " }); pre = "";
    }
    const trailing = pre; // escapes after the last glyph (e.g. a closing reset)
    if (!cells.length) { out.push(trailing); continue; }
    let i = 0, active = "", carried = "";
    while (i < cells.length) {
      let j = i, count = 0, lastSpace = -1;
      while (j < cells.length && (j === i || count + cells[j].ch.length <= width)) { if (cells[j].sp) lastSpace = j; count += cells[j].ch.length; j++; } // charge each glyph its visLen width (a surrogate pair is 2) so an emoji can't overshoot the column budget; always take >=1 glyph to guarantee progress
      if (j < cells.length && cells[j].sp) lastSpace = j; // a space sitting exactly at the boundary fills the line, then is dropped
      let end, nextStart;
      if (j >= cells.length) { end = nextStart = cells.length; }
      else if (!inCode && lastSpace > i && (lastSpace - i) >= width * 0.4) { end = lastSpace; nextStart = lastSpace + 1; }
      else { end = nextStart = j; }
      let seg = carried, lineActive = active;
      for (let k = i; k < end; k++) { seg += cells[k].pre + cells[k].ch; lineActive = sgrActive(lineActive, cells[k].pre); }
      let consumed = lineActive;
      for (let k = end; k < nextStart; k++) consumed = sgrActive(consumed, cells[k].pre); // escapes on a dropped space
      out.push(seg + (lineActive ? "\x1b[0m" : ""));
      carried = active = consumed;
      i = nextStart;
    }
    if (trailing) out[out.length - 1] = (out[out.length - 1] + trailing).replace(/(?:\x1b\[0m)+$/, "\x1b[0m");
  }
  return out;
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
  const W = Math.min(cols - 2, 74);              // outer width incl. borders
  const inner = W - 4;                           // text width between "│ " and " │"
  const narrow = inner < 46;                     // drop to a compact layout on small terminals
  const P = opts.paint || {};
  const id = (s) => s;
  const brand = P.brand || id, border = P.border || id, muted = P.muted || id, faint = P.faint || id;
  const accent = P.accent || brand, label = P.label || muted, key = P.key || brand;
  const version = opts.version ? "v" + String(opts.version).replace(/^v/, "") : "";
  const row = (s) => border("│") + " " + padRight(fitWidth(s, inner), inner) + " " + border("│");
  const rule = () => border("├" + "─".repeat(W - 2) + "┤");
  const lines = [""];
  lines.push(border("╭" + "─".repeat(W - 2) + "╮"));
  // ---- title: brand + tagline on the left, version on the right ----
  const tagline = "agentic coding in your terminal";
  const titleFull = brand("Nexus") + "  " + faint(tagline);
  if (!narrow && inner - visLen(titleFull) - version.length >= 2) {
    lines.push(row(titleFull + " ".repeat(inner - visLen(titleFull) - version.length) + faint(version)));
  } else {
    const b = brand("Nexus"); const g = inner - visLen(b) - version.length;
    lines.push(row(g >= 2 ? b + " ".repeat(g) + faint(version) : b));
  }
  lines.push(rule());
  // ---- session details: aligned label / value rows ----
  const kv = (k, v) => lines.push(row("  " + label(padRight(k, 10)) + v));
  if (opts.model) kv("Model", brand(opts.model) + (opts.effort ? muted("  ·  ") + faint(opts.effort) : ""));
  if (opts.engineLabel) kv("Engine", opts.engineLabel);
  const where = opts.cwd ? shortenPath(opts.cwd, inner - 12 - (opts.branch ? opts.branch.length + 5 : 0), opts.home) : "";
  if (where) kv("Project", muted(where) + (opts.branch ? muted("  ·  ") + accent(opts.branch) : ""));
  const sess = [];
  if (opts.contextLabel) sess.push(opts.contextLabel + " context");
  if (opts.guard) sess.push("guard " + opts.guard);
  if (opts.mcp) sess.push(opts.mcp + " MCP server" + (opts.mcp > 1 ? "s" : ""));
  if (sess.length) kv("Session", muted(sess.join("  ·  ")));
  // ---- quick start: two-column command grid (surfaces customization too) ----
  lines.push(rule());
  lines.push(row(accent("Quick start")));
  const QUICK = opts.quickCommands || [
    ["/help", "all commands"], ["/open", "web dashboard"],
    ["/model", "switch model"], ["/agents", "background agents"],
    ["/mcp", "manage servers"], ["/settings", "preferences"],
    ["/theme", "colors & look"], ["/resume", "resume a session"],
  ];
  const kw = 11;                                  // command-name column width
  const cell = (pair, w) => padRight(key(pair[0]), kw) + muted(fitWidth(pair[1], Math.max(4, w - kw)));
  if (narrow) {
    for (const p of QUICK) lines.push(row("  " + cell(p, inner - 2)));
  } else {
    const half = Math.floor((inner - 2) / 2);
    for (let i = 0; i < QUICK.length; i += 2) {
      const l = cell(QUICK[i], half);
      const r = QUICK[i + 1] ? cell(QUICK[i + 1], inner - 2 - half) : "";
      lines.push(row("  " + padRight(l, half) + r));
    }
  }
  // ---- tip line ----
  if (opts.tip) { lines.push(rule()); lines.push(row(label(padRight("Tip", 10)) + faint(opts.tip))); }
  lines.push(border("╰" + "─".repeat(W - 2) + "╯"));
  lines.push("");
  return lines;
}

// Idle "home" shown below the welcome card while the chat is still empty, so a
// fresh session fills the screen instead of a dark void: a large gradient NEXUS
// wordmark, a one-line positioning strip, a few real "try asking" starter prompts,
// and a live one-line project pulse. Pure layout — every colour comes from
// opts.paint / opts.grad, so it degrades to readable plain text under NO_COLOR.
// opts: { cols, paint, grad, suggestions:[string], project:{name,branch,dirty,files,commits,last} }
// paint roles: brand, accent, muted, faint, key. grad(plainLine)->coloured (hero only).
const _NX_GLYPHS = {
  N: ["█   █", "██  █", "█ █ █", "█  ██", "█   █"],
  E: ["█████", "█    ", "████ ", "█    ", "█████"],
  X: ["█   █", " █ █ ", "  █  ", " █ █ ", "█   █"],
  U: ["█   █", "█   █", "█   █", "█   █", "█████"],
  S: ["█████", "█    ", "█████", "    █", "█████"],
};
function idleHome(opts) {
  opts = opts || {};
  const cols = Math.max(30, opts.cols || 80);
  const W = cols - 2;                              // usable width (the renderer adds a 1-col gutter)
  const P = opts.paint || {};
  const id = (s) => s;
  const brand = P.brand || id, accent = P.accent || id, muted = P.muted || id, faint = P.faint || id, key = P.key || brand;
  const grad = opts.grad || null;
  const center = (s, w) => " ".repeat(Math.max(0, Math.floor((W - w) / 2))) + s;   // w = visible width of `s`
  const L = ["", ""];
  // ---- hero wordmark: NEXUS in 5-row block letters, swept with the theme gradient ----
  const hero = ["", "", "", "", ""];
  "NEXUS".split("").forEach((ch, li) => { const g = _NX_GLYPHS[ch]; for (let r = 0; r < 5; r++) hero[r] += (li ? " " : "") + g[r]; });
  const heroW = hero[0].length;                    // 29 for NEXUS
  if (heroW <= W) { for (const r of hero) L.push(center(grad ? grad(r) : brand(r), heroW)); }
  else { const w = "N E X U S"; L.push(center(brand(w), w.length)); }   // compact fallback on a very narrow terminal
  L.push("");
  const sub = "runs on your machine · your keys & data stay yours · six engines, one agent";
  if (visLen(sub) <= W) L.push(center(faint(sub), visLen(sub)));
  L.push(""); L.push("");
  // ---- try asking: real starter prompts, left-aligned under a centred heading ----
  const sugg = (opts.suggestions && opts.suggestions.length ? opts.suggestions : [
    "explain what this project does and how it is structured",
    "find a bug, fix it, and run the tests",
    "scan this repository for leaked secrets",
    "review my uncommitted changes",
  ]).map((s) => fitWidth(s, Math.max(10, W - 4)));
  const blockW = sugg.reduce((m, s) => Math.max(m, visLen(s) + 2), 0);  // +2 for the "❯ " prefix
  L.push(center(accent("Try asking"), 10));
  L.push("");
  for (const s of sugg) L.push(center(key("❯ ") + muted(s), blockW));
  // ---- project pulse: one live line of real repo context ----
  const pr = opts.project;
  if (pr && pr.name) {
    const seg = [accent(pr.name)];
    if (pr.branch) seg.push(accent(pr.branch));
    if (typeof pr.files === "number") seg.push(muted(pr.files + " file" + (pr.files === 1 ? "" : "s")));
    if (pr.commits) seg.push(muted(pr.commits + " commit" + (pr.commits === 1 ? "" : "s")));
    seg.push(muted(pr.dirty ? "uncommitted changes" : "working tree clean"));
    const line = seg.join(faint("  ·  "));
    L.push(""); L.push("");
    L.push(center(fitWidth(line, W), Math.min(visLen(line), W)));
    if (pr.last) { const last = faint("latest  " + pr.last); L.push(center(fitWidth(last, W), Math.min(visLen(last), W))); }
  }
  L.push("");
  return L;
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


// ---- Claude Code-style tool result view ----------------------------------
// Turns a raw tool result into the short "⎿" lines Claude Code prints under a
// tool call: "Read 42 lines", the first lines of command output, "Found 3
// files", a todo checklist, "Error: …". Engine-neutral: native (ollama) tool
// names are mapped onto the Claude Code ones first. Returns
// { lines: [{ k: "text"|"out"|"err"|"todo", text, s? }], more } where `more`
// is how many lines were folded away (shown as "… +N lines (ctrl+o …)").
const CC_NAME = {
  read_file: "Read", write_file: "Write", edit_file: "Edit", multi_edit: "MultiEdit", multiedit: "MultiEdit",
  run_command: "Bash", search: "Grep", grep: "Grep", find: "Glob", find_files: "Glob", glob: "Glob",
  list_dir: "LS", http_fetch: "WebFetch", web_fetch: "WebFetch", fetch_url: "WebFetch", http: "WebFetch",
  web_search: "WebSearch", search_web: "WebSearch", google: "WebSearch", spawn_agents: "Task",
  todo_write: "TodoWrite", todos: "TodoWrite", todo_list: "TodoWrite", write_todos: "TodoWrite",
};
const ccName = (n) => CC_NAME[n] || n;
const nLines = (n, w) => n + " " + w + (n === 1 ? "" : "s");
const kb = (n) => n < 1024 ? n + " B" : (n / 1024).toFixed(1) + " KB";
function asText(c) {
  if (c == null) return "";
  if (typeof c === "string") return c;
  if (Array.isArray(c)) return c.map((x) => (x && typeof x.text === "string") ? x.text : typeof x === "string" ? x : "").join("\n");
  if (typeof c === "object") { // native tool result object
    if (c.error) return String(c.error);
    if (typeof c.output === "string") return c.output;
    if (typeof c.content === "string") return c.content;
    if (Array.isArray(c.items)) return c.items.join("\n");
    return JSON.stringify(c);
  }
  return String(c);
}
function todoList(input) {
  const raw = (input && (input.todos || input.items || input.tasks)) || [];
  return raw.map((t) => {
    const st = String((t && t.status) || "pending").toLowerCase();
    return { k: "todo", s: /done|complete/.test(st) ? "done" : /progress|active|doing/.test(st) ? "active" : "todo", text: String((t && (t.content || t.text || t.title || t.task)) || t || "") };
  });
}
function toolResultView(name, input, content, opts) {
  const o = opts || {}, N = ccName(name), a = input || {};
  const cap = o.expanded ? 40 : 3;
  if (o.interrupted) return { lines: [{ k: "err", text: "Interrupted by user" }], more: 0 };
  if (N === "TodoWrite") return { lines: todoList(a), more: 0 };
  const obj = content && typeof content === "object" && !Array.isArray(content) ? content : null;
  const txt = asText(content).replace(/\r/g, "").replace(/\n*\[diagnosis\][^\n]*/g, ""); // the [diagnosis] note is for the model, not the screen
  const all = txt.split("\n"); while (all.length && !all[all.length - 1].trim()) all.pop();
  const clipOut = (ls, k) => ({ lines: ls.slice(0, cap).map((t) => ({ k, text: t })), more: Math.max(0, ls.length - cap) });
  const isErr = o.isError || !!(obj && obj.error) || (N === "Bash" && obj && typeof obj.code === "number" && obj.code !== 0);
  if (isErr) {
    const body = (obj && obj.error) ? [String(obj.error)] : all.filter((l) => l.trim());
    const head = N === "Bash" && obj && typeof obj.code === "number" && obj.code !== 0 ? "Error: Exit code " + obj.code : "Error: " + (String(body.shift() || "failed").replace(/^Error:\s*/i, "").replace(/^<tool_use_error>|<\/tool_use_error>$/g, ""));
    const v = clipOut(body, "err"); v.lines.unshift({ k: "err", text: head }); return v;
  }
  if (N === "Read") {
    if (/^\s*\(unchanged since/.test(txt)) return { lines: [{ k: "text", text: "Unchanged since last read" }], more: 0 };
    const numbered = all.filter((l) => /^\s*\d+(\t|→)/.test(l)).length;
    const n = numbered || all.length;
    return { lines: [{ k: "text", text: n ? "Read " + nLines(n, "line") : "Read file (empty)" }], more: 0 };
  }
  if (N === "Bash") {
    const body = o.expanded ? all.filter((l, i) => l.trim() || i > 0) : all.filter((l) => l.trim()); // collapsed preview never spends a row on a blank line
    if (!body.length) return { lines: [{ k: "text", text: "(No content)" }], more: 0 };
    return clipOut(body, "out");
  }
  if (N === "Grep" || N === "Glob") {
    const ls = all.filter((l) => l.trim());
    if (!ls.length || /^no (matches|files) found/i.test(ls[0])) return { lines: [{ k: "text", text: N === "Glob" ? "No files found" : "No matches found" }], more: 0 };
    if (/^Found \d+/.test(ls[0])) return { lines: [{ k: "text", text: ls[0].replace(/:$/, "") }], more: 0 };
    const files = a.output_mode === "files_with_matches" || N === "Glob" || ls.every((l) => !/:\d+:/.test(l) && !/\s/.test(l));
    return { lines: [{ k: "text", text: "Found " + nLines(ls.length, files ? "file" : "line") }], more: 0 };
  }
  if (N === "LS") return { lines: [{ k: "text", text: "Listed " + nLines(obj && Array.isArray(obj.items) ? obj.items.length : all.filter((l) => l.trim()).length, "path") }], more: 0 };
  if (N === "WebFetch") return { lines: [{ k: "text", text: "Received " + kb(Buffer.byteLength(txt)) + (obj && obj.status ? " (" + obj.status + ")" : "") }], more: 0 };
  if (N === "WebSearch") return { lines: [{ k: "text", text: "Did 1 search" + (o.secs ? " in " + o.secs : "") }], more: 0 };
  if (N === "Task") { const v = o.expanded ? clipOut(all.filter((l) => l.trim()), "out") : { lines: [], more: 0 }; v.lines.unshift({ k: "text", text: "Done" }); return v; }
  if (obj && obj.ok === true && Object.keys(obj).length === 1) return { lines: [{ k: "text", text: "Done" }], more: 0 };
  return clipOut(all.filter((l) => l.trim()), "out");
}

module.exports = { sanitizeTerm, toolResultView, ccName, stripAnsi, visLen, fitWidth, ansiWrap, padRight, shortenPath, bootHeader, welcomeCard, idleHome, footerLine, helpLines, modelLabel, effortLabel, explainEngineError };
