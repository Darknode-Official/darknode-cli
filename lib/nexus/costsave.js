"use strict";
// Extra cost savers that make Nexus cheaper than a naive CLI/website caller:
//   • squeezeContext — cut INPUT tokens every turn: dedupe identical inlined file
//     blocks (same file pinned + @mentioned, or repeated) and collapse whitespace.
//     Near-lossless: trailing spaces + 3+ blank lines collapse, which can
//     touch whitespace-significant content (Markdown hard breaks, diffs) — rare
//     in practice, but not byte-identical.
//   • response cache — serve an EXACT repeat answer for FREE. The key includes the
//     full prompt+inlined-context, so if any referenced file changed the key changes
//     and it re-runs (never serves a stale answer). Only read-only turns are cached.
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

// Terminal noise in pasted/attached logs: ANSI colour/cursor escapes and
// carriage-return redraws (progress bars repaint one line dozens of times). The
// model reads exactly what the terminal SHOWED — the final repaint, no escapes —
// so this is lossless for meaning. Raw ESC bytes never occur in real source files
// (code writes "\x1b", not the byte), so source text is untouched.
const ANSI_RE = /\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07\x1b]*(?:\x07|\x1b\\)|[@-Z\\-_])/g;
function stripTermNoise(text) {
  if (!text || typeof text !== "string" || (text.indexOf("\x1b") < 0 && text.indexOf("\r") < 0)) return text || "";
  text = text.replace(ANSI_RE, "").replace(/\r\n/g, "\n");
  // a bare \r returns the cursor to column 0 — keep only the last repaint of each line
  return text.indexOf("\r") < 0 ? text : text.split("\n").map((l) => { if (l.indexOf("\r") < 0) return l; const segs = l.split("\r").filter((x) => x.length); return segs.length ? segs[segs.length - 1] : ""; }).join("\n");
}

// Dedupe inlined "--- <tag> ---\n<body>\n--- end <tag> ---" blocks by body, and
// collapse trailing spaces + 3+ blank lines. Returns { text, saved } (est. tokens).
function squeezeContext(text) {
  if (!text || typeof text !== "string") return { text: text || "", saved: 0 };
  const orig = text;
  text = stripTermNoise(text);
  const seen = new Set();
  text = text.replace(/(-{3} [^\n]+ -{3}\n)([\s\S]*?)(\n-{3} end [^\n]+ -{3})/g, (m, head, body, tail) => {
    // key on filename+body, not body alone: the same file shown twice (even under
    // different tags like "pinned:"/"context:") still collapses, but two DISTINCT files
    // with byte-identical content must not be mistaken for one another.
    const fn = (head.match(/([^\s]+)\s+-{3}\s*$/) || [])[1] || head;
    const key = fn + "\x00" + body.trim();
    if (body.trim().length < 40) return m;             // don't bother with tiny blocks
    if (seen.has(key)) return head.replace(/(-{3} [^\n]+?) -{3}/, "$1 — already shown above ---") + tail;
    seen.add(key); return m;
  });
  text = text.replace(/[ \t]+(\r?\n)/g, "$1").replace(/\n{3,}/g, "\n\n");
  return { text, saved: Math.max(0, Math.ceil((orig.length - text.length) / 4)) };
}

// Formatting-only differences (CRLF, trailing spaces, leading/trailing blank
// lines) don't change what a prompt asks, so they must not cause a cache miss.
// Interior spacing and case are kept — they can matter (code, identifiers).
function normPrompt(p) { return String(p == null ? "" : p).replace(/\r\n?/g, "\n").replace(/[ \t]+\n/g, "\n").trim(); }

// sha256(engine|model|prompt) → stable cache key. Prompt already contains any
// inlined file content, so this keys on the exact context state.
function cacheKey(engine, model, prompt) {
  return crypto.createHash("sha256").update(String(engine) + "\u001f" + String(model) + "\u001f" + normPrompt(prompt)).digest("hex").slice(0, 32);
}
function cacheDir(cwd) { return path.join(cwd, ".nexus", "cache"); }
function cacheGet(cwd, key, ttlMs) {
  try { const f = path.join(cacheDir(cwd), key + ".json"); const st = fs.statSync(f); if (ttlMs && Date.now() - st.mtimeMs > ttlMs) return null; return JSON.parse(fs.readFileSync(f, "utf8")); } catch (_) { return null; }
}
function cachePut(cwd, key, rec) {
  try { const d = cacheDir(cwd); fs.mkdirSync(d, { recursive: true }); fs.writeFileSync(path.join(d, key + ".json"), JSON.stringify(rec)); return true; } catch (_) { return false; }
}
function cacheClear(cwd) { try { fs.rmSync(cacheDir(cwd), { recursive: true, force: true }); return true; } catch (_) { return false; } }
function cacheStats(cwd) {
  const s = { entries: 0, hits: 0, savedTok: 0, savedCost: 0 };
  try {
    for (const f of fs.readdirSync(cacheDir(cwd))) {
      if (!f.endsWith(".json")) continue; s.entries++;
      try { const r = JSON.parse(fs.readFileSync(path.join(cacheDir(cwd), f), "utf8")); const h = r.hits || 0; s.hits += h; s.savedTok += ((r.inTok || 0) + (r.outTok || 0)) * h; s.savedCost += (r.cost || 0) * h; } catch (_) {}
    }
  } catch (_) {}
  return s;
}
// Lossless re-read supersession. When a file is read again and its full current
// contents are now in the latest tool message, any EARLIER full copy of that same
// file in the message history is pure waste — the model holds the newest version,
// and the stale copy both costs tokens and risks reasoning over outdated code.
// This stubs the older copy IN PLACE and returns the estimated tokens saved.
//   msgs    : the running [{role, content}] array (appended-to / mutated in place)
//   snap    : a Map(absPath -> index in msgs holding that file's full contents)
//   fp      : absolute path just read
//   rel     : short path to name in the stub
//   newIdx  : index of the just-pushed read observation (defaults to last msg)
// Returns tokens saved (0 if nothing was superseded). Only ever shrinks history,
// never drops the newest copy, so it cannot remove context the model still needs.
function supersedeReread(msgs, snap, fp, rel, newIdx) {
  if (!Array.isArray(msgs) || !snap || !fp) return 0;
  const oi = newIdx == null ? msgs.length - 1 : newIdx;
  const prev = snap.get(fp);
  let saved = 0;
  if (prev != null && prev < oi && msgs[prev] && msgs[prev].role === "tool" &&
      typeof msgs[prev].content === "string" && msgs[prev].content.length > 160 &&
      !msgs[prev].content.startsWith("[superseded")) {
    const stub = "[superseded — a later re-read of " + (rel || fp) + " below holds the current contents]";
    saved = Math.max(0, Math.ceil((msgs[prev].content.length - stub.length) / 4));
    msgs[prev].content = stub;
  }
  snap.set(fp, oi);
  return saved;
}

// Command output often repeats one line many times (retry loops, "waiting…",
// identical warnings). Runs of 4+ identical consecutive lines keep the first
// copy plus an exact count, so nothing is lost: the model still knows the
// line and how many times it appeared. Only applied to command OUTPUT fields,
// never to file contents (an edit needs the exact text). Returns { text, saved }.
function collapseRepeats(text, min) {
  min = min || 4;
  if (!text || typeof text !== "string" || text.indexOf("\n") < 0) return { text: text || "", saved: 0 };
  const lines = text.split("\n"), out = [];
  for (let i = 0; i < lines.length;) {
    let j = i + 1;
    while (j < lines.length && lines[j] === lines[i]) j++;
    const n = j - i;
    if (n >= min && lines[i].trim()) { out.push(lines[i], "[previous line repeated " + (n - 1) + " more times]"); }
    else for (let k = i; k < j; k++) out.push(lines[k]);
    i = j;
  }
  const t = out.join("\n");
  return { text: t, saved: Math.max(0, Math.ceil((text.length - t.length) / 4)) };
}
const OUTPUT_FIELDS = ["stdout", "stderr", "output", "log", "tail"];
function collapseToolOutput(result) {
  let saved = 0;
  if (!result || typeof result !== "object") return 0;
  for (const f of OUTPUT_FIELDS) if (typeof result[f] === "string") { const r = collapseRepeats(result[f]); if (r.saved > 0) { result[f] = r.text; saved += r.saved; } }
  return saved;
}

// Read-only tool memo: when the agent repeats the SAME read-only call (same
// tool, same args) and nothing that could change files ran in between, the
// answer is byte-identical to one already in its context. Send a pointer
// instead of the duplicate. The earlier copy is checked to still be in history
// unchanged (not stubbed or trimmed), so the pointer always resolves.
const READ_ONLY = new Set(["search", "grep", "find", "find_files", "glob", "list_dir", "list", "ls", "repo_map", "outline", "file_outline", "symbols", "find_symbol", "find_references", "references", "module_graph", "import_graph", "json_query", "read_symbol"]);
function createToolMemo() {
  const seen = new Map();
  return {
    // Before pushing an observation: returns a pointer string to use instead, or null.
    lookup(name, args, obs, msgs) {
      if (!READ_ONLY.has(name)) { seen.clear(); return null; }      // anything else may have changed files
      const key = name + "\x00" + JSON.stringify(args || {}); // model key order differs → just a miss, never a wrong hit
      const prev = seen.get(key);
      if (prev && msgs[prev.idx] && msgs[prev.idx].content === obs && obs.length > 200) return "[identical to the earlier " + name + " result above — nothing has changed since]";
      seen.set(key, { idx: msgs.length });
      return null;
    },
    clear() { seen.clear(); },
  };
}

module.exports = { stripTermNoise, normPrompt, squeezeContext, cacheKey, cacheGet, cachePut, cacheClear, cacheStats, supersedeReread, collapseRepeats, collapseToolOutput, createToolMemo, READ_ONLY };
