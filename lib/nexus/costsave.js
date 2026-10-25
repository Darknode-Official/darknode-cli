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

module.exports = { stripTermNoise, normPrompt, squeezeContext, cacheKey, cacheGet, cachePut, cacheClear, cacheStats, supersedeReread };
