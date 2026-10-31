"use strict";
// Pure helpers for the local (Ollama / OpenAI-compatible) agent loop in darknode.js.
//
//   capObservation(result, max) -> JSON string of a tool result, at most ~max chars,
//                                  cut inside its longest string field and SAID so
//   compactTail(msgs, keep)     -> the last `keep` messages after the system message,
//                                  starting at a user message when there is one, else
//                                  at the model's own step: never an orphaned tool result

// A plain .slice() of the JSON cut the tail off silently: read_file caps a file at
// 10,000 chars, but JSON escaping (\n, \", \\) can push the observation past the
// cap, so the model lost the end of the file AND the note telling it where to
// continue from, with nothing saying anything was missing.
function capObservation(result, max) {
  const s = JSON.stringify(result);
  if (typeof s !== "string") return String(s);
  if (s.length <= max) return s;
  if (result && typeof result === "object" && !Array.isArray(result)) {
    let key = null;
    for (const k of Object.keys(result)) if (typeof result[k] === "string" && (key === null || result[k].length > result[key].length)) key = k;
    if (key !== null) {
      const v = result[key], c = Object.assign({}, result);
      let keepLen = v.length;
      for (let i = 0; i < 6; i++) {
        keepLen = Math.max(0, Math.floor(keepLen * (max / JSON.stringify(c).length)) - 64);
        c[key] = v.slice(0, keepLen).replace(/[\uD800-\uDBFF]$/, "") + "\n…[" + (v.length - keepLen) + " more chars of " + key + " cut to fit — ask for less (offset/limit, a narrower command) to see them]";
        const out = JSON.stringify(c);
        if (out.length <= max) return out;
      }
    }
  }
  const n = s.length - max;
  return s.slice(0, max) + " …[" + n + " more chars of this tool result cut to fit]";
}

function compactTail(msgs, keep) {
  const tail = (msgs || []).slice(1).slice(-keep);
  let i = tail.findIndex((m) => m && m.role === "user");
  if (i < 0) i = tail.findIndex((m) => m && m.role === "assistant"); // one long turn: keep each tool result with the call that produced it
  return i < 0 ? [] : tail.slice(i);
}

module.exports = { capObservation, compactTail };
