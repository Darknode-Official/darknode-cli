"use strict";
// Pure helpers for the local (Ollama / OpenAI-compatible) agent loop in darknode.js.
//
//   capObservation(result, max) -> JSON string of a tool result, at most ~max chars,
//                                  cut inside its longest string field and SAID so
//   compactTail(msgs, keep)     -> the last `keep` messages after the system message,
//                                  starting at a user message when there is one, else
//                                  at the model's own step: never an orphaned tool result
//   wantsToolWork(text)         -> true when the request clearly asks for work on the
//                                  project (a file/path, or a verb aimed at code, files,
//                                  the repo or the shell) and doesn't rule tools out
//   forbidsTools(text)          -> the user said not to use tools
//   sameText(a, b)              -> b already says a (whitespace/case-insensitive), so a
//                                  final step's `thought` needn't be shown above it

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

// The "look before you answer" reminder for a local model that answers a project question
// from memory. A plain question ("explain closures", "write a haiku", "what is 2+2") must
// never be pushed into tool calls: the model then invents one (a pointless grep, or an
// edit) just to satisfy the reminder. So it fires only for clear project work.
const NO_TOOLS = /\b(?:no|without(?:\s+using)?|don'?t\s+(?:use|call|run)|do\s+not\s+(?:use|call|run)|never\s+(?:use|call)|avoid(?:\s+using)?)\s+(?:any\s+)?tools?\b|\bno\s+tool\s+(?:calls?|use)\b/i;
function forbidsTools(text) { return NO_TOOLS.test(String(text || "")); }
const FILE_REF = /(?:^|[\s"'`(@])(?:\.{0,2}\/)?[\w.-]+\/[\w./-]+|\b[\w-]+\.(?:m?js|cjs|tsx?|jsx|py|go|rs|rb|java|kt|c|h|cc|cpp|hpp|cs|php|sh|bash|json|ya?ml|toml|ini|cfg|conf|md|txt|html?|css|scss|sql|lock|env|xml|gradle|dockerfile)\b|\b(?:Makefile|Dockerfile|README)\b/i;
const FS_WORK = /\b(?:run|execute|install|build|compile|test|lint|commit|grep|search|find|list|read|open|show|edit|modify|change|fix|refactor|rename|delete|remove|create|write|add|save|update|implement|debug|scan|check|look\s+at|inspect)\b[^.?!\n]*\b(?:files?|folders?|director(?:y|ies)|dirs?|repo(?:sitory)?|project|codebase|workspace|branch(?:es)?|commits?)\b/i;
const CODE_WORK = /\b(?:run|execute|install|build|compile|test|lint|edit|modify|change|fix|refactor|rename|delete|remove|update|debug|scan|check|look\s+at|inspect)\b[^.?!\n]*\b(?:code|functions?|class(?:es)?|modules?|scripts?|tests?|commands?|shell|packages?|dependenc(?:y|ies))\b/i;
const HERE = /\b(?:in|from|of|at|inside)\s+(?:this|the|my|our)\s+(?:repo(?:sitory)?|project|codebase|folder|directory|code|workspace)\b|\b(?:files?|folders?)\s+here\b/i;
function wantsToolWork(text) {
  const t = String(text || "");
  if (!t.trim() || forbidsTools(t)) return false;
  return FILE_REF.test(t) || FS_WORK.test(t) || CODE_WORK.test(t) || HERE.test(t);
}
const NO_TOOLS_REPLY = "Not run: the user asked you not to use tools for this. Answer directly with action \"final\".";
const NUDGE = "You answered without looking at the project. This request is about the files here: use a tool first (read_file, list_dir, search or run_command), then give your final answer.";

const _norm = (x) => String(x == null ? "" : x).replace(/\s+/g, " ").trim().toLowerCase();
function sameText(a, b) { const x = _norm(a), y = _norm(b); return !!x && !!y && y.includes(x); }

module.exports = { capObservation, compactTail, wantsToolWork, forbidsTools, sameText, NUDGE, NO_TOOLS_REPLY };
