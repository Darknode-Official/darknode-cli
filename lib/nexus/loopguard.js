"use strict";
// ================= loopguard: stop the agent getting stuck in a loop =================
// A classic failure mode of coding agents (worst on weaker/local models) is burning the
// whole step budget repeating itself: re-running the same failing command, re-reading the
// same file, or oscillating A,B,A,B between two actions without making progress. The model
// usually can't see that it's looping — each step looks locally reasonable.
//
// loopguard watches the stream of (tool, args, outcome) and, when it detects a stall,
// escalates: first a NUDGE (an injected system message telling the model exactly what it
// keeps doing and to try something different), then — if the same stall continues — a BREAK
// that ends the turn cleanly instead of spinning to the step cap.
//
// It is pure, dependency-free and deterministic, so it unit-tests with synthetic signatures.
//
//   const lg = makeLoopGuard();
//   const v = lg.note(lg.signature(name, args), ok);   // ok = did the action succeed?
//   if (v && v.action === "nudge") oMsgs.push({ role:"tool", content: v.message });
//   if (v && v.action === "break") { /* end the turn with v.message */ }

// How many times the SAME action may appear before it's a repeat-stall.
const REPEAT_LIMIT = 3;
// How many times the same action may FAIL before it's a failure-stall (lower — a failing
// action repeated even twice is already wasteful).
const FAIL_LIMIT = 2;
// Sliding window of recent actions we reason over.
const WINDOW = 8;

// Short, stable hash for long values (file contents, big commands) so two genuinely
// different large payloads don't collide just because their first chars match.
function hashStr(s) {
  let h = 5381;
  for (let i = 0; i < s.length; i++) h = ((h << 5) + h + s.charCodeAt(i)) | 0;
  return (h >>> 0).toString(36);
}

// Build a stable signature for a tool action: the tool name plus its most identifying
// argument(s). Two calls with the same signature are "the same action" for loop purposes.
function signature(name, args) {
  const a = args && typeof args === "object" ? args : {};
  const parts = [String(name || "").toLowerCase()];
  const KEYS = ["command", "path", "pattern", "query", "q", "glob", "find", "url", "to", "from", "name", "symbol", "kind"];
  for (const k of KEYS) {
    if (a[k] == null) continue;
    const v = String(a[k]);
    parts.push(k + "=" + (v.length > 120 ? "#" + hashStr(v) : v));
  }
  // content / patch bodies: hash so identical rewrites match, near-identical ones don't.
  for (const k of ["content", "patch", "diff", "replace"]) {
    if (a[k] != null) parts.push(k + "#" + hashStr(String(a[k])));
  }
  if (parts.length === 1) {
    try { parts.push("@" + hashStr(JSON.stringify(a))); } catch (_) { /* unserialisable */ }
  }
  return parts.join("|");
}

function makeLoopGuard(opts) {
  opts = opts || {};
  const repeatLimit = opts.repeatLimit || REPEAT_LIMIT;
  const failLimit = opts.failLimit || FAIL_LIMIT;
  const window = opts.window || WINDOW;
  const history = [];        // [{ sig, ok }]
  const nudged = new Set();  // signatures (or pattern keys) we've already nudged about

  // Detect A,B,A,B oscillation: the last 4 actions are two signatures alternating.
  function oscillating() {
    const n = history.length;
    if (n < 4) return null;
    const [w, x, y, z] = history.slice(n - 4).map((h) => h.sig);
    if (w === y && x === z && w !== x) return w + "~" + x;
    return null;
  }

  function note(sig, ok) {
    history.push({ sig, ok: !!ok });
    if (history.length > window) history.shift();

    // 1) same action failing again and again — the most wasteful stall.
    const fails = history.filter((h) => h.sig === sig && !h.ok).length;
    if (!ok && fails >= failLimit) {
      const key = "fail:" + sig;
      if (!nudged.has(key)) {
        nudged.add(key);
        return { action: "nudge", kind: "repeat-failure", sig,
          message: "LOOP GUARD: this exact action has now failed " + fails + " times and keeps producing the same error. Stop repeating it. Diagnose WHY it fails (re-read the file/error, check the path or syntax) and take a DIFFERENT action — or if it can't work, say so in your final answer." };
      }
      return { action: "break", kind: "repeat-failure", sig,
        message: "Stopped: the same action failed " + fails + " times even after a warning, so Nexus ended the turn instead of looping. Last error stands — try a different approach or ask the operator." };
    }

    // 2) same action repeated many times (succeeding or not) — spinning without progress.
    const repeats = history.filter((h) => h.sig === sig).length;
    if (repeats >= repeatLimit) {
      const key = "rep:" + sig;
      if (!nudged.has(key)) {
        nudged.add(key);
        return { action: "nudge", kind: "repeat", sig,
          message: "LOOP GUARD: you've run this same action " + repeats + " times in a row without making progress. It is not moving the task forward — change approach, move to the next step, or finish." };
      }
      return { action: "break", kind: "repeat", sig,
        message: "Stopped: the same action repeated " + repeats + " times with no progress even after a warning, so Nexus ended the turn." };
    }

    // 3) A,B,A,B oscillation between two actions.
    const osc = oscillating();
    if (osc) {
      const key = "osc:" + osc;
      if (!nudged.has(key)) {
        nudged.add(key);
        return { action: "nudge", kind: "oscillation", sig: osc,
          message: "LOOP GUARD: you're bouncing between the same two actions over and over. Break the cycle — step back, reconsider the plan, and take a genuinely different step." };
      }
      return { action: "break", kind: "oscillation", sig: osc,
        message: "Stopped: oscillating between the same two actions even after a warning, so Nexus ended the turn." };
    }

    return null;
  }

  function reset() { history.length = 0; nudged.clear(); }

  return { note, reset, signature, _history: history };
}

module.exports = { makeLoopGuard, signature, hashStr, REPEAT_LIMIT, FAIL_LIMIT, WINDOW };
