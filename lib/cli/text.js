"use strict";
// Small pure text helpers used throughout the CLI/agent. Dependency-free, tested.

// Collapse whitespace to single spaces and truncate to n chars with an ellipsis.
function oneline(s, n) { s = String(s || "").replace(/\s+/g, " ").trim(); return s.length > (n || 44) ? s.slice(0, (n || 44) - 1) + "…" : s; }

// Pull the first JSON array or object out of noisy model text; fallback on failure.
function extractJson(text, fallback) {
  const s = String(text || "").trim();
  // The whole reply is usually just the JSON (verdict object, task array) — parse it
  // first so a `reason` string containing "[...]" isn't mistaken for an array.
  if (s) { try { const w = JSON.parse(s); if (w && typeof w === "object") return w; } catch (_) {} }
  const arr = s.match(/\[[\s\S]*\]/), obj = s.match(/\{[\s\S]*\}/);
  // When both shapes appear in surrounding prose, prefer whichever opens FIRST, so the
  // outer container wins over a bracket/brace nested inside one of its string values.
  const order = (arr && obj) ? (arr.index <= obj.index ? [arr, obj] : [obj, arr]) : [arr, obj];
  for (const m of order) if (m) { try { return JSON.parse(m[0]); } catch (_) {} }
  return fallback;
}

// Longest common prefix of a list of strings ("" for none / no shared prefix).
function commonPrefix(strings) {
  if (!strings || !strings.length) return "";
  let p = String(strings[0]);
  for (let i = 1; i < strings.length; i++) {
    const s = String(strings[i]); let j = 0;
    while (j < p.length && j < s.length && p[j] === s[j]) j++;
    p = p.slice(0, j); if (!p) break;
  }
  return p;
}

// @path Tab-completion decision (pure). `matches` is the already-filtered,
// sorted list of directory-entry names that start with `bpart`. Returns null
// when nothing matches, a unique completion, or — when several match — the
// longest common prefix so completion advances bash-style without silently
// committing to the first alphabetical entry. The caller does the fs I/O and
// decides a trailing "/" vs " " for a unique hit.
function completePath(matches, bpart) {
  if (!matches || !matches.length) return null;
  if (matches.length === 1) return { value: matches[0], unique: true };
  return { value: commonPrefix(matches), unique: false, count: matches.length };
}
module.exports = { oneline, extractJson, commonPrefix, completePath };
