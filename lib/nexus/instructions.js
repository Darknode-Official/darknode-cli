"use strict";
// Project instruction files: the conventions files other coding agents read, so a
// repo set up for one of them works in Nexus without copying anything.
//
// Read, from the repo root down to the working directory (nested files apply to
// their subtree): AGENTS.md, CLAUDE.md, GEMINI.md, .cursorrules, then
// .nexus/NEXUS.md in the working directory. Later files are MORE specific and win
// where they disagree, and the header tells the model so. Identical files (CLAUDE.md
// is often a copy or symlink of AGENTS.md) are included once.
//
// These are instructions written by people, not learned memory. They come from the
// repo, which may be a fresh clone, so they only ever reach the prompt: nothing here
// can change permissions, policy or the safety floor.
//
// Everything is capped and a cut is announced in the text, never silent. (The loop
// used to send only the first 1000 chars of NEXUS.md and drop the rest unannounced.)
const fs = require("fs"), path = require("path"), crypto = require("crypto");

const NAMES = ["AGENTS.md", "CLAUDE.md", "GEMINI.md", ".cursorrules"];
const PER_FILE = 6000, TOTAL = 12000;

// The repo root: nearest ancestor with a .git entry, else the directory itself.
function repoRoot(dir) {
  for (let d = path.resolve(dir); ; d = path.dirname(d)) {
    if (fs.existsSync(path.join(d, ".git"))) return d;
    if (path.dirname(d) === d) return path.resolve(dir);
  }
}

// Directories from the repo root down to cwd, root first.
function chain(cwd) {
  const root = repoRoot(cwd), out = [];
  for (let d = path.resolve(cwd); ; d = path.dirname(d)) { out.unshift(d); if (d === root || path.dirname(d) === d) break; }
  return out;
}

function readSmall(p) {
  try { const st = fs.statSync(p); if (!st.isFile() || st.size > 512 * 1024) return null; return fs.readFileSync(p, "utf8").replace(/^﻿/, ""); } catch (_) { return null; }
}

// -> { text, files: [{ rel, chars, cut }] }. text is "" when nothing was found.
function loadInstructions(cwd, opts) {
  opts = opts || {};
  const perFile = opts.perFile || PER_FILE, total = opts.total || TOTAL;
  const found = [];
  for (const d of chain(cwd)) for (const n of NAMES) found.push(path.join(d, n));
  found.push(path.join(path.resolve(cwd), ".nexus", "NEXUS.md"));
  const seen = new Set(), files = [], parts = [];
  let used = 0;
  for (const p of found) {
    const body = readSmall(p);
    if (body == null || !body.trim()) continue;
    const key = crypto.createHash("sha1").update(body.trim()).digest("hex");
    if (seen.has(key)) continue;
    seen.add(key);
    const rel = path.relative(path.resolve(cwd), p) || path.basename(p);
    const room = Math.max(0, Math.min(perFile, total - used));
    if (room < 200) { files.push({ rel, chars: body.length, cut: body.length }); continue; }
    const cut = Math.max(0, body.length - room);
    const shown = cut ? body.slice(0, room) + "\n[... " + cut + " more chars not shown - read " + rel + " for the rest]" : body;
    parts.push("--- " + rel + " ---\n" + shown.trim());
    files.push({ rel, chars: body.length, cut });
    used += Math.min(body.length, room);
  }
  const skipped = files.filter((f) => f.cut === f.chars).map((f) => f.rel);
  const text = parts.length ? "Project instructions (later files are more specific and win where they conflict):\n" + parts.join("\n\n")
    + (skipped.length ? "\n[not shown, over the size budget: " + skipped.join(", ") + "]" : "") : "";
  return { text, files };
}

module.exports = { loadInstructions, repoRoot, NAMES };
