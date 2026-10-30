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

// -> { body } | { skip: reason } | null (absent). A fresh clone can ship AGENTS.md as a symlink to
// ../../.ssh/id_rsa and its text would go to the model provider, so a target outside the repo is
// refused unless opts.allowOutside (a trusted repo); a skip is announced, never silent.
function readSmall(p, root, allowOutside) {
  try {
    const st = fs.statSync(p); if (!st.isFile()) return null;
    if (!allowOutside) { const rel = path.relative(fs.realpathSync(root), fs.realpathSync(p)); if (rel.startsWith("..") || path.isAbsolute(rel)) return { skip: "links outside the repo" }; }
    if (st.size > 512 * 1024) return { skip: "over 512 KB" };
    return { body: fs.readFileSync(p, "utf8").replace(/^\uFEFF/, "") };
  } catch (_) { return null; }
}

// -> { text, files: [{ rel, chars, cut }] }. text is "" when nothing was found.
function loadInstructions(cwd, opts) {
  opts = opts || {};
  const perFile = opts.perFile || PER_FILE, total = opts.total || TOTAL;
  const found = [];
  for (const d of chain(cwd)) for (const n of NAMES) found.push(path.join(d, n));
  found.push(path.join(path.resolve(cwd), ".nexus", "NEXUS.md"));
  const seen = new Set(), items = [], refused = [], root = repoRoot(cwd);
  for (const p of found) {
    const r = readSmall(p, root, opts.allowOutside);
    if (r && r.skip) { refused.push((path.relative(path.resolve(cwd), p) || path.basename(p)) + " (" + r.skip + ")"); continue; }
    const body = r && r.body;
    if (body == null || !body.trim()) continue;
    const key = crypto.createHash("sha1").update(body.trim()).digest("hex");
    if (seen.has(key)) continue;
    seen.add(key);
    items.push({ rel: path.relative(path.resolve(cwd), p) || path.basename(p), body });
  }
  // Spend the budget on the most specific files first (they win), so a large root file
  // can't push a nested file or NEXUS.md out; print in root-first order.
  let used = 0;
  for (let i = items.length - 1; i >= 0; i--) {
    const it = items[i];
    it.room = Math.max(0, Math.min(perFile, total - used));
    it.skip = it.room < Math.min(200, it.body.length); // a small file that fits is never skipped
    if (!it.skip) used += Math.min(it.body.length, it.room);
  }
  const files = [], parts = [];
  for (const { rel, body, room, skip } of items) {
    if (skip) { files.push({ rel, chars: body.length, cut: body.length }); continue; }
    const cut = Math.max(0, body.length - room);
    const shown = cut ? body.slice(0, room) + "\n[... " + cut + " more chars not shown - read " + rel + " for the rest]" : body;
    parts.push("--- " + rel + " ---\n" + shown.trim());
    files.push({ rel, chars: body.length, cut });
  }
  const skipped = files.filter((f) => f.cut === f.chars).map((f) => f.rel);
  const text = parts.length || refused.length ? "Project instructions (later files are more specific and win where they conflict):\n" + parts.join("\n\n")
    + (skipped.length ? "\n[not shown, over the size budget: " + skipped.join(", ") + "]" : "") + (refused.length ? "\n[not loaded: " + refused.join(", ") + "]" : "") : "";
  return { text, files };
}

module.exports = { loadInstructions, repoRoot, NAMES };
