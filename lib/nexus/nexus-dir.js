"use strict";
// The project's .nexus/ holds session transcripts, usage, checkpoints and caches. Every
// place that creates it goes through ensureNexusDir so the folder carries its own
// ".gitignore" with "*": git ignores the whole folder without Nexus editing the user's
// own .gitignore, and `git add -A` can't commit a conversation by accident.
const fs = require("fs"), path = require("path");

function ignoreNexusDir(dir) {
  const gi = path.join(dir, ".gitignore");
  try { if (!fs.existsSync(gi)) fs.writeFileSync(gi, "*\n"); } catch (_) {}
}

// mkdir -p <cwd>/.nexus[/sub...] and make sure .nexus/.gitignore exists. Returns the
// created path. Throws like fs.mkdirSync (callers already wrap it).
function ensureNexusDir(cwd, ...sub) {
  const dir = path.join(cwd, ".nexus");
  const full = sub.length ? path.join(dir, ...sub) : dir;
  fs.mkdirSync(full, { recursive: true });
  ignoreNexusDir(dir);
  return full;
}

module.exports = { ensureNexusDir, ignoreNexusDir };
