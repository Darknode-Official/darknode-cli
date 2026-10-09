"use strict";
// ================= filestate: stale-write guard =================
// Coding agents clobber work when they do a FULL-FILE overwrite (write_file) based on a copy
// of the file they read earlier, while something else — the user's editor, a formatter, a
// `git checkout`, a parallel sub-agent — changed that file on disk in the meantime. The
// agent's write silently throws those changes away.
//
// filestate remembers a content hash for every file the agent READS. Before a full overwrite
// it checks whether the file on disk still matches what the agent last saw; if it drifted, the
// write is refused so the agent re-reads the current content first and doesn't destroy the
// external change. It is scoped to files the agent actually read — a brand-new file, or one it
// never looked at, is never "stale".
//
// edit_file / multi_edit / apply_patch do NOT need this guard: they read the file fresh from
// disk at apply time and match on context, so they already edit the current content rather
// than a stale copy. Only the blind full overwrite is dangerous.
//
// Pure + dependency-free; the fs lives in the caller. Keyed by absolute path.
//
//   const fg = makeFileState();
//   fg.recordRead(absPath, content);            // after read_file
//   const s = fg.checkOverwrite(absPath, diskContent);  // before write_file
//   if (s.stale) refuse(s.reason);
//   fg.recordWrite(absPath, newContent);        // after any write/edit so knowledge is current

function hashStr(s) {
  s = s == null ? "" : String(s);
  let h = 5381;
  for (let i = 0; i < s.length; i++) h = ((h << 5) + h + s.charCodeAt(i)) | 0;
  return (h >>> 0).toString(36) + ":" + s.length;
}

function makeFileState() {
  const seen = new Map(); // absPath -> hash of content when the agent last saw it

  // Record what the agent now knows a file to contain (after reading or writing it).
  function recordRead(p, content) { if (p) seen.set(p, hashStr(content)); }
  const recordWrite = recordRead; // after we write, our knowledge is the content we just wrote

  // Decide whether a full overwrite of `p` would clobber an un-seen on-disk change.
  // diskContent is the file's CURRENT content (null/undefined if it doesn't exist yet).
  function checkOverwrite(p, diskContent) {
    if (!p || !seen.has(p)) return { stale: false };          // never read it → nothing to clobber
    if (diskContent == null) return { stale: false };          // vanished from disk → let the write recreate it
    if (seen.get(p) === hashStr(diskContent)) return { stale: false };
    return { stale: true, reason: "STALE WRITE BLOCKED: " + p + " changed on disk since you last read it (an editor, formatter, git, or another agent). Overwriting now would discard those changes. Re-read the file, then redo your edit on the current content — or use edit_file/apply_patch, which apply to the live file." };
  }

  function forget(p) { seen.delete(p); }
  function clear() { seen.clear(); }

  return { recordRead, recordWrite, checkOverwrite, forget, clear, _seen: seen };
}

module.exports = { makeFileState, hashStr };
