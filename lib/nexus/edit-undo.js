"use strict";
// undo_edit — let the agent take back its OWN last change to one file, without
// a git checkpoint round-trip and without touching anything else it did.
// Before every write_file / edit_file / multi_edit / apply_patch the host
// snapshots the target files; after it, only files that really changed are
// recorded. undo restores the file as it was before that change (deleting it
// if the change created it) — but only if nobody has touched it since, so it
// can never clobber a later edit (the user's or the agent's).

const fs = require("fs");
const path = require("path");

const MAX_ENTRIES = 200;
const MAX_BYTES = 2 * 1024 * 1024; // don't keep copies of huge files in memory

const readOrNull = (fp) => { try { const st = fs.statSync(fp); if (!st.isFile() || st.size > MAX_BYTES) return undefined; return fs.readFileSync(fp, "utf8"); } catch (_) { return null; } };

function createEditUndo() {
  const stack = []; // { fp, before (null = did not exist), after, at }
  return {
    // Snapshot before a write. Returns a token for commit(); files too big to keep are skipped.
    snapshot(fps) {
      const snap = [];
      for (const fp of new Set(fps || [])) { const before = readOrNull(fp); if (before !== undefined) snap.push({ fp, before }); }
      return snap;
    },
    // After the write: record each file whose content actually changed.
    commit(snap) {
      let n = 0;
      for (const s of snap || []) {
        const after = readOrNull(s.fp);
        if (after === undefined || after === s.before) continue;
        stack.push({ fp: s.fp, before: s.before, after, at: Date.now() }); n++;
      }
      while (stack.length > MAX_ENTRIES) stack.shift();
      return n;
    },
    // Undo the most recent recorded change to fp.
    undo(fp, opts) {
      opts = opts || {};
      let i = stack.length - 1;
      while (i >= 0 && stack[i].fp !== fp) i--;
      if (i < 0) return { error: "no edit of this file to undo this session (only write_file/edit_file/multi_edit/apply_patch changes are tracked)" };
      const e = stack[i];
      const now = readOrNull(fp);
      if (now !== e.after && !opts.force) return { error: "the file changed after that edit (by you or the user) — re-read it and edit it back instead, or pass force:true to restore the old version anyway" };
      try {
        if (e.before === null) fs.rmSync(fp, { force: true });
        else { fs.mkdirSync(path.dirname(fp), { recursive: true }); fs.writeFileSync(fp, e.before); }
      } catch (err) { return { error: err.message }; }
      stack.splice(i, 1);
      const remaining = stack.filter((x) => x.fp === fp).length;
      return { ok: true, restored: e.before === null ? "deleted (the edit had created it)" : "previous version (" + e.before.split("\n").length + " lines)", olderUndos: remaining };
    },
    list() { return stack.map((e) => ({ fp: e.fp, at: e.at, created: e.before === null })); },
    clear() { stack.length = 0; },
  };
}

module.exports = { createEditUndo };
