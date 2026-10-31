"use strict";
// Conversation branches (/branch): what a branch file stores and what loading
// one may change. Pure; the TUI does the file I/O.
//
//   branchFile(dir, name)            -> path of the branch's JSON file
//   branchRecord(state, redactBlock) -> the object written to that file
//   applyBranchSess(sess, saved)     -> adopt a loaded branch's context size only
const path = require("path");

const branchFile = (dir, name) => path.join(dir, String(name).replace(/[^\w.-]/g, "_") + ".json");

// readCache and fileSnap index the CURRENT oMsgs; fileSnap is a Map, which JSON
// turns into {} (then .clear()/.get() throw). Transcript blocks are written the
// way session.json writes them: ephemeral notes dropped, secrets redacted.
function branchRecord(st, redactBlock) {
  const { readCache: _rc, fileSnap: _fs, ...sess } = st.sess || {};
  const red = typeof redactBlock === "function" ? redactBlock : (b) => b;
  return { engine: st.engine, model: sess.model, transcript: (st.transcript || []).filter((b) => !(b && b.ephemeral)).map(red), sess, oMsgs: st.oMsgs || [], ts: st.ts || Date.now() };
}

// A branch is a conversation, not a session: the engine/model in use, the spend
// counters (and so the budget cap) and the per-model token totals stay as they
// are. Only the context size follows the restored conversation, and the
// read-dedup indices start empty because they described the other branch's oMsgs.
function applyBranchSess(sess, saved) {
  const ss = (saved && saved.sess) || {};
  sess.ctxUsed = typeof ss.ctxUsed === "number" && ss.ctxUsed >= 0 ? ss.ctxUsed : 0;
  sess.readCache = {};
  sess.fileSnap = new Map();
  return sess;
}

module.exports = { branchFile, branchRecord, applyBranchSess };
