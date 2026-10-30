"use strict";
// Shell health for engine turns (/fixshell, /doctor). Linux execve refuses (E2BIG) any single
// argv/env string over MAX_ARG_STRLEN (128 KB) and the whole argv+env over ARG_MAX, and then no
// tool shell can start. Each engine turn is a fresh process resumed by session id, so repairing the
// environment and the engine's shell snapshots here fixes the next turn without losing the chat.
const fs = require("fs"), path = require("path"), os = require("os");

const MAX_STR = 128 * 1024; // MAX_ARG_STRLEN on Linux
const SAFE_STR = 100 * 1024; // keep argv/env strings well under the limit
const SNAP_WARN = 64 * 1024; // a healthy shell snapshot is a few KB; nvm/bash-completion can push it past 100 KB

const bytes = (s) => Buffer.byteLength(String(s == null ? "" : s));
const fmtKB = (n) => (n < 1024 ? n + " B" : (n / 1024).toFixed(1) + " KB");

// size of an environment as execve sees it ("K=V\0" per entry), plus the largest entries
function envReport(env) {
  const rows = Object.keys(env || {}).map((k) => ({ name: k, size: bytes(k) + 1 + bytes(env[k]) + 1 }));
  rows.sort((a, b) => b.size - a.size);
  const total = rows.reduce((n, r) => n + r.size, 0);
  return { total, count: rows.length, largest: rows.slice(0, 5), oversize: rows.filter((r) => r.size > SAFE_STR).map((r) => r.name) };
}

// drop repeated and empty entries from a PATH-style list, keeping first-seen order
function dedupeList(v, sep) {
  const seen = new Set(), out = [];
  for (const p of String(v || "").split(sep)) { if (!p || seen.has(p)) continue; seen.add(p); out.push(p); }
  return out.join(sep);
}

// repair env in place: dedupe *PATH lists, drop any entry too large to exec. Returns what changed.
function repairEnv(env, opts) {
  opts = opts || {};
  const sep = opts.sep || path.delimiter, limit = opts.limit || SAFE_STR;
  const deduped = [], removed = [];
  for (const k of Object.keys(env)) {
    if (!/PATH$/.test(k) || typeof env[k] !== "string") continue;
    const v = dedupeList(env[k], sep);
    if (v !== env[k]) { deduped.push({ name: k, saved: bytes(env[k]) - bytes(v) }); env[k] = v; }
  }
  for (const k of Object.keys(env)) {
    if (k === "PATH") continue; // never drop PATH itself; deduping is all we do to it
    if (bytes(k) + bytes(env[k]) + 2 > limit) { removed.push({ name: k, size: bytes(env[k]) }); delete env[k]; }
  }
  return { deduped, removed };
}

const snapDir = (home) => path.join(home || os.homedir(), ".claude", "shell-snapshots");

function listSnapshots(dir, _fs) {
  _fs = _fs || fs;
  let names = [];
  try { names = _fs.readdirSync(dir); } catch (_) { return []; }
  const out = [];
  for (const n of names) {
    if (!/^snapshot-.*\.sh$/.test(n)) continue;
    try { const st = _fs.statSync(path.join(dir, n)); if (st.isFile()) out.push({ file: n, size: st.size, mtime: st.mtimeMs }); } catch (_) {}
  }
  return out.sort((a, b) => b.size - a.size);
}

// remove oversized snapshots (or all with opts.all). The engine writes a fresh one on its next start.
function cleanSnapshots(dir, opts, _fs) {
  _fs = _fs || fs; opts = opts || {};
  const removed = [];
  for (const s of listSnapshots(dir, _fs)) {
    if (!opts.all && s.size <= SNAP_WARN) continue;
    try { _fs.unlinkSync(path.join(dir, s.file)); removed.push(s); } catch (_) {}
  }
  return removed;
}

// does this text look like a tool shell that could not start because of E2BIG?
const isE2big = (t) => /\bE2BIG\b|argument list too long/i.test(String(t || ""));

module.exports = { MAX_STR, SAFE_STR, SNAP_WARN, bytes, fmtKB, envReport, dedupeList, repairEnv, snapDir, listSnapshots, cleanSnapshots, isE2big };
