"use strict";
// ================= batch: many READ-ONLY lookups in ONE tool call =================
// The agent often investigates by firing lots of tiny, separate tool calls — read one
// file, grep one pattern, read another file, list a dir — and each is its own
// round-trip that burns tokens and clutters the transcript. `batch` lets the model ask
// for several read-only operations at once and get every result back in a single
// observation, labeled by which op produced it.
//
// It does NOT reimplement reading/searching: each sub-op is routed through the SAME tool
// dispatcher the agent already uses (read_file / search / find / list_dir), so behaviour,
// sandboxing and truncation stay identical to calling those tools directly.
//
// SAFETY: batch is deliberately read-only. It maps each sub-op onto a fixed whitelist of
// read tool names and refuses anything else, so writes/exec/network can never slip through
// a batch even though the injected dispatcher is capable of them.
//
// LIMITS (so one batch can never blow the context window):
//   MAX_OPS         20     ops beyond this are dropped (reported as opsDropped)
//   MAX_OP_CHARS    12000  each op's text output is capped to this
//   MAX_TOTAL_CHARS 60000  combined output budget across the whole batch
// Exposed agent tool (wired in darknode.js deviceTool): batch.

const MAX_OPS = 20;
const MAX_OP_CHARS = 12000;
const MAX_TOTAL_CHARS = 60000;

// op `kind` (what the model writes) -> the canonical read-only tool name we dispatch.
// Anything not in this table is rejected per-op (reported, never executed).
const OP_ALIASES = {
  read: "read_file", read_file: "read_file", cat: "read_file", file: "read_file",
  search: "search", grep: "search",
  glob: "find", find: "find", find_files: "find",
  list: "list_dir", list_dir: "list_dir", ls: "list_dir", dir: "list_dir",
};

// Turn whatever a sub-op's dispatcher returned into a single text block for the model.
// read_file -> its content (optionally line-sliced); search/find/list_dir -> their list,
// one per line; anything else -> compact JSON.
function resultToText(canonical, op, result) {
  if (result == null) return "";
  if (typeof result === "string") return result;
  if (canonical === "read_file" && typeof result.content === "string") {
    let text = result.content;
    const start = Number(op.start || op.from || op.startLine);
    const end = Number(op.end || op.to || op.endLine);
    if (start > 0 || end > 0) {
      const lines = text.split("\n");
      const a = start > 0 ? start - 1 : 0;
      const b = end > 0 ? end : lines.length;
      text = lines.slice(a, b).join("\n");
    }
    return text;
  }
  if (Array.isArray(result.matches)) return result.matches.join("\n");
  if (Array.isArray(result.files)) return result.files.join("\n");
  if (Array.isArray(result.items)) return result.items.join("\n");
  try { return JSON.stringify(result); } catch (_) { return String(result); }
}

// A short human/model-readable label of what the op was aimed at.
function targetOf(op) {
  return op.path || op.pattern || op.query || op.glob || op.name || op.dir || "";
}

// Build the argument object the dispatched read tool expects from a batch sub-op.
function argsFor(canonical, op) {
  if (canonical === "read_file") return { path: op.path || op.file };
  if (canonical === "search") return { pattern: op.pattern || op.query || op.q, path: op.path || op.dir };
  if (canonical === "find") return { glob: op.glob || op.pattern || op.name, path: op.path || op.dir };
  if (canonical === "list_dir") return { path: op.path || op.dir };
  return {};
}

// Core, pure-ish engine: run a list of read-only ops through `dispatch(name, args)` and
// return one consolidated, labeled, size-capped result. `dispatch` is injected so this is
// unit-testable with a fake; an invalid op is reported inline and never aborts the batch.
async function runBatch(ops, dispatch, limits) {
  limits = limits || {};
  const maxOps = limits.maxOps || MAX_OPS;
  const maxOpChars = limits.maxOpChars || MAX_OP_CHARS;
  const maxTotalChars = limits.maxTotalChars || MAX_TOTAL_CHARS;
  const list = Array.isArray(ops) ? ops : [];
  const requested = list.length;
  const run = list.slice(0, maxOps);
  const opsDropped = requested - run.length;

  const results = [];
  let used = 0;
  let truncated = false;

  for (let i = 0; i < run.length; i++) {
    const op = run[i] && typeof run[i] === "object" ? run[i] : {};
    const kind = String(op.op || op.kind || op.type || op.tool || "").toLowerCase();
    const canonical = OP_ALIASES[kind];
    if (!canonical) {
      results.push({ index: i, op: kind || "(none)", error: "unknown or non-read-only op — allowed: read, search, glob, list" });
      continue;
    }
    if (typeof dispatch !== "function") {
      results.push({ index: i, op: kind, error: "no dispatcher available" });
      continue;
    }
    let raw;
    try { raw = await dispatch(canonical, argsFor(canonical, op)); }
    catch (e) { results.push({ index: i, op: kind, target: targetOf(op), error: (e && e.message) || String(e) }); continue; }
    if (raw && typeof raw === "object" && typeof raw.error === "string") {
      results.push({ index: i, op: kind, target: targetOf(op), error: raw.error });
      continue;
    }
    let text = resultToText(canonical, op, raw);
    let opTrunc = false;
    if (text.length > maxOpChars) { text = text.slice(0, maxOpChars); opTrunc = true; }
    const remaining = maxTotalChars - used;
    if (remaining <= 0) { text = ""; opTrunc = true; truncated = true; }
    else if (text.length > remaining) { text = text.slice(0, remaining); opTrunc = true; truncated = true; }
    used += text.length;
    if (opTrunc) truncated = true;
    const entry = { index: i, op: kind, target: targetOf(op), output: text };
    if (opTrunc) entry.truncated = true;
    results.push(entry);
  }

  const out = { ops: requested, ran: results.length, results };
  if (opsDropped > 0) out.opsDropped = opsDropped;
  if (opsDropped > 0) out.note = "op limit is " + maxOps + " per batch; " + opsDropped + " extra op(s) were dropped";
  if (truncated) out.truncated = true;
  return out;
}

// Wiring entry point used by deviceTool. Accepts the raw tool args + cwd + the agent's own
// tool dispatcher, and returns the consolidated result object (or null if `dispatch` is a
// function we were not given — matching the browserTool "not ours" contract is unnecessary
// here since deviceTool only calls this for name === "batch").
async function batchTool(a, cwd, dispatch) {
  a = a || {};
  const ops = a.ops || a.operations || a.calls || a.batch || a.reads;
  if (!Array.isArray(ops) || !ops.length) {
    return { error: "batch needs a non-empty 'ops' array, each like {op:'read',path:'x'} / {op:'search',pattern:'y'} / {op:'glob',glob:'**/*.js'} / {op:'list',path:'src'}" };
  }
  return await runBatch(ops, dispatch, null);
}

module.exports = {
  batchTool, runBatch,
  // exported for tests / wiring
  OP_ALIASES, resultToText, argsFor, targetOf,
  MAX_OPS, MAX_OP_CHARS, MAX_TOTAL_CHARS,
};
