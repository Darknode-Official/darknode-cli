"use strict";
// ================= notebook_edit: read & edit Jupyter .ipynb cells =================
// A .ipynb is JSON, but editing one as raw text is how an agent corrupts it — the cell
// `source` is an array of lines, code cells carry `outputs`/`execution_count`, and the
// nbformat envelope must survive. notebook_edit operates on the parsed notebook so the model
// can read a cell summary and then edit / insert / delete a cell by index without ever
// hand-splicing JSON. It does NOT execute cells (no kernel, zero-dep) — purely structural.
//
// SANDBOXING: like view-image.js, deviceTool injects its own rp() path-escape guard as
// `resolve`; the file read/write stay inside the project directory. applyNotebookOp is a pure
// function over the parsed notebook object (unit-tested); the wrapper does the fs I/O.
// Exposed agent tool (wired in darknode.js deviceTool): notebook_edit.

const OPS = { read: 1, view: 1, show: 1, edit: 1, replace: 1, insert: 1, add: 1, append: 1, delete: 1, remove: 1 };

// Pure: normalize source into nbformat's array-of-lines (each line keeps its trailing \n
// except the last), accepting either a string or an already-split array.
function toSourceLines(src) {
  if (Array.isArray(src)) return src.map((s) => String(s));
  const text = String(src == null ? "" : src);
  if (text === "") return [];
  const parts = text.split("\n");
  return parts.map((line, i) => (i < parts.length - 1 ? line + "\n" : line)).filter((_, i, arr) => !(i === arr.length - 1 && arr[i] === ""));
}

// Pure: a fresh cell of the given type.
function newCell(type, source) {
  const t = type === "markdown" || type === "md" ? "markdown" : "code";
  const cell = { cell_type: t, metadata: {}, source: toSourceLines(source) };
  if (t === "code") { cell.execution_count = null; cell.outputs = []; }
  return cell;
}

// Pure: a compact, model-readable summary of a cell (source joined + truncated, output count).
function summarizeCell(cell, index, max) {
  const src = Array.isArray(cell.source) ? cell.source.join("") : String(cell.source || "");
  const cap = max || 600;
  const o = { index, cell_type: cell.cell_type || "code", source: src.length > cap ? src.slice(0, cap) + "\n...[truncated]" : src };
  if (cell.cell_type === "code") { o.execution_count = cell.execution_count == null ? null : cell.execution_count; o.outputs = Array.isArray(cell.outputs) ? cell.outputs.length : 0; }
  return o;
}

// Pure: apply one op to a parsed notebook object. Returns { nb, result } (nb mutated for
// write ops) or { error }. `read` leaves nb untouched. Never throws on bad input.
function applyNotebookOp(nb, a) {
  a = a || {};
  if (!nb || typeof nb !== "object" || !Array.isArray(nb.cells)) return { error: "not a valid notebook (missing a 'cells' array)" };
  const op = String(a.op || a.action || "read").toLowerCase();
  if (!OPS[op]) return { error: "unknown op '" + op + "' — one of: read, edit, insert, delete" };
  const cells = nb.cells;
  const n = cells.length;

  if (op === "read" || op === "view" || op === "show") {
    if (a.index != null) {
      const i = Number(a.index);
      if (!(i >= 0 && i < n)) return { error: "index " + a.index + " out of range (0.." + (n - 1) + ")" };
      return { nb, result: { nbformat: nb.nbformat || null, cellCount: n, cell: summarizeCell(cells[i], i, a.max) } };
    }
    return { nb, result: { nbformat: nb.nbformat || null, cellCount: n, cells: cells.map((c, i) => summarizeCell(c, i, a.max)) } };
  }

  if (op === "edit" || op === "replace") {
    const i = Number(a.index);
    if (!(i >= 0 && i < n)) return { error: "edit needs a valid 'index' (0.." + (n - 1) + ")" };
    if (a.source == null && a.content == null) return { error: "edit needs 'source' (the new cell contents)" };
    cells[i].source = toSourceLines(a.source != null ? a.source : a.content);
    if (cells[i].cell_type === "code") { cells[i].outputs = []; cells[i].execution_count = null; } // edited code is now unexecuted
    return { nb, result: { ok: true, op: "edit", index: i, cell: summarizeCell(cells[i], i, a.max) } };
  }

  if (op === "insert" || op === "add" || op === "append") {
    const cell = newCell(a.cell_type || a.type || "code", a.source != null ? a.source : a.content);
    let at = a.index == null || op === "append" ? n : Number(a.index);
    if (!(at >= 0 && at <= n)) return { error: "insert index " + a.index + " out of range (0.." + n + ")" };
    cells.splice(at, 0, cell);
    return { nb, result: { ok: true, op: "insert", index: at, cellCount: cells.length, cell: summarizeCell(cell, at, a.max) } };
  }

  // delete / remove
  const i = Number(a.index);
  if (!(i >= 0 && i < n)) return { error: "delete needs a valid 'index' (0.." + (n - 1) + ")" };
  const removed = cells.splice(i, 1)[0];
  return { nb, result: { ok: true, op: "delete", index: i, cellCount: cells.length, removed: summarizeCell(removed, i, 120) } };
}

// Wiring entry point used by deviceTool. `a` raw args, `cwd` project root, `resolve` the
// injected rp() path guard, `opts.fs` a test seam. Reads the .ipynb, applies the op, and for
// write ops serializes it back (nbformat uses 1-space indent). Never throws → { error }.
function notebookEditTool(a, cwd, resolve, opts) {
  a = a || {}; opts = opts || {};
  const fs = opts.fs || require("fs");
  const path = require("path");
  const p = a.path || a.file || a.notebook;
  if (!p || typeof p !== "string") return { error: "notebook_edit needs a 'path' to a .ipynb file" };
  if (!/\.ipynb$/i.test(p)) return { error: "notebook_edit only edits .ipynb files: " + p };

  let abs;
  try { abs = resolve ? resolve(p) : path.resolve(cwd || ".", p); }
  catch (e) { return { error: (e && e.message) || String(e) }; }

  let nb;
  try { nb = JSON.parse(fs.readFileSync(abs, "utf8")); }
  catch (e) { return { error: "cannot read/parse notebook: " + ((e && e.message) || e) }; }

  const applied = applyNotebookOp(nb, a);
  if (applied.error) return applied;

  const op = String(a.op || a.action || "read").toLowerCase();
  if (op !== "read" && op !== "view" && op !== "show") {
    try { fs.writeFileSync(abs, JSON.stringify(applied.nb, null, 1) + "\n"); }
    catch (e) { return { error: "cannot write notebook: " + ((e && e.message) || e) }; }
    applied.result.path = p;
    applied.result.summary = "notebook_edit " + applied.result.op + " on " + path.basename(p) + " (cell " + applied.result.index + ", now " + (applied.result.cellCount != null ? applied.result.cellCount : "?") + " cells)";
  }
  return applied.result;
}

module.exports = {
  notebookEditTool, applyNotebookOp, toSourceLines, newCell, summarizeCell,
  OPS,
};
