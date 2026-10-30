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
  if (Array.isArray(src)) {
    // a plain list of lines (no trailing \n on any but the last) was stored as-is and Jupyter
    // glued them into one line ("import osimport sys"); nbformat's own arrays keep their \n
    if (src.length > 1 && src.slice(0, -1).every((s) => !String(s).endsWith("\n"))) return toSourceLines(src.join("\n"));
    return src.map((s) => String(s));
  }
  const text = String(src == null ? "" : src);
  if (text === "") return [];
  const parts = text.split("\n");
  return parts.map((line, i) => (i < parts.length - 1 ? line + "\n" : line)).filter((_, i, arr) => !(i === arr.length - 1 && arr[i] === ""));
}

// nbformat 4.5+ requires a unique cell id (1-64 chars of [A-Za-z0-9_-]).
function cellId(cells) {
  const used = new Set((cells || []).map((c) => c && c.id));
  for (;;) { const id = require("crypto").randomBytes(4).toString("hex"); if (!used.has(id)) return id; }
}

// Pure: a fresh cell of the given type.
function newCell(type, source, nb) {
  const t = type === "markdown" || type === "md" ? "markdown" : type === "raw" ? "raw" : "code";
  const cell = { cell_type: t, metadata: {}, source: toSourceLines(source) };
  if (nb && (nb.nbformat > 4 || (nb.nbformat === 4 && nb.nbformat_minor >= 5))) cell.id = cellId(nb.cells);
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
  if (!Object.prototype.hasOwnProperty.call(OPS, op)) return { error: "unknown op '" + op + "' — one of: read, edit, insert, delete" }; // own keys only: "constructor"/"__proto__" hit Object.prototype and fell through to delete
  const cells = nb.cells;
  const n = cells.length;
  if (a.index != null && a.index !== "" && !Number.isInteger(Number(a.index))) return { error: "index must be a whole number, got " + a.index };
  // a missing index stays missing (Number(null) and Number("") are 0, so edit/delete hit cell 0); -1 = last cell
  const at0 = a.index == null || a.index === "" ? NaN : Number(a.index);
  const idx = at0 < 0 ? n + at0 : at0;

  if (op === "read" || op === "view" || op === "show") {
    if (a.index != null && a.index !== "") {
      const i = idx;
      if (!(i >= 0 && i < n)) return { error: "index " + a.index + " out of range (0.." + (n - 1) + ")" };
      return { nb, result: { nbformat: nb.nbformat || null, cellCount: n, cell: summarizeCell(cells[i], i, a.max) } };
    }
    return { nb, result: { nbformat: nb.nbformat || null, cellCount: n, cells: cells.map((c, i) => summarizeCell(c, i, a.max)) } };
  }

  if (op === "edit" || op === "replace") {
    const i = idx;
    if (!(i >= 0 && i < n)) return { error: "edit needs a valid 'index' (0.." + (n - 1) + ")" };
    if (a.source == null && a.content == null) return { error: "edit needs 'source' (the new cell contents)" };
    cells[i].source = toSourceLines(a.source != null ? a.source : a.content);
    if (cells[i].cell_type === "code") { cells[i].outputs = []; cells[i].execution_count = null; } // edited code is now unexecuted
    return { nb, result: { ok: true, op: "edit", index: i, cellCount: n, cell: summarizeCell(cells[i], i, a.max) } };
  }

  if (op === "insert" || op === "add" || op === "append") {
    const cell = newCell(a.cell_type || a.type || "code", a.source != null ? a.source : a.content, nb);
    let at = isNaN(at0) || op === "append" ? n : at0 < 0 ? n + 1 + at0 : at0; // -1 = after the last cell
    if (!(at >= 0 && at <= n)) return { error: "insert index " + a.index + " out of range (0.." + n + ")" };
    cells.splice(at, 0, cell);
    return { nb, result: { ok: true, op: "insert", index: at, cellCount: cells.length, cell: summarizeCell(cell, at, a.max) } };
  }

  // delete / remove
  const i = idx;
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
  try { nb = JSON.parse(fs.readFileSync(abs, "utf8").replace(/^\uFEFF/, "")); }
  catch (e) { return { error: "cannot read/parse notebook: " + ((e && e.message) || e) }; }

  let applied; // a null or non-object cell in a hand-edited notebook threw out of the "never throws" tool
  try { applied = applyNotebookOp(nb, a); } catch (e) { return { error: "malformed notebook: " + ((e && e.message) || e) }; }
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
