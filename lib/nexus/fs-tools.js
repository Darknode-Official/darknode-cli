"use strict";
// File-system tools the agent uses to move things around. The plain fs calls
// they replace had sharp edges: move/copy silently overwrote an existing
// destination (data loss), copy failed on folders, move failed across disks,
// delete reported success for a path that never existed (hiding a typo), and
// list_dir cut off at 200 entries without saying so. Every function takes an
// `rp` that resolves a path inside the project (the host's path jail).

const fs = require("fs");
const path = require("path");

const SKIP_DIR = /^(\.git|node_modules|dist|build|out|coverage|\.nexus|\.cache|\.next|__pycache__|\.venv|venv|target)$/;
const exists = (p) => { try { fs.lstatSync(p); return true; } catch (_) { return false; } };
const human = (n) => n < 1024 ? n + " B" : n < 1048576 ? (n / 1024).toFixed(1) + " KB" : (n / 1048576).toFixed(1) + " MB";

// delete/move act on a symlink itself, like rm/mv: rp() canonicalises, so `delete link` removed
// the link's TARGET (and `delete linkdir recursive` the whole real folder). The link's parent
// folder is still jail-checked.
function linkOrRp(raw, cwd, rp) {
  if (raw == null) return rp(raw);
  const lex = path.resolve(cwd, String(raw));
  try { if (fs.lstatSync(lex).isSymbolicLink()) return path.join(rp(path.dirname(lex)), path.basename(lex)); } catch (_) {}
  return rp(raw);
}

// The project root as rp() sees it (the real path). Messages are relative to it, so a project
// reached through a symlink doesn't report "../../real/proj/x".
function realRoot(cwd, rp) { try { return rp("."); } catch (_) { return path.resolve(cwd); } }

// Resolve the destination like `mv`/`cp`: into an existing folder keeps the name.
function destOf(src, dst) {
  try { if (fs.statSync(dst).isDirectory() && !(fs.statSync(src).isDirectory() && path.resolve(src) === path.resolve(dst))) return path.join(dst, path.basename(src)); } catch (_) {}
  return dst;
}

function moveTool(a, cwd, rp) {
  const root = realRoot(cwd, rp);
  let src, dst;
  try { src = linkOrRp(a.from || a.src || a.source, cwd, rp); dst = rp(a.to || a.dest || a.destination); } catch (e) { return { error: e.message }; }
  if (!exists(src)) return { error: "nothing at " + path.relative(root, src) };
  dst = destOf(src, dst);
  if (path.resolve(src) === path.resolve(dst)) return { error: "source and destination are the same" };
  if ((dst + path.sep).startsWith(src + path.sep)) return { error: "cannot move a folder into itself" };
  // Foo.js -> foo.js on a case-insensitive disk (macOS, Windows): dst "exists" because it IS src
  const sameFile = src.toLowerCase() === dst.toLowerCase() && (() => { try { const x = fs.lstatSync(src), y = fs.lstatSync(dst); return x.ino === y.ino && x.dev === y.dev; } catch (_) { return false; } })();
  if (exists(dst) && !a.overwrite && !sameFile) return { error: path.relative(root, dst) + " already exists — pass overwrite:true to replace it" };
  try {
    fs.mkdirSync(path.dirname(dst), { recursive: true });
    try { fs.renameSync(src, dst); }
    catch (e) { if (e.code !== "EXDEV") throw e; fs.cpSync(src, dst, { recursive: true }); fs.rmSync(src, { recursive: true, force: true }); } // across disks
  } catch (e) { return { error: e.message }; }
  return { ok: true, moved: path.relative(root, src) + " → " + path.relative(root, dst) };
}

function copyTool(a, cwd, rp) {
  const root = realRoot(cwd, rp);
  let src, dst;
  try { src = rp(a.from || a.src || a.source); dst = rp(a.to || a.dest || a.destination); } catch (e) { return { error: e.message }; }
  if (!exists(src)) return { error: "nothing at " + path.relative(root, src) };
  dst = destOf(src, dst);
  if (path.resolve(src) === path.resolve(dst)) return { error: "source and destination are the same" };
  const isDir = fs.statSync(src).isDirectory();
  if (isDir && (dst + path.sep).startsWith(src + path.sep)) return { error: "cannot copy a folder into itself" };
  if (exists(dst) && !a.overwrite) return { error: path.relative(root, dst) + " already exists — pass overwrite:true to replace it" };
  try {
    fs.mkdirSync(path.dirname(dst), { recursive: true });
    if (isDir) fs.cpSync(src, dst, { recursive: true, force: !!a.overwrite, errorOnExist: !a.overwrite });
    else fs.copyFileSync(src, dst);
  } catch (e) { return { error: e.message }; }
  return { ok: true, copied: path.relative(root, src) + " → " + path.relative(root, dst) + (isDir ? " (folder)" : "") };
}

function deleteTool(a, cwd, rp) {
  const root = realRoot(cwd, rp);
  let fp; try { fp = linkOrRp(a.path || a.file, cwd, rp); } catch (e) { return { error: e.message }; }
  // rp() returns the real path: compare with the real root too, or a project reached through a
  // symlink (macOS /tmp -> /private/tmp, a linked home) let `delete . recursive` wipe it
  if (path.resolve(fp) === root || path.resolve(fp) === path.resolve(cwd)) return { error: "refusing to delete the project root" };
  if (!exists(fp)) return { ok: true, note: "nothing at " + path.relative(root, fp) + " — already gone (check the path if you expected a file)" };
  const st = fs.lstatSync(fp);
  if (st.isDirectory() && !a.recursive) {
    let n = 0; try { n = fs.readdirSync(fp).length; } catch (_) {}
    if (n) return { error: path.relative(root, fp) + " is a folder with " + n + " entr" + (n === 1 ? "y" : "ies") + " — pass recursive:true to delete it and everything in it" };
  }
  try { fs.rmSync(fp, { recursive: st.isDirectory(), force: true }); } catch (e) { return { error: e.message }; }
  return { ok: true, deleted: path.relative(root, fp) + (st.isDirectory() ? "/" : "") };
}

// list_dir: folders first, sizes for files, optional depth (a compact tree).
function listDirTool(a, cwd, rp) {
  let root; try { root = rp(a.path || "."); } catch (e) { return { error: e.message }; }
  const depth = Math.max(1, Math.min(4, a.depth | 0 || 1));
  const max = Math.max(1, Math.min(2000, a.max_results || 400));
  const items = []; let total = 0;
  const walk = (dir, d, indent) => {
    let ents; try { ents = fs.readdirSync(dir, { withFileTypes: true }); } catch (e) { if (d === 1) throw e; return; }
    ents.sort((x, y) => (y.isDirectory() - x.isDirectory()) || x.name.localeCompare(y.name));
    for (const e of ents) {
      total++;
      const fp = path.join(dir, e.name);
      if (e.isDirectory()) {
        const skip = d > 1 || depth > 1 ? SKIP_DIR.test(e.name) : false;
        if (items.length < max) items.push(indent + e.name + "/" + (skip && depth > 1 ? "  (not expanded)" : ""));
        if (d < depth && !skip) walk(fp, d + 1, indent + "  ");
      } else if (items.length < max) {
        let sz = ""; if (a.sizes !== false) { try { sz = "  " + human(fs.statSync(fp).size); } catch (_) {} }
        items.push(indent + e.name + (e.isSymbolicLink() ? " -> " + (() => { try { return fs.readlinkSync(fp); } catch (_) { return "?"; } })() : sz));
      }
    }
  };
  try { walk(root, 1, ""); } catch (e) { return { error: e.message }; }
  const res = { path: path.relative(cwd, root) || ".", items };
  if (total > items.length) res.truncated = "showing " + items.length + " of " + total + " entries — list a subfolder or raise max_results";
  return res;
}

module.exports = { moveTool, copyTool, deleteTool, listDirTool, destOf };
