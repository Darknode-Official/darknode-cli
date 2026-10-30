"use strict";
// replace_in_files — one find/replace across many files (rename a function,
// update an import path, swap a config key). One call instead of reading and
// editing every file in turn, and a dry run shows exactly what would change
// before anything is written. Literal text by default; regex:true for a
// pattern, word:true for whole-word matches (safe renames: `get` won't hit
// `getAll`). Every file still goes through the host's policy/secret check,
// and every write is recorded so undo_edit can take it back file by file.

const fs = require("fs");
const path = require("path");

const SKIP_DIR = /^(\.git|node_modules|dist|build|out|coverage|\.nexus|\.cache|\.next|vendor|target|__pycache__|\.venv|venv)$/;
const MAX_FILE = 1024 * 1024;
const MAX_FILES_SCANNED = 20000;
const MAX_FILES_CHANGED = 500;

const { globToRe } = require("./glob"); // shared glob (lib/nexus/glob.js)
const { keepEol } = require("./edit"); // CRLF restore that leaves untouched lines' endings alone

function buildMatcher(a) {
  const find = a.find != null ? a.find : a.pattern;
  if (find == null || find === "") return { error: "replace_in_files needs find (the text or pattern to replace)" };
  let src = a.regex ? String(find) : String(find).replace(/\r\n/g, "\n").replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  if (a.word) src = "(?<![\\w$])(?:" + src + ")(?![\\w$])"; // grouped, or foo|bar checks only the outer ends
  try { return { find: String(find).replace(/\r\n/g, "\n"), re: new RegExp(src, "g" + (a.ignore_case || a.ignoreCase ? "i" : "") + (a.regex && a.multiline !== false ? "m" : "")) }; }
  catch (e) { return { error: "invalid regex: " + e.message }; }
}

function* walk(root, rel) {
  let ents;
  try { ents = fs.readdirSync(path.join(root, rel), { withFileTypes: true }); } catch (_) { return; }
  for (const e of ents) {
    const r = rel ? rel + "/" + e.name : e.name;
    if (e.isDirectory()) { if (!SKIP_DIR.test(e.name)) yield* walk(root, r); }
    else if (e.isFile()) yield r;
  }
}

// deps.check(relPath, newText) -> null (ok) or a reason string (skip this file)
// deps.onWrite(absPath) -> before writing (for undo snapshots); deps.afterWrite(absPath)
function replaceInFilesTool(a, cwd, rp, deps) {
  deps = deps || {};
  const m = buildMatcher(a);
  if (m.error) return { error: m.error };
  const rep = a.replace != null ? String(a.replace) : a.replacement != null ? String(a.replacement) : null;
  if (rep == null) return { error: "replace_in_files needs replace (the new text; use \"\" to delete matches)" };
  let root;
  try { root = rp(a.path || "."); } catch (e) { return { error: e.message }; }
  const globs = [].concat(a.glob || a.include || []).filter(Boolean).map(globToRe);
  const dry = a.dry_run === true || a.dryRun === true || a.preview === true;
  const st = (() => { try { return fs.statSync(root); } catch (_) { return null; } })();
  if (!st) return { error: "no such path: " + (a.path || ".") };
  const files = st.isFile() ? [path.basename(root)] : null;
  const base = st.isFile() ? path.dirname(root) : root;
  const changed = [], skipped = [];
  let scanned = 0, total = 0;
  const iter = files || walk(base, "");
  for (const r of iter) {
    if (++scanned > MAX_FILES_SCANNED) { skipped.push({ file: "…", reason: "stopped after " + MAX_FILES_SCANNED + " files — narrow path/glob" }); break; }
    const abs = path.join(base, r), relCwd = path.relative(cwd, abs);
    if (globs.length && !globs.some((g) => g.test(r) || g.test(path.basename(r)) || g.test(relCwd.split(path.sep).join("/")))) continue; // src/ui/*.ts with path:"src" too
    let txt;
    let buf;
    // a too-big file that holds a match is reported, not passed over as "no matches"
    try { const s = fs.statSync(abs); if (s.size > MAX_FILE) { m.re.lastIndex = 0; if (s.size <= 64 * MAX_FILE && m.re.test(fs.readFileSync(abs, "utf8"))) skipped.push({ file: relCwd, reason: "over " + (MAX_FILE >> 20) + " MB — edit it directly" }); continue; } buf = fs.readFileSync(abs); txt = buf.toString("utf8"); } catch (_) { continue; }
    if (txt.indexOf("\u0000") >= 0) continue; // binary
    const notUtf8 = txt.includes("\uFFFD") && !Buffer.from(txt, "utf8").equals(buf); // Latin-1 etc.: a UTF-8 round trip would corrupt its other non-ASCII bytes
    // literal multi-line text on a CRLF file: match and splice on LF, restore CRLF after
    // (an LF find never matched, and an LF replace left mixed line endings)
    // A regex is matched on LF too (a\nb found nothing, a newline in the replacement left a bare LF),
    // unless the pattern names \r itself.
    const crlf = (a.regex ? !/\\r|\r/.test(String(m.find)) : /\n/.test(String(m.find) + rep)) && (txt.match(/\r\n/g) || []).length * 2 > (txt.match(/\n/g) || []).length;
    const orig = txt;
    if (crlf) txt = txt.replace(/\r\n/g, "\n");
    const repF = crlf || !/\r\n/.test(orig) ? rep.replace(/\r\n/g, "\n") : rep; // LF here: CRLF is restored below, and never spliced into an LF file
    // a regex that matches empty at the very end ("^", "$" in multiline) hit the phantom line
    // after the final newline: "^" -> "// " appended a stray "// " line. Match without it.
    let nl = "";
    if (a.regex && /\n$/.test(txt)) { const y = new RegExp(m.re.source, m.re.flags.replace("g", "") + "y"); y.lastIndex = txt.length; const z = y.exec(txt); if (z && z[0] === "") { nl = txt.match(/\r?\n$/)[0]; txt = txt.slice(0, -nl.length); } }
    m.re.lastIndex = 0;
    if (!m.re.test(txt)) continue;
    m.re.lastIndex = 0;
    const sub = a.regex ? repF : () => repF; // literal mode: "$" in the new text is just a "$"
    const count = (txt.match(m.re) || []).length;
    m.re.lastIndex = 0;
    const samples = [];
    const lines = txt.split("\n");
    for (let i = 0; i < lines.length && samples.length < 3; i++) { m.re.lastIndex = 0; if (m.re.test(lines[i])) { m.re.lastIndex = 0; samples.push((i + 1) + ": " + lines[i].trim().slice(0, 120) + "  →  " + lines[i].replace(m.re, sub).trim().slice(0, 120)); } }
    m.re.lastIndex = 0;
    let out = txt.replace(m.re, sub) + nl;
    if (crlf) out = keepEol(orig, out);
    if (out === orig) continue;
    if (notUtf8) { skipped.push({ file: relCwd, reason: "not UTF-8 text (likely Latin-1); left unchanged so its other characters are not corrupted" }); continue; }
    if (changed.length >= MAX_FILES_CHANGED) { skipped.push({ file: relCwd, reason: "over " + MAX_FILES_CHANGED + " files — run again for the rest" }); continue; }
    const why = deps.check ? deps.check(relCwd, out) : null;
    if (why) { skipped.push({ file: relCwd, reason: why }); continue; }
    if (!dry) {
      try { if (deps.onWrite) deps.onWrite(abs); fs.writeFileSync(abs, out); if (deps.afterWrite) deps.afterWrite(abs); }
      catch (e) { skipped.push({ file: relCwd, reason: e.message }); continue; }
    }
    total += count;
    changed.push({ file: relCwd, replacements: count, samples });
  }
  const res = { dry_run: dry, files: changed.length, replacements: total, changed };
  if (skipped.length) res.skipped = skipped;
  if (!changed.length) res.note = "no matches" + (globs.length ? " in files matching " + [].concat(a.glob || a.include).join(", ") : "") + (a.word ? " (whole-word)" : "");
  else if (dry) res.note = "dry run — nothing written; call again without dry_run to apply";
  return res;
}

module.exports = { replaceInFilesTool, buildMatcher, globToRe };
