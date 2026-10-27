"use strict";
// Syntax check after an agent edit: did this edit leave the file with a syntax error
// it did not have before? If so the tool result says where, so the model fixes it on
// the next step instead of finding out from a failing build three steps later.
//
// It WARNS, it never blocks or reverts: an agent often makes two edits in a row where
// the file is briefly invalid in between, and blocking the first would break that.
// Only errors the edit INTRODUCED are reported - a file that already failed to parse
// before the edit is not the edit's fault. A file it can't check is "not checked",
// never a pass.
//
// Zero-dep: JSON in-process; JS via `node --check` (this Node); TS/JSX/TSX via the
// PROJECT's own `typescript` package if it has one (syntactic diagnostics only, so a
// missing import is not reported as a syntax error); Python via `python3`'s ast.parse
// on stdin (writes no __pycache__). Anything else is skipped.
const fs = require("fs"), os = require("os"), path = require("path"), cp = require("child_process");

const JSONC = /(^|[\\/])(tsconfig[^\\/]*|jsconfig[^\\/]*|\.eslintrc|devcontainer)\.json$|\.jsonc$|[\\/]\.vscode[\\/][^\\/]+\.json$/i;
const TIMEOUT = 5000;

function langOf(fp) {
  const e = path.extname(fp).toLowerCase();
  if (e === ".json") return JSONC.test(fp) ? null : "json"; // JSON-with-comments files are not JSON
  if (e === ".js" || e === ".mjs" || e === ".cjs") return "js";
  if (e === ".ts" || e === ".mts" || e === ".cts" || e === ".tsx" || e === ".jsx") return "ts";
  if (e === ".py") return "py";
  return null;
}

// JSX in a .js file is valid for the project's bundler but not for `node --check`.
const looksJsx = (t) => /<\/[A-Za-z][\w.]*\s*>|\/>\s*[)\n;,]/.test(t) && /return\s*\(\s*<|=>\s*\(?\s*<[A-Za-z]/.test(t);
const looksEsm = (t) => /^\s*(import\s[\s\S]*?from\s|import\s*["'{*]|export\s)/m.test(t);

function viaNode(fp, text) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "nxsyn-"));
  const tmp = path.join(dir, "check" + (path.extname(fp) === ".mjs" || path.extname(fp) === ".cjs" ? path.extname(fp) : looksEsm(text) ? ".mjs" : ".cjs"));
  try {
    fs.writeFileSync(tmp, text);
    const r = cp.spawnSync(process.execPath, ["--check", tmp], { encoding: "utf8", timeout: TIMEOUT });
    if (r.error) return { checked: false };
    if (r.status === 0) return { checked: true, ok: true };
    const err = String(r.stderr || "");
    const loc = err.match(/check\.[cm]?js:(\d+)/), msg = err.match(/^(SyntaxError: .*)$/m);
    if (!msg) return { checked: false }; // some other failure (not a syntax error) - don't guess
    return { checked: true, ok: false, error: (loc ? "line " + loc[1] + ": " : "") + msg[1] };
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
}

function projectTs(fp) {
  try { return require(require.resolve("typescript", { paths: [path.dirname(fp)] })); } catch (_) { return null; }
}

function viaTs(fp, text) {
  const ts = projectTs(fp);
  if (!ts) return { checked: false };
  const out = ts.transpileModule(text, { fileName: path.basename(fp), reportDiagnostics: true, compilerOptions: { jsx: 1 /* Preserve */ } });
  const d = (out.diagnostics || [])[0];
  if (!d) return { checked: true, ok: true };
  const pos = d.file && d.start != null ? d.file.getLineAndCharacterOfPosition(d.start) : null;
  return { checked: true, ok: false, error: (pos ? "line " + (pos.line + 1) + ": " : "") + ts.flattenDiagnosticMessageText(d.messageText, " ") };
}

function viaPython(fp, text) {
  const code = "import ast,sys\ntry:\n ast.parse(sys.stdin.read())\nexcept SyntaxError as e:\n print('line %s: SyntaxError: %s' % (e.lineno, e.msg)); sys.exit(3)";
  const r = cp.spawnSync("python3", ["-c", code], { input: text, encoding: "utf8", timeout: TIMEOUT });
  if (r.error || (r.status !== 0 && r.status !== 3)) return { checked: false };
  return r.status === 0 ? { checked: true, ok: true } : { checked: true, ok: false, error: String(r.stdout).trim() };
}

// { checked, ok, error? } for `text` as the contents of `fp`.
function check(fp, text) {
  const lang = langOf(fp);
  try {
    if (lang === "json") { try { JSON.parse(String(text).replace(/^\uFEFF/, "")); return { checked: true, ok: true }; } catch (e) { return { checked: true, ok: false, error: e.message }; } }
    if (lang === "js") return looksJsx(text) ? viaTs(fp, text) : viaNode(fp, text);
    if (lang === "ts") return viaTs(fp, text);
    if (lang === "py") return viaPython(fp, text);
  } catch (_) { /* a checker crash is "not checked", never a verdict */ }
  return { checked: false };
}

// Before the edit: remember what the file looked like.
function capture(fp) {
  if (!langOf(fp)) return null;
  let before = null;
  try { before = fs.readFileSync(fp, "utf8"); } catch (_) {}
  return { fp, before };
}

// After the edit: a warning string if the edit introduced a syntax error, else null.
function afterEdit(cap, label) {
  if (!cap) return null;
  let after;
  try { after = fs.readFileSync(cap.fp, "utf8"); } catch (_) { return null; }
  if (after === cap.before) return null;
  const r = check(cap.fp, after);
  if (!r.checked || r.ok) return null;
  if (cap.before != null) { const b = check(cap.fp, cap.before); if (b.checked && !b.ok) return null; } // already broken before
  return "this edit left " + (label || path.basename(cap.fp)) + " with a syntax error it did not have before (" + r.error + "). The edit WAS applied - fix it next.";
}

module.exports = { check, capture, afterEdit, langOf };
