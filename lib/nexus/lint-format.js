"use strict";
// ================= lint_format: auto-detect and FIX formatting/lint =================
// Nexus already has `verify`, but verify only REPORTS (runs the project's test/build/lint and
// tells you what's wrong). lint_format is the complementary writer: it detects the project's
// formatter/linter from its manifest and runs it in --fix/--write mode so the agent can
// actually clean up what it just wrote (trailing whitespace, import order, quote style, ...)
// instead of hand-editing style nits. `check:true` runs the same tools in report-only mode.
//
// ZERO-DEP / GRACEFUL: it ships no formatter. It drives whatever is already installed through
// the injected `run(cmd)->{code,output}` (the agent's own coderShell), using `npx --no-install`
// for JS so nothing is ever downloaded. A tool that isn't installed exits "command not found"
// and is reported as skipped — the tool degrades to a note, never an error. The detection table
// and plan builder are pure and unit-tested.
// Exposed agent tool (wired in darknode.js deviceTool): lint_format.

// A missing binary shows up as one of these in the shell output (sh 127, npx, Windows, cargo).
// Only these specific messages (or sh's 127) mean "missing": a bare "not found" also appears in the
// lint findings eslint/ruff print when they exit 1, which used to be reported as "not installed".
const NOT_INSTALLED = /command not found|is not recognized as an internal|could not determine executable|npx canceled due to missing packages|no such (?:sub)?command/i;

// {t} is replaced by the target (default ".", or a caller-supplied path). Ordered: the first
// available tool per language is the default; `all:true` runs every detected tool.
const LANGS = [
  { lang: "js", detect: ["package.json"], tools: [
    { bin: "prettier", fix: "npx --no-install prettier --write {t}", check: "npx --no-install prettier --check {t}" },
    { bin: "eslint", fix: "npx --no-install eslint {t} --fix", check: "npx --no-install eslint {t}" },
  ] },
  { lang: "python", detect: ["pyproject.toml", "requirements.txt", "setup.py", "setup.cfg", "Pipfile", "tox.ini"], tools: [
    { bin: "ruff", fix: "ruff check {t} --fix && ruff format {t}", check: "ruff check {t} && ruff format --check {t}" },
    { bin: "black", fix: "black {t}", check: "black --check {t}" },
  ] },
  { lang: "go", detect: ["go.mod"], tools: [
    { bin: "gofmt", fix: "gofmt -w {t}", check: "gofmt -l {t}" },
  ] },
  { lang: "rust", detect: ["Cargo.toml"], tools: [
    { bin: "cargo-fmt", fix: "cargo fmt", check: "cargo fmt --check" },
  ] },
];

// Single-quote escape a target path for /bin/sh.
function shq(s) { return "'" + String(s == null ? "" : s).replace(/'/g, "'\\''") + "'"; }

// Pure: which languages this directory listing looks like (by manifest presence).
function detectLangs(entries) {
  const have = new Set((entries || []).map((e) => (typeof e === "string" ? e : e && e.name) || ""));
  return LANGS.filter((l) => l.detect.some((f) => have.has(f)));
}

// JS formatters the project itself uses (package.json deps or a config file). npx --no-install
// also finds a GLOBAL prettier/eslint, which would restyle a project that never chose it.
const JS_CONF = { prettier: /^(\.prettierrc(\..+)?|prettier\.config\.(c|m)?js)$/, eslint: /^(\.eslintrc(\..+)?|eslint\.config\.(c|m)?[jt]s)$/ };
function jsDeclared(entries, pkg) {
  const names = (entries || []).map((e) => (typeof e === "string" ? e : e && e.name) || "");
  const deps = Object.assign({}, pkg && pkg.dependencies, pkg && pkg.devDependencies);
  return new Set(Object.keys(JS_CONF).filter((b) => deps[b] || (b === "prettier" && pkg && pkg.prettier) || (b === "eslint" && pkg && pkg.eslintConfig) || names.some((n) => JS_CONF[b].test(n))));
}

// Pure: turn detected langs + options into an ordered run plan of { lang, bin, cmd }.
// opts: { fix:true, target:".", all:false, tool:null }. target is already shell-safe or ".".
function buildPlan(langs, opts) {
  opts = opts || {};
  const fix = opts.fix !== false;
  const target = opts.target || ".";
  const only = opts.tool ? String(opts.tool).toLowerCase() : null;
  const plan = [];
  for (const l of langs || []) {
    let tools = l.tools;
    if (only) tools = tools.filter((t) => t.bin === only);
    else if (l.lang === "js" && opts.jsDeclared) tools = tools.filter((t) => opts.jsDeclared.has(t.bin));
    // without all:, `fallback` marks the rest of a language's tools: run only if the one before was not installed
    tools.forEach((t, i) => plan.push({ lang: l.lang, bin: t.bin, cmd: (fix ? t.fix : t.check).replace(/\{t\}/g, target), fallback: !opts.all && !only && i > 0 }));
  }
  return plan;
}

// Wiring entry point used by deviceTool. `a` raw args, `cwd` project root, `deps.run` injected
// shell runner, `deps.readdir` an optional dir-lister seam (defaults to fs.readdirSync(cwd)).
async function lintFormatTool(a, cwd, deps) {
  a = a || {}; deps = deps || {};
  const run = deps.run;
  if (typeof run !== "function") return { error: "no shell runner available" };
  let entries;
  try { entries = deps.readdir ? deps.readdir() : require("fs").readdirSync(cwd || "."); }
  catch (e) { return { error: "cannot read project directory: " + ((e && e.message) || e) }; }

  const langs = detectLangs(entries);
  if (!langs.length) return { ran: false, note: "no recognized project manifest (package.json / pyproject.toml / go.mod / Cargo.toml) in the project root — pass tool: to force a formatter" };

  const fix = !(a.check || a.checkOnly || a.dryRun) && a.fix !== false;
  // A formatter runs with --write by default, so a path must stay inside the project root and
  // must not start with "-" (which the formatter would read as an option, not a path).
  const rawPath = a.path || a.file;
  if (rawPath != null && rawPath !== "") {
    const raw = String(rawPath);
    const path = require("path");
    if (/^-/.test(raw) || /[\0\n\r]/.test(raw)) return { error: "invalid path (leading '-', newline, or NUL byte)" };
    const root = path.resolve(cwd || ".");
    const resolved = path.resolve(root, raw);
    if (resolved !== root && !resolved.startsWith(root + path.sep)) return { error: "path escapes the project directory" };
  }
  const target = (a.path || a.file) ? shq(a.path || a.file) : ".";
  let pkg = null;
  if (langs.some((l) => l.lang === "js")) { try { pkg = JSON.parse(require("fs").readFileSync(require("path").join(cwd || ".", "package.json"), "utf8").replace(/^\uFEFF/, "")); } catch (_) {} }
  const declared = jsDeclared(entries, pkg);
  const plan = buildPlan(langs, { fix, target, all: !!a.all, tool: a.tool, jsDeclared: declared });
  const jsNote = langs.some((l) => l.lang === "js") && !a.tool && !declared.size ? "this JS project declares no formatter (prettier/eslint in package.json or a config file), so none was run - pass tool:'prettier' or 'eslint' to run one anyway" : "";
  if (!plan.length && jsNote) return { ran: false, note: jsNote };
  if (!plan.length) return { ran: false, note: "no matching formatter" + (a.tool ? " for tool '" + a.tool + "'" : "") + " among detected languages: " + langs.map((l) => l.lang).join(", ") };

  const results = [];
  const done = new Set();
  for (const step of plan) {
    if (step.fallback && done.has(step.lang)) continue;
    let r;
    try { r = await run(step.cmd); } catch (e) { r = { code: -1, output: (e && e.message) || String(e) }; }
    const output = r && r.output != null ? String(r.output) : "";
    if (r && r.code !== 0 && (r.code === 127 || NOT_INSTALLED.test(output))) {
      results.push({ tool: step.bin, lang: step.lang, skipped: step.lang === "js" && declared.has(step.bin) ? "not installed - the project declares it; run npm install" : "not installed" });
      continue;
    }
    done.add(step.lang);
    results.push({ tool: step.bin, lang: step.lang, code: r ? r.code : -1, ok: !!r && r.code === 0, output: output.slice(0, 4000) });
  }

  const ran = results.filter((x) => !x.skipped);
  const skipped = results.filter((x) => x.skipped);
  const out = { mode: fix ? "fix" : "check", languages: langs.map((l) => l.lang), results };
  if (!ran.length) out.note = "detected " + langs.map((l) => l.lang).join(", ") + " but no formatter was installed (" + skipped.map((s) => s.tool).join(", ") + ")";
  else out.summary = (fix ? "Ran " : "Checked ") + ran.length + " formatter(s): " + ran.map((x) => x.tool + (x.ok ? " ok" : " (" + x.code + ")")).join(", ") + (skipped.length ? "; skipped " + skipped.map((s) => s.tool).join(", ") + " (not installed)" : "");
  if (jsNote) out.note = (out.note ? out.note + "; " : "") + jsNote;
  return out;
}

module.exports = {
  jsDeclared,
  lintFormatTool, detectLangs, buildPlan, shq,
  LANGS, NOT_INSTALLED,
};
