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
const NOT_INSTALLED = /command not found|not found|no such file|is not recognized|could not determine executable|npm error could not determine|ENOENT|no such subcommand/i;

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
    else if (!opts.all) tools = tools.slice(0, 1);
    for (const t of tools) plan.push({ lang: l.lang, bin: t.bin, cmd: (fix ? t.fix : t.check).replace(/\{t\}/g, target) });
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
  const target = (a.path || a.file) ? shq(a.path || a.file) : ".";
  const plan = buildPlan(langs, { fix, target, all: !!a.all, tool: a.tool });
  if (!plan.length) return { ran: false, note: "no matching formatter" + (a.tool ? " for tool '" + a.tool + "'" : "") + " among detected languages: " + langs.map((l) => l.lang).join(", ") };

  const results = [];
  for (const step of plan) {
    let r;
    try { r = await run(step.cmd); } catch (e) { r = { code: -1, output: (e && e.message) || String(e) }; }
    const output = r && r.output != null ? String(r.output) : "";
    if (NOT_INSTALLED.test(output) && (r.code === 127 || r.code === -1 || r.code === 1)) {
      results.push({ tool: step.bin, lang: step.lang, skipped: "not installed" });
      continue;
    }
    results.push({ tool: step.bin, lang: step.lang, code: r ? r.code : -1, ok: !!r && r.code === 0, output: output.slice(0, 4000) });
  }

  const ran = results.filter((x) => !x.skipped);
  const skipped = results.filter((x) => x.skipped);
  const out = { mode: fix ? "fix" : "check", languages: langs.map((l) => l.lang), results };
  if (!ran.length) out.note = "detected " + langs.map((l) => l.lang).join(", ") + " but no formatter was installed (" + skipped.map((s) => s.tool).join(", ") + ")";
  else out.summary = (fix ? "Ran " : "Checked ") + ran.length + " formatter(s): " + ran.map((x) => x.tool + (x.ok ? " ok" : " (" + x.code + ")")).join(", ") + (skipped.length ? "; skipped " + skipped.map((s) => s.tool).join(", ") + " (not installed)" : "");
  return out;
}

module.exports = {
  lintFormatTool, detectLangs, buildPlan, shq,
  LANGS, NOT_INSTALLED,
};
