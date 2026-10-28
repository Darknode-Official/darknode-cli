"use strict";
// ================= git_tool: READ-ONLY, structured git for the agent =================
// The agent can already run `git ...` through run_command, but it then has to eyeball raw
// porcelain text. git_tool does the parsing for it: one `op` in, a small structured object
// out (branch + ahead/behind + changed files, parsed commits, a blame map, ...). It is
// deliberately READ-ONLY — every state-changing verb (commit/add/push/reset/checkout/merge/
// rebase/clean/stash/...) is refused and pointed back at run_command, so a model cannot
// mutate the repo "by accident" through what it thinks is an inspection tool.
//
// INJECTION: it does not spawn anything itself. deviceTool hands in `run(cmd) -> {code,output}`
// (the agent's own coderShell, already scoped to cwd), exactly like batch.js is handed the
// dispatcher and view-image.js the path guard. Every ref/path argument is single-quote escaped
// before it reaches the shell. The command builders and output parsers are pure and unit-tested.
// Exposed agent tool (wired in darknode.js deviceTool): git_tool.

// read-only operations the model may ask for -> canonical op.
const OP_ALIASES = {
  status: "status", st: "status",
  log: "log", history: "log", commits: "log",
  diff: "diff", changes: "diff",
  show: "show",
  blame: "blame", annotate: "blame",
  branch: "branch", branches: "branch",
};

// verbs that change repo state — explicitly refused (reported, never executed) so the agent
// uses run_command (which goes through the danger/guardrail gate) for anything mutating.
const WRITE_OPS = new Set([
  "commit", "add", "stage", "push", "pull", "fetch", "reset", "checkout", "switch",
  "merge", "rebase", "clean", "rm", "mv", "stash", "tag", "cherry-pick", "revert",
  "restore", "gc", "prune", "apply", "am", "init", "clone", "config", "remote",
]);

// Single-quote escape for /bin/sh so a ref/path cannot break out of its argument.
function shq(s) { return "'" + String(s == null ? "" : s).replace(/'/g, "'\\''") + "'"; }

// Reject args that have no business in a git ref/path. Shell quoting stops the shell from
// splitting the value, but it is stripped before git parses argv, so a value starting with "-"
// still reaches git as an OPTION, not a revision/path — e.g. ref "--output=/abs/file" makes
// `git diff`/`git show --output=<file>` write to an attacker-chosen absolute path, escaping the
// cwd jail this read-only tool relies on. Legitimate git revs/paths never start with "-", so
// reject a leading dash (plus newlines/NUL, which are just nonsense here).
function badArg(s) { return typeof s === "string" && (/[\0\n\r]/.test(s) || /^-/.test(s)); }

// Pure: build the git command string for a read-only op, or return { error }. Never runs anything.
function buildGitCommand(op, a) {
  a = a || {};
  const canonical = OP_ALIASES[String(op || "").toLowerCase()];
  if (!canonical) {
    if (WRITE_OPS.has(String(op || "").toLowerCase())) return { error: "git_tool is read-only — use run_command for '" + op + "'" };
    return { error: "unknown git op '" + op + "' — read-only ops: " + Object.keys(OP_ALIASES).filter((k, i, arr) => arr.indexOf(OP_ALIASES[k]) === i).join(", ") };
  }
  const ref = a.ref || a.commit || a.rev;
  const file = a.path || a.file;
  if (badArg(ref) || badArg(file) || badArg(a.range) || badArg(a.line)) return { error: "invalid git argument (leading '-', newline, or NUL byte)" };
  if (canonical === "status") return { op: canonical, cmd: "git status --porcelain=v1 --branch" };
  if (canonical === "log") {
    const n = Math.max(1, Math.min(200, Number(a.count || a.n || a.max || 20) || 20));
    // %x1f = unit separator between fields, one commit per line.
    let cmd = "git log --no-color --pretty=format:%H%x1f%an%x1f%ar%x1f%s -n " + n;
    if (file) cmd += " -- " + shq(file);
    return { op: canonical, cmd };
  }
  if (canonical === "diff") {
    let cmd = "git --no-pager diff --no-color" + (a.staged || a.cached ? " --staged" : "") + (a.stat ? " --stat" : "");
    if (ref) cmd += " " + shq(ref);
    if (file) cmd += " -- " + shq(file);
    return { op: canonical, cmd };
  }
  if (canonical === "show") {
    return { op: canonical, cmd: "git --no-pager show --no-color --stat " + shq(ref || "HEAD") + (file ? " -- " + shq(file) : "") };
  }
  if (canonical === "blame") {
    if (!file) return { error: "git blame needs a 'path'" };
    let cmd = "git --no-pager -c blame.coloring=none blame -w --line-porcelain"; // blame has no --no-color: git 2.4x rejects it as ambiguous (--no-color-lines / --no-color-by-age)
    if (a.line || a.range) { // "2" alone made git print its usage text (-L needs start,end); 2-5 is read as 2,5
      const L = String(a.range || a.line).trim().replace(/^(\d+)\s*[-:]\s*(\d+)$/, "$1,$2");
      cmd += " -L " + shq(/^\d+$/.test(L) ? L + "," + L : L);
    }
    cmd += " -- " + shq(file); // -- so a path can never be read as a revision/option
    return { op: canonical, cmd };
  }
  if (canonical === "branch") return { op: canonical, cmd: "git branch -a --no-color" };
  return { error: "unhandled op" };
}

// git C-quotes a path with a space, quote, backslash or non-ASCII byte: "caf\303\251.txt".
// Undo that (octal escapes are UTF-8 bytes) so the path can be opened as-is.
const CESC = { a: 7, b: 8, t: 9, n: 10, v: 11, f: 12, r: 13, '"': 34, "\\": 92 };
function unquotePath(p) {
  if (!/^".*"$/.test(p)) return p;
  const bytes = [];
  for (let i = 1; i < p.length - 1; i++) {
    const c = p[i];
    if (c !== "\\") { bytes.push(...Buffer.from(c)); continue; }
    const o = /^[0-7]{3}/.exec(p.slice(i + 1));
    if (o) { bytes.push(parseInt(o[0], 8)); i += 3; } else { const e = p[++i]; bytes.push(CESC[e] != null ? CESC[e] : e.charCodeAt(0)); }
  }
  return Buffer.from(bytes).toString("utf8");
}

// Pure: parse `git status --porcelain=v1 --branch` into { branch, upstream, ahead, behind, files }.
function parseStatus(text) {
  const out = { branch: null, upstream: null, ahead: 0, behind: 0, files: [], clean: true };
  const lines = String(text || "").split("\n");
  for (const line of lines) {
    if (!line) continue;
    if (line.startsWith("## ")) {
      const b = line.slice(3);
      const m = /^(.+?)(?:\.\.\.(\S+))?(?:\s+\[(.+)\])?$/.exec(b);
      if (m) {
        // Fresh repos report `## No commits yet on <branch>`; strip that prefix to the bare name.
        out.branch = m[1].replace(/^No commits yet on /, "");
        if (m[2]) out.upstream = m[2];
        if (m[3]) { const am = /ahead (\d+)/.exec(m[3]); const bm = /behind (\d+)/.exec(m[3]); if (am) out.ahead = Number(am[1]); if (bm) out.behind = Number(bm[1]); }
      }
      continue;
    }
    const code = line.slice(0, 2);
    const p = line.slice(3);
    // rename/copy: `old -> new` (each side quoted on its own when needed)
    const rn = /^[RC]/.test(code) || /^.[RC]/.test(code) ? /^("(?:[^"\\]|\\.)*"|.+?) -> ("(?:[^"\\]|\\.)*"|.+)$/.exec(p) : null;
    if (rn) out.files.push({ status: code, path: unquotePath(rn[2]), from: unquotePath(rn[1]) });
    else out.files.push({ status: code, path: unquotePath(p) });
  }
  out.clean = out.files.length === 0;
  return out;
}

// Pure: parse the %H\x1f%an\x1f%ar\x1f%s log stream into commit objects.
function parseLog(text) {
  const out = [];
  for (const line of String(text || "").split("\n")) {
    if (!line) continue;
    const f = line.split("\x1f");
    if (f.length >= 4) out.push({ hash: f[0], short: f[0].slice(0, 9), author: f[1], date: f[2], subject: f.slice(3).join("\x1f") });
  }
  return out;
}

// Pure: parse `git blame` lines into { commit, author, date, line, text } rows (cap rows).
function parseBlame(text, max) {
  const out = [];
  const cap = max || 400;
  const lines = String(text || "").split("\n");
  // --line-porcelain: a "<sha> <orig> <final>" header, key/value lines, then "\t<text>". Immune to
  // spaces in file names (a renamed file adds a name column) and parentheses in author names.
  if (/^[0-9a-f]{40} \d+ \d+/.test(lines[0] || "")) {
    let cur = null;
    for (const l of lines) {
      const h = /^([0-9a-f]{40}) \d+ (\d+)/.exec(l);
      if (h) { cur = { commit: h[1].slice(0, 9), author: "", date: "", line: Number(h[2]), text: "" }; continue; }
      if (!cur) continue;
      if (l.startsWith("author ")) cur.author = l.slice(7);
      else if (l.startsWith("author-time ")) cur.t = Number(l.slice(12));
      else if (l.startsWith("author-tz ")) { const z = /([-+])(\d\d)(\d\d)/.exec(l); cur.tz = z ? (z[1] === "-" ? -1 : 1) * (z[2] * 3600 + z[3] * 60) : 0; }
      else if (l[0] === "\t") {
        if (cur.t) cur.date = new Date((cur.t + (cur.tz || 0)) * 1000).toISOString().slice(0, 10);
        delete cur.t; delete cur.tz; cur.text = l.slice(1); out.push(cur); cur = null;
        if (out.length >= cap) break;
      }
    }
    return out;
  }
  for (const line of lines) {
    if (!line) continue;
    const m = /^\^?([0-9a-f]{6,40})\s+(?:\S+\s+)?\(\s*(.+?)\s+(\d{4}-\d{2}-\d{2})[^)]*?\s+(\d+)\)\s?(.*)$/.exec(line);
    if (m) out.push({ commit: m[1].slice(0, 9), author: m[2], date: m[3], line: Number(m[4]), text: m[5] });
    else out.push({ raw: line });
    if (out.length >= cap) break;
  }
  return out;
}

// Pure: parse `git branch -a` into { current, local, remote }.
function parseBranches(text) {
  const out = { current: null, local: [], remote: [] };
  for (const raw of String(text || "").split("\n")) {
    const line = raw.replace(/\s+$/, "");
    if (!line) continue;
    const cur = line.startsWith("*");
    const name = line.replace(/^\*?\s+/, "").split(" ")[0];
    if (!name || name.startsWith("(")) continue;
    if (cur) out.current = name;
    if (name.startsWith("remotes/")) out.remote.push(name.replace(/^remotes\//, ""));
    else out.local.push(name);
  }
  return out;
}

// Wiring entry point used by deviceTool. `a` is the raw tool args, `cwd` the project root,
// `deps.run(cmd) -> {code,output}` the injected shell runner (coderShell). Never throws: a
// missing runner, a non-repo, or a bad op all come back as { error } / a structured note.
async function gitTool(a, cwd, deps) {
  a = a || {}; deps = deps || {};
  const op = a.op || a.command || a.action || a.subcommand;
  if (!op) return { error: "git_tool needs an 'op' — one of: status, log, diff, show, blame, branch" };
  const built = buildGitCommand(op, a);
  if (built.error) return built;
  if (typeof deps.run !== "function") return { error: "no shell runner available" };
  let res;
  try { res = await deps.run(built.cmd); } catch (e) { return { error: (e && e.message) || String(e) }; }
  const output = res && res.output != null ? String(res.output) : "";
  if (res && res.code && /not a git repository/i.test(output)) return { error: "not a git repository (no .git here)" };
  if (res && res.code && output && !/\S/.test(output)) return { error: "git exited with code " + res.code };
  if (res && res.code && built.op === "log" && /does not have any commits/.test(output)) return { op: "log", commits: [] };
  // any other failure (bad ref, untracked file for blame, bad -L) is git's message, not rows to parse
  if (res && res.code && /\S/.test(output)) return { error: "git " + built.op + " failed: " + output.trim().split("\n").filter((l) => /\S/.test(l)).slice(0, 4).join(" | ").slice(0, 400) };
  if (built.op === "status") return { op: "status", status: parseStatus(output) };
  if (built.op === "log") return { op: "log", commits: parseLog(output) };
  if (built.op === "blame") return { op: "blame", file: a.path || a.file, lines: parseBlame(output, a.max) };
  if (built.op === "branch") return { op: "branch", branches: parseBranches(output) };
  // diff / show: structured parsing adds little over the raw patch — return it (already capped by coderShell).
  return { op: built.op, output: output || "(no output)" };
}

module.exports = {
  gitTool, buildGitCommand,
  parseStatus, parseLog, parseBlame, parseBranches,
  shq, OP_ALIASES, WRITE_OPS,
};
