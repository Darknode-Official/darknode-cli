"use strict";
// ================= invariants: deterministic diff-lint the agent runs on ITS OWN diff =====
// A coding agent's single worst habit is making a change that passes the compiler/tests yet
// quietly violates a project rule the model never internalised: it leaves a stray debug log,
// adds a new TODO, slips a new dependency into package.json, edits a generated/vendored file,
// deletes a test, or touches a path it was told to keep its hands off. Humans catch these in
// review; by then the agent has moved on.
//
// `invariants` turns those project rules into DATA (.nexus/invariants.json) and lets the agent
// (or an automatic finish-gate) run its own pending diff through them BEFORE a turn is accepted.
// Because the rules are deterministic they need no model to evaluate, so the check is cheap,
// reproducible and reviewer-trustable — and a violation can trip the per-turn checkpoint to roll
// the change back. This is "invariants as code" applied to the agent's edits, not the runtime.
//
// WHY NOVEL: linters/pre-commit hooks lint the WORKING TREE against generic style rules. This
// lints the AGENT'S DIFF (added vs removed lines, file set, deps delta) against per-repo intent
// the author declared, as a tool the agent calls on itself mid-task — a self-review gate, not a
// CI step a human wired up. It only ever flags lines the diff ADDS, so pre-existing debt a rule
// would match never blocks an unrelated change.
//
// The engine is pure + dependency-free + deterministic: checkInvariants(files, rules) over a
// parsed diff. The git/fs I/O lives in the thin wiring entry (invariantsTool) so the core unit-
// tests with synthetic diffs, exactly like loopguard/filestate/diagnose.
//
// RULES (all optional; every rule is scoped to ADDED lines / the changed file set):
//   maxFiles            n        at most n files may change in one turn
//   allowPaths          [glob]   every changed file MUST match one of these globs
//   forbidPaths         [glob]   no changed file may match any of these (generated/vendored/etc.)
//   noDelete            [glob]   files matching these globs may not be deleted (e.g. "test/**")
//   noNewMarkers        bool|[s] forbid ADDING TODO/FIXME/HACK/XXX markers (or a custom word list)
//   noDebug             bool|[s] forbid ADDING debug lines (console.log/debugger/print(/dbg!/...)
//   noNewDeps           bool     forbid ADDING entries to a dependency manifest (package.json deps,
//                                requirements.txt, go.mod require, Cargo.toml [dependencies], ...)
//   forbidAdded         [regex]  forbid ADDING any line matching one of these regexes
//   requireTestWithSrc  bool     if any source file changed, a test file must change too (ratchet)
// Exposed agent tool (wired in darknode.js): invariants (aliases check_invariants, difflint).

// ---- tiny self-contained glob matcher (posix-ish; ** spans dirs, * within a segment) ----
function globToRe(g) {
  let re = "";
  for (let i = 0; i < g.length; i++) {
    const c = g[i];
    if (c === "*") {
      if (g[i + 1] === "*") { re += ".*"; i++; if (g[i + 1] === "/") i++; }
      else re += "[^/]*";
    } else if (c === "?") re += "[^/]";
    else if (".+^${}()|[]\\".includes(c)) re += "\\" + c;
    else re += c;
  }
  return new RegExp("^" + re + "$");
}
function matchesAny(rel, globs) {
  const p = String(rel || "").replace(/\\/g, "/").replace(/^\.\//, "");
  const base = p.split("/").pop();
  return (globs || []).some((g) => { try { const re = globToRe(g); return re.test(p) || re.test(base); } catch (_) { return false; } });
}

// ---- diff parsing: `git diff` unified text -> [{path, status, added:[{n,text}], removed:[text]}] ----
// status: "A" added, "D" deleted, "M" modified, "R" renamed. `added` carries 1-based NEW-file line
// numbers so a violation can point the agent at the exact line it just wrote.
function parseDiff(diffText) {
  const text = String(diffText == null ? "" : diffText);
  const files = [];
  let cur = null, newLineNo = 0;
  const lines = text.split("\n");
  const pushCur = () => { if (cur) files.push(cur); };
  for (let i = 0; i < lines.length; i++) {
    const ln = lines[i];
    if (ln.startsWith("diff --git ")) {
      pushCur();
      // "diff --git a/x b/y" — take the b-side path (handles most cases incl. spaces-free paths)
      const m = /^diff --git a\/(.+) b\/(.+)$/.exec(ln);
      cur = { path: m ? m[2] : (ln.split(" b/")[1] || ln.slice(11)), status: "M", added: [], removed: [] };
      newLineNo = 0;
      continue;
    }
    if (!cur) continue;
    if (ln.startsWith("new file mode")) { cur.status = "A"; continue; }
    if (ln.startsWith("deleted file mode")) { cur.status = "D"; continue; }
    if (ln.startsWith("rename to ")) { cur.status = "R"; cur.path = ln.slice(10).trim(); continue; }
    if (ln.startsWith("rename from ") || ln.startsWith("similarity index") || ln.startsWith("index ") || ln.startsWith("--- ") || ln.startsWith("+++ ")) continue;
    const hh = /^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@/.exec(ln);
    if (hh) { newLineNo = parseInt(hh[1], 10); continue; }
    if (ln[0] === "+") { cur.added.push({ n: newLineNo, text: ln.slice(1) }); newLineNo++; }
    else if (ln[0] === "-") { cur.removed.push(ln.slice(1)); }
    else if (ln[0] === " " || ln === "") { newLineNo++; }
    // "\ No newline at end of file" and anything else: ignore, don't advance
  }
  pushCur();
  return files;
}

// A whole untracked/new file surfaced outside `git diff` (git diff HEAD omits untracked files).
// Represent it as an all-added file so allow/forbid/marker/debug rules still see it.
function fileFromNewContent(path, content) {
  const added = String(content == null ? "" : content).split("\n").map((t, i) => ({ n: i + 1, text: t }));
  return { path, status: "A", added, removed: [] };
}

// Default signal words/patterns (used when a rule is `true` rather than a custom list).
const MARKER_WORDS = ["TODO", "FIXME", "HACK", "XXX", "WIP"];
const DEBUG_PATTERNS = [
  /\bconsole\.(log|debug|dir|trace)\s*\(/,
  /\bdebugger\b/,
  /\bprint\s*\(/,           // python/js debug prints
  /\bpp\s*\(/,
  /\bdbg!\s*\(/,            // rust
  /\bfmt\.Println\s*\(/,    // go debug
  /\bvar_dump\s*\(/,        // php
  /\bSystem\.out\.println\s*\(/,
];
// Files that declare dependencies — adding a line here with noNewDeps on is a new-dep signal.
const DEP_MANIFESTS = [
  "package.json", "requirements.txt", "pyproject.toml", "go.mod",
  "cargo.toml", "gemfile", "pom.xml", "build.gradle", "composer.json",
];
// Heuristic: is this path a source file vs a test file (for requireTestWithSrc).
function isTestPath(p) { return /(^|\/)(tests?|__tests__|spec)(\/|$)|(\.|_|-)(test|spec)\.|_test\.|test_/i.test(p); }
function isSourcePath(p) { return /\.(js|jsx|ts|tsx|py|go|rs|rb|java|c|cc|cpp|h|hpp|cs|php|swift|kt)$/i.test(p) && !isTestPath(p); }

function toRegexList(list) {
  return (list || []).map((r) => {
    if (r instanceof RegExp) return r;
    try { return new RegExp(String(r)); } catch (_) { try { return new RegExp(String(r).replace(/[.*+?^${}()|[\]\\]/g, "\\$&")); } catch (_2) { return null; } }
  }).filter(Boolean);
}

// Pure engine. `files` is the parsed diff (parseDiff output, optionally plus fileFromNewContent
// entries). Returns { ok, violations:[{rule,path,line,message}], checked:[ruleNames], files:n }.
function checkInvariants(files, rules) {
  files = Array.isArray(files) ? files : [];
  rules = rules && typeof rules === "object" ? rules : {};
  const V = [];
  const checked = [];
  const changed = files.map((f) => f.path);
  const add = (rule, path, line, message) => V.push({ rule, path, line: line || 0, message });

  if (rules.maxFiles != null) {
    checked.push("maxFiles");
    const n = Number(rules.maxFiles);
    if (changed.length > n) add("maxFiles", "", 0, "this turn changes " + changed.length + " files; the limit is " + n + " — split the work or raise maxFiles");
  }
  if (Array.isArray(rules.allowPaths) && rules.allowPaths.length) {
    checked.push("allowPaths");
    for (const f of files) if (!matchesAny(f.path, rules.allowPaths)) add("allowPaths", f.path, 0, f.path + " is outside the paths this task is allowed to touch (" + rules.allowPaths.join(", ") + ")");
  }
  if (Array.isArray(rules.forbidPaths) && rules.forbidPaths.length) {
    checked.push("forbidPaths");
    for (const f of files) if (matchesAny(f.path, rules.forbidPaths)) add("forbidPaths", f.path, 0, f.path + " matches a protected path (" + rules.forbidPaths.join(", ") + ") — do not modify it");
  }
  if (Array.isArray(rules.noDelete) && rules.noDelete.length) {
    checked.push("noDelete");
    for (const f of files) if (f.status === "D" && matchesAny(f.path, rules.noDelete)) add("noDelete", f.path, 0, f.path + " may not be deleted (matches noDelete)");
  }
  if (rules.noNewMarkers) {
    checked.push("noNewMarkers");
    const words = Array.isArray(rules.noNewMarkers) ? rules.noNewMarkers : MARKER_WORDS;
    const re = new RegExp("\\b(" + words.map((w) => String(w).replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join("|") + ")\\b");
    for (const f of files) for (const a of f.added) if (re.test(a.text)) add("noNewMarkers", f.path, a.n, "adds a " + (re.exec(a.text) || [])[1] + " marker: " + a.text.trim().slice(0, 100));
  }
  if (rules.noDebug) {
    checked.push("noDebug");
    const pats = Array.isArray(rules.noDebug) ? toRegexList(rules.noDebug) : DEBUG_PATTERNS;
    for (const f of files) for (const a of f.added) for (const p of pats) if (p.test(a.text)) { add("noDebug", f.path, a.n, "adds a debug/log line: " + a.text.trim().slice(0, 100)); break; }
  }
  if (rules.noNewDeps) {
    checked.push("noNewDeps");
    for (const f of files) {
      const base = String(f.path).split("/").pop().toLowerCase();
      if (!DEP_MANIFESTS.includes(base)) continue;
      // An added line that looks like a dependency entry (a quoted/bare name) — ignore pure
      // structural additions like a lone "{" or "}" or a version bump of an existing dep is hard
      // to tell apart, so we flag any added line that names something, and let the author allow it.
      for (const a of f.added) {
        const t = a.text.trim();
        if (!t || t === "{" || t === "}" || t === "[" || t === "]" || t === "}," || t === "],") continue;
        if (/^[#;]/.test(t)) continue; // comment
        add("noNewDeps", f.path, a.n, "adds a line to a dependency manifest (possible new dependency): " + t.slice(0, 100));
      }
    }
  }
  if (Array.isArray(rules.forbidAdded) && rules.forbidAdded.length) {
    checked.push("forbidAdded");
    const pats = toRegexList(rules.forbidAdded);
    for (const f of files) for (const a of f.added) for (let i = 0; i < pats.length; i++) if (pats[i].test(a.text)) { add("forbidAdded", f.path, a.n, "adds a forbidden pattern (/" + (rules.forbidAdded[i]) + "/): " + a.text.trim().slice(0, 100)); break; }
  }
  if (rules.requireTestWithSrc) {
    checked.push("requireTestWithSrc");
    const touchedSrc = files.some((f) => isSourcePath(f.path));
    const touchedTest = files.some((f) => isTestPath(f.path));
    if (touchedSrc && !touchedTest) add("requireTestWithSrc", "", 0, "source files changed but no test file was added or updated — add/adjust a test (requireTestWithSrc)");
  }

  return { ok: V.length === 0, violations: V, checked, files: changed.length };
}

// ---- thin wiring entry: gather the agent's pending diff and run the engine ----
// Compares the working tree against HEAD (tracked changes) and folds in untracked files, so a
// freshly-created file the agent just wrote is linted too. Reads rules from a.rules or
// .nexus/invariants.json. Never writes anything. Returns the engine result plus a short summary.
function invariantsTool(a, cwd, deps) {
  a = a || {};
  deps = deps || {};
  const cp = deps.cp || require("child_process");
  const fs = deps.fs || require("fs");
  const path = deps.path || require("path");
  let rules = a.rules && typeof a.rules === "object" ? a.rules : null;
  if (!rules) {
    try { rules = JSON.parse(fs.readFileSync(path.join(cwd, ".nexus", "invariants.json"), "utf8")); } catch (_) { rules = null; }
  }
  if (!rules || !Object.keys(rules).length) {
    return { error: "no invariants configured — create .nexus/invariants.json (e.g. {\"noDebug\":true,\"noNewMarkers\":true,\"noNewDeps\":true,\"allowPaths\":[\"src/**\"],\"requireTestWithSrc\":true}) or pass rules inline" };
  }
  let diffText = "";
  try { diffText = cp.execSync("git diff HEAD", { cwd, encoding: "utf8", maxBuffer: 2e7 }); }
  catch (_) {
    try { diffText = cp.execSync("git diff", { cwd, encoding: "utf8", maxBuffer: 2e7 }); } catch (_2) { return { error: "could not read a git diff here — invariants lints the agent's diff and needs a git repo" }; }
  }
  const files = parseDiff(diffText);
  // fold in untracked files (git diff HEAD omits them) as all-added
  try {
    const un = cp.execSync("git ls-files --others --exclude-standard", { cwd, encoding: "utf8", maxBuffer: 1e7 }).split("\n").map((s) => s.trim()).filter(Boolean);
    const seen = new Set(files.map((f) => f.path));
    for (const u of un) {
      if (seen.has(u)) continue;
      let content = ""; try { if (fs.statSync(path.join(cwd, u)).size <= 500000) content = fs.readFileSync(path.join(cwd, u), "utf8"); } catch (_) {}
      files.push(fileFromNewContent(u, content));
    }
  } catch (_) {}
  const res = checkInvariants(files, rules);
  res.summary = res.ok
    ? "invariants OK — " + res.files + " changed file(s) satisfy " + res.checked.length + " rule(s): " + res.checked.join(", ")
    : res.violations.length + " invariant violation(s) across " + res.files + " changed file(s). Fix them before finishing (or adjust .nexus/invariants.json if the rule is wrong).";
  return res;
}

module.exports = {
  invariantsTool, checkInvariants, parseDiff, fileFromNewContent,
  // exported for tests / reuse
  globToRe, matchesAny, isTestPath, isSourcePath,
  MARKER_WORDS, DEBUG_PATTERNS, DEP_MANIFESTS,
};
