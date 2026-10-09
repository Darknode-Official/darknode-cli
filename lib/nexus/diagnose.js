"use strict";
// ================= diagnose: make command failures legible =================
// When a shell command or test run exits non-zero, the raw output is often a wall of text and
// weaker models react poorly — they retry blindly, give up, or fixate on the wrong line. This
// module reads the output heuristically and returns a compact, structured diagnosis: the
// category of failure, the single most relevant line, and a concrete next-step hint. It is
// appended to the tool observation so the agent recovers deliberately instead of flailing.
//
// It also flags TRANSIENT failures (network blips, a busy port) where exactly one automatic
// retry is reasonable — the caller decides whether to act on `transient`.
//
// Pure, dependency-free, deterministic → unit-testable.  diagnose(output, code, command).

// Ordered rules: first match wins. Each: a test (regex or fn over the combined text) and a
// builder returning { category, summary, hint, transient }. `m` is the regex match if any.
const RULES = [
  { re: /(command not found|: not found|is not recognized as (?:an )?internal or external command)/i,
    build: (t, m) => { const cmd = (/^(?:.*?[:\s])?([\w.-]+): (?:command )?not found/i.exec(t) || [])[1] || (/'([\w.-]+)' is not recognized/i.exec(t) || [])[1]; return { category: "missing-command", summary: (cmd ? "`" + cmd + "` " : "a command ") + "is not installed or not on PATH", hint: "Install the tool (or the package that provides it), or use the project's own runner (check package.json scripts / Makefile). Don't retry the same command — it will fail identically." }; } },
  { re: /(Cannot find module|Module not found|ModuleNotFoundError|ImportError: No module named|error\[E0432\]|unresolved import)/i,
    build: (t) => { const mod = (/Cannot find module '([^']+)'|No module named '?([\w.-]+)'?|Module not found: Error: Can't resolve '([^']+)'/i.exec(t) || []); const name = mod[1] || mod[2] || mod[3]; return { category: "missing-dependency", summary: "a dependency is missing" + (name ? ": " + name : ""), hint: "Install deps (npm install / pip install -r / cargo fetch) or add the missing package. If it's a local path, the import path is wrong — check it against the repo map." }; } },
  { re: /(SyntaxError|Unexpected token|Unexpected end of|ParseError|IndentationError|error TS\d+|error\[E\d+\]|expected .* found)/i,
    build: (t) => { const loc = (/([\w./-]+):(\d+)(?::(\d+))?/.exec(t) || []); return { category: "syntax-error", summary: "the code has a syntax/parse/type error" + (loc[1] ? " near " + loc[1] + ":" + loc[2] : ""), hint: "Open the referenced file:line and fix the syntax before anything else — re-running won't help until the code parses." }; } },
  { re: /(ENOENT|No such file or directory)/i,
    build: (t) => { const p = (/ENOENT[^']*'([^']+)'|No such file or directory[:,]?\s*'?([^'\n]+)?/i.exec(t) || []); const path = (p[1] || p[2] || "").trim(); return { category: "no-such-path", summary: "a file or directory does not exist" + (path ? ": " + path : ""), hint: "Check the path and your working directory (list_dir), or create the parent first. The path is likely wrong, not the command." }; } },
  { re: /(EACCES|Permission denied|Operation not permitted)/i,
    build: () => ({ category: "permission", summary: "permission denied", hint: "You lack rights for this path/operation. Pick a writable location in the workspace; do not escalate privileges automatically." }) },
  { re: /(EADDRINUSE|address already in use|port \d+ is already in use)/i,
    build: (t) => { const port = (/:(\d{2,5})\b|port (\d{2,5})/i.exec(t) || []); return { category: "port-in-use", summary: "the port is already in use" + (port[1] || port[2] ? " (" + (port[1] || port[2]) + ")" : ""), hint: "Something is already listening. Use a different port, or stop the existing process (check background jobs / list_processes) before retrying." }; } },
  { re: /(ECONNREFUSED|ETIMEDOUT|ENOTFOUND|ECONNRESET|EAI_AGAIN|socket hang up|network (?:is )?unreachable|getaddrinfo)/i,
    build: (t, m) => ({ category: "network", summary: "a network request failed (" + (m[1] || "connection error") + ")", hint: "This is often transient. One retry is reasonable; if it persists the host/URL is wrong or the service is down — don't loop on it.", transient: true }) },
  { re: /(AssertionError|\bFAILED\b|\d+ (?:failed|failing)|Tests?:.*\bfail|✗|×\s|\bFAIL\b|panicked at|thread '.*' panicked)/i,
    build: (t) => { const c = (/(\d+)\s+(?:failed|failing)/i.exec(t) || /Tests:\s+(\d+)\s+failed/i.exec(t) || []); return { category: "test-failure", summary: (c[1] ? c[1] + " test(s) failing" : "tests are failing"), hint: "Read the first failing assertion (not the summary), find the file:line it names, and fix the code or the test. Re-run only after a change." }; } },
  { re: /(error:|error\b.*:|rejected|fatal:)/i,
    build: (t) => ({ category: "error", summary: "the command reported an error", hint: "Read the first error line above and address its specific cause before retrying." }) },
];

// Pick the single most relevant line to surface (the first line matching the chosen rule's
// signal, else the first non-empty line).
function keyLine(text, re) {
  const lines = String(text).split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
  if (re) { for (const l of lines) if (re.test(l)) return l.slice(0, 240); }
  return (lines[0] || "").slice(0, 240);
}

// diagnose(output, code, command?) -> null if the command clearly succeeded and says nothing
// notable, else { category, summary, hint, line, transient }.
function diagnose(output, code, command) {
  const text = String(output == null ? "" : output);
  const failed = (typeof code === "number" && code !== 0);
  // Nothing to diagnose on a clean success with no error-shaped text.
  if (!failed && !/\b(error|exception|failed|traceback|fatal)\b/i.test(text)) return null;
  for (const r of RULES) {
    const m = r.re.exec(text);
    if (m) { const d = r.build(text, m); d.line = keyLine(text, r.re); d.transient = !!d.transient; return d; }
  }
  if (failed) return { category: "nonzero-exit", summary: "the command exited with code " + code, hint: "No recognizable error pattern — read the output above for the cause.", line: keyLine(text, null), transient: false };
  return null;
}

// Render a diagnosis as a short suffix to attach to a tool observation.
function annotate(d) {
  if (!d) return "";
  return "\n\n[diagnosis] " + d.summary + ". " + d.hint + (d.transient ? " (transient — one retry ok.)" : "");
}

module.exports = { diagnose, annotate, RULES };
