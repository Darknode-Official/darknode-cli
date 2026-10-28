"use strict";
// Capability-based gates for the agent tool-dispatch loop.
//
// The danger gate (/guard), the enterprise policy and the compiled-in HARD_DENY
// floor must screen EVERY tool that ultimately runs a shell command — not only
// run_command/run_background. Otherwise a jailbroken/compromised model (exactly
// the threat these gates exist for) just picks another name — verify, bisect,
// shrink, lint_format — to slip a destructive command past them.
//
// Plan mode is advertised as a read-only posture, so it must block everything
// that writes, executes or egresses the network — by MEMBERSHIP, so a tool that
// is simply absent from a hand-typed list is not silently allowed to run.

// Tools whose argument reaches a shell (directly or via coderShell/runTest).
const EXEC_TOOLS = new Set([
  "run_command", "run_background", "write_stdin",
  "verify", "run_tests", "test_project",
  "bisect", "regression_bisect",
  "shrink", "minimize_change", "ddmin",
  "explain_break", "explainbreak", "blame_turn",
  "lint_format", "lint", "format", "fmt",
]);

// Tools blocked while plan mode is on: everything mutating, executing or egressing.
const PLAN_BLOCKED = new Set([
  "write_file", "edit_file", "multi_edit", "multiedit", "apply_patch", "patch", "undo_edit", "replace_in_files",
  "delete", "delete_file", "rm", "move", "move_file", "rename", "copy", "copy_file", "make_dir", "mkdir",
  "spawn_agents", "notebook_edit", "notebook", "ipynb", "remember", "todo_write", "todos", "todo_list", "write_todos", "stop_background",
  "http_fetch", "web_fetch", "fetch_url", "http", "web_search", "search_web", "google", "browser_eval", "browser_exec", "browser_screenshot", "browser_shot",
  ...EXEC_TOOLS,
]);

const isExecTool = (name) => EXEC_TOOLS.has(name);
// The shell command an exec tool will run, for the danger gate and policy. bisect, shrink and
// explain_break take it as `test` (a.command is only their fallback), write_stdin as `input`;
// reading only a.command let `bisect {test: "rm -rf ~"}` past the gate as "no command".
const execCommand = (name, a) => { a = a || {}; const c = a.command != null && a.command !== "" ? a.command : a.test != null && a.test !== "" ? a.test : name === "write_stdin" ? (a.input != null ? a.input : a.text) : undefined; return c == null ? undefined : String(c); };
const isPlanBlocked = (name) => PLAN_BLOCKED.has(name) || String(name || "").startsWith("mcp__");

module.exports = { EXEC_TOOLS, PLAN_BLOCKED, isExecTool, isPlanBlocked, execCommand };
