"use strict";
// Local-agent tool catalog + `discover` search (a Glitch idea): let the agent look
// up which tool fits a need by keyword instead of relying on a fixed prompt list —
// useful once MCP tools inflate the toolset. Pure/testable.
// Keep this in step with the agent's real tool set (the schemas in native-tools.js
// and the system-prompt list in darknode.js). `discover` searches these, so a stale
// entry makes a real tool invisible to the agent.
const TOOL_CATALOG = [
  ["read_file", "read a file's contents"],
  ["write_file", "create or overwrite a file"],
  ["edit_file", "find and replace within a file"],
  ["multi_edit", "apply several find/replace edits to one file atomically"],
  ["apply_patch", "apply a unified diff, anchored on context (line numbers can drift)"],
  ["list_dir", "list the entries of a directory"],
  ["run_command", "run a shell command and get its output"],
  ["run_background", "start a long-running command in the background"],
  ["check_background", "check a background command's output/status"],
  ["stop_background", "stop a background command"],
  ["search", "grep file contents for a pattern"],
  ["find", "find files by glob pattern"],
  ["batch", "run several read-only lookups (read/search/glob/list) in one call to save round-trips"],
  ["repo_map", "ranked file+symbol map of the repo to get oriented fast"],
  ["outline", "list one file's functions/classes/types in order with line numbers"],
  ["find_symbol", "jump to where a function/class/symbol is defined"],
  ["find_references", "every usage/caller of a symbol across the repo (impact analysis)"],
  ["module_graph", "what imports a file and what it imports (blast radius)"],
  ["http_fetch", "make an HTTP(S) request to a url"],
  ["web_search", "search the web for a query"],
  ["view_image", "load a local image (screenshot/diagram/mockup) so a vision model can see it"],
  ["verify", "auto-detect and run the project's own tests/build"],
  ["invariants", "lint the pending diff against .nexus/invariants.json rules"],
  ["attest", "report what this run touched (files/commands/network) from the audit log"],
  ["bisect", "binary-search checkpoints to find the turn that broke the tests"],
  ["explain_break", "blame the turn most likely to have broken a failing test"],
  ["shrink", "delta-debug the edits to the minimal subset that still breaks the test"],
  ["todo_write", "track a structured task list for the current turn"],
  ["sysinfo", "OS, CPU, memory and disk information"],
  ["list_processes", "list running processes"],
  ["make_dir", "create a directory"],
  ["move", "move or rename a file"],
  ["copy", "copy a file"],
  ["delete", "delete a file"],
  ["remember", "save a durable project convention or preference to NEXUS.md"],
  ["spawn_agents", "run several independent sub-tasks in parallel via sub-agents"],
  ["ask_user", "pause and ask the user a multiple-choice question when a decision is theirs"],
  ["discover", "search available tools by keyword"],
  ["browser_status", "check if the user's own browser is attachable (agentic control)"],
  ["browser_tabs", "list the tabs the user already has open in their browser"],
  ["browser_read", "read the visible text of a tab the user is looking at"],
  ["browser_eval", "run JavaScript inside one of the user's open tabs"],
  ["browser_screenshot", "screenshot one of the user's open browser tabs"],
];
function discoverTools(query, catalog) {
  catalog = catalog || TOOL_CATALOG;
  const words = String(query || "").toLowerCase().split(/\s+/).filter(Boolean);
  const hit = words.length
    ? catalog.filter(([n, d]) => words.some((w) => n.toLowerCase().includes(w) || d.toLowerCase().includes(w)))
    : catalog.slice();
  return hit.map(([name, description]) => ({ name, description }));
}
module.exports = { TOOL_CATALOG, discoverTools };
