"use strict";
// ================= native-tools: structured (native) tool-calling for capable models =================
// Nexus's local loop asks the model to emit {thought,action,tool,args} JSON as TEXT and parses it.
// That is why normalizeToolCall exists — weak models mangle the JSON (wrong key, tool name with the
// args packed onto it, a bare shell string, an array, ...). Providers with NATIVE tool-calling
// (Ollama /api/chat `tools`, OpenAI `tools`, Anthropic `tools`) remove that whole class of failure:
// the runtime returns a guaranteed tool name + a JSON-schema-checked argument object.
//
// This module is the PURE translation layer (no network — the ollama client does the POST):
//   - TOOL_SCHEMAS / schemaFor / buildToolList : Nexus tool -> a JSON input schema
//   - toAnthropicTools / toOpenAITools / toOllamaTools : -> each provider's tool-spec shape
//   - parseAnthropicReply / parseOpenAIReply / normalizeReply : provider reply -> ONE shape,
//         { text, toolCalls:[{id,name,args}], done } — the same {name,args} the dispatch already runs
//   - the *ToolResult / *AssistantTurn helpers : build the follow-up messages for the next request
// Everything is string/JSON in, JSON out, and covered by test/run.js.

const { validateArgs } = require("./schema-check"); // pure JSON-schema-subset validator (NSAFE-039)

const S = (desc) => ({ type: "string", description: desc });

// Input schemas for Nexus's built-in tools. Deliberately small; `additionalProperties` is left
// open (not set false) so a model passing an extra hint isn't hard-rejected by a strict provider.
const TOOL_SCHEMAS = {
  read_file: { description: "Read a text file's contents. Big files come back in pages with a note saying where to continue.", properties: { path: S("file path"), offset: { type: "integer", description: "1-based line to start from (optional)" }, limit: { type: "integer", description: "max lines to return (optional)" } }, required: ["path"] },
  write_file: { description: "Create or overwrite a text file.", properties: { path: S("file path"), content: S("full new file contents") }, required: ["path", "content"] },
  edit_file: { description: "Find and replace a unique snippet within a file (whitespace-tolerant).", properties: { path: S("file path"), find: S("exact text to find"), replace: S("replacement text") }, required: ["path", "find", "replace"] },
  multi_edit: { description: "Apply several find/replace edits to ONE file atomically (all-or-nothing).", properties: { path: S("file path"), edits: { type: "array", description: "list of {find, replace}", items: { type: "object", properties: { find: S("text to find"), replace: S("replacement"), replaceAll: { type: "boolean" } }, required: ["find", "replace"] } } }, required: ["path", "edits"] },
  apply_patch: { description: "Apply a unified diff; anchors on context so drifted @@ line numbers still apply.", properties: { patch: S("unified diff text") }, required: ["patch"] },
  list_dir: { description: "List a folder: subfolders first, file sizes. depth:2-4 shows a compact tree (node_modules/.git/build are listed but not expanded). Says when the listing is cut off.", properties: { path: S("directory (default: cwd)"), depth: { type: "integer", description: "levels to expand (1-4, default 1)" } }, required: [] },
  run_command: { description: "Run a shell command and get its output.", properties: { command: S("shell command") }, required: ["command"] },
  run_background: { description: "Start a long-running command in the background.", properties: { command: S("shell command") }, required: ["command"] },
  check_background: { description: "Check a background command: its status and the output it printed SINCE YOUR LAST CHECK (earlier output is not repeated). full:true re-shows the recent tail. No id lists all jobs.", properties: { id: S("job id (optional)"), full: { type: "boolean", description: "re-show the recent output tail, not just what is new" } }, required: [] },
  write_stdin: { description: "Send input to a RUNNING background command's stdin (answer a prompt, drive a REPL or interactive CLI started with run_background), then return what it printed in response. A newline is added unless newline:false. Checked by the same command guard as run_command.", properties: { id: S("job id from run_background"), input: S("text to send"), newline: { type: "boolean", description: "append Enter (default true)" }, wait_ms: { type: "integer", description: "how long to collect the response (default 400, max 5000)" } }, required: ["id", "input"] },
  wait_for: { description: "Wait until something is READY instead of guessing with sleep: a local port accepts connections, a local URL answers, a file exists, or a background job prints a line matching a pattern (or exits). Returns as soon as it is ready, or times out (default 30s, max 180s) with the job's recent output.", properties: { port: { type: "integer", description: "local TCP port" }, url: S("local URL (localhost/127.0.0.1 only)"), status: { type: "integer", description: "with url: the exact HTTP status to wait for (default: any < 500)" }, file: S("file path to wait for"), job: S("background job id"), pattern: S("with job: regex to wait for in its output"), timeout_s: { type: "integer", description: "max seconds to wait (default 30)" } }, required: [] },
  stop_background: { description: "Stop a background command.", properties: { id: S("job id") }, required: ["id"] },
  search: { description: "Grep file contents for a regex (case-insensitive unless case_sensitive). Results are grouped by file with line numbers; long lines are cut around the match. context:N (0-5) adds N lines before/after each hit — often enough to skip a read_file. glob limits files (e.g. **/*.py or src/**/*.{ts,tsx}). Skips .git, node_modules, build output, binaries, and lockfiles/minified files (include_generated:true searches those).", properties: { pattern: S("regex or text"), path: S("file or folder (default: project root)"), glob: S("only files matching this glob"), context: { type: "integer", description: "lines of context around each match (0-5)" }, literal: { type: "boolean", description: "treat pattern as plain text" }, case_sensitive: { type: "boolean", description: "match case exactly" }, max_results: { type: "integer", description: "stop after N matches (default 100, max 500)" }, include_generated: { type: "boolean", description: "also search lockfiles / minified / source maps" } }, required: ["pattern"] },
  find: { description: "Find files by glob (**/*.js, src/**/*.{ts,tsx}, *.md) — or by a substring of the file name if there are no glob characters. sort:\"recent\" lists the most recently modified first. Skips .git, node_modules and build output.", properties: { glob: S("glob e.g. **/*.js, or part of a file name"), path: S("root (default: cwd)"), sort: S("\"name\" (default) or \"recent\""), max_results: { type: "integer", description: "default 300" } }, required: ["glob"] },
  http_fetch: { description: "Make an HTTP(S) request to a URL.", properties: { url: S("url"), method: S("HTTP method (default GET)") }, required: ["url"] },
  web_search: { description: "Search the web for a query.", properties: { query: S("search query") }, required: ["query"] },
  view_image: { description: "Load a local image file (png/jpg/jpeg/gif/webp/bmp/svg) so a multimodal model can SEE it — screenshots, diagrams, error captures, UI mockups. Base64-encodes it into a vision content block; refuses files >10MB or outside the project directory.", properties: { path: S("local image file path") }, required: ["path"] },
  git_tool: { description: "READ-ONLY structured git: inspect the repo and get back a parsed object, not raw porcelain. op status (branch + ahead/behind + changed files), log (recent commits), diff (working/staged patch), show (a commit), blame (line authorship), branch (local+remote). Mutating verbs (commit/add/push/reset/checkout/...) are refused — use run_command for those.", properties: { op: S("status | log | diff | show | blame | branch"), path: S("limit to this file (log/diff/show/blame)"), ref: S("commit/branch/range (diff/show)"), count: S("number of commits (log, default 20)"), staged: { type: "boolean", description: "diff the staged index (diff)" }, line: S("line range like 10,40 (blame)") }, required: ["op"] },
  lint_format: { description: "Auto-detect the project's formatter/linter and FIX code style in place (prettier/eslint --fix, ruff/black, gofmt -w, cargo fmt). Complements `verify`, which only reports. Pass check:true for report-only. A formatter that isn't installed is skipped gracefully.", properties: { check: { type: "boolean", description: "report only, don't rewrite files" }, path: S("limit to this file/dir (default: whole project)"), tool: S("force a specific formatter e.g. prettier, eslint, ruff, black"), all: { type: "boolean", description: "run every detected formatter, not just the first" } }, required: [] },
  notebook_edit: { description: "Read and edit Jupyter .ipynb notebook CELLS structurally (never hand-splice the JSON). op read (summarize cells), edit (replace a cell's source by index), insert (add a code/markdown cell), delete (remove a cell). Does not execute cells.", properties: { path: S("path to a .ipynb file"), op: S("read | edit | insert | delete"), index: S("cell index (0-based)"), source: S("new/added cell contents (edit/insert)"), cell_type: S("code | markdown (insert)") }, required: ["path"] },
  sysinfo: { description: "OS, CPU, memory and disk information.", properties: {}, required: [] },
  list_processes: { description: "List running processes.", properties: { filter: S("optional name filter") }, required: [] },
  make_dir: { description: "Create a directory.", properties: { path: S("dir path") }, required: ["path"] },
  move: { description: "Move or rename a file or folder (into an existing folder keeps the name, works across disks). Refuses to replace an existing destination unless overwrite:true.", properties: { from: S("source path"), to: S("destination path or folder"), overwrite: { type: "boolean", description: "replace an existing destination" } }, required: ["from", "to"] },
  copy: { description: "Copy a file or a whole folder (into an existing folder keeps the name). Refuses to replace an existing destination unless overwrite:true.", properties: { from: S("source path"), to: S("destination path or folder"), overwrite: { type: "boolean", description: "replace an existing destination" } }, required: ["from", "to"] },
  delete: { description: "Delete a file, an empty folder, or (with recursive:true) a folder and everything in it. A deleted FILE can be restored with undo_edit.", properties: { path: S("file or folder path"), recursive: { type: "boolean", description: "required to delete a non-empty folder" } }, required: ["path"] },
  repo_map: { description: "Ranked file + symbol map of the project to get oriented fast.", properties: {}, required: [] },
  find_symbol: { description: "Find where a function/class/type is defined (go-to-definition).", properties: { name: S("symbol name") }, required: ["name"] },
  find_references: { description: "Find every USAGE of a symbol across the repo — the reverse of find_symbol's go-to-definition. Returns all callers/references of a function, class, variable or type, grouped by file with line numbers, each tagged def / import / usage, and the most-referenced files first. Whole-word identifier match; read-only. Use it for impact analysis BEFORE renaming, changing a signature, or deleting a symbol.", properties: { name: S("the symbol/identifier to find usages of"), path: S("subtree to scan (default: whole project)"), context: { type: "number", description: "lines of surrounding context per hit (0-5, default 0)" } }, required: ["name"] },
  module_graph: { description: "The project's import/dependency graph — whole-FILE impact analysis, the level above find_references. With path: that file's internal imports, external packages, and every file that imports IT (its dependents). Without path: a project summary — the most-imported files and the likely entry points (files nothing imports). Read-only; JS/TS relative imports are resolved precisely, Python/Go best-effort. Use it to see a change's blast radius before editing a shared module.", properties: { path: S("a repo-relative source file (omit for a whole-project summary)"), top: { type: "number", description: "how many files to list in the summary (default 15)" } }, required: [] },
  read_symbol: { description: "Read ONE function, class, method or type by name — just its definition (with its doc comment), numbered, instead of the whole file. Much cheaper than read_file on a big file. Use outline to list a file's symbols first if unsure of the name. Read-only.", properties: { path: S("file containing the symbol"), name: S("symbol name, e.g. handleLogin or User.save"), index: { type: "integer", description: "which definition if the name appears more than once (0 = first)" } }, required: ["path", "name"] },
  json_query: { description: "Read one value from a JSON/JSONC file by path instead of loading the whole file — package.json scripts, one key of a big config, a record in a data dump. Path syntax: a.b.c, items[0].name, deps[\"@scope/pkg\"], -1 for the last element, * to map over all keys. keys_only:true lists the keys at that level. Read-only.", properties: { path: S("JSON or JSONC file"), query: S("path into the document (empty = root)"), keys_only: { type: "boolean", description: "return only the keys / length at that level" } }, required: ["path"] },
  replace_in_files: { description: "Find and replace across MANY files in one call — rename a function or variable, change an import path, swap a config key. Literal text by default; regex:true for a pattern ($1 groups in replace), word:true for whole-word only (safe renames), glob to limit files (e.g. **/*.ts or src/**/*.{js,jsx}). dry_run:true previews every change without writing — do that first for broad changes. Skips .git, node_modules, build output and binaries; protected paths are refused; each changed file can be reverted with undo_edit.", properties: { find: S("text (or regex with regex:true) to find"), replace: S("replacement text (\"\" deletes matches)"), path: S("file or folder to search (default: project root)"), glob: S("only files matching this glob"), regex: { type: "boolean", description: "treat find as a regular expression" }, word: { type: "boolean", description: "whole-word matches only" }, ignore_case: { type: "boolean", description: "case-insensitive" }, dry_run: { type: "boolean", description: "preview only, write nothing" } }, required: ["find", "replace"] },
  undo_edit: { description: "Undo YOUR most recent change to one file made this session with write_file, edit_file, multi_edit, apply_patch, replace_in_files, delete or move — restores the version before that change (or deletes the file if that change created it). Refuses if the file changed since (by you or the user) unless force:true. Call again to step further back. Does not undo run_command or folder deletes.", properties: { path: S("the file to restore"), force: { type: "boolean", description: "restore even if the file changed after that edit" } }, required: ["path"] },
  outline: { description: "The structural outline of ONE file: its functions, classes, types and methods in source order with line numbers. Get oriented in a big unfamiliar file fast without reading the whole thing. Read-only.", properties: { path: S("the file to outline") }, required: ["path"] },
  verify: { description: "Auto-detect and RUN the project's own tests/build/lint to check your work.", properties: { kind: S("test|build|lint|typecheck (optional)") }, required: [] },
  remember: { description: "Save a durable project convention or preference to NEXUS.md.", properties: { text: S("the fact to remember") }, required: ["text"] },
  discover: { description: "Search available tools by keyword.", properties: { query: S("keywords") }, required: ["query"] },
  todo_write: { description: "Record or update the task todo list.", properties: { todos: { type: "array", description: "todo items", items: { type: "object" } } }, required: ["todos"] },
  spawn_agents: { description: "Run several independent sub-tasks in parallel via sub-agents.", properties: { tasks: { type: "array", description: "independent task descriptions", items: { type: "string" } } }, required: ["tasks"] },
  batch: { description: "Run SEVERAL read-only lookups in ONE call and get all results back together: read files, grep patterns, glob/list files. Use this instead of many separate read_file/search/find/list_dir calls to save round-trips and tokens when investigating. Read-only: no writes, no shell. Up to 20 ops; output is size-capped.", properties: { ops: { type: "array", description: "list of read-only ops, in order", items: { type: "object", properties: { op: S("'read' (a file), 'search' (grep a pattern), 'glob' (find files by name/glob), or 'list' (list a directory)"), path: S("file or directory path (read/list, or search/glob root)"), pattern: S("regex or text to grep (op:search)"), glob: S("glob or name fragment to match (op:glob)"), start: { type: "number", description: "first line to return, 1-based (op:read)" }, end: { type: "number", description: "last line to return (op:read)" } }, required: ["op"] } } }, required: ["ops"] },
  browser_status: { description: "Check whether the user's own browser is reachable for agentic control (started with a remote-debugging port). If not, returns the exact command to start one that keeps their profile/logins.", properties: { port: S("debug port (default 9222)") }, required: [] },
  browser_tabs: { description: "List the tabs the user ALREADY has open in their running browser (title + URL). Use this to see what they are looking at — do NOT open a new tab.", properties: { port: S("debug port (default 9222)") }, required: [] },
  browser_read: { description: "Read the visible text of one of the user's open tabs (what they are actually seeing). Defaults to the active page; target selects another tab.", properties: { target: S("tab index, id, or a URL/title substring (optional)"), selector: S("optional CSS selector to read just one element"), max: S("max characters (optional)") }, required: [] },
  browser_eval: { description: "Run a JavaScript expression inside one of the user's open tabs and return the result. Powerful: can read page state or click/fill elements via the DOM.", properties: { expression: S("JavaScript to evaluate in the page"), target: S("tab index, id, or URL/title substring (optional)") }, required: ["expression"] },
  browser_screenshot: { description: "Save a PNG screenshot of one of the user's open tabs to the project directory.", properties: { target: S("tab index, id, or URL/title substring (optional)"), path: S("output file (optional)"), fullPage: { type: "boolean", description: "capture beyond the viewport" } }, required: [] },
};

// hasOwnProperty guard: `name` is model-controlled, so a plain [name] lookup would resolve
// "constructor"/"__proto__"/"toString" to an inherited member (a truthy function) instead of
// undefined — in schemaFor that leaks a junk schema, in preflightArgs it silently skips arg
// validation for those names.
function ownSchema(name) { return Object.prototype.hasOwnProperty.call(TOOL_SCHEMAS, name) ? TOOL_SCHEMAS[name] : null; }

function schemaFor(name) {
  return ownSchema(name) || { description: name, properties: {}, required: [] };
}

// Normalize a list of tool names (or already-built {name,description,input_schema} objects — e.g.
// MCP tools) into a common { name, description, input_schema } form. Defaults to all built-ins.
function buildToolList(names) {
  const list = (names && names.length) ? names : Object.keys(TOOL_SCHEMAS);
  return list.map((n) => {
    if (n && typeof n === "object") {
      const schema = n.input_schema || n.parameters || { type: "object", properties: n.properties || {}, required: n.required || [] };
      return { name: n.name, description: n.description || n.name, input_schema: schema };
    }
    const s = schemaFor(n);
    return { name: n, description: s.description, input_schema: { type: "object", properties: s.properties || {}, required: s.required || [] } };
  });
}

function toAnthropicTools(names) {
  return buildToolList(names).map((t) => ({ name: t.name, description: t.description, input_schema: t.input_schema }));
}
function toOpenAITools(names) {
  return buildToolList(names).map((t) => ({ type: "function", function: { name: t.name, description: t.description, parameters: t.input_schema } }));
}
// Ollama's /api/chat uses the OpenAI-style function shape.
const toOllamaTools = toOpenAITools;

// ---- reply parsing --------------------------------------------------------------------------
// Coerce a tool-call argument value into an object no matter how the provider delivered it
// (object already, JSON string, or garbage → {}). Never throws.
function safeArgs(v) {
  if (v == null) return {};
  if (typeof v === "object") return Array.isArray(v) ? { items: v } : v;
  if (typeof v === "string") { const t = v.trim(); if (!t) return {}; try { const p = JSON.parse(t); return p && typeof p === "object" && !Array.isArray(p) ? p : { value: p }; } catch (_) { return {}; } }
  return {};
}

function parseAnthropicReply(body) {
  body = body || {};
  const content = Array.isArray(body.content) ? body.content : [];
  let text = ""; const toolCalls = [];
  for (const b of content) {
    if (!b) continue;
    if (b.type === "text") text += b.text || "";
    else if (b.type === "tool_use") toolCalls.push({ id: b.id || ("call_" + toolCalls.length), name: b.name, args: safeArgs(b.input) });
  }
  return { text: text.trim(), toolCalls, done: !toolCalls.length };
}

function parseOpenAIReply(body) {
  body = body || {};
  const choice = (body.choices && body.choices[0]) || {};
  const msg = choice.message || {};
  const toolCalls = [];
  for (const tc of msg.tool_calls || []) {
    const fn = tc.function || {};
    toolCalls.push({ id: tc.id || ("call_" + toolCalls.length), name: fn.name, args: safeArgs(fn.arguments) });
  }
  return { text: String(msg.content == null ? "" : msg.content).trim(), toolCalls, done: !toolCalls.length };
}

// Ollama /api/chat returns { message: { content, tool_calls:[{function:{name, arguments}}] } }.
// arguments is an OBJECT (not a JSON string) — safeArgs handles either.
function parseOllamaReply(body) {
  body = body || {};
  const msg = body.message || {};
  const toolCalls = [];
  for (const tc of msg.tool_calls || []) {
    const fn = tc.function || {};
    toolCalls.push({ id: tc.id || ("call_" + toolCalls.length), name: fn.name, args: safeArgs(fn.arguments) });
  }
  return { text: String(msg.content == null ? "" : msg.content).trim(), toolCalls, done: !toolCalls.length };
}

function normalizeReply(provider, body) {
  if (provider === "openai") return parseOpenAIReply(body);
  if (provider === "anthropic") return parseAnthropicReply(body);
  return parseOllamaReply(body); // ollama (default)
}

// ---- follow-up messages for the NEXT request turn -------------------------------------------
// Anthropic: the assistant's tool_use blocks go back as an assistant turn, then a USER turn holds
// one tool_result block per call.
function anthropicAssistantTurn(text, toolCalls) {
  const content = [];
  if (text) content.push({ type: "text", text });
  for (const tc of toolCalls) content.push({ type: "tool_use", id: tc.id, name: tc.name, input: tc.args || {} });
  return { role: "assistant", content };
}
function anthropicToolResults(results) { // results: [{id, content, isError?}]
  return { role: "user", content: results.map((r) => ({ type: "tool_result", tool_use_id: r.id, content: String(r.content == null ? "" : r.content), is_error: !!r.isError })) };
}
// OpenAI / Ollama: the assistant turn carries tool_calls; each result is its own role:"tool" msg.
function openaiAssistantTurn(text, toolCalls) {
  return { role: "assistant", content: text || "", tool_calls: toolCalls.map((tc) => ({ id: tc.id, type: "function", function: { name: tc.name, arguments: typeof tc.args === "string" ? tc.args : JSON.stringify(tc.args || {}) } })) };
}
function openaiToolResult(id, content) { return { role: "tool", tool_call_id: id, content: String(content == null ? "" : content) }; }

// ---- native tool loop orchestrator ----------------------------------------------------------
// The whole edit->run->observe loop, provider-agnostic and dependency-injected so it is unit-
// testable with a fake model. `chat(messages, tools)` resolves { provider, body } (in real use,
// ollamaChatNative). `dispatch(name, args)` runs a tool and resolves a result string. It mutates
// nothing global: builds and returns the transcript, the final text, and every tool call made.
// Stops when the model returns no tool calls (done) or maxSteps is hit.
// Validate a model-supplied argument object against a built-in tool's schema
// before it is dispatched (NSAFE-039). Returns null when the tool is unknown
// (custom/test dispatch handles those) or the args are valid, else a short
// human-readable error. coerceScalars because numeric fields are typed as
// string; ignorePattern because the built-ins carry no pattern constraints and
// it keeps any future untrusted pattern out of the hot path.
function preflightArgs(name, args) {
  const schema = ownSchema(name);
  if (!schema) return null;
  const root = { type: "object", properties: schema.properties || {}, required: schema.required || [] };
  const r = validateArgs(root, args == null ? {} : args, { coerceScalars: true, ignorePattern: true });
  if (r.ok) return null;
  return "invalid arguments for " + name + ": " + r.errors.map((e) => (e.path ? e.path + " " : "") + e.code).join(", ");
}

async function runNativeToolLoop(opts) {
  const chat = opts.chat, dispatch = opts.dispatch;
  const tools = opts.tools || [];
  const maxSteps = opts.maxSteps || 20;
  const messages = (opts.messages || []).slice();
  const calls = [];
  let finalText = "", steps = 0, stopped = false;
  for (steps = 1; steps <= maxSteps; steps++) {
    if (opts.shouldStop && opts.shouldStop()) { stopped = true; break; }
    const res = await chat(messages, tools);
    const reply = normalizeReply(res && res.provider, res && res.body);
    const provider = (res && res.provider) || "ollama";
    if (opts.onReply) opts.onReply(reply, provider);
    if (!reply.toolCalls.length) { finalText = reply.text; break; }
    // record the assistant's tool turn in the provider's own shape
    messages.push(provider === "anthropic" ? anthropicAssistantTurn(reply.text, reply.toolCalls) : openaiAssistantTurn(reply.text, reply.toolCalls));
    const results = [];
    for (const tc of reply.toolCalls) {
      let out; const _ae = preflightArgs(tc.name, tc.args || {}); // reject malformed args before any tool runs
      if (_ae) out = "error: " + _ae;
      else try { out = await dispatch(tc.name, tc.args || {}); } catch (e) { out = "error: " + ((e && e.message) || e); }
      out = out == null ? "" : String(out);
      calls.push({ name: tc.name, args: tc.args || {}, result: out });
      if (opts.onTool) opts.onTool(tc, out);
      results.push({ id: tc.id, content: out });
    }
    if (provider === "anthropic") messages.push(anthropicToolResults(results));
    else for (const r of results) messages.push(openaiToolResult(r.id, r.content));
  }
  return { finalText, calls, steps, messages, stopped, hitLimit: steps > maxSteps };
}

module.exports = {
  TOOL_SCHEMAS, schemaFor, buildToolList, runNativeToolLoop, preflightArgs,
  toAnthropicTools, toOpenAITools, toOllamaTools,
  parseAnthropicReply, parseOpenAIReply, parseOllamaReply, normalizeReply, safeArgs,
  anthropicAssistantTurn, anthropicToolResults, openaiAssistantTurn, openaiToolResult,
};
