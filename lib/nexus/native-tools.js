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

const S = (desc) => ({ type: "string", description: desc });

// Input schemas for Nexus's built-in tools. Deliberately small; `additionalProperties` is left
// open (not set false) so a model passing an extra hint isn't hard-rejected by a strict provider.
const TOOL_SCHEMAS = {
  read_file: { description: "Read a text file's contents.", properties: { path: S("file path") }, required: ["path"] },
  write_file: { description: "Create or overwrite a text file.", properties: { path: S("file path"), content: S("full new file contents") }, required: ["path", "content"] },
  edit_file: { description: "Find and replace a unique snippet within a file (whitespace-tolerant).", properties: { path: S("file path"), find: S("exact text to find"), replace: S("replacement text") }, required: ["path", "find", "replace"] },
  multi_edit: { description: "Apply several find/replace edits to ONE file atomically (all-or-nothing).", properties: { path: S("file path"), edits: { type: "array", description: "list of {find, replace}", items: { type: "object", properties: { find: S("text to find"), replace: S("replacement"), replaceAll: { type: "boolean" } }, required: ["find", "replace"] } } }, required: ["path", "edits"] },
  apply_patch: { description: "Apply a unified diff; anchors on context so drifted @@ line numbers still apply.", properties: { patch: S("unified diff text") }, required: ["patch"] },
  list_dir: { description: "List the entries of a directory.", properties: { path: S("directory (default: cwd)") }, required: [] },
  run_command: { description: "Run a shell command and get its output.", properties: { command: S("shell command") }, required: ["command"] },
  run_background: { description: "Start a long-running command in the background.", properties: { command: S("shell command") }, required: ["command"] },
  check_background: { description: "Check output of a background command.", properties: { id: S("job id (optional)") }, required: [] },
  stop_background: { description: "Stop a background command.", properties: { id: S("job id") }, required: ["id"] },
  search: { description: "Grep file contents for a pattern.", properties: { pattern: S("regex or text"), path: S("dir to search (default: cwd)") }, required: ["pattern"] },
  find: { description: "Find files by glob pattern.", properties: { glob: S("glob e.g. **/*.js"), path: S("root (default: cwd)") }, required: ["glob"] },
  http_fetch: { description: "Make an HTTP(S) request to a URL.", properties: { url: S("url"), method: S("HTTP method (default GET)") }, required: ["url"] },
  web_search: { description: "Search the web for a query.", properties: { query: S("search query") }, required: ["query"] },
  sysinfo: { description: "OS, CPU, memory and disk information.", properties: {}, required: [] },
  list_processes: { description: "List running processes.", properties: { filter: S("optional name filter") }, required: [] },
  make_dir: { description: "Create a directory.", properties: { path: S("dir path") }, required: ["path"] },
  move: { description: "Move or rename a file.", properties: { from: S("source path"), to: S("destination path") }, required: ["from", "to"] },
  copy: { description: "Copy a file.", properties: { from: S("source path"), to: S("destination path") }, required: ["from", "to"] },
  delete: { description: "Delete a file.", properties: { path: S("file path") }, required: ["path"] },
  repo_map: { description: "Ranked file + symbol map of the project to get oriented fast.", properties: {}, required: [] },
  find_symbol: { description: "Find where a function/class/type is defined (go-to-definition).", properties: { name: S("symbol name") }, required: ["name"] },
  verify: { description: "Auto-detect and RUN the project's own tests/build/lint to check your work.", properties: { kind: S("test|build|lint|typecheck (optional)") }, required: [] },
  remember: { description: "Save a durable project convention or preference to NEXUS.md.", properties: { text: S("the fact to remember") }, required: ["text"] },
  discover: { description: "Search available tools by keyword.", properties: { query: S("keywords") }, required: ["query"] },
  todo_write: { description: "Record or update the task todo list.", properties: { todos: { type: "array", description: "todo items", items: { type: "object" } } }, required: ["todos"] },
  spawn_agents: { description: "Run several independent sub-tasks in parallel via sub-agents.", properties: { tasks: { type: "array", description: "independent task descriptions", items: { type: "string" } } }, required: ["tasks"] },
  browser_status: { description: "Check whether the user's own browser is reachable for agentic control (started with a remote-debugging port). If not, returns the exact command to start one that keeps their profile/logins.", properties: { port: S("debug port (default 9222)") }, required: [] },
  browser_tabs: { description: "List the tabs the user ALREADY has open in their running browser (title + URL). Use this to see what they are looking at — do NOT open a new tab.", properties: { port: S("debug port (default 9222)") }, required: [] },
  browser_read: { description: "Read the visible text of one of the user's open tabs (what they are actually seeing). Defaults to the active page; target selects another tab.", properties: { target: S("tab index, id, or a URL/title substring (optional)"), selector: S("optional CSS selector to read just one element"), max: S("max characters (optional)") }, required: [] },
  browser_eval: { description: "Run a JavaScript expression inside one of the user's open tabs and return the result. Powerful: can read page state or click/fill elements via the DOM.", properties: { expression: S("JavaScript to evaluate in the page"), target: S("tab index, id, or URL/title substring (optional)") }, required: ["expression"] },
  browser_screenshot: { description: "Save a PNG screenshot of one of the user's open tabs to the project directory.", properties: { target: S("tab index, id, or URL/title substring (optional)"), path: S("output file (optional)"), fullPage: { type: "boolean", description: "capture beyond the viewport" } }, required: [] },
};

function schemaFor(name) {
  return TOOL_SCHEMAS[name] || { description: name, properties: {}, required: [] };
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
      let out; try { out = await dispatch(tc.name, tc.args || {}); } catch (e) { out = "error: " + ((e && e.message) || e); }
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
  TOOL_SCHEMAS, schemaFor, buildToolList, runNativeToolLoop,
  toAnthropicTools, toOpenAITools, toOllamaTools,
  parseAnthropicReply, parseOpenAIReply, parseOllamaReply, normalizeReply, safeArgs,
  anthropicAssistantTurn, anthropicToolResults, openaiAssistantTurn, openaiToolResult,
};
