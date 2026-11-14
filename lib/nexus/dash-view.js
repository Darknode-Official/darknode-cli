"use strict";
// Pure builders for the /open dashboard: turn the live TUI transcript and agent
// list into plain JSON the browser can render (full conversation, terminal log,
// file activity). No I/O, so it is unit-tested directly (test/dashboard.test.js).

const ANSI = /\x1b\[[0-9;?]*[ -/]*[@-~]/g;
const strip = (s) => String(s == null ? "" : s).replace(ANSI, "");
const cap = (s, n) => { s = String(s == null ? "" : s); return s.length > n ? s.slice(0, n) + "\n… [" + (s.length - n).toLocaleString("en-US") + " more characters]" : s; };

const OUT_CAP = 20000, TEXT_CAP = 60000, INPUT_CAP = 8000, DIFF_ROWS = 400;

// Any tool result shape (string, content blocks, local-tool object) as text.
function asText(r) {
  if (r == null) return "";
  if (typeof r === "string") return r;
  if (Array.isArray(r)) return r.map((x) => (x && typeof x.text === "string") ? x.text : typeof x === "string" ? x : (x && x.type === "image") ? "[image]" : "").join("\n");
  if (typeof r === "object" && typeof r.output === "string") return r.output + (r.code ? "\n[exit " + r.code + "]" : "");
  try { return JSON.stringify(r, null, 2); } catch (_) { return String(r); }
}

const FILE_KEYS = ["file_path", "notebook_path", "path"];
const fileOf = (input) => { if (!input || typeof input !== "object") return ""; for (const k of FILE_KEYS) if (typeof input[k] === "string" && input[k]) return input[k]; return ""; };
const commandOf = (name, input) => (input && typeof input === "object" && typeof input.command === "string" && /^(Bash|run_command|run_background|BashOutput)$/.test(name)) ? input.command : "";

// What kind of thing a tool call did, for the activity icons and filters.
function kindOf(name) {
  const n = String(name || "");
  if (/^(Bash|run_command|run_background|BashOutput|KillShell|check_background)$/.test(n)) return "shell";
  if (/^(Read|read_file|NotebookRead|view_file)$/.test(n)) return "read";
  if (/^(Write|Edit|MultiEdit|NotebookEdit|write_file|edit_file|create_file|apply_patch)$/.test(n)) return "edit";
  if (/^(Glob|Grep|LS|list_dir|search|find_files|grep)$/.test(n)) return "search";
  if (/^(WebFetch|WebSearch|web_fetch|web_search|fetch_url)$/.test(n)) return "web";
  if (/^(Task|Agent|spawn_agents)$/.test(n)) return "agent";
  if (/^mcp__/.test(n)) return "mcp";
  if (/^(TodoWrite|ExitPlanMode)$/.test(n)) return "plan";
  return "tool";
}

function toolView(it, tail) {
  const out = it.result !== undefined ? asText(it.result) : (it.live && tail ? tail(it.live) : "");
  const v = {
    type: "tool", id: String(it.id || ""), name: String(it.name || "tool"), kind: kindOf(it.name), label: strip(it.label || it.name || "tool"),
    status: it.interrupted ? "stopped" : it.status === "err" ? "error" : it.status === "run" ? "running" : it.status === "wait" ? "waiting" : "done",
    start: it.start || 0, end: it.end || 0,
    file: fileOf(it.input), command: commandOf(String(it.name || ""), it.input),
    input: it.input == null ? "" : cap(typeof it.input === "string" ? it.input : JSON.stringify(it.input, null, 2), INPUT_CAP),
    output: cap(strip(out), OUT_CAP), live: it.result === undefined && !!it.live,
  };
  if (it.diff && Array.isArray(it.diff.rows)) v.diff = { added: it.diff.added || 0, removed: it.diff.removed || 0, rows: it.diff.rows.slice(0, DIFF_ROWS).map((r) => [r.t || " ", strip(r.text), r.ln || 0]), more: Math.max(0, it.diff.rows.length - DIFF_ROWS) };
  if (it._agId) v.agent = it._agId;
  return v;
}

function itemsView(items, tail) {
  const out = [];
  for (const it of items || []) {
    if (!it) continue;
    if (it.type === "text" && it.full) out.push({ type: "text", text: cap(strip(it.full), TEXT_CAP) });
    else if (it.type === "thinking" && it.full) out.push({ type: "thinking", text: cap(strip(it.full), TEXT_CAP) });
    else if (it.type === "tool") out.push(toolView(it, tail));
  }
  return out;
}

// The whole conversation, newest last. opts.tail(liveTail) -> text of a running command so far.
function conversation(transcript, opts) {
  const tail = opts && opts.tail;
  const out = [];
  (transcript || []).forEach((b, i) => {
    if (!b || b.role === "art") return;
    if (b.role === "user") out.push({ i, role: "user", text: cap(strip(b.text), TEXT_CAP) });
    else if (b.role === "system") { const t = Array.isArray(b.lines) ? b.lines.map(strip).join("\n") : strip(b.text); if (t.trim()) out.push({ i, role: "system", text: cap(t, OUT_CAP) }); }
    else if (b.role === "nexus") out.push({ i, role: "assistant", items: itemsView(b.items, tail) });
    else if (b.role === "diff") out.push({ i, role: "system", text: cap(strip(b.text || "[diff]"), OUT_CAP) });
  });
  return out;
}

// Every shell command in order, with its output: the "terminal" view.
function terminal(conv, bang) {
  const rows = [];
  for (const m of conv) {
    if (m.role === "system" && /^\$ /.test(m.text)) { const nl = m.text.indexOf("\n"); rows.push({ by: "you", command: m.text.slice(2, nl < 0 ? undefined : nl), output: nl < 0 ? "" : m.text.slice(nl + 1), status: /\nrunning…$/.test(m.text) ? "running" : "done" }); }
    if (m.role !== "assistant") continue;
    for (const it of m.items) if (it.type === "tool" && it.kind === "shell" && it.command) rows.push({ by: "agent", command: it.command, output: it.output, status: it.status, start: it.start, end: it.end, live: it.live });
  }
  return rows;
}

// Files the agent read, changed and searched, with counts; plus web fetches.
function fileActivity(conv) {
  const files = new Map(), searches = [], web = [];
  const hit = (p, k, t) => { if (!p) return; const f = files.get(p) || { path: p, read: 0, edit: 0, last: 0, diffs: 0 }; f[k]++; f.last = Math.max(f.last, t || 0); files.set(p, f); };
  for (const m of conv) {
    if (m.role !== "assistant") continue;
    for (const it of m.items) {
      if (it.type !== "tool") continue;
      if (it.kind === "read") hit(it.file, "read", it.start);
      else if (it.kind === "edit") { hit(it.file, "edit", it.start); if (it.diff && it.file) files.get(it.file).diffs++; }
      else if (it.kind === "search") searches.push({ label: it.label, status: it.status });
      else if (it.kind === "web") web.push({ label: it.label, status: it.status });
    }
  }
  return { files: [...files.values()].sort((a, b) => b.last - a.last), searches: searches.slice(-200), web: web.slice(-200) };
}

// Sub-agents with their own conversations.
function agentsView(agents, tail) {
  return (agents || []).map((a) => ({ id: a.id, task: strip(a.task), status: a.status, start: a.start || 0, end: a.end || 0, engine: a.engine || "", result: cap(strip(a.result), OUT_CAP), prompt: cap(strip(a.prompt || ""), INPUT_CAP), items: itemsView(a.items, tail) }));
}

// Cheap change signature, so the browser refetches the heavy detail only when something moved.
function revision(transcript, agents) {
  let h = (transcript || []).length + ":" + (agents || []).length;
  const tailBlocks = (transcript || []).slice(-3);
  for (const b of tailBlocks) {
    h += "|" + (b && b.role) + (b && b.text ? String(b.text).length : 0);
    for (const it of (b && b.items) || []) h += "," + (it.status || "") + (it.full ? it.full.length : 0) + "." + (it.result !== undefined ? asText(it.result).length : 0) + (it.live ? "L" + ((it.live.bytes || 0) + (it.live.droppedBytes || 0) + String(it.live.partial || "").length) : "");
  }
  for (const a of agents || []) h += "|" + a.status + ((a.items || []).length) + (a.result ? String(a.result).length : 0);
  return h;
}

module.exports = { asText, kindOf, conversation, terminal, fileActivity, agentsView, revision, strip };
