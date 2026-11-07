"use strict";
// hub/tool — the `sessions` agent tool: lets an agent run other agents in background
// sessions, hand them a task, wait until they finish or need a person, and read their
// screen. The same tool is offered to Nexus's own loop (darknode.js deviceTool) and to
// external engines through the nexus MCP bridge (ask-mcp.js). Returns { error } instead
// of throwing.
const path = require("path"), fs = require("fs");
const P = require("./paths");

const SCHEMA = {
  description: "Run other coding agents in background sessions (the Nexus session hub) and coordinate with them. " +
    "action=spawn starts one (Nexus by default, or agent: claude|codex|opencode|gemini, or a shell command) in a folder inside this project, optionally with a first prompt; " +
    "send types a prompt into a session; wait blocks until a session is idle, blocked (waiting for a person) or done; " +
    "peek reads its screen; list shows every session with working/blocked/idle/done; kill stops one. " +
    "A person can watch or take over any session with `nexus attach <name>`.",
  properties: {
    action: { type: "string", enum: ["list", "spawn", "send", "wait", "peek", "kill"], description: "what to do" },
    id: { type: "string", description: "session id or name (send, wait, peek, kill)" },
    name: { type: "string", description: "spawn: a short name for the new session" },
    agent: { type: "string", description: "spawn: nexus (default), claude, codex, opencode or gemini" },
    command: { type: "string", description: "spawn: run this shell command instead of an agent" },
    cwd: { type: "string", description: "spawn: folder inside this project (default: the project root)" },
    prompt: { type: "string", description: "spawn: first prompt, typed once the agent is ready" },
    text: { type: "string", description: "send: the prompt or reply to type (Enter is pressed after it)" },
    until: { type: "string", description: "wait: idle, blocked, done, or stopped (= anything but working; the default)" },
    timeout_s: { type: "number", description: "wait: give up after this many seconds (default 600, max 3600)" },
    lines: { type: "number", description: "peek/wait: how many screen lines to return (default 40)" },
  },
  required: ["action"],
};

const AGENTS = new Set(["nexus", "claude", "codex", "opencode", "gemini"]);
const slim = (s) => ({ id: s.id, name: s.name, state: s.state, kind: s.kind === "nexus" ? "nexus" : (s.cmd || []).join(" "), cwd: s.cwd, title: s.title || "", attached: s.attached || 0, exitCode: s.exitCode });

async function sessionsTool(a, cwd, deps = {}) {
  a = a || {};
  try {
    if (!P.supported()) return { error: "background sessions need Linux or macOS" };
    const ensure = deps.ensureHub || require("./cli").ensureHub, call = deps.call || P.call;
    const action = String(a.action || "list").toLowerCase();
    const root = path.resolve(cwd || process.cwd());
    await ensure();
    const ask = async (m, o) => { const r = await call(m, o); if (!r.ok) throw new Error(r.error || "the hub refused"); return r; };
    if (action === "list") { const r = await ask({ op: "list" }); return { sessions: r.sessions.map(slim) }; }
    if (action === "spawn") {
      const dir = path.resolve(root, a.cwd || ".");
      if (dir !== root && !dir.startsWith(root + path.sep)) return { error: "spawn: cwd must be inside the project (" + root + ")" };
      if (!fs.existsSync(dir)) return { error: "spawn: no such folder " + dir };
      const agent = String(a.agent || "nexus").toLowerCase();
      if (!a.command && !AGENTS.has(agent)) return { error: "spawn: agent must be nexus, claude, codex, opencode or gemini (or give a command)" };
      const cmd = a.command ? ["/bin/sh", "-c", String(a.command)] : agent === "nexus" ? null : [agent];
      const r = await ask({ op: "spawn", name: a.name, cwd: dir, cmd, prompt: a.prompt, cols: 120, rows: 40 });
      return { session: slim(r.session), hint: "watch it with: nexus attach " + r.session.name };
    }
    if (!a.id) return { error: action + " needs id (a session id or name; action=list shows them)" };
    if (action === "send") {
      if (a.text == null || String(a.text) === "") return { error: "send needs text" };
      const r = await ask({ op: "send", id: String(a.id), text: String(a.text) });
      return { sent: true, session: slim(r.session) };
    }
    if (action === "wait") {
      const t = Math.min(3600, Math.max(1, Number(a.timeout_s) || 600));
      const r = await ask({ op: "wait", id: String(a.id), until: a.until || "stopped", timeout: t, lines: Number(a.lines) || 40 }, { timeout: (t + 10) * 1000 });
      return { reached: r.reached, state: r.session.state, session: slim(r.session), screen: r.tail };
    }
    if (action === "peek") { const r = await ask({ op: "peek", id: String(a.id), lines: Number(a.lines) || 40 }); return { session: slim(r.session), screen: r.text }; }
    if (action === "kill") {
      if (process.env.NEXUS_HUB_ID && (String(a.id) === process.env.NEXUS_HUB_ID || String(a.id) === process.env.NEXUS_HUB_NAME)) return { error: "kill: that is this session" };
      const r = await ask({ op: "kill", id: String(a.id) }); return { stopping: slim(r.session) };
    }
    return { error: "unknown action " + action + " (list, spawn, send, wait, peek, kill)" };
  } catch (e) { return { error: (e && e.message) || String(e) }; }
}

// The shell command a call will run, for the danger gate and policy (tool-gates execCommand).
const gateCommand = (a) => { a = a || {}; const act = String(a.action || "").toLowerCase(); return act === "spawn" ? (a.command || a.agent || "nexus") : act === "send" ? a.text : ""; };

module.exports = { sessionsTool, SCHEMA, gateCommand, slim };
