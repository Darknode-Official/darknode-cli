"use strict";
// ================= ACP client (Agent Client Protocol) =================
// Drives an engine that speaks ACP (JSON-RPC 2.0, one JSON object per line on
// stdio) instead of scraping its plain-text output. What that buys over the
// classic one-shot `<bin> run "<prompt>"` path:
//   - real tool calls as they happen (title, kind, status, files, output) for the
//     TUI's tool cards, plus streamed text and thinking
//   - the engine ASKS before acting (session/request_permission) and Nexus answers
//     from its own mode, guard and permission rules, so plan mode, deny rules and
//     the destructive-command guard apply to the engine's tools too
//   - file reads/writes the engine routes through the client stay inside the
//     project jail; real token usage from the prompt result
//   - a clean cancel (session/cancel) before any process kill
// Zero dependencies. The host passes callbacks; this module never touches the TUI.

const { spawn } = require("child_process");
const fs = require("fs");
const path = require("path");

const PROTOCOL_VERSION = 1;
const READ_KINDS = new Set(["read", "search", "think", "fetch"]); // what plan mode lets through (fetch = reading the web)

// ACP mcpServers entries from Nexus's { name: { command, args, env } | { url, headers } } map.
function toAcpMcpServers(servers, caps) {
  const out = [];
  const pairs = (o) => Object.keys(o || {}).map((k) => ({ name: k, value: String(o[k]) }));
  for (const name of Object.keys(servers || {})) {
    const s = servers[name];
    if (s && s.command) out.push({ name, command: s.command, args: (s.args || []).map(String), env: pairs(s.env) });
    else if (s && s.url) {
      const t = String(s.type || "").toLowerCase() === "sse" ? "sse" : "http";
      if (caps && caps.mcpCapabilities && caps.mcpCapabilities[t]) out.push({ type: t, name, url: s.url, headers: pairs(s.headers) });
    }
  }
  return out;
}

// Pick the optionId for a decision ("allow" | "allow_always" | "reject") from the
// options the agent offered. Falls back across once/always of the same polarity.
function pickOption(options, decision) {
  const opts = Array.isArray(options) ? options : [];
  const want = decision === "allow_always" ? ["allow_always", "allow_once"] : decision === "allow" ? ["allow_once", "allow_always"] : ["reject_once", "reject_always"];
  for (const k of want) { const o = opts.find((x) => x && x.kind === k); if (o) return o.optionId; }
  return null;
}

// Plain text of a tool_call / tool_call_update content array.
function contentText(content) {
  if (!Array.isArray(content)) return "";
  const parts = [];
  for (const c of content) {
    if (!c) continue;
    if (c.type === "content" && c.content && c.content.type === "text") parts.push(c.content.text || "");
    else if (c.type === "diff") parts.push("diff " + (c.path || "") + "\n" + diffLines(c.oldText, c.newText));
    else if (c.type === "text") parts.push(c.text || "");
  }
  return parts.join("\n");
}
function diffLines(a, b) {
  const A = String(a == null ? "" : a).split("\n"), B = String(b == null ? "" : b).split("\n");
  let i = 0; while (i < A.length && i < B.length && A[i] === B[i]) i++;
  let ja = A.length - 1, jb = B.length - 1; while (ja >= i && jb >= i && A[ja] === B[jb]) { ja--; jb--; }
  return A.slice(i, ja + 1).map((l) => "-" + l).concat(B.slice(i, jb + 1).map((l) => "+" + l)).slice(0, 200).join("\n");
}

class AcpClient {
  // opts: { cmd, args, cwd, env, onNotify(method, params), onRequest(method, params) -> Promise<result>, onExit(code, stderr), spawnFn }
  constructor(opts) {
    this.o = opts;
    this.id = 0; this.pend = new Map(); this.buf = ""; this.err = ""; this.closed = false;
    const sp = opts.spawnFn || spawn;
    this.p = sp(opts.cmd, opts.args || [], { cwd: opts.cwd, env: opts.env || process.env, detached: process.platform !== "win32", stdio: ["pipe", "pipe", "pipe"] });
    this.p.stdout.setEncoding("utf8"); this.p.stderr.setEncoding("utf8");
    this.p.stdout.on("data", (d) => this._data(d));
    this.p.stderr.on("data", (d) => { this.err += d; if (this.err.length > 20000) this.err = this.err.slice(-20000); if (opts.onActivity) opts.onActivity(); });
    this.p.stdin.on("error", () => {});
    const done = (code, e) => {
      if (this.closed) return; this.closed = true;
      const why = e ? "spawn error: " + e.message : "agent exited (code " + code + ")" + (this.err.trim() ? ": " + this.err.trim().split("\n").slice(-3).join(" | ") : "");
      for (const [, r] of this.pend) r.reject(new Error(why));
      this.pend.clear();
      if (opts.onExit) opts.onExit(code, this.err, e);
    };
    this.p.on("error", (e) => done(null, e));
    this.p.on("close", (code) => done(code));
  }
  get pid() { return this.p.pid; }
  _write(obj) { if (this.closed) return; try { this.p.stdin.write(JSON.stringify(obj) + "\n"); } catch (_) {} }
  _data(d) {
    if (this.o.onActivity) this.o.onActivity();
    this.buf += d;
    let nl;
    while ((nl = this.buf.indexOf("\n")) >= 0) {
      const line = this.buf.slice(0, nl).trim(); this.buf = this.buf.slice(nl + 1);
      if (!line || line[0] !== "{") continue; // stray log lines on stdout are skipped, not fatal
      let m; try { m = JSON.parse(line); } catch (_) { continue; }
      if (m.method && m.id != null) this._serve(m);
      else if (m.method) { try { this.o.onNotify && this.o.onNotify(m.method, m.params || {}); } catch (_) {} }
      else if (m.id != null && this.pend.has(m.id)) { const r = this.pend.get(m.id); this.pend.delete(m.id); if (m.error) { const e = new Error((m.error && m.error.message) || "ACP error"); e.code = m.error.code; e.data = m.error.data; r.reject(e); } else r.resolve(m.result); }
    }
  }
  async _serve(m) {
    let result, error;
    try {
      if (!this.o.onRequest) throw Object.assign(new Error("method not found: " + m.method), { code: -32601 });
      result = await this.o.onRequest(m.method, m.params || {});
    } catch (e) { error = { code: e.code || -32603, message: e.message || String(e) }; }
    this._write(error ? { jsonrpc: "2.0", id: m.id, error } : { jsonrpc: "2.0", id: m.id, result: result === undefined ? null : result });
  }
  request(method, params) {
    if (this.closed) return Promise.reject(new Error("agent is not running"));
    const id = ++this.id;
    return new Promise((resolve, reject) => { this.pend.set(id, { resolve, reject }); this._write({ jsonrpc: "2.0", id, method, params: params || {} }); });
  }
  notify(method, params) { this._write({ jsonrpc: "2.0", method, params: params || {} }); }
  kill(sig) { if (this.p.pid == null) return; try { process.kill(-this.p.pid, sig || "SIGTERM"); } catch (_) { try { this.p.kill(sig || "SIGTERM"); } catch (__) {} } }
  close() { try { this.p.stdin.end(); } catch (_) {} }
}

// Map one session/update into host callbacks. Kept pure for tests.
function routeUpdate(u, h, st) {
  if (!u || typeof u !== "object") return;
  const t = u.sessionUpdate;
  if (t === "agent_message_chunk") { const c = u.content || {}; if (c.type === "text" && c.text) { st.text += c.text; h.onText && h.onText(c.text); } }
  else if (t === "agent_thought_chunk") { const c = u.content || {}; if (c.type === "text" && c.text) h.onThought && h.onThought(c.text); }
  else if (t === "tool_call") {
    const tc = { id: u.toolCallId, title: u.title || u.kind || "tool", kind: u.kind || "other", status: u.status || "pending", input: u.rawInput, locations: u.locations || [], text: contentText(u.content) };
    st.tools.set(tc.id, tc); h.onTool && h.onTool(tc);
  } else if (t === "tool_call_update") {
    const tc = st.tools.get(u.toolCallId) || { id: u.toolCallId, title: u.title || "tool", kind: u.kind || "other", locations: [] };
    if (u.title) tc.title = u.title; if (u.kind) tc.kind = u.kind; if (u.status) tc.status = u.status;
    if (u.rawInput !== undefined) tc.input = u.rawInput; if (u.locations) tc.locations = u.locations;
    const txt = contentText(u.content); if (txt) tc.text = txt;
    if (u.rawOutput !== undefined) tc.output = u.rawOutput;
    st.tools.set(tc.id, tc); h.onToolUpdate && h.onToolUpdate(tc);
  } else if (t === "plan") { h.onPlan && h.onPlan(u.entries || []); }
  else if (t === "usage_update") { st.ctx = { used: u.used, size: u.size, cost: u.cost }; h.onUsage && h.onUsage(st.ctx); }
  else if (t === "current_mode_update") { h.onMode && h.onMode(u.currentModeId); }
}

// Run ONE prompt turn on an ACP agent. Resolves (never rejects) with
//   { ok, interrupted, output, stopReason, usage, ctx, acpFailed, error }
// acpFailed = the handshake itself failed (the host should fall back to its
// classic path); once a session exists, failures are reported as ok:false.
// o: { cmd, args, cwd, env, prompt, plan, model, mcpServers, decide(toolCall, options) -> Promise<"allow"|"allow_always"|"reject"|"cancel">,
//      jail(absPath) -> realPath (throws outside), onText, onThought, onTool, onToolUpdate, onPlan, onUsage, onWrite(path),
//      ctl: { kids: [] }, idle(kill) -> { touch, clear } (engine-watchdog's idleWatchdog), spawnFn }
function runTurn(o) {
  return new Promise((resolve) => {
    const st = { text: "", tools: new Map(), ctx: null };
    let sid = null, interrupted = false, settled = false, cancelT = null, wd = null;
    const finish = (r) => { if (settled) return; settled = true; if (cancelT) clearTimeout(cancelT); if (wd) wd.clear(); try { client.close(); } catch (_) {} setTimeout(() => client.kill("SIGTERM"), 300); resolve(Object.assign({ output: st.text, ctx: st.ctx, tools: [...st.tools.values()] }, r)); };
    const onRequest = async (method, p) => {
      if (method === "session/request_permission") {
        if (interrupted) return { outcome: { outcome: "cancelled" } };
        const tc = Object.assign({}, st.tools.get(p.toolCall && p.toolCall.toolCallId) || {}, p.toolCall || {});
        let d = "reject";
        try { d = o.decide ? await o.decide({ id: tc.toolCallId || tc.id, title: tc.title || "", kind: tc.kind || "other", input: tc.rawInput !== undefined ? tc.rawInput : tc.input, locations: tc.locations || [] }, p.options || []) : "allow"; } catch (_) { d = "reject"; }
        if (d === "cancel") return { outcome: { outcome: "cancelled" } };
        const optionId = pickOption(p.options, d);
        return optionId ? { outcome: { outcome: "selected", optionId } } : { outcome: { outcome: "cancelled" } };
      }
      if (method === "fs/read_text_file") {
        const real = o.jail(p.path);
        let text = fs.readFileSync(real, "utf8");
        if (p.line || p.limit) { const lines = text.split("\n"); const s = Math.max(0, (p.line || 1) - 1); text = lines.slice(s, p.limit ? s + p.limit : undefined).join("\n"); }
        return { content: text };
      }
      if (method === "fs/write_text_file") {
        if (o.plan) throw Object.assign(new Error("plan mode is on: writes are blocked"), { code: -32000 });
        const real = o.jail(p.path);
        fs.mkdirSync(path.dirname(real), { recursive: true });
        fs.writeFileSync(real, String(p.content == null ? "" : p.content));
        if (o.onWrite) o.onWrite(real);
        return null;
      }
      throw Object.assign(new Error("method not supported by this client: " + method), { code: -32601 });
    };
    const client = new AcpClient({
      cmd: o.cmd, args: o.args, cwd: o.cwd, env: o.env, spawnFn: o.spawnFn,
      onActivity: () => { if (wd) wd.touch(); },
      onNotify: (method, p) => { if (method === "session/update" && (!sid || !p.sessionId || p.sessionId === sid)) routeUpdate(p.update, o, st); },
      onRequest,
      onExit: (code, stderr, e) => { if (!settled) finish(sid ? { ok: false, interrupted, error: e ? e.message : "agent exited (code " + code + ")", stderr } : { ok: false, acpFailed: true, interrupted, error: e ? e.message : "agent exited before the handshake (code " + code + ")" + (String(stderr || "").trim() ? ": " + String(stderr).trim().split("\n").slice(-2).join(" | ") : "") }); },
    });
    if (o.idle) wd = o.idle(() => client.kill("SIGKILL")); // hang guard: fires only after a long silence (and never while the user is answering)
    if (o.ctl && o.ctl.kids) o.ctl.kids.push(() => {
      interrupted = true;
      if (sid) client.notify("session/cancel", { sessionId: sid });
      cancelT = setTimeout(() => { client.kill("SIGINT"); setTimeout(() => client.kill("SIGKILL"), 1200); }, 1500); // an agent that ignores cancel is stopped anyway
    });
    (async () => {
      let init;
      try {
        init = await withTimeout(client.request("initialize", { protocolVersion: PROTOCOL_VERSION, clientCapabilities: { fs: { readTextFile: !!o.jail, writeTextFile: !!o.jail }, terminal: false }, clientInfo: { name: "nexus", version: o.version || "" } }), o.handshakeMs || 20000, "initialize timed out");
        if (!init || typeof init.protocolVersion !== "number") throw new Error("not an ACP agent (bad initialize reply)");
      } catch (e) { return finish({ ok: false, acpFailed: true, error: e.message }); }
      let sess;
      try {
        sess = await withTimeout(client.request("session/new", { cwd: o.cwd, mcpServers: toAcpMcpServers(o.mcpServers, init.agentCapabilities) }), o.handshakeMs || 20000, "session/new timed out");
        sid = sess && sess.sessionId; if (!sid) throw new Error("agent returned no session id");
      } catch (e) { return finish({ ok: false, acpFailed: !/auth/i.test(e.message), needsAuth: /auth/i.test(e.message) || e.code === -32000, error: e.message }); }
      // Best effort: the engine's own read-only mode for plan, and the user's model. Nexus's
      // permission answers enforce plan mode either way, so a refusal here is not fatal.
      await applyConfig(client, sid, sess, { plan: o.plan, model: o.model });
      try {
        const r = await client.request("session/prompt", { sessionId: sid, prompt: [{ type: "text", text: o.prompt }] });
        const stop = (r && r.stopReason) || "end_turn";
        finish({ ok: stop !== "refusal" && !interrupted && stop !== "cancelled", interrupted: interrupted || stop === "cancelled", stopReason: stop, usage: (r && r.usage) || null });
      } catch (e) { finish({ ok: false, interrupted, error: e.message }); }
    })();
  });
}

function withTimeout(p, ms, msg) {
  let t; return Promise.race([p, new Promise((_, rej) => { t = setTimeout(() => rej(new Error(msg)), ms); })]).finally(() => clearTimeout(t));
}

// Select plan mode / model through whichever API the agent exposes: configOptions
// (session/set_config_option) or the older modes list (session/set_mode).
async function applyConfig(client, sid, sess, want) {
  const opts = (sess && Array.isArray(sess.configOptions)) ? sess.configOptions : [];
  const find = (id) => opts.find((c) => c && (c.id === id || c.category === id));
  const has = (c, v) => c && Array.isArray(c.options) && c.options.some((x) => x && x.value === v);
  const tries = [];
  const mode = find("mode");
  if (want.plan) {
    if (has(mode, "plan")) tries.push(["session/set_config_option", { sessionId: sid, configId: mode.id, value: "plan" }]);
    else if (sess && sess.modes && Array.isArray(sess.modes.availableModes) && sess.modes.availableModes.some((m) => m.id === "plan")) tries.push(["session/set_mode", { sessionId: sid, modeId: "plan" }]);
  }
  const model = find("model");
  if (want.model && has(model, want.model) && model.currentValue !== want.model) tries.push(["session/set_config_option", { sessionId: sid, configId: model.id, value: want.model }]);
  const applied = [];
  for (const [m, p] of tries) { try { await withTimeout(client.request(m, p), 8000, m + " timed out"); applied.push(m + ":" + (p.value || p.modeId)); } catch (_) {} }
  return applied;
}

// The policy Nexus applies to a permission request. Pure: the host supplies the
// guard/permission checks. Returns "allow" | "reject" | "ask" (host asks the user).
//   mode: 0 normal, 1 auto-accept, 2 plan, 3 bypass
//   check(toolCall) -> { deny, ask, warn } (strings or null) from guard, permission rules and the project jail
function policyFor(mode, tc, check) {
  if (mode === 3) return { decision: "allow" };
  const kind = String(tc.kind || "other");
  if (/(^|[^a-z])ask_user\b/i.test(String(tc.title || "")) || /^mcp__nexus__/.test(String(tc.title || ""))) return { decision: "allow" }; // the Nexus ask bridge (read-only in plan mode) only raises the user's popup
  if (mode === 2 && !READ_KINDS.has(kind)) return { decision: "reject", why: "plan mode is on: " + kind + " is blocked" };
  const c = check ? check(tc) || {} : {};
  if (c.deny) return { decision: "reject", why: c.deny };
  if (c.ask) return { decision: "ask", why: c.ask }; // e.g. reaching outside the project: asks even in auto-accept (that accepts edits IN the project)
  if (c.warn && mode === 0) return { decision: "ask", why: c.warn };
  return { decision: "allow" };
}

// The shell command a tool call will run, when it is an execute call.
function commandOf(tc) {
  const i = tc && tc.input;
  if (!i || typeof i !== "object") return tc && tc.kind === "execute" ? String(tc.title || "") : "";
  const c = i.command != null ? i.command : i.cmd != null ? i.cmd : i.script;
  if (Array.isArray(c)) return c.join(" ");
  return c != null ? String(c) : (tc.kind === "execute" ? String(tc.title || "") : "");
}

// Tolerant JSONC read (comments, trailing commas) for engine config files. null on failure.
function readJsonc(file) {
  let raw; try { raw = fs.readFileSync(file, "utf8").replace(/^\uFEFF/, ""); } catch (_) { return null; }
  try { return JSON.parse(raw); } catch (_) {}
  try { return JSON.parse(raw.replace(/("(?:\\.|[^"\\])*")|\/\/[^\n]*|\/\*[\s\S]*?\*\//g, (m, str) => str || "").replace(/,(\s*[}\]])/g, "$1")); } catch (_) { return null; }
}

// opencode only sends session/request_permission for tools set to "ask". Make edit, bash
// and webfetch ask (so Nexus's plan mode, deny rules and guard apply to them), but never
// override a permission the user configured themselves. Returns the JSON for
// OPENCODE_CONFIG_CONTENT, or null when there is nothing to add.
function opencodePermOverlay(userConfigs) {
  const set = new Set();
  for (const c of userConfigs || []) {
    if (!c || typeof c !== "object") continue;
    if (typeof c.permission === "string") return null; // one blanket setting covers every tool
    if (c.permission && typeof c.permission === "object") for (const k of Object.keys(c.permission)) set.add(k);
  }
  const perm = {};
  for (const k of ["edit", "bash", "webfetch"]) if (!set.has(k)) perm[k] = "ask";
  return Object.keys(perm).length ? JSON.stringify({ permission: perm }) : null;
}
function opencodeUserConfigs(cwd, home, env) {
  env = env || process.env;
  const xdg = env.XDG_CONFIG_HOME || path.join(home, ".config");
  const files = [path.join(xdg, "opencode", "opencode.json"), path.join(xdg, "opencode", "opencode.jsonc"), path.join(xdg, "opencode", "config.json"), path.join(cwd, "opencode.json"), path.join(cwd, "opencode.jsonc"), path.join(cwd, ".opencode", "opencode.json"), path.join(cwd, ".opencode", "opencode.jsonc")];
  if (env.OPENCODE_CONFIG) files.push(env.OPENCODE_CONFIG);
  return files.map(readJsonc).filter(Boolean);
}

module.exports = { readJsonc, opencodePermOverlay, opencodeUserConfigs, AcpClient, runTurn, routeUpdate, toAcpMcpServers, pickOption, contentText, policyFor, commandOf, applyConfig, PROTOCOL_VERSION, READ_KINDS };
