#!/usr/bin/env node
"use strict";
// A scripted ACP agent for tests. FAKE_ACP_SCRIPT picks the behaviour:
//   edit     — asks permission to edit, writes note.txt via the client fs on allow
//   exec     — asks permission to run FAKE_ACP_CMD (execute kind)
//   slow     — streams forever until session/cancel, then stops with "cancelled"
//   badinit  — exits before answering initialize
//   outside  — tries to read ../secret.txt through the client fs
//   sandbox  — writes FAKE_ACP_PATH directly from this process and reports the result
// Every request it receives is appended to FAKE_ACP_LOG (one JSON line each).
const fs = require("fs");
const script = process.env.FAKE_ACP_SCRIPT || "edit";
const log = (m) => { if (process.env.FAKE_ACP_LOG) fs.appendFileSync(process.env.FAKE_ACP_LOG, JSON.stringify(m) + "\n"); };
if (script === "badinit") { process.stdout.write("not json at all\n"); process.exit(3); }
let buf = "", id = 1000, cancelled = false;
const pend = new Map();
const send = (o) => process.stdout.write(JSON.stringify(Object.assign({ jsonrpc: "2.0" }, o)) + "\n");
const ask = (method, params) => new Promise((res) => { const i = ++id; pend.set(i, res); send({ id: i, method, params }); });
const update = (sessionId, u) => send({ method: "session/update", params: { sessionId, update: u } });
const text = (sid, t) => update(sid, { sessionUpdate: "agent_message_chunk", content: { type: "text", text: t } });

async function prompt(m) {
  const sid = m.params.sessionId;
  update(sid, { sessionUpdate: "agent_thought_chunk", content: { type: "text", text: "thinking" } });
  if (script === "edit" || script === "exec") {
    const exec = script === "exec";
    const tc = { toolCallId: "t1", title: exec ? "bash" : "edit note.txt", kind: exec ? "execute" : "edit", status: "pending", rawInput: exec ? { command: process.env.FAKE_ACP_CMD || "ls" } : { path: "note.txt" }, locations: exec ? [] : [{ path: "note.txt" }] };
    update(sid, Object.assign({ sessionUpdate: "tool_call" }, tc));
    const r = await ask("session/request_permission", { sessionId: sid, toolCall: tc, options: [{ optionId: "ok1", name: "Allow", kind: "allow_once" }, { optionId: "ok2", name: "Always", kind: "allow_always" }, { optionId: "no1", name: "Reject", kind: "reject_once" }] });
    const allowed = r.result && r.result.outcome && r.result.outcome.outcome === "selected" && /^ok/.test(r.result.outcome.optionId);
    if (allowed && !exec) { const w = await ask("fs/write_text_file", { sessionId: sid, path: process.cwd() + "/note.txt", content: "hello from acp" }); if (w.error) text(sid, "write failed: " + w.error.message); }
    update(sid, { sessionUpdate: "tool_call_update", toolCallId: "t1", status: allowed ? "completed" : "failed", content: [{ type: "content", content: { type: "text", text: allowed ? "done" : "rejected" } }] });
    text(sid, allowed ? "applied" : "skipped");
    return { stopReason: "end_turn", usage: { inputTokens: 120, outputTokens: 7, totalTokens: 127, cachedReadTokens: 40 } };
  }
  if (script === "outside") {
    const r = await ask("fs/read_text_file", { sessionId: sid, path: process.cwd() + "/../secret.txt" });
    text(sid, r.error ? "refused: " + r.error.message : "read: " + r.result.content);
    return { stopReason: "end_turn" };
  }
  if (script === "sandbox") {
    let res; try { fs.writeFileSync(process.env.FAKE_ACP_PATH, "x"); res = "wrote"; } catch (e) { res = "denied " + e.code; }
    let rd; try { fs.readFileSync(process.env.FAKE_ACP_SECRET, "utf8"); rd = "read-secret"; } catch (e) { rd = "secret-" + e.code; }
    text(sid, res + " " + rd + " " + (process.env.NEXUS_SANDBOXED || "unsandboxed"));
    return { stopReason: "end_turn" };
  }
  if (script === "slow") {
    while (!cancelled) { text(sid, "."); await new Promise((r) => setTimeout(r, 30)); }
    return { stopReason: "cancelled" };
  }
  text(sid, "hi");
  return { stopReason: "end_turn" };
}

process.stdin.setEncoding("utf8");
process.stdin.on("data", (d) => {
  buf += d; let nl;
  while ((nl = buf.indexOf("\n")) >= 0) {
    const line = buf.slice(0, nl); buf = buf.slice(nl + 1); if (!line.trim()) continue;
    const m = JSON.parse(line); log(m);
    if (m.id != null && !m.method && pend.has(m.id)) { pend.get(m.id)(m); pend.delete(m.id); continue; }
    if (m.method === "initialize") send({ id: m.id, result: { protocolVersion: 1, agentCapabilities: { mcpCapabilities: { http: true } }, authMethods: [] } });
    else if (m.method === "session/new") send({ id: m.id, result: { sessionId: "s1", configOptions: [{ id: "mode", category: "mode", type: "select", currentValue: "build", options: [{ value: "build" }, { value: "plan" }] }, { id: "model", category: "model", type: "select", currentValue: "a", options: [{ value: "a" }, { value: "b" }] }] } });
    else if (m.method === "session/set_config_option") send({ id: m.id, result: {} });
    else if (m.method === "session/prompt") prompt(m).then((r) => send({ id: m.id, result: r }));
    else if (m.method === "session/cancel") cancelled = true;
    else if (m.id != null) send({ id: m.id, error: { code: -32601, message: "nope" } });
  }
});
process.stdin.on("end", () => process.exit(0));
