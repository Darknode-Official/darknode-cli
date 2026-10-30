#!/usr/bin/env node
"use strict";
// ============================================================================
// ask-mcp — a tiny, dependency-free MCP (Model Context Protocol) server, run
// out-of-process by an external engine (claude, codex, …) so its model gains
// ONE Nexus tool it otherwise can't have: `ask_user`, the real terminal popup.
//
// The engine spawns this over stdio and speaks JSON-RPC 2.0. On a tools/call we
// forward the question to the Nexus TUI over the local socket named in
// $NEXUS_ASK_SOCK (see ask-bridge.js), wait for the user's answer, and return it
// as the tool result. Everything else (initialize / tools/list) is answered
// locally. No network, no deps — clean-room MCP, same stdio framing Nexus's own
// MCP client uses.
// ============================================================================
const net = require("net");

const SOCK = process.env.NEXUS_ASK_SOCK || "";
const PROTOCOLS = ["2025-06-18", "2025-03-26", "2024-11-05"];

const ASK_TOOL = {
  name: "ask_user",
  description:
    "Pause and ask the human operator a question in the Nexus terminal UI, then wait for their answer. " +
    "Use ONLY when a real decision is genuinely theirs to make — an ambiguous requirement, a destructive or " +
    "irreversible choice, or picking among approaches. Never for something you can decide or look up yourself, " +
    "and never more than needed. Three forms: pick-one (pass options), pick-many (pass options and multi:true), " +
    "or free-text (pass input:true with no options).",
  inputSchema: {
    type: "object",
    properties: {
      question: { type: "string", description: "The question to show the user." },
      options: { type: "array", items: { type: "string" }, description: "2-9 choices for a pick-one or pick-many question." },
      multi: { type: "boolean", description: "Allow selecting several options (checkboxes)." },
      input: { type: "boolean", description: "Free-text answer: the user types a reply (give no options)." },
      placeholder: { type: "string", description: "Short hint text for the free-text field." },
    },
    required: ["question"],
  },
};

function send(msg) { try { process.stdout.write(JSON.stringify(msg) + "\n"); } catch (_) {} }
function reply(id, result) { send({ jsonrpc: "2.0", id, result }); }
function replyErr(id, code, message) { send({ jsonrpc: "2.0", id, error: { code, message } }); }

// Forward one question to the Nexus TUI and resolve with its normalized answer.
function askNexus(args) {
  return new Promise((resolve, reject) => {
    if (!SOCK) return reject(new Error("Nexus ask bridge is not available (no NEXUS_ASK_SOCK)"));
    const sock = net.connect(SOCK);
    let buf = "", done = false;
    const finish = (fn, v) => { if (done) return; done = true; try { sock.end(); } catch (_) {} fn(v); };
    sock.setEncoding("utf8");
    sock.on("connect", () => {
      try {
        sock.write(JSON.stringify({ id: 1, question: args.question, options: args.options, multi: args.multi, input: args.input, placeholder: args.placeholder }) + "\n");
      } catch (e) { finish(reject, e instanceof Error ? e : new Error(String(e))); }
    });
    sock.on("data", (d) => {
      buf += d;
      const nl = buf.indexOf("\n");
      if (nl < 0) return;
      let resp; try { resp = JSON.parse(buf.slice(0, nl)); } catch (e) { return finish(reject, new Error("bad bridge response")); }
      if (resp.error) return finish(reject, new Error(resp.error));
      finish(resolve, resp.answer);
    });
    sock.on("error", (e) => finish(reject, e instanceof Error ? e : new Error(String(e))));
    sock.on("close", () => { if (!done) finish(reject, new Error("Nexus ask bridge closed before answering")); });
  });
}

// Render the normalized answer as plain text the model reads as its tool result.
function fmtAnswer(ans) {
  if (!ans || ans.cancelled || ans.skipped) return "The user dismissed the question without answering. Decide yourself or ask differently.";
  if (ans.answer != null) return "The user answered: " + String(ans.answer);
  if (Array.isArray(ans.selected)) return "The user selected: " + (ans.selected.join(", ") || "(none)");
  if (ans.selected != null) return "The user chose: " + String(ans.selected);
  return JSON.stringify(ans);
}

async function handle(msg) {
  const id = msg.id, method = msg.method;
  if (id === undefined) return; // a notification (no id) never gets a reply, whatever its method
  if (method === "initialize") {
    return reply(id, {
      protocolVersion: PROTOCOLS.includes(msg.params && msg.params.protocolVersion) ? msg.params.protocolVersion : PROTOCOLS[0], // never echo a version we don't speak
      capabilities: { tools: {} },
      serverInfo: { name: "nexus", version: "1.0.0" },
    });
  }
  if (method === "ping") return reply(id, {}); // MCP liveness check: an empty result, never an error
  if (method === "tools/list") return reply(id, { tools: [ASK_TOOL] });
  if (method === "tools/call") {
    const p = msg.params || {};
    if (p.name !== "ask_user") return replyErr(id, -32602, "Unknown tool: " + p.name); // the spec's code for an unknown tool
    const a = p.arguments;
    if (!a || typeof a !== "object" || typeof a.question !== "string" || !a.question.trim()) return replyErr(id, -32602, "Invalid params: ask_user needs a non-empty string question");
    try {
      const ans = await askNexus(a);
      return reply(id, { content: [{ type: "text", text: fmtAnswer(ans) }] });
    } catch (e) {
      return reply(id, { content: [{ type: "text", text: "Could not reach the user: " + ((e && e.message) || e) }], isError: true });
    }
  }
  return replyErr(id, -32601, "method not found: " + method);
}

// Drive the stdio JSON-RPC loop only when run as a real MCP server (not when
// required by the test runner — attaching stdin handlers there could exit it).
function main() {
  let rbuf = "";
  process.stdin.setEncoding("utf8");
  process.stdin.on("data", (d) => {
    rbuf += d;
    let nl;
    while ((nl = rbuf.indexOf("\n")) >= 0) {
      const line = rbuf.slice(0, nl); rbuf = rbuf.slice(nl + 1);
      if (!line.trim()) continue;
      let msg; try { msg = JSON.parse(line); } catch (_) { replyErr(null, -32700, "Parse error"); continue; }
      // a batch: answer each member (this shim's replies are independent lines; clients match by id)
      for (const m of Array.isArray(msg) ? msg : [msg]) {
        if (!m || typeof m !== "object" || Array.isArray(m)) { replyErr(null, -32600, "Invalid Request"); continue; } // a bare `null`/number line threw in handle() and killed the server
        handle(m).catch(() => {});
      }
    }
  });
  process.stdin.on("end", () => process.exit(0));
  process.on("SIGINT", () => process.exit(0));
  process.on("SIGTERM", () => process.exit(0));
}

if (require.main === module) main();

module.exports = { fmtAnswer, ASK_TOOL, handle, askNexus }; // for unit tests
