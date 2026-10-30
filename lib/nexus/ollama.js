"use strict";
// Local/any-model client — chat, model listing, coder-model selection.
// By default talks to the local Ollama HTTP API (127.0.0.1:11434). If an
// OpenAI-COMPATIBLE endpoint is configured (DARKNODE_API_BASE, e.g. OpenAI,
// OpenRouter, Groq, DeepSeek, Together, Mistral, LM Studio, vLLM, llama.cpp),
// it transparently drives ANY model there instead — same agentic tool loop.
// The tool loop that USES this (ollamaExec / the TUI local turn) is in darknode.js.
const http = require("http");
const R = require("./retry");
// OLLAMA_HOST follows Ollama's own format: "host", "host:port" or "http://host:port"
// (what `ollama serve` users already export). 0.0.0.0 is a bind address, so connect
// to loopback. OLLAMA_PORT still works when OLLAMA_HOST carries no port.
function ollamaAddr(env) {
  env = env || process.env;
  const raw = String(env.OLLAMA_HOST || "").trim();
  let host = "127.0.0.1", port = 0;
  if (raw) {
    try { const u = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(raw) ? raw : "http://" + raw); host = u.hostname.replace(/^\[|\]$/g, "") || host; port = +u.port || 0; }
    catch (_) { host = raw; }
  }
  if (host === "0.0.0.0" || host === "::") host = "127.0.0.1";
  return { host, port: port || +(env.OLLAMA_PORT || 11434) };
}
const HOST = () => ollamaAddr().host;
const PORT = () => ollamaAddr().port;
// Context window requested from Ollama (tokens). Bigger = more memory; override with OLLAMA_NUM_CTX.
const NUM_CTX = () => Math.max(2048, +(process.env.OLLAMA_NUM_CTX || 16384) || 16384);
// Configured OpenAI-compatible base URL (any provider). When set, we route there.
const API_BASE = () => (process.env.DARKNODE_API_BASE || process.env.OPENAI_BASE_URL || process.env.OPENAI_API_BASE || "").trim();
const API_KEY = () => (process.env.DARKNODE_API_KEY || process.env.OPENAI_API_KEY || process.env.OPENROUTER_API_KEY || process.env.GROQ_API_KEY || "").trim();

// POST to any OpenAI-compatible /chat/completions. The tool loop's role:"tool"
// messages are mapped to user turns (this protocol is prompt-driven, not native
// function-calling, so it works with strict OpenAI and lenient providers alike).
function openaiCompatChat(base, model, messages, format, signal) {
  return new Promise((resolve, reject0) => { let reject = reject0;
    let url;
    try { url = new URL(base.replace(/\/+$/, "") + "/chat/completions"); }
    catch (e) { return reject(new Error("invalid DARKNODE_API_BASE: " + base)); }
    const lib = url.protocol === "https:" ? require("https") : require("http");
    const msgs = messages.map((m) => m.role === "tool" ? { role: "user", content: "[tool result] " + m.content } : m);
    const payload = { model, messages: msgs, stream: false, temperature: 0.2 };
    if (format) payload.response_format = { type: "json_object" }; // ask for valid JSON; providers that ignore it still work (prompt already asks)
    const body = JSON.stringify(payload);
    const headers = { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(body) };
    const key = API_KEY(); if (key) headers["Authorization"] = "Bearer " + key;
    const req = lib.request({ hostname: url.hostname, port: url.port || (url.protocol === "https:" ? 443 : 80), path: url.pathname + url.search, method: "POST", signal, headers },
      (res) => { reject = (e) => reject0(R.tag(e, res)); res.setEncoding("utf8"); let d = ""; res.on("data", (c) => (d += c)); res.on("end", () => {
        try {
          const j = JSON.parse(d);
          if (!j.error && res.statusCode >= 400) return reject(httpError(res, d));
          if (j.error) return reject(new Error("API error: " + (j.error.message || JSON.stringify(j.error))));
          const c = j.choices && j.choices[0] && j.choices[0].message && j.choices[0].message.content;
          resolve(c || "");
        } catch (e) { reject(new Error("bad API response (" + res.statusCode + "): " + String(d).slice(0, 200))); }
      }); });
    req.setTimeout(+(process.env.OLLAMA_TIMEOUT || 300000), () => req.destroy(new Error("model API timed out (no response)")));
    req.on("error", (e) => reject(Object.assign(new Error("cannot reach model API at " + base + " — " + e.message), { code: e.code })));
    req.write(body); req.end();
  });
}

// Native Anthropic (Claude) Messages API — "actual Claude" via an API key, in-process
// (NO headless Claude Code CLI). Used whenever the model id starts with "claude" and a
// key is present. Same prompt-driven tool loop as every other engine.
const ANTHROPIC_KEY = () => (process.env.ANTHROPIC_API_KEY || process.env.DARKNODE_ANTHROPIC_KEY || "").trim();
function hasAnthropic() { return !!ANTHROPIC_KEY(); }
// Prompt caching: without this, every step of an agent turn (up to the step limit)
// re-bills the full system prompt + tool manifest + prior turns at input price.
// Anthropic does NOT auto-cache — it needs explicit cache_control breakpoints. We
// mark the system block, the tool list, and the last message so the large stable
// prefix is billed at ~0.1x on every step after the first. Opt out with
// DARKNODE_NO_PROMPT_CACHE=1. Header is harmless where caching is already GA.
const ANTHROPIC_BETA = "prompt-caching-2024-07-31";
const cacheOn = () => !process.env.DARKNODE_NO_PROMPT_CACHE;
function anthropicCache(payload) {
  if (!cacheOn()) return payload;
  try {
    const bp = { type: "ephemeral" };
    if (typeof payload.system === "string" && payload.system) payload.system = [{ type: "text", text: payload.system, cache_control: bp }];
    else if (Array.isArray(payload.system) && payload.system.length) payload.system[payload.system.length - 1].cache_control = bp;
    if (Array.isArray(payload.tools) && payload.tools.length) payload.tools[payload.tools.length - 1].cache_control = bp;
    const msgs = payload.messages;
    if (Array.isArray(msgs) && msgs.length) {
      const last = msgs[msgs.length - 1];
      if (typeof last.content === "string") last.content = [{ type: "text", text: last.content, cache_control: bp }];
      else if (Array.isArray(last.content) && last.content.length) last.content[last.content.length - 1].cache_control = bp;
    }
  } catch (_) {}
  return payload;
}
function anthropicChat(model, messages, format, signal) {
  return new Promise((resolve, reject0) => { let reject = reject0;
    const https = require("https");
    const sys = messages.filter((m) => m.role === "system").map((m) => m.content).join("\n\n")
      + (format ? "\n\nRespond with ONLY valid JSON matching the requested schema — no prose, no code fences." : "");
    // map tool->user, merge consecutive same-role turns, and ensure it starts with user
    const mapped = messages.filter((m) => m.role !== "system")
      .map((m) => ({ role: m.role === "assistant" ? "assistant" : "user", content: m.role === "tool" ? "[tool result] " + m.content : String(m.content) }));
    const msgs = [];
    for (const m of mapped) { const last = msgs[msgs.length - 1]; if (last && last.role === m.role) last.content += "\n\n" + m.content; else msgs.push({ ...m }); }
    if (!msgs.length || msgs[0].role !== "user") msgs.unshift({ role: "user", content: "(begin)" });
    const body = JSON.stringify(anthropicCache({ model, max_tokens: 4096, system: sys, messages: msgs }));
    const headers = { "content-type": "application/json", "content-length": Buffer.byteLength(body), "x-api-key": ANTHROPIC_KEY(), "anthropic-version": "2023-06-01" };
    if (cacheOn()) headers["anthropic-beta"] = ANTHROPIC_BETA;
    const req = https.request({ hostname: "api.anthropic.com", path: "/v1/messages", method: "POST", signal, headers },
      (res) => { reject = (e) => reject0(R.tag(e, res)); res.setEncoding("utf8"); let d = ""; res.on("data", (c) => (d += c)); res.on("end", () => {
        try { const j = JSON.parse(d); if (!j.error && res.statusCode >= 400) return reject(httpError(res, d)); if (j.error) return reject(new Error("Claude API: " + (j.error.message || String(d).slice(0, 200))));
          resolve((j.content && j.content.map((b) => b.text || "").join("")) || ""); }
        catch (e) { reject(new Error("bad Claude response (" + res.statusCode + "): " + String(d).slice(0, 160))); }
      }); });
    req.setTimeout(+(process.env.OLLAMA_TIMEOUT || 300000), () => req.destroy(new Error("Claude API timed out (no response)")));
    req.on("error", (e) => reject(Object.assign(new Error("cannot reach Claude API — " + e.message), { code: e.code })));
    req.write(body); req.end();
  });
}

function ollamaChatOnce(model, messages, format, signal) {
  const base = API_BASE();
  if (base) return openaiCompatChat(base, model, messages, format, signal);   // an explicitly configured API base always wins
  if (/^claude/i.test(String(model)) && hasAnthropic()) return anthropicChat(model, messages, format, signal);  // else native Claude for claude-* models
  return new Promise((resolve, reject0) => { let reject = reject0;
    const body = JSON.stringify({ model, stream: false, format, keep_alive: "30m", options: { temperature: 0.2, num_ctx: NUM_CTX() }, messages });
    const req = http.request({ host: HOST(), port: PORT(), path: "/api/chat", method: "POST", signal, headers: { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(body) } },
      (res) => { reject = (e) => reject0(R.tag(e, res)); res.setEncoding("utf8"); let d = ""; res.on("data", (c) => (d += c)); res.on("end", () => { try { const j = JSON.parse(d); if (!j.error && res.statusCode >= 400) return reject(httpError(res, d)); if (j.error) return reject(new Error("Ollama: " + j.error)); resolve((j.message && j.message.content) || ""); } catch (e) { reject(new Error("bad model response")); } }); });
    req.setTimeout(+(process.env.OLLAMA_TIMEOUT || 300000), () => { req.destroy(new Error("Ollama timed out (no response) — is the model stuck loading?")); });
    req.on("error", (e) => reject(Object.assign(new Error("cannot reach Ollama at " + HOST() + ":" + PORT() + " — is it running? (" + e.message + ")"), { code: e.code }))); req.write(body); req.end();
  });
}
// Native (structured) tool-calling variant. Same routing as ollamaChat, but sends `tools` and
// resolves the RAW provider body + a provider tag so the caller (via lib/nexus/native-tools.js)
// can read guaranteed tool name + JSON args instead of parsing hand-written JSON out of text.
// `tools` must already be in each provider's shape (native-tools.js builds them). Returns
// { provider: "ollama"|"openai"|"anthropic", body: <parsed JSON> }.
function ollamaChatNativeOnce(model, messages, tools, signal) {
  const base = API_BASE();
  if (base) return new Promise((resolve, reject0) => { let reject = reject0;
    let url; try { url = new URL(base.replace(/\/+$/, "") + "/chat/completions"); } catch (e) { return reject(new Error("invalid DARKNODE_API_BASE: " + base)); }
    const lib = url.protocol === "https:" ? require("https") : require("http");
    const payload = { model, messages, stream: false, temperature: 0.2 };
    if (tools && tools.length) { payload.tools = tools; payload.tool_choice = "auto"; }
    const body = JSON.stringify(payload);
    const headers = { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(body) };
    const key = API_KEY(); if (key) headers["Authorization"] = "Bearer " + key;
    const req = lib.request({ hostname: url.hostname, port: url.port || (url.protocol === "https:" ? 443 : 80), path: url.pathname + url.search, method: "POST", signal, headers },
      (res) => { reject = (e) => reject0(R.tag(e, res)); res.setEncoding("utf8"); let d = ""; res.on("data", (c) => (d += c)); res.on("end", () => { try { const j = JSON.parse(d); if (!j.error && res.statusCode >= 400) return reject(httpError(res, d)); if (j.error) return reject(new Error("API error: " + (j.error.message || JSON.stringify(j.error)))); resolve({ provider: "openai", body: j }); } catch (e) { reject(new Error("bad API response (" + res.statusCode + "): " + String(d).slice(0, 200))); } }); });
    req.setTimeout(+(process.env.OLLAMA_TIMEOUT || 300000), () => req.destroy(new Error("model API timed out (no response)")));
    req.on("error", (e) => reject(Object.assign(new Error("cannot reach model API at " + base + " — " + e.message), { code: e.code })));
    req.write(body); req.end();
  });
  if (/^claude/i.test(String(model)) && hasAnthropic()) return new Promise((resolve, reject0) => { let reject = reject0;
    const https = require("https");
    const sys = messages.filter((m) => m.role === "system").map((m) => m.content).join("\n\n");
    const msgs = messages.filter((m) => m.role !== "system");
    const payload = { model, max_tokens: 4096, messages: msgs }; if (sys) payload.system = sys; if (tools && tools.length) payload.tools = tools;
    const body = JSON.stringify(anthropicCache(payload));
    const headers = { "content-type": "application/json", "content-length": Buffer.byteLength(body), "x-api-key": ANTHROPIC_KEY(), "anthropic-version": "2023-06-01" };
    if (cacheOn()) headers["anthropic-beta"] = ANTHROPIC_BETA;
    const req = https.request({ hostname: "api.anthropic.com", path: "/v1/messages", method: "POST", signal, headers },
      (res) => { reject = (e) => reject0(R.tag(e, res)); res.setEncoding("utf8"); let d = ""; res.on("data", (c) => (d += c)); res.on("end", () => { try { const j = JSON.parse(d); if (!j.error && res.statusCode >= 400) return reject(httpError(res, d)); if (j.error) return reject(new Error("Claude API: " + (j.error.message || String(d).slice(0, 200)))); resolve({ provider: "anthropic", body: j }); } catch (e) { reject(new Error("bad Claude response (" + res.statusCode + "): " + String(d).slice(0, 160))); } }); });
    req.setTimeout(+(process.env.OLLAMA_TIMEOUT || 300000), () => req.destroy(new Error("Claude API timed out")));
    req.on("error", (e) => reject(Object.assign(new Error("cannot reach Claude API — " + e.message), { code: e.code })));
    req.write(body); req.end();
  });
  return new Promise((resolve, reject0) => { let reject = reject0;
    const payload = { model, stream: false, keep_alive: "30m", options: { temperature: 0.2, num_ctx: NUM_CTX() }, messages };
    if (tools && tools.length) payload.tools = tools;
    const body = JSON.stringify(payload);
    const req = http.request({ host: HOST(), port: PORT(), path: "/api/chat", method: "POST", signal, headers: { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(body) } },
      (res) => { reject = (e) => reject0(R.tag(e, res)); res.setEncoding("utf8"); let d = ""; res.on("data", (c) => (d += c)); res.on("end", () => { let j; try { j = JSON.parse(d); } catch (e) { return reject(new Error("bad model response")); } if (j && !j.error && res.statusCode >= 400) return reject(httpError(res, d)); if (j && j.error) return reject(new Error("Ollama: " + j.error)); resolve({ provider: "ollama", body: j }); }); }); // an error body (model not found, busy) rejects: it used to come back as an empty answer, and a 503 was never retried
    req.setTimeout(+(process.env.OLLAMA_TIMEOUT || 300000), () => req.destroy(new Error("Ollama timed out (no response)")));
    req.on("error", (e) => reject(Object.assign(new Error("cannot reach Ollama at " + HOST() + ":" + PORT() + " — " + e.message), { code: e.code }))); req.write(body); req.end();
  });
}

// Every model call rides through transient failures (429/529/503/dropped connection) — lib/nexus/retry.js.
// An HTTP error whose JSON body has no `error` field (gateways send {"detail":..} or {"message":..})
// used to resolve as an empty reply: never retried, never reported. It is an error with its status.
function httpError(res, d) {
  let msg = ""; try { const j = JSON.parse(d); msg = j.detail || j.message || (j.error && j.error.message) || ""; if (typeof msg !== "string") msg = JSON.stringify(msg); } catch (_) {}
  return new Error("model API HTTP " + res.statusCode + (msg ? ": " + msg : ": " + String(d).slice(0, 160)));
}
function ollamaChat(model, messages, format, signal) { return R.withRetry(() => ollamaChatOnce(model, messages, format, signal), signal); }
function ollamaChatNative(model, messages, tools, signal) { return R.withRetry(() => ollamaChatNativeOnce(model, messages, tools, signal), signal); }

function ollamaTags() {
  const base = API_BASE();
  if (base) return new Promise((resolve) => {                 // GET <base>/models (OpenAI list format)
    let url; try { url = new URL(base.replace(/\/+$/, "") + "/models"); } catch (e) { return resolve([]); }
    const lib = url.protocol === "https:" ? require("https") : require("http");
    const key = API_KEY();
    // timeout: a server that accepts the connection but never answers left this (and the caller) waiting forever
    lib.get({ hostname: url.hostname, port: url.port || (url.protocol === "https:" ? 443 : 80), path: url.pathname, headers: key ? { Authorization: "Bearer " + key } : {}, timeout: 10000 },
      (res) => { res.setEncoding("utf8"); let d = ""; res.on("data", (c) => (d += c)); res.on("end", () => { try { const j = JSON.parse(d); resolve((j.data || j.models || []).map((m) => m.id || m.name).filter(Boolean)); } catch (_) { resolve([]); } }); }).on("timeout", function () { this.destroy(new Error("timed out")); }).on("error", () => resolve([]));
  });
  return new Promise((resolve) => {
    // [] with .unreachable = true when nothing answers, so callers can say "start Ollama" rather than "pull a model"
    http.get({ host: HOST(), port: PORT(), path: "/api/tags", timeout: 10000 }, (res) => { res.setEncoding("utf8"); let d = ""; res.on("data", (c) => (d += c)); res.on("end", () => { try { resolve((JSON.parse(d).models || []).map((m) => m.name)); } catch (_) { resolve([]); } }); }).on("timeout", function () { this.destroy(new Error("timed out")); }).on("error", () => resolve(Object.assign([], { unreachable: true })));
  });
}
// Pick the best available model for coding/agentic work. gpt-oss (OpenAI's open-weight
// reasoning models) is preferred — gpt-oss:120b first, then 20b — as it's far stronger at
// tool use than small local models. DARKNODE_MODEL overrides. Falls back through known
// coder models, then anything code-ish, then whatever's installed.
function pickCoderModel(ms) {
  ms = ms || [];
  const rawWant = (process.env.DARKNODE_MODEL || "").trim();
  if (rawWant) { const w = rawWant.toLowerCase(); const hit = ms.find((m) => m.toLowerCase() === w) || ms.find((m) => m.toLowerCase().startsWith(w)); return hit || rawWant; } // honor explicit choice even if not yet pulled (Ollama fetches on first use)
  const pri = ["darknode", "gpt-oss:120b", "gpt-oss:20b", "gpt-oss", "qwen2.5-coder", "deepseek-coder", "codellama", "hermes3", "dolphin3", "llama3.1"];
  for (const p of pri) { const hit = ms.find((m) => m.toLowerCase().startsWith(p)); if (hit) return hit; }
  return ms.find((m) => /coder|code/i.test(m)) || ms[0] || "";
}
// Is an external OpenAI-compatible model API configured (vs local Ollama)?
function apiConfigured() { return !!API_BASE(); }

// The local coder Nexus ships with. qwen2.5-coder is small, tool-capable and genuinely good at
// code — a far better out-of-the-box default for Nexus's OWN loop than a general chat model.
// Weights can't live in npm (~4.7GB), so "comes with Nexus" means: auto-pulled via Ollama on
// first run when the user has no capable coder yet.
const DEFAULT_CODER = "qwen2.5-coder";
// Prefixes of models already good enough to code with — if any is installed, don't pull anything.
const CAPABLE_CODER = ["gpt-oss", "qwen2.5-coder", "qwen3", "qwen2", "deepseek-coder", "deepseek-v", "codellama", "darknode", "codestral", "starcoder"];
// Pure: given the installed tags, return the model to pull (DEFAULT_CODER) or null if a capable
// coder is already present. Testable without touching the network.
function chooseCoderToPull(tags) {
  const ms = (tags || []).map((t) => String(t).toLowerCase());
  if (ms.some((m) => CAPABLE_CODER.some((p) => m.startsWith(p)))) return null;
  return DEFAULT_CODER;
}
// First-run: make sure a capable local coder exists, pulling qwen2.5-coder if not. Never throws;
// returns the model name that is (now) available, or null on failure / when an API is configured.
async function ensureCoderModel(log) {
  log = typeof log === "function" ? log : (() => {});
  try {
    if (apiConfigured() || process.env.DARKNODE_NO_AUTOINSTALL) return null;
    const tags = await ollamaTags();
    const want = chooseCoderToPull(tags);
    if (!want) return pickCoderModel(tags); // already have something capable
    log("No local coding model found — pulling " + want + " (first run, a few minutes)...");
    const code = await new Promise((resolve) => {
      let p; try { p = require("child_process").spawn("ollama", ["pull", want], { stdio: ["ignore", "pipe", "pipe"] }); }
      catch (e) { log("failed to start ollama: " + e.message); return resolve(1); }
      const onData = (b) => String(b).split(/\r?\n/).forEach((l) => { if (l.trim()) log(l.slice(0, 200)); });
      p.stdout.on("data", onData); p.stderr.on("data", onData);
      p.on("error", (e) => { log("ollama pull error: " + e.message); resolve(1); });
      p.on("close", (c) => resolve(c || 0));
    });
    if (code === 0) { log(want + " ready."); return want; }
    log(want + " pull failed (ollama pull exit " + code + ").");
    return null;
  } catch (e) { try { log("coder auto-install error: " + e.message); } catch (_) {} return null; }
}

// First-run auto-install of the local "darknode" Ollama model. This is a persona
// build (a bundled Modelfile: FROM a base security model + a Darknode SYSTEM
// prompt), NOT a fine-tune. `ollama create` pulls the base and builds the model.
// Never throws. Returns true when "darknode" is installed (already, or after a
// successful build); false on any failure. Set DARKNODE_NO_AUTOINSTALL to skip.
async function ensureDarknodeModel(log) {
  log = typeof log === "function" ? log : (() => {});
  try {
    if (process.env.DARKNODE_NO_AUTOINSTALL) return;
    if (apiConfigured()) return; // a remote API is configured; nothing to build locally
    const tags = await ollamaTags();
    if (tags.some((t) => t === "darknode" || t.startsWith("darknode:"))) return true; // already installed
    const path = require("path");
    const modelfile = path.join(__dirname, "darknode.Modelfile"); // resolve relative to this module (works when installed globally)
    if (!require("fs").existsSync(modelfile)) { log("Darknode Modelfile not found at " + modelfile); return false; }
    log("Installing the Darknode model (first run) — pulling the base, this can take a few minutes...");
    const code = await new Promise((resolve) => {
      let p;
      try { p = require("child_process").spawn("ollama", ["create", "darknode", "-f", modelfile], { stdio: ["ignore", "pipe", "pipe"] }); }
      catch (e) { log("failed to start ollama: " + e.message); return resolve(1); }
      const onData = (b) => String(b).split(/\r?\n/).forEach((l) => { if (l.trim()) log(l.slice(0, 200)); });
      p.stdout.on("data", onData); p.stderr.on("data", onData);
      p.on("error", (e) => { log("ollama create error: " + e.message); resolve(1); });
      p.on("close", (c) => resolve(c || 0));
    });
    if (code === 0) { log("Darknode model ready."); return true; }
    log("Darknode model install failed (ollama create exit " + code + ").");
    return false;
  } catch (e) {
    try { log("Darknode auto-install error: " + e.message); } catch (_) {}
    return false;
  }
}
module.exports = { ollamaAddr, NUM_CTX, ollamaChat, ollamaChatNative, ollamaTags, pickCoderModel, apiConfigured, ensureDarknodeModel, ensureCoderModel, chooseCoderToPull, DEFAULT_CODER, API_BASE, API_KEY, hasAnthropic, ANTHROPIC_KEY };
