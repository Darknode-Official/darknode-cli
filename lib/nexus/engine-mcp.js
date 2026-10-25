"use strict";
// ============================================================================
// engine-mcp — builds the MCP-server set an EXTERNAL engine (claude, codex, …)
// is launched with, so its model reaches the same tools the local engine has.
// Always includes the `nexus` ask bridge (the real popup, via ask-mcp.js talking
// back to the TUI over a socket); optionally re-declares the servers the user
// deliberately configured for Nexus (.nexus/mcp.json) so those reach the engine
// too. Bundled defaults are intentionally NOT forwarded — the engine likely has
// its own copies, and duplicate server names only cause confusion.
// ============================================================================
const fs = require("fs");
const path = require("path");

// buildEngineMcpServers({ sockPath, askMcpPath, nodePath?, userServers? })
//   -> { name: { command, args, env? }, ... }  (MCP config shape)
function buildEngineMcpServers(opts) {
  opts = opts || {};
  const out = {};
  const userServers = opts.userServers;
  if (userServers && typeof userServers === "object") {
    for (const k of Object.keys(userServers)) {
      const s = userServers[k];
      if (s && s.command && k !== "nexus") out[k] = JSON.parse(JSON.stringify(s)); // 'nexus' is reserved for the ask bridge
    }
  }
  if (opts.sockPath && opts.askMcpPath) {
    out.nexus = { command: opts.nodePath || process.execPath || "node", args: [opts.askMcpPath], env: { NEXUS_ASK_SOCK: opts.sockPath } };
  }
  return out;
}

// Write a Claude-style { mcpServers: {...} } config file into `dir` and return
// its path (or null on failure). `dir` is normally the repo's .nexus/ (gitignored).
function writeMcpConfigFile(dir, servers) {
  try {
    fs.mkdirSync(dir, { recursive: true });
    const p = path.join(dir, ".mcp-engine.json");
    fs.writeFileSync(p, JSON.stringify({ mcpServers: servers || {} }, null, 2));
    return p;
  } catch (_) { return null; }
}

// opencode uses a different schema ({ mcp: { name: { type, command:[bin,...args],
// environment, enabled } } }) and is pointed at a config file via $OPENCODE_CONFIG
// (verified read). We merge our server INTO a copy of the user's project config so
// their own providers / models / MCP servers are preserved, never replaced.
function toOpencodeConfig(servers, baseConfig) {
  const out = (baseConfig && typeof baseConfig === "object") ? JSON.parse(JSON.stringify(baseConfig)) : {};
  if (!out["$schema"]) out["$schema"] = "https://opencode.ai/config.json";
  if (!out.mcp || typeof out.mcp !== "object") out.mcp = {};
  for (const k of Object.keys(servers || {})) {
    const s = servers[k];
    if (!s || !s.command) continue;
    const entry = { type: "local", command: [s.command].concat(s.args || []), enabled: true };
    if (s.env && Object.keys(s.env).length) entry.environment = Object.assign({}, s.env);
    out.mcp[k] = entry;
  }
  return out;
}

// Write any config object into `dir/filename` and return the path (or null).
function writeEngineConfigFile(dir, filename, obj) {
  try {
    fs.mkdirSync(dir, { recursive: true });
    const p = path.join(dir, filename);
    fs.writeFileSync(p, JSON.stringify(obj || {}, null, 2));
    return p;
  } catch (_) { return null; }
}

// Codex has no per-invocation --mcp-config flag; it takes `-c key=value` config
// overrides instead. Translate one server spec into the `-c` args that register
// it under [mcp_servers.<name>] for this single `codex exec` run only (no global
// config mutation). Values use TOML literals (strings quoted, arrays bracketed).
function codexMcpArgs(name, spec) {
  if (!spec || !spec.command) return [];
  const toml = (v) => JSON.stringify(v); // JSON string/array literals are valid TOML here
  const base = "mcp_servers." + name + ".";
  const args = ["-c", base + "command=" + toml(spec.command)];
  if (spec.args && spec.args.length) args.push("-c", base + "args=" + toml(spec.args));
  if (spec.env && Object.keys(spec.env).length) {
    const inline = "{ " + Object.keys(spec.env).map((k) => k + " = " + toml(String(spec.env[k]))).join(", ") + " }";
    args.push("-c", base + "env=" + inline);
  }
  return args;
}

module.exports = { buildEngineMcpServers, writeMcpConfigFile, codexMcpArgs, toOpencodeConfig, writeEngineConfigFile };
