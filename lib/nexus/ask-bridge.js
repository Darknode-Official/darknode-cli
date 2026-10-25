"use strict";
// ============================================================================
// ask-bridge — the Nexus-side half of letting an EXTERNAL engine (claude, codex,
// …) raise the real terminal popup. External engines run headless in their own
// process with their OWN toolset, so they can't call Nexus's in-process
// `ask_user`. The bridge closes that gap: Nexus listens on a local socket; the
// out-of-process MCP shim (ask-mcp.js, spawned by the engine) connects to it
// when the model calls the `ask_user` MCP tool, forwards the question, and this
// server shows the real popup via `onAsk` and sends the user's answer back.
//
// Line-delimited JSON, one request/response per connection is fine but the
// protocol tolerates several. No deps; Unix domain socket (or a Windows named
// pipe). Pure wiring — the popup itself lives in the host (darknode.js).
// ============================================================================
const net = require("net");
const os = require("os");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");

// A short, collision-resistant socket path. Unix socket paths are length-limited
// (~104-108 bytes), so keep it in the temp dir with a compact random suffix.
function askSockPath() {
  const rand = crypto.randomBytes(6).toString("hex");
  if (process.platform === "win32") return "\\\\.\\pipe\\nexus-ask-" + process.pid + "-" + rand;
  return path.join(os.tmpdir(), "nexus-ask-" + process.pid + "-" + rand + ".sock");
}

// createAskServer(onAsk) -> { sockPath, close }
// onAsk(spec) is called with { question, options?, multi?, input?, placeholder? }
// and must resolve to a normalized answer object:
//   { answer: "..." }            free-text
//   { selected: ["a","b"], indices:[...] }  multi-select
//   { selected: "a", index: 0 }  single-select
//   { cancelled:true } / { skipped:true }   the user dismissed it
function createAskServer(onAsk) {
  const sockPath = askSockPath();
  try { if (process.platform !== "win32" && fs.existsSync(sockPath)) fs.unlinkSync(sockPath); } catch (_) {}
  const server = net.createServer((sock) => {
    let buf = "";
    sock.setEncoding("utf8");
    sock.on("data", (d) => {
      buf += d;
      let nl;
      while ((nl = buf.indexOf("\n")) >= 0) {
        const line = buf.slice(0, nl); buf = buf.slice(nl + 1);
        if (!line.trim()) continue;
        let req; try { req = JSON.parse(line); } catch (_) { continue; }
        const id = req.id;
        Promise.resolve().then(() => onAsk(req)).then((ans) => {
          try { sock.write(JSON.stringify({ id, answer: ans || { skipped: true } }) + "\n"); } catch (_) {}
        }).catch((e) => {
          try { sock.write(JSON.stringify({ id, error: String((e && e.message) || e) }) + "\n"); } catch (_) {}
        });
      }
    });
    sock.on("error", () => {});
  });
  server.on("error", () => {}); // a dead socket must never crash the TUI
  try { server.listen(sockPath); } catch (_) {}
  return {
    sockPath,
    close() {
      try { server.close(); } catch (_) {}
      try { if (process.platform !== "win32" && fs.existsSync(sockPath)) fs.unlinkSync(sockPath); } catch (_) {}
    },
  };
}

module.exports = { createAskServer, askSockPath };
