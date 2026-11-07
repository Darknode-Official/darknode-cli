"use strict";
// hub/paths — where the session hub keeps its socket and state, and how to talk to it.
// Everything lives in ~/.nexus/hub (mode 700, so only this user can reach the socket).
// NEXUS_HUB_DIR overrides it (tests, or a second hub).
const fs = require("fs"), path = require("path"), os = require("os"), net = require("net");

function hubDir() {
  const d = process.env.NEXUS_HUB_DIR || path.join(os.homedir(), ".nexus", "hub");
  try { fs.mkdirSync(d, { recursive: true, mode: 0o700 }); fs.chmodSync(d, 0o700); } catch (_) {}
  return d;
}
const sockPath = (dir) => path.join(dir || hubDir(), "hub.sock");
const statePath = (dir) => path.join(dir || hubDir(), "sessions.json");
const supported = () => process.platform === "linux" || process.platform === "darwin";

// One JSON line in, JSON lines out. `onLine` gets each reply; return true to keep listening.
function call(msg, opts = {}) {
  return new Promise((resolve, reject) => {
    const sock = net.connect(opts.sock || sockPath(opts.dir));
    let buf = "", done = false;
    const finish = (err, v) => { if (done) return; done = true; try { sock.destroy(); } catch (_) {} err ? reject(err) : resolve(v); };
    const t = opts.timeout ? setTimeout(() => finish(new Error("the session hub did not answer")), opts.timeout) : null;
    sock.on("connect", () => sock.write(JSON.stringify(msg) + "\n"));
    sock.on("data", (d) => {
      buf += d.toString("utf8");
      let i;
      while ((i = buf.indexOf("\n")) >= 0) {
        const line = buf.slice(0, i); buf = buf.slice(i + 1);
        let j; try { j = JSON.parse(line); } catch (_) { continue; }
        if (opts.onLine && opts.onLine(j)) continue;
        if (t) clearTimeout(t);
        return finish(null, j);
      }
    });
    sock.on("error", (e) => { if (t) clearTimeout(t); finish(e); });
    sock.on("close", () => { if (t) clearTimeout(t); finish(new Error("the session hub closed the connection")); });
  });
}

module.exports = { hubDir, sockPath, statePath, supported, call };
