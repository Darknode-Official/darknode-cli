"use strict";
// hub/report — a Nexus TUI running inside a background session tells the hub its exact
// state (working / blocked on an ask_user or approval / idle), so `nexus ls` and `wait`
// do not have to guess from the screen. Does nothing outside a hub session.
const net = require("net");
const REFRESH_MS = 4000; // the hub trusts a report for 15s; refresh well inside that

function startReporter(getState, env = process.env) {
  const id = env.NEXUS_HUB_ID, sock = env.NEXUS_HUB_SOCK;
  if (!id || !sock) return () => {};
  let conn = null, last = "", lastAt = 0;
  const send = (state) => {
    try {
      if (!conn || conn.destroyed) {
        conn = net.connect(sock);
        conn.on("error", () => { conn = null; });
        conn.on("data", () => {});
        conn.unref();
      }
      conn.write(JSON.stringify({ op: "report", id, state }) + "\n");
    } catch (_) { conn = null; }
  };
  const poke = () => {
    let st; try { st = getState(); } catch (_) { return; }
    const now = Date.now();
    if (st === last && now - lastAt < REFRESH_MS) return;
    last = st; lastAt = now; send(st);
  };
  const t = setInterval(poke, REFRESH_MS); if (t.unref) t.unref();
  return poke;
}

module.exports = { startReporter };
