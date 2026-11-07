"use strict";
// ============================================================================
// hub/server — the Nexus session hub: a small per-user background process that
// owns agent sessions so they keep running when you close the terminal.
//
//   nexus bg            start a session (Nexus by default, or any agent: -- claude)
//   nexus attach <id>   watch and drive it; Ctrl+] detaches, the session keeps going
//   nexus ls            every session marked working / blocked / idle / done
//   nexus send|wait|peek|kill ...   the same things, scriptable (and the agent tool)
//
// Each session runs under a real pseudo-terminal. Nexus has no native modules, so the
// terminal comes from the system `script` program (util-linux on Linux, BSD on macOS);
// resizing is `stty` on the session's tty, which makes the kernel send SIGWINCH.
//
// Protocol: one JSON object per line over a unix socket in ~/.nexus/hub (mode 700).
// `attach` turns the connection into a raw byte stream until it closes.
// ============================================================================
const fs = require("fs"), path = require("path"), net = require("net"), cp = require("child_process");
const { StringDecoder } = require("string_decoder");
const { Screen } = require("./screen");
const { classify, reached } = require("./status");
const { hubDir, sockPath, statePath } = require("./paths");

const RAW_KEEP = 256 * 1024;   // raw output kept per session (not replayed; the screen model repaints)
const IDLE_EXIT_MS = 10 * 60 * 1000; // hub exits after this long with no sessions and no clients
const TICK_MS = 400;
const DONE_KEEP_MS = 30 * 60 * 1000; // a finished session stays listed this long

const q = (s) => "'" + String(s).replace(/'/g, "'\\''") + "'";
const nexusEntry = () => (process.pkg ? [process.execPath] : [process.execPath, path.join(__dirname, "..", "..", "..", "darknode.js")]);

function createHub(opts = {}) {
  const dir = opts.dir || hubDir();
  const sock = sockPath(dir), stateFile = statePath(dir);
  const notify = opts.notify || (() => {});
  const sessions = new Map(); // id -> session
  const waiters = new Set();  // { id, until, resolve }
  let seq = 0, server = null, clients = 0, lastBusy = Date.now(), ticker = null;
  let saved = []; // sessions from a previous hub that are not running (restorable)
  try { const j = JSON.parse(fs.readFileSync(stateFile, "utf8")); saved = Array.isArray(j.sessions) ? j.sessions : []; seq = j.seq | 0; } catch (_) {}

  const persist = () => {
    const live = [...sessions.values()].filter((s) => !s.exited).map(meta);
    const keep = saved.filter((x) => !live.some((l) => l.id === x.id));
    try { fs.writeFileSync(stateFile, JSON.stringify({ seq, sessions: live.concat(keep) }, null, 2), { mode: 0o600 }); } catch (_) {}
  };
  const meta = (s) => ({ id: s.id, name: s.name, cwd: s.cwd, kind: s.kind, cmd: s.cmd, created: s.created });
  const summary = (s) => ({ ...meta(s), state: s.state, since: s.since, title: s.screen.title, attached: s.clients.size, pid: s.proc && s.proc.pid, exitCode: s.exitCode == null ? null : s.exitCode });

  function find(key) {
    if (key == null || key === "") { const live = [...sessions.values()].filter((s) => !s.exited); return live.length === 1 ? live[0] : null; }
    const k = String(key);
    if (sessions.has(k)) return sessions.get(k);
    const all = [...sessions.values()];
    return all.find((s) => s.name === k) || (all.filter((s) => s.name.startsWith(k)).length === 1 ? all.find((s) => s.name.startsWith(k)) : null);
  }
  function uniqueName(base) {
    base = String(base || "session").replace(/[^\w.-]+/g, "-").slice(0, 40) || "session";
    const taken = new Set([...sessions.values()].filter((s) => !s.exited).map((s) => s.name));
    if (!taken.has(base)) return base;
    for (let i = 2; ; i++) if (!taken.has(base + "-" + i)) return base + "-" + i;
  }

  function spawnSession(o) {
    const cwd = path.resolve(o.cwd || process.cwd());
    if (!fs.existsSync(cwd)) throw new Error("no such folder: " + cwd);
    const cols = Math.max(20, o.cols | 0 || 120), rows = Math.max(5, o.rows | 0 || 34);
    const kind = o.cmd && o.cmd.length ? "cmd" : "nexus";
    const argv = kind === "nexus" ? nexusEntry().concat(["nexus"], o.nexusArgs || []) : o.cmd.map(String);
    const id = String(o.id || ++seq);
    const name = o.name ? uniqueName(o.name) : uniqueName(kind === "nexus" ? path.basename(cwd) : path.basename(String(argv[0])));
    const ttyFile = path.join(dir, "s" + id + ".tty");
    try { fs.unlinkSync(ttyFile); } catch (_) {}
    const inner = "tty > " + q(ttyFile) + " 2>/dev/null; stty rows " + rows + " cols " + cols + " 2>/dev/null; exec " + argv.map(q).join(" ");
    const env = Object.assign({}, process.env, o.env || {}, { TERM: process.env.TERM && process.env.TERM !== "dumb" ? process.env.TERM : "xterm-256color", NEXUS_HUB_ID: id, NEXUS_HUB_SOCK: sock, NEXUS_HUB_NAME: name });
    const args = process.platform === "darwin" ? ["-q", "/dev/null", "/bin/sh", "-c", inner] : ["-qfec", inner, "/dev/null"];
    const proc = (opts.spawn || cp.spawn)("script", args, { cwd, env, stdio: ["pipe", "pipe", "pipe"], detached: true });
    const s = {
      id, name, cwd, kind, cmd: kind === "cmd" ? o.cmd.map(String) : null, nexusArgs: o.nexusArgs || [], created: Date.now(),
      proc, screen: new Screen(cols, rows), raw: [], rawLen: 0, dec: new StringDecoder("utf8"),
      lastOutputAt: Date.now(), report: null, exited: false, exitCode: null, clients: new Set(), ttyFile, tty: "",
      state: "working", since: Date.now(), prompt: o.prompt ? String(o.prompt) : "", promptSent: false,
    };
    const onOut = (d) => {
      s.lastOutputAt = Date.now();
      s.raw.push(d); s.rawLen += d.length;
      while (s.rawLen > RAW_KEEP && s.raw.length > 1) s.rawLen -= s.raw.shift().length;
      s.screen.write(s.dec.write(d));
      for (const c of s.clients) { try { c.write(d); } catch (_) {} }
    };
    proc.stdout.on("data", onOut); proc.stderr.on("data", onOut);
    proc.on("error", (e) => { onOut(Buffer.from("\r\n[nexus hub] could not start the session: " + e.message + "\r\n")); end(s, 127); });
    proc.on("exit", (code) => end(s, code));
    proc.stdin.on("error", () => {});
    sessions.set(id, s);
    saved = saved.filter((x) => x.id !== id);
    persist(); bump();
    return s;
  }
  function end(s, code) {
    if (s.exited) return;
    s.exited = true; s.exitCode = code == null ? null : code;
    try { fs.unlinkSync(s.ttyFile); } catch (_) {}
    for (const c of s.clients) { try { c.end("\r\n[nexus hub] session " + s.name + " ended" + (code ? " (exit " + code + ")" : "") + "\r\n"); } catch (_) {} }
    s.clients.clear();
    persist(); tick();
  }
  function tty(s) {
    if (s.tty) return s.tty;
    try { s.tty = fs.readFileSync(s.ttyFile, "utf8").trim(); } catch (_) {}
    return /^\/dev\//.test(s.tty) ? s.tty : "";
  }
  function resize(s, cols, rows) {
    cols = Math.max(20, Math.min(1000, cols | 0)); rows = Math.max(5, Math.min(500, rows | 0));
    s.screen.resize(cols, rows);
    const t = tty(s); if (!t) return;
    (opts.spawnSync || cp.spawnSync)("stty", [process.platform === "darwin" ? "-f" : "-F", t, "rows", String(rows), "cols", String(cols)], { stdio: "ignore" });
  }
  function input(s, data) { if (!s.exited) try { s.proc.stdin.write(data); } catch (_) {} }
  // Type a prompt the way a person would: pasted as one block when the program asked for
  // bracketed paste (so a newline inside it does not submit early), then Enter.
  function sendText(s, text, enter = true) {
    const t = String(text == null ? "" : text);
    if (t) input(s, s.screen.modes.has(2004) ? "\x1b[200~" + t + "\x1b[201~" : t.replace(/\r?\n/g, "\r"));
    if (enter) setTimeout(() => input(s, "\r"), t ? 60 : 0);
  }

  // Linux: is the session's program (a shell) running a job in the foreground? The tty's
  // foreground process group moves off the shell while `sleep 30` or `npm test` runs, so a
  // quiet command still counts as working. Agents keep their tools in their own group.
  function fgJob(s) {
    if (process.platform !== "linux" || s.exited || !s.proc || !s.proc.pid) return false;
    try {
      if (!s.childPid) s.childPid = Number(fs.readFileSync("/proc/" + s.proc.pid + "/task/" + s.proc.pid + "/children", "utf8").trim().split(/\s+/)[0]) || 0;
      if (!s.childPid) return false;
      const st = fs.readFileSync("/proc/" + s.childPid + "/stat", "utf8");
      const tpgid = Number(st.slice(st.lastIndexOf(")") + 2).split(" ")[5]);
      return tpgid > 0 && tpgid !== s.childPid;
    } catch (_) { return false; }
  }

  function tick() {
    const now = Date.now();
    for (const [k, s] of sessions) if (s.exited && now - s.since > DONE_KEEP_MS && !s.clients.size) sessions.delete(k);
    for (const s of sessions.values()) {
      const st = classify({ exited: s.exited, lastOutputAt: s.lastOutputAt, report: s.report, fgJob: fgJob(s), tail: s.exited ? "" : s.screen.text() }, now);
      if (st !== s.state) {
        const prev = s.state; s.state = st; s.since = now;
        if (st === "blocked" && !s.clients.size) notify("Nexus: " + s.name + " needs you", (s.screen.title || s.name) + " is waiting for an answer. Run: nexus attach " + s.name);
        if (st === "done" && prev !== "done" && !s.clients.size) notify("Nexus: " + s.name + " finished", s.exitCode ? "exited with code " + s.exitCode : "the session ended");
      }
      // A prompt given at spawn is typed once the program first settles.
      if (s.prompt && !s.promptSent && !s.exited && st !== "working" && now - s.created > 800) { s.promptSent = true; sendText(s, s.prompt); }
    }
    for (const w of [...waiters]) {
      const s = sessions.get(w.id);
      if (!s) { waiters.delete(w); w.resolve({ ok: false, error: "no such session" }); continue; }
      // a just-sent prompt has not been read yet: a wait right after `send` must not see the old idle
      if (now < w.notBefore && s.state !== "done") continue;
      if (reached(s.state, w.until)) { waiters.delete(w); w.resolve({ ok: true, reached: true, session: summary(s), tail: s.screen.tail(w.lines || 30) }); }
      else if (w.deadline && now > w.deadline) { waiters.delete(w); w.resolve({ ok: true, reached: false, session: summary(s), tail: s.screen.tail(w.lines || 30) }); }
    }
    if ([...sessions.values()].some((s) => !s.exited) || clients > 0 || waiters.size) lastBusy = now;
    else if (!opts.stayUp && now - lastBusy > IDLE_EXIT_MS) stop();
  }
  const bump = () => { lastBusy = Date.now(); };

  function restore() {
    const out = [];
    for (const m of saved.slice()) {
      if (sessions.has(m.id) && !sessions.get(m.id).exited) continue;
      try {
        const s = spawnSession(m.kind === "nexus" ? { id: m.id, name: m.name, cwd: m.cwd, nexusArgs: ["--resume"] } : { id: m.id, name: m.name, cwd: m.cwd, cmd: m.cmd });
        out.push(summary(s));
      } catch (e) { out.push({ id: m.id, name: m.name, error: e.message }); }
    }
    return out;
  }

  // ---- protocol ----
  function handle(c, msg, reply) {
    const op = msg && msg.op;
    if (op === "ping") return reply({ ok: true, pid: process.pid, sessions: sessions.size });
    if (op === "list") return reply({ ok: true, sessions: [...sessions.values()].map(summary), saved: saved.filter((m) => !sessions.has(m.id) || sessions.get(m.id).exited) });
    if (op === "spawn") {
      try { const s = spawnSession(msg); return reply({ ok: true, session: summary(s) }); }
      catch (e) { return reply({ ok: false, error: e.message }); }
    }
    if (op === "restore") return reply({ ok: true, sessions: restore() });
    if (op === "forget") { saved = msg.id ? saved.filter((m) => m.id !== String(msg.id) && m.name !== msg.id) : []; for (const [k, s] of sessions) if (s.exited) sessions.delete(k); persist(); return reply({ ok: true }); }
    if (op === "stop") { reply({ ok: true }); return setTimeout(stop, 50); }
    const s = find(msg.id);
    if (op === "report") { // from a Nexus TUI running inside a session
      const r = sessions.get(String(msg.id));
      if (r && ["working", "blocked", "idle"].includes(msg.state)) { r.report = { state: msg.state, at: Date.now() }; tick(); }
      return reply({ ok: true });
    }
    if (!s) return reply({ ok: false, error: msg.id ? "no session named " + msg.id + " (see: nexus ls)" : "more than one session is running: name one (see: nexus ls)" });
    if (op === "send") { if (s.exited) return reply({ ok: false, error: s.name + " has ended" }); sendText(s, msg.text, msg.enter !== false); return reply({ ok: true, session: summary(s) }); }
    if (op === "keys") { input(s, Buffer.from(String(msg.data || ""), "base64")); return reply({ ok: true }); }
    if (op === "peek") return reply({ ok: true, session: summary(s), text: msg.screen ? s.screen.text() : s.screen.tail(Math.min(400, msg.lines | 0 || 40)) });
    if (op === "resize") { resize(s, msg.cols, msg.rows); return reply({ ok: true }); }
    if (op === "kill") {
      if (!s.exited) { try { process.kill(-s.proc.pid, "SIGTERM"); } catch (_) { try { s.proc.kill("SIGTERM"); } catch (_) {} } setTimeout(() => { if (!s.exited) { try { process.kill(-s.proc.pid, "SIGKILL"); } catch (_) {} } }, 3000); }
      return reply({ ok: true, session: summary(s) });
    }
    if (op === "wait") {
      const secs = Number(msg.timeout); const now = Date.now();
      waiters.add({ id: s.id, until: msg.until || "stopped", lines: msg.lines, notBefore: now + (msg.settle === false ? 0 : 1200), deadline: Number.isFinite(secs) && secs > 0 ? now + secs * 1000 : 0, resolve: reply, _c: c });
      return tick();
    }
    if (op === "attach") {
      if (s.exited) return reply({ ok: false, error: s.name + " has ended" });
      reply({ ok: true, session: summary(s) });
      c._attached = s; s.clients.add(c);
      if (msg.cols && msg.rows) resize(s, msg.cols, msg.rows);
      try { c.write(s.screen.repaint()); } catch (_) {}
      // Nudge the program to redraw itself at the client's size: a size change, then back.
      if (msg.cols && msg.rows) setTimeout(() => { resize(s, msg.cols, Math.max(5, msg.rows - 1)); setTimeout(() => resize(s, msg.cols, msg.rows), 60); }, 30);
      return;
    }
    return reply({ ok: false, error: "unknown op " + op });
  }

  function onConn(c) {
    clients++; bump();
    let buf = "";
    c.on("data", (d) => {
      if (c._attached) { input(c._attached, d); return; }
      buf += d.toString("utf8");
      if (buf.length > 1024 * 1024) return c.destroy();
      let i;
      while (!c._attached && (i = buf.indexOf("\n")) >= 0) {
        const line = buf.slice(0, i); buf = buf.slice(i + 1);
        let msg; try { msg = JSON.parse(line); } catch (_) { continue; }
        handle(c, msg, (obj) => { try { c.write(JSON.stringify(obj) + "\n"); } catch (_) {} });
        if (c._attached && buf) { input(c._attached, Buffer.from(buf, "utf8")); buf = ""; }
      }
    });
    const gone = () => { if (c._gone) return; c._gone = true; clients--; if (c._attached) c._attached.clients.delete(c); for (const w of waiters) if (w._c === c) waiters.delete(w); };
    c.on("close", gone); c.on("error", gone);
  }

  function listen() {
    return new Promise((resolve, reject) => {
      server = net.createServer(onConn);
      const go = () => server.listen(sock, () => { try { fs.chmodSync(sock, 0o600); } catch (_) {} ticker = setInterval(tick, TICK_MS); resolve(api); });
      server.on("error", (e) => {
        if (e.code !== "EADDRINUSE") return reject(e);
        // a socket file is there: another hub is alive, or it is stale from a crash
        const probe = net.connect(sock);
        probe.on("connect", () => { probe.destroy(); reject(Object.assign(new Error("a session hub is already running"), { code: "HUB_RUNNING" })); });
        probe.on("error", () => { try { fs.unlinkSync(sock); } catch (_) {} server.removeAllListeners("error"); server.on("error", reject); go(); });
      });
      go();
    });
  }
  function stop() {
    if (ticker) clearInterval(ticker); ticker = null;
    for (const s of sessions.values()) if (!s.exited) { try { process.kill(-s.proc.pid, "SIGTERM"); } catch (_) {} }
    persist();
    try { server && server.close(); } catch (_) {}
    try { fs.unlinkSync(sock); } catch (_) {}
    if (opts.onStop) opts.onStop();
  }
  const api = { listen, stop, tick, sessions, spawnSession, find, sock, dir, _handle: handle };
  return api;
}

// Entry point for `nexus hub serve` (started in the background by the client).
async function serve() {
  let osNotify = () => {};
  try { osNotify = require("../os-notify").osNotify; } catch (_) {}
  const hub = createHub({ notify: (t, b) => { try { osNotify(t, b); } catch (_) {} }, onStop: () => process.exit(0) });
  try { await hub.listen(); }
  catch (e) { if (e.code === "HUB_RUNNING") process.exit(0); throw e; }
  process.on("SIGTERM", () => hub.stop());
  process.on("SIGHUP", () => {}); // the terminal that started us closing must not end the sessions
}

module.exports = { createHub, serve };
