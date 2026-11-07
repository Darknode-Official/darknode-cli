"use strict";
// ============================================================================
// hub/cli — the commands people (and agents) use to run Nexus sessions in the
// background. See hub/server.js for what the hub is.
//
//   nexus bg [--name N] [--cwd DIR] [--prompt TEXT] [-- command args...]
//   nexus ls [--json]                 nexus attach [id|name]   (Ctrl+] detaches)
//   nexus send <id> <text...>         nexus peek <id> [--lines N | --screen]
//   nexus wait <id> [--until blocked|idle|done|stopped] [--timeout SECS]
//   nexus kill <id>                   nexus sessions   (live list: Enter attaches)
//   nexus hub restore | stop | serve
// ============================================================================
const path = require("path"), cp = require("child_process"), net = require("net");
const P = require("./paths");
const { RESET_CLIENT } = require("./screen");
const { WAIT_STATES } = require("./status");

const DETACH = 0x1d; // Ctrl+]
const IDENT = (s) => s;

function fmtAge(ms) {
  const s = Math.max(0, Math.floor(ms / 1000));
  if (s < 60) return s + "s"; const m = Math.floor(s / 60); if (m < 60) return m + "m";
  const h = Math.floor(m / 60); if (h < 48) return h + "h" + String(m % 60).padStart(2, "0"); return Math.floor(h / 24) + "d";
}
const home = (p) => { const h = require("os").homedir(); return p && p.startsWith(h) ? "~" + p.slice(h.length) : p; };
const cut = (s, n) => { s = String(s || ""); return s.length > n ? s.slice(0, Math.max(0, n - 1)) + "…" : s; };

// The session table, used by `nexus ls` and the live list. Pure.
function renderTable(list, o = {}) {
  const c = o.colors || {}, now = o.now || Date.now(), width = o.width || 100, sel = o.sel == null ? -1 : o.sel;
  const paint = { working: c.cyan || IDENT, blocked: c.yellow || IDENT, idle: c.gray || IDENT, done: c.green || IDENT, failed: c.red || IDENT, stopped: c.gray || IDENT };
  const label = (s) => (s.saved ? "stopped" : s.state === "done" && s.exitCode ? "failed" : s.state);
  const rows = list.map((s, i) => {
    const st = label(s);
    const name = cut(s.name, 22).padEnd(22), state = st.padEnd(8);
    const age = (s.saved ? "" : fmtAge(now - (s.since != null ? s.since : now))).padStart(5);
    const extra = (s.attached ? "attached  " : "") + (s.title && s.title !== s.name ? s.title : "");
    const lead = i === sel ? "›" : " ";
    const room = Math.max(0, width - 46);
    const tail = cut(home(s.cwd) + (extra ? "  " + extra : ""), room);
    const line = lead + " " + String(s.id).padStart(3) + "  " + name + "  " + paint[st](state) + " " + (c.gray || IDENT)(age) + "  " + (c.gray || IDENT)(tail);
    return i === sel && c.bold ? c.bold(line) : line;
  });
  return rows;
}

async function ensureHub(o = {}) {
  if (!P.supported()) throw new Error("background sessions need Linux or macOS for now");
  try { return await P.call({ op: "ping" }, { timeout: 1500 }); } catch (e) { if (o.noStart) throw e; }
  const entry = process.pkg ? [process.execPath] : [process.execPath, path.join(__dirname, "..", "..", "..", "darknode.js")];
  const child = cp.spawn(entry[0], entry.slice(1).concat(["nexus", "hub", "serve"]), { detached: true, stdio: "ignore", cwd: require("os").homedir() });
  child.unref();
  for (let i = 0; i < 40; i++) {
    await new Promise((r) => setTimeout(r, 100));
    try { return await P.call({ op: "ping" }, { timeout: 800 }); } catch (_) {}
  }
  throw new Error("could not start the session hub");
}
async function req(msg, o) { await ensureHub(); const r = await P.call(msg, o); if (!r.ok) throw new Error(r.error || "the hub refused"); return r; }

// ---- attach: this terminal becomes the session's terminal until Ctrl+] ----
function attach(id, o = {}) {
  return new Promise((resolve, reject) => {
    const out = o.stdout || process.stdout, inp = o.stdin || process.stdin;
    if (!inp.isTTY) return reject(new Error("attach needs a terminal"));
    const sock = net.connect(P.sockPath());
    let ready = false, buf = Buffer.alloc(0), name = String(id || ""), ended = false;
    const size = () => ({ cols: out.columns || 100, rows: out.rows || 30 });
    const onResize = () => { const z = size(); P.call({ op: "resize", id: name, cols: z.cols, rows: z.rows }).catch(() => {}); };
    const onKey = (d) => {
      const k = d.indexOf(DETACH);
      if (k >= 0) { if (k > 0) sock.write(d.slice(0, k)); return finish("detached"); }
      sock.write(d);
    };
    const finish = (why) => {
      if (ended) return; ended = true;
      try { inp.removeListener("data", onKey); inp.setRawMode(false); inp.pause(); } catch (_) {}
      out.removeListener("resize", onResize);
      try { sock.destroy(); } catch (_) {}
      out.write(RESET_CLIENT + "\r\n");
      resolve({ why, name });
    };
    sock.on("connect", () => { const z = size(); sock.write(JSON.stringify({ op: "attach", id, cols: z.cols, rows: z.rows }) + "\n"); });
    sock.on("data", (d) => {
      if (ready) return out.write(d);
      buf = Buffer.concat([buf, d]);
      const i = buf.indexOf(10); if (i < 0) return;
      let r; try { r = JSON.parse(buf.slice(0, i).toString("utf8")); } catch (_) { r = { ok: false, error: "bad reply from the hub" }; }
      if (!r.ok) { sock.destroy(); ended = true; return reject(new Error(r.error)); }
      ready = true; name = r.session.name;
      const rest = buf.slice(i + 1); buf = null;
      inp.setRawMode(true); inp.resume(); inp.on("data", onKey);
      out.on("resize", onResize);
      if (rest.length) out.write(rest);
    });
    sock.on("close", () => (ready ? finish("ended") : !ended && reject(new Error("the session hub closed the connection"))));
    sock.on("error", (e) => (ready ? finish("ended") : reject(e)));
  });
}

function parseFlags(args, spec) {
  const o = { _: [] };
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === "--") { o["--"] = args.slice(i + 1); break; }
    const m = /^--([\w-]+)(?:=(.*))?$/.exec(a);
    if (m && spec[m[1]] === "bool") o[m[1]] = true;
    else if (m && spec[m[1]]) o[m[1]] = m[2] != null ? m[2] : args[++i];
    else o._.push(a);
  }
  return o;
}

// ---- live list (nexus sessions / nexus hub) ----
async function liveList(C) {
  const out = process.stdout, inp = process.stdin;
  if (!inp.isTTY) { await printList(C); return; }
  let sel = 0, list = [], note = "", armedKill = null, timer = null, closed = false, busy = false;
  const fetch = async () => { const r = await req({ op: "list" }); list = r.sessions.slice().sort(order).concat((r.saved || []).map((m) => ({ ...m, saved: true, state: "stopped" }))); if (sel >= list.length) sel = Math.max(0, list.length - 1); };
  const draw = () => {
    if (closed) return;
    const w = out.columns || 100;
    const lines = [C.bold("  Nexus sessions") + C.gray("   " + list.filter((s) => !s.saved && s.state !== "done").length + " running"), ""];
    if (!list.length) lines.push(C.gray("  nothing running. Press n to start Nexus here in the background."));
    else lines.push(...renderTable(list, { colors: C, sel, width: w }));
    lines.push("", C.gray("  enter attach   n new here   x stop   r restore stopped   q quit   (Ctrl+] inside a session comes back here)"));
    if (note) lines.push("  " + note);
    out.write("\x1b[H\x1b[2J" + lines.join("\r\n"));
  };
  const enter = () => { out.write("\x1b[?1049h\x1b[?25l"); inp.setRawMode(true); inp.resume(); inp.on("data", onKey); };
  const leave = () => { inp.removeListener("data", onKey); try { inp.setRawMode(false); } catch (_) {} inp.pause(); out.write("\x1b[?25h\x1b[?1049l"); };
  const refresh = async () => { if (busy) return; try { await fetch(); } catch (e) { note = C.red(e.message); } draw(); };
  let done;
  const onKey = async (d) => {
    const k = d.toString("utf8");
    if (k === "q" || k === "\x1b" || k === "\x03") { closed = true; clearInterval(timer); leave(); return done(); }
    if (k === "\x1b[A" || k === "k") sel = Math.max(0, sel - 1);
    else if (k === "\x1b[B" || k === "j") sel = Math.min(list.length - 1, sel + 1);
    else if (k === "n") { try { const r = await req({ op: "spawn", cwd: process.cwd(), cols: out.columns, rows: out.rows }); note = "started " + r.session.name; } catch (e) { note = C.red(e.message); } }
    else if (k === "r") { try { const r = await req({ op: "restore" }); note = r.sessions.length ? "restored " + r.sessions.map((s) => s.name).join(", ") : "nothing to restore"; } catch (e) { note = C.red(e.message); } }
    else if (k === "x" && list[sel] && !list[sel].saved) {
      const s = list[sel];
      if (armedKill === s.id) { armedKill = null; try { await req({ op: "kill", id: s.id }); note = "stopping " + s.name; } catch (e) { note = C.red(e.message); } }
      else { armedKill = s.id; note = C.yellow("press x again to stop " + s.name); }
    }
    else if ((k === "\r" || k === "\n") && list[sel] && !list[sel].saved && list[sel].state !== "done") {
      busy = true; clearInterval(timer); leave();
      try { const r = await attach(list[sel].id); note = r.why === "detached" ? "detached from " + r.name + " (still running)" : r.name + " ended"; }
      catch (e) { note = C.red(e.message); }
      busy = false; enter(); timer = setInterval(refresh, 700);
    }
    if (k !== "x") armedKill = null;
    await refresh();
  };
  enter(); await refresh(); timer = setInterval(refresh, 700);
  return new Promise((r) => { done = r; });
}
// blocked first (they need you), then working, idle, done
const RANK = { blocked: 0, working: 1, idle: 2, done: 3 };
const order = (a, b) => (RANK[a.state] - RANK[b.state]) || (a.id - b.id);

async function printList(C, json) {
  const r = await req({ op: "list" });
  if (json) return console.log(JSON.stringify({ sessions: r.sessions, saved: r.saved || [] }, null, 2));
  const list = r.sessions.slice().sort(order).concat((r.saved || []).map((m) => ({ ...m, saved: true, state: "stopped" })));
  if (!list.length) return console.log(C.gray("  no sessions. Start one: nexus bg   (or: nexus bg -- claude)"));
  console.log(C.gray("   ID  NAME                    STATE      AGE  FOLDER"));
  renderTable(list, { colors: C, width: process.stdout.columns || 100 }).forEach((l) => console.log(l));
  if (list.some((s) => s.saved)) console.log(C.gray("\n  stopped sessions came from an earlier hub: nexus hub restore brings them back"));
}

async function main(sub, args, C) {
  C = Object.assign({ bold: IDENT, gray: IDENT, cyan: IDENT, yellow: IDENT, green: IDENT, red: IDENT }, C || {});
  const say = (s) => console.log("  " + s);
  if (sub === "bg") {
    const f = parseFlags(args, { name: 1, cwd: 1, prompt: 1, attach: "bool" });
    const cmd = f["--"] && f["--"].length ? f["--"] : null;
    const nexusArgs = cmd ? [] : f._;
    const r = await req({ op: "spawn", name: f.name, cwd: f.cwd || process.cwd(), cmd, nexusArgs, prompt: f.prompt, cols: process.stdout.columns, rows: process.stdout.rows });
    const s = r.session;
    if (f.attach) return attach(s.id).then((x) => say(x.why === "detached" ? "detached from " + x.name + " — it keeps running. nexus attach " + x.name : x.name + " ended"));
    say("started " + C.bold(s.name) + C.gray("  (id " + s.id + ", " + (s.kind === "nexus" ? "Nexus" : s.cmd.join(" ")) + ")"));
    say(C.gray("attach: nexus attach " + s.name + "    list: nexus ls    Ctrl+] detaches"));
    return;
  }
  if (sub === "ls") return printList(C, args.includes("--json"));
  if (sub === "sessions" || sub === "hub" && !args[0]) return liveList(C);
  if (sub === "attach") {
    const id = args[0];
    await ensureHub();
    const x = await attach(id);
    return say(x.why === "detached" ? "detached from " + C.bold(x.name) + " — it keeps running. nexus attach " + x.name : x.name + " ended");
  }
  if (sub === "send") {
    const [id, ...rest] = args; const f = parseFlags(rest, { "no-enter": "bool" });
    if (!id || !f._.length) throw new Error("usage: nexus send <id|name> <text>");
    await req({ op: "send", id, text: f._.join(" "), enter: !f["no-enter"] });
    return say("sent to " + id);
  }
  if (sub === "peek") {
    const [id, ...rest] = args; const f = parseFlags(rest, { lines: 1, screen: "bool" });
    const r = await req({ op: "peek", id, lines: Number(f.lines) || 40, screen: !!f.screen });
    console.log(C.gray("── " + r.session.name + " · " + r.session.state + (r.session.title ? " · " + r.session.title : "") + " ──"));
    return console.log(r.text);
  }
  if (sub === "wait") {
    const [id, ...rest] = args; const f = parseFlags(rest, { until: 1, timeout: 1, quiet: "bool" });
    const until = f.until || "stopped";
    for (const u of until.split(/[,|]/)) if (!WAIT_STATES.has(u)) throw new Error("--until takes blocked, idle, done, stopped or working");
    const r = await req({ op: "wait", id, until, timeout: Number(f.timeout) || 0 });
    if (!f.quiet) say(r.session.name + " is " + r.session.state + (r.reached ? "" : " (timed out waiting for " + until + ")"));
    if (!r.reached) process.exitCode = 2;
    return;
  }
  if (sub === "kill") { const r = await req({ op: "kill", id: args[0] }); return say("stopping " + r.session.name); }
  if (sub === "hub") {
    const a = args[0];
    if (a === "serve") return require("./server").serve().then(() => new Promise(() => {}));
    if (a === "stop") { try { await P.call({ op: "stop" }, { timeout: 2000 }); say("hub stopped (its sessions were ended)"); } catch (_) { say("no hub running"); } return; }
    if (a === "restore") { const r = await req({ op: "restore" }); return say(r.sessions.length ? "restored " + r.sessions.map((s) => s.name + (s.error ? " (" + s.error + ")" : "")).join(", ") : "nothing to restore"); }
    if (a === "forget") { await req({ op: "forget", id: args[1] }); return say("forgot stopped sessions" + (args[1] ? " named " + args[1] : "")); }
    if (a === "status") { try { const r = await P.call({ op: "ping" }, { timeout: 1500 }); say("hub running (pid " + r.pid + ", " + r.sessions + " sessions)"); } catch (_) { say("no hub running"); } return; }
    throw new Error("nexus hub: serve | stop | restore | forget | status   (no argument opens the live list)");
  }
  throw new Error("unknown sessions command " + sub);
}

// `nexus <words>` is also a one-shot prompt, so only words that cannot start a prompt are
// always commands. send / wait / peek / kill are commands only when the next word names a
// session that exists (`nexus kill the dev server` stays a prompt); `nexus hub <cmd>` always works.
const ALWAYS = new Set(["bg", "attach", "sessions", "hub"]);
const IF_SESSION = new Set(["send", "wait", "peek", "kill"]);
async function claims(sub, args) {
  if (!P.supported()) return false;
  if (ALWAYS.has(sub)) return true;
  if (sub === "ls") return args.length === 0 || (args.length === 1 && args[0] === "--json");
  if (!IF_SESSION.has(sub) || !args[0]) return false;
  try {
    const r = await P.call({ op: "list" }, { timeout: 800 });
    return r.sessions.some((x) => String(x.id) === args[0] || x.name === args[0]);
  } catch (_) { return false; }
}
// `nexus hub <cmd> ...` routes every command, so nothing is ambiguous there.
async function hubMain(args, C) {
  const [a, ...rest] = args;
  if (a && a !== "serve" && a !== "stop" && a !== "restore" && a !== "forget" && a !== "status" && (ALWAYS.has(a) || IF_SESSION.has(a) || a === "ls")) return main(a, rest, C);
  return main("hub", args, C);
}

module.exports = { main, hubMain, claims, ALWAYS, IF_SESSION, renderTable, parseFlags, attach, ensureHub, req, fmtAge };
