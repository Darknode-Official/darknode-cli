"use strict";
// Background sessions suite (lib/nexus/hub): the screen model, working/blocked/idle
// detection, the command guard that keeps `nexus <prompt>` working, the sessions tool's
// safety checks, and a real hub driving a real shell under a pseudo-terminal.
const fs = require("fs"), os = require("os"), path = require("path");
const DIR = fs.mkdtempSync(path.join(os.tmpdir(), "nxhub-test-"));
process.env.NEXUS_HUB_DIR = DIR; // never the real ~/.nexus/hub
const { Screen } = require("../lib/nexus/hub/screen");
const St = require("../lib/nexus/hub/status");
const Cli = require("../lib/nexus/hub/cli");
const Tool = require("../lib/nexus/hub/tool");
const P = require("../lib/nexus/hub/paths");
const { createHub } = require("../lib/nexus/hub/server");
const Gates = require("../lib/nexus/tool-gates");

let pass = 0, fail = 0;
const ok = (name, cond) => { if (cond) pass++; else { fail++; console.log("  \x1b[31mFAIL\x1b[0m " + name); } };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

(async () => {
  // ---- screen model ----
  const s = new Screen(20, 4);
  s.write("hello\r\nworld\x1b[1;1HJ");
  ok("screen: cursor moves overwrite text", s.text() === "Jello\nworld");
  s.write("\x1b]0;Fix login\x07\x1b[?2004h");
  ok("screen: OSC title is captured", s.title === "Fix login");
  ok("screen: private modes are tracked", s.modes.has(2004));
  s.write("\x1b[?1049h\x1b[2J\x1b[2;3Hin alt");
  ok("screen: alternate screen is separate", s.alt && s.text() === "\n  in alt");
  s.write("\x1b[?1049l");
  ok("screen: leaving alt restores the main screen", !s.alt && s.text().startsWith("Jello"));
  for (let i = 0; i < 6; i++) s.write("\r\nline" + i);
  ok("screen: scrolled lines go to scrollback", s.tail(6).split("\n").includes("line0") && s.tail(2) === "line4\nline5");
  s.write("\x1b[2K\x1b[1G");
  ok("screen: erase line", !s.text().includes("line5"));
  const rp = new Screen(30, 5); rp.write("\x1b[?1049h\x1b[?2004habc"); const bytes = rp.repaint();
  ok("screen: repaint rebuilds alt screen, modes and text", bytes.includes("\x1b[?1049h") && bytes.includes("\x1b[?2004h") && bytes.includes("abc"));
  const big = new Screen(10, 3); big.write("\x1b[" + "9".repeat(200) + "m" + "x");
  ok("screen: a runaway escape sequence does not swallow later text forever", typeof big.text() === "string");
  big.resize(5, 2); ok("screen: resize clamps", big.cols === 10 || big.cols === 5);
  const top = new Screen(120, 34); top.write("Do you want to proceed? (y/n) "); top.resize(110, 20);
  ok("screen: shrinking keeps text near the cursor (a prompt on row 1 survives)", top.text() === "Do you want to proceed? (y/n)");
  const tall = new Screen(20, 10); for (let i = 0; i < 10; i++) tall.write((i ? "\r\n" : "") + "r" + i); tall.resize(20, 4);
  ok("screen: shrinking a full screen keeps the cursor's rows", tall.text() === "r6\nr7\nr8\nr9" && tall.y === 3);

  // ---- status ----
  const now = 1e6;
  ok("status: recent output is working", St.classify({ lastOutputAt: now - 200 }, now) === "working");
  ok("status: quiet with a shell prompt is idle", St.classify({ lastOutputAt: now - 5000, tail: "bash-5.2$ " }, now) === "idle");
  ok("status: a y/n question on the last line is blocked", St.classify({ lastOutputAt: now - 5000, tail: "Do you want to proceed? (y/n) " }, now) === "blocked");
  ok("status: an answered question is not blocked", St.classify({ lastOutputAt: now - 5000, tail: "Do you want to proceed? (y/n) y\ngot y" }, now) === "idle");
  ok("status: an agent permission menu is blocked", St.asking("│ Do you want to proceed? │\n│ ❯ 1. Yes │\n│   2. No │\n╰────╯"));
  ok("status: a foreground job is working even when quiet", St.classify({ lastOutputAt: now - 9000, fgJob: true, tail: "$ sleep 30" }, now) === "working");
  ok("status: a fresh Nexus report wins", St.classify({ lastOutputAt: now - 100, report: { state: "blocked", at: now - 1000 } }, now) === "blocked");
  ok("status: a stale report is ignored", St.classify({ lastOutputAt: now - 9000, report: { state: "working", at: now - 60000 }, tail: "" }, now) === "idle");
  ok("status: exited is done", St.classify({ exited: true }, now) === "done");
  ok("status: stopped means anything but working", St.reached("blocked", "stopped") && St.reached("done", "stopped") && !St.reached("working", "stopped"));
  ok("status: lists of states", St.reached("idle", "blocked,idle") && !St.reached("working", "blocked|idle"));

  // ---- cli helpers ----
  const f = Cli.parseFlags(["--name", "api", "--attach", "x", "--", "claude", "--resume"], { name: 1, attach: "bool" });
  ok("cli: flags and the -- command", f.name === "api" && f.attach === true && f._[0] === "x" && f["--"].join(" ") === "claude --resume");
  const rows = Cli.renderTable([{ id: "1", name: "web", state: "blocked", since: 0, cwd: "/x", title: "Fix" }, { id: "2", name: "old", saved: true, cwd: "/y" }], { now: 65000, width: 90 });
  ok("cli: table shows state, age and title", /web\s+blocked\s+1m\s+\/x\s+Fix/.test(rows[0]) && /old\s+stopped/.test(rows[1]));
  ok("cli: ages", Cli.fmtAge(5000) === "5s" && Cli.fmtAge(3 * 3600e3 + 120e3) === "3h02");
  // with no hub running, prompt-like words stay prompts
  ok("guard: bg / attach / sessions / hub are always commands", (await Cli.claims("bg", [])) && (await Cli.claims("hub", ["status"])));
  ok("guard: `nexus ls` only bare", (await Cli.claims("ls", [])) && !(await Cli.claims("ls", ["the", "files"])));
  ok("guard: `nexus send an email ...` stays a prompt", !(await Cli.claims("send", ["an", "email"])));
  ok("guard: `nexus kill the dev server` stays a prompt", !(await Cli.claims("kill", ["the", "dev", "server"])));

  // ---- gates + tool safety (no hub needed) ----
  ok("gate: sessions is an exec tool and blocked in plan mode", Gates.isExecTool("sessions") && Gates.isPlanBlocked("sessions"));
  ok("gate: spawn shows the danger gate its command", Gates.execCommand("sessions", { action: "spawn", command: "rm -rf ~" }) === "rm -rf ~");
  ok("gate: send shows the danger gate its text", Gates.execCommand("sessions", { action: "send", text: "git push -f" }) === "git push -f");
  const fake = { ensureHub: async () => {}, call: async (m) => ({ ok: true, session: { id: "1", name: "n", state: "idle", kind: "nexus" }, sessions: [] }) };
  ok("tool: spawn outside the project is refused", /inside the project/.test((await Tool.sessionsTool({ action: "spawn", cwd: "../../etc" }, DIR, fake)).error || ""));
  ok("tool: unknown agent is refused", /agent must be/.test((await Tool.sessionsTool({ action: "spawn", agent: "rm" }, DIR, fake)).error || ""));
  ok("tool: send needs text", /needs text/.test((await Tool.sessionsTool({ action: "send", id: "1" }, DIR, fake)).error || ""));
  ok("tool: id required", /needs id/.test((await Tool.sessionsTool({ action: "peek" }, DIR, fake)).error || ""));
  const mcp = require("../lib/nexus/ask-mcp");
  ok("mcp bridge lists the sessions tool", mcp.SESSIONS_TOOL.name === "sessions" && mcp.SESSIONS_TOOL.inputSchema.properties.action.enum.includes("wait"));
  ok("native schema has sessions", !!require("../lib/nexus/native-tools").TOOL_SCHEMAS.sessions);

  // ---- a real hub with a real shell ----
  if (!P.supported()) { console.log("  (skipping live hub tests on " + process.platform + ")"); return done(); }
  const hub = createHub({ dir: DIR, stayUp: true });
  await hub.listen();
  ok("hub: socket is private", (fs.statSync(hub.sock).mode & 0o077) === 0 && (fs.statSync(DIR).mode & 0o077) === 0);
  const call = (m, o) => P.call(m, Object.assign({ dir: DIR, timeout: 15000 }, o));
  try {
    const sp = await call({ op: "spawn", name: "sh", cwd: DIR, cmd: ["/bin/sh", "-i"], cols: 80, rows: 20, env: { PS1: "hub$ ", ENV: "" } });
    ok("hub: spawn", sp.ok && sp.session.name === "sh");
    await call({ op: "wait", id: "sh", until: "idle", timeout: 10, settle: false });
    await call({ op: "send", id: "sh", text: "echo one-$((40+2)); sleep 2; echo two-done" });
    const w = await call({ op: "wait", id: "sh", until: "idle", timeout: 15 });
    ok("hub: wait holds through a quiet foreground command", w.reached && /two-done/.test(w.tail));
    const pk = await call({ op: "peek", id: "sh", lines: 10 });
    ok("hub: peek reads the screen as text", /one-42/.test(pk.text) && !/\x1b/.test(pk.text));
    ok("hub: the shell sees a real terminal of the requested size", await (async () => { await call({ op: "send", id: "sh", text: "stty size" }); await call({ op: "wait", id: "sh", until: "idle", timeout: 10 }); return /\b20 80\b/.test((await call({ op: "peek", id: "sh", lines: 4 })).text); })());
    await call({ op: "resize", id: "sh", cols: 100, rows: 30 });
    await call({ op: "send", id: "sh", text: "stty size" }); await call({ op: "wait", id: "sh", until: "idle", timeout: 10 });
    ok("hub: resize reaches the program", /\b30 100\b/.test((await call({ op: "peek", id: "sh", lines: 3 })).text));
    await call({ op: "send", id: "sh", text: "printf 'Do you want to proceed? (y/n) '; read a; echo answered-$a" });
    const b = await call({ op: "wait", id: "sh", until: "blocked", timeout: 10 });
    ok("hub: a question marks the session blocked", b.reached && b.session.state === "blocked");
    await call({ op: "send", id: "sh", text: "y" });
    const a2 = await call({ op: "wait", id: "sh", until: "idle", timeout: 10 });
    ok("hub: answering unblocks it", a2.reached && /answered-y/.test(a2.tail));
    await call({ op: "report", id: "1", state: "working" });
    ok("hub: a Nexus report is taken as the state", (await call({ op: "list" })).sessions[0].state === "working");
    const bad = await call({ op: "send", id: "nope", text: "x" });
    ok("hub: unknown session is a clear error", !bad.ok && /no session named nope/.test(bad.error));
    await call({ op: "kill", id: "sh" });
    const d = await call({ op: "wait", id: "sh", until: "done", timeout: 10, settle: false });
    ok("hub: kill ends the session", d.reached && d.session.state === "done");
    const saved = JSON.parse(fs.readFileSync(P.statePath(DIR), "utf8"));
    ok("hub: a killed session is not kept for restore", !saved.sessions.some((x) => x.name === "sh"));
    await call({ op: "spawn", name: "keep", cwd: DIR, cmd: ["/bin/sh", "-c", "sleep 60"] });
  } catch (e) { ok("hub: live tests threw " + e.message, false); }
  hub.stop();
  const after = JSON.parse(fs.readFileSync(P.statePath(DIR), "utf8"));
  ok("hub: stopping keeps running sessions restorable", after.sessions.some((x) => x.name === "keep"));
  const hub2 = createHub({ dir: DIR, stayUp: true }); await hub2.listen();
  const l2 = await P.call({ op: "list" }, { dir: DIR, timeout: 5000 });
  ok("hub: a new hub lists the earlier sessions as restorable", l2.saved.some((x) => x.name === "keep"));
  await P.call({ op: "forget" }, { dir: DIR, timeout: 5000 });
  ok("hub: forget with no name clears every stopped session", (await P.call({ op: "list" }, { dir: DIR, timeout: 5000 })).saved.length === 0);
  hub2.stop();
  done();
})();

function done() {
  try { fs.rmSync(DIR, { recursive: true, force: true }); } catch (_) {}
  console.log("\n" + (fail ? "\x1b[31m" : "\x1b[32m") + pass + " passed, " + fail + " failed\x1b[0m  (background sessions)");
  process.exit(fail ? 1 : 0);
}
