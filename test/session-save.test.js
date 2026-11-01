"use strict";
// session-save suite: the saved-transcript transform in darknode.js (size caps +
// nested-item redaction). Extracts the helper block so it tests the shipped code.
const fs = require("fs"), path = require("path");
const Redact = require("../lib/nexus/redact");
const { asText } = require("../lib/cli/tui-format");

let pass = 0, fail = 0;
const ok = (name, cond) => { if (cond) pass++; else { fail++; console.log("  \x1b[31mFAIL\x1b[0m " + name); } };

const src = fs.readFileSync(path.join(__dirname, "..", "darknode.js"), "utf8");
const a = src.indexOf("    const SAVE_CAP = 8000,"), b = src.indexOf("    const restoreSession");
ok("found the save helpers", a > 0 && b > a);
const { redactBlock, capResult } = new Function("Redact", "asText", src.slice(a, b) + "\nreturn { redactBlock, capResult };")(Redact, asText);

const secret = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8";
const big = "HEAD-" + "x".repeat(50000) + "-TAIL";
const mk = () => ({ role: "nexus", items: [
  { type: "tool", id: "t1", name: "Bash", status: "ok", input: { command: "echo " + secret }, result: big, detail: "d", label: "Bash" },
  { type: "text", full: "token " + secret, shown: 10 },
  { type: "tool", id: "t2", name: "Read", status: "ok", result: [{ type: "text", text: big }] },
] });

const blk = mk(), saved = redactBlock(blk, 0, [blk]);
const r0 = saved.items[0].result;
ok("oversized string result is capped", typeof r0 === "string" && r0.length < 9000);
ok("capped result keeps head and tail", r0.startsWith("HEAD-") && r0.endsWith("-TAIL") && r0.includes("chars trimmed when the session was saved"));
ok("oversized array result becomes capped text", typeof saved.items[2].result === "string" && saved.items[2].result.length < 9000);
ok("secret in nested tool input is redacted", !JSON.stringify(saved.items[0].input).includes(secret));
ok("secret in nested text is redacted", !saved.items[1].full.includes(secret));
ok("live transcript keeps the full result", blk.items[0].result === big && blk.items[1].full.includes(secret));
ok("unchanged items are reused across saves", redactBlock(blk, 0, [blk]).items[0] === saved.items[0]);

const arr = Array.from({ length: 50 }, mk), oldSaved = redactBlock(arr[0], 0, arr), newSaved = redactBlock(arr[49], 49, arr);
ok("older blocks get the tighter cap", oldSaved.items[0].result.length < 2000 && newSaved.items[0].result.length > 5000);

ok("small results pass through untouched", capResult("short") === "short" && JSON.stringify(capResult({ output: "x" })) === '{"output":"x"}');
ok("null result stays null", capResult(null) === null && capResult(undefined) === undefined);

// ---- incremental save: snapshot + append-only log, replayed by loadSessionFile ----
{
  const os = require("os");
  const d0 = src.indexOf("    const _disk = {"), d1 = src.indexOf("      return s;\n    };", d0) + "      return s;\n    };".length;
  ok("found the incremental save code", d0 > 0 && d1 > d0);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "nx-sess-"));
  const T = [], S = { model: "m" };
  const api = new Function("Redact", "asText", "fs", "path", "cwd", "stripBom", "secureNexus", "transcript", "sess", "engine", "claudeSid",
    src.slice(a, b) + src.slice(d0, d1) + "\nreturn { saveSession, loadSessionFile, blockJson, _disk };")(Redact, asText, fs, path, dir, (x) => x, () => {}, T, S, "claude", null);
  const sp = path.join(dir, ".nexus", "session.json"), lp = path.join(dir, ".nexus", "session.log");
  const expect = () => JSON.stringify(JSON.parse("[" + T.filter((x) => !x.ephemeral).map(api.blockJson).join(",") + "]"));
  const loaded = () => JSON.stringify(api.loadSessionFile().transcript);
  const logLines = () => { try { return fs.readFileSync(lp, "utf8").split("\n").filter(Boolean); } catch (_) { return []; } };
  const tool = (n) => ({ type: "tool", id: "t" + n, name: "Bash", status: "ok", input: { command: "ls " + n }, result: "out " + n + " " + "y".repeat(1000) });
  for (let n = 0; n < 30; n++) { T.push({ role: "user", text: "q" + n }); T.push({ role: "nexus", items: [tool(n), { type: "text", full: "a" + n, shown: 2 }] }); }

  api.saveSession();
  ok("first save writes a snapshot and no log", fs.existsSync(sp) && logLines().length === 0 && loaded() === expect());
  const base = fs.statSync(sp).size;

  T.push({ role: "user", text: "next" }); T.push({ role: "nexus", items: [tool(99)] }); api.saveSession();
  const l1 = logLines();
  ok("a turn appends one small log line, snapshot untouched", l1.length === 1 && l1[0].length < 10000 && fs.statSync(sp).size === base);
  ok("the line starts at the first changed block", JSON.parse(l1[0]).from === 60);
  ok("load = snapshot + log", loaded() === expect());

  api.saveSession();
  ok("a save with nothing changed appends nothing", logLines().length === 1);

  T[61].items[0].status = "err"; api.saveSession();
  ok("editing an older block replays from that block", JSON.parse(logLines()[1]).from === 61 && loaded() === expect());

  T.push({ role: "system", ephemeral: true, text: "note" }); api.saveSession();
  ok("ephemeral blocks are not saved", logLines().length === 2 && loaded() === expect());

  fs.appendFileSync(lp, '{"gen":"other","from":0,"blocks":[]}\n{"gen":"' + api._disk.gen + '","from":0,"blo');
  ok("other-generation lines are skipped and a torn last line ends the replay", loaded() === expect());

  T.length = 2; api.saveSession();
  ok("after /clear-style shrink the snapshot is rewritten and the log folded in", logLines().length === 0 && fs.statSync(sp).size < base / 2 && loaded() === expect());

  for (let n = 0; n < 400; n++) { T.push({ role: "user", text: "z" + n }); T.push({ role: "nexus", items: [tool(1000 + n)] }); api.saveSession(); }
  ok("the log is compacted once it outgrows the snapshot", fs.statSync(lp, { throwIfNoEntry: false }) == null || fs.statSync(lp).size <= Math.max(1e6, fs.statSync(sp).size / 2) + 20000);
  ok("still exact after many saves and compactions", loaded() === expect());

  const gen = api._disk.gen; fs.writeFileSync(sp, fs.readFileSync(sp, "utf8").replace(gen, "foreign")); T.push({ role: "user", text: "after" }); api.saveSession();
  ok("a snapshot rewritten by another process forces a fresh snapshot", api._disk.gen !== gen && logLines().length === 0 && loaded() === expect());

  const legacy = { engine: "claude", transcript: [{ role: "user", text: "old" }], ts: 1 }; fs.writeFileSync(sp, JSON.stringify(legacy)); fs.writeFileSync(lp, '{"gen":"x","from":0,"blocks":[]}\n');
  ok("an old single-file session.json still loads as is", JSON.stringify(api.loadSessionFile().transcript) === JSON.stringify(legacy.transcript));
  T.length = 0; for (let n = 0; n < 45; n++) { T.push({ role: "nexus", items: [{ type: "tool", id: "b" + n, name: "Bash", status: "ok", result: "r".repeat(6000) }] }); }
  api.saveSession(); api.saveSession(); // fresh snapshot
  const before = logLines().length; let maxLine = 0;
  for (let n = 0; n < 5; n++) { T.push({ role: "user", text: "age" + n }); api.saveSession(); const ls = logLines(); maxLine = Math.max(maxLine, ls[ls.length - 1].length); }
  ok("blocks aging past the recent window are not re-appended each turn", logLines().length === before + 5 && maxLine < 2000);
  fs.rmSync(dir, { recursive: true, force: true });
}

if (fail) { console.log("session-save: " + pass + " passed, " + fail + " FAILED"); process.exit(1); }
console.log("session-save: " + pass + " passed");
