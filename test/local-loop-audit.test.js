"use strict";
// Local agent loop suite: tool-call parsing (normalizeToolCall in darknode.js), the tool
// observation cap and /compact keep-tail (lib/nexus/local-loop.js), /compact after /resume,
// and the /budget, /settings budget, /report since and /savings since argument parsing.
const fs = require("fs"), path = require("path"), vm = require("vm");
const L = require("../lib/nexus/local-loop");
const { parseUsd, isIsoSince } = require("../lib/cli/text");

let pass = 0, fail = 0;
const ok = (name, cond) => { if (cond) pass++; else { fail++; console.log("  \x1b[31mFAIL\x1b[0m " + name); } };

const src = fs.readFileSync(path.join(__dirname, "..", "darknode.js"), "utf8");

// normalizeToolCall, evaluated straight from darknode.js
const ctx = {}; vm.createContext(ctx);
const code = src.slice(src.indexOf("const TOOL_ARGKEY ="), src.indexOf("// A conversational / trivial message")).replace(/^const PR = .*$/m, "").replace(/^const \{ lineRange \}.*$/m, "");
vm.runInContext(code + ";this.normalizeToolCall = normalizeToolCall;", ctx);
const ntc = ctx.normalizeToolCall;
ok("a command's own closing quote is kept (echo \"a\")", ntc({ tool: 'run_command(echo "a")' }).a.command === 'echo "a"');
ok("a string arg ending in a quote is kept", ntc({ tool: "run_command", args: 'grep -n "x"' }).a.command === 'grep -n "x"');
ok("one matching quote pair around the whole value is stripped", ntc({ tool: "read_file", args: "'a b.txt'" }).a.path === "a b.txt" && ntc({ tool: 'read_file("a.txt")' }).a.path === "a.txt");
ok("two separately quoted words are left alone", ntc({ tool: "run_command", args: "'a' && 'b'" }).a.command === "'a' && 'b'");
ok("key: value with a quoted value is unquoted", ntc({ tool: "edit_file", args: 'path: "a.js"' }).a.path === "a.js");
ok("a JSON-encoded todo list maps to todos", JSON.stringify(ntc({ tool: "todo_write", args: '[{"content":"x"}]' }).a) === '{"todos":[{"content":"x"}]}');
ok("a JSON-encoded task list maps to tasks", JSON.stringify(ntc({ tool: "spawn_agents", args: '["a","b"]' }).a) === '{"tasks":["a","b"]}');
ok("JSON-object string args still parse", ntc({ tool: "write_file", args: '{"path":"a","content":"b"}' }).a.content === "b");
ok("a plain path arg still lands on the tool's key", ntc({ tool: "read_file", args: "a.txt" }).a.path === "a.txt");

// observation cap
const body = ('"k": "v\\\\n",\n').repeat(700).slice(0, 9990);
const res = { content: body, note: "showing lines 1-700 of 2000 — continue with offset 701" };
ok("(repro) JSON escaping pushes a capped read past 14000", JSON.stringify(res).length > 14000);
const capped = L.capObservation(res, 14000);
let parsed = null; try { parsed = JSON.parse(capped); } catch (_) {}
ok("a capped observation is still valid JSON within the cap", parsed && capped.length <= 14000);
ok("the continue-from note survives the cap", parsed && parsed.note === res.note);
ok("the cut is said, not silent", parsed && /more chars of content cut to fit/.test(parsed.content));
ok("a small observation is passed through unchanged", L.capObservation({ a: 1 }, 14000) === '{"a":1}');
const arr = L.capObservation(["x".repeat(20000)], 14000);
ok("a non-object observation is sliced with a marker", arr.length > 14000 && arr.length < 14100 && /cut to fit\]$/.test(arr));
ok("an undefined result does not throw", L.capObservation(undefined, 10) === "undefined");

// /compact keep-tail
const m = (r) => ({ role: r, content: r });
const msgs = ["system", "user", "assistant", "tool", "assistant", "tool", "assistant", "tool", "assistant"].map(m);
ok("(repro) the old slice(-6) started on a tool result", msgs.slice(-6)[0].role === "tool");
ok("the tail never starts on an orphaned tool result", L.compactTail(msgs, 6)[0].role === "assistant" && L.compactTail(msgs, 6).length === 5);
const two = ["system", "user", "assistant", "tool", "assistant", "user", "assistant", "tool", "assistant"].map(m);
ok("the tail starts at a user message when one is in range", L.compactTail(two, 6)[0].role === "user" && L.compactTail(two, 6).length === 4);
ok("a short history never includes the system message", L.compactTail(["system", "user", "assistant"].map(m), 6).every((x) => x.role !== "system"));
ok("an all-tool tail keeps nothing rather than orphans", L.compactTail(["system", "tool", "tool"].map(m), 6).length === 0);

// darknode.js wiring
const obsLine = src.split("\n").find((l) => l.includes("let obs = ")) || "";
ok("the loop caps observations with capObservation", /LocalLoop\.capObservation\(_obsRes, 14000\)/.test(obsLine) && !/\.slice\(0, 14000\)/.test(obsLine));
ok("a non-string final answer is shown as JSON, not [object Object]", /typeof o\.final === "string" \? o\.final : JSON\.stringify\(o\.final, null, 2\)/.test(src));
const dc = src.slice(src.indexOf("const doCompact = (auto) =>"), src.indexOf("const cancelCompact = () =>"));
ok("/compact keeps its tail through compactTail", /LocalLoop\.compactTail\(src, lean \? 4 : 6\)/.test(dc));
ok("/compact summarizes the /resume replay queue too", /engine === "ollama" && \(oMsgs\.length > 2 \|\| localReplay\.length\)/.test(dc) && /localReplay\.length \? \[oMsgs\[0\]\]\.concat\(localReplay\) : oMsgs/.test(dc));
ok("/compact replaces the replay queue with summary + tail", /if \(localReplay\.length\) localReplay = head\.concat\(tail\)/.test(dc));

// argument parsing
ok("parseUsd takes plain amounts", parseUsd("5") === 5 && parseUsd("5.00") === 5 && parseUsd("$2.5") === 2.5 && parseUsd(".5") === 0.5 && parseUsd("0.00") === 0);
ok("parseUsd rejects trailing junk and exponents", isNaN(parseUsd("5abc")) && isNaN(parseUsd("1e3")) && isNaN(parseUsd("-5")) && isNaN(parseUsd("")));
ok("isIsoSince accepts ISO dates and prefixes", ["2026", "2026-10", "2026-10-01", "2026-10-01T12:00"].every(isIsoSince));
ok("isIsoSince rejects a missing or non-ISO date", [undefined, "", "yesterday", "10/01/2026", "json"].every((s) => !isIsoSince(s)));
const budgetLine = src.split("\n").find((l) => l.includes('cmd === "/budget"')) || "";
ok("/budget parses strictly and treats 0.00 as off", /const v = parseUsd\(arg\)/.test(budgetLine) && /arg === "off" \|\| v === 0/.test(budgetLine));
ok("/settings budget parses strictly", (src.match(/parseUsd\(parts\[1\]\)/g) || []).length === 2);
for (const c of ["/report", "/savings"]) {
  const line = src.split("\n").find((l) => l.includes('cmd === "' + c + '"')) || "";
  ok(c + " reads the whole argument (since <date> works)", /const parts = argstr\.split/.test(line) && !/\(arg \|\| ""\)/.test(line));
  ok(c + " since without a valid date says so", /!isIsoSince\(since\)/.test(line));
}

console.log("local-loop-audit: " + pass + " passed, " + fail + " failed");
if (fail) process.exit(1);
