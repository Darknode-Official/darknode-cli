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

if (fail) { console.log("session-save: " + pass + " passed, " + fail + " FAILED"); process.exit(1); }
console.log("session-save: " + pass + " passed");
