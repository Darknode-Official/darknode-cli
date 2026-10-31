"use strict";
// command-help suite (lib/cli/command-help.js + its /help <cmd> wiring).
// Keeps the usage/examples table honest against the REAL command list parsed
// out of darknode.js, so a renamed or removed command can't leave a stale card.
const fs = require("fs"), path = require("path");
const CmdHelp = require("../lib/cli/command-help");

let pass = 0, fail = 0;
const ok = (name, cond) => { if (cond) pass++; else { fail++; console.log("  \x1b[31mFAIL\x1b[0m " + name); } };

// Real command names: the CMDS table in darknode.js is the source of truth.
const src = fs.readFileSync(path.join(__dirname, "..", "darknode.js"), "utf8");
const block = src.match(/const CMDS = \[([\s\S]*?)\n    \];/);
ok("found the CMDS table", !!block);
const menu = new Set([...block[1].matchAll(/\["(\/[a-z0-9-]+)"/g)].map((m) => m[1]));
ok("CMDS has the expected scale (>120)", menu.size > 120);
// The full command set also includes handler-dispatched commands not in the menu
// (e.g. /allow, /deny) — same union builtinNames() builds at runtime.
const names = new Set([...menu, ...[...src.matchAll(/cmd === "(\/[a-z0-9-]+)"/g)].map((m) => m[1])]);

// Every documented command is a real command.
const unknown = Object.keys(CmdHelp.HELP).filter((k) => !names.has(k));
ok("every HELP key is a real command" + (unknown.length ? " (stray: " + unknown.join(", ") + ")" : ""), unknown.length === 0);

// Every `see also` points at a real command.
const badSee = [];
for (const [k, h] of Object.entries(CmdHelp.HELP)) for (const s of (h.see || [])) if (!names.has(s)) badSee.push(k + "→" + s);
ok("every 'see also' target exists" + (badSee.length ? " (" + badSee.join(", ") + ")" : ""), badSee.length === 0);

// Every example is a runnable slash command (its own, or a sibling it references
// — e.g. /permissions shows /allow and /deny). Catches typos and non-commands.
const startsWithCmd = (e) => { const first = e.split(/\s+/)[0]; return names.has(first); };
const badEx = [];
for (const [k, h] of Object.entries(CmdHelp.HELP)) for (const e of (h.ex || [])) if (!startsWithCmd(e)) badEx.push(k + ": " + e);
ok("every example is a real slash command" + (badEx.length ? " (" + badEx.join(" | ") + ")" : ""), badEx.length === 0);

// card() renders for EVERY real command (documented or not) without throwing.
let threw = null;
for (const n of menu) { try { const c = CmdHelp.card(n, "desc here"); if (!c.includes(n)) threw = n + " (missing name)"; } catch (e) { threw = n + " (" + e.message + ")"; } }
ok("card() renders every command" + (threw ? " — failed at " + threw : ""), threw === null);

// usageLine echoes the command and is empty only when there are no args.
ok("usageLine includes the command", CmdHelp.usageLine("/loop").includes("/loop") && CmdHelp.usageLine("/loop").includes("<goal>"));
ok("usageLine is empty for an argless/unknown command", CmdHelp.usageLine("/clear") === "" && CmdHelp.usageLine("/nope") === "");

// resolve() accepts bare or slashed tokens, rejects unknowns.
ok("resolve maps a bare word to its command", CmdHelp.resolve("model", names) === "/model" && CmdHelp.resolve("/model", names) === "/model");
ok("resolve is case-insensitive and trims", CmdHelp.resolve("  MODEL ", names) === "/model");
ok("resolve returns null for an unknown token", CmdHelp.resolve("definitely-not", names) === null && CmdHelp.resolve("", names) === null);

if (fail) { console.log("command-help: " + pass + " passed, " + fail + " FAILED"); process.exit(1); }
console.log("command-help: " + pass + " passed");
