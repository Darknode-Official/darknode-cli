"use strict";
// Desktop notification suite (lib/nexus/os-notify.js): text the model wrote
// (an ask_user question) must never become AppleScript / PowerShell source.
const { osNotify } = require("../lib/nexus/os-notify");

let pass = 0, fail = 0;
const ok = (name, cond) => { if (cond) pass++; else { fail++; console.log("  \x1b[31mFAIL\x1b[0m " + name); } };

const run = (platform, title, body) => { const calls = []; osNotify(title, body, { platform, spawn: (cmd, args, o) => { calls.push({ cmd, args, o }); return { on() {} }; } }); return calls[0]; };
const evil = 'x" with title "y"\ndo shell script "touch /tmp/pwned" --';
const ps = "'; Start-Process calc; '$(whoami)";

const mac = run("darwin", "Nexus needs your answer", evil);
ok("macOS: the script source is fixed", mac.cmd === "osascript" && mac.args.slice(0, 6).join(" ") === "-e on run argv -e display notification (item 2 of argv) with title (item 1 of argv) -e end run");
ok("macOS: the text is passed as argv, not in the script", !mac.args.slice(0, 6).some((a) => a.includes("pwned")) && mac.args[7].includes("touch /tmp/pwned"));
ok("control characters (newlines) are flattened", !/[\x00-\x1f]/.test(mac.args[7]));

const win = run("win32", "t", ps);
ok("Windows: the PowerShell source never contains the text", !win.args.join(" ").includes("calc") && !win.args.join(" ").includes("whoami"));
ok("Windows: the text travels in environment variables", win.o.env.NEXUS_NOTIFY_BODY.includes("Start-Process calc") && win.o.env.NEXUS_NOTIFY_TITLE === "t");

const lin = run("linux", "-u critical", "--icon=/etc/passwd");
ok("Linux: -- stops a leading dash being read as an option", lin.cmd === "notify-send" && lin.args[0] === "--" && lin.args[1] === "-u critical");

ok("long text is capped", run("linux", "t", "z".repeat(5000)).args[2].length === 240);
let threw = false; try { osNotify("t", "b", { platform: "linux", spawn: () => { throw new Error("ENOENT"); } }); } catch (_) { threw = true; }
ok("a missing notifier never throws", !threw);

console.log("\n" + (fail ? "\x1b[31m" : "\x1b[32m") + pass + " passed, " + fail + " failed\x1b[0m  (desktop notifications)");
process.exit(fail ? 1 : 0);
