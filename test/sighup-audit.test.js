"use strict";
// Closing the terminal (SIGHUP) must not end in process.exit(): Node then resets the dead tty
// and aborts on a failed assertion, leaving a core dump / crash report for every closed window.
const fs = require("fs"), path = require("path"), cp = require("child_process");

let pass = 0, fail = 0;
const ok = (name, cond) => { if (cond) pass++; else { fail++; console.log("  \x1b[31mFAIL\x1b[0m " + name); } };

const src = fs.readFileSync(path.join(__dirname, "..", "darknode.js"), "utf8");
const hup = (src.match(/const onHup = \(\) => \{[^\n]*/) || [""])[0];
ok("the TUI has a named SIGHUP handler", /process\.on\("SIGHUP", onHup\)/.test(src));
ok("it cleans up, then ends by SIGKILL", /cleanup\(\)/.test(hup) && /process\.kill\(process\.pid, "SIGKILL"\)/.test(hup));
ok("cleanup removes the SIGHUP listener", /process\.removeListener\("SIGHUP", onHup\)/.test(src));
ok("no SIGHUP path calls process.exit(129) directly", !/"SIGHUP", \(\) => \{[^}]*process\.exit\(129\)/.test(src));

// The mechanism itself: SIGKILL after a SIGHUP leaves no native abort on stderr.
if (process.platform !== "win32") {
  const r = cp.spawnSync(process.execPath, ["-e", 'process.on("SIGHUP", () => process.kill(process.pid, "SIGKILL")); process.kill(process.pid, "SIGHUP"); setTimeout(() => {}, 2000);'], { encoding: "utf8" });
  ok("a SIGHUP handled this way ends by SIGKILL with nothing on stderr", r.signal === "SIGKILL" && !/Assertion failed/.test(r.stderr || ""));
}

console.log("\n" + (fail ? "\x1b[31m" : "\x1b[32m") + pass + " passed, " + fail + " failed\x1b[0m  (sighup)");
process.exit(fail ? 1 : 0);
