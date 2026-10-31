"use strict";
// `printf '/help\n/clear\n' | nexus` must run every piped line and end at end of input.
// A readline interface per question dropped everything after the first line.
const path = require("path"), cp = require("child_process"), fs = require("fs"), os = require("os");
const { Readable } = require("stream");
const { makeLineReader } = require("../lib/cli/line-reader");

let pass = 0, fail = 0;
const ok = (name, cond) => { if (cond) pass++; else { fail++; console.log("  \x1b[31mFAIL\x1b[0m " + name); } };

(async () => {
  const r = makeLineReader(Readable.from(["a\nb\n", "c"]));
  const got = [await r.next(), await r.next(), await r.next(), await r.next(), await r.next()];
  ok("the reader returns every line in order, then null at the end", JSON.stringify(got) === JSON.stringify(["a", "b", "c", null, null]));

  const home = fs.mkdtempSync(path.join(os.tmpdir(), "nx-pipe-")), dir = fs.mkdtempSync(path.join(os.tmpdir(), "nx-pipe-cwd-"));
  const res = cp.spawnSync(process.execPath, [path.join(__dirname, "..", "darknode.js"), "nexus", "--new"], { cwd: dir, input: "/auto\n/auto\n/clear\n", encoding: "utf8", timeout: 30000, env: { ...process.env, HOME: home, NO_COLOR: "1", DARKNODE_FAST: "1" } });
  const out = res.stdout || "";
  ok("all three piped commands ran", (out.match(/auto-approve ON/g) || []).length === 1 && (out.match(/auto-approve OFF/g) || []).length === 1 && /conversation cleared/.test(out));
  ok("end of input ends the session cleanly", res.status === 0 && /stay sharp/.test(out));
  fs.rmSync(home, { recursive: true, force: true }); fs.rmSync(dir, { recursive: true, force: true });

  console.log("\n" + (fail ? "\x1b[31m" : "\x1b[32m") + pass + " passed, " + fail + " failed\x1b[0m  (piped stdin)");
  process.exit(fail ? 1 : 0);
})();
