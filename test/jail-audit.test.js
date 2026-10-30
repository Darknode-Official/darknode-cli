"use strict";
// Sandbox + process audit (lib/nexus/jail.js, procs.js, shell-run.js, bgjobs.js, wait-for.js):
// symlink escapes the path jail must refuse, port-ownership spoofing the fetch guard relies on,
// and that the shell runner really kills/caps what it starts.
const fs = require("fs");
const os = require("os");
const path = require("path");
const { spawn } = require("child_process");
const J = require("../lib/nexus/jail");
const P = require("../lib/nexus/procs");
const { coderShell } = require("../lib/nexus/shell-run");
const { createBgJobs } = require("../lib/nexus/bgjobs");
const { waitForTool } = require("../lib/nexus/wait-for");

let pass = 0, fail = 0;
const ok = (name, cond) => { if (cond) pass++; else { fail++; console.log("  \x1b[31mFAIL\x1b[0m " + name); } };
const group = (t) => console.log("\n\x1b[1m" + t + "\x1b[0m");
const alive = (pid) => { try { process.kill(pid, 0); return true; } catch (_) { return false; } };
const posix = process.platform !== "win32";

const T = fs.mkdtempSync(path.join(os.tmpdir(), "nx-jail-audit-"));
const R = path.join(T, "proj"), O = path.join(T, "outside");
fs.mkdirSync(path.join(R, "a", "b"), { recursive: true }); fs.mkdirSync(O); fs.mkdirSync(R + "-evil");
fs.writeFileSync(path.join(O, "secret"), "x");
const kids = [];

(async () => {
  group("path jail");
  ok("plain relative path is inside", J.resolveInJail("a/new.txt", R).inside);
  ok("../ escape refused", !J.resolveInJail("../outside/secret", R).inside);
  ok("prefix confusion (proj vs proj-evil) refused", !J.resolveInJail("../proj-evil/x", R).inside);
  ok("absolute outside path refused", !J.resolveInJail(path.join(O, "secret"), R).inside);
  let threw = false; try { J.resolveInJail("a\0b", R); } catch (_) { threw = true; } ok("NUL byte throws", threw);
  threw = false; try { J.resolveInJail("a/".repeat(3000), R); } catch (_) { threw = true; } ok("over-long path throws", threw);
  ok("~ expands to home (outside the project)", !J.resolveInJail("~/x", R, { home: O }).inside);
  ok("root '/' contains its children", J.resolveInJail("etc", "/").inside);
  if (posix) {
    fs.symlinkSync(O, path.join(R, "dirlink"));
    fs.symlinkSync(path.join(O, "secret"), path.join(R, "filelink"));
    fs.symlinkSync(path.join(O, "nope", "new"), path.join(R, "dangling"));
    fs.symlinkSync("loop2", path.join(R, "loop1")); fs.symlinkSync("loop1", path.join(R, "loop2"));
    ok("file symlink outside refused", !J.resolveInJail("filelink", R).inside);
    ok("NEW file through a symlinked dir refused", !J.resolveInJail("dirlink/brand-new.txt", R).inside);
    ok("dangling symlink pointing outside refused", !J.resolveInJail("dangling", R).inside);
    ok("symlink loop terminates", typeof J.resolveInJail("loop1/x", R).inside === "boolean");
    // a/b/l -> ..  (= a), a/dl -> ../../escape: physically T/escape, lexically a/escape.
    fs.symlinkSync("..", path.join(R, "a", "b", "l")); fs.symlinkSync("../../escape", path.join(R, "a", "dl"));
    ok("dangling link behind a symlinked parent resolves physically (refused)", !J.resolveInJail("a/b/l/dl", R).inside);
    const rl = path.join(T, "rootlink"); fs.symlinkSync(R, rl);
    ok("root that is itself a symlink still contains its files", J.resolveInJail("a/x", rl).inside && !J.resolveInJail("dirlink/x", rl).inside);
  }

  group("port ownership (fetch guard)");
  const ps = "PID PPID %CPU %MEM ELAPSED ARGS\n100 1 0 0 1:00 sh -c dev\n102 100 0 0 1:00 node srv\n200 1 0 0 1:00 postgres\n";
  ok("our job's descendant alone is ours", P.portOwnedBy(3000, [100], { ps, portLookup: () => ({ pids: new Set([102]) }) }));
  ok("shared port (ours on 127.0.0.2, theirs on 127.0.0.1) is NOT ours", !P.portOwnedBy(3000, [100], { ps, portLookup: () => ({ pids: new Set([102, 200]) }) }));
  ok("a listener with no visible pid makes it NOT ours", !P.portOwnedBy(3000, [100], { ps, portLookup: () => ({ pids: new Set([102]), unattributed: 1 }) }));
  if (process.platform === "linux") {
    const port = 46000 + Math.floor(Math.random() * 2000);
    const srv = (h) => { const c = spawn(process.execPath, ["-e", "require('http').createServer((q,r)=>r.end()).listen(" + port + ",'" + h + "')"], { detached: true, stdio: "ignore" }); kids.push(c); return c; };
    const user = srv("127.0.0.1"), job = srv("127.0.0.2");
    await new Promise((r) => setTimeout(r, 700));
    ok("live: job on 127.0.0.2 cannot claim the user's 127.0.0.1 port", !P.portOwnedBy(port, [job.pid]));
    try { process.kill(user.pid, "SIGKILL"); } catch (_) {}
    await new Promise((r) => setTimeout(r, 300));
    ok("live: once it is the only listener, the job owns it", P.portOwnedBy(port, [job.pid]));
  }

  group("shell runner");
  if (posix) {
    const pidf = path.join(T, "gc.pid");
    const r1 = await coderShell("sh -c 'echo $$ > " + pidf + "; sleep 30' ; echo done", T, { timeoutMs: 1000 });
    const gc = +fs.readFileSync(pidf, "utf8");
    await new Promise((r) => setTimeout(r, 200));
    ok("timeout reports 124 and kills the grandchild", r1.timedOut && r1.code === 124 && !alive(gc));
    const t0 = Date.now(); const r2 = await coderShell("sleep 30 & echo hi", T);
    ok("`cmd &` holding the pipe is stopped after the shell exits", Date.now() - t0 < 6000 && /hi/.test(r2.output) && r2.code === 0);
    const r3 = await coderShell("node -e \"process.stdout.write('x'.repeat(2e6))\"", T);
    ok("huge output is capped head+tail", r3.output.length < 20000 && /bytes trimmed/.test(r3.output));
    const r4 = await coderShell("printf '\\377\\376ok'", T);
    ok("non-UTF8 output does not crash", /ok/.test(r4.output));
    const r5 = await coderShell("exit 3", T); ok("immediate exit code kept", r5.code === 3);
  }

  group("background jobs + wait_for");
  {
    const jobs = createBgJobs();
    const c = spawn("sh", ["-c", "echo ready; exit 0"], { detached: posix }); kids.push(c);
    const id = jobs.start("x", c, 0); c.stdout.on("data", (d) => jobs.append(id, d)); c.on("close", (code, sig) => jobs.finish(id, code, sig));
    const w = await waitForTool({ job: id, pattern: "ready", timeout_s: 5 }, T, (p) => J.assertInJail(p, T), { jobs });
    ok("wait_for sees a job that exits immediately", w.ready === true);
    ok("stop on a finished job is a no-op (no kill of a reused pid)", jobs.stop(id) && jobs.get(id).status === "done");
    const wf = await waitForTool({ file: "../../etc/passwd", timeout_s: 1 }, T, (p) => J.assertInJail(p, T), {});
    ok("wait_for file is jailed", !!wf.error);
    const wu = await waitForTool({ url: "http://example.com/" }, T, null, {});
    ok("wait_for refuses remote URLs", !!wu.error);
  }

  for (const c of kids) { try { process.kill(posix ? -c.pid : c.pid, "SIGKILL"); } catch (_) {} }
  fs.rmSync(T, { recursive: true, force: true });
  console.log("\n" + (fail ? "\x1b[31m" : "\x1b[32m") + pass + " passed, " + fail + " failed\x1b[0m  (jail + process audit)");
  process.exit(fail ? 1 : 0);
})();
