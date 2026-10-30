"use strict";
// Audit regressions: git_tool option injection via non-string args, semver precedence for the
// self-updater, grep truncation honesty + ReDoS watchdog, code_search reporting a capped index.
const fs = require("fs"), os = require("os"), path = require("path"), cp = require("child_process");
const { gitTool, buildGitCommand } = require("../lib/nexus/git-tool");
const { semverGt } = require("../lib/nexus/update");
const S = require("../lib/nexus/search");
const C = require("../lib/nexus/code-search");

let pass = 0, fail = 0;
const ok = (name, cond) => { if (cond) pass++; else { fail++; console.log("  \x1b[31mFAIL\x1b[0m " + name); } };
const group = (t) => console.log("\n\x1b[1m" + t + "\x1b[0m");
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "nx-gsa-"));

(async () => {
  try {
    group("git_tool: non-string args cannot become options");
    {
      const repo = path.join(tmp, "repo"); fs.mkdirSync(repo);
      const sh = (c) => cp.spawnSync("sh", ["-c", c], { cwd: repo, encoding: "utf8" });
      sh("git init -q && echo hi > a.txt && git add . && git -c user.email=t@t -c user.name=t commit -qm init");
      const run = (c) => { const r = sh(c); return { code: r.status, output: (r.stdout || "") + (r.stderr || "") }; };
      const canary = path.join(tmp, "canary");
      for (const a of [{ op: "diff", ref: ["--output=" + canary] }, { op: "show", ref: ["--output=" + canary] }, { op: "diff", ref: { toString: () => "--output=" + canary } }, { op: "blame", path: "a.txt", line: ["-x"] }]) {
        const r = await gitTool(a, repo, { run });
        ok(a.op + " " + JSON.stringify(a.ref || a.line) + " refused", !!r.error && /invalid git argument/.test(r.error));
      }
      ok("no canary file written", !fs.existsSync(canary));
      ok("normal ref still works", (await gitTool({ op: "show", ref: "HEAD" }, repo, { run })).op === "show");
      ok("numeric line still accepted", !buildGitCommand("blame", { path: "a.txt", line: 1 }).error);
    }

    group("semverGt");
    ok("1.10.0 > 1.9.0", semverGt("1.10.0", "1.9.0"));
    ok("release > its rc", semverGt("1.0.0", "1.0.0-rc.1"));
    ok("rc is not > release", !semverGt("1.0.0-rc.1", "1.0.0"));
    ok("rc.10 > rc.9", semverGt("1.0.0-rc.10", "1.0.0-rc.9") && !semverGt("1.0.0-rc.9", "1.0.0-rc.10"));
    ok("alpha > numeric pre-release id", semverGt("1.0.0-alpha", "1.0.0-1"));
    ok("more pre-release ids wins", semverGt("1.0.0-alpha.1", "1.0.0-alpha"));
    ok("build metadata ignored", !semverGt("1.0.0+build.5", "1.0.0"));
    ok("v prefix tolerated", semverGt("v1.2.0", "1.1.0") && !semverGt("1.1.0", "v1.2.0"));
    ok("garbage never wins", !semverGt("<html>", "1.0.0") && !semverGt("", "0.0.1") && !semverGt(undefined, "1.0.0"));
    ok("shorter numeric still works", semverGt("2.45.1", "2.45") && !semverGt("2.45", "2.45.0"));

    group("search: truncation and watchdog");
    {
      const d = path.join(tmp, "s"); fs.mkdirSync(d);
      fs.writeFileSync(path.join(d, "a.txt"), "foo\nfoo\n");
      fs.writeFileSync(path.join(d, "b.txt"), "x\r\nfoo;\r\n");
      const rp = (p) => path.resolve(d, p);
      let r = S.searchTool({ pattern: "foo", max: 2, path: "a.txt" }, d, rp);
      ok("exactly max matches is not truncated", !r.truncated && /Found 2/.test(r.summary));
      r = S.searchTool({ pattern: "foo", max: 2 }, d, rp);
      ok("more than max is truncated with max shown", !!r.truncated && /Found 2 /.test(r.summary));
      r = S.searchTool({ pattern: "foo;$" }, d, rp);
      ok("CRLF line end + line number", /b\.txt\n {2}2: foo;/.test(r.results || ""));
      ok("invalid regex falls back to literal", /not a valid regex/.test(S.searchTool({ pattern: "(" }, d, rp).summary));
      fs.writeFileSync(path.join(d, "slow.txt"), "a".repeat(5000) + "\n");
      const t0 = Date.now();
      r = S.searchTool({ pattern: "(a+)+$x" }, d, rp);
      ok("catastrophic regex is stopped, not hung (" + (Date.now() - t0) + "ms)", Date.now() - t0 < 15000 && /backtracks/.test(r.truncated || ""));
    }

    group("code_search: capped index is reported");
    {
      const d = path.join(tmp, "cs"); fs.mkdirSync(d);
      for (let i = 0; i < 4005; i++) fs.writeFileSync(path.join(d, "f" + i + ".js"), "function f" + i + "() {}\n");
      ok("capped index flagged", /partial/.test(C.codeSearchTool({ query: "zebra" }, d).truncated || ""));
      const e = path.join(tmp, "cs2"); fs.mkdirSync(e); fs.writeFileSync(path.join(e, "a.js"), "function zebra() {}\n");
      ok("small tree not flagged", !C.codeSearchTool({ query: "zebra" }, e).truncated);
    }
  } catch (e) { fail++; console.log("  \x1b[31mFAIL\x1b[0m threw: " + (e && e.stack)); }
  finally { fs.rmSync(tmp, { recursive: true, force: true }); }
  console.log("\n" + pass + " passed, " + fail + " failed");
  process.exit(fail ? 1 : 0);
})();
