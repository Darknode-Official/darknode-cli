"use strict";
// Dev-helper audit (lib/nexus glob, invariants, code-review, attest, explainbreak, lint-format,
// code-review-auto): glob escapes, diff parsing of deleted files and "++"/"--" body lines, audit
// manifests that must see every write/exec tool, failure-path extraction, and file names that
// look like String.replace patterns. Git fixtures live in a temp dir.
const fs = require("fs");
const os = require("os");
const path = require("path");
const cp = require("child_process");
const { globToRe } = require("../lib/nexus/glob");
const { parseDiff } = require("../lib/nexus/invariants");
const { rightLines } = require("../lib/nexus/code-review");
const { buildManifest, checkClaims } = require("../lib/nexus/attest");
const { extractRefs } = require("../lib/nexus/explainbreak");
const { buildPlan, detectLangs, shq } = require("../lib/nexus/lint-format");
const { autoReview } = require("../lib/nexus/code-review-auto");

let pass = 0, fail = 0;
const ok = (name, cond) => { if (cond) pass++; else { fail++; console.log("  \x1b[31mFAIL\x1b[0m " + name); } };
const group = (t) => console.log("\n\x1b[1m" + t + "\x1b[0m");

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "nx-devhelpers-"));
const git = (dir, args) => cp.execFileSync("git", ["-c", "user.email=t@t", "-c", "user.name=t", "-c", "commit.gpgsign=false"].concat(args), { cwd: dir, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] });
const repo = (name) => { const d = path.join(tmp, name); fs.mkdirSync(d); git(d, ["init", "-q"]); return d; };

group("glob");
ok("glob: \\[id\\] matches the literal Next.js folder", globToRe("app/\\[id\\]/page.tsx").test("app/[id]/page.tsx"));
ok("glob: \\[id\\] is not a character class", !globToRe("app/\\[id\\]/page.tsx").test("app/i/page.tsx"));
ok("glob: \\* is a literal star", globToRe("\\*.js").test("*.js") && !globToRe("\\*.js").test("a.js"));
ok("glob: escaped ] inside a class is a member", globToRe("[a\\]].txt").test("].txt") && globToRe("[a\\]].txt").test("a.txt"));
ok("glob: escaped - inside a class is not a range", !globToRe("[a\\-c]").test("b") && globToRe("[a\\-c]").test("-"));
ok("glob: [!]a] excludes ]", globToRe("[!]a]").test("b") && !globToRe("[!]a]").test("]"));
ok("glob: unescaped class + braces still work", globToRe("app/[id]/page.tsx").test("app/d/page.tsx") && globToRe("**/*.{js,ts}").test("x/a.ts"));

group("invariants diff parsing");
{
  const d = repo("inv");
  fs.writeFileSync(path.join(d, "q.sql"), "select 1;\n-- drop table x\n");
  git(d, ["add", "."]); git(d, ["commit", "-qm", "i"]); git(d, ["rm", "-q", "q.sql"]);
  const files = parseDiff(git(d, ["diff", "HEAD"]));
  ok("deleted file whose line starts with '-- ' keeps its path (noDelete can see it)", files.length === 1 && files[0].path === "q.sql" && files[0].status === "D");
  ok("that '-- ' line is a removed line", files[0] && files[0].removed.includes("-- drop table x"));
}

group("code-review rightLines");
{
  const d = repo("cr");
  fs.writeFileSync(path.join(d, "a.c"), "int a;\n");
  git(d, ["add", "."]); git(d, ["commit", "-qm", "i"]);
  fs.writeFileSync(path.join(d, "a.c"), "int a;\n++i;\nint b;\n");
  const rl = rightLines(git(d, ["diff"]));
  ok("an added '++i;' line is counted (no off-by-one after it)", rl["a.c"] && [...rl["a.c"]].join(",") === "1,2,3");
}

group("attest");
{
  const m = buildManifest([
    { seq: 0, tool: "verify", cmd: "rm -rf build", status: "ok" },
    { seq: 1, tool: "lint_format", cmd: "npx prettier --write .", status: "ok" },
    { seq: 2, tool: "notebook_edit", path: "secret/x.ipynb", status: "ok" },
    { seq: 3, tool: "undo_edit", path: "other/y.js", status: "ok" },
  ]);
  ok("commands run through verify/lint_format are in the manifest", m.commands.length === 2);
  ok("noCommands fails on an rm run via verify", !checkClaims(m, { noCommands: ["rm -rf"] }).ok);
  ok("notebook_edit / undo_edit count as writes", m.writes.includes("secret/x.ipynb") && m.writes.includes("other/y.js"));
  ok("onlyPaths fails on a notebook edit outside the allowed paths", !checkClaims(m, { onlyPaths: ["src/**"] }).ok);
}

group("explainbreak");
{
  const p = extractRefs("Error in src/App.tsx:12:3 and config.json and lib/x.cpp:5").paths;
  ok("App.tsx is not truncated to App.ts, and keeps its line", p.some((x) => x.path === "src/App.tsx" && x.line === 12));
  ok("config.json is not read as config.js", p.some((x) => x.path === "config.json") && !p.some((x) => x.path === "config.js"));
  ok("x.cpp is not read as x.c", p.some((x) => x.path === "lib/x.cpp" && x.line === 5));
}

group("lint-format");
{
  const cmd = buildPlan(detectLangs(["go.mod"]), { target: shq("a$&b.go") })[0].cmd;
  ok("a '$&' in the file name stays literal", cmd === "gofmt -w 'a$&b.go'");
}

group("code-review-auto");
{
  const d = repo("cra");
  fs.writeFileSync(path.join(d, "README"), "x\n"); fs.writeFileSync(path.join(d, "a.js"), "let a = 1;\n");
  git(d, ["add", "."]); git(d, ["commit", "-qm", "i"]);
  fs.appendFileSync(path.join(d, "README"), "y\n"); git(d, ["add", "README"]);
  fs.appendFileSync(path.join(d, "a.js"), "eval(y)\n");
  ok("only a README staged: unstaged source changes are still reviewed", /a\.js/.test(autoReview("", d)) && /SEC002/.test(autoReview("", d)));
}

try { fs.rmSync(tmp, { recursive: true, force: true }); } catch (_) {}
console.log("\n" + (fail ? "\x1b[31m" : "\x1b[32m") + pass + " passed, " + fail + " failed\x1b[0m  (dev-helpers audit)");
process.exit(fail ? 1 : 0);
