"use strict";
// Code-intel / radar audit (lib/nexus pipelines, code-radar, repo-map, codestats, smart-test,
// ctf-helper, project-bootstrap, git-security): shell-free pipeline argv, symlink-loop and
// over-broad ignore in the radar walk, quadratic/exponential regexes, inherited-key lookups
// ("constructor" as an extension/template/category), and generated Python tests that must parse.
const fs = require("fs");
const os = require("os");
const path = require("path");
const cp = require("child_process");

let pass = 0, fail = 0;
const ok = (name, cond) => { if (cond) pass++; else { fail++; console.log("  \x1b[31mFAIL\x1b[0m " + name); } };
const group = (t) => console.log("\n\x1b[1m" + t + "\x1b[0m");
const ms = (f) => { const t = Date.now(); f(); return Date.now() - t; };

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "nx-radar-"));

group("pipelines (no shell)");
{
  // fake engine: records its argv as JSON
  const cli = path.join(tmp, "fake-engine");
  fs.writeFileSync(cli, "#!" + process.execPath + "\nprocess.stdout.write(JSON.stringify(process.argv.slice(2)));\n");
  fs.chmodSync(cli, 0o755);
  const pwned = path.join(tmp, "pwned");
  const prev = process.env.NEXUS_PIPELINE_CLI;
  process.env.NEXUS_PIPELINE_CLI = cli;
  delete require.cache[require.resolve("../lib/nexus/pipelines")];
  const P = require("../lib/nexus/pipelines");
  if (prev == null) delete process.env.NEXUS_PIPELINE_CLI; else process.env.NEXUS_PIPELINE_CLI = prev;
  const val = "$(touch " + pwned + ")";
  let out = null; try { out = JSON.parse(P.pipelineRun("build", tmp, { msg: val, "bad key!": "`id`" }, { model: "m1", dryRun: true })); } catch (_) {}
  ok("pipelineRun: --var $(...) is not executed", !fs.existsSync(pwned));
  ok("pipelineRun: --var value reaches the engine verbatim", out && out.join(" ") === "pipeline run build --model m1 --dry-run --var msg=" + val + " --var badkey=`id`");
  const bt = "`touch " + pwned + "2`";
  try { out = JSON.parse(P.pipelineNew("p1", tmp, { description: "a \"q\" " + bt, type: "t" })); } catch (_) { out = null; }
  ok("pipelineNew: backticks in --description are not executed", !fs.existsSync(pwned + "2"));
  ok("pipelineNew: description passed as one argv entry", out && out[3] === "--description" && out[4] === "a \"q\" " + bt);
  try { out = JSON.parse(P.pipelineStatus(tmp)); } catch (_) { out = null; }
  ok("pipelineStatus: no runId -> no empty arg", out && out.length === 2);
  try { out = JSON.parse(P.gapsAdd(tmp, { title: "x; touch " + pwned + "3" })); } catch (_) { out = null; }
  ok("gapsAdd: --title not shell-parsed", !fs.existsSync(pwned + "3") && out && out[3] === "x; touch " + pwned + "3");
  ok("hasEngine: finds the binary by path", P.hasEngine() === true);
}

group("code-radar walk");
{
  const d = path.join(tmp, "radar");
  fs.mkdirSync(path.join(d, "src"), { recursive: true });
  fs.writeFileSync(path.join(d, "src", "a.js"), "function f(){}\n");
  fs.writeFileSync(path.join(d, "src", "distance.js"), "function g(){}\n");
  fs.writeFileSync(path.join(d, "rebuild.py"), "x = 1\n");
  fs.mkdirSync(path.join(d, "build")); fs.writeFileSync(path.join(d, "build", "out.js"), "var o\n");
  fs.symlinkSync("..", path.join(d, "src", "up"));
  fs.symlinkSync(".", path.join(d, "src", "self"));
  const r = cp.spawnSync(process.execPath, ["-e", "process.stdout.write(require(" + JSON.stringify(path.join(__dirname, "..", "lib", "nexus", "code-radar")) + ").scanProject(" + JSON.stringify(d) + "))"], { encoding: "utf8", timeout: 15000 });
  ok("radar: symlinked dirs (up -> .., self -> .) do not loop the walk", r.status === 0);
  ok("radar: counts rebuild.py / distance.js, still skips build/", /Files: 3\b/.test(r.stdout || ""));
}

group("repo-map");
{
  const rm = require("../lib/nexus/repo-map");
  ok("mentionsOf: 40 KB identifier run is linear", ms(() => rm.mentionsOf("a".repeat(40000))) < 600);
  ok("mentionsOf: still finds paths", rm.mentionsOf("see lib/nexus/repo-map.js and src/x").paths.has("lib/nexus/repo-map.js"));
  const map = rm.buildRepoMap([{ path: "a.constructor", content: "x" }, { path: "b.js", content: "function f(){}\n" }]);
  ok("buildRepoMap: x.constructor is not a language", Object.keys(map.languages).join() === "js");
}

group("codestats");
{
  const { langOf, summarizeStats } = require("../lib/nexus/codestats");
  ok("langOf: x.constructor / x.toString -> null", langOf("x.constructor") === null && langOf("y.toString") === null);
  ok("langOf: still maps .ts", langOf("a.ts") === "TypeScript");
  ok("summarizeStats: inherited-name files not counted", summarizeStats([{ file: "x.constructor", lines: 3, lang: langOf("x.constructor") }]).totalFiles === 0);
}

group("smart-test");
{
  const { generateTests } = require("../lib/nexus/smart-test");
  const d = path.join(tmp, "st"); fs.mkdirSync(d);
  fs.writeFileSync(path.join(d, "m.py"), "def run(callback, enabled, title, count):\n    return 1\n");
  generateTests("m.py", d);
  const py = fs.readFileSync(path.join(d, "m_test.py"), "utf8");
  ok("python tests: no JS literals (=>, true, .repeat, NaN)", !py.split("\n").filter((l) => !/"""/.test(l)).some((l) => /=>|\btrue\b|\.repeat\(|\bNaN\b/.test(l)));
  const hasPy = cp.spawnSync("python3", ["--version"]).status === 0;
  if (hasPy) ok("python tests: file parses", cp.spawnSync("python3", ["-c", "import ast,sys;ast.parse(open(sys.argv[1]).read())", path.join(d, "m_test.py")]).status === 0);
  fs.writeFileSync(path.join(d, "q.js"), "function asyncQueue(items) {\n  return items;\n}\n");
  generateTests("q.js", d);
  const js = fs.readFileSync(path.join(d, "q.test.js"), "utf8");
  ok("js tests: a sync fn named asyncQueue is not treated as async", !/await|async \(\)/.test(js));
  fs.writeFileSync(path.join(d, "r.js"), "export async function load(path) {\n  return path;\n}\nconst go = async (x) => x;\n");
  generateTests("r.js", d);
  ok("js tests: real async fns still awaited", /await load\(/.test(fs.readFileSync(path.join(d, "r.test.js"), "utf8")));
}

group("ctf-helper");
{
  const c = require("../lib/nexus/ctf-helper");
  ok("detectCiphers: octal check is not exponential", ms(() => c.detectCiphers("0".repeat(64) + " 1")) < 300);
  const oct = (s) => c.detectCiphers(s).some((h) => /octal/i.test(h.name));
  ok("detectCiphers: octal still detected", oct("110 145 154 154 157") && oct("110145154"));
  ok("detectCiphers: a lone single digit is not octal", !oct("110 145 1"));
  let r = null; try { r = c.suggestApproach("constructor"); } catch (_) {}
  ok("suggestApproach('constructor') does not crash", r && Array.isArray(r.recommendedSteps));
}

group("project-bootstrap");
{
  const { bootstrap } = require("../lib/nexus/project-bootstrap");
  let r = null; try { r = bootstrap("constructor", path.join(tmp, "bs")); } catch (_) {}
  ok("bootstrap('constructor') -> unknown template, no crash", /Unknown template/.test(r || ""));
}

group("git-security");
{
  const gs = require("../lib/nexus/git-security");
  const pat = gs.SECRET_PATTERNS.find((p) => p.id === "npm-token").regex;
  ok("npm-token: npm_package_* env names are not tokens", !pat.test("echo $npm_package_devDependencies_eslint_plugin_react"));
  ok("npm-token: real-format token detected", pat.test("token=" + "npm_" + "aB3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY3zA5"));
  ok("npm-token: .npmrc authToken detected", pat.test("//registry.npmjs.org/:_authToken=" + "0123456789abcdef0123456789abcdef0123"));
}

try { fs.rmSync(tmp, { recursive: true, force: true }); } catch (_) {}
console.log("\n" + (fail ? "\x1b[31m" : "\x1b[32m") + pass + " passed, " + fail + " failed\x1b[0m  (radar audit)");
process.exit(fail ? 1 : 0);
