#!/usr/bin/env node
"use strict";
// Mine benchmark tasks from this repo's own history: every commit that changed both
// source and tests is a real bug + fix + a test that should fail without the fix.
//
//   node eval/mine.js                         # list candidates  -> eval/mined/candidates.json
//   node eval/mine.js --validate [--limit N]  # also validate each one in a scratch copy
//   node eval/mine.js --repo ../other-repo    # mine another repo (same output layout)
//
// A task's agent-facing prompt is the commit subject's first sentence. It is marked
// reviewed:false: a human must check it describes the symptom, not the fix, before
// the task is used. Validation extracts the parent commit with `git archive` (no
// worktree, nothing written under .git), applies only the test changes and runs each
// test file on its own (must come out worse), then applies the source fix and runs
// again (must complete cleanly). That second run is the reference gradeDir() compares
// an agent's attempt against.
//
// Grading reads the output format the test files already print ("FAIL <name>" lines and
// an "N passed, M failed" summary) rather than a new reporter, because the mined base
// commits predate any reporter added now. A file that never prints its summary crashed
// or hung, and counts as failed: one crash must not hide the tests after it.
const fs = require("fs"), os = require("os"), path = require("path"), cp = require("child_process");

const ROOT = path.join(__dirname, "..");
const FIXLIKE = /(fix|bug|wrong|was |were |missed|broke|crash|threw|instead of|no longer|never )/i;
const isTest = (f) => /(^|\/)tests?\//.test(f) || /\.test\.(c|m)?[jt]s$/.test(f);
const isSrc = (f) => /\.(c|m)?[jt]s$|\.py$/.test(f) && !isTest(f);

// git that fails loudly: a git error must never read as "no commits" (it did once).
function git(repo, args, opts) {
  const r = cp.spawnSync("git", ["-C", repo].concat(args), Object.assign({ encoding: "utf8", maxBuffer: 256 << 20 }, opts));
  if (r.status !== 0) throw new Error("git " + args.join(" ") + " failed: " + (r.stderr || r.error || "exit " + r.status));
  return r.stdout;
}

// Pure: parse `git log --format=%x00%H%x09%P%x09%ad%x09%s --name-only` into commits.
function parseLog(text) {
  const out = [];
  for (const chunk of String(text).split("\0").slice(1)) {
    const lines = chunk.split("\n");
    const [hash, parents, date, ...subj] = lines[0].split("\t");
    out.push({ hash, parents: parents ? parents.split(" ") : [], date, subject: subj.join("\t"), files: lines.slice(1).filter(Boolean) });
  }
  return out;
}

// Pure: the agent-facing prompt. First sentence of the subject: our commit style puts
// the symptom first and the fix after, but that is a convention, not a guarantee.
function promptFrom(subject) {
  const m = String(subject).match(/^(.+?[.!?])(\s|$)/);
  return (m ? m[1] : String(subject)).trim();
}

// Pure: commits worth turning into tasks.
function candidates(commits) {
  return commits.filter((c) => c.parents.length === 1 && c.files.some(isTest) && c.files.some(isSrc))
    .map((c) => ({ ...c, kind: FIXLIKE.test(c.subject) ? "fix" : "feature" }));
}

// Pure: the test commands of a package.json "test" script ("node a && node b").
function suiteFromScript(script) {
  return String(script || "").split("&&").map((s) => s.trim()).filter((s) => /^node\s+\S+/.test(s));
}

const ANSI = /\x1b\[[0-9;]*m/g;
// Pure: parse one test file's output -> { completed, pass, fails[] }.
function parseRun(output) {
  const text = String(output).replace(ANSI, "");
  const fails = [];
  for (const line of text.split(/\r?\n/)) { const m = line.match(/^\s*FAIL\s+(.+?)\s*$/); if (m) fails.push(m[1]); }
  const sums = [...text.matchAll(/(\d+) passed, (\d+) failed/g)];
  const last = sums[sums.length - 1];
  return { completed: !!last, pass: last ? +last[1] : 0, fails };
}

// Pure: is an attempt at least as good as the reference? Every file must complete,
// fail nothing the reference didn't, and pass at least as many tests.
function judge(attempt, reference) {
  const why = [];
  for (const cmd of Object.keys(reference)) {
    const a = attempt[cmd], r = reference[cmd];
    if (!a || !a.completed) { why.push(cmd + ": did not complete"); continue; }
    const extra = a.fails.filter((f) => !r.fails.includes(f));
    if (extra.length) why.push(cmd + ": " + extra.length + " test(s) failing, e.g. " + extra[0].slice(0, 120));
    if (a.pass < r.pass) why.push(cmd + ": " + a.pass + " passed, reference " + r.pass);
  }
  return { pass: why.length === 0, why };
}

// Run each suite command in `dir` with an isolated HOME (tests must never touch the
// real ~/.nexus). Returns { cmd: parseRun(...) }.
function runSuite(dir, suite, timeoutS) {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "nxmine-home-"));
  const res = {};
  try {
    for (const cmd of suite) {
      const r = cp.spawnSync("sh", ["-c", cmd], { cwd: dir, encoding: "utf8", timeout: (timeoutS || 300) * 1000, maxBuffer: 64 << 20,
        env: Object.assign({}, process.env, { HOME: home, NO_COLOR: "1", CI: "1" }) });
      res[cmd] = parseRun((r.stdout || "") + "\n" + (r.stderr || ""));
    }
  } finally { fs.rmSync(home, { recursive: true, force: true }); }
  return res;
}

function gradeDir(task, dir) { return judge(runSuite(dir, task.suite, task.timeoutS), task.reference); }

function extract(repo, rev, dir) {
  fs.mkdirSync(dir, { recursive: true });
  const tar = cp.spawnSync("git", ["-C", repo, "archive", "--format=tar", rev], { maxBuffer: 1 << 30 });
  if (tar.status !== 0) throw new Error("git archive " + rev + " failed: " + tar.stderr);
  const x = cp.spawnSync("tar", ["-x", "-C", dir], { input: tar.stdout });
  if (x.status !== 0) throw new Error("tar -x failed: " + x.stderr);
}

function applyPatch(dir, patch) {
  if (!patch.trim()) return true;
  return cp.spawnSync("git", ["apply", "--whitespace=nowarn"], { cwd: dir, input: patch }).status === 0;
}

// Validate one candidate; returns the task record (valid true/false + reason).
function validate(repo, c, opts) {
  const base = c.parents[0];
  const pkg = JSON.parse(git(repo, ["show", base + ":package.json"]).replace(/^﻿/, ""));
  const suite = suiteFromScript(pkg.scripts && pkg.scripts.test);
  const tests = c.files.filter(isTest), srcs = c.files.filter((f) => !isTest(f));
  const testPatch = git(repo, ["diff", "--binary", base, c.hash, "--"].concat(tests));
  const srcPatch = git(repo, ["diff", "--binary", base, c.hash, "--"].concat(srcs));
  const task = { id: path.basename(repo) + "-" + c.hash.slice(0, 8), repo: path.basename(repo), base, commit: c.hash, date: c.date,
    kind: c.kind, prompt: promptFrom(c.subject), reviewed: false, suite, timeoutS: opts.timeoutS || 300,
    hiddenTestFiles: tests, testPatch, valid: false, reason: "" };
  if (!suite.length) { task.reason = "no node test commands in package.json at base"; return task; }
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "nxmine-"));
  try {
    extract(repo, base, dir);
    if (!applyPatch(dir, testPatch)) { task.reason = "test patch does not apply to base"; return task; }
    const before = runSuite(dir, suite, task.timeoutS);
    if (!applyPatch(dir, srcPatch)) { task.reason = "source patch does not apply"; return task; }
    const ref = runSuite(dir, suite, task.timeoutS);
    const refBad = Object.entries(ref).find(([, r]) => !r.completed);
    if (refBad) { task.reason = "reference run did not complete: " + refBad[0]; return task; }
    if (judge(before, ref).pass) { task.reason = "hidden tests already pass without the fix"; return task; }
    task.reference = ref; task.valid = true; task.reason = "ok";
    return task;
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
}

function main(argv) {
  const o = { repo: ROOT, validate: false, limit: Infinity, kind: "fix", out: path.join(__dirname, "mined"), timeoutS: 300 };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--repo") o.repo = path.resolve(argv[++i]);
    else if (a === "--validate") o.validate = true;
    else if (a === "--limit") o.limit = Math.max(1, parseInt(argv[++i], 10) || 1);
    else if (a === "--kind") o.kind = argv[++i]; // fix | feature | all
    else if (a === "--out") o.out = path.resolve(argv[++i]);
    else if (a === "--timeout") o.timeoutS = Math.max(10, parseInt(argv[++i], 10) || 300);
  }
  const branch = git(o.repo, ["rev-parse", "--abbrev-ref", "HEAD"]).trim();
  const log = git(o.repo, ["log", "--format=%x00%H%x09%P%x09%ad%x09%s", "--date=short", "--name-only", "HEAD"]);
  const commits = parseLog(log);
  if (!commits.length) throw new Error("no commits parsed from " + o.repo + " - treat as an error, not as zero tasks");
  const cands = candidates(commits).filter((c) => o.kind === "all" || c.kind === o.kind);
  fs.mkdirSync(o.out, { recursive: true });
  const summary = { repo: path.basename(o.repo), branch, commits: commits.length, candidates: cands.length, minedAt: new Date().toISOString() };
  fs.writeFileSync(path.join(o.out, summary.repo + "-candidates.json"),
    JSON.stringify(Object.assign({}, summary, { list: cands.map((c) => ({ hash: c.hash, date: c.date, kind: c.kind, subject: c.subject })) }), null, 1) + "\n");
  console.log(summary.repo + " (" + branch + "): " + commits.length + " commits, " + cands.length + " " + o.kind + " candidates");
  if (!o.validate) return;
  const tdir = path.join(o.out, "tasks");
  fs.mkdirSync(tdir, { recursive: true });
  const tally = {};
  for (const c of cands.slice(0, o.limit)) {
    let t;
    try { t = validate(o.repo, c, o); } catch (e) { t = { id: c.hash.slice(0, 8), valid: false, reason: "error: " + e.message.split("\n")[0] }; }
    tally[t.valid ? "valid" : t.reason.replace(/:.*$/, "")] = (tally[t.valid ? "valid" : t.reason.replace(/:.*$/, "")] || 0) + 1;
    if (t.valid) fs.writeFileSync(path.join(tdir, t.id + ".json"), JSON.stringify(t, null, 1) + "\n");
    console.log((t.valid ? "  ok   " : "  skip ") + c.hash.slice(0, 8) + "  " + t.reason);
  }
  console.log(JSON.stringify(tally));
}

if (require.main === module) {
  try { main(process.argv.slice(2)); } catch (e) { console.error("mine: " + e.message); process.exit(1); }
}

module.exports = { parseLog, promptFrom, candidates, suiteFromScript, parseRun, judge, runSuite, gradeDir, isTest, isSrc };
