#!/usr/bin/env node
"use strict";
// NX-008 — Nexus evaluation harness. Runnable by a third party from eval/README.md.
//
//   node eval/harness.js --dry                 # exercise the pipeline, no model
//   node eval/harness.js --engine ollama       # real run against an engine
//   node eval/harness.js --seeds 5 --task <id>  # N seeds of one task (variance)
//   node eval/harness.js --final                # the held-out set — USE ONCE
//
// It loads the DEVELOPMENT task set (eval/tasks/), builds an isolated sandbox per
// task, runs the agent (headless `darknode nexus run --print`, or a no-model stub
// under --dry), scores deterministically (eval/score.js), records cost / latency /
// tokens per seed, aggregates mean+variance across seeds, and writes
// eval/results/<timestamp>.json. It refuses to read eval/held-out/ unless --final.
const fs = require("fs"), os = require("os"), path = require("path"), cp = require("child_process");
const { scoreRun, aggregate } = require("./score");

const ROOT = path.join(__dirname, "..");
const DEV_DIR = path.join(__dirname, "tasks");
const HELD_DIR = path.join(__dirname, "held-out");
const RESULTS = path.join(__dirname, "results");

function parseArgs(argv) {
  const o = { dry: false, seeds: 1, task: null, engine: "ollama", final: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--dry") o.dry = true;
    else if (a === "--final") o.final = true;
    else if (a === "--seeds") o.seeds = Math.max(1, parseInt(argv[++i], 10) || 1);
    else if (a === "--task") o.task = argv[++i];
    else if (a === "--engine") o.engine = argv[++i];
  }
  return o;
}

function loadTasks(dir) {
  if (!fs.existsSync(dir)) return [];
  return fs.readdirSync(dir).filter((f) => f.endsWith(".json")).map((f) => {
    const t = JSON.parse(fs.readFileSync(path.join(dir, f), "utf8"));
    t._file = f;
    return t;
  });
}

// Every task must declare provenance + a contamination argument, or it is excluded
// (the brief: "Unknown contamination status excludes the task").
function admissible(t) {
  return !!(t && t.id && t.axis && t.type && t.prompt && t.provenance && t.contamination && (t.verify || t.type === "finding"));
}

function sandbox() { return fs.mkdtempSync(path.join(os.tmpdir(), "nexus-eval-")); }
function sh(cmd, cwd, timeoutMs) {
  const r = cp.spawnSync("bash", ["-lc", cmd], { cwd, encoding: "utf8", timeout: timeoutMs || 120000 });
  return { code: r.status === null ? 124 : r.status, out: (r.stdout || "") + (r.stderr || "") };
}

// One seeded run of one task. Returns { seed, score, metrics }.
function runOnce(task, seed, opts) {
  const dir = sandbox();
  try {
    if (task.setup) sh(task.setup, dir);
    const t0 = Date.now();
    let agentOut = "", metrics = { latencyMs: 0, tokens: 0, costUsd: 0 };
    if (!opts.dry) {
      // Real agent run: headless, single engine, seeded via env for reproducibility.
      const r = cp.spawnSync(process.execPath, [path.join(ROOT, "darknode.js"), "nexus", "run", task.prompt, "-e", opts.engine, "--print", "-y"],
        { cwd: dir, encoding: "utf8", timeout: task.timeoutMs || 600000, env: Object.assign({}, process.env, { NEXUS_SEED: String(seed) }) });
      agentOut = (r.stdout || "") + (r.stderr || "");
      // Best-effort usage parse from the per-run ledger the agent writes.
      try {
        const led = path.join(dir, ".nexus", "usage.jsonl");
        if (fs.existsSync(led)) for (const line of fs.readFileSync(led, "utf8").split("\n").filter(Boolean)) {
          const u = JSON.parse(line); metrics.tokens += (u.inTok || 0) + (u.outTok || 0); metrics.costUsd += (u.costUsd || 0);
        }
      } catch (_) {}
    }
    metrics.latencyMs = Date.now() - t0;
    let verify;
    if (task.type === "finding") {
      // The agent is asked to print "<kind>:<path>" lines; parse them as findings.
      const findings = agentOut.split("\n").map((l) => l.trim()).filter((l) => /^[\w-]+:\S+$/.test(l));
      verify = { findings };
    } else {
      verify = sh(task.verify, dir, task.timeoutMs);
    }
    return { seed, score: scoreRun(task, verify), metrics };
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

function main() {
  const opts = parseArgs(process.argv.slice(2));
  const dir = opts.final ? HELD_DIR : DEV_DIR;
  if (opts.final) console.error("!! Reading the HELD-OUT set. Per NX-008 this invalidates it for future comparison. Use once, at the end.");
  let tasks = loadTasks(dir).filter(admissible);
  if (opts.task) tasks = tasks.filter((t) => t.id === opts.task);
  if (!tasks.length) { console.error("no admissible tasks in " + dir + " (each needs id/axis/type/prompt/provenance/contamination/verify)"); process.exit(1); }

  const report = { startedAt: new Date().toISOString(), dry: opts.dry, engine: opts.dry ? null : opts.engine, seeds: opts.seeds, set: opts.final ? "held-out" : "dev", tasks: [] };
  for (const task of tasks) {
    const runs = [];
    for (let s = 1; s <= opts.seeds; s++) runs.push(runOnce(task, s, opts));
    const agg = aggregate(runs);
    report.tasks.push({ id: task.id, axis: task.axis, type: task.type, runs, aggregate: agg });
    const pct = (agg.passRate * 100).toFixed(0);
    console.log(`${task.id.padEnd(28)} ${task.axis.padEnd(26)} pass ${pct}% (n=${agg.n})  cost~$${agg.cost.mean.toFixed(4)}  ${Math.round(agg.latencyMs.mean)}ms` + (agg.findings ? `  FPR ${(agg.findings.falsePositiveRate * 100).toFixed(0)}%` : ""));
  }
  report.finishedAt = new Date().toISOString();
  fs.mkdirSync(RESULTS, { recursive: true });
  const out = path.join(RESULTS, report.startedAt.replace(/[:.]/g, "-") + (opts.dry ? "-dry" : "") + ".json");
  fs.writeFileSync(out, JSON.stringify(report, null, 2) + "\n");
  console.log("\nwrote " + path.relative(ROOT, out));
  if (opts.dry) console.log("NOTE: --dry exercises load+score+aggregate+output only. A real baseline requires an engine and is NOT produced here.");
}

if (require.main === module) main();
module.exports = { parseArgs, loadTasks, admissible, runOnce };
