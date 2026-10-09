#!/usr/bin/env node
// ================= Nexus coding-agent benchmark runner =================
// Runs each configured agent against each task in an ISOLATED copy of the task's seed files,
// then scores it OBJECTIVELY by running the task's own `node test.js` (exit 0 = pass). No agent
// sees another's work; nothing is scored on opinion. Metrics: pass/fail, wall-clock, files changed.
//
//   node bench/run.mjs                         # all enabled agents x all tasks
//   node bench/run.mjs --agents=nexus-local    # only these agents
//   node bench/run.mjs --tasks=fix-range,fix-csv
//   node bench/run.mjs --timeout=300           # per-task seconds cap (meta.timeout wins if smaller)
//
// Agents are command TEMPLATES in bench/agents.json; {PROMPT} is replaced with the shell-escaped
// task instruction and the command runs with cwd = the isolated workdir. The prompt is also in
// $BENCH_PROMPT. An agent "passes" a task purely by making `node test.js` exit 0.
import { readdirSync, readFileSync, existsSync, mkdtempSync, cpSync, rmSync, mkdirSync, writeFileSync, statSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { spawn, spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { createHash } from "node:crypto";

const HERE = dirname(fileURLToPath(import.meta.url));
const TASKS_DIR = join(HERE, "tasks");
const args = Object.fromEntries(process.argv.slice(2).map((a) => { const m = a.match(/^--([^=]+)=?(.*)$/); return m ? [m[1], m[2]] : [a, ""]; }));
const onlyAgents = args.agents ? args.agents.split(",").map((s) => s.trim()).filter(Boolean) : null;
const onlyTasks = args.tasks ? args.tasks.split(",").map((s) => s.trim()).filter(Boolean) : null;
const globalTimeout = args.timeout ? Number(args.timeout) : 0;

function shq(s) { return "'" + String(s).replace(/'/g, "'\\''") + "'"; }
function loadTasks() {
  const out = [];
  for (const id of readdirSync(TASKS_DIR).sort()) {
    const dir = join(TASKS_DIR, id);
    const metaPath = join(dir, "meta.json");
    if (!existsSync(metaPath)) continue;
    if (onlyTasks && !onlyTasks.includes(id)) continue;
    const meta = JSON.parse(readFileSync(metaPath, "utf8"));
    out.push({ id, dir, seed: join(dir, "seed"), prompt: meta.prompt, timeout: meta.timeout || 240 });
  }
  return out;
}
function loadAgents() {
  const p = join(HERE, "agents.json");
  const all = JSON.parse(readFileSync(p, "utf8"));
  return all.filter((a) => (a.enabled !== false) && (!onlyAgents || onlyAgents.includes(a.name)));
}
// Fingerprint every file under a dir (path -> sha1) so we can count what the agent actually changed.
function fingerprint(root) {
  const map = {};
  const walk = (d, base) => { for (const e of readdirSync(d, { withFileTypes: true })) { const abs = join(d, e.name); const rel = base ? base + "/" + e.name : e.name; if (e.isDirectory()) walk(abs, rel); else map[rel] = createHash("sha1").update(readFileSync(abs)).digest("hex"); } };
  try { walk(root, ""); } catch (_) {}
  return map;
}
function countChanged(before, after) {
  let n = 0; const keys = new Set([...Object.keys(before), ...Object.keys(after)]);
  for (const k of keys) if (before[k] !== after[k]) n++;
  return n;
}
function runAgent(cmd, cwd, prompt, timeoutSec) {
  return new Promise((resolve) => {
    const started = Date.now();
    // detached:true puts the child in its own process group so we can kill the WHOLE tree on
    // timeout (the agent spawns node -> ollama etc.; killing just `sh` leaves them running).
    const child = spawn("sh", ["-c", cmd.replaceAll("{PROMPT}", shq(prompt))], { cwd, env: { ...process.env, NO_COLOR: "1", BENCH_PROMPT: prompt }, detached: true });
    let out = ""; const cap = (b) => { if (out.length < 200000) out += b.toString(); };
    child.stdout.on("data", cap); child.stderr.on("data", cap);
    let killed = false;
    const killTree = () => { try { process.kill(-child.pid, "SIGKILL"); } catch (_) { try { child.kill("SIGKILL"); } catch (_) {} } };
    const timer = setTimeout(() => { killed = true; killTree(); }, timeoutSec * 1000);
    child.on("close", (code) => { clearTimeout(timer); resolve({ code, out, killed, seconds: (Date.now() - started) / 1000 }); });
    child.on("error", (e) => { clearTimeout(timer); resolve({ code: -1, out: out + "\nspawn error: " + e.message, killed, seconds: (Date.now() - started) / 1000 }); });
  });
}
function verify(cwd) {
  const r = spawnSync("node", ["test.js"], { cwd, encoding: "utf8", timeout: 30000 });
  return { pass: r.status === 0, output: (r.stdout || "") + (r.stderr || "") };
}

(async () => {
  const tasks = loadTasks();
  const agents = loadAgents();
  if (!agents.length) { console.error("No enabled agents matched. Edit bench/agents.json or --agents=."); process.exit(2); }
  const runId = new Date().toISOString().replace(/[:.]/g, "-");
  const outDir = join(HERE, "results", runId);
  mkdirSync(join(outDir, "logs"), { recursive: true });
  console.log(`Nexus benchmark — ${agents.length} agent(s) x ${tasks.length} task(s)\nrun: ${runId}\n`);

  const results = []; // {agent, task, pass, seconds, filesChanged, killed}
  for (const agent of agents) {
    for (const task of tasks) {
      const work = mkdtempSync(join(tmpdir(), `bench-${task.id}-`));
      cpSync(task.seed, work, { recursive: true });
      const before = fingerprint(work);
      const cap = globalTimeout ? Math.min(globalTimeout, task.timeout) : task.timeout;
      process.stdout.write(`  ${agent.name} :: ${task.id} ... `);
      const run = await runAgent(agent.cmd, work, task.prompt, cap);
      const after = fingerprint(work);
      const v = verify(work);
      const rec = { agent: agent.name, task: task.id, pass: v.pass, seconds: +run.seconds.toFixed(1), filesChanged: countChanged(before, after), killed: run.killed, exit: run.code };
      results.push(rec);
      writeFileSync(join(outDir, "logs", `${agent.name}__${task.id}.log`), `# agent stdout/stderr\n${run.out}\n\n# verify (node test.js)\nexit pass=${v.pass}\n${v.output}`);
      console.log(`${v.pass ? "PASS" : "FAIL"}  (${rec.seconds}s, ${rec.filesChanged} file(s)${run.killed ? ", TIMED OUT" : ""})`);
      try { rmSync(work, { recursive: true, force: true }); } catch (_) {}
    }
  }

  // ---- report ----
  const byAgent = {};
  for (const a of agents) byAgent[a.name] = results.filter((r) => r.agent === a.name);
  const lines = [];
  lines.push(`# Nexus coding-agent benchmark — ${runId}`, "");
  lines.push("Objective scoring: an agent passes a task only by making `node test.js` exit 0, in an isolated copy of the task. No opinion, no partial credit.", "");
  // matrix
  const header = ["task", ...agents.map((a) => a.name)];
  lines.push("| " + header.join(" | ") + " |");
  lines.push("| " + header.map(() => "---").join(" | ") + " |");
  for (const task of tasks) {
    const row = [task.id];
    for (const a of agents) { const r = results.find((x) => x.agent === a.name && x.task === task.id); row.push(r ? (r.pass ? `PASS ${r.seconds}s` : (r.killed ? "FAIL (timeout)" : "FAIL")) : "-"); }
    lines.push("| " + row.join(" | ") + " |");
  }
  lines.push("");
  lines.push("| agent | passed | pass rate | avg s (passed) |");
  lines.push("| --- | --- | --- | --- |");
  for (const a of agents) {
    const rs = byAgent[a.name]; const p = rs.filter((r) => r.pass); const avg = p.length ? (p.reduce((s, r) => s + r.seconds, 0) / p.length).toFixed(1) : "-";
    lines.push(`| ${a.name} | ${p.length}/${rs.length} | ${((p.length / rs.length) * 100).toFixed(0)}% | ${avg} |`);
  }
  const report = lines.join("\n") + "\n";
  writeFileSync(join(outDir, "report.md"), report);
  writeFileSync(join(outDir, "results.json"), JSON.stringify({ runId, agents: agents.map((a) => a.name), results }, null, 2));
  console.log("\n" + report);
  console.log(`Full report + per-run logs: ${outDir}`);
})();
