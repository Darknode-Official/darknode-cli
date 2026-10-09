#!/usr/bin/env node
// ================= benchmark self-test =================
// Proves every task is well-formed and that the scorer is honest, WITHOUT any agent or model:
//   1. seed alone must FAIL  `node test.js`  (else the task is trivially already-solved = useless)
//   2. seed + solution/ must PASS            (else the task is unsolvable / the test is wrong)
// If both hold for every task, a PASS in run.mjs genuinely means the agent fixed the code.
//   node bench/selftest.mjs
import { readdirSync, readFileSync, existsSync, mkdtempSync, cpSync, rmSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";

const HERE = dirname(fileURLToPath(import.meta.url));
const TASKS_DIR = join(HERE, "tasks");
const runTest = (cwd) => spawnSync("node", ["test.js"], { cwd, encoding: "utf8", timeout: 30000 }).status === 0;

let bad = 0, n = 0;
for (const id of readdirSync(TASKS_DIR).sort()) {
  const dir = join(TASKS_DIR, id);
  if (!existsSync(join(dir, "meta.json"))) continue;
  n++;
  // 1. seed must fail
  const w1 = mkdtempSync(join(tmpdir(), `st-${id}-seed-`));
  cpSync(join(dir, "seed"), w1, { recursive: true });
  const seedPass = runTest(w1);
  rmSync(w1, { recursive: true, force: true });
  // 2. seed + solution must pass
  const w2 = mkdtempSync(join(tmpdir(), `st-${id}-sol-`));
  cpSync(join(dir, "seed"), w2, { recursive: true });
  if (existsSync(join(dir, "solution"))) cpSync(join(dir, "solution"), w2, { recursive: true });
  const solPass = runTest(w2);
  rmSync(w2, { recursive: true, force: true });

  const ok = !seedPass && solPass;
  if (!ok) bad++;
  console.log(`  ${ok ? "ok  " : "BAD "} ${id}  (seed ${seedPass ? "PASS(!)" : "fail"}, solution ${solPass ? "pass" : "FAIL(!)"})`);
}
console.log(`\n${n - bad}/${n} tasks well-formed` + (bad ? `  — ${bad} BAD (a task must fail on seed and pass with solution)` : ""));
process.exit(bad ? 1 : 0);
