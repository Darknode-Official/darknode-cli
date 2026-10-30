"use strict";
// Pipeline-engine integration — exposes an external multi-stage run orchestrator
// through Nexus slash commands. Pure wrappers + formatters; the TUI wires these
// into /pipeline. The engine is opt-in: set NEXUS_PIPELINE_CLI to the orchestrator
// binary on your PATH. When it is unset the integration stays inert (no engine).
const { execFileSync, spawn } = require("child_process");

const CLI = process.env.NEXUS_PIPELINE_CLI || "";

function hasEngine() {
  if (!CLI) return false;
  try { execFileSync("which", [CLI], { encoding: "utf8", timeout: 3000, stdio: ["ignore", "pipe", "ignore"] }); return true; }
  catch (_) { return false; }
}

// args is an argv array (no shell), so names/values are never re-parsed or expanded.
function run(args, cwd, timeout) {
  if (!CLI) return "";
  try {
    return execFileSync(CLI, args.filter((a) => a !== "" && a != null).map(String), {
      cwd, encoding: "utf8", timeout: timeout || 15000,
      env: Object.assign({}, process.env, { NO_COLOR: "1", FORCE_COLOR: "0" }),
    }).trim();
  } catch (e) {
    const out = (e.stdout || "").toString().trim() || (e.stderr || "").toString().trim() || e.message;
    return out;
  }
}

function pipelineList(cwd) {
  return run(["pipeline", "list"], cwd);
}

function pipelineRun(name, cwd, vars, opts) {
  const cmd = ["pipeline", "run", name];
  if (opts && opts.headless) cmd.push("--headless");
  if (opts && opts.model) cmd.push("--model", opts.model);
  if (opts && opts.provider) cmd.push("--provider", opts.provider);
  if (opts && opts.from) cmd.push("--from", opts.from);
  if (opts && opts.to) cmd.push("--to", opts.to);
  if (opts && opts.pause) cmd.push("--pause");
  if (opts && opts.dryRun) cmd.push("--dry-run");
  if (vars) for (const [k, v] of Object.entries(vars)) { const safeK = String(k).replace(/[^a-zA-Z0-9_]/g, ""); if (safeK) cmd.push("--var", safeK + "=" + String(v)); }
  return run(cmd, cwd, 300000);
}

function pipelineNew(name, cwd, opts) {
  const cmd = ["pipeline", "new", name];
  if (opts && opts.description) cmd.push("--description", opts.description);
  if (opts && opts.type) cmd.push("--type", opts.type);
  if (opts && opts.model) cmd.push("--model", opts.model);
  return run(cmd, cwd, 60000);
}

function pipelineStatus(cwd, runId) {
  return run(["pipeline", "status", runId], cwd);
}

function pipelineHistory(cwd) {
  return run(["pipeline", "history"], cwd);
}

function pipelineGraph(name, cwd) {
  return run(["pipeline", "graph", name], cwd);
}

function pipelineStages(name, cwd) {
  return run(["pipeline", "stages", name], cwd);
}

function pipelineLint(name, cwd) {
  return run(["pipeline", "lint", name], cwd);
}

function pipelineRetry(runId, cwd) {
  return run(["pipeline", "retry", runId], cwd, 300000);
}

function pipelinePause(runId, cwd) {
  return run(["pipeline", "pause", runId], cwd);
}

function pipelineCancel(runId, cwd) {
  return run(["pipeline", "cancel", runId], cwd);
}

function pipelineResume(runId, cwd) {
  return run(["pipeline", "resume", runId], cwd, 300000);
}

function pipelineApprove(runId, cwd) {
  return run(["pipeline", "approve", runId], cwd);
}

function pipelineRepair(runId, cwd, stage) {
  return run(["pipeline", "repair", runId, stage], cwd, 300000);
}

// --- Other orchestrator integrations ---

function crewList(cwd) {
  return run(["crew", "status"], cwd);
}

function crewRun(name, role, cwd) {
  return run(["crew", "run", name, role], cwd, 300000);
}

function crewInit(name, cwd) {
  return run(["crew", "init", name], cwd);
}

function observeSummary(cwd) {
  return run(["observe", "summary"], cwd);
}

function observeAgents(cwd) {
  return run(["observe", "agents"], cwd);
}

function observePipelines(cwd) {
  return run(["observe", "pipelines"], cwd);
}

function observeCosts(cwd) {
  return run(["observe", "costs"], cwd);
}

function composeList(cwd) {
  return run(["compose", "list"], cwd);
}

function composeGraph(cwd, agent) {
  return run(["compose", "graph", agent], cwd);
}

function composeHistory(cwd) {
  return run(["compose", "history"], cwd);
}

function gapsList(cwd) {
  return run(["gaps", "list"], cwd);
}

function gapsShow(id, cwd) {
  return run(["gaps", "show", id], cwd);
}

function gapsAdd(cwd, opts) {
  const cmd = ["gaps", "add"];
  if (opts && opts.id) cmd.push("--id", opts.id);
  if (opts && opts.title) cmd.push("--title", opts.title);
  return run(cmd, cwd);
}

function gapsClose(id, cwd) {
  return run(["gaps", "close", id], cwd);
}

function gapsDispatch(id, cwd) {
  return run(["gaps", "dispatch", id], cwd, 300000);
}

function providerList(cwd) {
  return run(["provider", "list"], cwd);
}

function engineDoctor(cwd) {
  return run(["doctor"], cwd, 30000);
}

function testList(cwd) {
  return run(["test", "list"], cwd);
}

function testRun(suite, cwd) {
  return run(["test", "run", suite], cwd, 300000);
}

function impactReceipt(cwd) {
  return run(["impact"], cwd);
}

function costsBreakdown(cwd) {
  return run(["costs"], cwd);
}

function spawnPipelineRun(name, cwd, vars, opts) {
  if (!CLI) return null;
  const args = ["pipeline", "run", name];
  if (opts && opts.model) args.push("--model", opts.model);
  if (opts && opts.provider) args.push("--provider", opts.provider);
  if (opts && opts.from) args.push("--from", opts.from);
  if (opts && opts.to) args.push("--to", opts.to);
  if (opts && opts.pause) args.push("--pause");
  if (vars) for (const [k, v] of Object.entries(vars)) args.push("--var", k + "=" + String(v));
  return spawn(CLI, args, {
    cwd,
    env: Object.assign({}, process.env, { NO_COLOR: "1", FORCE_COLOR: "0" }),
  });
}

module.exports = {
  hasEngine,
  pipelineList, pipelineRun, pipelineNew, pipelineStatus, pipelineHistory,
  pipelineGraph, pipelineStages, pipelineLint, pipelineRetry, pipelinePause,
  pipelineCancel, pipelineResume, pipelineApprove, pipelineRepair,
  spawnPipelineRun,
  crewList, crewRun, crewInit,
  observeSummary, observeAgents, observePipelines, observeCosts,
  composeList, composeGraph, composeHistory,
  gapsList, gapsShow, gapsAdd, gapsClose, gapsDispatch,
  providerList, engineDoctor, testList, testRun,
  impactReceipt, costsBreakdown,
};
