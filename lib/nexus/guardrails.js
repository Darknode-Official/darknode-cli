"use strict";
// Guardrails — one gate for a proposed agent action.
//
// A single verdict (allow | ask | deny) over a command or file write, composed
// from Nexus's existing, separately-tested governance primitives:
//   - policyCheck      — path / denied-command / network allow-lists
//   - classifyDanger   — destructive shell-command classifier (block/warn/ok)
//   - scanSecrets      — would this leak a credential?
// Every rule that fires is reported with its source, and the decision is the
// strongest escalation among them. Pure: the caller enforces the verdict and
// records it to the tamper-evident audit chain (governance/policy auditLog).
const { policyCheck } = require("../governance/policy");
const { classifyDanger, scanSecrets } = require("../governance/security");

const RANK = { allow: 0, ask: 1, deny: 2 };

// The policy module speaks type "run"/"write"/"edit"/"delete"/"move"/"fetch".
// Normalize our friendlier vocabulary ("command") onto it.
function mapAction(a) {
  return { type: a.type === "command" ? "run" : a.type, command: a.command, path: a.path };
}

// action: { type: "command"|"run"|"write"|"edit"|"delete"|"move"|"fetch",
//           command?, path?, content? }
// policy: governance policy (protectedPaths, requireApprovalPaths, deniedCommands, allowNetwork…)
// opts:   { denyOnSecret?: bool }
// -> { decision: "allow"|"ask"|"deny", risk: "none"|"warn"|"block", reasons: [{source, why}] }
function evaluateAction(action, policy, opts) {
  const a = action || {}, o = opts || {};
  const reasons = [];
  let decision = "allow";
  const escalate = (d) => { if (RANK[d] > RANK[decision]) decision = d; };

  // 1) Hard policy — paths, denied commands, network.
  const pol = policyCheck(policy || {}, mapAction(a));
  if (!pol.allow) { reasons.push({ source: "policy", why: pol.reason }); escalate(pol.approval ? "ask" : "deny"); }

  // 2) Destructive-command classifier (command actions only).
  let dangerLevel = "ok";
  if ((a.type === "run" || a.type === "command") && a.command) {
    const d = classifyDanger(a.command);
    dangerLevel = d.level;
    if (d.level === "block") { reasons.push({ source: "danger", why: d.why }); escalate("deny"); }
    else if (d.level === "warn") { reasons.push({ source: "danger", why: d.why }); escalate("ask"); }
  }

  // 3) Secret exposure — content being written, or a credential embedded in a command.
  const text = a.content != null ? String(a.content) : (a.command != null ? String(a.command) : "");
  if (text) {
    const secrets = scanSecrets(text);
    if (secrets.length) { reasons.push({ source: "secret", why: "would expose " + secrets.join(", ") }); escalate(o.denyOnSecret ? "deny" : "ask"); }
  }

  const risk = dangerLevel !== "ok" ? dangerLevel
    : decision === "deny" ? "block" : decision === "ask" ? "warn" : "none";
  return { decision, risk, reasons };
}

module.exports = { evaluateAction, mapAction, RANK };
