"use strict";
// Local-agent tool catalog + `discover` search: let the agent look
// up which tool fits a need by keyword instead of relying on a fixed prompt list —
// useful once MCP tools inflate the toolset. Pure/testable.
//
// The catalog is DERIVED from native-tools' TOOL_SCHEMAS so the two lists can no
// longer drift: every schema'd tool shows up in `discover` automatically, with the
// schema's own description. TOOL_SCHEMAS is not quite the whole set — a handful of
// agentic tools are dispatched (darknode.js ~2132-2160, :3701) without a native
// schema — so those are listed explicitly in EXTRA_TOOLS below. If you add a tool,
// give it a schema in native-tools.js (preferred) OR an EXTRA_TOOLS entry here.
const { TOOL_SCHEMAS } = require("./native-tools");

// Agentic tools that are really dispatched but carry no native-tool schema yet.
// Keep in step with the dispatch switch in darknode.js.
const EXTRA_TOOLS = [
  ["invariants", "lint the pending diff against .nexus/invariants.json rules"],
  ["attest", "report what this run touched (files/commands/network) from the audit log"],
  ["bisect", "binary-search checkpoints to find the turn that broke the tests"],
  ["explain_break", "blame the turn most likely to have broken a failing test"],
  ["shrink", "delta-debug the edits to the minimal subset that still breaks the test"],
  ["ask_user", "pause and ask the user a multiple-choice question when a decision is theirs"],
];

const TOOL_CATALOG = Object.keys(TOOL_SCHEMAS)
  .map((name) => [name, (TOOL_SCHEMAS[name] && TOOL_SCHEMAS[name].description) || name])
  .concat(EXTRA_TOOLS);

function discoverTools(query, catalog) {
  catalog = catalog || TOOL_CATALOG;
  const words = String(query || "").toLowerCase().split(/\s+/).filter(Boolean);
  const hit = words.length
    ? catalog.filter(([n, d]) => words.some((w) => n.toLowerCase().includes(w) || d.toLowerCase().includes(w)))
    : catalog.slice();
  return hit.map(([name, description]) => ({ name, description }));
}
module.exports = { TOOL_CATALOG, discoverTools, EXTRA_TOOLS };
