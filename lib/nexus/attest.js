"use strict";
// ================= attest: capability attestation from the hash-chained audit log =========
// Nexus already records every enforced tool action to a tamper-evident, hash-chained audit log
// (.nexus/audit.jsonl: each record carries seq + prevHash + a sha256 over itself). That log
// proves the records weren't altered after the fact — but on its own it's just a list. What a
// reviewer (or a CI gate, or the operator who let the agent run unattended) actually wants to
// know is a SUMMARY they can trust and a set of CLAIMS they can PROVE:
//   "this run made zero network calls"
//   "it only wrote files under src/ and test/"
//   "it never deleted anything"
//   "it ran no command matching /curl|wget|rm -rf/"
//
// `attest` reads the chained log and emits (1) a capability manifest — exactly which tools ran,
// which paths were written, which commands executed, whether the network was touched, and the
// chain-integrity verdict — and (2) a claim check: it evaluates declared expectations against
// the manifest and returns pass/fail with evidence for each. Because the manifest is derived
// from a chain the reviewer can independently verify, a PASS is a provable statement about what
// the run did, not a promise the agent makes about itself.
//
// WHY NOVEL: tamper-evident agent logs exist (agentproofs, halo-record). What's new here is
// turning that chain into a CAPABILITY ATTESTATION with checkable claims — a reviewer-facing
// "prove it touched only X / reached no network" gate built on the agent's own provenance trail.
//
// The engine is pure + deterministic: buildManifest(records) and checkClaims(manifest, claims).
// Chain verification + file reading live in the thin wiring entry (attestTool), which reuses the
// canonical auditVerify so there is exactly one hash-chain implementation. Unit-tested without a
// model, like loopguard/filestate/diagnose.

// ---- tiny self-contained glob matcher (kept local so this module is dependency-free) ----
function globToRe(g) {
  let re = "";
  for (let i = 0; i < g.length; i++) {
    const c = g[i];
    if (c === "*") { if (g[i + 1] === "*") { re += ".*"; i++; if (g[i + 1] === "/") i++; } else re += "[^/]*"; }
    else if (c === "?") re += "[^/]";
    else if (".+^${}()|[]\\".includes(c)) re += "\\" + c;
    else re += c;
  }
  return new RegExp("^" + re + "$");
}
function matchesAny(rel, globs) {
  const p = String(rel || "").replace(/\\/g, "/").replace(/^\.\//, "");
  const base = p.split("/").pop();
  return (globs || []).some((g) => { try { const re = globToRe(g); return re.test(p) || re.test(base); } catch (_) { return false; } });
}
function toRegex(r) {
  if (r instanceof RegExp) return r;
  try { return new RegExp(String(r)); } catch (_) { try { return new RegExp(String(r).replace(/[.*+?^${}()|[\]\\]/g, "\\$&")); } catch (_2) { return null; } }
}

// Tool-name families (the audit log stores the raw tool name the agent called).
const NETWORK_TOOLS = new Set(["http_fetch", "web_fetch", "fetch_url", "http", "web_search", "search_web", "google"]);
const WRITE_TOOLS = new Set(["write_file", "edit_file", "multi_edit", "multiedit", "apply_patch", "patch"]);
const DELETE_TOOLS = new Set(["delete", "delete_file", "rm"]);
const MOVE_TOOLS = new Set(["move", "move_file", "rename", "copy", "copy_file"]);
const EXEC_TOOLS = new Set(["run_command", "run_background"]);

// A record is "effective" (the action actually happened) when it was not blocked by policy/hook.
function effective(rec) { return rec && rec.status !== "blocked"; }

// ---- pure engine: summarize a list of audit records into a capability manifest ----
// records: parsed audit.jsonl entries (array of objects). Returns a structured, sorted summary.
function buildManifest(records) {
  const recs = Array.isArray(records) ? records.filter((r) => r && typeof r === "object") : [];
  const tools = {};            // toolName -> count (effective actions only)
  const writes = new Set();    // paths created/edited
  const deletes = new Set();   // paths deleted
  const moves = new Set();     // destination paths of moves/copies
  const commands = [];         // { cmd, status }
  const network = [];          // { tool, status } for each network invocation (any status)
  const blocked = [];          // { tool, path, cmd, reason }
  const errors = [];           // { tool, path, cmd }
  const engines = new Set();
  let firstTs = null, lastTs = null, maxSeq = -1;

  for (const r of recs) {
    const tool = String(r.tool || "");
    if (r.engine) engines.add(String(r.engine));
    if (r.ts) { if (firstTs == null) firstTs = r.ts; lastTs = r.ts; }
    if (typeof r.seq === "number" && r.seq > maxSeq) maxSeq = r.seq;
    if (r.status === "blocked") { blocked.push({ tool, path: r.path || "", cmd: r.cmd || "", reason: r.reason || "" }); continue; }
    if (r.status === "error") errors.push({ tool, path: r.path || "", cmd: r.cmd || "" });
    tools[tool] = (tools[tool] || 0) + 1;
    if (NETWORK_TOOLS.has(tool)) network.push({ tool, status: r.status || "ok" });
    if (WRITE_TOOLS.has(tool) && r.path) writes.add(r.path);
    if (DELETE_TOOLS.has(tool) && r.path) deletes.add(r.path);
    if (MOVE_TOOLS.has(tool) && r.path) moves.add(r.path);
    if (EXEC_TOOLS.has(tool) && r.cmd) commands.push({ cmd: r.cmd, status: r.status || "ok" });
  }

  const sort = (s) => Array.from(s).sort();
  return {
    records: recs.length,
    seqRange: recs.length ? { from: recs[0].seq != null ? recs[0].seq : null, to: maxSeq } : null,
    timeSpan: { from: firstTs, to: lastTs },
    engines: sort(engines),
    tools,
    writes: sort(writes),
    deletes: sort(deletes),
    moves: sort(moves),
    commands,
    network,                     // empty array === no network action was taken
    touchedNetwork: network.length > 0,
    blocked,
    errors,
    counts: { writes: writes.size, deletes: deletes.size, moves: moves.size, commands: commands.length, network: network.length, blocked: blocked.length, errors: errors.length },
  };
}

// ---- pure engine: evaluate declared claims against a manifest ----
// claims is a flat object; each recognised key becomes one checked claim. Returns
// { ok, claims:[{claim, pass, detail}], checked }. An unrecognised key is reported, not silently
// ignored, so a typo'd claim can't masquerade as a pass.
function checkClaims(manifest, claims) {
  manifest = manifest || buildManifest([]);
  claims = claims && typeof claims === "object" ? claims : {};
  const out = [];
  const add = (claim, pass, detail) => out.push({ claim, pass: !!pass, detail: detail || "" });
  const allPaths = () => manifest.writes.concat(manifest.deletes, manifest.moves);

  for (const key of Object.keys(claims)) {
    const val = claims[key];
    if (key === "noNetwork") {
      const n = manifest.network.length;
      add("noNetwork", n === 0, n === 0 ? "no network tool was invoked" : n + " network invocation(s): " + manifest.network.map((x) => x.tool + "(" + x.status + ")").join(", "));
    } else if (key === "noDelete") {
      add("noDelete", manifest.deletes.length === 0, manifest.deletes.length === 0 ? "nothing was deleted" : "deleted: " + manifest.deletes.join(", "));
    } else if (key === "onlyPaths") {
      const globs = Array.isArray(val) ? val : [val];
      const bad = allPaths().filter((p) => !matchesAny(p, globs));
      add("onlyPaths", bad.length === 0, bad.length === 0 ? "all touched paths are within " + globs.join(", ") : "outside the allowed paths: " + bad.join(", "));
    } else if (key === "noPaths") {
      const globs = Array.isArray(val) ? val : [val];
      const hit = allPaths().filter((p) => matchesAny(p, globs));
      add("noPaths", hit.length === 0, hit.length === 0 ? "no touched path matched the forbidden set" : "touched forbidden path(s): " + hit.join(", "));
    } else if (key === "maxWrites") {
      const n = Number(val);
      add("maxWrites", manifest.writes.length <= n, "wrote " + manifest.writes.length + " file(s), limit " + n);
    } else if (key === "noCommands") {
      const pats = (Array.isArray(val) ? val : [val]).map(toRegex).filter(Boolean);
      const hit = manifest.commands.filter((c) => pats.some((p) => p.test(c.cmd)));
      add("noCommands", hit.length === 0, hit.length === 0 ? "no command matched the forbidden patterns" : "ran forbidden command(s): " + hit.map((c) => c.cmd).join(" ; "));
    } else if (key === "allowCommands") {
      const pats = (Array.isArray(val) ? val : [val]).map(toRegex).filter(Boolean);
      const bad = manifest.commands.filter((c) => !pats.some((p) => p.test(c.cmd)));
      add("allowCommands", bad.length === 0, bad.length === 0 ? "every command matched an allowed pattern" : "command(s) outside the allowlist: " + bad.map((c) => c.cmd).join(" ; "));
    } else if (key === "noErrors") {
      add("noErrors", manifest.errors.length === 0, manifest.errors.length === 0 ? "no tool action errored" : manifest.errors.length + " action(s) errored");
    } else if (key === "chainVerified") {
      // Evaluated by the wiring (needs the on-disk chain). manifest._chain is attached there.
      const c = manifest._chain;
      if (!c) add("chainVerified", false, "chain status unavailable (no log read)");
      else add("chainVerified", !!c.ok, c.ok ? "hash chain verified (" + (c.count || 0) + " records)" : "CHAIN BROKEN: " + (c.reason || "tampered"));
    } else {
      add(key, false, "unknown claim — supported: noNetwork, noDelete, onlyPaths, noPaths, maxWrites, noCommands, allowCommands, noErrors, chainVerified");
    }
  }
  return { ok: out.every((c) => c.pass), claims: out, checked: out.length };
}

// ---- thin wiring entry: read the chained log, verify it, build the manifest, check claims ----
// Options: a.since (only records with seq >= this), a.sinceTs (ISO cutoff), a.claims (object).
// Reuses the canonical auditVerify so the chain is verified by the same code the CLI trusts.
function attestTool(a, cwd, deps) {
  a = a || {};
  deps = deps || {};
  const fs = deps.fs || require("fs");
  const path = deps.path || require("path");
  const auditVerify = deps.auditVerify || require("../governance/policy").auditVerify;
  let raw;
  try { raw = fs.readFileSync(path.join(cwd, ".nexus", "audit.jsonl"), "utf8"); }
  catch (_) { return { error: "no audit trail (.nexus/audit.jsonl) in this directory — attestation needs the hash-chained log, which fills as enforced tool actions run (policy.audit must be on)" }; }
  let records = raw.trim().split("\n").filter(Boolean).map((l) => { try { return JSON.parse(l); } catch (_) { return null; } }).filter(Boolean);
  const since = a.since != null ? Number(a.since) : null;
  if (since != null && !isNaN(since)) records = records.filter((r) => typeof r.seq === "number" && r.seq >= since);
  if (a.sinceTs) records = records.filter((r) => r.ts && r.ts >= a.sinceTs);
  const chain = auditVerify(cwd); // verifies the WHOLE on-disk chain (integrity is a whole-file property)
  const manifest = buildManifest(records);
  manifest.chain = { verified: !!chain.ok, records: chain.count || 0, reason: chain.ok ? undefined : chain.reason };
  const result = { manifest };
  if (a.claims && typeof a.claims === "object" && Object.keys(a.claims).length) {
    manifest._chain = chain;
    const cc = checkClaims(manifest, a.claims);
    delete manifest._chain;
    result.claims = cc;
    result.ok = cc.ok && (a.claims.chainVerified ? true : chain.ok !== false);
  }
  const m = manifest;
  result.summary = m.records + " audited action(s)" + (m.seqRange ? " (seq " + m.seqRange.from + "–" + m.seqRange.to + ")" : "") +
    " · " + m.counts.writes + " file(s) written, " + m.counts.deletes + " deleted, " + m.counts.commands + " command(s) run, " +
    (m.touchedNetwork ? m.counts.network + " network call(s)" : "NO network") + " · chain " + (chain.ok ? "verified" : (chain.empty ? "empty" : "BROKEN")) +
    (result.claims ? " · claims " + (result.claims.ok ? "PASS" : "FAIL (" + result.claims.claims.filter((c) => !c.pass).length + ")") : "");
  return result;
}

module.exports = {
  attestTool, buildManifest, checkClaims,
  // exported for tests / reuse
  globToRe, matchesAny, NETWORK_TOOLS, WRITE_TOOLS, DELETE_TOOLS, EXEC_TOOLS,
};
