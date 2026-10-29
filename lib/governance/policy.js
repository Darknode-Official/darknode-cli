"use strict";
// Enterprise guardrails engine — pure policy evaluation + a tamper-evident audit
// trail. Dependency-free (fs/crypto only); the darknodeHome-aware two-tier merge
// (org floor + local) lives in darknode.js as loadPolicy(), which uses these.

const { redactCommandSecrets } = require("./security"); // strip inline command credentials before they persist in the audit log (NSAFE-064)

const POLICY_DEFAULTS = {
  protectedPaths: [".env", ".env.*", "**/.env", "**/.env.*", "*.pem", "*.key", "id_rsa*", "id_ed25519*", "**/.ssh/**", "**/secrets/**", "**/.git/**", "**/credentials*", "**/*.pfx"],
  deniedCommands: [],          // extra regex strings, on top of the built-in destructive-command guard
  requireApprovalPaths: [],    // globs that may only be changed after explicit approval
  maxFilesPerTurn: 0,          // 0 = unlimited
  blockSecrets: true,          // refuse to write a file that contains a detected secret
  allowNetwork: true,          // allow the http_fetch tool
  audit: true,                 // append every enforced action to .nexus/audit.jsonl
};
const { globToRe } = require("../nexus/glob"); // shared glob (lib/nexus/glob.js): braces, **/ spans whole directories
function pathMatchesAny(rel, globs) { const p = String(rel || "").replace(/\\/g, "/").replace(/^\.\//, ""); const base = p.split("/").pop(); return (globs || []).some((g) => { try { const re = globToRe(g); return re.test(p) || re.test(base); } catch (_) { return false; } }); }
// --- Built-in deny floor (NSAFE-016) -------------------------------------
// A tiny, compiled-in set of host-destroying or self-tampering actions that NO
// policy setting or saved approval can permit — defense in depth against both an
// operator mistake and a compromised policy file. Evaluated first in policyCheck,
// so it sits below every allow/deny layer. Deliberately minimal (host
// destruction, and tampering with the audit log / safety settings / the Nexus
// process); everything else stays policy-controlled. Deeply frozen so a test —
// or a bug — cannot mutate it at runtime. Lives here, not in guardrails.js, so
// the floor is enforced at the one layer every gate funnels through without a
// require cycle (guardrails.js imports this module and re-exports HARD_DENY).
// normalise so `.nexus/./settings.json`, `.nexus//x` or `a/../.nexus/x` can't dodge the suffix match
const _np = (s) => { const t = String(s == null ? "" : s).replace(/\\/g, "/"); return (t ? require("path").posix.normalize(t) : t).toLowerCase(); };
const _refs = (a, needle) =>
  (["write", "edit", "delete", "move"].includes(a.type) && _np(a.path).endsWith(needle)) ||
  (a.type === "run" && _np(a.command).includes(needle));
const HARD_DENY = Object.freeze([
  { id: "host-rm-root", why: "deletes a system or root filesystem path", match: (a) => a.type === "run" && /\brm\s+(-\S*\s+)*(\/(\s|$)|\/\*|~(\/|\s|$)|\$home\b|\/(etc|usr|var|boot|bin|lib|sys|dev|opt|root)\b)/i.test(a.command || "") },
  { id: "raw-disk-write", why: "writes to or formats a raw disk device", match: (a) => (a.type === "run" && (/\bmkfs(\.\w+)?\b/i.test(a.command || "") || /\bdd\b[^\n]*\bof=\/dev\//i.test(a.command || "") || /\b(wipefs|shred)\b/i.test(a.command || "") || />\s*\/dev\/(sd|nvme|hd|mmcblk)/i.test(a.command || ""))) || /^\/dev\/(sd|nvme|hd|mmcblk)/.test(_np(a.path)) },
  { id: "tamper-audit-log", why: "disables or destroys the tamper-evident audit log", match: (a) => _refs(a, ".nexus/audit.jsonl") },
  { id: "tamper-safety-config", why: "edits the Nexus safety settings", match: (a) => _refs(a, ".nexus/settings.json") },
  // hooks.json too: a hook runs unguarded on every tool call, so an agent that writes one escapes the guard from the next launch.
  // A shell command naming these files is caught as well (echo > / sed -i / cp), unless it is one plain read with no pipe or redirect.
  { id: "tamper-policy", why: "edits the rules the agent itself runs under (.nexus/policy.json / permissions.json / hooks.json)", match: (a) => [".nexus/policy.json", ".nexus/permissions.json", ".nexus/hooks.json"].some((n) => _refs(a, n)) && !(a.type === "run" && /^\s*(cat|head|tail|less|more|jq|grep|wc|ls|stat|file)\b[^|;&<>`$\n]*$/i.test(a.command || "")) },
  { id: "kill-nexus", why: "kills the running Nexus process", match: (a) => a.type === "run" && (/\b(pkill|killall)\b[^\n]*\b(nexus|darknode)\b/i.test(a.command || "") || /\bkill\b[^\n]*\bnexus\b/i.test(a.command || "")) },
].map(Object.freeze));
// Does an action hit the floor? Returns the matching rule or null. A matcher that
// throws is treated as a non-match so a bad rule can never crash the gate.
function hitsHardDeny(action) {
  const a = action || {};
  for (const rule of HARD_DENY) { let hit = false; try { hit = rule.match(a); } catch (_) {} if (hit) return rule; }
  return null;
}

// action = { type: "write"|"edit"|"delete"|"move"|"run"|"fetch", path?, command? } -> { allow, reason?, approval?, floor? }
function policyCheck(policy, action) {
  const floor = hitsHardDeny(action);
  if (floor) return { allow: false, reason: "hard-deny: " + floor.why, floor: floor.id };
  const t = action.type;
  if ((t === "write" || t === "edit" || t === "delete" || t === "move") && action.path) {
    if (pathMatchesAny(action.path, policy.protectedPaths)) return { allow: false, reason: "protected path: " + action.path };
    if (pathMatchesAny(action.path, policy.requireApprovalPaths)) return { allow: false, reason: "requires approval: " + action.path, approval: true };
  }
  if (t === "run" && action.command) for (const rs of (policy.deniedCommands || [])) { try { if (new RegExp(rs).test(action.command)) return { allow: false, reason: "denied command: /" + rs + "/" }; } catch (_) {} }
  if (t === "fetch" && !policy.allowNetwork) return { allow: false, reason: "network disabled by policy" };
  return { allow: true };
}
// Tamper-evident audit trail: each record carries seq + prevHash and a sha256 over
// itself, forming a hash chain. Deleting, reordering or editing any past entry breaks
// the chain, which `auditVerify` detects — compliance-grade provenance.
function auditLog(cwd, entry) {
  try {
    const fs = require("fs"), path = require("path"), crypto = require("crypto");
    fs.mkdirSync(path.join(cwd, ".nexus"), { recursive: true });
    const file = path.join(cwd, ".nexus", "audit.jsonl");
    let prevHash = "0".repeat(64), seq = 0;
    try { const lines = fs.readFileSync(file, "utf8").trim().split("\n").filter(Boolean); if (lines.length) { const last = JSON.parse(lines[lines.length - 1]); prevHash = last.hash || prevHash; seq = (last.seq || 0) + 1; } } catch (_) {}
    if (entry && typeof entry.cmd === "string") entry = Object.assign({}, entry, { cmd: redactCommandSecrets(entry.cmd) }); // never persist an inline credential
    const rec = Object.assign({ ts: new Date().toISOString(), seq }, entry, { prevHash });
    rec.hash = crypto.createHash("sha256").update(JSON.stringify(rec)).digest("hex"); // chains prevHash (a field of rec)
    fs.appendFileSync(file, JSON.stringify(rec) + "\n");
  } catch (_) {}
}
function auditVerify(cwd) {
  const fs = require("fs"), path = require("path"), crypto = require("crypto");
  let lines; try { lines = fs.readFileSync(path.join(cwd, ".nexus", "audit.jsonl"), "utf8").trim().split("\n").filter(Boolean); } catch (_) { return { ok: true, count: 0, empty: true }; }
  let prevHash = "0".repeat(64);
  for (let i = 0; i < lines.length; i++) {
    let rec; try { rec = JSON.parse(lines[i]); } catch (_) { return { ok: false, count: lines.length, badLine: i + 1, reason: "unparseable record" }; }
    if (rec.prevHash !== prevHash) return { ok: false, count: lines.length, badLine: i + 1, reason: "chain break (prevHash mismatch — an entry was removed or reordered)" };
    const stored = rec.hash, copy = Object.assign({}, rec); delete copy.hash;
    if (crypto.createHash("sha256").update(JSON.stringify(copy)).digest("hex") !== stored) return { ok: false, count: lines.length, badLine: i + 1, reason: "tampered (hash mismatch — an entry was edited)" };
    prevHash = stored;
  }
  return { ok: true, count: lines.length };
}

module.exports = { POLICY_DEFAULTS, globToRe, pathMatchesAny, policyCheck, auditLog, auditVerify, HARD_DENY, hitsHardDeny };
