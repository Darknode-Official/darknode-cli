"use strict";
// Engagement gate — the hard check in front of every run, plus the audit trail.
// Store layout (under $DARKNODE_HOME, default ~/.darknode):
//   authorizers.json                       { keyId: publicKeyPem }  trusted signers (deny-all if absent)
//   engagements/<id>/authorization.json    signed envelope (see authorization.js)
//   engagements/<id>/REVOKED.json          { at, reason, by }       presence = hard stop
//   engagements/<id>/audit.jsonl           hash-chained decision/exec log
//   audit-unscoped.jsonl                   denials that can't be attributed to an engagement
//
// Fail-closed rules: no signed authorization / bad signature / outside window / revoked /
// unknown tool / unknown flag / target not in scope / audit write failure  => DENY, nothing runs.
// A decision is written to the audit log BEFORE the gate returns allow.
const fs = require("fs"), os = require("os"), path = require("path"), crypto = require("crypto"), cp = require("child_process");
const A = require("./authorization");

const home = () => process.env.DARKNODE_HOME || path.join(os.homedir(), ".darknode");
function engDir(id) { if (!A.ID_RE.test(String(id || ""))) throw new Error("invalid engagement id: " + JSON.stringify(id)); return path.join(home(), "engagements", id); }
const operator = () => process.env.DARKNODE_OPERATOR || (() => { try { return os.userInfo().username; } catch (_) { return "unknown"; } })();

// ---- tool grammar ------------------------------------------------------------------
// Every runnable tool declares its class and an ALLOW-LIST of flags. An unknown flag is a
// deny — that is what stops target-smuggling (`-iL file`, `--resolve`, `-H Host: …`, list
// files, config includes). Flag kinds: 0 = boolean, 1 = takes a value, "t" = value is a TARGET.
// positional: "targets" (many) | ["target","value"] (fixed roles).
const TOOLS = {
  // native darknode subcommands (gated in-process by darknode.js)
  dns:      { cls: "recon",     positional: ["target"] },
  whois:    { cls: "recon",     positional: ["target"] },
  ipinfo:   { cls: "recon",     positional: ["target"] },
  subs:     { cls: "recon",     positional: ["target"] },
  subrecon: { cls: "scan",      positional: ["target"] },  // probes discovered hosts: each is re-checked via filterInScope
  scan:     { cls: "scan",      positional: ["target", "value"] },
  headers:  { cls: "scan",      positional: ["target"] },
  cert:     { cls: "scan",      positional: ["target"] },
  fuzz:     { cls: "vuln-scan", positional: ["target", "value"] },
  // external binaries (run by the gate itself: `darknode authz run <id> -- nmap …`)
  nmap:     { cls: "scan", bin: "nmap", positional: "targets",
              flags: { "-sS": 0, "-sT": 0, "-sV": 0, "-sn": 0, "-Pn": 0, "-n": 0, "-F": 0, "-v": 0, "-vv": 0, "-O": 0, "-p": 1, "-T": 1, "--top-ports": 1, "--max-rate": 1, "--min-rate": 1, "-oN": 1, "-oX": 1, "-oG": 1 } },
  nuclei:   { cls: "vuln-scan", bin: "nuclei", positional: [],
              flags: { "-u": "t", "-target": "t", "-silent": 0, "-jsonl": 0, "-nc": 0, "-duc": 0, "-severity": 1, "-tags": 1, "-rl": 1, "-c": 1, "-timeout": 1, "-o": 1, "-t": 1 } },
};
const PORTSPEC = /^(top|[0-9]{1,5}(-[0-9]{1,5})?(,[0-9]{1,5}(-[0-9]{1,5})?)*|-)$/;

// -> { targets[], error? }. Pure.
function parseInvocation(tool, argv) {
  const spec = Object.prototype.hasOwnProperty.call(TOOLS, tool) ? TOOLS[tool] : null;
  if (!spec) return { error: "tool '" + tool + "' is not permitted in an engagement (not in the gated tool registry)" };
  if (!Array.isArray(argv) || argv.some((a) => typeof a !== "string")) return { error: "argv must be an array of strings" };
  const flags = spec.flags || {}, targets = [], positionals = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--") return { error: "'--' is not permitted (ambiguous argument boundary)" };
    if (!a.startsWith("-") || a === "-") { positionals.push(a); continue; }
    let name = a, val = null;
    const eq = a.indexOf("=");
    if (a.startsWith("--") && eq > 0) { name = a.slice(0, eq); val = a.slice(eq + 1); }
    if (!Object.prototype.hasOwnProperty.call(flags, name)) {
      // attached short value: -T4, -p80,443
      const short = Object.keys(flags).find((f) => /^-[A-Za-z]$/.test(f) && flags[f] !== 0 && a.startsWith(f) && a.length > f.length);
      if (!short) return { error: "flag '" + a + "' is not permitted for " + tool };
      name = short; val = a.slice(short.length);
    }
    const kind = flags[name];
    if (kind === 0) { if (val !== null) return { error: "flag " + name + " takes no value" }; continue; }
    if (val === null) { if (i + 1 >= argv.length) return { error: "flag " + name + " needs a value" }; val = argv[++i]; }
    if (kind === "t") targets.push(val);
  }
  const pos = spec.positional;
  if (pos === "targets") targets.push(...positionals);
  else {
    if (positionals.length > pos.length) return { error: "unexpected extra argument: " + positionals[pos.length] };
    for (let i = 0; i < positionals.length; i++) {
      if (pos[i] === "target") targets.push(positionals[i]);
      else if (tool === "scan" && !PORTSPEC.test(positionals[i])) return { error: "invalid port spec: " + positionals[i] };
    }
  }
  if (!targets.length) return { error: "no target given" };
  return { targets, cls: spec.cls, spec };
}

// ---- strict, hash-chained audit ------------------------------------------------------
const ZERO = "0".repeat(64);
const sleepMs = (ms) => Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
function withLock(file, fn) {
  const lock = file + ".lock", t0 = Date.now(); let fd;
  for (;;) {
    try { fd = fs.openSync(lock, "wx"); break; }
    catch (e) {
      if (e.code !== "EEXIST") throw e;
      try { if (Date.now() - fs.statSync(lock).mtimeMs > 10000) fs.unlinkSync(lock); } catch (_) {}
      if (Date.now() - t0 > 5000) throw new Error("audit lock timeout");
      sleepMs(15);
    }
  }
  try { return fn(); } finally { try { fs.closeSync(fd); } catch (_) {} try { fs.unlinkSync(lock); } catch (_) {} }
}
// Unlike policy.auditLog this THROWS on failure — callers must treat that as a deny.
function auditAppend(file, entry) {
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  return withLock(file, () => {
    let prevHash = ZERO, seq = 0;
    if (fs.existsSync(file)) {
      const lines = fs.readFileSync(file, "utf8").split("\n").filter(Boolean);
      if (lines.length) { const last = JSON.parse(lines[lines.length - 1]); prevHash = last.hash; seq = last.seq + 1; if (typeof prevHash !== "string" || !Number.isInteger(seq)) throw new Error("audit log corrupt"); }
    }
    const rec = Object.assign({ ts: new Date().toISOString(), seq }, entry, { prevHash });
    rec.hash = crypto.createHash("sha256").update(JSON.stringify(rec)).digest("hex");
    fs.appendFileSync(file, JSON.stringify(rec) + "\n", { mode: 0o600 });
    return rec;
  });
}
function auditVerifyFile(file) {
  let lines; try { lines = fs.readFileSync(file, "utf8").split("\n").filter(Boolean); } catch (_) { return { ok: true, count: 0, empty: true }; }
  let prev = ZERO;
  for (let i = 0; i < lines.length; i++) {
    let rec; try { rec = JSON.parse(lines[i]); } catch (_) { return { ok: false, count: lines.length, badLine: i + 1, reason: "unparseable record" }; }
    if (rec.prevHash !== prev) return { ok: false, count: lines.length, badLine: i + 1, reason: "chain break (an entry was removed or reordered)" };
    if (rec.seq !== i) return { ok: false, count: lines.length, badLine: i + 1, reason: "sequence gap" };
    const stored = rec.hash, copy = Object.assign({}, rec); delete copy.hash;
    if (crypto.createHash("sha256").update(JSON.stringify(copy)).digest("hex") !== stored) return { ok: false, count: lines.length, badLine: i + 1, reason: "tampered (an entry was edited)" };
    prev = stored;
  }
  return { ok: true, count: lines.length, head: prev };
}
const auditFile = (id) => path.join(engDir(id), "audit.jsonl");
const unscopedAudit = () => path.join(home(), "audit-unscoped.jsonl");
function auditTail(id, n) { try { return fs.readFileSync(auditFile(id), "utf8").split("\n").filter(Boolean).slice(-(n || 20)).map((l) => JSON.parse(l)); } catch (_) { return []; } }

// ---- store ---------------------------------------------------------------------------
function readJson(f) { try { return JSON.parse(fs.readFileSync(f, "utf8")); } catch (_) { return null; } }
const trustedKeys = () => readJson(path.join(home(), "authorizers.json")) || {};
const loadEnvelope = (id) => readJson(path.join(engDir(id), "authorization.json"));
const loadRevocation = (id) => readJson(path.join(engDir(id), "REVOKED.json"));

// Verify + validate + install a signed envelope. Refuses to overwrite unless replace=true
// (the old one is kept in history/). -> { ok, error?, digest? }
function installEnvelope(envelope, opts) {
  opts = opts || {};
  try {
    const rec = envelope && envelope.record;
    if (!rec) return { ok: false, error: "not an authorization envelope" };
    const sig = A.verifySignature(envelope, trustedKeys()); if (!sig.ok) return { ok: false, error: sig.reason };
    const v = A.validateRecord(rec); if (!v.ok) return { ok: false, error: v.errors.join("; ") };
    const dir = engDir(rec.engagement), f = path.join(dir, "authorization.json");
    if (fs.existsSync(f) && !opts.replace) return { ok: false, error: "an authorization already exists for '" + rec.engagement + "' (use --replace to supersede; the old one is archived)" };
    fs.mkdirSync(path.join(dir, "history"), { recursive: true, mode: 0o700 });
    const digest = A.recordDigest(rec);
    // write the audit line first: if it fails, nothing is installed
    auditAppend(auditFile(rec.engagement), { event: "authorization_installed", engagement: rec.engagement, operator: operator(), recordDigest: digest, signedBy: sig.keyId, replaced: fs.existsSync(f) });
    if (fs.existsSync(f)) fs.renameSync(f, path.join(dir, "history", "authorization." + Date.now() + ".json"));
    fs.writeFileSync(f, JSON.stringify(envelope, null, 2), { mode: 0o600 });
    return { ok: true, digest };
  } catch (e) { return { ok: false, error: String(e && e.message || e) }; }
}
function revoke(id, reason) {
  const dir = engDir(id);
  if (!fs.existsSync(dir)) throw new Error("no such engagement: " + id);
  const r = { at: new Date().toISOString(), reason: String(reason || "unspecified"), by: operator() };
  fs.writeFileSync(path.join(dir, "REVOKED.json"), JSON.stringify(r, null, 2), { mode: 0o600 });
  try { auditAppend(auditFile(id), { event: "revoked", engagement: id, operator: r.by, reason: r.reason }); } catch (_) {} // revocation must succeed even if the log can't be written
  return r;
}

// ---- the gate ------------------------------------------------------------------------
// authorize({ engagement, tool, argv, dryRun? }) -> decision (always audited before return).
function authorize(req) {
  const id = req.engagement, tool = req.tool, argv = req.argv || [];
  const base = { engagement: id, operator: operator(), host: os.hostname(), tool, argv };
  let decision, cls = null, targets = [];
  try {
    const inv = parseInvocation(tool, argv);
    if (inv.error) decision = { allow: false, code: /not permitted in an engagement/.test(inv.error) ? "UNKNOWN_TOOL" : "BAD_ARGS", reason: inv.error };
    else {
      cls = inv.cls; targets = inv.targets;
      decision = A.evaluate({ envelope: loadEnvelope(id), trustedKeys: trustedKeys(), revoked: loadRevocation(id), now: req.now, class: cls, targets });
    }
  } catch (e) { decision = { allow: false, code: "GATE_ERROR", reason: "gate error (fail closed): " + (e && e.message || e) }; }
  const entry = Object.assign({ event: "decision", class: cls, targets, dryRun: !!req.dryRun, allow: decision.allow, code: decision.code, reason: decision.reason, recordDigest: decision.recordDigest || null, checked: decision.checked }, base);
  let file; try { file = fs.existsSync(engDir(id)) ? auditFile(id) : unscopedAudit(); } catch (_) { file = unscopedAudit(); }
  try { auditAppend(file, entry); }
  catch (e) { return { allow: false, code: "AUDIT_FAILURE", reason: "cannot write audit trail — refusing to run (" + (e && e.message || e) + ")", tool, targets, cls }; }
  return Object.assign({}, decision, { tool, argv, targets, cls });
}

class GateDenied extends Error { constructor(d) { super("GATE DENIED [" + d.code + "]: " + d.reason); this.decision = d; this.code = d.code; } }

// In-process guard for native subcommands: authorize, run fn, audit the outcome.
async function guard(id, tool, argv, fn) {
  const d = authorize({ engagement: id, tool, argv });
  if (!d.allow) throw new GateDenied(d);
  let outcome = "ok";
  try { return await fn(d); } catch (e) { outcome = "error: " + (e && e.message || e); throw e; }
  finally { try { auditAppend(auditFile(id), { event: "exec_end", engagement: id, operator: operator(), tool, outcome }); } catch (_) {} }
}

// Drop discovered hosts that fall outside scope (used by subrecon, which finds its own targets).
// One audit entry summarises the filtering. -> { allowed[], dropped[] }
function filterInScope(id, cls, hosts) {
  const env = loadEnvelope(id), keys = trustedKeys(), rev = loadRevocation(id);
  const allowed = [], dropped = [];
  for (const h of hosts) (A.evaluate({ envelope: env, trustedKeys: keys, revoked: rev, class: cls, targets: [h] }).allow ? allowed : dropped).push(h);
  try { auditAppend(auditFile(id), { event: "discovered_filter", engagement: id, operator: operator(), class: cls, allowedCount: allowed.length, dropped }); }
  catch (_) { return { allowed: [], dropped: hosts.slice() }; } // can't audit -> use nothing
  return { allowed, dropped };
}

// Run an external tool under the gate. Re-checks authorization every `pollMs` and kills
// the child the moment the engagement is revoked or its window closes.
function runExternal(id, tool, argv, opts) {
  opts = opts || {};
  return new Promise((resolve, reject) => {
    const d = authorize({ engagement: id, tool, argv });
    if (!d.allow) return reject(new GateDenied(d));
    const spec = TOOLS[tool];
    if (!spec.bin) return reject(new Error(tool + " is an in-process tool, not an external binary"));
    let child; try { child = cp.spawn(spec.bin, argv, { stdio: opts.stdio || "inherit", shell: false }); } catch (e) { return reject(e); }
    let killed = null;
    const poll = setInterval(() => {
      const chk = A.evaluate({ envelope: loadEnvelope(id), trustedKeys: trustedKeys(), revoked: loadRevocation(id), class: d.cls, targets: d.targets });
      if (!chk.allow && !killed) {
        killed = chk.code;
        try { auditAppend(auditFile(id), { event: "watchdog_kill", engagement: id, tool, code: chk.code, reason: chk.reason }); } catch (_) {}
        try { child.kill("SIGTERM"); } catch (_) {}
        setTimeout(() => { try { child.kill("SIGKILL"); } catch (_) {} }, 5000).unref();
      }
    }, opts.pollMs || 2000);
    const fin = (code, signal, err) => {
      clearInterval(poll);
      try { auditAppend(auditFile(id), { event: "exec_end", engagement: id, operator: operator(), tool, code, signal: signal || null, killedBy: killed, error: err ? String(err.message || err) : undefined }); } catch (_) {}
      err ? reject(err) : resolve({ code: code === null ? 1 : code, killedBy: killed });
    };
    child.on("close", (code, signal) => fin(code, signal));
    child.on("error", (e) => fin(1, null, e));
  });
}

// Commands that never touch a target and are safe in an engagement session. Everything else
// that isn't in TOOLS is refused when DARKNODE_ENGAGEMENT is set (allow-list, not block-list).
const OFFLINE_COMMANDS = new Set(["hash", "hashfile", "totp", "genpass", "payloads", "tools", "docs", "doc", "help", "policy", "audit", "report", "authz", "cve", "lab", "login", "logout", "whoami"]);

module.exports = { TOOLS, OFFLINE_COMMANDS, parseInvocation, home, engDir, auditAppend, auditVerifyFile, auditFile, auditTail, trustedKeys, loadEnvelope, loadRevocation, installEnvelope, revoke, authorize, guard, filterInScope, runExternal, GateDenied };
