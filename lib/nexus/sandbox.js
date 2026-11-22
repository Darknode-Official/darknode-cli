"use strict";
// ================= engine sandbox (Linux Landlock) =================
// Wraps an engine spawn so the engine, and every process it starts, can read the
// system but NOT the user's secrets (~/.ssh, cloud/CLI tokens, browser profiles,
// shell history), and can write only the project (not in plan mode), the temp dir
// and the engine's own state dirs. Network stays open: cloud engines need it.
//
// Unprivileged: Landlock needs no root, setuid helper or user namespaces (bubblewrap
// is blocked by AppArmor's userns restriction on Ubuntu 24.04+). The policy is applied
// by lib/nexus/landlock.py, a stdlib-only python3 launcher that restricts itself and
// then execs the engine. Where Landlock or python3 is missing, sandboxFor() returns
// null with a reason and the engine runs unsandboxed, as before.
//
// Settings (/sandbox, NEXUS_SANDBOX): "auto" (default) sandboxes plan-mode turns and
// repos whose .nexus config is held back as untrusted; "always" sandboxes every engine
// turn; "off" never does.

const fs = require("fs");
const os = require("os");
const path = require("path");
const { spawnSync } = require("child_process");

const LAUNCHER = path.join(__dirname, "landlock.py");
const MODES = ["auto", "always", "off"];

// Under $HOME: never readable by a sandboxed engine.
const HOME_DENY = [
  ".ssh", ".gnupg", ".aws", ".azure", ".kube", ".docker", ".netrc", ".git-credentials", ".npmrc", ".pypirc",
  ".vault-token", ".terraform.d", ".password-store", ".pki", ".mozilla", ".thunderbird", ".wrangler", ".darknode",
  ".bash_history", ".zsh_history", ".python_history", ".node_repl_history", ".psql_history", ".mysql_history", ".sqlite_history",
  ".config/gh", ".config/hub", ".config/gcloud", ".config/doctl", ".config/rclone", ".config/darknode", ".config/configstore",
  ".config/.wrangler", ".config/op", ".config/google-chrome", ".config/chromium", ".config/BraveSoftware", ".config/microsoft-edge",
  ".config/vivaldi", ".config/opera", ".local/share/keyrings", ".local/share/fish/fish_history", "snap/firefox", "snap/chromium",
  ".var/app/org.mozilla.firefox", ".var/app/com.google.Chrome",
];
// Under $HOME: engine state the engines must write (logins, sessions, caches).
const HOME_WRITE = [
  ".claude", ".claude.json", ".claude.json.backup", ".gemini", ".codex", ".qwen", ".config/goose", ".local/share/goose",
  ".config/opencode", ".local/share/opencode", ".local/state/opencode", ".cache", ".npm", ".bun", ".local/state", ".aider",
  ".aider.chat.history.md", ".aider.input.history",
];

let _probe; // { ok, abi, why } — probed once per process
function probe(force) {
  if (_probe && !force) return _probe;
  if (process.platform !== "linux") return (_probe = { ok: false, why: "the sandbox needs Linux (Landlock)" });
  if (!fs.existsSync(LAUNCHER)) return (_probe = { ok: false, why: "sandbox launcher missing" });
  const r = spawnSync("python3", ["-I", LAUNCHER, "--probe"], { encoding: "utf8", timeout: 5000 });
  if (r.error) return (_probe = { ok: false, why: "python3 not found (the sandbox launcher needs it)" });
  const abi = parseInt(String(r.stdout || "").trim(), 10);
  if (r.status !== 0 || !(abi > 0)) return (_probe = { ok: false, why: (String(r.stderr || "").replace(/^nexus-sandbox: /, "").trim() || "Landlock unavailable") });
  return (_probe = { ok: true, abi });
}

const normMode = (v) => { const s = String(v == null ? "" : v).trim().toLowerCase(); return s === "on" ? "always" : MODES.includes(s) ? s : ""; };

// Should this turn be sandboxed? -> null, or { writable, reason }.
//   setting: "auto" | "always" | "off"; plan: plan mode (read-only); untrusted: repo config held back.
function decide(setting, { plan, untrusted } = {}) {
  const s = normMode(setting) || "auto";
  if (s === "off") return null;
  if (s === "always") return { writable: !plan, reason: plan ? "plan mode" : "sandbox always" };
  if (plan) return { writable: false, reason: "plan mode" };
  if (untrusted) return { writable: true, reason: "untrusted repo" };
  return null;
}

// The Landlock policy for one engine run.
function policy({ cwd, home, writable, extraWrite }) {
  home = home || os.homedir();
  const tmp = os.tmpdir();
  const rw = ["/dev/null", "/dev/tty", "/dev/pts", "/dev/ptmx", "/dev/shm", tmp];
  if (tmp !== "/tmp") rw.push("/tmp");
  if (writable && cwd) rw.push(path.resolve(cwd));
  for (const r of HOME_WRITE) rw.push(path.join(home, r));
  for (const x of extraWrite || []) if (x) rw.push(path.resolve(x));
  const deny = HOME_DENY.map((r) => path.join(home, r));
  return { ro: ["/"], rw, deny };
}

// Rewrite a spawn so it runs under the sandbox. Returns { cmd, args, env }.
function wrap(cmd, args, env, pol) {
  const e = Object.assign({}, env || process.env, { NEXUS_LL_POLICY: JSON.stringify(pol) });
  return { cmd: "python3", args: ["-I", LAUNCHER, "--", cmd].concat(args || []), env: e };
}

// One call for the host: decide + probe + wrap. Returns { cmd, args, env, sandbox }
// where sandbox is null (not sandboxed; .why says why when it was wanted) or
// { reason, writable, abi }.
function prepare(cmd, args, env, opts) {
  opts = opts || {};
  const d = decide(opts.setting, opts);
  if (!d) return { cmd, args, env, sandbox: null };
  const pr = probe();
  if (!pr.ok) return { cmd, args, env, sandbox: null, why: pr.why };
  const w = wrap(cmd, args, env, policy({ cwd: opts.cwd, home: opts.home, writable: d.writable, extraWrite: opts.extraWrite }));
  return Object.assign(w, { sandbox: { reason: d.reason, writable: d.writable, abi: pr.abi } });
}

module.exports = { probe, decide, policy, wrap, prepare, normMode, MODES, HOME_DENY, HOME_WRITE, LAUNCHER };
