"use strict";
// ACP engine transport (lib/nexus/acp-client.js) against a scripted fake agent, and
// the Landlock engine sandbox (lib/nexus/sandbox.js + landlock.py) for real.
const fs = require("fs");
const os = require("os");
const path = require("path");
const A = require("../lib/nexus/acp-client");
const S = require("../lib/nexus/sandbox");
const Jail = require("../lib/nexus/jail");

let pass = 0, fail = 0;
const ok = (name, cond) => { if (cond) pass++; else { fail++; console.log("  FAIL " + name); } };
const AGENT = path.join(__dirname, "fixtures", "fake-acp-agent.js");
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "nx-acp-"));
const proj = path.join(tmp, "proj"); fs.mkdirSync(proj);
fs.writeFileSync(path.join(tmp, "secret.txt"), "TOPSECRET");
const logf = path.join(tmp, "agent.log");
const reqs = () => { try { return fs.readFileSync(logf, "utf8").trim().split("\n").filter(Boolean).map((l) => JSON.parse(l)); } catch (_) { return []; } };

const turn = (script, extra) => {
  try { fs.unlinkSync(logf); } catch (_) {}
  const seen = { text: "", thought: "", tools: [], updates: [], writes: [], asked: [] };
  const o = Object.assign({
    cmd: process.execPath, args: [AGENT], cwd: proj,
    env: Object.assign({}, process.env, { FAKE_ACP_SCRIPT: script, FAKE_ACP_LOG: logf }, (extra && extra.env) || {}),
    prompt: "do it", jail: (p) => Jail.assertInJail(p, proj),
    onText: (t) => { seen.text += t; }, onThought: (t) => { seen.thought += t; },
    onTool: (tc) => seen.tools.push(Object.assign({}, tc)), onToolUpdate: (tc) => seen.updates.push(Object.assign({}, tc)),
    onWrite: (p) => seen.writes.push(p),
    decide: async (tc, opts) => { seen.asked.push({ tc, opts }); return "allow"; },
  }, Object.assign({}, extra || {}, { env: undefined }));
  o.env = Object.assign({}, process.env, { FAKE_ACP_SCRIPT: script, FAKE_ACP_LOG: logf }, (extra && extra.env) || {}); // extra.env adds to the base env instead of replacing it
  return A.runTurn(o).then((r) => Object.assign(r, { seen }));
};

(async () => {
  // ---- pure helpers ----
  ok("pickOption: allow prefers allow_once, reject prefers reject_once, falls back within polarity",
    A.pickOption([{ optionId: "a", kind: "allow_always" }, { optionId: "o", kind: "allow_once" }, { optionId: "r", kind: "reject_once" }], "allow") === "o"
    && A.pickOption([{ optionId: "a", kind: "allow_always" }], "allow") === "a"
    && A.pickOption([{ optionId: "a", kind: "allow_once" }], "reject") === null
    && A.pickOption([{ optionId: "r", kind: "reject_always" }], "reject") === "r");
  const ms = A.toAcpMcpServers({ nexus: { command: "node", args: ["x.js"], env: { K: "v" } }, web: { url: "https://h/mcp" }, sse: { type: "sse", url: "https://h/sse" } }, { mcpCapabilities: { http: true } });
  ok("toAcpMcpServers: stdio servers get name/value env pairs; http only when the agent supports it", ms.length === 2 && ms[0].env[0].name === "K" && ms[0].env[0].value === "v" && ms[1].type === "http" && !ms.some((s) => s.type === "sse"));
  ok("policyFor: bypass allows everything", A.policyFor(3, { kind: "delete" }).decision === "allow");
  ok("policyFor: plan rejects edit/execute/delete/move/other and allows read/search/think/fetch",
    ["edit", "execute", "delete", "move", "other", "switch_mode"].every((k) => A.policyFor(2, { kind: k }).decision === "reject")
    && ["read", "search", "think", "fetch"].every((k) => A.policyFor(2, { kind: k }).decision === "allow"));
  ok("policyFor: the Nexus ask bridge passes even in plan mode", A.policyFor(2, { kind: "other", title: "nexus_ask_user" }).decision === "allow" && A.policyFor(2, { kind: "other", title: "mcp__nexus__ask_user" }).decision === "allow");
  ok("policyFor: a guard/permission deny rejects in normal and auto-accept", A.policyFor(0, { kind: "execute" }, () => ({ deny: "rm -rf" })).decision === "reject" && A.policyFor(1, { kind: "execute" }, () => ({ deny: "x" })).decision === "reject");
  ok("policyFor: a guard warning asks in normal mode, passes in auto-accept", A.policyFor(0, { kind: "execute" }, () => ({ warn: "w" })).decision === "ask" && A.policyFor(1, { kind: "execute" }, () => ({ warn: "w" })).decision === "allow");
  ok("policyFor: reaching outside the project asks in normal AND auto-accept, is rejected in plan, allowed in bypass",
    A.policyFor(0, { kind: "other" }, () => ({ ask: "o" })).decision === "ask" && A.policyFor(1, { kind: "edit" }, () => ({ ask: "o" })).decision === "ask"
    && A.policyFor(2, { kind: "other", title: "external_directory" }, () => ({ ask: "o" })).decision === "reject" && A.policyFor(3, { kind: "other" }, () => ({ ask: "o" })).decision === "allow");
  ok("commandOf: reads command/cmd/script and arrays", A.commandOf({ input: { command: "ls -la" } }) === "ls -la" && A.commandOf({ input: { cmd: ["git", "push"] } }) === "git push" && A.commandOf({ kind: "execute", title: "rm x" }) === "rm x" && A.commandOf({ kind: "read", input: {} }) === "");
  ok("contentText: text and diff content", /hello/.test(A.contentText([{ type: "content", content: { type: "text", text: "hello" } }])) && /\+b/.test(A.contentText([{ type: "diff", path: "f", oldText: "a", newText: "b" }])));

  // ---- end to end with the fake agent ----
  let r = await turn("edit");
  ok("edit: handshake, prompt and end_turn succeed", r.ok && r.stopReason === "end_turn" && !r.acpFailed);
  ok("edit: streamed text and thinking reach the host", r.seen.text === "applied" && r.seen.thought === "thinking" && r.output === "applied");
  ok("edit: the tool call and its update reach the host with kind/status", r.seen.tools.length === 1 && r.seen.tools[0].kind === "edit" && r.seen.updates.some((u) => u.status === "completed"));
  ok("edit: the permission request goes to decide() with the agent's options", r.seen.asked.length === 1 && r.seen.asked[0].tc.kind === "edit" && r.seen.asked[0].opts.length === 3);
  ok("edit: the write lands through the jailed client fs and is reported", fs.readFileSync(path.join(proj, "note.txt"), "utf8") === "hello from acp" && r.seen.writes.length === 1);
  ok("edit: real token usage comes back from the prompt result", r.usage && r.usage.inputTokens === 120 && r.usage.outputTokens === 7 && r.usage.cachedReadTokens === 40);
  const init = reqs().find((m) => m.method === "initialize");
  ok("initialize advertises protocol 1 and client fs (jail present), no terminal", init && init.params.protocolVersion === 1 && init.params.clientCapabilities.fs.writeTextFile === true && init.params.clientCapabilities.terminal === false);
  fs.unlinkSync(path.join(proj, "note.txt"));

  r = await turn("edit", { decide: async () => "reject" });
  ok("reject: a rejected edit is never written", !fs.existsSync(path.join(proj, "note.txt")) && r.seen.text === "skipped");
  const permReply = reqs().find((m) => m.id && m.result && m.result.outcome);
  ok("reject: the reply selects the reject_once option", permReply && permReply.result.outcome.optionId === "no1");

  r = await turn("edit", { plan: true, decide: async () => "allow" });
  ok("plan: plan mode is selected through session/set_config_option", reqs().some((m) => m.method === "session/set_config_option" && m.params.configId === "mode" && m.params.value === "plan"));
  ok("plan: client fs refuses writes even when a decision allowed them", !fs.existsSync(path.join(proj, "note.txt")) && /write failed: plan mode/.test(r.seen.text));

  r = await turn("edit", { model: "b" });
  ok("model: a model the agent offers is selected", reqs().some((m) => m.method === "session/set_config_option" && m.params.configId === "model" && m.params.value === "b"));
  r = await turn("edit", { model: "zzz" });
  ok("model: a model the agent does not offer is not sent", !reqs().some((m) => m.method === "session/set_config_option" && m.params.configId === "model"));
  fs.rmSync(path.join(proj, "note.txt"), { force: true });

  r = await turn("outside");
  ok("jail: the client fs refuses a read outside the project", /refused/.test(r.seen.text) && !/TOPSECRET/.test(r.seen.text));

  r = await turn("exec", { env: { FAKE_ACP_CMD: "git push --force" }, decide: async (tc) => (A.commandOf(tc) === "git push --force" ? "reject" : "allow") });
  ok("exec: the execute call's command reaches decide() and a reject stops it", r.tools[0] && A.commandOf(r.tools[0]) === "git push --force" && r.seen.text === "skipped" && r.tools[0].status === "failed");

  const ctl = { kids: [] };
  const pr = turn("slow", { ctl });
  await new Promise((res) => setTimeout(res, 400));
  for (const k of ctl.kids) k();
  r = await pr;
  ok("cancel: ctl kill sends session/cancel and the turn ends interrupted", r.interrupted && !r.ok && r.stopReason === "cancelled" && reqs().some((m) => m.method === "session/cancel"));

  r = await turn("badinit");
  ok("badinit: a failed handshake is flagged acpFailed so the host falls back", !r.ok && r.acpFailed === true);
  r = await A.runTurn({ cmd: path.join(tmp, "no-such-binary"), args: [], cwd: proj, prompt: "x" });
  ok("spawn error: a missing binary is acpFailed, never a throw", !r.ok && r.acpFailed === true);

  // ---- sandbox ----
  ok("sandbox.decide: off never, always everywhere (read-only in plan), auto only plan or untrusted",
    S.decide("off", { plan: true, untrusted: true }) === null
    && S.decide("always", {}).writable === true && S.decide("always", { plan: true }).writable === false
    && S.decide("auto", {}) === null && S.decide("auto", { plan: true }).writable === false && S.decide("auto", { untrusted: true }).writable === true
    && S.decide("", { plan: true }).writable === false && S.normMode("on") === "always" && S.normMode("bogus") === "");
  const fakeHome = path.join(tmp, "home"); fs.mkdirSync(path.join(fakeHome, ".ssh"), { recursive: true });
  const pol = S.policy({ cwd: proj, home: fakeHome, writable: true });
  ok("sandbox.policy: reads /, writes the project + tmp + engine state, denies ~/.ssh and tokens",
    pol.ro[0] === "/" && pol.rw.includes(proj) && pol.rw.includes(os.tmpdir()) && pol.rw.includes(path.join(fakeHome, ".claude"))
    && pol.deny.includes(path.join(fakeHome, ".ssh")) && pol.deny.includes(path.join(fakeHome, ".config", "gh")) && pol.deny.includes(path.join(fakeHome, ".bash_history")));
  ok("sandbox.policy: plan mode leaves the project read-only", !S.policy({ cwd: proj, home: fakeHome, writable: false }).rw.includes(proj));
  ok("sandbox.prepare: off returns the spawn unchanged", (() => { const p = S.prepare("x", ["a"], {}, { setting: "off", plan: true }); return p.cmd === "x" && p.args[0] === "a" && p.sandbox === null; })());

  const pb = S.probe();
  if (!pb.ok) console.log("  (skipping live sandbox checks: " + pb.why + ")");
  else {
    fs.writeFileSync(path.join(fakeHome, ".ssh", "id_ed25519"), "PRIVATE");
    const outside = path.join(fakeHome, "outside.txt");
    // the fake home lives under the (writable) temp dir, so this also proves a denied path
    // inside a granted directory stays denied
    const run = (writable, target) => {
      const w = S.wrap(process.execPath, [AGENT], Object.assign({}, process.env, { FAKE_ACP_SCRIPT: "sandbox", FAKE_ACP_PATH: target, FAKE_ACP_SECRET: path.join(fakeHome, ".ssh", "id_ed25519") }), Object.assign(S.policy({ cwd: proj, home: fakeHome, writable }), { rw: S.policy({ cwd: proj, home: fakeHome, writable }).rw.filter((p) => p !== os.tmpdir() && p !== "/tmp") }));
      return A.runTurn({ cmd: w.cmd, args: w.args, env: w.env, cwd: proj, prompt: "x" });
    };
    r = await run(true, path.join(proj, "in.txt"));
    ok("sandbox live: the engine runs under Landlock and can write the project", r.ok && /^wrote /.test(r.output) && /landlock-\d/.test(r.output));
    ok("sandbox live: ~/.ssh is unreadable even though its parent is readable", /secret-EACCES/.test(r.output));
    r = await run(true, outside);
    ok("sandbox live: a write outside the project is denied", /^denied EACCES/.test(r.output) && !fs.existsSync(outside));
    r = await run(false, path.join(proj, "plan.txt"));
    ok("sandbox live: plan mode cannot write the project", /^denied EACCES/.test(r.output) && !fs.existsSync(path.join(proj, "plan.txt")));
    const { coderShell } = require("../lib/nexus/shell-run");
    const cs = await coderShell("echo a > cs.txt; cat " + path.join(fakeHome, ".ssh", "id_ed25519") + "; echo b > " + path.join(fakeHome, "cs-out.txt") + "; echo end", proj, { sandbox: { setting: "always", cwd: proj, home: fakeHome } });
    ok("sandbox live: the local agent's run_command (coderShell) runs fenced: project write ok, secret and outside write denied", /end/.test(cs.output) && fs.existsSync(path.join(proj, "cs.txt")) && !/PRIVATE/.test(cs.output) && !fs.existsSync(path.join(fakeHome, "cs-out.txt")));
    const pp = S.prepare("node", ["-v"], process.env, { setting: "auto", plan: true, cwd: proj, home: fakeHome });
    ok("sandbox.prepare: auto + plan wraps the spawn in the launcher", pp.cmd === "python3" && pp.args.includes(S.LAUNCHER) && pp.sandbox && pp.sandbox.writable === false && JSON.parse(pp.env.NEXUS_LL_POLICY).deny.length > 10);
  }

  // ---- settings + host wiring ----
  const NS = require("../lib/cli/nexus-settings");
  const sh = path.join(tmp, "sh"); fs.mkdirSync(sh);
  let rs = NS.resolve(sh, {});
  ok("settings: acp and sandbox default to auto", rs.value.acp === "auto" && rs.value.sandbox === "auto");
  rs = NS.resolve(sh, { NEXUS_ACP: "off", NEXUS_SANDBOX: "on" });
  ok("settings: NEXUS_ACP=off and NEXUS_SANDBOX=on (= always) pin one launch", rs.value.acp === "off" && rs.value.sandbox === "always" && rs.source.sandbox === "env");
  rs = NS.resolve(sh, { NEXUS_SANDBOX: "bogus" });
  ok("settings: an invalid NEXUS_SANDBOX is ignored", rs.value.sandbox === "auto");
  const src = fs.readFileSync(path.join(__dirname, "..", "darknode.js"), "utf8");
  ok("host: claude turns and classic engine turns carry the sandbox options", /disallow: mode === 2 \? READONLY_TOOLS : undefined, sandbox: sbxOpts\(\) \|\| undefined \}\);/.test(src) && /\{ sandbox: sbxOpts\(\) \|\| undefined, onSandbox \}\)\)\.then\(\(res\) =>/.test(src));
  ok("host: runEngineTask and runClaudeStream wrap the spawn through Sandbox.prepare", (src.match(/Sandbox\.prepare\(/g) || []).length >= 3);
  ok("host: ACP is skipped when /acp is off or the engine failed its handshake this session, and falls back to the classic turn", /if \(acpMode === "off" \|\| !m \|\| !m\.acp \|\| acpBroken\[eng\]\) return null;/.test(src) && /if \(acpL\) acpEngineTurn\(acpL, mdl, classicTurn,/.test(src) && /return fallback\(\);/.test(src));
  ok("host: an engine permission ask holds the hang watchdog while the user decides", /engineWaits\.n\+\+;[\s\S]{0,200}askUser\([\s\S]{0,900}finally \{ engineWaits\.n--; \}/.test(src));
  ok("host: a non-read tool call touching a path outside the project (or opencode's external_directory ask) asks the user", /if \(outside \|\| tc\.title === "external_directory"\) return \{ ask:/.test(src));
  ok("host: the opencode permission overlay is skipped in bypass mode and when the user set OPENCODE_CONFIG_CONTENT", /!process\.env\.OPENCODE_CONFIG_CONTENT && mode !== 3/.test(src));

  try { fs.rmSync(tmp, { recursive: true, force: true }); } catch (_) {}
  console.log("acp-sandbox: " + pass + " passed, " + fail + " failed");
  if (fail) process.exit(1);
})();
