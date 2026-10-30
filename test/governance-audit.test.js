"use strict";
// Governance + local-model audit (lib/governance/{authorization,engagement-gate,default-guard,rbac,
// audit-log,identity,usage}.js, lib/nexus/{tool-gates,ollama}.js): scope checks that let a target
// through, fail-open paths, gate/exec argument mismatches, a racy hash chain, and a model call that
// hung forever on a dropped connection.
const fs = require("fs");
const os = require("os");
const path = require("path");
const http = require("http");
const { spawn } = require("child_process");

let pass = 0, fail = 0;
const ok = (name, cond) => { if (cond) pass++; else { fail++; console.log("  \x1b[31mFAIL\x1b[0m " + name); } };
const group = (t) => console.log("\n\x1b[1m" + t + "\x1b[0m");

const T = fs.mkdtempSync(path.join(os.tmpdir(), "nx-gov-audit-"));
process.env.DARKNODE_HOME = path.join(T, "dkhome");
const A = require("../lib/governance/authorization");
const G = require("../lib/governance/engagement-gate");
const DG = require("../lib/governance/default-guard");
const TG = require("../lib/nexus/tool-gates");
const RB = require("../lib/governance/rbac");
const AL = require("../lib/governance/audit-log");
const U = require("../lib/governance/usage");
const { resolveOperator } = require("../lib/governance/identity");

const key = A.generateAuthorizerKey();
const record = (over) => Object.assign({
  version: 1, engagement: "eng-audit", client: { legalName: "Client", signatory: { name: "S", title: "CISO" } },
  agreement: { ref: "SOW-1", sha256: "a".repeat(64), signedAt: "2020-01-01T00:00:00Z" }, assetOwnership: { confirmed: true },
  window: { notBefore: "2020-01-01T00:00:00Z", notAfter: "2099-01-01T00:00:00Z" }, emergencyContact: { name: "N", channel: "phone" },
  allowedClasses: ["recon", "scan", "vuln-scan"], scope: { inScope: ["a.example.com", "*.0.0-255"] },
}, over || {});
const env = A.signRecord(record(), key.privatePem, "k1");
const trusted = { k1: key.publicPem };
const evalT = (targets, extra) => A.evaluate(Object.assign({ envelope: env, trustedKeys: trusted, class: "scan", targets }, extra || {}));

(async () => {
  group("authorization scope + window");
  ok("in-scope host still allowed", evalT(["A.Example.com."]).allow);
  ok("an unparseable evaluation time fails closed (NaN skipped every window check)", evalT(["a.example.com"], { now: "garbage" }).code === "BAD_CLOCK");
  ok("an expired window still denies", evalT(["a.example.com"], { now: "2100-01-01T00:00:00Z" }).code === "AFTER_WINDOW");
  ok("an nmap range (numeric last label) is not a hostname a wildcard can cover", evalT(["10.0.0.0-255"]).code === "BAD_TARGET");
  ok("a real hostname with digits/dashes still parses", A.parseTarget("host-1.example.com").kind === "host");

  group("engagement gate argv grammar");
  const nu = (argv) => G.parseInvocation("nuclei", argv);
  ok("nuclei -target=evil.com is a TARGET, not a -t template value", (nu(["-u", "a.example.com", "-target=evil.com"]).targets || []).includes("evil.com"));
  ok("nuclei -u=x form is a target too", (nu(["-u=evil.com"]).targets || []).includes("evil.com"));
  ok("nuclei comma-separated -u is split into each target", JSON.stringify(nu(["-u", "http://a.example.com/x,http://evil.com"]).targets) === JSON.stringify(["http://a.example.com/x", "http://evil.com"]));
  ok("unknown -flag=value is refused, not read as an attached short value", !!nu(["-tx=evil.com", "-u", "a.example.com"]).error);
  ok("nmap attached short values still work", JSON.stringify(G.parseInvocation("nmap", ["-T4", "-p80,443", "a.example.com"]).targets) === JSON.stringify(["a.example.com"]));
  ok("a boolean flag given =value is refused", !!nu(["-silent=true", "-u", "a.example.com"]).error);

  group("engagement gate revocation (presence = hard stop)");
  fs.mkdirSync(process.env.DARKNODE_HOME, { recursive: true });
  fs.writeFileSync(path.join(process.env.DARKNODE_HOME, "authorizers.json"), JSON.stringify(trusted));
  ok("install the signed authorization", G.installEnvelope(env).ok);
  ok("allowed before revocation", G.authorize({ engagement: "eng-audit", tool: "dns", argv: ["a.example.com"] }).allow);
  const rf = path.join(G.engDir("eng-audit"), "REVOKED.json");
  for (const body of ["", "{not json", "null", "false"]) {
    fs.writeFileSync(rf, body);
    ok("a REVOKED.json of " + JSON.stringify(body) + " still revokes", G.authorize({ engagement: "eng-audit", tool: "dns", argv: ["a.example.com"] }).code === "REVOKED");
  }
  fs.unlinkSync(rf);
  ok("removing it restores access", G.authorize({ engagement: "eng-audit", tool: "dns", argv: ["a.example.com"] }).allow);
  ok("gate audit chain verifies", G.auditVerifyFile(G.auditFile("eng-audit")).ok);

  group("default guard (non-engagement active commands)");
  ok("nmap 127.0.0.1/0 (the whole internet) is not local", !DG.isLocalTarget("127.0.0.1/0"));
  ok("a range that leaves the private block is not local", !DG.isLocalTarget("10.0.0.0/7"));
  ok("an all-private range is local", DG.isLocalTarget("10.1.0.0/16") && DG.isLocalTarget("127.0.0.1/8"));
  ok("an IPv6 CIDR is not local", !DG.isLocalTarget("::1/0"));
  ok("http://evil.com\\@127.0.0.1 is evil.com (URL() reads \\ as /)", !DG.isLocalTarget("http://evil.com\\@127.0.0.1/") && new URL("http://evil.com\\@127.0.0.1/").hostname === "evil.com");
  ok("plain local targets still local", DG.isLocalTarget("http://localhost:3000/x") && DG.isLocalTarget("192.168.1.5"));
  ok("guardActive refuses the /0 range without --authorized", !DG.guardActive("nmap", "127.0.0.1/0").allow);

  group("tool gates: the gate sees the command that runs");
  ok("write_stdin: the gate sees `input`, not a decoy `command`", TG.execCommand("write_stdin", { command: "ls", input: "rm -rf ~" }) === "rm -rf ~");
  ok("write_stdin falls back to `text`", TG.execCommand("write_stdin", { text: "echo hi" }) === "echo hi");
  ok("bisect {test:false, command:rm} shows the rm (tools pick by truthiness)", TG.execCommand("bisect", { test: false, command: "rm -rf ~" }) === "rm -rf ~");
  ok("shrink {test:0, command:rm} shows the rm", TG.execCommand("shrink", { test: 0, command: "rm -rf ~" }) === "rm -rf ~");
  ok("bisect test still wins over command", TG.execCommand("bisect", { test: "rm -rf ~", command: "true" }) === "rm -rf ~");
  ok("run_command command; no command -> undefined", TG.execCommand("run_command", { command: "ls" }) === "ls" && TG.execCommand("run_command", {}) === undefined);

  group("rbac");
  let threw = false, r;
  try { r = RB.checkPermission("constructor", "file:read"); } catch (_) { threw = true; }
  ok("a prototype-key role is unknown, not a crash", !threw && r && r.allowed === false);
  threw = false; try { r = RB.checkPermission("__proto__", "file:read"); } catch (_) { threw = true; }
  ok("__proto__ role denied", !threw && r.allowed === false);
  ok("validateRule rejects a prototype-key role", RB.validateRule({ id: "x", effect: "allow", roles: ["toString"], actions: ["*"], resources: ["*"] }).length > 0);
  ok("case/whitespace role variants are unknown", !RB.checkPermission("Admin", "file:read").allowed && !RB.checkPermission(" admin", "file:read").allowed);
  const pol = RB.createPolicy([
    { id: "ws", effect: "allow", roles: ["*"], actions: ["*"], resources: ["/workspace/*"], priority: 10 },
    { id: "etc", effect: "deny", roles: ["*"], actions: ["*"], resources: ["/etc/*"], priority: 20 },
  ]);
  ok("/workspace/../etc/shadow is denied by the /etc rule, not allowed by /workspace", RB.authorize("analyst", "file:read", "/workspace/../etc/shadow", pol).allowed === false);
  ok("/etc//./shadow still hits the deny", RB.authorize("analyst", "file:read", "/etc//./shadow", pol).allowed === false);
  ok("/workspace/a.txt allowed", RB.authorize("analyst", "file:read", "/workspace/a.txt", pol).allowed === true);

  group("audit-log hash chain");
  const D = path.join(T, "proj");
  fs.mkdirSync(D);
  AL.createAuditLog(D);
  const worker = path.join(T, "w.js");
  fs.writeFileSync(worker, "const AL=require(" + JSON.stringify(path.resolve(__dirname, "../lib/governance/audit-log")) + ");for(let i=0;i<40;i++)AL.logAction(process.argv[2],{type:'TOOL_INVOKE',tool:'t'+i});");
  await Promise.all([0, 1, 2].map(() => new Promise((res) => spawn(process.execPath, [worker, D], { stdio: "ignore" }).on("close", res))));
  const v = AL.verifyIntegrity(D);
  ok("3 concurrent writers x 40 appends keep the chain intact", v.valid && v.entries === 121);
  fs.writeFileSync(path.join(D, ".nexus", "audit-meta.json"), JSON.stringify({ seq: 1, lastHash: "0".repeat(64) }));
  AL.logAction(D, { type: "TOOL_INVOKE", tool: "after-stale-meta" });
  ok("a stale meta sidecar no longer forks the chain (tail is the truth)", AL.verifyIntegrity(D).valid);
  AL.logAction(D, { type: "TOOL_INVOKE", tool: "x", detail: { note: "line1\n{\"forged\":true}" } });
  ok("newline in a detail stays one JSONL line", AL.verifyIntegrity(D).valid);
  const lp = path.join(D, ".nexus", "audit.jsonl");
  const lines = fs.readFileSync(lp, "utf8").trim().split("\n");
  fs.writeFileSync(lp, [lines[0], lines[2], lines[1]].concat(lines.slice(3)).join("\n") + "\n");
  ok("reordering is detected", !AL.verifyIntegrity(D).valid);
  fs.writeFileSync(lp, lines.map((l, i) => i === 5 ? l.replace("TOOL_INVOKE", "TOOL_RESULT") : l).join("\n") + "\n");
  ok("an edited entry is detected", AL.verifyIntegrity(D).errors.some((e) => e.type === "hash_mismatch"));
  fs.writeFileSync(lp, lines.slice(0, -2).join("\n") + "\n");
  ok("tail truncation is caught by the meta cross-check", AL.verifyIntegrity(D).errors.some((e) => e.type === "meta_desync"));

  group("identity + usage");
  const id = resolveOperator({ env: { DARKNODE_OPERATOR: "alice\n[ALLOW] root\x1b[31m", DARKNODE_TEAM: "red\rteam" }, cwd: T });
  ok("control chars are stripped from operator/team", id.operator === "alice[ALLOW] root[31m" && id.team === "redteam");
  ok("an operator that is only control chars falls through to the OS user", resolveOperator({ env: { DARKNODE_OPERATOR: "\n\x1b" }, cwd: T }).source !== "sso-env");
  ok("operator is length-capped", resolveOperator({ env: { DARKNODE_OPERATOR: "x".repeat(5000) }, cwd: T }).operator.length === 128);
  const s = U.summarize([{ cost: "0.5", inTok: "100" }, { cost: 1, inTok: 10 }, { cost: NaN }, { cost: Infinity }]);
  ok("string/NaN/Infinity ledger numbers count as 0 (no string concat, no $NaN)", s.cost === 1 && s.inTok === 10 && !/NaN/.test(U.renderReport(s)));
  const sv = U.analyzeSavings([{ cost: 2, engine: "claude", model: "opus" }], { mechanicalFraction: NaN });
  ok("a NaN mechanicalFraction falls back to the default", sv.localFrac === 0.3 && Number.isFinite(sv.totalSavable));

  group("ollama client: a dropped connection mid-body");
  let hits = 0;
  const srv = http.createServer((q, res) => {
    hits++;
    res.writeHead(200, { "content-type": "application/json" });
    if (hits === 1) { res.write('{"message":{"con'); setTimeout(() => res.socket.destroy(), 30); }
    else res.end(JSON.stringify({ message: { content: "ok" } }));
  });
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  delete process.env.DARKNODE_API_BASE; delete process.env.OPENAI_BASE_URL; delete process.env.OPENAI_API_BASE;
  process.env.OLLAMA_HOST = "127.0.0.1:" + srv.address().port;
  const O = require("../lib/nexus/ollama");
  const race = (p) => Promise.race([p.then((x) => ({ x }), (e) => ({ e })), new Promise((r) => setTimeout(() => r("HUNG"), 15000))]);
  const got = await race(O.ollamaChat("m", [{ role: "user", content: "x" }], null));
  ok("a body cut mid-stream rejects as retryable and the retry succeeds (it used to hang forever)", got !== "HUNG" && got.x === "ok" && hits === 2);
  hits = 0;
  const ac = new AbortController(); setTimeout(() => ac.abort(), 10);
  const ab = await race(O.ollamaChat("m", [{ role: "user", content: "x" }], null, ac.signal));
  ok("an abort still reports the abort, not a retried drop", ab !== "HUNG" && ab.e && /abort/i.test(ab.e.message));
  srv.close();

  {
    const DG = require("../lib/governance/default-guard");
    const g = (c, a) => DG.guardArgs(c, a, {}).allow;
    ok("default guard checks EVERY target: nmap 127.0.0.1 evil.com is refused", !g("nmap", ["127.0.0.1", "evil.com"]));
    ok("default guard: nuclei localhost -u evil.com is refused", !g("nuclei", ["localhost", "-u", "evil.com"]));
    ok("default guard: a comma list hiding a remote URL is refused", !g("nuclei", ["-u", "http://a.local/x,http://evil.com"]));
    ok("default guard: port specs and output files are not targets", g("scan", ["127.0.0.1", "80,443"]) && g("nmap", ["10.0.0.5", "-p", "1-1000", "-oN", "out.txt"]));
    ok("default guard: --authorized still allows a remote target", DG.guardArgs("nmap", ["127.0.0.1", "evil.com"], { authorized: true }).allow);
  }

  fs.rmSync(T, { recursive: true, force: true });
  console.log("\n" + (fail ? "\x1b[31m" : "\x1b[32m") + pass + " passed, " + fail + " failed\x1b[0m  (governance + local-model audit)");
  process.exit(fail ? 1 : 0);
})();
