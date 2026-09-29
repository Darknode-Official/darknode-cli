"use strict";
// Authorization & scope gate — unit + integration suite. `npm test` runs it after test/run.js.
const fs = require("fs"), os = require("os"), path = require("path"), cp = require("child_process");
const A = require("../lib/governance/authorization");

let pass = 0, fail = 0;
const ok = (name, cond) => { if (cond) pass++; else { fail++; console.log("  \x1b[31mFAIL\x1b[0m " + name); } };
const eq = (name, a, b) => ok(name + "  (" + JSON.stringify(a) + " === " + JSON.stringify(b) + ")", JSON.stringify(a) === JSON.stringify(b));
const group = (t) => console.log("\n\x1b[1m" + t + "\x1b[0m");

// temp store, so the suite never touches a real ~/.darknode
const HOME = fs.mkdtempSync(path.join(os.tmpdir(), "darknode-authz-"));
process.env.DARKNODE_HOME = HOME; process.env.DARKNODE_OPERATOR = "test-operator";
const G = require("../lib/governance/engagement-gate");

const key = A.generateAuthorizerKey(), other = A.generateAuthorizerKey();
const TRUST = { "auth-1": key.publicPem };
const NOW = new Date("2026-10-01T12:00:00Z");
const mk = (over) => Object.assign({
  version: 1, engagement: "acme-2026-q4",
  client: { legalName: "Acme Corp", signatory: { name: "J. Doe", title: "CISO", email: "j@acme.example" } },
  agreement: { ref: "MSA-2026-014", sha256: "a".repeat(64), signedAt: "2026-09-20T09:00:00Z" },
  assetOwnership: { confirmed: true, thirdPartyConsents: [] },
  window: { notBefore: "2026-09-30T00:00:00Z", notAfter: "2026-10-15T00:00:00Z" },
  emergencyContact: { name: "SOC", channel: "+1-555-0100" },
  allowedClasses: ["recon", "scan"],
  scope: { inScope: ["app.example.com", "*.corp.example.com", "203.0.113.0/28", "https://api.example.com/v1"], outOfScope: ["admin.corp.example.com", "203.0.113.9"] },
}, over || {});
const sign = (rec, k, id) => A.signRecord(rec, (k || key).privatePem, id || "auth-1");
const ev = (env, targets, over) => A.evaluate(Object.assign({ envelope: env, trustedKeys: TRUST, revoked: null, now: NOW, class: "scan", targets }, over || {}));

group("target + scope-entry parsing");
eq("ip", A.parseTarget("10.0.0.5").kind, "ip");
eq("decimal-obfuscated IP normalised", A.parseTarget("2130706433").value, "127.0.0.1");
eq("hex-obfuscated IP normalised", A.parseTarget("0x7f.1").value, "127.0.0.1");
eq("octal-obfuscated IP normalised", A.parseTarget("0177.0.0.1").value, "127.0.0.1");
eq("legacy shorthand IP normalised the way a resolver reads it", A.parseTarget("1.2.3").value, "1.2.0.3");
eq("host:port -> host", A.parseTarget("App.Example.com:8443").value, "app.example.com");
eq("url -> host + path", [A.parseTarget("https://app.example.com/x/y").value, A.parseTarget("https://app.example.com/x/y").url.path], ["app.example.com", "/x/y"]);
eq("trailing dot stripped", A.parseTarget("app.example.com.").value, "app.example.com");
eq("cidr normalised to network", A.parseTarget("10.0.0.7/24").value, "10.0.0.0/24");
for (const bad of ["", "*.example.com", "[::1]", "::1", "http://user:pw@a.example.com", "ftp://a.example.com", "a b", "10.0.0.1-50/x", "999.1.1.1", "host/path"])
  ok("bad target rejected: " + JSON.stringify(bad), !!A.parseTarget(bad).error);
eq("wildcard entry", A.parseScopeEntry("*.corp.example.com").kind, "wildcard");
for (const bad of ["*.com", "*", "0.0.0.0/0", "10.0.0.0/8", "10.0.0.0/15", "*.*.example.com", "a*.example.com", ""])
  ok("bad scope entry rejected: " + JSON.stringify(bad), !!A.parseScopeEntry(bad).error);
ok("/16 is the broadest allowed", !A.parseScopeEntry("10.0.0.0/16").error);

group("covers / overlaps");
const T = (s) => A.parseTarget(s), E = (s) => A.parseScopeEntry(s);
ok("wildcard covers subdomain", A.covers(E("*.corp.example.com"), T("a.b.corp.example.com")));
ok("wildcard does NOT cover apex", !A.covers(E("*.corp.example.com"), T("corp.example.com")));
ok("wildcard does not cover look-alike", !A.covers(E("*.corp.example.com"), T("evilcorp.example.com")) && !A.covers(E("*.corp.example.com"), T("corp.example.com.evil.net")));
ok("host entry is exact (no subdomains)", A.covers(E("app.example.com"), T("app.example.com")) && !A.covers(E("app.example.com"), T("x.app.example.com")));
ok("domain scope does not cover its IP", !A.covers(E("app.example.com"), T("203.0.113.1")));
ok("ip scope does not cover a hostname", !A.covers(E("203.0.113.1"), T("app.example.com")));
ok("cidr covers ip inside, not outside", A.covers(E("203.0.113.0/28"), T("203.0.113.15")) && !A.covers(E("203.0.113.0/28"), T("203.0.113.16")));
ok("cidr covers a contained sub-range", A.covers(E("203.0.113.0/28"), T("203.0.113.8/29")));
ok("cidr does NOT cover a wider / partially-outside range", !A.covers(E("203.0.113.0/28"), T("203.0.113.0/24")) && !A.covers(E("203.0.113.0/28"), T("203.0.113.16/28")));
ok("url entry: path-prefix scoped", A.covers(E("https://api.example.com/v1"), T("https://api.example.com/v1/users")) && !A.covers(E("https://api.example.com/v1"), T("https://api.example.com/v10")) && !A.covers(E("https://api.example.com/v1"), T("https://api.example.com/admin")));
ok("url entry: bare host is not the whole site", !A.covers(E("https://api.example.com/v1"), T("api.example.com")));
ok("excluded host also excludes its subdomains", A.overlaps(E("admin.corp.example.com"), T("x.admin.corp.example.com")));
ok("excluded ip overlaps a range containing it", A.overlaps(E("203.0.113.9"), T("203.0.113.8/29")) && !A.overlaps(E("203.0.113.9"), T("203.0.113.0/30")));

group("record validation");
ok("good record validates", A.validateRecord(mk()).ok);
for (const [name, rec] of [
  ["missing agreement hash", mk({ agreement: { ref: "x", sha256: "nope", signedAt: "2026-09-20T09:00:00Z" } })],
  ["ownership not attested", mk({ assetOwnership: { confirmed: false } })],
  ["no signatory", mk({ client: { legalName: "A", signatory: {} } })],
  ["window inverted", mk({ window: { notBefore: "2026-10-15T00:00:00Z", notAfter: "2026-09-30T00:00:00Z" } })],
  ["no emergency contact", mk({ emergencyContact: {} })],
  ["no classes", mk({ allowedClasses: [] })],
  ["unknown class", mk({ allowedClasses: ["scan", "pwn-everything"] })],
  ["empty scope", mk({ scope: { inScope: [] } })],
  ["bad engagement id", mk({ engagement: "../etc" })],
  ["wrong version", mk({ version: 2 })],
]) ok("invalid: " + name, !A.validateRecord(rec).ok);

group("signature");
const env = sign(mk());
ok("valid signature verifies", A.verifySignature(env, TRUST).ok);
ok("altered record fails", !A.verifySignature(Object.assign({}, env, { record: mk({ scope: { inScope: ["*.corp.example.com", "evil.example.org"] } }) }), TRUST).ok);
ok("untrusted signer fails", !A.verifySignature(sign(mk(), other, "auth-2"), TRUST).ok);
ok("right keyId, wrong key fails", !A.verifySignature(sign(mk(), other, "auth-1"), TRUST).ok);
ok("missing signature fails", !A.verifySignature({ record: mk() }, TRUST).ok);
ok("prototype-key keyId fails", !A.verifySignature({ record: mk(), signature: { alg: "ed25519", keyId: "__proto__", value: "AAAA" } }, TRUST).ok);

group("evaluate — the decision");
ok("in-scope host allowed", ev(env, ["app.example.com"]).allow);
ok("in-scope wildcard child + cidr ip + url all allowed together", ev(env, ["x.corp.example.com", "203.0.113.4", "https://api.example.com/v1/users"]).allow);
eq("out-of-scope host denied", ev(env, ["evil.example.org"]).code, "NOT_IN_SCOPE");
eq("ONE out-of-scope target among many denies all", ev(env, ["app.example.com", "evil.example.org"]).code, "NOT_IN_SCOPE");
eq("wildcard apex denied", ev(env, ["corp.example.com"]).code, "NOT_IN_SCOPE");
eq("explicit exclusion beats wildcard", ev(env, ["admin.corp.example.com"]).code, "OUT_OF_SCOPE_EXCLUDED");
eq("excluded ip inside allowed cidr", ev(env, ["203.0.113.9"]).code, "OUT_OF_SCOPE_EXCLUDED");
eq("range containing an excluded ip denied", ev(env, ["203.0.113.8/29"]).code, "OUT_OF_SCOPE_EXCLUDED");
eq("obfuscated IP cannot dodge the match", ev(env, ["0xcb007109"]).code, "OUT_OF_SCOPE_EXCLUDED"); // 203.0.113.9
eq("IPv6 refused (v1)", ev(env, ["::1"]).code, "BAD_TARGET");
eq("class not permitted", ev(env, ["app.example.com"], { class: "exploit" }).code, "CLASS_NOT_PERMITTED");
eq("unknown class", ev(env, ["app.example.com"], { class: "yolo" }).code, "UNKNOWN_CLASS");
eq("no target", ev(env, []).code, "NO_TARGET");
eq("before window", ev(env, ["app.example.com"], { now: new Date("2026-09-29T23:59:59Z") }).code, "BEFORE_WINDOW");
eq("window end is exclusive", ev(env, ["app.example.com"], { now: new Date("2026-10-15T00:00:00Z") }).code, "AFTER_WINDOW");
eq("after window", ev(env, ["app.example.com"], { now: new Date("2027-01-01T00:00:00Z") }).code, "AFTER_WINDOW");
eq("agreement dated in the future", ev(sign(mk({ agreement: { ref: "x", sha256: "b".repeat(64), signedAt: "2026-12-01T00:00:00Z" } })), ["app.example.com"]).code, "NOT_YET_SIGNED");
eq("revoked", ev(env, ["app.example.com"], { revoked: { at: "2026-10-01T11:00:00Z", reason: "client request" } }).code, "REVOKED");
eq("no envelope", ev(null, ["app.example.com"]).code, "NO_AUTHORIZATION");
eq("tampered envelope", ev(Object.assign({}, env, { record: mk({ window: { notBefore: "2026-01-01T00:00:00Z", notAfter: "2030-01-01T00:00:00Z" } }) }), ["app.example.com"]).code, "BAD_SIGNATURE");
eq("signed but invalid record (no ownership attestation)", ev(sign(mk({ assetOwnership: { confirmed: false } })), ["app.example.com"]).code, "INVALID_RECORD");
eq("no trusted keys => deny", ev(env, ["app.example.com"], { trustedKeys: {} }).code, "BAD_SIGNATURE");
eq("garbage input fails closed", A.evaluate({ envelope: { record: 5 }, trustedKeys: TRUST, class: "scan", targets: ["a.example.com"] }).allow, false);
eq("throwing input fails closed", A.evaluate(null).allow, false);

group("tool grammar (parseInvocation)");
const P = (t, a) => G.parseInvocation(t, a);
eq("nmap: flags + attached -T4 + target", P("nmap", ["-sT", "-T4", "-p", "1-1024", "app.example.com"]).targets, ["app.example.com"]);
eq("nmap: multiple positionals are all targets", P("nmap", ["a.example.com", "b.example.com"]).targets, ["a.example.com", "b.example.com"]);
for (const bad of [["-iL", "targets.txt", "a.example.com"], ["--script", "vuln", "a.example.com"], ["-A", "a.example.com"], ["--resolve", "x", "a.example.com"], ["-sS", "--", "a.example.com"], ["-p"], []])
  ok("nmap rejects " + JSON.stringify(bad), !!P("nmap", bad).error);
eq("nuclei: -u is a target flag", P("nuclei", ["-u", "https://app.example.com", "-severity", "high"]).targets, ["https://app.example.com"]);
for (const bad of [["-l", "list.txt"], ["-list", "x"], ["-u", "https://a.example.com", "-H", "Host: evil"], ["-severity", "high"]])
  ok("nuclei rejects " + JSON.stringify(bad), !!P("nuclei", bad).error);
eq("scan: target + portspec", P("scan", ["10.0.0.1", "22,80,8000-8100"]).targets, ["10.0.0.1"]);
ok("scan: bad port spec", !!P("scan", ["10.0.0.1", "22;rm"]).error);
ok("scan: extra arg", !!P("scan", ["10.0.0.1", "22", "extra"]).error);
ok("unknown tool (nexus, sqlmap…) refused", !!P("nexus", ["x"]).error && !!P("sqlmap", ["-u", "x"]).error && !!P("__proto__", []).error && !!P("constructor", []).error);
ok("non-string argv refused", !!P("scan", [{ toString() { return "a"; } }]).error);
eq("class map", [P("dns", ["a.example.com"]).cls, P("scan", ["a.example.com"]).cls, P("fuzz", ["https://a.example.com"]).cls, P("nuclei", ["-u", "a.example.com"]).cls], ["recon", "scan", "vuln-scan", "vuln-scan"]);

group("gate: store, audit, fail-closed");
const ID = "acme-2026-q4";
const now = Date.now();
const live = (over) => mk(Object.assign({ window: { notBefore: new Date(now - 3600e3).toISOString(), notAfter: new Date(now + 3600e3).toISOString() } }, over || {}));
let d = G.authorize({ engagement: ID, tool: "scan", argv: ["app.example.com"] });
eq("no authorization on file => deny", d.code, "NO_AUTHORIZATION");
d = G.authorize({ engagement: "../../etc", tool: "scan", argv: ["app.example.com"] });
ok("path-traversal engagement id => deny, no throw, nothing written outside store", !d.allow && !fs.existsSync(path.join(HOME, "..", "..", "etc", "audit.jsonl")));
ok("denials with no engagement go to the unscoped audit log", G.auditVerifyFile(path.join(HOME, "audit-unscoped.jsonl")).count >= 1);
eq("unknown tool => deny", G.authorize({ engagement: ID, tool: "nexus", argv: [] }).code, "UNKNOWN_TOOL");

fs.writeFileSync(path.join(HOME, "authorizers.json"), JSON.stringify(TRUST));
ok("install refuses an untrusted signature", !G.installEnvelope(sign(live(), other, "auth-2")).ok);
ok("install refuses an invalid record", !G.installEnvelope(sign(live({ assetOwnership: { confirmed: false } }))).ok);
ok("install refuses a tampered record", !G.installEnvelope(Object.assign({}, sign(live()), { record: live({ scope: { inScope: ["evil.example.org"] } }) })).ok);
ok("nothing installed by refused attempts", G.loadEnvelope(ID) === null);
const good = sign(live());
ok("install accepts a trusted, valid envelope", G.installEnvelope(good).ok);
ok("second install without --replace refused", !G.installEnvelope(good).ok);
ok("replace archives the old one", G.installEnvelope(sign(live()), { replace: true }).ok && fs.readdirSync(path.join(G.engDir(ID), "history")).length === 1);

d = G.authorize({ engagement: ID, tool: "scan", argv: ["app.example.com", "22"] });
ok("in-scope scan allowed", d.allow && d.cls === "scan");
eq("out-of-scope scan denied", G.authorize({ engagement: ID, tool: "scan", argv: ["evil.example.org"] }).code, "NOT_IN_SCOPE");
eq("class not authorised (vuln-scan)", G.authorize({ engagement: ID, tool: "fuzz", argv: ["https://app.example.com"] }).code, "CLASS_NOT_PERMITTED");
eq("smuggled second target denied", G.authorize({ engagement: ID, tool: "nmap", argv: ["app.example.com", "evil.example.org"] }).code, "NOT_IN_SCOPE");
eq("target-list file flag denied", G.authorize({ engagement: ID, tool: "nmap", argv: ["-iL", "hosts.txt", "app.example.com"] }).code, "BAD_ARGS");
const chain = G.auditVerifyFile(G.auditFile(ID));
ok("audit chain intact and records every decision", chain.ok && chain.count >= 7);
const tail = G.auditTail(ID, 50);
ok("audit entries carry operator, tool, argv, targets, verdict", tail.some((e) => e.event === "decision" && e.allow === true && e.operator === "test-operator" && e.tool === "scan" && e.targets[0] === "app.example.com" && Array.isArray(e.argv)));
ok("denials are audited too", tail.some((e) => e.event === "decision" && e.allow === false && e.code === "NOT_IN_SCOPE"));

// tamper with the log
const af = G.auditFile(ID), orig = fs.readFileSync(af, "utf8"), lines = orig.trim().split("\n");
fs.writeFileSync(af, lines.map((l, i) => i === 3 ? l.replace('"allow":false', '"allow":true') : l).join("\n") + "\n");
ok("edited audit entry detected", !G.auditVerifyFile(af).ok && G.auditVerifyFile(af).reason.startsWith("tampered"));
fs.writeFileSync(af, lines.filter((_, i) => i !== 3).join("\n") + "\n");
ok("deleted audit entry detected", !G.auditVerifyFile(af).ok);
fs.writeFileSync(af, orig);
ok("restored log verifies again", G.auditVerifyFile(af).ok);

// audit failure => deny (no audit, no run)
fs.renameSync(af, af + ".bak"); fs.mkdirSync(af);
d = G.authorize({ engagement: ID, tool: "scan", argv: ["app.example.com"] });
ok("cannot write audit => DENY (AUDIT_FAILURE), even though in scope", !d.allow && d.code === "AUDIT_FAILURE");
fs.rmdirSync(af); fs.renameSync(af + ".bak", af);
ok("audit healthy again => allow", G.authorize({ engagement: ID, tool: "scan", argv: ["app.example.com"] }).allow);

// guard(): denial throws, allowed runs and is closed out in the log
let ran = 0;
G.guard(ID, "scan", ["evil.example.org"], () => { ran++; }).catch(() => {}).then(async () => {
  eq("guard: denied => body never runs", ran, 0);
  await G.guard(ID, "dns", ["app.example.com"], () => { ran++; });
  eq("guard: allowed => body runs", ran, 1);
  ok("guard: exec_end recorded", G.auditTail(ID, 3).some((e) => e.event === "exec_end" && e.tool === "dns"));

  group("gate: discovered-host filter (subrecon)");
  const f = G.filterInScope(ID, "scan", ["x.corp.example.com", "admin.corp.example.com", "evil.example.org", "corp.example.com"]);
  eq("only in-scope discovered hosts survive", f.allowed, ["x.corp.example.com"]);
  eq("dropped hosts are listed", f.dropped, ["admin.corp.example.com", "evil.example.org", "corp.example.com"]);
  ok("filtering is audited", G.auditTail(ID, 2).some((e) => e.event === "discovered_filter" && e.dropped.length === 3));

  group("gate: external tool runner + watchdog");
  G.TOOLS.testecho = { cls: "scan", bin: "echo", positional: "targets", flags: {} };
  G.TOOLS.testsleep = { cls: "scan", bin: process.execPath, positional: "targets", flags: { "-e": 1 } };
  const r1 = await G.runExternal(ID, "testecho", ["app.example.com"], { stdio: "ignore" });
  eq("allowed external tool runs and exits 0", r1.code, 0);
  let denied = null; try { await G.runExternal(ID, "testecho", ["evil.example.org"], { stdio: "ignore" }); } catch (e) { denied = e; }
  ok("out-of-scope external tool never spawns", denied instanceof G.GateDenied && denied.code === "NOT_IN_SCOPE");
  const t0 = Date.now();
  const running = G.runExternal(ID, "testsleep", ["-e", "setTimeout(()=>{},30000)", "app.example.com"], { stdio: "ignore", pollMs: 100 });
  setTimeout(() => G.revoke(ID, "client asked us to stop"), 300);
  const r2 = await running;
  ok("revocation kills a running tool within seconds", r2.killedBy === "REVOKED" && Date.now() - t0 < 5000);
  ok("watchdog kill is audited", G.auditTail(ID, 6).some((e) => e.event === "watchdog_kill" && e.code === "REVOKED"));
  eq("after revoke every run is denied", G.authorize({ engagement: ID, tool: "scan", argv: ["app.example.com"] }).code, "REVOKED");
  ok("audit chain still intact after all of that", G.auditVerifyFile(G.auditFile(ID)).ok);

  group("darknode CLI in engagement mode (end-to-end)");
  const ID2 = "e2e-local-lab";
  const e2e = sign(live({ engagement: ID2, scope: { inScope: ["127.0.0.1"], outOfScope: [] }, allowedClasses: ["recon", "scan"] }));
  ok("install e2e authorization", G.installEnvelope(e2e).ok);
  const run = (args, env) => cp.spawnSync(process.execPath, [path.join(__dirname, "..", "darknode.js")].concat(args), { encoding: "utf8", timeout: 30000, env: Object.assign({}, process.env, { DARKNODE_HOME: HOME, DARKNODE_ENGAGEMENT: ID2 }, env || {}) });
  let r = run(["scan", "127.0.0.1", "1"]);
  ok("in-scope scan runs, exit 0", r.status === 0);
  ok("…and is audited (decision + exec_end)", G.auditTail(ID2, 5).some((e) => e.event === "decision" && e.allow) && G.auditTail(ID2, 5).some((e) => e.event === "exec_end"));
  r = run(["scan", "127.0.0.2", "1"]);
  ok("out-of-scope scan refused, exit 1, says why", r.status === 1 && /GATE DENIED \[NOT_IN_SCOPE\]/.test(r.stderr));
  r = run(["nexus", "--print", "x"]); ok("nexus (ungated agent) refused", r.status === 1 && /UNKNOWN_TOOL/.test(r.stderr));
  r = run(["api", "start"]); ok("api server refused", r.status === 1 && /UNKNOWN_TOOL/.test(r.stderr));
  r = run(["serve", "."]); ok("serve refused", r.status === 1);
  r = run([]); ok("interactive menu refused", r.status === 1 && /engagement mode/.test(r.stderr));
  r = run(["nmap", "-iL", "x", "127.0.0.1"]); ok("darknode nmap with target-list flag refused", r.status === 1 && /BAD_ARGS/.test(r.stderr));
  r = run(["uuid"]); ok("offline helper still works", r.status === 0 && /^[0-9a-f-]{36}/.test(r.stdout));
  r = run(["scan", "127.0.0.1", "1"], { DARKNODE_ENGAGEMENT: "no-such-engagement" }); ok("engagement without authorization refused", r.status === 1 && /NO_AUTHORIZATION/.test(r.stderr));
  r = cp.spawnSync(process.execPath, [path.join(__dirname, "..", "sentinel.js"), "scan", "127.0.0.1"], { encoding: "utf8", env: Object.assign({}, process.env, { DARKNODE_ENGAGEMENT: ID2 }) });
  ok("legacy sentinel.js refuses to run in engagement mode", r.status === 1 && /ungated/.test(r.stderr));
  r = run(["authz", "status", ID2], { DARKNODE_ENGAGEMENT: "" }); ok("authz status reports the engagement in force", r.status === 0 && /IN FORCE/.test(r.stdout) && /intact/.test(r.stdout));
  r = run(["authz", "check", ID2, "scan", "127.0.0.9"], { DARKNODE_ENGAGEMENT: "" }); ok("authz check: dry-run deny", r.status === 1 && /NOT_IN_SCOPE/.test(r.stdout));
  r = run(["authz", "revoke", ID2, "--reason", "test"], { DARKNODE_ENGAGEMENT: "" }); ok("authz revoke", r.status === 0);
  r = run(["scan", "127.0.0.1", "1"]); ok("revoked engagement refuses in-scope scan", r.status === 1 && /REVOKED/.test(r.stderr));

  fs.rmSync(HOME, { recursive: true, force: true });
  console.log("\n" + (fail ? "\x1b[31m" : "\x1b[32m") + pass + " passed, " + fail + " failed\x1b[0m  (authorization gate)");
  process.exit(fail ? 1 : 0);
}).catch((e) => { console.log("  \x1b[31mFAIL\x1b[0m suite threw: " + (e && e.stack || e)); process.exit(1); });
