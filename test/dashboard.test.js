"use strict";
// /open dashboard suite: the pure view builders (lib/nexus/dash-view.js) and the
// server's guards (lib/nexus/dashboard.js): loopback Host/Origin checks, read-only,
// CSP with a per-load nonce, and the detail/job endpoints.
const http = require("http");
const V = require("../lib/nexus/dash-view");
const { startDashboard } = require("../lib/nexus/dashboard");
const { createTail, pushTail, tailText } = require("../lib/cli/tool-tail");

let pass = 0, fail = 0;
const ok = (name, cond) => { if (cond) pass++; else { fail++; console.log("  \x1b[31mFAIL\x1b[0m " + name); } };
const eq = (name, a, b) => ok(name + "  (" + JSON.stringify(a) + " === " + JSON.stringify(b) + ")", JSON.stringify(a) === JSON.stringify(b));
const group = (t) => console.log("\n\x1b[1m" + t + "\x1b[0m");
const get = (port, path, headers, method) => new Promise((res) => {
  const r = http.request({ host: "127.0.0.1", port, path, method: method || "GET", headers: Object.assign({ Host: "127.0.0.1:" + port }, headers || {}) }, (x) => { let b = ""; x.on("data", (d) => (b += d)); x.on("end", () => res({ status: x.statusCode, headers: x.headers, body: b })); });
  r.on("error", () => res({ status: 0 })); r.end();
});

(async () => {
  group("view builders");
  const live = createTail(); pushTail(live, "building...\nstep 2\n");
  const transcript = [
    { role: "user", text: "fix the build" },
    { role: "system", text: "\x1b[36mcache\x1b[0m warm" },
    { role: "nexus", items: [
      { type: "thinking", full: "look at the error first" },
      { type: "tool", id: "t1", name: "Read", input: { file_path: "src/a.js" }, label: "Read(a.js)", status: "ok", start: 1000, end: 1200, result: [{ type: "text", text: "const a = 1;" }] },
      { type: "tool", id: "t2", name: "Edit", input: { file_path: "src/a.js", old_string: "1", new_string: "2" }, label: "Edit(a.js)", status: "ok", start: 1300, end: 1400, result: "ok", diff: { added: 1, removed: 1, rows: [{ t: "-", text: "const a = 1;", ln: 1 }, { t: "+", text: "const a = 2;", ln: 1 }] } },
      { type: "tool", id: "t3", name: "Bash", input: { command: "npm test" }, label: "Bash(npm test)", status: "err", start: 1500, end: 2500, result: "1 failed", isError: true },
      { type: "tool", id: "t4", name: "run_command", input: { command: "make" }, label: "make", status: "run", start: 3000 },
      { type: "tool", id: "t5", name: "Grep", input: { pattern: "foo" }, label: "Grep(foo)", status: "ok", start: 3100, end: 3150, result: "x" },
      { type: "text", full: "Fixed it." },
    ] },
    { role: "system", text: "$ ls\na.js" },
    { role: "art" },
  ];
  Object.defineProperty(transcript[2].items[4], "live", { value: live, configurable: true });
  const conv = V.conversation(transcript, { tail: tailText });
  eq("roles in order, art skipped", conv.map((m) => m.role), ["user", "system", "assistant", "system"]);
  eq("ANSI colour codes are stripped", conv[1].text, "cache warm");
  const items = conv[2].items;
  eq("item types", items.map((i) => i.type), ["thinking", "tool", "tool", "tool", "tool", "tool", "text"]);
  eq("content-block results become text", items[1].output, "const a = 1;");
  eq("tool kinds", items.filter((i) => i.type === "tool").map((i) => i.kind), ["read", "edit", "shell", "shell", "search"]);
  eq("statuses", items.filter((i) => i.type === "tool").map((i) => i.status), ["done", "done", "error", "running", "done"]);
  ok("a running command shows its live output", items[4].live && /step 2/.test(items[4].output));
  eq("diff rows kept", items[2].diff.rows, [["-", "const a = 1;", 1], ["+", "const a = 2;", 1]]);
  eq("shell command extracted", items[3].command, "npm test");
  const term = V.terminal(conv);
  eq("terminal: agent commands then your ! command", term.map((r) => [r.by, r.command, r.status]), [["agent", "npm test", "error"], ["agent", "make", "running"], ["you", "ls", "done"]]);
  const fa = V.fileActivity(conv);
  eq("file activity merges reads and edits", fa.files.map((f) => [f.path, f.read, f.edit, f.diffs]), [["src/a.js", 1, 1, 1]]);
  eq("searches listed", fa.searches.length, 1);
  const big = V.conversation([{ role: "nexus", items: [{ type: "tool", id: "b", name: "Bash", input: { command: "cat x" }, status: "ok", result: "y".repeat(50000) }] }]);
  ok("huge output is capped with a note", big[0].items[0].output.length < 21000 && /more characters/.test(big[0].items[0].output));
  eq("object results (local tools) render", V.asText({ code: 2, output: "boom" }), "boom\n[exit 2]");
  const ag = V.agentsView([{ id: "a1", task: "scan", status: "run", start: 1, prompt: "scan repo", items: [{ type: "text", full: "working" }] }]);
  eq("agents carry their own items", ag[0].items, [{ type: "text", text: "working" }]);
  const r1 = V.revision(transcript, []); pushTail(live, "step 3\n"); const r2 = V.revision(transcript, []);
  ok("revision changes when a running command prints", r1 !== r2);
  ok("revision is stable when nothing changes", V.revision(transcript, []) === r2);
  const lean = JSON.stringify(transcript[2].items[4]);
  ok("the live tail is still not serialized with the card", !/step 2/.test(lean));

  group("server");
  const d = await startDashboard({ port: 7990, getState: () => ({ rev: "r1", engine: "claude" }), getDetail: () => ({ conversation: conv, terminal: term, files: fa, agents: [], turns: [] }), getJob: (id) => id === "j1" ? { id, output: "job out" } : null });
  const p = d.port;
  const page = await get(p, "/");
  ok("page served", page.status === 200 && /NEXUS/.test(page.body));
  const csp = page.headers["content-security-policy"] || "", nonce = (/'nonce-([^']+)'/.exec(csp) || [])[1];
  ok("CSP: script needs the nonce, never framed", nonce && /frame-ancestors 'none'/.test(csp) && /default-src 'none'/.test(csp));
  ok("the nonce is on the inline script", page.body.includes('<script nonce="' + nonce + '">') && !page.body.includes("__NONCE__"));
  ok("a fresh nonce per load", ((/'nonce-([^']+)'/.exec((await get(p, "/")).headers["content-security-policy"]) || [])[1]) !== nonce);
  eq("state", JSON.parse((await get(p, "/api/state")).body).rev, "r1");
  eq("detail", JSON.parse((await get(p, "/api/detail")).body).terminal.length, 3);
  eq("job output", JSON.parse((await get(p, "/api/job?id=j1")).body).output, "job out");
  eq("unknown job", JSON.parse((await get(p, "/api/job?id=nope")).body).output, null);
  eq("foreign Host refused (DNS rebinding)", (await get(p, "/api/detail", { Host: "evil.example:" + p })).status, 403);
  eq("foreign Origin refused", (await get(p, "/api/detail", { Origin: "https://evil.example" })).status, 403);
  eq("localhost Host allowed", (await get(p, "/api/state", { Host: "localhost:" + p })).status, 200);
  eq("read-only: POST refused", (await get(p, "/api/state", {}, "POST")).status, 405);
  const boom = await startDashboard({ port: 7991, getState: () => { throw new Error("x"); }, getDetail: () => { throw new Error("y"); } });
  eq("a throwing provider still answers", JSON.parse((await get(boom.port, "/api/detail")).body).agents, []);
  boom.close(); d.close();

  console.log("\n" + (fail ? "\x1b[31m" : "\x1b[32m") + pass + " passed, " + fail + " failed\x1b[0m  (dashboard)");
  process.exit(fail ? 1 : 0);
})();
