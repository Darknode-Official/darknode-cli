"use strict";
// bg-cutoff: spot Claude Code ending a turn while its background agents are mid-task.
const { createBgTracker, HOST_NOTE, resumePrompt, RESUME_LIMIT } = require("../lib/nexus/bg-cutoff");
let pass = 0, fail = 0;
const ok = (name, cond) => { if (cond) pass++; else { fail++; console.log("  FAIL " + name); } };
const run = (evs) => { const t = createBgTracker(); for (const e of evs) t.event(e); return t.cut(); };
const sub = (pid, type = "assistant") => ({ type, parent_tool_use_id: pid, message: { content: [] } });
const main = { type: "assistant", parent_tool_use_id: null, message: { content: [] } };
const result = { type: "result", subtype: "success" };

ok("a plain turn is not a cut-off", run([main, result]) === 0);
ok("foreground agents that finish before the reply are not a cut-off", run([main, sub("t1"), sub("t1", "user"), main, result]) === 0);
ok("agents still working after the reply, then exit = cut off", run([main, result, sub("t1"), sub("t2"), sub("t1", "user"), sub("t3", "stream_event")]) === 3);
ok("agents that finish and Claude replies again = not cut off", run([main, result, sub("t1"), main, result]) === 0);
ok("a later burst after the second reply still counts", run([result, sub("a"), result, sub("b")]) === 1);
ok("system and rate-limit events are ignored", run([result, { type: "system", subtype: "task_progress", parent_tool_use_id: "x" }, { type: "rate_limit_event" }]) === 0);
ok("junk input never throws", (() => { const t = createBgTracker(); t.event(null); t.event("x"); return t.cut() === 0; })());
ok("host note names the 10-minute stop and both ways out", /10 minutes/.test(HOST_NOTE) && /run_in_background: false/.test(HOST_NOTE) && /mcp__nexus__sessions/.test(HOST_NOTE));
ok("resume prompt counts agents", /^Your 3 background agents were/.test(resumePrompt(3)) && /^Your background agent was/.test(resumePrompt(1)));
ok("resumes are capped", RESUME_LIMIT > 0 && RESUME_LIMIT <= 10);
console.log("bg-cutoff: " + pass + " passed, " + fail + " failed");
if (fail) process.exit(1);
