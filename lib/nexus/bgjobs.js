"use strict";
// Background jobs manager (Claude Code idea): long-running commands the agent
// starts without blocking the turn, whose output it can poll later. This holds the
// pure state machine (start -> running -> done/killed) with a bounded output buffer;
// the caller wires the actual child process + its stdout/close events in.
const MAX_BUF = 200000; // cap per-job buffer so a chatty server can't grow unbounded

function createBgJobs() {
  const jobs = {}; let seq = 0;
  const trim = (s) => (s.length > MAX_BUF ? s.slice(s.length - MAX_BUF) : s);
  // Models say "1", 1, "bg1", "job 1" or "#1" for the same job; with no id and exactly
  // one job running, that job is meant. Unknown → null.
  const key = (id) => {
    if (id == null || id === "") { const r = Object.keys(jobs).filter((k) => jobs[k].status === "running"); return r.length === 1 ? r[0] : null; }
    const s = String(id).trim();
    if (jobs[s]) return s;
    const n = s.replace(/^(bg|job)?\s*#?\s*/i, "");
    return /^\d+$/.test(n) && jobs["bg" + n] ? "bg" + n : null;
  };
  // Kill the job's whole process group (spawned detached), so `npm run dev` → node dies too.
  const killTree = (j) => { if (!j.child) return; const pid = j.child.pid; try { if (process.platform !== "win32" && pid) process.kill(-pid, "SIGKILL"); else j.child.kill("SIGKILL"); } catch (_) { try { j.child.kill("SIGKILL"); } catch (_) {} } };
  const api = {
    key,
    start(command, child, now) {
      const id = "bg" + (++seq);
      jobs[id] = { id, command: String(command || ""), status: "running", out: "", total: 0, seen: 0, code: null, start: now || 0, child: child || null };
      return id;
    },
    append(id, chunk) { const j = jobs[id]; if (j) { const c = String(chunk); j.out = trim(j.out + c); j.total += c.length; } },
    // Output produced since the last readNew (what the agent hasn't seen yet). `dropped`
    // counts unseen chars that already fell out of the bounded buffer.
    readNew(id, max) {
      id = key(id); const j = id && jobs[id]; if (!j) return null;
      const unseen = j.total - j.seen, avail = Math.min(unseen, j.out.length);
      let text = avail > 0 ? j.out.slice(j.out.length - avail) : "";
      const dropped = unseen - avail;
      let cut = 0; if (max && text.length > max) { cut = text.length - max; text = text.slice(-max); }
      j.seen = j.total;
      return { text, dropped: dropped + cut, earlier: j.total - unseen };
    },
    // Send input to a running job's stdin.
    write(id, text) {
      const k = key(id), j = k && jobs[k]; if (!j) return { error: "no such job " + id + api.known() }; id = k;
      if (j.status !== "running" || !j.child) return { error: "job " + id + " is not running (" + j.status + ")" };
      if (!j.child.stdin || j.child.stdin.destroyed || !j.child.stdin.writable) return { error: "job " + id + " has no open stdin" };
      try { j.child.stdin.write(String(text)); return { ok: true }; } catch (e) { return { error: e.message }; }
    },
    finish(id, code) { const j = jobs[id]; if (j && j.status === "running") { j.status = "done"; j.code = (code == null ? 0 : code); j.child = null; } },
    get(id) { const k = key(id); return k ? jobs[k] : null; },
    tail(id, n) { const k = key(id), j = k && jobs[k]; return j ? j.out.slice(-(n || 4000)) : null; },
    list() { return Object.keys(jobs).map((id) => ({ id, command: jobs[id].command, status: jobs[id].status, code: jobs[id].code, bytes: jobs[id].out.length })); },
    running() { let c = 0; for (const id in jobs) if (jobs[id].status === "running") c++; return c; },
    stop(id) { const k = key(id), j = k && jobs[k]; if (!j) return false; if (j.status === "running") { killTree(j); j.status = "killed"; j.child = null; } return true; },
    killAll() { for (const id in jobs) { const j = jobs[id]; if (j.status === "running") { killTree(j); j.status = "killed"; j.child = null; } } },
    // root pids of running jobs (for "is this local port one of OUR servers?")
    pids() { const out = []; for (const id in jobs) { const j = jobs[id]; if (j.status === "running" && j.child && j.child.pid) out.push(j.child.pid); } return out; },
    // " (running: bg1 npm run dev, bg2 …)" — appended to unknown-id errors
    known() { const r = Object.keys(jobs).map((k) => k + " " + jobs[k].status + ": " + jobs[k].command.slice(0, 40)); return r.length ? " — jobs: " + r.join("; ") : " — no background jobs this session"; },
  };
  return api;
}
module.exports = { createBgJobs, MAX_BUF };
