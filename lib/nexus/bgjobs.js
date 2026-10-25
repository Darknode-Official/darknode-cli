"use strict";
// Background jobs manager (Claude Code idea): long-running commands the agent
// starts without blocking the turn, whose output it can poll later. This holds the
// pure state machine (start -> running -> done/killed) with a bounded output buffer;
// the caller wires the actual child process + its stdout/close events in.
const MAX_BUF = 200000; // cap per-job buffer so a chatty server can't grow unbounded

function createBgJobs() {
  const jobs = {}; let seq = 0;
  const trim = (s) => (s.length > MAX_BUF ? s.slice(s.length - MAX_BUF) : s);
  return {
    start(command, child, now) {
      const id = "bg" + (++seq);
      jobs[id] = { id, command: String(command || ""), status: "running", out: "", total: 0, seen: 0, code: null, start: now || 0, child: child || null };
      return id;
    },
    append(id, chunk) { const j = jobs[id]; if (j) { const c = String(chunk); j.out = trim(j.out + c); j.total += c.length; } },
    // Output produced since the last readNew (what the agent hasn't seen yet). `dropped`
    // counts unseen chars that already fell out of the bounded buffer.
    readNew(id, max) {
      const j = jobs[id]; if (!j) return null;
      const unseen = j.total - j.seen, avail = Math.min(unseen, j.out.length);
      let text = avail > 0 ? j.out.slice(j.out.length - avail) : "";
      const dropped = unseen - avail;
      let cut = 0; if (max && text.length > max) { cut = text.length - max; text = text.slice(-max); }
      j.seen = j.total;
      return { text, dropped: dropped + cut, earlier: j.total - unseen };
    },
    // Send input to a running job's stdin.
    write(id, text) {
      const j = jobs[id]; if (!j) return { error: "no such job " + id };
      if (j.status !== "running" || !j.child) return { error: "job " + id + " is not running (" + j.status + ")" };
      if (!j.child.stdin || j.child.stdin.destroyed || !j.child.stdin.writable) return { error: "job " + id + " has no open stdin" };
      try { j.child.stdin.write(String(text)); return { ok: true }; } catch (e) { return { error: e.message }; }
    },
    finish(id, code) { const j = jobs[id]; if (j && j.status === "running") { j.status = "done"; j.code = (code == null ? 0 : code); j.child = null; } },
    get(id) { return jobs[id] || null; },
    tail(id, n) { const j = jobs[id]; return j ? j.out.slice(-(n || 4000)) : null; },
    list() { return Object.keys(jobs).map((id) => ({ id, command: jobs[id].command, status: jobs[id].status, code: jobs[id].code, bytes: jobs[id].out.length })); },
    running() { let c = 0; for (const id in jobs) if (jobs[id].status === "running") c++; return c; },
    stop(id) { const j = jobs[id]; if (!j) return false; if (j.status === "running") { if (j.child) { try { j.child.kill("SIGKILL"); } catch (_) {} } j.status = "killed"; j.child = null; } return true; },
    killAll() { for (const id in jobs) { const j = jobs[id]; if (j.status === "running") { if (j.child) { try { j.child.kill("SIGKILL"); } catch (_) {} } j.status = "killed"; j.child = null; } } },
  };
}
module.exports = { createBgJobs, MAX_BUF };
