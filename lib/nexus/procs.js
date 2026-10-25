"use strict";
// list_processes — what is running, in a shape worth the tokens: busiest first,
// kernel threads dropped, only the columns that matter (pid, parent, cpu, mem,
// age, command), long command lines clipped. filter matches the command or a
// pid; port answers the usual EADDRINUSE question ("what is holding :3000?").

const { execFileSync } = require("child_process");

const MAX_CMD = 160;

const run = (cmd, args) => { try { return execFileSync(cmd, args, { encoding: "utf8", maxBuffer: 8e6, stdio: ["ignore", "pipe", "ignore"], timeout: 8000 }); } catch (e) { return e.stdout ? String(e.stdout) : null; } };

// Parse `ps -Ao pid,ppid,pcpu,pmem,etime,args` output into rows.
function parsePs(text) {
  const rows = [];
  for (const line of String(text || "").split("\n").slice(1)) {
    const m = line.trim().match(/^(\d+)\s+(\d+)\s+([\d.]+)\s+([\d.]+)\s+(\S+)\s+(.*)$/);
    if (m) rows.push({ pid: +m[1], ppid: +m[2], cpu: +m[3], mem: +m[4], age: m[5], cmd: m[6] });
  }
  return rows;
}

// Pids listening on a TCP port: ss (Linux) or lsof (macOS/BSD).
function pidsOnPort(port) {
  const pids = new Set();
  const ss = run("ss", ["-ltnpH", "sport = :" + port]);
  if (ss) for (const m of ss.matchAll(/pid=(\d+)/g)) pids.add(+m[1]);
  if (!pids.size) { const ls = run("lsof", ["-nP", "-iTCP:" + port, "-sTCP:LISTEN", "-t"]); if (ls) for (const p of ls.split(/\s+/)) if (/^\d+$/.test(p)) pids.add(+p); }
  return { pids, listening: !!(ss && ss.trim()) };
}

function formatRows(rows, max) {
  const out = ["PID     PPID     %CPU %MEM  AGE          COMMAND"];
  for (const r of rows.slice(0, max)) {
    const cmd = r.cmd.length > MAX_CMD ? r.cmd.slice(0, MAX_CMD) + "…" : r.cmd;
    out.push(String(r.pid).padEnd(7) + " " + String(r.ppid).padEnd(7) + " " + r.cpu.toFixed(1).padStart(5) + " " + r.mem.toFixed(1).padStart(4) + "  " + r.age.padEnd(11) + "  " + cmd);
  }
  return out.join("\n");
}

// opts.ps / opts.portLookup are injectable for tests.
function listProcessesTool(a, opts) {
  a = a || {}; opts = opts || {};
  const max = Math.max(1, Math.min(200, a.max || a.limit || 40));
  if (process.platform === "win32" && !opts.ps) {
    const r = run("tasklist", []);
    if (r == null) return { error: "tasklist failed" };
    let lines = r.split("\n");
    if (a.filter) lines = lines.slice(0, 3).concat(lines.slice(3).filter((l) => l.toLowerCase().includes(String(a.filter).toLowerCase())));
    return { processes: lines.slice(0, max + 3).join("\n") };
  }
  const text = opts.ps != null ? opts.ps : run("ps", ["-Ao", "pid,ppid,pcpu,pmem,etime,args"]);
  if (text == null) return { error: "ps failed" };
  let rows = parsePs(text).filter((r) => !r.cmd.startsWith("ps -Ao pid,ppid,pcpu")); // drop our own ps call
  const total = rows.length;
  const res = {};
  if (a.port) {
    const port = +a.port;
    if (!(port > 0 && port < 65536)) return { error: "port must be 1-65535" };
    const { pids, listening } = (opts.portLookup || pidsOnPort)(port);
    rows = rows.filter((r) => pids.has(r.pid));
    if (!rows.length) return { port, note: listening ? "something is listening on :" + port + " but its process is not visible (owned by another user — try sudo ss -ltnp)" : "nothing is listening on :" + port };
    res.port = port;
  } else if (a.filter) {
    const f = String(a.filter).toLowerCase();
    rows = rows.filter((r) => String(r.pid) === f || r.cmd.toLowerCase().includes(f));
    if (!rows.length) return { filter: a.filter, note: "no running process matches \"" + a.filter + "\" (" + total + " processes checked)" };
  } else {
    rows = rows.filter((r) => !/^\[.*\]$/.test(r.cmd)); // kernel threads
  }
  rows.sort((x, y) => y.cpu - x.cpu || y.mem - x.mem);
  res.count = rows.length;
  res.processes = formatRows(rows, max);
  if (rows.length > max) res.truncated = "showing the " + max + " busiest of " + rows.length + " — pass filter (name or pid) or port to narrow";
  return res;
}

module.exports = { listProcessesTool, parsePs, formatRows };
