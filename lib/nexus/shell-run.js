"use strict";
// coderShell — run one shell command for the agent and return {code, output}.
// Output is kept head+tail so a noisy build can't flood memory; stdin is closed
// (a command that waits for input gets EOF instead of hanging the turn); git
// never prompts for credentials; and on timeout or interrupt the WHOLE process
// group is killed, so a background child holding the pipe can't keep it open.

const { spawn } = require("child_process");

function coderShell(command, cwd, opts) {
  opts = opts || {};
  return new Promise((resolve) => {
    const win = process.platform === "win32";
    // Own process group (POSIX) so a timeout/interrupt kills the whole tree — killing only
    // `sh` left a dev server or test runner holding the output pipe, and the turn hung.
    // GIT_TERMINAL_PROMPT=0 + a closed stdin make prompts fail fast instead of waiting
    // for input that can never come.
    const p = spawn(win ? "cmd.exe" : "/bin/sh", [win ? "/c" : "-c", command], { cwd, detached: !win, env: Object.assign({}, process.env, { GIT_TERMINAL_PROMPT: "0" }) });
    try { p.stdin.end(); } catch (_) {}
    // Keep the HEAD and (crucially) the TAIL: test/build runners print the failing
    // assertions and the "N failed" summary at the END, so a head-only cap hid every
    // real failure from diagnose and the agent. Collapse the middle, bounded by MAX.
    const HEAD = 8000, TAIL = 4000, MAX = 400000;
    let out = "", total = 0, timedOut = false, interrupted = false;
    const add = (s) => { if (opts.onData) { try { opts.onData(s); } catch (_) {} } total += s.length; out += s; if (out.length > MAX) out = out.slice(0, HEAD) + out.slice(-TAIL); };
    const killTree = () => { try { if (!win && p.pid) process.kill(-p.pid, "SIGKILL"); else p.kill("SIGKILL"); } catch (_) { try { p.kill("SIGKILL"); } catch (_) {} } };
    const ms = Math.max(1000, Math.min(600000, opts.timeoutMs || 120000));
    const to = setTimeout(() => { timedOut = true; killTree(); }, ms);
    const iv = opts.ctl ? setInterval(() => { if (opts.ctl.stopped) { interrupted = true; killTree(); } }, 200) : null;
    if (p.stdout) { p.stdout.setEncoding("utf8"); p.stdout.on("data", add); }
    if (p.stderr) { p.stderr.setEncoding("utf8"); p.stderr.on("data", add); }
    p.on("close", (code, sig) => {
      clearTimeout(to); if (iv) clearInterval(iv);
      let output = total > HEAD + TAIL ? out.slice(0, HEAD) + "\n...[" + (total - HEAD - TAIL) + " bytes trimmed]...\n" + out.slice(-TAIL) : (out || "(no output)");
      if (timedOut) output += "\n[timed out after " + Math.round(ms / 1000) + "s — the command and its child processes were killed. For servers/watchers use run_background, then wait_for]";
      else if (interrupted) output += "\n[interrupted — the command and its child processes were stopped]";
      else if (code == null && sig) output += "\n[killed by " + sig + "]";
      resolve({ code: timedOut ? 124 : interrupted ? 130 : code == null ? 128 : code, output, timedOut, interrupted });
    });
    p.on("error", (e) => { clearTimeout(to); if (iv) clearInterval(iv); resolve({ code: -1, output: "spawn error: " + e.message }); });
  });
}

module.exports = { coderShell };
