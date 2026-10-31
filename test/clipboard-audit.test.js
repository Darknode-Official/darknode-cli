"use strict";
// /copy suite: copyToClipboard from darknode.js picks a clipboard tool that can work in the
// current session (wl-copy needs Wayland, xclip/xsel need X), else reports OSC-52 honestly.
const fs = require("fs"), path = require("path");

let pass = 0, fail = 0;
const ok = (name, cond) => { if (cond) pass++; else { fail++; console.log("  \x1b[31mFAIL\x1b[0m " + name); } };

const src = fs.readFileSync(path.join(__dirname, "..", "darknode.js"), "utf8");
const i = src.indexOf("function copyToClipboard(");
let d = 0, body = ""; for (let k = src.indexOf("{", i); k < src.length; k++) { if (src[k] === "{") d++; else if (src[k] === "}" && --d === 0) { body = src.slice(i, k + 1); break; } }

function attempt(env, installed) {
  const spawned = [], saved = {};
  for (const k of ["WAYLAND_DISPLAY", "DISPLAY", "SSH_TTY", "SSH_CONNECTION"]) { saved[k] = process.env[k]; delete process.env[k]; }
  Object.assign(process.env, env);
  const fakeCp = { spawn: (bin) => { spawned.push(bin); return { on() {}, stdin: { end() {} } }; } };
  const fn = new Function("_cp", "hasBin", body + "\nreturn copyToClipboard;")(fakeCp, (b) => installed.includes(b));
  let osc = "";
  const said = fn("hello", { write: (s) => { osc += s; } });
  for (const k of Object.keys(saved)) { if (saved[k] === undefined) delete process.env[k]; else process.env[k] = saved[k]; }
  return { said, spawned, osc };
}

if (process.platform === "linux") {
  const all = ["wl-copy", "xclip", "xsel"];
  const x11 = attempt({ DISPLAY: ":0" }, all);
  ok("X11 with wl-clipboard installed uses xclip, not wl-copy", x11.spawned[0] === "xclip" && x11.said === "clipboard");
  const way = attempt({ WAYLAND_DISPLAY: "wayland-0", DISPLAY: ":0" }, all);
  ok("a Wayland session (with XWayland) uses wl-copy", way.spawned[0] === "wl-copy");
  const pureWay = attempt({ WAYLAND_DISPLAY: "wayland-0" }, ["xclip"]);
  ok("Wayland without X does not run xclip", pureWay.spawned.length === 0 && /OSC-52/.test(pureWay.said));
  const none = attempt({}, all);
  ok("no display at all runs no tool and says OSC-52", none.spawned.length === 0 && /OSC-52/.test(none.said));
  const xsel = attempt({ DISPLAY: ":0" }, ["xsel"]);
  ok("xsel is the fallback under X", xsel.spawned[0] === "xsel");
}
const ssh = attempt({ SSH_TTY: "/dev/pts/1", DISPLAY: ":0" }, ["xclip"]);
ok("over SSH only OSC-52 is used", ssh.spawned.length === 0 && /OSC-52/.test(ssh.said));
ok("OSC-52 is always written, base64-encoded", ssh.osc === "\x1b]52;c;" + Buffer.from("hello").toString("base64") + "\x07");

console.log("\n" + (fail ? "\x1b[31m" : "\x1b[32m") + pass + " passed, " + fail + " failed\x1b[0m  (clipboard)");
process.exit(fail ? 1 : 0);
