"use strict";
// One-shot subcommands print remote and repo text straight to the terminal (no TUI frame to
// clean it). A TXT record, commit message or source comment carrying ESC ] 0;...BEL (window
// title), ESC [ 2J (clear) or OSC 52 (clipboard) must not reach the terminal live.
const fs = require("fs"), os = require("os"), path = require("path"), dgram = require("dgram");
const { execFileSync, spawn } = require("child_process");

let pass = 0, fail = 0;
const ok = (name, cond) => { if (cond) pass++; else { fail++; console.log("  \x1b[31mFAIL\x1b[0m " + name); } };
const BIN = path.join(__dirname, "..", "darknode.js");
const LIVE = /\x1b(?!\[[0-9;]*m)/; // any escape that is not plain SGR colour
const home = fs.mkdtempSync(path.join(os.tmpdir(), "nx-esc-home-"));
const repo = fs.mkdtempSync(path.join(os.tmpdir(), "nx-esc-repo-"));
const env = { HOME: home, PATH: process.env.PATH, TERM: "xterm-256color" };
const git = (...a) => execFileSync("git", a, { cwd: repo, stdio: ["ignore", "pipe", "pipe"] });

git("init", "-q");
fs.writeFileSync(path.join(repo, "app.js"), "// TODO: fix \x1b]0;PWNED\x07 now\n// FIXME \x1b[2J wipe\n");
git("add", ".");
git("-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "feat: add \x1b]52;c;aGk=\x07 thing");

const run = (args, extra = {}) => new Promise((res) => {
  const p = spawn(process.execPath, [BIN, ...args], { cwd: repo, env: { ...env, ...extra }, stdio: ["ignore", "pipe", "pipe"] });
  let out = ""; p.stdout.on("data", (d) => (out += d)); p.stderr.on("data", (d) => (out += d));
  const t = setTimeout(() => p.kill("SIGKILL"), 15000);
  p.on("close", () => { clearTimeout(t); res(out); });
});

// A DNS server that answers every TXT query with a hostile record.
function evilDns() {
  const s = dgram.createSocket("udp4");
  s.on("message", (q, r) => {
    let i = 12; while (q[i]) i += q[i] + 1;
    const qend = i + 5, qtype = q.readUInt16BE(i + 1);
    const hdr = Buffer.from(q.slice(0, 12)); hdr[2] = 0x81; hdr[3] = 0x80; hdr.writeUInt16BE(1, 4);
    const txt = Buffer.from("v=spf1 \x1b]0;PWNED\x07\x1b[2J -all", "latin1");
    const ans = qtype === 16 ? Buffer.concat([Buffer.from([0xc0, 0x0c, 0, 16, 0, 1, 0, 0, 0, 60, 0, txt.length + 1, txt.length]), txt]) : Buffer.alloc(0);
    hdr.writeUInt16BE(qtype === 16 ? 1 : 0, 6); hdr.writeUInt16BE(0, 8); hdr.writeUInt16BE(0, 10);
    s.send(Buffer.concat([hdr, q.slice(12, qend), ans]), r.port, r.address);
  });
  return new Promise((res) => s.bind(0, "127.0.0.1", () => res(s)));
}

(async () => {
  for (const sub of ["changelog", "todo"]) {
    const out = await run([sub]);
    ok(sub + " prints the repo text", /fix|thing/.test(out));
    ok(sub + " sends no live escape from repo text", !LIVE.test(out));
  }
  const dns = await evilDns();
  const pre = path.join(home, "dns-pre.js");
  fs.writeFileSync(pre, 'require("dns").setServers(["127.0.0.1:' + dns.address().port + '"]);');
  const out = await run(["dns", "evil.test"], { NODE_OPTIONS: "--require " + pre });
  dns.close();
  ok("dns prints the TXT record", /TXT\s+v=spf1/.test(out));
  ok("dns sends no live escape from a TXT record", !LIVE.test(out));

  const src = fs.readFileSync(BIN, "utf8");
  ok("whois output is sanitised", /console\.log\(sanitizeTerm\(await whois\(/.test(src));
  ok("subs, headers server and ipinfo fields are sanitised", /r\.forEach\(\(s\) => console\.log\(sanitizeTerm\(String\(s\)\)\)\)/.test(src) && /" server:" \+ sanitizeTerm\(String\(r\.server\)\)/.test(src) && /cyan\(sanitizeTerm\(String\(v\)\)\)/.test(src));

  for (const d of [home, repo]) fs.rmSync(d, { recursive: true, force: true });
  console.log("\n" + (fail ? "\x1b[31m" : "\x1b[32m") + pass + " passed, " + fail + " failed\x1b[0m  (one-shot escapes)");
  process.exit(fail ? 1 : 0);
})();
