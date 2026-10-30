"use strict";
// /fixshell suite (lib/nexus/shellfix.js): an oversized environment or shell snapshot makes every
// engine tool shell fail with E2BIG; repair must fix that without touching the conversation.
const fs = require("fs"), os = require("os"), path = require("path"), cp = require("child_process");
const sf = require("../lib/nexus/shellfix");

let pass = 0, fail = 0;
const ok = (name, cond) => { if (cond) pass++; else { fail++; console.log("  \x1b[31mFAIL\x1b[0m " + name); } };

// environment report
const big = "x".repeat(140 * 1024);
const r = sf.envReport({ A: "1", HUGE: big });
ok("env size counts K=V plus separators", r.total === ("A=1".length + 1) + ("HUGE=".length + big.length + 1));
ok("largest entry is listed first", r.largest[0].name === "HUGE");
ok("an entry over the safe limit is flagged", r.oversize.length === 1 && r.oversize[0] === "HUGE");
ok("multi-byte values are measured in bytes", sf.bytes("é") === 2);

// repair
ok("PATH lists keep first-seen order without repeats or blanks", sf.dedupeList("/a::/b:/a:/c:/b", ":") === "/a:/b:/c");
const env = { PATH: "/a:/b:/a", MANPATH: "/m:/m", KEEP: "small", HUGE: big };
const rep = sf.repairEnv(env, { sep: ":" });
ok("PATH and *PATH vars are deduped", env.PATH === "/a:/b" && env.MANPATH === "/m" && rep.deduped.length === 2);
ok("an entry too large to exec is dropped and reported", !("HUGE" in env) && rep.removed[0].name === "HUGE" && rep.removed[0].size === big.length);
ok("ordinary vars are left alone", env.KEEP === "small");
const env2 = { PATH: "/p:".repeat(50000) + "/q" };
sf.repairEnv(env2, { sep: ":" });
ok("PATH itself is never dropped, only deduped", env2.PATH === "/p:/q");

// the repaired environment really starts a process where the broken one could not (Linux)
if (process.platform === "linux") {
  const broken = Object.assign({}, process.env, { NEXUS_TEST_HUGE: big });
  const a = cp.spawnSync("sh", ["-c", "exit 0"], { env: broken });
  ok("an env var over 128 KB really makes exec fail with E2BIG", a.error && a.error.code === "E2BIG");
  sf.repairEnv(broken);
  const b = cp.spawnSync("sh", ["-c", "exit 0"], { env: broken });
  ok("after repairEnv the same shell starts", !b.error && b.status === 0);
}

// snapshots
const dir = fs.mkdtempSync(path.join(os.tmpdir(), "nx-snap-"));
fs.writeFileSync(path.join(dir, "snapshot-bash-1-small.sh"), "a".repeat(4000));
fs.writeFileSync(path.join(dir, "snapshot-bash-2-big.sh"), "b".repeat(sf.SNAP_WARN + 1));
fs.writeFileSync(path.join(dir, "notes.txt"), "c".repeat(sf.SNAP_WARN + 1));
const ls = sf.listSnapshots(dir);
ok("only snapshot-*.sh files are listed, largest first", ls.length === 2 && ls[0].file === "snapshot-bash-2-big.sh");
const gone = sf.cleanSnapshots(dir);
ok("default clean removes only oversized snapshots", gone.length === 1 && !fs.existsSync(path.join(dir, "snapshot-bash-2-big.sh")) && fs.existsSync(path.join(dir, "snapshot-bash-1-small.sh")));
ok("unrelated files in the folder are never touched", fs.existsSync(path.join(dir, "notes.txt")));
sf.cleanSnapshots(dir, { all: true });
ok("clean all removes every snapshot", sf.listSnapshots(dir).length === 0 && fs.existsSync(path.join(dir, "notes.txt")));
ok("a missing snapshot folder is not an error", sf.listSnapshots(path.join(dir, "nope")).length === 0 && sf.cleanSnapshots(path.join(dir, "nope")).length === 0);
fs.rmSync(dir, { recursive: true, force: true });
ok("snapshot folder is under ~/.claude", sf.snapDir("/h") === path.join("/h", ".claude", "shell-snapshots"));

// detection
ok("E2BIG errors are recognised", sf.isE2big("spawn E2BIG") && sf.isE2big("bash: Argument list too long") && sf.isE2big("status null error E2BIG"));
ok("ordinary errors are not", !sf.isE2big("command not found") && !sf.isE2big("") && !sf.isE2big(null));

// darknode.js wiring
const src = fs.readFileSync(path.join(__dirname, "..", "darknode.js"), "utf8");
ok("/fixshell is handled in the TUI", /cmd === "\/fixshell"/.test(src));
ok("/fixshell is listed in help", /\["\/fixshell", "repair/.test(src));
ok("a large prompt goes on stdin, not argv", /viaStdin \? \[\] : \[prompt\]/.test(src) && /cp\.stdin\.end\(viaStdin \? prompt : undefined\)/.test(src));
ok("a large system prompt goes through a file", /--append-system-prompt-file/.test(src));

console.log("\n" + (fail ? "\x1b[31m" : "\x1b[32m") + pass + " passed, " + fail + " failed\x1b[0m  (fixshell)");
process.exit(fail ? 1 : 0);
