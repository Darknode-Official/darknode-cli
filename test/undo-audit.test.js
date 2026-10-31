"use strict";
// /undo + /redo suite: nexusCheckpoint / nexusRestore from darknode.js, run against a real
// temporary git repo. A path the snapshot never covers (outside the repo, inside a nested
// repo) must not be mistaken for a file the turn created and deleted on /undo.
const fs = require("fs"), os = require("os"), path = require("path"), cp = require("child_process");

let pass = 0, fail = 0;
const ok = (name, cond) => { if (cond) pass++; else { fail++; console.log("  \x1b[31mFAIL\x1b[0m " + name); } };

const src = fs.readFileSync(path.join(__dirname, "..", "darknode.js"), "utf8");
const fnSrc = (name) => { const i = src.indexOf("function " + name + "("); if (i < 0) throw new Error("missing " + name); let d = 0, j = src.indexOf("{", i); for (let k = j; k < src.length; k++) { if (src[k] === "{") d++; else if (src[k] === "}" && --d === 0) return src.slice(i, k + 1); } throw new Error("unbalanced " + name); };
const api = new Function("_cp", "require", ["nexusCheckpoint", "inSnapshotScope", "nexusRestore"].map(fnSrc).join("\n") + "\nreturn { nexusCheckpoint, nexusRestore, inSnapshotScope };")(cp, require);

const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "nx-undo-")));
const proj = path.join(root, "proj"), outside = path.join(root, "outside");
fs.mkdirSync(proj); fs.mkdirSync(outside);
const git = (args, cwd) => cp.execFileSync("git", args, { cwd: cwd || proj, stdio: "ignore" });
git(["init", "-q"]);
fs.writeFileSync(path.join(proj, "in.txt"), "before\n");
fs.writeFileSync(path.join(proj, ".gitignore"), ".env.local\n");
fs.writeFileSync(path.join(proj, ".env.local"), "SECRET=1\n");
fs.writeFileSync(path.join(outside, "cfg"), "keep me\n");
fs.mkdirSync(path.join(proj, "nested")); git(["init", "-q"], path.join(proj, "nested"));
fs.writeFileSync(path.join(proj, "nested", "lib.txt"), "nested before\n");
const idEnv = Object.assign({}, process.env, { GIT_AUTHOR_NAME: "t", GIT_AUTHOR_EMAIL: "t@test", GIT_COMMITTER_NAME: "t", GIT_COMMITTER_EMAIL: "t@test" });
cp.execFileSync("git", ["add", "-A"], { cwd: path.join(proj, "nested"), stdio: "ignore" }); cp.execFileSync("git", ["commit", "-qm", "init"], { cwd: path.join(proj, "nested"), env: idEnv, stdio: "ignore" }); // a real nested clone has commits

const tree = api.nexusCheckpoint(proj);
ok("a checkpoint is taken in a git repo", typeof tree === "string" && /^[0-9a-f]{40,64}$/.test(tree));

// the "turn": edit a tracked file, create a new one, and edit files the snapshot cannot hold
fs.writeFileSync(path.join(proj, "in.txt"), "after\n");
fs.writeFileSync(path.join(proj, "new.txt"), "created\n");
fs.writeFileSync(path.join(outside, "cfg"), "edited by the turn\n");
fs.writeFileSync(path.join(proj, "nested", "lib.txt"), "nested after\n");
fs.writeFileSync(path.join(proj, ".env.local"), "SECRET=2\n");
const paths = ["in.txt", "new.txt", "../outside/cfg", "nested/lib.txt", ".env.local"];

ok("scope: a repo file is covered", api.inSnapshotScope(proj, "in.txt") && api.inSnapshotScope(proj, "new.txt"));
ok("scope: a file outside the repo is not", !api.inSnapshotScope(proj, "../outside/cfg") && !api.inSnapshotScope(proj, path.join(outside, "cfg")));
ok("scope: a file in a nested repo is not", !api.inSnapshotScope(proj, "nested/lib.txt"));

const done = api.nexusRestore(proj, tree, paths);
ok("undo succeeds", done === true);
ok("an edited tracked file is restored", fs.readFileSync(path.join(proj, "in.txt"), "utf8") === "before\n");
ok("a file the turn created is removed", !fs.existsSync(path.join(proj, "new.txt")));
ok("a file outside the repo the turn edited is NOT deleted", fs.existsSync(path.join(outside, "cfg")) && fs.readFileSync(path.join(outside, "cfg"), "utf8") === "edited by the turn\n");
ok("a file in a nested repo the turn edited is NOT deleted", fs.existsSync(path.join(proj, "nested", "lib.txt")));
ok("a git-ignored file is still kept", fs.existsSync(path.join(proj, ".env.local")));
const kept = api.nexusRestore.kept || [];
ok("every left-alone file is reported", ["../outside/cfg", "nested/lib.txt", ".env.local"].every((p) => kept.includes(p)) && !kept.includes("new.txt"));

fs.writeFileSync(path.join(proj, "in.txt"), "x\n");
ok("a missing snapshot restores and deletes nothing", api.nexusRestore(proj, null, ["in.txt"]) === false && fs.readFileSync(path.join(proj, "in.txt"), "utf8") === "x\n");
ok("no paths restores nothing (never a full-tree clobber)", api.nexusRestore(proj, tree, []) === true);
ok("outside a git repo nothing is in scope", !api.inSnapshotScope(outside, "cfg"));
ok("/undo's note names the new reasons", /outside the repo or in a nested repo/.test(src));

fs.rmSync(root, { recursive: true, force: true });
console.log("\n" + (fail ? "\x1b[31m" : "\x1b[32m") + pass + " passed, " + fail + " failed\x1b[0m  (undo)");
process.exit(fail ? 1 : 0);
