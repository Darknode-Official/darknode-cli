"use strict";
// Safety-filter audit regressions: classifyDanger misses / false positives and scanSecrets /
// redact misses / false positives found by feeding realistic inputs. Secrets are fake but
// format-valid.
const { classifyDanger, scanSecrets, maskSecrets } = require("../lib/governance/security");
const { redact } = require("../lib/nexus/redact");

let pass = 0, fail = 0;
const ok = (name, cond) => { if (cond) pass++; else { fail++; console.log("  \x1b[31mFAIL\x1b[0m " + name); } };
const group = (t) => console.log("\n\x1b[1m" + t + "\x1b[0m");
const lvl = (c) => classifyDanger(c).level;
const red = (t) => redact(t, { sink: "audit", key: "k" }).text;

group("classifyDanger");
ok("rm --recursive (long flag) warns like rm -r", lvl("rm --recursive --force build") === "warn" && lvl("rm --recursive build") === "warn");
ok("git clean with split flags (-f -d, --force -d, -d --force) blocks like -fd", ["git clean -f -d", "git clean -d -f", "git clean --force -d", "git clean -d --force -x"].every((c) => lvl(c) === "block") && lvl("git clean -n -d") === "ok");
ok("chmod --recursive 777 / blocks like -R", lvl("chmod --recursive 777 /") === "block" && lvl("chmod --recursive 755 /") === "ok");
ok("curl | sudo -E bash (sudo with flags) is pipe-to-shell", lvl("curl x | sudo -E bash") === "block" && lvl("curl x | sudo -H sh") === "block");
ok(">| (noclobber override) onto a system file blocks like >", lvl("echo x >| /etc/hosts") === "block" && lvl("ls >| out.txt") === "ok");
ok("mv of the home directory blocks; mv inside it stays ok", ["mv ~ /tmp/x", "mv ~/ /tmp", "mv $HOME /tmp"].every((c) => lvl(c) === "block") && lvl("mv ~/proj ~/proj2") === "ok");
ok("git push deleting remote refs (--delete, :ref, -d, --mirror) blocks; normal pushes warn", ["git push origin :main", "git push --delete origin main", "git push -d origin v1", "git push origin --mirror"].every((c) => lvl(c) === "block") && ["git push origin main:main", "git push -u origin feat", "git push --follow-tags"].every((c) => lvl(c) === "warn"));
ok("rm under ~/ warns (like /home/<u>/sub); ~ itself still blocks", lvl("rm -rf ~/projects/app/build") === "warn" && lvl("rm -rf $HOME/projects/app/dist") === "warn" && ["rm -rf ~", "rm -rf ~/", "rm -rf ~/*", "rm -rf $HOME", "rm -rf \"$HOME/\"", "rm -rf ${HOME:?}/", "rm -rf $HOME/*", "rm -rf ~;ls"].every((c) => lvl(c) === "block"));
ok("backslash inside a word (r\\m) is seen through", lvl("r\\m -rf ~") === "block");

group("scanSecrets / redact");
const body = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7";
ok("ENCRYPTED and PGP private-key blocks are detected", scanSecrets("-----BEGIN ENCRYPTED PRIVATE KEY-----\n" + body + "\n-----END ENCRYPTED PRIVATE KEY-----").includes("private key") && scanSecrets("-----BEGIN PGP PRIVATE KEY BLOCK-----\nlQ" + body + "\n-----END PGP PRIVATE KEY BLOCK-----").includes("private key"));
const rd = "redis://:Xq7vR2mK9pLw4tZ8@localhost:6379/0";
ok("connection string with an empty username (redis://:pw@) is detected and redacted", scanSecrets(rd).length === 1 && !maskSecrets(rd).includes("Xq7vR2mK9pLw4tZ8") && !red(rd).includes("Xq7vR2mK9pLw4tZ8") && scanSecrets("postgres://user:${PGPASSWORD}@db/app").length === 0);
const npmrc = "//registry.npmjs.org/:_authToken=" + "3f2b9c1e-7a4d-4e8b-" + "9c2f-1a6d8e5b7c40"; // split so push protection does not read a test value as a live token
ok("legacy .npmrc _authToken (UUID) is detected, masked and redacted; ${NPM_TOKEN} is not", scanSecrets(npmrc).includes("npm token") && !maskSecrets(npmrc).includes("3f2b9c1e") && !red(npmrc).includes("3f2b9c1e") && scanSecrets("//registry.npmjs.org/:_authToken=${NPM_TOKEN}").length === 0);
ok("a *_URL / *_path key holding a URL or path is not a credential", ["TOKEN_URL=https://auth.example.com/oauth/token", "--private-key-path=/etc/ssl/key.pem", "private_key_path: /home/dev/.ssh/id_rsa"].every((t) => scanSecrets(t).length === 0) && red("private_key_path: /home/dev/.ssh/id_rsa") === "private_key_path: /home/dev/.ssh/id_rsa" && scanSecrets("api_key: Zx9-Qw3-Lp7-Mn2").length === 1);
ok("a quoted \"${VAR}\" reference is not a hardcoded credential; a literal still is", scanSecrets('"sessionToken": "${SESSION_TOKEN}"').length === 0 && scanSecrets('password: "${{ secrets.DB_PASSWORD }}"').length === 0 && scanSecrets('"password": "Tr0ub4dor&3x"').length === 1);

console.log("\n" + (fail ? "\x1b[31m" : "\x1b[32m") + pass + " passed, " + fail + " failed\x1b[0m  (safety-filter audit)");
process.exit(fail ? 1 : 0);
