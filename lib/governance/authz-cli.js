"use strict";
// `darknode authz …` — operator surface for the authorization & scope gate.
// Returns a process exit code. Plain output (no ANSI) so it is safe to pipe into tickets.
const fs = require("fs"), path = require("path");
const A = require("./authorization");
const G = require("./engagement-gate");

const HELP = `darknode authz — authorization & scope gate

  template <engagement-id>                      print an unsigned scope record to fill in
  keygen <key-id> [--out <dir>]                 create an authorizer keypair (private key stays with the authorizer)
  sign <record.json> --key <private.pem> --key-id <id> [--out <file>]
                                                sign a completed record (authorizer only)
  trust <key-id> <public.pem>                   add a public key to the trusted authorizers
  install <envelope.json> [--replace]           verify + install a signed authorization
  status <engagement-id>                        show validity, window, scope, revocation, audit-chain health
  check <engagement-id> <tool> [args…]          dry-run the gate for a command (audited, nothing runs)
  run <engagement-id> -- <tool> [args…]         run an external tool (nmap, nuclei) through the gate
  revoke <engagement-id> --reason "<why>"       hard stop: all further runs are denied, running tools are killed
  log <engagement-id> [--verify] [--tail N]     show / verify the hash-chained audit trail

Set DARKNODE_ENGAGEMENT=<id> to run darknode itself in engagement mode: only gated tools run.
Nothing is authorised until a trusted authorizer has signed the record.`;

function opt(rest, name) { const i = rest.indexOf(name); return i >= 0 ? rest[i + 1] : undefined; }
function template(id) {
  return {
    version: 1, engagement: id,
    client: { legalName: "", signatory: { name: "", title: "", email: "" } },
    agreement: { ref: "", sha256: "<sha256 of the signed agreement PDF>", signedAt: "<ISO-8601>" },
    assetOwnership: { confirmed: false, thirdPartyConsents: [] },
    window: { notBefore: "<ISO-8601 with offset>", notAfter: "<ISO-8601 with offset>" },
    emergencyContact: { name: "", channel: "" },
    allowedClasses: ["recon", "scan"],
    scope: { inScope: ["app.example.com", "*.example.com", "203.0.113.0/28"], outOfScope: ["admin.example.com"] },
    notes: "",
  };
}

async function authzCommand(rest) {
  const [sub, ...a] = rest;
  const out = (s) => console.log(s), err = (s) => console.error(s);
  try {
    switch (sub) {
      case "template": { if (!A.ID_RE.test(a[0] || "")) { err("usage: authz template <engagement-id>  (lowercase letters/digits/dashes, 3–64 chars)"); return 2; } out(JSON.stringify(template(a[0]), null, 2)); return 0; }
      case "keygen": {
        if (!a[0]) { err("usage: authz keygen <key-id> [--out <dir>]"); return 2; }
        const dir = opt(a, "--out") || process.cwd(), k = A.generateAuthorizerKey();
        const priv = path.join(dir, a[0] + ".private.pem"), pub = path.join(dir, a[0] + ".public.pem");
        fs.writeFileSync(priv, k.privatePem, { mode: 0o600, flag: "wx" }); fs.writeFileSync(pub, k.publicPem);
        out("private key: " + priv + "  (keep offline; whoever holds it can authorise targets)\npublic key:  " + pub + "\nnext: darknode authz trust " + a[0] + " " + pub); return 0;
      }
      case "sign": {
        const f = a[0], key = opt(a, "--key"), keyId = opt(a, "--key-id");
        if (!f || !key || !keyId) { err("usage: authz sign <record.json> --key <private.pem> --key-id <id> [--out <file>]"); return 2; }
        const rec = JSON.parse(fs.readFileSync(f, "utf8")); const v = A.validateRecord(rec);
        if (!v.ok) { err("record is not valid — refusing to sign:\n  " + v.errors.join("\n  ")); return 1; }
        const env = A.signRecord(rec, fs.readFileSync(key, "utf8"), keyId), dest = opt(a, "--out") || f.replace(/\.json$/, "") + ".signed.json";
        fs.writeFileSync(dest, JSON.stringify(env, null, 2)); out("signed → " + dest + "\ndigest " + A.recordDigest(rec)); return 0;
      }
      case "trust": {
        if (!a[0] || !a[1]) { err("usage: authz trust <key-id> <public.pem>"); return 2; }
        fs.mkdirSync(G.home(), { recursive: true, mode: 0o700 });
        const f = path.join(G.home(), "authorizers.json"), cur = G.trustedKeys(); cur[a[0]] = fs.readFileSync(a[1], "utf8");
        fs.writeFileSync(f, JSON.stringify(cur, null, 2), { mode: 0o600 }); out("trusted authorizers: " + Object.keys(cur).join(", ")); return 0;
      }
      case "install": {
        if (!a[0]) { err("usage: authz install <envelope.json> [--replace]"); return 2; }
        const r = G.installEnvelope(JSON.parse(fs.readFileSync(a[0], "utf8")), { replace: a.includes("--replace") });
        if (!r.ok) { err("REFUSED: " + r.error); return 1; } out("installed. record digest " + r.digest); return 0;
      }
      case "status": {
        const id = a[0]; if (!id) { err("usage: authz status <engagement-id>"); return 2; }
        const env = G.loadEnvelope(id), rev = G.loadRevocation(id);
        if (!env) { out("NO AUTHORIZATION on file for '" + id + "' — every run will be denied."); return 1; }
        const probe = A.evaluate({ envelope: env, trustedKeys: G.trustedKeys(), revoked: rev, class: env.record.allowedClasses[0], targets: [String(env.record.scope.inScope[0]).replace(/^\*\./, "x.")] });
        const r = env.record, chain = G.auditVerifyFile(G.auditFile(id));
        out("engagement  " + id + "\nclient      " + r.client.legalName + "\nagreement   " + r.agreement.ref + " (sha256 " + r.agreement.sha256.slice(0, 12) + "…, signed " + r.agreement.signedAt + ")\nwindow      " + r.window.notBefore + " → " + r.window.notAfter + "\nclasses     " + r.allowedClasses.join(", ") + "\nin scope    " + r.scope.inScope.join(", ") + "\nexcluded    " + (r.scope.outOfScope || []).join(", ") + "\nsigned by   " + env.signature.keyId + "\nrevoked     " + (rev ? rev.at + " — " + rev.reason : "no") + "\ngate state  " + (probe.allow || ["NOT_IN_SCOPE", "NO_TARGET", "BAD_TARGET", "OUT_OF_SCOPE_EXCLUDED"].includes(probe.code) ? "IN FORCE" : "DENYING (" + probe.code + ": " + probe.reason + ")") + "\naudit chain " + (chain.ok ? "intact (" + chain.count + " entries" + (chain.head ? ", head " + chain.head.slice(0, 12) : "") + ")" : "BROKEN at line " + chain.badLine + ": " + chain.reason));
        return chain.ok ? 0 : 1;
      }
      case "check": {
        const [id, tool, ...argv] = a; if (!id || !tool) { err("usage: authz check <engagement-id> <tool> [args…]"); return 2; }
        const d = G.authorize({ engagement: id, tool, argv, dryRun: true });
        out((d.allow ? "ALLOW " : "DENY  ") + "[" + d.code + "] " + d.reason + (d.allow ? "\n  targets: " + d.checked.map((c) => c.target + " ⊂ " + c.matched).join(", ") : "")); return d.allow ? 0 : 1;
      }
      case "run": {
        const dd = a.indexOf("--"); const id = a[0], tail = dd >= 0 ? a.slice(dd + 1) : a.slice(1);
        if (!id || !tail.length) { err("usage: authz run <engagement-id> -- <tool> [args…]"); return 2; }
        try { return (await G.runExternal(id, tail[0], tail.slice(1))).code; }
        catch (e) { if (e instanceof G.GateDenied) { err(e.message); return 1; } throw e; }
      }
      case "revoke": {
        const id = a[0], why = opt(a, "--reason"); if (!id || !why) { err('usage: authz revoke <engagement-id> --reason "<why>"'); return 2; }
        const r = G.revoke(id, why); out("REVOKED " + id + " at " + r.at + " — all runs denied, gated tools in flight will be terminated."); return 0;
      }
      case "log": {
        const id = a[0]; if (!id) { err("usage: authz log <engagement-id> [--verify] [--tail N]"); return 2; }
        const v = G.auditVerifyFile(G.auditFile(id));
        if (a.includes("--verify")) { out(v.empty ? "audit trail empty" : v.ok ? "audit chain intact: " + v.count + " entries, head " + v.head : "AUDIT CHAIN BROKEN at line " + v.badLine + ": " + v.reason); return v.ok ? 0 : 1; }
        for (const e of G.auditTail(id, parseInt(opt(a, "--tail"), 10) || 20)) out(e.seq + " " + e.ts + " " + e.event + (e.tool ? " " + e.tool : "") + (e.code ? " [" + e.code + "]" : "") + (e.targets && e.targets.length ? " → " + e.targets.join(",") : "") + (e.reason ? " — " + e.reason : "") + " (" + (e.operator || "?") + ")");
        return v.ok ? 0 : 1;
      }
      default: out(HELP); return sub ? 2 : 0;
    }
  } catch (e) { err("authz: " + (e && e.message || e)); return 1; }
}
module.exports = { authzCommand, template, HELP };
