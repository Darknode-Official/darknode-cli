"use strict";
// Operator + team identity for attribution (chargeback) and audit provenance.
// Resolution order, highest priority first:
//   1. Environment — DARKNODE_OPERATOR / DARKNODE_TEAM. This is the SSO / IdP hook:
//      an enterprise provisions these from its identity provider (an OIDC/SAML
//      session, a login wrapper, or CI secrets) so every turn is attributed to a
//      real person and team without the CLI implementing a browser SSO handshake.
//   2. Local config — .nexus/identity.json { "operator": "...", "team": "..." }.
//   3. Fallback — the OS username, so attribution is never blank.
// Pure + injectable (pass env/cwd) so it is unit-tested.
const os = require("os"), fs = require("fs"), path = require("path");

// Attribution lands in reports and the terminal: strip control chars (newline/ESC forge report
// lines or recolor the screen) and cap the length. A value that is ONLY junk falls through.
const clean = (v) => String(v == null ? "" : v).replace(/[\x00-\x1f\x7f-\x9f]/g, "").trim().slice(0, 128);

function resolveOperator(opts) {
  opts = opts || {};
  const env = opts.env || process.env;
  const cwd = opts.cwd || process.cwd();
  let operator = clean(env.DARKNODE_OPERATOR || env.DARKNODE_USER);
  let team = clean(env.DARKNODE_TEAM);
  let source = operator ? "sso-env" : "";
  if (!operator || !team) {
    try {
      const cfg = JSON.parse(fs.readFileSync(path.join(cwd, ".nexus", "identity.json"), "utf8"));
      if (!operator && cfg && cfg.operator) { operator = clean(cfg.operator); source = source || "config"; }
      if (!team && cfg && cfg.team) team = clean(cfg.team);
    } catch (_) {}
  }
  if (!operator) { try { operator = clean(os.userInfo().username); } catch (_) {} source = source || "os"; }
  if (!operator) { operator = "unknown"; source = source || "os"; }
  return { operator, team: team || "", source: source || "os" };
}

module.exports = { resolveOperator };
