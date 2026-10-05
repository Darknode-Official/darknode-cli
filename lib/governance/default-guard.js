"use strict";
// NX-002 — default-posture guard.
//
// Outside engagement mode, commands that actively interact with a live REMOTE
// system (port scan, content fuzz, vuln templates) require EITHER a local/
// private target (your own lab) OR an explicit authorization acknowledgment
// (--authorized / DARKNODE_AUTHORIZED=1). Passive recon over public data
// (dns/whois/cert/headers/subs) is unrestricted.
//
// This is the lightweight default. Engagement mode (DARKNODE_ENGAGEMENT) uses
// the stronger signed-authorization gate instead and bypasses this one. The
// point: a target is not actionable by an active command until the operator has
// *said* they are authorized — it can never be reached silently by default.
const { ipToInt, inCidr } = require("../toolkit/scanutil");

// Commands that reach out and touch the target host itself.
const ACTIVE = new Set(["scan", "nmap", "nuclei", "fuzz"]);

// RFC1918 + loopback + link-local + CGNAT + "this host" — i.e. your own infra.
const PRIVATE_V4 = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16", "100.64.0.0/10", "0.0.0.0/8"];
// Hostname suffixes that are, by convention, local/non-public.
const LOCAL_SUFFIX = /(^|\.)(localhost|local|internal|intranet|lan|test|example|invalid|localdomain)$/i;

// Reduce a raw argument (url / host:port / userinfo@host / [v6]) to a bare host.
function hostOf(raw) {
  let s = String(raw || "").trim();
  if (!s) return "";
  s = s.replace(/^[a-z][a-z0-9+.-]*:\/\//i, ""); // scheme://
  s = s.replace(/[/?#].*$/, "");                 // path / query / fragment
  s = s.replace(/^[^@]*@/, "");                  // userinfo@
  if (s[0] === "[") { const m = s.match(/^\[([^\]]+)\]/); return (m ? m[1] : s).toLowerCase(); } // [v6]:port
  if ((s.match(/:/g) || []).length === 1) s = s.replace(/:\d+$/, ""); // host:port, but not a bare IPv6 literal
  return s.toLowerCase();
}

function isLocalTarget(raw) {
  const h = hostOf(raw);
  if (!h) return false;
  if (h === "localhost") return true;
  if (/^::1$/.test(h) || /^fe80:/i.test(h) || /^fc[0-9a-f]{2}:/i.test(h) || /^fd[0-9a-f]{2}:/i.test(h)) return true; // v6 loopback / link-local / ULA
  if (ipToInt(h) !== null) return PRIVATE_V4.some((c) => inCidr(h, c));
  if (h.indexOf(":") !== -1) return false; // any other IPv6 literal => remote
  return LOCAL_SUFFIX.test(h);
}

// cmd: the CLI verb. target: the raw target argument. opts.authorized: ack given.
// -> { allow: bool, scope?: "local"|"authorized", reason?: string }
function guardActive(cmd, target, opts) {
  const o = opts || {};
  if (!ACTIVE.has(cmd)) return { allow: true };           // passive / non-active verb
  if (isLocalTarget(target)) return { allow: true, scope: "local" };
  if (o.authorized) return { allow: true, scope: "authorized" };
  return { allow: false, reason: "active '" + cmd + "' against a non-local target (" + (hostOf(target) || "?") +
    ") needs authorization. Re-run with --authorized if you are permitted to test it, or use engagement mode " +
    "(DARKNODE_ENGAGEMENT with a signed authorization) for audited, scope-enforced testing." };
}

module.exports = { ACTIVE, PRIVATE_V4, isLocalTarget, hostOf, guardActive };
