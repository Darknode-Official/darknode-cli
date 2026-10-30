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
const { ipToInt, inCidr, cidrCalc } = require("../toolkit/scanutil");

// Commands that reach out and touch the target host itself.
// subrecon is active (engagement-gate.js classifies it cls:"scan") — it brute-
// forces subdomains against the target, so it belongs here or it slips the gate.
const ACTIVE = new Set(["scan", "nmap", "nuclei", "fuzz", "subrecon"]);

// RFC1918 + loopback + link-local + CGNAT + "this host" — i.e. your own infra.
const PRIVATE_V4 = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16", "100.64.0.0/10", "0.0.0.0/8"];
// Hostname suffixes that are, by convention, local/non-public.
const LOCAL_SUFFIX = /(^|\.)(localhost|local|internal|intranet|lan|test|example|invalid|localdomain)$/i;

// Reduce a raw argument (url / host:port / userinfo@host / [v6]) to a bare host.
function hostOf(raw) {
  let s = String(raw || "").trim();
  if (!s) return "";
  s = s.replace(/^[a-z][a-z0-9+.-]*:\/\//i, ""); // scheme://
  s = s.replace(/[/\\?#].*$/, "");               // path / query / fragment (URL() treats a backslash as "/": http://evil.com\@127.0.0.1 is evil.com)
  s = s.replace(/^[^@]*@/, "");                  // userinfo@
  if (s[0] === "[") { const m = s.match(/^\[([^\]]+)\]/); return (m ? m[1] : s).toLowerCase(); } // [v6]:port
  if ((s.match(/:/g) || []).length === 1) s = s.replace(/:\d+$/, ""); // host:port, but not a bare IPv6 literal
  return s.toLowerCase();
}

function isLocalTarget(raw) {
  // a bare CIDR (nmap 127.0.0.1/0) is a RANGE: local only if all of it sits in one private block - hostOf would drop the /bits
  const cm = /^\s*([0-9a-f:.]+)\/(\d{1,3})\s*$/i.exec(String(raw || ""));
  if (cm) { const c = cidrCalc(cm[1] + "/" + cm[2]); return !!c && PRIVATE_V4.some((p) => inCidr(c.network, p) && inCidr(c.broadcast, p)); }
  const h = hostOf(raw);
  if (!h) return false;
  if (h === "localhost") return true;
  if (/^::1$/.test(h) || /^fe[89a-f][0-9a-f]:/i.test(h) || /^fc[0-9a-f]{2}:/i.test(h) || /^fd[0-9a-f]{2}:/i.test(h)) return true; // v6 loopback / link-local fe80::/10 / site-local fec0::/10 / ULA
  if (ipToInt(h) !== null) return PRIVATE_V4.some((c) => inCidr(h, c));
  if (h === "::") return true; // unspecified address = this host
  // an IPv4 address carried in IPv6 (::ffff:169.254.169.254 - URL() rewrites it to ::ffff:a9fe:a9fe - or NAT64 64:ff9b::) reaches that IPv4 host
  // also the deprecated IPv4-compatible ::a.b.c.d and 6to4 2002:AABB:CCDD:: forms, where a host's stack routes them
  const m6to4 = /^2002:([0-9a-f]{1,4}):([0-9a-f]{1,4})(?::|$)/i.exec(h);
  if (m6to4) { const a = parseInt(m6to4[1], 16), b = parseInt(m6to4[2], 16), v4 = [a >> 8, a & 255, b >> 8, b & 255].join("."); if (PRIVATE_V4.some((c) => inCidr(v4, c))) return true; }
  const m4 = /^(?:::ffff:|64:ff9b::|::)(?:(\d+\.\d+\.\d+\.\d+)|([0-9a-f]{1,4}):([0-9a-f]{1,4}))$/i.exec(h);
  if (m4) { const v4 = m4[1] || [parseInt(m4[2], 16) >> 8, parseInt(m4[2], 16) & 255, parseInt(m4[3], 16) >> 8, parseInt(m4[3], 16) & 255].join("."); return ipToInt(v4) !== null && PRIVATE_V4.some((c) => inCidr(v4, c)); }
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

// Every argument that names a network target, not just the first: `nmap 127.0.0.1 evil.com`
// and `nuclei localhost -u evil.com` passed the local check and then scanned evil.com.
// Port specs (80,443 / 1-1000) and file names (out.txt, words.lst) are not targets.
const FILE_EXT = /\.(txt|lst|list|json|ya?ml|xml|csv|html?|log|nmap|gnmap|md|conf|cfg|out|sh|py|js)$/i;
function looksLikeTarget(a) {
  if (!a || /^[\d,\-]+$/.test(a)) return false;
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(a) || /^\[?[0-9a-f]*:[0-9a-f:.]+\]?$/i.test(a) || /^localhost(:\d+)?$/i.test(a)) return true;
  if (/^\d{1,3}(\.\d{1,3}){3}(\/\d{1,2})?(:\d+)?$/.test(a)) return true;
  return /^(?:[^@\s/]+@)?[a-z0-9-]+(\.[a-z0-9-]+)+\.?(:\d+)?$/i.test(a) && !FILE_EXT.test(a);
}
function targetsOf(args) {
  const out = [];
  for (const raw of args || []) {
    if (raw == null) continue;
    const v = String(raw).replace(/^-{1,2}[A-Za-z][\w-]*=/, ""); // --target=x / -u=x carry their value inline
    if (v[0] === "-") continue;
    for (const part of v.split(",")) if (looksLikeTarget(part.trim())) out.push(part.trim());
  }
  return out;
}
// guardActive over every target in argv; falls back to the first positional when none look like one.
function guardArgs(cmd, args, opts) {
  if (!ACTIVE.has(cmd)) return { allow: true };
  const ts = targetsOf(args);
  if (!ts.length) return guardActive(cmd, (args || []).find((a) => a && a[0] !== "-") || (args || [])[0], opts);
  let last = { allow: true };
  for (const t of ts) { last = guardActive(cmd, t, opts); if (!last.allow) return last; }
  return last;
}

module.exports = { ACTIVE, PRIVATE_V4, isLocalTarget, hostOf, guardActive, guardArgs, targetsOf };
