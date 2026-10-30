"use strict";
// IP scope classifier — offline, no lookups. Given an IPv4 or IPv6 address, report
// its RFC scope (private / loopback / link-local / CGNAT / documentation / multicast
// / reserved / global), whether it's publicly routable, and its reverse-DNS (PTR)
// name. Complements `ipinfo` (which geolocates a public IP over the network) with a
// pure, instant "what KIND of address is this" answer for firewall/allowlist review.
const net = require("net");

function parseV4(ip) {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(String(ip).trim());
  if (!m) return null;
  const o = m.slice(1).map(Number);
  if (o.some((n) => n > 255)) return null;
  return o;
}

function classifyV4(ip) {
  const o = parseV4(ip);
  if (!o) return null;
  const [a, b] = o;
  const n = (o[0] << 24) | (o[1] << 16) | (o[2] << 8) | o[3];
  const inNet = (net, bits) => (n >>> (32 - bits)) === (net >>> (32 - bits));
  let scope = "global", routable = true, note = "";
  if (a === 0) { scope = "this-network"; routable = false; note = "RFC 1122 'this network'"; }
  else if (a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168)) { scope = "private"; routable = false; note = "RFC 1918 private"; }
  else if (a === 127) { scope = "loopback"; routable = false; note = "RFC 1122 loopback"; }
  else if (a === 169 && b === 254) { scope = "link-local"; routable = false; note = "RFC 3927 APIPA"; }
  else if (a === 100 && b >= 64 && b <= 127) { scope = "cgnat"; routable = false; note = "RFC 6598 carrier-grade NAT"; }
  else if (inNet((192 << 24) | (0 << 16) | (2 << 8), 24) || inNet((198 << 24) | (51 << 16) | (100 << 8), 24) || inNet((203 << 24) | (0 << 16) | (113 << 8), 24)) { scope = "documentation"; routable = false; note = "RFC 5737 TEST-NET"; }
  else if (a === 198 && (b === 18 || b === 19)) { scope = "benchmarking"; routable = false; note = "RFC 2544 benchmarking"; }
  else if ((n >>> 0) === 0xffffffff) { scope = "broadcast"; routable = false; note = "limited broadcast"; } // n is SIGNED (built with <<): it never equalled 0xffffffff, so 255.255.255.255 read as "reserved"
  else if (a >= 224 && a <= 239) { scope = "multicast"; routable = false; note = "RFC 5771 multicast (class D)"; }
  else if (a >= 240) { scope = "reserved"; routable = false; note = "RFC 1112 reserved (class E)"; }
  const klass = a < 128 ? "A" : a < 192 ? "B" : a < 224 ? "C" : a < 240 ? "D" : "E";
  const ptr = o.slice().reverse().join(".") + ".in-addr.arpa";
  return { version: 4, address: o.join("."), scope, routable, note, klass, ptr };
}

// Expand a valid IPv6 address to its 8 16-bit groups ("::" filled, a trailing dotted quad
// folded in), or null. Classifying on the numeric groups rather than string prefixes: "fe8::1"
// is 0fe8::1 (global, not link-local), "2001:db80::" is not 2001:db8::/32, and
// "0:0:0:0:0:0:0:1" IS loopback.
function v6Groups(s) {
  if (!net.isIPv6(s)) return null;
  let t = s;
  const q = /(\d+)\.(\d+)\.(\d+)\.(\d+)$/.exec(t);
  if (q) t = t.slice(0, q.index) + ((+q[1] << 8) | +q[2]).toString(16) + ":" + ((+q[3] << 8) | +q[4]).toString(16);
  const halves = t.split("::"), head = halves[0] ? halves[0].split(":") : [], tail = halves[1] ? halves[1].split(":") : [];
  const fill = halves.length === 2 ? 8 - head.length - tail.length : 0;
  return head.concat(Array(fill).fill("0"), tail).map((x) => parseInt(x, 16));
}

function classifyV6(ip) {
  const s = String(ip).trim().toLowerCase().replace(/%.*$/, ""); // drop a zone id (fe80::1%eth0)
  const g = v6Groups(s);
  if (!g) return null; // also rejects ":::" and 9-group strings the old charset check let through
  const zero5 = g[0] === 0 && g[1] === 0 && g[2] === 0 && g[3] === 0 && g[4] === 0;
  let scope = "global", routable = true, note = "";
  if (zero5 && g[5] === 0 && g[6] === 0 && g[7] === 1) { scope = "loopback"; routable = false; note = "RFC 4291 loopback"; }
  else if (g.every((x) => x === 0)) { scope = "unspecified"; routable = false; note = "unspecified address"; }
  else if ((g[0] & 0xffc0) === 0xfe80) { scope = "link-local"; routable = false; note = "RFC 4291 link-local"; }
  else if ((g[0] & 0xfe00) === 0xfc00) { scope = "unique-local"; routable = false; note = "RFC 4193 ULA"; }
  else if ((g[0] & 0xff00) === 0xff00) { scope = "multicast"; routable = false; note = "RFC 4291 multicast"; }
  else if (g[0] === 0x2001 && g[1] === 0x0db8) { scope = "documentation"; routable = false; note = "RFC 3849 documentation"; }
  else if (zero5 && g[5] === 0xffff) {
    const v4 = classifyV4([g[6] >> 8, g[6] & 255, g[7] >> 8, g[7] & 255].join("."));
    scope = "ipv4-mapped"; routable = v4.routable; note = "IPv4-mapped IPv6 (" + v4.address + ": " + v4.scope + ")"; // ::ffff:10.0.0.1 is as private as 10.0.0.1
  }
  return { version: 6, address: s, scope, routable, note, klass: "-", ptr: "-" };
}

function classifyIp(ip) {
  return classifyV4(ip) || classifyV6(ip);
}
module.exports = { classifyIp, classifyV4, classifyV6 };
