"use strict";
// IP scope classifier — offline, no lookups. Given an IPv4 or IPv6 address, report
// its RFC scope (private / loopback / link-local / CGNAT / documentation / multicast
// / reserved / global), whether it's publicly routable, and its reverse-DNS (PTR)
// name. Complements `ipinfo` (which geolocates a public IP over the network) with a
// pure, instant "what KIND of address is this" answer for firewall/allowlist review.

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
  else if (n === -1 >>> 0 || n === 0xffffffff) { scope = "broadcast"; routable = false; note = "limited broadcast"; }
  else if (a >= 224 && a <= 239) { scope = "multicast"; routable = false; note = "RFC 5771 multicast (class D)"; }
  else if (a >= 240) { scope = "reserved"; routable = false; note = "RFC 1112 reserved (class E)"; }
  const klass = a < 128 ? "A" : a < 192 ? "B" : a < 224 ? "C" : a < 240 ? "D" : "E";
  const ptr = o.slice().reverse().join(".") + ".in-addr.arpa";
  return { version: 4, address: o.join("."), scope, routable, note, klass, ptr };
}

function classifyV6(ip) {
  const s = String(ip).trim().toLowerCase();
  if (!/^[0-9a-f:]+$/.test(s) || s.indexOf(":") < 0) return null;
  let scope = "global", routable = true, note = "";
  if (s === "::1") { scope = "loopback"; routable = false; note = "RFC 4291 loopback"; }
  else if (s === "::") { scope = "unspecified"; routable = false; note = "unspecified address"; }
  else if (/^fe[89ab]/.test(s)) { scope = "link-local"; routable = false; note = "RFC 4291 link-local"; }
  else if (/^f[cd]/.test(s)) { scope = "unique-local"; routable = false; note = "RFC 4193 ULA"; }
  else if (s.startsWith("ff")) { scope = "multicast"; routable = false; note = "RFC 4291 multicast"; }
  else if (s.startsWith("2001:db8")) { scope = "documentation"; routable = false; note = "RFC 3849 documentation"; }
  else if (s.startsWith("::ffff:")) { scope = "ipv4-mapped"; routable = true; note = "IPv4-mapped IPv6"; }
  return { version: 6, address: s, scope, routable, note, klass: "-", ptr: "-" };
}

function classifyIp(ip) {
  return classifyV4(ip) || classifyV6(ip);
}
module.exports = { classifyIp, classifyV4, classifyV6 };
