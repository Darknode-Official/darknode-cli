"use strict";
// Toolkit audit (lib/toolkit/*, lib/nexus/nmap-parser.js, report-generator.js, vuln-scanner.js):
// encoders that must round-trip, calculators checked against published vectors, classifiers on
// edge ranges, parsers on real nmap output, regexes that must stay linear on 100 KB input, and
// report text that must not carry live HTML. No network.
const fs = require("fs");
const path = require("path");
const { b58encode, b58decode } = require("../lib/toolkit/base58");
const { base32encode, base32decode } = require("../lib/toolkit/base32");
const { ENC } = require("../lib/toolkit/encoders");
const { rot } = require("../lib/toolkit/rot");
const { xorEncryptHex, xorDecryptHex } = require("../lib/toolkit/xorcipher");
const { hexdump } = require("../lib/toolkit/hexdump");
const { analyzeJwt } = require("../lib/toolkit/jwt");
const { luhnValid, luhnCheckDigit } = require("../lib/toolkit/luhn");
const { hotp, totp } = require("../lib/toolkit/totp");
const { shannon, assess } = require("../lib/toolkit/entropy");
const { convert } = require("../lib/toolkit/epoch");
const { digests } = require("../lib/toolkit/hashing");
const { classifyIp } = require("../lib/toolkit/ipclass");
const { parsePorts, idHash, cidrCalc, inCidr } = require("../lib/toolkit/scanutil");
const { parseUA } = require("../lib/toolkit/useragent");
const { defang, refang } = require("../lib/toolkit/ioc");
const W = require("../lib/toolkit/web-scanner");
const N = require("../lib/nexus/nmap-parser");
const RG = require("../lib/nexus/report-generator");

let pass = 0, fail = 0;
const ok = (name, cond) => { if (cond) pass++; else { fail++; console.log("  \x1b[31mFAIL\x1b[0m " + name); } };
const group = (t) => console.log("\n\x1b[1m" + t + "\x1b[0m");
const fast = (fn, ms = 300) => { const t = Date.now(); fn(); return Date.now() - t < ms; };
const throwsNot = (fn) => { try { fn(); return true; } catch (_) { return false; } };

group("encoders");
ok("base58: one zero byte is '1', not '11'", b58encode(Buffer.from([0])) === "1" && b58encode(Buffer.from([0, 0])) === "11");
ok("base58: '1' decodes to ONE zero byte", b58decode("1").equals(Buffer.from([0])));
ok("base58: leading zeros round-trip", b58decode(b58encode(Buffer.from([0, 0, 1, 255]))).equals(Buffer.from([0, 0, 1, 255])));
ok("base58: known vector", b58encode("hello world") === "StV1DL6CwTryKyV");
ok("base58: invalid char -> null, empty -> empty", b58decode("0OIl") === null && b58decode("").length === 0 && b58encode("") === "");
ok("base32: RFC 4648 vectors round-trip", ["", "f", "fo", "foo", "foob", "fooba", "foobar"].every((v) => base32decode(base32encode(v)) === v) && base32encode("foobar") === "MZXW6YTBOI======");
ok("base32: padding followed by a newline still decodes", base32decode("MZXW6===\n") === "foo" && base32decode("mzxw6=== ") === "foo");
ok("base32: '=' mid-string / bad char -> null", base32decode("MZ=XW6") === null && base32decode("MZXW1") === null);
ok("hex decode: a bad pair is reported, not silently truncated", ENC.hexd("4g41") === "(invalid hex)" && ENC.hexd("414") === "(invalid hex)");
ok("hex decode: dump separators and 0x prefix", ENC.hexd("41 42") === "AB" && ENC.hexd("41:42") === "AB" && ENC.hexd("0x4142") === "AB");
ok("rot13 / rot -3 / NaN n is identity", rot(13, "Hello") === "Uryyb" && rot(-3, "abc") === "xyz" && rot(NaN, "abc") === "abc" && rot(1.7, "a") === "b");
ok("xor round-trip (utf8) and bad hex -> null", xorDecryptHex("k", xorEncryptHex("k", "héllo")) === "héllo" && xorDecryptHex("k", "zz") === null);
ok("hexdump offsets: row 2 at 0x10, trailer = length", (() => { const l = hexdump("A".repeat(17)).split("\n"); return l[1].startsWith("00000010  41") && l[2] === "00000011"; })());
ok("hexdump: negative width does not hang", hexdump("abc", { width: -1 }).split("\n").length === 4);
{
  const none = analyzeJwt("eyJhbGciOiJub25lIn0.eyJzdWIiOjEsImV4cCI6MTB9.", 100);
  ok("jwt: alg none flagged, expired computed", none && none.alg === "none" && none.warnings.length === 1 && none.state === "expired");
  ok("jwt: bad segments -> null", analyzeJwt("a") === null && analyzeJwt("bad.bad") === null && analyzeJwt("") === null);
}

group("checksums and generators");
ok("luhn: spaces/dashes ignored, letters rejected", luhnValid("4539 1488 0343 6467") && luhnValid("4539-1488-0343-6467") && !luhnValid("4539a14880343 6467") && !luhnValid(" "));
ok("luhn: check digit for 7992739871 is 3", luhnCheckDigit("7992739871") === 3);
{
  // RFC 6238 Appendix B (8 digits, the per-algorithm seeds)
  const k1 = base32encode("12345678901234567890"), k256 = base32encode("12345678901234567890123456789012"), k512 = base32encode("1234567890123456789012345678901234567890123456789012345678901234");
  const V = [[59, "94287082", "46119246", "90693936"], [1111111109, "07081804", "68084774", "25091201"], [1111111111, "14050471", "67062674", "99943326"], [1234567890, "89005924", "91819424", "93441116"], [2000000000, "69279037", "90698825", "38618901"], [20000000000, "65353130", "77737706", "47863826"]];
  ok("totp: RFC 6238 vectors (sha1/256/512, incl. a counter past 2^32)", V.every(([t, a, b, c]) => totp(k1, { time: t, digits: 8 }) === a && totp(k256, { time: t, digits: 8, algo: "sha256" }) === b && totp(k512, { time: t, digits: 8, algo: "sha512" }) === c));
  ok("totp: lowercase, unpadded, spaced secrets parse", totp(k1.toLowerCase().replace(/=/g, ""), { time: 59 }) === "287082" && totp("gezd gnbv gy3t qojq gezd gnbv gy3t qojq", { time: 59 }) === "287082");
  ok("totp: pre-1970 time -> null, not a RangeError", throwsNot(() => totp(k1, { time: -1 })) && totp(k1, { time: -1 }) === null);
  ok("hotp: RFC 4226 vectors", [0, 1, 2, 9].map((c) => hotp(Buffer.from("12345678901234567890"), c)).join() === "755224,287082,359152,520489");
}
ok("entropy: one repeated emoji is 0 bits, not 0.5", shannon("\u{1F600}\u{1F600}") === 0 && shannon("\u{1F600}a") === 1 && assess("\u{1F600}a").totalBits === 2);
ok("epoch: -1 is one second before 1970, not the year 2001", convert("-1").iso === "1969-12-31T23:59:59.000Z");
ok("epoch: seconds vs ms, fractional seconds", convert("1700000000").epochMs === 1700000000000 && convert("1700000000000").epochSeconds === 1700000000 && convert("1700000000.5").epochMs === 1700000000500);
ok("epoch: a zone-less ISO date-time is UTC regardless of TZ", convert("2024-01-01T10:00:00").iso === "2024-01-01T10:00:00.000Z" && convert("2024-01-01 10:00").iso === "2024-01-01T10:00:00.000Z" && convert("2024-01-01T10:00:00+02:00").iso === "2024-01-01T08:00:00.000Z");
ok("epoch: garbage -> null, huge -> null", convert("nope") === null && convert("9".repeat(20)) === null);
{
  const d = Object.fromEntries(digests("abc"));
  ok("hash vectors (abc)", d.md5 === "900150983cd24fb0d6963f7d28e17f72" && d.sha1 === "a9993e364706816aba3e25717850c26c9cd0d89d" && d.sha256 === "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" && d.sha512.startsWith("ddaf35a193617aba"));
}
ok("hashid: sha256crypt / yescrypt / argon2 / bcrypt $2x$ recognised", idHash("$5$salt$abc") === "sha256crypt" && idHash("$y$j9T$salt$hash") === "yescrypt" && idHash("$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$aGFzaA") === "argon2" && idHash("$2x$10$abc") === "bcrypt");
ok("hashid: hex lengths, non-string input", /MD5/.test(idHash("a".repeat(32))) && /SHA-256/.test(idHash("a".repeat(64))) && idHash(null) === "unknown");

group("network helpers");
const scope = (a) => { const r = classifyIp(a); return r && r.scope; };
ok("ipv4: 255.255.255.255 is broadcast (was 'reserved')", scope("255.255.255.255") === "broadcast" && scope("240.0.0.1") === "reserved");
ok("ipv4: edges", scope("100.64.0.0") === "cgnat" && scope("100.128.0.0") === "global" && scope("172.31.255.255") === "private" && scope("172.32.0.0") === "global" && scope("198.51.100.7") === "documentation" && scope("256.1.1.1") === null);
ok("ipv6: compressed short groups are not link-local/ULA/multicast", scope("fe8::1") === "global" && scope("fc::1") === "global" && scope("ff::1") === "global");
ok("ipv6: 2001:db80:: is not the doc prefix; 2001:0db8:: is", scope("2001:db80::1") === "global" && scope("2001:0db8::1") === "documentation");
ok("ipv6: uncompressed loopback / unspecified", scope("0:0:0:0:0:0:0:1") === "loopback" && scope("0::0") === "unspecified");
ok("ipv6: invalid strings rejected", classifyIp(":::") === null && classifyIp("1:2:3:4:5:6:7:8:9") === null && classifyIp("fe80::g") === null);
ok("ipv6: mapped dotted form parsed, routability follows the v4", scope("::ffff:127.0.0.1") === "ipv4-mapped" && classifyIp("::ffff:10.0.0.1").routable === false && classifyIp("::ffff:8.8.8.8").routable === true);
ok("ipv6: zone id and real ranges", scope("fe80::1%eth0") === "link-local" && scope("febf::1") === "link-local" && scope("fd12::1") === "unique-local" && scope("ff02::1") === "multicast" && scope("2606:4700::1") === "global");
{
  const z = cidrCalc("1.2.3.4/0"), a = cidrCalc("10.0.0.1/31"), b = cidrCalc("10.0.0.1/32");
  ok("cidr /0", z.network === "0.0.0.0" && z.broadcast === "255.255.255.255" && z.hosts === 4294967294);
  ok("cidr /31 and /32", a.hosts === 2 && a.firstUsable === "10.0.0.0" && a.lastUsable === "10.0.0.1" && b.hosts === 1 && b.network === "10.0.0.1");
  ok("cidr invalid", cidrCalc("10.0.0.1/33") === null && cidrCalc("10.0.0/8") === null && cidrCalc("") === null && cidrCalc("300.0.0.0/8") === null);
  ok("inCidr", inCidr("255.255.255.255", "0.0.0.0/0") === true && inCidr("10.0.0.2", "10.0.0.1/31") === false && inCidr("x", "10.0.0.0/8") === null);
}
ok("ports: a list may mix ranges; no fractions, no repeats", parsePorts("22,80-82").join() === "22,80,81,82" && parsePorts("1.5,80").join() === "80" && parsePorts("80,80").join() === "80" && parsePorts("1-999999999").length === 65535);
ok("useragent: browser/os basics", (() => { const u = parseUA("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0"); return u.browser === "Edge" && u.os === "Windows 10/11" && !u.bot; })());
ok("useragent: 100 KB pathological UA stays fast", fast(() => { parseUA("Version/1 ".repeat(10000)); parseUA("iPhone ".repeat(14000)); parseUA("Trident ".repeat(12000)); }));

group("ioc + body scanning (ReDoS)");
ok("defang/refang round-trip, idempotent defang", refang(defang("https://a.evil.com/x?y=1@2")) === "https://a.evil.com/x?y=1@2" && defang(defang("evil.com")) === "evil[.]com");
ok("refang variants", refang("hxxps[://]evil[dot]com") === "https://evil.com" && refang("a [at] b(.)c") === "a@b.c");
ok("defang/refang on 100 KB lines is linear", fast(() => { defang("a.".repeat(50000)); refang("[".repeat(100000)); refang(" ".repeat(100000) + "x"); }));
ok("body scan: 100 KB of letters no longer takes seconds (email regex)", fast(() => { W.scanResponseBody("a".repeat(100000)); W.scanResponseBody("x@" + "a-".repeat(50000) + "!"); W.scanResponseBody("PostgreSQL ".repeat(9000)); }, 500));
ok("body scan: still finds emails and SQL errors", (() => { const r = W.scanResponseBody("mail first.last+tag@sub.example.co.uk; PostgreSQL query failed: ERROR"); return r.findings.some((f) => f.name === "Email Addresses" && f.samples[0] === "first.last+tag@sub.example.co.uk") && r.findings.some((f) => f.name === "SQL Error Messages"); })());
ok("csp: a repeated directive keeps the FIRST (as browsers do)", W.validateCSP("script-src 'self'; script-src * 'unsafe-inline'").directives["script-src"].join(" ") === "'self'");

group("nmap parsers");
const XML = `<?xml version="1.0"?><nmaprun scanner="nmap" args="nmap -sV -sC 10.0.0.1 ::1" start="1700000000" version="7.94">
<host><status state="up" reason="echo-reply"/><address addr="10.0.0.1" addrtype="ipv4"/><address addr="AA:BB:CC:DD:EE:FF" addrtype="mac" vendor="A &amp; B"/>
<hostnames><hostname name="router.lan" type="PTR"/></hostnames><ports><extraports state="closed" count="998"/>
<port protocol="tcp" portid="22"><state state="open" reason="syn-ack"/><service name="ssh" product="OpenSSH" version="8.2p1"><cpe>cpe:/a:openbsd:openssh:8.2p1</cpe></service><script id="ssh-hostkey" output="&#xa;  3072 aa:bb (RSA)"/><script id="banner" output="x &amp;lt;tag&amp;gt;"></script></port>
<port protocol="tcp" portid="80"><state state="open" reason="syn-ack"/><service name="http" product="nginx" version="1.18.0"/><script id="http-title" output="T"><elem key="title">Site &lt;b&gt;</elem></script><script id="vulners" output="v"><table key="cpe"><table><elem key="id">CVE-2021-23017</elem></table><elem>CVE-2019-20372</elem></table></script></port>
</ports><hostscript><script id="smb-os-discovery" output="OS: Windows"/></hostscript></host>
<host><status state="up"/><address addr="::1" addrtype="ipv6"/><ports><port protocol="tcp" portid="631"><state state="open"/><service name="ipp"/></port></ports></host>
<runstats><finished time="1700000020"/><hosts up="2" down="0" total="2"/></runstats></nmaprun>`;
{
  const r = N.parseNmapXML(XML), h = r.hosts[0], p22 = h.ports[0], p80 = h.ports[1];
  ok("xml: 2 hosts incl. IPv6, MAC + vendor unescaped", r.hosts.length === 2 && r.hosts[1].ip === "::1" && h.mac === "AA:BB:CC:DD:EE:FF" && h.addresses[1].vendor === "A & B");
  ok("xml: self-closing script is not doubled and does not swallow the next one", p22.scripts.map((s) => s.id).join() === "ssh-hostkey,banner");
  ok("xml: &#xa; in script output decodes to a newline", p22.scripts[0].output === "\n  3072 aa:bb (RSA)");
  ok("xml: &amp;lt; decodes once (to &lt;), not twice", p22.scripts[1].output === "x &lt;tag&gt;");
  ok("xml: elem values unescaped, keyless list elems kept", p80.scripts[0].elements[0].value === "Site <b>" && p80.scripts[1].elements.map((e) => e.value).join() === "CVE-2021-23017,CVE-2019-20372");
  ok("xml: hostscript, cpe, runstats", h.scripts[0].id === "smb-os-discovery" && p22.service.cpe[0] === "cpe:/a:openbsd:openssh:8.2p1" && r.runStats.durationSeconds === 20);
  ok("xml: malformed input does not throw", throwsNot(() => { N.parseNmapXML("<nmaprun>"); N.parseNmapXML("<host><status state=\"up\"/>"); N.parseNmapXML("<nmaprun start=\"x\"><host></host></nmaprun>"); }));
  ok("xml: pathological input stays fast", fast(() => { N.parseNmapXML("<host " + "a".repeat(100000)); N.parseNmapXML("<script ".repeat(20000)); }));
}
{
  const g = N.parseNmapGrep("# Nmap 7.94 scan initiated Mon Jan  1 00:00:00 2024 as: nmap -oG - x\nHost: 10.0.0.1 (router.lan)\tStatus: Up\nHost: 10.0.0.1 (router.lan)\tPorts: 22/open/tcp//ssh//OpenSSH 8.2p1 Ubuntu/, 80/open/tcp//http//nginx 1.18.0/\tIgnored State: closed (998)\tOS: Linux 5.X\tSeq Index: 260\nHost: fe80::1 ()\tStatus: Up\nHost: fe80::1 ()\tPorts: 631/open/tcp//ipp//CUPS 2.4/\n# Nmap done at Mon Jan  1 00:00:20 2024 -- 2 IP addresses (2 hosts up) scanned in 20.00 seconds");
  ok("grep: Status+Ports lines merge, IPv6 host, versions split", g.hosts.length === 2 && g.hosts[0].ports.map((p) => p.portId + ":" + p.service.product + ":" + p.service.version).join() === "22:OpenSSH:8.2p1,80:nginx:1.18.0" && g.hosts[1].addresses[0].addrtype === "ipv6" && g.hosts[0].os[0].name === "Linux 5.X");
  ok("grep: run stats", g.runStats.hostsTotal === 2 && g.runStats.hostsUp === 2 && g.scanInfo.version === "7.94");
  ok("grep: 'Host: 1:1:1:...' (100 KB) no longer backtracks for seconds", fast(() => N.parseNmapGrep("Host: " + "1:".repeat(50000) + " ")));
  ok("grep: junk lines ignored", throwsNot(() => N.parseNmapGrep("Host: \tPorts: x\ngarbage")));
}

group("report generator escaping");
{
  const evil = "<img src=x onerror=alert(1)>";
  const md = RG.formatFinding({ summary: evil + " | x", host: "h|1", hostname: "a\nb", port: 80, service: "<s>", description: "<script>x</script>\nline2", evidence: "a\n```\n<b>", remediation: "<i>fix</i>", references: [evil] });
  ok("finding: no raw HTML from finding text", !/<img|<script|<s>|<i>/.test(md.replace(/^`{3,}[\s\S]*?^`{3,}$/m, "")));
  ok("finding: '|' and newlines cannot break the table row", /\| Host \| h\\\|1 \(a b\) \|/.test(md));
  ok("finding: evidence holding ``` gets a longer fence", /^````$/m.test(md) && md.includes("a\n```\n<b>"));
  ok("finding: description keeps its line breaks", md.includes("&lt;script&gt;x&lt;/script&gt;\nline2"));
  const data = { findings: [{ severity: "high", summary: evil, host: "10.0.0.1", port: 80, remediation: evil, cve: ["CVE-1|<x>"] }], hosts: [{ ip: "10.0.0.1", status: "up", hostnames: [{ name: evil }], os: [{ name: evil, accuracy: 9 }], ports: [{ portId: 80, state: "open", protocol: "tcp", service: { name: evil, version: "|" } }] }], scanInfo: { args: "nmap `id` | x" } };
  const all = RG.listTemplates().map((t) => RG.generateReport(t.id, JSON.parse(JSON.stringify(data)), { organization: evil, assessor: evil })).join("\n");
  ok("every template: no raw HTML anywhere, no section errors", !/<img|<x>/.test(all) && !/Error generating section/.test(all));
  const inc = RG.generateReport("incident", { findings: [] }, { incident: { description: evil, timeline: [{ time: "t", event: evil, detail: "a|b" }], iocs: [{ type: "url", value: "a`b|c", context: evil }], lessonsLearned: [evil] } });
  ok("incident report: IOC code span survives a backtick, no raw HTML", !/<img/.test(inc) && inc.includes("`` a`b\\|c ``"));
}

console.log("\n" + (fail ? "\x1b[31m" : "\x1b[32m") + pass + " passed, " + fail + " failed\x1b[0m  (toolkit audit)");
process.exit(fail ? 1 : 0);
