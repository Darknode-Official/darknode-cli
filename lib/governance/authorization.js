"use strict";
// Authorization & scope model — pure logic (fs-free, network-free). Answers one
// question: "is this action, on this target, covered by a signed, in-force written
// authorization?" Every path FAILS CLOSED: malformed input, unknown target shape,
// bad signature, expired window, anything unexpected => deny.
//
// An authorization is an ENVELOPE: { record, signature }.
//   record    the scope record (client, agreement reference, in/out-of-scope assets,
//             permitted action classes, testing window, emergency contact)
//   signature Ed25519 over canonical(record), by a key in the trusted-authorizers set.
//             The signer attests that a signed client agreement exists (record.agreement
//             carries its reference + sha256) — the gate never signs, it only verifies.
const crypto = require("crypto");
const { ipToInt, cidrCalc } = require("../toolkit/scanutil");

// Action classes, least -> most intrusive. A record lists the classes it permits.
//   recon      passive/OSINT lookups about the target (dns, whois, cert transparency)
//   scan       active probes that touch the target (port scan, banner/header/TLS grab)
//   vuln-scan  active vulnerability checks / content fuzzing
//   exploit    anything that attempts to gain access or change state on the target
const ACTION_CLASSES = ["recon", "scan", "vuln-scan", "exploit"];
const MIN_CIDR_BITS = 16; // refuse absurdly broad ranges — almost certainly a typo, and never intended

function canonical(v) {
  if (Array.isArray(v)) return "[" + v.map(canonical).join(",") + "]";
  if (v && typeof v === "object") return "{" + Object.keys(v).sort().map((k) => JSON.stringify(k) + ":" + canonical(v[k])).join(",") + "}";
  return JSON.stringify(v);
}

// ---- target / scope-entry parsing ------------------------------------------------
// Host normalisation goes through the WHATWG URL parser on purpose: it canonicalises
// decimal / hex / octal IPv4 obfuscation (2130706433, 0x7f.1, 0177.0.0.1 -> 127.0.0.1)
// and IDN -> punycode, so those tricks cannot dodge the scope match.
function normHost(h) {
  h = String(h || "").trim();
  if (!h || /[\s/\\@?#]/.test(h)) return null;
  if (h.includes(":") || h.startsWith("[")) return null; // IPv6 / host:port handled by callers; IPv6 unsupported in v1
  let u; try { u = new URL("http://" + h); } catch (_) { return null; }
  const host = u.hostname.replace(/\.$/, "").toLowerCase();
  return host || null;
}
const isIPv4 = (s) => ipToInt(s) !== null;

// Parse a concrete TARGET (what a tool will touch). Returns
//   { kind: "ip"|"host"|"cidr", value, cidr?, url? } or { error }
function parseTarget(raw) {
  let s = String(raw == null ? "" : raw).trim();
  if (!s) return { error: "empty target" };
  if (s.includes("*")) return { error: "wildcard is not a concrete target: " + s };
  let url = null;
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(s)) {
    let u; try { u = new URL(s); } catch (_) { return { error: "unparseable URL: " + s }; }
    if (!/^https?:$/.test(u.protocol)) return { error: "unsupported URL scheme: " + u.protocol };
    if (u.username || u.password) return { error: "credentials in URL are not permitted" };
    url = { path: u.pathname || "/" };
    s = u.hostname; // URL parser already canonicalised it
    if (s.startsWith("[")) return { error: "IPv6 targets unsupported" };
  } else if (/^[^/\s]+:\d{1,5}$/.test(s) && !s.includes("]") && s.split(":").length === 2) {
    s = s.split(":")[0]; // host:port -> host (v1 scopes assets, not ports)
  }
  const cm = s.match(/^([^/]+)\/(\d{1,2})$/);
  if (cm) {
    const ip = normHost(cm[1]); const c = ip && isIPv4(ip) ? cidrCalc(ip + "/" + cm[2]) : null;
    if (!c) return { error: "invalid CIDR: " + s };
    return { kind: "cidr", value: c.network + "/" + c.bits, cidr: c };
  }
  if (s.includes("/")) return { error: "unexpected '/' in target: " + s };
  const h = normHost(s);
  if (!h) return { error: "invalid host: " + s };
  if (isIPv4(h)) return Object.assign({ kind: "ip", value: h }, url ? { url } : {});
  if (/^[0-9.]+$/.test(h)) return { error: "malformed IPv4 address: " + s }; // digits-and-dots that isn't a valid IP
  if (!/^[a-z0-9_]([a-z0-9_.-]*[a-z0-9_])?$/.test(h) && !/^xn--/.test(h)) return { error: "invalid hostname: " + s };
  return Object.assign({ kind: "host", value: h }, url ? { url } : {});
}

// Parse a SCOPE ENTRY (a string in record.scope.inScope / outOfScope):
//   "10.0.0.5"  ip     "10.0.0.0/24"  cidr    "app.example.com"  host (exact)
//   "*.example.com" wildcard (subdomains only, NOT the apex)    "https://app.example.com/api"  url
function parseScopeEntry(raw) {
  const s = String(raw == null ? "" : raw).trim();
  if (!s) return { error: "empty scope entry" };
  if (s.startsWith("*.")) {
    const base = normHost(s.slice(2));
    if (!base || isIPv4(base) || base.split(".").length < 2) return { error: "wildcard needs a registrable base domain (e.g. *.example.com): " + s };
    if (base.includes("*")) return { error: "only a single leading wildcard is allowed: " + s };
    return { kind: "wildcard", value: base };
  }
  if (s.includes("*")) return { error: "wildcards are only allowed as a leading '*.': " + s };
  const t = parseTarget(s);
  if (t.error) return t;
  if (t.kind === "cidr" && t.cidr.bits < MIN_CIDR_BITS) return { error: "CIDR broader than /" + MIN_CIDR_BITS + " is refused: " + s };
  if (/^https?:\/\//i.test(s)) return { kind: "url", value: t.value, path: (t.url && t.url.path) || "/" };
  return t;
}

const dotSuffix = (h, base) => h.endsWith("." + base);
const cidrRange = (c) => [ipToInt(c.network), ipToInt(c.broadcast)];

// Does in-scope entry `e` CONTAIN target `t`?
function covers(e, t) {
  if (e.kind === "ip") return t.kind === "ip" && t.value === e.value;
  if (e.kind === "cidr") {
    const [lo, hi] = cidrRange(e.cidr);
    if (t.kind === "ip") { const n = ipToInt(t.value); return n >= lo && n <= hi; }
    if (t.kind === "cidr") { const [tlo, thi] = cidrRange(t.cidr); return tlo >= lo && thi <= hi; } // whole target range inside
    return false;
  }
  if (e.kind === "host") return t.kind === "host" && t.value === e.value;
  if (e.kind === "wildcard") return t.kind === "host" && dotSuffix(t.value, e.value);
  if (e.kind === "url") {
    if (t.kind !== "host" || t.value !== e.value) return false;
    if (!t.url) return e.path === "/"; // bare host only if the entry is the whole site
    return e.path === "/" || t.url.path === e.path || t.url.path.startsWith(e.path.endsWith("/") ? e.path : e.path + "/");
  }
  return false;
}
// Does OUT-of-scope entry `e` TOUCH target `t`? Deliberately wider than `covers`:
// any overlap is a deny (a /24 target that merely contains an excluded host is denied).
function overlaps(e, t) {
  if (e.kind === "ip" || e.kind === "cidr") {
    const [elo, ehi] = e.kind === "ip" ? [ipToInt(e.value), ipToInt(e.value)] : cidrRange(e.cidr);
    if (t.kind === "ip") { const n = ipToInt(t.value); return n >= elo && n <= ehi; }
    if (t.kind === "cidr") { const [tlo, thi] = cidrRange(t.cidr); return tlo <= ehi && thi >= elo; }
    return false;
  }
  if (t.kind !== "host") return false;
  if (e.kind === "host") return t.value === e.value || dotSuffix(t.value, e.value); // excluding a host excludes its subdomains
  if (e.kind === "wildcard") return dotSuffix(t.value, e.value);
  if (e.kind === "url") { if (t.value !== e.value) return false; if (e.path === "/") return true; return !t.url || t.url.path === e.path || t.url.path.startsWith(e.path.endsWith("/") ? e.path : e.path + "/"); }
  return false;
}

// ---- record validation ------------------------------------------------------------
const ID_RE = /^[a-z0-9][a-z0-9-]{2,63}$/;
const isoOk = (s) => typeof s === "string" && !Number.isNaN(Date.parse(s));
const nonEmpty = (s) => typeof s === "string" && s.trim().length > 0;

// -> { ok, errors[], parsed: { inScope[], outOfScope[] } }
function validateRecord(rec) {
  const errors = []; const parsed = { inScope: [], outOfScope: [] };
  if (!rec || typeof rec !== "object") return { ok: false, errors: ["record missing"], parsed };
  if (rec.version !== 1) errors.push("unsupported record version (expected 1)");
  if (!ID_RE.test(String(rec.engagement || ""))) errors.push("engagement id must match " + ID_RE);
  if (!rec.client || !nonEmpty(rec.client.legalName)) errors.push("client.legalName required");
  if (!rec.client || !rec.client.signatory || !nonEmpty(rec.client.signatory.name) || !nonEmpty(rec.client.signatory.title)) errors.push("client.signatory.name and .title required (person with authority to consent for the scoped assets)");
  const a = rec.agreement;
  if (!a || !nonEmpty(a.ref) || !/^[a-f0-9]{64}$/i.test(String(a.sha256 || "")) || !isoOk(a.signedAt)) errors.push("agreement.ref, agreement.sha256 (of the signed document) and agreement.signedAt required");
  if (!rec.assetOwnership || rec.assetOwnership.confirmed !== true) errors.push("assetOwnership.confirmed must be true (client attests it owns / may authorise every in-scope asset; third-party-hosted assets need the host's consent recorded in assetOwnership.thirdPartyConsents)");
  const w = rec.window;
  if (!w || !isoOk(w.notBefore) || !isoOk(w.notAfter)) errors.push("window.notBefore and window.notAfter (ISO-8601 with offset) required");
  else if (!(Date.parse(w.notBefore) < Date.parse(w.notAfter))) errors.push("window.notBefore must precede window.notAfter");
  if (!rec.emergencyContact || !nonEmpty(rec.emergencyContact.name) || !nonEmpty(rec.emergencyContact.channel)) errors.push("emergencyContact.name and .channel required");
  if (!Array.isArray(rec.allowedClasses) || !rec.allowedClasses.length) errors.push("allowedClasses required (subset of " + ACTION_CLASSES.join(", ") + ")");
  else for (const c of rec.allowedClasses) if (!ACTION_CLASSES.includes(c)) errors.push("unknown action class: " + c);
  const sc = rec.scope;
  if (!sc || !Array.isArray(sc.inScope) || !sc.inScope.length) errors.push("scope.inScope must list at least one asset");
  else for (const raw of sc.inScope) { const p = parseScopeEntry(raw); if (p.error) errors.push("inScope: " + p.error); else parsed.inScope.push(Object.assign({ raw }, p)); }
  if (sc && sc.outOfScope !== undefined) {
    if (!Array.isArray(sc.outOfScope)) errors.push("scope.outOfScope must be an array");
    else for (const raw of sc.outOfScope) { const p = parseScopeEntry(raw); if (p.error) errors.push("outOfScope: " + p.error); else parsed.outOfScope.push(Object.assign({ raw }, p)); }
  }
  return { ok: !errors.length, errors, parsed };
}

// ---- signatures --------------------------------------------------------------------
function generateAuthorizerKey() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  return { publicPem: publicKey.export({ type: "spki", format: "pem" }), privatePem: privateKey.export({ type: "pkcs8", format: "pem" }) };
}
function signRecord(record, privatePem, keyId) {
  const sig = crypto.sign(null, Buffer.from(canonical(record)), crypto.createPrivateKey(privatePem));
  return { record, signature: { alg: "ed25519", keyId, value: sig.toString("base64") } };
}
// trustedKeys: { keyId: publicKeyPem }. -> { ok, reason? }
function verifySignature(envelope, trustedKeys) {
  try {
    const s = envelope && envelope.signature;
    if (!s || s.alg !== "ed25519" || !nonEmpty(s.keyId) || !nonEmpty(s.value)) return { ok: false, reason: "signature missing or malformed" };
    const pem = trustedKeys && Object.prototype.hasOwnProperty.call(trustedKeys, s.keyId) ? trustedKeys[s.keyId] : null;
    if (!pem) return { ok: false, reason: "signing key '" + s.keyId + "' is not a trusted authorizer" };
    const good = crypto.verify(null, Buffer.from(canonical(envelope.record)), crypto.createPublicKey(pem), Buffer.from(s.value, "base64"));
    return good ? { ok: true, keyId: s.keyId } : { ok: false, reason: "signature does not match record (record was altered or signed by another key)" };
  } catch (e) { return { ok: false, reason: "signature check failed: " + (e && e.message || e) }; }
}
const recordDigest = (record) => crypto.createHash("sha256").update(canonical(record)).digest("hex");

// ---- the decision -------------------------------------------------------------------
// evaluate({ envelope, trustedKeys, revoked, now, class, targets }) ->
//   { allow, code, reason, engagement?, recordDigest?, checked: [{ target, result }] }
// `revoked` is { at, reason } or null. `targets` is an array of raw strings; ALL must pass.
function evaluate(opts) {
  const deny = (code, reason, extra) => Object.assign({ allow: false, code, reason }, extra || {});
  try {
    const { envelope, trustedKeys, revoked, class: cls } = opts;
    const now = opts.now instanceof Date ? opts.now : new Date(opts.now || Date.now());
    if (!envelope || !envelope.record) return deny("NO_AUTHORIZATION", "no authorization on file for this engagement");
    const rec = envelope.record;
    const base = { engagement: rec.engagement, recordDigest: recordDigest(rec) };
    const sig = verifySignature(envelope, trustedKeys);
    if (!sig.ok) return deny("BAD_SIGNATURE", sig.reason, base);
    const v = validateRecord(rec);
    if (!v.ok) return deny("INVALID_RECORD", v.errors.join("; "), base);
    if (revoked) return deny("REVOKED", "authorization revoked" + (revoked.at ? " at " + revoked.at : "") + (revoked.reason ? ": " + revoked.reason : ""), base);
    const t = now.getTime();
    if (Date.parse(rec.agreement.signedAt) > t) return deny("NOT_YET_SIGNED", "agreement signedAt is in the future", base);
    if (t < Date.parse(rec.window.notBefore)) return deny("BEFORE_WINDOW", "testing window opens " + rec.window.notBefore, base);
    if (t >= Date.parse(rec.window.notAfter)) return deny("AFTER_WINDOW", "testing window closed " + rec.window.notAfter, base);
    if (!ACTION_CLASSES.includes(cls)) return deny("UNKNOWN_CLASS", "unknown action class: " + cls, base);
    if (!rec.allowedClasses.includes(cls)) return deny("CLASS_NOT_PERMITTED", "action class '" + cls + "' is not permitted by this authorization (permitted: " + rec.allowedClasses.join(", ") + ")", base);
    const targets = opts.targets;
    if (!Array.isArray(targets) || !targets.length) return deny("NO_TARGET", "no target supplied — the gate needs at least one explicit target", base);
    const checked = [];
    for (const raw of targets) {
      const tg = parseTarget(raw);
      if (tg.error) return deny("BAD_TARGET", tg.error, Object.assign({ checked }, base));
      const hit = v.parsed.outOfScope.find((e) => overlaps(e, tg));
      if (hit) return deny("OUT_OF_SCOPE_EXCLUDED", "target " + raw + " is explicitly excluded (" + hit.raw + ")", Object.assign({ checked }, base));
      const inn = v.parsed.inScope.find((e) => covers(e, tg));
      if (!inn) return deny("NOT_IN_SCOPE", "target " + raw + " is not covered by any in-scope entry", Object.assign({ checked }, base));
      checked.push({ target: raw, normalized: tg.value, matched: inn.raw });
    }
    return Object.assign({ allow: true, code: "ALLOW", reason: "in scope", checked }, base);
  } catch (e) { return deny("GATE_ERROR", "gate error (fail closed): " + (e && e.message || e)); }
}

module.exports = { ACTION_CLASSES, MIN_CIDR_BITS, ID_RE, canonical, parseTarget, parseScopeEntry, covers, overlaps, validateRecord, generateAuthorizerKey, signRecord, verifySignature, recordDigest, evaluate };
